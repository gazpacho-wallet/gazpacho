# The funding engine (docs/notes/composite-node.md 9, 12.1, 14; step P4.5).
#
#   gazpacho_funding   pure core: strict C11, freestanding, no allocation, no
#                      I/O, no writable data; checked by
#                      tools/check-core-isolation.sh (test funding_isolation)
#
# Not wired into core/node or program/ yet: the wiring waits for P4.3
# (docs/notes/funding.md, "The wiring"). core/node calls only the pure
# gz_fund_set_aside_sat (setaside.c), for the host's early start and view.

set(GZ_FUNDING_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(GZ_FUNDING_TESTS ${PROJECT_SOURCE_DIR}/tests/funding)
set(GZ_FUNDING_SOURCES ${GZ_FUNDING_DIR}/funding.c ${GZ_FUNDING_DIR}/txsize.c ${GZ_FUNDING_DIR}/setaside.c)

add_library(gazpacho_funding STATIC ${GZ_FUNDING_SOURCES})
set_target_properties(gazpacho_funding PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_funding PUBLIC ${GZ_FUNDING_DIR}/include)
target_link_libraries(gazpacho_funding PUBLIC gazpacho_core gazpacho_tree)
target_compile_options(gazpacho_funding PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

string(JOIN " " GZ_FUNDING_SCAN_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${GZ_BUILD_TYPE_UPPER}} -std=c11 ${GZ_CORE_FLAGS}
       -I${GZ_FUNDING_DIR}/include -I${PROJECT_SOURCE_DIR}/core/gazpacho/include -I${PROJECT_SOURCE_DIR}/core/tree/include)
add_test(NAME funding_isolation
  COMMAND sh ${PROJECT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          --allow ${PROJECT_SOURCE_DIR}/tools/funding-allowed-calls.txt
          $<TARGET_FILE:gazpacho_funding> --sources ${CMAKE_C_COMPILER} ${GZ_FUNDING_SCAN_FLAGS} ${GZ_FUNDING_SOURCES})

foreach(t test_funding test_funding_model)
  add_executable(${t} ${GZ_FUNDING_TESTS}/${t}.c)
  target_link_libraries(${t} PRIVATE gazpacho_funding)
  target_compile_options(${t} PRIVATE ${GZ_NEW_CODE_WARNINGS})
endforeach()
add_test(NAME funding COMMAND test_funding)
add_test(NAME funding_model COMMAND test_funding_model 300)

# Every decoder (the three records, a command, the chain events and the
# transaction walker) under hostile bytes: never an error but CORRUPT at
# load, never a step past the declared bounds.
if(GZ_LIBFUZZER)
  add_executable(fuzz_funding ${GZ_FUNDING_TESTS}/fuzz_funding.c)
  target_link_options(fuzz_funding PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_funding ${GZ_FUNDING_TESTS}/fuzz_funding.c ${PROJECT_SOURCE_DIR}/tests/net/fuzz_main.c)
  add_test(NAME funding_fuzz COMMAND fuzz_funding 200000)
endif()
target_link_libraries(fuzz_funding PRIVATE gazpacho_funding)
target_compile_options(fuzz_funding PRIVATE ${GZ_NEW_CODE_WARNINGS})

# The regtest driver's engine harness (tools/regtest-funding.py): the real
# engine over the real wallet, on stdin and stdout. Not a CTest test: it needs
# a regtest bitcoind.
add_executable(gz-funding-harness ${GZ_FUNDING_TESTS}/regtest_harness.c)
target_link_libraries(gz-funding-harness PRIVATE gazpacho_funding gazpacho_wallet_tx)
target_compile_options(gz-funding-harness PRIVATE ${GZ_NEW_CODE_WARNINGS})
