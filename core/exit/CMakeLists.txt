# The exit engine, tree half (spec/exit.md 6.8; Slice 1.5 plan item P3).
#
#   gazpacho_exit   pure core: strict C11, freestanding, no allocation, no
#                   I/O, no writable data; checked by
#                   tools/check-core-isolation.sh (test exit_isolation)
#
# Not linked into core/node or program/ yet: the wiring is plan items P4
# (the member's "publish my path") and P5 (the host's sweep command).

set(GZ_EXIT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(GZ_EXIT_TESTS ${PROJECT_SOURCE_DIR}/tests/exit)
set(GZ_EXIT_SOURCES ${GZ_EXIT_DIR}/exit_engine.c)

add_library(gazpacho_exit STATIC ${GZ_EXIT_SOURCES})
set_target_properties(gazpacho_exit PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_exit PUBLIC ${GZ_EXIT_DIR}/include)
target_link_libraries(gazpacho_exit PUBLIC gazpacho_core gazpacho_tree)
target_compile_options(gazpacho_exit PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

string(JOIN " " GZ_EXIT_SCAN_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${GZ_BUILD_TYPE_UPPER}} -std=c11 ${GZ_CORE_FLAGS}
       -I${GZ_EXIT_DIR}/include -I${PROJECT_SOURCE_DIR}/core/gazpacho/include -I${PROJECT_SOURCE_DIR}/core/tree/include)
add_test(NAME exit_isolation
  COMMAND sh ${PROJECT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          --allow ${PROJECT_SOURCE_DIR}/tools/exit-allowed-calls.txt
          $<TARGET_FILE:gazpacho_exit> --sources ${CMAKE_C_COMPILER} ${GZ_EXIT_SCAN_FLAGS} ${GZ_EXIT_SOURCES})

# The engine over T1 trees at depths 1, 2 and 3, through the real runner,
# against a pretend chain and chain view (the trees are built with the test
# keys through the crypto provider, hence the import library).
add_executable(test_exit_engine ${GZ_EXIT_TESTS}/test_exit_engine.c)
target_link_libraries(test_exit_engine PRIVATE gazpacho_exit gazpacho_tree_import)
target_compile_options(test_exit_engine PRIVATE ${GZ_NEW_CODE_WARNINGS})
add_test(NAME exit_engine COMMAND test_exit_engine)
