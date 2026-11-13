# The factory tree from signed lobby terms, and the creation checks
# (spec/terms.md 4, spec/signing-round.md 4.1 and 13, spec/safety-rule.md C1
# to C11 and H1, spec/exit.md 4.1 to 4.4).
#
#   gazpacho_tree         pure core: strict C11, freestanding, no allocation,
#                         no I/O, no writable data; checked by
#                         tools/check-core-isolation.sh (test tree_isolation)
#   gazpacho_tree_import  the build through the imported SuperScalar code and a
#                         crypto provider on secp256k1-zkp; outside the core

set(GZ_TREE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(GZ_TREE_TESTS ${PROJECT_SOURCE_DIR}/tests/tree)

set(GZ_TREE_SOURCES ${GZ_TREE_DIR}/sha256.c ${GZ_TREE_DIR}/terms.c ${GZ_TREE_DIR}/shape.c ${GZ_TREE_DIR}/model.c
    ${GZ_TREE_DIR}/checks.c ${GZ_TREE_DIR}/exit.c)
# The core's own flags (GZ_CORE_FLAGS, top-level CMakeLists.txt): strict C11,
# freestanding, no VLAs, -fno-common, and no floating-point or vector
# registers where the compiler can promise it.
add_library(gazpacho_tree STATIC ${GZ_TREE_SOURCES})
set_target_properties(gazpacho_tree PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_tree PUBLIC ${GZ_TREE_DIR}/include)
target_compile_options(gazpacho_tree PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

add_library(gazpacho_tree_import STATIC import/tree_import.c)
target_link_libraries(gazpacho_tree_import PUBLIC gazpacho_tree gazpacho_superscalar secp256k1)
target_compile_options(gazpacho_tree_import PRIVATE ${GZ_NEW_CODE_WARNINGS})

# The same isolation rules as the rest of the core (core_isolation): the
# library, in this build's mode, and its sources scanned with this build's flags.
string(JOIN " " GZ_TREE_SCAN_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${GZ_BUILD_TYPE_UPPER}} -std=c11 ${GZ_CORE_FLAGS}
       -I${GZ_TREE_DIR}/include)
add_test(NAME tree_isolation
  COMMAND sh ${PROJECT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          $<TARGET_FILE:gazpacho_tree> --sources ${CMAKE_C_COMPILER} ${GZ_TREE_SCAN_FLAGS} ${GZ_TREE_SOURCES})

function(gz_tree_test name)
  add_executable(test_tree_${name} ${GZ_TREE_TESTS}/test_tree_${name}.c)
  target_link_libraries(test_tree_${name} PRIVATE gazpacho_tree_import)
  target_compile_options(test_tree_${name} PRIVATE ${GZ_NEW_CODE_WARNINGS})
  add_test(NAME tree_${name} COMMAND test_tree_${name} ${ARGN})
endfunction()

gz_tree_test(terms)
gz_tree_test(exit)
gz_tree_test(build ${PROJECT_SOURCE_DIR}/tests/reference/tree-from-terms-txids.txt)
gz_tree_test(checks)

# The randomized model test: tools/spec-vectors.py's own functions against the
# library, through a driver that uses the pure library only.
add_executable(tree_model_driver ${GZ_TREE_TESTS}/tree_model_driver.c)
target_link_libraries(tree_model_driver PRIVATE gazpacho_tree)
target_compile_options(tree_model_driver PRIVATE ${GZ_NEW_CODE_WARNINGS})
find_program(GZ_PYTHON3 python3)
if(GZ_PYTHON3)
  add_test(NAME tree_model
    COMMAND ${GZ_PYTHON3} -I ${GZ_TREE_TESTS}/model_check.py $<TARGET_FILE:tree_model_driver>
            ${PROJECT_SOURCE_DIR}/tools/spec-vectors.py 1500 1)
endif()

# Fuzz targets: the terms decoder (both records, with the canonical round
# trip as the property) and the transaction reader. Plain driver by default,
# libFuzzer with -DGZ_LIBFUZZER=ON (docs/notes/ci.md).
foreach(target tree_terms tree_tx)
  if(GZ_LIBFUZZER)
    add_executable(fuzz_${target} ${GZ_TREE_TESTS}/fuzz_${target}.c)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  else()
    add_executable(fuzz_${target} ${GZ_TREE_TESTS}/fuzz_${target}.c ${PROJECT_SOURCE_DIR}/tests/net/fuzz_main.c)
    add_test(NAME fuzz_${target} COMMAND fuzz_${target} 200000)
  endif()
  target_link_libraries(fuzz_${target} PRIVATE gazpacho_tree)
  target_compile_options(fuzz_${target} PRIVATE ${GZ_NEW_CODE_WARNINGS})
endforeach()
