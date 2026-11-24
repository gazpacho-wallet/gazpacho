# The signer (docs/notes/signer.md): the one library that holds secret keys
# and signs, with typed operations only. Stage 1: the interface, the tables
# of section 3, slots and envelope signatures; the rest refuses until S4.
# Added by add_subdirectory(signer) in the top-level CMakeLists.txt, after
# core/signing, core/tree and wallet/.

set(GZ_SIGNER_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(GZ_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(gazpacho_signer STATIC signer.c policy.c)
set_target_properties(gazpacho_signer PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_signer PUBLIC ${GZ_SIGNER_DIR}/include
  PRIVATE ${GZ_ROOT_DIR}/core/lobby/include)
# gz_rmsg_hash (core/signing/round_msg.c), BIP 32 (wallet), the wallet's
# transaction types (wallet/tx), secp256k1-zkp.
target_link_libraries(gazpacho_signer PUBLIC gazpacho_signing gazpacho_wallet_keys gazpacho_wallet_tx secp256k1)
target_compile_options(gazpacho_signer PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

# The vectors build: the same sources with GZ_SG_VECTORS, which alone allows
# BIP 340's all-zero aux_rand (for the kinds table 3.2 marks), so that test
# vectors compare byte for byte. Linked by tests only; nothing else may link it.
add_library(gazpacho_signer_vectors STATIC signer.c policy.c)
set_target_properties(gazpacho_signer_vectors PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_signer_vectors PUBLIC ${GZ_SIGNER_DIR}/include
  PRIVATE ${GZ_ROOT_DIR}/core/lobby/include)
target_compile_definitions(gazpacho_signer_vectors PRIVATE GZ_SG_VECTORS)
target_link_libraries(gazpacho_signer_vectors PUBLIC gazpacho_signing gazpacho_wallet_keys gazpacho_wallet_tx secp256k1)
target_compile_options(gazpacho_signer_vectors PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

# test_signer: the production library (fresh aux_rand always).
# test_signer_vectors: the vectors build, the deterministic vectors exactly.
add_executable(test_signer tests/test_signer.c)
target_link_libraries(test_signer PRIVATE gazpacho_signer)
target_compile_options(test_signer PRIVATE ${GZ_NEW_CODE_WARNINGS})
target_compile_definitions(test_signer PRIVATE GZ_SIGNER_VECTORS="${GZ_SIGNER_DIR}/tests/vectors.txt")
add_test(NAME signer COMMAND test_signer ${GZ_SIGNER_DIR}/tests/vectors.txt)
add_executable(test_signer_vectors tests/test_signer.c)
target_link_libraries(test_signer_vectors PRIVATE gazpacho_signer_vectors)
target_compile_options(test_signer_vectors PRIVATE ${GZ_NEW_CODE_WARNINGS})
target_compile_definitions(test_signer_vectors PRIVATE GZ_SG_VECTORS
  GZ_SIGNER_VECTORS="${GZ_SIGNER_DIR}/tests/vectors.txt")
add_test(NAME signer_vectors COMMAND test_signer_vectors ${GZ_SIGNER_DIR}/tests/vectors.txt)

# The vectors the test reads, recomputed by an independent pure-Python
# implementation (tools/signer-vectors.py).
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME signer_vectors_py
    COMMAND ${Python3_EXECUTABLE} -I ${GZ_ROOT_DIR}/tools/signer-vectors.py --check ${GZ_SIGNER_DIR}/tests/vectors.txt)
endif()

# The same test under memcheck where valgrind is (the valgrind shards also
# run every compiled test), and the constant-time test: built where
# valgrind's headers are, run where valgrind is and nothing is sanitized.
if(GZ_VALGRIND AND GZ_VALGRIND_TESTS AND NOT GZ_SANITIZE)
  add_test(NAME valgrind_signer COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_signer> ${GZ_SIGNER_DIR}/tests/vectors.txt)
  add_test(NAME valgrind_signer_vectors COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_signer_vectors> ${GZ_SIGNER_DIR}/tests/vectors.txt)
endif()
include(CheckIncludeFile)
check_include_file(valgrind/memcheck.h GZ_SIGNER_HAVE_MEMCHECK_H)
if(GZ_SIGNER_HAVE_MEMCHECK_H)
  add_executable(test_signer_ctime tests/test_signer_ctime.c policy.c)
  set_target_properties(test_signer_ctime PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(test_signer_ctime PRIVATE ${GZ_SIGNER_DIR}/include ${GZ_ROOT_DIR}/core/lobby/include)
  target_link_libraries(test_signer_ctime PRIVATE gazpacho_signing gazpacho_wallet_keys gazpacho_wallet_tx secp256k1)
  target_compile_options(test_signer_ctime PRIVATE ${GZ_NEW_CODE_WARNINGS} -Wno-unused-function)
  if(GZ_VALGRIND AND NOT GZ_SANITIZE AND NOT CMAKE_C_FLAGS MATCHES "-fsanitize")
    add_test(NAME signer_ctime COMMAND ${GZ_VALGRIND} --quiet --error-exitcode=9 --track-origins=yes
             $<TARGET_FILE:test_signer_ctime>)
  endif()
endif()

# The CI checks of signer.md 7 and their own tests (tools/, report mode in S1).
if(Python3_Interpreter_FOUND)
  add_test(NAME signer_check_tags_selftest
    COMMAND ${Python3_EXECUTABLE} -I ${GZ_ROOT_DIR}/tests/tools/test_check_tags.py)
  add_test(NAME signer_boundary_selftest
    COMMAND ${Python3_EXECUTABLE} -I ${GZ_ROOT_DIR}/tests/tools/test_check_signer_boundary.py)
endif()

# The vectors build cannot stand in for the production one (review A of #71,
# H3): other entry-point names and a marker, checked in the archives here,
# and (top-level CMakeLists.txt, gz_signer_vectors_guard) refused by CMake if
# any target but test_signer_vectors links it.
add_test(NAME signer_link_guard
  COMMAND sh ${GZ_SIGNER_DIR}/tests/link_guard.sh $<TARGET_FILE:gazpacho_signer> $<TARGET_FILE:gazpacho_signer_vectors>)
