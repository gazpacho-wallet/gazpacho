cmake_minimum_required(VERSION 3.14)
project(gazpacho_import VERSION 0.0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# Extensions stay ON (gnu11), exactly as in SuperScalar's own build: bip39.c uses strtok_r.
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GZ_SANITIZE "Build everything (including secp256k1-zkp) with AddressSanitizer + UBSan" OFF)
if(GZ_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# --- secp256k1-zkp at the exact commit SuperScalar pins, same modules ---------
# Mirrors SuperScalar CMakeLists.txt lines 80-95. tools/update-import.sh checks this tag
# against the pinned SuperScalar commit's CMakeLists.txt.
include(FetchContent)
# Static secp256k1 (SuperScalar CMakeLists.txt line 76 does the same).
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG      ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS  ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY   ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS            OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK        OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES         OFF CACHE BOOL "" FORCE)
FetchContent_Declare(secp256k1-zkp
  GIT_REPOSITORY https://github.com/BlockstreamResearch/secp256k1-zkp.git
  GIT_TAG        6152622613fdf1c5af6f31f74c427c4e9ee120ce
)
FetchContent_MakeAvailable(secp256k1-zkp)

find_package(OpenSSL REQUIRED)   # libcrypto only is used

# --- imported SuperScalar files (unchanged) + shims ---------------------------
set(SS ${CMAKE_CURRENT_SOURCE_DIR}/core/superscalar)
file(GLOB GZ_SS_SOURCES CONFIGURE_DEPENDS ${SS}/src/*.c)
file(GLOB GZ_SHIM_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/shim/*.c)

add_library(gazpacho_superscalar STATIC ${GZ_SS_SOURCES} ${GZ_SHIM_SOURCES})
target_include_directories(gazpacho_superscalar
  PUBLIC  ${SS}/include
  PRIVATE ${SS}/src ${CMAKE_CURRENT_SOURCE_DIR}/core/shim)
target_link_libraries(gazpacho_superscalar PUBLIC secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_superscalar PRIVATE -Wall -Wextra)

# --- tests -------------------------------------------------------------------
enable_testing()
add_executable(test_reference_tree tests/test_reference_tree.c)
target_link_libraries(test_reference_tree PRIVATE gazpacho_superscalar)
target_compile_options(test_reference_tree PRIVATE -Wall -Wextra)
target_compile_definitions(test_reference_tree PRIVATE
  GZ_REFERENCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/tests/reference/superscalar-tree-txids.txt")
add_test(NAME reference_tree
  COMMAND test_reference_tree ${CMAKE_CURRENT_SOURCE_DIR}/tests/reference/superscalar-tree-txids.txt)

# Scale check of the planned tree shape. Built so it keeps compiling; run by hand
# (see docs/notes/tree-scale-check.md), not registered with CTest.
add_executable(tree_shapes tests/scale/tree_shapes.c)
target_link_libraries(tree_shapes PRIVATE gazpacho_superscalar)
target_compile_options(tree_shapes PRIVATE -Wall -Wextra -Werror)

# --- Gazpacho core: new code, portable C with no system calls -----------------
# -Werror applies to new code only; the imported files above keep their own flags.
set(GZ_NEW_CODE_WARNINGS -Wall -Wextra -Werror)

# The core is strict C11 (no GNU extensions), freestanding, with no
# variable-length arrays and no floating point or vector registers.
# tools/check-core-isolation.sh checks the result.
set(GZ_CORE_FLAGS -pedantic -Wvla -ffreestanding -mgeneral-regs-only)
set(GZ_CORE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/action.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/runner.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/node.c)
add_library(gazpacho_core STATIC ${GZ_CORE_SOURCES})
set_target_properties(gazpacho_core PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/include)
target_compile_options(gazpacho_core PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

# --- Simulator: deterministic harness around the core. Never linked into it. ---
add_library(gazpacho_sim STATIC sim/rng.c sim/sim.c)
target_include_directories(gazpacho_sim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/sim)
target_link_libraries(gazpacho_sim PUBLIC gazpacho_core)
target_compile_options(gazpacho_sim PRIVATE ${GZ_NEW_CODE_WARNINGS})

function(gz_add_test name source library)
  add_executable(test_${name} ${source})
  target_link_libraries(test_${name} PRIVATE ${library})
  target_compile_options(test_${name} PRIVATE ${GZ_NEW_CODE_WARNINGS})
  add_test(NAME ${name} COMMAND test_${name} ${ARGN})
endfunction()

gz_add_test(action    tests/core/test_action.c    gazpacho_core)
gz_add_test(runner    tests/core/test_runner.c    gazpacho_core)
gz_add_test(node      tests/core/test_node.c      gazpacho_core)
gz_add_test(rng       tests/sim/test_rng.c        gazpacho_sim)
gz_add_test(sim       tests/sim/test_sim.c        gazpacho_sim)
# One fixed seed must give the trace digest written in the test: compares
# separate processes and both build configurations, not only two simulators
# in one process.
gz_add_test(sim_known_trace tests/sim/test_sim_known.c gazpacho_sim)
# 1,000 seeds with every fault at a moderate rate, then the extreme profiles
# (see tests/sim/test_sim_seeds.c): 100 seeds of 300 steps each.
gz_add_test(sim_seeds tests/sim/test_sim_seeds.c  gazpacho_sim 1000 400 1 0)
foreach(profile RANGE 1 9)
  add_test(NAME sim_profile_${profile} COMMAND test_sim_seeds 100 300 1 ${profile})
endforeach()

# What the compiled core can reach and remember, and proof that the check
# refuses an object that breaks each rule.
if(GZ_SANITIZE)
  set(GZ_ISOLATION_MODE --sanitized)    # the checkers add writable sections of their own
endif()
add_test(NAME core_isolation
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          $<TARGET_FILE:gazpacho_core> --sources ${GZ_CORE_SOURCES})
add_library(isolation_sneaky OBJECT tests/isolation/sneaky.c)
string(JOIN " " GZ_CORE_FLAGS_TEXT -std=c11 ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
add_test(NAME core_isolation_refuses_sneaky_object
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/isolation/check-sneaky.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh
          $<TARGET_OBJECTS:isolation_sneaky>
          ${CMAKE_C_COMPILER}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/isolation
          ${CMAKE_CURRENT_BINARY_DIR}
          ${GZ_CORE_FLAGS_TEXT})

# The same tests under valgrind's memcheck with origin tracking, which sees
# what the compiler-based checkers cannot: uninitialised bytes, padding
# included, reaching a decision or an output. The tests compare or digest
# everything the core hands out, so such bytes show. Registered only where
# valgrind is installed, and not in the sanitizer build (the two do not mix).
find_program(GZ_VALGRIND valgrind)
if(GZ_VALGRIND AND NOT GZ_SANITIZE)
  set(GZ_MEMCHECK ${GZ_VALGRIND} --quiet --error-exitcode=9 --track-origins=yes --leak-check=full)
  foreach(name action runner node rng sim sim_known_trace)
    add_test(NAME valgrind_${name} COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_${name}>)
  endforeach()
  add_test(NAME valgrind_sim_seeds COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_sim_seeds> 20 300 1 0)
  add_test(NAME valgrind_sim_profile_3 COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_sim_seeds> 10 200 1 3)
endif()
