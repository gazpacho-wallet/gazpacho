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

# Fuzz targets: the transport's fuzz_noise and fuzz_tlv, and the wallet's
# fuzz_tx_parse (wallet/tx/CMakeLists.txt). Every target is an executable named
# fuzz_<name> whose source defines LLVMFuzzerTestOneInput. With this option ON
# (clang only), a target links with -fsanitize=fuzzer and without the plain
# driver that runs it as a CTest test; CI's fuzz job then runs each fuzz_*
# for 60 seconds. See docs/notes/ci.md.
option(GZ_LIBFUZZER "Link fuzz_* targets against clang's libFuzzer instead of the plain driver" OFF)

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
# -fno-common: a global left to the linker is refused by the isolation check
# as well (tests/isolation/cases.c, case 36).
set(GZ_CORE_FLAGS -pedantic -Wvla -ffreestanding -fno-common)
# -mgeneral-regs-only (no floating-point or vector registers, so the isolation
# check need not reason about them) exists only on x86 and AArch64.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i[0-9]86|AMD64|aarch64|arm64")
  list(APPEND GZ_CORE_FLAGS -mgeneral-regs-only)
endif()
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
foreach(profile RANGE 1 10)
  add_test(NAME sim_profile_${profile} COMMAND test_sim_seeds 100 300 1 ${profile})
endforeach()

# What the compiled core can reach and remember, and proof that the check
# refuses an object that breaks each rule.
if(GZ_SANITIZE OR CMAKE_C_FLAGS MATCHES "-fsanitize=")
  set(GZ_ISOLATION_MODE --sanitized)    # the checkers add writable sections of their own
endif()
# The source scan preprocesses with the build's own flags (and, in the script,
# again as release, debug and sanitizer builds).
string(TOUPPER "${CMAKE_BUILD_TYPE}" GZ_BUILD_TYPE_UPPER)
string(JOIN " " GZ_CORE_SCAN_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${GZ_BUILD_TYPE_UPPER}} -std=c11 ${GZ_CORE_FLAGS}
       -I${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/include)
add_test(NAME core_isolation
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          $<TARGET_FILE:gazpacho_core> --sources ${CMAKE_C_COMPILER} ${GZ_CORE_SCAN_FLAGS} ${GZ_CORE_SOURCES})
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
# GZ_VALGRIND_TESTS=OFF leaves them out (the wallet break-checks do, as the
# core cannot notice a wallet fault and they would run once per fault).
option(GZ_VALGRIND_TESTS "Register the core tests again under valgrind, where it is installed" ON)
find_program(GZ_VALGRIND valgrind)
if(GZ_VALGRIND AND GZ_VALGRIND_TESTS AND NOT GZ_SANITIZE)
  set(GZ_MEMCHECK ${GZ_VALGRIND} --quiet --error-exitcode=9 --track-origins=yes --leak-check=full)
  foreach(name action runner node rng sim sim_known_trace)
    add_test(NAME valgrind_${name} COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_${name}>)
  endforeach()
  add_test(NAME valgrind_sim_seeds COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_sim_seeds> 20 300 1 0)
  add_test(NAME valgrind_sim_profile_3 COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_sim_seeds> 10 200 1 3)
endif()

# --- Transport (ports/net): BOLT 8 and BOLT 1, outside the core ----------------
# Strict C11 like the core, but not freestanding: conn.c uses POSIX sockets.
# noise.c and frame.c do no input or output (spec/transport.md).
add_library(gazpacho_net STATIC ports/net/noise.c ports/net/frame.c ports/net/conn.c ports/net/wipe.c)
set_target_properties(gazpacho_net PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_net PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/ports/net ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/include)
target_link_libraries(gazpacho_net PUBLIC secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_net PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

add_executable(gz-net tools/gz-net/gz-net.c)
target_link_libraries(gz-net PRIVATE gazpacho_net)
target_compile_options(gz-net PRIVATE ${GZ_NEW_CODE_WARNINGS})

gz_add_test(net_noise tests/net/test_noise.c gazpacho_net)
gz_add_test(net_frame tests/net/test_frame.c gazpacho_net 20000)
gz_add_test(net_conn  tests/net/test_conn.c  gazpacho_net)
# Every wipe of a stack secret is counted, and HMAC is made to fail on demand
# (GNU ld's --wrap; review of PR 10, section 6).
gz_add_test(net_wipes tests/net/test_wipes.c gazpacho_net)
target_link_options(test_net_wipes PRIVATE "LINKER:--wrap=gz_net_wipe,--wrap=HMAC")
# A peer for gz-net's tests: unknown even and odd messages, a wrong pong.
add_executable(net_peer tests/net/net_peer.c)
target_link_libraries(net_peer PRIVATE gazpacho_net)
target_compile_options(net_peer PRIVATE ${GZ_NEW_CODE_WARNINGS})
add_test(NAME net_gz_net COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/net/test_gz_net.sh
         $<TARGET_FILE:gz-net> $<TARGET_FILE:net_peer>)
# gz-net against an independent Python BOLT 8 peer (the PR 10 reviewer's),
# in both roles past key rotation. Opt-in: needs python3 and `cryptography`.
# It should run in the automated checks wherever `cryptography` is installed
# (review of PR 10, round 2, N6; for the CI hardening work).
option(GZ_INTEROP_PY "Run gz-net against the independent Python BOLT 8 peer" OFF)
if(GZ_INTEROP_PY)
  add_test(NAME net_interop_py COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/net/interop/run.sh
           $<TARGET_FILE:gz-net> ${CMAKE_CURRENT_SOURCE_DIR}/tests/net/interop/bolt8_peer.py)
endif()
# Fuzz targets. Normally with the plain driver, as CTest tests; with
# -DGZ_LIBFUZZER=ON (clang; the option is declared at the top), linked with
# libFuzzer instead and run by tools/run-fuzz.sh (docs/notes/ci.md).
foreach(target noise tlv)
  if(GZ_LIBFUZZER)
    add_executable(fuzz_${target} tests/net/fuzz_${target}.c)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  else()
    add_executable(fuzz_${target} tests/net/fuzz_${target}.c tests/net/fuzz_main.c)
    add_test(NAME net_fuzz_${target} COMMAND fuzz_${target} 200000)
  endif()
  target_link_libraries(fuzz_${target} PRIVATE gazpacho_net)
  target_compile_options(fuzz_${target} PRIVATE ${GZ_NEW_CODE_WARNINGS})
endforeach()

add_subdirectory(wallet)

# --- chain view port (Esplora backend, comparing backend, gz-chain) ------------
add_subdirectory(ports/chain)
# --- Lobby engine (core/lobby): sans-I/O like the core, the same flags and ---
# --- the same isolation check. Signing and verifying go through a port.    ---
set(GZ_LOBBY_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/act.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/host.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/member.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/sha256.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/terms.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/wire.c)
add_library(gazpacho_lobby STATIC ${GZ_LOBBY_SOURCES})
set_target_properties(gazpacho_lobby PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_lobby PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include)
target_link_libraries(gazpacho_lobby PUBLIC gazpacho_core)
target_compile_options(gazpacho_lobby PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

# Tests use libsecp256k1 for the crypto port (BIP 340 with the test keys).
function(gz_lobby_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE gazpacho_lobby gazpacho_sim secp256k1)
  target_include_directories(${name} PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
  target_compile_options(${name} PRIVATE ${GZ_NEW_CODE_WARNINGS})
endfunction()
gz_lobby_test(test_lobby_vectors tests/lobby/test_lobby_vectors.c)
gz_lobby_test(test_lobby         tests/lobby/test_lobby.c)
gz_lobby_test(test_lobby_sim     tests/lobby/test_lobby_sim.c)
gz_lobby_test(fuzz_lobby         tests/lobby/fuzz_lobby.c)
gz_lobby_test(lobby_model_driver tests/lobby/model_driver.c)
add_test(NAME lobby_vectors COMMAND test_lobby_vectors)
add_test(NAME lobby COMMAND test_lobby)
# One host and 3 to 8 members: mixed faults, crashes only, network only, none.
foreach(profile RANGE 0 3)
  add_test(NAME lobby_sim_profile_${profile} COMMAND test_lobby_sim 100 ${profile})
endforeach()
add_test(NAME lobby_fuzz COMMAND fuzz_lobby 200000 1)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  # The independent model of the start rule, the choice of signers and the
  # conditions check, compared with the engine on random cases.
  add_test(NAME lobby_model COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/tests/lobby/lobby_model.py
           check $<TARGET_FILE:lobby_model_driver> 30000 1)
  add_test(NAME lobby_model_selftest COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/tests/lobby/lobby_model.py selftest)
endif()
# The lobby calls the core (gz_action_list_add), so the check runs on the two
# built together: the pair may call nothing outside itself.
add_library(gazpacho_lobby_with_core STATIC ${GZ_CORE_SOURCES} ${GZ_LOBBY_SOURCES})
set_target_properties(gazpacho_lobby_with_core PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_lobby_with_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include)
target_compile_options(gazpacho_lobby_with_core PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
string(JOIN " " GZ_LOBBY_SCAN_FLAGS ${GZ_CORE_SCAN_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include)
add_test(NAME lobby_isolation
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          $<TARGET_FILE:gazpacho_lobby_with_core> --sources ${CMAKE_C_COMPILER} ${GZ_LOBBY_SCAN_FLAGS} ${GZ_LOBBY_SOURCES})
if(GZ_VALGRIND AND NOT GZ_SANITIZE)
  add_test(NAME valgrind_lobby_vectors COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_lobby_vectors>)
  add_test(NAME valgrind_lobby COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_lobby>)
  add_test(NAME valgrind_lobby_sim COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_lobby_sim> 4 0)
  add_test(NAME valgrind_lobby_fuzz COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:fuzz_lobby> 5000 2)
endif()
