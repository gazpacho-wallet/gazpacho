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

# --- Signing round engine (core/signing): portable C11 like the core, sans-I/O,
# calling only secp256k1-zkp (an exact allow-list) and the core's action list.
set(GZ_SIGNING_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/signing.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/sign_tx.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/round_msg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/signing_node.c)
add_library(gazpacho_signing STATIC ${GZ_SIGNING_SOURCES})
set_target_properties(gazpacho_signing PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_signing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/include
  ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include)
target_link_libraries(gazpacho_signing PUBLIC gazpacho_core secp256k1)
target_compile_options(gazpacho_signing PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})

add_executable(test_signing tests/signing/test_signing.c)
target_link_libraries(test_signing PRIVATE gazpacho_signing gazpacho_sim gazpacho_superscalar gazpacho_tree)
target_compile_options(test_signing PRIVATE ${GZ_NEW_CODE_WARNINGS})
# One CTest test per section, so they run in parallel and each stays inside
# CI's per-test limit.
foreach(section blocks decoders golden model faults honest t1 crashes restores errors)
  add_test(NAME signing_${section} COMMAND test_signing ${section})
endforeach()
gz_add_test(round_msg tests/signing/test_round_msg.c gazpacho_signing)
# fuzz_signing drives whole engines from generated journals and messages with
# its own main; it is not a libFuzzer target (tools/run-fuzz.sh runs every
# fuzz_* there is), so it is built only with the plain drivers.
if(NOT GZ_LIBFUZZER)
  add_executable(fuzz_signing tests/signing/fuzz_signing.c)
  target_link_libraries(fuzz_signing PRIVATE gazpacho_signing gazpacho_sim gazpacho_superscalar gazpacho_tree)
  target_compile_options(fuzz_signing PRIVATE ${GZ_NEW_CODE_WARNINGS})
  add_test(NAME signing_fuzz COMMAND fuzz_signing 20000 20)
endif()
# Every round message decoder (messages.md 7), with libFuzzer or the plain driver.
if(GZ_LIBFUZZER)
  add_executable(fuzz_round_msg tests/signing/fuzz_round_msg.c)
  target_link_options(fuzz_round_msg PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_round_msg tests/signing/fuzz_round_msg.c tests/net/fuzz_main.c)
  add_test(NAME signing_fuzz_round_msg COMMAND fuzz_round_msg 200000)
  add_test(NAME signing_fuzz_round_msg_seed COMMAND fuzz_round_msg ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/round_msg/propose-4)
endif()
target_link_libraries(fuzz_round_msg PRIVATE gazpacho_signing)
target_compile_options(fuzz_round_msg PRIVATE ${GZ_NEW_CODE_WARNINGS})
# No call in the library hands out a secret nonce (review A, F5): the
# simulator's inspection reads the engine's structure in the test world.
add_test(NAME signing_no_secret_export
  COMMAND sh -c "nm -g \"$1\" > /dev/null && ! nm -g \"$1\" | grep -i -e inspect -e secnonce" sh $<TARGET_FILE:gazpacho_signing>)
add_test(NAME signing_isolation
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          --allow ${CMAKE_CURRENT_SOURCE_DIR}/tools/signing-allowed-calls.txt
          $<TARGET_FILE:gazpacho_signing> --sources ${CMAKE_C_COMPILER}
          "${GZ_CORE_SCAN_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/core/signing/include -I${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include -I${secp256k1-zkp_SOURCE_DIR}/include"
          ${GZ_SIGNING_SOURCES})

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
  add_test(NAME valgrind_signing COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_signing> tiny)
  add_test(NAME valgrind_round_msg COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_round_msg>)
endif()

# --- Transport (ports/net): BOLT 8 and BOLT 1, outside the core ----------------
# Strict C11 like the core, but not freestanding: conn.c uses POSIX sockets.
# noise.c and frame.c do no input or output (spec/transport.md).
add_library(gazpacho_net STATIC ports/net/noise.c ports/net/frame.c ports/net/conn.c ports/net/wipe.c
            ports/net/envelope.c ports/net/lnmsg.c ports/net/peers.c)
set_target_properties(gazpacho_net PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_net PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/ports/net)
target_link_libraries(gazpacho_net PUBLIC secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_net PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

add_executable(gz-net tools/gz-net/gz-net.c)
target_link_libraries(gz-net PRIVATE gazpacho_net)
target_compile_options(gz-net PRIVATE ${GZ_NEW_CODE_WARNINGS})

gz_add_test(net_noise tests/net/test_noise.c gazpacho_net)
gz_add_test(net_frame tests/net/test_frame.c gazpacho_net 20000)
gz_add_test(net_conn  tests/net/test_conn.c  gazpacho_net)
gz_add_test(net_envelope tests/net/test_envelope.c gazpacho_net)
gz_add_test(net_lnmsg tests/net/test_lnmsg.c gazpacho_net)
gz_add_test(net_peers tests/net/test_peers.c gazpacho_net)
# Kind 32767 (test traffic, contract v2 section 7) exists only in a build
# with GZ_TEST_KINDS: a second copy of the library for its test, so the
# library everything else links never knows it.
add_library(gazpacho_net_testkinds STATIC ports/net/noise.c ports/net/frame.c ports/net/conn.c ports/net/wipe.c
            ports/net/envelope.c ports/net/lnmsg.c ports/net/peers.c)
set_target_properties(gazpacho_net_testkinds PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_net_testkinds PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ports/net)
target_compile_definitions(gazpacho_net_testkinds PUBLIC GZ_TEST_KINDS)
target_link_libraries(gazpacho_net_testkinds PUBLIC secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_net_testkinds PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)
gz_add_test(net_test_kind tests/net/test_testkind.c gazpacho_net_testkinds)
# ports/net and gz-net include no core header (contract v2, section 12).
add_test(NAME net_no_core_headers COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-net-no-core.sh
         ${CMAKE_C_COMPILER} ${secp256k1-zkp_SOURCE_DIR}/include)
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
# Two processes hold a lobby connection with pings: 4 s at a 100 ms ping in
# CI; with -DGZ_LONG_TESTS=ON also six minutes at messages.md's 15 s ping and
# 30 s pong timeout (not run in CI).
add_test(NAME net_keepalive COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/net/test_keepalive.sh
         $<TARGET_FILE:gz-net> 4 100 1000)
option(GZ_LONG_TESTS "Register the long keep-alive test (six minutes)" OFF)
if(GZ_LONG_TESTS)
  add_test(NAME net_keepalive_long COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/net/test_keepalive.sh
           $<TARGET_FILE:gz-net> 360 15000 30000)
  set_tests_properties(net_keepalive_long PROPERTIES TIMEOUT 600 LABELS slow)
endif()
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
# fuzz_envelope runs fewer plain-driver inputs: some build 65,000-byte parts.
foreach(target noise tlv envelope)
  if(GZ_LIBFUZZER)
    add_executable(fuzz_${target} tests/net/fuzz_${target}.c)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  elseif(target STREQUAL "envelope")
    add_executable(fuzz_${target} tests/net/fuzz_${target}.c tests/net/fuzz_main.c)
    add_test(NAME net_fuzz_${target} COMMAND fuzz_${target} 5000)
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
# --- The terms and SHA-256 are core/tree's (gazpacho_tree, pure core).     ---
set(GZ_LOBBY_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/act.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/fit.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/host.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/member.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/wire.c)
set(GZ_LOBBY_TREE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/sha256.c ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/terms.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/shape.c ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/checks.c ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/exit.c)
add_library(gazpacho_lobby STATIC ${GZ_LOBBY_SOURCES})
set_target_properties(gazpacho_lobby PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_lobby PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include)
target_link_libraries(gazpacho_lobby PUBLIC gazpacho_core gazpacho_tree)
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
gz_lobby_test(lobby_model_driver tests/lobby/model_driver.c)
add_test(NAME lobby_vectors COMMAND test_lobby_vectors)
add_test(NAME lobby COMMAND test_lobby)
# Real stack frames, so a record byte left unwritten keeps the poison the test puts there.
set_tests_properties(lobby PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_stack_use_after_return=0")
# One host and 3 to 8 members: mixed faults, crashes only, network only, none.
# 25 seeds per profile here (about two minutes under the sanitizers); the
# reports quote runs of 100 seeds per profile, made by hand.
foreach(profile RANGE 0 3)
  add_test(NAME lobby_sim_profile_${profile} COMMAND test_lobby_sim 25 ${profile})
endforeach()
# The fuzz target, as the transport's (docs/notes/ci.md): a plain driver and a
# CTest test normally; with GZ_LIBFUZZER, linked with libFuzzer for CI's job.
if(GZ_LIBFUZZER)
  add_executable(fuzz_lobby tests/lobby/fuzz_lobby.c)
  target_link_options(fuzz_lobby PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_lobby tests/lobby/fuzz_lobby.c tests/lobby/fuzz_lobby_main.c)
  add_test(NAME lobby_fuzz COMMAND fuzz_lobby 200000 1)
endif()
target_link_libraries(fuzz_lobby PRIVATE gazpacho_lobby gazpacho_sim secp256k1)
target_include_directories(fuzz_lobby PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_compile_options(fuzz_lobby PRIVATE ${GZ_NEW_CODE_WARNINGS})
# The sequence target: each input is a script of signed messages from several
# keys to one host, or from the host to one member (review A, S9).
if(GZ_LIBFUZZER)
  add_executable(fuzz_lobby_seq tests/lobby/fuzz_lobby_seq.c)
  target_link_options(fuzz_lobby_seq PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_lobby_seq tests/lobby/fuzz_lobby_seq.c tests/lobby/fuzz_lobby_seq_main.c)
  add_test(NAME lobby_fuzz_seq COMMAND fuzz_lobby_seq 5000 1)
endif()
target_link_libraries(fuzz_lobby_seq PRIVATE gazpacho_lobby gazpacho_sim secp256k1)
target_include_directories(fuzz_lobby_seq PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_compile_options(fuzz_lobby_seq PRIVATE ${GZ_NEW_CODE_WARNINGS})
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
add_library(gazpacho_lobby_with_core STATIC ${GZ_CORE_SOURCES} ${GZ_LOBBY_SOURCES} ${GZ_LOBBY_TREE_SOURCES})
set_target_properties(gazpacho_lobby_with_core PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_lobby_with_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/gazpacho/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include)
target_compile_options(gazpacho_lobby_with_core PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
string(JOIN " " GZ_LOBBY_SCAN_FLAGS ${GZ_CORE_SCAN_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/core/lobby/include
       -I${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include)
add_test(NAME lobby_isolation
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-core-isolation.sh ${GZ_ISOLATION_MODE}
          $<TARGET_FILE:gazpacho_lobby_with_core> --sources ${CMAKE_C_COMPILER} ${GZ_LOBBY_SCAN_FLAGS} ${GZ_LOBBY_SOURCES})
if(GZ_VALGRIND AND NOT GZ_SANITIZE)
  add_test(NAME valgrind_lobby_vectors COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_lobby_vectors>)
  add_test(NAME valgrind_lobby COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:test_lobby>)
  if(NOT GZ_LIBFUZZER)
    add_test(NAME valgrind_lobby_fuzz COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:fuzz_lobby> 3000 2)
    add_test(NAME valgrind_lobby_fuzz_seq COMMAND ${GZ_MEMCHECK} $<TARGET_FILE:fuzz_lobby_seq> 300 2)
  endif()
endif()

# --- Storage journal (spec/journal.md): the outer layer's file storage. -------
# POSIX file I/O, so it is not part of the core and not under its isolation
# check. Everything it asks of the operating system goes through a table the
# tests replace (tests/journal/memfs.c) to fail or crash at any write or sync.
add_library(gazpacho_journal STATIC ports/storage/journal.c)
set_target_properties(gazpacho_journal PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_journal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ports/storage)
target_link_libraries(gazpacho_journal PUBLIC gazpacho_core gazpacho_superscalar)
target_compile_options(gazpacho_journal PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

add_executable(gz-journal tools/gz-journal.c)
target_link_libraries(gz-journal PRIVATE gazpacho_journal)
target_compile_options(gz-journal PRIVATE ${GZ_NEW_CODE_WARNINGS})

add_library(gazpacho_journal_testfs STATIC tests/journal/memfs.c)
target_link_libraries(gazpacho_journal_testfs PUBLIC gazpacho_journal)
target_compile_options(gazpacho_journal_testfs PRIVATE ${GZ_NEW_CODE_WARNINGS})

gz_add_test(journal       tests/journal/test_journal.c       gazpacho_journal_testfs)
gz_add_test(journal_edges tests/journal/test_journal_edges.c gazpacho_journal_testfs)
# Crash before every write and sync point, power-loss settles, process kills,
# the real node; and the "rule removed" run that must find a loss.
gz_add_test(journal_crash tests/journal/test_journal_crash.c gazpacho_journal_testfs)
gz_add_test(journal_fuzz  tests/journal/test_journal_fuzz.c  gazpacho_journal_testfs 100000 1)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  # 10,000 random journals against the independent reader written from the spec.
  add_test(NAME journal_crosscheck
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/journal/crosscheck.py
            $<TARGET_FILE:gz-journal> 10000 1)
  # The tool's verdicts and exit codes; its dump never prints record bytes.
  add_test(NAME journal_tool
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/journal/test_tool.py
            $<TARGET_FILE:gz-journal>)
endif()
# The restore marker, pull mode (program/store.h's complete()) and the fence.
gz_add_test(journal_restore tests/journal/test_journal_restore.c gazpacho_journal_testfs)
# Review A's findings: a failed sync the way Linux fails one, the import's
# order, the folder lock, the start counter, the hard limit with two marks,
# a kept guard batch, 2^63, flushes with no runner or from on_confirmed.
gz_add_test(journal_review  tests/journal/test_journal_review.c  gazpacho_journal_testfs)
# Review B: journal.lock removed or replaced during an import (200 rounds of
# two processes), the import's floor, the name's durability, an unreadable
# marker, the O_DIRECT fallback, the reader after a failure, the guard.
gz_add_test(journal_review_b tests/journal/test_journal_review_b.c gazpacho_journal_testfs)
# The journal with its own allocations failing: journal.c is compiled into
# this test with malloc, calloc and realloc routed through the test's hook.
add_executable(test_journal_alloc tests/journal/test_journal_alloc.c tests/journal/journal_alloc_hook.c)
target_link_libraries(test_journal_alloc PRIVATE gazpacho_journal_testfs)
target_compile_options(test_journal_alloc PRIVATE ${GZ_NEW_CODE_WARNINGS})
add_test(NAME journal_alloc COMMAND test_journal_alloc)
# Review B's stateful model of the whole API and its scan-and-open target
# against an independent reader: libFuzzer targets with GZ_LIBFUZZER, plain
# drivers (and tests) otherwise.
foreach(target journal_model journal_open)
  add_executable(fuzz_${target} tests/journal/fuzz_${target}.c)
  target_link_libraries(fuzz_${target} PRIVATE gazpacho_journal_testfs)
  target_compile_options(fuzz_${target} PRIVATE ${GZ_NEW_CODE_WARNINGS})
  if(GZ_LIBFUZZER)
    target_compile_definitions(fuzz_${target} PRIVATE LIBFUZZER)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  endif()
endforeach()
if(NOT GZ_LIBFUZZER)
  add_test(NAME journal_fuzz_model COMMAND fuzz_journal_model 2000 1)
  add_test(NAME journal_fuzz_open  COMMAND fuzz_journal_open 20000 1)
endif()
# Under valgrind: every journal test runs in the valgrind job
# (tools/valgrind-tests.py, which takes journal_fuzz on a smaller case).

# --- trees from terms and the creation checks (core/tree) ---
add_subdirectory(core/tree)

# --- storage encryption (ports/storage/crypto): libsodium, outside the core ---
add_subdirectory(ports/storage/crypto)

# --- Signing engine: white-box tests of the guards no public input reaches ---
# (tests/signing/test_signing_wb.c compiles core/signing/signing.c into itself),
# and the engine's outcome into the lobby host, built only with the lobby engine.
add_executable(test_signing_wb tests/signing/test_signing_wb.c core/signing/sign_tx.c core/signing/round_msg.c)
set_target_properties(test_signing_wb PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(test_signing_wb PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include ${secp256k1-zkp_SOURCE_DIR}/include)
target_link_libraries(test_signing_wb PRIVATE gazpacho_core secp256k1 gazpacho_sim gazpacho_superscalar gazpacho_tree)
target_compile_options(test_signing_wb PRIVATE ${GZ_NEW_CODE_WARNINGS} -Wno-unused-function)
add_test(NAME signing_wb COMMAND test_signing_wb)

# The engine behind the node's two calls, for the program's composite node (adapter only, PR 27).
add_executable(test_signing_node tests/signing/test_signing_node.c)
target_link_libraries(test_signing_node PRIVATE gazpacho_signing gazpacho_sim gazpacho_superscalar gazpacho_tree)
target_compile_options(test_signing_node PRIVATE ${GZ_NEW_CODE_WARNINGS} -Wno-unused-function)
add_test(NAME signing_node COMMAND test_signing_node)

# BIP 327's vectors (the pinned library's copy, src/modules/musig/vectors.h)
# through the calls the engine makes.
add_executable(test_bip327 tests/signing/test_bip327.c)
target_include_directories(test_bip327 PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include ${secp256k1-zkp_SOURCE_DIR}/src)
target_link_libraries(test_bip327 PRIVATE secp256k1)
target_compile_options(test_bip327 PRIVATE ${GZ_NEW_CODE_WARNINGS})
add_test(NAME signing_bip327 COMMAND test_bip327)

# BIP 341's wallet vectors through the engine's own Taproot code (the tweak
# check_def makes every output key with, and the signature hash's last step).
add_executable(test_bip341 tests/signing/test_bip341.c)
target_link_libraries(test_bip341 PRIVATE gazpacho_signing)
target_compile_options(test_bip341 PRIVATE ${GZ_NEW_CODE_WARNINGS})
add_test(NAME signing_bip341 COMMAND test_bip341)

# Constant time of the engine's own code around secrets, under memcheck
# (tests/signing/test_signing_ctime.c): built where valgrind's headers are,
# run where valgrind is and nothing is sanitized (as storage_ctime).
include(CheckIncludeFile)
check_include_file(valgrind/memcheck.h GZ_SIGN_HAVE_MEMCHECK_H)
if(GZ_SIGN_HAVE_MEMCHECK_H)
  add_executable(test_signing_ctime tests/signing/test_signing_ctime.c core/signing/sign_tx.c core/signing/round_msg.c)
  set_target_properties(test_signing_ctime PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(test_signing_ctime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/include
                             ${CMAKE_CURRENT_SOURCE_DIR}/core/tree/include ${secp256k1-zkp_SOURCE_DIR}/include)
  target_link_libraries(test_signing_ctime PRIVATE gazpacho_core secp256k1 gazpacho_sim gazpacho_superscalar gazpacho_tree)
  target_compile_options(test_signing_ctime PRIVATE ${GZ_NEW_CODE_WARNINGS} -Wno-unused-function)
  if(GZ_VALGRIND AND NOT GZ_SANITIZE AND NOT CMAKE_C_FLAGS MATCHES "-fsanitize")
    add_test(NAME signing_ctime COMMAND ${GZ_VALGRIND} --quiet --error-exitcode=9 --track-origins=yes $<TARGET_FILE:test_signing_ctime>)
  endif()
endif()

# The engine's start over any journal, then messages (tests/signing/fuzz_signing_replay.c):
# libFuzzer in CI's fuzz job, the plain driver and the seeds here.
if(GZ_LIBFUZZER)
  add_executable(fuzz_signing_replay tests/signing/fuzz_signing_replay.c)
  target_link_options(fuzz_signing_replay PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_signing_replay tests/signing/fuzz_signing_replay.c tests/net/fuzz_main.c)
  add_test(NAME signing_fuzz_replay COMMAND fuzz_signing_replay 20000)
  file(GLOB GZ_REPLAY_SEEDS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/signing_replay/*)
  if(GZ_REPLAY_SEEDS)
    add_test(NAME signing_fuzz_replay_seeds COMMAND fuzz_signing_replay ${GZ_REPLAY_SEEDS})
  endif()
endif()
target_link_libraries(fuzz_signing_replay PRIVATE gazpacho_signing gazpacho_sim gazpacho_superscalar gazpacho_tree)
target_compile_options(fuzz_signing_replay PRIVATE ${GZ_NEW_CODE_WARNINGS} -Wno-unused-function)
if(TARGET gazpacho_lobby)
  add_library(gazpacho_signing_lobby STATIC ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/lobby_outcome.c)
  set_target_properties(gazpacho_signing_lobby PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(gazpacho_signing_lobby PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core/signing/include)
  target_link_libraries(gazpacho_signing_lobby PUBLIC gazpacho_lobby gazpacho_core)
  target_compile_options(gazpacho_signing_lobby PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
  add_executable(test_signing_lobby tests/signing/test_signing_lobby.c)
  target_link_libraries(test_signing_lobby PRIVATE gazpacho_signing_lobby)
  target_compile_options(test_signing_lobby PRIVATE ${GZ_NEW_CODE_WARNINGS})
  add_test(NAME signing_lobby COMMAND test_signing_lobby)
endif()

# --- the local API server (spec/local-api.md), its fake backend and tests ------
add_subdirectory(ports/api)

# --- the gazpacho program (stream S11): executor, port adapters, executables ----
add_subdirectory(program)
