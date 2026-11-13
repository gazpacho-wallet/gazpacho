# The `gazpacho` program (stream S11): the executor around the core's node and
# runner, and the adapters that connect its actions to the ports. See
# docs/notes/program.md. POSIX only. Built against main's core only
# (contract-v2.md section 14: no probes).
#
# Two builds of the same sources:
#   gazpacho       release: the transport without test kinds, no --test-* hooks
#   gazpacho-test  test build: GZ_TEST_KINDS in the transport (kind 32767 carries
#                  the placeholder's bytes until P4), and the --test-* hooks
# The release binary's symbols are checked (program_release_build, T12).

set(GZP_SOURCES options.c datadir.c journal_standin.c net.c pchain.c notify.c executor.c testping.c)

foreach(variant release test)
  if(variant STREQUAL "release")
    set(lib gazpacho_program)
    set(net gazpacho_net)
  else()
    set(lib gazpacho_program_test)
    set(net gazpacho_net_testkinds)
  endif()
  add_library(${lib} STATIC ${GZP_SOURCES})
  target_include_directories(${lib} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${lib} PUBLIC gazpacho_core ${net} gazpacho_wallet_keys gazpacho_chain OpenSSL::Crypto)
  target_compile_options(${lib} PRIVATE ${GZ_NEW_CODE_WARNINGS})
  if(variant STREQUAL "test")
    target_compile_definitions(${lib} PUBLIC GZP_TEST_BUILD=1)
  endif()
  # The chain servers are reached over HTTPS through libcurl. Without it (the
  # MemorySanitizer job builds without curl) the program still builds and
  # runs with --no-chain only.
  if(TARGET gazpacho_chain_curl)
    target_link_libraries(${lib} PUBLIC gazpacho_chain_curl)
    target_compile_definitions(${lib} PUBLIC GZP_HAVE_CURL=1)
  endif()
endforeach()

add_executable(gazpacho main.c)
target_link_libraries(gazpacho PRIVATE gazpacho_program)
target_compile_options(gazpacho PRIVATE ${GZ_NEW_CODE_WARNINGS})

add_executable(gazpacho-test main.c)
target_link_libraries(gazpacho-test PRIVATE gazpacho_program_test)
target_compile_options(gazpacho-test PRIVATE ${GZ_NEW_CODE_WARNINGS})

# A BOLT 8 client that completes the handshake and then never sends init
# (T6). Uses conn.h, which the program itself never does.
add_executable(gzp_silent_peer ${CMAKE_SOURCE_DIR}/tests/program/silent_peer.c)
target_link_libraries(gzp_silent_peer PRIVATE gazpacho_net)
target_compile_options(gzp_silent_peer PRIVATE ${GZ_NEW_CODE_WARNINGS})

# --- tests ---------------------------------------------------------------------
gz_add_test(program_store ${CMAKE_SOURCE_DIR}/tests/program/test_store.c gazpacho_program_test)
gz_add_test(program_options ${CMAKE_SOURCE_DIR}/tests/program/test_options.c gazpacho_program_test)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  set(GZP_PY ${Python3_EXECUTABLE} -I)
  set(GZP_T ${CMAKE_SOURCE_DIR}/tests/program)
  # A host and two members as separate processes over the lobby transport on
  # loopback, through their real runners and the journal stand-in.
  add_test(NAME program_two_process
    COMMAND ${GZP_PY} ${GZP_T}/two_process.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/two_process)
  # T6: slow and silent clients hold only their own slots.
  add_test(NAME program_slow_peers
    COMMAND ${GZP_PY} ${GZP_T}/slow_peers.py $<TARGET_FILE:gazpacho-test> $<TARGET_FILE:gzp_silent_peer>
            ${CMAKE_CURRENT_BINARY_DIR}/slow_peers)
  # T8: the start counter keeps a restored journal from reusing an incarnation.
  add_test(NAME program_restore_counter
    COMMAND ${GZP_PY} ${GZP_T}/restore_counter.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/restore_counter)
  # T15: one network per folder; signet and testnet4 never meet; mainnet refused.
  add_test(NAME program_networks
    COMMAND ${GZP_PY} ${GZP_T}/networks.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/networks)
  # T12 (second half) and the release build: no seeded source, no test hooks,
  # kind 32767 never delivered.
  add_test(NAME program_release_build
    COMMAND ${GZP_PY} ${GZP_T}/release_build.py $<TARGET_FILE:gazpacho> $<TARGET_FILE:gazpacho-test>
            ${CMAKE_CURRENT_BINARY_DIR}/release_build)
  # Storage and node failures, the in-process restart (review of PR 27: H1, M5).
  add_test(NAME program_storage_failure
    COMMAND ${GZP_PY} ${GZP_T}/storage_failure.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/storage_failure)
  # A flooding peer, an idle loop's timers, listening after the start, SIGPIPE (M1, M4, M5).
  add_test(NAME program_loop_liveness
    COMMAND ${GZP_PY} ${GZP_T}/liveness.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/liveness)
  # T14: no core probes and no old names left.
  add_test(NAME program_no_probes
    COMMAND ${GZP_PY} ${GZP_T}/no_probes.py ${CMAKE_SOURCE_DIR})
  set_tests_properties(program_two_process program_slow_peers program_restore_counter program_networks
                       program_release_build program_storage_failure program_loop_liveness PROPERTIES TIMEOUT 300)
  if(GZ_LIVE_TESTS AND TARGET gazpacho_chain_curl)
    # Read-only: the public signet servers' block 0 and tip, the wallet's
    # first address, and a refusal of a mainnet server. Needs the network.
    add_test(NAME program_signet_check
      COMMAND ${GZP_PY} ${GZP_T}/signet_check.py $<TARGET_FILE:gazpacho> ${CMAKE_CURRENT_BINARY_DIR}/signet_check)
    set_tests_properties(program_signet_check PROPERTIES TIMEOUT 300 LABELS "live")
  endif()
endif()
