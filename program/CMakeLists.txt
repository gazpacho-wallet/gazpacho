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

set(GZP_SOURCES options.c datadir.c store_journal.c store_unlock.c net.c pchain.c notify.c executor.c testping.c)

foreach(variant release test)
  if(variant STREQUAL "release")
    set(lib gazpacho_program)
    set(net gazpacho_net)
    set(node gazpacho_node)
  else()
    set(lib gazpacho_program_test)
    set(net gazpacho_net_testkinds)
    set(node gazpacho_node_test)
  endif()
  if(variant STREQUAL "release")
    set(sc gazpacho_storage_crypto)
    add_library(${lib} STATIC ${GZP_SOURCES})
  else()
    # The journal stand-in stays for the tests that read its files
    # (--test-standin-store); the release program has only the real store.
    # The test build links the storage library's test entry point (the
    # parameter floor of --test-kdf-floor); the release build never does.
    set(sc gazpacho_storage_crypto_test)
    add_library(${lib} STATIC ${GZP_SOURCES} journal_standin.c store_powercut.c)
  endif()
  target_include_directories(${lib} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${lib} PUBLIC ${node} ${net} gazpacho_wallet_keys gazpacho_chain gazpacho_journal ${sc} OpenSSL::Crypto)
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
gz_add_test(program_net ${CMAKE_SOURCE_DIR}/tests/program/test_net.c gazpacho_program_test)
# Kind 0xffff (the signing engine's SEND bridge until P4.3) never reaches a
# program, and the lobby's bridge, deleted in P4.2, stays deleted
# (composite-node.md, tasks T-P42-1, T-P43-1).
add_test(NAME program_send_whole_unlinked
  COMMAND sh ${CMAKE_SOURCE_DIR}/tools/check-send-whole.sh ${CMAKE_SOURCE_DIR} $<TARGET_FILE:gazpacho>
          $<TARGET_FILE:gazpacho-test>)
add_test(NAME lobby_send_whole_gone
  COMMAND sh ${CMAKE_SOURCE_DIR}/tools/check-send-whole.sh ${CMAKE_SOURCE_DIR})

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
  # Review B of PR 27: its own tests, copied as written. The start queue under
  # load (4,100 x 200 bytes, the 64-byte overhead), a timer due during a held
  # start, and a restart's timers; an in-process restart with members connected
  # (stale connection slots); the tip told at every start, against a loopback
  # Esplora stub (plain HTTP on 127.0.0.1, which ports/chain allows: needs curl).
  add_test(NAME program_start_queue
    COMMAND ${GZP_PY} ${GZP_T}/start_queue.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/start_queue)
  add_test(NAME program_restart_slots
    COMMAND ${GZP_PY} ${GZP_T}/restart_slots.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/restart_slots)
  set_tests_properties(program_start_queue program_restart_slots PROPERTIES TIMEOUT 300)
  if(TARGET gazpacho_chain_curl)
    add_test(NAME program_chain_stub
      COMMAND ${GZP_PY} ${GZP_T}/chain_stub.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/chain_stub)
    set_tests_properties(program_chain_stub PROPERTIES TIMEOUT 300)
    # P7: the chain worker in two processes (watches, restarts, BUSY, mainnet).
    add_test(NAME program_chain_watch
      COMMAND ${GZP_PY} ${GZP_T}/chain_watch.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/chain_watch)
    set_tests_properties(program_chain_watch PROPERTIES TIMEOUT 300)
  endif()
  # The restart window and a stop during a restart (M6); the start queue's
  # messages under the right connection, after its connected, and the queue's
  # total cap (B41, B42, B5); smaller refusals and the reconnect delay (B7).
  add_test(NAME program_restart_policy
    COMMAND ${GZP_PY} ${GZP_T}/restart_policy.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/restart_policy)
  add_test(NAME program_queue_peers
    COMMAND ${GZP_PY} ${GZP_T}/queue_peers.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/queue_peers)
  add_test(NAME program_refusals
    COMMAND ${GZP_PY} ${GZP_T}/refusals.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/refusals)
  set_tests_properties(program_restart_policy program_queue_peers program_refusals PROPERTIES TIMEOUT 300)
  # The composite node, P4.1 (docs/notes/composite-node.md 15): two test
  # engines, hand-off batches, node errors, routing gates, slot generations,
  # the watch registry; contract v2's T1, T2 (steps 1 and 2) and T7.
  foreach(t composite resend_on_connect links envelope)
    add_test(NAME program_${t}
      COMMAND ${GZP_PY} ${GZP_T}/${t}.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/${t})
    set_tests_properties(program_${t} PROPERTIES TIMEOUT 300)
  endforeach()
  # S5 and S6 in the program: the start order (locked until unlocked), the
  # passphrase layer's attempts, a damaged key file, the release program
  # staying locked without the local interface; kill -9 before every storage
  # write, sync or rename from set-up to an anchored batch, then a restart;
  # damaged files refused and never half-applied; a restore from an older
  # backup never reusing an epoch or a key index.
  add_test(NAME program_unlock
    COMMAND ${GZP_PY} ${GZP_T}/unlock.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/unlock
            $<TARGET_FILE:gazpacho>)
  add_test(NAME program_journal_kill
    COMMAND ${GZP_PY} ${GZP_T}/journal_kill.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/journal_kill 3)
  add_test(NAME program_journal_kill_full
    COMMAND ${GZP_PY} ${GZP_T}/journal_kill.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/journal_kill_full)
  set_tests_properties(program_journal_kill_full PROPERTIES TIMEOUT 3600 LABELS "slow")
  # The same with power cuts (review A of PR 54, M3): every sixth call in CI,
  # every call on the build server (slow).
  add_test(NAME program_journal_powercut
    COMMAND ${GZP_PY} ${GZP_T}/journal_kill.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/journal_powercut 6 power)
  add_test(NAME program_journal_powercut_full
    COMMAND ${GZP_PY} ${GZP_T}/journal_kill.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/journal_powercut_full 1 power)
  set_tests_properties(program_journal_powercut PROPERTIES TIMEOUT 2400)
  set_tests_properties(program_journal_powercut_full PROPERTIES TIMEOUT 3600 LABELS "slow")
  add_test(NAME program_storage_damage
    COMMAND ${GZP_PY} ${GZP_T}/storage_damage.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/storage_damage)
  add_test(NAME program_journal_restore
    COMMAND ${GZP_PY} ${GZP_T}/journal_restore.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/journal_restore)
  set_tests_properties(program_unlock program_storage_damage program_journal_restore PROPERTIES TIMEOUT 600)
  set_tests_properties(program_journal_kill PROPERTIES TIMEOUT 2400)
  # The lobby in the composite, P4.2 (docs/notes/composite-node.md 15): a host
  # with two lobbies and its members as separate processes, the signing
  # stand-in behind the hand-off; crashes, a storage failure, the gates.
  add_test(NAME program_lobby
    COMMAND ${GZP_PY} ${GZP_T}/lobby.py $<TARGET_FILE:gazpacho-test> ${CMAKE_CURRENT_BINARY_DIR}/lobby)
  set_tests_properties(program_lobby PROPERTIES TIMEOUT 900)
  # Every program test may start gazpacho-test with a launcher of its own:
  # the passphrase file's path and the Argon2id floor come through the
  # environment (gazpacho-test only; the harness passes the options itself).
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test-passphrase "gazpacho test wallet passphrase, signet only")
  if(NOT CMAKE_VERSION VERSION_LESS 3.19)
    file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/test-passphrase PERMISSIONS OWNER_READ OWNER_WRITE)
  endif()
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

# The unlock for every program test (see test-passphrase above).
get_property(_gzp_tests DIRECTORY PROPERTY TESTS)
foreach(_t ${_gzp_tests})
  if(_t MATCHES "^program_")
    set_property(TEST ${_t} APPEND PROPERTY ENVIRONMENT
      "GZP_TEST_PASSPHRASE_FILE=${CMAKE_CURRENT_BINARY_DIR}/test-passphrase" "GZP_TEST_KDF_FLOOR=1")
  endif()
endforeach()
