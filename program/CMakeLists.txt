# The `gazpacho` program (stream S11): the executor around the core's node and
# runner, and the adapters that connect its actions to the ports. See
# docs/notes/program.md. POSIX only.

include(CheckCSourceCompiles)

# Which version of the core contract this tree carries. The program is built
# against main and is ready for the contract additions of the core follow-up
# (PR 9 / PR 21); each check below turns on the code for one addition, so the
# same sources build against either core (docs/notes/program.md, "Contract
# changes still to come").
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_SOURCE_DIR}/core/gazpacho/include)
check_c_source_compiles("
#include \"gazpacho/node.h\"
int main(void) { gz_storage_reader_t r; int w = GZ_WAITING; (void)r; return w; }"
  GZP_CORE_STEPPED_START)
check_c_source_compiles("
#include \"gazpacho/ports.h\"
int main(void) { gz_random_purpose_t p = GZ_RANDOM_SECRET; return (int)p; }"
  GZP_CORE_RANDOM_PURPOSE)
check_c_source_compiles("
#include \"gazpacho/action.h\"
int main(void) { return (int)GZ_ACTION_WATCH_TX + (int)GZ_ACTION_WATCH_OUTPOINT; }"
  GZP_CORE_WATCH_TX)
check_c_source_compiles("
#include \"gazpacho/event.h\"
int main(void) { return (int)GZ_EVENT_PEER_CONNECTED; }"
  GZP_CORE_PEER_EVENTS)
unset(CMAKE_REQUIRED_INCLUDES)

set(GZP_DEFS "")
foreach(flag GZP_CORE_STEPPED_START GZP_CORE_RANDOM_PURPOSE GZP_CORE_WATCH_TX GZP_CORE_PEER_EVENTS)
  if(${flag})
    list(APPEND GZP_DEFS ${flag}=1)
  endif()
endforeach()

# Everything but main.c, so tests can link the pieces.
add_library(gazpacho_program STATIC
  options.c datadir.c journal_standin.c net.c pchain.c notify.c executor.c testping.c)
target_include_directories(gazpacho_program PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gazpacho_program PUBLIC gazpacho_core gazpacho_net gazpacho_wallet_keys
                      gazpacho_chain OpenSSL::Crypto)
target_compile_definitions(gazpacho_program PUBLIC ${GZP_DEFS})
target_compile_options(gazpacho_program PRIVATE ${GZ_NEW_CODE_WARNINGS})
# The chain servers are reached over HTTPS through libcurl. Without it (the
# MemorySanitizer job builds without curl) the program still builds and runs
# with --no-chain only.
if(TARGET gazpacho_chain_curl)
  target_link_libraries(gazpacho_program PUBLIC gazpacho_chain_curl)
  target_compile_definitions(gazpacho_program PUBLIC GZP_HAVE_CURL=1)
endif()

add_executable(gazpacho main.c)
target_link_libraries(gazpacho PRIVATE gazpacho_program)
target_compile_options(gazpacho PRIVATE ${GZ_NEW_CODE_WARNINGS})

# --- tests ---------------------------------------------------------------------
gz_add_test(program_store ${CMAKE_SOURCE_DIR}/tests/program/test_store.c gazpacho_program)
gz_add_test(program_options ${CMAKE_SOURCE_DIR}/tests/program/test_options.c gazpacho_program)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  # A host and two members as separate processes over loopback: the
  # placeholder ping through the real runner, the transport and the journal
  # stand-in, a crash and a storage failure recovered from storage, the data
  # folder lock and the mainnet refusal. Short timers; about 20 seconds.
  add_test(NAME program_two_process
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_SOURCE_DIR}/tests/program/two_process.py
            $<TARGET_FILE:gazpacho> ${CMAKE_CURRENT_BINARY_DIR}/two_process)
  set_tests_properties(program_two_process PROPERTIES TIMEOUT 300)
  if(GZ_LIVE_TESTS AND TARGET gazpacho_chain_curl)
    # Read-only: the public signet servers' block 0 and tip, the wallet's
    # first address, and a refusal of a mainnet server. Needs the network.
    add_test(NAME program_signet_check
      COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_SOURCE_DIR}/tests/program/signet_check.py
              $<TARGET_FILE:gazpacho> ${CMAKE_CURRENT_BINARY_DIR}/signet_check)
    set_tests_properties(program_signet_check PROPERTIES TIMEOUT 300 LABELS "live")
  endif()
endif()
