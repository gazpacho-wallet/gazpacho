# The chain view port: Esplora HTTP backend, comparing backend, header checks,
# the gz-chain tool and their tests. Self-contained: the top-level file only
# says add_subdirectory(ports/chain).

option(GZ_LIVE_TESTS "Add the opt-in test that queries the public signet chain servers" OFF)
# Warnings are always on. Treating them as errors is for the project's own
# checks (CI turns it on); someone building with a newer compiler should not
# be stopped by a warning that compiler has just learned.
option(GZ_WERROR "Treat compiler warnings in ports/chain as errors" OFF)

find_package(OpenSSL REQUIRED) # libcrypto only (SHA-256)

set(GZ_CHAIN_WARNINGS -Wall -Wextra)
if(GZ_WERROR)
  list(APPEND GZ_CHAIN_WARNINGS -Werror)
endif()

# watch.c is the watch engine; chainw.c runs it on the chain worker thread
# (POSIX threads and a pipe).
find_package(Threads REQUIRED)
add_library(gazpacho_chain STATIC chain.c headers.c verify.c json.c esplora.c multi.c watch.c chainw.c)
target_include_directories(gazpacho_chain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gazpacho_chain PUBLIC OpenSSL::Crypto Threads::Threads)
target_compile_options(gazpacho_chain PRIVATE ${GZ_CHAIN_WARNINGS})

# The HTTPS transport and the tool need libcurl. The library and its unit
# tests do not, so a machine without the curl development package still
# builds and tests everything else. The transport is POSIX only.
find_package(CURL QUIET)
if(CURL_FOUND)
  add_library(gazpacho_chain_curl STATIC http_curl.c)
  target_link_libraries(gazpacho_chain_curl PUBLIC gazpacho_chain CURL::libcurl)
  target_compile_options(gazpacho_chain_curl PRIVATE ${GZ_CHAIN_WARNINGS})

  add_executable(gz-chain tools/gz-chain.c)
  target_link_libraries(gz-chain PRIVATE gazpacho_chain_curl)
  target_compile_options(gz-chain PRIVATE ${GZ_CHAIN_WARNINGS})
else()
  message(WARNING "libcurl development files not found: the HTTPS transport and gz-chain are not built "
                  "(Debian/Ubuntu: apt install libcurl4-openssl-dev)")
endif()

# --- tests (fake transport, recorded answers; no network) ---------------------
# GZ_CHAIN_TESTS=OFF leaves them out. wallet/tests/break-checks.sh builds a
# copy of the whole tree for every fault it injects into the wallet code and
# runs its tests; nothing in the wallet uses this port, so it turns these off.
option(GZ_CHAIN_TESTS "Build and register the chain port's tests" ON)
if(GZ_CHAIN_TESTS)
add_library(gazpacho_chain_test_support STATIC tests/test_support.c)
target_link_libraries(gazpacho_chain_test_support PUBLIC gazpacho_chain)
target_compile_options(gazpacho_chain_test_support PRIVATE ${GZ_CHAIN_WARNINGS})
target_compile_definitions(gazpacho_chain_test_support PRIVATE
  GZ_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")

foreach(t json headers esplora multi confirm model fuzz)
  add_executable(chain_test_${t} tests/test_${t}.c)
  target_link_libraries(chain_test_${t} PRIVATE gazpacho_chain_test_support)
  target_compile_options(chain_test_${t} PRIVATE ${GZ_CHAIN_WARNINGS})
  add_test(NAME chain_${t} COMMAND chain_test_${t})
endforeach()

# Fuzz targets are further down (docs/notes/ci.md): with the plain driver as
# CTest tests; with -DGZ_LIBFUZZER=ON (clang) linked with libFuzzer and run by
# tools/run-fuzz.sh.

# The watch engine against a made-up chain told by two simulated servers
# (tests/sim.c), through the real Esplora and comparing backends.
add_library(gazpacho_chain_sim STATIC tests/sim.c)
target_link_libraries(gazpacho_chain_sim PUBLIC gazpacho_chain_test_support)
target_compile_options(gazpacho_chain_sim PRIVATE ${GZ_CHAIN_WARNINGS})
add_executable(chain_test_watch tests/test_watch.c)
target_link_libraries(chain_test_watch PRIVATE gazpacho_chain_sim)
target_compile_options(chain_test_watch PRIVATE ${GZ_CHAIN_WARNINGS})
add_test(NAME chain_watch COMMAND chain_test_watch)
# The worker thread, its queues and its descriptor, on the real clock.
add_executable(chain_test_chainw tests/test_chainw.c)
target_link_libraries(chain_test_chainw PRIVATE gazpacho_chain_sim)
target_compile_options(chain_test_chainw PRIVATE ${GZ_CHAIN_WARNINGS})
add_test(NAME chain_chainw COMMAND chain_test_chainw)
set_tests_properties(chain_chainw PROPERTIES TIMEOUT 600)

if(GZ_LIBFUZZER)
  add_executable(fuzz_chain_parse tests/fuzz_chain_parse.c)
  target_link_options(fuzz_chain_parse PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_chain_parse tests/fuzz_chain_parse.c tests/fuzz_main.c)
  add_test(NAME chain_fuzz_parse COMMAND fuzz_chain_parse 200000)
endif()
target_link_libraries(fuzz_chain_parse PRIVATE gazpacho_chain)
target_compile_options(fuzz_chain_parse PRIVATE ${GZ_CHAIN_WARNINGS})
#   chain_watch  the watch engine against servers that say anything
if(GZ_LIBFUZZER)
  add_executable(fuzz_chain_watch tests/fuzz_chain_watch.c)
  target_link_options(fuzz_chain_watch PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_chain_watch tests/fuzz_chain_watch.c tests/fuzz_main.c)
  add_test(NAME chain_fuzz_watch COMMAND fuzz_chain_watch 20000)
endif()
target_link_libraries(fuzz_chain_watch PRIVATE gazpacho_chain_sim)
target_compile_options(fuzz_chain_watch PRIVATE ${GZ_CHAIN_WARNINGS})

if(CURL_FOUND)
  # The tool must refuse to broadcast on mainnet, before touching the network.
  # The refusal exits 2; the wrapper checks that exit status and the text.
  add_test(NAME chain_tool_refuses_mainnet_broadcast
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/expect-exit.sh 2 "refusing to broadcast on mainnet"
            $<TARGET_FILE:gz-chain> --network mainnet broadcast 00)
  add_test(NAME chain_tool_usage COMMAND gz-chain --help)
  set_tests_properties(chain_tool_usage PROPERTIES PASS_REGULAR_EXPRESSION "usage: gz-chain")

  # The real transport and the tool against servers started on this machine
  # only (127.0.0.1): a hostile HTTP server, HTTPS servers with bad
  # certificates, and two small Esplora look-alikes. Needs python3 and the
  # openssl command; skipped (not failed) without them. Takes some seconds
  # because it waits out real time limits, hence the label.
  add_executable(chain_test_transport tests/test_transport.c)
  target_link_libraries(chain_test_transport PRIVATE gazpacho_chain_curl)
  target_compile_options(chain_test_transport PRIVATE ${GZ_CHAIN_WARNINGS})
  add_test(NAME chain_local_servers
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/local-servers.sh
            $<TARGET_FILE:chain_test_transport> $<TARGET_FILE:gz-chain>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR}/local-servers)
  set_tests_properties(chain_local_servers PROPERTIES LABELS "slow" TIMEOUT 240 SKIP_RETURN_CODE 77)

  # The worker over real HTTP against a scripted Esplora stub on 127.0.0.1
  # (tests/watch_stub.py), playing reorganisations, double spends, lagging,
  # disagreeing and lying servers, evictions, broadcasts, a 30 s stall and
  # broken connections. Needs python3; skipped (not failed) without it.
  add_executable(chain_test_stub tests/test_stub.c)
  target_link_libraries(chain_test_stub PRIVATE gazpacho_chain_sim gazpacho_chain_curl)
  target_compile_options(chain_test_stub PRIVATE ${GZ_CHAIN_WARNINGS})
  add_test(NAME chain_watch_stub
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/watch-stub.sh $<TARGET_FILE:chain_test_stub>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR}/watch-stub)
  set_tests_properties(chain_watch_stub PROPERTIES TIMEOUT 600 SKIP_RETURN_CODE 77)

  # Opt-in only: talks to mempool.space and blockstream.info on signet.
  # Never part of the default ctest run or of CI.
  if(GZ_LIVE_TESTS)
    add_executable(chain_test_live tests/test_live.c)
    target_link_libraries(chain_test_live PRIVATE gazpacho_chain_test_support gazpacho_chain_curl)
    target_compile_options(chain_test_live PRIVATE ${GZ_CHAIN_WARNINGS})
    add_test(NAME chain_live COMMAND chain_test_live)
    set_tests_properties(chain_live PROPERTIES TIMEOUT 600)
    add_executable(chain_test_live_watch tests/test_live_watch.c)
    target_link_libraries(chain_test_live_watch PRIVATE gazpacho_chain_test_support gazpacho_chain_curl)
    target_compile_options(chain_test_live_watch PRIVATE ${GZ_CHAIN_WARNINGS})
    add_test(NAME chain_live_watch COMMAND chain_test_live_watch)
    set_tests_properties(chain_live_watch PROPERTIES TIMEOUT 600)
  endif()
endif()
endif() # GZ_CHAIN_TESTS
