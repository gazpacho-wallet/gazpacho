# The chain view port: Esplora HTTP backend, comparing backend, header checks,
# the gz-chain tool and their tests. Self-contained: the top-level file only
# says add_subdirectory(ports/chain).

option(GZ_LIVE_TESTS "Add the opt-in test that queries the public signet chain servers" OFF)

find_package(OpenSSL REQUIRED) # libcrypto only (SHA-256)

set(GZ_CHAIN_WARNINGS -Wall -Wextra -Werror)

add_library(gazpacho_chain STATIC chain.c headers.c verify.c json.c esplora.c multi.c)
target_include_directories(gazpacho_chain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gazpacho_chain PUBLIC OpenSSL::Crypto)
target_compile_options(gazpacho_chain PRIVATE ${GZ_CHAIN_WARNINGS})

# The HTTPS transport and the tool need libcurl. The library and its unit
# tests do not, so a machine without the curl development package still
# builds and tests everything else.
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
add_library(gazpacho_chain_test_support STATIC tests/test_support.c)
target_link_libraries(gazpacho_chain_test_support PUBLIC gazpacho_chain)
target_compile_options(gazpacho_chain_test_support PRIVATE ${GZ_CHAIN_WARNINGS})
target_compile_definitions(gazpacho_chain_test_support PRIVATE
  GZ_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")

foreach(t json headers esplora multi fuzz)
  add_executable(chain_test_${t} tests/test_${t}.c)
  target_link_libraries(chain_test_${t} PRIVATE gazpacho_chain_test_support)
  target_compile_options(chain_test_${t} PRIVATE ${GZ_CHAIN_WARNINGS})
  add_test(NAME chain_${t} COMMAND chain_test_${t})
endforeach()

if(CURL_FOUND)
  # The tool must refuse to broadcast on mainnet, before touching the network.
  add_test(NAME chain_tool_refuses_mainnet_broadcast
    COMMAND gz-chain --network mainnet broadcast 00)
  set_tests_properties(chain_tool_refuses_mainnet_broadcast PROPERTIES
    PASS_REGULAR_EXPRESSION "refusing to broadcast on mainnet")
  add_test(NAME chain_tool_usage COMMAND gz-chain --help)
  set_tests_properties(chain_tool_usage PROPERTIES PASS_REGULAR_EXPRESSION "usage: gz-chain")

  # Opt-in only: talks to mempool.space and blockstream.info on signet.
  # Never part of the default ctest run or of CI.
  if(GZ_LIVE_TESTS)
    add_executable(chain_test_live tests/test_live.c)
    target_link_libraries(chain_test_live PRIVATE gazpacho_chain_test_support gazpacho_chain_curl)
    target_compile_options(chain_test_live PRIVATE ${GZ_CHAIN_WARNINGS})
    add_test(NAME chain_live COMMAND chain_test_live)
    set_tests_properties(chain_live PROPERTIES TIMEOUT 300)
  endif()
endif()
