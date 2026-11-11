# On-chain wallet key handling: library, official-vector runner, tests, and the
# gz-wallet-keys command-line tool.  Added to the build by one
# add_subdirectory(wallet) line in the top-level CMakeLists.txt.

set(GZW_WARNINGS -Wall -Wextra -Werror)
set(GZ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# The library: no I/O, no randomness source, no global state.
# It uses the imported BIP 39 code and word list (read-only), secp256k1 and libcrypto.
add_library(gazpacho_wallet_keys STATIC
  src/address.c
  src/bip32.c
  src/phrase.c
  src/taproot.c)
target_include_directories(gazpacho_wallet_keys
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${GZ_ROOT}/core/superscalar/src)   # bip39_wordlist.h
target_link_libraries(gazpacho_wallet_keys PUBLIC gazpacho_superscalar secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_wallet_keys PRIVATE ${GZW_WARNINGS})

# The official BIP vectors and the code that runs them (shared by the test and the tool).
add_library(gazpacho_wallet_vectors STATIC vectors/official_vectors.c)
target_include_directories(gazpacho_wallet_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vectors)
target_link_libraries(gazpacho_wallet_vectors PUBLIC gazpacho_wallet_keys)
target_compile_options(gazpacho_wallet_vectors PRIVATE ${GZW_WARNINGS})

# The command-line tool (outside the core: it reads the OS random source and files).
add_executable(gz-wallet-keys ${GZ_ROOT}/tools/gz-wallet-keys/main.c)
target_link_libraries(gz-wallet-keys PRIVATE gazpacho_wallet_vectors gazpacho_wallet_keys)
target_compile_options(gz-wallet-keys PRIVATE ${GZW_WARNINGS})

# Tests.
add_executable(test_wallet_vectors tests/test_wallet_vectors.c)
target_link_libraries(test_wallet_vectors PRIVATE gazpacho_wallet_vectors)
target_compile_options(test_wallet_vectors PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_vectors COMMAND test_wallet_vectors)

add_executable(test_wallet_keys tests/test_wallet_keys.c)
target_include_directories(test_wallet_keys PRIVATE ${GZ_ROOT}/core/superscalar/src)
target_link_libraries(test_wallet_keys PRIVATE gazpacho_wallet_keys)
target_compile_options(test_wallet_keys PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_keys COMMAND test_wallet_keys)

add_test(NAME wallet_tool
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_tool.sh $<TARGET_FILE:gz-wallet-keys>)

# The library must not reach the outside world: no file, network, clock or
# randomness calls among its undefined symbols.
add_test(NAME wallet_keys_no_io
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_no_io.sh $<TARGET_FILE:gazpacho_wallet_keys>)
