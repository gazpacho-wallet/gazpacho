# On-chain wallet transactions: library, tests, fuzz target and the
# gz-wallet-tx tool.  Added by add_subdirectory(tx) in wallet/CMakeLists.txt,
# which sets GZW_WARNINGS and GZ_ROOT.

set(GZT_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# The library: no I/O, no randomness source, no global state.
add_library(gazpacho_wallet_tx STATIC src/tx.c src/sighash.c src/funding.c)
target_include_directories(gazpacho_wallet_tx PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gazpacho_wallet_tx PUBLIC gazpacho_wallet_keys secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_wallet_tx PRIVATE ${GZW_WARNINGS})

foreach(t test_tx_vectors test_tx fuzz_tx_parse)
  add_executable(${t} tests/${t}.c)
  target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vectors)
  target_link_libraries(${t} PRIVATE gazpacho_wallet_tx)
  target_compile_options(${t} PRIVATE ${GZW_WARNINGS})
endforeach()
add_test(NAME wallet_tx_vectors COMMAND test_tx_vectors)
add_test(NAME wallet_tx COMMAND test_tx)
add_test(NAME wallet_tx_fuzz COMMAND fuzz_tx_parse 200000)

# Verify-after-sign, with the signer replaced at link time.
add_executable(test_tx_faults tests/test_tx_faults.c)
target_link_libraries(test_tx_faults PRIVATE gazpacho_wallet_tx)
target_link_options(test_tx_faults PRIVATE -Wl,--wrap=secp256k1_schnorrsig_sign32)
target_compile_options(test_tx_faults PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_tx_faults COMMAND test_tx_faults)

# The same allow-list as the key library, plus what signing needs.
add_test(NAME wallet_tx_no_io
  COMMAND ${Python3_EXECUTABLE} ${GZW_TESTS}/check_no_io.py $<TARGET_FILE:gazpacho_wallet_tx>
          --also-allow "secp256k1_schnorrsig_sign32|secp256k1_schnorrsig_verify|gzw_wipe|gzw_ct_equal|gzw_bip86_output_from_master|gzw_bip86_tweaked_keypair")

# The tool.  Its chain commands are compiled in when the chain port's libcurl
# target exists anywhere in the build (it is on another branch for now).
add_executable(gz-wallet-tx ${GZ_ROOT}/tools/gz-wallet-tx/main.c)
target_link_libraries(gz-wallet-tx PRIVATE gazpacho_wallet_tx
  $<$<TARGET_EXISTS:gazpacho_chain_curl>:gazpacho_chain_curl>)
target_compile_definitions(gz-wallet-tx PRIVATE
  $<$<TARGET_EXISTS:gazpacho_chain_curl>:GZT_WITH_CHAIN>)
target_compile_options(gz-wallet-tx PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_tx_tool
  COMMAND sh ${GZT_TESTS}/test_tool.sh $<TARGET_FILE:gz-wallet-tx> ${CMAKE_CURRENT_BINARY_DIR}/tool-test)
