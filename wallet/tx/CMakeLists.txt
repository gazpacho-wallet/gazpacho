# On-chain wallet transactions: library, tests, fuzz target and the
# gz-wallet-tx tool.  Added by add_subdirectory(tx) in wallet/CMakeLists.txt,
# which sets GZW_WARNINGS and GZ_ROOT.

set(GZT_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# The library: no I/O, no randomness source, no global state.
add_library(gazpacho_wallet_tx STATIC src/tx.c src/sighash.c src/funding.c)
target_include_directories(gazpacho_wallet_tx PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gazpacho_wallet_tx PUBLIC gazpacho_wallet_keys secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_wallet_tx PRIVATE ${GZW_WARNINGS})

foreach(t test_tx_vectors test_tx)
  add_executable(${t} tests/${t}.c)
  target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vectors)
  target_link_libraries(${t} PRIVATE gazpacho_wallet_tx)
  target_compile_options(${t} PRIVATE ${GZW_WARNINGS})
endforeach()
add_test(NAME wallet_tx_vectors COMMAND test_tx_vectors)
add_test(NAME wallet_tx COMMAND test_tx)

# The parser's fuzz target (docs/notes/ci.md): with GZ_LIBFUZZER the target
# alone, linked with libFuzzer and run by tools/run-fuzz.sh; otherwise with
# the plain driver as a CTest test.  A non-numeric argument is refused.
if(GZ_LIBFUZZER)
  add_executable(fuzz_tx_parse tests/fuzz_tx_parse.c)
  target_link_options(fuzz_tx_parse PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_tx_parse tests/fuzz_tx_parse.c tests/fuzz_tx_main.c)
  target_include_directories(fuzz_tx_parse PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vectors)
  add_test(NAME wallet_tx_fuzz COMMAND fuzz_tx_parse 200000)
  add_test(NAME wallet_tx_fuzz_refuses_flags COMMAND fuzz_tx_parse -max_total_time=60)
  set_tests_properties(wallet_tx_fuzz_refuses_flags PROPERTIES WILL_FAIL TRUE)
endif()
target_link_libraries(fuzz_tx_parse PRIVATE gazpacho_wallet_tx)
target_compile_options(fuzz_tx_parse PRIVATE ${GZW_WARNINGS})

# The header from C++ (callers such as mobile wrappers), if a C++ compiler
# is installed: strict C++11, syntax only.
find_program(GZT_CXX NAMES c++ g++ clang++)
if(GZT_CXX)
  add_test(NAME wallet_tx_header_cxx
    COMMAND ${GZT_CXX} -std=c++11 -pedantic-errors -Wall -Wextra -Werror -fsyntax-only
            "-I$<JOIN:$<TARGET_PROPERTY:gazpacho_wallet_tx,INCLUDE_DIRECTORIES>,;-I>"
            "-I$<JOIN:$<TARGET_PROPERTY:gazpacho_wallet_keys,INTERFACE_INCLUDE_DIRECTORIES>,;-I>"
            "-I$<JOIN:$<TARGET_PROPERTY:secp256k1,INTERFACE_INCLUDE_DIRECTORIES>,;-I>"
            ${GZT_TESTS}/header_cxx.cpp
    COMMAND_EXPAND_LISTS)
endif()

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
add_test(NAME wallet_tx_tool_chain
  COMMAND sh ${GZT_TESTS}/test_tool_chain.sh $<TARGET_FILE:gz-wallet-tx> ${CMAKE_CURRENT_BINARY_DIR}/tool-chain-test)
set_tests_properties(wallet_tx_tool_chain PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
