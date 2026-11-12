# On-chain wallet key handling: library, official-vector runner, tests, and the
# gz-wallet-keys command-line tool.  Added to the build by one
# add_subdirectory(wallet) line in the top-level CMakeLists.txt.

set(GZW_WARNINGS -Wall -Wextra -Werror)
set(GZ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(GZW_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/tests)

option(GZW_BREAK_CHECKS
  "Register wallet/tests/break-checks.sh as a CTest test (slow; builds without sanitizers only)" ON)

find_package(Python3 REQUIRED COMPONENTS Interpreter)   # tests/check_no_io.py

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

# ---- tests -------------------------------------------------------------------

# Official vectors.
add_executable(test_wallet_vectors tests/test_wallet_vectors.c)
target_link_libraries(test_wallet_vectors PRIVATE gazpacho_wallet_vectors)
target_compile_options(test_wallet_vectors PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_vectors COMMAND test_wallet_vectors)

# Unit tests.
add_executable(test_wallet_keys tests/test_wallet_keys.c)
target_include_directories(test_wallet_keys PRIVATE ${GZ_ROOT}/core/superscalar/src)
target_link_libraries(test_wallet_keys PRIVATE gazpacho_wallet_keys)
target_compile_options(test_wallet_keys PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_keys COMMAND test_wallet_keys)

# BIP 32's rare invalid cases, forced by replacing HMAC at link time.
add_executable(test_wallet_rare tests/test_wallet_rare.c)
target_link_libraries(test_wallet_rare PRIVATE gazpacho_wallet_keys)
target_link_options(test_wallet_rare PRIVATE -Wl,--wrap=HMAC)
target_compile_options(test_wallet_rare PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_rare COMMAND test_wallet_rare)

# The tool.
add_test(NAME wallet_tool
  COMMAND sh ${GZW_TESTS}/test_tool.sh $<TARGET_FILE:gz-wallet-keys>)

# The tool with its system calls routed through tests/tool_faults.c.
add_executable(gz-wallet-keys-faults ${GZ_ROOT}/tools/gz-wallet-keys/main.c tests/tool_faults.c)
target_link_libraries(gz-wallet-keys-faults PRIVATE gazpacho_wallet_vectors gazpacho_wallet_keys)
target_link_options(gz-wallet-keys-faults PRIVATE
  -Wl,--wrap=getrandom -Wl,--wrap=write -Wl,--wrap=read -Wl,--wrap=fsync
  -Wl,--wrap=link -Wl,--wrap=open -Wl,--wrap=geteuid)
target_compile_options(gz-wallet-keys-faults PRIVATE ${GZW_WARNINGS})
add_test(NAME wallet_tool_faults
  COMMAND sh ${GZW_TESTS}/test_tool_faults.sh
          $<TARGET_FILE:gz-wallet-keys-faults> $<TARGET_FILE:gz-wallet-keys>)

# The library must not reach the outside world.  An allow-list of the symbols
# its objects may reference, applied also to the imported objects it pulls in.
add_test(NAME wallet_keys_no_io
  COMMAND ${Python3_EXECUTABLE} ${GZW_TESTS}/check_no_io.py
          $<TARGET_FILE:gazpacho_wallet_keys> $<TARGET_FILE:gazpacho_superscalar>)

# Negative tests of that check: it must fail on a library that does any of these.
function(gzw_bad_lib name source symbols)
  add_library(gzw_bad_${name} STATIC tests/bad_libs/${source})
  target_compile_options(gzw_bad_${name} PRIVATE ${GZW_WARNINGS})
  add_test(NAME wallet_no_io_rejects_${name}
    COMMAND ${Python3_EXECUTABLE} ${GZW_TESTS}/check_no_io.py
            $<TARGET_FILE:gzw_bad_${name}> --expect-fail ${symbols})
endfunction()
gzw_bad_lib(opens_file   opens_file.c   "openat|openat64|__openat_2|__openat64_2")
gzw_bad_lib(reads_clock  reads_clock.c  "timespec_get|clock_gettime")
gzw_bad_lib(prints       prints.c       "fprintf|__fprintf_chk")
gzw_bad_lib(keeps_state  keeps_state.c  "gzw_bad_counter")
gzw_bad_lib(reads_random reads_random.c "getrandom")

# Break-checks: damage one protection at a time in a scratch copy and require a
# test to fail.  Slow, so it has the label "slow" (ctest -LE slow leaves it out)
# and is not registered in sanitizer builds, where it would add nothing.
if(GZW_BREAK_CHECKS AND NOT GZ_SANITIZE)
  add_test(NAME wallet_break_checks
    COMMAND sh ${GZW_TESTS}/break-checks.sh ${GZ_ROOT}
            ${CMAKE_CURRENT_BINARY_DIR}/break-checks ${secp256k1-zkp_SOURCE_DIR})
  set_tests_properties(wallet_break_checks PROPERTIES LABELS slow TIMEOUT 3600)
endif()

# Wallet transactions (wallet/tx).
add_subdirectory(tx)
