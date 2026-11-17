#!/bin/sh
# Builds the chain worker, the watch engine and their threaded test
# (ports/chain/tests/test_chainw.c) with ThreadSanitizer and runs it: watches,
# requests, events, resets and shutdown racing, with the simulated servers
# changing and failing underneath. Any data race or lock-order report fails.
#
# usage: tools/chain-tsan.sh [WORK_DIR]        CC selects the compiler
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
p=$root/ports/chain
work=${1:-$(mktemp -d)}
mkdir -p "$work"
${CC:-cc} -std=c11 -O1 -g -fsanitize=thread -fno-omit-frame-pointer -Wall -Wextra -Werror   -I"$p/include" -DGZ_TEST_DATA_DIR="\"$p/tests/data\""   "$p/chain.c" "$p/headers.c" "$p/verify.c" "$p/json.c" "$p/esplora.c" "$p/multi.c"   "$p/watch.c" "$p/chainw.c" "$p/tests/test_support.c" "$p/tests/sim.c"   "$p/tests/test_chainw.c" -o "$work/chain_test_chainw_tsan" -lcrypto -lpthread
TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1" "$work/chain_test_chainw_tsan"
echo "PASS: the chain worker test is clean under ThreadSanitizer"
