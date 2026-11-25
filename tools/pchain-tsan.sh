#!/bin/sh
# Builds the program's chain adapter (program/pchain.c) with the chain port and
# its libcurl transport under ThreadSanitizer, and runs
# tests/program/test_pchain_threads.c against a local Esplora stub
# (tests/program/pchain_threads.py): the loop's lookups while the chain
# worker polls. Any data race between the two threads fails
# (docs/notes/integration.md B11). Needs libcurl's and OpenSSL's headers and
# python3.
#
# usage: tools/pchain-tsan.sh [WORK_DIR]        CC selects the compiler
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
p=$root/ports/chain
work=${1:-$(mktemp -d)}
mkdir -p "$work"
${CC:-cc} -std=gnu11 -O1 -g -fsanitize=thread -fno-omit-frame-pointer -Wall -Wextra -DGZP_HAVE_CURL=1 \
  -I"$root/program" -I"$root/core/gazpacho/include" -I"$p/include" \
  "$root/program/pchain.c" "$root/tests/program/test_pchain_threads.c" \
  "$p/chain.c" "$p/headers.c" "$p/verify.c" "$p/json.c" "$p/esplora.c" "$p/multi.c" "$p/watch.c" "$p/chainw.c" \
  "$p/http_curl.c" -o "$work/test_pchain_threads_tsan" -lcurl -lcrypto -lpthread
python3 -I "$root/tests/program/pchain_threads.py" "$work/test_pchain_threads_tsan"
