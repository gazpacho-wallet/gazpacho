#!/bin/sh
# Symbol checks of spec 13 and 4.2 (review F24).
#   check-symbols.sh no-test-entry LIB   the release storage library defines no gz_sc_test_*
#   check-symbols.sh no-sodium LIB       gazpacho_core neither defines nor calls sodium_* or crypto_*
set -eu
mode=$1
lib=$2
command -v nm >/dev/null 2>&1 || { echo "SKIP: nm not found"; exit 77; }
case $mode in
no-test-entry)
    bad=$(nm -g "$lib" | grep -E ' gz_sc_test_' || true)
    # The test library must have them, or the check proves nothing.
    test_lib=$(dirname "$lib")/libgazpacho_storage_crypto_test.a
    if [ -f "$test_lib" ] && ! nm -g "$test_lib" | grep -q ' T gz_sc_test_set_floor'; then
        echo "FAIL: the test library lacks gz_sc_test_set_floor; the check is broken"; exit 1
    fi ;;
no-sodium)
    bad=$(nm "$lib" | grep -E ' [TUtWw] (sodium_|crypto_|randombytes_)' || true) ;;
*) echo "usage"; exit 2 ;;
esac
if [ -n "$bad" ]; then
    echo "FAIL ($mode): $lib has"
    echo "$bad"
    exit 1
fi
echo "ok ($mode): $lib"
