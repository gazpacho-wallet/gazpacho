#!/bin/sh
# The vectors build cannot stand in for the production signer (review A of
# #71, H3; decision K20).
#   PROD  libgazpacho_signer.a: defines gz_sg_sign_envelope and no gz_sgv_*
#         symbol, and not the marker gz_sg_vectors_build_never_ship;
#   VECT  libgazpacho_signer_vectors.a: defines the marker and gz_sgv_*, and
#         none of the production entry points, so nothing written against
#         gazpacho/signer.h links against it.
# usage: link_guard.sh PROD VECT
set -eu
prod=$1 vect=$2
fail=0
defined() { nm -g --defined-only "$1" 2>/dev/null | awk '{print $NF}' | sort -u; }
p=$(defined "$prod"); v=$(defined "$vect")
[ -n "$p" ] && [ -n "$v" ] || { echo "FAIL: nm found no symbols"; exit 1; }
echo "$p" | grep -qx gz_sg_sign_envelope || { echo "FAIL: production lacks gz_sg_sign_envelope"; fail=1; }
if echo "$p" | grep -q -e '^gz_sgv_' -e '^gz_sg_vectors_build_never_ship$'; then
    echo "FAIL: production library holds vectors-build symbols:"; echo "$p" | grep -e '^gz_sgv_' -e never_ship; fail=1
fi
echo "$v" | grep -qx gz_sg_vectors_build_never_ship || { echo "FAIL: vectors build lacks its marker"; fail=1; }
echo "$v" | grep -qx gz_sgv_sign_envelope || { echo "FAIL: vectors build lacks gz_sgv_sign_envelope"; fail=1; }
if echo "$v" | grep -v -x gz_sg_vectors_build_never_ship | grep -q -e '^gz_sg_[a-z]' -e '^gz_signer_'; then
    echo "FAIL: vectors build exports production names:"; echo "$v" | grep -e '^gz_sg_[a-z]' -e '^gz_signer_' | grep -v never_ship; fail=1
fi
[ $fail -eq 0 ] && echo "signer link guard: production and vectors builds are apart"
exit $fail
