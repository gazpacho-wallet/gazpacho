#!/usr/bin/env python3
"""Constant-time check of the key port (docs/notes/keys.md 8).

    python3 -I ct_keys.py VALGRIND CT_KEYS

Runs ct_keys under memcheck, with the seed it hands out marked undefined
(secret). Every memcheck report is a branch or an index on secret-derived
data. Each must be one of the triaged points below, where the value is public
by design; any other report fails the test. keys.c itself has none: every
point is in the wallet library or libsecp256k1, below it. If wallet/src/
bip32.c changes and a line moves, this fails until the new line is triaged.

Triaged (2026-11-17):
  gzw_bip32_master bip32.c:114          the master's validity, secp256k1_ec_seckey_verify on
                                        I_L: BIP 32's "no master key" case, public by nature
  gzw_bip32_child_priv bip32.c:149      the parent key's validity check (always valid here)
  gzw_bip32_child_priv bip32.c:171      the child's validity, the result of
                                        secp256k1_ec_seckey_tweak_add: BIP 32's invalid child
  seckey_to_pubkey33 bip32.c:88         the result of making the parent's PUBLIC key (for the
                                        fingerprint) or the public key handed out
  secp256k1_pubkey_load,                serialising that public key: the point is public
  secp256k1_fe_impl_normalize_var,      (reached only through seckey_to_pubkey33). In a Release
  secp256k1_ec_pubkey_serialize         build libsecp256k1 has no line information and its
                                        helpers are inlined, so the report names
                                        secp256k1_ec_pubkey_serialize itself (integration B10)

ct_keys is built with its own line-numbered copy of keys.c and the wallet's key
code in every build type (program/CMakeLists.txt), so the bip32.c lines above
hold in Release as in RelWithDebInfo.
"""
import re
import subprocess
import sys

ALLOWED_TOP = {("gzw_bip32_master", "bip32.c:114"), ("gzw_bip32_child_priv", "bip32.c:149"),
               ("gzw_bip32_child_priv", "bip32.c:171"), ("seckey_to_pubkey33", "bip32.c:88")}
PUBLIC_POINT = {"secp256k1_pubkey_load", "secp256k1_fe_impl_normalize_var", "secp256k1_ec_pubkey_serialize"}


def frames(block):
    return [(f.split(".")[0], loc.split("/")[-1])
            for f, loc in re.findall(r"(?:at|by) 0x[0-9A-Fa-f]+: (\S+) \(([^)]*)\)", block)]


def main():
    vg, exe = sys.argv[1], sys.argv[2]
    p = subprocess.run([vg, "--track-origins=yes", "--num-callers=30", exe], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    out = p.stdout
    if "ct_keys: ran" not in out:
        print(out)
        print("ct_keys: the harness did not run to its end")
        return 1
    blocks = [b for b in re.split(r"==\d+== \n", out) if "depends on uninitialised" in b or "Use of uninitialised" in b]
    bad = []
    for b in blocks:
        fr = frames(b)
        if not fr:
            bad.append(b)
            continue
        top = fr[0]
        if (top[0], top[1].split()[-1] if top[1] else "") in ALLOWED_TOP:
            continue
        if top[0] in PUBLIC_POINT and any(f[0] == "seckey_to_pubkey33" for f in fr):
            continue
        bad.append(b)
    for b in bad:
        print("UNTRIAGED secret-dependent branch or index:\n" + b)
    print("ct_keys: %d reports, all triaged as public by design" % len(blocks) if not bad else
          "ct_keys: %d of %d reports not triaged" % (len(bad), len(blocks)))
    return 1 if bad or not blocks else 0  # no report at all would mean the seed was not marked


if __name__ == "__main__":
    sys.exit(main())
