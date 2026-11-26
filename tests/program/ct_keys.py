#!/usr/bin/env python3
"""Constant-time check of the key port (docs/notes/keys.md 8).

    python3 -I ct_keys.py VALGRIND CT_KEYS

Runs ct_keys under memcheck, with the seed it hands out marked undefined
(secret). ct_keys builds wallet/src/bip32.c with its declassify hook set to
valgrind's (tests/program/ct_bip32.c, as the signer's own test does since
#71), so a key's validity and the public keys are declared public where they
are computed. Nothing else may then depend on the seed: every memcheck report
fails the test, except the one deliberate memory index in ct_canary, which must be
there, so the run shows that the seed was marked."""
import re
import subprocess
import sys

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
    bad, canary = [], 0
    for b in blocks:
        fr = frames(b)
        if fr and fr[0][0] == "ct_canary":
            canary += 1
            continue
        bad.append(b)
    for b in bad:
        print("UNTRIAGED secret-dependent branch or index:\n" + b)
    if not canary:
        print("ct_keys: no report from ct_canary: the seed was not marked secret, so the check saw nothing")
    print("ct_keys: %d report(s), the canary's only" % len(blocks) if not bad and canary else
          "ct_keys: %d of %d reports depend on the seed" % (len(bad), len(blocks)))
    return 1 if bad or not canary else 0


if __name__ == "__main__":
    sys.exit(main())
