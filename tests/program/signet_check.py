#!/usr/bin/env python3
"""Read-only signet check of the gazpacho program (opt-in: GZ_LIVE_TESTS).

    python3 -I signet_check.py PATH_TO_GAZPACHO WORK_DIR

Against public chain servers, reading only (nothing is broadcast):
  - a signet server is accepted: its block 0 is signet's, its tip is read, and
    the wallet's first address is looked up;
  - a mainnet server is refused for a signet program (its block 0 differs).
Needs the network. Exits 0 if every check passes.
"""
import os
import re
import shutil
import subprocess
import sys

SIGNET = "https://mempool.space/signet/api"
MAINNET = "https://mempool.space/api"

failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures.append(what)


def run(exe, d, url):
    r = subprocess.run([exe, "--data-dir", d, "--role", "host", "--listen", "127.0.0.1:0", "--no-interface",
                        "--chain-url", url, "--test-exit-after-chain"],
                       capture_output=True, text=True, timeout=120)
    print(r.stdout + r.stderr, flush=True)
    return r.returncode, r.stdout + r.stderr


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    code, out = run(exe, os.path.join(work, "a"), SIGNET)
    m = re.search(r"chain network=signet tip=(\d+) hash=([0-9a-f]{64})", out)
    check(code == 0 and m is not None and int(m.group(1)) > 200000, "a signet server is accepted and its tip read")
    check(re.search(r"wallet network=signet first-address=tb1p[0-9a-z]{58}", out) is not None,
          "the wallet's first address is a signet taproot address")
    check(re.search(r"wallet-outputs count=\d+ total_sat=\d+", out) is not None,
          "the wallet's first address is looked up (read-only)")
    code, out = run(exe, os.path.join(work, "b"), MAINNET)
    check(code == 5 and "is on mainnet, not signet: refused" in out, "a mainnet server is refused (exit %s)" % code)
    if failures:
        print("FAIL: %d check(s)" % len(failures))
        return 1
    print("PASS: signet read-only check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
