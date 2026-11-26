#!/usr/bin/env python3
"""program_chain_throttle (docs/notes/integration.md B22, F22): a host whose
chain server throttles, as public servers do, still reads its coins, on a
real Bitcoin Core regtest node.

    python3 -I chain_throttle.py PATH_TO_GAZPACHO_TEST WORK_DIR BITCOIN_BIN_DIR

Signet run 2's preparation: mempool.space answered 429, then nothing, to the
host's chain clients, and the wallet's scan never finished. Here the Esplora
look-alike answers 429 to any GET beyond 12 in the last 4 seconds, from any
client (GZ_ESPLORA_THROTTLE). The host is paid one coin and started; the chain
worker polls the tip four times a second meanwhile.

  1. The look-alike throttles: it answers some GETs 429.
  2. The host's wallet port still reads its one coin, its scan complete.
  3. No node-error, repair or fatal line.
Exits 77 (skipped) without bitcoind.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import kill_all  # noqa: E402
import slice1  # noqa: E402
from lobby import started  # noqa: E402

check = slice1.check


def main():
    exe, work, bindir = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else os.environ.get("GZ_BITCOIN_BIN", "")
    if not bindir or not os.path.exists(os.path.join(bindir, "bitcoind")):
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR or GZ_BITCOIN_BIN)")
        return 77
    os.makedirs(work, exist_ok=True)
    log = os.path.join(work, "esplora-requests.log")
    if os.path.exists(log):
        os.remove(log)
    os.environ["GZ_ESPLORA_LOG"] = log
    os.environ["GZ_ESPLORA_THROTTLE"] = "12:4"
    rt = slice1.Regtest(bindir, work)
    w = slice1.ChainWorld(exe, work, "throttle", rt)
    try:
        addr = w.host_address()
        if not check(addr is not None, "the host's first receive address is a regtest one"):
            return check.result("program_chain_throttle", work)
        rt.pay(addr, slice1.FUNDED_SAT)
        h = w.host()
        if not check(started(h), "the host starts on regtest"):
            return check.result("program_chain_throttle", work)
        m = h.wait_for(r"wallet-coins count=1 total_sat=%d lookups-failed=0" % slice1.FUNDED_SAT, timeout=240)
        with open(log) as f:
            codes = [l.split(" code=")[1].split()[0] for l in f if " code=" in l]
        check(codes.count("429") > 0, "1: the look-alike throttles (%d of %d GETs answered 429)" % (codes.count("429"), len(codes)))
        check(m is not None, "2: the host's wallet port still reads its one coin, its scan complete")
        check(not slice1.has(h, r"node-error|repair|fatal"), "3: no node-error, repair or fatal line")
    finally:
        kill_all(w.procs)
        rt.stop()
    return check.result("program_chain_throttle", work)


if __name__ == "__main__":
    sys.exit(main())
