#!/usr/bin/env python3
"""program_host_funds (docs/notes/integration.md; spec/local-api.md 15.2;
#55's funds check): the host's funds check asks the host's own wallet, on a
real Bitcoin Core regtest node.

    python3 -I host_funds.py PATH_TO_GAZPACHO_TEST WORK_DIR BITCOIN_BIN_DIR

The node's funding config carries the program's wallet port (wport.h), so
opening a hosted lobby is answered from the host's real coins, never from a
stand-in and never no_wallet:

  1. A host whose wallet holds no coin: once its wallet port has read the
     chain, opening a lobby is refused funds_short; no slot opens.
  2. The host stopped, a coin paid to its first receive address and
     confirmed, the host started again (the wallet port reads its coins at
     the start): once the wallet port finds it, the same open is accepted
     and the lobby opens.
  3. No answer anywhere is no_wallet or coins_unknown.
Exits 77 (skipped) without bitcoind.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import kill_all  # noqa: E402
import slice1  # noqa: E402
from lobby import started  # noqa: E402

check = slice1.check


def results(h):
    """Every command-result line's (status, error), in order."""
    rx = re.compile(r"command-result id=\S+ status=(\d+) error=(\S*)")
    with h.cv:
        lines = list(h.lines)
    return [m.groups() for m in map(rx.search, lines) if m]


def main():
    exe, work, bindir = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else os.environ.get("GZ_BITCOIN_BIN", "")
    if not bindir or not os.path.exists(os.path.join(bindir, "bitcoind")):
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR or GZ_BITCOIN_BIN)")
        return 77
    os.makedirs(work, exist_ok=True)
    rt = slice1.Regtest(bindir, work)
    w = slice1.ChainWorld(exe, work, "funds", rt)
    try:
        addr = w.host_address()
        if not check(addr is not None, "the host's first receive address is a regtest one"):
            return check.result("program_host_funds", work)
        h = w.host()
        if not check(started(h) and w.hkey is not None, "the host starts on regtest"):
            return check.result("program_host_funds", work)
        check(h.wait_for(r"wallet-coins count=0 total_sat=0", timeout=30) is not None,
              "1: its wallet port reads the chain and finds no coin")
        t = slice1.Terms(w.hkey, 900)
        w.open(h, t)
        m = h.wait_for(r"command-result id=\S+ status=(\d+) error=(\S*)", timeout=20)
        check(m is not None and m.group(1) == "409" and m.group(2) == "funds_short",
              "1: with no coin, opening is refused funds_short (%s)" % (m.group(0) if m else "no answer"))
        check(h.wait_for(r"slot-opened scope=%s" % t.tag, timeout=2) is None, "1: no slot opens")

        first = results(h)
        # The wallet port reads the coins once, at the start (wport.c): the host is
        # stopped, the coin paid, and the host started again on its folder.
        h.stop()
        rt.pay(addr, slice1.FUNDED_SAT)
        h = w.host()
        if not check(started(h), "2: the host starts again"):
            return check.result("program_host_funds", work)
        check(h.wait_for(r"wallet-coins count=1 total_sat=%d" % slice1.FUNDED_SAT, timeout=30) is not None,
              "2: the wallet port finds the paid coin, confirmed")
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=20) is not None,
              "2: with the coin, the same open is accepted and the lobby opens")
        # the open's answer may come just after its slot-opened line: waited for, not read at once
        m = h.wait_for(r"command-result id=\S+ status=(\d+) error=(\S*)", timeout=20)
        check(m is not None and m.group(1).startswith("2") and m.group(2) == "-",
              "2: the open's answer is a success (%s)" % (m.group(0) if m else "no answer"))
        rs = results(h)
        rs = first + rs
        check(not any(e in ("no_wallet", "coins_unknown") for _, e in rs),
              "3: no answer is no_wallet or coins_unknown (%s)" % rs)
        check(not slice1.has(h, r"node-error|repair|fatal"), "no node-error, repair or fatal line")
    finally:
        kill_all(w.procs)
        rt.stop()
    return check.result("program_host_funds", work)


if __name__ == "__main__":
    sys.exit(main())
