#!/usr/bin/env python3
"""program_never_fund (Slice 1.5 plan, P6a; the program half of S5): the
host's --test-never-fund on the local test chain, every party a separate
gazpacho-test process, the chain a real Bitcoin Core regtest node (as
program_slice1, whose node and Esplora look-alike it uses).

    python3 -I never_fund.py PATH_TO_GAZPACHO_TEST WORK_DIR BITCOIN_BIN_DIR

Exits 77 (skipped) when BITCOIN_BIN_DIR holds no bitcoind. Every fee is 0.1 sat/vB.

  1. A host with --test-never-fund and three AUTO members: the round is
     signed, every member acks, the host's wallet signs the funding F, and the
     switch holds it ("test-never-fund held txid=F"): F is never queued for
     the chain and the node never has it.
  2. Past the members' funding deadline (the tip at the ack + 36): every
     member reports the creation abandoned (fund-report kind=3). The host's own
     engine abandons it too; the switch holds its spend-back as well
     ("held-spend-back ... funding=F"), so no input of F is spent yet.
  3. The host stopped. --test-spend-coin on the plan's one input, without the
     switch (a copy of the folder): printed only, never broadcast. With
     --test-never-fund: the program broadcasts the spend itself
     ("spend-coin-broadcast ... outcome=accepted") and the node has it.
  4. Once the spend is buried, every member reports the creation dead
     (fund-report kind=2), and none ever reports it Live.
Every process is checked for no node-error, repair or fatal line.
"""
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, kill_all, passphrase_file  # noqa: E402
import lobby  # noqa: E402
import slice1  # noqa: E402
from lobby import started, state  # noqa: E402

check = Checks()
lobby.check = check
slice1.check = check
FUNDING = slice1.FUNDING
FUNDED_SAT = slice1.FUNDED_SAT


def has(p, pattern):
    return p.count(pattern) > 0


def mine_until(rt, procs, pattern, timeout=90):
    """A block every two seconds until every process shows `pattern`, or the time is up."""
    end = time.time() + timeout
    while time.time() < end:
        if all(has(p, pattern) for p in procs):
            return True
        rt.mine(1)
        time.sleep(2)
    return all(has(p, pattern) for p in procs)


def spend_coin(w, folder, spec, *extra):
    a = w.args("host", "host")
    a[a.index("--data-dir") + 1] = folder
    a += ["--test-spend-coin", spec, "--test-passphrase-file", passphrase_file(), "--test-kdf-floor"] + list(extra)
    r = subprocess.run(a, capture_output=True, text=True, timeout=120)
    return r.stdout + r.stderr


def never_fund(exe, work, rt, name="S5 never funded"):
    w = slice1.ChainWorld(exe, work, "nf", rt)
    tick = ("--test-sign-tick-ms", "100")
    try:
        addr = w.host_address()
        if not check(addr is not None, "%s: the host's first receive address is a regtest one" % name):
            return
        coin_txid = rt.pay(addr, FUNDED_SAT)
        spk = rt.cli("-rpcwallet=miner", "getaddressinfo", addr)["scriptPubKey"]
        coin = rt.cli("getrawtransaction", coin_txid, "1")
        vout = [v["n"] for v in coin["vout"] if v["scriptPubKey"]["hex"] == spk]
        if not check(len(vout) == 1, "%s: the host's coin is on chain" % name):
            return
        h = w.host("--test-never-fund", *tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts on regtest" % name):
            return
        check(h.wait_for(r"wallet-coins count=1 total_sat=%d" % FUNDED_SAT, timeout=30) is not None,
              "%s: its wallet port finds its one coin" % name)
        t = slice1.Terms(w.hkey, 900)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = {n: w.member(n, "--member-signing", "auto", *tick) for n in ("m1", "m2", "m3")}
        check(all(started(m) for m in ms.values()), "%s: three members start" % name)
        for n in ms:
            w.join(ms[n], t)
        check(state(h, t, "host", FUNDING, timeout=240), "%s: the round is signed: the host reaches Funding" % name)

        # 1. The funding is signed and held.
        m = h.wait_for(r"test-never-fund held txid=([0-9a-f]{64})", timeout=60)
        if not check(m is not None, "%s: the switch holds the signed funding" % name):
            return
        f = m.group(1)
        check(has(h, r"wallet-plan inputs=1 ") and not has(h, r"broadcast-queued id=\d+ txid=%s" % f),
              "%s: the funding was planned from the coin and never queued for the chain" % name)
        time.sleep(3)
        check(not slice1.chain_tx(rt, f), "%s: the node does not have the funding" % name)
        members = list(ms.values())

        # 2. Past the members' deadline: abandoned; the host's spend-back held too.
        rt.mine(36)
        check(mine_until(rt, members, r"fund-report scope=%s kind=3" % t.tag),
              "%s: past the deadline every member reports the creation abandoned" % name)
        check(h.wait_for(r"test-never-fund held-spend-back txid=[0-9a-f]{64} funding=%s" % f, timeout=60) is not None,
              "%s: the host's own spend-back of the funding's input is held as well" % name)
        out = rt.esplora("/tx/%s/outspend/%d" % (coin_txid, vout[0]))
        check('"spent":false' in out.replace(" ", ""), "%s: the funding's input is still unspent (%s)" % (name, out[:80]))
        check(not slice1.chain_tx(rt, f), "%s: the funding never reached the node" % name)

        # 3. The spend of the input: printed only without the switch; broadcast with it.
        h.stop()
        spec = "%s:%d:%d:%s" % (coin_txid, vout[0], FUNDED_SAT, spk)
        copy = os.path.join(w.work, "host-copy")
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(os.path.join(w.work, "host"), copy, symlinks=True)
        o = spend_coin(w, copy, spec)
        tx = re.search(r"spend-tx amount=\d+ fee=\d+ out=\d+ vsize=\d+ tx=([0-9a-f]+)", o)
        check(tx is not None and "spend-coin-broadcast" not in o,
              "%s: without the switch the spend is printed, not broadcast" % name)
        if tx:
            stxid = rt.cli("decoderawtransaction", tx.group(1))["txid"]
            check(not slice1.chain_tx(rt, stxid), "%s: and the node does not have it" % name)
        o = spend_coin(w, os.path.join(w.work, "host"), spec, "--test-never-fund")
        b = re.search(r"spend-coin-broadcast txid=([0-9a-f]{64}) outcome=(\S+)", o)
        check(b is not None and b.group(2) == "accepted",
              "%s: with --test-never-fund the program broadcasts the spend (%s)" % (name, b.group(0) if b else o[-300:]))
        if b:
            check(bool(slice1.chain_tx(rt, b.group(1))), "%s: the node has the spend" % name)

        # 4. Buried: every member reports the creation dead; nobody Live.
        check(mine_until(rt, members, r"fund-report scope=%s kind=2" % t.tag),
              "%s: once the spend is buried every member reports the creation dead" % name)
        check(not any(has(p, r"fund-report scope=%s kind=[14]" % t.tag) for p in members + [h]),
              "%s: nobody judged it Live" % name)
        w.clean(name)
    finally:
        w.stop()
        kill_all(w.procs)


def main():
    exe, work = sys.argv[1], sys.argv[2]
    bindir = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("GZ_BITCOIN_BIN", "")
    if not bindir or not os.path.exists(os.path.join(bindir, "bitcoind")):
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR or GZ_BITCOIN_BIN)")
        return 77
    os.makedirs(work, exist_ok=True)
    rt = slice1.Regtest(bindir, work)
    try:
        never_fund(exe, work, rt)
    finally:
        rt.stop()
    return check.result("program_never_fund", work)


if __name__ == "__main__":
    sys.exit(main())
