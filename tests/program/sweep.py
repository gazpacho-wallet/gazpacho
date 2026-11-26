#!/usr/bin/env python3
"""program_sweep (docs/notes/integration.md, the signet run's recovery;
spec/exit.md 3.2 and H15, the INTERIM rules of Slice 1): the host's timeout
sweep of a Live factory, on a real Bitcoin Core regtest node.

    python3 -I sweep.py PATH_TO_GAZPACHO_TEST WORK_DIR BITCOIN_BIN_DIR

A host and three AUTO members fund a factory as program_slice1 does, and it
goes Live; every process stops. The host's folder is then copied for every
run of the tool (gazpacho-test --test-sweep: opening a journal can write).

  1. At the tip, every timeout spend of the root kickoff's outputs is refused
     by the tool (not yet). Built anyway (--test-sweep-force), the node
     refuses them too (non-final), also once the root kickoff is confirmed.
  2. With member 1 owed (--test-owed 1), the output above member 1 is
     refused; the others are built.
  3. At the heights, the root kickoff and every spend are accepted and mined,
     paying the host's first receive address at 0.1 sat/vB; every satoshi of
     the factory is accounted for: funding = root fee + root anchor + the
     spends' fees + what they pay.
  4. Nothing else touches a member's output: no other tree transaction is on
     chain, and each root output is spent by the host's spend, nothing else.
Exits 77 (skipped) without bitcoind.
"""
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import passphrase_file, kill_all  # noqa: E402
import slice1  # noqa: E402
from lobby import started, state  # noqa: E402

check = slice1.check


def tool(w, folder, height, *extra):
    a = w.args("host", "host")
    a[a.index("--data-dir") + 1] = folder
    a += ["--test-sweep", str(height), "--test-passphrase-file", passphrase_file(), "--test-kdf-floor"] + list(extra)
    r = subprocess.run(a, capture_output=True, text=True, timeout=120)
    lines = r.stdout.splitlines()
    kv = lambda l: dict(x.split("=", 1) for x in l.split()[1:] if "=" in x)
    return r.returncode, {
        "round": [kv(l) for l in lines if l.startswith("sweep-round")],
        "tree": [kv(l) for l in lines if l.startswith("sweep-tree")],
        "refused": [kv(l) for l in lines if l.startswith("sweep-refused")],
        "spend": [kv(l) for l in lines if l.startswith("sweep-spend")],
        "error": [l for l in lines if l.startswith("sweep-error")] + ([r.stderr.strip()] if r.returncode else []),
    }


def fresh_copy(w, n):
    src = os.path.join(w.work, "host")
    dst = os.path.join(w.work, "host-copy-%d" % n)
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, symlinks=True)
    return dst


def accept(rt, txhex):
    r = rt.cli("testmempoolaccept", '["%s"]' % txhex)
    return r[0]


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    bindir = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("GZ_BITCOIN_BIN", "")
    if not bindir or not os.path.exists(os.path.join(bindir, "bitcoind")):
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR or GZ_BITCOIN_BIN)")
        return 77
    os.makedirs(work, exist_ok=True)
    rt = slice1.Regtest(bindir, work)
    w = slice1.ChainWorld(exe, work, "sweep", rt)
    tick = ("--test-sign-tick-ms", "100")
    try:
        addr = w.host_address()
        if not check(addr is not None, "the host's first receive address"):
            return check.result("program_sweep", work)
        host_spk = rt.cli("-rpcwallet=miner", "getaddressinfo", addr)["scriptPubKey"]
        rt.pay(addr, slice1.FUNDED_SAT)
        h = w.host(*tick)
        if not check(started(h) and w.hkey is not None, "the host starts"):
            return check.result("program_sweep", work)
        check(h.wait_for(r"wallet-coins count=1 ", timeout=30) is not None, "its wallet port finds its coin")
        t = slice1.Terms(w.hkey, 900, lifetime=144)
        w.open(h, t)
        ms = [w.member(n, "--member-signing", "auto", *tick) for n in ("m1", "m2", "m3")]
        check(all(started(m) for m in ms), "three members start")
        for m in ms:
            w.join(m, t)
        check(state(h, t, "host", slice1.FUNDING, timeout=300), "the round is signed: Funding")
        fm = h.wait_for(r"broadcast-queued id=\d+ txid=([0-9a-f]{64})", timeout=60)
        funding_txid = fm.group(1) if fm else None
        check(slice1.bury(rt, [h] + ms, t), "the factory goes Live on the host and every member")
        w.clean("before the sweep")
        w.stop()
        tip = rt.cli("getblockcount")

        # 1. Before the heights: refused by the tool, and by the node.
        rc, o = tool(w, fresh_copy(w, 1), tip)
        check(rc == 0 and not o["error"] and len(o["round"]) == 1, "the tool reads one funded round (%s)" % o["error"][:2])
        if not o["round"]:
            return check.result("program_sweep", work)
        rnd = o["round"][0]
        tree = {int(x["node"]): x for x in o["tree"]}
        root = tree.get(0)
        kids = [x for x in o["tree"] if x["parent"] == "0"]
        check(root is not None and len(kids) >= 1, "the signed tree: the root kickoff and %d outputs below it" % len(kids))
        check(len(o["refused"]) == len(kids) and all(x["why"] == "not-yet" for x in o["refused"]) and not o["spend"],
              "at the tip (%d) the tool refuses every spend: not yet" % tip)
        locks = sorted(int(x["cltv"]) for x in kids)
        check(all(l > tip for l in locks), "every timeout height (%s) is above the tip" % locks)
        rc, of = tool(w, fresh_copy(w, 2), tip, "--test-sweep-force")
        check(rc == 0 and len(of["spend"]) == len(kids), "forced, the tool builds the spends anyway, for the node to judge")
        acc = accept(rt, root["tx"])
        check(acc.get("allowed"), "the root kickoff is valid now (key path, no timeout): %s" % acc.get("reject-reason"))
        rt.cli("sendrawtransaction", root["tx"])
        rt.mine(1)
        check(slice1.chain_tx(rt, root["txid"]).get("confirmations", 0) >= 1, "the root kickoff is confirmed")
        for x in of["spend"]:
            a = accept(rt, x["tx"])
            check(not a.get("allowed") and "non-final" in str(a.get("reject-reason")),
                  "the node refuses the spend of node %s before height %s: %s" % (x["node"], x["locktime"],
                                                                               a.get("reject-reason")))

        # 2. An owed member below an output: refused.
        rc, ow = tool(w, fresh_copy(w, 3), max(locks), "--test-owed", "1")
        owed = [x for x in ow["refused"] if x["why"] == "owed"]
        check(len(owed) == 1 and owed[0]["member"] == "1", "with member 1 owed, its output is refused")
        check(len(ow["spend"]) == len(kids) - 1, "and only the others are built")

        # 3. At the heights: accepted, mined, every satoshi accounted for.
        while rt.cli("getblockcount") < max(locks):
            rt.mine(min(50, max(locks) - rt.cli("getblockcount")))
        rc, oa = tool(w, fresh_copy(w, 4), rt.cli("getblockcount"))
        check(rc == 0 and not oa["refused"] and len(oa["spend"]) == len(kids), "at the heights the tool builds every spend")
        ok = True
        for x in oa["spend"]:
            a = accept(rt, x["tx"])
            ok = ok and a.get("allowed")
            if a.get("allowed"):
                rt.cli("sendrawtransaction", x["tx"])
        check(ok, "the node accepts every spend")
        rt.mine(1)
        rtx = slice1.chain_tx(rt, root["txid"])
        outs = [round(v["value"] * 1e8) for v in rtx["vout"]]
        amount = int(rnd["amount"])
        root_fee = amount - sum(outs)
        swept = sum(int(x["out"]) for x in oa["spend"])
        fees = sum(int(x["fee"]) for x in oa["spend"])
        anchors = sum(v for i, v in enumerate(outs) if i not in [int(k["vout"]) for k in kids])
        check(amount == root_fee + anchors + fees + swept,
              "every satoshi: %d = root fee %d + anchor %d + spends' fees %d + to the host %d"
              % (amount, root_fee, anchors, fees, swept))
        check(root_fee >= int(root["vsize"]) * 0.1 and root_fee < int(root["vsize"]) * 0.2 + 2 and
              all(int(x["fee"]) >= int(x["vsize"]) * 0.1 and int(x["fee"]) < int(x["vsize"]) * 0.2 + 2 for x in oa["spend"]),
              "every fee at 0.1 sat/vB")
        paid = []
        for x in oa["spend"]:
            d = rt.cli("decoderawtransaction", x["tx"])
            st = slice1.chain_tx(rt, d["txid"])
            paid.append(st.get("confirmations", 0) >= 1 and d["vout"][0]["scriptPubKey"]["hex"] == host_spk)
        check(paid and all(paid), "every spend is mined and pays the host's first receive address")

        # 4. Nothing else: no other tree transaction on chain; each root output spent by the host's spend only.
        others = [x for i, x in tree.items() if i != 0 and slice1.chain_tx(rt, x["txid"])]
        check(not others, "no other tree transaction (no member's path) was published")
        spenders = {}
        for x in oa["spend"]:
            d = rt.cli("decoderawtransaction", x["tx"])
            spenders[int(x["vout"])] = d["txid"]
        good = True
        for k in kids:
            r = rt.esplora("/tx/%s/outspend/%s" % (root["txid"], k["vout"]))
            good = good and ('"spent":true' in r.replace(" ", "")) and spenders.get(int(k["vout"]), "?") in r
        check(good, "each root output is spent by the host's timeout spend, nothing else")

        # 5. The funding's change (the wallet's first change, index 0 since #91), spent whole to the first address.
        ftx = slice1.chain_tx(rt, funding_txid) if funding_txid else {}
        ch = [v for v in ftx.get("vout", []) if v["n"] != 0]
        if check(len(ch) == 1, "the funding has one change output"):
            c = ch[0]
            spec = "%s:%d:%d:%s" % (ftx["txid"], c["n"], round(c["value"] * 1e8), c["scriptPubKey"]["hex"])
            a = w.args("host", "host")
            a[a.index("--data-dir") + 1] = fresh_copy(w, 5)
            a += ["--test-spend-coin", spec, "--test-passphrase-file", passphrase_file(), "--test-kdf-floor"]
            r = subprocess.run(a, capture_output=True, text=True, timeout=120)
            m = re.search(r"spend-coin change=(\d+) index=(\d+)", r.stdout)
            check(m is not None and m.group(1) == "1" and m.group(2) == "0",
                  "the tool finds the coin at change index 0 (%s)" % (m.group(0) if m else r.stdout[-200:]))
            m = re.search(r"spend-tx amount=(\d+) fee=(\d+) out=(\d+) vsize=(\d+) tx=([0-9a-f]+)", r.stdout)
            if check(m is not None, "and builds the spend"):
                amt, fee, out, vs, txh = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), m.group(5)
                acc = accept(rt, txh)
                check(acc.get("allowed"), "the node accepts it: %s" % acc.get("reject-reason"))
                rt.cli("sendrawtransaction", txh)
                rt.mine(1)
                d = rt.cli("decoderawtransaction", txh)
                check(slice1.chain_tx(rt, d["txid"]).get("confirmations", 0) >= 1 and
                      d["vout"][0]["scriptPubKey"]["hex"] == host_spk and len(d["vout"]) == 1 and
                      amt == out + fee and fee >= vs * 0.1 and fee < vs * 0.2 + 2,
                      "mined, all of it to the first address less %d sat (%d vB, 0.1 sat/vB)" % (fee, vs))
            other = "%s:%d:%d:%s" % (ftx["txid"], c["n"], 1000, rt.cli("-rpcwallet=miner", "getaddressinfo",
                                                                    rt.cli("-rpcwallet=miner", "getnewaddress", "",
                                                                           "bech32m"))["scriptPubKey"])
            a[a.index("--test-spend-coin") + 1] = other
            a[a.index("--data-dir") + 1] = fresh_copy(w, 6)
            r = subprocess.run(a, capture_output=True, text=True, timeout=120)
            check("spend-refused why=not-this-wallet" in r.stdout and "spend-tx" not in r.stdout,
                  "a coin of another wallet is refused")
    finally:
        w.stop()
        kill_all(w.procs)
        rt.stop()
    return check.result("program_sweep", work)


if __name__ == "__main__":
    sys.exit(main())
