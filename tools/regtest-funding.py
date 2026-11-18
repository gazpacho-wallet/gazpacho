#!/usr/bin/env python3
"""Regtest run of the funding engine (step P4.5) against Bitcoin Core.

Starts its own regtest bitcoind (never the signet service): its own data
folder, RPC on 127.0.0.1, listen=0, stopped at the end. Drives
gz-funding-harness (the real engine over the real wallet) and relays its
broadcasts and watches to the node.

  A  a 0.1 sat/vB funding (version 2, not TRUC) is accepted alone, and buried:
     the engine reports Live;
  B  the funding stays in the mempool past the host's deadline (empty blocks):
     the spend-back at the minimum replacement fee replaces it, is buried, and
     the engine ends Dead;
  C  a node whose increment is 1 sat/vB (Core 28.x and 29.0) refuses that
     spend-back; the engine escalates once and the node accepts it.

usage: tools/regtest-funding.py BITCOIN_BIN_DIR HARNESS [--port N] [--keep]
Standard library only. Exits 0 if every scenario passed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BIN, HARNESS = sys.argv[1], sys.argv[2]
PORT = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 18990
FACTORY = "5120" + "ab" * 32


def rev(h):
    return bytes.fromhex(h)[::-1].hex()


class Node:
    def __init__(self, extra):
        self.dir = tempfile.mkdtemp(prefix="gz-p45-regtest-")
        args = [os.path.join(BIN, "bitcoind"), "-regtest", "-datadir=" + self.dir, "-listen=0",
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % PORT, "-txindex=1",
                "-fallbackfee=0.0001", "-daemon=0", "-printtoconsole=0", "-server=1"] + extra
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.5)
        raise SystemExit("bitcoind did not start")

    def rpc(self, method, *params):
        cmd = [os.path.join(BIN, "bitcoin-cli"), "-regtest", "-datadir=" + self.dir, "-rpcport=%d" % PORT,
               "-rpcconnect=127.0.0.1", method] + [p if isinstance(p, str) else json.dumps(p) for p in params]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except ValueError:
            return out

    def stop(self):
        try:
            self.rpc("stop")
            self.proc.wait(timeout=60)
        except Exception:
            self.proc.kill()
        if "--keep" not in sys.argv:
            shutil.rmtree(self.dir, ignore_errors=True)


class Harness:
    def __init__(self):
        self.p = subprocess.Popen([HARNESS], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def say(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        out = []
        while True:
            l = self.p.stdout.readline()
            if not l:
                raise SystemExit("harness died after: " + line[:60])
            l = l.strip()
            if l == "ok":
                return out
            out.append(l)

    def close(self):
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
        except Exception:
            pass
        self.p.wait(timeout=10)


class Run:
    """One engine, one node: relays actions and reports chain facts."""

    def __init__(self, node, h):
        self.n, self.h = node, h
        self.watch_tx, self.watch_op = set(), set()
        self.known = {}       # txid (internal) -> raw hex of what we broadcast
        self.seen = {}        # fact key -> last value reported
        self.saves, self.reports, self.broadcasts = [], [], []

    def act(self, lines):
        for l in lines:
            w = l.split()
            if w[0] == "broadcast":
                self.broadcasts.append(w[1])
                dec = self.n.rpc("decoderawtransaction", w[1])
                txid = rev(dec["txid"])
                self.known[txid] = w[1]
                try:
                    self.n.rpc("sendrawtransaction", w[1])
                    res = "ok"
                except RuntimeError as e:
                    print("  refused:", str(e)[:120])
                    res = "refused"
                self.act(self.h.say("bres %s %s" % (txid, res)))
            elif w[0] == "watch_tx":
                self.watch_tx.add(w[1])
            elif w[0] == "watch_op":
                self.watch_op.add((w[1], int(w[2])))
            elif w[0] == "save":
                self.saves.append(int(w[1]))
            elif w[0] == "report":
                self.reports.append(int(w[1]))

    def conf_of(self, txid):
        try:
            t = self.n.rpc("getrawtransaction", rev(txid), True)
        except RuntimeError:
            return None
        if "confirmations" in t:
            return t["confirmations"], self.n.rpc("getblock", t["blockhash"])["height"]
        mp = self.n.rpc("getrawmempool")
        return (0, 0) if rev(txid) in mp else None

    def facts(self):
        for txid in list(self.watch_tx):
            c = self.conf_of(txid)
            v = c[0] if c else 0
            if self.seen.get(("tx", txid), 0) != v:
                self.seen[("tx", txid)] = v
                self.act(self.h.say("conf %s %d %d" % (txid, v, c[1] if c else 0)))
        for (op, vout) in list(self.watch_op):
            for txid, raw in self.known.items():
                dec = self.n.rpc("decoderawtransaction", raw)
                if not any(rev(i["txid"]) == op and i["vout"] == vout for i in dec["vin"]):
                    continue
                c = self.conf_of(txid)
                if c is None:
                    continue
                key = ("op", op, vout, txid)
                if self.seen.get(key) != c[0]:
                    self.seen[key] = c[0]
                    self.act(self.h.say("spent %s %d %s %d" % (op, vout, txid, c[0])))

    def tip(self):
        height = self.n.rpc("getblockcount")
        self.act(self.h.say("tip %d" % height))
        self.facts()
        self.act(self.h.say("synced %d" % height))   # every fact for this tip told (B12)
        for _ in range(4):
            self.act(self.h.say("tick"))
            self.facts()

    def mine(self, k, empty=False):
        addr = self.n.rpc("getnewaddress") if self.n.rpc("listwallets") else None
        for _ in range(k):
            if empty:
                self.n.rpc("generateblock", "raw(51)", [])
            else:
                self.n.rpc("generatetodescriptor", 1, "raw(51)")
            self.tip()
        return addr


def fund_coins(node, h, n=3):
    scripts = [l.split()[2] for l in h.say("scripts %d" % n)]
    for s in scripts:
        node.rpc("generatetodescriptor", 1, "raw(%s)" % s)
    node.rpc("generatetodescriptor", 101, "raw(51)")
    height = node.rpc("getblockcount")
    for i, s in enumerate(scripts):
        blk = node.rpc("getblock", node.rpc("getblockhash", height - 101 - (n - 1 - i)), 2)
        cb = blk["tx"][0]
        h.say("coin %s 0 %d %d" % (rev(cb["txid"]), round(cb["vout"][0]["value"] * 1e8), i))


def scenario(name, extra, body):
    print("== %s" % name)
    node = Node(extra)
    h = Harness()
    try:
        info = node.rpc("getnetworkinfo")
        print("  node %s relayfee %s incrementalfee %s" % (info["subversion"], info["relayfee"], info["incrementalfee"]))
        fund_coins(node, h)
        r = Run(node, h)
        r.tip()
        body(node, h, r)
        print("  PASS")
        return True
    except (AssertionError, RuntimeError) as e:
        print("  FAIL:", e)
        return False
    finally:
        h.close()
        node.stop()


def plan_and_fund(node, h, r, amount=100000):
    p = h.say("plan %d %s" % (amount, FACTORY))
    assert p[0].startswith("plan ok"), p
    r.act(h.say("fund"))
    assert r.broadcasts, "no funding broadcast"
    fund_txid = rev(node.rpc("decoderawtransaction", r.broadcasts[0])["txid"])
    entry = node.rpc("getmempoolentry", rev(fund_txid))
    rate = entry["fees"]["base"] * 1e8 / entry["vsize"]
    print("  funding %d vB, fee %d sat, %.3f sat/vB, version %d" % (
        entry["vsize"], round(entry["fees"]["base"] * 1e8), rate,
        node.rpc("decoderawtransaction", r.broadcasts[0])["version"]))
    assert 0.1 <= rate < 0.11, "not 0.1 sat/vB"
    return fund_txid


def a_live(node, h, r):
    fund_txid = plan_and_fund(node, h, r)
    r.mine(3)
    assert 1 in r.reports, "no Live report: %s" % r.reports
    assert r.saves[-1] == 4, r.saves
    assert node.rpc("getrawtransaction", rev(fund_txid), True)["confirmations"] >= 3


def spend_backs(node, r, fund_txid):
    """The distinct transactions broadcast other than the funding (which is
    broadcast again at every tip while it is not buried)."""
    out = []
    for raw in r.broadcasts:
        d = node.rpc("decoderawtransaction", raw)
        if rev(d["txid"]) != fund_txid and d["txid"] not in [x["txid"] for x in out]:
            out.append(d)
    return out


def b_spend_back(node, h, r):
    fund_txid = plan_and_fund(node, h, r)
    r.facts()
    r.mine(36, empty=True)   # the funding left in the mempool, to the deadline (tip at the plan + 36)
    assert not spend_backs(node, r, fund_txid), "spend-back before the deadline"
    r.mine(2, empty=True)    # past it
    assert 3 in r.reports, "no Abandoned report: %s" % r.reports
    sbs = spend_backs(node, r, fund_txid)
    assert len(sbs) == 1, "spend-backs: %d" % len(sbs)
    sb = sbs[0]
    assert len(sb["vin"]) == 1 and len(sb["vout"]) == 1 and sb["vout"][0]["scriptPubKey"]["hex"] != FACTORY
    mp = node.rpc("getrawmempool")
    assert rev(fund_txid) not in mp and sb["txid"] in mp, "the spend-back did not replace the funding"
    e = node.rpc("getmempoolentry", sb["txid"])
    print("  spend-back %d vB, fee %d sat (replaces the funding)" % (e["vsize"], round(e["fees"]["base"] * 1e8)))
    r.mine(3)
    assert r.saves[-1] == 6, "not Dead: %s" % r.saves


def c_escalate(node, h, r):
    fund_txid = plan_and_fund(node, h, r)
    r.facts()
    r.mine(40, empty=True)
    sbs = spend_backs(node, r, fund_txid)
    assert len(sbs) == 2, "spend-backs: %d (want the refused one and the escalated one)" % len(sbs)
    mp = node.rpc("getrawmempool")
    sb = sbs[-1]
    e = node.rpc("getmempoolentry", sb["txid"])
    print("  escalated spend-back %d vB, fee %d sat" % (e["vsize"], round(e["fees"]["base"] * 1e8)))
    assert sb["txid"] in mp and rev(fund_txid) not in mp
    r.mine(3)
    assert r.saves[-1] == 6, r.saves


def d_h11(node, h, r):
    """H11: after a release the new plan spends input 0 of the previous one."""
    p1 = h.say("plan %d %s" % (100000, FACTORY))
    assert p1[0].startswith("plan ok"), p1
    first = node.rpc("decoderawtransaction", p1[0].split()[2])
    p2 = h.say("replan %d %s" % (100000, FACTORY))
    assert p2[0].startswith("plan ok"), p2
    second = node.rpc("decoderawtransaction", p2[0].split()[2])
    assert first["txid"] != second["txid"], "the same funding outpoint after a release"
    v0, w0 = first["vin"][0], second["vin"][0]
    assert (v0["txid"], v0["vout"]) == (w0["txid"], w0["vout"]), "input 0 not reused"
    print("  new plan spends the old input 0, %d inputs" % len(second["vin"]))
    r.act(h.say("fund"))
    fund_txid = rev(second["txid"])
    assert node.rpc("getmempoolentry", second["txid"])
    r.mine(3)
    assert 1 in r.reports, r.reports


ok = scenario("A: funding at 0.1 sat/vB, buried, Live", [], a_live)
ok &= scenario("B: abandoned, spend-back replaces the funding, Dead", [], b_spend_back)
ok &= scenario("C: a 1 sat/vB increment refuses, the engine escalates", ["-incrementalrelayfee=0.00001", "-minrelaytxfee=0.000001"], c_escalate)
ok &= scenario("D: H11, a new plan after a release reuses input 0, buried", [], d_h11)
print("regtest-funding:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
