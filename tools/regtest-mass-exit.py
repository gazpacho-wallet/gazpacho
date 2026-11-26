#!/usr/bin/env python3
"""Every member of a large factory exits at once, on a real regtest node (R6).

The Slice 1.5 plan's P8 (docs/SLICE-1.5-PLAN.md, test R6, the risk U-3): a
factory of N members (128 and 512 in the nightly run; 4 and 16 to prove the
harness) is built and signed by tests/regtest/tree_massexit with the core in
one process, funded on a node this tool starts, and then every member
publishes its own exit path at the same time, from its own thread, against a
mempool kept full of other traffic. It checks, against the node:

  1. every tree transaction is version 3 with its 240-sat P2A anchor last and
     is mined, one level after another, each in a one-parent-one-child
     package with a child on its anchor;
  2. siblings publishing the same shared step at the same moment never
     conflict: every member sends the identical package for a shared step, so
     the second copy is "already in the mempool", never a replacement;
  3. every path confirms, and the amounts are right: each tree transaction
     on chain pays exactly the outputs the tree was signed with, every
     interior output and every anchor is spent by the tree, each member's
     channel output is unspent on chain with its own amount and script, and
     the funding amount = the leaves' outputs + every tree fee + every
     anchor, to the satoshi;
  4. no step is refused for any reason but "already there".

The full mempool: the node runs with -maxmempool (5 MB by default) and,
before each round of publishing, the tool fills it with its own large
transactions at --fill sat/vB until the node refuses one for the mempool's
own minimum: the mempool is full, has evicted, and its minimum fee is above
the filler's rate (the run fails if it never gets there).
A tree transaction pays 0.1 sat/vB (T1's 100 sat/kvB), so against a full
mempool its anchor child must pay: with --bump wallet (the default when
filling) the child spends a test coin of the node's wallet and brings the
package to --package-rate sat/vB; with --bump anchor it is exit.md 6.2's
65-byte anchor-only child, which pays nothing (use it with --fill 0).

THE EXIT ENGINE HOOK. Which step a member publishes next is decided by an
engine (--engine). Today the only one is "raw": the first step of the
member's path not yet confirmed, published as soon as its parent is
confirmed and its relative and absolute locks allow, with the harness's own
child. The exit engine of Slice 1.5's P3 (branch slice15-p3-exit) replaces
it: class RawEngine below is the interface it plugs into (next_step and
child_for), and a P3 engine also decides the child and its fee. The ledger
check of P1 (tools/chain-ledger.py) reads the report this tool writes
(--out DIR/mass-exit.json: the funding, every tree txid with its height,
every member's channel output); until P1 lands, step 3 above is this tool's
own total check.

It starts its own regtest bitcoind (own datadir, own RPC port on 127.0.0.1,
-listen=0, no peers), runs, and stops it. Regtest only: it refuses any other
chain. THE KEYS ARE TEST KEYS.

usage: tools/regtest-mass-exit.py BITCOIND_BIN_DIR DATADIR TREE_MASSEXIT --members N
           [--shape S] [--rate SATKVB] [--fill SATVB] [--maxmempool MB]
           [--bump wallet|anchor] [--package-rate SATVB] [--engine raw]
           [--threads T] [--port P] [--out DIR] [--max-rounds R] [--seed X]
  BITCOIND_BIN_DIR  holds bitcoind (29.1 or later)
  DATADIR           a fresh directory; created; never a live node's
  TREE_MASSEXIT     the built tests/regtest/tree_massexit
  --shape           interior widths from the root, e.g. 8,4 (default by N:
                    ps up to 4, 4 up to 16, 8 up to 64, 8,4 up to 128,
                    15,4 up to 256, 15,15 above)
  --fill            filler rate in sat/vB; 0 = no filler (default 2)
"""
import base64
import hashlib
import http.client
import json
import math
import os
import random
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

P2A = "51024e73"
ANCHOR_SAT = 240
P2WSH_TRUE = "0020" + hashlib.sha256(b"\x51").hexdigest()   # the filler's outputs: standard, nobody's coins
WALLET = "gz-massexit"
FILLER_OUTPUTS = 1500                                         # about 64.6 kvB a filler transaction
FILLER_VSIZE = 10 + 1 + 41 + 3 + FILLER_OUTPUTS * 43 + 31 + 28  # an upper bound, so the rate is at least --fill
FILLER_COIN = 1_000_000
BUMP_COIN = 50_000
CHILD_VSIZE = 156                                             # anchor + P2WPKH in, P2WPKH out (an upper bound)
ALREADY = ("txn-already-in-mempool", "txn-already-known", "already in")


def default_shape(n):
    if n <= 4:
        return "ps"
    if n <= 16:
        return "4"
    if n <= 64:
        return "8"
    if n <= 128:
        return "8,4"
    if n <= 256:
        return "15,4"
    return "15,15"


# ------------------------------------------------------------------ the node

class Node:
    def __init__(self, bindir, datadir, port, maxmempool):
        self.datadir, self.port = datadir, port
        self.local = threading.local()
        os.makedirs(datadir, exist_ok=True)
        args = [os.path.join(bindir, "bitcoind"), "-regtest", "-datadir=" + datadir, "-daemonwait",
                "-listen=0", "-connect=0", "-dnsseed=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                f"-rpcport={port}", "-minrelaytxfee=0.000001", "-fallbackfee=0.0001", "-txindex=0",
                f"-maxmempool={maxmempool}", "-rpcthreads=16", "-rpcworkqueue=512", "-printtoconsole=0"]
        subprocess.run(args, check=True)
        self.cookie = os.path.join(datadir, "regtest", ".cookie")
        for _ in range(100):
            if os.path.exists(self.cookie):
                break
            time.sleep(0.1)
        with open(self.cookie) as f:
            self.auth = base64.b64encode(f.read().strip().encode()).decode()
        if self.rpc("getblockchaininfo")["chain"] != "regtest":
            raise SystemExit("the node is not on regtest")

    def rpc(self, method, *params, wallet=None):
        """One call on this thread's own kept-alive connection."""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
        path = "/wallet/" + wallet if wallet else "/"
        for attempt in range(3):
            c = getattr(self.local, "conn", None)
            if c is None:
                c = self.local.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=600)
            try:
                c.request("POST", path, body, {"Authorization": "Basic " + self.auth,
                                               "Content-Type": "application/json"})
                r = json.loads(c.getresponse().read())
                break
            except (http.client.HTTPException, OSError):
                c.close()
                self.local.conn = None
                if attempt == 2:
                    raise
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]

    def w(self, method, *params):
        return self.rpc(method, *params, wallet=WALLET)

    def stop(self):
        try:
            self.rpc("stop")
        except Exception:
            pass
        for _ in range(300):
            if not os.path.exists(os.path.join(self.datadir, "regtest", "bitcoind.pid")):
                return
            time.sleep(0.1)


# --------------------------------------------------------- transaction bytes

def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def ser_tx(version, ins, outs, locktime=0):
    """No witness. ins: (txid in display order, vout, nSequence); outs: (sat, script hex)."""
    b = version.to_bytes(4, "little") + varint(len(ins))
    for txid, vout, seq in ins:
        b += bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little") + b"\x00" + seq.to_bytes(4, "little")
    b += varint(len(outs))
    for sat, script in outs:
        s = bytes.fromhex(script)
        b += sat.to_bytes(8, "little") + varint(len(s)) + s
    return (b + locktime.to_bytes(4, "little")).hex()


def anchor_only_child(parent_txid, anchor_vout):
    """exit.md 6.2: version 3, the parent's anchor, empty scriptSig, nSequence
    0xfffffffd, one zero-value OP_RETURN of three zero bytes, lock time 0."""
    tx = ser_tx(3, [(parent_txid, anchor_vout, 0xFFFFFFFD)], [(0, "6a03000000")])
    assert len(tx) == 130
    return tx


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{os.path.basename(cmd[0])} {cmd[1]} failed: {r.stderr.strip()}")
    return r.stdout


# ----------------------------------------------------------------- the wallet

class Coins:
    """Test coins of the node's wallet, made by one split, handed out once each."""

    def __init__(self, node):
        self.node = node
        self.script = node.w("getaddressinfo", node.w("getnewaddress"))["scriptPubKey"]
        self.bump, self.filler = [], []
        self.lock = threading.Lock()

    def split(self, n_bump, n_filler):
        for want, value, into in ((n_bump, BUMP_COIN, self.bump), (n_filler, FILLER_COIN, self.filler)):
            left = want
            while left > 0:
                k = min(left, 500)
                raw = ser_tx(2, [], [(value, self.script)] * k)
                fund = self.node.w("fundrawtransaction", raw, {"fee_rate": 1, "changePosition": k}, False)
                signed = self.node.w("signrawtransactionwithwallet", fund["hex"])
                txid = self.node.rpc("sendrawtransaction", signed["hex"])
                into.extend((txid, i, value) for i in range(k))
                left -= k

    def take(self, kind):
        with self.lock:
            pool = self.bump if kind == "bump" else self.filler
            if not pool:
                raise SystemExit(f"out of {kind} coins: raise the split in main()")
            return pool.pop()

    def sign(self, raw, prevtxs=()):
        r = self.node.w("signrawtransactionwithwallet", raw, list(prevtxs))
        # The P2A input needs no signature (an empty witness); the wallet may or
        # may not count it as solved. Anything else unsigned is an error.
        errs = [e for e in r.get("errors", []) if not any(e["txid"] == p["txid"] and e["vout"] == p["vout"]
                                                         for p in prevtxs)]
        if errs:
            raise SystemExit(f"the wallet could not sign: {errs}")
        return r["hex"]


# ---------------------------------------------------------- the full mempool

class Filler:
    """Keeps the mempool full of the harness's own traffic at a fixed rate."""

    def __init__(self, node, coins, rate):
        self.node, self.coins, self.rate = node, coins, rate
        self.sent = 0

    def fill(self, cap=120):
        """Add filler until the node refuses one for its own minimum: it is
        full, has evicted, and its minimum is now above the filler's rate."""
        made, why = 0, "cap"
        for _ in range(cap):
            txid, vout, value = self.coins.take("filler")
            fee = math.ceil(self.rate * FILLER_VSIZE)
            change = value - FILLER_OUTPUTS * 330 - fee
            raw = ser_tx(2, [(txid, vout, 0xFFFFFFFD)], [(330, P2WSH_TRUE)] * FILLER_OUTPUTS + [(change, self.coins.script)])
            try:
                self.node.rpc("sendrawtransaction", self.coins.sign(raw), 0)
            except RuntimeError as e:
                if "mempool min fee not met" in str(e) or "mempool full" in str(e):
                    why = "minfee"           # full: the node now evicts below its rising minimum
                    break
                raise
            made += 1
        self.sent += made
        return made, why


# ------------------------------------------------------------------- the tree

class Tree:
    def __init__(self, out):
        self.nodes, self.members = [], []
        for line in out.splitlines():
            w = line.split()
            if not w:
                continue
            if w[0] == "node":
                d = dict(zip(w[0::2], w[1::2]))
                nd = {k: int(d[k]) for k in ("node", "parent", "vout", "type", "signers", "seq", "in", "fee", "anchor")}
                nd["txid"], nd["tx"] = d["txid"], d["tx"]
                nd["outs"] = [(int(a), s) for a, s in (o.split(":") for o in d["outs"].split(","))]
                nd["locktime"] = int.from_bytes(bytes.fromhex(d["tx"][-8:]), "little")
                self.nodes.append(nd)
            elif w[0] == "member":
                d = dict(zip(w[0::2], w[1::2]))
                self.members.append({"member": int(d["member"]), "leaf": int(d["leaf"]),
                                     "channel": int(d["channel"]), "script": d["script"]})
        for m in self.members:
            path, i = [], m["leaf"]
            while i >= 0:
                path.append(i)
                i = self.nodes[i]["parent"]
            m["path"] = path[::-1]


class RawEngine:
    """The harness's own exit decisions: the hook P3's exit engine replaces.

    next_step(member, chain) -> node index to publish now, or None (the path
    is done, or its next step is not yet allowed); wait_until(member, chain)
    -> the lowest tip at which next_step can return a step; child_for(node)
    -> the child on that step's anchor, the same bytes for every member."""

    def __init__(self, tree, coins, bump, package_rate):
        self.tree, self.coins, self.bump, self.rate = tree, coins, bump, package_rate
        self.children, self.lock = {}, threading.Lock()

    def first_missing(self, m, chain):
        for i in m["path"]:
            if self.tree.nodes[i]["txid"] not in chain.height:
                return i
        return None

    def ready_tip(self, i, chain):
        """The lowest tip at which node i may enter the mempool, or None while its parent is unconfirmed."""
        nd = self.tree.nodes[i]
        parent = chain.funding if nd["parent"] < 0 else self.tree.nodes[nd["parent"]]["txid"]
        if parent not in chain.height:
            return None
        need = chain.height[parent]                     # in the mempool from the tip of the parent's block
        if not nd["seq"] & (1 << 31):
            if nd["seq"] & (1 << 22):
                raise SystemExit(f"node {i}: a time-based relative lock; regtest heights only")
            need = max(need, chain.height[parent] + (nd["seq"] & 0xFFFF) - 1)
        if nd["seq"] != 0xFFFFFFFF and 0 < nd["locktime"] < 500_000_000:
            need = max(need, nd["locktime"])             # final in the block after the tip
        return need

    def next_step(self, m, chain):
        i = self.first_missing(m, chain)
        if i is None:
            return None
        t = self.ready_tip(i, chain)
        return i if t is not None and chain.tip >= t else None

    def wait_until(self, m, chain):
        i = self.first_missing(m, chain)
        return None if i is None else self.ready_tip(i, chain)

    def child_for(self, i, node):
        with self.lock:
            if i in self.children:
                return self.children[i]
            nd = self.tree.nodes[i]
            if self.bump == "anchor":
                child = anchor_only_child(nd["txid"], nd["anchor"])
            else:
                fee = max(math.ceil(self.rate * (nd["vsize"] + CHILD_VSIZE)) - nd["fee"], math.ceil(self.rate * CHILD_VSIZE))
                txid, vout, value = self.coins.take("bump")
                raw = ser_tx(3, [(nd["txid"], nd["anchor"], 0xFFFFFFFD), (txid, vout, 0xFFFFFFFD)],
                             [(value + ANCHOR_SAT - fee, self.coins.script)])
                child = self.coins.sign(raw, [{"txid": nd["txid"], "vout": nd["anchor"], "scriptPubKey": P2A,
                                               "amount": ANCHOR_SAT / 1e8}])
            self.children[i] = child
            return child


ENGINES = {"raw": RawEngine}


class Chain:
    """What the harness knows of the chain: each confirmed txid's height."""

    def __init__(self, node, funding):
        self.node, self.funding = node, funding
        self.height, self.block = {}, {}
        self.tip = node.rpc("getblockcount")

    def mine(self, k, addr, watch):
        """Mine k blocks; record the heights of the watched txids they hold."""
        hashes = self.node.rpc("generatetoaddress", k, addr)
        for h in hashes:
            blk = self.node.rpc("getblock", h, 1)
            for txid in blk["tx"]:
                if txid in watch:
                    self.height[txid], self.block[txid] = blk["height"], h
        self.tip = self.node.rpc("getblockcount")
        return hashes


# ------------------------------------------------------------------ the run

def main():
    a = sys.argv[1:]
    if len(a) < 3 or "--members" not in a:
        sys.exit(__doc__)
    bindir, datadir, tool = a[0], a[1], a[2]

    def opt(name, default):
        return a[a.index(name) + 1] if name in a else default

    n = int(opt("--members", "4"))
    shape = opt("--shape", default_shape(n))
    rate = int(opt("--rate", "100"))
    fill_rate = float(opt("--fill", "2"))
    maxmempool = int(opt("--maxmempool", "5"))
    bump = opt("--bump", "wallet" if fill_rate > 0 else "anchor")
    package_rate = float(opt("--package-rate", str(max(1.0, 2 * fill_rate + 1))))
    engine_name = opt("--engine", "raw")
    threads = int(opt("--threads", "32"))
    port = int(opt("--port", "18998"))
    out = opt("--out", "")
    max_rounds = int(opt("--max-rounds", "60"))
    rng = random.Random(int(opt("--seed", "1")))
    if bump not in ("wallet", "anchor") or engine_name not in ENGINES:
        sys.exit("--bump is wallet or anchor; --engine is " + " or ".join(ENGINES))
    if bump == "anchor" and fill_rate > 0:
        sys.exit("an anchor-only child pays nothing: it cannot enter a full mempool (use --bump wallet, or --fill 0)")
    if os.path.exists(os.path.join(datadir, "regtest")):
        sys.exit("DATADIR already holds a regtest chain: give a fresh directory")
    started = time.time()
    print(run([os.path.join(bindir, "bitcoind"), "-version"]).splitlines()[0])

    p = run([tool, "params", str(n), str(rate), shape]).split()
    amount, script, n_nodes = int(p[p.index("funding") + 1]), p[p.index("script") + 1], int(p[p.index("nodes") + 1])
    print(f"R6: {n} members, levels {p[1]} (D {p[3]}), {n_nodes} tree transactions, R(root) {amount} sat, "
          f"tree rate {rate} sat/kvB; the rules' byte-for-byte check: {p[p.index('rules') + 1]}")
    print(f"mempool: -maxmempool={maxmempool} MB, " + (f"kept full at {fill_rate} sat/vB" if fill_rate else "no filler")
          + f"; children: {bump}" + (f" at {package_rate} sat/vB a package" if bump == "wallet" else "")
          + f"; engine: {engine_name}; {threads} publishing threads")

    node = Node(bindir, datadir, port, maxmempool)
    report = {"members": n, "shape": p[1], "nodes": n_nodes, "funding_amount": amount, "rounds": []}
    try:
        node.rpc("createwallet", WALLET)
        addr = node.w("getnewaddress")
        node.rpc("generatetoaddress", 200, addr)
        coins = Coins(node)

        # The funding, and the test coins for the children and the filler.
        fund_addr = node.rpc("deriveaddresses", node.rpc("getdescriptorinfo", f"rawtr({script[4:]})")["descriptor"])[0]
        ftxid = node.w("sendtoaddress", fund_addr, f"{amount / 1e8:.8f}")
        coins.split(n_nodes + 16 if bump == "wallet" else 0, 900 if fill_rate else 0)
        node.rpc("generatetoaddress", 1, addr)
        ftx = node.rpc("getrawtransaction", ftxid, True, node.rpc("getbestblockhash"))
        vout = next(o["n"] for o in ftx["vout"] if o["scriptPubKey"]["hex"] == script)
        tip = node.rpc("getblockcount")
        E = tip + 144 + 36
        print(f"funding {ftxid}:{vout} confirmed at {tip}; end height E = {E}")

        t0 = time.time()
        tree = Tree(run([tool, "build", str(n), str(rate), shape, ftxid, str(vout), str(amount), str(E)]))
        print(f"built, signed and checked in {time.time() - t0:.1f} s: {len(tree.nodes)} transactions, {len(tree.members)} members")
        if len(tree.nodes) != n_nodes or len(tree.members) != n:
            sys.exit("the build's counts differ from its parameters")
        for nd in tree.nodes:
            dec = node.rpc("decoderawtransaction", nd["tx"])
            if dec["version"] != 3 or dec["txid"] != nd["txid"] or dec["vout"][-1]["scriptPubKey"]["hex"] != P2A \
                    or round(dec["vout"][-1]["value"] * 1e8) != ANCHOR_SAT:
                sys.exit(f"node {nd['node']}: not version 3 with its P2A anchor last, or not the txid printed")
            nd["vsize"] = dec["vsize"]
        depths = [len(m["path"]) for m in tree.members]
        print(f"paths: {min(depths)} to {max(depths)} transactions; widest transaction {max(len(nd['outs']) for nd in tree.nodes)} outputs")

        chain = Chain(node, ftxid)
        chain.height[ftxid] = tip
        engine = ENGINES[engine_name](tree, coins, bump, package_rate)
        filler = Filler(node, coins, fill_rate) if fill_rate else None
        watch = {nd["txid"] for nd in tree.nodes}
        refused, published, dup, rnd = {}, 0, 0, 0
        pool = ThreadPoolExecutor(max_workers=threads)

        def publish(m, i):
            nd = tree.nodes[i]
            try:
                r = node.rpc("submitpackage", [nd["tx"], engine.child_for(i, node)])
            except RuntimeError as e:
                return m["member"], i, "error", str(e)
            if r.get("package_msg") == "success":
                return m["member"], i, "ok", ""
            errs = [v.get("error", "") for v in r.get("tx-results", {}).values() if v.get("error")]
            if errs and all(any(x in e for x in ALREADY) for e in errs):
                return m["member"], i, "ok", "already"
            return m["member"], i, "refused", "; ".join(errs) or r.get("package_msg", "?")

        while True:
            todo = [m for m in tree.members if tree.nodes[m["leaf"]]["txid"] not in chain.height]
            if not todo:
                break
            rnd += 1
            if rnd > max_rounds:
                sys.exit(f"{len(todo)} paths still open after {max_rounds} rounds")
            steps = [(m, engine.next_step(m, chain)) for m in todo]
            steps = [(m, i) for m, i in steps if i is not None]
            if not steps:
                # Every open path waits on a lock: mine to the first tip that frees one.
                waits = [engine.wait_until(m, chain) for m in todo]
                waits = [t for t in waits if t is not None]
                if not waits:
                    sys.exit("open paths, none waiting on a lock and none ready: a step is missing")
                k = max(1, min(waits) - chain.tip)
                chain.mine(k, addr, watch)
                print(f"round {rnd}: every open path waits on a lock; mined {k} blocks to tip {chain.tip}")
                report["rounds"].append({"round": rnd, "mined": k, "tip": chain.tip})
                continue
            made, why = filler.fill() if filler else (0, "-")
            before = node.rpc("getmempoolinfo")
            if filler and (why != "minfee" or before["mempoolminfee"] * 1e5 <= fill_rate):
                sys.exit(f"the mempool is not full: the filler stopped ({why}) with the minimum at "
                         f"{before['mempoolminfee'] * 1e5:.2f} sat/vB, not above the filler's {fill_rate}")
            # Children first (the wallet is one), then every member at once, in a random order.
            for i in {i for _, i in steps}:
                engine.child_for(i, node)
            rng.shuffle(steps)
            results = list(pool.map(lambda s: publish(*s), steps))
            per_step = {}
            for member, i, status, why_r in results:
                per_step.setdefault(i, []).append(status)
                if status != "ok":
                    refused.setdefault(why_r, []).append((member, i))
            published += len(results)
            dup += sum(len(v) - 1 for v in per_step.values())
            bad = [r for r in results if r[2] != "ok"]
            chain.mine(1, addr, watch)
            confirmed = sum(1 for i in per_step if tree.nodes[i]["txid"] in chain.height)
            print(f"round {rnd}: mempool {before['size']} txs, {before['bytes']} vB, usage {before['usage']}/{before['maxmempool']},"
                  f" min fee {before['mempoolminfee'] * 1e5:.2f} sat/vB (filler +{made}, {why}); {len(steps)} members published"
                  f" {len(per_step)} steps ({len(results) - len(per_step)} shared copies), {len(bad)} refused;"
                  f" block {chain.tip}: {confirmed} of those steps mined")
            report["rounds"].append({"round": rnd, "tip": chain.tip, "mempool": before, "filler_added": made,
                                     "members_published": len(steps), "steps": len(per_step), "refused": len(bad),
                                     "steps_mined": confirmed})
            for r in bad[:5]:
                print(f"  refused: member {r[0]} node {r[1]}: {r[3]}")
            if bad:
                sys.exit("a step was refused; R6 requires none (see above)")
        pool.shutdown()
        print(f"every path confirmed after {rnd} rounds, at tip {chain.tip}: {published} publications,"
              f" {dup} of them a sibling's identical copy of a shared step, none refused")

        # ---- The amounts, from the chain.
        total_leaf, total_fee = 0, 0
        leaves = {m["leaf"] for m in tree.members}
        for nd in tree.nodes:
            tx = node.rpc("getrawtransaction", nd["txid"], True, chain.block[nd["txid"]])
            got = [(round(o["value"] * 1e8), o["scriptPubKey"]["hex"]) for o in tx["vout"]]
            if got != nd["outs"]:
                sys.exit(f"node {nd['node']}: the outputs on chain are not the signed tree's")
            spent = ftxid if nd["parent"] < 0 else tree.nodes[nd["parent"]]["txid"]
            if tx["vin"][0]["txid"] != spent or tx["vin"][0]["vout"] != (vout if nd["parent"] < 0 else nd["vout"]):
                sys.exit(f"node {nd['node']}: does not spend its parent's output")
            fee = nd["in"] - sum(a for a, _ in got)
            if fee != nd["fee"]:
                sys.exit(f"node {nd['node']}: fee {fee} on chain, {nd['fee']} signed")
            total_fee += fee
            for k, (amt, _) in enumerate(got):
                left = node.rpc("gettxout", nd["txid"], k)
                is_leaf_out = nd["node"] in leaves and k != nd["anchor"]
                if is_leaf_out:
                    total_leaf += amt
                    if left is None or round(left["value"] * 1e8) != amt:
                        sys.exit(f"node {nd['node']} output {k}: a leaf output is not unspent on chain")
                elif left is not None:
                    sys.exit(f"node {nd['node']} output {k}: " + ("the anchor" if k == nd["anchor"] else "a child output")
                             + " is still unspent")
        for m in tree.members:
            leaf = tree.nodes[m["leaf"]]
            o = node.rpc("gettxout", leaf["txid"], 0)
            if o is None or round(o["value"] * 1e8) != m["channel"] or o["scriptPubKey"]["hex"] != m["script"]:
                sys.exit(f"member {m['member']}: the channel output is not on chain with its amount and script")
        anchors = ANCHOR_SAT * len(tree.nodes)
        print(f"amounts: funding {amount} = leaves {total_leaf} + tree fees {total_fee} + anchors {anchors}"
              f" ({total_leaf + total_fee + anchors})")
        if total_leaf + total_fee + anchors != amount:
            sys.exit("the funding does not balance")
        channels = [m["channel"] for m in tree.members]
        print(f"every member's channel output is unspent on chain: {n} outputs, {min(channels)} to {max(channels)} sat")
        report.update({"funding": f"{ftxid}:{vout}", "tip": chain.tip, "publications": published, "shared_copies": dup,
                       "filler_transactions": filler.sent if filler else 0, "seconds": round(time.time() - started, 1),
                       "tree": [{"node": nd["node"], "txid": nd["txid"], "height": chain.height[nd["txid"]]} for nd in tree.nodes],
                       "members_out": [{"member": m["member"], "txid": tree.nodes[m["leaf"]]["txid"], "vout": 0,
                                        "amount": m["channel"], "script": m["script"]} for m in tree.members]})
        print(f"\nPASS: R6 at {n} members: every member's path confirmed against a "
              + (f"full mempool ({fill_rate} sat/vB filler)" if fill_rate else "mempool without filler")
              + f", no conflict between siblings, the funding balanced to the satoshi ({time.time() - started:.0f} s)")
    finally:
        node.stop()
        if out:
            os.makedirs(out, exist_ok=True)
            with open(os.path.join(out, "mass-exit.json"), "w") as f:
                json.dump(report, f, indent=1)
            log = os.path.join(datadir, "regtest", "debug.log")
            if os.path.exists(log):
                shutil.copy(log, os.path.join(out, "debug.log"))


if __name__ == "__main__":
    main()
