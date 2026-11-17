#!/usr/bin/env python3
"""A T1 tree on a real Bitcoin Core regtest node, level by level (spec/exit.md 6.8).

What it shows, against the node itself, not our own model of its policy:
  1. every tree transaction is standard: version 3 (TRUC), with its P2A anchor;
  2. each level goes in as a one-parent-one-child package, the tree
     transaction with its 65-byte keyless anchor-only child (exit.md 6.2), is
     accepted by submitpackage and is mined; the next level only after;
  3. with the node's floor above the tree's 0.1 sat/vB (-minrelaytxfee
     0.00001, the default before Bitcoin Core 29.1 and still common on
     servers), a tree transaction alone is refused and its package is
     accepted; at the floor of 29.1 (0.000001) it is accepted alone too.
     At 4 members (shape [3]) every anchor-only package is above 1 sat/vB;
     a width-4 level (5 members and up) is 0.84 sat/vB (exit.md X6) and
     would need a wallet child at a 1 sat/vB floor;
  4. the end date on member 1's leaf: the host's timeout spend of the
     channel output (nLockTime H_leaf = E - 10 d, nSequence 0xfffffffe) is
     refused as non-final until the tip reaches H_leaf, then accepted.

It starts its own regtest bitcoind (own datadir, own RPC port on 127.0.0.1,
listen=0, no peers), runs, and stops it. THE KEYS ARE TEST KEYS.

usage: tools/regtest-tree.py BITCOIND_BIN_DIR DATADIR TREE_REGTEST [--port P] [--members N]
  BITCOIND_BIN_DIR  holds bitcoind and bitcoin-cli (29.1 or later)
  DATADIR           a fresh directory; created; never a live node's
  TREE_REGTEST      the built tests/regtest/tree_regtest
"""
import base64
import hashlib
import http.client
import json
import os
import subprocess
import sys
import time

RATE = 100            # T1's tree fee rate, sat/kvB
WALLET = "gz-regtest"


class Node:
    def __init__(self, bindir, datadir, port, minrelay):
        self.bindir, self.datadir, self.port = bindir, datadir, port
        os.makedirs(datadir, exist_ok=True)
        args = [os.path.join(bindir, "bitcoind"), "-regtest", "-datadir=" + datadir, "-daemonwait",
                "-listen=0", "-connect=0", "-dnsseed=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                f"-rpcport={port}", f"-minrelaytxfee={minrelay}", "-fallbackfee=0.0001", "-txindex=0",
                "-printtoconsole=0"]
        subprocess.run(args, check=True)
        self.cookie = os.path.join(datadir, "regtest", ".cookie")
        for _ in range(100):
            if os.path.exists(self.cookie):
                break
            time.sleep(0.1)

    def rpc(self, method, *params, wallet=None):
        with open(self.cookie) as f:
            auth = base64.b64encode(f.read().strip().encode()).decode()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        path = "/wallet/" + wallet if wallet else "/"
        c.request("POST", path, json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}),
                  {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        r = json.loads(c.getresponse().read())
        c.close()
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]

    def stop(self):
        try:
            self.rpc("stop")
        except Exception:
            pass
        for _ in range(300):
            if not os.path.exists(os.path.join(self.datadir, "regtest", "bitcoind.pid")):
                return
            time.sleep(0.1)


def anchor_child(parent_txid_display, anchor_vout):
    """exit.md 6.2: version 3, the parent's anchor, empty scriptSig, nSequence
    0xfffffffd, one zero-value OP_RETURN of three zero bytes, lock time 0."""
    prev = bytes.fromhex(parent_txid_display)[::-1]
    tx = ((3).to_bytes(4, "little") + b"\x01" + prev + anchor_vout.to_bytes(4, "little") + b"\x00"
          + (0xFFFFFFFD).to_bytes(4, "little") + b"\x01" + (0).to_bytes(8, "little")
          + b"\x05\x6a\x03\x00\x00\x00" + (0).to_bytes(4, "little"))
    assert len(tx) == 65
    return tx.hex()


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{cmd[0]} failed: {r.stderr.strip()}")
    return r.stdout


def factory(node, tool, n, addr, label, alone_must_fail):
    """Fund a T1 factory of n members and publish its whole tree, one level per block."""
    print(f"\n== {label}: T1, {n} members, tree fee rate {RATE} sat/kvB")
    w = run([tool, "params", str(n), str(RATE)]).split()
    amount, script = int(w[w.index("funding") + 1]), w[w.index("script") + 1]
    print(f"  shape {w[1]} D {w[3]}, funding amount R(root) = {amount} sat")
    info = node.rpc("getdescriptorinfo", f"rawtr({script[4:]})")
    fund_addr = node.rpc("deriveaddresses", info["descriptor"])[0]
    ftxid = node.rpc("sendtoaddress", fund_addr, f"{amount / 1e8:.8f}", wallet=WALLET)
    node.rpc("generatetoaddress", 1, addr)
    ftx = node.rpc("getrawtransaction", ftxid, True, node.rpc("getbestblockhash"))
    vout = next(o["n"] for o in ftx["vout"] if o["scriptPubKey"]["hex"] == script)
    tip = node.rpc("getblockcount")
    E = tip + 144 + 36                                  # T1: lifetime 144, wind-down 36
    print(f"  funding {ftxid}:{vout} confirmed at {tip}; end height E = {E}")
    nodes, timeout = [], None
    for line in run([tool, "build", str(n), str(RATE), ftxid, str(vout), str(amount), str(E)]).splitlines():
        w = line.split()
        if w[0] == "node":
            d = dict(zip(w[0::2], w[1::2]))
            nodes.append(d)
        elif w[0] == "timeout":
            timeout = dict(zip(w[1::2], w[2::2]))      # "timeout node I locktime L tx HEX"
    # A node's level is its number of ancestors.
    for nd in nodes:
        lvl, p = 0, int(nd["parent"])
        while p >= 0:
            lvl, p = lvl + 1, int(nodes[p]["parent"])
        nd["level"] = lvl
    levels = max(nd["level"] for nd in nodes) + 1
    for lvl in range(levels):
        here = [nd for nd in nodes if nd["level"] == lvl]
        for nd in here:
            dec = node.rpc("decoderawtransaction", nd["tx"])
            assert dec["version"] == 3 and dec["txid"] == nd["txid"], nd["node"]
            assert dec["vout"][-1]["scriptPubKey"]["hex"] == "51024e73"
            alone = node.rpc("testmempoolaccept", [nd["tx"]])[0]
            refused = not alone["allowed"]
            if alone_must_fail and not refused:
                sys.exit(f"node {nd['node']}: accepted alone below the floor")
            if not alone_must_fail and refused:
                sys.exit(f"node {nd['node']}: refused alone at the 29.1 floor: {alone.get('reject-reason')}")
            child = anchor_child(nd["txid"], int(nd["anchor"]))
            pk = node.rpc("submitpackage", [nd["tx"], child])
            if pk.get("package_msg") != "success":
                sys.exit(f"node {nd['node']}: package refused: {json.dumps(pk)}")
            print(f"  level {lvl} node {int(nd['node']):2d} ({dec['vsize']} vB, kind {nd['kind']}): alone "
                  + (f"refused ({alone.get('reject-reason')})" if refused else "accepted")
                  + ", package with the anchor-only child accepted")
        node.rpc("generatetoaddress", 1, addr)
        for nd in here:
            got = node.rpc("getrawtransaction", nd["txid"], True, node.rpc("getbestblockhash"))
            assert got.get("confirmations", 0) >= 1, nd["node"]
        print(f"  level {lvl}: {len(here)} transactions mined in block {node.rpc('getblockcount')}")
    # The end date on member 1's leaf.
    L = int(timeout["locktime"])
    leaf = nodes[int(timeout["node"])]
    d = int(leaf["depth"])
    assert L == E - 10 * d, (L, E, d)
    assert int(leaf["cltv"]) == L
    tip = node.rpc("getblockcount")
    if tip < L - 1:
        node.rpc("generatetoaddress", L - 1 - tip, addr)
    early = node.rpc("testmempoolaccept", [timeout["tx"]])[0]
    print(f"  member 1's leaf at depth {d}: H_leaf = E - 10 d = {L}; at tip {node.rpc('getblockcount')} the host's timeout "
          f"spend is {'accepted' if early['allowed'] else 'refused (' + str(early.get('reject-reason')) + ')'}")
    if early["allowed"] or early.get("reject-reason") != "non-final":
        sys.exit("the timeout spend was not refused as non-final before H_leaf")
    node.rpc("generatetoaddress", 1, addr)
    late = node.rpc("testmempoolaccept", [timeout["tx"]])[0]
    print(f"  at tip {node.rpc('getblockcount')} (= H_leaf) it is {'accepted' if late['allowed'] else 'refused (' + str(late.get('reject-reason')) + ')'}")
    if not late["allowed"]:
        sys.exit("the timeout spend was refused at H_leaf")
    return len(nodes)


def main():
    a = sys.argv[1:]
    if len(a) < 3:
        sys.exit(__doc__)
    bindir, datadir, tool = a[0], a[1], a[2]
    port = int(a[a.index("--port") + 1]) if "--port" in a else 18999
    n = int(a[a.index("--members") + 1]) if "--members" in a else 4
    if os.path.exists(os.path.join(datadir, "regtest")):
        sys.exit("DATADIR already holds a regtest chain: give a fresh directory")
    ver = run([os.path.join(bindir, "bitcoind"), "-version"]).splitlines()[0]
    print(ver)
    total = 0
    for floor, label, must_fail in (("0.00001", "node floor 1 sat/vB (before 29.1)", True),
                                   ("0.000001", "node floor 0.1 sat/vB (29.1 default)", False)):
        node = Node(bindir, datadir, port, floor)
        try:
            if not total:
                node.rpc("createwallet", WALLET)
                addr = node.rpc("getnewaddress", wallet=WALLET)
                node.rpc("generatetoaddress", 101, addr)
            else:
                node.rpc("loadwallet", WALLET)
                addr = node.rpc("getnewaddress", wallet=WALLET)
            info = node.rpc("getmempoolinfo")
            print(f"\nnode restarted with -minrelaytxfee={floor}: mempool minimum {info['mempoolminfee']}, "
                  f"relay {info['minrelaytxfee']} BTC/kvB")
            total += factory(node, tool, n, addr, label, must_fail)
        finally:
            node.stop()
    print(f"\nPASS: {total} tree transactions, every one standard, version 3, mined one level per block in a"
          f" package with its anchor-only child; the end date held on regtest heights")


if __name__ == "__main__":
    main()

