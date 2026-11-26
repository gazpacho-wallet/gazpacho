#!/usr/bin/env python3
"""program_regtest_helpers (docs/SLICE-1.5-PLAN.md, P7): each regtest helper
the Slice 1.5 tests lean on does what it claims, on real Bitcoin Core nodes.

    python3 -I regtest_helpers.py PATH_TO_GAZPACHO_TEST WORK_DIR [BITCOIN_BIN_DIR]

Core versions come from BITCOIN_BIN_DIR, GZ_BITCOIN_BIN and every
GZ_BITCOIN_BIN_<x> (regtest_kit.core_bins); each case runs on every version
found (R7, R8: 29.0 and 29.1). GZ_REQUIRE_CORE="29.0 29.1" makes a missing
version a failure, not a narrower run. Exits 77 (skipped) with no bitcoind.

  A. Nodes (Node, Net): every version at relay floors 1 and 0.1 sat/vB, all
     peered. Each node runs the version and floor asked for; a block mined on
     one reaches all; a 0.5 sat/vB transaction is accepted by the 0.1 nodes
     and refused by the 1 sat/vB nodes for the floor.
  B. Look-alikes (Shim): each answers under its operator name; each reports
     its node's floor as the mempool minimum, so two of them differ (S7 d);
     the mempool_min control overrides one and clearing it restores it.
  C. Packages (S12, R8): per node, the zero-fee version-3 parent with its
     240-sat P2A is refused alone by POST /tx and accepted with its
     anchor-only child by POST /txs/package (Core's answer as Core wrote
     it); an empty array is answered 400 there and 404 at a path no server
     has; with the endpoint off (control, and --no-package) both package
     paths answer 404 and nothing reaches the mempool.
  D. Hide and freeze (S13): a hidden confirmed transaction is unconfirmed,
     404 and absent on the hiding server, its spend and the spend of its
     output invisible there, while another server shows it all; unhidden, it
     is back. A frozen server keeps its tip while the chain grows, and what
     confirmed above it is unconfirmed there; unfrozen, it catches up.
  E. Reorganisations (R1): at depth 1 and at depth 2 the invalidated blocks
     really remove the txid from every node's chain (back in each mempool,
     the look-alike says unconfirmed), and a new, longer branch mines the
     same txid again in another block; reconsiderblock brings the old block
     back; a branch mined empty (only=[]) leaves the txid unconfirmed.
  F. Mempool filler (R4): two nodes at -maxmempool=5 are filled at 2 sat/vB
     until each node's mempool minimum is above the anchor-only package's
     rate: each filler transaction pays the rate (not less, and less than
     2.05), a 1.5 sat/vB transaction is then refused for the mempool
     minimum, the anchor-only package is refused, and each look-alike
     reports the raised minimum.
  G. Operator names (with the program): two look-alikes on this machine,
     127.0.0.1 and localhost, named op-a and op-b, are accepted together by
     gazpacho-test --check-chain; unnamed they are one operator
     (this-machine), so the comparing backend has no quorum: refused.
"""
import json
import math
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, free_port, passphrase_file  # noqa: E402
import regtest_kit as rk  # noqa: E402

check = Checks()


def pay(coins, rate, version=2):
    """One test coin to the coins wallet's own script at `rate` sat/vB: (raw, txid, spk)."""
    txid, vout, value, spk = coins.take()
    unsigned = rk.ser_tx(version, [(txid, vout, 0xFFFFFFFD)], [(0, spk)])
    bound = math.ceil((len(unsigned) // 2 * 4 + rk.P2WPKH_WITNESS_WU) / 4)
    raw = coins.sign(rk.ser_tx(version, [(txid, vout, 0xFFFFFFFD)], [(value - math.ceil(rate * bound), spk)]))
    return raw, coins.node.rpc("decoderawtransaction", raw)["txid"], spk, (txid, vout)


def spend_output(coins, txid, vout, value, spk, rate):
    """Spends (txid, vout), a coins-wallet output, to the same script: (raw, txid)."""
    unsigned = rk.ser_tx(2, [(txid, vout, 0xFFFFFFFD)], [(0, spk)])
    bound = math.ceil((len(unsigned) // 2 * 4 + rk.P2WPKH_WITNESS_WU) / 4)
    raw = coins.sign(rk.ser_tx(2, [(txid, vout, 0xFFFFFFFD)], [(value - math.ceil(rate * bound), spk)]))
    return raw, coins.node.rpc("decoderawtransaction", raw)["txid"]


def scripthash(spk):
    import hashlib
    return hashlib.sha256(bytes.fromhex(spk)).hexdigest()


def case_nodes(net, specs, bins):
    print("-- A. nodes, floors, peers", flush=True)
    for n, (v, floor) in zip(net.nodes, specs):
        want = rk.core_version(bins[v])[1]
        check(n.version == want, "A: %s runs Core %s (version %d)" % (n.name, v, n.version))
        check(abs(n.floor() - floor) < 1e-9, "A: %s relays from %s sat/vB (getnetworkinfo %s)" % (n.name, floor, n.floor()))
        check(n.rpc("getconnectioncount") >= len(net.nodes) - 1, "A: %s is peered with every other node" % n.name)
    best = net.mine(1)[0]
    check(all(n.rpc("getbestblockhash") == best for n in net.nodes), "A: a block mined on one node is every node's tip")
    coins = rk.Coins(net)
    coins.split(40, 200000)
    raw, txid, _spk, _p = pay(coins, 0.5)
    for n, (_v, floor) in zip(net.nodes, specs):
        ok, why = n.accept(raw)
        if floor <= 0.5:
            check(ok, "A: %s accepts a 0.5 sat/vB transaction" % n.name)
        else:
            check(not ok and "min relay fee not met" in why,
                  "A: %s refuses a 0.5 sat/vB transaction for its floor (%s)" % (n.name, why))
    return coins


def case_shims(shims, specs):
    print("-- B. look-alikes: operator names, mempool minimums", flush=True)
    for s, (_v, floor) in zip(shims, specs):
        code, text, hdr = s.get("/blocks/tip/height")
        check(code == 200 and int(text) == s.node.tip(), "B: %s answers the node's tip (%s)" % (s.operator, text))
        check(hdr.get("X-Gz-Operator") == s.operator, "B: %s answers as operator %s" % (s.url, hdr.get("X-Gz-Operator")))
        check(abs(s.mempool_min() - floor) < 1e-9, "B: %s reports its node's minimum, %s sat/vB" % (s.operator, floor))
    mins = {s.mempool_min() for s in shims}
    check(len(mins) > 1, "B: the look-alikes' mempool minimums differ (%s)" % sorted(mins))
    shims[0].set_mempool_min(3.5)
    check(shims[0].mempool_min() == 3.5, "B: the mempool_min control makes %s report 3.5" % shims[0].operator)
    check(all(abs(s.mempool_min() - f) < 1e-9 for s, (_v, f) in zip(shims[1:], specs[1:])),
          "B: the other look-alikes are unchanged")
    shims[0].set_mempool_min(None)
    check(abs(shims[0].mempool_min() - specs[0][1]) < 1e-9, "B: cleared, %s reports its node's minimum again" % shims[0].operator)


def case_packages(net, shims, specs, coins, work):
    print("-- C. packages (S12 steps 2 and 3, R8)", flush=True)
    table = []
    for s, (v, floor) in zip(shims, specs):
        parent, child, ptxid, ctxid = rk.truc_package(coins)
        code, text, _ = s.broadcast(parent)
        alone = "refused: " + text if code != 200 else "accepted"
        check(code == 400 and "min relay fee not met" in text and not s.node.in_mempool(ptxid),
              "C: %s: the zero-fee version-3 parent alone is refused (%s)" % (s.operator, text.strip()))
        code, text, _ = s.package([parent, child])
        try:
            j = json.loads(text)
        except ValueError:
            j = {}
        ok = code == 200 and j.get("package_msg") == "success"
        check(ok and s.node.in_mempool(ptxid) and s.node.in_mempool(ctxid),
              "C: %s: parent and anchor-only child accepted as a package (%d %s)" % (s.operator, code, j.get("package_msg")))
        check(re.search(r"\d[eE]-\d", text) is None and "0.00000240" in text,
              "C: %s: the package answer keeps Core's numbers as written (0.00000240)" % s.operator)
        table.append("Core %-5s floor %-4s alone: %s; package: %s" % (v, floor, alone.strip(), j.get("package_msg", text)))
    s = shims[0]
    code, _t, _h = s.request("/txs/package", "[]", "application/json")
    check(code == 400, "C: an empty array at /txs/package is answered 400 (the probe: endpoint there), got %d" % code)
    code, _t, _h = s.request("/gz-probe-control-path", "[]", "application/json")
    check(code == 404, "C: the same body at a path no server has is answered 404, got %d" % code)
    s.set_package(False)
    parent, child, ptxid, ctxid = rk.truc_package(coins)
    codes = [s.package([parent, child], path)[0] for path in ("/txs/package", "/v1/txs/package")]
    check(codes == [404, 404] and not s.node.in_mempool(ptxid) and not s.node.in_mempool(ctxid),
          "C: with the control's package off, both package paths answer 404 and nothing is sent (%s)" % codes)
    s.set_package(True)
    code, text, _ = s.package([parent, child], "/v1/txs/package")
    check(code == 200 and json.loads(text).get("package_msg") == "success",
          "C: back on, /v1/txs/package takes the same package")
    off = rk.Shim(s.node, name="op-nopkg", package=False, log=os.path.join(work, "esplora-nopkg.log"))
    try:
        parent, child, ptxid, _c = rk.truc_package(coins)
        codes = [off.package([parent, child], path)[0] for path in ("/txs/package", "/v1/txs/package")]
        check(codes == [404, 404] and not s.node.in_mempool(ptxid),
              "C: a look-alike started with --no-package answers 404 at both paths (%s)" % codes)
    finally:
        off.stop()
    print("   what each node accepts (R8):")
    for row in table:
        print("     " + row)
    net.mine(1)


def case_hide_freeze(net, hider, honest, coins):
    print("-- D. hide and freeze (S13)", flush=True)
    raw, t, spk, prev = pay(coins, 2)
    net.send_everywhere(raw)
    blk = net.mine(1)[0]
    h = net.tip()
    value = int(round(net.nodes[0].rpc("getrawtransaction", t, True)["vout"][0]["value"] * 1e8))
    st = honest.get_json("/tx/%s/status" % t)
    check(st.get("confirmed") and st.get("block_hash") == blk, "D: the transaction is confirmed (honest server)")
    hider.hide(t)
    check(hider.get_json("/tx/%s/status" % t) == {"confirmed": False}, "D: hidden: /tx/T/status is unconfirmed")
    check(hider.get("/tx/%s/hex" % t)[0] == 404, "D: hidden: /tx/T/hex is 404")
    check(hider.get("/tx/%s/merkle-proof" % t)[0] == 404, "D: hidden: /tx/T/merkle-proof is 404")
    check(hider.get_json("/tx/%s/outspend/%d" % prev) == {"spent": False},
          "D: hidden: the coin T spends shows unspent")
    check(honest.get_json("/tx/%s/outspend/%d" % prev).get("txid") == t, "D: the honest server shows T spending it")
    utxo = [u["txid"] for u in hider.get_json("/scripthash/%s/utxo" % scripthash(spk))]
    check(t not in utxo, "D: hidden: T's output is absent from its script's coins")
    check(t in [u["txid"] for u in honest.get_json("/scripthash/%s/utxo" % scripthash(spk))],
          "D: the honest server lists T's output")
    sraw, s_txid = spend_output(coins, t, 0, value, spk, 2)
    net.send_everywhere(sraw)
    check(hider.get_json("/tx/%s/outspend/0" % t) == {"spent": False}, "D: hidden: T's outspends are empty")
    check(honest.get_json("/tx/%s/outspend/0" % t).get("txid") == s_txid, "D: the honest server shows T's output spent")
    hider.unhide(t)
    st = hider.get_json("/tx/%s/status" % t)
    check(st.get("confirmed") and st.get("block_height") == h and hider.get("/tx/%s/hex" % t)[0] == 200,
          "D: unhidden, T is confirmed again on that server")
    hider.freeze()
    net.mine(2)
    check(int(hider.get("/blocks/tip/height")[1]) == h, "D: frozen: the tip stays at %d while the chain is at %d" % (h, net.tip()))
    check(hider.get("/block-height/%d" % (h + 1))[0] == 404, "D: frozen: no block above the frozen tip")
    check(hider.get_json("/tx/%s/status" % s_txid) == {"confirmed": False},
          "D: frozen: a transaction confirmed above the frozen tip is unconfirmed there")
    check(honest.get_json("/tx/%s/status" % s_txid).get("block_height") == h + 1
          and int(honest.get("/blocks/tip/height")[1]) == h + 2, "D: the honest server is at the chain's tip")
    hider.unfreeze()
    check(int(hider.get("/blocks/tip/height")[1]) == h + 2 and hider.get_json("/tx/%s/status" % s_txid).get("confirmed"),
          "D: unfrozen, the server catches up")


def case_reorg(net, shim, coins):
    print("-- E. reorganisations (R1)", flush=True)
    for depth in (1, 2):
        raw, t, _spk, _p = pay(coins, 2)
        net.send_everywhere(raw)
        first = net.mine(1)[0]
        if depth == 2:
            net.mine(1)
        tip = net.tip()
        check(all(n.confirmations(t) == depth for n in net.nodes), "E%d: T is %d deep on every node" % (depth, depth))
        old, txids = net.disconnect(depth)
        check(old == first and t in txids, "E%d: invalidateblock at depth %d takes T's block" % (depth, depth))
        check(all(n.block_of(t) is None and n.in_mempool(t) for n in net.nodes),
              "E%d: T is out of every node's chain and back in its mempool" % depth)
        check(all(n.rpc("getblockheader", old)["confirmations"] == -1 for n in net.nodes),
              "E%d: the old block is off every node's chain" % depth)
        check(shim.get_json("/tx/%s/status" % t) == {"confirmed": False}, "E%d: the look-alike says unconfirmed" % depth)
        new = net.mine(depth + 1, address=net.nodes[0].address())
        check(all(n.block_of(t) == new[0] for n in net.nodes) and new[0] != first,
              "E%d: the same txid is mined again, in another block" % depth)
        st = shim.get_json("/tx/%s/status" % t)
        check(net.tip() == tip + 1 and st.get("block_hash") == new[0],
              "E%d: the new branch is the longer, and the look-alike follows it" % depth)
    raw, t, _spk, _p = pay(coins, 2)
    net.send_everywhere(raw)
    b = net.mine(1)[0]
    old, _txids = net.disconnect(1)
    check(all(n.block_of(t) is None for n in net.nodes), "E: disconnected again, T is unconfirmed")
    net.reconsider(old)
    check(all(n.block_of(t) == b and n.rpc("getbestblockhash") == b for n in net.nodes),
          "E: reconsiderblock brings the old block back on every node, T in it")
    old, txids, new = net.reorg(1, only=[])
    check(t in txids and all(n.block_of(t) is None and n.in_mempool(t) for n in net.nodes) and len(new) == 2,
          "E: a new branch mined empty (only=[]) leaves T unconfirmed, in every mempool")
    net.mine(1)


def case_filler(fnet, fshims, coins_net):
    print("-- F. mempool filler (R4)", flush=True)
    coins = rk.Coins(fnet)
    coins.split(len(fnet.nodes) + 2, 200000)
    parent, child, ptx, _c = rk.truc_package(coins)
    pkg_rate = rk.ANCHOR_SAT / (rk.vsize(fnet.nodes[0], parent) + rk.vsize(fnet.nodes[0], child))
    print("   the anchor-only package pays %.3f sat/vB" % pkg_rate)
    for n in fnet.nodes:
        check(n.mempool_min() < pkg_rate, "F: before: %s's mempool minimum %s is below it" % (n.name, n.mempool_min()))
    filler = rk.Filler(fnet)
    filler.prepare(90, 2.5)
    mins = filler.fill(2.0, pkg_rate)
    print("   %d filler transactions; minimums %s" % (len(filler.sent), mins))
    check(all(m > pkg_rate for m in mins.values()), "F: every node's mempool minimum is above the package's rate")
    rates = []
    for n in fnet.nodes:
        for t in filler.sent:
            try:
                e = n.rpc("getmempoolentry", t)
            except rk.RPCError:
                continue   # evicted
            rates.append(e["fees"]["base"] * 1e8 / e["vsize"])
    check(rates and min(rates) >= 2.0 and max(rates) < 2.05,
          "F: each filler transaction pays the chosen 2 sat/vB (%.4f to %.4f)" % (min(rates or [0]), max(rates or [0])))
    raw, _t, _s, _p = pay(coins, 1.5)
    for n in fnet.nodes:
        ok, why = n.accept(raw)
        check(not ok and "mempool min fee not met" in why, "F: %s refuses 1.5 sat/vB for its mempool minimum (%s)" % (n.name, why))
    for s in fshims:
        code, text, _ = s.package([parent, child])
        j = json.loads(text) if code == 200 else {}
        check(j.get("package_msg") != "success" and not s.node.in_mempool(ptx),
              "F: %s: the anchor-only package is refused (%d %s)" % (s.operator, code, j.get("package_msg", text.strip())))
        check(s.mempool_min() > pkg_rate, "F: %s reports the raised minimum, %s sat/vB" % (s.operator, s.mempool_min()))


def case_operators(exe, work, a, b):
    print("-- G. operator names, with the program", flush=True)

    def run(tag, args):
        d = os.path.join(work, "op-" + tag)
        cmd = [exe, "--data-dir", d, "--role", "host", "--name", "host", "--test-regtest"] + args + [
            "--chain-poll-ms", "250", "--no-interface", "--test-engines", "0", "--test-commands",
            "--listen", "127.0.0.1:%d" % free_port(), "--max-per-address", "0", "--check-chain",
            "--test-passphrase-file", passphrase_file(), "--test-kdf-floor"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr

    code, out = run("named", a.chain_args() + b.chain_args())
    check(code == 0 and re.search(r"first-address=bcrt1", out) is not None,
          "G: %s (op-a) and %s (op-b) are taken together (exit %d)" % (a.url, b.url, code))
    code, out = run("unnamed", ["--chain-url", a.url, "--chain-url", b.url])
    last = (out.strip().splitlines() or [""])[-1]
    check(code != 0 and "no-quorum" in out,
          "G: unnamed, the two look-alikes are one operator and are refused (exit %d: %s)" % (code, last))


def main():
    exe, work = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3 and sys.argv[3]:
        os.environ.setdefault("GZ_BITCOIN_BIN", sys.argv[3])
    bins = rk.core_bins()
    required = os.environ.get("GZ_REQUIRE_CORE", "").split()
    if not bins:
        if required:
            print("FAIL: GZ_REQUIRE_CORE asks for %s and no bitcoind was found" % required)
            return 1
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR, GZ_BITCOIN_BIN or GZ_BITCOIN_BIN_<version>)")
        return 77
    os.makedirs(work, exist_ok=True)
    check(all(v in bins for v in required), "Core versions here: %s; asked for: %s" % (sorted(bins), required or "any"))
    versions = sorted(bins)
    specs = [(v, f) for v in versions for f in (1.0, 0.1)]
    started = []
    try:
        nodes = []
        for v, f in specs:
            nodes.append(rk.Node(bins[v], work, "core%s-floor%s" % (v, f), floor=f))
            started.append(nodes[-1])
        net = rk.Net(nodes)
        net.mine(101)
        shims = []
        for i, n in enumerate(nodes):
            shims.append(rk.Shim(n, name="op-%d" % i, host="127.0.0.1" if i % 2 == 0 else "localhost",
                                 log=os.path.join(work, "esplora-%d.log" % i)))
            started.append(shims[-1])
        coins = case_nodes(net, specs, bins)
        case_shims(shims, specs)
        case_packages(net, shims, specs, coins, work)
        case_hide_freeze(net, shims[0], shims[1], coins)
        case_reorg(net, shims[1], coins)
        fspecs = [(versions[0], 1.0), (versions[-1], 0.1)]
        fnodes = []
        for v, f in fspecs:
            fnodes.append(rk.Node(bins[v], work, "fill%s-floor%s" % (v, f), floor=f, maxmempool=5))
            started.append(fnodes[-1])
        fnet = rk.Net(fnodes)
        fnet.mine(101)
        fshims = []
        for i, n in enumerate(fnodes):
            fshims.append(rk.Shim(n, name="fill-%d" % i, log=os.path.join(work, "esplora-fill-%d.log" % i)))
            started.append(fshims[-1])
        case_filler(fnet, fshims, net)
        if os.path.exists(exe):
            a = rk.Shim(nodes[0], name="op-a", host="127.0.0.1", log=os.path.join(work, "esplora-a.log"))
            started.append(a)
            b = rk.Shim(nodes[1], name="op-b", host="localhost", log=os.path.join(work, "esplora-b.log"))
            started.append(b)
            case_operators(exe, work, a, b)
        else:
            check(False, "G: no program at %s" % exe)
    finally:
        for x in reversed(started):
            x.stop()
    return check.result("program_regtest_helpers", work)


if __name__ == "__main__":
    sys.exit(main())
