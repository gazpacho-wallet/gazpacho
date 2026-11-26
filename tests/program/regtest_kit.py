"""Regtest helpers for the program tests (docs/SLICE-1.5-PLAN.md, P7).

Test side only: nothing here is part of the program. Every node is a Bitcoin
Core regtest node of the test's own (its own data folder under the test's
work folder, RPC and peer ports on 127.0.0.1 picked free, stopped by stop()),
so tests run side by side without sharing a chain. Regtest runs as fast as
blocks are asked for: nothing here waits for a clock, only for the nodes to
agree.

    Node      one bitcoind: a chosen Core (its bin folder), a chosen relay
              floor (-minrelaytxfee, in sat/vB), a chosen -maxmempool
    Shim      tools/esplora-regtest.py over a node, with an operator name and
              the run-time controls: package endpoint on or off (S12), hide a
              txid, freeze the tip (S13), report another mempool minimum (S7 d)
    Net       nodes peered with one another: mine and wait for every node,
              invalidateblock / reconsiderblock at a depth and the same
              transactions mined again (R1 to R3)
    Coins     test coins of a node's wallet, split off in a block of their own
    Filler    fills every node's mempool with large transactions paying a
              chosen rate until each node's mempool minimum is above a
              chosen rate (R4)
    truc_package  a zero-fee version-3 parent with a 240-sat P2A and its
              anchor-only child (S12 steps 2 and 3, R7, R8)

Core versions: core_bins() finds them from GZ_BITCOIN_BIN and every
GZ_BITCOIN_BIN_<x> (for example GZ_BITCOIN_BIN_29_0, GZ_BITCOIN_BIN_29_1),
each named by what its bitcoind -version says.
"""
import base64
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

from gzp_harness import free_port

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools")
P2A = "51024e73"                                          # pay-to-anchor, keyless
P2WSH_TRUE = "0020" + hashlib.sha256(b"\x51").hexdigest()  # standard, nobody's coins: the filler's outputs
ANCHOR_SAT = 240


def btc_kvb(sat_vb):
    """sat/vB as Core's option text in BTC/kvB."""
    return "%.8f" % (sat_vb / 1e5)


def core_version(bindir):
    """('29.1', 290100) for the bitcoind in bindir, or None."""
    exe = os.path.join(bindir, "bitcoind")
    if not os.path.exists(exe):
        return None
    out = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=30).stdout
    m = re.search(r"version v(\d+)\.(\d+)(?:\.(\d+))?", out)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    name = "%d.%d" % (major, minor) + (".%d" % patch if patch else "")
    return name, major * 10000 + minor * 100 + patch


def core_bins():
    """{'29.0': bindir, '29.1': bindir, ...} from GZ_BITCOIN_BIN and GZ_BITCOIN_BIN_*."""
    found = {}
    for k in sorted(os.environ):
        if k == "GZ_BITCOIN_BIN" or k.startswith("GZ_BITCOIN_BIN_"):
            v = core_version(os.environ[k]) if os.environ[k] else None
            if v and v[0] not in found:
                found[v[0]] = os.environ[k]
    return found


class RPCError(RuntimeError):
    pass


class Node:
    """One regtest bitcoind of the test's own.

    floor: -minrelaytxfee in sat/vB (None: the version's default). The
    block-making floor goes to zero with it, so whatever the node relays it
    also mines. listen: a peer port on 127.0.0.1 (for Net); listen=False is
    a node alone, as program_slice1's."""

    def __init__(self, bindir, work, name, floor=None, maxmempool=None, incremental=None, listen=True,
                 extra=()):
        self.bin, self.name = bindir, name
        self.dir = os.path.join(work, name)
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        self.rpc_port = free_port()
        self.p2p_port = free_port() if listen else None
        a = [os.path.join(bindir, "bitcoind"), "-regtest", "-datadir=" + self.dir]
        if listen:
            a += ["-listen=1", "-bind=127.0.0.1:%d" % self.p2p_port, "-discover=0", "-dnsseed=0",
                  "-fixedseeds=0", "-listenonion=0"]
        else:
            a += ["-listen=0"]
        a += ["-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % self.rpc_port,
              "-txindex=1", "-fallbackfee=0.0001", "-mintxfee=0.000001"]
        if floor is not None:
            a += ["-minrelaytxfee=" + btc_kvb(floor), "-blockmintxfee=0"]
        if incremental is not None:
            a += ["-incrementalrelayfee=" + btc_kvb(incremental)]
        if maxmempool is not None:
            a += ["-maxmempool=%d" % maxmempool]
        a += list(extra) + ["-printtoconsole=0", "-daemon=0"]
        self.proc = subprocess.Popen(a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(240):
            if self.proc.poll() is not None:
                raise SystemExit("bitcoind %s exited at its start (%s)" % (name, " ".join(a[1:])))
            try:
                self.rpc("getblockcount")
                break
            except (OSError, RPCError):
                time.sleep(0.25)
        else:
            raise SystemExit("bitcoind %s did not start" % name)
        self.version = self.rpc("getnetworkinfo")["version"]
        self.wallets = set()

    # -- calls ---------------------------------------------------------------
    def rpc(self, method, *params, wallet=None, **named):
        """One JSON-RPC call over HTTP (the cookie of this node); named or positional."""
        with open(os.path.join(self.dir, "regtest", ".cookie")) as f:
            auth = base64.b64encode(f.read().strip().encode()).decode()
        c = http.client.HTTPConnection("127.0.0.1", self.rpc_port, timeout=120)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": named if named else list(params)})
        c.request("POST", "/wallet/" + wallet if wallet else "/", body,
                  {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        r = json.loads(c.getresponse().read())
        c.close()
        if r.get("error"):
            raise RPCError(r["error"].get("message", "error"))
        return r["result"]

    def cli(self, *args):
        """bitcoin-cli, as program_slice1 has always called it."""
        r = subprocess.run([os.path.join(self.bin, "bitcoin-cli"), "-regtest", "-datadir=" + self.dir,
                            "-rpcport=%d" % self.rpc_port, "-rpcconnect=127.0.0.1"] + list(args),
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except ValueError:
            return out

    # -- state -------------------------------------------------------------
    def floor(self):
        """The relay floor in force, sat/vB."""
        return round(self.rpc("getnetworkinfo")["relayfee"] * 1e5, 6)

    def mempool_min(self):
        """The mempool minimum in force (the floor, or higher when the mempool is full), sat/vB."""
        return round(self.rpc("getmempoolinfo")["mempoolminfee"] * 1e5, 6)

    def tip(self):
        return self.rpc("getblockcount")

    def wallet(self, name="miner"):
        if name not in self.wallets:
            if name not in self.rpc("listwallets"):
                try:
                    self.rpc("createwallet", name)
                except RPCError:
                    self.rpc("loadwallet", name)
            self.wallets.add(name)
        return name

    def address(self, wallet="miner"):
        return self.rpc("getnewaddress", wallet=self.wallet(wallet))

    def script_of(self, address):
        return self.rpc("validateaddress", address)["scriptPubKey"]

    def confirmations(self, txid):
        """0 in the mempool, None unknown, else the depth (the node's own view)."""
        try:
            t = self.rpc("getrawtransaction", txid, True)
        except RPCError:
            return None
        return t.get("confirmations", 0) if "blockhash" in t else (0 if self.in_mempool(txid) else None)

    def block_of(self, txid):
        try:
            return self.rpc("getrawtransaction", txid, True).get("blockhash")
        except RPCError:
            return None

    def in_mempool(self, txid):
        try:
            self.rpc("getmempoolentry", txid)
            return True
        except RPCError:
            return False

    def accept(self, raw):
        """testmempoolaccept for one transaction: (allowed, reject-reason)."""
        r = self.rpc("testmempoolaccept", [raw])[0]
        return r.get("allowed", False), r.get("reject-reason", "")

    def stop(self):
        try:
            self.rpc("stop")
        except (OSError, RPCError):
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class Shim:
    """tools/esplora-regtest.py over one node, run-time controls through its control file.

    name: the operator it stands for (X-Gz-Operator, --chain-operator).
    host: the spelling of 127.0.0.1 in its URL. The comparing backend refuses
    two servers on one host name, so a second look-alike on this machine is
    given "localhost" and an operator name of its own."""

    def __init__(self, node, name=None, host="127.0.0.1", package=True, log=None):
        self.node, self.operator, self.host = node, name, host
        tag = name or "shim"
        self.control_file = os.path.join(node.dir, "esplora-%s.control" % tag)
        self.ctl = {}
        self._write()
        pf = os.path.join(node.dir, "esplora.port" if name is None else "esplora-%s.port" % tag)
        if os.path.exists(pf):
            os.remove(pf)
        a = [sys.executable, "-I", os.path.join(TOOLS, "esplora-regtest.py"), node.dir, str(node.rpc_port), pf,
             "--control", self.control_file]
        if name:
            a += ["--name", name]
        if not package:
            a += ["--no-package"]
        err = open(log, "w") if log else subprocess.DEVNULL
        self.proc = subprocess.Popen(a, stdout=subprocess.DEVNULL, stderr=err)
        for _ in range(120):
            if os.path.exists(pf):
                break
            if self.proc.poll() is not None:
                raise SystemExit("esplora-regtest exited at its start")
            time.sleep(0.25)
        with open(pf) as f:
            self.port = int(f.read().strip())
        self.url = "http://%s:%d" % (host, self.port)

    # -- controls ------------------------------------------------------------
    def _write(self):
        tmp = self.control_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.ctl, f)
        os.replace(tmp, self.control_file)

    def control(self, **kv):
        """Set (or, with None, clear) control fields: package, hide, freeze_at, mempool_min."""
        for k, v in kv.items():
            if v is None:
                self.ctl.pop(k, None)
            else:
                self.ctl[k] = v
        self._write()

    def hide(self, txid):
        self.control(hide=sorted(set(self.ctl.get("hide", [])) | {txid}))

    def unhide(self, txid=None):
        left = [] if txid is None else [t for t in self.ctl.get("hide", []) if t != txid]
        self.control(hide=left or None)

    def freeze(self, height=None):
        """The tip this server shows stays at height (default: the node's tip now)."""
        self.control(freeze_at=self.node.tip() if height is None else height)

    def unfreeze(self):
        self.control(freeze_at=None)

    def set_package(self, on):
        self.control(package=bool(on))

    def set_mempool_min(self, sat_vb):
        self.control(mempool_min=sat_vb)

    # -- requests ------------------------------------------------------------
    def request(self, path, body=None, ctype="text/plain"):
        """(status, text, headers) of one GET, or POST when body is given."""
        data = None if body is None else (body if isinstance(body, bytes) else body.encode())
        req = urllib.request.Request(self.url + path, data=data, method="GET" if body is None else "POST")
        if body is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers)

    def get(self, path):
        return self.request(path)

    def get_json(self, path):
        code, text, _ = self.request(path)
        if code != 200:
            raise RuntimeError("%s %s: %d %s" % (self.operator, path, code, text))
        return json.loads(text)

    def broadcast(self, raw):
        return self.request("/tx", raw)

    def package(self, raws, path="/txs/package"):
        return self.request(path, json.dumps(list(raws)), "application/json")

    def mempool_min(self):
        return self.get_json("/v1/fees/recommended")["minimumFee"]

    def chain_args(self):
        """The program's options for this server: --chain-url, and --chain-operator when named."""
        return ["--chain-url", self.url] + (["--chain-operator", self.operator] if self.operator else [])

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def wait_for(cond, timeout=60, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class Net:
    """Nodes peered with one another (every pair), one chain between them.
    Node 0 mines; the miner wallet is node 0's."""

    def __init__(self, nodes):
        self.nodes = list(nodes)
        for i, a in enumerate(self.nodes):
            for b in self.nodes[i + 1:]:
                a.rpc("addnode", "127.0.0.1:%d" % b.p2p_port, "onetry")
        need = len(self.nodes) - 1
        if not wait_for(lambda: all(n.rpc("getconnectioncount") >= need for n in self.nodes), 60):
            raise SystemExit("the regtest nodes did not peer")
        self.miner = self.nodes[0].address("miner")

    def tip(self):
        return self.nodes[0].tip()

    def sync(self, timeout=60):
        """Every node on node 0's best block."""
        best = self.nodes[0].rpc("getbestblockhash")
        if not wait_for(lambda: all(n.rpc("getbestblockhash") == best for n in self.nodes), timeout):
            raise RuntimeError("the nodes did not agree on block %s" % best)
        return best

    def mine(self, n=1, address=None):
        """n blocks on node 0 (its mempool in them), every node then on them."""
        hashes = self.nodes[0].rpc("generatetoaddress", n, address or self.miner)
        self.sync()
        return hashes

    def mine_only(self, txs, address=None):
        """One block holding exactly these transactions (txids in node 0's mempool, or raw hex)."""
        h = self.nodes[0].rpc("generateblock", address or self.nodes[0].address(), list(txs))["hash"]
        self.sync()
        return h

    def send_everywhere(self, raw):
        """sendrawtransaction on every node: [(node name, txid or None, refusal)]."""
        out = []
        for n in self.nodes:
            try:
                out.append((n.name, n.rpc("sendrawtransaction", raw, 0), ""))
            except RPCError as e:
                out.append((n.name, None, str(e)))
        return out

    def disconnect(self, depth):
        """invalidateblock on every node at the block depth blocks below the tip
        (depth 1: the tip itself). The blocks' transactions go back to each
        node's mempool. Returns (the first invalidated block's hash, the
        txids its blocks held, coinbases left out)."""
        tip = self.tip()
        first = tip - depth + 1
        txids = []
        for h in range(first, tip + 1):
            blk = self.nodes[0].rpc("getblock", self.nodes[0].rpc("getblockhash", h), 1)
            txids += blk["tx"][1:]
        bh = self.nodes[0].rpc("getblockhash", first)
        for n in self.nodes:
            n.rpc("invalidateblock", bh)
        if not wait_for(lambda: all(n.tip() == first - 1 for n in self.nodes), 60):
            raise RuntimeError("the nodes did not drop to height %d" % (first - 1))
        return bh, txids

    def reconsider(self, block_hash):
        """reconsiderblock on every node: the old branch back if it is the longer."""
        for n in self.nodes:
            n.rpc("reconsiderblock", block_hash)
        return self.sync()

    def reorg(self, depth, blocks=None, only=None):
        """disconnect(depth), then a new branch of `blocks` blocks (default
        depth + 1, so it is the longer) mined on node 0 to a fresh address
        (never the old blocks again). only=None: the first new block takes
        node 0's mempool, so the same transactions are mined again; else it
        holds exactly `only` (txids or raw hex) and the rest are empty.
        Returns (the old branch's first hash, its txids, the new hashes)."""
        old, txids = self.disconnect(depth)
        blocks = depth + 1 if blocks is None else blocks
        addr = self.nodes[0].address()
        if only is None:
            new = self.nodes[0].rpc("generatetoaddress", blocks, addr)
        else:
            new = [self.nodes[0].rpc("generateblock", addr, list(only))["hash"]]
            new += [self.nodes[0].rpc("generateblock", addr, [])["hash"] for _ in range(blocks - 1)]
        self.sync()
        return old, txids, new

    def stop(self):
        for n in self.nodes:
            n.stop()


# -- transactions ------------------------------------------------------------
def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def ser_tx(version, ins, outs, locktime=0):
    """Unsigned (no witness) transaction hex. ins: [(txid, vout, sequence)]; outs: [(sat, script hex)]."""
    b = version.to_bytes(4, "little") + varint(len(ins))
    for txid, vout, seq in ins:
        b += bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little") + b"\x00" + seq.to_bytes(4, "little")
    b += varint(len(outs))
    for sat, spk in outs:
        s = bytes.fromhex(spk)
        b += sat.to_bytes(8, "little") + varint(len(s)) + s
    return (b + locktime.to_bytes(4, "little")).hex()


P2WPKH_WITNESS_WU = 2 + 1 + 1 + 72 + 1 + 33   # marker and flag, count, signature at most, key


class Coins:
    """Test coins of one node's wallet: P2WPKH outputs split off from the
    miner wallet's coins, confirmed in a block holding only the split (so a
    mempool under test is not mined)."""

    def __init__(self, net, node=0, wallet="coins"):
        self.net, self.node = net, net.nodes[node]
        self.wallet = self.node.wallet(wallet)
        self.free = []

    def split(self, n, value_sat):
        """n coins of value_sat each, confirmed; mines blocks for the miner wallet if it is short."""
        need = n * value_sat / 1e8 + 0.01
        while self.node.rpc("getbalance", wallet="miner") < need:
            self.net.mine(101 if self.node.rpc("getbalance", wallet="miner") == 0 else 10)
        while n > 0:
            k = min(n, 200)
            outs = {self.node.address(self.wallet): "%.8f" % (value_sat / 1e8) for _ in range(k)}
            floor = max(m.floor() for m in self.net.nodes)
            txid = self.node.rpc("send", outputs=[{a: v} for a, v in outs.items()], fee_rate=floor,
                                 wallet="miner")["txid"]
            self.net.mine_only([txid])
            tx = self.node.rpc("getrawtransaction", txid, True)
            for o in tx["vout"]:
                if int(round(o["value"] * 1e8)) == value_sat and o["scriptPubKey"].get("address") in outs:
                    self.free.append((txid, o["n"], value_sat, o["scriptPubKey"]["hex"]))
            n -= k

    def take(self):
        if not self.free:
            raise RuntimeError("no test coin left: split more first")
        return self.free.pop(0)

    def sign(self, raw):
        r = self.node.rpc("signrawtransactionwithwallet", raw, wallet=self.wallet)
        if not r.get("complete"):
            raise RuntimeError("could not sign: %s" % r.get("errors"))
        return r["hex"]


def vsize(node, raw):
    return node.rpc("decoderawtransaction", raw)["vsize"]


def truc_package(coins, child_fee=ANCHOR_SAT):
    """S12's pair: a zero-fee version-3 parent, one test coin to itself plus a
    240-sat P2A, and its anchor-only child (the anchor in, a 4-byte OP_RETURN
    out, 66 bytes, the whole 240 sat as fee). Returns (parent hex, child hex,
    parent txid, child txid)."""
    txid, vout, value, spk = coins.take()
    parent = coins.sign(ser_tx(3, [(txid, vout, 0xFFFFFFFD)], [(value - ANCHOR_SAT, spk), (ANCHOR_SAT, P2A)]))
    ptxid = coins.node.rpc("decoderawtransaction", parent)["txid"]
    child = ser_tx(3, [(ptxid, 1, 0xFFFFFFFD)], [(ANCHOR_SAT - child_fee, "6a04" + "677a7037")])
    ctxid = coins.node.rpc("decoderawtransaction", child)["txid"]
    return parent, child, ptxid, ctxid


class Filler:
    """Large transactions paying a chosen rate, sent to every node of a Net
    until each node's mempool minimum is above a chosen rate. The nodes need
    a small -maxmempool (5 MB: about 40 of these). Each transaction spends a
    test coin to FILLER_OUTPUTS outputs of 330 sat to P2WSH(OP_TRUE) and its
    change; its fee is the rate times an upper bound of its virtual size, so
    it pays the rate or a little more, never less."""

    FILLER_OUTPUTS = 1500   # about 64.6 kvB a transaction

    def __init__(self, net, coins=None):
        self.net = net
        self.coins = coins or Coins(net, wallet="filler")
        self.sent = []      # txids sent

    def prepare(self, n, rate):
        """n coins, enough for a filler transaction at `rate` sat/vB each."""
        self.coins.split(n, self.FILLER_OUTPUTS * 330 + math.ceil(rate * 70000) + 20000)

    def one(self, rate):
        """One filler transaction (signed hex) paying at least `rate` sat/vB."""
        txid, vout, value, spk = self.coins.take()
        outs = [(330, P2WSH_TRUE)] * self.FILLER_OUTPUTS
        unsigned = ser_tx(2, [(txid, vout, 0xFFFFFFFD)], outs + [(0, spk)])
        bound = math.ceil((len(unsigned) // 2 * 4 + P2WPKH_WITNESS_WU) / 4)
        change = value - self.FILLER_OUTPUTS * 330 - math.ceil(rate * bound)
        if change < 330:
            raise RuntimeError("a filler coin is too small for %s sat/vB" % rate)
        return self.coins.sign(ser_tx(2, [(txid, vout, 0xFFFFFFFD)], outs + [(change, spk)]))

    def fill(self, rate, above, cap=200):
        """Send filler at `rate` to every node until every node's mempool
        minimum is above `above` sat/vB. Returns {node name: minimum}. Raises
        if the coins run out, the cap is reached, or every node refuses one."""
        nodes = self.net.nodes
        for _ in range(cap):
            if all(n.mempool_min() > above for n in nodes):
                return {n.name: n.mempool_min() for n in nodes}
            raw = self.one(rate)
            res = self.net.send_everywhere(raw)
            got = [t for _n, t, _e in res if t]
            if got:
                self.sent.append(got[0])
            elif not all("mempool full" in e or "mempool min fee not met" in e for _n, _t, e in res):
                raise RuntimeError("every node refused a filler transaction: %s" % res)
            # "mempool full": this one was evicted on arrival, the node's minimum
            # has just risen; the loop's test above sees it
        raise RuntimeError("the mempools are not above %s sat/vB after %d filler transactions" % (above, cap))
