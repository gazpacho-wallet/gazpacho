#!/usr/bin/env python3
"""An Esplora look-alike over a Bitcoin Core regtest node, for tests only.

The chain port (ports/chain) speaks Esplora's HTTP API and nothing else. On
regtest there is no public Esplora, so this serves the endpoints the port
uses (docs/notes/chain-port.md) from Core's RPC: the program's chain worker,
its watches, its broadcasts and the wallet's coins then meet a real chain.

    esplora-regtest.py BITCOIN_DATADIR RPC_PORT LISTEN_PORT_FILE
                       [--name NAME] [--control FILE] [--no-package]

Listens on 127.0.0.1 only, on a port the system picks, written to
LISTEN_PORT_FILE. Reads the RPC cookie of the regtest node in BITCOIN_DATADIR.
With GZ_ESPLORA_LOG set to a file name, one line per GET is appended to it:
the time, the client's port, the wait for the lock, the time taken, the
status and the path (what a chain worker asked, and when).
With GZ_ESPLORA_THROTTLE set to N:W, it throttles as a public server does:
a GET beyond N in the last W seconds, from any client, is answered 429 Too
Many Requests (program_chain_throttle; signet run 2's preparation).
Refuses to serve anything but regtest (getblockchaininfo.chain). Standard
library only. Test tool: never used against signet or any public network.

Endpoints: /blocks/tip/height, /block-height/N, /block/H/header, /block/H,
/block/H/txid/0, /tx/T/hex, /tx/T/status, /tx/T/outspend/N,
/tx/T/merkle-proof, /scripthash/S/utxo (S is sha256 of the script, in either
byte order), /fee-estimates, /v1/fees/recommended (mempool.space's form; its
minimumFee is the node's mempool minimum in sat/vB), POST /tx, and POST
/txs/package and /v1/txs/package (a JSON array of transactions in hex,
passed to Core's submitpackage; its answer is returned as Core wrote it, and
an RPC error is answered 400 with Core's words).

Options (docs/SLICE-1.5-PLAN.md, P7):
  --name NAME     the operator this server stands for: sent as the
                  X-Gz-Operator header of every answer and written in each
                  log line (two look-alikes on one machine are told apart;
                  the program is told the same name by --chain-operator)
  --no-package    the package paths answer 404, as servers without package
                  relay do (S12's 404 case)
  --control FILE  a JSON object read again whenever the file changes, so a
                  test changes what this server says while it runs:
      "package": false             as --no-package (true: served)
      "hide": ["<txid>", ...]      for each: /tx/T/status unconfirmed,
                                   /tx/T/hex and /tx/T/merkle-proof 404, its
                                   outputs unspent-and-absent and the coins
                                   it spends unspent, everywhere (S13)
      "freeze_at": H               the tip stays at height H: no block above
                                   H is served, and what confirmed above it
                                   is unconfirmed (S13 step 2)
      "mempool_min": R             the mempool minimum this server reports,
                                   in sat/vB, whatever the node's (S7 run d)
  A missing or unreadable control file is no change.
"""
import base64
import hashlib
import http.client
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATADIR, RPC_PORT, PORT_FILE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
NAME, CONTROL_FILE, PACKAGE_DEFAULT = "", "", True
_a = sys.argv[4:]
while _a:
    if _a[0] == "--name" and len(_a) > 1:
        NAME, _a = _a[1], _a[2:]
    elif _a[0] == "--control" and len(_a) > 1:
        CONTROL_FILE, _a = _a[1], _a[2:]
    elif _a[0] == "--no-package":
        PACKAGE_DEFAULT, _a = False, _a[1:]
    else:
        raise SystemExit("esplora-regtest: unknown option " + _a[0])
LOCK = threading.Lock()
THROTTLE = os.environ.get("GZ_ESPLORA_THROTTLE", "")
RECENT = []   # when each GET answered in the throttle's window started


class Control:
    """What the test asks this server to say (--control), read again on change."""

    def __init__(self):
        self.stamp = None
        self.package, self.hide, self.freeze_at, self.mempool_min = PACKAGE_DEFAULT, set(), None, None

    def refresh(self):
        if not CONTROL_FILE:
            return
        try:
            st = os.stat(CONTROL_FILE)
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
            if stamp == self.stamp:
                return
            with open(CONTROL_FILE) as f:
                c = json.load(f)
        except (OSError, ValueError):
            return
        self.stamp = stamp
        self.package = bool(c.get("package", PACKAGE_DEFAULT))
        self.hide = {str(t).lower() for t in c.get("hide", [])}
        self.freeze_at = None if c.get("freeze_at") is None else int(c["freeze_at"])
        self.mempool_min = None if c.get("mempool_min") is None else float(c["mempool_min"])


CTL = Control()


def throttled(now):
    """True if a GET now is one too many for GZ_ESPLORA_THROTTLE (N:W); counts it if not."""
    if not THROTTLE:
        return False
    n, w = THROTTLE.split(":")
    while RECENT and RECENT[0] < now - float(w):
        RECENT.pop(0)
    if len(RECENT) >= int(n):
        return True
    RECENT.append(now)
    return False


def rpc_text(method, *params):
    """(parsed reply, reply text) of one RPC call; raises on an RPC error."""
    with open(os.path.join(DATADIR, "regtest", ".cookie")) as f:
        auth = base64.b64encode(f.read().strip().encode()).decode()
    c = http.client.HTTPConnection("127.0.0.1", RPC_PORT, timeout=30)
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
    c.request("POST", "/", body, {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    text = c.getresponse().read().decode()
    c.close()
    r = json.loads(text)
    if r.get("error"):
        raise RuntimeError(r["error"].get("message", "error"))
    return r["result"], text


def rpc(method, *params):
    return rpc_text(method, *params)[0]


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Index:
    """Every output and spend of the active chain, built block by block (a
    regtest chain is small); rebuilt from scratch after a reorganisation."""

    def __init__(self):
        self.hashes = []          # height -> block hash
        self.outputs = {}         # (txid, vout) -> (script hex, value sat, height)
        self.spent = {}           # (txid, vout) -> (spender txid, vin, height)
        self.tx_height = {}       # txid -> height
        self.scripts = {}         # sha256 hex, both orders -> script hex

    def sync(self):
        tip = rpc("getblockcount")
        # A reorganisation: the stored hash at some height is no longer the chain's.
        while self.hashes and (len(self.hashes) - 1 > tip or rpc("getblockhash", len(self.hashes) - 1) != self.hashes[-1]):
            self.__init__()
        for h in range(len(self.hashes), tip + 1):
            bh = rpc("getblockhash", h)
            blk = rpc("getblock", bh, 2)
            for tx in blk["tx"]:
                self.add_tx(tx, h)
            self.hashes.append(bh)

    def note_script(self, spk):
        d = hashlib.sha256(bytes.fromhex(spk)).digest()
        self.scripts[d.hex()] = spk
        self.scripts[d[::-1].hex()] = spk

    def add_tx(self, tx, h, into=None):
        outs, spent = (self.outputs, self.spent) if into is None else into
        if h is not None:
            self.tx_height[tx["txid"]] = h
        for i, vin in enumerate(tx["vin"]):
            if "txid" in vin:
                spent[(vin["txid"], vin["vout"])] = (tx["txid"], i, h)
        for o in tx["vout"]:
            spk = o["scriptPubKey"]["hex"]
            self.note_script(spk)
            outs[(tx["txid"], o["n"])] = (spk, int(round(o["value"] * 1e8)), h)

    def mempool(self):
        outs, spent = {}, {}
        for txid in rpc("getrawmempool"):
            try:
                self.add_tx(rpc("getrawtransaction", txid, True), None, (outs, spent))
            except RuntimeError:
                pass   # left the mempool meanwhile
        return outs, spent


IDX = Index()


def top():
    """The tip this server shows: the chain's, or the frozen height (--control freeze_at)."""
    tip = len(IDX.hashes) - 1
    return tip if CTL.freeze_at is None else min(tip, CTL.freeze_at)


def seen_height(h):
    """A confirmation height as this server shows it: None (unconfirmed) above its tip."""
    return None if h is None or h > top() else h


def status(h):
    h = seen_height(h)
    if h is None:
        return {"confirmed": False}
    hdr = rpc("getblockheader", IDX.hashes[h])
    return {"confirmed": True, "block_height": h, "block_hash": IDX.hashes[h], "block_time": hdr["time"]}


def hidden(txid):
    return txid in CTL.hide


def spends():
    """Every spend this server shows, chain then mempool: hidden spenders left out."""
    moutputs, mspent = IDX.mempool()
    chain = {k: v for k, v in IDX.spent.items() if not hidden(v[0])}
    mem = {k: v for k, v in mspent.items() if not hidden(v[0])}
    return moutputs, chain, mem


def package(body):
    """POST /txs/package: Core's submitpackage, its answer as Core wrote it."""
    try:
        txs = json.loads(body.decode())
    except (UnicodeDecodeError, ValueError):
        return 400, "text/plain", b"Invalid package: not JSON"
    if not isinstance(txs, list) or not all(isinstance(t, str) for t in txs):
        return 400, "text/plain", b"Invalid package: not an array of hex strings"
    try:
        result, text = rpc_text("submitpackage", txs)
    except RuntimeError as e:
        return 400, "text/plain", ("submitpackage RPC error: " + str(e)).encode()
    # The reply is {"result":...,"error":null,"id":1}: the result's own text keeps
    # Core's numbers as written (0.00000240, not 2.4e-06).
    head, tail = '{"result":', ',"error":null,"id":1}'
    t = text.strip()
    raw = t[len(head):-len(tail)] if t.startswith(head) and t.endswith(tail) else json.dumps(result)
    return 200, "application/json", raw.encode()


def answer(path, body=None):
    """(code, content type, bytes) for one request."""
    CTL.refresh()
    IDX.sync()
    p = path.split("?")[0].strip("/").split("/")
    if body is not None:
        if p == ["tx"]:
            try:
                return 200, "text/plain", rpc("sendrawtransaction", body.decode().strip(), 0).encode()
            except RuntimeError as e:
                return 400, "text/plain", ("sendrawtransaction RPC error: " + str(e)).encode()
        if p in (["txs", "package"], ["v1", "txs", "package"]) and CTL.package:
            return package(body)
        return 404, "text/plain", b"Not found"
    if p == ["blocks", "tip", "height"]:
        return 200, "text/plain", str(top()).encode()
    if len(p) == 2 and p[0] == "block-height":
        h = int(p[1])
        if h > top():
            return 404, "text/plain", b"Block not found"
        return 200, "text/plain", IDX.hashes[h].encode()
    if p[0] == "block" and len(p) >= 2:
        bh = p[1]
        if bh not in IDX.hashes[:top() + 1]:
            return 404, "text/plain", b"Block not found"
        if len(p) == 3 and p[2] == "header":
            return 200, "text/plain", rpc("getblockheader", bh, False).encode()
        if len(p) == 4 and p[2] == "txid":
            return 200, "text/plain", rpc("getblock", bh, 1)["tx"][int(p[3])].encode()
        if len(p) == 2:
            b = rpc("getblock", bh, 1)
            j = {"id": bh, "height": b["height"], "version": b["version"], "timestamp": b["time"],
                 "tx_count": b["nTx"], "size": b["size"], "weight": b["weight"], "merkle_root": b["merkleroot"],
                 "previousblockhash": b.get("previousblockhash"), "mediantime": b["mediantime"],
                 "nonce": b["nonce"], "bits": int(b["bits"], 16), "difficulty": b["difficulty"]}
            return 200, "application/json", json.dumps(j).encode()
    if p[0] == "tx" and len(p) >= 3:
        txid = p[1]
        if p[2] == "hex":
            if hidden(txid):
                return 404, "text/plain", b"Transaction not found"
            try:
                return 200, "text/plain", rpc("getrawtransaction", txid).encode()
            except RuntimeError:
                return 404, "text/plain", b"Transaction not found"
        if p[2] == "status":
            if txid in IDX.tx_height and not hidden(txid):
                return 200, "application/json", json.dumps(status(IDX.tx_height[txid])).encode()
            return 200, "application/json", b'{"confirmed":false}'
        if p[2] == "outspend" and len(p) == 4:
            key = (txid, int(p[3]))
            s = None
            if not hidden(txid):
                s = IDX.spent.get(key)
                if s is not None and hidden(s[0]):
                    s = None
                if s is None:
                    s = spends()[2].get(key)
            if s is None:
                return 200, "application/json", b'{"spent":false}'
            return 200, "application/json", json.dumps({"spent": True, "txid": s[0], "vin": s[1],
                                                        "status": status(s[2])}).encode()
        if p[2] == "merkle-proof":
            h = seen_height(IDX.tx_height.get(txid))
            if h is None or hidden(txid):
                return 404, "text/plain", b"Transaction not found"
            txids = rpc("getblock", IDX.hashes[h], 1)["tx"]
            pos = txids.index(txid)
            level = [bytes.fromhex(t)[::-1] for t in txids]
            i, merkle = pos, []
            while len(level) > 1:
                if len(level) % 2:
                    level.append(level[-1])
                merkle.append(level[i ^ 1][::-1].hex())
                level = [dsha(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
                i //= 2
            return 200, "application/json", json.dumps({"block_height": h, "merkle": merkle, "pos": pos}).encode()
    if len(p) == 3 and p[0] == "scripthash" and p[2] == "utxo":
        spk = IDX.scripts.get(p[1].lower())
        moutputs, cspent, mspent = spends()
        if spk is None:
            spk = IDX.scripts.get(p[1].lower())   # first seen in the mempool
        res = []
        if spk is not None:
            for src in (IDX.outputs, moutputs):
                for (t, v), (s, val, h) in src.items():
                    if s == spk and not hidden(t) and (t, v) not in cspent and (t, v) not in mspent:
                        res.append({"txid": t, "vout": v, "status": status(h), "value": val})
        res.sort(key=lambda r: (r["txid"], r["vout"]))
        return 200, "application/json", json.dumps(res).encode()
    if len(p) == 2 and p[0] == "scripthash":
        # the address's stats (chain_stats, mempool_stats): every transaction
        # that paid or spent it, as electrs gives them
        spk = IDX.scripts.get(p[1].lower())
        moutputs, cspent, mspent = spends()

        def stats(funded, spent):
            # funded: [((txid, vout), value)]; spent: [((txid, vout), value, spender txid)]
            txs = {t for (t, _v), _val in funded} | {sp for _k, _val, sp in spent}
            return {"funded_txo_count": len(funded), "funded_txo_sum": sum(val for _k, val in funded),
                    "spent_txo_count": len(spent), "spent_txo_sum": sum(val for _k, val, _sp in spent),
                    "tx_count": len(txs)}
        cf, mf, cs, ms = [], [], [], []
        if spk is not None:
            cf = [((t, v), val) for (t, v), (s, val, h) in IDX.outputs.items() if s == spk and not hidden(t)]
            mf = [((t, v), val) for (t, v), (s, val, h) in moutputs.items() if s == spk and not hidden(t)]
            vals = dict(cf + mf)
            cs = [(k, vals[k], cspent[k][0]) for k in vals if k in cspent]
            ms = [(k, vals[k], mspent[k][0]) for k in vals if k in mspent and k not in cspent]
        body = {"scripthash": p[1].lower(), "chain_stats": stats(cf, cs), "mempool_stats": stats(mf, ms)}
        return 200, "application/json", json.dumps(body).encode()
    if p == ["fee-estimates"]:
        return 200, "application/json", b'{"1":1.0,"6":1.0,"144":1.0}'
    if p == ["v1", "fees", "recommended"]:
        # mempool.space's form; minimumFee is the node's mempool minimum
        # (getmempoolinfo.mempoolminfee, BTC/kvB to sat/vB), or the control's
        m = CTL.mempool_min
        if m is None:
            m = round(rpc("getmempoolinfo")["mempoolminfee"] * 1e5, 3)
        rate = max(1.0, m)
        return 200, "application/json", json.dumps({"fastestFee": rate, "halfHourFee": rate, "hourFee": rate,
                                                    "economyFee": rate, "minimumFee": m}).encode()
    return 404, "text/plain", b"Not found"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, data):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if NAME:
                self.send_header("X-Gz-Operator", NAME)
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass   # the client went away (a timeout of its own)

    def do_GET(self):
        t0 = time.time()
        with LOCK:
            t1 = time.time()
            try:
                r = (429, "text/plain", b"Too Many Requests") if throttled(t0) else answer(self.path)
                self.send(*r)
            except Exception as e:  # a test tool: say what failed
                r = (500, "text/plain", str(e).encode())
                self.send(*r)
        log = os.environ.get("GZ_ESPLORA_LOG")
        if log:
            with open(log, "a") as f:
                f.write("%.3f port=%d%s wait=%.3f took=%.3f code=%d %s%s" % (
                    t0, self.client_address[1], " op=" + NAME if NAME else "", t1 - t0, time.time() - t1,
                    r[0], self.path, chr(10)))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        with LOCK:
            try:
                self.send(*answer(self.path, body))
            except Exception as e:
                self.send(500, "text/plain", str(e).encode())


def main():
    if rpc("getblockchaininfo")["chain"] != "regtest":
        raise SystemExit("esplora-regtest: the node is not on regtest")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(PORT_FILE + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(PORT_FILE + ".tmp", PORT_FILE)
    srv.serve_forever()


if __name__ == "__main__":
    main()
