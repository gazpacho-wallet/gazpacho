#!/usr/bin/env python3
"""An Esplora look-alike over a Bitcoin Core regtest node, for tests only.

The chain port (ports/chain) speaks Esplora's HTTP API and nothing else. On
regtest there is no public Esplora, so this serves the endpoints the port
uses (docs/notes/chain-port.md) from Core's RPC: the program's chain worker,
its watches, its broadcasts and the wallet's coins then meet a real chain.

    esplora-regtest.py BITCOIN_DATADIR RPC_PORT LISTEN_PORT_FILE

Listens on 127.0.0.1 only, on a port the system picks, written to
LISTEN_PORT_FILE. Reads the RPC cookie of the regtest node in BITCOIN_DATADIR.
With GZ_ESPLORA_LOG set to a file name, one line per GET is appended to it:
the time, the client's port, the wait for the lock, the time taken, the
status and the path (what a chain worker asked, and when).
Refuses to serve anything but regtest (getblockchaininfo.chain). Standard
library only. Test tool: never used against signet or any public network.

Endpoints: /blocks/tip/height, /block-height/N, /block/H/header, /block/H,
/block/H/txid/0, /tx/T/hex, /tx/T/status, /tx/T/outspend/N,
/tx/T/merkle-proof, /scripthash/S/utxo (S is sha256 of the script, in either
byte order), /fee-estimates, POST /tx. A package endpoint is answered 404 (no
package relay), as some public servers do.
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
LOCK = threading.Lock()


def rpc(method, *params):
    with open(os.path.join(DATADIR, "regtest", ".cookie")) as f:
        auth = base64.b64encode(f.read().strip().encode()).decode()
    c = http.client.HTTPConnection("127.0.0.1", RPC_PORT, timeout=30)
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
    c.request("POST", "/", body, {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    r = json.loads(c.getresponse().read())
    c.close()
    if r.get("error"):
        raise RuntimeError(r["error"].get("message", "error"))
    return r["result"]


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


def status(h):
    if h is None:
        return {"confirmed": False}
    hdr = rpc("getblockheader", IDX.hashes[h])
    return {"confirmed": True, "block_height": h, "block_hash": IDX.hashes[h], "block_time": hdr["time"]}


def answer(path, body=None):
    """(code, content type, bytes) for one request."""
    IDX.sync()
    p = path.split("?")[0].strip("/").split("/")
    if body is not None:
        if p == ["tx"]:
            try:
                return 200, "text/plain", rpc("sendrawtransaction", body.decode().strip(), 0).encode()
            except RuntimeError as e:
                return 400, "text/plain", ("sendrawtransaction RPC error: " + str(e)).encode()
        return 404, "text/plain", b"Not found"
    if p == ["blocks", "tip", "height"]:
        return 200, "text/plain", str(len(IDX.hashes) - 1).encode()
    if len(p) == 2 and p[0] == "block-height":
        h = int(p[1])
        if h >= len(IDX.hashes):
            return 404, "text/plain", b"Block not found"
        return 200, "text/plain", IDX.hashes[h].encode()
    if p[0] == "block" and len(p) >= 2:
        bh = p[1]
        if bh not in IDX.hashes:
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
            try:
                return 200, "text/plain", rpc("getrawtransaction", txid).encode()
            except RuntimeError:
                return 404, "text/plain", b"Transaction not found"
        if p[2] == "status":
            if txid in IDX.tx_height:
                return 200, "application/json", json.dumps(status(IDX.tx_height[txid])).encode()
            return 200, "application/json", b'{"confirmed":false}'
        if p[2] == "outspend" and len(p) == 4:
            key = (txid, int(p[3]))
            s = IDX.spent.get(key)
            if s is None:
                s = IDX.mempool()[1].get(key)
            if s is None:
                return 200, "application/json", b'{"spent":false}'
            return 200, "application/json", json.dumps({"spent": True, "txid": s[0], "vin": s[1],
                                                        "status": status(s[2])}).encode()
        if p[2] == "merkle-proof":
            h = IDX.tx_height.get(txid)
            if h is None:
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
        moutputs, mspent = IDX.mempool()
        if spk is None:
            spk = IDX.scripts.get(p[1].lower())   # first seen in the mempool
        res = []
        if spk is not None:
            for src in (IDX.outputs, moutputs):
                for (t, v), (s, val, h) in src.items():
                    if s == spk and (t, v) not in IDX.spent and (t, v) not in mspent:
                        res.append({"txid": t, "vout": v, "status": status(h), "value": val})
        res.sort(key=lambda r: (r["txid"], r["vout"]))
        return 200, "application/json", json.dumps(res).encode()
    if len(p) == 2 and p[0] == "scripthash":
        # the address's stats (chain_stats, mempool_stats): every transaction
        # that paid or spent it, as electrs gives them
        spk = IDX.scripts.get(p[1].lower())
        moutputs, mspent = IDX.mempool()

        def stats(funded, spent):
            # funded: [((txid, vout), value)]; spent: [((txid, vout), value, spender txid)]
            txs = {t for (t, _v), _val in funded} | {sp for _k, _val, sp in spent}
            return {"funded_txo_count": len(funded), "funded_txo_sum": sum(val for _k, val in funded),
                    "spent_txo_count": len(spent), "spent_txo_sum": sum(val for _k, val, _sp in spent),
                    "tx_count": len(txs)}
        cf, mf, cs, ms = [], [], [], []
        if spk is not None:
            cf = [((t, v), val) for (t, v), (s, val, h) in IDX.outputs.items() if s == spk]
            mf = [((t, v), val) for (t, v), (s, val, h) in moutputs.items() if s == spk]
            vals = dict(cf + mf)
            cs = [(k, vals[k], IDX.spent[k][0]) for k in vals if k in IDX.spent]
            ms = [(k, vals[k], mspent[k][0]) for k in vals if k in mspent and k not in IDX.spent]
        body = {"scripthash": p[1].lower(), "chain_stats": stats(cf, cs), "mempool_stats": stats(mf, ms)}
        return 200, "application/json", json.dumps(body).encode()
    if p == ["fee-estimates"]:
        return 200, "application/json", b'{"1":1.0,"6":1.0,"144":1.0}'
    return 404, "text/plain", b"Not found"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, data):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass   # the client went away (a timeout of its own)

    def do_GET(self):
        t0 = time.time()
        with LOCK:
            t1 = time.time()
            try:
                r = answer(self.path)
                self.send(*r)
            except Exception as e:  # a test tool: say what failed
                r = (500, "text/plain", str(e).encode())
                self.send(*r)
        log = os.environ.get("GZ_ESPLORA_LOG")
        if log:
            with open(log, "a") as f:
                f.write("%.3f port=%d wait=%.3f took=%.3f code=%d %s%s" % (
                    t0, self.client_address[1], t1 - t0, time.time() - t1, r[0], self.path, chr(10)))

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
