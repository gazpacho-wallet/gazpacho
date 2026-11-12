#!/usr/bin/env python3
"""Fake signet Esplora servers for the gz-wallet-tx chain tests.

  fake_esplora.py WORKDIR

Listens on 127.0.0.1 only, on a port the system picks, and writes it to
WORKDIR/port. Nothing here talks to any other machine. Every path starts
with a persona:

  good, good2  answer every lookup; accept every broadcast
  flaky        answers 429 to the first 3 coin lookups, then like good
  down         answers 429 to every coin lookup
  refuse       refuses every broadcast (400, a node's own words)
  known        answers every broadcast with "already in mempool", and then
               shows the transaction (so the client may count it as had)

The wallet's one coin: the script in WORKDIR/coin_script (hex) holds one
confirmed output of 100000 sat; every other script holds nothing. Every POST
is logged to WORKDIR/posts.log as "PERSONA TXID".
"""
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORK = sys.argv[1]
GENESIS_SIGNET = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
COIN_TXID = "11" * 32
PERSONAS = ("good", "good2", "flaky", "down", "refuse", "known")
lock = threading.Lock()
lookups = {}  # persona -> coin lookups seen
seen = {}  # txid -> hex, for "known"


def varint(b, i):
    n = b[i]
    if n < 0xFD:
        return n, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + w], "little"), i + 1 + w


def txid_of(raw):
    """Display-order txid: the hash of the form without witnesses."""
    if len(raw) > 6 and raw[4] == 0 and raw[5] == 1:
        i = 6
        n_in, i = varint(raw, i)
        for _ in range(n_in):
            i += 36
            ln, i = varint(raw, i)
            i += ln + 4
        n_out, i = varint(raw, i)
        for _ in range(n_out):
            i += 8
            ln, i = varint(raw, i)
            i += ln
        body = raw[6:i]
        raw = raw[:4] + body + raw[-4:]
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def coin_scripthash():
    try:
        with open(os.path.join(WORK, "coin_script")) as f:
            return hashlib.sha256(bytes.fromhex(f.read().strip())).hexdigest()
    except OSError:
        return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def plain(self, status, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def split(self):
        parts = self.path.split("/", 2)
        if len(parts) != 3 or parts[1] not in PERSONAS:
            return None, None
        return parts[1], "/" + parts[2]

    def do_GET(self):
        who, p = self.split()
        if who is None:
            return self.plain(404, "not found")
        if p == "/block-height/0":
            return self.plain(200, GENESIS_SIGNET)
        if p == "/blocks/tip/height":
            return self.plain(200, "1000")
        if p.startswith("/scripthash/") and p.endswith("/utxo"):
            with lock:
                lookups[who] = lookups.get(who, 0) + 1
                count = lookups[who]
            if who == "down" or (who == "flaky" and count <= 3):
                return self.plain(429, "Too Many Requests")
            if p.split("/")[2] == coin_scripthash():
                return self.plain(200, json.dumps([{
                    "txid": COIN_TXID, "vout": 0, "value": 100000,
                    "status": {"confirmed": True, "block_height": 900,
                               "block_hash": "00" * 32, "block_time": 1793823982}}]))
            return self.plain(200, "[]")
        if p.startswith("/tx/"):
            parts = p.split("/")
            with lock:
                hexed = seen.get(parts[2])
            if who == "known" and hexed is not None:
                if parts[3:] == ["status"]:
                    return self.plain(200, '{"confirmed":false}')
                if parts[3:] == ["hex"]:
                    return self.plain(200, hexed)
            if parts[3:] == ["status"]:
                return self.plain(200, '{"confirmed":false}')
            return self.plain(404, "Transaction not found")
        return self.plain(404, "not found")

    def do_POST(self):
        who, p = self.split()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if who is None or p != "/tx":
            return self.plain(404, "not found")
        try:
            txid = txid_of(bytes.fromhex(body.decode()))
        except (ValueError, IndexError):
            return self.plain(400, "TX decode failed")
        with lock:
            with open(os.path.join(WORK, "posts.log"), "a") as log:
                log.write("%s %s\n" % (who, txid))
            seen[txid] = body.decode()
        if who == "refuse":
            return self.plain(400, 'sendrawtransaction RPC error: {"code":-25,'
                                   '"message":"bad-txns-inputs-missingorspent"}')
        if who == "known":
            return self.plain(400, 'sendrawtransaction RPC error: {"code":-27,'
                                   '"message":"Transaction already in block chain"}')
        return self.plain(200, txid)


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


srv = Quiet(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
with open(os.path.join(WORK, "port.tmp"), "w") as f:
    f.write("%d\n" % srv.server_address[1])
os.rename(os.path.join(WORK, "port.tmp"), os.path.join(WORK, "port"))
while True:
    time.sleep(3600)
