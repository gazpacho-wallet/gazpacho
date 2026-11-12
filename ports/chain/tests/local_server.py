#!/usr/bin/env python3
"""Local servers for the chain port's transport and tool tests.

Listens on 127.0.0.1 only, on ports the system picks, and writes them to
WORKDIR/ports as shell assignments. Started and stopped by local-servers.sh.

  local_server.py WORKDIR DATADIR

One plain-HTTP server offers:
  - hostile answers for the transport test (/ok, /big, /bigchunked, /endless,
    /redir, /slow, /trickle, /gzip, /hugeheader, /agent, /post);
  - small Esplora look-alikes under /<persona>/..., built from the recorded
    signet answers in DATADIR. Personas: honest, honest2 (the same answers),
    hider (hides transaction A), mainnet (claims mainnet's block 0), behind
    (has not seen block 329439), feehigh (another operator's fee estimates).
Three HTTPS servers offer /ok with, in turn: a certificate for localhost
signed by the test authority; one for another name signed by the same
authority; a self-signed one. Every POST is logged to WORKDIR/posts.log.
"""
import gzip
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORK, DATA = sys.argv[1], sys.argv[2]

TX_A = "8690387a65262437580d45b77f1cb0792faff46cecb72c5ee22390e5193a6c9a"
TX_B = "a8f29683fcf6687b0944580cca8ee91b44c7ce3fa79fddcafc3c33334e5f411f"
TX_CB = "f5b99c0f9b9150d7b980e249419425152f849b0d3e3bf0c1052c534688a18f54"
TX_SP = "ee18add119d09dc5b01cde93367391947495b656c30c5935cbde8374aa9d944b"
TX_NONE = "0000000000000000000000000000000000000000000000000000000000000001"
H37 = "00000006b68515903881b6dc0f91070ac24d499369dd97f7778d8612d39108b5"
H38 = "0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4"
H39 = "0000000598cb99835ee5e9b03bbbf95e3627cb8ac471e664f19e02b43f8e8318"
SCRIPT_KEY = "c7ecf6689f2f6ac8edddcd98b48ab7ab6283d59ccf1c692124f86ba503387cd0"
GENESIS_SIGNET = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
GENESIS_MAINNET = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def data(name):
    with open(os.path.join(DATA, name), "rb") as f:
        return f.read()


def honest_routes():
    r = {
        "/blocks/tip/height": (200, b"329439"),
        "/block-height/0": (200, GENESIS_SIGNET.encode()),
        "/block-height/329440": (404, b"Block not found"),
        "/fee-estimates": (200, data("fee_estimates_mempool.json")),
        "/tx/%s/status" % TX_NONE: (200, b'{"confirmed":false}'),
        "/tx/%s/hex" % TX_NONE: (404, b"Transaction not found"),
        "/tx/%s/outspend/0" % TX_NONE: (200, b'{"spent":false}'),
    }
    files = {
        "/block-height/329437": "block_hash_329437.txt",
        "/block-height/329438": "block_hash_329438.txt",
        "/block-height/329439": "block_hash_329439.txt",
        "/block/%s/header" % H37: "header_329437.txt",
        "/block/%s/header" % H38: "header_329438.txt",
        "/block/%s/header" % H39: "header_329439.txt",
        "/block/%s" % H38: "block_329438.json",
        "/block/%s/txid/0" % H38: "block_329438_txid_0.txt",
        "/tx/%s/status" % TX_A: "tx_a_status.json",
        "/tx/%s/hex" % TX_A: "tx_a_hex.txt",
        "/tx/%s/merkle-proof" % TX_A: "tx_a_merkle_proof.json",
        "/tx/%s/outspend/0" % TX_A: "tx_a_outspend_0.json",
        "/tx/%s/outspend/2" % TX_A: "tx_a_outspend_2.json",
        "/tx/%s/hex" % TX_CB: "tx_coinbase_hex.txt",
        "/tx/%s/status" % TX_SP: "tx_spender_status.json",
        "/tx/%s/hex" % TX_SP: "tx_spender_hex.txt",
        "/tx/%s/merkle-proof" % TX_CB: "tx_coinbase_merkle_proof.json",
        "/scripthash/%s/utxo" % SCRIPT_KEY: "utxo_script_a2.json",
    }
    for path, name in files.items():
        r[path] = (200, data(name))
    return r


PERSONAS = {"honest": honest_routes(), "honest2": honest_routes(), "hider": honest_routes(),
            "mainnet": honest_routes(), "behind": honest_routes(), "feehigh": honest_routes()}
PERSONAS["hider"]["/tx/%s/status" % TX_A] = (200, b'{"confirmed":false}')
PERSONAS["hider"]["/tx/%s/hex" % TX_A] = (404, b"Transaction not found")
PERSONAS["mainnet"]["/block-height/0"] = (200, GENESIS_MAINNET.encode())
# has not seen block 329439 yet: the spender is still in its mempool
PERSONAS["behind"]["/blocks/tip/height"] = (200, b"329438")
PERSONAS["behind"]["/block-height/329439"] = (404, b"Block not found")
PERSONAS["behind"]["/tx/%s/status" % TX_SP] = (200, b'{"confirmed":false}')
# the other operator's recorded estimates: 10 against 1 sat/vB for the next block
PERSONAS["feehigh"]["/fee-estimates"] = (200, data("fee_estimates_blockstream.json"))
POST_ANSWER = (400, data("post_known_blockstream.txt"))
post_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def plain(self, status, body, extra=()):
        self.send_response(status)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            self.route_get()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            with post_lock:
                with open(os.path.join(WORK, "posts.log"), "a") as log:
                    log.write("%s %d\n" % (self.path, len(body)))
            if self.path == "/post":
                ctype = self.headers.get("Content-Type", "")
                self.plain(200, ctype.encode() + b"|" + body)
            elif self.path.endswith("/tx") and self.path.split("/")[1] in PERSONAS:
                self.plain(*POST_ANSWER)
            else:
                self.plain(404, b"")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def route_get(self):
        p = self.path
        parts = p.split("/", 2)
        if len(parts) == 3 and parts[1] in PERSONAS:
            status, body = PERSONAS[parts[1]].get("/" + parts[2], (404, b"not found"))
            self.plain(status, body)
        elif p == "/ok":
            self.plain(200, b"330437")
        elif p == "/agent":
            self.plain(200, self.headers.get("User-Agent", "").encode())
        elif p == "/big":
            self.plain(200, b"9" * 1000000)
        elif p == "/bigchunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(2000):
                chunk = b"9" * 500
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.write(b"0\r\n\r\n")
        elif p == "/endless":
            # never ends: only the client stopping, or its time limit, ends it
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"9" * 1000
            while True:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.01)
        elif p == "/redir":
            self.plain(302, b"", [("Location", "/ok")])
        elif p == "/slow":
            time.sleep(5)
            self.plain(200, b"ok")
        elif p == "/trickle":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(40):
                self.wfile.write(b"1\r\n9\r\n")
                self.wfile.flush()
                time.sleep(0.3)
            self.wfile.write(b"0\r\n\r\n")
        elif p == "/gzip":
            self.plain(200, gzip.compress(b"0" * 50000), [("Content-Encoding", "gzip")])
        elif p == "/hugeheader":
            self.send_response(200)
            for i in range(200):
                self.send_header("X-Pad-%d" % i, "a" * 4000)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.plain(404, b"")


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients are expected to hang up on us


def serve(cert=None):
    srv = Quiet(("127.0.0.1", 0), Handler)
    if cert is not None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(WORK, cert + ".pem"), os.path.join(WORK, cert + ".key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


ports = {"HTTP_PORT": serve(), "GOOD_PORT": serve("good"), "WRONGNAME_PORT": serve("wrongname"),
         "SELFSIGNED_PORT": serve("selfsigned")}
with open(os.path.join(WORK, "ports.tmp"), "w") as f:
    for k, v in ports.items():
        f.write("%s=%d\n" % (k, v))
os.rename(os.path.join(WORK, "ports.tmp"), os.path.join(WORK, "ports"))
while True:
    time.sleep(3600)
