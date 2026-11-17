#!/usr/bin/env python3
"""A scripted Esplora look-alike for the chain worker test (test_stub.c).

    watch_stub.py WORKDIR

Listens on 127.0.0.1 only, on a port the system picks, written to
WORKDIR/stub.port. It plays two servers, under /a/... and /b/.... What each
says is read, at every request, from the scene the test has published:
WORKDIR/current names a directory, and in it a.routes and b.routes hold

    G <path> <status> <hex body, or ->     the answer to GET <path>
    P <path> <rule>                        how POST <path> is answered
    X <fault> <text>                       misbehave on paths containing <text>

The test program writes these from its made-up chain (sim.c, sim_dump), so
the stub holds no chain of its own. A GET that is not listed is answered as
a server answers about something it has never seen.

POST rules: /tx: accept, known, reject, down. /txs/package and
/v1/txs/package: ok, fail, none, down.

Faults (every path if <text> is *):
    delay MS    answer after MS milliseconds (X delay 30000 *)
    drop        send the headers and half the body, then close
    drip        send the body one byte every 30 ms
    huge        send two megabytes
    close       close without answering
    status N    answer with status N and an empty body

Every request is appended to WORKDIR/a.log or b.log as "GET <path>" or
"POST <path> <body length>".
"""
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORK = sys.argv[1]
log_lock = threading.Lock()


def scene(persona):
    """The routes, POST rules and faults now published for a persona."""
    gets, posts, faults = {}, {}, []
    try:
        with open(os.path.join(WORK, "current")) as f:
            where = f.read().strip()
        with open(os.path.join(WORK, where, persona + ".routes")) as f:
            lines = f.read().splitlines()
    except OSError:
        return gets, posts, faults
    for line in lines:
        part = line.split(" ")
        if part[0] == "G" and len(part) == 4:
            gets[part[1]] = (int(part[2]), b"" if part[3] == "-" else bytes.fromhex(part[3]))
        elif part[0] == "P" and len(part) == 3:
            posts[part[1]] = part[2]
        elif part[0] == "X" and len(part) >= 3:
            faults.append((part[1], part[2:]))
    return gets, posts, faults


def unlisted(path):
    """What a server says about a block or transaction it does not have."""
    if path.startswith("/tx/") and path.endswith("/status"):
        return 200, b'{"confirmed":false}'
    if path.startswith("/tx/") and "/outspend/" in path:
        return 200, b'{"spent":false}'
    if path.startswith("/block-height/"):
        return 404, b"Block not found"
    return 404, b"not found"


def txid(raw):
    """The txid of a transaction without witness data, as servers print it."""
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def package_answer(body, ok):
    ids = [txid(bytes.fromhex(h)) for h in json.loads(body)]
    if ok:
        results = {i: {"txid": i, "vsize": 61, "fees": {"base": 0.000001}} for i in ids}
        return {"package_msg": "success", "tx-results": results, "replaced-transactions": []}
    errors = ["min relay fee not met, 0 < 61", "bad-txns-inputs-missingorspent"]
    results = {i: {"txid": i, "error": errors[min(n, 1)]} for n, i in enumerate(ids)}
    return {"package_msg": "transaction failed", "tx-results": results,
            "replaced-transactions": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def note(self, persona, text):
        with log_lock:
            with open(os.path.join(WORK, persona + ".log"), "a") as f:
                f.write(text + "\n")

    def split(self):
        part = self.path.split("/", 2)
        if len(part) == 3 and part[1] in ("a", "b"):
            return part[1], "/" + part[2]
        return None, self.path

    def hang_up(self):
        self.close_connection = True
        try:
            self.connection.shutdown(2)
        except OSError:
            pass

    def answer(self, status, body, faults, path):
        """Sends the answer, misbehaving as the scene says. False: hung up."""
        for kind, arg in faults:
            if arg[-1] != "*" and arg[-1] not in path:
                continue
            if kind == "delay":
                time.sleep(int(arg[0]) / 1000.0)
            elif kind == "close":
                self.hang_up()
                return
            elif kind == "status":
                status, body = int(arg[0]), b""
            elif kind == "huge":
                body = b"9" * 2000000
            elif kind == "drop":
                self.send_response(status)
                self.send_header("Content-Length", str(len(body) + 40))
                self.end_headers()
                self.wfile.write(body[:len(body) // 2])
                self.wfile.flush()
                self.hang_up()
                return
            elif kind == "drip":
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                for i in range(len(body)):
                    self.wfile.write(body[i:i + 1])
                    self.wfile.flush()
                    time.sleep(0.03)
                return
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            persona, path = self.split()
            if persona is None:
                self.answer(404, b"", [], path)
                return
            self.note(persona, "GET " + path)
            gets, _, faults = scene(persona)
            status, body = gets.get(path) or unlisted(path)
            self.answer(status, body, faults, path)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_POST(self):
        try:
            persona, path = self.split()
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if persona is None:
                self.answer(404, b"", [], path)
                return
            self.note(persona, "POST %s %d" % (path, len(body)))
            _, posts, faults = scene(persona)
            rule = posts.get(path, "none")
            if rule == "down":
                self.hang_up()
            elif path == "/tx" and rule == "accept":
                self.answer(200, txid(bytes.fromhex(body.decode())).encode(), faults, path)
            elif path == "/tx" and rule == "known":
                self.answer(400, b'sendrawtransaction RPC error: {"code":-27,"message":'
                                 b'"Transaction outputs already in utxo set"}', faults, path)
            elif path == "/tx" and rule == "reject":
                self.answer(400, b'sendrawtransaction RPC error: {"code":-26,"message":'
                                 b'"min relay fee not met, 6 < 11"}', faults, path)
            elif path.endswith("/txs/package") and rule in ("ok", "fail"):
                self.answer(200, json.dumps(package_answer(body, rule == "ok")).encode(),
                            faults, path)
            else:
                self.answer(404, ("endpoint does not exist " + json.dumps(path)).encode(),
                            faults, path)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients are expected to hang up on us


srv = Quiet(("127.0.0.1", 0), Handler)
with open(os.path.join(WORK, "stub.port.tmp"), "w") as f:
    f.write("%d\n" % srv.server_address[1])
os.rename(os.path.join(WORK, "stub.port.tmp"), os.path.join(WORK, "stub.port"))
srv.serve_forever()
