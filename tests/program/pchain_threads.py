#!/usr/bin/env python3
"""The chain adapter's lookups while its worker runs, under ThreadSanitizer
(docs/notes/integration.md B11; tools/pchain-tsan.sh builds the program).

    pchain_threads.py TEST_PCHAIN_THREADS [ROUNDS]

Serves a local Esplora stub (plain HTTP on 127.0.0.1, which ports/chain
allows) with the recorded signet blocks 329437 to 329439, runs the program
against it, and requires: exit 0, no ThreadSanitizer report, every lookup
answered, and the worker's tip polls and the lookups interleaved (else the
run proved nothing). Standard library only."""
import http.server
import os
import subprocess
import sys
import threading

EXE = sys.argv[1]
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 24
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ports", "chain", "tests", "data")
GENESIS_SIGNET = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"


def data(name):
    with open(os.path.join(DATA, name), "rb") as f:
        return f.read().strip().decode()


HASH = {h: data("block_hash_%d.txt" % h) for h in (329437, 329438, 329439)}
HEADER = {HASH[h]: data("header_%d.txt" % h) for h in HASH}
TIP = 329438
lock = threading.Lock()
order = []  # "t" for a tip poll, "u" for a lookup, in the order they came


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path
        body = None
        if p == "/blocks/tip/height":
            body = str(TIP)
            with lock:
                order.append("t")
        elif p == "/block-height/0":
            body = GENESIS_SIGNET
        elif p.startswith("/block-height/") and p.rsplit("/", 1)[1].isdigit() \
                and int(p.rsplit("/", 1)[1]) in HASH and int(p.rsplit("/", 1)[1]) <= TIP:
            body = HASH[int(p.rsplit("/", 1)[1])]
        elif p.startswith("/block/") and p.endswith("/header") and p[7:71] in HEADER:
            body = HEADER[p[7:71]]
        elif p.startswith("/scripthash/") and p.endswith("/utxo"):
            body = "[]"
            with lock:
                order.append("u")
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if body == "[]" else "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = "http://127.0.0.1:%d" % srv.server_address[1]
env = dict(os.environ, TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1 exitcode=66")
p = subprocess.run([EXE, url, str(ROUNDS)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                   timeout=300, text=True, errors="replace")
srv.shutdown()
out = p.stdout
fails = []
if p.returncode != 0:
    fails.append("exit %d" % p.returncode)
if "ThreadSanitizer" in out:
    fails.append("a ThreadSanitizer report")
if "lookups=%d" % ROUNDS not in out:
    fails.append("not every lookup was answered")
seq = "".join(order)
# a tip poll between two lookups, at least a few times: the threads overlapped
overlaps = sum(1 for i in range(1, len(seq) - 1) if seq[i] == "t" and "u" in seq[:i] and "u" in seq[i + 1:])
if overlaps < 3:
    fails.append("the worker polled the tip only %d times during the lookups" % overlaps)
if fails:
    sys.stdout.write(out[-20000:])
    print("FAIL: " + "; ".join(fails))
    sys.exit(1)
print("PASS: %d lookups beside %d tip polls of the worker (%d during the lookups), no data race"
      % (ROUNDS, seq.count("t"), overlaps))
