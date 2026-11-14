#!/usr/bin/env python3
"""program_chain_stub (written by review B of PR 27, copied as written): the chain adapter against a local Esplora stub (plain
HTTP on loopback, which ports/chain allows). usage: chain_t.py GAZPACHO_TEST WORKDIR [ignored]"""
import http.server
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

EXE, WORK = sys.argv[1], sys.argv[2]
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
GEN = {"signet": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
       "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
       "testnet4": "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"}
state = {"genesis": GEN["signet"], "tip": 100, "delay": 0.0, "hits": 0}
fails = []


def check(c, what):
    print(("ok   " if c else "FAIL ") + what, flush=True)
    if not c:
        fails.append(what)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        state["hits"] += 1
        if state["delay"] and self.path == "/blocks/tip/height":
            time.sleep(state["delay"])
        if self.path == "/blocks/tip/height":
            body = str(state["tip"])
        elif self.path == "/block-height/0":
            body = state["genesis"]
        elif self.path.startswith("/block-height/"):
            h = int(self.path.rsplit("/", 1)[1])
            body = "%064x" % (0xabc000 + h)
        else:
            self.send_response(404)
            self.end_headers()
            return
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]


def run(name, args, timeout=None):
    d = os.path.join(WORK, name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    p = subprocess.Popen([EXE, "--data-dir", d, "--name", name, "--no-interface", "--role", "host",
                          "--listen", "127.0.0.1:0", "--chain-url", URL] + args,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    threading.Thread(target=lambda: [lines.append(l.rstrip("\n")) for l in p.stdout], daemon=True).start()
    return p, lines


# Wrong networks are refused at start (exit 5).
for net in ("mainnet", "testnet4"):
    state["genesis"] = GEN[net]
    p, L = run("wrong-" + net, [])
    rc = p.wait(20)
    check(rc == 5, "a %s chain server is refused for a signet host (exit %s)" % (net, rc))
state["genesis"] = GEN["signet"]

# The tip is told at every start, including an in-process restart; a new tip once.
p, L = run("tip", ["--chain-poll-ms", "200", "--test-node-error-at", "1", "--test-timer-ms", "1000"])
time.sleep(2.0)
state["tip"] = 101
time.sleep(1.5)
p.terminate()
p.wait(15)
time.sleep(0.2)
open(os.path.join(WORK, "tip.log"), "w").write("\n".join(L) + "\n")
readies = [i for i, l in enumerate(L) if " ready incarnation=" in l]
check(len(readies) >= 2, "the host restarted in process (%d readies)" % len(readies))
for k, i in enumerate(readies):
    nxt = readies[k + 1] if k + 1 < len(readies) else len(L)
    check(any("chain-tip told height=100" in l for l in L[i:nxt]),
          "incarnation %d is told the tip after its start" % (k + 1))
new = [l for l in L if re.search(r" chain-tip height=101", l)]
check(len(new) == 1, "a new tip is reported once (%d)" % len(new))
check(not any(re.search(r" chain-tip height=100", l) for l in L), "an unchanged tip is not reported again")

# A slow chain server holds the one loop (P7, known): measure.
state["delay"] = 3.0
p, L = run("slow", ["--chain-poll-ms", "100", "--test-timer-ms", "50"])
time.sleep(8)
p.terminate()
t0 = time.time()
p.wait(30)
stop_s = time.time() - t0
fires = sum(1 for l in L if " test-timer fired " in l)
print("note: slow chain server (3 s per tip read): %d test-timer fires in 8 s at 50 ms; SIGTERM took %.1f s" % (fires, stop_s))
print("RESULT %s failures=%d" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
