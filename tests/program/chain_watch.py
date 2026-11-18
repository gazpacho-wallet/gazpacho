#!/usr/bin/env python3
"""program_chain_watch (P7): the chain worker wired into the program.

Two gazpacho-test processes, a host and a member connected to it, each with a
chain worker against one local Esplora stub that serves the recorded signet
blocks 329437 to 329439 (ports/chain/tests/data: real headers, real Merkle
proofs). The test engine sets watches through the node's actions; what the
worker reports reaches the node as GZ_CHAIN_* events, which the test engine
logs ("node-log test-chain area=0x7e57 kind=K conf=C height=H").

  1. both processes: a transaction confirmed (1, then 2 at the next block),
     its output 0 spent; the new tip once.
 1b. broadcasts straight into the chain adapter (the test command
     chain-broadcast; a test engine may not broadcast, test_node_handoff):
     bytes that are not a transaction, and a real transaction the server
     refuses. Both come back REFUSED with their reason, nothing is fatal, and
     the worker goes on (a new watch is still reported). The full path,
     engine to node to server and back, waits for the first engine allowed
     to broadcast (P4.5); composite.c drops GZ_CHAIN_BROADCAST_RESULT until then.
  2. the host killed (a crash) and started again on its folder: its watches
     come back from its journal and are reported again, with no command;
  3. a node error in the middle (restart from storage in the same process):
     the watches come back, and nothing of the old incarnation is reported;
  4. BUSY (small queues, a slow server, forty watch requests): kept and asked
     again, never fatal, the backlog drained;
  5. a chain server on mainnet: refused at start;
  6. a slow chain server does not hold the loop: a 50 ms timer keeps firing,
     and SIGTERM stops the program within 2 s.

After the review of PR 50:
  7. (M1) two servers on this machine, named as two operators
     (--chain-operator): one hides a confirmation. Nothing is reported while
     they disagree; the truth once they agree. Without the names the two
     loopback servers are one operator and the start is refused.
  8. (M2) a worker that holds fewer watches than the node asks for
     (--test-chain-watches 2): one explained stop (exit 7), no restart, and
     the same again at the next start (the saved watches come back).
  9. (L2, L3) a full backlog (--test-chain-backlog 16, small queues, a slow
     server), a broadcast held behind watches in it: fatal, one restart from
     storage, the held broadcast written as dropped, the saved watch set
     again and reported.
 10. (L4) a watch command repeated: one watch record in the journal.
 (5, L1) the mainnet server is refused before anything is written to the
     data folder.

usage: chain_watch.py GAZPACHO_TEST WORKDIR
"""
import http.server
import os
import shutil
import signal
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, area, cmd  # noqa: E402

EXE, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ports", "chain", "tests", "data")
shutil.rmtree(WORK, ignore_errors=True)
LOGS = os.path.join(WORK, "logs")
os.makedirs(LOGS)

TX_A = "8690387a65262437580d45b77f1cb0792faff46cecb72c5ee22390e5193a6c9a"
TX_SP = "ee18add119d09dc5b01cde93367391947495b656c30c5935cbde8374aa9d944b"
TX_CB = "f5b99c0f9b9150d7b980e249419425152f849b0d3e3bf0c1052c534688a18f54"
TX_CB39 = "bfe8f6f98a4052d3e0c3989ab13cb9744d724b2905a4de15f4366be0ba77eb16"
GEN = {"signet": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
       "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"}
A = 0x7e57
TE_WATCH, TE_WATCH_OUTPOINT, TE_UNWATCH = 0x7e05, 0x7e0c, 0x7e10
KIND_CONFIRMED, KIND_TIP, KIND_SPENT = 2, 3, 5


def data(name):
    with open(os.path.join(DATA, name), "rb") as f:
        return f.read().strip()


HASH = {h: data("block_hash_%d.txt" % h).decode() for h in (329437, 329438, 329439)}
state = {"tip": 329438, "genesis": GEN["signet"], "delay": 0.0, "delay_path": "", "requests": [], "posts": []}
lock = threading.Lock()


def answer(path):
    """(status, body) for GET `path` from the stub's chain at state["tip"]."""
    tip = state["tip"]
    if path == "/blocks/tip/height":
        return 200, str(tip).encode()
    if path == "/block-height/0":
        return 200, state["genesis"].encode()
    if path.startswith("/block-height/"):
        h = int(path.rsplit("/", 1)[1])
        return (200, HASH[h].encode()) if h in HASH and h <= tip else (404, b"Block not found")
    for h, bh in HASH.items():
        if h > tip:
            continue
        if path == "/block/%s/header" % bh:
            return 200, data("header_%d.txt" % h)
        if h >= 329438 and path == "/block/%s" % bh:
            return 200, data("block_%d.json" % h)
        if h >= 329438 and path == "/block/%s/txid/0" % bh:
            return 200, data("block_%d_txid_0.txt" % h)
    files = {"/tx/%s/status" % TX_A: "tx_a_status.json", "/tx/%s/hex" % TX_A: "tx_a_hex.txt",
             "/tx/%s/merkle-proof" % TX_A: "tx_a_merkle_proof.json",
             "/tx/%s/hex" % TX_CB: "tx_coinbase_hex.txt",
             "/tx/%s/merkle-proof" % TX_CB: "tx_coinbase_merkle_proof.json",
             "/tx/%s/hex" % TX_SP: "tx_spender_hex.txt"}
    if tip >= 329439:
        files.update({"/tx/%s/outspend/0" % TX_A: "tx_a_outspend_0.json",
                      "/tx/%s/status" % TX_SP: "tx_spender_status.json",
                      "/tx/%s/merkle-proof" % TX_SP: "tx_spender_merkle_proof.json",
                      "/tx/%s/hex" % TX_CB39: "tx_coinbase_329439_hex.txt",
                      "/tx/%s/merkle-proof" % TX_CB39: "tx_coinbase_329439_merkle_proof.json"})
    if path in files:
        return 200, data(files[path])
    if path.endswith("/status"):
        return 200, b'{"confirmed":false}'
    if "/outspend/" in path:
        return 200, b'{"spent":false}'
    return 404, b"not found"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            with lock:
                state["requests"].append(self.path)
            if state["delay"] and state["delay_path"] in self.path:
                time.sleep(state["delay"])
            if getattr(self.server, "hide", False) and TX_A in self.path:
                # The lying server: TX_A was never confirmed, its output 0 unspent.
                if self.path.endswith("/status"):
                    return self.reply(200, b'{"confirmed":false}')
                if "/outspend/" in self.path:
                    return self.reply(200, b'{"spent":false}')
                if self.path.endswith("/merkle-proof"):
                    return self.reply(404, b"Transaction not found")
            self.reply(*answer(self.path))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            with lock:
                state["posts"].append((self.path, body))
            self.reply(400, b"sendrawtransaction RPC error: rejected by the stub")
        except (BrokenPipeError, ConnectionResetError):
            pass


class Quiet(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


srv = Quiet(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]
liar = Quiet(("127.0.0.1", 0), H)   # a second server, for step 7, named by another spelling (the comparing backend refuses one host name twice; plain HTTP only on loopback names)
liar.hide = False
threading.Thread(target=liar.serve_forever, daemon=True).start()
URL2 = "http://localhost:%d" % liar.server_address[1]
check = Checks()
procs = []


def requests_for(txid, since=0):
    with lock:
        return sum(1 for p in state["requests"][since:] if txid in p)


def mark_requests():
    with lock:
        return len(state["requests"])


def start(name, role, *extra, urls=None):
    d = os.path.join(WORK, name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    args = [EXE, "--data-dir", d, "--role", role, "--name", name, "--no-interface"]
    args += urls if urls is not None else ["--chain-url", URL]
    args += ["--chain-poll-ms", "200", "--test-engines", "1", "--test-commands"]
    if role == "host":
        args += ["--listen", "127.0.0.1:0"]
    p = Proc(name, args + list(extra), LOGS, stdin=True)
    procs.append(p)
    return p


def watch(p, depth=2):
    p.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", depth))))
    p.send(cmd(TE_WATCH_OUTPOINT, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", 0)),
               (16, struct.pack(">I", 1))))


def saw(p, kind, conf=None, height=None, start=0, timeout=30):
    rx = r"node-log test-chain area=0x7e57 kind=%d" % kind
    rx += r" conf=%d" % conf if conf is not None else r" conf=\d+"
    rx += r" height=%d" % height if height is not None else ""
    return p.wait_for(rx, timeout=timeout, start=start) is not None


def no_trouble(p, what):
    check(p.count(r"node-error|chain-request-refused|chain-backlog-full") == 0, "%s: nothing fatal" % what)


try:
    # 1. two processes ---------------------------------------------------------
    h = start("host", "host")
    hkey = h.wait_for(r"host key=([0-9a-f]{66})").group(1)
    port = h.wait_for(r"listening address=127\.0\.0\.1:(\d+)").group(1)
    m = start("member", "member", "--reconnect-ms", "100", "--connect", "%s@127.0.0.1:%s" % (hkey, port))
    check(m.wait_for(r" ready incarnation=") is not None and h.wait_for(r"connected peer=") is not None,
          "1: host and member up and connected")
    for p in (h, m):
        watch(p)
    for p in (h, m):
        check(saw(p, KIND_CONFIRMED, 1, 329438), "1: %s: the transaction confirmed once, in 329438" % p.name)
    hm, mm = h.mark(), m.mark()
    state["tip"] = 329439
    for p, mk in ((h, hm), (m, mm)):
        check(saw(p, KIND_TIP, 0, 329439, start=mk), "1: %s: the new tip" % p.name)
        check(saw(p, KIND_CONFIRMED, 2, 329438, start=mk), "1: %s: two confirmations at the next block" % p.name)
        check(saw(p, KIND_SPENT, 1, 329439, start=mk), "1: %s: output 0 spent, one confirmation" % p.name)
    time.sleep(1.0)
    for p in (h, m):
        check(p.count(r"node-log test-chain area=0x7e57 kind=3 conf=0 height=329439") == 1,
              "1: %s: the new tip told once" % p.name)
        no_trouble(p, "1: " + p.name)

    # 1b. broadcasts straight into the chain adapter ------------------------
    mk = h.mark()
    h.p.stdin.write("chain-broadcast 01020304\n")
    h.p.stdin.flush()
    check(h.wait_for(r"broadcast-refused len=4 why=not-a-transaction", start=mk) is not None and
          h.wait_for(r"chain-broadcast-result txid=0{64} outcome=refused reason=not a transaction", start=mk)
          is not None, "1b: bytes that are not a transaction: REFUSED, not a transaction")
    sp_hex = data("tx_spender_hex.txt").decode()
    h.p.stdin.write("chain-broadcast %s\n" % sp_hex)
    h.p.stdin.flush()
    check(h.wait_for(r"broadcast-queued id=\d+ txid=%s" % TX_SP, start=mk) is not None,
          "1b: a real transaction queued to the worker")
    check(h.wait_for(r"chain-broadcast-result txid=%s outcome=refused reason=.*rejected by the stub" % TX_SP,
                     start=mk) is not None, "1b: refused by the server, with its reason")
    with lock:
        posts = list(state["posts"])
    check(any(b.decode(errors="replace").strip() == sp_hex for _, b in posts), "1b: the server was sent the transaction")
    h.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_SP)[::-1]), (14, struct.pack(">I", 1))))
    check(saw(h, KIND_CONFIRMED, 1, 329439, start=mk), "1b: the worker goes on: a new watch is reported")
    no_trouble(h, "1b")

    # 2. a crash of the host: its watches come back from its journal -----------
    h.p.send_signal(signal.SIGKILL)
    h.exit_code(10)
    before = mark_requests()
    h = start("host", "host")
    check(h.wait_for(r" ready incarnation=") is not None, "2: the host started again on its folder")
    check(h.wait_for(r"watch-tx txid=%s depth=2" % bytes.fromhex(TX_A)[::-1].hex()) is not None,
          "2: its watch on the transaction set again at start")
    check(saw(h, KIND_CONFIRMED, 2, 329438) and saw(h, KIND_SPENT, 1, 329439),
          "2: and reported again, with no command")
    check(requests_for(TX_A, before) > 0, "2: the worker asked the server again")
    no_trouble(h, "2")

    # 2b. (P4.5, UNWATCH) a released watch is not set again at the next start --
    sp_le = bytes.fromhex(TX_SP)[::-1]
    check(h.wait_for(r"watch-tx txid=%s depth=1" % sp_le.hex()) is not None, "2b: the spender's watch came back too")
    mk = h.mark()
    h.send(cmd(TE_UNWATCH, area(A), (12, sp_le), (14, struct.pack(">I", 0)), (16, b"\x01")))
    check(h.wait_for(r"unwatch txid=%s vout=0 tx=1" % sp_le.hex(), start=mk) is not None,
          "2b: the release reached the chain worker")
    h.send(cmd(TE_UNWATCH, area(A), (12, sp_le), (14, struct.pack(">I", 0)), (16, b"\x01")))
    check(h.wait_for(r"command-result id=\S+ status=404 error=no_such_watch", start=mk) is not None, "2b: released twice: refused, not fatal")
    h.p.send_signal(signal.SIGKILL)
    h.exit_code(10)
    h = start("host", "host")
    check(h.wait_for(r" ready incarnation=") is not None, "2b: started again")
    check(h.wait_for(r"watch-tx txid=%s depth=2" % bytes.fromhex(TX_A)[::-1].hex()) is not None,
          "2b: the watch still wanted is set again")
    check(h.wait_for(r"chain-synced tx=%s" % TX_A) is not None,
          "2b: the worker reports the watch synced once it has answered it (WATCH_SYNCED, H-1)")
    check(h.wait_for(r"chain-tip-synced height=\d+") is not None,
          "2b: and the tip synced once every watch has its answer for it (TIP_SYNCED, B12)")
    time.sleep(2.0)
    check(h.count(r"watch-tx txid=%s" % sp_le.hex()) == 0, "2b: the released watch is not set again")
    no_trouble(h, "2b")
    h.stop()

    # 3. a node error in the middle: restart from storage in the same process ---
    n = start("restarts", "host", "--test-node-error-at", "6")
    check(n.wait_for(r" ready incarnation=") is not None, "3: up")
    watch(n)
    r = n.index_of(r"restart-from-storage", timeout=30)
    check(r is not None, "3: the node error restarted it from storage")
    if r is not None:
        ready = n.index_of(r" ready incarnation=", start=r)
        check(ready is not None and n.wait_for(r"chain-restart generation=", start=r) is not None,
              "3: the worker began a new generation")
        check(ready is not None and saw(n, KIND_CONFIRMED, 2, 329438, start=ready),
              "3: the watches came back and were reported after the restart")
    n.stop()

    # 4. BUSY: small queues, a slow server, forty watch requests ---------------
    b = start("busy", "host", "--test-chain-small")
    check(b.wait_for(r" ready incarnation=") is not None, "4: up")
    time.sleep(0.5)
    state["delay"], state["delay_path"] = 0.5, "/tx/"
    for d in range(1, 41):
        b.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", d))))
    check(b.wait_for(r"chain-busy kind=1 held=", timeout=20) is not None, "4: the worker answered BUSY")
    check(b.wait_for(r"chain-backlog asked=\d+ left=0", timeout=60) is not None, "4: every refused request asked again")
    state["delay"] = 0.0
    no_trouble(b, "4")
    check(b.count(r"restart-from-storage") == 0, "4: no restart")
    b.stop()

    # 5. a chain server on mainnet ----------------------------------------------
    state["genesis"] = GEN["mainnet"]
    w = start("mainnet", "host")
    check(w.exit_code(30) == 5, "5: a mainnet chain server refused at start (exit 5)")
    left = sorted(os.listdir(os.path.join(WORK, "mainnet")))
    check(left == [], "5: nothing written to the data folder before the check (%s)" % ", ".join(left))
    state["genesis"] = GEN["signet"]

    # 6. a slow server does not hold the loop ----------------------------------
    s = start("slow", "host", "--test-timer-ms", "50")
    check(s.wait_for(r" ready incarnation=") is not None, "6: up")
    watch(s)
    state["delay"], state["delay_path"] = 3.0, "/"
    mk = s.mark()
    time.sleep(6.0)
    fires = s.count(r"test-timer fired", mk)
    check(fires >= 80, "6: a 50 ms timer fired %d times in 6 s while every chain request took 3 s" % fires)
    t0 = time.time()
    s.p.send_signal(signal.SIGTERM)
    code = s.exit_code(10)
    took = time.time() - t0
    check(code == 0 and took < 2.0, "6: SIGTERM stopped it in %.2f s (exit %s)" % (took, code))
    state["delay"] = 0.0

    # 7. (M1) two servers named as two operators, one hiding a confirmation ---
    two = ["--chain-url", URL, "--chain-operator", "honest.test", "--chain-url", URL2, "--chain-operator", "liar.test"]
    u = start("unnamed", "host", urls=["--chain-url", URL, "--chain-url", URL2])
    # Accepted as two servers, but both count as one operator ("this-machine"),
    # so the comparing backend never has a quorum: the first tip read fails.
    check(u.exit_code(30) == 5 and u.wait_for(r"cannot read the chain tip: no-quorum", timeout=5) is not None,
          "7: two loopback servers without names are one operator: no quorum, refused at start (exit 5)")
    liar.hide = True
    before = mark_requests()
    o = start("operators", "host", urls=two)
    check(o.wait_for(r"chain network=signet servers=2 ") is not None and o.wait_for(r" ready incarnation=") is not None,
          "7: up over the comparing backend, two servers")
    watch(o)
    check(o.wait_for(r"chain-sources servers-disagree", timeout=30) is not None,
          "7: the worker reports that the servers disagree")
    time.sleep(3.0)
    check(o.count(r"node-log test-chain area=0x7e57 kind=(2|5) ") == 0,
          "7: nothing about the hidden transaction reported while they disagree")
    check(requests_for(TX_A, before) > 0, "7: both were asked")
    mk = o.mark()
    liar.hide = False
    check(saw(o, KIND_CONFIRMED, 2, 329438, start=mk, timeout=60) and saw(o, KIND_SPENT, 1, 329439, start=mk, timeout=60),
          "7: the truth reported once they agree")
    no_trouble(o, "7")
    o.stop()

    # 8. (M2) a worker that holds fewer watches than the node asks for -------
    f = start("fullset", "host", "--test-chain-watches", "2")
    check(f.wait_for(r" ready incarnation=") is not None, "8: up, a worker of 2 watches")
    watch(f)
    f.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_SP)[::-1]), (14, struct.pack(">I", 1))))
    check(f.exit_code(30) == 7, "8: the third watch: one stop, exit 7")
    check(f.find(r"chain-watch-set-full kind=1 watches=2")[0] is not None and
          f.find(r"stopping why=chain-watch-set-full")[0] is not None, "8: the stop is explained")
    check(f.count(r"restart-from-storage") == 0, "8: no restart into it")
    f2 = start("fullset", "host", "--test-chain-watches", "2")
    check(f2.exit_code(30) == 7 and f2.count(r"restart-from-storage") == 0 and f2.count(r" ready incarnation=") == 0,
          "8: started again: the saved watches come back at the start, one stop again, no loop")

    # 9. (L2, L3) a full backlog, with a broadcast held in it -----------------
    k = start("backlog", "host", "--test-chain-small", "--test-chain-backlog", "16")
    check(k.wait_for(r" ready incarnation=") is not None, "9: up, small queues, a backlog of 16")
    time.sleep(0.5)
    state["delay"], state["delay_path"] = 0.5, "/tx/"
    sp_hex = data("tx_spender_hex.txt").decode()
    lines = []
    for d in range(1, 45):
        lines.append(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", d))))
    lines.append("chain-broadcast %s" % sp_hex)
    for d in range(45, 90):
        lines.append(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", d))))
    k.p.stdin.write("\n".join(lines) + "\n")
    k.p.stdin.flush()
    check(k.wait_for(r"chain-busy kind=3 held=", timeout=30) is not None, "9: the broadcast held behind watches")
    check(k.wait_for(r"chain-backlog-full held=16", timeout=30) is not None and
          k.wait_for(r"fatal why=chain-backlog-full", timeout=10) is not None, "9: a full backlog is fatal")
    r = k.index_of(r"restart-from-storage", timeout=30)
    check(r is not None, "9: one restart from storage")
    if r is not None:
        check(k.wait_for(r"chain-broadcast-dropped id=\d+ why=restart", start=r) is not None,
              "9: the held broadcast written as dropped")
        check(k.wait_for(r"watch-tx txid=%s depth=\d+" % bytes.fromhex(TX_A)[::-1].hex(), start=r) is not None,
              "9: the saved watch set again after the restart")
        state["delay"] = 0.0
        check(saw(k, KIND_CONFIRMED, None, 329438, start=r, timeout=60), "9: and reported")
    state["delay"] = 0.0
    time.sleep(1.0)
    check(k.count(r"restart-from-storage") == 1 and k.count(r"fatal why=") == 1, "9: one fatal error only")
    k.stop()

    # 10. (L4) a repeated watch command: one record ---------------------------
    j = start("repeat", "host")
    check(j.wait_for(r" ready incarnation=") is not None, "10: up")
    for _ in range(5):
        j.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", 2))))
    j.send(cmd(TE_WATCH, area(A), (12, bytes.fromhex(TX_A)[::-1]), (14, struct.pack(">I", 3))))
    check(j.wait_for(r"watch-tx txid=\w+ depth=3") is not None, "10: the deeper one asked")
    time.sleep(0.5)
    j.stop()
    dump = Proc("repeat-dump", [EXE, "--data-dir", os.path.join(WORK, "repeat"), "--role", "host", "--name", "repeat",
                                "--no-interface", "--no-chain", "--test-dump-journal"], LOGS)
    procs.append(dump)
    check(dump.exit_code(30) == 0, "10: the journal read")
    n8 = dump.count(r"journal-record .*type=0x7e570008 ")
    check(n8 == 2, "10: six watch commands, two depths: %d watch records (2)" % n8)

finally:
    for p in procs:
        if p.p.poll() is None:
            p.p.kill()
    srv.shutdown()

sys.exit(check.result("program_chain_watch", LOGS))
