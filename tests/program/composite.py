#!/usr/bin/env python3
"""program_composite (docs/notes/composite-node.md, P4.1): a host and a
member, each with two test engines (areas 0x7e57 and 0x7e58), through their
real runners and the journal stand-in, test commands on standard input.

    python3 -I composite.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Both engines ping and get replies; each engine's records carry its own
     area; each engine's timer (both id 1) fires only into its own engine.
  2. A hand-off: engine A saves, sets a timer and hands off to engine B, which
     saves: one batch holds both records (--test-dump-journal). Killed after
     the save and before its confirmation, the restarted host holds both or
     neither. A variant where A sends between its saves trips the test-build
     check: a node error, a restart from storage, nothing of it saved.
  3. A node error in engine B: the node restarts from storage; nothing of the
     failed step is in the journal (the GZ_ERR_FAILED after it: a unit test).
  4. A scope-valid lobby kind for a scope with no slot, from the member's
     host: dropped and counted on the member. On the host, a member's hello
     for an unknown scope gets lobby state 0, and 30 such hellos in a second
     get one answer.
  5. Slot generations: a slot whose engine sets a timer is closed and another
     opened: the first timer never fires into the second.
  6. Both engines watch one txid at depths 1 and 3: one watch, raised to 3;
     a report reaches both.
  7. A storage failure in the middle: one in-process restart; the engines'
     timers fire only after the new start (none was set again).
Review fixes (PR 41):
  4. The host closes the member's connection with the transport's warning at
     the twentieth ignored hello: exactly twenty are counted, nothing after
     the close reaches the node (an adapter that ignores DISCONNECT, or one
     that goes on delivering what it had read, fails here).
  8. CONNECT: a bad address is refused to the person (400 bad_address),
     nothing saved, never fatal; an address the resolver refuses is a counted
     failure retried with backoff, live and across restarts; a bad target
     already in storage is passed over at every start.
  9. Seventy watches: sixteen taken, the rest refused (409), no node error.
 10. Thirty-three seats on one slot: the 33rd refused (409), no node error.
 11. A 200,000-byte message (split by the transport) and a DISCONNECT after
     it in one list: the member receives it whole; the close never drops it.
 12. SET_SEATED reaches the transport: with room for two connections, a
     seated member is never evicted for a newcomer; an unseated one is.
Every process asserts that no node-error line appears, except where the case
is about one.
"""
import hashlib
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import (Checks, Proc, area, cmd, journal_types, kill_all, peer_id, run,  # noqa: E402
                         tlv)

check = Checks()
A, B = 0x7e57, 0x7e58
TE_CONNECT, TE_TIMER, TE_HANDOFF, TE_FAIL, TE_WATCH, TE_SEND = 0x7e01, 0x7e02, 0x7e03, 0x7e04, 0x7e05, 0x7e06
SLOT_OPEN, SLOT_CLOSE, SLOT_SEAT = 0x7e80, 0x7e81, 0x7e82
TE_WATCH_LIMIT = 16


def results_since(p, mark):
    """(status, error) of every command-result line from `mark` on."""
    out = []
    for line in p.lines[mark:]:
        if line.startswith("command-result ") or " command-result " in line:
            st = line.split("status=")[1].split()[0]
            er = line.split("error=")[1].split()[0] if "error=" in line else "-"
            out.append((int(st), er))
    return out


def wait_results(p, mark, n, timeout=20):
    end = time.time() + timeout
    while time.time() < end and len(results_since(p, mark)) < n:
        time.sleep(0.05)
    return results_since(p, mark)


def append_batch(path, records):
    """Append one batch of `records` [(type, bytes)] to a stopped program's
    journal stand-in, under its newest incarnation and the next sequence, as
    an earlier program would have saved it (gzp_harness.parse_journal's
    format)."""
    with open(path, "rb") as fh:
        data = fh.read()
    inc, seq, off = 0, 0, 16
    while off + 8 <= len(data):
        tag, ln = struct.unpack(">II", data[off:off + 8])
        body = data[off + 8:off + 8 + ln]
        if tag == 0x494e434e:
            inc, seq = struct.unpack(">Q", body)[0], 0
        elif tag == 0x42544348:
            seq = max(seq, struct.unpack(">Q", body[8:16])[0])
        off += 8 + ln + 32
    body = struct.pack(">QQI", inc, seq + 1, len(records))
    for t, b in records:
        body += struct.pack(">II", t, len(b)) + b
    head = struct.pack(">II", 0x42544348, len(body))
    with open(path, "ab") as fh:
        fh.write(head + body + hashlib.sha256(head + body).digest())


def host(exe, work, logs, name, *extra):
    return Proc(name, [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen", "127.0.0.1:0",
                       "--name", "host", "--no-chain", "--no-interface", "--test-engines", "2",
                       "--test-commands"] + list(extra), logs, stdin=True)


def member(exe, work, logs, name, hkey, port, *extra):
    return Proc(name, [exe, "--data-dir", os.path.join(work, "member"), "--role", "member", "--name", "member",
                       "--no-chain", "--no-interface", "--test-engines", "2", "--test-commands",
                       "--reconnect-ms", "100", "--connect", "%s@127.0.0.1:%s" % (hkey, port)] + list(extra),
                logs, stdin=True)


def dump(exe, work, who):
    code, out = run(exe, "--data-dir", os.path.join(work, who), "--role", who, "--no-chain", "--no-interface",
                    "--test-dump-journal")
    batches, cur = [], None
    for line in out.splitlines():
        if line.startswith("journal-batch"):
            cur = []
            batches.append(cur)
        elif line.startswith("journal-record") and cur is not None:
            cur.append(int(line.split("type=")[1].split()[0], 16))
    return code, batches


def no_node_error(p, what):
    check(p.count(r"node-error") == 0, "%s: no node-error line" % what)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    procs = []
    try:
        # 1. two engines -------------------------------------------------------
        h = host(exe, work, logs, "host-1")
        procs.append(h)
        k = h.wait_for(r"host key=([0-9a-f]{66})")
        m = h.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "the host starts")
            return check.result("composite", logs)
        hkey, port = k.group(1), m.group(1)
        mem = member(exe, work, logs, "member-1", hkey, port, "--test-pings", "3", "--test-ping-ms", "50")
        procs.append(mem)
        check(mem.wait_for(r"pings-done peer=%s n=3" % peer_id(hkey), timeout=30) is not None,
              "1: both engines answer the member's pings")
        check(mem.count(r"pong peer=.* area=0x7e57") >= 3 and mem.count(r"pong peer=.* area=0x7e58") >= 3,
              "1: replies come from each engine")
        for a in (A, B):
            h.send(cmd(TE_TIMER, area(a), (12, struct.pack(">I", 200))))
        check(h.wait_for(r"node-log test-timer area=0x7e57 id=1") is not None and
              h.wait_for(r"node-log test-timer area=0x7e58 id=1") is not None, "1: each engine's timer id 1 fires")
        time.sleep(0.5)
        check(h.count(r"test-timer area=0x7e57 id=1") == 1 and h.count(r"test-timer area=0x7e58 id=1") == 1,
              "1: each fires once, into its own engine")

        # 4. drops and hellos (member and host running) -------------------------
        mark = mem.mark()
        scope = bytes([0x44]) * 32
        mkey = mem.wait_for(r"member key=([0-9a-f]{66})").group(1)
        h.send(cmd(TE_SEND, (12, bytes.fromhex(mkey)), (14, struct.pack(">H", 28)), (16, scope),
                   (18, tlv((2, b"\0"), (4, b"\0"), (6, b"\0" * 4), (8, b"\0\0"), (10, b"\0\0")))))
        check(mem.wait_for(r"node-log drop why=no-slot kind=28", start=mark, timeout=10) is not None,
              "4: a lobby kind for a scope with no slot is dropped and counted on the member")
        check(mem.count(r"disconnected", start=mark) == 0, "4: ... and the connection is kept")
        mark = mem.mark()
        hmark = h.mark()
        unknown = bytes([0x55]) * 32
        for _ in range(30):
            mem.send(cmd(TE_SEND, (12, bytes.fromhex(hkey)), (14, struct.pack(">H", 16)), (16, unknown), (18, b"")))
        time.sleep(1.5)
        answers = mem.count(r"node-log drop why=no-slot kind=28", start=mark)
        check(answers == 1, "4: 30 hellos for an unknown scope within a second get one lobby state 0 (%d)" % answers)
        mp = peer_id(mkey)
        check(h.wait_for(r"disconnect peer=%s why=1 connected=1" % mp, start=hmark, timeout=10) is not None,
              "4: at the twentieth ignored hello the host refuses the member (DISCONNECT refused)")
        check(mem.wait_for(r"warning conn=\d+ text=.*refused", start=mark, timeout=10) is not None and
              mem.wait_for(r"disconnected peer=%s" % peer_id(hkey), start=mark, timeout=10) is not None,
              "4: ... the member gets the transport's warning and the connection closes")
        time.sleep(0.5)
        ignored = h.count(r"drop why=hello-limit", start=hmark)
        check(ignored == 20, "4: exactly twenty ignored hellos are counted; nothing after the close reaches the "
                             "node part as a hello (%d)" % ignored)
        check(mem.wait_for(r"connected peer=%s" % peer_id(hkey), start=mem.index_of(r"disconnected peer=", start=mark) or mark,
                           timeout=10) is not None, "4: the member's CONNECT stands: it connects again")
        no_node_error(mem, "member")

        # 8. CONNECT targets the program cannot reach ---------------------------
        mark = mem.mark()
        other = bytes.fromhex("02" + "ab" * 32)
        for addr in (b"not-an-address", b"127.0.0.1", b"127.0.0.1:0", b"host.example:9735"):
            mem.send(cmd(TE_CONNECT, (12, other), (14, addr)))
        res = wait_results(mem, mark, 4)
        check(res == [(400, "bad_address")] * 4,
              "8: a CONNECT address that is not host:port, numeric, is refused to the person (%s)" % res)
        mark = mem.mark()
        mem.send(cmd(TE_CONNECT, (12, other), (14, b"999.999.999.999:9735")))
        res = wait_results(mem, mark, 1)
        check(res == [(200, "-")], "8: an address of the right form is taken (%s)" % res)
        check(mem.wait_for(r"connect-failed why=\S+ host=%s count=2" % peer_id(other.hex()), start=mark,
                           timeout=10) is not None,
              "8: the resolver refuses it: a counted failure, tried again with backoff")
        check(mem.count(r"fatal", start=mark) == 0, "8: ... never fatal")



        # 5. slot generations ---------------------------------------------------
        hmark = h.mark()
        s1, s2 = bytes([1]) * 32, bytes([2]) * 32
        h.send(cmd(SLOT_OPEN, (12, s1), (14, b"\x01"), (20, struct.pack(">I", 1500))))
        h.send(cmd(SLOT_CLOSE, (12, s1)))
        h.send(cmd(SLOT_OPEN, (12, s2), (14, b"\x01"), (20, struct.pack(">I", 300))))
        check(h.wait_for(r"node-log slot-timer gen=2", start=hmark, timeout=5) is not None,
              "5: the second slot's timer fires into it")
        time.sleep(2.0)
        check(h.count(r"slot-timer gen=1", start=hmark) == 0, "5: the first slot's timer never fires")

        # 6. the watch registry -------------------------------------------------
        hmark = h.mark()
        txid = bytes(range(32))
        h.send(cmd(TE_WATCH, area(A), (12, txid), (14, struct.pack(">I", 1))))
        h.send(cmd(TE_WATCH, area(B), (12, txid), (14, struct.pack(">I", 3))))
        h.send(cmd(TE_WATCH, area(A), (12, txid), (14, struct.pack(">I", 1))))
        h.wait_for(r"command-result .*", start=hmark)
        time.sleep(0.5)
        check(h.count(r"watch-tx txid=%s depth=1" % txid.hex(), start=hmark) == 1 and
              h.count(r"watch-tx txid=%s depth=3" % txid.hex(), start=hmark) == 1,
              "6: one watch, issued again only for the larger depth")
        h.send("chain-tx %s 2" % txid.hex())
        check(h.wait_for(r"test-chain area=0x7e57 .*conf=2", start=hmark, timeout=5) is not None and
              h.wait_for(r"test-chain area=0x7e58 .*conf=2", start=hmark, timeout=5) is not None,
              "6: the report reaches both engines")

        # 9. seventy watches ------------------------------------------------------
        hmark = h.mark()
        for i in range(70):
            h.send(cmd(TE_WATCH, area(A), (12, bytes([0x90, i]) * 16), (14, struct.pack(">I", 1))))
        res = wait_results(h, hmark, 70)
        # Engine A holds one watch already (case 6): fifteen more fit.
        check(res.count((200, "-")) == TE_WATCH_LIMIT - 1 and res.count((409, "too_many_watches")) == 70 - 15,
              "9: an engine's sixteen distinct watches are taken, the rest refused (%d taken)" % res.count((200, "-")))
        no_node_error(h, "host after seventy watches")

        # 10. thirty-three seats on one slot ---------------------------------------
        hmark = h.mark()
        s3 = bytes([3]) * 32
        h.send(cmd(SLOT_OPEN, (12, s3), (14, b"\x01")))
        for i in range(33):
            h.send(cmd(SLOT_SEAT, (12, s3), (14, bytes([2]) + bytes([0x70, i]) * 16)))
        res = wait_results(h, hmark, 34)
        check(res[:33] == [(200, "-")] * 33 and res[33:] == [(409, "too_many_seats")],
              "10: thirty-two seats are taken, the 33rd refused (%s)" % res[30:])
        h.send(cmd(SLOT_CLOSE, (12, s3)))
        no_node_error(h, "host after thirty-three seats")

        # 11. a split message, then a DISCONNECT, in one list -------------------------
        hmark, mark = h.mark(), mem.mark()
        h.send(cmd(TE_SEND, (12, bytes.fromhex(mkey)), (14, struct.pack(">H", 28)), (16, bytes([0x66]) * 32),
                   (18, tlv((2, b"\0"), (4, b"\0"), (6, b"\0" * 4), (8, b"\0\0"), (10, b"\0\0"))),
                   (20, struct.pack(">I", 200000)), (22, b"\x00")))
        check(h.wait_for(r"disconnect peer=%s why=0 connected=1" % mp, start=hmark, timeout=10) is not None,
              "11: the host sends 200,010 bytes of kind 28, then closes the connection (why 0)")
        check(mem.wait_for(r"node-log drop why=no-slot kind=28", start=mark, timeout=15) is not None,
              "11: the member receives the message, put together from its parts: the close sent it first")
        check(mem.wait_for(r"connected peer=%s" % peer_id(hkey), start=mark, timeout=10) is not None,
              "11: and connects again")
        no_node_error(mem, "member after the split message")

        # 2. a hand-off in one batch --------------------------------------------
        hmark = h.mark()
        h.send(cmd(TE_HANDOFF, area(A), (12, struct.pack(">H", B))))
        check(h.wait_for(r"node-log test-handoff taken area=0x7e58", start=hmark, timeout=5) is not None,
              "2: engine B takes the hand-off")
        h.wait_for(r"command-result .*status=200", start=hmark)
        no_node_error(h, "host")
        h.stop()
        mem.stop()
        code, batches = dump(exe, work, "host")
        both = [b for b in batches if 0x7e570006 in b or 0x7e580007 in b]
        check(code == 0 and len(both) == 1 and 0x7e570006 in both[0] and 0x7e580007 in both[0],
              "2: one batch holds both engines' records %s" % both)
        pings = [b for b in batches if 0x7e570001 in b or 0x7e580001 in b]
        check(any(0x7e570001 in b for b in pings) and any(0x7e580001 in b for b in pings),
              "1: each engine's records carry its own area")

        # 2. killed around the hand-off's batch: both or neither ------------------
        for hook in ("--test-crash-after-save", "--test-crash-before-confirm"):
            before = len([b for b in dump(exe, work, "host")[1] if 0x7e570006 in b])
            hx = host(exe, work, logs, "host-crash" + hook[6:], hook, "1")
            procs.append(hx)
            hx.wait_for(r"listening address")
            hx.send(cmd(TE_HANDOFF, area(A), (12, struct.pack(">H", B))))
            code = hx.exit_code(timeout=15)
            check(code == 70 and hx.count(r"test-crash") == 1, "2: %s 1 stops the host (exit %s)" % (hook, code))
            hr = host(exe, work, logs, "host-after" + hook[6:])
            procs.append(hr)
            check(hr.wait_for(r"ready incarnation") is not None, "2: the host starts again after the crash")
            hr.stop()
            b2 = dump(exe, work, "host")[1]
            halves = [(0x7e570006 in b, 0x7e580007 in b) for b in b2 if 0x7e570006 in b or 0x7e580007 in b]
            check(all(x == (True, True) for x in halves) and len(halves) in (before, before + 1),
                  "2: after %s the journal holds both records or neither (%s)" % (hook, halves))
            no_node_error(hr, "host after a crash")

        # 2. the variant that sends between its saves ----------------------------
        before = len([b for b in dump(exe, work, "host")[1] if 0x7e570006 in b])
        hv = host(exe, work, logs, "host-between")
        procs.append(hv)
        hv.wait_for(r"listening address")
        hv.send(cmd(TE_HANDOFF, area(A), (12, struct.pack(">H", B)), (14, b"\x01")))
        check(hv.wait_for(r"node-error engine=0x7e57 status=bug", timeout=10) is not None,
              "2: a send between the saves of a bracket trips the test-build check")
        check(hv.wait_for(r"restart-from-storage after=node-error", timeout=10) is not None and
              hv.wait_for(r"ready incarnation", start=hv.index_of(r"restart-from-storage") or 0) is not None,
              "2: ... fatal for the node: it restarts from storage")
        hv.stop()
        after = len([b for b in dump(exe, work, "host")[1] if 0x7e570006 in b])
        check(after == before, "2: nothing of that step is in the journal")

        # 3. a node error in engine B -------------------------------------------
        he = host(exe, work, logs, "host-error")
        procs.append(he)
        port = he.wait_for(r"listening address=127\.0\.0\.1:(\d+)").group(1)
        he.send(cmd(TE_FAIL, area(B), (12, struct.pack(">I", 1))))
        he.wait_for(r"command-result")
        me = member(exe, work, logs, "member-3", hkey, port, "--test-pings", "3")
        procs.append(me)
        check(he.wait_for(r"node-error engine=0x7e58 status=no-space", timeout=15) is not None,
              "3: engine B's error is a node error naming it")
        check(he.wait_for(r"restart-from-storage after=node-error", timeout=10) is not None,
              "3: the node restarts from storage")
        inc = he.wait_for(r"ready incarnation=(\d+)", start=he.index_of(r"restart-from-storage") or 0)
        rep = me.wait_for(r"test-reply area=0x7e5[78] serial=\d+ incarnation=(\d+)", timeout=20)
        check(inc is not None and rep is not None and int(rep.group(1)) > 1,
              "3: the host's replies carry the incarnation its node was given (%s)" % (rep.group(1) if rep else None))
        he.stop()
        me.stop()
        b3 = dump(exe, work, "host")[1]
        check(not any(t == 0x7e580006 for b in b3 for t in b), "3: nothing of the failed step is in the journal")

        # 7. a storage failure in the middle -------------------------------------
        hs = Proc("host-storage", [exe, "--data-dir", os.path.join(work, "host7"), "--role", "host", "--listen",
                                   "127.0.0.1:0", "--name", "host7", "--no-chain", "--no-interface",
                                   "--test-engines", "2", "--test-commands", "--test-storage-fail-at", "2"],
                  logs, stdin=True)
        procs.append(hs)
        hs.wait_for(r"listening address")
        hs.send(cmd(TE_TIMER, area(A), (12, struct.pack(">I", 1500))))
        hs.send(cmd(TE_HANDOFF, area(A), (12, struct.pack(">H", B))))
        hs.send(cmd(TE_HANDOFF, area(A), (12, struct.pack(">H", B))))
        i_f = hs.index_of(r"fatal why=storage-failed", timeout=10)
        i_r = hs.index_of(r"ready incarnation=2", timeout=10)
        check(i_f is not None and i_r is not None and i_r > i_f and hs.count(r"restart-from-storage") == 1,
              "7: one in-process restart after the storage failure")
        time.sleep(2.0)
        fired = [i for i in range(len(hs.lines)) if "test-timer area" in hs.lines[i]]
        check(all(i > (i_r or 0) for i in fired) and not fired,
              "7: the old incarnation's engine timer never fires into the new node")
        no_node_error(hs, "host with a storage failure")
        hs.stop()

        # 8. across restarts: the target that cannot be reached, and one saved
        #    before the address rule ---------------------------------------------
        hb = host(exe, work, logs, "host-8")
        procs.append(hb)
        port = hb.wait_for(r"listening address=127\.0\.0\.1:(\d+)").group(1)
        mb = member(exe, work, logs, "member-8", hkey, port)
        procs.append(mb)
        check(mb.wait_for(r"ready incarnation") is not None and
              mb.wait_for(r"connect-failed why=\S+ host=%s" % peer_id(other.hex()), timeout=10) is not None,
              "8: after a restart the saved target is issued again: a counted failure, not fatal")
        mb.stop()
        append_batch(os.path.join(work, "member", "journal.standin"),
                     [(0x7e570005, bytes.fromhex("02" + "cd" * 32) + struct.pack(">II", 0, 40) + b"not-an-address")])
        for run_no in (1, 2):
            mc = member(exe, work, logs, "member-8-saved-%d" % run_no, hkey, port)
            procs.append(mc)
            check(mc.wait_for(r"node-log test-connect-skipped area=0x7e57 why=bad-address count=1", timeout=15)
                  is not None and mc.wait_for(r"ready incarnation") is not None,
                  "8: a bad target in storage is passed over with a notice; the start completes (run %d)" % run_no)
            check(mc.wait_for(r"connected peer=%s" % peer_id(hkey), timeout=10) is not None,
                  "8: ... and the good target beside it is connected (run %d)" % run_no)
            check(mc.count(r"fatal") == 0, "8: ... never fatal (run %d)" % run_no)
            no_node_error(mc, "member with a bad saved target")
            mc.stop()
        hb.stop()

        # 12. SET_SEATED reaches the transport ------------------------------------
        hq = Proc("host-seats", [exe, "--data-dir", os.path.join(work, "host12"), "--role", "host", "--listen",
                                 "127.0.0.1:0", "--name", "host12", "--no-chain", "--no-interface",
                                 "--test-engines", "1", "--test-commands", "--test-max-conns", "2"], logs, stdin=True)
        procs.append(hq)
        qk = hq.wait_for(r"host key=([0-9a-f]{66})").group(1)
        qport = hq.wait_for(r"listening address=127\.0\.0\.1:(\d+)").group(1)
        hq.send(cmd(SLOT_OPEN, (12, bytes([0x12]) * 32), (14, b"\x01")))
        seats = {}
        for n in ("seated", "x", "y"):
            p = Proc("m12-" + n, [exe, "--data-dir", os.path.join(work, "m12-" + n), "--role", "member", "--name", n,
                                  "--no-chain", "--no-interface", "--reconnect-ms", "200",
                                  "--connect", "%s@127.0.0.1:%s" % (qk, qport)], logs)
            procs.append(p)
            seats[n] = (p, p.wait_for(r"member key=([0-9a-f]{66})").group(1))
            check(hq.wait_for(r"connected peer=%s" % peer_id(seats[n][1]), timeout=15) is not None,
                  "12: member %s connects" % n)
            if n == "seated":
                hq.send(cmd(SLOT_SEAT, (12, bytes([0x12]) * 32), (14, bytes.fromhex(seats[n][1]))))
                hq.wait_for(r"seated key=\S+ seated=1", timeout=10)
        time.sleep(1.5)
        sk = seats["seated"][1]
        check(not any("closed conn=" in l and ("key=" + sk) in l for l in hq.lines) and
              seats["seated"][0].count(r"disconnected peer=") == 0,
              "12: the seated member is never evicted for a newcomer")
        xk = seats["x"][1]
        check(any("closed conn=" in l and "evict" in l and ("key=" + xk) in l for l in hq.lines),
              "12: an unseated one is (the transport has the seat)")
        no_node_error(hq, "host with two connections")
        for p, _ in seats.values():
            p.stop()
        hq.stop()
    finally:
        kill_all(procs)
    return check.result("composite", logs)


if __name__ == "__main__":
    sys.exit(main())
