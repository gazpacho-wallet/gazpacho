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
Every process asserts that no node-error line appears, except where the case
is about one.
"""
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
SLOT_OPEN, SLOT_CLOSE = 0x7e80, 0x7e81


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
        check(h.count(r"drop why=hello-limit", start=hmark) >= 20, "4: the rest are counted on the host")
        no_node_error(mem, "member")

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
        me = member(exe, work, logs, "member-3", hkey, port)
        procs.append(me)
        check(he.wait_for(r"node-error engine=0x7e58 status=no-space", timeout=15) is not None,
              "3: engine B's error is a node error naming it")
        check(he.wait_for(r"restart-from-storage after=node-error", timeout=10) is not None,
              "3: the node restarts from storage")
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
    finally:
        kill_all(procs)
    return check.result("composite", logs)


if __name__ == "__main__":
    sys.exit(main())
