#!/usr/bin/env python3
"""T7, program_envelope (contract-v2.md section 7): factory messages carry
kind, scope and records from engine to engine.

    python3 -I envelope.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Pings travel as kind 32767 through gz_peers_send and arrive with kind and
     scope intact: answered, and acknowledged (PING_ACKED in the host's
     journal).
  2. A raw factory message of an unknown even kind: the host closes the
     connection. An unknown odd kind: ignored, the connection kept.
  3. A host test reply padded to 60,000 bytes reaches the member whole and the
     member's acknowledgement comes back. (Contract v2 asks for 200,000 bytes
     as parts; kind 32767 is never split by the transport, so a reply over
     65,495 bytes cannot travel as test traffic: reported, not improvised.)
  4. A member test message of 70,000 bytes: the member's incarnation ends
     (message-too-big, fatal) and it restarts from storage.
"""
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, cmd, free_port, kill_all, parse_journal, peer_id, tlv  # noqa: E402

check = Checks()


def acked(work):
    return sum(1 for e in parse_journal(os.path.join(work, "host", "journal.standin")) if e[0] == "BTCH"
               for r in e[3] if r[0] == 0x7e570004)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()
    base = ["--no-chain", "--no-interface"]
    procs = []
    try:
        h = Proc("host", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen",
                          "127.0.0.1:%d" % port, "--name", "host", "--test-big-reply", "60000"] + base, logs)
        procs.append(h)
        hkey = h.wait_for(r"host key=([0-9a-f]{66})").group(1)
        h.wait_for(r"listening address")
        m = Proc("member", [exe, "--data-dir", os.path.join(work, "m"), "--role", "member", "--name", "m",
                            "--reconnect-ms", "100", "--connect", "%s@127.0.0.1:%d" % (hkey, port),
                            "--test-pings", "3", "--test-ping-ms", "50", "--test-commands"] + base, logs, stdin=True)
        procs.append(m)
        check(m.wait_for(r"pings-done peer=%s n=3" % peer_id(hkey), timeout=20) is not None,
              "1, 3: kind-32767 pings answered with 60,000-byte replies")
        check(m.wait_for(r"test-reply area=0x7e57 serial=3 ", timeout=20) is not None and m.count(r"test-reply area=0x7e57") >= 3,
              "3: each padded reply reached the member's engine whole")

        # 2: unknown kinds, raw --------------------------------------------------
        mark = m.mark()
        m.send("raw-kind 1001")
        time.sleep(1.0)
        check(m.count(r"disconnected", start=mark) == 0, "2: an unknown odd kind is ignored, the connection kept")
        m.send("raw-kind 1000")
        check(m.wait_for(r"disconnected peer=%s" % peer_id(hkey), start=mark, timeout=10) is not None,
              "2: an unknown even kind: the host closes the connection")
        check(m.wait_for(r" connected peer=%s" % peer_id(hkey), start=m.index_of(r"disconnected", start=mark) or mark,
                         timeout=10) is not None, "2: the member connects again")

        # 4: a member message too big ---------------------------------------------
        mark = m.mark()
        big = tlv((1, b"GZPX" + b"\0" * 69990))
        m.send(cmd(0x7e06, (12, bytes.fromhex(hkey)), (14, struct.pack(">H", 32767)), (16, b"\0" * 32), (18, big)))
        check(m.wait_for(r"fatal why=message-too-big", start=mark, timeout=10) is not None,
              "4: a member message over 65,495 bytes is fatal for the incarnation")
        check(m.wait_for(r"ready incarnation", start=m.index_of(r"restart-from-storage", start=mark) or mark,
                         timeout=10) is not None, "4: the member restarts from storage")
        m.stop()
        h.stop()
        check(acked(work) >= 3, "1, 3: the acknowledgements came back and were saved (%d)" % acked(work))
        for p in (m, h):
            check(p.count(r"node-error") == 0, "%s: no node-error line" % p.name)
    finally:
        kill_all(procs)
    return check.result("envelope", logs)


if __name__ == "__main__":
    sys.exit(main())
