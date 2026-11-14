#!/usr/bin/env python3
"""T1, program_resend_on_connect (contract-v2.md section 1): a reply that did
not reach the member reaches it when it comes back, through the reconnect
step (node.h rule 6: the member's hello pulls what it has not acknowledged).

    python3 -I resend_on_connect.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. The member sends ping 1 and exits at once (--test-exit-after-send); the
     host saves the ping; its reply finds no member.
  2. The host is killed (SIGKILL) and restarted. The member is started again:
     at PEER_CONNECTED it sends GZPH; the host answers with reply 1; the
     member acknowledges; the host saves PING_ACKED 1.
  3. The host is restarted once more: after the member's hello it sends no
     reply (the acknowledgement is stored).
  4. The same with only the member restarted: a new unacknowledged reply
     arrives after the member's restart, and after a further restart nothing.
  5. During a start held for 2 s, the member reconnecting in a loop, a test
     timer due and a test command given: the connection, the timer and the
     command reach the node after the start (the command meanwhile answered
     503), and the reply still arrives.
  6. A restart in one process after a storage failure: every connection
     closes, incarnation n + 1 starts, the member reconnects and the
     unacknowledged reply arrives.
  7. A full queue: the host's max_queue below the size of a padded reply
     (60,000 bytes: kind 32767 is never split, so the 200 KB of contract v2's
     T1 cannot travel as test traffic); the connection closes, the member
     reconnects; with max_queue restored the reply arrives.
No process may show a node-error line.
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, cmd, free_port, kill_all, parse_journal, peer_id  # noqa: E402

check = Checks()
ACKED = 0x7e570004


def acked(work):
    return sum(1 for e in parse_journal(os.path.join(work, "host", "journal.standin")) if e[0] == "BTCH"
               for r in e[3] if r[0] == ACKED)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()
    base = ["--no-chain", "--no-interface"]
    procs = []
    n = [0]

    def host(*extra, stdin=False):
        n[0] += 1
        p = Proc("host-%d" % n[0], [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen",
                                    "127.0.0.1:%d" % port, "--name", "host"] + base + list(extra), logs, stdin=stdin)
        procs.append(p)
        return p

    def member(*extra):
        n[0] += 1
        p = Proc("member-%d" % n[0], [exe, "--data-dir", os.path.join(work, "member"), "--role", "member",
                                      "--name", "m%d" % n[0], "--reconnect-ms", "100",
                                      "--connect", "%s@127.0.0.1:%d" % (hkey, port)] + base + list(extra), logs)
        procs.append(p)
        return p

    def unacked_reply():
        """A ping whose reply the member never handles: it drops what it receives and exits right after sending."""
        m = member("--test-pings", "1", "--test-exit-after-send", "--test-drop-kind", "32767")
        code = m.exit_code(timeout=20)
        check(code == 70, "the member sent a ping and exited at once (exit %s)" % code)
        time.sleep(1.2)  # past the host's one hello answer a second for this link

    try:
        h = host()
        k = h.wait_for(r"host key=([0-9a-f]{66})")
        hkey = k.group(1) if k else "00"
        h.wait_for(r"listening address")

        # 1 and 2 -----------------------------------------------------------------
        unacked_reply()
        time.sleep(0.5)
        h.p.kill()
        h.exit_code()
        check(acked(work) == 0, "1: the ping is saved and nothing acknowledges its reply")
        h = host()
        h.wait_for(r"listening address")
        m = member()
        check(m.wait_for(r"test-reply area=0x7e57 serial=1", timeout=20) is not None,
              "2: after the restarts the member's hello pulls reply 1")
        end = time.time() + 10
        while time.time() < end and h.count(r"connected") and acked(work) == 0:
            time.sleep(0.2)
        check(acked(work) == 1, "2: the host saved PING_ACKED 1")

        # 3 -----------------------------------------------------------------------
        h.stop()
        mark = m.mark()
        h = host()
        check(m.wait_for(r" connected peer=%s" % peer_id(hkey), start=mark, timeout=15) is not None,
              "3: the member reconnects to the restarted host")
        time.sleep(1.5)
        check(m.count(r"test-reply", start=mark) == 0, "3: no reply is sent again: its acknowledgement is stored")
        m.stop()

        # 4 -----------------------------------------------------------------------
        unacked_reply()
        m = member()
        check(m.wait_for(r"test-reply area=0x7e57 serial=2", timeout=15) is not None,
              "4: only the member restarted: reply 2 arrives")
        time.sleep(0.5)
        m.stop()
        m = member()
        m.wait_for(r" connected peer=", timeout=15)
        time.sleep(1.5)
        check(m.count(r"test-reply") == 0, "4: after another restart, nothing")
        m.stop()

        # 5 -----------------------------------------------------------------------
        unacked_reply()
        h.stop()
        h = host("--test-start-delay-ms", "2000", "--test-timer-ms", "300", "--test-commands", stdin=True)
        h.wait_for(r"start-delay ms=2000")
        m = member()
        h.send(cmd(0x7e7f))
        i_ready = h.index_of(r"ready incarnation", timeout=15)
        check(h.find(r"command-answer status=503 code=node_stopped")[0] is not None and
              h.find(r"command-answer")[0] < (i_ready or 0), "5: a command during the start is answered 503")
        check(m.wait_for(r"test-reply area=0x7e57 serial=3", timeout=20) is not None,
              "5: the reply arrives after the start")
        i_conn = h.index_of(r" connected peer=", timeout=5)
        i_timer = h.index_of(r"test-timer fired", timeout=5)
        check(i_ready is not None and i_conn is not None and i_conn > i_ready and i_timer is not None and
              i_timer > i_ready, "5: the connection and the due timer reach the node after the start")
        check(h.count(r"message-from-unreported-peer") == 0, "5: no message before its connection's connected")
        m.stop()

        # 6 -----------------------------------------------------------------------
        unacked_reply()
        h.stop()
        h = host("--test-storage-fail-at", "1")
        m = member("--test-pings", "1", "--test-ping-ms", "50")
        check(h.wait_for(r"fatal why=storage-failed", timeout=15) is not None, "6: the host's storage fails once")
        check(h.wait_for(r"ready incarnation", start=h.index_of(r"restart-from-storage") or 0, timeout=15)
              is not None, "6: ... and it restarts in process")
        check(m.wait_for(r"test-reply area=0x7e57 serial=4", timeout=20) is not None,
              "6: the member reconnects and the unacknowledged reply arrives")
        m.stop()

        # 7 -----------------------------------------------------------------------
        unacked_reply()
        h.stop()
        h = host("--max-queue", "32768", "--test-big-reply", "60000")
        m = member()
        check(h.wait_for(r"closed conn=\d+ why=\S*(send|queue|refused)\S*", timeout=15) is not None,
              "7: a reply over max_queue closes the connection")
        check(m.count(r"test-reply") == 0, "7: ... and does not arrive")
        h.stop()
        mark = m.mark()
        h = host("--test-big-reply", "60000")
        check(m.wait_for(r"test-reply area=0x7e57 serial=", start=mark, timeout=20) is not None,
              "7: with max_queue restored the member reconnects and the reply arrives")
        m.stop()
        h.stop()
        for p in procs:
            check(p.count(r"node-error") == 0, "%s: no node-error line" % p.name)
    finally:
        kill_all(procs)
    return check.result("resend on connect", logs)


if __name__ == "__main__":
    sys.exit(main())
