#!/usr/bin/env python3
"""T2 steps 1 and 2, program_links (contract-v2.md section 2): peers are named
by links, and a reply goes only to the link it belongs to.

    python3 -I links.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Member A pings; the host is killed after the ping is durable and before
     the reply leaves (--test-crash-at-ping); restarted, it answers A's hello
     on A's link; member B, connected too, never receives A's reply.
  2. A connects a second time with the same keys (a copy of its folder) while
     the first connection is open: the host shows the older connection
     replaced, then the new one connected, no `host full` refusal, and
     exactly one reply per ping reaches the new connection.
(Step 3, a second index pair to the same host, needs derived keys: P8.)
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, free_port, kill_all, peer_id  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()
    base = ["--no-chain", "--no-interface"]
    procs = []
    try:
        h = Proc("host-1", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen",
                            "127.0.0.1:%d" % port, "--name", "host", "--test-crash-at-ping", "1"] + base, logs)
        procs.append(h)
        hkey = h.wait_for(r"host key=([0-9a-f]{66})").group(1)
        h.wait_for(r"listening address")
        conn = "%s@127.0.0.1:%d" % (hkey, port)
        b = Proc("member-b", [exe, "--data-dir", os.path.join(work, "b"), "--role", "member", "--name", "b",
                              "--reconnect-ms", "100", "--connect", conn] + base, logs)
        procs.append(b)
        check(h.wait_for(r" connected peer=", timeout=15) is not None, "B connects first")
        a = Proc("member-a", [exe, "--data-dir", os.path.join(work, "a"), "--role", "member", "--name", "a",
                              "--reconnect-ms", "100", "--connect", conn, "--test-pings", "1"] + base, logs)
        procs.append(a)
        akey = a.wait_for(r"member key=([0-9a-f]{66})").group(1)
        check(h.wait_for(r"test-crash ping-durable peer=%s" % peer_id(akey), timeout=15) is not None and
              h.exit_code(timeout=10) == 70, "1: the host stops once A's ping is durable, before the reply")
        check(a.count(r"test-reply") == 0, "1: A got no reply before the crash")
        h2 = Proc("host-2", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen",
                             "127.0.0.1:%d" % port, "--name", "host"] + base, logs)
        procs.append(h2)
        check(a.wait_for(r"test-reply area=0x7e57 serial=1", timeout=20) is not None,
              "1: the restarted host answers A's hello on A's link")
        time.sleep(1.0)
        check(b.count(r"test-reply") == 0 and b.count(r"pong ") == 0, "1: B never receives A's reply")

        # 2 ---------------------------------------------------------------------
        a.stop()
        shutil.copytree(os.path.join(work, "a"), os.path.join(work, "a2"))
        os.chmod(os.path.join(work, "a2"), 0o700)
        a = Proc("member-a-again", [exe, "--data-dir", os.path.join(work, "a"), "--role", "member", "--name", "a",
                                    "--reconnect-ms", "60000", "--connect", conn] + base, logs)
        procs.append(a)
        check(a.wait_for(r" connected peer=", timeout=15) is not None, "2: A is connected")
        mark = h2.mark()
        a2 = Proc("member-a-copy", [exe, "--data-dir", os.path.join(work, "a2"), "--role", "member", "--name", "a2",
                                    "--reconnect-ms", "100", "--connect", conn, "--test-pings", "2",
                                    "--test-ping-ms", "100"] + base, logs)
        procs.append(a2)
        i_rep = h2.index_of(r"closed conn=\d+ why=replaced-by-a-newer-connection", start=mark, timeout=15)
        i_dis = h2.index_of(r"disconnected peer=%s" % peer_id(akey), start=mark, timeout=15)
        i_con = h2.index_of(r" connected peer=%s" % peer_id(akey), start=(i_dis or mark), timeout=15)
        check(i_rep is not None and i_dis is not None and i_con is not None and i_con > i_dis,
              "2: the host shows the old connection replaced, then the new one connected")
        check(h2.count(r"host-full", start=mark) == 0, "2: no refusal for a full host")
        check(a2.wait_for(r"pings-done peer=%s n=2" % peer_id(hkey), timeout=20) is not None,
              "2: the copy's pings are answered")
        time.sleep(0.5)
        check(a2.count(r"pong peer=.* k=0 .*dup=0") == 1 and a2.count(r"pong peer=.* k=1 .*dup=0") == 1,
              "2: exactly one reply per ping reaches the new connection")
        for p in (b, a2, h2):
            check(p.count(r"node-error") == 0, "%s: no node-error line" % p.name)
    finally:
        kill_all(procs)
    return check.result("links", logs)


if __name__ == "__main__":
    sys.exit(main())
