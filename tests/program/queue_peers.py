#!/usr/bin/env python3
"""program_queue_peers: the start queue hands each connection's messages to
the node under that connection, after its connected (review B of PR 27, B2:
mutants B41 and B42), and the queue as a whole is capped (B5).

    python3 -I queue_peers.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Two members connect and ping during a host's held start, each with its
     own payloads ("a/k", "b/k"). Afterwards every ping record in the host's
     journal names, as its peer, the member that sent that payload; each
     member's 5 pings are there; nothing reached the host's node from a peer
     it had not been told was connected (the test build's check line); and
     both members get every pong.
  2. Five members each queue 976,800 bytes (3,700 messages of 200 bytes plus
     64 bytes counted per message: under the 1 MiB per connection) during a
     held start: together past the queue's 4 MiB, so a connection is closed
     "over-total", none "over-1MiB", and the start still completes.
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import RECORD_TEST_PING, Checks, Proc, free_port, kill_all, parse_journal, peer_id  # noqa: E402

check = Checks()
SCALE = float(os.environ.get("GZP_TIME_SCALE", "1"))


def ms(v):
    return str(int(v * SCALE))


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    base = ["--no-chain", "--no-interface", "--reconnect-ms", "100", "--handshake-ms", "3000", "--recv-ms", "5000",
            "--send-ms", "5000"]
    procs = []
    try:
        # 1. attribution ------------------------------------------------------------
        hd = os.path.join(work, "host")
        port = free_port()  # the "listening" line comes only after the start
        host = Proc("host", [exe, "--data-dir", hd, "--role", "host", "--listen", "127.0.0.1:%d" % port, "--name", "host",
                             "--max-per-address", "0", "--test-start-delay-ms", ms(3000),
                             "--test-listen-during-start"] + base, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        if not (k and host.wait_for(r"start-delay ms=")):
            check(False, "the host holds its start, listening")
            return 1
        hp = peer_id(k.group(1))
        connect = ["--connect", "%s@127.0.0.1:%d" % (k.group(1), port)]
        mem = {}
        for n in ("a", "b"):
            mem[n] = Proc(n, [exe, "--data-dir", os.path.join(work, n), "--role", "member", "--name", n,
                              "--test-pings", "5", "--test-ping-ms", "50"] + connect + base, logs)
            procs.append(mem[n])
        keys = {}
        for n, p in mem.items():
            mk = p.wait_for(r"member key=([0-9a-f]{66})")
            keys[n] = mk.group(1) if mk else ""
            check(p.wait_for(r"connected peer=%s" % hp, timeout=10) is not None,
                  "member %s connects during the host's start" % n)
        i_ready = host.index_of(r"ready incarnation=1", timeout=30)
        sent_during = all(any(t < host.times[i_ready] for i, t in enumerate(p.times) if " connected peer=" in p.lines[i])
                          for p in mem.values()) if i_ready is not None else False
        check(i_ready is not None and sent_during, "both members were up, queued, before the host's ready")
        for n, p in mem.items():
            check(p.wait_for(r"pings-done peer=%s n=5" % hp, timeout=30) is not None,
                  "member %s gets every pong" % n)
        host.stop()
        for p in mem.values():
            p.stop()
        recs = [r[1] for e in parse_journal(os.path.join(hd, "journal.standin")) if e[0] == "BTCH"
                for r in e[3] if r[0] in RECORD_TEST_PING and len(r[1]) >= 82]
        wrong, per = [], {"a": 0, "b": 0}
        for r in recs:
            who = r[82:].split(b"/")[0].decode(errors="replace")
            if who in keys:
                per[who] += 1
                if r[41:74].hex() != keys[who]:    # the link's remote key (test_engine.h)
                    wrong.append((r[82:].decode(errors="replace"), r[41:74].hex()))
        check(per["a"] >= 5 and per["b"] >= 5 and not wrong,
              "every ping record names the member that sent it (a %d, b %d, wrong %s)" % (per["a"], per["b"], wrong[:4]))
        check(host.count(r"test-order message-from-unreported-peer") == 0,
              "no message reached the host's node before its connection's connected (%d)"
              % host.count(r"test-order message-from-unreported-peer"))
        i_c = [host.index_of(r"connected peer=%s" % peer_id(keys[n]), timeout=1) for n in ("a", "b")]
        check(None not in i_c and i_ready is not None and min(i_c) > i_ready,
              "each member's connected comes after the host's ready")

        # 2. the cap on the whole queue -------------------------------------------
        hd2 = os.path.join(work, "host2")
        port2 = free_port()
        h2 = Proc("host2", [exe, "--data-dir", hd2, "--role", "host", "--listen", "127.0.0.1:%d" % port2, "--name", "host2",
                            "--max-per-address", "0", "--test-start-delay-ms", ms(8000),
                            "--test-listen-during-start"] + base, logs)
        procs.append(h2)
        k2 = h2.wait_for(r"host key=([0-9a-f]{66})")
        if not (k2 and h2.wait_for(r"start-delay ms=")):
            check(False, "the second host holds its start, listening")
            return 1
        connect2 = ["--connect", "%s@127.0.0.1:%d" % (k2.group(1), port2)]
        big = []
        for i in range(5):
            p = Proc("big%d" % i, [exe, "--data-dir", os.path.join(work, "big%d" % i), "--role", "member", "--name",
                                   "big%d" % i, "--test-burst", "3700x200"] + connect2 + base, logs)
            procs.append(p)
            big.append(p)
            time.sleep(0.2)
        for p in big:
            check(p.wait_for(r"burst-sent", timeout=15) is not None, "%s sends its burst during the start" % p.name)
        check(h2.wait_for(r"start-queue closed conn=\d+ why=over-total", timeout=15) is not None,
              "the queue as a whole is capped: a connection past 4 MiB in all is closed")
        check(h2.count(r"why=over-1MiB") == 0, "no connection was over its own 1 MiB")
        check(h2.wait_for(r"ready incarnation=1", timeout=30) is not None, "the held start completes")
        h2.stop()
    finally:
        kill_all(procs)
    return check.result("start queue per peer", logs)


if __name__ == "__main__":
    sys.exit(main())
