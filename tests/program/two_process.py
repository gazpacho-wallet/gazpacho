#!/usr/bin/env python3
"""Two-process test of the gazpacho program (stream S11, contract v2 P3).

    python3 -I two_process.py PATH_TO_GAZPACHO_TEST WORK_DIR

A host and two members, each a separate `gazpacho-test` process with its own
data folder, over the lobby transport (peers.h) on loopback, short timers:

  1. The members connect; every process sends placeholder pings to its peers
     (kind 32767, test build) and every node answers through its real runner
     and journal stand-in. The host listens only after its start.
  2. The host stops dead (--test-crash-at-ping) right after one ping record is
     durable, before its reply could leave. Restarted on the same folder, it
     starts under incarnation 2; its start sends nothing; the member's
     reconnect repairs it (node.h rule 6: the member's test engine asks with
     its hello, and the test traffic sends its unanswered ping again) and
     the reply arrives.
  3. Member 1's journal fails (--test-storage-fail-at): fatal; the program
     closes every connection, starts again from storage in the same process
     under incarnation 2, reconnects and goes on.
  4. Member 2 is killed (SIGKILL) mid-run and restarted: incarnation 2.
  5. Every ping of every process is answered.
  6. The start queue: a host whose start is held open (--test-start-delay-ms)
     while listening (--test-listen-during-start): a member that connects and
     pings meanwhile reaches its node only after "ready", and is answered.
  7. The lock, the role check, mainnet refused before any folder is made,
     SIGTERM stops each process cleanly in the shutdown order.
"""
import os
import shutil
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, peer_id, run  # noqa: E402

PINGS = 40
PING_MS = 40
CRASH_AT = 15        # the host stops after its 15th durable ping record
FAIL_AT = 6          # member 1's 6th journal append fails
SLOW = ["--test-ping-ms", "150"]  # member 2 pings slowly, so it is mid-run when killed
# GZP_TIME_SCALE stretches the held starts and short waits (for runs under valgrind).
SCALE = float(os.environ.get("GZP_TIME_SCALE", "1"))


def ms(v):
    return str(int(v * SCALE))

check = Checks()


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    hdir, m1dir, m2dir, m3dir = (os.path.join(work, n) for n in ("host", "m1", "m2", "m3"))
    common = ["--no-chain", "--no-interface", "--handshake-ms", "3000", "--recv-ms", "3000",
              "--send-ms", "3000", "--reconnect-ms", "100", "--max-per-address", "0",
              "--test-pings", str(PINGS), "--test-ping-ms", str(PING_MS)]
    procs = []
    try:
        code, out = run(exe, "--data-dir", os.path.join(work, "never"), "--role", "host",
                        "--no-chain", "--network", "mainnet")
        check(code == 2 and "mainnet" in out and not os.path.exists(os.path.join(work, "never")),
              "mainnet is refused and no data folder is made (exit %s)" % code)

        # --- the host: listens only after its start --------------------------
        host = Proc("host-1", [exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:0",
                               "--name", "host", "--test-crash-at-ping", str(CRASH_AT)] + common, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        hkey = k.group(1) if k else ""
        i_ready = host.index_of(r"ready incarnation=1 resent=0")
        i_listen = host.index_of(r"listening address=127\.0\.0\.1:(\d+)")
        check(k is not None and i_ready is not None and i_listen is not None and i_ready < i_listen,
              "host starts under incarnation 1 and only then listens")
        if i_listen is None:
            return 1
        port = host.find(r"listening address=127\.0\.0\.1:(\d+)")[1].group(1)
        check(host.find(r"start-counter state=created incarnation=1")[0] is not None,
              "the first start creates the start counter")

        code, out = run(exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:0", "--no-chain")
        check(code == 3 and "in use" in out, "a second program on the host's folder is refused (exit %s)" % code)
        os.unlink(os.path.join(hdir, "lock"))  # the pid file, deleted from under the running host
        code, out = run(exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:0", "--no-chain")
        check(code == 3 and "in use" in out,
              "with its lock file deleted the folder is still refused to a second program (exit %s)" % code)

        connect = ["--connect", "%s@127.0.0.1:%s" % (hkey, port)]
        m1 = Proc("m1-1", [exe, "--data-dir", m1dir, "--role", "member", "--name", "m1",
                           "--test-storage-fail-at", str(FAIL_AT)] + connect + common, logs)
        m2 = Proc("m2-1", [exe, "--data-dir", m2dir, "--role", "member", "--name", "m2"] + connect + common + SLOW, logs)
        procs += [m1, m2]
        keys = {}
        for mp, n in ((m1, "m1"), (m2, "m2")):
            mm = mp.wait_for(r"member key=([0-9a-f]{66}) host-peer=([0-9a-f]{16})")
            check(mm is not None and mm.group(2) == peer_id(hkey), "%s names the host by its key" % n)
            keys[n] = mm.group(1) if mm else ""
        check(host.wait_for(r"connected peer=%s" % peer_id(keys["m1"])) is not None and
              host.wait_for(r"connected peer=%s" % peer_id(keys["m2"])) is not None,
              "both members connect to the host over the lobby transport")

        # --- the host stops dead after a ping is durable ----------------------
        c = host.wait_for(r"test-crash ping-durable peer=([0-9a-f]{16}) payload=([0-9a-f]+)")
        check(c is not None, "the host stops after the %dth ping record is durable" % CRASH_AT)
        check(host.exit_code() == 70, "the host's crash exit status is the test hook's")
        crash_peer, crash_payload = (c.group(1), bytes.fromhex(c.group(2)).decode()) if c else ("", "")
        print("     the reply cut off was to %s for ping %s" % (crash_peer, crash_payload), flush=True)

        # Restarted with its start held open and listening, so the member's
        # connection is up (queued) while the start resends: the resend must
        # still be dropped (nothing of a queued connection is reported yet).
        host2 = None
        for _ in range(40):
            host2 = Proc("host-2", [exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:" + port,
                                    "--name", "host", "--test-start-delay-ms", ms(1500),
                                    "--test-listen-during-start"] + common, logs)
            if host2.wait_for(r"start-delay|listening address", timeout=5) is not None:
                break
            host2.exit_code(5)
            time.sleep(0.25)
        procs.append(host2)
        r = host2.wait_for(r"ready incarnation=(\d+) resent=(\d+)")
        check(r is not None and r.group(1) == "2" and int(r.group(2)) == 0,
              "the restarted host starts from storage under incarnation 2; its start sends nothing (resent=%s)"
              % (r.group(2) if r else "?"))
        check(host2.count(r"start-resend ") == 0,
              "the reply that never left is not pushed by the start: the member's hello pulls it (node.h rule 6)")
        who = "m1" if crash_peer == peer_id(keys["m1"]) else "m2"
        mp = m1 if who == "m1" else m2
        i_r = host2.index_of(r"ready incarnation=2")
        up = [mp.times[i] for i, l in enumerate(mp.lines) if " connected peer=" in l]
        check(i_r is not None and any(t < host2.times[i_r] for t in up if t > host2.started),
              "%s's connection was up, in the host's start queue, while the start resent" % who)
        kk = crash_payload.split("/")[-1]
        hp = peer_id(hkey)
        check(crash_payload.startswith(who + "/") and mp.wait_for(r"pong peer=%s k=%s " % (hp, kk)) is not None,
              "%s's reconnect repairs it: the pong for %s arrives" % (who, crash_payload))

        # --- member 1's storage failure: fatal, every connection closed --------
        check(m1.wait_for(r"fatal why=storage-failed incarnation=1") is not None,
              "member 1's journal failure is fatal for its incarnation")
        i_rs = m1.index_of(r"restart-from-storage after=storage-failed")
        i_r2 = m1.index_of(r"ready incarnation=2")
        check(i_rs is not None and i_r2 is not None and i_rs < i_r2 and
              m1.wait_for(r"connected peer=%s" % hp, start=i_r2) is not None,
              "member 1 starts again from storage in the same process (incarnation 2) and reconnects")

        # --- member 2 is killed mid-run and restarted --------------------------
        mark = m2.mark()
        check(m2.wait_for(r"pong peer=", start=mark) is not None and m2.p.poll() is None and
              m2.find(r"pings-done peer=%s" % hp)[0] is None,
              "member 2 is mid-run (pings still unanswered) when it is killed")
        m2.p.send_signal(signal.SIGKILL)
        m2.exit_code()
        m2b = Proc("m2-2", [exe, "--data-dir", m2dir, "--role", "member", "--name", "m2"] + connect + common + SLOW, logs)
        procs.append(m2b)
        check(m2b.wait_for(r"ready incarnation=2") is not None, "member 2 restarts under incarnation 2")

        # --- every ping answered ----------------------------------------------
        check(m1.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS)) is not None,
              "member 1: all %d pings to the host answered" % PINGS)
        check(m2b.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS)) is not None,
              "member 2 (restarted): all %d pings to the host answered" % PINGS)
        for n in ("m1", "m2"):
            check(host2.wait_for(r"pings-done peer=%s n=%d" % (peer_id(keys[n]), PINGS)) is not None,
                  "host: all %d pings to %s answered by %s's node" % (PINGS, n, n))

        # --- the start queue ------------------------------------------------------
        host2.stop()
        host3 = Proc("host-3", [exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:" + port,
                                "--name", "host", "--test-start-delay-ms", ms(2500), "--test-timer-ms", "300",
                                "--test-listen-during-start"] + common, logs)
        procs.append(host3)
        check(host3.wait_for(r"start-delay ms=") is not None, "a host holds its start open, listening")
        m3 = Proc("m3-1", [exe, "--data-dir", m3dir, "--role", "member", "--name", "m3"] + connect + common, logs)
        procs.append(m3)
        mm = m3.wait_for(r"member key=([0-9a-f]{66})")
        k3 = mm.group(1) if mm else ""
        # m3's transport is up and its pings go out while the host still starts
        check(m3.wait_for(r"connected peer=%s" % hp, timeout=10) is not None,
              "member 3's connection is made during the host's start")
        i_delay = host3.index_of(r"start-delay")
        i_ready3 = host3.index_of(r"ready incarnation=3")
        i_conn3 = host3.index_of(r"connected peer=%s" % peer_id(k3))
        between = [l for l in host3.lines[i_delay + 1:i_ready3 or 0]
                   if " connected " in l or " pong " in l or "pings-done" in l] if i_delay is not None else ["?"]
        check(i_ready3 is not None and i_conn3 is not None and i_conn3 > i_ready3 and not between,
              "nothing reaches the starting node: member 3's connected comes after ready")
        check(m3.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS)) is not None,
              "member 3's pings sent during the start are answered after it")

        # A member that connects and pings during a held start and is killed
        # before it ends is never reported; one that sends over 1 MiB during
        # it is closed, and reported only once it comes back after the start.
        host3.stop()
        host4 = Proc("host-4", [exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:" + port,
                                "--name", "host", "--test-start-delay-ms", ms(4000), "--test-timer-ms", "300",
                                "--test-listen-during-start"] + common, logs)
        procs.append(host4)
        check(host4.wait_for(r"start-delay ms=") is not None, "a host holds its start open again")
        m4 = Proc("m4-1", [exe, "--data-dir", os.path.join(work, "m4"), "--role", "member", "--name", "m4"]
                  + connect + common, logs)
        m5 = Proc("m5-1", [exe, "--data-dir", os.path.join(work, "m5"), "--role", "member", "--name", "m5",
                           "--test-burst", "20x60000"] + connect + common, logs)
        m6 = Proc("m6-1", [exe, "--data-dir", os.path.join(work, "m6"), "--role", "member", "--name", "m6",
                           "--test-burst", "4100x200"] + connect + common, logs)
        procs += [m4, m5, m6]
        k4 = m4.wait_for(r"member key=([0-9a-f]{66})")
        k5 = m5.wait_for(r"member key=([0-9a-f]{66})")
        k6 = m6.wait_for(r"member key=([0-9a-f]{66})")
        check(m4.wait_for(r"connected peer=%s" % hp, timeout=3 * SCALE) is not None and
              m4.wait_for(r"pong peer=|burst|test-ping", timeout=0.5) is None,
              "member 4 connects during the start (its pings go unanswered meanwhile)")
        m4.p.kill()
        m4.exit_code()
        check(m5.wait_for(r"burst-sent", timeout=3 * SCALE) is not None, "member 5 sends 1.2 MB during the start")
        p5 = peer_id(k5.group(1)) if k5 else "?"
        p6 = peer_id(k6.group(1)) if k6 else "?"
        check(host4.wait_for(r"start-queue closed conn=\d+ why=over-1MiB peer=%s" % p5, timeout=6 * SCALE) is not None,
              "the host closes member 5's connection past the 1 MiB start-queue cap")
        # On the boundary (review B of PR 27, B2): 4,100 messages of 200 bytes
        # are 820,000 bytes of payload, under 1 MiB (1,048,576), and 1,082,400
        # with the 64 bytes counted per message, over it. Without the
        # overhead this connection would stay open.
        check(m6.wait_for(r"burst-sent", timeout=6 * SCALE) is not None and
              host4.wait_for(r"start-queue closed conn=\d+ why=over-1MiB peer=%s" % p6, timeout=6 * SCALE) is not None,
              "member 6's 4,100 x 200 bytes (payload under 1 MiB) pass the cap only with 64 bytes counted "
              "per message: closed")
        i_r4 = host4.index_of(r"ready incarnation=4", timeout=10 * SCALE)
        check(host4.wait_for(r"start-queue dropped conn=\d+ why=closed-during-start", timeout=1) is not None and
              host4.find(r"connected peer=%s" % peer_id(k4.group(1) if k4 else "00"))[0] is None,
              "member 4, gone before the start ended, is never reported to the node")
        # B5: what it queued is freed when it closes, not when the start ends.
        i_d4 = host4.find(r"start-queue dropped conn=\d+ why=closed-during-start peer=%s messages=[1-9]\d*"
                          % peer_id(k4.group(1) if k4 else "00"))[0]
        check(i_d4 is not None and i_r4 is not None and i_d4 < i_r4,
              "member 4's queued pings are dropped when it closes, during the start")
        i_c5 = host4.index_of(r"connected peer=%s" % peer_id(k5.group(1) if k5 else "00"), timeout=10)
        check(i_r4 is not None and i_c5 is not None and i_c5 > i_r4, "member 5 comes back after the start")
        i_t = host4.index_of(r"test-timer fired", timeout=5)
        check(i_r4 is not None and i_t is not None and i_t > i_r4 and
              host4.find(r"test-timer fired")[0] == i_t,
              "a test timer due during the start fires only after it")

        # --- clean stop, in the shutdown order, read from the state -------------
        for p in (host4, m1, m2b, m3, m5, m6):
            p.p.send_signal(signal.SIGTERM)
        want = [("node-stopped", "transport=1 storage=1 lock=1"),
                ("connections-closed", "transport=0 storage=1 lock=1"),
                ("storage-closed", "transport=0 storage=0 lock=1"),
                ("lock-released", "transport=0 storage=0 lock=0")]
        for p in (host4, m1, m2b, m3, m5, m6):
            ok = p.exit_code() == 0
            idx = [p.index_of(r"shutdown %s %s" % w, timeout=2) for w in want]
            check(ok and None not in idx and idx == sorted(idx) and p.wait_for(r"stopped status=0", timeout=2),
                  "%s stops cleanly on SIGTERM: transport, then storage, then the lock" % p.name)

        code, out = run(exe, "--data-dir", hdir, "--role", "member", "--no-chain",
                        "--connect", "%s@127.0.0.1:%s" % (hkey, port))
        check(code == 4 and "belongs to a host" in out, "the host's folder is refused as a member's (exit %s)" % code)
    finally:
        kill_all(procs)
    return check.result("two-process test", logs)


if __name__ == "__main__":
    sys.exit(main())
