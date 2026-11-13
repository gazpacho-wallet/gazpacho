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
     starts under incarnation 2; its start resends that reply, which is
     dropped (no outbox: nobody is connected during a start); the member's
     reconnect repairs it (the test traffic's stand-in for rule 6: what is
     unanswered is sent again at connect) and the reply arrives.
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

        host2 = None
        for _ in range(40):
            host2 = Proc("host-2", [exe, "--data-dir", hdir, "--role", "host",
                                    "--listen", "127.0.0.1:" + port, "--name", "host"] + common, logs)
            if host2.wait_for(r"listening address", timeout=5) is not None:
                break
            host2.exit_code(5)
            time.sleep(0.25)
        procs.append(host2)
        r = host2.wait_for(r"ready incarnation=(\d+) resent=(\d+)")
        check(r is not None and r.group(1) == "2" and int(r.group(2)) >= 1,
              "the restarted host starts from storage under incarnation 2 and resends (resent=%s)"
              % (r.group(2) if r else "?"))
        i_resend = host2.index_of(r"start-resend peer=%s payload=%s" % (crash_peer, crash_payload.encode().hex()),
                                  timeout=1)
        i_drop = host2.index_of(r"send-dropped peer=%s why=not-connected" % crash_peer, timeout=1)
        check(i_resend is not None and i_drop is not None and i_drop > i_resend,
              "its start resends the reply that never left, and it is dropped: nobody is connected (no outbox)")
        who = "m1" if crash_peer == peer_id(keys["m1"]) else "m2"
        mp = m1 if who == "m1" else m2
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
                                "--name", "host", "--test-start-delay-ms", "2500",
                                "--test-listen-during-start"] + common, logs)
        procs.append(host3)
        check(host3.wait_for(r"start-delay ms=2500") is not None, "a host holds its start open, listening")
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

        # --- clean stop, in the shutdown order ----------------------------------
        for p in (host3, m1, m2b, m3):
            p.p.send_signal(signal.SIGTERM)
        for p in (host3, m1, m2b, m3):
            ok = p.exit_code() == 0
            idx = [p.index_of(r"shutdown " + s, timeout=2) for s in
                   ("node-stopped", "connections-closed", "storage-closed", "lock-released")]
            check(ok and None not in idx and idx == sorted(idx) and p.wait_for(r"stopped status=0", timeout=2),
                  "%s stops cleanly on SIGTERM, in the shutdown order" % p.name)

        code, out = run(exe, "--data-dir", hdir, "--role", "member", "--no-chain",
                        "--connect", "%s@127.0.0.1:%s" % (hkey, port))
        check(code == 4 and "belongs to a host" in out, "the host's folder is refused as a member's (exit %s)" % code)
    finally:
        kill_all(procs)
    return check.result("two-process test", logs)


if __name__ == "__main__":
    sys.exit(main())
