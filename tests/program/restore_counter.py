#!/usr/bin/env python3
"""T8, program_restore_counter (contract-v2.md section 8), stand-in counter.

    python3 -I restore_counter.py PATH_TO_GAZPACHO_TEST WORK_DIR

A member runs to incarnation 2 and its journal is copied aside (the backup).
It is started three more times (incarnation 5). The copy is put back as a
restore (--test-restore-from, which sets the restore marker): the restored
start's incarnation is 6, not 3; its first batch is the restore batch, with a
restore epoch other than the original installation's (0); pings before and
after are answered; the marker is gone once that batch is durable.
Variants: with starts.standin removed before the restore the incarnation is
3 and the output says the person is told (counter_found 0); a counter of
2^63 refuses the start.
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, parse_journal, peer_id  # noqa: E402

PINGS = 5
check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    common = ["--no-chain", "--no-interface", "--reconnect-ms", "100",
              "--test-pings", str(PINGS), "--test-ping-ms", "30"]
    procs = []
    runs = [0]

    try:
        host = Proc("host", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host",
                             "--listen", "127.0.0.1:0", "--name", "host"] + common, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "host listens")
            return 1
        hkey, port = k.group(1), m.group(1)
        hp = peer_id(hkey)
        connect = ["--connect", "%s@127.0.0.1:%s" % (hkey, port)]

        def member(folder, *extra):
            runs[0] += 1
            p = Proc("%s-%d" % (os.path.basename(folder), runs[0]),
                     [exe, "--data-dir", folder, "--role", "member", "--name", "m"] + connect + common + list(extra),
                     logs)
            procs.append(p)
            return p

        def run_once(folder, *extra):
            """Start, wait for every ping answered, stop. The incarnation, or None."""
            p = member(folder, *extra)
            r = p.wait_for(r"ready incarnation=(\d+)")
            done = p.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS))
            p.stop()
            return p, (int(r.group(1)) if r else None), done is not None

        for variant in ("counter", "no-counter"):
            folder = os.path.join(work, "member-" + variant)
            backup = os.path.join(work, "backup-" + variant)
            incs = []
            for _ in range(2):
                _, inc, ok = run_once(folder)
                incs.append(inc)
                check(ok, "%s: pings answered at incarnation %s" % (variant, inc))
            shutil.copyfile(os.path.join(folder, "journal.standin"), backup)
            for _ in range(3):
                _, inc, ok = run_once(folder)
                incs.append(inc)
            check(incs == [1, 2, 3, 4, 5], "%s: five starts, incarnations %s" % (variant, incs))
            if variant == "no-counter":
                os.unlink(os.path.join(folder, "starts.standin"))
            p, inc, ok = run_once(folder, "--test-restore-from", backup)
            want = 6 if variant == "counter" else 3
            check(inc == want, "%s: the restored start's incarnation is %d (got %s)" % (variant, want, inc))
            st = p.find(r"start-counter state=(\w+) incarnation=(\d+) restored=1")[1]
            check(st is not None and st.group(1) == ("found" if variant == "counter" else "missing"),
                  "%s: the start sees the restore marker and the counter %s" %
                  (variant, "found" if variant == "counter" else "missing"))
            i_rb, rb = p.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")
            i_ping, _ = p.find(r"pong peer=")
            check(rb is not None and rb.group(1) != "00000000" and (i_ping is None or i_rb < i_ping),
                  "%s: the first batch is the restore batch, epoch %s (the original's is 0)" %
                  (variant, rb.group(1) if rb else "?"))
            check(p.find(r"restore answered")[0] is not None and
                  not os.path.exists(os.path.join(folder, "restore.pending")),
                  "%s: the marker is gone once that batch is durable" % variant)
            check(ok, "%s: pings answered after the restore" % variant)
            if variant == "no-counter":
                check(p.find(r"restore counter_found=0: the person is told")[0] is not None,
                      "no-counter: the output says the person is told (counter_found 0)")
            p2, inc2, ok2 = run_once(folder)
            check(inc2 == want + 1 and p2.find(r"restored=0")[0] is not None and ok2,
                  "%s: the next start is an ordinary one, incarnation %d" % (variant, want + 1))

        # The counter is written before the incarnation entry: stopped between
        # the two, the counter holds the new number and the journal does not,
        # and the next start skips that number rather than reuse it.
        folder = os.path.join(work, "member-crash")
        _, inc, _ = run_once(folder)
        p = member(folder, "--test-crash-after-counter")
        code = p.exit_code(30)
        with open(os.path.join(folder, "starts.standin")) as f:
            counter = f.read().strip()
        incs = [e[1] for e in parse_journal(os.path.join(folder, "journal.standin")) if e[0] == "INCN"]
        check(inc == 1 and code == 70 and p.find(r"test-crash after-counter incarnation=2")[0] is not None and
              counter == "GZSTART0 2" and max(incs) == 1,
              "stopped between the two writes: the counter says 2, the journal's highest is 1")
        _, inc, ok = run_once(folder)
        check(inc == 3 and ok, "the next start skips 2 and starts at 3 (got %s)" % inc)

        # A counter at 2^63 refuses the start.
        folder = os.path.join(work, "member-counter")
        with open(os.path.join(folder, "starts.standin"), "w") as f:
            f.write("GZSTART0 9223372036854775808\n")
        p = member(folder)
        code = p.exit_code(30)
        check(code == 4 and p.find(r"start-refused why=storage")[0] is not None and
              p.find(r"ready incarnation")[0] is None,
              "a start counter of 2^63 refuses the start (exit %s)" % code)
    finally:
        kill_all(procs)
    return check.result("restore counter", logs)


if __name__ == "__main__":
    sys.exit(main())
