#!/usr/bin/env python3
"""program_journal_kill: kill -9 at every storage write, then restart (S5, S6).

    python3 -I journal_kill.py PATH_TO_GAZPACHO_TEST WORK_DIR [STEP]

Two lives of a member, each run again and again with --test-kill-at K for
K = 1, 2, ... (every STEP-th, default 1) until a run passes all its storage
calls: SIGKILL just before the K-th write, sync, truncate, rename or removal
of any storage file of the process (the journal's and the storage layer's).

  set-up    from nothing: the key file, guard, start counter, mark file and
            journal (storage 7.4), the attempts file, the first start (the
            counter, the incarnation entry and its sync mark), the CONNECT
            target saved;
  restore   on a wallet with a few starts, an older backup imported
            (--test-restore-from): the staged copy, restore.gzr, the rename,
            the mark file started again with the restore marker, the
            counter, the incarnation, the restore batch (an anchored batch:
            its mark-file entry and the guard file), the marker cleared.

After each kill the same folder is started with no hook (twice), and must:
start (a kill never makes a journal corrupt, behind or possibly old, nor a
wallet that cannot be opened); hold a journal whose incarnations rise and
whose batches are 1, 2, 3 ... within each; in the restore life, be a restore
until the restore batch is durable and an ordinary start after it, with a
restore epoch other than 0; and stop cleanly.
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, dump_journal, free_port, kill_all  # noqa: E402

check = Checks()
HOST_KEY = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
KEY_EPOCH = 0x00040002


def journal_ok(entries):
    """Rising incarnations, and batch sequences 1, 2, 3 ... within each."""
    inc, seq = 0, 0
    for e in entries:
        if e[0] == "INCN":
            if e[1] <= inc:
                return False
            inc, seq = e[1], 0
        else:
            if e[1] != inc or e[2] != seq + 1:
                return False
            seq = e[2]
    return True


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()  # nobody listens: the member saves its target and retries
    procs = []
    n = [0]

    def args(folder):
        return [exe, "--data-dir", folder, "--role", "member", "--name", "m", "--no-chain", "--no-interface",
                "--reconnect-ms", "200", "--connect", "%s@127.0.0.1:%d" % (HOST_KEY, port)]

    def run(folder, *extra, name="run"):
        """Start and stop once: (the ready line or None, the proc)."""
        n[0] += 1
        p = Proc("%s-%d" % (name, n[0]), args(folder) + list(extra), logs)
        procs.append(p)
        m = p.wait_for(r"ready incarnation=(\d+)|start-refused.*|unlock op=\w+ status=(?!ok)\w+.*|test-kill before=\S+",
                       timeout=60)
        return m, p

    # The restore life's base: set up, three starts, a backup after the first.
    base = os.path.join(work, "base")
    backup = os.path.join(work, "backup.gzj")
    for i in range(3):
        m, p = run(base, name="base")
        p.wait_for(r"connect-kept")
        p.stop()
        if i == 0:
            shutil.copyfile(os.path.join(base, "journal.gzj"), backup)
    check(m is not None and m.group(0).startswith("ready"), "the restore life's base starts three times")

    totals = {}
    try:
        for life in ("set-up", "restore"):
            kills = restored_after = 0
            k = 0
            while True:
                k += step
                folder = os.path.join(work, "%s-%d" % (life, k))
                extra = []
                if life == "restore":
                    shutil.copytree(base, folder)
                    extra = ["--test-restore-from", backup]
                m, p = run(folder, *(extra + ["--test-kill-at", str(k)]), name="kill-" + life)
                if m is None:
                    check(False, "%s K=%d: the run neither died nor started" % (life, k))
                    break
                if not m.group(0).startswith("test-kill"):
                    # This run passed every storage call: the life is covered.
                    ok = m.group(0).startswith("ready")
                    p.wait_for(r"connect-kept")
                    p.stop()
                    check(ok and p.exit_code() == 0, "%s K=%d: the run past the last storage call starts and stops"
                          % (life, k))
                    break
                code = p.exit_code(timeout=30)
                kills += 1
                if not check(code == -9, "%s K=%d: killed %s (exit %s)" % (life, k, m.group(0), code)):
                    continue
                for again in (0, 1):
                    m2, q = run(folder, name="after-" + life)
                    ok = m2 is not None and m2.group(0).startswith("ready")
                    check(ok, "%s K=%d start %d after the kill: %s" % (life, k, again + 1, m2.group(0) if m2 else None))
                    restored = q.find(r"start steps=\d+ restored=1")[0] is not None
                    if life == "restore" and again == 0 and restored:
                        restored_after += 1
                        e = q.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
                        check(e is not None and e.group(1) != "00000000",
                              "%s K=%d: the repeated restore saves a new epoch" % (life, k))
                    if again == 1:
                        check(not restored, "%s K=%d: once answered, the next start is ordinary" % (life, k))
                    q.wait_for(r"connect-kept")
                    q.stop()
                    check(q.exit_code() == 0, "%s K=%d start %d: stops cleanly" % (life, k, again + 1))
                    if not ok:
                        break
                    entries = dump_journal(folder, exe)
                    check(journal_ok(entries) and any(e[0] == "BTCH" for e in entries),
                          "%s K=%d start %d: incarnations rise, sequences 1, 2, 3 ..." % (life, k, again + 1))
                    eps = [b for e in entries if e[0] == "BTCH" for t, b in e[3] if t == KEY_EPOCH]
                    check(len(eps) == len(set(eps)), "%s K=%d: no key epoch saved twice" % (life, k))
                shutil.rmtree(folder, ignore_errors=True)
                for q in procs:
                    q.stop()
                procs[:] = []
            totals[life] = (kills, restored_after)
        check(totals.get("set-up", (0,))[0] >= 20 // step and totals.get("restore", (0,))[0] >= 20 // step,
              "killed at every storage call: %s (kills, starts that repeated the restore)" % totals)
    finally:
        kill_all(procs)
    return check.result("program_journal_kill", logs)


if __name__ == "__main__":
    sys.exit(main())
