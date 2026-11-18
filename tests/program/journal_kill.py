#!/usr/bin/env python3
"""program_journal_kill: kill -9 at every storage write, then restart (S5, S6).

    python3 -I journal_kill.py PATH_TO_GAZPACHO_TEST WORK_DIR [STEP [power]]

With "power" (program_journal_powercut), each kill is a power cut instead
(--test-power-cut-at K, review A of PR 54, M3): before the SIGKILL the
folder is put back to what a disk keeps, every file's data as of its last
fsync and the folder's names as of its last folder sync, so a missing fsync
or folder sync loses its write.

Two lives of a member, each run again and again with --test-kill-at K for
K = 1, 2, ... (every STEP-th, default 1) until a run passes all its storage
calls: SIGKILL just before the K-th write, sync, truncate, rename or removal
of any storage file of the process (the journal's and the storage layer's).

  set-up    from nothing: the key file, guard, start counter, mark file and
            journal (storage 7.4), the attempts file, the first start (the
            counter, the incarnation entry and its sync mark), the CONNECT
            target saved;
  restore-other  the same import on a folder whose journal a restore (6.3
            step 0) has made again, so the backup has another file_id (the
            confirmation review of PR 54, N2);
  restore   on a wallet with a few starts, an older backup imported
            (--test-restore-from): the staged copy, restore.gzr, the rename,
            the mark file started again with the restore marker, the
            counter, the incarnation, the restore batch (an anchored batch:
            its mark-file entry and the guard file), the marker cleared.

After each kill the same folder is started with no hook (twice), and must:
start (a kill never makes a journal corrupt, behind or possibly old, nor a
wallet that cannot be opened); hold a journal whose incarnations rise and
whose batches are 1, 2, 3 ... within each; never say the start counter is
missing (a kill during set-up between the key file and the counter is told
in softer words, never hidden: storage 7.4, pending the storage reviewers),
and say "set-up may have been interrupted" only where no start was ever
made, still telling the person, the start still a restore with a new epoch (6.3 step 0;
review A of PR 54, H1); hold no set-up marker (setup.gzp) once started;
never save one key epoch under two incarnations across the folder's whole
history; in the restore life, be a restore
until the restore batch is durable and an ordinary start after it, with a
restore epoch other than 0; and stop cleanly.
"""
import os
import shutil
import sys
import time

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
    power = len(sys.argv) > 4 and sys.argv[4] == "power"
    name = "program_journal_powercut" if power else "program_journal_kill"
    hook = "--test-power-cut-at" if power else "--test-kill-at"
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
    # The other life's base: the journal and mark file removed, so the next
    # start is a restore with a new journal (another file_id), then a start.
    base_other = os.path.join(work, "base-other")
    shutil.copytree(base, base_other)
    for gone in ("journal.gzj", "mark.gzm"):
        os.unlink(os.path.join(base_other, gone))
    for i in range(2):
        m, p = run(base_other, name="base-other")
        p.wait_for(r"connect-kept")
        p.stop()
    check(m is not None and m.group(0).startswith("ready"), "the other restore life's base starts")

    totals = {}
    try:
        for life in ("set-up", "restore", "restore-other"):
            kills = restored_after = 0
            k = 0
            while True:
                k += step
                folder = os.path.join(work, "%s-%d" % (life, k))
                extra = []
                if life.startswith("restore"):
                    shutil.copytree(base if life == "restore" else base_other, folder)
                    extra = ["--test-restore-from", backup]
                m, p = run(folder, *(extra + [hook, str(k)]), name="kill-" + life)
                if m is None:
                    check(False, "%s K=%d: the run neither died nor started" % (life, k))
                    break
                if m.group(0).startswith("ready"):
                    # Started: its storage calls go on after the start (the
                    # CONNECT target's batch); the kill may still come.
                    m2 = p.wait_for(r"connect-kept|test-kill before=\S+", timeout=30)
                    if m2 is None or not m2.group(0).startswith("test-kill"):
                        time.sleep(0.5)
                        m2 = p.find(r"test-kill before=\S+")[1] or m2
                    if m2 is not None and m2.group(0).startswith("test-kill"):
                        m = m2
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
                started_before = life.startswith("restore") or p.find(r"ready incarnation=")[0] is not None
                history = {}  # key epoch -> the incarnations that saved it, across the folder's journals
                for again in (0, 1):
                    m2, q = run(folder, name="after-" + life)
                    ok = m2 is not None and m2.group(0).startswith("ready")
                    check(ok, "%s K=%d start %d after the kill: %s" % (life, k, again + 1, m2.group(0) if m2 else None))
                    restored = q.find(r"start steps=\d+ restored=1")[0] is not None
                    if ok:
                        check(q.find(r"start-counter state=missing")[0] is None,
                              "%s K=%d start %d: no false warning (the start counter is not missing)"
                              % (life, k, again + 1))
                        check(not os.path.exists(os.path.join(folder, "setup.gzp")),
                              "%s K=%d start %d: no set-up marker once started" % (life, k, again + 1))
                        if q.find(r"set-up may have been interrupted")[0] is not None:
                            check(q.find(r"set-up may have been interrupted.*the person is told")[0] is not None,
                                  "%s K=%d: the softer words still tell the person" % (life, k))
                            e0 = q.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
                            check(restored and e0 is not None and e0.group(1) != "00000000",
                                  "%s K=%d: an interrupted set-up is still a restore with a new epoch" % (life, k))
                            check(not started_before,
                                  "%s K=%d: 'set-up may have been interrupted' follows no earlier start" % (life, k))
                        check(q.find(r"setup-finished")[0] is None,
                              "%s K=%d start %d: never finished as a new wallet" % (life, k, again + 1))
                        started_before = True
                    if life.startswith("restore") and again == 0 and restored:
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
                    for e in entries:
                        if e[0] == "BTCH":
                            for t, b in e[3]:
                                if t == KEY_EPOCH:
                                    history.setdefault(b, set()).add(e[1])
                    twice = {b.hex(): sorted(v) for b, v in history.items() if len(v) > 1}
                    check(not twice, "%s K=%d start %d: no key epoch saved under two incarnations across the "
                          "folder's history %s" % (life, k, again + 1, twice))
                shutil.rmtree(folder, ignore_errors=True)
                for q in procs:
                    q.stop()
                procs[:] = []
            totals[life] = (kills, restored_after)
        check(totals.get("set-up", (0,))[0] >= 20 // step and totals.get("restore", (0,))[0] >= 20 // step,
              "killed at every storage call: %s (kills, starts that repeated the restore)" % totals)
    finally:
        kill_all(procs)
    return check.result(name, logs)


if __name__ == "__main__":
    sys.exit(main())
