#!/usr/bin/env python3
"""program_storage_damage: damaged files are refused, never half-applied (S5, S6).

    python3 -I storage_damage.py PATH_TO_GAZPACHO_TEST WORK_DIR

A member with a few incarnations and an anchored batch (its CONNECT target)
is copied, and each copy is damaged one way. For each, the start either
refuses with every file of the folder unchanged byte for byte (nothing
half-applied, nothing "repaired"), or goes on exactly as the specification
says:

  - a byte flipped in a batch before a sync mark: corruption, refused;
  - a byte flipped in the header: refused (not this wallet's journal);
  - the last entry cut in half (a torn tail): cut, and the start goes on;
  - mark.gzm removed, or a byte of it flipped: possibly old, files_behind;
  - guard.gzg removed, or damaged: possibly old, files_behind;
  - an older mark file put back... (a journal cut back to an older copy):
    behind, files_behind;
  (files_behind names which, behind or possibly_old: local-api.md's cause);
  - starts.gzs damaged or removed: treated as missing, the person told, the
    incarnation still above the journal's;
  - restore.gzr damaged: refused;
  - an older journal put back with a forged restore.gzr (review A of PR 54,
    M1: the marker is not authenticated): files_behind, every file unchanged
    (the mark file, the evidence, is not rewritten); restore.gzr is trusted
    only where the sealed mark file's newest entry is the restore marker.
"""
import hashlib
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, dump_journal, free_port, kill_all  # noqa: E402

check = Checks()
HOST_KEY = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def snapshot(folder):
    out = {}
    for n in sorted(os.listdir(folder)):
        p = os.path.join(folder, n)
        if os.path.isfile(p) and n not in ("lock", "attempts.gza"):
            out[n] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def flip(path, at):
    with open(path, "r+b") as f:
        size = f.seek(0, 2)
        at = at if at >= 0 else size + at
        f.seek(at)
        b = f.read(1)
        f.seek(at)
        f.write(bytes([b[0] ^ 0x40]))


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()
    procs = []
    runs = [0]
    base = os.path.join(work, "base")

    def start(folder, *extra):
        runs[0] += 1
        p = Proc("run-%d" % runs[0], [exe, "--data-dir", folder, "--role", "member", "--name", "m", "--no-chain",
                                      "--no-interface", "--reconnect-ms", "200",
                                      "--connect", "%s@127.0.0.1:%d" % (HOST_KEY, port)] + list(extra), logs)
        procs.append(p)
        return p

    def outcome(folder, *extra):
        """Start once: ("ready", incarnation, proc) or ("refused", why, proc)."""
        p = start(folder, *extra)
        m = p.wait_for(r"ready incarnation=(\d+)|unlock op=\w+ status=(?!ok\b)(\w+) .*reason=(\S+)|"
                       r"start-refused why=(\S+)", timeout=60)
        if m and m.group(0).startswith("ready"):
            p.wait_for(r"connect-kept", timeout=30)
            p.stop()
            return "ready", int(m.group(1)), p
        code = p.exit_code(timeout=30)
        why = (m.group(2) + ":" + m.group(3)) if m and m.group(2) else (m.group(4) if m else "none")
        return "refused", "%s exit=%s" % (why, code), p

    try:
        # The base: a start (its target saved), a backup, a start, the backup
        # imported (the restore batch is anchored: the mark file names it),
        # and a start after it.
        st, inc, _ = outcome(base)
        backup = os.path.join(work, "base-backup.gzj")
        shutil.copyfile(os.path.join(base, "journal.gzj"), backup)
        st, inc, _ = outcome(base)
        st, inc, p = outcome(base, "--test-restore-from", backup)
        check(st == "ready" and p.find(r"restore-batch seq=1 ")[0] is not None, "base: a restore, its batch anchored")
        st, inc, _ = outcome(base)
        check(st == "ready" and inc >= 4, "base: four starts (incarnation %s)" % inc)
        entries = dump_journal(base, exe)
        incs = [e[1] for e in entries if e[0] == "INCN"]
        jsize = os.path.getsize(os.path.join(base, "journal.gzj"))

        def case(name, damage, expect, why_part=None):
            folder = os.path.join(work, name)
            shutil.copytree(base, folder)
            damage(folder)
            before = snapshot(folder)
            st, info, _ = outcome(folder)
            if expect == "refused":
                check(st == "refused" and (why_part is None or why_part in info),
                      "%s: refused (%s)" % (name, info))
                after = snapshot(folder)
                check(after == before, "%s: every file unchanged by the refusal %s" %
                      (name, sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))))
            else:
                check(st == "ready" and info > max(incs), "%s: starts above incarnation %d (%s)" % (name, max(incs), info))
            return folder

        J = "journal.gzj"
        # A byte of the first batch's ciphertext (after the header, the first
        # incarnation entry (69) and its sync mark (69), inside the batch).
        case("journal-middle", lambda f: flip(os.path.join(f, J), 185 + 69 + 69 + 50), "refused", "storage_failed")
        case("journal-header", lambda f: flip(os.path.join(f, J), 100), "refused")
        case("journal-torn", lambda f: os.truncate(os.path.join(f, J), jsize - 30), "ready")
        case("mark-removed", lambda f: os.unlink(os.path.join(f, "mark.gzm")), "refused", "files_behind:possibly_old")
        case("mark-flipped", lambda f: flip(os.path.join(f, "mark.gzm"), 60), "refused", "files_behind:possibly_old")
        case("guard-removed", lambda f: os.unlink(os.path.join(f, "guard.gzg")), "refused", "files_behind:possibly_old")
        case("guard-flipped", lambda f: flip(os.path.join(f, "guard.gzg"), -5), "refused", "files_behind:possibly_old")

        def older_journal(f):
            # The journal of the first start, put back by hand: behind its mark file.
            shutil.copyfile(os.path.join(work, "first.gzj"), os.path.join(f, J))
        first = os.path.join(work, "first")
        st, _, _ = outcome(first)
        shutil.copyfile(os.path.join(first, J), os.path.join(work, "first.gzj"))
        shutil.rmtree(first)
        # Not the same wallet: a journal of another wallet is refused too.
        case("other-wallet-journal", older_journal, "refused")

        def cut_back(f):
            # This wallet's own journal cut back at an entry boundary before its
            # anchored batch's mark: the mark file names a mark it lacks.
            data = open(os.path.join(f, J), "rb").read()
            open(os.path.join(f, J), "wb").write(data[:185 + 69 + 69])
        case("journal-cut-back", cut_back, "refused", "files_behind:behind")

        def forged_marker(f):
            import hashlib
            import struct
            shutil.copyfile(backup, os.path.join(f, J))
            chain = open(os.path.join(f, J), "rb").read(41)[9:41]
            body = b"GZRESTO1" + chain + struct.pack(">QQ", 1000, 0)
            open(os.path.join(f, "restore.gzr"), "wb").write(body + hashlib.sha256(body).digest()[:8])
        case("old-journal-forged-marker", forged_marker, "refused", "files_behind")

        import struct

        def forged(f, base_inc, floor):
            chain = open(os.path.join(f, J), "rb").read(41)[9:41]
            body = b"GZRESTO1" + chain + struct.pack(">QQ", base_inc, floor)
            open(os.path.join(f, "restore.gzr"), "wb").write(body + hashlib.sha256(body).digest()[:8])

        # A refused import leaves the mark file as it was (confirmation review
        # of PR 54, N1; review B, L3): the backup is checked whole first.
        fi = os.path.join(work, "refused-import")
        shutil.copytree(base, fi)
        bad = os.path.join(work, "damaged-backup.gzj")
        shutil.copyfile(backup, bad)
        flip(bad, 185 + 69 + 69 + 50)
        mark_before = open(os.path.join(fi, "mark.gzm"), "rb").read()
        st, info, _ = outcome(fi, "--test-restore-from", bad)
        check(st == "refused", "refused-import: a damaged backup is refused (%s)" % (info,))
        check(open(os.path.join(fi, "mark.gzm"), "rb").read() == mark_before,
              "refused-import: mark.gzm unchanged by the refused import")

        # A forged restore.gzr floor is never used, and the file goes
        # (confirmation review, N3; review B, L1).
        ff = os.path.join(work, "forged-floor")
        shutil.copytree(base, ff)
        forged(ff, 1000, (1 << 63) - 2)  # base above the journal: unanswered
        st, inc, _ = outcome(ff)
        check(st == "ready" and inc < 1 << 32, "forged-floor: an ordinary start (%s %s)" % (st, inc))
        check(not os.path.exists(os.path.join(ff, "restore.gzr")), "forged-floor: the forged marker is removed")
        st, inc, _ = outcome(ff, "--test-restore-from", backup)
        check(st == "ready" and inc < 1 << 32, "forged-floor: a later import does not take the forged floor (%s)" % (inc,))

        # A forged floor beside a real import: the floor is never used
        # (review B of PR 54, L7: b_floor_trusted).
        fr = os.path.join(work, "forged-floor-import")
        shutil.copytree(base, fr)
        forged(fr, 1000, (1 << 63) - 2)
        st, inc, p = outcome(fr, "--test-restore-from", backup)
        check(st == "ready" and p.find(r"start steps=\d+ restored=1")[0] is not None and inc < 1 << 32,
              "forged-floor-import: a restore, its incarnation %s far below the forged floor" % (inc,))

        # An import of another file_id interrupted after its mark file (review
        # B of PR 54, R2-2): the start rule restarts the mark file for the
        # journal here and the start is a restore.
        b2 = os.path.join(work, "base-other")
        shutil.copytree(base, b2)
        for gone in ("journal.gzj", "mark.gzm"):
            os.unlink(os.path.join(b2, gone))
        outcome(b2)
        outcome(b2)
        found = None
        for k in range(1, 80):
            fk2 = os.path.join(work, "interrupted-import-%d" % k)
            shutil.copytree(b2, fk2)
            q = start(fk2, "--test-restore-from", backup, "--test-kill-at", str(k))
            km = q.wait_for(r"test-kill before=\S+|ready incarnation=", timeout=60)
            if km is not None and km.group(0).startswith("ready"):
                q.stop()
                break
            q.exit_code(timeout=30)
            mk = open(os.path.join(fk2, "mark.gzm"), "rb").read()
            jn = open(os.path.join(fk2, J), "rb").read(73)
            if mk[41:57] != jn[57:73]:
                found = fk2
                break
        check(found is not None, "interrupted-import: a kill leaves a mark file for another file_id")
        if found:
            st, inc, p = outcome(found)
            e2 = p.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
            check(st == "ready" and p.find(r"start steps=\d+ restored=1")[0] is not None and e2 is not None and
                  e2.group(1) != "00000000", "interrupted-import: a restore with a new epoch (%s %s)" % (st, inc))
            mk = open(os.path.join(found, "mark.gzm"), "rb").read()
            jn = open(os.path.join(found, J), "rb").read(73)
            check(mk[41:57] == jn[57:73], "interrupted-import: the mark file is started again for the journal here")

        # A current journal with a forged restore.gzr: an ordinary start, the
        # mark file not rewritten (review B of PR 54, L7).
        fc = os.path.join(work, "current-forged-marker")
        shutil.copytree(base, fc)
        forged(fc, 1000, 0)
        mark_before = open(os.path.join(fc, "mark.gzm"), "rb").read()
        st, inc, p = outcome(fc)
        check(st == "ready" and p.find(r"start steps=\d+ restored=0")[0] is not None,
              "current-forged-marker: an ordinary start (%s %s)" % (st, inc))
        check(open(os.path.join(fc, "mark.gzm"), "rb").read()[:len(mark_before)] == mark_before,
              "current-forged-marker: mark.gzm not rewritten")

        # An unreadable start counter (a directory of that name) refuses the
        # start: never taken as missing, which would lose its floor (L7).
        fu = os.path.join(work, "counter-unreadable")
        shutil.copytree(base, fu)
        os.unlink(os.path.join(fu, "starts.gzs"))
        os.mkdir(os.path.join(fu, "starts.gzs"))
        st, info, p = outcome(fu)
        check(st == "refused" and p.find(r"start-counter state=missing")[0] is None and
              p.find(r"cannot read the start counter")[0] is not None,
              "counter-unreadable: refused at its read, not taken as missing (%s)" % (info,))

        # The clock set back a day during a delay (storage 12.3): the delay
        # still holds, and never more than the 15-minute cap.
        import time as _t
        fa = os.path.join(work, "clock-back")
        shutil.copytree(base, fa)
        chain = open(os.path.join(fa, J), "rb").read(41)[9:41]
        now = int(_t.time())
        body = (b"GZTRIES1" + chain + struct.pack(">QIQQ", 9, 6, now + 86400, now + 86400 + 2) + bytes([1]))
        open(os.path.join(fa, "attempts.gza"), "wb").write(body + hashlib.sha256(body).digest()[:16])
        st, info, p = outcome(fa)
        ra = p.find(r"unlock op=\w+ status=busy .*retry_after_s=(\d+)")[1]
        check(st == "refused" and ra is not None and 1 <= int(ra.group(1)) <= 900,
              "clock-back: the delay holds, at most the 15-minute cap (%s)" % (ra.group(0) if ra else info))

        # A key file open to others is refused (storage 4.5; L7).
        fk = os.path.join(work, "keyfile-open")
        shutil.copytree(base, fk)
        os.chmod(os.path.join(fk, "keys.gzk"), 0o644)
        st, info, p = outcome(fk)
        check(st == "refused", "keyfile-open: a key file open to others is refused (%s)" % (info,))
        st, inc, _ = outcome(ff)
        check(st == "ready", "forged-floor: and the next start goes on (%s)" % (st,))

        f = case("counter-flipped", lambda f: flip(os.path.join(f, "starts.gzs"), -3), "ready")
        p = procs[-1]
        check(p.find(r"start-counter state=missing")[0] is not None and
              p.find(r"start-counter was missing: rewritten from the journal; the person is told once")[0] is not None,
              "counter-flipped: treated as missing, the person told")
        case("counter-removed", lambda f: os.unlink(os.path.join(f, "starts.gzs")), "ready")
        check(procs[-1].find(r"start-counter state=missing")[0] is not None, "counter-removed: missing, told")
        st, inc2, _ = outcome(f)
        check(st == "ready" and procs[-1].find(r"start-counter state=found")[0] is not None,
              "counter-flipped: written again, found at the next start")

        def bad_marker(f):
            with open(os.path.join(f, "restore.gzr"), "wb") as w:
                w.write(b"GZRESTO1" + b"\0" * 56)
        case("marker-damaged", bad_marker, "refused")
    finally:
        kill_all(procs)
    return check.result("program_storage_damage", logs)


if __name__ == "__main__":
    sys.exit(main())
