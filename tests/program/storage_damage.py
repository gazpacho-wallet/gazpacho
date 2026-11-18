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
