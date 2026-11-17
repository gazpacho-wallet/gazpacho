#!/usr/bin/env python3
"""program_journal_restore: restores from older backups (S5, S6, P9).

    python3 -I journal_restore.py PATH_TO_GAZPACHO_TEST WORK_DIR

On the sealed journal, with the sealed start counter (starts.gzs), the mark
file, the sealed guard file and the restore marker (journal.md 8.2, 8.3;
storage 6.3; contract-v2.md section 8; composite-node.md and safety-rule.md
section 9's R2 and R7):

1. A member saves its CONNECT target (a key index pair, a guard record) at
   its first start; its journal is copied aside (the oldest backup). It is
   started again three times.
2. The oldest backup is imported four times in a row (--test-restore-from),
   each time on the device's newest files. Every restored start: is a
   restore (restored=1), saves the restore batch first with a new epoch,
   never 0 and never one used before; its incarnation is above every
   incarnation the device used; its guard counter is above the device's;
   and no (epoch, key index) pair is ever saved twice across every journal
   the folder had. The device's epochs stay in the guard (the union).
3. A journal put back by hand (no import) is behind its mark file: refused,
   files behind, nothing written.
4. The journal removed alone: the key file with no journal starts as a
   restore (storage 6.3 step 0) with a new epoch, the guard carried on.
5. starts.gzs removed before an import: the restore goes ahead from the
   journal alone and the person is told (counter missing).
"""
import os
import re
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, dump_journal, free_port, kill_all  # noqa: E402

check = Checks()
HOST_KEY = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
KEY_EPOCH, KEY_INDEX, GUARD = 0x00040002, 0x00040004, 0x0004000a


def tlv_find(b, t):
    """Record field `t` of a TLV record (bigsize types and lengths), or None."""
    p = 0

    def big(p):
        v = b[p]
        if v < 0xfd:
            return v, p + 1
        n = {0xfd: 2, 0xfe: 4, 0xff: 8}[v]
        return int.from_bytes(b[p + 1:p + 1 + n], "big"), p + 1 + n
    while p < len(b):
        ty, p = big(p)
        ln, p = big(p)
        if ty == t:
            return b[p:p + ln]
        p += ln
    return None


def guard_counter(b):
    return struct.unpack(">Q", b[40:48])[0]


def guard_epochs(b):
    n = struct.unpack(">H", b[48:50])[0]
    return [struct.unpack(">I", b[50 + 8 * i:54 + 8 * i])[0] for i in range(n)]


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    port = free_port()
    procs = []
    runs = [0]
    folder = os.path.join(work, "member")
    seen_pairs = []      # every key_index record ever saved, across every journal
    seen_epochs = set()  # every key_epoch ever saved
    max_inc = [0]
    max_guard = [0]

    def run(*extra):
        runs[0] += 1
        p = Proc("run-%d" % runs[0], [exe, "--data-dir", folder, "--role", "member", "--name", "m", "--no-chain",
                                      "--no-interface", "--reconnect-ms", "200",
                                      "--connect", "%s@127.0.0.1:%d" % (HOST_KEY, port)] + list(extra), logs)
        procs.append(p)
        m = p.wait_for(r"ready incarnation=(\d+)|unlock op=\w+ status=(?!ok)\w+.*|start-refused.*", timeout=60)
        if not m or not m.group(0).startswith("ready"):
            p.exit_code(timeout=30)
            return p, None
        p.wait_for(r"connect-kept", timeout=30)
        p.stop()
        return p, int(m.group(1))

    def take(entries):
        """New key epochs, key indexes and guards of this journal: (epochs, pairs, guards)."""
        eps, pairs, guards = [], [], []
        for e in entries:
            if e[0] != "BTCH":
                continue
            for t, b in e[3]:
                if t == KEY_EPOCH:
                    eps.append(tlv_find(b, 2) or b)  # the epoch, record 2 (u32)
                elif t == KEY_INDEX:
                    pairs.append(b)
                elif t == GUARD:
                    guards.append(b)
        return eps, pairs, guards

    def note(entries, what):
        eps, pairs, guards = take(entries)
        new_pairs = [x for x in pairs if x not in seen_pairs]
        for x in new_pairs:
            seen_pairs.append(x)
        for x in eps:
            seen_epochs.add(x)
        incs = [e[1] for e in entries if e[0] == "INCN"]
        if incs:
            max_inc[0] = max(max_inc[0], max(incs))
        if guards:
            max_guard[0] = max(max_guard[0], guard_counter(guards[-1]))
        return eps, pairs, guards

    try:
        # 1. The first start, the oldest backup, three more starts.
        p, inc = run()
        check(inc is not None, "1: the first start")
        backup = os.path.join(work, "oldest.gzj")
        shutil.copyfile(os.path.join(folder, "journal.gzj"), backup)
        note(dump_journal(folder, exe), "first")
        for _ in range(3):
            p, inc = run()
        note(dump_journal(folder, exe), "device")
        check(inc is not None and inc >= 4, "1: three more starts (incarnation %s)" % inc)

        # 2. The oldest backup imported four times in a row.
        for r in range(1, 5):
            before_inc, before_guard, before_epochs = max_inc[0], max_guard[0], set(seen_epochs)
            p, inc = run("--test-restore-from", backup)
            check(inc is not None and inc > before_inc,
                  "2.%d: the restored start's incarnation %s is above every one used (%d)" % (r, inc, before_inc))
            check(p.find(r"start steps=\d+ restored=1")[0] is not None, "2.%d: a restored start" % r)
            m = p.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
            epoch = bytes.fromhex(m.group(1)) if m else None
            check(epoch is not None and epoch != b"\0\0\0\0" and epoch not in before_epochs,
                  "2.%d: the restore batch is sequence 1 with a new epoch %s" % (r, m.group(1) if m else None))
            g = p.find(r"restore-guard chain=\S+ counter=(\d+)")[1]
            check(g is not None and int(g.group(1)) > before_guard,
                  "2.%d: the guard counter %s is above the device's %d" % (r, g.group(1) if g else None, before_guard))
            entries = dump_journal(folder, exe)
            eps, pairs, guards = take(entries)
            dup = [x.hex() for x in pairs if pairs.count(x) > 1]
            check(not dup, "2.%d: no key index record twice in the journal" % r)
            ge = guard_epochs(guards[-1]) if guards else []
            old = [struct.unpack(">I", e)[0] for e in before_epochs]
            check(all(e in ge for e in old[-15:]) and struct.unpack(">I", epoch)[0] in ge if epoch else False,
                  "2.%d: the guard keeps the device's epochs and the new one: %s" % (r, ge))
            note(entries, "restored")
            # The restored node saves its target again under the new epoch:
            # a pair never seen before (the epoch is in it).
            check(len(seen_pairs) == len(set(seen_pairs)), "2.%d: no (epoch, index) pair reused" % r)
            p2, inc2 = run()
            check(inc2 is not None and p2.find(r"start steps=\d+ restored=0")[0] is not None,
                  "2.%d: the next start is an ordinary one" % r)
            note(dump_journal(folder, exe), "after")

        # 3. A journal put back by hand is behind its mark file.
        f3 = folder
        saved = os.path.join(work, "newest.gzj")
        shutil.copyfile(os.path.join(f3, "journal.gzj"), saved)
        shutil.copyfile(backup, os.path.join(f3, "journal.gzj"))
        before = open(os.path.join(f3, "journal.gzj"), "rb").read()
        p, inc = run()
        check(inc is None and p.find(r"status=files_behind")[0] is not None, "3: a journal put back by hand: files behind")
        check(open(os.path.join(f3, "journal.gzj"), "rb").read() == before, "3: nothing written to it")
        shutil.copyfile(saved, os.path.join(f3, "journal.gzj"))
        p, inc = run()
        check(inc is not None, "3: the newer journal put back starts")
        note(dump_journal(folder, exe), "back")

        # 4. The journal removed alone: step 0, a restore with the guard carried.
        before_epochs, before_guard = set(seen_epochs), max_guard[0]
        os.unlink(os.path.join(folder, "journal.gzj"))
        p, inc = run()
        m = p.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
        check(inc is not None and m is not None and bytes.fromhex(m.group(1)) not in before_epochs and
              m.group(1) != "00000000", "4: no journal: a restore with a new epoch (%s)" % (m.group(1) if m else None))
        g = p.find(r"restore-guard chain=\S+ counter=(\d+)")[1]
        check(g is not None and int(g.group(1)) > before_guard, "4: the guard carried on (counter %s > %d)" %
              (g.group(1) if g else None, before_guard))
        note(dump_journal(folder, exe), "step0")

        # 5. starts.gzs removed before an import: the person is told.
        os.unlink(os.path.join(folder, "starts.gzs"))
        p, inc = run("--test-restore-from", backup)
        check(inc is not None and p.find(r"restore counter_found=0: the person is told")[0] is not None,
              "5: a restore without its counter goes ahead from the journal alone; the person is told")
        m = p.find(r"restore-batch seq=1 epoch=([0-9a-f]{8})")[1]
        check(m is not None and bytes.fromhex(m.group(1)) not in seen_epochs, "5: still a new epoch")
    finally:
        kill_all(procs)
    return check.result("program_journal_restore", logs)


if __name__ == "__main__":
    sys.exit(main())
