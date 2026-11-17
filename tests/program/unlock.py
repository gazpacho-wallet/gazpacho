#!/usr/bin/env python3
"""program_unlock: the start order and the passphrase layer (S6; unlock.h).

    python3 -I unlock.py PATH_TO_GAZPACHO_TEST WORK_DIR

1. A new folder comes up with no wallet; the passphrase file sets it up
   (keys.gzk, guard.gzg, mark.gzm, starts.gzs, attempts.gza, journal.gzj),
   and only after the unlock does the node start and the host listen
   ("wallet state" before "ready" before "listening"). Nothing of the old
   stand-in key files is made. The passphrase is in no output line, in no
   file of the folder and on no command line.
2. Wrong passphrases are counted (storage 12.3, local-api.md 4.3): one try a
   second, five free, then the delay doubles; a try inside the delay is
   refused before any derivation and not counted; the right passphrase
   after the delay opens the wallet and clears the count.
3. A missing attempts file is the strictest state: refused for 15 minutes.
4. A damaged key file reads as a wrong passphrase (4.5) and opens nothing.
5. The release program, without the local interface, stays locked: no
   journal is made, nothing listens, it stops on SIGTERM.
"""
import os
import re
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, TEST_PASSPHRASE, can_connect, free_port, kill_all  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    release = sys.argv[3] if len(sys.argv) > 3 else None
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    folder = os.path.join(work, "host")
    wrong = os.path.join(work, "wrong-pass")
    with open(wrong, "w") as f:
        f.write("not the passphrase of this wallet at all")
    os.chmod(wrong, 0o600)
    procs = []
    runs = [0]

    def start(*extra, name="host"):
        runs[0] += 1
        port = free_port()
        p = Proc("%s-%d" % (name, runs[0]), [exe, "--data-dir", folder, "--role", "host", "--name", "h",
                                            "--listen", "127.0.0.1:%d" % port, "--no-chain", "--no-interface"]
                 + list(extra), logs)
        procs.append(p)
        return p, port

    def attempt(passfile):
        """One start with this passphrase file: (exit code or None if it started, result line)."""
        p, _ = start("--test-passphrase-file", passfile, "--test-kdf-floor")
        m = p.wait_for(r"unlock op=\w+ status=(\w+) wrong_in_row=(\d+) attempts_left=(\d+) retry_after_s=(\d+)")
        if m and m.group(1) == "ok":
            p.wait_for(r"ready incarnation=")
            p.stop()
            return None, m
        return p.exit_code(timeout=30), m

    try:
        # 1. Set-up, the start order, no stand-in key files, the passphrase nowhere.
        p, port = start()
        i_state = p.index_of(r"wallet state=none")
        i_ok = p.index_of(r"unlock op=create status=ok")
        i_ready = p.index_of(r"ready incarnation=")
        i_listen = p.index_of(r"listening address=")
        check(None not in (i_state, i_ok, i_ready, i_listen) and i_state < i_ok < i_ready < i_listen,
              "1: no wallet, then set-up, then the node, then listening")
        check(can_connect(port), "1: the host listens once unlocked")
        cmdline = open("/proc/%d/cmdline" % p.p.pid, "rb").read()
        check(TEST_PASSPHRASE.encode() not in cmdline, "1: the passphrase is not on the command line")
        p.stop()
        files = sorted(os.listdir(folder))
        for f in ("keys.gzk", "guard.gzg", "mark.gzm", "starts.gzs", "attempts.gza", "journal.gzj"):
            check(f in files, "1: set-up made " + f)
        for f in ("transport.key", "wallet-seed.standin", "journal.standin", "starts.standin"):
            check(f not in files, "1: no stand-in file " + f)
        leaked = [f for f in files if TEST_PASSPHRASE.encode() in open(os.path.join(folder, f), "rb").read()]
        check(not leaked, "1: the passphrase is in no file of the folder %s" % leaked)
        out = "".join(open(os.path.join(logs, n)).read() for n in os.listdir(logs))
        check(TEST_PASSPHRASE not in out, "1: the passphrase is in no output line")
        for f in ("keys.gzk", "guard.gzg", "mark.gzm", "starts.gzs", "journal.gzj"):
            check(os.stat(os.path.join(folder, f)).st_mode & 0o077 == 0, "1: %s closed to others" % f)

        # 2. Wrong passphrases: counted, then delayed; one inside the delay is not counted.
        # Each try at once after the last: one that comes inside the delay is
        # busy and leaves the count alone; one after it (a slow start, under
        # a sanitizer, can outlast a 1 s delay) is counted. Until seven are
        # counted, so that a 4 s delay certainly catches a try inside it.
        seen, prev, busy, steps = [], 0, 0, 0
        while prev < 7 and steps < 40:
            steps += 1
            code, m = attempt(wrong)
            if not check(code == 8 and m is not None, "2: try %d refused (%s)" % (steps, m.group(0) if m else None)):
                break
            st, n = m.group(1), int(m.group(2))
            if st == "busy":
                busy += 1
                check(n == prev, "2: a try inside the delay is refused and not counted (%s)" % m.group(0))
                time.sleep(int(m.group(4)) + 0.2)
            else:
                check(st == "wrong" and n == prev + 1, "2: wrong passphrase %d counted (%s)" % (prev + 1, m.group(0)))
                seen.append((int(m.group(3)), int(m.group(4))))
                prev = n
        check(busy >= 1, "2: %d tries inside the delay, each refused and not counted" % busy)
        check([a for a, _ in seen] == [4, 3, 2, 1, 0, 0, 0], "2: attempts left 4, 3, 2, 1, 0, 0, 0: %s" % seen)
        check(len(seen) == 7 and seen[4][1] >= 1 and seen[5][1] >= 2 * seen[4][1] and seen[6][1] >= 2 * seen[5][1],
              "2: past five the delay doubles: %s" % seen)
        time.sleep((seen[-1][1] if seen else 1) + 0.2)
        code, m = attempt(_pass_file())
        check(code is None and m and m.group(1) == "ok", "2: the right passphrase opens the wallet after the delay")
        code, m = attempt(wrong)
        check(code == 8 and m and m.group(1) == "wrong" and int(m.group(2)) == 1,
              "2: the count starts again after a right one (%s)" % (m.group(0) if m else None))
        time.sleep(1.2)

        # 3. A missing attempts file is the strictest state.
        os.unlink(os.path.join(folder, "attempts.gza"))
        code, m = attempt(_pass_file())
        check(code == 8 and m and m.group(1) == "busy" and int(m.group(4)) >= 890,
              "3: a missing attempts file refuses for 15 minutes (%s)" % (m.group(0) if m else None))

        # 4. A damaged key file opens nothing (a fresh folder, set up again).
        shutil.rmtree(folder)
        code, m = attempt(_pass_file())
        check(code is None, "4: a new wallet is set up")
        kf = os.path.join(folder, "keys.gzk")
        with open(kf, "r+b") as f:
            f.seek(300)
            b = f.read(1)
            f.seek(300)
            f.write(bytes([b[0] ^ 1]))
        time.sleep(1.1)
        code, m = attempt(_pass_file())
        check(code == 8 and m and m.group(1) in ("wrong", "storage_failed"),
              "4: a damaged key file is refused (%s)" % (m.group(0) if m else None))
        check(not os.path.exists(os.path.join(folder, "restore.gzr")), "4: nothing written by the refusal")

        # 6. Reveal and the words check (storage 9.2): statuses only, never a word.
        shutil.rmtree(folder)
        p, _ = start("--test-passphrase-file", _pass_file(), "--test-kdf-floor", "--test-reveal-check")
        ok = p.wait_for(r"test-reveal wrong status=(\w+) words=(\d+)", timeout=60)
        check(p.find(r"test-reveal status=ok words=24")[0] is not None, "6: the 24 words are revealed")
        check(p.find(r"test-words-check right status=ok")[0] is not None, "6: three right words at their positions: ok")
        check(p.find(r"test-words-check changed status=words_differ")[0] is not None,
              "6: one word changed: words_differ")
        check(ok is not None and ok.group(1) == "wrong" and ok.group(2) == "0",
              "6: a wrong passphrase reveals nothing and is counted wrong")
        p.stop()

        # 7. seed() (unlock.h, for P8): -1 while locked with the buffer untouched,
        #    0 and the seed once unlocked, -2 with the buffer wiped on a storage
        #    fault; and no line holds a seed's 128 hex digits.
        time.sleep(1.2)
        p, _ = start("--test-passphrase-file", _pass_file(), "--test-kdf-floor", "--test-seed-check")
        f = p.wait_for(r"test-seed fault rc=(-?\d+) wiped=(\d)", timeout=60)
        lk = p.find(r"test-seed locked rc=(-?\d+) untouched=(\d)")[1]
        ul = p.find(r"test-seed unlocked rc=(-?\d+) filled=(\d)")[1]
        check(lk is not None and lk.group(1) == "-1" and lk.group(2) == "1", "7: locked: -1, the buffer untouched")
        check(ul is not None and ul.group(1) == "0" and ul.group(2) == "1", "7: unlocked: 0 and the seed")
        check(f is not None and f.group(1) == "-2" and f.group(2) == "1", "7: a storage fault: -2, the buffer wiped")
        p.stop()
        out = "".join(open(os.path.join(logs, n)).read() for n in os.listdir(logs))
        check(re.search(r"[0-9a-f]{128}", out) is None, "7: no output line holds 64 bytes in hex")

        # 5. The release program stays locked without the local interface.
        if release:
            rfolder = os.path.join(work, "release")
            rport = free_port()
            r = Proc("release", [release, "--data-dir", rfolder, "--role", "host", "--name", "r",
                                 "--listen", "127.0.0.1:%d" % rport, "--no-chain", "--no-interface"], logs)
            procs.append(r)
            check(r.wait_for(r"locked: waiting for the local interface") is not None, "5: release comes up locked")
            time.sleep(0.5)
            check(not can_connect(rport), "5: nothing listens while locked")
            check(not os.path.exists(os.path.join(rfolder, "journal.gzj")), "5: no journal while locked")
            r.stop()
            check(r.exit_code() == 0, "5: SIGTERM stops a locked program")
    finally:
        kill_all(procs)
    return check.result("program_unlock", logs)


def _pass_file():
    from gzp_harness import passphrase_file
    return passphrase_file()


if __name__ == "__main__":
    sys.exit(main())
