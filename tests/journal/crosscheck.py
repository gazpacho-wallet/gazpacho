"""Cross-check of the C journal reader against an independent one.

indep_reader.py was written from spec/journal.md alone, by someone who had
not seen the C code. This script builds random journals with its own encoder,
damages most of them, and compares, file by file, what `gz-journal verify`
decides with what indep_reader decides: the state, the cut point, the next
incarnation, and a digest of every kept batch and record in order.

    python3 crosscheck.py GZ_JOURNAL_BINARY [COUNT] [SEED]
"""
import hashlib
import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import indep_reader  # noqa: E402

SIGNET = bytes.fromhex("f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000")
MAINNET = bytes.fromhex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
TYPES = [0x7E570001, 0x7E570002, 0x00020006, 0x00010006, 0x0004000A, 0x00030004,
         0x00050001, 0x7FFF0003]          # the last two: unknown odd
RARE = [0x00050002, 0x00040008]           # unknown even


def sha8(b):
    return hashlib.sha256(b).digest()[:8]


def entry(kind, inc, seq, payload):
    body = struct.pack(">IBQQ", 17 + len(payload), kind, inc, seq) + payload
    return body + sha8(body)


def header(chain=SIGNET):
    h = b"GZJOURNL" + chain
    return h + sha8(h)


def gen(rng):
    """A valid journal, as the writer would leave it (possibly with unmarked batches)."""
    d = bytearray(header())
    inc = 0
    for _ in range(rng.randint(0, 4)):
        inc += rng.choice([1, 1, 1, 2, 7])
        d += entry(1, inc, 0, struct.pack(">Q", rng.getrandbits(40)))
        d += entry(3, inc, 0, struct.pack(">Q", len(d)))
        seq = 0
        for _ in range(rng.randint(0, 5)):
            recs = []
            for _ in range(rng.randint(0, 3)):
                t = rng.choice(TYPES) if rng.random() > 0.02 else rng.choice(RARE)
                recs.append((t, rng.randbytes(rng.randint(0, 30))))
            seq += 1
            payload = struct.pack(">I", len(recs)) + b"".join(
                struct.pack(">II", t, len(b)) + b for t, b in recs)
            d += entry(2, inc, seq, payload)
            if rng.random() < 0.6:
                d += entry(3, inc, 0, struct.pack(">Q", len(d)))
    return d


def damage(rng, d):
    k = rng.randrange(12)
    if k <= 1 or len(d) <= 48:
        return d
    at = rng.randrange(len(d))
    if k == 2:
        d[at] ^= 1 << rng.randrange(8)
    elif k == 3:
        return d[:at]
    elif k == 4:
        return d + bytes(rng.randint(1, 50))
    elif k == 5:
        return d + rng.randbytes(rng.randint(1, 50))
    elif k == 6:                       # a well-formed entry that breaks an order rule
        inc = rng.choice([0, 1, 2, 3, 50])
        d += rng.choice([entry(1, inc, 0, bytes(8)), entry(2, inc, rng.randint(0, 4), bytes(4)),
                         entry(3, inc, 0, struct.pack(">Q", len(d))), entry(1, inc, 5, bytes(8))])
    elif k == 7:                       # a mark naming another offset
        d += entry(3, 1, 0, struct.pack(">Q", len(d) + rng.choice([-1, 1, 37])))
    elif k == 8:                       # damage, then a valid mark: corruption if before it
        d[at] ^= 0x80
        d += entry(3, 1, 0, struct.pack(">Q", len(d)))
    elif k == 9:
        d = d[:at] + rng.randbytes(rng.randint(1, 9)) + d[at:]
    elif k == 10:
        return bytearray(header(MAINNET)) + d[48:]
    else:
        a, b = sorted((rng.randrange(len(d)), rng.randrange(len(d))))
        d += d[a:b]
    return d


def digest(res):
    out, recs = bytearray(), iter(res["records"])
    for inc, seq, kept in res["batches"]:
        out += struct.pack(">QQI", inc, seq, kept)
        for _ in range(kept):
            t, b = next(recs)
            out += struct.pack(">II", t, len(b)) + b
    return hashlib.sha256(bytes(out)).hexdigest()


def main():
    binary = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    states, mismatches = {}, 0
    with tempfile.TemporaryDirectory() as tmp:
        names, expect = [], {}
        for i in range(count):
            d = damage(rng, gen(rng))
            name = os.path.join(tmp, "j%05d" % i)
            with open(name, "wb") as f:
                f.write(d)
            r = indep_reader.read(bytes(d), SIGNET)
            want = [r["state"], "-" if r["cut_to"] is None else str(r["cut_to"]),
                    "-" if r["next_incarnation"] is None else str(r["next_incarnation"]),
                    digest(r) if r["records"] is not None else "-"]
            names.append(name)
            expect[name] = want
            states[r["state"]] = states.get(r["state"], 0) + 1
        out = subprocess.run([binary, "verify", "-"], input="\n".join(names) + "\n",
                             capture_output=True, text=True).stdout.splitlines()
        if len(out) != count:
            print("FAIL: %d lines for %d files" % (len(out), count))
            return 1
        for line in out:
            f = line.split()
            if f[1:] != expect[f[0]]:
                mismatches += 1
                if mismatches <= 10:
                    print("MISMATCH %s: C %s, independent %s" % (os.path.basename(f[0]), f[1:], expect[f[0]]))
    print("cross-check: %d journals, states %s, %d mismatches" % (count, dict(sorted(states.items())), mismatches))
    missing = {"clean", "torn", "corrupt", "order", "bad_header", "unknown_record"} - set(states)
    if missing:
        print("FAIL: never produced %s" % sorted(missing))
        return 1
    print("RESULT: %s" % ("PASS" if mismatches == 0 else "FAIL"))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
