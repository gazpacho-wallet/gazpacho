#!/usr/bin/env python3
"""The signer's test vectors, computed independently of the C code.

    python3 -I tools/signer-vectors.py            print the vectors
    python3 -I tools/signer-vectors.py --check F  exit 1 unless F holds exactly them

Pure Python (hashlib and hmac only): BIP 32 hardened derivation, BIP 340
signing with the all-zero aux_rand, the envelope hash of messages.md 4.3 and
the spend-back's fee cap of docs/notes/signer.md 2.3, and the kinds that
spec/messages.md gives a signature (record 240), by sender: the C test takes
its expected kind table from these, never from the code. The primitives are
first checked against BIP 32's and BIP 340's own published vectors. The C
test (signer/tests/test_signer.c) reads signer/tests/vectors.txt and
compares libsecp256k1's results with these.

The seed is the 64 bytes 00 01 ... 3f: a test value, never for coins, with
no recovery phrase.
"""
import hashlib
import hmac
import os
import re
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HARD = 0x80000000
PURPOSE = 254315617
TESTNET4, SIGNET, REGTEST = 1, 2, 4   # PR #53's network levels
MESSAGES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "messages.md")


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def compressed(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def bip32_master(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    assert 0 < k < N
    return k, i[32:]


def bip32_hardened(path, seed):
    k, c = bip32_master(seed)
    for step in path:
        i = hmac.new(c, b"\0" + k.to_bytes(32, "big") + (step | HARD).to_bytes(4, "big"), hashlib.sha512).digest()
        il = int.from_bytes(i[:32], "big")
        assert il < N
        k, c = (il + k) % N, i[32:]
        assert k
    return k


def schnorr_sign(msg, d0, aux):
    pt = mul(d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    px = pt[0].to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + px + msg), "big") % N
    assert k0
    r = mul(k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(tagged("BIP0340/challenge", rx + px + msg), "big") % N
    return rx + ((k + e * d) % N).to_bytes(32, "big")


def envelope_hash(kind, scope, records):
    return tagged("gazpacho/msg", bytes.fromhex("677a6601") + kind.to_bytes(2, "big") + scope + records)


def fee(rate, vsize):
    return (rate * vsize + 999) // 1000


FEERATE_HARD_MAX = 5000      # sat/kvB: the most a signer's ceiling may be (GZ_SG_FEERATE_HARD_MAX)
U64 = 2**64 - 1


def fee_cap(plan_fee, plan_vsize, sb_vsize, ceiling):
    """signer.md 2.3; 0 (refuse every fee) for any input out of range."""
    if not (0 < plan_vsize <= 4000000 and 0 < sb_vsize <= 4000000 and ceiling <= FEERATE_HARD_MAX
            and plan_fee <= 2100000000000000 and plan_fee <= U64 // sb_vsize):
        return 0
    top = plan_fee + fee(1000, sb_vsize)
    top = max(top, plan_fee * sb_vsize // plan_vsize + 1)
    return max(fee(ceiling, sb_vsize), top)


def signed_kinds(path):
    """{"host": [...], "member": [...]}: the kinds spec/messages.md gives a record 240, by sender."""
    kinds = {"host": set(), "member": set()}
    section = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^### [67]\.\d+ `[a-z_]+` \((\d+)\), (host → member|member → host|either way)", line)
            if m:
                section = (int(m.group(1)), m.group(2))
                continue
            if line.startswith("#"):
                section = None
                continue
            if section and re.match(r"^\| 240 \| `sig` \|", line):
                kind, who = section
                if who in ("host → member", "either way"):
                    kinds["host"].add(kind)
                if who in ("member → host", "either way"):
                    kinds["member"].add(kind)
    return {k: sorted(v) for k, v in kinds.items()}


def self_check():
    # BIP 32 test vector 1: m and m/0H of seed 000102...0f
    seed = bytes(range(16))
    assert bip32_master(seed)[0] == int("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", 16)
    assert bip32_hardened([0], seed) == int("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", 16)
    # BIP 340 test vectors 0 and 1
    assert schnorr_sign(bytes(32), 3, bytes(32)).hex().upper() == (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assert schnorr_sign(bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                        int("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16),
                        bytes(31) + b"\x01").hex().upper() == (
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A")


def vectors():
    kinds = signed_kinds(MESSAGES)
    assert kinds["host"] and kinds["member"], "no signed kinds found in spec/messages.md"
    seed = bytes(range(64))
    scope = bytes(range(0x40, 0x60))
    records = bytes.fromhex("0203616263" "0501ff")
    host = bip32_hardened([PURPOSE, SIGNET, 1, 0], seed)
    # a member's first two pairs as the node part allocates them: (1, 2) and (3, 4)
    contribution = bip32_hardened([PURPOSE, SIGNET, 0, 7, 1], seed)
    factory = bip32_hardened([PURPOSE, SIGNET, 0, 7, 2], seed)
    contribution2 = bip32_hardened([PURPOSE, SIGNET, 0, 7, 3], seed)
    factory2 = bip32_hardened([PURPOSE, SIGNET, 0, 7, 4], seed)
    host_factory = bip32_hardened([PURPOSE, SIGNET, 2, 7, 2], seed)
    out = [
        ("seed", seed.hex()),
        ("scope", scope.hex()),
        ("records", records.hex()),
        ("signed_kinds_host", ",".join(str(k) for k in kinds["host"])),
        ("signed_kinds_member", ",".join(str(k) for k in kinds["member"])),
        ("host_pub", compressed(mul(host)).hex()),
        ("host_pub_testnet4", compressed(mul(bip32_hardened([PURPOSE, TESTNET4, 1, 0], seed))).hex()),
        ("host_pub_regtest", compressed(mul(bip32_hardened([PURPOSE, REGTEST, 1, 0], seed))).hex()),
        ("member_contribution_pub", compressed(mul(contribution)).hex()),
        ("member_factory_pub", compressed(mul(factory)).hex()),
        ("member_contribution_pub_2", compressed(mul(contribution2)).hex()),
        ("member_factory_pub_2", compressed(mul(factory2)).hex()),
        ("host_factory_pub", compressed(mul(host_factory)).hex()),
    ]
    h72 = envelope_hash(72, scope, records)
    h78 = envelope_hash(78, scope, b"")
    h22 = envelope_hash(22, scope, records)
    out += [
        ("msg_hash_72", h72.hex()),
        ("host_sig_72", schnorr_sign(h72, host, bytes(32)).hex()),
        ("msg_hash_78_empty", h78.hex()),
        ("host_sig_78_empty", schnorr_sign(h78, host, bytes(32)).hex()),
        ("msg_hash_22", h22.hex()),
    ]
    # plan fee, plan vsize, spend-back vsize, ceiling (sat/kvB) -> cap; 0 refuses every fee
    for case in ((16, 154, 111, 1000), (16, 154, 111, 100), (2000, 154, 111, 1000), (16, 154, 111, 5000),
                 (1, 400, 111, 0), (100000, 100, 300, 0), (1, 400, 111, 4999),
                 (2100000000000000, 154, 111, 1000), (16, 154, 111, 5001), (16, 0, 111, 1000)):
        out.append(("fee_cap_%d_%d_%d_%d" % case, str(fee_cap(*case))))
    return out


def main(argv):
    self_check()
    text = "".join("%s %s\n" % kv for kv in vectors())
    if argv[:1] == ["--check"]:
        with open(argv[1], encoding="utf-8") as f:
            have = "".join(l for l in f if l.strip() and not l.startswith("#"))
        if have != text:
            sys.stdout.write("signer vectors differ from %s; expected:\n%s" % (argv[1], text))
            return 1
        print("signer vectors: %d match" % len(text.splitlines()))
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
