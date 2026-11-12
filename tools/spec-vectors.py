#!/usr/bin/env python3
"""Compute the test vectors printed in spec/terms.md, spec/messages.md,
spec/journal.md, spec/discovery.md, (section E) spec/storage-encryption.md and
(section X, deadline arithmetic) spec/exit.md.
Factory messages use the native type 52791; vector M3 shows the same bytes
through the bLIP-56 adapter (open PR lightning/blips#56).

    python -I tools/spec-vectors.py           # everything except E2r
    python -I tools/spec-vectors.py --slow    # also recomputes E2r: Argon2id at 256 MiB, about 30 minutes

Standard library only. Run it again whenever one of those encodings changes,
and paste the new output into the specification.

Changed after review 3 (docs/reviews/spec-review-3.md): the shape table carries the
leaf kind (F1), T1 uses one-member pseudo-Spilman shapes and a short Slice 1
life, so T1 to T6, M1 and M3 changed; the split and funding rules of terms.md
section 4 are checked here against the build-server run; the journal has sync
marks (F2), so J4 changed and J5 and J6 are new. J1 to J3 and M2 are unchanged.

THE KEYS HERE ARE TEST KEYS. They are derived from public strings, so anyone
can recompute them. Never use them for coins.

The BIP 340 code below follows the reference implementation in BIP 340 and is
checked against its first official test vector before anything is printed.
It is NOT constant time and is for vectors only.
"""
import hashlib

# ---------------------------------------------------------------- BIP 340 ---
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def point_mul(p, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = point_add(r, p)
        p = point_add(p, p)
    return r


def xonly(sk: int) -> bytes:
    return point_mul(G, sk)[0].to_bytes(32, "big")


def compressed(sk: int) -> bytes:
    pt = point_mul(G, sk)
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y & 1 == 0 else P - y)


def schnorr_sign(msg: bytes, sk: int, aux: bytes) -> bytes:
    pt = point_mul(G, sk)
    d = sk if pt[1] % 2 == 0 else N - sk
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + pt[0].to_bytes(32, "big") + msg), "big") % N
    assert k0 != 0
    r = point_mul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   r[0].to_bytes(32, "big") + pt[0].to_bytes(32, "big") + msg), "big") % N
    sig = r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
    assert schnorr_verify(msg, pt[0].to_bytes(32, "big"), sig)
    return sig


def schnorr_verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    pt = lift_x(int.from_bytes(pub, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    rr = point_add(point_mul(G, s), point_mul(pt, N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


# BIP 340 official test vector 0.
_v0 = schnorr_sign(bytes(32), 3, bytes(32))
assert xonly(3).hex().upper() == "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
assert _v0.hex().upper() == ("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                            "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

# ------------------------------------------------------------- encodings ---


def bigsize(x: int) -> bytes:
    if x < 0xfd:
        return bytes([x])
    if x < 0x10000:
        return b"\xfd" + x.to_bytes(2, "big")
    if x < 0x100000000:
        return b"\xfe" + x.to_bytes(4, "big")
    return b"\xff" + x.to_bytes(8, "big")


def tlv(records) -> bytes:
    """records: list of (type, value bytes); written in strictly increasing type."""
    out = b""
    last = -1
    for t, v in records:
        assert t > last, "types must strictly increase"
        last = t
        out += bigsize(t) + bigsize(len(v)) + v
    return out


def u8(x): return x.to_bytes(1, "big")
def u16(x): return x.to_bytes(2, "big")
def u32(x): return x.to_bytes(4, "big")
def u64(x): return x.to_bytes(8, "big")
def rng(lo, hi): return u64(lo) + u64(hi)


def show(name, b: bytes):
    print(f"{name} ({len(b)} bytes):")
    h = b.hex()
    for i in range(0, len(h), 64):
        print("    " + h[i:i + 64])


# ----------------------------------------------------- the custom type -----
d = hashlib.sha256(b"gazpacho factory message").digest()
raw = int.from_bytes(d[:2], "big")
custom_type = raw | 0x8001          # into 32768..65535 and odd
print("== messages.md: custom message type")
print(f"sha256('gazpacho factory message')[0:2] = 0x{raw:04x}; | 0x8001 = {custom_type} (0x{custom_type:04x})")
assert 32768 <= custom_type <= 65535 and custom_type % 2 == 1
MAGIC = bytes.fromhex("677a6601")   # the native 4-byte protocol tag

# ------------------------------------- bLIP-56 adapter (not in slice 1) ----
FACTORY_MESSAGE_ID = 32800           # bLIP-56 factory_message_id
SUB_SUPPORTED = 2                    # supported_factory_protocols
SUB_PIGGYBACK = 4                    # factory_piggyback
PROTOCOL_NAME = b"SuperScalar/1"
PROTOCOL_ID = hashlib.sha256(PROTOCOL_NAME).digest()
print("\n== messages.md: factory_protocol_id = sha256('SuperScalar/1'), decided (owner, 2026-11-12)")
print(PROTOCOL_ID.hex())


def piggyback(inner: bytes) -> bytes:
    """A whole Lightning message: type 32800, submessage 4, TLV 0 and TLV 1024."""
    return u16(FACTORY_MESSAGE_ID) + u16(SUB_PIGGYBACK) + tlv([(0, PROTOCOL_ID), (1024, inner)])


supported = u16(FACTORY_MESSAGE_ID) + u16(SUB_SUPPORTED) + tlv([(512, PROTOCOL_ID)])
print("\n== vector M0, supported_factory_protocols naming only SuperScalar/1")
print(supported.hex())
OVERHEAD = len(piggyback(bytes(60_000))) - 60_000
print("piggyback overhead for a payload of 253..65535 bytes:", OVERHEAD, "bytes; largest payload:", 65_535 - OVERHEAD)

# ----------------------------------------------------- chain and keys ------
SIGNET_GENESIS_DISPLAY = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
chain = bytes.fromhex(SIGNET_GENESIS_DISPLAY)[::-1]
print("\n== chain_hash for signet (genesis hash, internal byte order)")
print(chain.hex())

def test_key(label: str) -> int:
    return int.from_bytes(hashlib.sha256(("gazpacho test key: " + label).encode()).digest(), "big") % N

host_sk = test_key("host")
mem_factory_sk = test_key("member 1 factory")
mem_contrib_sk = test_key("member 1 contribution")
AUX = bytes(32)  # fixed auxiliary randomness, for repeatable vectors only

print("\n== TEST KEYS (never for coins)")
print("host secret        = sha256('gazpacho test key: host') mod n")
print("  host_key (33)    =", compressed(host_sk).hex())
print("member 1 factory   = sha256('gazpacho test key: member 1 factory') mod n")
print("  factory_key (33) =", compressed(mem_factory_sk).hex())
print("member 1 contrib.  = sha256('gazpacho test key: member 1 contribution') mod n")
print("  contribution (33)=", compressed(mem_contrib_sk).hex())
print("aux_rand for every signature below = 32 zero bytes")

# ----------------------------------------------------- terms ---------------
salt = hashlib.sha256(b"gazpacho test lobby salt").digest()[:16]
# Shape table (terms.md section 4, after review 3): per entry max_members (u16),
# n_interior (u8), the interior widths from the root down (u8 each, 4..15), and
# the leaf kind (u8, 3 = one-member pseudo-Spilman leaf). The import is given
# level arity = interior widths ++ [leaf kind]; its last entry selects the leaf type.
LEAF_PS = 3
SHAPE_T1 = [(4, [], LEAF_PS), (16, [4], LEAF_PS)]


def shape_bytes(entries) -> bytes:
    out = b""
    for max_members, interior, leaf in entries:
        out += u16(max_members) + u8(len(interior)) + bytes(interior) + u8(leaf)
    return out


def split_walk(levels, m, d=0):
    """terms.md section 4's split rule, as the import applies it. Yields
    (depth, members) for every leaf; raises if a node at an interior depth would
    itself be a leaf (a multi-member or non-pseudo-Spilman leaf)."""
    a = levels[d] if d < len(levels) else levels[-1]
    if a == LEAF_PS:
        if m == 1:
            yield (d, 1)
            return
        left = m // 2
        yield from split_walk(levels, left, d + 1)
        yield from split_walk(levels, m - left, d + 1)
        return
    if m <= a:
        raise ValueError(f"{m} members at depth {d} under width {a} would be one leaf")
    rem = m
    for j in range(a):
        if rem == 0:
            break
        c = min(rem, -(-rem // (a - j)))
        yield from split_walk(levels, c, d + 1)
        rem -= c


def funding_requirement(levels, m, channel, fee, anchor, d=0):
    """terms.md section 4.2: the funding amount of a tree whose interior nodes are
    all fixed: R(leaf) = 2 channel + 2 fee + 2 anchor; R(node with k children)
    = k * max R(child) + fee + anchor."""
    a = levels[d] if d < len(levels) else levels[-1]
    if a == LEAF_PS:
        if m == 1:
            return 2 * channel + 2 * fee + 2 * anchor
        left = m // 2
        kids = [left, m - left]
    else:
        kids, rem = [], m
        for j in range(a):
            if rem == 0:
                break
            c = min(rem, -(-rem // (a - j)))
            kids.append(c)
            rem -= c
    return len(kids) * max(funding_requirement(levels, k, channel, fee, anchor, d + 1) for k in kids) + fee + anchor


print("\n== terms.md: shape table of T1, checked by the split rule")
prev = 2
for max_members, interior, leaf in SHAPE_T1:
    levels = interior + [leaf]
    for n in range(max(3, prev + 1), max_members + 1):
        leaves = list(split_walk(levels, n))
        assert len(leaves) == n and all(k == 1 for _, k in leaves)
        D = max(dd for dd, _ in leaves)
        if n in (3, 4, 5, 8, 16):
            print(f"  {n:2d} members: level arity {levels}, {n} one-member pseudo-Spilman leaves, fixed_levels D = {D}")
    prev = max_members
# Reproduces the build-server run of 2026-11-12 (see terms.md section 4.2).
assert funding_requirement([3], 3, 100_000, 17, 240) == 802_827
assert funding_requirement([3], 4, 100_000, 17, 240) == 802_827
assert funding_requirement([4, 3], 5, 100_000, 26, 240) == 1_605_586
assert funding_requirement([4, 3], 16, 100_000, 26, 240) == 3_211_970
print("  funding_amount, channel 100000, anchors on: 3 or 4 members (fee 17) =",
      funding_requirement([3], 3, 100_000, 17, 240), "; 16 members (fee 26) =",
      funding_requirement([4, 3], 16, 100_000, 26, 240))
for bad in ([4], [4, 3]):
    try:
        list(split_walk(bad, 3))
        raise AssertionError("must be refused")
    except ValueError as e:
        print(f"  level arity {bad} at 3 members is refused: {e}")
shape = shape_bytes(SHAPE_T1)
outer_records = [
    (2, chain),
    (4, compressed(host_sk)),
    (6, salt),
    (8, u8(2)),                 # Standard
    (10, u16(8)),               # target
    (12, u16(3)),               # minimum
    (14, u64(1794441600)),      # deadline: 2026-11-12T00:00:00Z
    (16, u8(0)),                # on shortfall: cancel
    (18, u32(30_000)),          # ready window
    (20, u32(600_000)),         # signing budget
    (22, u32(60_000)),          # step timeout
    (24, shape),
    (26, u32(144)),             # lifetime blocks (Slice 1: a short life, about a day)
    (28, u32(36)),              # wind-down blocks
    (30, u64(100_000)),         # channel_sat: smallest channel output on any leaf
    (32, u32(100)),             # tree fee rate, sat per 1000 vB = 0.1 sat/vB
    (34, u8(0)),                # switches: names, chat, change requests all off
    (64, rng(0, 2_000)),        # joining fee, sat
    (66, rng(0, 1_000)),        # fee base, msat
    (68, rng(100, 2_500)),      # fee proportional, millionths
]
outer = tlv(outer_records)
outer_digest = tagged_hash("gazpacho/terms/outer", outer)
outer_sig = schnorr_sign(outer_digest, host_sk, AUX)

def current(version, jf, base, prop):
    return tlv([(2, outer_digest), (4, u32(version)), (64, u64(jf)), (66, u64(base)), (68, u64(prop))])

cur1 = current(1, 500, 1_000, 1_000)
cur1_digest = tagged_hash("gazpacho/terms/current", cur1)
cur1_sig = schnorr_sign(cur1_digest, host_sk, AUX)
cur2 = current(2, 1_500, 1_000, 1_000)
cur2_digest = tagged_hash("gazpacho/terms/current", cur2)
cur2_sig = schnorr_sign(cur2_digest, host_sk, AUX)

import datetime
print("\n== terms.md: vector T1, outer rules")
print("deadline 1794441600 =", datetime.datetime.fromtimestamp(1794441600, datetime.timezone.utc).isoformat())
print("lobby_salt =", salt.hex(), "= sha256('gazpacho test lobby salt')[0:16]")
show("outer record", outer)
print("outer_digest = tagged_hash('gazpacho/terms/outer', outer) =", outer_digest.hex())
print("outer_sig    =", outer_sig.hex())
print("\n== vector T2, current values version 1 (joining fee 500, base 1000, prop 1000)")
show("current v1", cur1)
print("current_digest v1 =", cur1_digest.hex())
print("current_sig v1    =", cur1_sig.hex())
print("\n== vector T3, current values version 2 (joining fee 1500)")
show("current v2", cur2)
print("current_digest v2 =", cur2_digest.hex())
print("current_sig v2    =", cur2_sig.hex())

# Hostile variants: each must be refused.
bad_nonmin = outer.replace(bytes([10, 2]) + u16(8), bytes([10, 0xfd, 0x00, 0x02]) + u16(8), 1)
print("\n== vector T4 (refuse): T1 with the length of record 10 written as fd0002 (not minimal)")
print("first differing offset:", next(i for i in range(len(outer)) if outer[i] != bad_nonmin[i]))
print("digest if a careless parser hashed it anyway:", tagged_hash("gazpacho/terms/outer", bad_nonmin).hex())
cur_out = current(3, 2_001, 1_000, 1_000)
print("== vector T5 (refuse): current version 3 with joining fee 2001, outside 0..2000")
show("current v3", cur_out)

# --------------------------------------------- the ready message --------------
KIND_READY = 22
binding = tagged_hash("gazpacho/bind", outer_digest + compressed(mem_factory_sk) + compressed(mem_contrib_sk))
binding_sig = schnorr_sign(binding, mem_factory_sk, AUX)
binding_sig_c = schnorr_sign(binding, mem_contrib_sk, AUX)
ready_body = tlv([(2, outer_digest), (4, u32(1)), (6, cur1_digest)])
header = MAGIC + u16(KIND_READY) + outer_digest
msg_hash = tagged_hash("gazpacho/msg", header + ready_body)
ready_sig = schnorr_sign(msg_hash, mem_contrib_sk, AUX)
ready_env = header + ready_body + tlv([(240, ready_sig)])
wire = u16(custom_type) + ready_env
adapted = piggyback(ready_env[4:])   # the tag is dropped; TLV 0 carries the id
print("\n== messages.md: vector M1, member 1 'ready' for T1 / T2, no ready check")
print("binding = tagged_hash('gazpacho/bind', lobby_id||factory_key||contribution_key) =", binding.hex())
print("bind_by_factory      =", binding_sig.hex())
print("bind_by_contribution =", binding_sig_c.hex())
print("signed hash = tagged_hash('gazpacho/msg', tag||kind||scope||records before 240) =", msg_hash.hex())
show("Lightning message, native (52791, tag, kind, scope, records)", wire)
print("\n== vector M3, the same message through the bLIP-56 adapter (same signature)")
show("Lightning message, adapter (32800, submessage 4, TLV 0, TLV 1024)", adapted)
assert MAGIC + adapted[2 + 2 + 34 + 4:] == ready_env

# --------------------------------------------- a part --------------------------
inner = bytes(range(256)) * 300   # 76,800 bytes of test data as an inner body
INNER_KIND = 68
tid = tagged_hash("gazpacho/part", u16(INNER_KIND) + inner)
CH = 65_000
count = -(-len(inner) // CH)
print("\n== messages.md: vector M2, a 76,800-byte body of kind 68 split in", count, "parts")
print("transfer_id =", tid.hex())
for i in range(count):
    data = inner[i * CH:(i + 1) * CH]
    body = tlv([(2, tid), (4, u16(INNER_KIND)), (6, u32(len(inner))), (8, u16(i)), (10, u16(count)), (12, data)])
    env = MAGIC + u16(2) + outer_digest + body
    print(f"part {i}: data {len(data)} bytes, native Lightning message {len(env) + 2} bytes, "
          f"through the adapter {len(piggyback(env[4:]))} bytes, "
          f"first 64 hex of body: {body[:32].hex()}")

# --------------------------------------------- terms classification ----------
print("\n== terms.md: vector T6, member limits against T1 and T2")
limits = {"joining fee": (64, 1_000), "fee base": (66, 1_000), "fee prop": (68, 2_500)}
ranges = {64: (0, 2_000), 66: (0, 1_000), 68: (100, 2_500)}
curv = {64: 500, 66: 1_000, 68: 1_000}
for name, (t, lim) in limits.items():
    lo, hi = ranges[t]
    whole = hi <= lim
    now = curv[t] <= lim
    print(f"{name}: limit {lim}, range {lo}..{hi}, current {curv[t]} -> "
          f"{'fits the whole range' if whole else ('fits only now' if now else 'does not fit')}")

# --------------------------------------------- journal entries ----------------
print("\n== journal.md: vector J1, file header")
jmagic = b"GZJOURNL"
hdr = jmagic + chain
hdr_check = hashlib.sha256(hdr).digest()[:8]
show("header", hdr + hdr_check)

def entry(kind, inc, seq, payload):
    body = u8(kind) + u64(inc) + u64(seq) + payload
    head = u32(len(body)) + body
    return head + hashlib.sha256(head).digest()[:8]

HEADER_LEN = len(hdr) + 8          # 48
inc_entry = entry(1, 1, 0, u64(1_794_000_000_000))
print("== vector J2, incarnation 1, clock 1794000000000 ms")
show("entry", inc_entry)
rec = u32(1) + u32(0x7e570001) + u32(4) + b"ping"
batch_entry = entry(2, 1, 1, rec)
print("== vector J3, batch (1,1) holding one record of type 0x7e570001 with bytes 'ping'")
show("entry", batch_entry)


def mark(inc, offset):
    """Sync mark (kind 3): written after a sync returned; says 'every byte before
    this entry was synced'. Its payload is its own offset in the file."""
    return entry(3, inc, 0, u64(offset))


mark1 = mark(1, HEADER_LEN + len(inc_entry))
print(f"== vector J5, sync mark of incarnation 1 at offset {HEADER_LEN + len(inc_entry)} (just after J2)")
show("entry", mark1)


def read_journal(data: bytes):
    """journal.md section 5, steps 3 and 4: returns ('clean'|'torn'|'corrupt', V)."""
    pos = HEADER_LEN
    def valid_at(p):
        if p + 4 > len(data):
            return None
        ln = int.from_bytes(data[p:p + 4], "big")
        if ln < 21 or ln > 8_388_625 or p + 4 + ln + 8 > len(data):
            return None
        body = data[p:p + 4 + ln]
        if hashlib.sha256(body).digest()[:8] != data[p + 4 + ln:p + 4 + ln + 8]:
            return None
        kind = data[p + 4]
        if kind not in (1, 2, 3) or (kind in (1, 3) and ln != 25):
            return None
        return p + 4 + ln + 8, kind, body
    while pos < len(data):
        r = valid_at(pos)
        if r is None:
            break
        pos = r[0]
    if pos == len(data):
        return "clean", pos
    # Damage at pos: is there a valid sync mark after it, naming its own offset?
    for p in range(pos + 1, len(data)):
        r = valid_at(p)
        if r and r[1] == 3 and int.from_bytes(r[2][21:29], "big") == p:
            return "corrupt", pos
    return "torn", pos


j4 = hdr + hdr_check + inc_entry + mark1 + batch_entry[:-3]
state, v = read_journal(j4)
assert state == "torn" and v == HEADER_LEN + len(inc_entry) + len(mark1)
print(f"== vector J4 (torn): header, J2, J5, then J3 with its last 3 bytes missing: {len(j4)} bytes;"
      f" no sync mark after the damage, so the reader cuts to offset {v} and keeps J2 and J5")
off_j3 = HEADER_LEN + len(inc_entry) + len(mark1)
mark2 = mark(1, off_j3 + len(batch_entry))
damaged = bytearray(batch_entry)
damaged[25] ^= 0x01                 # one bit of the record type inside J3
j6 = hdr + hdr_check + inc_entry + mark1 + bytes(damaged) + mark2
state, v = read_journal(j6)
assert state == "corrupt" and v == off_j3
print(f"== vector J6 (corruption): header, J2, J5, J3 with bit 0 of byte 25 flipped, then the sync mark "
      f"at offset {off_j3 + len(batch_entry)}: {len(j6)} bytes; the damage at {v} lies before a sync mark,"
      f" so the start is refused")
show("second sync mark (offset %d)" % (off_j3 + len(batch_entry)), mark2)
assert read_journal(hdr + hdr_check + inc_entry + mark1 + batch_entry + mark2)[0] == "clean"

# ===================================================== discovery.md ==========
# Draft 4.1 (after docs/reviews/review-discovery-d4-confirm.md): the reader's pending
# pool checks the price first and evicts from the link holding most (D28, E1);
# beacons from asked-for pool pages are relayed only within the arrival cap (D29,
# E2); tombstones of beacons this node held are never evicted (D30, E3).
# Draft 3 (after docs/reviews/review-discovery-d2.md): the listing withdrawal is its
# own signed record (D4w, tag gazpacho/withdrawal); D2t adds a BIP 86 coin
# anchor; D5's "unknown" answer names the requested digest; beacon sequences
# are height x 16 + counter, so D7, D8, D9, D15 and D17 changed; D12 and the
# new D20 to D23 RUN the acceptance rules in arrival order (a small reference
# reader below) instead of computing the result; D13c and D15b are new.
#
# Vectors D0 to D23 of spec/discovery.md draft 3 (draft 2 notes follow). Every number marked CANDIDATE
# is a reproducible random pick, not a final number: it must pass the checks of
# discovery.md section 2 on the day it is chosen.
#
# Changed in draft 2: one feature bit (the factory_host pair is gone); the host
# card is withdrawn (D1 and D3 are no longer printed; its TLV number and Nostr
# kind are only reserved), so the index record of D5 changed; the beacon carries
# two proposed filter fields, profile and channel_sat, so D7, D8 and D9 changed.
# New: D13 overlay_init (lobby store flag), D14 pool_request, D15 pool, D16
# listing_not_held, D17 equivocation tie-break, D18 orphan pool bounds, D19
# host_list_request naming keys. D2, D4, D6 (listing content), D10, D11, D12 are
# unchanged.
import base64

print("\n\n######## discovery.md ########")

# ---- D0: candidate numbers -------------------------------------------------
# Known uses read or recalled in docs/research/discovery-research.md. Not exhaustive.
KNOWN_BITS = {0: "BOLT", 256: "hosted_channels", 257: "hosted_channels", 258: "dns_resolver",
              259: "dns_resolver", 270: "bLIP-56", 271: "bLIP-56", 728: "LSPS", 729: "LSPS"}
KNOWN_ONION = {64: "BOLT 12 invoice_request", 66: "BOLT 12 invoice", 68: "BOLT 12 invoice_error",
               65536: "bLIP-32", 65538: "bLIP-32", 65550: "bLIP-32"}
KNOWN_NA_TLV = {1: "CLN will_fund (bolts#878)", 5: "bolts#1153 will_fund_rates", 1339: "Eclair prototype"}
KNOWN_NOSTR = set(range(30000, 30031)) | {30078, 30311, 30315, 30402, 30403, 30617, 30618,
                                          31922, 31923, 31924, 31925, 31989, 31990, 34235, 34236,
                                          34550, 37375, 38099, 38101, 39735} | set(range(38383, 38390)) \
              | set(range(39000, 39010))


def h16(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:2], "big")


print("== D0: candidate numbers (NOT final; see discovery.md section 2)")
# Feature bit: one pair, 256..511 so the feature field stays at most 64 bytes.
# The pick still walks 4-aligned blocks, as in draft 1, so the candidate is
# unchanged (448/449); the upper pair of the block (draft 1's factory_host) is
# free again, neither used nor reserved.
pick = h16("gazpacho feature bits")
bit_cands = []
step = 0
while len(bit_cands) < 3:
    base = 256 + 4 * ((pick + step) % 64)
    step += 1
    if any(b in KNOWN_BITS for b in range(base, base + 4)):
        continue
    bit_cands.append(base)
for base in bit_cands:
    print(f"  bit: factory_capable {base}/{base + 1} (advertise {base + 1});"
          f" features field with bit {base + 1} set = {(base + 1) // 8 + 1} bytes")
FC_ODD = bit_cands[0] + 1
assert FC_ODD == 449

# Onion payload types: one block of 64 above 65,600; odd types base+1, +3, ...
# Draft 2 appends three types; the first six are unchanged.
pick = h16("gazpacho onion payload types")
ON_BASE = 65_600 + 64 * (pick % 1024)
ON = {name: ON_BASE + 1 + 2 * i for i, name in enumerate(
    ["lobby_index_request", "lobby_index", "listing_request", "listing",
     "host_list_request", "host_list", "pool_request", "pool", "listing_not_held"])}
assert not set(ON.values()) & set(KNOWN_ONION)
print("  onion payload types:", ", ".join(f"{k} {v}" for k, v in ON.items()))
# node_announcement TLV for the withdrawn host card: odd, above 65,536. Reserved only.
CARD_TLV = 65_537 + 2 * h16("gazpacho host card tlv")
assert CARD_TLV % 2 == 1 and CARD_TLV not in KNOWN_NA_TLV
print("  node_announcement TLV type", CARD_TLV, "RESERVED (host card withdrawn in draft 2; never sent)")


def nostr_kind(label):
    k = 30000 + h16(label) % 10000
    while k in KNOWN_NOSTR:
        k += 1
    return k


NK_LISTING = nostr_kind("gazpacho nostr listing kind")
NK_CARD = nostr_kind("gazpacho nostr card kind")
print(f"  Nostr addressable kind: listing {NK_LISTING}; {NK_CARD} RESERVED (was the host card)")

# Native kinds: fixed by discovery.md section 6.3 in PROTOCOL.md's range 128..159.
K_INDEX_REQ, K_INDEX, K_LISTING_REQ, K_LISTING, K_HL_REQ, K_HL, K_BEACON, K_BFILTER = \
    129, 131, 133, 135, 137, 139, 141, 143
K_POOL_REQ, K_POOL = 145, 147                 # new in draft 2
K_SUMMARY, K_STORE_SYNC = 149, 151            # reserved: no format
K_OVERLAY_INIT, K_NOT_HELD = 153, 155         # new in draft 2
K_HOST_PROOFS = 157                           # reserved: no format
assert all(k % 2 == 1 and 128 <= k <= 159 for k in
           (K_POOL_REQ, K_POOL, K_SUMMARY, K_STORE_SYNC, K_OVERLAY_INIT, K_NOT_HELD, K_HOST_PROOFS))

# ---- shared test values ----------------------------------------------------
host_pub = compressed(host_sk)
coin_sk = test_key("host coin")
coin_q = xonly(coin_sk)                       # treated as the P2TR output key Q
coin_txid = hashlib.sha256(b"gazpacho test coin txid").digest()
coin_outpoint = coin_txid + u32(0)            # big-endian index, messages.md section 1
TIP = 290_000                                 # a signet height used by every vector
START = TIP
EXPIRY = TIP + 144
VALID_UNTIL = TIP + 1_008


def native(kind, records):
    """A whole Lightning message on the native carrier, scope all zero."""
    return u16(custom_type) + MAGIC + u16(kind) + bytes(32) + records


def onion_payload(ptype, records):
    """The one payload field inside the final hop's onionmsg_tlv."""
    return bigsize(ptype) + bigsize(len(records)) + records


# ---- D1: host card: WITHDRAWN in draft 2 (number reserved, no vector) --------
print("\n== D1: withdrawn (host card removed in draft 2)")

# ---- D2: coin anchor ---------------------------------------------------------
anchor_msg = chain + host_pub + coin_outpoint + u32(VALID_UNTIL)
anchor_digest = tagged_hash("gazpacho/anchor", anchor_msg)
anchor_sig = schnorr_sign(anchor_digest, coin_sk, AUX)
anchor = tlv([(4, coin_outpoint), (6, u32(VALID_UNTIL)), (8, anchor_sig)])
print("\n== D2: coin anchor (test coin; never for coins)")
print("coin secret = sha256('gazpacho test key: host coin') mod n; output key Q =", coin_q.hex())
print("outpoint txid = sha256('gazpacho test coin txid'), index 0; valid_until_height", VALID_UNTIL)
print("anchor_digest = TH('gazpacho/anchor', chain||host_key||outpoint||valid_until) =", anchor_digest.hex())
show("anchor record value", anchor)
# A borrowed coin: the same signature presented for another host key fails.
other_pub = compressed(test_key("other host"))
borrowed = tagged_hash("gazpacho/anchor", chain + other_pub + coin_outpoint + u32(VALID_UNTIL))
assert not schnorr_verify(borrowed, coin_q, anchor_sig)
print("the same anchor under another host key: signature fails (D11)")


def allowance(value, unit):
    """discovery.md section 9, rule A3."""
    if value < unit // 4:
        return 0
    return min(4, max(1, value // unit))


for v in (2_499, 2_500, 19_999, 20_000, 100_000):
    print(f"  signet anchor of {v} sat backs {allowance(v, 10_000)} open listing(s)")
assert [allowance(v, 10_000) for v in (2_499, 2_500, 19_999, 20_000, 100_000)] == [0, 1, 1, 2, 4]

# ---- D2t: a BIP 86 wallet coin as the anchor ---------------------------------
# A wallet's P2TR key-path coin has output key Q = P + t*G, with P the internal
# key (even y) and t = TH("TapTweak", x(P)). coin_sig is made with the tweaked
# secret. D2 used a secret directly as Q, which is also a valid P2TR output key.
int_sk = test_key("host coin internal")
P_pt = point_mul(G, int_sk)
d_even = int_sk if P_pt[1] % 2 == 0 else N - int_sk
t_tw = int.from_bytes(tagged_hash("TapTweak", P_pt[0].to_bytes(32, "big")), "big")
assert t_tw < N
tw_sk = (d_even + t_tw) % N
Q86 = xonly(tw_sk)
assert point_add(point_mul(G, d_even), point_mul(G, t_tw))[0].to_bytes(32, "big") == Q86
anchor86_sig = schnorr_sign(anchor_digest, tw_sk, AUX)
assert schnorr_verify(anchor_digest, Q86, anchor86_sig)
print("\n== D2t: BIP 86 coin anchor (same outpoint and statement as D2)")
print("internal secret = sha256('gazpacho test key: host coin internal') mod n; internal key P =",
      xonly(int_sk).hex())
print("tweak t = TH('TapTweak', x(P)) =", t_tw.to_bytes(32, "big").hex())
print("output key Q = P + tG =", Q86.hex(), "; script 5120 || Q")
print("coin_sig with the tweaked secret =", anchor86_sig.hex())

# ---- D3: signed card: WITHDRAWN in draft 2 (tag gazpacho/card reserved) ------
print("\n== D3: withdrawn (signed host card removed in draft 2)")

# ---- D4: the listing for lobby T1 -------------------------------------------
def listing_record(start, expiry, with_anchor=True, key=host_sk):
    recs = [(2, compressed(key)), (4, outer), (6, u32(start)), (8, u32(expiry))]
    if with_anchor:
        recs.append((10, anchor))
    body = tlv(recs)
    dg = tagged_hash("gazpacho/listing", body)
    return body + tlv([(240, schnorr_sign(dg, key, AUX))]), dg


listing, listing_digest = listing_record(START, EXPIRY)
print("\n== D4: listing of lobby T1, start", START, "expiry", EXPIRY, "with the coin anchor")
print("listing_id = outer_digest =", outer_digest.hex())
print("listing_digest = TH('gazpacho/listing', records before 240) =", listing_digest.hex())
show("listing", listing)
print("listing_sig =", listing[-64:].hex())
def withdrawal_record(listing_id, height, key=host_sk):
    """discovery.md 5.3: a signed tombstone, its own record and tag."""
    body = tlv([(2, compressed(key)), (4, listing_id), (6, u32(height))])
    dg = tagged_hash("gazpacho/withdrawal", body)
    return body + tlv([(240, schnorr_sign(dg, key, AUX))]), dg


WD_HEIGHT = TIP + 10
withdrawal, wd_digest = withdrawal_record(outer_digest, WD_HEIGHT)
print(f"== D4w: withdrawal of lobby T1 at height {WD_HEIGHT} (tag gazpacho/withdrawal)")
print("withdrawal_digest =", wd_digest.hex())
show("withdrawal record", withdrawal)
too_long, _ = listing_record(START, START + 1_009)
print("D4x refuse: expiry = start + 1009, listing_sig", too_long[-64:].hex())
# Size bound of discovery.md section 5: the sum of each record's maximum.
MAX_LISTING = (1 + 1 + 33) + (1 + 3 + 4096) + 6 + 6 + (1 + 3 + 600) + (2 + 64)
print("largest possible listing:", MAX_LISTING, "bytes")

# ---- D5: the queries ---------------------------------------------------------
idx_req = tlv([(2, chain)])
entry_t1 = outer_digest + u64(1794441600) + u8(2) + u64(100_000)
idx_body = tlv([(2, chain), (4, host_pub), (6, u32(TIP)), (8, entry_t1)])   # draft 2: no card
idx_digest = tagged_hash("gazpacho/index", idx_body)
index = idx_body + tlv([(240, schnorr_sign(idx_digest, host_sk, AUX))])
idx_msg = tlv([(2, index)])
lst_req = tlv([(2, chain), (4, outer_digest)])
lst_msg = tlv([(2, listing)])
unk_msg = tlv([(4, outer_digest)])          # draft 3: names the requested digest (Q4)
wdn_msg = tlv([(6, withdrawal)])            # draft 3: the host answers a withdrawn lobby so
print("\n== D5: queries for the test host (records; same bytes on both carriers)")
show("lobby_index_request records", idx_req)
print("index_digest = TH('gazpacho/index', records before 240) =", idx_digest.hex())
show("index record", index)
show("lobby_index records", idx_msg)
show("listing_request records", lst_req)
print(f"listing answer records: {len(lst_msg)} bytes = record 2 holding the D4 listing")
show("listing answer 'unknown' (record 4 = the requested outer_digest)", unk_msg)
print(f"listing answer 'withdrawn' (record 6 = D4w): {len(wdn_msg)} bytes")
show(f"native lobby_index_request (kind {K_INDEX_REQ})", native(K_INDEX_REQ, idx_req))
show(f"native listing_request (kind {K_LISTING_REQ})", native(K_LISTING_REQ, lst_req))
show(f"onion payload field, lobby_index_request (type {ON['lobby_index_request']}, candidate)",
     onion_payload(ON["lobby_index_request"], idx_req))
print("sizes: native lobby_index", len(native(K_INDEX, idx_msg)), "bytes; native listing",
      len(native(K_LISTING, lst_msg)), "bytes; onion listing payload field",
      len(onion_payload(ON["listing"], lst_msg)), "bytes")
assert native(K_LISTING, lst_msg).endswith(lst_msg) and onion_payload(ON["listing"], lst_msg).endswith(lst_msg)

# ---- D6: Nostr content -------------------------------------------------------
print("\n== D6: Nostr annex (content only; event ids depend on author and time)")
print(f"listing event kind {NK_LISTING} (candidate), d =", outer_digest.hex())
print("content (base64 of D4):")
b64 = base64.b64encode(listing).decode()
for i in range(0, len(b64), 76):
    print("    " + b64[i:i + 76])
print(f"content: {len(b64)} characters; no card event in draft 2 (kind {NK_CARD} reserved)")

# ---- D7 to D10: lobby beacon -------------------------------------------------
# Draft 2 added two PROPOSED filter fields, copied from the outer record:
# 12 profile (u8: 1 Safety, 2 Standard, 3 Starter; never 4 Circle) and
# 14 channel_sat (u64, at least 546). Draft 3: sequence = height x 16 + counter
# (discovery.md 8.1), so it survives a restore and cannot jump to 2^32 - 1.
BEACON_PROFILE, BEACON_CHANNEL = 2, 100_000


def seq_of(height, counter=0):
    assert 0 <= counter < 16
    return height * 16 + counter


def beacon(seq, digest=outer_digest, open_h=TIP, deadline_h=TIP + 144, key=host_sk,
           profile=BEACON_PROFILE, channel_sat=BEACON_CHANNEL):
    body = tlv([(2, compressed(key)), (4, digest), (6, u32(open_h)), (8, u32(deadline_h)),
                (10, u32(seq)), (12, u8(profile)), (14, u64(channel_sat))])
    bid = tagged_hash("gazpacho/beacon", body)
    return body + tlv([(240, schnorr_sign(bid, key, AUX))]), bid


S1 = seq_of(TIP, 0)
b1, b1_id = beacon(S1)
print(f"\n== D7: lobby beacon for lobby T1, open {TIP} deadline {TIP + 144} sequence {S1} (= {TIP} x 16 + 0),",
      "profile 2 (Standard), channel_sat 100000")
print("beacon_id = TH('gazpacho/beacon', records before 240) =", b1_id.hex())
show("beacon records", b1)
show(f"native lobby_beacon (kind {K_BEACON})", native(K_BEACON, b1))
S2 = seq_of(TIP + 10, 0)
b2, b2_id = beacon(S2, open_h=TIP, deadline_h=TIP)
print(f"== D8: the same lobby withdrawn at height {TIP + 10}: sequence {S2} (= {TIP + 10} x 16), "
      "deadline_height = open_height")
print("beacon_id =", b2_id.hex(), "; sig", b2[-64:].hex())
forged, _ = beacon(S1, key=test_key("other host"))
forged = b1[:35] + forged[35:]                # host id of the test host, signed by another key
assert not schnorr_verify(tagged_hash("gazpacho/beacon", forged[:-66]), host_pub[1:], forged[-64:])
print("== D9 (refuse): D7's records with the signature of key 'other host': signature fails")
bf_all = tlv([(2, chain), (4, u32(0)), (6, u32(0xFFFFFFFF))])
bf_off = tlv([(2, chain), (4, u32(0xFFFFFFFF)), (6, u32(0))])
print("== D10: beacon_filter")
show(f"native beacon_filter 'everything' (kind {K_BFILTER})", native(K_BFILTER, bf_all))
show("beacon_filter records 'nothing' (off)", bf_off)
# Seen-set and held-set bounds, discovery.md section 8.6 (draft 3 sizing: the
# seen-set also holds tombstones and every accepted id for 1,008 blocks).
for hosts in (10, 1_000, 10_000):
    entries = min(262_144, max(4_096, 64 * hosts))
    print(f"  seen-set for {hosts} factory-capable nodes in the graph: {entries} entries, {entries * 40} bytes")
print(f"  held set at 1000 hosts: at most 4 x 1000 x {len(b1)} = {4 * 1000 * len(b1)} bytes of live beacons")


def read_bigsize(b: bytes, i: int):
    if b[i] < 0xfd:
        return b[i], i + 1
    n = {0xfd: 2, 0xfe: 4, 0xff: 8}[b[i]]
    return int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n


def read_tlv(b: bytes) -> dict:
    out, i, last = {}, 0, -1
    while i < len(b):
        t, i = read_bigsize(b, i)
        ln, i = read_bigsize(b, i)
        assert t > last and i + ln <= len(b)
        out[t], i, last = b[i:i + ln], i + ln, t
    return out


# ---- The reference reader: discovery.md 8.3 to 8.6, in arrival order -------
UNIT_SIGNET = 10_000


class Reader:
    """A minimal relay that runs B1 to B10 in order (draft 4). Signatures are
    checked for real. graph: {host point: (half-capacity sat, oldest channel age)}.
    Draft 4 adds: the pending pool for beacons ahead of this node's tip,
    re-offered on each new block (R-P1 to R-P3); the arrival-rate cap (B9 b);
    the tombstone cap (B10); and B3's full shape checks."""

    KNOWN = {2, 4, 6, 8, 10, 12, 14, 240}

    def __init__(self, tip, graph, unit=UNIT_SIGNET):
        self.tip, self.graph, self.unit = tip, graph, unit
        self.seen = set()
        self.held = {}          # (host, digest) -> (seq, bid, withdrawn, open_h, deadline_h, rec)
        self.seqs = {}          # host -> {seq}
        self.arrivals = {}      # host -> [tip at acceptance of each new number, relayed path]
        self.orphans = []
        self.pending = []       # (link, time, rec)
        self.relayed = []
        self.lobbies = set()    # (host, digest) of every live beacon accepted (E3)
        self.synced = False     # draft 4.1, E1: a node not behind holds at most 12 blocks ahead
        self.clock = 0

    def set_tip(self, tip):
        """A new block: re-offer pending beacons (R-P2). Returns their results."""
        self.tip = tip
        again, self.pending = self.pending, []
        return [self.offer(rec, link) for link, _, rec in again]

    def offer(self, rec, link="l0", from_pool=False):
        r = read_tlv(rec)
        host, dg = r[2], r[4]
        open_h, dl = int.from_bytes(r[6], "big"), int.from_bytes(r[8], "big")
        seq = int.from_bytes(r[10], "big")
        bid = tagged_hash("gazpacho/beacon", rec[:-66])
        if (not set(r) >= self.KNOWN or any(t % 2 == 0 and t not in self.KNOWN for t in r)
                or r[12][0] not in (1, 2, 3) or int.from_bytes(r[14], "big") < 546
                or dl < open_h or dl > open_h + 1_008):          # B3 (Ignore)
            return "ignore:B3"
        if bid in self.seen:                                      # B4
            return "ignore:dup"
        if not schnorr_verify(bid, host[1:], r[240]):             # B5: never seen
            return "reject:B5"
        withdrawal = dl == open_h
        h = seq >> 4
        if h < open_h:
            return "ignore:B6"
        if open_h > self.tip + 6 or h > self.tip + 6:             # B6: ahead
            ahead = 12 if self.synced else 144                    # E1
            if h > self.tip + ahead or open_h > self.tip + ahead:
                return "ignore:B6"                                # too far ahead: not pending
            g0 = self.graph.get(host)                             # E1: price first if known
            if g0 is not None and (g0[1] < 144 or allowance(g0[0], self.unit) == 0):
                return "ignore:B7"
            self.clock += 1
            mine_l = [x for x in self.pending if x[0] == link]
            if len(mine_l) >= 8:
                self.pending.remove(mine_l[0])                    # that link's oldest
            if len(self.pending) >= 64:                           # oldest of the link holding most
                counts = {}
                for x in self.pending:
                    counts[x[0]] = counts.get(x[0], 0) + 1
                worst = max(counts, key=lambda l: (counts[l], -min(x[1] for x in self.pending if x[0] == l)))
                self.pending.remove(min((x for x in self.pending if x[0] == worst), key=lambda x: x[1]))
            self.pending.append((link, self.clock, rec))
            return "pending"
        if withdrawal and open_h + 1_008 <= self.tip:
            return "ignore:B6"
        if not withdrawal and dl <= self.tip:
            return "ignore:B6"
        g = self.graph.get(host)                                  # B7
        if g is None:
            self.orphans.append(rec)
            return "orphan"
        cap, age = g
        allow = allowance(cap, self.unit) if age >= 144 else 0
        if allow == 0:
            return "ignore:B7"
        old = self.held.get((host, dg))                           # B8 a
        if old is not None:
            if old[2] and not withdrawal:
                return "ignore:B8a"                               # a tombstone is final
            if seq <= old[0]:
                if not (seq == old[0] and bid < old[1]):
                    return "ignore:B8a"
        for (hh, d2), v in list(self.held.items()):               # B8 b, other lobby
            if hh == host and d2 != dg and v[0] == seq:
                if bid < v[1]:
                    del self.held[(hh, d2)]
                else:
                    return "ignore:B8b"
        mine = self.seqs.setdefault(host, set())
        arr = self.arrivals.setdefault(host, [])
        if seq not in mine:
            hs = sorted([s >> 4 for s in mine] + [h])             # B9 a: by height part
            for lo in range(h - 143, h + 1):
                if sum(1 for x in hs if lo <= x < lo + 144) > 8:
                    return "ignore:B9"
            if not from_pool and sum(1 for t in arr if t > self.tip - 144) >= 8:
                return "ignore:B9"                                # B9 b: by arrival
        if withdrawal:                                            # B10, E3: only orphan tombstones capped
            capped = (host, dg) not in self.lobbies
            same = sorted((v[0], k) for k, v in self.held.items()
                          if k[0] == host and v[2] and k[1] != dg and k not in self.lobbies)
            limit = allow + 4
        else:
            capped = True
            same = sorted((v[0], k) for k, v in self.held.items()
                          if k[0] == host and not v[2] and k[1] != dg)
            limit = allow
        if capped and len(same) >= limit:
            if seq < same[0][0]:
                return "ignore:B10"
            del self.held[same[0][1]]
        self.held[(host, dg)] = (seq, bid, withdrawal, open_h, dl, rec)
        if not withdrawal:
            self.lobbies.add((host, dg))
        relay = True
        if seq not in mine:
            mine.add(seq)
            if from_pool:                                         # E2: relay a pool-page number
                relay = sum(1 for t in arr if t > self.tip - 144) < 8   # only if it passes B9 (b)
            if relay:
                arr.append(self.tip)
        self.seen.add(bid)
        if relay:
            self.relayed.append(bid)
        return "tombstone" if withdrawal else "held"

    def live(self, host):
        return sorted(v[0] for k, v in self.held.items() if k[0] == host and not v[2])

    def tombs(self, host):
        return sorted(v[0] for k, v in self.held.items() if k[0] == host and v[2])

    def pending_ids(self):
        return [tagged_hash("gazpacho/beacon", x[2][:-66]) for x in self.pending]

    def pool(self):
        """PL1: live beacons and tombstones."""
        return [k for k in self.held]


def relay_to(src, dst, known, link="a"):
    """RL1 and RL2 between two readers: send every held beacon of src that dst
    is not known to have. known: the beacon ids already sent on this link."""
    out = []
    for v in list(src.held.values()):
        if v[1] in known:
            continue
        known.add(v[1])
        out.append(dst.offer(v[5], link))
    return out


class PoolServer:
    """discovery.md 11.4, PL1 to PL3 (draft 4), over one reader.
    Cursor = (host_id, sequence); a new request may carry `after` (a scout)."""

    def __init__(self, reader):
        self.r, self.tokens, self.new_on = reader, {}, {}

    def answer(self, conn, now, after=None, token=None, profiles=None, crange=None, max_entries=356):
        if token is not None:
            t = self.tokens.pop(token, None)                      # one use
            if t is None or t[0] != conn or t[1] != after or now - t[2] > 60:
                return "dropped"
        else:
            last = self.new_on.get(conn)                          # one new request an hour
            if last is not None and now - last < 3_600:
                return "dropped"
            self.new_on[conn] = now
        rows = []
        for v in self.r.held.values():
            rec = v[5]
            if beacon_matches(rec, profiles, crange):             # tombstones filtered too
                rows.append(((read_tlv(rec)[2], v[0]), rec))
        rows.sort(key=lambda x: x[0])
        if after is not None:
            rows = [x for x in rows if x[0] > after]
        page, rest = rows[:max_entries], rows[max_entries:]
        nxt = page[-1][0] if rest else None
        tok2 = None
        if nxt is not None:
            tok2 = hashlib.sha256(b"tok" + repr((conn, now, nxt)).encode()).digest()[:8]
            self.tokens[tok2] = (conn, nxt, now)
        return [x[1] for x in page], nxt, tok2


GRAPH = {host_pub: (100_000, 1_008)}       # half-capacity 100,000 sat on signet: allowance 4

# ---- D12: five beacons of one host, in arrival order ------------------------
rd = Reader(TIP + 4, GRAPH)
for c in range(5):
    rec, _ = beacon(seq_of(TIP + c), digest=hashlib.sha256(b"lobby %d" % c).digest(), open_h=TIP + c)
    assert rd.offer(rec) == "held"
assert rd.live(host_pub) == [seq_of(TIP + c) for c in range(1, 5)]
print("\n== D12 (run in arrival order): five beacons, heights 290000 to 290004, one per lobby:"
      " the fifth evicts the first; held = the last four")

# ---- D20: churn, in both orders (finding 1) -----------------------------------
# An attacker sends 12 new numbers for 12 lobbies, all inside one 144-block
# window, in three orders. Draft 2's rules relayed every one of them after a
# first sequence of 2^32 - 1.
def churn2(pairs):
    r = Reader(TIP + 6, GRAPH)
    res = []
    for h, c in pairs:
        rec, _ = beacon(seq_of(h, c), digest=hashlib.sha256(b"c2 %d %d" % (h, c)).digest(),
                        open_h=TIP, deadline_h=TIP + 144)
        res.append(r.offer(rec))
    return res, r


ascending = [(TIP + i, 0) for i in range(6)] + [(TIP + 6, c) for c in range(6)]
descending = list(reversed(ascending))
desc_asc = [(TIP + 6, 5 - c) for c in range(6)] + [(TIP + i, 0) for i in range(6)]
huge, _ = beacon(0xFFFFFFFF, digest=hashlib.sha256(b"huge").digest())
r_h = Reader(TIP, GRAPH)
assert r_h.offer(huge) == "ignore:B6"
res_up, r_up = churn2(ascending)
assert len(r_up.relayed) == 8 and res_up.count("ignore:B9") == 4
counts = []
for order in (ascending, descending, desc_asc):
    res, r = churn2(order)
    assert len(r.relayed) <= 8 and len(r.seqs[host_pub]) <= 8
    counts.append(len(r.relayed))
print("== D20 (finding 1): sequence 2^32 - 1 is ignored (B6: its height part is far ahead)."
      " 12 new numbers for 12 lobbies in one 144-block window: ascending, descending, and"
      " descending-then-ascending; relayed", counts, "(never more than 8; ascending: 8 held, 4 ignored by B9)")

# ---- D21: withdrawal first; resurrection by a relay; catch-up (finding 3) ---
r1 = Reader(TIP + 10, GRAPH)
assert r1.offer(b2) == "tombstone"             # D8 before D7
assert r1.offer(b1) == "ignore:B8a"            # D7 afterwards, from any relay
assert (host_pub, outer_digest) in r1.pool()   # the tombstone is in pool answers
r2 = Reader(TIP + 10, GRAPH)
assert r2.offer(b1) == "held"
assert r2.offer(b2) == "tombstone" and r2.live(host_pub) == []
assert r2.offer(b1) == "ignore:dup"
print("== D21 (finding 3): D8 then D7: D7 ignored, the tombstone is held and served in pool;"
      " D7 then D8: the lobby is withdrawn; D7 resent by a relay: ignored")

# ---- D22: a node behind the tip does not mark beacons seen (finding 3) ----
r3 = Reader(TIP - 10, GRAPH)
assert r3.offer(b1) == "pending" and b1_id not in r3.seen
assert r3.set_tip(TIP) == ["held"]
r4 = Reader(TIP, {})
assert r4.offer(b1) == "orphan" and b1_id not in r4.seen
r4.graph = GRAPH
assert r4.offer(r4.orphans.pop()) == "held"
cheap = Reader(TIP, {host_pub: (2_499, 1_008)})
assert cheap.offer(b1) == "ignore:B7"
young = Reader(TIP, {host_pub: (100_000, 143)})
assert young.offer(b1) == "ignore:B7"
print("== D22 (finding 3, 4): a node 10 blocks behind holds D7 pending without marking it seen,"
      " and accepts it at its next block (R-P2); an orphan is accepted once the host's gossip arrives;"
      " a host with 2,499 sat of half-capacity, or a channel 143 blocks old, is below the beacon price (B7)")

# ---- D23: the listing reader: tombstones and the per-host cap (finding 2) ---
def show_listings(records, tip, unit=UNIT_SIGNET):
    """discovery.md 5.2 and 5.3: returns the listing_ids shown, in order."""
    tomb, lst = set(), {}
    for kind, rec in records:
        r = read_tlv(rec)
        if kind == "w":
            dg = tagged_hash("gazpacho/withdrawal", rec[:-66])
            hgt = int.from_bytes(r[6], "big")
            if schnorr_verify(dg, r[2][1:], r[240]) and hgt <= tip + 6 and tip < hgt + 1_014:
                tomb.add((r[2], r[4]))
            continue
        dg = tagged_hash("gazpacho/listing", rec[:-66])
        if not schnorr_verify(dg, r[2][1:], r[240]):
            continue
        st, ex = int.from_bytes(r[6], "big"), int.from_bytes(r[8], "big")
        lid = tagged_hash("gazpacho/terms/outer", r[4])
        if not (st <= tip + 6 and st <= ex <= st + 1_008 and tip < ex):
            continue
        cur = lst.get((r[2], lid))
        if cur is None or (ex, dg) < (cur[1], cur[2]):
            lst[(r[2], lid)] = (st, ex, dg)
    shown = {}
    for (hk, lid), (st, ex, dg) in lst.items():
        if (hk, lid) in tomb:
            continue
        shown.setdefault(hk, []).append((st, lid))
    out = []
    for hk, v in shown.items():
        v.sort(key=lambda x: (-x[0], x[1]))            # latest start first
        out += [lid for _, lid in v[:4]]
    return out


L_T1 = ("l", listing)
W_T1 = ("w", withdrawal)
assert show_listings([L_T1, W_T1], TIP + 10) == []
assert show_listings([W_T1, L_T1], TIP + 10) == []
assert show_listings([L_T1], TIP + 10) == [outer_digest]
other_wd, _ = withdrawal_record(outer_digest, WD_HEIGHT, key=test_key("other host"))
assert show_listings([L_T1, ("w", other_wd)], TIP + 10) == [outer_digest]


def lobby_outer(i):
    recs = [x for x in outer_records if x[0] != 6] + [(6, hashlib.sha256(b"salt %d" % i).digest()[:16])]
    return tlv(sorted(recs))


def signed_listing(o, start, expiry):
    body = tlv([(2, host_pub), (4, o), (6, u32(start)), (8, u32(expiry))])
    dg = tagged_hash("gazpacho/listing", body)
    return body + tlv([(240, schnorr_sign(dg, host_sk, AUX))])


old = [("l", signed_listing(lobby_outer(i), TIP, TIP + 1_008)) for i in range(4)]
new_o = lobby_outer(9)
new = ("l", signed_listing(new_o, TIP + 100, TIP + 244))
seen_ids = show_listings(old + [new], TIP + 101)
assert tagged_hash("gazpacho/terms/outer", new_o) in seen_ids and len(seen_ids) == 4
tombs = [("w", withdrawal_record(tagged_hash("gazpacho/terms/outer", lobby_outer(i)), TIP + 50)[0])
         for i in range(4)]
assert show_listings(old + tombs + [new], TIP + 101) == [tagged_hash("gazpacho/terms/outer", new_o)]
print("\n== D23 (finding 2): D4 and D4w in either order: nothing shown; a withdrawal signed by"
      " another key: ignored. A replay of four old listings (start 290000) beside the host's new"
      " lobby (start 290100): the new lobby is shown (latest start wins the cap); with the four"
      " old lobbies' withdrawals: only the new lobby is shown")

# ---- D13: overlay_init, the lobby store flag ---------------------------------
oi_store = tlv([(2, chain), (4, u8(1))])
oi_relay = tlv([(2, chain), (4, u8(0))])
oi_client = tlv([(2, chain), (4, u8(0)), (5, u8(1))])
print(f"\n== D13: overlay_init (kind {K_OVERLAY_INIT}), sent once per connection before any beacon")
show(f"native overlay_init, store = 1 (kind {K_OVERLAY_INIT})", native(K_OVERLAY_INIT, oi_store))
show("overlay_init records, store = 0 (relay only)", oi_relay)
show("D13c overlay_init records, light client (store = 0, client = 1)", oi_client)

# ---- D14: pool_request ---------------------------------------------------------
PROFILE_BITS_STANDARD = 1 << (2 - 1)          # bit (profile - 1): Standard = bit 1
pr = tlv([(2, chain), (3, u8(PROFILE_BITS_STANDARD)), (5, rng(50_000, 200_000))])
pr_all = tlv([(2, chain)])
print(f"\n== D14: pool_request (kind {K_POOL_REQ}): Standard only, channel_sat 50000..200000")
show("pool_request records", pr)
show(f"native pool_request (kind {K_POOL_REQ})", native(K_POOL_REQ, pr))
show(f"onion payload field, pool_request (type {ON['pool_request']}, candidate)",
     onion_payload(ON["pool_request"], pr))
show("pool_request records, no filter (everything)", pr_all)
assert native(K_POOL_REQ, pr).endswith(pr) and onion_payload(ON["pool_request"], pr).endswith(pr)


def beacon_matches(rec: bytes, profiles=None, crange=None) -> bool:
    """discovery.md section 11.4: the pool filter. rec is a beacon's records."""
    r = read_tlv(rec)
    prof, chan = r[12][0], int.from_bytes(r[14], "big")
    if profiles is not None and not (profiles >> (prof - 1)) & 1:
        return False
    if crange is not None and not (crange[0] <= chan <= crange[1]):
        return False
    return True


assert beacon_matches(b1, PROFILE_BITS_STANDARD, (50_000, 200_000))
b_starter, _ = beacon(seq_of(TIP, 1), digest=hashlib.sha256(b"starter lobby").digest(), profile=3)
assert not beacon_matches(b_starter, PROFILE_BITS_STANDARD, (50_000, 200_000))
b_big, _ = beacon(seq_of(TIP, 2), digest=hashlib.sha256(b"big lobby").digest(), channel_sat=1_000_000)
assert not beacon_matches(b_big, PROFILE_BITS_STANDARD, (50_000, 200_000))
print("  filter check: D7 matches; a Starter beacon and a 1,000,000-sat beacon do not")

# ---- D15: pool answer -----------------------------------------------------------
pool = tlv([(2, chain), (4, u16(len(b1)) + b1)])
print(f"\n== D15: pool (kind {K_POOL}) answering D14 with the one matching beacon, D7; no 'next' record")
show("pool records", pool)
print(f"native pool {len(native(K_POOL, pool))} bytes; onion payload field "
      f"{len(onion_payload(ON['pool'], pool))} bytes")
per_entry = 2 + len(b1)
print(f"  one entry = {per_entry} bytes; a 30,000-byte onion page holds {(30_000 - 34 - 4 - 35 - 10) // per_entry}"
      f" beacons; a 60,000-byte native page {(60_000 - 34 - 4 - 35 - 10) // per_entry};"
      f" a 1,366-byte onion holds {(1_100 - 34 - 4 - 35 - 10) // per_entry}")
tok = hashlib.sha256(b"gazpacho test pool token").digest()[:8]
pr_next = tlv([(2, chain), (7, host_pub + u32(S1)), (9, tok)])
print("== D15b: a continuation pool_request: after = test host key and D7 sequence, token = sha256('gazpacho test pool token')[0:8]")
show("pool_request records (continuation)", pr_next)
pr_scout = tlv([(2, chain), (7, host_pub + u32(0)), (11, u16(64))])
print("== D15c: a scout pool_request: a new request with after (test host key, 0) and max_entries 64, no token")
show("pool_request records (scout)", pr_scout)

# ---- D24: back-dated sequences and orphan tombstones (draft 3 review N4) ---
GRAPH1 = {host_pub: (10_000, 1_008)}       # allowance 1 on signet
T_LATE = TIP + 1_000
r24 = Reader(T_LATE, GRAPH1)
res24 = []
BACK = [beacon(seq_of(TIP + 18 * i), digest=hashlib.sha256(b"back %d" % i).digest(),
               open_h=TIP, deadline_h=TIP + 1_008)[0] for i in range(56)]
for rec in BACK:
    res24.append(r24.offer(rec))
assert len(r24.relayed) <= 8 and res24.count("ignore:B9") >= 48
r24t = Reader(T_LATE, GRAPH1)
TOMBS = [beacon(seq_of(TIP + 18 * i), digest=hashlib.sha256(b"tomb %d" % i).digest(),
                open_h=TIP, deadline_h=TIP)[0] for i in range(56)]
for rec in TOMBS:
    r24t.offer(rec, from_pool=True)            # asked-for page: no arrival cap; B9 a and B10 still apply
assert len(r24t.tombs(host_pub)) <= 1 + 4
r24r = Reader(T_LATE, GRAPH1)
for rec in TOMBS:
    r24r.offer(rec)
assert len(r24r.relayed) <= 8
print(f"\n== D24 (review 2, N4): one host with allowance 1, 56 beacons back-dated one every 18 blocks,"
      f" offered at tip {T_LATE}: {len(r24.relayed)} relayed (draft 3: 56). 56 withdrawals for unknown"
      f" lobbies: {len(r24r.relayed)} relayed; from asked-for pool pages, {len(r24t.tombs(host_pub))}"
      " tombstones held (allowance + 4)")

# ---- D25: a node behind the tip gets the beacon again (N7) ------------------
ra, rb, rc = Reader(TIP, GRAPH), Reader(TIP - 10, GRAPH), Reader(TIP, GRAPH)
assert ra.offer(b1) == "held"
k_ab, k_bc = set(), set()
assert relay_to(ra, rb, k_ab) == ["pending"]
assert relay_to(ra, rb, k_ab) == []           # RL2: never sent twice on one link
assert relay_to(rb, rc, k_bc) == []           # pending beacons are not relayed
assert rb.set_tip(TIP) == ["held"]            # R-P2: re-offered on a new block
assert relay_to(rb, rc, k_bc) == ["held"]
print("== D25 (review 2, N7): D7 reaches a node 10 blocks behind: held pending, not relayed, never"
      " resent on that link; at the next block it is accepted from the pending pool and relayed on")

# ---- D26: pool paging, scouts, tokens, tombstone filter (N2, N4) -----------
keys26 = [test_key("pool host %d" % i) for i in range(6)]
graph26 = {compressed(k): (100_000, 1_008) for k in keys26}
r26 = Reader(TIP + 10, graph26)
for i, k in enumerate(keys26):
    d_live = hashlib.sha256(b"p live %d" % i).digest()
    d_gone = hashlib.sha256(b"p gone %d" % i).digest()
    prof = 3 if i == 0 else 2
    assert r26.offer(beacon(seq_of(TIP, 0), digest=d_live, key=k, profile=prof)[0], from_pool=True) == "held"
    assert r26.offer(beacon(seq_of(TIP + 1, 0), digest=d_gone, key=k, open_h=TIP, deadline_h=TIP,
                            profile=prof)[0], from_pool=True) == "tombstone"
srv = PoolServer(r26)
mid = (sorted(compressed(k) for k in keys26)[2], 0)
scout = srv.answer("scout", 0, after=mid, max_entries=4)
assert scout != "dropped" and len(scout[0]) == 4                    # N2: a scout's random `after`
got, after, token, now = [], None, None, 0
while True:
    ans = srv.answer("c1", now, after=after, token=token, max_entries=5)
    assert ans != "dropped"
    page, after, token = ans
    got += page
    now += 10
    if after is None:
        break
assert len(got) == 12 and len(set(got)) == 12                     # every entry once, hosts split across pages
again = srv.answer("c2", 0, max_entries=5)
assert srv.answer("c2", 5, after=again[1], token=again[2], max_entries=5) != "dropped"
assert srv.answer("c2", 6, after=again[1], token=again[2], max_entries=5) == "dropped"   # one use
late = srv.answer("c3", 0, max_entries=5)
assert srv.answer("c3", 61, after=late[1], token=late[2]) == "dropped"                 # 60 s
assert srv.answer("c1", 100) == "dropped"                                              # one new an hour
std = PoolServer(r26).answer("c4", 0, profiles=PROFILE_BITS_STANDARD)
assert len(std[0]) == 10                                            # tombstones are filtered too
print("== D26 (review 2, N2, N4): 6 hosts, each 1 live beacon and 1 tombstone: a scout's new request"
      " with a random `after` and no token is answered; paging 5 at a time returns all 12 entries once,"
      " splitting hosts across pages; a reused token, a token older than 60 s, and a second new"
      " request within the hour are dropped; a Standard-only filter drops the Starter host's beacon"
      " and its tombstone")

# ---- D27: Tor budgets per connection, served in turn (N1) --------------------
def tor_budget(per_connection, seconds=30):
    """H2 for Tor: 8 lobby_index_requests per 10 s in total. Draft 3 shared one
    budget first come, first served; draft 4 serves connections in turn, at
    most 1 per connection per 10 s. One attacker sends 10 a second from t = 0;
    one honest wallet asks once at t = 0.5. Returns the time it is answered."""
    queue = []
    for t10 in range(seconds * 10):
        t = t10 / 10
        queue.append(("attacker", t))
        if t10 == 50:
            queue.append(("honest", t))
    served, used, last = None, {}, {}
    for w in range(0, seconds, 10):
        budget = 8
        waiting = [q for q in queue if q[1] < w + 10 and q not in used]
        if per_connection:
            order, seenc = [], set()
            for q in waiting:
                if q[0] not in seenc and last.get(q[0], -99) <= w - 10:
                    order.append(q)
                    seenc.add(q[0])
        else:
            order = waiting
        for q in order[:budget]:
            used[q] = True
            last[q[0]] = w
            if q[0] == "honest":
                served = max(q[1], w)
        if served is not None:
            return served
    return None


assert tor_budget(False) is None
assert tor_budget(True) is not None and tor_budget(True) <= 30
print("== D27 (review 2, N1): one Tor attacker at 10 index requests a second and one honest Tor"
      " wallet: draft 3's shared Tor budget never answers the wallet in 30 s; draft 4 answers it"
      f" at t = {tor_budget(True)} s")

# ---- D28: pending pool against junk (confirmation review E1) ---------------
r28 = Reader(TIP, {host_pub: (100_000, 1_008), compressed(test_key("unpriced")): (2_499, 1_008)})
honest_ahead, _ = beacon(seq_of(TIP + 10), open_h=TIP + 10, deadline_h=TIP + 154)
assert r28.offer(honest_ahead, "good") == "pending"
junk_key = test_key("junk host")
for j in range(9):
    for n in range(8):
        rec, _ = beacon(seq_of(TIP + 10), digest=hashlib.sha256(b"junk %d %d" % (j, n)).digest(),
                        open_h=TIP + 10, deadline_h=TIP + 154, key=junk_key)
        assert r28.offer(rec, "j%d" % j) == "pending"
assert len(r28.pending) == 64
assert tagged_hash("gazpacho/beacon", honest_ahead[:-66]) in r28.pending_ids()
unpriced, _ = beacon(seq_of(TIP + 10), open_h=TIP + 10, deadline_h=TIP + 154, key=test_key("unpriced"))
assert r28.offer(unpriced, "j0") == "ignore:B7"
r28s = Reader(TIP, GRAPH)
r28s.synced = True
far, _ = beacon(seq_of(TIP + 100), open_h=TIP + 100, deadline_h=TIP + 244)
assert r28s.offer(far, "j0") == "ignore:B6"
print("\n== D28 (confirmation review E1): one honest beacon 10 blocks ahead from link 'good', then 72 junk"
      " beacons from an unknown host over 9 links: the pending pool holds 64 and the honest beacon"
      " survives (eviction from the link holding most); a priced-out known host is ignored at B7"
      " before pending; a synced node does not hold a beacon 100 blocks ahead")

# ---- D29: pool pages are not relayed past the arrival cap (E2) -------------
r29 = Reader(T_LATE, GRAPH1)
for rec in BACK:
    r29.offer(rec, from_pool=True)
assert len(r29.relayed) <= 8 and len(r29.live(host_pub)) == 1
assert len(r24t.relayed) <= 8
print("== D29 (E2): the 56 back-dated beacons of D24 arriving in an asked-for pool page: accepted"
      f" (the newest held), {len(r29.relayed)} relayed (draft 4: 56); the 56 orphan withdrawals:"
      f" {len(r24t.relayed)} relayed, {len(r24t.tombs(host_pub))} held")

# ---- D30: tombstones of beacons this node held are never evicted (E3) ------
r30 = Reader(TIP, GRAPH1)
OPENED = []
for day in range(6):
    hgt = TIP + 144 * day
    r30.tip = hgt + 1
    d30 = hashlib.sha256(b"daily lobby %d" % day).digest()
    live30, _ = beacon(seq_of(hgt, 0), digest=d30, open_h=hgt, deadline_h=hgt + 1_008)
    gone30, _ = beacon(seq_of(hgt + 1, 0), digest=d30, open_h=hgt, deadline_h=hgt)
    assert r30.offer(live30) == "held"
    assert r30.offer(gone30) == "tombstone"
    OPENED.append(live30)
assert len(r30.tombs(host_pub)) == 6
assert r30.offer(OPENED[0]) == "ignore:dup"
r30.seen.clear()
assert r30.offer(OPENED[0]) == "ignore:B8a"
print("== D30 (E3): a host with allowance 1 opens and withdraws one lobby a day for 6 days: all 6"
      " tombstones are kept (they withdraw beacons this node held), and day 1's beacon offered"
      " again, even after the seen-set lost it, is ignored by its tombstone")

# ---- D16: listing_not_held ---------------------------------------------------------
nh = tlv([(2, chain), (4, outer_digest)])
print(f"\n== D16: listing_not_held (kind {K_NOT_HELD}): a store peer does not hold T1's listing")
show(f"native listing_not_held (kind {K_NOT_HELD})", native(K_NOT_HELD, nh))

# ---- D17: two valid beacons, one host, one sequence, run in both orders ----
bx, bx_id = beacon(S1, digest=hashlib.sha256(b"lobby 2").digest())
keep = min(b1_id, bx_id)
for first, second in ((b1, bx), (bx, b1)):
    rr = Reader(TIP, GRAPH)
    rr.offer(first)
    rr.offer(second)
    kept = [v[1] for v in rr.held.values()]
    assert kept == [keep]
print("\n== D17 (run in both orders): D7 and a beacon for lobby sha256('lobby 2'), both sequence", S1)
print("  other beacon_id =", bx_id.hex())
print("  kept everywhere (lower beacon_id):", "D7" if keep == b1_id else "the other", keep.hex())


# ---- D18: orphan pool bounds -------------------------------------------------
def orphan_pool(arrivals, per_link=8, total=64):
    """discovery.md section 8.4. arrivals: list of (time_s, link). Returns the
    pool as {link: [times]} after eviction (oldest from the link holding most)."""
    pool = {}
    for t, link in arrivals:
        pool = {l: [x for x in ts if t - x < 1_200] for l, ts in pool.items()}   # 20 minutes
        pool.setdefault(link, []).append(t)
        if len(pool[link]) > per_link:
            pool[link].pop(0)
        while sum(len(v) for v in pool.values()) > total:
            worst = max(pool, key=lambda l: (len(pool[l]), -min(pool[l])))
            pool[worst].pop(0)
    return pool


p = orphan_pool([(i, "a") for i in range(10)])
assert len(p["a"]) == 8 and p["a"][0] == 2
p = orphan_pool([(i, l) for i, l in enumerate([f"l{k}" for k in range(9) for _ in range(8)])])
assert sum(len(v) for v in p.values()) == 64
p20 = orphan_pool([(0, "a"), (1_199, "b"), (1_200, "b")])
assert "a" not in p20 or p20["a"] == []
print("\n== D18: orphan pool: 10 orphans on one link keep the last 8; 72 orphans over 9 links keep 64;"
      " an orphan 20 minutes old is gone")

# ---- D19: host_list_request naming keys ---------------------------------------
hlr = tlv([(2, chain), (5, host_pub)])
print(f"\n== D19: host_list_request (kind {K_HL_REQ}) asking only for the test host")
show(f"native host_list_request (kind {K_HL_REQ})", native(K_HL_REQ, hlr))


# ===================================================== storage-encryption.md =====
# Section E, draft 2 (2026-11-12). Storage encryption: the passphrase key (Argon2id,
# RFC 9106), subkeys (HKDF-SHA256, RFC 5869), XChaCha20-Poly1305 (RFC 8439 with
# draft-irtf-cfrg-xchacha-03) with hedged nonces, the key file, the encrypted journal,
# the guard file and the export. Neither Argon2id nor XChaCha20-Poly1305 is in the
# Python standard library, so both are written out below from their specifications
# and checked against the published vectors (E0) before anything is printed. Like the
# BIP 340 code above they are slow, NOT constant time, and for vectors only. The
# implementation uses libsodium; its results must equal these (storage-encryption.md
# section 15). E2r, at the real parameters, runs only with --slow (about 30 minutes).
import hmac
import struct
import sys
import unicodedata

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1


# ------------------------------------------------ ChaCha20, RFC 8439 ---------
def _rotl32(v, c):
    return ((v << c) & M32) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl32(s[b] ^ s[c], 7)


def _rounds(s):
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)


_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def chacha20_block(key, counter, nonce12):
    init = list(_SIGMA) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce12))
    s = init[:]
    _rounds(s)
    return struct.pack("<16I", *[(s[i] + init[i]) & M32 for i in range(16)])


def chacha20_xor(key, counter, nonce12, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce12)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def hchacha20(key, nonce16):
    s = list(_SIGMA) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    _rounds(s)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def poly1305(key32, msg):
    r = int.from_bytes(key32[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def aead_chacha20_poly1305_encrypt(key, nonce12, pt, ad):
    otk = chacha20_block(key, 0, nonce12)[:32]
    ct = chacha20_xor(key, 1, nonce12, pt)
    mac = ad + _pad16(ad) + ct + _pad16(ct) + struct.pack("<QQ", len(ad), len(ct))
    return ct + poly1305(otk, mac)


def aead_chacha20_poly1305_decrypt(key, nonce12, ct_tag, ad):
    if len(ct_tag) < 16:
        return None
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    otk = chacha20_block(key, 0, nonce12)[:32]
    mac = ad + _pad16(ad) + ct + _pad16(ct) + struct.pack("<QQ", len(ad), len(ct))
    if not hmac.compare_digest(poly1305(otk, mac), tag):
        return None
    return chacha20_xor(key, 1, nonce12, ct)


def xchacha_encrypt(key, nonce24, pt, ad):
    """AEAD_XChaCha20_Poly1305, draft-irtf-cfrg-xchacha-03 section 2.3; libsodium
    crypto_aead_xchacha20poly1305_ietf_encrypt. Returns ciphertext || tag."""
    return aead_chacha20_poly1305_encrypt(hchacha20(key, nonce24[:16]), b"\x00" * 4 + nonce24[16:], pt, ad)


def xchacha_decrypt(key, nonce24, ct_tag, ad):
    return aead_chacha20_poly1305_decrypt(hchacha20(key, nonce24[:16]), b"\x00" * 4 + nonce24[16:], ct_tag, ad)


# ------------------------------------------------ Argon2id, RFC 9106 ---------
def _blake2b(data, n):
    return hashlib.blake2b(data, digest_size=n).digest()


def _hprime(data, t):
    """RFC 9106 section 3.3, H'^T."""
    x = struct.pack("<I", t) + data
    if t <= 64:
        return _blake2b(x, t)
    r = (t + 31) // 32 - 2
    v = _blake2b(x, 64)
    out = v[:32]
    for _ in range(r - 1):
        v = _blake2b(v, 64)
        out += v[:32]
    return out + _blake2b(v, t - 32 * r)


def _gb(v, a, b, c, d):
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & M32) * (vb & M32)) & M64
    vd ^= va; vd = ((vd >> 32) | (vd << 32)) & M64
    vc = (vc + vd + 2 * (vc & M32) * (vd & M32)) & M64
    vb ^= vc; vb = ((vb >> 24) | (vb << 40)) & M64
    va = (va + vb + 2 * (va & M32) * (vb & M32)) & M64
    vd ^= va; vd = ((vd >> 16) | (vd << 48)) & M64
    vc = (vc + vd + 2 * (vc & M32) * (vd & M32)) & M64
    vb ^= vc; vb = ((vb >> 63) | (vb << 1)) & M64
    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _perm(v, idx):
    w = [v[i] for i in idx]
    _gb(w, 0, 4, 8, 12); _gb(w, 1, 5, 9, 13); _gb(w, 2, 6, 10, 14); _gb(w, 3, 7, 11, 15)
    _gb(w, 0, 5, 10, 15); _gb(w, 1, 6, 11, 12); _gb(w, 2, 7, 8, 13); _gb(w, 3, 4, 9, 14)
    for k, i in enumerate(idx):
        v[i] = w[k]


_ROWS = [list(range(16 * i, 16 * i + 16)) for i in range(8)]
_COLS = [[2 * i + 16 * j + k for j in range(8) for k in (0, 1)] for i in range(8)]


def _g(x, y):
    """RFC 9106 section 3.5, compression function G on 128-word blocks."""
    r = [a ^ b for a, b in zip(x, y)]
    q = r[:]
    for idx in _ROWS:
        _perm(q, idx)
    for idx in _COLS:
        _perm(q, idx)
    return [a ^ b for a, b in zip(q, r)]


_U = struct.Struct("<128Q")
_u = _U.unpack
def _pk(w):
    return _U.pack(*w)


def _words(b):
    return list(struct.unpack("<128Q", b))


def argon2id(password, salt, t, m_kib, p, taglen, secret=b"", ad=b""):
    """Argon2id version 0x13 (RFC 9106). For vectors only: slow, not constant time."""
    y, ver = 2, 0x13
    h0 = _blake2b(struct.pack("<6I", p, taglen, m_kib, t, ver, y)
                  + struct.pack("<I", len(password)) + password
                  + struct.pack("<I", len(salt)) + salt
                  + struct.pack("<I", len(secret)) + secret
                  + struct.pack("<I", len(ad)) + ad, 64)
    mp = 4 * p * (m_kib // (4 * p))
    q = mp // p
    sl = q // 4
    B = [[None] * q for _ in range(p)]
    for l in range(p):
        B[l][0] = _hprime(h0 + struct.pack("<II", 0, l), 1024)
        B[l][1] = _hprime(h0 + struct.pack("<II", 1, l), 1024)
    zero = [0] * 128
    for r in range(t):
        for s in range(4):
            for l in range(p):
                indep = (r == 0 and s < 2)
                addr, counter = None, 0
                start = 2 if (r == 0 and s == 0) else 0
                for i in range(start, sl):
                    if indep and (addr is None or i % 128 == 0):
                        counter += 1
                        z = [r, l, s, mp, t, y, counter] + [0] * 121
                        addr = _g(zero, _g(zero, z))
                    col = s * sl + i
                    prev = col - 1 if col > 0 else q - 1
                    rnd = addr[i % 128] if indep else struct.unpack_from("<Q", B[l][prev])[0]
                    j1, j2 = rnd & M32, rnd >> 32
                    lr = l if (r == 0 and s == 0) else j2 % p
                    if lr == l:
                        w = (s * sl + i - 1) if r == 0 else (q - sl + i - 1)
                    else:
                        w = (s * sl if r == 0 else q - sl) - (1 if i == 0 else 0)
                    x = (j1 * j1) >> 32
                    yy = (w * x) >> 32
                    zz = w - 1 - yy
                    startpos = 0 if (r == 0 or s == 3) else (s + 1) * sl
                    ref = (startpos + zz) % q
                    nb = _g(_u(B[l][prev]), _u(B[lr][ref]))
                    if r > 0:
                        nb = [a ^ b for a, b in zip(nb, _u(B[l][col]))]
                    B[l][col] = _pk(nb)
    c = _u(B[0][q - 1])
    for l in range(1, p):
        c = [a ^ b for a, b in zip(c, _u(B[l][q - 1]))]
    return _hprime(struct.pack("<128Q", *c), taglen)


# ------------------------------------------------ HKDF, RFC 5869 -------------
def hkdf_sha256(ikm, salt, info, n):
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]



# ---------------------------------------------------- E0: the primitives check ---
# Each primitive is checked against its published vector before anything is printed.
_k8439 = bytes(range(0x80, 0xa0))
_pt8439 = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
           b"for the future, sunscreen would be it.")
_ad8439 = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_o = aead_chacha20_poly1305_encrypt(_k8439, bytes.fromhex("070000004041424344454647"), _pt8439, _ad8439)
assert _o[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"            # RFC 8439 2.8.2
assert _o[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"
assert hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex() == (
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")  # xchacha-03 2.2.1
_o = xchacha_encrypt(_k8439, bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
                     _pt8439, _ad8439)
assert _o[-16:].hex() == "c0875924c1c7987947deafd8780acf49"            # xchacha-03 A.3.1
assert _o[:16].hex() == "bd6d179d3e83d43b9576579493c0e939"
assert xchacha_decrypt(_k8439, bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
                       _o, _ad8439) == _pt8439
assert hkdf_sha256(b"\x0b" * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42).hex() == (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")  # RFC 5869 A.1
assert argon2id(b"\x01" * 32, b"\x02" * 16, 3, 32, 4, 32, b"\x03" * 8, b"\x04" * 12).hex() == (
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")  # RFC 9106 5.3
print("\n== storage-encryption.md: vector E0, primitives checked against RFC 8439 2.8.2, "
      "draft-irtf-cfrg-xchacha-03 2.2.1 and A.3.1, RFC 5869 A.1, RFC 9106 5.3: all pass")


# ---------------------------------------------------- storage test values -------
# THESE ARE TEST VALUES, derived from public strings. Real files draw every salt,
# identifier, key and nonce input r from the operating system's random source.
# Draft 2: every sealing key has its own nonce key from the same input keying
# material under its own label (review F14); passphrase-derived wraps carry a key
# commitment (F12); the key file is 363 bytes and the export slot ends at 188.
def tv(label, n=32):
    return hashlib.sha256(b"gazpacho test " + label.encode()).digest()[:n]


HKDF_SALT = b"gazpacho/v1/storage"


def derive(ikm, label, ctx):
    """storage-encryption.md section 4.4: one 32-byte subkey per (label, context)."""
    return hkdf_sha256(ikm, HKDF_SALT, label.encode() + b"\x00" + ctx, 32)


def keys(ikm, label, ctx):
    """A sealing key and its nonce key (section 5.2): labels '<label>' and '<label> nonce'."""
    return derive(ikm, label, ctx), derive(ikm, label + " nonce", ctx)


def seal(kp, r, pt, ad):
    """Section 5.2: XChaCha20-Poly1305 with a hedged nonce (Bellare-Tackmann).
    r is 32 fresh random bytes. Returns nonce || ct || tag."""
    k, nk = kp
    n = hmac.new(nk, r + u32(len(ad)) + ad + pt, hashlib.sha256).digest()[:24]
    return n + xchacha_encrypt(k, n, pt, ad)


def sealed(kp, label, pt, ad):
    """seal() with the test input r = sha256('gazpacho test r: <label>')."""
    return seal(kp, tv("r: " + label), pt, ad)


def unseal(kp, data, ad):
    return xchacha_decrypt(kp[0], data[:24], data[24:], ad)


def commitment(pk, label, ctx, ad):
    """Section 4.6: key commitment of a passphrase-derived wrap (review F12)."""
    return hmac.new(derive(pk, label, ctx), ad, hashlib.sha256).digest()


KDF_CEIL_M = 4_194_304                       # KiB; the implementation also caps it (4.2)


def params_ok(alg, t, m, p, floor):
    return alg == 1 and p == 1 and floor[0] <= t <= 16 and floor[1] <= m <= KDF_CEIL_M


def nfc_utf8(s):
    return unicodedata.normalize("NFC", s).encode("utf-8")


PW1 = "gazpacho test passphrase, never for coins: caf\u00e9"
PW1_DECOMPOSED = "gazpacho test passphrase, never for coins: cafe\u0301"
PW2 = "gazpacho second test passphrase, never for coins"
assert PW1 != PW1_DECOMPOSED and nfc_utf8(PW1) == nfc_utf8(PW1_DECOMPOSED)
print("\n== vector E1, passphrase normalisation: NFC, then UTF-8. 'caf' + U+00E9 and 'cafe' + U+0301"
      " give the same bytes")
show("  passphrase bytes", nfc_utf8(PW1))

T_TEST, M_TEST = 3, 64                       # test parameters: 64 KiB, 3 passes, 1 lane
T_REAL, M_REAL = 3, 262_144                  # the default: 256 MiB, 3 passes, 1 lane
SALT1 = tv("kdf salt", 16)
SALT2 = tv("kdf salt 2", 16)
VAULT_ID = tv("vault id", 16)
FILE_ID = tv("journal file id", 16)
MSK = tv("storage key")
ENTROPY = tv("words entropy")                 # 32 bytes: 24 words
SEED64 = hashlib.sha512(b"gazpacho test bip39 seed").digest()   # stands for the BIP 39 seed

pk1 = argon2id(nfc_utf8(PW1), SALT1, T_TEST, M_TEST, 1, 32)
print(f"\n== vector E2, Argon2id v1.3, t = {T_TEST}, m = {M_TEST} KiB, p = 1, 32 bytes, no secret, no"
      " associated data. TEST PARAMETERS, below the floor: only the test entry point accepts them")
print("  salt = sha256('gazpacho test kdf salt')[0:16] =", SALT1.hex())
print("  passphrase key PK =", pk1.hex())
# E2r: the default parameters. The pure-Python Argon2id above needs about 30 minutes for
# them, so E2r runs only with --slow. E2R_EXPECTED was computed by this reference on
# 2026-11-12 and agrees with OpenSSL 3.5.5 (openssl kdf -keylen 32 -kdfopt hexpass:...
# -kdfopt hexsalt:... -kdfopt iter:3 -kdfopt memcost:262144 -kdfopt lanes:1 ARGON2ID) and
# Node 24's crypto.argon2Sync (built on OpenSSL). Still to be confirmed with libsodium
# crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13), the implementation's library.
E2R_EXPECTED = "acfe7a0e9b72c011d3382684f2b9b06a221f61aeb29fe3382299419b6433c945"
if "--slow" in sys.argv:
    _pkr = argon2id(nfc_utf8(PW1), SALT1, T_REAL, M_REAL, 1, 32)
    print(f"== vector E2r, the same passphrase and salt at t = {T_REAL}, m = {M_REAL} KiB, p = 1:", _pkr.hex())
    if E2R_EXPECTED is not None:
        assert _pkr.hex() == E2R_EXPECTED
else:
    print(f"== vector E2r (t = {T_REAL}, m = {M_REAL} KiB, p = 1, same passphrase and salt):",
          E2R_EXPECTED, "(recomputed only with --slow)")


# ---------------------------------------------------- the key file --------------
KF_MAGIC = b"GZKEYFIL"
KF_LEN = 363
FLOOR_TEST, FLOOR_RELEASE = (1, 8), (3, 65_536)


def key_file(pw, salt, t, m, msk, entropy, seed64, tag):
    head = KF_MAGIC + u8(1) + chain + VAULT_ID + u8(1) + u32(t) + u32(m) + u8(1) + salt
    assert len(head) == 83
    pk = argon2id(nfc_utf8(pw), salt, t, m, 1, 32)
    ctx = chain + VAULT_ID
    out = (head + commitment(pk, "key file commitment", ctx, head)
           + sealed(keys(pk, "key file wrap", ctx), "key file wrap " + tag, msk, head)
           + sealed(keys(pk, "words", ctx), "key file words " + tag, entropy, head)
           + sealed(keys(msk, "node seed", ctx), "key file seed", seed64, head[:57]))
    assert len(out) == KF_LEN
    return out


def kf_params(data):
    return data[57], int.from_bytes(data[58:62], "big"), int.from_bytes(data[62:66], "big"), data[66]


def open_key_file(data, pw, floor=FLOOR_TEST):
    """Section 4.5. Returns (msk, seed64) or the refusal. The words are opened separately (9)."""
    if len(data) != KF_LEN or data[:8] != KF_MAGIC or data[8] != 1:
        return "not a key file"
    if data[9:41] != chain:
        return "other network"
    alg, t, m, p = kf_params(data)
    if not params_ok(alg, t, m, p, floor):
        return "parameters refused"
    head, ctx = data[:83], chain + data[41:57]
    pk = argon2id(nfc_utf8(pw), data[67:83], t, m, 1, 32)
    if not hmac.compare_digest(commitment(pk, "key file commitment", ctx, head), data[83:115]):
        return "wrong passphrase or damaged key file"
    msk = unseal(keys(pk, "key file wrap", ctx), data[115:187], head)
    if msk is None:
        return "wrong passphrase or damaged key file"
    seed = unseal(keys(msk, "node seed", ctx), data[259:363], data[:57])
    if seed is None:
        return "damaged key file"
    return msk, seed


def open_words(data, pw):
    _, t, m, _ = kf_params(data)
    pk = argon2id(nfc_utf8(pw), data[67:83], t, m, 1, 32)
    ctx = chain + data[41:57]
    if not hmac.compare_digest(commitment(pk, "key file commitment", ctx, data[:83]), data[83:115]):
        return None
    return unseal(keys(pk, "words", ctx), data[187:259], data[:83])


kf1 = key_file(PW1, SALT1, T_TEST, M_TEST, MSK, ENTROPY, SEED64, "1")
_ctx_v = chain + VAULT_ID
print(f"\n== vector E3, key file keys.gzk ({KF_LEN} bytes), passphrase of E1, parameters and salt of E2")
print("  vault_id = sha256('gazpacho test vault id')[0:16] =", VAULT_ID.hex())
print("  storage key MSK = sha256('gazpacho test storage key') =", MSK.hex())
print("  words entropy = sha256('gazpacho test words entropy'); BIP 39 seed stand-in = sha512('gazpacho test bip39 seed')")
print("  nonce inputs r = sha256('gazpacho test r: <label>'), labels 'key file wrap 1', 'key file words 1', 'key file seed'")
print("  commitment key =", derive(pk1, "key file commitment", _ctx_v).hex())
print("  wrap key KW    =", derive(pk1, "key file wrap", _ctx_v).hex())
print("  words key KD   =", derive(pk1, "words", _ctx_v).hex())
print("  seed key KS    =", derive(MSK, "node seed", _ctx_v).hex())
show("key file", kf1)
assert open_key_file(kf1, PW1) == (MSK, SEED64)
assert open_key_file(kf1, PW1_DECOMPOSED) == (MSK, SEED64)
assert open_words(kf1, PW1) == ENTROPY

# E4: refusals.
assert open_key_file(kf1, PW1 + " ") == "wrong passphrase or damaged key file"
_bad = bytearray(kf1); _bad[65] ^= 0x01                     # m: 64 -> 65 KiB
assert open_key_file(bytes(_bad), PW1) == "wrong passphrase or damaged key file"
_bad = bytearray(kf1); _bad[61] = 1                          # t: 3 -> 1
assert open_key_file(bytes(_bad), PW1) == "wrong passphrase or damaged key file"
_bad = bytearray(kf1); _bad[90] ^= 0x01                      # the key commitment
assert open_key_file(bytes(_bad), PW1) == "wrong passphrase or damaged key file"
_bad = bytearray(kf1); _bad[150] ^= 0x01                     # the wrapped MSK
assert open_key_file(bytes(_bad), PW1) == "wrong passphrase or damaged key file"
_bad = bytearray(kf1); _bad[330] ^= 0x80                     # seed ciphertext
assert open_key_file(bytes(_bad), PW1) == "damaged key file"
_bad = bytearray(kf1); _bad[9] ^= 0x01                       # chain
assert open_key_file(bytes(_bad), PW1) == "other network"
assert open_key_file(kf1, PW1, floor=FLOOR_RELEASE) == "parameters refused"
_bad = bytearray(kf1); _bad[62:66] = u32(KDF_CEIL_M + 1)     # above the ceiling: refused before deriving
assert open_key_file(bytes(_bad), PW1) == "parameters refused"
print("== vector E4 (refuse): E3 opened with the passphrase plus a space; with m changed to 65 KiB; with t"
      " changed to 1; with a bit of the key commitment or of the wrapped MSK flipped; with a bit of the seed"
      " ciphertext flipped (damaged key file); with the chain changed; under the release floor (t >= 3,"
      " m >= 65536 KiB); with m above the ceiling (refused before any derivation)")

# ---------------------------------------------------- the journal ---------------
JE_MAGIC = b"GZJOURNE"
JE_HEADER_LEN = 185
KJ = keys(MSK, "journal", chain + FILE_ID)
KR = keys(SEED64, "journal recovery", chain + FILE_ID)


def ejournal_header(msk, seed64, file_id):
    jh = JE_MAGIC + u8(1) + chain + VAULT_ID + file_id
    pre = jh + sealed(keys(seed64, "journal recovery", chain + file_id), "journal recovery", msk, jh)
    out = pre + sealed(keys(msk, "journal", chain + file_id), "journal header", b"", pre)
    assert len(out) == JE_HEADER_LEN
    return out


ehdr = ejournal_header(MSK, SEED64, FILE_ID)
print(f"\n== vector E5, encrypted journal header ({JE_HEADER_LEN} bytes), file_id = sha256('gazpacho test journal file id')[0:16]")
print("  journal key KJ  =", KJ[0].hex(), " nonce key", KJ[1].hex())
print("  recovery key KR =", KR[0].hex(), "(from the BIP 39 seed)")
show("header", ehdr)


def check_header(data, msk=None, seed64=None):
    """Section 5.3. With msk: the key file's storage key. With seed64 only: recovery by the words."""
    if data[:8] != JE_MAGIC or data[8] != 1:
        return "not a journal"
    if data[9:41] != chain:
        return "other network"
    jh, fid = data[:73], data[57:73]
    if msk is None:
        msk = unseal(keys(seed64, "journal recovery", chain + fid), data[73:145], jh)
        if msk is None:
            return "not this wallet's journal"
    if unseal(keys(msk, "journal", chain + fid), data[145:185], data[:145]) != b"":
        return "not this wallet's journal"
    return msk


assert check_header(ehdr, msk=MSK) == MSK
assert check_header(ehdr, seed64=SEED64) == MSK
assert check_header(ehdr, msk=tv("other storage key")) == "not this wallet's journal"
_bad = bytearray(ehdr); _bad[50] ^= 1                                  # vault_id
assert check_header(bytes(_bad), msk=MSK) == "not this wallet's journal"
_bad = bytearray(ehdr); _bad[9] ^= 1                                   # chain
assert check_header(bytes(_bad), msk=MSK) == "other network"


def eentry(kind, inc, seq, payload, offset, label, kj=KJ, file_id=FILE_ID):
    head = u32(57 + len(payload)) + u8(kind) + u64(inc) + u64(seq)
    return head + sealed(kj, label, payload, file_id + u64(offset) + head)


off_inc = JE_HEADER_LEN
e_inc = eentry(1, 1, 0, u64(1_794_000_000_000), off_inc, "entry incarnation 1")
off_m1 = off_inc + len(e_inc)
e_m1 = eentry(3, 1, 0, u64(off_m1), off_m1, "entry mark 1")
off_b = off_m1 + len(e_m1)
PING = u32(1) + u32(0x7e570001) + u32(4) + b"ping"
e_b = eentry(2, 1, 1, PING, off_b, "entry batch 1 1")
off_m2 = off_b + len(e_b)
e_m2 = eentry(3, 1, 0, u64(off_m2), off_m2, "entry mark 2")
assert (len(e_inc), len(e_m1), len(e_b), len(e_m2)) == (69, 69, 77, 69)
print(f"== vector E6, encrypted entries after E5: incarnation 1 (clock 1794000000000 ms) at {off_inc}; sync"
      f" mark at {off_m1}; batch (1,1) with one record of type 0x7e570001 and bytes 'ping' at {off_b}; sync"
      f" mark at {off_m2}. Nonce input labels 'entry incarnation 1', 'entry mark 1', 'entry batch 1 1',"
      " 'entry mark 2'")
show("E6a incarnation entry", e_inc)
show("E6b sync mark", e_m1)
show("E6c batch entry", e_b)
show("E6d sync mark", e_m2)
EJ_GOOD = ehdr + e_inc + e_m1 + e_b + e_m2


def read_ejournal(data, kj=KJ, file_id=FILE_ID):
    """journal.md section 5 steps 3 and 4 over encrypted entries (section 5.5 here).
    Returns (state, V, offset of the last valid sync mark, [(kind, inc, seq, payload)])."""
    def valid_at(p):
        if p + 4 > len(data):
            return None
        ln = int.from_bytes(data[p:p + 4], "big")
        if ln < 61 or ln > 8_388_665 or p + 4 + ln > len(data):
            return None
        kind = data[p + 4]
        if kind not in (1, 2, 3) or (kind in (1, 3) and ln != 65):
            return None
        head = data[p:p + 21]
        pt = unseal(kj, data[p + 21:p + 4 + ln], file_id + u64(p) + head)
        if pt is None or (kind == 3 and int.from_bytes(pt, "big") != p):
            return None
        return p + 4 + ln, kind, int.from_bytes(head[5:13], "big"), int.from_bytes(head[13:21], "big"), pt
    pos, last_mark, got = JE_HEADER_LEN, None, []
    while pos < len(data):
        r = valid_at(pos)
        if r is None:
            break
        if r[1] == 3:
            last_mark = pos
        got.append(r[1:])
        pos = r[0]
    if pos == len(data):
        return "clean", pos, last_mark, got
    for p in range(pos + 1, len(data) - 68):
        if data[p:p + 5] == u32(65) + u8(3) and valid_at(p):
            return "corrupt", pos, last_mark, got
    return "torn", pos, last_mark, got


st = read_ejournal(EJ_GOOD)
assert st[0] == "clean" and st[2] == off_m2 and [g[0] for g in st[3]] == [1, 3, 2, 3]
assert st[3][2][3] == PING
MARKS_GOOD = [off_m1, off_m2]

# E7: tampering.
_t = bytearray(EJ_GOOD); _t[off_b + 50] ^= 0x01                         # a bit of the batch ciphertext
assert read_ejournal(bytes(_t))[:2] == ("corrupt", off_b)
_t = bytearray(EJ_GOOD); _t[off_b + 10] ^= 0x01                         # the batch's clear incarnation
assert read_ejournal(bytes(_t))[:2] == ("corrupt", off_b)
_e7c = read_ejournal(EJ_GOOD + e_b)                                      # the batch appended again
assert _e7c[:2] == ("torn", len(EJ_GOOD)) and len(_e7c[3]) == 4
_ofid = tv("other journal file id", 16)
_spliced = eentry(2, 1, 1, PING, off_b, "other", kj=keys(MSK, "journal", chain + _ofid), file_id=_ofid)
assert read_ejournal(ehdr + e_inc + e_m1 + _spliced + e_m2)[:2] == ("corrupt", off_b)
_swap = read_ejournal(ehdr + e_inc + e_m1 + e_m2 + e_b)                 # two entries swapped
assert _swap[1] == off_b and len(_swap[3]) == 2
_e7g = read_ejournal(EJ_GOOD[:-3])
assert _e7g[:2] == ("torn", off_m2)
_e7h = read_ejournal(EJ_GOOD[:off_b])                                    # cut at an entry boundary
assert _e7h[0] == "clean" and _e7h[2] == off_m1
_t = bytearray(EJ_GOOD); _t[off_b + 50] ^= 0x01; _t[off_m2 + 50] ^= 0x01   # F25: corruption made to look torn
_e7i = read_ejournal(bytes(_t))
assert _e7i[:2] == ("torn", off_b)
print(f"== vector E7 (tampering), each applied to the {len(EJ_GOOD)} bytes of E5 + E6:")
print(f"  E7a one bit of the batch ciphertext flipped: invalid at {off_b}, a sync mark follows: corruption, refused")
print(f"  E7b one bit of the batch's clear incarnation field flipped: the same")
print(f"  E7c the batch entry appended again at {len(EJ_GOOD)}: invalid there (its offset is in the associated"
      " data); no mark follows: cut as a torn tail; never read as a batch")
print(f"  E7d the batch replaced by one from another journal file under the same storage key: corruption at {off_b}")
print(f"  E7e the batch and the second mark swapped: invalid at {off_b}; nothing after it is read")
print(f"  E7f the last 3 bytes missing: torn tail, cut to {off_m2}")
print(f"  E7g the file cut at {off_b}, an entry boundary: reads as a clean, shorter journal whose last mark is"
      f" at {off_m1}. Only the guard's high-water mark (E9) shows it")
print(f"  E7h the batch and every later sync mark damaged: reads as a torn tail at {off_b}, like E7g;"
      " caught only by the high-water mark (review F25)")

# ---------------------------------------------------- passphrase change ---------
kf2 = key_file(PW2, SALT2, T_TEST, M_TEST, MSK, ENTROPY, SEED64, "2")
assert kf2[259:] == kf1[259:]                 # the seed part is copied unchanged
assert kf2[:67] == kf1[:67]                   # same vault, same parameters
assert open_key_file(kf2, PW2) == (MSK, SEED64) and open_words(kf2, PW2) == ENTROPY
assert open_key_file(kf2, PW1) == "wrong passphrase or damaged key file"
assert open_key_file(kf1, PW1) == (MSK, SEED64)   # an old copy still opens with the old passphrase
assert check_header(ehdr, msk=open_key_file(kf2, PW2)[0]) == MSK
print("\n== vector E8, passphrase change to '" + PW2 + "', salt sha256('gazpacho test kdf salt 2')[0:16],"
      " labels 'key file wrap 2' and 'key file words 2': the same storage key rewrapped; bytes 259 to 362"
      " (the seed) unchanged; the journal untouched; the old key file still opens with the old passphrase")
show("new key file", kf2)

# ---------------------------------------------------- the guard file ------------
KG = keys(SEED64, "guard", chain)
GUARD_PLAIN = u64(3) + u16(1) + u32(0) + u32(2) + u64(1) + FILE_ID + u64(1) + u64(off_m2)
_gh = b"GZGUARDE" + u8(1) + chain
e_guard = _gh + sealed(KG, "guard", GUARD_PLAIN, _gh)
print("\n== vector E9, encrypted guard file guard.gzg: counter 3; one epoch, 0, highest index 2; one round"
      f" started; high-water mark: file_id of E5, incarnation 1, last sync mark at {off_m2}")
print("  guard key KG =", KG[0].hex(), "(from the BIP 39 seed)")
show("guard file", e_guard)
_gp = unseal(KG, e_guard[41:], e_guard[:41])
assert _gp == GUARD_PLAIN


def behind_guard(journal_state, guard_plain):
    """Section 6.3 step 2, the mark test: the guard's mark must be a valid sync mark of the journal."""
    mark = int.from_bytes(guard_plain[-8:], "big")
    marks = [o for o, g in zip(_offsets(journal_state), journal_state[3]) if g[0] == 3]
    return guard_plain[-32:-16] != FILE_ID or mark not in marks


def _offsets(state):
    out, p = [], JE_HEADER_LEN
    for k, inc, seq, pt in state[3]:
        out.append(p)
        p += 4 + 57 + len(pt)
    return out


assert behind_guard(_e7h, _gp) and behind_guard(_e7i, _gp) and not behind_guard(st, _gp)
print(f"  against E7g (last mark {_e7h[2]}) and E7h the guard's mark {off_m2} is not a sync mark of the journal:"
      " the start is refused as a rolled-back journal (section 6.3); against E6 it passes")

# ---------------------------------------------------- the export ----------------
BK = derive(SEED64, "backup", chain)
EXPORT_ID = tv("export id", 16)
EK = keys(BK, "export", chain + EXPORT_ID)
SALT_X = tv("export kdf salt", 16)
EX_SLOT_END = 58 + 26 + 32 + 72               # 188


def export_file(profile, body, chunk, pw=None):
    head = b"GZBACKUP" + u8(1) + u8(profile) + chain + EXPORT_ID
    if profile == 1:
        slot = u8(1) + u32(T_TEST) + u32(M_TEST) + u8(1) + SALT_X
        pkx = argon2id(nfc_utf8(pw), SALT_X, T_TEST, M_TEST, 1, 32)
        ctx = chain + EXPORT_ID
        prefix = (head + slot + commitment(pkx, "backup commitment", ctx, head + slot)
                  + sealed(keys(pkx, "backup wrap", ctx), "export slot", BK, head + slot))
        assert len(prefix) == EX_SLOT_END
    else:
        prefix = head
    out = prefix
    parts = [body[i:i + chunk] for i in range(0, len(body), chunk)] or [b""]
    for i, part in enumerate(parts):
        fin = 1 if i == len(parts) - 1 else 0
        sc = sealed(EK, f"export chunk {i}", part, prefix + u64(i) + u8(fin))
        out += u32(len(sc)) + sc
    return out


def open_export(data, pw=None, seed64=None, floor=FLOOR_TEST):
    """Section 11. Returns the body or the refusal."""
    if data[:8] != b"GZBACKUP" or data[8] != 1 or data[10:42] != chain:
        return "not a backup of this network"
    profile, eid = data[9], data[42:58]
    ctx = chain + eid
    if profile == 1:
        prefix_len = EX_SLOT_END
        if pw is not None:
            alg, t, m, p = data[58], int.from_bytes(data[59:63], "big"), int.from_bytes(data[63:67], "big"), data[67]
            if not params_ok(alg, t, m, p, floor):
                return "parameters refused"
            pkx = argon2id(nfc_utf8(pw), data[68:84], t, m, 1, 32)
            if not hmac.compare_digest(commitment(pkx, "backup commitment", ctx, data[:84]), data[84:116]):
                return "wrong passphrase"
            bk = unseal(keys(pkx, "backup wrap", ctx), data[116:188], data[:84])
            if bk is None:
                return "wrong passphrase"
        else:
            bk = derive(seed64, "backup", chain)
    elif profile == 2:
        prefix_len = 58
        if seed64 is None:
            return "needs the 24 words"
        bk = derive(seed64, "backup", chain)
    else:
        return "unknown profile"
    ek, prefix = keys(bk, "export", ctx), data[:prefix_len]
    pos, i, body = prefix_len, 0, b""
    while True:
        if pos + 4 > len(data):
            return "truncated"
        n = int.from_bytes(data[pos:pos + 4], "big")
        if n < 40 or n > 65_576 or pos + 4 + n > len(data):
            return "truncated"
        sc = data[pos + 4:pos + 4 + n]
        pt = unseal(ek, sc, prefix + u64(i) + u8(1))
        if pt is not None:
            if pos + 4 + n != len(data):
                return "data after the final chunk"
            body += pt
            break
        pt = unseal(ek, sc, prefix + u64(i) + u8(0))
        if pt is None:
            return "damaged"
        if pt == b"":
            return "empty chunk before the end"
        body += pt
        pos, i = pos + 4 + n, i + 1
    return body


def plain_entries(entries):
    return b"".join(u8(k) + u64(inc) + u64(seq) + u32(len(pt)) + pt for k, inc, seq, pt in entries)


EXP_BODY = (u8(1) + u64(1_794_000_100_000) + u8(0) + u32(len(GUARD_PLAIN)) + GUARD_PLAIN
            + plain_entries(st[3]))
ex1 = export_file(1, EXP_BODY, 65_536, PW1)
ex2 = export_file(2, EXP_BODY, 65_536)
ex1s = export_file(1, EXP_BODY, 64, PW1)
print("\n== vector E10, export (.gzb), export_id = sha256('gazpacho test export id')[0:16], slot salt"
      " sha256('gazpacho test export kdf salt')[0:16], test parameters of E2, created 1794000100000 ms,"
      " flags 0 (no words), body = the entries of E6 and the guard of E9")
print("  backup key BK =", BK.hex(), "(from the BIP 39 seed)")
print("  export key EK =", EK[0].hex())
show("E10a profile 1, the person's export: passphrase slot with key commitment, one chunk", ex1)
show("E10b profile 2, the host's copy: no slot, one chunk", ex2)
assert open_export(ex1, pw=PW1) == EXP_BODY
assert open_export(ex1, pw=PW1_DECOMPOSED) == EXP_BODY
assert open_export(ex1, seed64=SEED64) == EXP_BODY
assert open_export(ex2, seed64=SEED64) == EXP_BODY
assert open_export(ex2, pw=PW1) == "needs the 24 words"
assert open_export(ex1, pw=PW2) == "wrong passphrase"
assert open_export(ex1, seed64=hashlib.sha512(b"other").digest()) == "damaged"
assert open_export(ex1s, pw=PW1) == EXP_BODY
_chunks, _p = [], EX_SLOT_END
while _p < len(ex1s):
    _chunks.append(_p); _p += 4 + int.from_bytes(ex1s[_p:_p + 4], "big")
assert open_export(ex1s[:_chunks[-1]], pw=PW1) == "truncated"
_sw = ex1s[:_chunks[0]] + ex1s[_chunks[1]:_chunks[2]] + ex1s[_chunks[0]:_chunks[1]] + ex1s[_chunks[2]:]
assert open_export(_sw, pw=PW1) == "damaged"
assert open_export(ex1s + ex1s[_chunks[-1]:], pw=PW1) == "data after the final chunk"
_bad = bytearray(ex1); _bad[64] ^= 0x01                                  # the slot's m
assert open_export(bytes(_bad), pw=PW1) == "wrong passphrase"
_bad = bytearray(ex1); _bad[63:67] = u32(0xFFFFFFFF)                     # F9: m = 2^32 - 1 KiB
assert open_export(bytes(_bad), pw=PW1) == "parameters refused"
_bad = bytearray(ex1); _bad[67] = 4                                      # F9: four lanes
assert open_export(bytes(_bad), pw=PW1) == "parameters refused"
# F17: an empty chunk that is not the last.
_prefix = ex1[:EX_SLOT_END]
_empty = sealed(EK, "export empty chunk", b"", _prefix + u64(0) + u8(0))
_rest = sealed(EK, "export chunk after empty", EXP_BODY, _prefix + u64(1) + u8(1))
assert open_export(_prefix + u32(len(_empty)) + _empty + u32(len(_rest)) + _rest, pw=PW1) == "empty chunk before the end"
print(f"== vector E11 (refuse): E10a's body sealed in {len(_chunks)} chunks of at most 64 bytes opens; with the"
      " last chunk dropped: truncated; with chunks 0 and 1 swapped: damaged; with the last chunk repeated:"
      " data after the final chunk; with the slot's memory changed or the second passphrase: wrong passphrase;"
      " with the slot's memory 2^32 - 1 KiB or four lanes: parameters refused before deriving; an empty"
      " chunk before the last: refused; with other words: damaged; E10b with a passphrase: needs the 24 words")

# ---------------------------------------------------- the watch bundle ----------
# storage-encryption.md section 8.7, draft 2. The envelope only: the contents' records
# are spec/exit.md's. KB is a random root key kept in the OS key store; the bundle and
# the watcher's log have their own keys under it (review F5).
KB = tv("watch bundle key")
BUNDLE_ID = tv("watch bundle id", 16)
KWB = keys(KB, "watch bundle", chain + BUNDLE_ID)
_bh = b"GZWATCH1" + u8(1) + chain + BUNDLE_ID + u64(7)
BUNDLE_PLAIN = tlv([(2, b"test contents: see spec/exit.md")])
e_bundle = _bh + sealed(KWB, "watch bundle 7", BUNDLE_PLAIN, _bh)


def open_bundle(data, kb, last_counter=0):
    if data[:8] != b"GZWATCH1" or data[8] != 1 or data[9:41] != chain:
        return "not a bundle of this network"
    head = data[:65]
    pt = unseal(keys(kb, "watch bundle", chain + data[41:57]), data[65:], head)
    if pt is None:
        return "damaged"
    if int.from_bytes(head[57:65], "big") < last_counter:
        return "older than the last bundle seen"
    return pt


assert open_bundle(e_bundle, KB) == BUNDLE_PLAIN
_bad = bytearray(e_bundle); _bad[64] ^= 0x01                         # counter 7 -> 6
assert open_bundle(bytes(_bad), KB) == "damaged"
assert open_bundle(e_bundle, KB, last_counter=8) == "older than the last bundle seen"
assert open_bundle(e_bundle, MSK) == "damaged"
_kwl = keys(KB, "watch log", chain + tv("watch log file id", 16))
assert unseal(_kwl, e_bundle[65:], _bh) is None                      # the log key cannot open the bundle
print("\n== vector E12, watch-and-exit bundle watch.gzw (65-byte clear header): bundle_id"
      " sha256('gazpacho test watch bundle id')[0:16], counter 7, contents one placeholder TLV record"
      " (spec/exit.md defines them)")
print("  root key KB = sha256('gazpacho test watch bundle key') =", KB.hex())
print("  bundle key  =", KWB[0].hex())
show("bundle", e_bundle)
print("== vector E13 (refuse): E12 with its counter changed: damaged; opened after counter 8 was seen:"
      " older than the last bundle seen; under the storage key, or under the watcher log's key: damaged")

# ---------------------------------------------------- the attempts file ---------
# Section 12.3, draft 2 (review F20): keyed under KB when KB is in an OS store.
def attempts_file(wrong, last_s, until_s, kb=None):
    body = b"GZTRIES1" + chain + u32(wrong) + u64(last_s) + u64(until_s) + u8(2 if kb else 1)
    if kb:
        return body + hmac.new(derive(kb, "attempts", chain), body, hashlib.sha256).digest()[:16]
    return body + hashlib.sha256(body).digest()[:16]


def read_attempts(data, kb=None, now=1_794_000_000):
    strict = ("strictest", now + 900)
    if len(data) != 77 or data[:8] != b"GZTRIES1" or data[8:40] != chain:
        return strict
    body, mode = data[:61], data[60]
    want = (hmac.new(derive(kb, "attempts", chain), body, hashlib.sha256).digest()[:16] if mode == 2 and kb
            else hashlib.sha256(body).digest()[:16] if mode == 1 else None)
    if want is None or not hmac.compare_digest(want, data[61:]) or (kb and mode != 2):
        return strict
    return int.from_bytes(data[40:44], "big"), int.from_bytes(data[52:60], "big")


at = attempts_file(6, 1_793_999_990, 1_794_000_030, kb=KB)
assert read_attempts(at, kb=KB) == (6, 1_794_000_030)
_bad = bytearray(at); _bad[43] = 0                                    # count reset by a folder writer
assert read_attempts(bytes(_bad), kb=KB)[0] == "strictest"
assert read_attempts(attempts_file(0, 0, 0), kb=KB)[0] == "strictest"   # a plain file where KB exists
print("\n== vector E14, attempts file attempts.gza (77 bytes), keyed under KB: 6 wrong in a row, last at"
      " 1793999990, blocked until 1794000030")
show("attempts file", at)
print("  with the count rewritten, or replaced by an unkeyed file while KB exists: read as the strictest state")
print("\n== storage-encryption.md: section E done")


# ============================================================== exit.md =====
# Section X, draft 1 (2026-11-12). The deadline arithmetic of spec/exit.md
# section 4, the transaction sizes it uses, and the keyless anchor-only child of
# section 6.2. Everything here is integer arithmetic on heights, sizes and fees;
# none of it signs anything. The timeout formula is the import's
# (core/superscalar/src/factory.c:1475, :1635-1644, :1314); the sizes follow
# tx_builder.c:65-100 and BIP 141.

X_STEP = 5                      # TIMEOUT_STEP_BLOCKS, factory.c:1475
X_BURY = 3                      # B: burial depth, signet (safety-rule.md 12 value 3)
X_ALLOW = 6                     # A: confirmation allowance per transaction, signet (12 value 6)
X_M_SAFE = 6                    # M_safe (safety-rule.md 12 value 6)
X_M_LAG = 2                     # M_lag: chain-view lag
X_M_SPIKE = 6                   # M_spike: fee spike, signet placeholder
X_M = X_M_SAFE + X_M_LAG + X_M_SPIKE
X_M_HOST = X_M_SAFE + X_M_LAG   # the host's margin (exit.md 9.3)
X_PAY_STOP = X_ALLOW            # no new payment within one allowance of leave_by
X_ANCHOR = 240                  # ANCHOR_OUTPUT_AMOUNT, channel.h:16
X_BLOCK_FAST_S = 300            # exit.md 4.5: blocks assumed at most twice as fast as 600 s


def x_cltv_feeding(E, j, kind):
    """Height in the host-only timeout leaf of the output that feeds the node at
    depth j (factory.c:1635-1644). kind 'fixed' or 'leaf_kickoff' uses ko_cltv,
    'leaf' (the leaf transaction, a state node) uses st_cltv. The channel output
    of a pseudo-Spilman leaf copies the leaf node's spending script
    (factory.c:1314), so it carries the 'leaf' height too."""
    if j == 0:
        return None             # the root kickoff spends the funding output: no timeout
    if kind == "leaf":
        return E - 2 * j * X_STEP
    return E - (2 * j - 1) * X_STEP


def x_path_timeouts(E, d):
    """[(transaction, height of the timeout on the output it spends)] for a
    member whose leaf is at depth d, then the channel output."""
    rows = [(f"fixed kickoff, depth {j}", x_cltv_feeding(E, j, "fixed")) for j in range(d)]
    rows.append((f"leaf kickoff, depth {d}", x_cltv_feeding(E, d, "leaf_kickoff")))
    rows.append((f"leaf transaction, depth {d}", x_cltv_feeding(E, d, "leaf")))
    rows.append(("commitment (spends the channel output)", x_cltv_feeding(E, d, "leaf")))
    return rows


def x_h_leaf(E, d):
    return E - 2 * d * X_STEP


def x_n_path(d):
    return d + 3                # d fixed kickoffs, leaf kickoff, leaf transaction, commitment


def x_last_safe_confirm(E, d, bury=X_BURY):
    # The host's timeout spend has nLockTime = H_leaf (factory.c:4856-4861), so it can
    # first be mined in block H_leaf + 1. Ours must have `bury` confirmations at tip H_leaf.
    return x_h_leaf(E, d) - (bury - 1)


def x_leave_by(E, d, n_missing=None, allow=X_ALLOW, m=X_M):
    n = x_n_path(d) if n_missing is None else n_missing
    return x_last_safe_confirm(E, d) - n * allow - m


def x_step_due(E, d, i, n_missing=None, allow=X_ALLOW, m=X_M):
    """Latest height at which missing step i (1 = first) must be confirmed."""
    n = x_n_path(d) if n_missing is None else n_missing
    return x_last_safe_confirm(E, d) - (n - i) * allow - m


def x_vsize_tree(k_outputs):
    """A tree transaction: 1 key-path input, k P2TR outputs and the 240-sat P2A.
    Unsigned bytes 64 + 43 k; signed vsize ceil((4 (64 + 43 k) + 2 + 66) / 4)."""
    unsigned = 4 + 1 + 41 + 1 + 43 * k_outputs + 13 + 4
    assert unsigned == 64 + 43 * k_outputs
    return -(-(4 * unsigned + 2 + 66) // 4)


assert x_vsize_tree(2) == 167 and x_vsize_tree(4) == 253   # terms.md 4.2: V = 167, 253


def x_path_shape(levels, n, member):
    """Leaf depth of member `member` (0-based, in placement order), and the number
    of outputs (without the anchor) of each tree transaction on its path."""
    def walk(m, d, offset):
        a = levels[d] if d < len(levels) else levels[-1]
        if a == LEAF_PS:
            if m == 1:
                return [1, 2] if offset == member else None    # leaf kickoff: 1 output; leaf: 2
            left = m // 2
            parts = [left, m - left]
        else:
            parts, rem = [], m
            for j in range(a):
                if rem == 0:
                    break
                c = min(rem, -(-rem // (a - j)))
                parts.append(c)
                rem -= c
        off = offset
        for c in parts:
            if off <= member < off + c:
                below = walk(c, d + 1, off)
                return [len(parts)] + below
            off += c
        return None
    outs = walk(n, 0, 0)
    return len(outs) - 2, outs


# The keyless anchor-only child (exit.md 6.2): one input spending the parent's
# pay-to-anchor output with an empty scriptSig and no witness, one zero-value
# OP_RETURN output of 3 zero bytes, so the transaction is exactly 65 bytes, the
# smallest standard non-witness size. Its whole input, 240 sat, is its fee.
def x_anchor_child(parent_txid_display: bytes, anchor_vout: int, version: int) -> bytes:
    prev = parent_txid_display[::-1]
    tx = (version.to_bytes(4, "little") + b"\x01" + prev + anchor_vout.to_bytes(4, "little")
          + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little") + b"\x01" + (0).to_bytes(8, "little")
          + b"\x05" + b"\x6a\x03\x00\x00\x00" + (0).to_bytes(4, "little"))
    assert len(tx) == 65
    return tx


def x_txid(tx: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(tx).digest()).digest()[::-1].hex()


def x_package_rate_kvb(fee_parent, v_parent, fee_child, v_child):
    """Package fee rate in sat per 1000 vB, rounded down."""
    return (1000 * (fee_parent + fee_child)) // (v_parent + v_child)


# A wallet-funded child: inputs the P2A (no witness) and one P2TR key-path coin
# (64-byte signature), one P2TR change output. Non-witness 4+1+2*41+1+43+4 = 135;
# witness: marker and flag 2, P2A item count 1, P2TR count 1 + length 1 + 64.
X_V_CHILD_WALLET = -(-(4 * 135 + 2 + 1 + 66) // 4)
assert X_V_CHILD_WALLET == 153


def x_child_fee(rate_kvb, fee_parent, v_parent, v_child=X_V_CHILD_WALLET):
    """Child fee so that the package pays at least rate_kvb."""
    return max(0, -(-(rate_kvb * (v_parent + v_child)) // 1000) - fee_parent)


print("\n== exit.md: section X, deadline arithmetic (signet constants B=%d, A=%d, M=%d+%d+%d=%d)"
      % (X_BURY, X_ALLOW, X_M_SAFE, X_M_LAG, X_M_SPIKE, X_M))
X_TIP = 290_000
X_E = X_TIP + 144 + 36            # T1: lifetime 144, wind-down 36 (terms.md T1)
print(f"  T1 factory proposed at tip {X_TIP}: end height E = {X_E}; lifetime ends at {X_TIP + 144}")

print("\n== X1: host-only timeouts on a member's path, leaf depth d (the root kickoff has none)")
for d in (1, 2, 3):
    print(f"  d = {d}:")
    for name, h in x_path_timeouts(X_E, d):
        print(f"    {name:40s} spends an output timing out at {'none' if h is None else h}"
              + ("" if h is None else f" (E - {X_E - h})"))
    hs = [h for _, h in x_path_timeouts(X_E, d) if h is not None]
    assert min(hs) == x_h_leaf(X_E, d) == X_E - 10 * d
print("  so H_leaf = E - 10 d, not E - 5 d: two tree transactions (kickoff and leaf) per leaf depth,"
      " and fixed levels step by 10 too")

print("\n== X2: path shapes and sizes for T1 (fee_per_tx 17 at up to 4 members, 26 above)")
for n, member in ((3, 0), (3, 1), (4, 0), (5, 0), (5, 4), (8, 0), (16, 0), (16, 15)):
    levels = (SHAPE_T1[0][1] if n <= 4 else SHAPE_T1[1][1]) + [LEAF_PS]
    d, outs = x_path_shape(levels, n, member)
    assert d == [dd for dd, _ in split_walk(levels, n)][member]
    sizes = [x_vsize_tree(k) for k in outs]
    fee = 17 if n <= 4 else 26
    print(f"  {n:2d} members, member {member + 1:2d}: leaf depth d = {d}, tree transactions {len(outs)} = d + 2,"
          f" vsizes {sizes}, each pays {fee} sat; with the commitment, n = {x_n_path(d)} transactions")

print("\n== X3: start leaving by, step deadlines, and the T1 wind-down shortfall")
for d in (1, 2, 3):
    lb = x_leave_by(X_E, d)
    lsc = x_last_safe_confirm(X_E, d)
    dues = [x_step_due(X_E, d, i) for i in range(1, x_n_path(d) + 1)]
    assert dues[-1] == lsc - X_M and dues[0] == lb + X_ALLOW
    lead = X_E - lb
    print(f"  d = {d}: H_leaf = {x_h_leaf(X_E, d)}, last safe confirmation = {lsc}, "
          f"leave_by = {lb} (E - {lead}), step deadlines {dues}")
    print(f"         lead time E - leave_by = {lead} blocks against wind-down 36: "
          + ("inside the wind-down" if lead <= 36 else f"starts {lead - 36} blocks before the lifetime ends"))
    hf = x_last_safe_confirm(X_E, d) - x_n_path(d) * X_ALLOW - X_M_HOST
    assert hf == lb + X_M_SPIKE
    print(f"         host_force_by = {hf} (leave_by + {hf - lb})")
assert x_leave_by(X_E, 1) == X_E - 50 and x_leave_by(X_E, 2) == X_E - 66 and x_leave_by(X_E, 3) == X_E - 82
# Part of the path already on chain (U-a'): only the missing steps count.
for missing in (5, 3, 1):
    print(f"  d = 2 with {missing} of 5 steps missing: leave_by = {x_leave_by(X_E, 2, missing)}")
assert x_leave_by(X_E, 2, 1) == X_E - 20 - 2 - 6 - 14
print(f"  smallest wind-down at which leave_by never falls inside the lifetime: "
      f"{X_E - x_leave_by(X_E, 3)} blocks for d <= 3 (T1 has 36)")

print("\n== X4: payments against the exit (d = 2, every step missing)")
d = 2
n = x_n_path(d)
min_delta = (n + 1) * X_ALLOW + (X_BURY - 1) + X_M
print(f"  an incoming payment is accepted at tip t only if its expiry h >= t + {min_delta}"
      f" ((n + 1) A + (B - 1) + M, n = {n}); invoices ask min_final_cltv_expiry_delta >= {min_delta}")
h = X_TIP + 100
print(f"  an incoming payment expiring at {h} whose secret is released and not yet removed goes on chain by "
      f"{h - (X_BURY - 1) - (n + 1) * X_ALLOW - X_M}")
print(f"  no new payment once the tip reaches leave_by - {X_PAY_STOP} = {x_leave_by(X_E, d) - X_PAY_STOP}")
W = 2016
c = X_TIP + 120
print(f"  a revoked host commitment confirmed at {c} with to_self_delay W = {W} (example; channel.md sets W):"
      f" the penalty must be confirmed by {c + W - X_BURY} (c + W - B) and sent by"
      f" {c + W - X_BURY - X_ALLOW - X_M} (c + W - B - A - M)")

print("\n== X5: the tip estimate while the chain view is in doubt (exit.md 4.5)")
t_trusted, at = X_E - 80, 1_800_000_000
for elapsed, claimed in ((3600, X_E - 75), (3600, X_E - 60), (14400, X_E - 30)):
    bound = t_trusted + -(-elapsed // X_BLOCK_FAST_S)
    est = max(t_trusted, min(claimed, bound))
    print(f"  last trusted tip {t_trusted}, {elapsed} s later, highest claimed {claimed}: "
          f"clock bound {bound}, estimate {est}")

print("\n== X6: the anchor-only child, keyless (exit.md 6.2)")
x_parent = hashlib.sha256(b"gazpacho test exit parent").digest()
child = x_anchor_child(x_parent, 2, 2)
print("  parent txid (test value, display order) =", x_parent.hex(), " anchor vout 2, version 2")
show("anchor-only child (65 bytes, no witness)", child)
print("  txid =", x_txid(child))
child3 = x_anchor_child(x_parent, 2, 3)
print("  the same for a TRUC parent (version 3): txid =", x_txid(child3))
for k, fee in ((1, 17), (2, 17), (2, 26), (4, 26)):
    v = x_vsize_tree(k)
    r = x_package_rate_kvb(fee, v, X_ANCHOR, 65)
    print(f"  parent {v} vB paying {fee} sat ({1000 * fee // v} sat/kvB) + anchor-only child: package {r} sat/kvB")
assert x_package_rate_kvb(17, 167, 240, 65) == 1107

print("\n== X7: wallet-funded child (P2A + one P2TR coin, change to P2TR): %d vB; fee for a package rate" % X_V_CHILD_WALLET)
X_LADDER = [2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000]   # sat/kvB, exit.md 6.6
X_INCREMENTAL_KVB = 100         # Bitcoin Core 29.1 and later: -incrementalrelayfee 100 sat/kvB


def x_replaces(fee_new, v_new, fee_old, v_old, fee_parent, v_parent):
    """exit.md 6.3: a child replacing another on the same anchor must (a) pay at
    least the old fee plus the incremental fee on its own size (BIP 125 rule 4),
    (b) have a higher fee rate of its own than the child it replaces (the
    pre-cluster rule 6), and (c) give the parent a higher package rate (the
    cluster mempool's diagram check, 31.0 and later)."""
    a = fee_new >= fee_old + -(-(X_INCREMENTAL_KVB * v_new) // 1000)
    b = fee_new * v_old > fee_old * v_new
    c = (fee_parent + fee_new) * (v_parent + v_old) > (fee_parent + fee_old) * (v_parent + v_new)
    return a and b and c


# A wallet child at a package rate of 1 sat/vB does NOT replace the anchor-only child:
assert not x_replaces(x_child_fee(1_000, 17, 167), X_V_CHILD_WALLET, X_ANCHOR, 65, 17, 167)
x_min_first = next(f for f in range(X_ANCHOR, 10_000)
                   if x_replaces(f, X_V_CHILD_WALLET, X_ANCHOR, 65, 17, 167))
print(f"  the smallest wallet child that replaces the anchor-only child of the 167 vB leaf transaction:"
      f" fee {x_min_first} sat, package {x_package_rate_kvb(17, 167, x_min_first, X_V_CHILD_WALLET)} sat/kvB"
      f" (a 1 sat/vB rung, fee {x_child_fee(1_000, 17, 167)}, would be refused)")


def x_ladder(fee_parent, v_parent):
    """exit.md 6.6: each rung pays the larger of its rate's fee and the smallest
    fee that replaces the rung below (rung 0 is the anchor-only child)."""
    out, prev_f, prev_v = [], X_ANCHOR, 65
    for r in X_LADDER:
        f = x_child_fee(r, fee_parent, v_parent)
        while not x_replaces(f, X_V_CHILD_WALLET, prev_f, prev_v, fee_parent, v_parent):
            f += 1
        out.append((r, f))
        prev_f, prev_v = f, X_V_CHILD_WALLET
    return out


for v_p, f_p in ((124, 17), (167, 17), (167, 26), (253, 26)):
    rungs = x_ladder(f_p, v_p)
    print(f"  parent {v_p} vB paying {f_p} sat: rung fees "
          + ", ".join(f"{r / 1000:g} sat/vB {f}" for r, f in rungs))
assert x_ladder(17, 167)[0] == (2_000, 623) and x_ladder(17, 124)[0] == (2_000, 565)
print("\n== exit.md: section X done")
