#!/usr/bin/env python3
"""Compute the test vectors printed in spec/terms.md, spec/messages.md and
spec/journal.md. Factory messages use the native type 52791; vector M3 shows the
same bytes through the bLIP-56 adapter (open PR lightning/blips#56).

    python tools/spec-vectors.py

Standard library only. Run it again whenever one of those encodings changes,
and paste the new output into the specification.

Changed after review 3 (notes/spec-review-3.md): the shape table carries the
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
print("\n== messages.md: proposed factory_protocol_id = sha256('SuperScalar/1')")
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
