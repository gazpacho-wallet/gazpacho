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
# Draft 3 (after notes/review-discovery-d2.md): the listing withdrawal is its
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
# Known uses read or recalled in notes/discovery-research.md. Not exhaustive.
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
        self.pending = []       # (link, rec)
        self.relayed = []

    def set_tip(self, tip):
        """A new block: re-offer pending beacons (R-P2). Returns their results."""
        self.tip = tip
        again, self.pending = self.pending, []
        return [self.offer(rec, link) for link, rec in again]

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
            if h > self.tip + 144 or open_h > self.tip + 144:
                return "ignore:B6"                                # far ahead: not pending
            mine_l = [x for x in self.pending if x[0] == link]
            if len(mine_l) >= 8:
                self.pending.remove(mine_l[0])
            if len(self.pending) >= 64:
                self.pending.pop(0)
            self.pending.append((link, rec))
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
        same = sorted((v[0], k) for k, v in self.held.items()
                      if k[0] == host and v[2] == withdrawal and k[1] != dg)
        limit = allow + 4 if withdrawal else allow                # B10: live and tombstone caps
        if len(same) >= limit:
            if seq < same[0][0]:
                return "ignore:B10"
            del self.held[same[0][1]]
        self.held[(host, dg)] = (seq, bid, withdrawal, open_h, dl, rec)
        if seq not in mine:
            mine.add(seq)
            if not from_pool:
                arr.append(self.tip)
        self.seen.add(bid)
        self.relayed.append(bid)
        return "tombstone" if withdrawal else "held"

    def live(self, host):
        return sorted(v[0] for k, v in self.held.items() if k[0] == host and not v[2])

    def tombs(self, host):
        return sorted(v[0] for k, v in self.held.items() if k[0] == host and v[2])

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
for i in range(56):
    rec, _ = beacon(seq_of(TIP + 18 * i), digest=hashlib.sha256(b"back %d" % i).digest(),
                    open_h=TIP, deadline_h=TIP + 1_008)
    res24.append(r24.offer(rec))
assert len(r24.relayed) <= 8 and res24.count("ignore:B9") >= 48
r24t = Reader(T_LATE, GRAPH1)
for i in range(56):
    rec, _ = beacon(seq_of(TIP + 18 * i), digest=hashlib.sha256(b"tomb %d" % i).digest(),
                    open_h=TIP, deadline_h=TIP)
    r24t.offer(rec, from_pool=True)            # asked-for page: no arrival cap; B9 a and B10 still apply
assert len(r24t.tombs(host_pub)) <= 1 + 4
r24r = Reader(T_LATE, GRAPH1)
for i in range(56):
    rec, _ = beacon(seq_of(TIP + 18 * i), digest=hashlib.sha256(b"tomb %d" % i).digest(),
                    open_h=TIP, deadline_h=TIP)
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
