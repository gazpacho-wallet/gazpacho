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

# ===================================================== discovery.md ==========
# Vectors D0 to D12 of spec/discovery.md. Every number marked CANDIDATE is a
# reproducible random pick, not a final number: it must pass the checks of
# discovery.md section 2 on the day it is chosen.
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
# Feature bits: two adjacent pairs from one pick, 256..511 so the feature field
# stays at most 64 bytes. Pair 1 factory_capable, pair 2 factory_host.
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
    print(f"  bits: factory_capable {base}/{base + 1}, factory_host {base + 2}/{base + 3};"
          f" features field with bit {base + 3} set = {(base + 3) // 8 + 1} bytes")
FC_ODD, FH_ODD = bit_cands[0] + 1, bit_cands[0] + 3

# Onion payload types: one block of 64 above 65,600; odd types base+1, +3, ...
pick = h16("gazpacho onion payload types")
ON_BASE = 65_600 + 64 * (pick % 1024)
ON = {name: ON_BASE + 1 + 2 * i for i, name in enumerate(
    ["lobby_index_request", "lobby_index", "listing_request", "listing",
     "host_list_request", "host_list"])}
assert not set(ON.values()) & set(KNOWN_ONION)
print("  onion payload types:", ", ".join(f"{k} {v}" for k, v in ON.items()))
# node_announcement TLV for the card: odd, above 65,536.
CARD_TLV = 65_537 + 2 * h16("gazpacho host card tlv")
assert CARD_TLV % 2 == 1 and CARD_TLV not in KNOWN_NA_TLV
print("  node_announcement TLV type for the host card:", CARD_TLV)


def nostr_kind(label):
    k = 30000 + h16(label) % 10000
    while k in KNOWN_NOSTR:
        k += 1
    return k


NK_LISTING = nostr_kind("gazpacho nostr listing kind")
NK_CARD = nostr_kind("gazpacho nostr card kind")
print(f"  Nostr addressable kinds: listing {NK_LISTING}, host card {NK_CARD}")

# Native kinds: fixed by discovery.md section 6 in PROTOCOL.md's range 128..159.
K_INDEX_REQ, K_INDEX, K_LISTING_REQ, K_LISTING, K_HL_REQ, K_HL, K_BEACON, K_BFILTER = \
    129, 131, 133, 135, 137, 139, 141, 143

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


# ---- D1: host card -----------------------------------------------------------
card = tlv([
    (2, PROTOCOL_ID),                 # protocol_id
    (4, u32(TIP)),                    # card_height
    (6, rng(100_000, 100_000)),       # channel_range
    (8, u16(0) + u16(24)),            # schedule: 00:00 UTC, every 24 h
    (10, u8(0b010)),                  # profiles: Standard
    (11, b"Gazpacho test host"),      # name
])
assert len(card) <= 256
na_tlv = tlv([(CARD_TLV, card)])
print("\n== D1: host card of the test host")
show("card", card)
show(f"as appended to node_announcement (TLV type {CARD_TLV}, candidate)", na_tlv)

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

# ---- D3: signed card publication (Nostr and host_list) -----------------------
pub_body = tlv([(2, chain), (4, host_pub), (6, card), (8, anchor)])
pub_digest = tagged_hash("gazpacho/card", pub_body)
pub = pub_body + tlv([(240, schnorr_sign(pub_digest, host_sk, AUX))])
print("\n== D3: signed card publication, with the coin anchor")
print("card_digest = TH('gazpacho/card', records before 240) =", pub_digest.hex())
show("signed card", pub)

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
withdrawal, wd_digest = listing_record(START, START)
print("D4w withdrawal (expiry = start):", "listing_digest", wd_digest.hex(), "; listing_sig", withdrawal[-64:].hex())
too_long, _ = listing_record(START, START + 1_009)
print("D4x refuse: expiry = start + 1009, listing_sig", too_long[-64:].hex())
# Size bound of discovery.md section 5: the sum of each record's maximum.
MAX_LISTING = (1 + 1 + 33) + (1 + 3 + 4096) + 6 + 6 + (1 + 3 + 600) + (2 + 64)
print("largest possible listing:", MAX_LISTING, "bytes")

# ---- D5: the queries ---------------------------------------------------------
idx_req = tlv([(2, chain)])
entry_t1 = outer_digest + u64(1794441600) + u8(2) + u64(100_000)
idx_body = tlv([(2, chain), (4, host_pub), (6, u32(TIP)), (8, entry_t1), (10, card)])
idx_digest = tagged_hash("gazpacho/index", idx_body)
index = idx_body + tlv([(240, schnorr_sign(idx_digest, host_sk, AUX))])
idx_msg = tlv([(2, index)])
lst_req = tlv([(2, chain), (4, outer_digest)])
lst_msg = tlv([(2, listing)])
unk_msg = tlv([(4, hashlib.sha256(b"no such lobby").digest())])
print("\n== D5: queries for the test host (records; same bytes on both carriers)")
show("lobby_index_request records", idx_req)
print("index_digest = TH('gazpacho/index', records before 240) =", idx_digest.hex())
show("index record", index)
show("lobby_index records", idx_msg)
show("listing_request records", lst_req)
print(f"listing answer records: {len(lst_msg)} bytes = record 2 holding the D4 listing")
show("listing answer 'unknown' (record 4 = sha256('no such lobby'))", unk_msg)
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
print(f"card event kind {NK_CARD} (candidate), d =", host_pub.hex(), "; content = base64 of D3,",
      len(base64.b64encode(pub)), "characters")

# ---- D7 to D10: lobby beacon -------------------------------------------------
def beacon(seq, digest=outer_digest, open_h=TIP, deadline_h=TIP + 144, key=host_sk):
    body = tlv([(2, compressed(key)), (4, digest), (6, u32(open_h)), (8, u32(deadline_h)), (10, u32(seq))])
    bid = tagged_hash("gazpacho/beacon", body)
    return body + tlv([(240, schnorr_sign(bid, key, AUX))]), bid


b1, b1_id = beacon(1)
print("\n== D7: lobby beacon for lobby T1, open", TIP, "deadline", TIP + 144, "sequence 1")
print("beacon_id = TH('gazpacho/beacon', records before 240) =", b1_id.hex())
show("beacon records", b1)
show(f"native lobby_beacon (kind {K_BEACON})", native(K_BEACON, b1))
b2, b2_id = beacon(2, deadline_h=TIP)
print("== D8: the same lobby withdrawn: sequence 2, deadline_height = open_height")
print("beacon_id =", b2_id.hex(), "; sig", b2[-64:].hex())
forged, _ = beacon(1, key=test_key("other host"))
forged = b1[:35] + forged[35:]                # host id of the test host, signed by another key
assert not schnorr_verify(tagged_hash("gazpacho/beacon", forged[:-66]), host_pub[1:], forged[-64:])
print("== D9 (refuse): D7's records with the signature of key 'other host': signature fails")
bf_all = tlv([(2, chain), (4, u32(0)), (6, u32(0xFFFFFFFF))])
bf_off = tlv([(2, chain), (4, u32(0xFFFFFFFF)), (6, u32(0))])
print("== D10: beacon_filter")
show(f"native beacon_filter 'everything' (kind {K_BFILTER})", native(K_BFILTER, bf_all))
show("beacon_filter records 'nothing' (off)", bf_off)
# Seen-set and active-set bounds, discovery.md section 8.6.
for hosts in (10, 1_000, 10_000):
    entries = min(65_536, max(1_024, 8 * hosts))
    print(f"  seen-set for {hosts} factory hosts in the graph: {entries} entries, {entries * 40} bytes")

# ---- D12: eviction of a fifth beacon ----------------------------------------
active = {}
for s in range(1, 6):
    _, bid = beacon(s, digest=hashlib.sha256(b"lobby %d" % s).digest())
    active[s] = bid
kept = sorted(active)[-4:]
assert kept == [2, 3, 4, 5]
print("== D12: five beacons of one host, sequences 1 to 5, different lobbies: keep 2, 3, 4, 5")
