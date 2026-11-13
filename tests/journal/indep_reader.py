"""Independent reader for the Gazpacho storage journal (journal.md section 11's
salted clear format; draft 2's framing with a salt and an offset-bound check).

Written only from the specification, as a cross-check for the C implementation,
by an author who had not seen that implementation. Do not change it to match
the C code: a disagreement is a finding about one of the two, or the spec.
"""
import hashlib
import struct

MAGIC = b"GZJOURNS"
SALT_LEN = 32
CHECK_LEN = 16
HEADER_LEN = 8 + 32 + SALT_LEN + CHECK_LEN  # 88
MIN_LEN = 21
MAX_LEN = 8_388_625
MARK_TOTAL = 4 + 25 + CHECK_LEN  # 45

KIND_INC, KIND_BATCH, KIND_MARK = 1, 2, 3

# Section 9: every type named with a record name. 0x00040008 ("not used") is absent on purpose.
KNOWN_TYPES = {
    0x00040002, 0x00040004, 0x00040006, 0x0004000A,
    0x00010002, 0x00010004, 0x00010006, 0x00010008, 0x0001000A, 0x0001000C,
    0x0001000E, 0x00010010, 0x00010012, 0x00010014, 0x00010016,
    0x00020002, 0x00020004, 0x00020006, 0x00020008, 0x0002000A, 0x0002000C,
    0x0002000E,
    0x00030002, 0x00030004, 0x00030006,
}


def check(salt, off, frame):
    """Section 11: SHA-256(salt || u64 offset || frame), the first 16 bytes."""
    return hashlib.sha256(salt + struct.pack(">Q", off) + frame).digest()[:CHECK_LEN]


def is_placeholder(t):
    return (t >> 16) == 0x7E57


def parse_records(payload):
    """Return list of (type, bytes), or None if the records do not fill the payload exactly."""
    if len(payload) < 4:
        return None
    (n,) = struct.unpack_from(">I", payload, 0)
    pos, recs = 4, []
    for _ in range(n):
        if pos + 8 > len(payload):
            return None
        t, ln = struct.unpack_from(">II", payload, pos)
        pos += 8
        if pos + ln > len(payload):
            return None
        recs.append((t, payload[pos:pos + ln]))
        pos += ln
    return recs if pos == len(payload) else None


def parse_entry(data, off, salt):
    """Parse the entry at `off`. Return a dict for a valid entry, None for an invalid one."""
    if len(data) - off < 4:
        return None
    (length,) = struct.unpack_from(">I", data, off)
    if length < MIN_LEN or length > MAX_LEN:
        return None
    if len(data) - off < 4 + length + CHECK_LEN:  # tested before the check is read
        return None
    kind = data[off + 4]
    if kind not in (KIND_INC, KIND_BATCH, KIND_MARK):
        return None
    if kind in (KIND_INC, KIND_MARK) and length != 25:
        return None
    body = data[off:off + 4 + length]
    if check(salt, off, body) != data[off + 4 + length:off + 4 + length + CHECK_LEN]:
        return None
    inc, seq = struct.unpack_from(">QQ", data, off + 5)
    payload = data[off + 21:off + 4 + length]
    e = {"kind": kind, "inc": inc, "seq": seq, "end": off + 4 + length + CHECK_LEN, "records": None}
    if kind == KIND_MARK:
        (mark_off,) = struct.unpack(">Q", payload)
        if mark_off != off:
            return None
    elif kind == KIND_BATCH:
        e["records"] = parse_records(payload)
        if e["records"] is None:
            return None
    return e


def result(state, cut_to=None, next_inc=None, records=None, batches=None):
    return {"state": state, "cut_to": cut_to, "next_incarnation": next_inc,
            "records": records, "batches": batches}


def read(data: bytes, chain: bytes) -> dict:
    data = bytes(data)
    body = 8 + 32 + SALT_LEN
    if (len(data) < HEADER_LEN or data[0:8] != MAGIC
            or hashlib.sha256(data[0:body]).digest()[:CHECK_LEN] != data[body:HEADER_LEN]
            or data[8:40] != chain):
        return result("bad_header")
    salt = data[40:40 + SALT_LEN]

    # Section 5 step 3: scan, checking order rules (3.4) on every valid entry.
    entries, off, cur_inc, next_seq = [], HEADER_LEN, None, 1
    end = len(data)
    while off < end:
        e = parse_entry(data, off, salt)
        if e is None:
            break
        if e["kind"] == KIND_INC:
            if e["seq"] != 0 or (cur_inc is not None and e["inc"] <= cur_inc):
                return result("order")
            cur_inc, next_seq = e["inc"], 1
        else:
            if cur_inc is None or e["inc"] != cur_inc:
                return result("order")
            if e["kind"] == KIND_MARK and e["seq"] != 0:
                return result("order")
            if e["kind"] == KIND_BATCH:
                if e["seq"] != next_seq:
                    return result("order")
                next_seq += 1
        entries.append(e)
        off = e["end"]
    v = off

    # Section 5 step 4: torn tail or corruption.
    if v < end:
        for p in range(v + 1, end - MARK_TOTAL + 1):
            m = parse_entry(data, p, salt)
            if m is not None and m["kind"] == KIND_MARK:
                return result("corrupt")

    # Section 6: read records, odd/even rule.
    records, batches = [], []
    for e in entries:
        if e["kind"] != KIND_BATCH:
            continue
        kept = 0
        for t, b in e["records"]:
            if not (is_placeholder(t) or t in KNOWN_TYPES):
                if t % 2 == 0:
                    return result("unknown_record")
                continue
            records.append((t, b))
            kept += 1
        batches.append((e["inc"], e["seq"], kept))

    next_inc = 1 + max((e["inc"] for e in entries), default=0)
    if v < end:
        return result("torn", v, next_inc, records, batches)
    return result("clean", None, next_inc, records, batches)
