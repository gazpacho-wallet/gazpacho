#!/usr/bin/env python3
"""The independent coin ledger: what confirmed transactions moved, from the chain alone.

docs/SLICE-1.5-PLAN.md 1.4 (piece P1); docs/TESTING.md principle 2: money is
counted from the transactions themselves, not by the code under test. This
tool links to no Gazpacho code. It has its own transaction parser and asks
each Esplora server the same questions, refusing any answer two servers
disagree on.

    python3 -I tools/chain-ledger.py --server URL --server URL --funding SAT TREE [options] TXID ...
    python3 -I tools/chain-ledger.py --server URL --server URL --funding SAT TREE [options] --follow TXID:VOUT

    TREE is --tree TXID (repeatable), --tree-file FILE, or --no-tree.

Transactions. Either a list of txids, or --follow TXID:VOUT: that transaction,
and every confirmed transaction that spends the named output, then every
output of those, and so on (the funding of a factory, followed from its
factory output; its other outputs, the host's change, are left alone).

For each transaction in the set, from every server:
  - the raw transaction (/tx/T/hex): every server must answer the same bytes,
    which must parse and hash to T;
  - its status (/tx/T/status): confirmed by every server, in the same block,
    with at least --min-conf confirmations (default 3, the burial depth) at
    the lowest tip any server reports (/blocks/tip/height);
  - each input's previous transaction (/tx/P/hex), checked the same way, for
    the value it spends: the servers' own "prevout" values are never used;
  - each output's spender (/tx/T/outspend/N): every server must name the
    same confirmed spender, or none. With --follow the spender joins the set;
    with a list, an output spent by a transaction outside the list is refused.

Then it prints every input and output, each transaction's fee (inputs less
outputs) and size, and the totals:

    funding = money in = fees + what is left in each group of outputs

"Money in" is every input that spends an output outside the set; "left" is
every output of the set that no transaction of the set spends. The second
equality holds for any set of transactions, so the checks that can fail are
the ones against what the caller knows without the chain:
  - --funding SAT (required): the satoshis the set takes from outside, as
    the test knows them (what it sent, or the host's coin);
  - every output left must be in a named group: --group NAME=SCRIPT_HEX
    (repeatable, several scripts may share a name), and every group so
    named needs its total, --expect NAME=SAT, unless --unchecked-groups. A
    240-sat pay-to-anchor output is in group "anchor" and a zero-value
    OP_RETURN output in "data" unless named; a pay-to-anchor or OP_RETURN
    output of any other value is like any other script. An output left to
    a script in no group is refused, unless --allow-unnamed, when it is
    counted in a group named after its script;
  - the host's tree (plan 1.4, steps 2 and 3), the txids it printed at
    signing: --tree TXID, or --tree-file FILE (its "sweep-tree ... txid=T"
    lines and the other sweep- lines it prints, bare lowercase txids, blank
    lines and # comments; any other line is a usage error).
      - Each transaction of the host's set that is in the set must be
        version 3 with a 240-sat pay-to-anchor output last.
      - One of the host's set confirmed but not in the set is refused.
      - With --follow, the followed output must be spent by a transaction
        of the host's set, or by none.
      - A transaction of the set shaped like a tree transaction (version 3,
        a pay-to-anchor output last) that is not in the host's set is
        refused, unless every input it spends is a pay-to-anchor output (a
        child on an anchor). This rule sees tree-shaped transactions only: a
        stranger that is not version 3 with an anchor last passes it, and is
        caught, if at all, by the funding and the groups above.
      - With a list, at least one transaction of the host's set must be in
        the list.
    --no-tree skips these checks, for a set that is not a factory's.
--expect NAME=SAT checks a group's total ("in" and "fees" check money in and
the fees; a name that is neither these, "anchor", "data" nor a --group is a
usage error); --expect-fee TXID=SAT checks one transaction's fee.

Servers: https:// URLs (http:// only to a loopback address, for a regtest
shim; a redirect is refused), or fixture:FILE, a recorded set of answers
for tests: a JSON object {"paths": {"/tx/T/hex": {"status": 200, "body":
"..."}, ...}}; a path not in it is answered 404. At least two servers
unless --one-server. At most MAX_TXS transactions in the set, MAX_FETCHED
read in all, and MAX_OUTSPENDS spenders asked for.

Exit codes: 0 every check passed; 1 a check failed (servers disagree, a
transaction not confirmed or not buried, an answer that is not the
transaction asked for, an output spent twice or outside the set, a negative
fee, the funding not met, an output left unnamed, a tree check, an expected
total not met); 2 usage; 3 a server could not be read or sent something
malformed. Read only: it never broadcasts. Standard library only.
"""
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 4 * 1024 * 1024
MAX_TXS = 20000                  # the set; 1,000 members make about 2,600 tree transactions and their children
MAX_FETCHED = 3 * MAX_TXS        # the set and the transactions its inputs spend
MAX_OUTSPENDS = 5 * MAX_TXS      # spenders asked for, each from every server
MAX_TREE_FILE = 64 * 1024 * 1024
ANCHOR_SAT = 240
MAX_MONEY = 21000000 * 100000000
# Always used with fullmatch: ASCII only, and "$" would let a newline through.
HEX64 = re.compile(r"[0-9a-f]{64}")
HEXRE = re.compile(r"[0-9a-f]*")
DIGITS = re.compile(r"[0-9]{1,16}")
P2A = bytes.fromhex("51024e73")


class Malformed(Exception):
    """A server's answer could not be read (exit 3)."""


class Mismatch(Exception):
    """A check failed (exit 1)."""


class Usage(Exception):
    """Bad arguments (exit 2)."""


# ---- reading transactions ------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise Malformed("transaction ends early")
        r = self.b[self.i:self.i + n]
        self.i += n
        return r

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def varint(self):
        n = self.take(1)[0]
        if n < 0xfd:
            return n
        size = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
        v = int.from_bytes(self.take(size), "little")
        if v < {2: 0xfd, 4: 0x10000, 8: 0x100000000}[size]:
            raise Malformed("non-canonical length")
        return v


def parse_tx(raw):
    """Parses one transaction; returns a dict. Strict: nothing may follow it."""
    r = Reader(raw)
    version = r.u32()
    segwit = False
    if len(raw) > 5 and raw[4] == 0:
        if raw[5] != 1:
            raise Malformed("bad segwit flag")
        r.take(2)
        segwit = True
    n_in = r.varint()
    if n_in == 0 or n_in > 100000:
        raise Malformed("bad input count")
    ins = []
    for _ in range(n_in):
        prev = r.take(32)[::-1].hex()
        vout = r.u32()
        script = r.take(r.varint())
        seq = r.u32()
        ins.append({"prev_txid": prev, "prev_vout": vout, "script_sig": script.hex(), "sequence": seq})
    n_out = r.varint()
    if n_out == 0 or n_out > 100000:
        raise Malformed("bad output count")
    outs = []
    for _ in range(n_out):
        value = r.u64()
        if value > MAX_MONEY:
            raise Malformed("output value above the supply")
        outs.append({"value": value, "script": r.take(r.varint()).hex()})
    base_end_io = r.i
    if segwit:
        for _ in range(n_in):
            for _ in range(r.varint()):
                r.take(r.varint())
    wit_end = r.i
    locktime = r.u32()
    if r.i != len(raw):
        raise Malformed("bytes after the transaction")
    if segwit:
        stripped = raw[:4] + raw[6:base_end_io] + raw[wit_end:]
    else:
        stripped = raw
    weight = len(stripped) * 3 + len(raw)
    return {"txid": sha256d(stripped)[::-1].hex(), "version": version, "segwit": segwit,
            "inputs": ins, "outputs": outs, "locktime": locktime,
            "weight": weight, "vsize": (weight + 3) // 4}


def script_kind(h):
    b = bytes.fromhex(h)
    if b == P2A:
        return "p2a"
    if len(b) == 34 and b[0] == 0x51 and b[1] == 0x20:
        return "p2tr"
    if len(b) == 22 and b[0] == 0x00 and b[1] == 0x14:
        return "p2wpkh"
    if len(b) == 34 and b[0] == 0x00 and b[1] == 0x20:
        return "p2wsh"
    if b[:1] == b"\x6a":
        return "op_return"
    return "other"


# ---- servers -------------------------------------------------------------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is answered as its own status (3xx), so it is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Server:
    def __init__(self, spec):
        self.spec = spec
        if spec.startswith("fixture:"):
            path = spec[len("fixture:"):]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.paths = data["paths"]
                if not isinstance(self.paths, dict):
                    raise ValueError
            except (OSError, ValueError, KeyError, TypeError):
                raise Usage("cannot read fixture %s" % path)
            self.base = None
        else:
            u = urllib.parse.urlsplit(spec)
            loop = u.hostname in ("127.0.0.1", "localhost", "::1")
            if u.scheme not in ("https", "http") or not u.hostname or (u.scheme == "http" and not loop):
                raise Usage("a server is https://..., http:// only on a loopback address, or fixture:FILE: %s" % spec)
            self.base = spec.rstrip("/")
            self.paths = None

    def get(self, path):
        """Returns (status, text)."""
        if self.paths is not None:
            e = self.paths.get(path)
            if e is None:
                return 404, "not found"
            if not isinstance(e, dict) or not isinstance(e.get("status"), int) or not isinstance(e.get("body"), str):
                raise Usage("bad fixture entry for %s in %s" % (path, self.spec))
            return e["status"], e["body"]
        req = urllib.request.Request(self.base + path, headers={"User-Agent": "chain-ledger"})
        try:
            with OPENER.open(req, timeout=30) as resp:
                body = resp.read(MAX_BODY + 1)
                status = resp.status
        except urllib.error.HTTPError as e:
            return e.code, ""
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise Malformed("%s%s: %s" % (self.spec, path, e))
        if len(body) > MAX_BODY:
            raise Malformed("%s%s: answer too long" % (self.spec, path))
        try:
            return status, body.decode("utf-8")
        except UnicodeDecodeError:
            raise Malformed("%s%s: not text" % (self.spec, path))

    def ok(self, path):
        status, text = self.get(path)
        if status != 200:
            raise Malformed("%s%s: HTTP %d" % (self.spec, path, status))
        return text

    def json(self, path):
        try:
            return json.loads(self.ok(path))
        except ValueError:
            raise Malformed("%s%s: not JSON" % (self.spec, path))


def need(cond, what):
    if not cond:
        raise Malformed(what)


def natural(x):
    """A JSON whole number of at least 0 (true and false are not numbers here)."""
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


class Chain:
    """Every question asked of every server; answers compared."""

    def __init__(self, servers, min_conf):
        self.servers = servers
        self.min_conf = min_conf
        self.txs = {}
        self.tip = None
        self.outspends = 0

    def tip_height(self):
        if self.tip is None:
            tips = []
            for s in self.servers:
                t = s.ok("/blocks/tip/height").strip()
                need(DIGITS.fullmatch(t) and len(t) < 12, "%s: tip height is not a number" % s.spec)
                tips.append(int(t))
            self.tip = min(tips)
        return self.tip

    def tx(self, txid):
        if txid in self.txs:
            return self.txs[txid]
        if len(self.txs) >= MAX_FETCHED:
            raise Mismatch("more than %d transactions to read" % MAX_FETCHED)
        raws = []
        for s in self.servers:
            h = s.ok("/tx/%s/hex" % txid).strip().lower()
            need(h and len(h) % 2 == 0 and HEXRE.fullmatch(h), "%s: /tx/%s/hex is not hex" % (s.spec, txid))
            raw = bytes.fromhex(h)
            t = parse_tx(raw)
            if t["txid"] != txid:
                raise Mismatch("%s answered another transaction for %s (it hashes to %s)" % (s.spec, txid, t["txid"]))
            raws.append(raw)
        if any(r != raws[0] for r in raws[1:]):
            raise Mismatch("servers disagree on the bytes of %s" % txid)
        t = parse_tx(raws[0])
        self.txs[txid] = t
        return t

    def status(self, txid):
        seen = []
        for s in self.servers:
            st = s.json("/tx/%s/status" % txid)
            need(isinstance(st, dict) and isinstance(st.get("confirmed"), bool),
                 "%s: /tx/%s/status has no confirmed flag" % (s.spec, txid))
            if st["confirmed"]:
                need(natural(st.get("block_height")) and isinstance(st.get("block_hash"), str)
                     and HEX64.fullmatch(st["block_hash"]), "%s: /tx/%s/status has no block" % (s.spec, txid))
                seen.append((st["block_height"], st["block_hash"]))
            else:
                seen.append(None)
        if any(x is None for x in seen):
            names = [s.spec for s, x in zip(self.servers, seen) if x is None]
            raise Mismatch("%s is not confirmed on %s" % (txid, ", ".join(names)))
        if any(x != seen[0] for x in seen[1:]):
            raise Mismatch("servers disagree on the block of %s: %s" % (txid, seen))
        height = seen[0][0]
        conf = self.tip_height() - height + 1
        if conf < self.min_conf:
            raise Mismatch("%s has %d confirmations, fewer than %d" % (txid, conf, self.min_conf))
        return height, seen[0][1], conf

    def on_chain(self, txid):
        """The servers that say txid is confirmed ("not found" counts as no)."""
        said = []
        for s in self.servers:
            code, text = s.get("/tx/%s/status" % txid)
            if code == 404:
                continue
            if code != 200:
                raise Malformed("%s/tx/%s/status: HTTP %d" % (s.spec, txid, code))
            try:
                st = json.loads(text)
            except ValueError:
                raise Malformed("%s/tx/%s/status: not JSON" % (s.spec, txid))
            need(isinstance(st, dict) and isinstance(st.get("confirmed"), bool),
                 "%s: /tx/%s/status has no confirmed flag" % (s.spec, txid))
            if st["confirmed"]:
                said.append(s.spec)
        return said

    def outspend(self, txid, vout, allow_pending):
        """The confirmed spender (txid, vin), or None. A spend still in a mempool is
        an error unless allow_pending, when the output counts as left."""
        self.outspends += 1
        if self.outspends > MAX_OUTSPENDS:
            raise Mismatch("more than %d spenders to ask for" % MAX_OUTSPENDS)
        seen, pending = [], False
        for s in self.servers:
            o = s.json("/tx/%s/outspend/%d" % (txid, vout))
            need(isinstance(o, dict) and isinstance(o.get("spent"), bool),
                 "%s: /tx/%s/outspend/%d has no spent flag" % (s.spec, txid, vout))
            if not o["spent"]:
                seen.append(None)
                continue
            st = o.get("status")
            need(isinstance(o.get("txid"), str) and HEX64.fullmatch(o["txid"]) and natural(o.get("vin"))
                 and isinstance(st, dict) and isinstance(st.get("confirmed"), bool),
                 "%s: /tx/%s/outspend/%d is malformed" % (s.spec, txid, vout))
            if not st["confirmed"]:
                pending = True
                seen.append(None)
                continue
            need(isinstance(st.get("block_hash"), str), "%s: outspend status has no block" % s.spec)
            seen.append((o["txid"], o["vin"], st["block_hash"]))
        if any(x != seen[0] for x in seen[1:]):
            raise Mismatch("servers disagree on the spender of %s:%d: %s" % (txid, vout, seen))
        if seen[0] is None and pending and not allow_pending:
            raise Mismatch("%s:%d is spent by a transaction not yet confirmed" % (txid, vout))
        return None if seen[0] is None else (seen[0][0], seen[0][1])


# ---- the ledger ----------------------------------------------------------

def build(chain, txids, follow, allow_pending):
    order, seen, spent_by = [], set(), {}
    if follow:
        root, vout = follow
        order.append(root)
        seen.add(root)
        queue = [(root, vout)]
        t = chain.tx(root)
        if vout >= len(t["outputs"]):
            raise Mismatch("%s has no output %d" % (root, vout))
        while queue:
            txid, n = queue.pop(0)
            sp = chain.outspend(txid, n, allow_pending)
            if sp is None:
                continue
            child, vin = sp
            ct = chain.tx(child)
            if vin >= len(ct["inputs"]) or (ct["inputs"][vin]["prev_txid"], ct["inputs"][vin]["prev_vout"]) != (txid, n):
                raise Mismatch("the servers' spender %s input %d does not spend %s:%d" % (child, vin, txid, n))
            spent_by[(txid, n)] = (child, vin)
            if child not in seen:
                if len(order) >= MAX_TXS:
                    raise Mismatch("more than %d transactions to follow" % MAX_TXS)
                order.append(child)
                seen.add(child)
                queue.extend((child, i) for i in range(len(ct["outputs"])))
    else:
        for t in txids:
            if t not in seen:
                order.append(t)
                seen.add(t)
    return order, spent_by


def ledger(chain, order, spent_by_follow, groups, listed=False, allow_pending=False, allow_unnamed=False):
    inset = set(order)
    used = {}
    rows, fees, money_in, left, unnamed = [], {}, 0, {}, []
    for txid in order:
        t = chain.tx(txid)
        height, block, conf = chain.status(txid)
        total_in = 0
        ins = []
        for i, x in enumerate(t["inputs"]):
            key = (x["prev_txid"], x["prev_vout"])
            if key in used:
                raise Mismatch("%s:%d is spent twice in the set (%s and %s)" % (key[0], key[1], used[key][0], txid))
            used[key] = (txid, i)
            prev = chain.tx(x["prev_txid"])
            if x["prev_vout"] >= len(prev["outputs"]):
                raise Mismatch("%s spends %s:%d, which does not exist" % (txid, key[0], key[1]))
            value = prev["outputs"][x["prev_vout"]]["value"]
            external = x["prev_txid"] not in inset
            if external:
                money_in += value
            total_in += value
            ins.append({"prev": "%s:%d" % key, "value": value, "external": external})
        total_out = sum(o["value"] for o in t["outputs"])
        fee = total_in - total_out
        if fee < 0:
            raise Mismatch("%s pays out %d more than it spends" % (txid, -fee))
        fees[txid] = fee
        rows.append({"txid": txid, "version": t["version"], "locktime": t["locktime"], "vsize": t["vsize"],
                     "height": height, "block": block, "confirmations": conf, "inputs": ins,
                     "outputs": [{"n": n, "value": o["value"], "script": o["script"], "kind": script_kind(o["script"])}
                                 for n, o in enumerate(t["outputs"])],
                     "fee": fee})
    for row in rows:
        for o in row["outputs"]:
            key = (row["txid"], o["n"])
            if key in used:
                o["spent_by"] = "%s:%d" % used[key]
                continue
            if listed and key not in spent_by_follow:
                sp = chain.outspend(key[0], key[1], allow_pending)
                if sp is not None:
                    spent_by_follow[key] = sp
            if key in spent_by_follow:
                raise Mismatch("%s:%d is spent by %s, which is not in the set" % (key[0], key[1], spent_by_follow[key][0]))
            g = groups.get(o["script"])
            if g is None:
                if o["kind"] == "p2a" and o["value"] == ANCHOR_SAT:
                    g = "anchor"
                elif o["kind"] == "op_return" and o["value"] == 0:
                    g = "data"
            if g is None:
                if not allow_unnamed:
                    unnamed.append("%s:%d %d sat to %s" % (key[0], key[1], o["value"], o["script"]))
                g = "script:" + o["script"]
            o["group"] = g
            left[g] = left.get(g, 0) + o["value"]
    if unnamed:
        raise Mismatch("left to a script in no group (name it with --group, or --allow-unnamed): "
                       + "; ".join(unnamed[:20]) + ("; and %d more" % (len(unnamed) - 20) if len(unnamed) > 20 else ""))
    total_fees = sum(fees.values())
    if money_in != total_fees + sum(left.values()):     # cannot happen: every fee is inputs less outputs
        raise Mismatch("money in %d is not fees %d plus outputs left %d" % (money_in, total_fees, sum(left.values())))
    return {"transactions": rows, "money_in": money_in, "fees": total_fees, "groups": left,
            "tip": chain.tip_height()}


def tree_checks(chain, order, tree, follow):
    """Plan 1.4 steps 2 and 3, against the host's printed set of tree txids."""
    inset = set(order)
    for txid in order:
        t = chain.tx(txid)
        last = t["outputs"][-1]
        shaped = t["version"] == 3 and last["script"] == P2A.hex()
        if txid in tree:
            if not shaped or last["value"] != ANCHOR_SAT:
                raise Mismatch("%s is in the host's set but is not version 3 with a %d-sat pay-to-anchor output last"
                               % (txid, ANCHOR_SAT))
            continue
        for x in t["inputs"]:
            key = (x["prev_txid"], x["prev_vout"])
            if follow and key == tuple(follow):
                raise Mismatch("the followed output %s:%d is spent by %s, not a tree transaction of the host's set"
                               % (key[0], key[1], txid))
        if shaped:
            # A child on an anchor spends pay-to-anchor outputs only; anything else
            # shaped like a tree transaction must be one of the host's.
            for x in t["inputs"]:
                prev = chain.tx(x["prev_txid"])
                if x["prev_vout"] >= len(prev["outputs"]) or prev["outputs"][x["prev_vout"]]["script"] != P2A.hex():
                    raise Mismatch("%s looks like a tree transaction (version 3, a pay-to-anchor last) and spends "
                                   "%s:%d, but is not in the host's set" % (txid, x["prev_txid"], x["prev_vout"]))
    if not follow and not (tree & inset):
        raise Mismatch("none of the host's tree transactions is in the set")
    for txid in sorted(tree - inset):
        said = chain.on_chain(txid)
        if said:
            raise Mismatch("%s of the host's set is confirmed (%s) but not in the set" % (txid, ", ".join(said)))


def check_expectations(result, expect, expect_fee):
    bad = []
    for name, want in expect:
        if name == "in":
            got = result["money_in"]
        elif name == "fees":
            got = result["fees"]
        else:
            got = result["groups"].get(name, 0)
        if got != want:
            bad.append("%s is %d, expected %d" % (name, got, want))
    fees = {r["txid"]: r["fee"] for r in result["transactions"]}
    for txid, want in expect_fee:
        if txid not in fees:
            bad.append("no transaction %s in the set" % txid)
        elif fees[txid] != want:
            bad.append("the fee of %s is %d, expected %d" % (txid, fees[txid], want))
    return bad


def print_text(result, out):
    for r in result["transactions"]:
        out.write("tx %s version %d height %d (%d confirmations) locktime %d vsize %d\n"
                  % (r["txid"], r["version"], r["height"], r["confirmations"], r["locktime"], r["vsize"]))
        for i, x in enumerate(r["inputs"]):
            out.write("  in  %d %s %d %s\n" % (i, x["prev"], x["value"], "money in" if x["external"] else "in the set"))
        for o in r["outputs"]:
            where = ("spent by " + o["spent_by"]) if "spent_by" in o else ("left, group " + o["group"])
            out.write("  out %d %d %s %s\n" % (o["n"], o["value"], o["kind"], where))
        out.write("  fee %d\n" % r["fee"])
    out.write("money in %d\n" % result["money_in"])
    out.write("fees %d\n" % result["fees"])
    for g in sorted(result["groups"]):
        out.write("group %s %d\n" % (g, result["groups"][g]))
    parts = ["%d (fees)" % result["fees"]] + ["%d (%s)" % (result["groups"][g], g) for g in sorted(result["groups"])]
    out.write("balance %d = %s\n" % (result["money_in"], " + ".join(parts)))
    out.write("funding %d = money in\n" % result["funding"])


# ---- arguments -----------------------------------------------------------

def read_tree_file(path):
    """The host's printed tree: "sweep-tree ... txid=T ..." lines, or one txid a line."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_TREE_FILE + 1)
    except OSError:
        raise Usage("cannot read %s" % path)
    if len(data) > MAX_TREE_FILE:
        raise Usage("%s is too long" % path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Usage("%s is not text" % path)
    tree = set()
    for n, line in enumerate(text.splitlines(), 1):
        w = line.split()
        if not w or w[0].startswith("#"):
            continue
        if w[0] == "sweep-tree":
            t = [x[5:] for x in w[1:] if x.startswith("txid=")]
            if len(t) != 1 or not HEX64.fullmatch(t[0]):
                raise Usage("%s line %d: a sweep-tree line without one lowercase txid" % (path, n))
            tree.add(t[0])
        elif w[0] in ("sweep-round", "sweep-spend", "sweep-refused"):
            continue                       # the host's other lines about the same round
        elif len(w) == 1 and HEX64.fullmatch(w[0]):
            tree.add(w[0])
        else:
            raise Usage("%s line %d: neither the host's sweep- lines nor a lowercase txid" % (path, n))
    if not tree:
        raise Usage("%s holds no tree txid" % path)
    if len(tree) > MAX_TXS:
        raise Usage("%s holds more than %d txids" % (path, MAX_TXS))
    return tree


def parse_args(argv):
    a = {"servers": [], "txids": [], "follow": None, "groups": {}, "expect": [], "expect_fee": [],
         "min_conf": 3, "json": False, "one": False, "pending": False, "funding": None, "tree": None,
         "tree_txids": [], "tree_file": None, "no_tree": False, "unnamed": False, "unchecked": False}
    i = 0

    def val():
        nonlocal i
        i += 1
        if i >= len(argv):
            raise Usage("%s needs a value" % argv[i - 1])
        return argv[i]

    def sat(s):
        if not DIGITS.fullmatch(s):
            raise Usage("not an amount in satoshis: %s" % s)
        return int(s)

    while i < len(argv):
        x = argv[i]
        if x == "--server":
            a["servers"].append(val())
        elif x == "--follow":
            t, _, v = val().partition(":")
            if not HEX64.fullmatch(t) or not DIGITS.fullmatch(v):
                raise Usage("--follow takes TXID:VOUT")
            a["follow"] = (t, int(v))
        elif x == "--group":
            name, _, h = val().partition("=")
            h = h.lower()
            if not name or not h or len(h) % 2 or not HEXRE.fullmatch(h) or name in ("in", "fees"):
                raise Usage("--group takes NAME=SCRIPT_HEX")
            if h in a["groups"] and a["groups"][h] != name:
                raise Usage("script %s is in two groups" % h)
            a["groups"][h] = name
        elif x == "--expect":
            name, _, v = val().partition("=")
            if not name:
                raise Usage("--expect takes NAME=SAT")
            a["expect"].append((name, sat(v)))
        elif x == "--expect-fee":
            t, _, v = val().partition("=")
            if not HEX64.fullmatch(t):
                raise Usage("--expect-fee takes TXID=SAT")
            a["expect_fee"].append((t, sat(v)))
        elif x == "--min-conf":
            v = val()
            if not DIGITS.fullmatch(v) or int(v) < 1 or int(v) > 1000000:
                raise Usage("--min-conf takes a count of at least 1")
            a["min_conf"] = int(v)
        elif x == "--funding":
            a["funding"] = sat(val())
        elif x == "--tree":
            t = val()
            if not HEX64.fullmatch(t):
                raise Usage("--tree takes a txid")
            a["tree_txids"].append(t)
        elif x == "--tree-file":
            a["tree_file"] = val()
        elif x == "--no-tree":
            a["no_tree"] = True
        elif x == "--allow-unnamed":
            a["unnamed"] = True
        elif x == "--unchecked-groups":
            a["unchecked"] = True
        elif x == "--json":
            a["json"] = True
        elif x == "--one-server":
            a["one"] = True
        elif x == "--allow-pending":
            a["pending"] = True
        elif x in ("-h", "--help"):
            raise Usage(None)
        elif x.startswith("-"):
            raise Usage("unknown option %s" % x)
        else:
            if not HEX64.fullmatch(x):
                raise Usage("not a txid: %s" % x)
            a["txids"].append(x)
        i += 1
    if bool(a["txids"]) == bool(a["follow"]):
        raise Usage("give either txids or --follow TXID:VOUT")
    if len(a["txids"]) > MAX_TXS:
        raise Usage("more than %d txids" % MAX_TXS)
    if a["funding"] is None:
        raise Usage("give --funding SAT: the satoshis the set takes from outside, as the test knows them")
    if a["no_tree"] == bool(a["tree_txids"] or a["tree_file"]):
        raise Usage("give the host's tree (--tree TXID or --tree-file FILE), or --no-tree")
    if not a["no_tree"]:
        a["tree"] = set(a["tree_txids"])
        if a["tree_file"]:
            a["tree"] |= read_tree_file(a["tree_file"])
    names = {"in", "fees", "anchor", "data"} | set(a["groups"].values())
    for name, _ in a["expect"]:
        if name not in names:
            raise Usage("--expect %s: no group of that name (give it with --group)" % name)
    if not a["unchecked"]:
        expected = {name for name, _ in a["expect"]}
        missing = sorted(set(a["groups"].values()) - expected)
        if missing:
            raise Usage("no --expect for the group%s %s: give each named group its total, or --unchecked-groups"
                        % ("s" if len(missing) > 1 else "", ", ".join(missing)))
    if len(a["servers"]) < (1 if a["one"] else 2):
        raise Usage("give at least two --server (or --one-server)")
    return a


def main(argv):
    try:
        a = parse_args(argv)
        servers = [Server(s) for s in a["servers"]]
        chain = Chain(servers, a["min_conf"])
        order, spent_by = build(chain, a["txids"], a["follow"], a["pending"])
        if a["tree"] is not None:
            tree_checks(chain, order, a["tree"], a["follow"])
        result = ledger(chain, order, spent_by, a["groups"], listed=not a["follow"], allow_pending=a["pending"],
                        allow_unnamed=a["unnamed"])
        if result["money_in"] != a["funding"]:
            raise Mismatch("money in %d is not the funding %d" % (result["money_in"], a["funding"]))
        result["funding"] = a["funding"]
    except Usage as e:
        if e.args and e.args[0]:
            sys.stderr.write("chain-ledger: %s\n" % e.args[0])
        sys.stderr.write("\n\n".join(__doc__.split("\n\n")[2:4]) + "\n")
        return 2
    except Malformed as e:
        sys.stderr.write("chain-ledger: unreadable answer: %s\n" % e)
        return 3
    except Mismatch as e:
        sys.stderr.write("chain-ledger: MISMATCH: %s\n" % e)
        return 1
    bad = check_expectations(result, a["expect"], a["expect_fee"])
    result["expectations_failed"] = bad
    if a["json"]:
        sys.stdout.write(json.dumps(result, indent=1, sort_keys=True) + "\n")
    else:
        print_text(result, sys.stdout)
    for b in bad:
        sys.stderr.write("chain-ledger: MISMATCH: %s\n" % b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
