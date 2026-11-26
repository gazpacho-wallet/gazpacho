#!/usr/bin/env python3
"""Test for tools/chain-ledger.py, on recorded answers only (no network).

    python3 -I tests/tools/test_chain_ledger.py

The fixture is signet run 1 of the Slice 1 integration (docs/notes/integration.md
section 8 on integration-slice1) and its planned recovery:

  - the host's coin ceab0e5a...:0, 100,000 sat, and the funding 26a86fc0...,
    both real signet transactions, recorded byte for byte from two operators'
    Esplora servers (mempool.space and blockstream.info answered the same);
  - the root kickoff and the host's timeout sweep, built here with the
    recovery's amounts (root fee 17, a 240-sat anchor, sweep fee 26), since
    the real ones are broadcast later. The tool is checked live on those.

    100,000 = 16 + 17,173 + 17 + 240 + 26 + 82,528

The transactions built here are serialised by this file's own code, not the
tool's parser. Every case writes two fixture files, one per "server", and
mutates one or both of them. The outspend answers are built here too.

Every imbalance case of section 8 gives no --expect: the tool must refuse it
by itself (an unknown spend, a satoshi moved, a tree transaction outside the
host's set, an output left to a script nobody named).

The plan's P1 also names the recorded answers of program_sweep's regtest
factory. That run lives on integration-slice1 and has no recording yet; it
is added when its harness can write one. Standard library only.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools", "chain-ledger.py")
failures = []

# ---- recorded signet answers (2026-11-25; identical on both operators) ----

COIN_TXID = "ceab0e5acfefe9665d4ecdcbc9a8794d1ea17b9032cf8277b5e828248a90791c"
COIN_HEX = ("02000000000101a12e094850b99a74acd9c2066a737ccd53dd0259b68573d48ba960ee5c99e6f10100000000feffffff02a086"
            "010000000000225120e1d2e50fce58f3452ecd831682c789bc0b2c4de043b409811ba0ee2a10074cdfc5c39900000000002251"
            "2084e7a5be08fa8f18c5f9214130c9cf314004769b2b8114a3663b1eb312bd1e3601406606dc3b17ea68f16cee5fb0b62bb1f8"
            "1a5b292e0512efec2d7a3e7c382ab13b7d63e0cce3154e067137196fc6e3d164fa062fe8c24701469f29ee6560703a0900000000")
FUND_TXID = "26a86fc0f31110d9fe3a36418c8e699bae3b7c25c8862c68b7e76c31ad9d29ec"
FUND_HEX = ("020000000001011c79908a2428e8b57782cf32907ba11e4d79a8c9cbcd4e5d66e9efcf5a0eabce0000000000feffffff027b43"
            "010000000000225120f8c691f7aaec03196e44efff26c81de5dbace05de1dd2779d726a6d6e4a057cc15430000000000002251"
            "20052ed6c8478a601ac496875ff7c7f0bdf65e6c4da9514cb23d154535a18851d901404872914da7a51475ff6506451b34639b"
            "bb1ffae36d3c9181670a04156e4aa959b8ebb655356f7796f528f4ef990af7f8e1a1a324fa520180b01838a5aee2951b00000000")
FUND_STATUS = ('{"confirmed":true,"block_height":332374,"block_hash":'
               '"00000008ed20cf94802de0e4bc1e8bbff8d2d8278bf6a8d94a111b8f9ddddf53","block_time":1795568006}')
FACTORY_SPK = "5120f8c691f7aaec03196e44efff26c81de5dbace05de1dd2779d726a6d6e4a057cc"
CHANGE_SPK = "5120052ed6c8478a601ac496875ff7c7f0bdf65e6c4da9514cb23d154535a18851d9"

# ---- this file's own serialiser -----------------------------------------


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def serialise(version, ins, outs, locktime, witnesses=None):
    """ins: (txid_hex, vout, sequence); outs: (value, script_hex); witnesses: one list of items per input."""
    body = varint(len(ins))
    for txid, vout, seq in ins:
        body += bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little") + b"\x00" + seq.to_bytes(4, "little")
    body += varint(len(outs))
    for value, spk in outs:
        s = bytes.fromhex(spk)
        body += value.to_bytes(8, "little") + varint(len(s)) + s
    v = version.to_bytes(4, "little")
    lt = locktime.to_bytes(4, "little")
    stripped = v + body + lt
    txid = hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()
    if not witnesses:
        return txid, stripped.hex()
    wit = b""
    for items in witnesses:
        wit += varint(len(items)) + b"".join(varint(len(x)) + x for x in items)
    return txid, (v + b"\x00\x01" + body + wit + lt).hex()


P2A = "51024e73"
BRANCH_A = "5120" + "a1" * 32
BRANCH_B = "5120" + "b2" * 32
HOST_FIRST = "5120" + "c3" * 32          # the host's first receive address (built)

ROOT_TXID, ROOT_HEX = serialise(3, [(FUND_TXID, 0, 0xfffffffd)],
                                [(41277, BRANCH_A), (41277, BRANCH_B), (240, P2A)], 0, [[b"\x11" * 64]])
SWEEP_TXID, SWEEP_HEX = serialise(2, [(ROOT_TXID, 0, 0xfffffffe), (ROOT_TXID, 1, 0xfffffffe)],
                                  [(82528, HOST_FIRST)], 332548,
                                  [[b"\x22" * 64, b"\x33" * 40, b"\xc0" + b"\x44" * 32],
                                   [b"\x55" * 64, b"\x33" * 40, b"\xc0" + b"\x66" * 32]])


def status(height, tag):
    return json.dumps({"confirmed": True, "block_height": height, "block_hash": tag * 32, "block_time": 1795600000})


def spent(txid, vin, height, tag):
    return json.dumps({"spent": True, "txid": txid, "vin": vin,
                       "status": {"confirmed": True, "block_height": height, "block_hash": tag * 32}})


UNSPENT = json.dumps({"spent": False})


def base_paths():
    p = {
        "/blocks/tip/height": "332560",
        "/tx/%s/hex" % COIN_TXID: COIN_HEX,
        "/tx/%s/hex" % FUND_TXID: FUND_HEX,
        "/tx/%s/hex" % ROOT_TXID: ROOT_HEX,
        "/tx/%s/hex" % SWEEP_TXID: SWEEP_HEX,
        "/tx/%s/status" % FUND_TXID: FUND_STATUS,
        "/tx/%s/status" % ROOT_TXID: status(332400, "0a"),
        "/tx/%s/status" % SWEEP_TXID: status(332549, "0b"),
        "/tx/%s/outspend/0" % FUND_TXID: spent(ROOT_TXID, 0, 332400, "0a"),
        "/tx/%s/outspend/1" % FUND_TXID: UNSPENT,
        "/tx/%s/outspend/0" % ROOT_TXID: spent(SWEEP_TXID, 0, 332549, "0b"),
        "/tx/%s/outspend/1" % ROOT_TXID: spent(SWEEP_TXID, 1, 332549, "0b"),
        "/tx/%s/outspend/2" % ROOT_TXID: UNSPENT,
        "/tx/%s/outspend/0" % SWEEP_TXID: UNSPENT,
    }
    return {k: {"status": 200, "body": v} for k, v in p.items()}


GROUPS = ["--group", "host=" + CHANGE_SPK, "--group", "host=" + HOST_FIRST]
EXPECT = ["--expect", "in=100000", "--expect", "fees=59", "--expect", "host=99701", "--expect", "anchor=240",
          "--expect-fee", "%s=16" % FUND_TXID, "--expect-fee", "%s=17" % ROOT_TXID,
          "--expect-fee", "%s=26" % SWEEP_TXID]
FOLLOW = ["--follow", FUND_TXID + ":0", "--funding", "100000", "--tree", ROOT_TXID] + GROUPS
LIST = [FUND_TXID, ROOT_TXID, SWEEP_TXID]
LISTED = LIST + ["--funding", "100000", "--tree", ROOT_TXID] + GROUPS
STRANGER = "5120" + "ee" * 32           # a script nobody named


def with_txs(p, *txs):
    """Adds (txid, hex, height, tag) transactions to a path table."""
    for txid, hx, height, tag in txs:
        p["/tx/%s/hex" % txid] = {"status": 200, "body": hx}
        p["/tx/%s/status" % txid] = {"status": 200, "body": status(height, tag)}
    return p


def setp(p, path, body):
    p[path] = {"status": 200, "body": body}
    return p


def run(work, name, a_paths, b_paths, args):
    fa = os.path.join(work, name + "-a.json")
    fb = os.path.join(work, name + "-b.json")
    for f, p in ((fa, a_paths), (fb, b_paths)):
        with open(f, "w", encoding="utf-8") as h:
            json.dump({"paths": p}, h)
    r = subprocess.run([sys.executable, "-I", TOOL, "--server", "fixture:" + fa, "--server", "fixture:" + fb] + args,
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def check(cond, what, detail=""):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)
        if detail:
            print("     " + detail.strip().replace("\n", "\n     "))


def expect_code(work, name, b_paths, args, code, words):
    c, out, err = run(work, name, base_paths(), b_paths, args)
    check(c == code and all(w in err for w in words), "%s: exit %d with %s" % (name, code, words),
          "exit %d\nstdout %s\nstderr %s" % (c, out[-400:], err[-400:]))


def mutate(**changes):
    p = base_paths()
    for k, v in changes.items():
        path = {"fund_hex": "/tx/%s/hex" % FUND_TXID, "sweep_hex": "/tx/%s/hex" % SWEEP_TXID,
                "coin_hex": "/tx/%s/hex" % COIN_TXID, "sweep_status": "/tx/%s/status" % SWEEP_TXID,
                "root_status": "/tx/%s/status" % ROOT_TXID, "root_out1": "/tx/%s/outspend/1" % ROOT_TXID,
                "tip": "/blocks/tip/height"}[k]
        if v is None:
            del p[path]
        elif isinstance(v, tuple):
            p[path] = {"status": v[0], "body": v[1]}
        else:
            p[path] = {"status": 200, "body": v}
    return p


def main():
    with tempfile.TemporaryDirectory() as work:
        # 1. Run 1, followed from the factory output: the whole recovery balances.
        c, out, err = run(work, "follow", base_paths(), base_paths(), FOLLOW + EXPECT)
        check(c == 0, "run 1 followed from the funding: every check passes", out + err)
        check("balance 100000 = 59 (fees) + 240 (anchor) + 99701 (host)" in out,
              "the balance line: 100,000 = fees 59 (16 + 17 + 26) + anchor 240 + host 99,701 (17,173 + 82,528)", out)
        check(("tx %s version 2" % FUND_TXID) in out and ("tx %s version 3" % ROOT_TXID) in out,
              "the real funding parsed (its own txid) and the root kickoff is version 3", out)

        c, out, err = run(work, "json", base_paths(), base_paths(), FOLLOW + ["--json"])
        try:
            j = json.loads(out)
            fees = [t["fee"] for t in j["transactions"]]
            ok = (c == 0 and j["money_in"] == 100000 and j["fees"] == 59 and fees == [16, 17, 26]
                  and j["groups"] == {"host": 99701, "anchor": 240}
                  and [t["txid"] for t in j["transactions"]] == LIST
                  and j["transactions"][2]["confirmations"] == 12)
        except (ValueError, KeyError, IndexError, TypeError):
            ok = False
        check(ok, "--json: the same totals, per-transaction fees 16, 17, 26, the sweep 12 blocks deep", out + err)

        # 2. The same transactions given as a list.
        c, out, err = run(work, "list", base_paths(), base_paths(), LISTED + EXPECT)
        check(c == 0 and "balance 100000 = 59 (fees) + 240 (anchor) + 99701 (host)" in out,
              "run 1 given as a list of txids: the same balance", out + err)

        # 3. Expectations.
        expect_code(work, "expect-host", base_paths(), FOLLOW + ["--expect", "host=99700"], 1,
                    ["host is 99701, expected 99700"])
        expect_code(work, "expect-fee", base_paths(), FOLLOW + ["--expect-fee", "%s=25" % SWEEP_TXID], 1,
                    ["expected 25"])

        # 4. Servers that disagree.
        expect_code(work, "other-tx", mutate(sweep_hex=ROOT_HEX), FOLLOW, 1, ["answered another transaction"])
        expect_code(work, "block-differs", mutate(root_status=status(332400, "0c")), FOLLOW, 1,
                    ["disagree on the block"])
        expect_code(work, "height-differs", mutate(root_status=status(332401, "0a")), FOLLOW, 1,
                    ["disagree on the block"])
        expect_code(work, "unconfirmed-on-one", mutate(sweep_status='{"confirmed":false}'), FOLLOW, 1,
                    ["is not confirmed on"])
        expect_code(work, "spender-differs", mutate(root_out1=UNSPENT), FOLLOW, 1, ["disagree on the spender"])
        pending = json.dumps({"spent": True, "txid": SWEEP_TXID, "vin": 1, "status": {"confirmed": False}})
        expect_code(work, "spender-pending-on-one", mutate(root_out1=pending), FOLLOW, 1, ["disagree on the spender"])

        # 5. Malformed or missing answers.
        expect_code(work, "not-hex", mutate(fund_hex="zz" + FUND_HEX[2:]), FOLLOW, 3, ["is not hex"])
        expect_code(work, "truncated", mutate(fund_hex=FUND_HEX[:-10]), FOLLOW, 3, ["ends early"])
        expect_code(work, "trailing", mutate(fund_hex=FUND_HEX + "00"), FOLLOW, 3, ["bytes after"])
        expect_code(work, "status-not-json", mutate(root_status="{confirmed"), FOLLOW, 3, ["not JSON"])
        expect_code(work, "status-no-flag", mutate(root_status="{}"), FOLLOW, 3, ["no confirmed flag"])
        expect_code(work, "prev-missing", mutate(coin_hex=None), FOLLOW, 3, ["HTTP 404"])
        expect_code(work, "server-error", mutate(coin_hex=(500, "oops")), FOLLOW, 3, ["HTTP 500"])
        expect_code(work, "tip-not-number", mutate(tip="tip"), FOLLOW, 3, ["not a number"])
        expect_code(work, "redirect", mutate(coin_hex=(302, "")), FOLLOW, 3, ["HTTP 302"])

        # 6. Not buried: the lower tip of the two counts.
        expect_code(work, "shallow", mutate(tip="332550"), FOLLOW + ["--min-conf", "3"], 1,
                    ["has 2 confirmations, fewer than 3"])

        # 7. A negative fee, and an output spent twice in the set.
        bad_txid, bad_hex = serialise(2, [(COIN_TXID, 0, 0xffffffff)], [(100001, CHANGE_SPK)], 0)
        bp = with_txs(base_paths(), (bad_txid, bad_hex, 332380, "0d"))
        plain = ["--funding", "100000", "--no-tree", "--allow-unnamed"]
        c, out, err = run(work, "negative-fee", bp, bp, [bad_txid] + plain)
        check(c == 1 and "pays out 1 more than it spends" in err, "a transaction paying out more than it spends: exit 1",
              err)
        c, out, err = run(work, "twice", bp, bp, [FUND_TXID, bad_txid] + plain)
        check(c == 1 and "spent twice in the set" in err, "two transactions of the set spending one output: exit 1", err)

        # 8. Imbalances the tool must refuse by itself: no --expect anywhere below.
        # 8a. The funding the caller knows is one satoshi more than went in.
        c, out, err = run(work, "funding-off", base_paths(), base_paths(),
                          ["--follow", FUND_TXID + ":0", "--funding", "100001", "--tree", ROOT_TXID] + GROUPS)
        check(c == 1 and "is not the funding 100001" in err, "funding one satoshi off: exit 1", err)

        # 8b. An extra unknown spend: the sweep left out of the list, though it spends the root's outputs.
        c, out, err = run(work, "list-omits-sweep", base_paths(), base_paths(),
                          [FUND_TXID, ROOT_TXID, "--funding", "100000", "--tree", ROOT_TXID] + GROUPS)
        check(c == 1 and ("is spent by %s, which is not in the set" % SWEEP_TXID) in err,
              "a list missing the sweep: the root's outputs are spent outside the set, exit 1", err)

        # 8c. Both servers hide the sweep: the root's outputs would be left to scripts nobody named.
        hide = base_paths()
        setp(hide, "/tx/%s/outspend/0" % ROOT_TXID, UNSPENT)
        setp(hide, "/tx/%s/outspend/1" % ROOT_TXID, UNSPENT)
        c, out, err = run(work, "servers-hide-sweep", hide, hide, FOLLOW)
        check(c == 1 and "left to a script in no group" in err and "5120a1" in err,
              "both servers hiding the sweep: the root's outputs left unnamed, exit 1", err)

        # 8d. One satoshi of the sweep paid to a script nobody named instead of the host.
        s_txid, s_hex = serialise(2, [(ROOT_TXID, 0, 0xfffffffe), (ROOT_TXID, 1, 0xfffffffe)],
                                  [(82527, HOST_FIRST), (1, STRANGER)], 332548,
                                  [[b"\x22" * 64], [b"\x55" * 64]])
        sp = with_txs(base_paths(), (s_txid, s_hex, 332549, "0b"))
        setp(sp, "/tx/%s/outspend/0" % ROOT_TXID, spent(s_txid, 0, 332549, "0b"))
        setp(sp, "/tx/%s/outspend/1" % ROOT_TXID, spent(s_txid, 1, 332549, "0b"))
        setp(sp, "/tx/%s/outspend/0" % s_txid, UNSPENT)
        setp(sp, "/tx/%s/outspend/1" % s_txid, UNSPENT)
        c, out, err = run(work, "satoshi-to-stranger", sp, sp, FOLLOW)
        check(c == 1 and "left to a script in no group" in err and STRANGER in err,
              "one satoshi of the sweep to a script nobody named: exit 1", err)
        c, out, err = run(work, "satoshi-to-stranger-allowed", sp, sp, FOLLOW + ["--allow-unnamed"])
        check(c == 0 and ("group script:%s 1" % STRANGER) in out,
              "the same with --allow-unnamed, the explicit opt-in: it balances and names the script", out + err)

        # 8e. One satoshi altered in the root kickoff (fee 16, a branch 41,278): a tree
        # transaction the host never printed spends the funding.
        a_root, a_root_hex = serialise(3, [(FUND_TXID, 0, 0xfffffffd)],
                                       [(41278, BRANCH_A), (41277, BRANCH_B), (240, P2A)], 0, [[b"\x11" * 64]])
        a_sweep, a_sweep_hex = serialise(2, [(a_root, 0, 0xfffffffe), (a_root, 1, 0xfffffffe)],
                                         [(82529, HOST_FIRST)], 332548, [[b"\x22" * 64], [b"\x55" * 64]])
        ap = with_txs(base_paths(), (a_root, a_root_hex, 332400, "0a"), (a_sweep, a_sweep_hex, 332549, "0b"))
        setp(ap, "/tx/%s/outspend/0" % FUND_TXID, spent(a_root, 0, 332400, "0a"))
        for n in range(3):
            setp(ap, "/tx/%s/outspend/%d" % (a_root, n), spent(a_sweep, n, 332549, "0b") if n < 2 else UNSPENT)
        setp(ap, "/tx/%s/outspend/0" % a_sweep, UNSPENT)
        ap["/tx/%s/status" % ROOT_TXID] = {"status": 404, "body": "Transaction not found"}
        c, out, err = run(work, "root-satoshi-altered", ap, ap, FOLLOW)
        check(c == 1 and "not a tree transaction of the host's set" in err,
              "a root kickoff with one satoshi moved: not the host's tree, exit 1", err)

        # 8f. A server answers the funding's txid with one satoshi altered in its bytes.
        alt = FUND_HEX.replace("7b43010000000000", "7c43010000000000")
        check(alt != FUND_HEX, "(the funding's 82,811-sat output found in its bytes)")
        expect_code(work, "bytes-satoshi-altered", mutate(fund_hex=alt), FOLLOW, 1, ["answered another transaction"])

        # 8g. A stranger's transaction, shaped like a tree transaction, spends a root branch.
        x_txid, x_hex = serialise(3, [(ROOT_TXID, 0, 0xfffffffd)], [(41037, HOST_FIRST), (240, P2A)], 0,
                                  [[b"\x77" * 64]])
        xp = with_txs(base_paths(), (x_txid, x_hex, 332549, "0b"))
        setp(xp, "/tx/%s/outspend/0" % ROOT_TXID, spent(x_txid, 0, 332549, "0b"))
        setp(xp, "/tx/%s/outspend/1" % ROOT_TXID, UNSPENT)
        setp(xp, "/tx/%s/outspend/0" % x_txid, UNSPENT)
        setp(xp, "/tx/%s/outspend/1" % x_txid, UNSPENT)
        c, out, err = run(work, "stranger-tree-tx", xp, xp, ["--follow", FUND_TXID + ":0", "--funding", "100000",
                                                            "--tree", ROOT_TXID, "--allow-unnamed"] + GROUPS)
        check(c == 1 and ("%s looks like a tree transaction" % x_txid) in err,
              "a version-3 transaction with a P2A anchor spending a branch, not in the host's set: exit 1", err)

        # 8h. A tree transaction of the host's set is confirmed, but the servers say the funding is unspent.
        hp = base_paths()
        setp(hp, "/tx/%s/outspend/0" % FUND_TXID, UNSPENT)
        c, out, err = run(work, "tree-tx-unreached", hp, hp, FOLLOW + ["--allow-unnamed"])
        check(c == 1 and ("%s of the host's set is confirmed" % ROOT_TXID) in err,
              "a confirmed tree transaction the funding does not lead to: exit 1", err)

        # 8i. A transaction of the host's set that is not version 3 with its 240-sat P2A last.
        c, out, err = run(work, "tree-shape", base_paths(), base_paths(), FOLLOW + ["--tree", SWEEP_TXID])
        check(c == 1 and ("%s is in the host's set but is not version 3" % SWEEP_TXID) in err,
              "a tree transaction of version 2 without an anchor: exit 1", err)

        # 8j. The host's set read from its sweep-tree lines.
        tf = os.path.join(work, "tree.txt")
        with open(tf, "w", encoding="utf-8") as h:
            h.write("sweep-round id=1 members=2 nodes=1 end=332548 funding=%s:0 amount=82811 finals=1\n" % FUND_TXID)
            h.write("sweep-tree node=0 parent=-1 vout=0 kind=0 depth=0 first=0 count=2 cltv=0 txid=%s vsize=167 tx=%s\n"
                    % (ROOT_TXID, ROOT_HEX))
        c, out, err = run(work, "tree-file", base_paths(), base_paths(),
                          ["--follow", FUND_TXID + ":0", "--funding", "100000", "--tree-file", tf] + GROUPS)
        check(c == 0, "the host's set read from its sweep-tree lines", out + err)

        # 9. Usage.
        fa = os.path.join(work, "follow-a.json")
        r = subprocess.run([sys.executable, "-I", TOOL, "--server", "fixture:" + fa] + FOLLOW,
                           capture_output=True, text=True, timeout=60)
        check(r.returncode == 2 and "at least two" in r.stderr, "one server without --one-server: usage, exit 2",
              r.stderr)
        r = subprocess.run([sys.executable, "-I", TOOL, "--server", "http://ledger.invalid", "--server", "fixture:" + fa]
                           + FOLLOW, capture_output=True, text=True, timeout=60)
        check(r.returncode == 2, "plain http to a non-loopback server: usage, exit 2", r.stderr)
        r = subprocess.run([sys.executable, "-I", TOOL, "--server", "fixture:" + fa, "--server", "fixture:" + fa,
                            FUND_TXID] + FOLLOW, capture_output=True, text=True, timeout=60)
        check(r.returncode == 2, "txids and --follow together: usage, exit 2", r.stderr)
        for name, args, words in (
                ("no --funding", ["--follow", FUND_TXID + ":0", "--tree", ROOT_TXID] + GROUPS, "--funding"),
                ("no tree set", ["--follow", FUND_TXID + ":0", "--funding", "100000"] + GROUPS, "--tree"),
                ("an --expect for a group nobody named", FOLLOW + ["--expect", "memebrs=0"], "memebrs")):
            r = subprocess.run([sys.executable, "-I", TOOL, "--server", "fixture:" + fa, "--server", "fixture:" + fa]
                               + args, capture_output=True, text=True, timeout=60)
            check(r.returncode == 2 and words in r.stderr, "%s: usage, exit 2" % name, r.stderr)

    print("%d failed" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
