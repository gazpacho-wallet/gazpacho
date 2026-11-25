#!/usr/bin/env python3
"""program_lobby (docs/notes/composite-node.md, P4.2): a host and its members
as separate processes, over the real transport and the journal stand-in, with
the lobby engine in the composite's slots and the signing stand-in behind the
hand-off (--test-sign-outcome, test build only).

    python3 -I lobby.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Two lobbies at once on one host, four members (two of them in both
     lobbies, each with two keys and two links), plus one member whose
     conditions refuse the terms: hello, terms, join, ready, the ready check,
     start, the hand-off to the stand-in, the outcome back; Funding in both
     lobbies on every side. Run twice, each from a clean start.
  2. Crashes at the worst points, restarted on the same folder: the host
     killed after start_sent is durable and before any start leaves; a member
     killed after start_received is durable. Each hands its saved start over
     again, once, and the lobby still reaches Funding. The host's SET_SEATED
     precedes its members' reconnects.
  3. A storage failure in the middle, on the host and on a member: one
     restart in process each; the members' hello gets the full state again;
     nothing is saved twice.
  4. Retry: the member restarted after it does not hand its spent start over
     again (B2). With the signing budget spent while no round is in flight
     the lobby cancels with reason 3.
  5. The host killed in Signing and restarted after the deadline passed: the
     unfinished attempt is failed, and the lobby is cancelled at once with
     reason 1 (B4). Its members, who were not connected then, learn it from
     the tombstone when they reconnect and say hello.
  6. The person cancels during a round: one batch holds lobby_ended, the
     stand-in's round end and slot_closed. A member that missed the cancel
     (--test-drop-kind 34) ends Cancelled with the reason from the tombstone
     once it is restarted without the drop. A chosen member's leave during a
     round reaches the stand-in.
  8. A stale restore (review of PR 41, confirmation F1): a member joins one
     lobby, its journal is copied, it joins a second, and the copy is put
     back as a restore. The restore batch's guard record keeps what was used
     since the backup: its counter is above the device's, and it lists the
     second lobby's key indexes under epoch 0, with a new epoch.
  7. The signing gate. WHEN_UNLOCKED: locked, the member is not counted;
     unlocked it readies; locked again it says unready reason 3 and leaves
     the count. AT_JOIN in two lobbies: ready with the passphrase in one, and
     only that lobby runs its check; after its round the scoped secret is
     forgotten (key-forget); the other lobby waits for the person.
Every process is checked for no node-error and no repair line.
"""
import hashlib
import os
import re
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, cmd, free_port, journal_types, kill_all, parse_journal, tlv  # noqa: E402

check = Checks()
OPEN, JOIN, READY, UNREADY, LEAVE, SET_VALUES, REMOVE, CANCEL = range(0x0101, 0x0109)
UNLOCK, LOCK = 0x0401, 0x0402
KEY_EPOCH, KEY_INDEX, GUARD, SLOT_OPENED, SLOT_CLOSED = 0x00040002, 0x00040004, 0x0004000a, 0x0004000c, 0x0004000e
LOCAL_IDS = 0x000D000E  # local-api.md 7.5: the slot's local id, in its first batch (P6a)
LOBBY_OPENED, LOBBY_ENDED, START_SENT, START_RECEIVED, LOBBY_STATE = (0x00010002, 0x0001000a, 0x00010014,
                                                                    0x00010016, 0x00010018)
SIGN_BEGUN, SIGN_ENDED = 0x7e5a0002, 0x7e5a0004
EXIT_TEST = 70

# terms.md section 11: T1 (outer rules) and T2 (its current values).
T1 = bytes.fromhex(
    "0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800"
    "0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e"
    "34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02"
    "00030e08000000006af501801001001204000075301404000927c016040000ea"
    "6018090004000300100104031a04000000901c04000000241e08000000000001"
    "86a02004000000642201004010000000000000000000000000000007d0421000"
    "0000000000000000000000000003e84410000000000000006400000000000009"
    "c4")
T2 = bytes.fromhex(
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000001400800000000000001f4420800000000000003e844080000"
    "0000000003e8")


def parse_tlv(b):
    out, i = [], 0

    def big():
        nonlocal i
        v = b[i]
        i += 1
        if v < 0xfd:
            return v
        n = {0xfd: 2, 0xfe: 4, 0xff: 8}[v]
        v = int.from_bytes(b[i:i + n], "big")
        i += n
        return v
    while i < len(b):
        t = big()
        ln = big()
        out.append((t, b[i:i + ln]))
        i += ln
    return out


def th(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


class Terms:
    """T1 for this host's key with three seats, a deadline, a ready window
    and a signing budget of the test's choosing; and T2 for it."""

    def __init__(self, hkey, deadline_in, window_ms=1000, budget_ms=60000):
        change = {4: bytes.fromhex(hkey), 10: struct.pack(">H", 3), 12: struct.pack(">H", 3),
                  14: struct.pack(">Q", int(time.time()) + deadline_in), 18: struct.pack(">I", window_ms),
                  20: struct.pack(">I", budget_ms)}
        self.outer = tlv(*[(t, change.get(t, v)) for t, v in parse_tlv(T1)])
        self.scope = th("gazpacho/terms/outer", self.outer)
        self.current = tlv(*[(t, self.scope if t == 2 else v) for t, v in parse_tlv(T2)])
        self.tag = self.scope[:4].hex()


def conditions(max_tree_feerate=0):
    """A member's conditions as LOBBY_JOIN carries them (core/node/lobbyslot.c)."""
    return struct.pack(">BHQIIIHBB", 0, 0, 0, max_tree_feerate, 0, 0, 0, 0, 0)


class World:
    def __init__(self, exe, work, name):
        self.exe, self.work = exe, os.path.join(work, name)
        self.logs = os.path.join(self.work, "logs")
        shutil.rmtree(self.work, ignore_errors=True)
        os.makedirs(self.logs)
        self.procs, self.port, self.hkey, self.runs = [], free_port(), None, {}

    def _start(self, who, role, extra):
        self.runs[who] = self.runs.get(who, 0) + 1
        args = [self.exe, "--data-dir", os.path.join(self.work, who), "--role", role, "--name", who, "--no-chain",
                "--no-interface", "--test-engines", "0", "--test-commands"]
        if role == "host":
            # Every member here comes from one address: no cap per address.
            args += ["--listen", "127.0.0.1:%d" % self.port, "--max-per-address", "0"]
        else:
            # --connect is still required of a member (the test engines' CONNECT);
            # with no test engine nothing uses it: the lobby's JOIN names the host.
            args += ["--reconnect-ms", "100", "--connect", "%s@127.0.0.1:%d" % (self.hkey, self.port)]
        p = Proc("%s-%d" % (who, self.runs[who]), args + list(extra), self.logs, stdin=True)
        self.procs.append(p)
        return p

    def host(self, *extra):
        h = self._start("host", "host", extra)
        k = h.wait_for(r"host key=([0-9a-f]{66})")
        if k:
            self.hkey = k.group(1)
        return h

    def member(self, who, *extra):
        return self._start(who, "member", extra)

    def open(self, h, t, listed=1):
        h.send(cmd(OPEN, (12, t.outer), (14, t.current), (16, bytes([listed]))))

    def join(self, m, t, cond=None):
        recs = [(12, t.scope), (14, bytes.fromhex(self.hkey)), (16, ("127.0.0.1:%d" % self.port).encode())]
        if cond is not None:
            recs.append((18, cond))
        m.send(cmd(JOIN, *recs))

    def journal(self, who):
        for root, _, files in os.walk(os.path.join(self.work, who)):
            for f in files:
                path = os.path.join(root, f)
                with open(path, "rb") as fh:
                    if fh.read(8) == b"GZJSTAND":
                        return journal_types(path)
        return []

    def stop(self):
        for p in self.procs:
            p.stop()

    def clean(self, what):
        """No node error and no repair anywhere (composite-node.md 15)."""
        bad = [(p.name, l) for p in self.procs for l in p.lines if "node-error" in l or "repair" in l or "fatal" in l]
        check(not bad, "%s: no node-error, repair or fatal line in any process%s" % (what, " " + repr(bad[:2]) if bad else ""))


def has_batch(batches, types):
    """Some batch holds every type of `types`, in that order."""
    for b in batches:
        at = 0
        for t in b:
            if at < len(types) and t == types[at]:
                at += 1
        if at == len(types):
            return True
    return False


def count_records(batches, rtype):
    return sum(1 for b in batches for t in b if t == rtype)


def state(p, t, role, st, timeout=40, start=0):
    return p.wait_for(r"lobby scope=%s role=%s state=%d\b" % (t.tag, role, st), timeout=timeout, start=start) is not None


def closed(p, t, st, timeout=40, start=0):
    return p.wait_for(r"slot-closed scope=%s serial=\d+ state=%d reason=(\d+)" % (t.tag, st), timeout=timeout, start=start)


def started(p):
    return p.wait_for(r"ready incarnation=", timeout=30) is not None


def happy(exe, work, name):
    """Case 1."""
    w = World(exe, work, name)
    try:
        h = w.host("--test-sign-outcome", "funding", "--test-sign-delay-ms", "200")
        if not check(started(h) and w.hkey is not None, "1 (%s): the host starts" % name):
            return
        a, b = Terms(w.hkey, 600), Terms(w.hkey, 601)
        w.open(h, a)
        w.open(h, b, 0)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % a.tag, timeout=10) is not None and
              h.wait_for(r"slot-opened scope=%s .*role=host" % b.tag, timeout=10) is not None,
              "1 (%s): two lobbies open on one host" % name)
        ms = {n: w.member(n, "--member-signing", "auto", "--test-sign-outcome", "funding")
              for n in ("m1", "m2", "m3", "m4", "mr")}
        check(all(started(m) for m in ms.values()), "1 (%s): five members start" % name)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], a)
        for n in ("m1", "m2", "m4"):
            w.join(ms[n], b)
        w.join(ms["mr"], a, conditions(max_tree_feerate=1))  # T1's tree fee rate is 100: it does not fit
        check(state(h, a, "host", 4) and state(h, b, "host", 4), "1 (%s): the host shows Funding in both lobbies" % name)
        for n, ts in (("m1", (a, b)), ("m2", (a, b)), ("m3", (a,)), ("m4", (b,))):
            check(all(state(ms[n], t, "member", 4) for t in ts), "1 (%s): %s shows Funding in its lobbies" % (name, n))
        idx = [int(x) for l in ms["m1"].lines for x in re.findall(r"slot-opened .*role=member index=(\d+)", l)]
        check(len(idx) == 2 and idx[0] != idx[1], "1 (%s): the member in both lobbies has two keys %r" % (name, idx))
        check(ms["m1"].count(r" connected peer=") >= 2 and ms["m3"].count(r" connected peer=") == 1,
              "1 (%s): and two links, where a member of one lobby has one" % name)
        check(ms["mr"].wait_for(r"lobby-note code=0x4c02", timeout=10) is not None and
              ms["mr"].count(r"role=member .*joined=1") == 0 and h.count(r"scope=%s role=host .*joined=4" % a.tag) == 0,
              "1 (%s): the member whose conditions are not met refuses: told, never joined, never seated" % name)
        check(h.count(r"sign-begin scope=%s" % a.tag) == 1 and h.count(r"sign-begin scope=%s" % b.tag) == 1 and
              ms["m1"].count(r"sign-begin scope=") == 2 and ms["m4"].count(r"sign-begin scope=") == 1,
              "1 (%s): one hand-off to the stand-in per lobby and node" % name)
        check(h.count(r"sign-outcome scope=") == 2 and ms["m2"].count(r"sign-outcome scope=") == 2,
              "1 (%s): and its outcome back, once" % name)
        w.clean("1 (%s)" % name)
        w.stop()
        hj, mj = w.journal("host"), w.journal("m1")
        check(len(hj) > 2 and hj[0] == [KEY_EPOCH, KEY_INDEX, GUARD, SLOT_OPENED, LOCAL_IDS, LOBBY_OPENED] and
              hj[1] == [KEY_INDEX, GUARD, SLOT_OPENED, LOCAL_IDS, LOBBY_OPENED],
              "1 (%s): a slot's first batch on the host: key_index, guard, slot_opened, local_ids, lobby_opened" % name)
        check(len(mj) > 2 and mj[0] == [KEY_EPOCH, KEY_INDEX, GUARD, SLOT_OPENED, LOCAL_IDS] and
              mj[1] == [KEY_INDEX, GUARD, SLOT_OPENED, LOCAL_IDS], "1 (%s): and on a member: key_index, guard, slot_opened, local_ids" % name)
        check(has_batch(hj, [SIGN_ENDED, LOBBY_STATE]) and has_batch(mj, [SIGN_ENDED, LOBBY_STATE]),
              "1 (%s): the round's end and the lobby's Funding are one batch" % name)
        check(count_records(hj, START_SENT) == 2 and count_records(mj, START_RECEIVED) == 2 and
              count_records(hj, SLOT_CLOSED) == 0, "1 (%s): one start per lobby, no slot closed" % name)
    finally:
        kill_all(w.procs)


def one_lobby(w, h, outcome, deadline_in=600, budget_ms=60000, flags=None, signing="auto"):
    """A lobby with members m1, m2, m3, each with `flags[name]`."""
    flags = flags or {}
    t = Terms(w.hkey, deadline_in, budget_ms=budget_ms)
    w.open(h, t)
    ms = {n: w.member(n, "--member-signing", signing, "--test-sign-outcome", outcome, *flags.get(n, ()))
          for n in ("m1", "m2", "m3")}
    ok = all(started(m) for m in ms.values())
    for m in ms.values():
        w.join(m, t)
    return t, ms, ok


def crashes(exe, work):
    """Case 2."""
    w = World(exe, work, "crashes")
    try:
        h = w.host("--test-sign-outcome", "funding", "--test-crash-after-record", "%08x" % START_SENT)
        started(h)
        t, ms, ok = one_lobby(w, h, "funding", flags={"m2": ("--test-crash-after-record", "%08x" % START_RECEIVED)})
        check(ok, "2: the host and three members start")
        check(h.wait_for(r"test-crash after-record", timeout=40) is not None and h.exit_code(20) == EXIT_TEST,
              "2: the host is killed once start_sent is durable, before any start leaves")
        check(all(m.count(r"sign-begin") == 0 for m in ms.values()), "2: no member was sent a start")
        hj = w.journal("host")
        check(count_records(hj, START_SENT) == 1 and count_records(hj, SIGN_BEGUN) == 0,
              "2: storage holds start_sent and nothing of the round")
        # The stand-in's outcome a few seconds after the hand-off: the members
        # reconnect and are sent their saved starts while the round runs.
        h2 = w.host("--test-sign-outcome", "funding", "--test-sign-delay-ms", "4000")
        check(started(h2), "2: the host starts again on the same folder")
        check(h2.wait_for(r"sign-begin scope=%s .*resume=1" % t.tag, timeout=20) is not None,
              "2: and hands its saved start to the stand-in again")
        seated = h2.find(r" seated key=\S+ seated=1")[0]
        conn = h2.index_of(r" connected peer=", timeout=20)
        check(seated is not None and conn is not None and h2.count(r" seated key=\S+ seated=1") == 3 and seated < conn,
              "2: SET_SEATED for every seat precedes the first member's reconnect")
        # m2 dies when its start_received is durable.
        check(ms["m2"].wait_for(r"test-crash after-record", timeout=40) is not None and ms["m2"].exit_code(20) == EXIT_TEST,
              "2: a member is killed once start_received is durable")
        check(ms["m2"].count(r"sign-begin") == 0, "2: before it handed anything over")
        m2 = w.member("m2", "--member-signing", "auto", "--test-sign-outcome", "funding")
        check(started(m2) and m2.wait_for(r"sign-begin scope=%s .*resume=1" % t.tag, timeout=20) is not None,
              "2: restarted, it hands its saved start over again")
        check(state(h2, t, "host", 4) and state(ms["m1"], t, "member", 4) and state(m2, t, "member", 4) and
              state(ms["m3"], t, "member", 4), "2: and the lobby reaches Funding on every side")
        time.sleep(1.0)
        check(h2.count(r"sign-begin scope=") == 1 and m2.count(r"sign-begin scope=") == 1,
              "2: each hand-off again happened once")
        w.clean("2")
        w.stop()
        check(count_records(w.journal("host"), START_SENT) == 1 and count_records(w.journal("m2"), START_RECEIVED) == 1,
              "2: one start_sent on the host and one start_received on the member, in all")
    finally:
        kill_all(w.procs)


def storage(exe, work):
    """Case 3."""
    w = World(exe, work, "storage")
    try:
        h = w.host("--test-sign-outcome", "funding", "--test-storage-fail-at", "5")
        started(h)
        t, ms, ok = one_lobby(w, h, "funding", flags={"m3": ("--test-storage-fail-at", "3")})
        check(ok, "3: the host and three members start")
        check(state(h, t, "host", 4, timeout=60) and all(state(m, t, "member", 4, timeout=60) for m in ms.values()),
              "3: with a storage failure on the host and on a member the lobby still reaches Funding")
        check(h.count(r"ready incarnation=") == 2 and ms["m3"].count(r"ready incarnation=") == 2 and
              ms["m1"].count(r"ready incarnation=") == 1, "3: one restart in process for each failure, none elsewhere")
        check(h.count(r"node-error") == 0 and ms["m3"].count(r"node-error") == 0, "3: a storage failure is no node error")
        w.stop()
        hj, mj = w.journal("host"), w.journal("m3")
        check(count_records(hj, LOBBY_OPENED) == 1 and count_records(hj, SLOT_OPENED) == 1 and
              count_records(hj, START_SENT) == 1 and count_records(mj, SLOT_OPENED) == 1 and
              count_records(mj, START_RECEIVED) == 1 and count_records(mj, 0x0001000e) == 1,
              "3: nothing is saved twice (one lobby_opened, slot_opened, start_sent; one joined, start_received)")
    finally:
        kill_all(w.procs)


def retry_budget(exe, work):
    """Case 4."""
    w = World(exe, work, "retry")
    try:
        h = w.host("--test-sign-outcome", "retry")
        started(h)
        t, ms, ok = one_lobby(w, h, "retry")
        check(ok and h.wait_for(r"sign-outcome scope=%s .*outcome=2" % t.tag, timeout=40) is not None,
              "4: the stand-in reports Retry")
        check(ms["m2"].wait_for(r"sign-outcome scope=%s .*outcome=2" % t.tag, timeout=20) is not None,
              "4: on the member too")
        ms["m2"].stop()
        m2 = w.member("m2", "--member-signing", "auto", "--test-sign-outcome", "retry")
        check(started(m2), "4: the member restarts")
        time.sleep(3.0)
        check(m2.count(r"sign-begin scope=%s .*resume=1" % t.tag) == 0,
              "4: and does not hand its spent start over again (B2)")
        c = closed(h, t, 7, timeout=90)
        check(c is not None and c.group(1) == "3",
              "4: the signing budget spent with no round in flight: the lobby cancels, reason 3")
        check(all(closed(m, t, 7, timeout=30) is not None for m in (ms["m1"], m2, ms["m3"])),
              "4: every member ends Failed")
        w.clean("4")
        w.stop()
        hj = w.journal("host")
        check(has_batch(hj, [LOBBY_ENDED, SLOT_CLOSED]) and has_batch(hj, [SIGN_ENDED, LOBBY_STATE]),
              "4: the retry in one batch with the round's end; the end in one batch with slot_closed")
    finally:
        kill_all(w.procs)


def deadline_restart(exe, work):
    """Case 5."""
    w = World(exe, work, "deadline")
    try:
        h = w.host("--test-sign-outcome", "unfinished")
        started(h)
        begun = time.time()
        t, ms, ok = one_lobby(w, h, "unfinished", deadline_in=15)
        check(ok and state(h, t, "host", 3, timeout=13), "5: the lobby is Signing before its deadline")
        time.sleep(max(0.0, begun + 17 - time.time()))  # the deadline passes during the round
        h.p.kill()
        h.exit_code(10)
        marks = {n: m.mark() for n, m in ms.items()}
        h2 = w.host("--test-sign-outcome", "unfinished")
        check(started(h2) and h2.wait_for(r"sign-resume-failed scope=%s" % t.tag, timeout=10) is not None,
              "5: restarted in Signing, the host fails its unfinished attempt")
        c = closed(h2, t, 6, timeout=10)
        check(c is not None and c.group(1) == "1", "5: and cancels at once for the deadline, reason 1 (B4)")
        check(h2.count(r"sign-begin scope=") == 0, "5: nothing is handed over again")
        check(all(closed(m, t, 6, timeout=30, start=marks[n]) is not None for n, m in ms.items()),
              "5: its members learn the end from the tombstone when they reconnect and say hello")
        w.clean("5")
        w.stop()
        check(has_batch(w.journal("m1"), [LOBBY_ENDED, SIGN_ENDED, SLOT_CLOSED]),
              "5: a member's end is one batch: lobby_ended, its round's end, slot_closed")
    finally:
        kill_all(w.procs)


def cancel(exe, work):
    """Case 6."""
    w = World(exe, work, "cancel")
    try:
        h = w.host("--test-sign-outcome", "unfinished")
        started(h)
        t, ms, ok = one_lobby(w, h, "unfinished", flags={"m3": ("--test-drop-kind", "34")})
        t2 = Terms(w.hkey, 602)
        w.open(h, t2)
        for m in ms.values():
            w.join(m, t2)
        check(ok and state(h, t, "host", 3) and state(h, t2, "host", 3), "6: two lobbies are Signing")
        # A chosen member leaves the second lobby during its round: the stand-in is told.
        ms["m2"].send(cmd(LEAVE, (12, t2.scope)))
        check(h.wait_for(r"sign-member-left scope=%s" % t2.tag, timeout=10) is not None,
              "6: a chosen member's leave during a round reaches the stand-in")
        h.send(cmd(CANCEL, (12, t.scope)))
        c = closed(h, t, 6, timeout=10)
        check(c is not None and c.group(1) == "2", "6: the person cancels during a round: Cancelled, reason 2")
        check(all(closed(ms[n], t, 6, timeout=10) is not None for n in ("m1", "m2")), "6: the members end Cancelled")
        time.sleep(1.5)
        check(ms["m3"].count(r"slot-closed scope=%s" % t.tag) == 0 and ms["m3"].count(r"test-drop kind=34") >= 1,
              "6: a member that never gets the cancel stays as it was")
        check(state(h, t2, "host", 3), "6: the other lobby goes on")
        ms["m3"].stop()
        m3 = w.member("m3", "--member-signing", "auto", "--test-sign-outcome", "unfinished")
        c3 = closed(m3, t, 6, timeout=20)
        check(started(m3) and c3 is not None,
              "6: restarted without the drop, it says hello to the tombstone and ends Cancelled")
        check(m3.count(r"slot-closed scope=%s" % t2.tag) == 0, "6: its other lobby is untouched")
        w.clean("6")
        w.stop()
        check(has_batch(w.journal("host"), [LOBBY_ENDED, SIGN_ENDED, SLOT_CLOSED]),
              "6: one batch on the host holds lobby_ended, the stand-in's round end and slot_closed")
    finally:
        kill_all(w.procs)


def gates(exe, work):
    """Case 7."""
    w = World(exe, work, "gates")
    try:
        h = w.host("--test-sign-outcome", "funding")
        started(h)
        a, b = Terms(w.hkey, 600), Terms(w.hkey, 601)
        w.open(h, a)
        w.open(h, b)
        m1 = w.member("m1", "--member-signing", "at-join", "--test-sign-outcome", "funding")
        m2 = w.member("m2", "--member-signing", "when-unlocked", "--test-sign-outcome", "funding")
        m3 = w.member("m3", "--member-signing", "auto", "--test-sign-outcome", "funding")
        m4 = w.member("m4", "--member-signing", "auto", "--test-sign-outcome", "funding")
        check(all(started(m) for m in (m1, m2, m3, m4)), "7: the host and four members start")
        for m in (m1, m2, m3):
            w.join(m, a)
        for m in (m1, m2, m4):
            w.join(m, b)
        check(h.wait_for(r"scope=%s role=host state=1 joined=3 ready=1\b" % a.tag, timeout=20) is not None and
              h.wait_for(r"scope=%s role=host state=1 joined=3 ready=1\b" % b.tag, timeout=20) is not None,
              "7: locked members hold seats and are not counted Ready")
        time.sleep(2.5)
        check(h.count(r"role=host state=2") == 0, "7: with its minimum met only by locked members the host starts no check")
        # WHEN_UNLOCKED: unlock, lock, unlock.
        mk = h.mark()
        m2.send(cmd(UNLOCK))
        check(h.wait_for(r"scope=%s role=host state=1 joined=3 ready=2\b" % a.tag, timeout=10, start=mk) is not None,
              "7: unlocked, the member readies and is counted")
        mk = h.mark()
        m2.send(cmd(LOCK))
        check(h.wait_for(r"scope=%s role=host state=1 joined=3 ready=1\b" % a.tag, timeout=10, start=mk) is not None and
              m2.wait_for(r"lobby-note code=0x4c0b", timeout=10) is not None,
              "7: locked again, it says unready (reason 3, locked) and leaves the count")
        mk = h.mark()
        m2.send(cmd(UNLOCK))
        check(h.wait_for(r"scope=%s role=host state=1 joined=3 ready=2\b" % a.tag, timeout=10, start=mk) is not None,
              "7: unlocked, it readies again")
        # AT_JOIN: ready with the passphrase, in lobby A only, for the values it holds (16, the
        # seen_current_digest the gate is bound to; review of #79, M1).
        m1.send(cmd(READY, (12, a.scope), (14, b"\x01"), (16, th("gazpacho/terms/current", a.current))))
        check(state(h, a, "host", 4) and state(m1, a, "member", 4), "7: ready with the passphrase in one lobby: its check runs, to Funding")
        check(m1.wait_for(r"key-forget scope=%s" % a.tag, timeout=10) is not None,
              "7: after its round the scoped secret is forgotten")
        time.sleep(2.0)
        check(h.count(r"scope=%s role=host state=2" % b.tag) == 0 and m1.count(r"key-forget scope=%s" % b.tag) == 0,
              "7: the other lobby, not readied, ran no check")
        m1.stop()
        m1 = w.member("m1", "--member-signing", "at-join", "--test-sign-outcome", "funding")
        check(started(m1), "7: the member restarts")
        time.sleep(2.5)
        check(h.count(r"scope=%s role=host state=2" % b.tag) == 0, "7: after a restart the lobby waits for the person")
        m1.send(cmd(READY, (12, b.scope), (14, b"\x01"), (16, th("gazpacho/terms/current", b.current))))
        check(state(h, b, "host", 4) and state(m1, b, "member", 4) and
              m1.wait_for(r"key-forget scope=%s" % b.tag, timeout=10) is not None,
              "7: readied with the passphrase, that lobby runs its check too, and its secret is forgotten after")
        w.clean("7")
        w.stop()
    finally:
        kill_all(w.procs)


def guard_records(path):
    """Every guard record of a journal: (incarnation, sequence, counter, {epoch: highest index})."""
    out = []
    for e in parse_journal(path):
        if e[0] != "BTCH":
            continue
        for t, b in e[3]:
            if t == GUARD and len(b) >= 58 and b[:8] == b"GZGUARD1":
                counter = struct.unpack(">Q", b[40:48])[0]
                n = struct.unpack(">H", b[48:50])[0]
                epochs = {}
                for k in range(n):
                    ep, hi = struct.unpack(">II", b[50 + 8 * k:58 + 8 * k])
                    epochs[ep] = hi
                out.append((e[1], e[2], counter, epochs))
    return out


def stale_restore(exe, work):
    """Case 8."""
    w = World(exe, work, "restore")
    try:
        h = w.host("--test-sign-outcome", "unfinished")
        started(h)
        a, b = Terms(w.hkey, 600), Terms(w.hkey, 601)
        w.open(h, a)
        w.open(h, b)
        folder = os.path.join(w.work, "m1")
        journal = os.path.join(folder, "journal.standin")
        backup = os.path.join(w.work, "m1-backup.standin")
        m = w.member("m1", "--member-signing", "auto")
        started(m)
        w.join(m, a)
        check(m.wait_for(r"slot-opened scope=%s .*index=1\b" % a.tag, timeout=10) is not None and
              state(m, a, "member", 1, timeout=20), "8: the member joins one lobby (key pair 1 and 2)")
        m.stop()
        shutil.copy(journal, backup)
        m = w.member("m1", "--member-signing", "auto")
        started(m)
        w.join(m, b)
        check(m.wait_for(r"slot-opened scope=%s .*index=3\b" % b.tag, timeout=10) is not None and
              state(m, b, "member", 1, timeout=20), "8: after the backup it joins a second (key pair 3 and 4)")
        m.stop()
        device = guard_records(journal)
        check(device and device[-1][2] == 2 and device[-1][3].get(0) == 4,
              "8: the device's guard: counter 2, epoch 0 up to index 4 (%r)" % (device[-1:],))
        check(os.path.exists(os.path.join(folder, "guard.standin")), "8: the stand-in keeps a guard file")
        m = w.member("m1", "--member-signing", "auto", "--test-restore-from", backup)
        check(started(m), "8: the backup is put back as a restore, and the member starts")
        gf = m.find(r"restore-guard-file counter=(\d+)")[1]
        check(gf is not None and gf.group(1) == "2", "8: the restored start is given the guard file (counter 2)")
        rg = m.wait_for(r"restore-guard chain=\S+ counter=(\d+)", timeout=10)
        check(rg is not None and rg.group(1) == "3", "8: the restore batch's guard counter is above the device's (3)")
        m.stop()
        restored = guard_records(journal)
        last = restored[-1] if restored else None
        check(last is not None and last[1] == 1 and last[3].get(0) == 4 and len(last[3]) == 2,
              "8: it lists epoch 0 up to index 4, the second lobby's keys, and one new epoch (%r)" % (last,))
        w.clean("8")
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    only = sys.argv[3:]
    cases = [("happy-1", lambda: happy(exe, work, "run-1")), ("happy-2", lambda: happy(exe, work, "run-2")),
             ("crashes", lambda: crashes(exe, work)), ("storage", lambda: storage(exe, work)),
             ("retry", lambda: retry_budget(exe, work)), ("deadline", lambda: deadline_restart(exe, work)),
             ("cancel", lambda: cancel(exe, work)), ("gates", lambda: gates(exe, work)),
             ("restore", lambda: stale_restore(exe, work))]
    os.makedirs(work, exist_ok=True)
    for name, fn in cases:
        if not only or name in only:
            fn()
    return check.result("lobby", work)


if __name__ == "__main__":
    sys.exit(main())
