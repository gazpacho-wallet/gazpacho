#!/usr/bin/env python3
"""program_signing (docs/notes/composite-node.md, P4.3): a host and its
members as separate processes, over the real transport and the journal
stand-in, with the signing engine in the composite: the real tree from the
terms, built by the rules and checked against the imported SuperScalar
builder on every member.

    python3 -I signing.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. One lobby, four members ready, three of them honest (one of those under
     AT_JOIN, readying with the passphrase) and one whose chain view is 100
     blocks ahead of the host's: its safe-to-sign checks refuse the proposal
     (the end height is outside its window, reason 9). The host blames it,
     and leaves it out of the next check although it readies again (by its
     key); the AT_JOIN member, whose gate closed with the attempt, readies
     again with the passphrase and the values digest it saw; the next attempt
     is signed by the host and the three others: every tree transaction, every ack, Funding on every side,
     in the batch that holds the ack (host) or round_completed (member). The
     AT_JOIN member's scoped factory secret is forgotten after each attempt.
  2. The same lobby again, restarted: nothing is signed twice, the journals
     load, Funding stays.
(The release build takes no commands on its standard input; that it hosts
and joins lobbies with the engine is checked at the node level,
tests/node/test_node_release.c.)
Every process is checked for no node-error and no repair line, and no
secp256k1 illegal-argument report.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, kill_all  # noqa: E402
import lobby  # noqa: E402
from lobby import World, cmd, parse_tlv, started, state, tlv  # noqa: E402

check = Checks()
lobby.check = check
OPEN, JOIN, READY, LEAVE = 0x0101, 0x0102, 0x0103, 0x0105
ROUND_STARTED, ROUND_PROPOSAL, EXPOSURE, ROUND_SIGNED, ROUND_COMPLETED, ACK_RECEIVED, ROUND_ENDED = (
    0x00020002, 0x00020004, 0x00020006, 0x00020008, 0x0002000a, 0x0002000c, 0x0002000e)
LOBBY_STATE, GUARD = 0x00010018, 0x0004000a
FUNDING_STATUS = 0x00030006
TIP = 200000


class Terms(lobby.Terms):
    """T1 with four seats, three at least, and a lifetime long enough for the
    exit-time checks (terms.md 4.4) at the test's tip."""

    def __init__(self, hkey, deadline_in, target=4, minimum=3, lifetime=4320, window_ms=2000, budget_ms=600000):
        super().__init__(hkey, deadline_in, window_ms=window_ms, budget_ms=budget_ms)
        change = {10: struct.pack(">H", target), 12: struct.pack(">H", minimum), 26: struct.pack(">I", lifetime)}
        self.outer = tlv(*[(t, change.get(t, v)) for t, v in parse_tlv(self.outer)])
        self.scope = lobby.th("gazpacho/terms/outer", self.outer)
        self.current = tlv(*[(t, self.scope if t == 2 else v) for t, v in parse_tlv(self.current)])
        self.tag = self.scope[:4].hex()


def has_batch(batches, types):
    return lobby.has_batch(batches, types)


def clean(w, what):
    w.clean(what)
    bad = [(p.name, l) for p in w.procs for l in p.lines if "secp-illegal-argument" in l]
    check(not bad, "%s: no illegal-argument report from secp256k1%s" % (what, " " + repr(bad[:1]) if bad else ""))


def sign(exe, work):
    """Cases 1 and 2."""
    w = World(exe, work, "sign")
    tick = ("--test-sign-tick-ms", "100")
    try:
        h = w.host("--tip", str(TIP), *tick)
        if not check(started(h) and w.hkey is not None, "1: the host starts"):
            return
        t = Terms(w.hkey, 900)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "1: the lobby opens")
        ms = {}
        for n in ("m1", "m2"):
            ms[n] = w.member(n, "--member-signing", "auto", "--tip", str(TIP), *tick)
        ms["m3"] = w.member("m3", "--member-signing", "at-join", "--tip", str(TIP), *tick)
        ms["m4"] = w.member("m4", "--member-signing", "auto", "--tip", str(TIP + 100), *tick)   # its chain view is ahead
        check(all(started(m) for m in ms.values()), "1: four members start")
        for n in ("m1", "m2", "m3", "m4"):
            w.join(ms[n], t)
        # AT_JOIN: the person readies with the passphrase once the terms are in (12.2).
        m3 = ms["m3"]
        check(m3.wait_for(r"lobby scope=%s role=member state=\d+ seat=\d+ joined=1" % t.tag, timeout=30) is not None,
              "1: the AT_JOIN member is seated")
        mk3 = m3.mark()
        m3.send(cmd(READY, (12, t.scope), (14, bytes([1])), (16, lobby.th("gazpacho/terms/current", t.current))))
        # The first attempt: four chosen; m4 refuses; the host blames it.
        check(ms["m4"].wait_for(r"sign-refused scope=%s .*rule=\d+ reason=9" % t.tag, timeout=90) is not None,
              "1: the member with another chain view refuses the proposal (reason 9)")
        check(h.wait_for(r"sign-outcome scope=%s .*outcome=2 blamed=1" % t.tag, timeout=90) is not None,
              "1: the host blames it: Retry, one member named")
        # It stays and, under AUTO, readies again; the host leaves it out of the next check, by its key
        # (review A of PR 52, M1), so it is not chosen, refused and blamed again until the budget ends.
        # AT_JOIN: the attempt over, the gate closes and the scoped secret is forgotten; back at the ready
        # check the seat is locked until the person readies again with the passphrase (12.2).
        i = m3.index_of(r"key-forget scope=%s" % t.tag, timeout=30, start=mk3)
        check(i is not None, "1: the attempt over, the AT_JOIN member's scoped secret is forgotten")
        check(m3.wait_for(r"lobby scope=%s role=member state=1 .*ready=0" % t.tag, timeout=30, start=i or 0) is not None,
              "1: back at the ready check the AT_JOIN member is locked")
        mk3 = m3.mark()
        m3.send(cmd(READY, (12, t.scope), (14, bytes([1])), (16, lobby.th("gazpacho/terms/current", t.current))))
        # The next attempt, without it: Funding everywhere it signed.
        check(state(h, t, "host", 4, timeout=180), "1: the host reaches Funding")
        for n in ("m1", "m2", "m3"):
            check(state(ms[n], t, "member", 4, timeout=60), "1: %s reaches Funding" % n)
        for n in ("m1", "m2", "m3"):
            check(ms[n].count(r"sign-refused") == 0, "1: %s never refuses" % n)
        check(ms["m4"].count(r"sign-refused") == 1, "1: the refusing member, still in the lobby, was chosen once only")
        check(h.count(r"sign-begin scope=%s .*members=4" % t.tag) >= 1 and h.count(r"sign-begin scope=%s .*members=3" % t.tag) == 1,
              "1: the first attempt with four members, the one that is signed with three")
        check(h.count(r"sign-outcome scope=%s .*outcome=1 " % t.tag) == 1, "1: one Funding outcome on the host")
        for n in ("m1", "m2", "m3"):
            check(ms[n].count(r"sign-outcome scope=%s .*outcome=1 " % t.tag) == 1, "1: one Funding outcome on %s" % n)
        check(m3.wait_for(r"key-forget scope=%s" % t.tag, timeout=20, start=mk3) is not None,
              "1: the AT_JOIN member's scoped secret is forgotten once its signed round is over")
        clean(w, "1")
        w.stop()
        hj = w.journal("host")
        check(has_batch(hj, [ROUND_PROPOSAL, ROUND_STARTED, GUARD]),
              "1: the host's attempt: round_proposal, round_started and the guard in one batch")
        check(has_batch(hj, [ACK_RECEIVED, LOBBY_STATE]),
              "1: the last ack and the lobby's Funding in one batch (rule 2)")
        check(has_batch(hj, [ROUND_ENDED, LOBBY_STATE]), "1: the refused attempt's end and the lobby's Retry in one batch")
        for n in ("m1", "m2", "m3"):
            mj = w.journal(n)
            check(has_batch(mj, [ROUND_PROPOSAL, ROUND_STARTED, GUARD]) and
                  any(EXPOSURE in b for b in mj) and any(ROUND_SIGNED in b for b in mj),
                  "1: %s saved its round: proposal, nonces' round_started with the guard, exposure, the finals" % n)
            check(has_batch(mj, [ROUND_COMPLETED, LOBBY_STATE]),
                  "1: %s: round_completed (its ack) and the lobby's Funding in one batch (rule 2)" % n)
            # With the funding engine wired (P4.6), a member's engine writes its first funding_status
            # (state 1, acked) from its ack, as funding.md's member row says (integration B13).
            check(any(FUNDING_STATUS in b for b in mj), "1: %s's funding engine writes funding_status from its ack" % n)
        m4j = w.journal("m4")
        check(all(FUNDING_STATUS not in b for b in m4j), "1: the refusing member writes no funding_status")
        check(all(EXPOSURE not in b and ROUND_STARTED not in b for b in m4j),
              "1: the refusing member saved no round and released nothing")

        # Case 2: everyone again on the same folders: nothing new is signed.
        h = w.host("--tip", str(TIP), *tick)
        ms = {n: w.member(n, "--member-signing", "auto" if n != "m3" else "at-join", "--tip", str(TIP), *tick)
              for n in ("m1", "m2", "m3")}
        check(started(h) and all(started(m) for m in ms.values()), "2: every process starts again")
        check(state(h, t, "host", 4, timeout=30), "2: the host shows Funding again")
        for n, m in ms.items():
            check(state(m, t, "member", 4, timeout=30), "2: %s shows Funding again" % n)
        check(h.count(r"sign-begin") == 0 and all(m.count(r"sign-outcome") == 0 for m in ms.values()),
              "2: nothing is begun or reported again")
        clean(w, "2")
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    sign(exe, work)
    return check.result("signing", work)


if __name__ == "__main__":
    sys.exit(main())
