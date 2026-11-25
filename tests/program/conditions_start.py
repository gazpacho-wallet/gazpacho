#!/usr/bin/env python3
"""program_conditions_start (local-api.md 13.2 and 15.2): the person's
conditions on a joined lobby, and the host's early start, with a host and
four members as separate processes over the real transport, the journal
stand-in and the signing stand-in.

    python3 -I conditions_start.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Conditions (0x0d03). Three members join a lobby of four (minimum
     three), all ready. m3's conditions tighten below the terms (the
     channel): it leaves, reason 1, its conditions and its leave in one
     batch, and the host counts two. A loosening as a plain command is
     refused (403), as an API request without its echo 409, with it 200.
     m3 tightens again and is restarted: the saved conditions are read back
     and copied into its next join, which T1 does not fit: it refuses and
     never joins.
  2. The early start (0x0109). m4 joins: three ready of four, ten minutes
     before the deadline, and the host's rule waits. As a plain command the
     start is refused (403); with an echo other than the lobby's set-aside
     amount (the host's slot-opened line says it) 409; with it, 202, and the
     ready check runs at once, then Funding on every side.
Every process is checked for no node-error and no repair line.
"""
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import cmd, kill_all, tlv  # noqa: E402
import lobby  # noqa: E402
from lobby import World, closed, has_batch, started, state  # noqa: E402

check = lobby.check
SET_CONDITIONS, START = 0x0d03, 0x0109
CONDITIONS, LOBBY_ENDED, SLOT_CLOSED = 0x000d0008, 0x0001000a, 0x0004000e
CHANNEL = 30  # terms.md type 30: what a tightened min_channel_sat loosens back


class Terms4(lobby.Terms):
    """T1 for this host with four seats and a minimum of three."""

    def __init__(self, hkey, deadline_in):
        change = {4: bytes.fromhex(hkey), 10: struct.pack(">H", 4), 12: struct.pack(">H", 3),
                  14: struct.pack(">Q", int(time.time()) + deadline_in), 18: struct.pack(">I", 1000),
                  20: struct.pack(">I", 60000)}
        self.outer = tlv(*[(t, change.get(t, v)) for t, v in lobby.parse_tlv(lobby.T1)])
        self.scope = lobby.th("gazpacho/terms/outer", self.outer)
        self.current = tlv(*[(t, self.scope if t == 2 else v) for t, v in lobby.parse_tlv(lobby.T2)])
        self.tag = self.scope[:4].hex()


def conditions(min_channel_sat=0):
    """The conditions as 0x0d03 and LOBBY_JOIN carry them (core/node/lobbyslot.c)."""
    return struct.pack(">BHQIIIHBB", 0, 0, min_channel_sat, 0, 0, 0, 0, 0, 0)


def cond_args(c, version, echo=None):
    recs = [(12, c), (14, struct.pack(">I", version))]
    if echo is not None:
        recs.append((16, echo))
    return recs


def api(code, rid, *records):
    """An `api` test line: the command as the API server sends a request."""
    return "api %04x %s %s" % (code, rid, tlv(*records).hex())


def result(p, start, status, error=None):
    pat = r"command-result id=\S+ status=%d error=%s" % (status, error or r"\S+")
    return p.wait_for(pat, timeout=10, start=start) is not None


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    w = World(exe, work, "conditions-start")
    try:
        h = w.host("--test-sign-outcome", "funding", "--test-sign-delay-ms", "200")
        if not check(started(h) and w.hkey is not None, "the host starts"):
            return check.result("conditions_start", work)
        ms = {n: w.member(n, "--member-signing", "auto", "--test-sign-outcome", "funding")
              for n in ("m1", "m2", "m3", "m4")}
        check(all(started(m) for m in ms.values()), "four members start")
        a, b = Terms4(w.hkey, 600), Terms4(w.hkey, 601)
        w.open(h, a)
        w.open(h, b)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], a)
        check(h.wait_for(r"lobby scope=%s role=host state=1 joined=3 ready=3\b" % a.tag, timeout=30) is not None,
              "1: three of four ready, Open")
        # 1. Conditions.
        m3 = ms["m3"]
        mk, hk = m3.mark(), h.mark()
        m3.send(cmd(SET_CONDITIONS, *cond_args(conditions(200000), 0)))
        check(result(m3, mk, 200, "-"), "1: a tightening needs no fresh sign-in: 200")
        c = closed(m3, a, 6, timeout=10, start=mk)
        check(c is not None and c.group(1) == "1", "1: m3 leaves the lobby the new conditions refuse, reason 1")
        check(h.wait_for(r"lobby scope=%s role=host state=1 joined=2 ready=2\b" % a.tag, timeout=10, start=hk) is not None,
              "1: and the host counts two")
        mk = m3.mark()
        m3.send(cmd(SET_CONDITIONS, *cond_args(conditions(0), 1)))
        check(result(m3, mk, 403, "fresh_sign_in_needed"), "1: a loosening as a plain command: 403")
        mk = m3.mark()
        m3.send(api(SET_CONDITIONS, "CondLoosenNoEcho01", *cond_args(conditions(0), 1)))
        check(result(m3, mk, 409, "confirm_mismatch"), "1: as an API request without its echo: 409")
        mk = m3.mark()
        m3.send(api(SET_CONDITIONS, "CondLoosenEcho0001", *cond_args(conditions(0), 1, bytes([CHANNEL]))))
        check(result(m3, mk, 200, "-"), "1: with the echo of what it loosens: 200")
        mk = m3.mark()
        m3.send(cmd(SET_CONDITIONS, *cond_args(conditions(200000), 2)))
        check(result(m3, mk, 200, "-"), "1: tightened again (version 3)")
        m3.stop()
        m3 = w.member("m3", "--member-signing", "auto", "--test-sign-outcome", "funding")
        check(started(m3), "1: m3 restarts")
        w.join(m3, b)  # no conditions given: the saved ones are copied
        check(m3.wait_for(r"lobby-note code=0x4c02", timeout=15) is not None and
              m3.find(r"lobby scope=%s role=member .*joined=1" % b.tag)[0] is None,
              "1: read back at the start, they are copied into its next join, which T1 does not fit: it never joins")
        check(state(h, b, "host", 1) and h.find(r"lobby scope=%s role=host state=1 joined=1" % b.tag)[0] is None,
              "1: and the host never seats it")
        # 2. The early start.
        hk = h.mark()
        w.join(ms["m4"], a)
        check(h.wait_for(r"lobby scope=%s role=host state=1 joined=3 ready=3\b" % a.tag, timeout=30, start=hk) is not None,
              "2: three of four ready again")
        time.sleep(2.0)
        check(h.find(r"lobby scope=%s role=host state=2" % a.tag)[0] is None, "2: the start rule waits for the target")
        opened = h.find(r"slot-opened scope=%s .*role=host .*set_aside=(\d+)" % a.tag)[1]
        aside = int(opened.group(1)) if opened else 0
        check(aside > 0, "2: the host's slot-opened line gives the set-aside amount (%d)" % aside)
        start_args = [(12, a.scope), (14, struct.pack(">Q", aside))]
        mk = h.mark()
        h.send(cmd(START, *start_args))
        check(result(h, mk, 403, "fresh_sign_in_needed"), "2: the start as a plain command: 403")
        mk = h.mark()
        h.send(api(START, "StartWrongEcho0001", (12, a.scope), (14, struct.pack(">Q", aside - 1))))
        check(result(h, mk, 409, "confirm_mismatch"), "2: an echo other than the set-aside amount: 409")
        mk = h.mark()
        h.send(api(START, "StartNowAtMinimum1", *start_args))
        check(result(h, mk, 202, "-"), "2: with the set-aside amount: 202")
        check(h.wait_for(r"lobby scope=%s role=host state=2\b" % a.tag, timeout=5, start=mk) is not None,
              "2: the ready check runs at once, long before the deadline")
        check(state(h, a, "host", 4, start=mk) and all(state(ms[n], a, "member", 4) for n in ("m1", "m2", "m4")),
              "2: and the lobby reaches Funding on every side")
        w.clean("conditions and start")
        w.stop()
        check(has_batch(w.journal("m3"), [CONDITIONS, LOBBY_ENDED, SLOT_CLOSED]),
              "1: m3's conditions, its leave and its slot's end are one batch")
    finally:
        kill_all(w.procs)
    return check.result("conditions_start", work)


if __name__ == "__main__":
    sys.exit(main())
