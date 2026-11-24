#!/usr/bin/env python3
"""program_keys_setting (docs/notes/integration.md F13; view-objects.md 6,
H3): the program's key routing follows the signing setting in force, not
--member-signing. Real signing (no stand-in), a fixed tip, no chain: one
host and three members, the terms of program_signing with three seats.

    python3 -I keys_setting.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. m1 runs with --member-signing at-join and saves auto (the API request
     with the echo); restarted with the same option, auto is in force. It
     must sign by itself: the round's secrets come from its keys, not from
     the scoped table it has none in, and the lobby reaches Funding.
  2. m1 runs with --member-signing auto and saves at_join (a narrowing);
     restarted with the same option, at_join is in force. When the person
     readies with the passphrase, the key port must open that lobby's scope
     (key-scope-open, AT_JOIN's routing); then the lobby reaches Funding.
Every process is checked for no node-error, repair or fatal line.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import cmd, kill_all, tlv  # noqa: E402
import lobby  # noqa: E402
from lobby import READY, World, started, state  # noqa: E402
import signing  # noqa: E402

check = signing.check
TIP = signing.TIP
SET_SIGNING = 0x0d02
AT_JOIN, AUTO = 0, 1
FUNDING = 4


def api(code, rid, *records):
    return "api %04x %s %s" % (code, rid, tlv(*records).hex())


def args(value, version, confirm=None):
    recs = [(12, bytes([value])), (14, struct.pack(">I", version))]
    if confirm is not None:
        recs.append((16, bytes([confirm])))
    return recs


def case(exe, work, name, option, saved):
    w = World(exe, work, "case" + name.split()[0])
    tick = ("--test-sign-tick-ms", "100")
    try:
        h = w.host("--tip", str(TIP), *tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts" % name):
            return
        m1 = w.member("m1", "--member-signing", option, "--tip", str(TIP), *tick)
        check(started(m1), "%s: m1 starts with --member-signing %s" % (name, option))
        mk = m1.mark()
        if saved == AUTO:
            m1.send(api(SET_SIGNING, "KeysSettingAutoReq01", *args(AUTO, 0, AUTO)))
        else:
            m1.send(cmd(SET_SIGNING, *args(AT_JOIN, 0)))
        check(m1.wait_for(r"command-result id=\S+ status=200\b", timeout=10, start=mk) is not None,
              "%s: the other setting is saved" % name)
        m1.stop()
        m1 = w.member("m1", "--member-signing", option, "--tip", str(TIP), *tick)
        want = "auto" if saved == AUTO else "at-join"
        check(started(m1) and m1.wait_for(r"member-signing in-force=%s option=%s source=saved" % (want, option),
                                          timeout=10) is not None,
              "%s: restarted with the same option, the saved %s is in force" % (name, want))
        t = signing.Terms(w.hkey, 900, target=3)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = [m1] + [w.member(n, "--member-signing", "auto", "--tip", str(TIP), *tick) for n in ("m2", "m3")]
        check(all(started(m) for m in ms[1:]), "%s: two more members start" % name)
        for m in ms:
            w.join(m, t)
        if saved == AT_JOIN:
            check(m1.wait_for(r"lobby scope=%s role=member state=\d+ seat=\d+ joined=1" % t.tag, timeout=30) is not None,
                  "%s: m1 is seated" % name)
            mk = m1.mark()
            m1.send(cmd(READY, (12, t.scope), (14, bytes([1])), (16, lobby.th("gazpacho/terms/current", t.current))))
            check(m1.wait_for(r"key-scope-open scope=%s ok=1" % t.tag, timeout=10, start=mk) is not None,
                  "%s: readied with the passphrase, the key port opens the lobby's scope (AT_JOIN's routing)" % name)
        check(m1.wait_for(r"sign-outcome scope=%s .*outcome=1 " % t.tag, timeout=120) is not None,
              "%s: m1 signs the round: Funding" % name)
        check(state(h, t, "host", FUNDING, timeout=60), "%s: the host reaches Funding" % name)
        check(m1.count(r"no_key|no-key") == 0, "%s: m1 never lacks a key" % name)
        w.clean(name)
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    case(exe, work, "1 at-join option, auto saved", "at-join", AUTO)
    case(exe, work, "2 auto option, at_join saved", "auto", AT_JOIN)
    return check.result("keys_setting", work)


if __name__ == "__main__":
    sys.exit(main())
