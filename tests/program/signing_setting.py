#!/usr/bin/env python3
"""program_signing_setting (review A of PR 55, H3; local-api.md 14.3): the
signing setting saved through the local API is the one in force from the
next start, for the core and for the program's key routing, whatever
--member-signing says. A host and three members as separate processes.

    python3 -I signing_setting.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. m1 runs with --member-signing at-join. A widening to auto as a plain
     command is refused (403); as an API request without the echo, 409; with
     it, 200 and in force only from the next start.
  2. m1 restarted with the same option: the program says the saved auto is
     in force (member-signing in-force=auto source=saved), and m1 takes part
     in a lobby by itself, as auto does: ready with no passphrase, Funding.
  3. at_join saved (a narrowing, any command), m1 restarted with
     --member-signing auto: at_join is in force, and in a second lobby m1
     joins but is not counted until the person readies with the passphrase.
Every process is checked for no node-error and no repair line.

The program sets its key routing (AT_JOIN: secrets for rounds only from the
scoped table, PR 53's gzp_keys_set_role) from the `member-signing in-force`
value, which is gz_node_member_signing's after the start's first call;
docs/notes/view-objects.md section 6.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, cmd, kill_all, tlv  # noqa: E402,F401
import lobby  # noqa: E402
from lobby import Terms, World, started, state  # noqa: E402

check = lobby.check
SET_SIGNING = 0x0d02
AT_JOIN, AUTO = 0, 1


def api(code, rid, *records):
    """An `api` test line: the command as the API server sends a request."""
    return "api %04x %s %s" % (code, rid, tlv(*records).hex())


def signing_args(value, version, confirm=None):
    recs = [(12, bytes([value])), (14, struct.pack(">I", version))]
    if confirm is not None:
        recs.append((16, bytes([confirm])))
    return recs


def result(p, start, status):
    return p.wait_for(r"command-result id=\S+ status=%d\b" % status, timeout=10, start=start) is not None


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    w = World(exe, work, "signing-setting")
    try:
        h = w.host("--test-sign-outcome", "funding", "--test-sign-delay-ms", "200")
        if not check(started(h) and w.hkey is not None, "the host starts"):
            return check.result("signing_setting", work)
        others = {n: w.member(n, "--member-signing", "auto", "--test-sign-outcome", "funding") for n in ("m2", "m3")}
        m1 = w.member("m1", "--member-signing", "at-join", "--test-sign-outcome", "funding")
        check(all(started(m) for m in list(others.values()) + [m1]), "1: three members start")
        check(m1.wait_for(r"member-signing in-force=at-join option=at-join", timeout=5) is not None,
              "1: m1 has at_join in force, from its option")
        # 1. The widening's authority in the core.
        mk = m1.mark()
        m1.send(cmd(SET_SIGNING, *signing_args(AUTO, 0, AUTO)))
        check(result(m1, mk, 403), "1: auto as a plain command: 403 (not the API's PUT /signing)")
        mk = m1.mark()
        m1.send(api(SET_SIGNING, "SigningNoEchoReq01", *signing_args(AUTO, 0)))
        check(result(m1, mk, 409), "1: auto as an API request without the echo: 409 confirm_mismatch")
        mk = m1.mark()
        m1.send(api(SET_SIGNING, "SigningToAutoReq01", *signing_args(AUTO, 0, AUTO)))
        check(result(m1, mk, 200), "1: auto with the echo, as an API request: 200, saved")
        # 2. In force from the next start, over the option.
        m1.stop()
        m1 = w.member("m1", "--member-signing", "at-join", "--test-sign-outcome", "funding")
        check(started(m1) and m1.wait_for(r"member-signing in-force=auto option=at-join source=saved",
                                          timeout=5) is not None,
              "2: restarted with --member-signing at-join, m1 has the saved auto in force")
        a = Terms(w.hkey, 600)
        w.open(h, a)
        for m in (m1, others["m2"], others["m3"]):
            w.join(m, a)
        check(m1.wait_for(r"lobby scope=%s role=member state=\d+ seat=\d+ joined=1 ready=1" % a.tag,
                          timeout=30) is not None, "2: m1 readies by itself, with no passphrase")
        check(state(h, a, "host", 4) and state(m1, a, "member", 4), "2: and the lobby reaches Funding with it")
        # 3. A narrowing saved; the opposite option at the next start.
        mk = m1.mark()
        m1.send(cmd(SET_SIGNING, *signing_args(AT_JOIN, 1)))
        check(result(m1, mk, 200), "3: at_join saved (a narrowing needs no echo)")
        m1.stop()
        m1 = w.member("m1", "--member-signing", "auto", "--test-sign-outcome", "funding")
        check(started(m1) and m1.wait_for(r"member-signing in-force=at-join option=auto source=saved",
                                          timeout=5) is not None,
              "3: restarted with --member-signing auto, m1 has the saved at_join in force")
        b = Terms(w.hkey, 601)
        w.open(h, b)
        mk = m1.mark()
        for m in (m1, others["m2"], others["m3"]):
            w.join(m, b)
        check(h.wait_for(r"scope=%s role=host state=1 joined=3 ready=2\b" % b.tag, timeout=30) is not None,
              "3: m1 joins the second lobby and is not counted (at_join: no passphrase yet)")
        check(m1.find(r"lobby scope=%s role=member state=\d+ seat=\d+ joined=1 ready=1" % b.tag, start=mk)[0] is None and
              h.find(r"lobby scope=%s role=host state=2" % b.tag)[0] is None,
              "3: it never readies, and the host runs no check")
        w.clean("signing setting")
    finally:
        kill_all(w.procs)
    return check.result("signing_setting", work)


if __name__ == "__main__":
    sys.exit(main())
