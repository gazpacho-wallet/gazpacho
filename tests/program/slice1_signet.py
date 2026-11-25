#!/usr/bin/env python3
"""program_slice1_signet (docs/notes/integration.md 8): Slice 1's case 1 on
signet, against the public Esplora servers of two operators. Opt in only.

    GZ_LIVE_TESTS=1 GZ_SIGNET_DIR=FOLDER python3 -I slice1_signet.py PATH_TO_GAZPACHO_TEST WORK_DIR

Exits 77 (skipped), touching no network, unless GZ_LIVE_TESTS is 1 and
GZ_SIGNET_DIR names a folder kept between runs: the host's folder lives
there, so that the address it is funded at stays its own. This test moves
no coin of its own accord. It reads the host's first receive address and
its wallet's coins; with none, it prints the address to fund (about 0.001
signet BTC, at 0.1 sat/vB, from the test coins the funds record lists) and
exits 77. With a coin:

  One host and three AUTO members, each a separate gazpacho-test process
  with --network signet and both operators' servers (the chain port
  compares them). The lobby fills, the round is signed, the host's funding
  engine plans the funding from its coin, runs H1 and broadcasts at
  0.1 sat/vB; the funding confirms and is buried (3 blocks, about half an
  hour); the host and every member go Active, each by its own chain view
  (C11). Nothing is mined here: the test waits for signet, up to
  GZ_SIGNET_WAIT_S seconds (default 10800).

The factory's coins come back to the host through the tree's host timeout
after its end height; the test prints the funding's txid.
Every process is checked for no node-error, repair or fatal line.
"""
import os
import re
import subprocess
import sys
import struct
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Proc, kill_all, passphrase_file  # noqa: E402
import lobby  # noqa: E402
from lobby import World, parse_tlv, started, state, tlv  # noqa: E402
import slice1  # noqa: E402

check = slice1.check
FUNDING, ACTIVE = slice1.FUNDING, slice1.ACTIVE
CHANNEL_SAT = 10000   # each member's smallest channel: the factory fits one 0.001 coin (terms.md 3, field 30)
SERVERS = ("https://mempool.space/signet/api", "https://blockstream.info/signet/api")


class SignetWorld(World):
    """lobby.World on signet: the host's folder kept in GZ_SIGNET_DIR, the members' new each run."""

    def __init__(self, exe, work, name, keep):
        super().__init__(exe, work, name)
        self.keep = keep

    def folder(self, who):
        return os.path.join(self.keep, who) if who == "host" else os.path.join(self.work, who)

    def args(self, who, role):
        a = [self.exe, "--data-dir", self.folder(who), "--role", role, "--name", who, "--network", "signet"]
        for u in SERVERS:
            a += ["--chain-url", u]
        a += ["--no-interface", "--test-engines", "0", "--test-commands"]
        if role == "host":
            a += ["--listen", "127.0.0.1:%d" % self.port, "--max-per-address", "0"]
        else:
            a += ["--reconnect-ms", "100", "--connect", "%s@127.0.0.1:%d" % (self.hkey, self.port)]
        return a

    def _start(self, who, role, extra):
        self.runs[who] = self.runs.get(who, 0) + 1
        p = Proc("%s-%d" % (who, self.runs[who]), self.args(who, role) + list(extra), self.logs, stdin=True)
        self.procs.append(p)
        return p

    def journal(self, who):
        raise NotImplementedError("not read here")

    def host_address(self):
        """The host folder made on first use, its first receive address read (--check-chain)."""
        a = self.args("host", "host") + ["--check-chain", "--test-passphrase-file", passphrase_file(),
                                          "--test-kdf-floor"]
        r = subprocess.run(a, capture_output=True, text=True, timeout=180)
        m = re.search(r"first-address=(tb1[a-z0-9]+)", r.stdout + r.stderr)
        return m.group(1) if m else None


def small_channels(t, sat):
    """The terms with channel_sat (field 30) set to `sat`; the scope and the current record follow."""
    t.outer = tlv(*[(k, struct.pack(">Q", sat) if k == 30 else v) for k, v in parse_tlv(t.outer)])
    t.scope = lobby.th("gazpacho/terms/outer", t.outer)
    t.current = tlv(*[(k, t.scope if k == 2 else v) for k, v in parse_tlv(t.current)])
    t.tag = t.scope[:4].hex()
    return t


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    keep = os.environ.get("GZ_SIGNET_DIR", "")
    if os.environ.get("GZ_LIVE_TESTS") != "1" or not keep:
        print("SKIP: a live signet test (GZ_LIVE_TESTS=1 and GZ_SIGNET_DIR, a folder kept between runs)")
        return 77
    wait_s = int(os.environ.get("GZ_SIGNET_WAIT_S", "10800"))
    os.makedirs(work, exist_ok=True)
    os.makedirs(keep, exist_ok=True)
    w = SignetWorld(exe, work, "signet", os.path.abspath(keep))
    try:
        addr = w.host_address()
        if not check(addr is not None, "the host's first receive address is a signet one"):
            return check.result("program_slice1_signet", work)
        h = w.host()
        if not check(started(h) and w.hkey is not None, "the host starts on signet"):
            return check.result("program_slice1_signet", work)
        m = h.wait_for(r"wallet-coins count=(\d+) total_sat=(\d+)", timeout=180)
        if not check(m is not None, "its wallet port reads its coins from the servers"):
            return check.result("program_slice1_signet", work)
        if int(m.group(1)) == 0:
            print("SKIP: no coin at the host's address %s: fund it (about 0.001 signet BTC, 0.1 sat/vB) "
                  "and run again; nothing was moved" % addr)
            return 77
        print("the host's coins: %s, %s sat" % (m.group(1), m.group(2)))
        # A day's lifetime (T1's own, 144 blocks, and its 36 of wind-down): the coins come back soon.
        t = small_channels(slice1.Terms(w.hkey, 1800, lifetime=144), CHANNEL_SAT)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=30) is not None, "the lobby opens")
        ms = {n: w.member(n, "--member-signing", "auto") for n in ("m1", "m2", "m3")}
        check(all(started(p) for p in ms.values()), "three members start on signet")
        for p in ms.values():
            w.join(p, t)
        if not check(state(h, t, "host", FUNDING, timeout=900), "the round is signed: Funding"):
            r = h.wait_for(r"wallet-plan-refused coins=(\d+) amount=(\d+)", timeout=1)
            if r:
                print("the host's coins cannot fund the factory: it needs %s sat" % r.group(2))
            return check.result("program_slice1_signet", work)
        f = h.wait_for(r"broadcast-queued id=\d+ txid=([0-9a-f]{64})", timeout=300)
        check(f is not None, "the funding is broadcast")
        if f:
            print("funding txid %s" % f.group(1))
        procs = [h] + list(ms.values())
        end = time.time() + wait_s
        while time.time() < end and not all(slice1.live(p, t) for p in procs):
            time.sleep(30)
        check(all(slice1.live(p, t) for p in procs),
              "buried on signet: the host and every member Active, each by its own funding engine")
        check(not any(slice1.has(p, r"fund-report scope=%s kind=[234]" % t.tag) for p in procs),
              "nobody judged it abandoned, dead or live late")
        w.clean("signet")
    finally:
        w.stop()
        kill_all(w.procs)
    return check.result("program_slice1_signet", work)


if __name__ == "__main__":
    sys.exit(main())
