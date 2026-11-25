#!/usr/bin/env python3
"""program_slice1 (docs/notes/composite-node.md P4.6; docs/notes/integration.md 5):
Slice 1 end to end on the local test chain, every party a separate
gazpacho-test process, the chain a real Bitcoin Core regtest node.

    python3 -I slice1.py PATH_TO_GAZPACHO_TEST WORK_DIR BITCOIN_BIN_DIR

Starts its own regtest bitcoind (its own data folder under WORK_DIR, RPC on
127.0.0.1 at a free port, -listen=0; stopped at the end) and the Esplora
look-alike over it (tools/esplora-regtest.py), through which every
process's chain worker sees the chain. Every fee here is 0.1 sat/vB.
Exits 77 (skipped) when BITCOIN_BIN_DIR holds no bitcoind.

  1. One host and three members (AUTO), from clean folders: the host's coins
     are real regtest coins, found by its wallet port at its start. The
     lobby fills, the round is signed, the host's funding engine plans the
     funding from those coins (the proposal carries its bytes), runs H1 and
     broadcasts; the funding confirms and is buried (3 blocks); the host and
     every member go Active (Live), each by its own chain view.
  2. The same with a fourth member whose conditions the terms do not meet
     (its highest tree fee rate is below the terms'): it refuses, is never
     seated and never funded: no round, no funding watched; the other three
     and the host go Live as in 1.
  3. Two lobbies of one host, funded from two coins: m1 in both, m2 and m3
     in A, m4 and m5 in B. Both factories go Live. Then every process is
     stopped and started again once on its folder: each comes back with its
     lobbies Active, nothing judged again (no abandoned, dead or late
     report), and no node-error.
Every process is checked for no node-error, repair or fatal line.
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, free_port, kill_all, passphrase_file  # noqa: E402
import lobby  # noqa: E402
from lobby import World, cmd, conditions, parse_tlv, started, state, tlv  # noqa: E402

check = Checks()
lobby.check = check
FUNDING, ACTIVE = 4, 5
LEAVE, PAUSE = lobby.LEAVE, 0x0d01
FUNDED_SAT = 5000000   # 0.05 coins to the host's first address
TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools")


class Terms(lobby.Terms):
    """T1 with the target and minimum given and a lifetime long enough for
    the exit-time checks (terms.md 4.4), as program_signing's."""

    def __init__(self, hkey, deadline_in, target=3, minimum=3, lifetime=4320, window_ms=2000, budget_ms=600000):
        super().__init__(hkey, deadline_in, window_ms=window_ms, budget_ms=budget_ms)
        change = {10: struct.pack(">H", target), 12: struct.pack(">H", minimum), 26: struct.pack(">I", lifetime)}
        self.outer = tlv(*[(t, change.get(t, v)) for t, v in parse_tlv(self.outer)])
        self.scope = lobby.th("gazpacho/terms/outer", self.outer)
        self.current = tlv(*[(t, self.scope if t == 2 else v) for t, v in parse_tlv(self.current)])
        self.tag = self.scope[:4].hex()


class Regtest:
    """Our own regtest node and the Esplora look-alike over it."""

    def __init__(self, bindir, work):
        self.bin, self.dir = bindir, os.path.join(work, "bitcoind")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        self.rpc_port = free_port()
        self.proc = subprocess.Popen(
            [os.path.join(bindir, "bitcoind"), "-regtest", "-datadir=" + self.dir, "-listen=0", "-server=1",
             "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % self.rpc_port, "-txindex=1",
             "-fallbackfee=0.0001", "-mintxfee=0.000001", "-printtoconsole=0", "-daemon=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):
            try:
                self.cli("getblockcount")
                break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise SystemExit("bitcoind did not start")
        pf = os.path.join(self.dir, "esplora.port")
        self.es = subprocess.Popen([sys.executable, "-I", os.path.join(TOOLS, "esplora-regtest.py"), self.dir,
                                    str(self.rpc_port), pf], stdout=subprocess.DEVNULL,
                                   stderr=open(os.path.join(work, "esplora.log"), "w"))
        for _ in range(80):
            if os.path.exists(pf):
                break
            time.sleep(0.25)
        with open(pf) as f:
            self.url = "http://127.0.0.1:%s" % f.read().strip()
        self.cli("createwallet", "miner")
        self.miner = self.cli("-rpcwallet=miner", "getnewaddress")
        self.mine(101)

    def cli(self, *args):
        r = subprocess.run([os.path.join(self.bin, "bitcoin-cli"), "-regtest", "-datadir=" + self.dir,
                            "-rpcport=%d" % self.rpc_port, "-rpcconnect=127.0.0.1"] + list(args),
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except ValueError:
            return out

    def mine(self, n):
        return self.cli("generatetoaddress", str(n), self.miner)

    def pay(self, address, sat):
        txid = self.cli("-rpcwallet=miner", "-named", "sendtoaddress", "address=" + address,
                        "amount=%.8f" % (sat / 1e8), "fee_rate=0.1")
        self.mine(1)
        return txid

    def esplora(self, path):
        with urllib.request.urlopen(self.url + path, timeout=10) as r:
            return r.read().decode()

    def stop(self):
        self.es.terminate()
        try:
            self.cli("stop")
        except RuntimeError:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class ChainWorld(World):
    """lobby.World with every process's chain worker on the regtest node."""

    def __init__(self, exe, work, name, rt):
        super().__init__(exe, work, name)
        self.rt = rt

    def args(self, who, role):
        a = [self.exe, "--data-dir", os.path.join(self.work, who), "--role", role, "--name", who,
             "--test-regtest", "--chain-url", self.rt.url, "--chain-poll-ms", "250",
             "--no-interface", "--test-engines", "0",
             "--test-commands"]
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

    def host_address(self):
        """The host folder made, its first receive address read (--check-chain), before it runs."""
        a = self.args("host", "host") + ["--check-chain", "--test-passphrase-file", passphrase_file(),
                                          "--test-kdf-floor"]
        r = subprocess.run(a, capture_output=True, text=True, timeout=120)
        m = re.search(r"first-address=(bcrt1[a-z0-9]+)", r.stdout + r.stderr)
        return m.group(1) if m else None


def funding_txid(h, t):
    m = h.wait_for(r"broadcast-queued id=\d+ txid=([0-9a-f]{64})", timeout=120)
    return m.group(1) if m else None


def has(p, pattern):
    """A line of p matches, now (Proc.find gives a pair, never None)."""
    return p.count(pattern) > 0


def chain_tx(rt, txid):
    """The transaction as the node shows it; the log's txid in either byte order."""
    for t in (txid, bytes.fromhex(txid)[::-1].hex()):
        try:
            return rt.cli("getrawtransaction", t, "1")
        except RuntimeError:
            pass
    return {}


def bury(rt, procs, t, timeout=60):
    """Mine a block every two seconds until every process shows Active and its own funding
    engine has judged the factory Live, or the time is up. A member shows Active from the
    host's status too, before its own chain view has the burial; and a chain worker proving
    new confirmations tells no tip for that pass (docs/notes/integration.md, B15)."""
    end = time.time() + timeout
    while time.time() < end:
        if all(live(p, t) for p in procs):
            return True
        rt.mine(1)
        time.sleep(2)
    return False


def live(p, t):
    """Active, and Live by its own funding engine."""
    return (has(p, r"lobby scope=%s role=\w+ state=%d\b" % (t.tag, ACTIVE)) and
            has(p, r"fund-report scope=%s kind=1" % t.tag))


def run_case(exe, work, rt, name, refusing):
    w = ChainWorld(exe, work, "case" + name.split()[0], rt)   # a folder name with no spaces
    tick = ("--test-sign-tick-ms", "100")
    try:
        addr = w.host_address()
        if not check(addr is not None, "%s: the host's first receive address is a regtest one" % name):
            return
        rt.pay(addr, FUNDED_SAT)
        spk = rt.cli("-rpcwallet=miner", "getaddressinfo", addr)["scriptPubKey"]
        seen = json.loads(rt.esplora("/scripthash/%s/utxo" % hashlib.sha256(bytes.fromhex(spk)).hexdigest()))
        check(len(seen) == 1 and seen[0]["value"] == FUNDED_SAT and seen[0]["status"]["confirmed"],
              "%s: the Esplora look-alike shows the paid coin, confirmed" % name)
        h = w.host(*tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts on regtest" % name):
            return
        check(h.wait_for(r"wallet-coins count=1 total_sat=%d" % FUNDED_SAT, timeout=30) is not None,
              "%s: its wallet port finds its one confirmed coin through the chain port" % name)
        t = Terms(w.hkey, 900)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = {n: w.member(n, "--member-signing", "auto", *tick) for n in ("m1", "m2", "m3")}
        if refusing:
            ms["mr"] = w.member("mr", "--member-signing", "auto", *tick)
        check(all(started(m) for m in ms.values()), "%s: %d members start on regtest" % (name, len(ms)))
        if refusing:
            # T1's tree fee rate is 100 sat/kvB: a member that takes at most 1 refuses on its conditions.
            w.join(ms["mr"], t, conditions(max_tree_feerate=1))
            check(ms["mr"].wait_for(r"lobby-note code=0x4c02", timeout=30) is not None,
                  "%s: the member whose conditions the terms do not meet refuses" % name)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], t)
        check(state(h, t, "host", FUNDING, timeout=240), "%s: the round is signed: the host reaches Funding" % name)
        check(has(h, r"sign-begin scope=%s .*members=3" % t.tag) and not has(h, r"sign-begin scope=%s .*members=4" % t.tag),
              "%s: the round has the three members" % name)
        check(has(h, r"wallet-plan inputs=1 ") and not has(h, r"sign-begin-refused") and not has(h, r"fund-h1-refused"),
              "%s: the plan is made from the real coin and H1 passes" % name)
        txid = funding_txid(h, t)
        if not check(txid is not None, "%s: the host's funding engine broadcasts the funding" % name):
            return
        honest = [h] + [ms[n] for n in ("m1", "m2", "m3")]
        check(bury(rt, honest, t), "%s: the funding is buried and the host and every member go Active" % name)
        tx = chain_tx(rt, txid)
        if not check(bool(tx), "%s: the node knows the broadcast funding" % name):
            return
        check(tx.get("confirmations", 0) >= 3, "%s: the funding has at least 3 confirmations on the chain" % name)
        check(len(tx["vout"]) == 2 and tx["vout"][0]["scriptPubKey"]["type"] == "witness_v1_taproot",
              "%s: the funding pays the factory (output 0, taproot) and the host's change, nothing else" % name)
        fee = round(sum(rt.cli("getrawtransaction", i["txid"], "1")["vout"][i["vout"]]["value"] for i in tx["vin"]) * 1e8
                    - sum(o["value"] for o in tx["vout"]) * 1e8)
        check(fee >= tx["vsize"] * 0.1 and fee < tx["vsize"] * 0.2 + 2,
              "%s: its fee is %d sat for %d vB: 0.1 sat/vB" % (name, fee, tx["vsize"]))
        for n in ("m1", "m2", "m3"):
            check(has(ms[n], r"fund-report scope=%s kind=1" % t.tag),
                  "%s: %s judged the factory Live from its own chain view (C11)" % (name, n))
        check(has(h, r"fund-report scope=%s kind=1" % t.tag), "%s: the host's funding engine reports Live" % name)
        check(not any(has(p, r"fund-report scope=%s kind=[234]" % t.tag) for p in honest),
              "%s: on time: nobody judged it abandoned, dead or live late" % name)
        # Live resolves each member's round (gz_sign_resolve from the funding report): nothing of it holds
        # the member any more (Slice 1 blocker C1's end, integration B19). A leave is not refused too_late,
        # and a pause holds no lobby (200, not 202 held_for_signing).
        mk = ms["m1"].mark()
        ms["m1"].send(cmd(LEAVE, (12, t.scope)))
        r = ms["m1"].wait_for(r"command-result id=\S+ status=(\d+) error=(\S+)", timeout=10, start=mk)
        check(r is not None and r.group(1) != "409",
              "%s: after Live, m1's leave is not refused too_late (got %s)" % (name, r.group(0) if r else None))
        mk = ms["m2"].mark()
        ms["m2"].send(cmd(PAUSE, (12, bytes([1]))))
        r = ms["m2"].wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk)
        check(r is not None and r.group(1) == "200",
              "%s: after Live, m2's pause holds nothing: 200 (got %s)" % (name, r.group(1) if r else None))
        if refusing:
            mr = ms["mr"]
            check(mr.count(r"role=member .*joined=1") == 0 and not has(mr, r"sign-begin|sign-outcome|fund-"),
                  "%s: the refusing member was never seated, signed nothing and follows no funding" % name)
            check(not has(mr, r"lobby scope=%s role=member state=%d\b" % (t.tag, ACTIVE)),
                  "%s: and is not part of the Live factory" % name)
        w.clean(name)
    finally:
        w.stop()
        kill_all(w.procs)


def two_lobbies(exe, work, rt, name="3 two lobbies, restarts"):
    w = ChainWorld(exe, work, "case3", rt)
    tick = ("--test-sign-tick-ms", "100")
    try:
        addr = w.host_address()
        if not check(addr is not None, "%s: the host's first receive address" % name):
            return
        rt.pay(addr, FUNDED_SAT)
        rt.pay(addr, FUNDED_SAT)
        h = w.host(*tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts" % name):
            return
        check(h.wait_for(r"wallet-coins count=2 total_sat=%d" % (2 * FUNDED_SAT), timeout=30) is not None,
              "%s: its wallet port finds its two coins" % name)
        a, b = Terms(w.hkey, 900), Terms(w.hkey, 901)
        w.open(h, a)
        w.open(h, b)
        check(all(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None for t in (a, b)),
              "%s: both lobbies open" % name)
        names = ("m1", "m2", "m3", "m4", "m5")
        ms = {n: w.member(n, "--member-signing", "auto", *tick) for n in names}
        check(all(started(m) for m in ms.values()), "%s: five members start" % name)
        lobbies = {"m1": (a, b), "m2": (a,), "m3": (a,), "m4": (b,), "m5": (b,)}
        for n in names:
            for t in lobbies[n]:
                w.join(ms[n], t)
        check(all(state(h, t, "host", FUNDING, timeout=300) for t in (a, b)), "%s: both rounds signed: Funding" % name)
        check(h.count(r"broadcast-queued id=\d+ txid=") >= 2 or h.wait_for(r"broadcast-queued id=2 ", timeout=60),
              "%s: two fundings broadcast" % name)
        procs = [h] + list(ms.values())
        end = time.time() + 90
        while time.time() < end and not all(
                live(p, t) for t in (a, b) for p in [h] + [ms[n] for n in names if t in lobbies[n]]):
            rt.mine(1)
            time.sleep(2)
        check(all(has(p, r"fund-report scope=%s kind=1" % t.tag) for t in (a, b)
                  for p in [h] + [ms[n] for n in names if t in lobbies[n]]),
              "%s: both factories Live on the host and on each of their members" % name)
        check(not any(has(p, r"fund-report scope=\S+ kind=[234]") for p in procs),
              "%s: nobody judged either abandoned, dead or live late" % name)
        w.clean(name + ", first run")
        # Every process stopped and started again once on its folder.
        w.stop()
        h2 = w.host(*tick)
        ms2 = {n: w.member(n, "--member-signing", "auto", *tick) for n in names}
        check(started(h2) and all(started(m) for m in ms2.values()), "%s: every process starts again" % name)
        for _ in range(3):   # a few blocks, so that every chain view moves on after the restart
            rt.mine(1)
            time.sleep(2)
        check(all(state(h2, t, "host", ACTIVE, timeout=30) for t in (a, b)),
              "%s: after the restart the host shows both lobbies Active" % name)
        check(all(state(ms2[n], t, "member", ACTIVE, timeout=30) for n in names for t in lobbies[n]),
              "%s: and every member its lobbies Active (m1 both)" % name)
        check(not any(has(p, r"fund-report scope=\S+ kind=[234]|sign-begin|funding-adopt-refused")
                      for p in [h2] + list(ms2.values())),
              "%s: nothing judged, begun or refused again after the restart" % name)
        # After the restart too, from the journal: m1's two Live rounds hold nothing.
        mk = ms2["m1"].mark()
        ms2["m1"].send(cmd(PAUSE, (12, bytes([1]))))
        r = ms2["m1"].wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk)
        check(r is not None and r.group(1) == "200",
              "%s: after the restart, m1's pause holds neither Live lobby: 200 (got %s)" % (name, r.group(1) if r else None))
        w.clean(name)
    finally:
        w.stop()
        kill_all(w.procs)


def main():
    exe, work, bindir = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else os.environ.get("GZ_BITCOIN_BIN", "")
    if not bindir or not os.path.exists(os.path.join(bindir, "bitcoind")):
        print("SKIP: no bitcoind (give BITCOIN_BIN_DIR or GZ_BITCOIN_BIN)")
        return 77
    os.makedirs(work, exist_ok=True)
    rt = Regtest(bindir, work)
    try:
        run_case(exe, work, rt, "1 three members", refusing=False)
        run_case(exe, work, rt, "2 one member refusing", refusing=True)
        two_lobbies(exe, work, rt)
    finally:
        rt.stop()
    return check.result("program_slice1", work)


if __name__ == "__main__":
    sys.exit(main())
