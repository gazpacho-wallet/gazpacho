#!/usr/bin/env python3
"""T13, program_derived_keys (docs/notes/keys.md 10; contract-v2.md 13), with
T2 step 3: keys derived from the seed, end to end, as separate processes.

    python3 -I derived_keys.py PATH_TO_GAZPACHO_TEST WORK_DIR

The host's folders are made from the test words "abandon ... art" (entropy
all zero) and the member's from "zoo ... vote" (entropy all 0xff), through
the stand-in seed file, and every key the processes show is compared
with tools/keys_ref.py, which shares no code with the program.

  1. The host's key at start is m/254315617'/2'/1'/0' (signet), the same after
     a restart; a testnet4 folder from the same words shows another key, its
     own vector (net level 1). The wallet's first address line is BIP 86's
     m/86'/1'/0'/0/0 of the same words. No transport.key is written.
  2. A member (AT_JOIN, the default: it joins and stays unready, so its
     lobbies stay Open) joins a lobby: its slot opens with index 1, and the host sees a
     connection from the vector key at (epoch 0, index 1); its journal's
     key_index says 2. A second lobby on the same host (T2 step 3): index 3,
     a second link from the (0, 3) key, and both lobbies join, each over its
     own link.
  3. The member restarted: the host sees the same two keys again.
  4. The member restored from a copy of its journal: a new epoch E; the
     backup's slots load without keys (keys epoch frozen until the restore
     batch), so the host sees neither old key again; joining a third lobby
     uses a key under E, the vector at (E, index), which no seat holds.
  5. Restarted after the restore: the epoch comes back from the journal and
     the member reconnects with the (E, index) key only.
  6. One set of words as host and as member (keys.md 3, K2): a member made
     from the host's own words joins the host's lobby with two others; every
     seat is accepted and the lobby reaches Funding on the host and on that
     member, through the signing stand-in. The host's own pairs are on 2',
     the member's on 0'.
THE KEYS HERE ARE TEST KEYS."""
import hashlib
import os
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
from gzp_harness import Checks, Proc, kill_all, parse_journal  # noqa: E402
import keys_ref as R  # noqa: E402
import lobby as L  # noqa: E402

check = Checks()
SEED = R.bip39_seed(R.ART)      # the host's words
SEED_M = R.bip39_seed(R.VOTE)   # the member's in steps 2 to 5; step 6 shares the host's


def seed_folder(path, byte="00"):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    fd = os.open(os.path.join(path, "wallet-seed.standin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, byte.encode() * 32 + b"\n")
    os.close(fd)


def pub(sec):
    return R.ser33(R.mul(sec)).hex()


def lobby_key(epoch, index, net="signet", seed=None):
    return pub(R.lobby(SEED_M if seed is None else seed, net, epoch, index))


def host_key(net):
    return pub(R.host(SEED, net)[1])


def peer(key_hex):
    return hashlib.sha256(bytes.fromhex(key_hex)).digest()[:8].hex()


def key_index_values(folder):
    """Every key_index record's value (field 2, u32) in the member's journal, oldest first."""
    out = []
    for e in parse_journal(os.path.join(folder, "journal.standin")):
        if e[0] == "BTCH":
            out += [int.from_bytes(b[2:6], "big") for t, b in e[3] if t == L.KEY_INDEX and len(b) >= 6]
    return out


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    procs = []
    try:
        # 1. the host's key ---------------------------------------------------
        w = L.World(exe, work, "t13")
        seed_folder(os.path.join(w.work, "host"))
        seed_folder(os.path.join(w.work, "m"), "ff")
        h = w.host()
        procs = w.procs
        check(L.started(h) and w.hkey == host_key("signet"),
              "1: the host's key is the vector m/254315617'/2'/1'/0' (%s)" % w.hkey)
        first = R.bip86(SEED, "signet", 0, 0)[2].hex()
        check(h.wait_for(r"wallet network=signet first-address=tb1p", timeout=5) is not None,
              "1: the wallet's first address is shown")
        check(not os.path.exists(os.path.join(w.work, "host", "transport.key")), "1: no transport.key is written")
        h.stop()
        h = w.host()
        check(L.started(h) and w.hkey == host_key("signet"), "1: the same key after a restart")
        t4 = os.path.join(w.work, "host4")
        seed_folder(t4)
        p4 = Proc("host-t4", [exe, "--data-dir", t4, "--role", "host", "--network", "testnet4", "--name", "h4",
                              "--no-chain", "--no-interface", "--listen", "127.0.0.1:0"], w.logs)
        procs.append(p4)
        k4 = p4.wait_for(r"host key=([0-9a-f]{66})")
        check(k4 is not None and k4.group(1) == host_key("testnet4") and k4.group(1) != w.hkey,
              "1: a testnet4 folder from the same words has its own key, the vector at net level 1")
        p4.stop()
        check(first[:4] == "5120", "1: BIP 86 scripts are 51 20 <key> (%s)" % first[:8])

        # 2. a member, two lobbies, two links ----------------------------------
        a, b = L.Terms(w.hkey, 600), L.Terms(w.hkey, 601)
        w.open(h, a)
        w.open(h, b, 0)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % a.tag, timeout=10) is not None and
              h.wait_for(r"slot-opened scope=%s .*role=host" % b.tag, timeout=10) is not None, "2: two lobbies open")
        m = w.member("m")
        check(L.started(m), "2: the member starts")
        k01, k03 = lobby_key(0, 1), lobby_key(0, 3)
        w.join(m, a)
        check(m.wait_for(r"slot-opened scope=%s .*role=member index=1\b" % a.tag, timeout=15) is not None,
              "2: the member's first slot opens with index 1 (the pair 1, 2)")
        check(h.wait_for(r"connected peer=%s key=%s" % (peer(k01), k01), timeout=15) is not None,
              "2: the host sees the vector key at (epoch 0, index 1)")
        w.join(m, b)
        check(m.wait_for(r"slot-opened scope=%s .*role=member index=3\b" % b.tag, timeout=15) is not None,
              "2: a second lobby opens the next pair, index 3")
        check(h.wait_for(r"connected peer=%s key=%s" % (peer(k03), k03), timeout=15) is not None,
              "2 (T2 step 3): a second link to the same host, from the (0, 3) key")
        check(m.wait_for(r"lobby scope=%s role=member .*joined=1" % a.tag, timeout=20) is not None and
              m.wait_for(r"lobby scope=%s role=member .*joined=1" % b.tag, timeout=20) is not None,
              "2 (T2 step 3): both lobbies join, each over its own link")
        check(m.count(r" connected peer=") == 2, "2: the member holds exactly two links")
        time.sleep(1)
        check(m.count(r"lobby-note code=0x4c06 a=\d+ b=7") == 0 and m.count(r"slot-closed") == 0,
              "2: neither seat is refused and both slots stay open (no key shared with the host)")
        m.stop()
        ki = key_index_values(os.path.join(w.work, "m"))
        check(ki[:2] == [2, 4], "2: the member's key_index records say 2, then 4 (%r)" % ki[:4])
        backup = os.path.join(w.work, "m-backup.journal")
        for f in os.listdir(os.path.join(w.work, "m")):
            if f.startswith("journal.standin") and not f.endswith(tuple("-%d" % i for i in range(10))):
                shutil.copyfile(os.path.join(w.work, "m", f), backup)
                break
        check(os.path.exists(backup), "2: the member's journal is copied for step 4")

        # 3. restarted: the same keys ----------------------------------------
        mark = h.mark()
        m = w.member("m")
        check(L.started(m), "3: the member restarts")
        check(h.wait_for(r"connected peer=%s key=%s" % (peer(k01), k01), timeout=15, start=mark) is not None and
              h.wait_for(r"connected peer=%s key=%s" % (peer(k03), k03), timeout=15, start=mark) is not None,
              "3: the host sees the same two keys again")
        m.stop()

        # 4. restored: a new epoch, old keys never again ----------------------
        mark = h.mark()
        m = w.member("m", "--test-restore-from", backup)
        rb = m.wait_for(r"restore-batch seq=\d+ epoch=([0-9a-f]{8})", timeout=20)
        check(rb is not None and int(rb.group(1), 16) != 0, "4: the restore draws a new epoch")
        epoch = int(rb.group(1), 16) if rb else 0
        check(m.find(r"keys epoch=00000000 frozen=1")[0] is not None,
              "4: the restore start derives nothing until the new epoch is saved")
        check(L.started(m), "4: the restored member starts")
        time.sleep(2)
        check(h.count(r"connected peer=%s" % peer(k01), start=mark) == 0 and
              h.count(r"connected peer=%s" % peer(k03), start=mark) == 0,
              "4: the host never sees an old key again (R3)")
        c = L.Terms(w.hkey, 602)
        w.open(h, c)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % c.tag, timeout=10) is not None, "4: a third lobby")
        w.join(m, c)
        so = m.wait_for(r"slot-opened scope=%s .*role=member index=(\d+)" % c.tag, timeout=15)
        idx = int(so.group(1)) if so else -1
        ke = lobby_key(epoch, idx) if so else "none"
        check(so is not None and h.wait_for(r"connected peer=%s key=%s" % (peer(ke), ke), timeout=15, start=mark)
              is not None, "4: joining again uses the vector key at (E, %d), which no seat holds" % idx)
        check(m.wait_for(r"lobby scope=%s role=member .*joined=1" % c.tag, timeout=20) is not None,
              "4: and joins")
        # 5. restarted after the restore: the epoch read back from storage --
        m.stop()
        mark = h.mark()
        m = w.member("m")
        check(m.wait_for(r"keys epoch=%08x frozen=0" % epoch, timeout=20) is not None,
              "5: restarted, the key port's epoch is the restore's, read from the journal")
        check(h.wait_for(r"connected peer=%s key=%s" % (peer(ke), ke), timeout=15, start=mark) is not None and
              h.count(r"connected peer=%s" % peer(k01), start=mark) == 0,
              "5: it reconnects with the (E, %d) key, never an old one" % idx)
        # 6. one seed, both roles (K2) ------------------------------------------
        # Fresh folders, so the host's first lobby pair and the member's are
        # both (1, 2): with both on one branch they would be the same keys.
        for p in procs:
            p.stop()
        w6 = L.World(exe, work, "k2")
        seed_folder(os.path.join(w6.work, "host"))
        seed_folder(os.path.join(w6.work, "ms"))  # the host's own words
        h6 = w6.host("--test-sign-outcome", "funding", "--test-sign-delay-ms", "200")
        procs += w6.procs
        check(L.started(h6) and w6.hkey == host_key("signet"), "6: a fresh host from the same words")
        d = L.Terms(w6.hkey, 603)
        w6.open(h6, d)
        check(h6.wait_for(r"slot-opened scope=%s .*role=host index=1$" % d.tag, timeout=10) is not None,
              "6: its first lobby, the host's pair (1, 2)")
        ms = [w6.member(n, "--member-signing", "auto", "--test-sign-outcome", "funding") for n in ("ms", "x2", "x3")]
        procs += [p for p in ms if p not in procs]
        check(all(L.started(p) for p in ms), "6: three members start, one from the host's words")
        for p in ms:
            w6.join(p, d)
        kd = lobby_key(0, 1, seed=SEED)
        check(ms[0].wait_for(r"slot-opened scope=%s .*role=member index=1$" % d.tag, timeout=15) is not None and
              h6.wait_for(r"connected peer=%s key=%s" % (peer(kd), kd), timeout=15) is not None,
              "6: the member with the host's words uses its pair (1, 2) on 0', key %s" % kd[:16])
        check(L.state(h6, d, "host", 4) and L.state(ms[0], d, "member", 4),
              "6: every seat is accepted and the lobby reaches Funding, on the host and on that member")
        check(ms[0].count(r"lobby-note code=0x4c06 a=\d+ b=7") == 0, "6: no seat is refused (no factory key shared)")
        bad = [(p.name, ln) for p in procs for ln in p.lines if "node-error" in ln or " fatal" in ln]
        check(not bad, "no node-error or fatal line in any process %r" % bad[:2])
        for p in procs:
            p.stop()
    finally:
        kill_all(procs)
    return check.result("derived keys", work)


if __name__ == "__main__":
    sys.exit(main())
