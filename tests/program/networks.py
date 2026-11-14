#!/usr/bin/env python3
"""T15, program_networks (contract-v2.md section 15).

    python3 -I networks.py PATH_TO_GAZPACHO_TEST WORK_DIR

A testnet4 host and a testnet4 member connect and ping. A signet member to the
testnet4 host: both sides close the connection over init (one chain hash
each, and they differ). --network mainnet exits 2 before any file is made.
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, peer_id, run  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    common = ["--no-chain", "--no-interface", "--reconnect-ms", "200", "--test-pings", "10", "--test-ping-ms", "30"]
    procs = []
    try:
        code, out = run(exe, "--data-dir", os.path.join(work, "main"), "--role", "host", "--no-chain",
                        "--network", "mainnet")
        check(code == 2 and not os.path.exists(os.path.join(work, "main")),
              "--network mainnet exits 2 before any file is made (exit %s)" % code)

        host = Proc("host-t4", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--network",
                                "testnet4", "--listen", "127.0.0.1:0", "--name", "host"] + common, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "testnet4 host listens")
            return 1
        hkey, port = k.group(1), m.group(1)
        connect = ["--connect", "%s@127.0.0.1:%s" % (hkey, port)]
        t4 = Proc("member-t4", [exe, "--data-dir", os.path.join(work, "t4"), "--role", "member", "--network",
                                "testnet4", "--name", "t4"] + connect + common, logs)
        procs.append(t4)
        check(t4.wait_for(r"pings-done peer=%s n=10" % peer_id(hkey)) is not None,
              "a testnet4 member and a testnet4 host connect and ping")
        check(t4.wait_for(r"interface off") is not None and t4.find(r"wallet network=testnet4 ")[0] is not None,
              "the member's folder is a testnet4 one")

        mark = host.mark()
        sg = Proc("member-signet", [exe, "--data-dir", os.path.join(work, "sg"), "--role", "member",
                                    "--name", "sg"] + connect + common, logs)
        procs.append(sg)
        check(sg.wait_for(r"closed conn=\d+ why=init-refused was_connected=0", timeout=15) is not None,
              "the signet member closes the connection over init")
        check(host.wait_for(r"closed conn=\d+ why=init-refused was_connected=0", timeout=15, start=mark) is not None,
              "the testnet4 host closes it over init too")
        check(sg.find(r" connected peer=")[0] is None, "the signet member never reports a connection")

        t4.stop()
        code, out = run(exe, "--data-dir", os.path.join(work, "t4"), "--role", "member", "--no-chain",
                        "--network", "signet", "--connect", "%s@127.0.0.1:%s" % (hkey, port))
        check(code == 4 and "belongs to a member testnet4" in out, "a testnet4 folder is refused as a signet one (exit %s)" % code)
    finally:
        kill_all(procs)
    return check.result("networks", logs)


if __name__ == "__main__":
    sys.exit(main())
