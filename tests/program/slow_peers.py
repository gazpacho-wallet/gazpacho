#!/usr/bin/env python3
"""T6, program_slow_peers (contract-v2.md section 6).

    python3 -I slow_peers.py PATH_TO_GAZPACHO_TEST PATH_TO_SILENT_PEER WORK_DIR

Against one host, three clients that never finish: a TCP client that sends
nothing, one that sends act one a byte per second, and one that completes
the BOLT 8 handshake and never sends init. A real member connecting
meanwhile is connected within a second and has every ping answered; each
slow client is closed at the handshake deadline, as the host's output shows.
"""
import os
import shutil
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, peer_id  # noqa: E402

HANDSHAKE_MS = 3000
check = Checks()


def trickle(port, stop):
    """Act one, a byte a second."""
    s = socket.create_connection(("127.0.0.1", port))
    data = os.urandom(50)
    for b in data:
        if stop.is_set():
            break
        try:
            s.send(bytes([b]))
        except OSError:
            break
        time.sleep(1)
    s.close()


def main():
    exe, silent, work = (os.path.abspath(a) for a in sys.argv[1:4])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    common = ["--no-chain", "--no-interface", "--handshake-ms", str(HANDSHAKE_MS), "--reconnect-ms", "100",
              "--test-pings", "20", "--test-ping-ms", "50"]
    procs, socks = [], []
    stop = threading.Event()
    try:
        host = Proc("host", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host",
                             "--listen", "127.0.0.1:0", "--max-per-address", "0", "--name", "host"] + common, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "host listens")
            return 1
        hkey, port = k.group(1), int(m.group(1))

        mark = host.mark()
        quiet = socket.create_connection(("127.0.0.1", port))      # 1: says nothing
        socks.append(quiet)
        threading.Thread(target=trickle, args=(port, stop), daemon=True).start()  # 2: a byte a second
        sp = Proc("silent", [silent, str(port), hkey, "10"], logs)  # 3: handshake, no init
        procs.append(sp)
        check(sp.wait_for(r"handshake-done", timeout=5) is not None, "the silent client completes its handshake")

        t0 = time.time()
        mem = Proc("member", [exe, "--data-dir", os.path.join(work, "member"), "--role", "member", "--name", "m",
                              "--connect", "%s@127.0.0.1:%d" % (hkey, port)] + common, logs)
        procs.append(mem)
        mk = mem.wait_for(r"member key=([0-9a-f]{66})")
        i_ready = mem.index_of(r"ready incarnation=1")
        i_conn = mem.index_of(r"connected peer=%s" % peer_id(hkey), timeout=10)
        delay = (mem.times[i_conn] - mem.times[i_ready]) if (i_conn is not None and i_ready is not None) else 99
        check(i_conn is not None and delay < 1.0,
              "the member is connected within 1 s of being able to connect (%.3f s)" % delay)
        check(host.wait_for(r"connected peer=%s" % peer_id(mk.group(1) if mk else "00")) is not None,
              "the host reports the member connected")
        check(mem.wait_for(r"pings-done peer=%s n=20" % peer_id(hkey)) is not None,
              "the member's pings are all answered while the slow clients hang")
        check(host.wait_for(r"pings-done peer=%s n=20" % peer_id(mk.group(1) if mk else "00")) is not None,
              "the host's pings to the member are all answered")
        time.sleep(HANDSHAKE_MS / 1000.0 + 1.5)
        n = host.count(r"closed conn=\d+ why=handshake-timed-out was_connected=0", start=mark)
        check(n >= 3, "each slow client is closed at the handshake deadline (%d closed)" % n)
        check(host.count(r"disconnected peer=%s" % peer_id(mk.group(1) if mk else "00")) == 0,
              "the member's connection stays up")
        del t0
    finally:
        stop.set()
        for s in socks:
            s.close()
        kill_all(procs)
    return check.result("slow peers", logs)


if __name__ == "__main__":
    sys.exit(main())
