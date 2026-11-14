#!/usr/bin/env python3
"""A SOCKS5 listener on 127.0.0.1 that records what a client sends and then
refuses the connection. Used by local-servers.sh to show that a configured
proxy is really used, that the name goes to the proxy (socks5h), and that
only "no authentication" is offered.

    socks_recorder.py WORK_DIR

Writes WORK_DIR/socks_port when listening. For each client it appends one
line to WORK_DIR/socks.log: "greeting HEX connect HEX". Standard library
only; never connects anywhere.
"""
import os
import socket
import sys


def read_exact(c, n):
    data = b""
    while len(data) < n:
        chunk = c.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def handle(c, log):
    c.settimeout(5)
    greeting = read_exact(c, 2)
    if len(greeting) == 2:
        greeting += read_exact(c, greeting[1])
    c.sendall(b"\x05\x00")  # no authentication
    head = read_exact(c, 4)
    req = head
    if len(head) == 4:
        if head[3] == 3:
            n = read_exact(c, 1)
            req += n + (read_exact(c, n[0] + 2) if n else b"")
        elif head[3] == 1:
            req += read_exact(c, 6)
        elif head[3] == 4:
            req += read_exact(c, 18)
    c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
    with open(log, "a") as f:
        f.write("greeting %s connect %s\n" % (greeting.hex(), req.hex()))


def main():
    work = sys.argv[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    tmp = os.path.join(work, "socks_port.tmp")
    with open(tmp, "w") as f:
        f.write("%d\n" % s.getsockname()[1])
    os.rename(tmp, os.path.join(work, "socks_port"))
    log = os.path.join(work, "socks.log")
    while True:
        c, _ = s.accept()
        try:
            handle(c, log)
        except OSError:
            pass
        finally:
            c.close()


if __name__ == "__main__":
    main()
