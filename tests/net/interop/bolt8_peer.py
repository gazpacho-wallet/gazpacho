#!/usr/bin/env python3
# Written by the independent reviewer of pull request 10 (2026-11-12),
# from the BOLT 8 text and not from this repository's code; copied here
# unchanged apart from these lines. Opt-in test: -DGZ_INTEROP_PY=ON.
"""Reviewer's independent BOLT 8 peer, written from 08-transport.md (not from
the PR's code). Pure-Python secp256k1; ChaCha20-Poly1305 from `cryptography`.

  bolt8_peer.py selftest                    BOLT 8 vectors, initiator side
  bolt8_peer.py member PORT HOSTPUB N       connect to gz-net listen, N pings
  bolt8_peer.py host N                      listen; prints port and pubkey, answers N pings
"""
import hashlib, hmac, os, socket, sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def _mul(k, pt):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r

def ser(pt): return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")

def parse(b):
    if len(b) != 33 or b[0] not in (2, 3): raise ValueError("pubkey")
    x = int.from_bytes(b[1:], "big")
    if x >= P: raise ValueError("pubkey")
    y2 = (x ** 3 + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2: raise ValueError("pubkey")
    if (y & 1) != (b[0] & 1): y = P - y
    return (x, y)

def pub(priv): return ser(_mul(int.from_bytes(priv, "big"), G))
def ecdh(priv, pubb): return hashlib.sha256(ser(_mul(int.from_bytes(priv, "big"), parse(pubb)))).digest()
def sha(*a): return hashlib.sha256(b"".join(a)).digest()

def hkdf(salt, ikm):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t1 = hmac.new(prk, b"\x01", hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + b"\x02", hashlib.sha256).digest()
    return t1, t2

def nonce(n): return b"\0" * 4 + n.to_bytes(8, "little")
def enc(k, n, ad, p): return ChaCha20Poly1305(k).encrypt(nonce(n), p, ad)
def dec(k, n, ad, c): return ChaCha20Poly1305(k).decrypt(nonce(n), c, ad)

class Dir:
    def __init__(self, k, ck): self.k, self.ck, self.n = k, ck, 0
    def use(self):
        n = self.n
        self.n += 1
        return n
    def after(self):
        if self.n == 1000:
            self.ck, self.k = hkdf(self.ck, self.k)
            self.n = 0

class Session:
    def __init__(self, sk, rk, ck): self.s, self.r = Dir(sk, ck), Dir(rk, ck)
    def encrypt(self, m):
        out = enc(self.s.k, self.s.use(), b"", len(m).to_bytes(2, "big")); self.s.after()
        out += enc(self.s.k, self.s.use(), b"", m); self.s.after()
        return out
    def recv(self, rd):
        l = int.from_bytes(dec(self.r.k, self.r.use(), b"", rd(18)), "big"); self.r.after()
        m = dec(self.r.k, self.r.use(), b"", rd(l + 16)); self.r.after()
        return m

def initial(rs_or_ls_pub):
    h = sha(b"Noise_XK_secp256k1_ChaChaPoly_SHA256")
    ck = h
    h = sha(h, b"lightning")
    return sha(h, rs_or_ls_pub), ck

class Initiator:
    def __init__(self, ls, e, rs):
        self.ls, self.e, self.rs = ls, e, rs
        self.h, self.ck = initial(rs)
    def act1(self):
        epub = pub(self.e)
        self.h = sha(self.h, epub)
        self.ck, k = hkdf(self.ck, ecdh(self.e, self.rs))
        c = enc(k, 0, self.h, b"")
        self.h = sha(self.h, c)
        return b"\0" + epub + c
    def act2_act3(self, a2):
        if len(a2) != 50 or a2[0] != 0: raise ValueError("act2")
        re, c = a2[1:34], a2[34:]
        self.h = sha(self.h, re)
        self.ck, k2 = hkdf(self.ck, ecdh(self.e, re))
        dec(k2, 0, self.h, c)
        self.h = sha(self.h, c)
        c3 = enc(k2, 1, self.h, pub(self.ls))
        self.h = sha(self.h, c3)
        self.ck, k3 = hkdf(self.ck, ecdh(self.ls, re))
        t = enc(k3, 0, self.h, b"")
        sk, rk = hkdf(self.ck, b"")
        return b"\0" + c3 + t, Session(sk, rk, self.ck)

class Responder:
    def __init__(self, ls, e):
        self.ls, self.e = ls, e
        self.h, self.ck = initial(pub(ls))
    def act1_act2(self, a1):
        if len(a1) != 50 or a1[0] != 0: raise ValueError("act1")
        self.re, c = a1[1:34], a1[34:]
        self.h = sha(self.h, self.re)
        self.ck, k1 = hkdf(self.ck, ecdh(self.ls, self.re))
        dec(k1, 0, self.h, c)
        self.h = sha(self.h, c)
        epub = pub(self.e)
        self.h = sha(self.h, epub)
        self.ck, self.k2 = hkdf(self.ck, ecdh(self.e, self.re))
        c2 = enc(self.k2, 0, self.h, b"")
        self.h = sha(self.h, c2)
        return b"\0" + epub + c2
    def act3(self, a3):
        if len(a3) != 66 or a3[0] != 0: raise ValueError("act3")
        c, t = a3[1:50], a3[50:]
        rs = dec(self.k2, 1, self.h, c)
        parse(rs)
        self.h = sha(self.h, c)
        self.ck, k3 = hkdf(self.ck, ecdh(self.e, rs))
        dec(k3, 0, self.h, t)
        rk, sk = hkdf(self.ck, b"")
        return rs, Session(sk, rk, self.ck)

def selftest():
    rs = bytes.fromhex("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")
    i = Initiator(b"\x11" * 32, b"\x12" * 32, rs)
    assert i.act1().hex() == "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
    a3, s = i.act2_act3(bytes.fromhex("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"))
    assert a3.hex() == "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
    want = {0: "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95",
            1: "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1",
            500: "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8",
            501: "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd",
            1000: "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09",
            1001: "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36"}
    for k in range(1002):
        c = s.encrypt(b"hello")
        if k in want: assert c.hex() == want[k], k
    # responder side of the same vector
    r = Responder(b"\x21" * 32, b"\x22" * 32)
    i = Initiator(b"\x11" * 32, b"\x12" * 32, rs)
    a2 = r.act1_act2(i.act1())
    assert a2.hex().startswith("0002466d7fcae563")
    a3, si = i.act2_act3(a2)
    rsv, sr = r.act3(a3)
    assert rsv.hex() == "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
    print("selftest ok")

def reader(sock):
    def rd(n):
        b = b""
        while len(b) < n:
            x = sock.recv(n - len(b))
            if not x: raise EOFError
            b += x
        return b
    return rd

def tu(v):
    b = v.to_bytes(8, "big").lstrip(b"\0")
    return b

def ping(kind, seq):
    t = tu(seq)
    return b"\x80\x01" + b"\x01\x01" + bytes([kind]) + b"\x03" + bytes([len(t)]) + t

def member(port, hostpub, n):
    sock = socket.create_connection(("127.0.0.1", port), timeout=20)
    rd = reader(sock)
    i = Initiator(os.urandom(32), os.urandom(32), bytes.fromhex(hostpub))
    sock.sendall(i.act1())
    a3, s = i.act2_act3(rd(50))
    sock.sendall(a3)
    # an unknown odd message must be ignored by the host
    sock.sendall(s.encrypt(b"\x80\x03odd"))
    # all pings first, then all pongs: the two sides rotate in different orders
    out = b"".join(s.encrypt(ping(1, 1000 + k)) for k in range(n))
    sock.sendall(out)
    for k in range(n):
        m = s.recv(rd)
        if m != ping(2, 1000 + k): raise SystemExit("bad pong %d: %s" % (k, m.hex()))
    # an unknown even message: the host must close
    sock.sendall(s.encrypt(b"\x80\x02even"))
    try:
        x = sock.recv(1)
        closed = x == b""
    except (ConnectionResetError, socket.timeout):
        closed = True
    print("member ok %d pongs, host closed on unknown even: %s" % (n, closed))
    if not closed: raise SystemExit(1)

def host(n):
    ls = os.urandom(32)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    print("host %d %s" % (srv.getsockname()[1], pub(ls).hex()), flush=True)
    srv.settimeout(30)
    c, _ = srv.accept()
    c.settimeout(20)
    rd = reader(c)
    r = Responder(ls, os.urandom(32))
    c.sendall(r.act1_act2(rd(50)))
    rs, s = r.act3(rd(66))
    for k in range(n):
        m = s.recv(rd)
        if m != ping(1, 1000 + k): raise SystemExit("bad ping %d" % k)
        c.sendall(s.encrypt(ping(2, 1000 + k)))
    print("host ok %d pings from %s" % (n, rs.hex()), flush=True)

if __name__ == "__main__":
    if sys.argv[1] == "selftest": selftest()
    elif sys.argv[1] == "member": member(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif sys.argv[1] == "host": host(int(sys.argv[2]))
