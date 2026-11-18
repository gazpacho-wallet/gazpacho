#!/usr/bin/env python3
"""A reference for docs/notes/keys.md, standard library only, sharing no code
with the C side: BIP 32 (private derivation), BIP 39 seed stretching, BIP 340
x-only keys and the BIP 341 / BIP 86 key-path tweak, over plain affine
secp256k1 arithmetic. NOT constant time: for test vectors only.

THE KEYS HERE ARE TEST KEYS, from public test phrases. Never use them for
coins.

It checks itself against BIP 32's test vector 1 and BIP 86's first vector
before anything else uses it (selftest())."""
import hashlib
import hmac

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HARD = 0x80000000
PURPOSE = 254315617
NET_LEVEL = {"testnet4": 1, "signet": 2, "testnet": 3, "regtest": 4}
COIN = {"testnet4": 1, "signet": 1, "testnet": 1, "regtest": 1, "mainnet": 0}


class Invalid(Exception):
    """BIP 32's invalid child (or master)."""


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def ser33(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def lift_x(x):
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("not a point")
    return (x, y if y % 2 == 0 else P - y)


def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def master(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if k == 0 or k >= N:
        raise Invalid(0)
    return k, i[32:]


def child(k, c, idx):
    if idx >= HARD:
        data = b"\x00" + k.to_bytes(32, "big") + idx.to_bytes(4, "big")
    else:
        data = ser33(mul(k)) + idx.to_bytes(4, "big")
    i = hmac.new(c, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    if il >= N:
        raise Invalid(idx)
    ki = (il + k) % N
    if ki == 0:
        raise Invalid(idx)
    return ki, i[32:]


def derive(seed, path):
    k, c = master(seed)
    for idx in path:
        k, c = child(k, c, idx)
    return k


def lobby(seed, net, epoch, index, host=False):
    """The secret at m/254315617'/net'/0'/epoch'/index', or on a host at
    m/254315617'/net'/2'/epoch'/index' (its own pairs, docs/notes/keys.md K2)."""
    return derive(seed, [PURPOSE | HARD, NET_LEVEL[net] | HARD, (2 if host else 0) | HARD, epoch | HARD, index | HARD])


def host(seed, net):
    """(k, secret) for m/254315617'/net'/1'/k', k the first valid."""
    k0, c0 = master(seed)
    for idx in (PURPOSE | HARD, NET_LEVEL[net] | HARD, 1 | HARD):
        k0, c0 = child(k0, c0, idx)
    for k in range(2 ** 31):
        try:
            return k, child(k0, c0, k | HARD)[0]
        except Invalid:
            continue
    raise Invalid("host")


def bip86(seed, net, change, j):
    """(internal x-only key, output x-only key, 34-byte script) at m/86'/coin'/0'/change/j."""
    d = derive(seed, [86 | HARD, COIN[net] | HARD, 0 | HARD, change, j])
    pt = mul(d)
    xp = pt[0].to_bytes(32, "big")
    t = int.from_bytes(tagged("TapTweak", xp), "big")
    q = add(lift_x(pt[0]), mul(t))
    xq = q[0].to_bytes(32, "big")
    return xp, xq, b"\x51\x20" + xq


def bip39_seed(phrase, passphrase=""):
    return hashlib.pbkdf2_hmac("sha512", phrase.encode(), ("mnemonic" + passphrase).encode(), 2048)


ABOUT = " ".join(["abandon"] * 11 + ["about"])   # BIP 86's test phrase
ART = " ".join(["abandon"] * 23 + ["art"])        # 32 zero bytes of entropy
VOTE = " ".join(["zoo"] * 23 + ["vote"])          # 32 bytes of 0xff (BIP 39's own vector)


def selftest():
    s = bytes(range(16))  # BIP 32 test vector 1
    k, c = master(s)
    assert ser33(mul(k)).hex() == "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    k, c = child(k, c, 0 | HARD)
    assert ser33(mul(k)).hex() == "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
    xp, xq, _ = bip86(bip39_seed(ABOUT), "mainnet", 0, 0)  # BIP 86, first receive address
    assert xp.hex() == "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    assert xq.hex() == "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    assert hashlib.sha256(b"gazpacho keys").digest()[:4].hex() == "8f288c61"
    assert int.from_bytes(hashlib.sha256(b"gazpacho keys").digest()[:4], "big") & 0x7FFFFFFF == PURPOSE


if __name__ == "__main__":
    selftest()
    print("keys_ref: self-test passed")
