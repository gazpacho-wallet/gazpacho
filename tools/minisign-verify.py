#!/usr/bin/env python3
"""Verify a minisign signature (prehashed "ED" or legacy "Ed") with the Python cryptography package.
usage: python3 -I tools/minisign-verify.py PUBKEY_B64 FILE FILE.minisig
Used by tools/verify-libsodium.sh where the minisign program is not installed."""
import base64, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pk_b = base64.b64decode(sys.argv[1])
assert pk_b[:2] == b"Ed" and len(pk_b) == 42
keyid, pk = pk_b[2:10], Ed25519PublicKey.from_public_bytes(pk_b[10:])
lines = open(sys.argv[3], "rb").read().decode().splitlines()
sig = base64.b64decode(lines[1]); tc = lines[2]; gsig = base64.b64decode(lines[3])
alg, sid, s = sig[:2], sig[2:10], sig[10:]
assert sid == keyid, "key id differs"
data = open(sys.argv[2], "rb").read()
msg = hashlib.blake2b(data, digest_size=64).digest() if alg == b"ED" else data
pk.verify(s, msg)
assert tc.startswith("trusted comment: ")
pk.verify(gsig, s + tc[len("trusted comment: "):].encode())
print("minisign OK:", alg.decode(), "key id", keyid[::-1].hex().upper(), "|", tc)
print("sha256", hashlib.sha256(data).hexdigest(), sys.argv[2])
