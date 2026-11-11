#!/usr/bin/env python3
"""Derive a BIP 86 address from a phrase file with implementations that share
no code with gazpacho_wallet_keys, for comparison with gz-wallet-keys.

usage: crosscheck.py PHRASE_FILE NETWORK [INDEX]     (NETWORK: signet, testnet, regtest)

Needs the Python packages embit and buidl (not installed system-wide; use a
virtual environment).  The phrase is read from the file inside this process
and is never printed.  Output: one line per implementation with the address,
scriptPubKey and account extended public key for m/86'/1'/0'/0/INDEX.
"""
import sys
from importlib.metadata import version

path, network = sys.argv[1], sys.argv[2]
index = int(sys.argv[3]) if len(sys.argv) > 3 else 0
if network not in ("signet", "testnet", "regtest"):
    sys.exit("network must be signet, testnet or regtest")
with open(path) as f:
    phrase = " ".join(f.read().split())

# --- embit ------------------------------------------------------------------
from embit import bip32, bip39, script
from embit.networks import NETWORKS

net = NETWORKS["test" if network == "testnet" else network]
root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(phrase))
account = root.derive("m/86h/1h/0h")
spk = script.p2tr(account.derive([0, index]))
print("embit %s: %s %s %s" % (version("embit"), spk.address(net), spk.data.hex(),
                              account.to_public().to_base58(net["xpub"])))

# --- buidl ------------------------------------------------------------------
from buidl.hd import HDPrivateKey

hd = HDPrivateKey.from_mnemonic(phrase, network=network)
leaf = hd.traverse("m/86'/1'/0'/0/%d" % index)
acct = hd.traverse("m/86'/1'/0'")
print("buidl %s: %s %s %s" % (version("buidl"), leaf.pub.point.p2tr_address(network=network),
                              leaf.pub.point.p2tr_script().raw_serialize().hex(),
                              acct.xpub()))
