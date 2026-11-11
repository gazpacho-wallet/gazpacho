# Hand-off to the SuperScalar repo session

From the Gazpacho session, 2026-11-11. Gazpacho imports SuperScalar's low-level files unchanged and builds a wallet on top. A trial run and an import study produced one bug report and three requests.

Tested at `2cebbdf` plus the start-up crash fix (`b812be3`, `292fbe1`), Release build, regtest, 4 clients, default pseudo-Spilman leaves, `--amount 1000000`.

## 1. Bug: a client cannot complete a unilateral exit

Steps: create the factory, make payments, kill the LSP, run the client with `--force-close` repeatedly while mining blocks.

Result: all 14 tree transactions confirm, then the client's commitment transaction is rejected on every attempt:

```
min relay fee not met, 154 < 167
```

The fee appears to be computed for a 154-vbyte transaction while the transaction is 167 vbytes. `--test-full-settlement` fails the same way on all four channels, including with `--fee-rate 2000`. So a client never reaches a spendable output without the LSP.

Also seen: the default `--amount 100000` cannot run a payment, because the per-side balance (5788 sats) is barely above the 5000-sat reserve.

## 2. Request: let the caller supply randomness

These files read the operating system's random source directly:

- `musig.c:9` (every signing nonce)
- `factory.c:3687`
- `bip39.c:171`
- `keyfile.c:60`, `keyfile.c:167`
- `wallet_source_hd.c:244`
- `invoice.c:27`

Gazpacho's core is handed all randomness by the program around it, so that a whole factory can be simulated repeatably from a seed. A callback or context parameter, defaulting to today's behaviour, would let us use these files unchanged.

## 3. Request: no direct output or environment access in the tree builder

- About 45 `fprintf(stderr, ...)` calls in `factory.c`.
- A `getenv` debug hook at `factory.c:2122`.
- A test-only global at `factory.c:2290`.

A log callback, and moving the test hooks behind a build flag, would do.

## 4. Request: a defined rule for participant order

Tree transaction IDs depend on each participant's slot, and slot order today is the order in which clients connect. Two parties can only build the same tree if they are told the order. Either a canonical rule (for example, sorted by public key) or an explicit order carried in the proposal and checked by every client would remove the dependence on connection timing.

## For reference

- 16 files build and run standalone with only secp256k1-zkp and libcrypto: factory, musig, dw_state, ladder, tx_builder, tapscript, adaptor, shachain, util, hd_key, bip39, bech32m, crypto_aead, fee, htlc_fee_bump, bolt11.
- A standalone program built from them reproduces the 14 on-chain tree transaction IDs of the real run exactly.
- Gazpacho does not import keyfile, invoice, sweeper or wallet_source_hd; they are tied to the database and channel code.

## Coming later

Gazpacho will propose a shared message format based on Lightning's own wire conventions (BOLT 8 transport, BOLT 1 framing and typed fields, standard taproot channel messages, one custom message type for factory messages). A draft will follow as a separate note.
