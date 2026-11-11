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

## 5. Finding: tree order can depend on the C library's sort

`factory_init_from_pubkeys` and `factory_init` set `placement_mode = PLACEMENT_TIMEZONE_CLUSTER` (`factory.c:888`, `:830`). `factory_build_tree` then sorts the clients with `cmp_timezone_cluster` (`factory.c:24-35`). `profiles[]` is zero-filled by default, so every comparison returns 0 and the result depends on how `qsort` orders equal elements, which the C standard leaves open. On glibc 2.39 the order comes out as 1..N. On another C library two honest parties could build different trees.

Suggested: default to `PLACEMENT_SEQUENTIAL`, or add a final tie-break on participant index in the comparison.

## 6. Finding: partial signatures are never verified individually

`musig_verify_partial_sig` exists (`musig.c:423`) but has no caller. `factory_session_set_partial_sig` stores each partial signature unchecked, and `factory_session_complete_node` aggregates without checking. Only the final aggregate is verified (`factory_verify_all`). A bad partial signature is therefore detected only as a failed aggregate, with no way to tell who sent it.

(Line numbers in sections 2 to 6 are at `3de6120`. At that commit the direct randomness reads are `musig.c:9-14`, `factory.c:3687-3697` and `bip39.c:262-265`; there are 37 `fprintf(stderr, ...)` calls in `factory.c`; the clock is read in `fee_estimator_static.c:45` and `:59`.)

## 7. Request: raise the size limit

`FACTORY_MAX_SIGNERS` and `FACTORY_MAX_LEAVES` are 256 in `factory.h` (the host plus up to 255 members). The owner's target is 512 members per factory, then 1,024.

## 8. Requests about planned removals

- Remove the older leaf types, not the timed layers above the leaves: Gazpacho's first release ships the full layered tree.
- Before deleting the older leaf types, confirm that pseudo-Spilman leaves under wide upper levels build and sign at the target sizes; the repository's own shape table uses the older types above 16 members.
- Tag the last commit before the removals, so the old channel format and the outside-peer code stay reachable.
- Say when a merge touches any of the 17 imported files, and when one changes the tree's transactions (for example the tree-fees change or paying members at every output on expiry), so Gazpacho's reference values are regenerated.

## For reference

- 16 files build and run standalone with only secp256k1-zkp and libcrypto: factory, musig, dw_state, ladder, tx_builder, tapscript, adaptor, shachain, util, hd_key, bip39, bech32m, crypto_aead, fee, htlc_fee_bump, bolt11.
- A standalone program built from them reproduces the 14 on-chain tree transaction IDs of the real run exactly.
- Gazpacho does not import keyfile, invoice, sweeper or wallet_source_hd; they are tied to the database and channel code.

## Coming later

Gazpacho will propose a shared message format based on Lightning's own wire conventions (BOLT 8 transport, BOLT 1 framing and typed fields, standard taproot channel messages, one custom message type for factory messages). A draft will follow as a separate note.
