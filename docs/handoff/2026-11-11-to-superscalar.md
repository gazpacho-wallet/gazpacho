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

## 9. Findings from a scale check of the tree builder (at `e657395`)

Gazpacho built and signed one-user pseudo-Spilman leaves under wide upper levels at 16 to 1000 users, in one process, in Release and under AddressSanitizer + UBSan. Every valid shape built, signed and verified, including 512 and 1000. The size limits in `factory.h` are now only defaults, so item 7 above is largely answered. Defects found, none fixed here:

1. `src/factory.c:148` (`node_nsequence`): out-of-bounds read at index -1 of `dw_counter_t.layers[8]` when a leaf that is not pseudo-Spilman sits inside the fixed (static) levels (`factory.c:1652`, `:1669`). In Release it appears to work and reports a 0-block delay.
2. `src/dw_state.c:46` (`dw_counter_init`), reached from `factory.c:826` and `:884`: out-of-bounds write. `factory_init` sets the layer count to depth + 1 without the cap of 8. From 257 users the count is 9; from 513 it is 10. The next `factory_set_arity` call re-initialises correctly, so calling it straight after init avoids the problem.
3. `factory_early_warning_time` (`factory.c:4900`) and `factory_compute_ewt_for_shape` (`:4945`) under-report the exit delay by 432 blocks for each timed level beyond 8: they return 3,024 where the transactions sum to 3,456 (255 users, two-way), 3,888 (512) and 4,320 (1000).
4. `factory_append_tree_anchor` (`factory.c:501`) silently drops the anchor on a node with 16 outputs while still deducting its 240 sats.
5. `subtree_is_leaf` (`factory.c:949-956`) silently changes the leaf type when a wide level meets a subtree with no more users than the width.
6. Read, not run: `apply_l_stock_hashlock` (`factory.c:393`) ignores a host-supplied leaf hash for node indexes of 512 or more.

Other limits that remain: `FACTORY_MAX_OUTPUTS` 16 (a level is at most 16 wide, 15 with its anchor), `FACTORY_MAX_LEVELS` 8 (longer width lists are silently truncated), `DW_MAX_LAYERS` 8, `MUSIG_NONCE_POOL_MAX` 256. Detail and the full table: `docs/notes/tree-scale-check.md` in the Gazpacho repository (pull request 5).

## For reference

- 16 files build and run standalone with only secp256k1-zkp and libcrypto: factory, musig, dw_state, ladder, tx_builder, tapscript, adaptor, shachain, util, hd_key, bip39, bech32m, crypto_aead, fee, htlc_fee_bump, bolt11.
- A standalone program built from them reproduces the 14 on-chain tree transaction IDs of the real run exactly.
- Gazpacho does not import keyfile, invoice, sweeper or wallet_source_hd; they are tied to the database and channel code.

## Coming later

Gazpacho will propose a shared message format based on Lightning's own wire conventions (BOLT 8 transport, BOLT 1 framing and typed fields, standard taproot channel messages, one custom message type for factory messages). A draft will follow as a separate note.
