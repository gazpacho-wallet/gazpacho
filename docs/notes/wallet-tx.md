# Wallet transactions: specification, tests and notes

Written 2026-11-11 for the first cut of `gazpacho_wallet_tx` (`wallet/tx/`) and the `gz-wallet-tx` tool. Purpose: Slice 1 needs the host to fund one factory output from its signet wallet, release that funding only after the whole tree is signed, and see it confirm. The interface is documented in `wallet/tx/include/gazpacho/wallet_tx.h`; this note says what the code must do, how it is tested, and what was decided where nothing was written down.

Status of this specification: written by the builder; reviewed once, with the code, by an independent agent on 2026-11-12 (verdict "merge after fixes"). The fixes are folded into the sections below.

## 1. What the library does

1. **Transactions.** A fixed-size transaction value (`gzt_tx`, no heap) with version, inputs, outputs, witnesses and lock time. Serialised in the segwit form when any input has a witness, otherwise in the legacy form, exactly as Bitcoin Core does. `txid` is the double SHA-256 of the form without witnesses, `wtxid` of the full form. Weight is 4 x (size without witnesses) + (size of marker, flag and witnesses); virtual size is weight / 4 rounded up.
2. **Parsing hostile bytes.** `gzt_tx_parse` accepts a transaction only if it is canonical: every length is a minimal compact size, nothing is left over, at least one input and one output, every output value and their sum at most 21 million bitcoin, a marker byte 00 only with flag 01, and a segwit form only if some input has a witness (Core's "superfluous witness" rule). Anything beyond the library's caps (64 inputs, 16 outputs, scripts of 128 bytes, 4 witness items of 80 bytes per input) is refused as `GZT_ERR_LIMIT`, never misread. Consequence, which the tests and the fuzz target check: anything that parses serialises back to the identical bytes.
3. **Signature hash.** BIP 341 `SigMsg` and `TapSighash` for key-path spends, every hash type (DEFAULT, ALL, NONE, SINGLE, each with ANYONECANPAY), no annex, no script path. The five whole-transaction hashes are exposed so the official intermediate values can be checked.
4. **Signing.** `gzt_sign_keypath` signs one input with SIGHASH_DEFAULT given a tweaked key pair (from `gzw_bip86_tweaked_keypair`) and 32 bytes of auxiliary randomness from the caller. It refuses unless the spent script is `OP_1 <32 bytes>` and the key pair's x-only key equals those 32 bytes, and it verifies the signature against that key before writing the witness (BIP 340's advice against faults).
5. **Fees.** A fee rate is its own type, `gzt_feerate`, in satoshi per 1000 virtual bytes. The project default for test networks is 100 sat/kvB (0.1 sat/vB). Fee = ceil(vsize x rate / 1000). Every builder takes a rate and a ceiling from the caller; a rate above the ceiling is refused, and so is a finished transaction whose fee (after small change is given up to it) is above the fee the ceiling rate gives for its size, rounded up to a whole satoshi. So the real rate can be above the ceiling by less than 1 sat in total (for example 12 sat for 111 vB at a ceiling of 100 sat/kvB, which is 108 sat/kvB); never by more. A rate from a chain server enters only through `gzt_feerate_from_server(server_rate, ceiling)`, which refuses rather than clamps. Rates above 10^8 sat/kvB and a rate of 0 are refused.
6. **Dust.** Destinations must be witness programs (`OP_0` with 20 or 32 bytes, `OP_1`..`OP_16` with 2 to 40 bytes); legacy scripts and `OP_RETURN` are refused, and so is a 2-byte program (a one-input transaction paying it without change would be 64 bytes without witness, below the 65-byte relay minimum). The factory funding is stricter still: P2TR only (1.8). Dust limit as Bitcoin Core computes it at 3 sat/vB for a witness output: (8 + 1 + script length + 67) x 3, which is 294 for P2WPKH and 330 for P2WSH and P2TR. A payment below it is refused; change below it is never made.
7. **Coin selection** ("pay exactly A to script S, change to C"):
   1. Coins are ordered by amount descending, then txid bytes ascending, then output index ascending, so the result depends on the set of coins and not on the order given.
   2. For k = 1, 2, ... (at most 64) take the first k coins with total T.
   3. If T < A + fee(no change), go on to k + 1.
   4. If T - A - fee(with change) >= 330, make change of that amount. Done.
   5. Otherwise make no change; the fee is T - A. Accept it only if it is at most the fee the ceiling rate gives for that size, rounded up (fee <= fee_for_vsize(ceiling, vsize)); otherwise go on to k + 1 (another coin usually makes the change large enough).
   6. If no k works: `GZT_ERR_FEE_CEILING` if some k covered the amount but overpaid; else `GZT_ERR_LIMIT` if more than 64 coins were offered and all of them together are at least A + fee(no change, 64 inputs) (the coins exist, the input cap stops it); else `GZT_ERR_FUNDS`.
   Duplicate outpoints, amounts above 21 million bitcoin and a total above it are refused.
8. **The funding builder.** `gzt_funding_build` refuses a funding script that is not P2TR (`OP_1 0x20 <32 bytes>`), selects coins, builds the transaction (version 2, lock time 0, sequence 0xfffffffe, the funding output at index 0, change at index 1), derives each coin's key from the master key and refuses a coin whose script is not the script of the key at its stated path, signs every input on a copy, verifies, checks the signed size equals the size the fee was computed for, and then **throws the signatures away**. The `gzt_funding` value holds the unsigned transaction and the key paths only, so holding or copying it gives nothing that can be broadcast. It hands out the funding outpoint, fee, size and change, which the tree needs before it is signed. `gzt_funding_release(ctx, master, f, expect_txid, aux, ...)` signs, and only after checking that the held transaction is within the caps and has no witness, that the txid recomputed from it equals both `expect_txid` and `f->info.txid`, and that its amounts agree with `info` (funding amount, number of outputs, inputs = outputs + fee). The txid does not depend on the signatures, so a release with other randomness gives the same txid. On any failure the caller's buffer is zeroed. Release may be repeated (to broadcast again after a restart). The gate protects against corruption and mistakes in the held value; it does not stop the holder of the master key, who can sign anything.
9. **Networks.** `gzt_network` is a one-member struct, so mixing it with `gzw_network`, `gz_network` or a plain number does not compile. It has no mainnet value and no zero value: `GZT_NET_SIGNET` is id 1. A zeroed or unknown id is refused everywhere, and the name "mainnet" is refused as `GZT_ERR_MAINNET`.
10. **No I/O.** The library calls no files, network, clock, randomness or printing and has no writable global data; the allow-list check of the key library is applied to it.

## 2. What is stored, in what order, and crashes

The library stores nothing. The caller (the node layer, later) must:

- record the change index it gave to `gzt_funding_build` before broadcasting, and never give it again, even if the funding is abandoned (checklist item 14). The library refuses an index held by an offered coin or listed in `used_change_indexes`; the record of every index ever given belongs to the node's journal;
- journal the released bytes before the first broadcast, so that after a crash the same transaction (same txid, which the tree spends) is broadcast again. A rebuild with the same coins, amount, rate and change index gives the same txid (selection is deterministic and the witness is not in the txid), so a restart before broadcast can rebuild; a rebuild after any of those changed gives another txid and orphans the signed tree.

The tool `gz-wallet-tx` is a thin first cut that keeps no journal: it takes the change index on the command line and prints the signed transaction it broadcasts.

## 3. Fee bumping and why not replacement

The funding is not replaced to raise its fee: a replacement changes the txid, and the tree spends the txid. A stuck funding is pushed by spending its change output with a higher fee (child pays for parent). The sequence is 0xfffffffe, which does not signal replacement (full replacement is the default in current relays anyway, so this is a statement of intent, not a protection). Every input is a taproot key-path spend, so the txid cannot be changed by a third party.

## 4. Tests listed before the code

| Test | Checks |
|---|---|
| BIP 341 key-path vectors | the unsigned and fully signed transactions parse and serialise back byte for byte; the five whole-transaction hashes; for the 7 inputs: tweak, tweaked private key, `SigMsg`, `SigHash`, and the signature (made with zero auxiliary randomness, compared byte for byte) |
| BIP 86 vectors | for the three published leaf keys: the tweaked key equals the published output key and script, and a key-path signature made by `gzt_sign_keypath` verifies against the key decoded from the published script |
| Round trip and malformed input | every truncation of valid transactions fails; non-minimal compact sizes, marker without flag 01, superfluous witness, trailing byte, zero inputs, zero outputs, value above 21 million, sum above 21 million, each cap plus one |
| Fuzz target | `LLVMFuzzerTestOneInput`: never crash or read out of bounds; whatever parses re-serialises identically; txid of the parsed form equals the hash of the legacy form. Run by a built-in driver (no libFuzzer on the build server) for a fixed number of mutated inputs, under the memory-error checkers in the sanitizer build |
| Fee and size | the size formula and the counted weight equal the weight of real serialisations for every input count 1..64 with P2TR and P2WPKH outputs, and for destination lengths 4, 5, 10, 20, 22, 33, 34, 35, 41, 42 with 1, 2, 63 and 64 inputs; every funding of 1..64 inputs is built, released and measured; fee rounding; the fee of the built funding is within the ceiling as defined in 1.5; 100 sat/kvB default. The fuzz target checks the counted weight against the serialisations of every accepted input |
| Selection, randomised | 2,000 random coin sets compared with an independent model written from section 1.7 (order and content of the chosen coins, change, fee), and the result unchanged under shuffling of the input order |
| Refusals | mainnet name, zero network, rate 0, rate above ceiling, server rate above ceiling, dust payment, legacy destination, `OP_RETURN`, a 2-byte program, every funding script but P2TR, duplicate coins, coin whose script is not its key, change index equal to an offered coin's or a listed used one, account or change index of 2^31, release with a wrong txid, release before build, signing for a key that is not the spent script's |
| Release gate (review M1) | no signature anywhere in the held value; a forged `info.txid`, asked for; the stored transaction edited, with and without `info.txid` made to match; spent amounts, scripts and key paths edited; counts beyond the caps (200 inputs) and a held witness; another wallet's key; a buffer one byte short leaves it zeroed; release again gives new signatures and the same txid; a failing or damaged signer at release gives nothing |
| Canonical lengths (review M2) | zero lengths written `fd 0000`, `fe 00000000`, `ff 00..00` for a scriptSig and for a witness item, where more input follows; a witness count `fd`, `fe` or `ff` cut short by the end of the input |
| No I/O | the allow-list check on the library objects |
| Tool | usage, refuses mainnet, `decode`, offline `plan` with the published BIP 86 phrase (public, not a secret) and made-up coins, `--release` output decodes to the planned txid |
| Mutation | every operator and constant in `wallet/tx/src` changed in turn (script `wallet/tx/tests/mutate.py`); survivors reported, and named "rule removed" runs for each safety rule |

## 5. Decisions taken where nothing was written (to confirm or overrule)

1. Funding output at index 0, change at index 1, always. Simple for the tree; reveals which output is change.
2. Sequence 0xfffffffe, lock time 0 (no anti-fee-sniping lock time in this cut).
3. Change index chosen by the caller, not by the library; the tool takes `--change-index`. The library refuses a change index equal to the change index of any coin offered to it (offered, not only selected) or listed in `used_change_indexes`; the tool lists the change indexes of unconfirmed coins there. Confirmed by the review, with that addition.
4. Destinations: witness programs of at least 3 bytes for payments; no legacy addresses. **The factory funding: P2TR only** (the review overruled the wider rule for the funding).
5. Largest-first selection (simple, deterministic; spends few inputs; not privacy-minded). No branch-and-bound.
6. The fee ceiling is a rate, and applies to the finished transaction's real rate, not only to the requested rate.
7. A server fee rate above the ceiling is refused, not clamped to the ceiling.
8. Auxiliary randomness: the caller gives 32 bytes per build and per release; input i is signed with SHA-256(aux || i as 4 bytes little-endian). The signatures are made at release (the review's preferred fix for M1); the build signs only to check, and discards.
9. All hash types are implemented in the signature hash (for the official vectors); signing uses SIGHASH_DEFAULT only. No annex.
10. Parser caps sized for the wallet's own transactions and the official vectors, not for every valid transaction.
11. Network type separate from `gzw_network` and `gz_network` (both have mainnet as 0), as a one-member struct (the review's request); converters at the edges.
12. A rate of 0 is refused, although 0 is a valid fee for some test relays.

## 6. Chain-port calls used by the tool

Coded against `ports/chain/include/gazpacho/chain.h` on `chain-esplora` (not merged into this branch; the tool's chain commands are compiled only when the `gazpacho_chain_curl` target exists in the build, through a generator expression, so the order of `add_subdirectory` lines does not matter).

- Lookups: `gz_chain_script_outputs` (coins of each scanned script; only confirmed ones are used), `gz_chain_fee_estimates` (only with `--feerate server`, then through `gzt_feerate_from_server` and the ceiling), `gz_chain_broadcast`, `gz_chain_confirm_tx` (status, header, proof of work and Merkle proof), `gz_chain_result_name`.
- Set-up: `gz_http_curl_create`, `gz_http_curl_destroy`, `gz_esplora_config_default`, `gz_esplora_create` (mempool.space and blockstream.info signet), `gz_multi_config_default`, `gz_multi_create` (quorum 2), `gz_chain_destroy`.
- Types: `gz_chain_output`, `gz_fee_estimates`, `gz_broadcast_result`, `gz_confirmation`, `GZ_NET_SIGNET`.

The library itself calls none of them: it takes coins and returns bytes.

## 7. Limits known now

- The held funding contains no signature. The signed bytes exist only inside `gzt_funding_release` (its local copies are wiped) and in the caller's buffer. `gzt_tx_weight` counts instead of serialising, and the wtxid buffer and the signer's signature copy are wiped, so `gzt_funding_build` leaves no signature on the stack either; this is shown by reading the code, not by a stack scan.
- The txid does not cover the spent amounts and scripts held in the funding. An edit of those is caught when it breaks the amount check or the key check; otherwise it gives signatures the network refuses. It never gives another txid.
- Secrets: key pairs are wiped after each input; the master key stays the caller's, and is needed again at release.
- Stack: `gzt_tx` is about 34 KB and `gzt_funding` about 46 KB; `gzt_funding_release` and `hash_form` each hold a 60 KB buffer, and release a `gzt_tx` copy. Fine on a main thread; size worker-thread stacks for about 200 KB.
- Test tooling is GNU-only: `test_tx_faults` uses `ld --wrap` (not Apple ld64), and `check_no_io.py` reads GNU `nm` output (no Mach-O leading underscores), as in the key library.
- Unconfirmed coins: the library takes whatever coins it is given; the tool passes confirmed coins only.

## 8. Not done in this cut

A second review after the fixes; a journal; anti-fee-sniping; child-pays-for-parent; script-path spends; scanning with a gap limit beyond a fixed range in the tool.

## 9. Mutation results (2026-11-12)

`wallet/tx/tests/mutate.py` changes one thing at a time in `wallet/tx/src` (comparisons, logical and arithmetic operators, integer constants, returned error codes, negations, one-line statements removed), rebuilds the four test programs and the tool against the mutant and runs them with the tool test. The tool itself was not mutated.

| Round | Build | Mutants | Caught | Survived | Did not compile |
|---|---|---|---|---|---|
| 1 | plain | 983 | 734 | 246 | 3 |
| 2, after tests for NULL arguments, boundaries, the 64-coin cut-off | AddressSanitizer and UBSan | 976 | 868 | 105 | 3 |
| 3, the 105 again after tests for caps on output 0 and stale items, exact-size buffers, the auxiliary-randomness rule | AddressSanitizer and UBSan | 105 | 8 | 97 | 0 |

So 976 mutants, 876 caught, 97 surviving. The source changed between rounds in three places the run pointed to: a needless "released" state was removed from the funding, a duplicated script-length check was removed from the funding builder (coin selection already refuses it), and the SIGHASH_SINGLE output writer now checks its own overflow.

**Named rule removals** (checklist item 7), all in round 2: 21 rules; 19 are caught (mainnet name, rate above ceiling, real rate above ceiling, server rate above ceiling, dust payment, dust change, witness-only destination, duplicate coins, signing key equals the spent script, verify after sign, change index not a spent coin's, release needs the txid, release needs a build, wipe on failure, trailing bytes, minimal compact size, superfluous witness, 21 million limit, length within the input). Two survive and are second lines, not tested protections:
- *a coin's script is its key* (funding builder): `gzt_sign_keypath` refuses the same thing one step later, and that refusal is tested;
- *the signed size is the size the fee was paid for*: a self-check that cannot fail while the size formula and the serialiser agree, which the size test checks for 1 to 64 inputs.

**The 95 other survivors**, judged by reading each one:

| Kind | Count | Why no test can see it |
|---|---|---|
| A larger array size in a declaration or a parameter | 28 | no behaviour changes |
| 1 changed to 2 where only truth matters | 8 | same truth value |
| A wipe of a local copy removed | 10 | not visible from outside; the key library's review checked wiping by scanning stack memory, which was not repeated here |
| Failure paths that cannot be reached, and self-checks | 17 | key derivation that fails only in BIP 32's 1-in-2^127 case, writers whose buffers are sized for the caps, the txid of a transaction just built, the signed-size and fee self-checks |
| Parser: the input has ended anyway (8), compact-size widths under the caps (2), a clamp never reached (3) | 13 | a failed read inside a compact size, or a field that reaches the very end, ends in `GZT_ERR_PARSE` at the next read; every value that needs the 0xfd form is above every cap. Some of these mutants read an uninitialised value first, which valgrind would show and these tests do not |
| Order of operations: a comparison inside a branch that already excludes equality, fields zeroed before being set, bytes overwritten later, witness items beyond the count never written | 15 | same result |
| One byte too many compared or copied inside a structure | 4 | the extra byte is the next field (the output index) in every case; `gzw_ct_equal` is in the key library, which the mutation build does not instrument |

None was judged a missing test after round 3. A reviewer should re-check that judgement, especially the 13 parser ones.
