# Review: wallet transactions library (`wallet-tx-lib`)

Reviewer: independent agent that did not write the code. Date 2026-11-12.
Scope: branch `wallet-tx-lib` of gazpacho-wallet/gazpacho, commits 024b209 (spec) and f3a5c79 (code) on e6fac8e, library `gazpacho_wallet_tx` in `wallet/tx/`, spec `docs/notes/wallet-tx.md`. The stacked branch `wallet-tx` (1ec2dad tool, 8ed8ce4 mutation script) was read only for how the tool uses the library and for the builder's mutation results. The library sources are byte-identical on both branches (`git diff f3a5c79 8ed8ce4 -- wallet/tx/src wallet/tx/include` is empty).

Work done on the build server in `/root/gz/review-wallet-tx/` only (a copy of the builder's tree at 8ed8ce4; release and AddressSanitizer+UBSan builds configured there, secp256k1-zkp source reused read-only from `/root/gz/build-rel/_deps`). Nothing pushed, committed or posted; no coins, no network calls beyond ssh.

## Verdict

**Merge after fixes.** The cryptographic core is right: the BIP 341 signature message, the BIP 86 tweak, signing and verify-after-sign pass the official vectors and an independent re-implementation over 317,284 (input, hash type) cases with no mismatch; the strict parser agrees with an independent model on 800,000 generated inputs and survived 22 million fuzz inputs on a new seed; sizes and fees are exact for every destination length. What must change before merge is the release gate (it trusts a caller-writable copy of the txid and does not re-check the transaction it serialises), two parser rules that no test pins (two of the builder's "equivalent" mutants are not equivalent), and a funding destination rule that is wider than a factory funding should accept. The rest are small claim corrections.

## Findings, ranked

Line numbers are of the files on `wallet-tx-lib` (f3a5c79). "Probe" means a program of mine (`/root/gz/review-wallet-tx/tools/rv/`, copies in the reviewer's scratch area) linked against the built library; its printed result is quoted.

### Medium

**M1. The release gate checks the txid against a caller-writable copy and never against the transaction it hands out.** `funding.c:343-353`: `gzt_funding_release` compares `expect_txid` with `f->info.txid`, a public member that the caller reads (the tool passes `f.info.txid` straight back, `tools/gz-wallet-tx/main.c:332,445`) and can overwrite. It then serialises `f->priv_tx` with `f->priv_sigs` without recomputing the txid or checking caps.
- Probe: write `0x42…42` into `info.txid` of a built funding, then release with that value. Result: `rc=0 released=1 real-txid-differs-from-expect=1`. The bytes come out, and their txid is not the one the caller asked for.
- Probe: change `priv_tx.out[0].value` and `n_out` after the build. Result: `rc=0 txid-differs-from-expect=1`. A transaction with invalid signatures, and another txid, is released.
- `funding.c:346` loops `i < signed_tx.n_in` and writes `signed_tx.in[i]` before any cap check. A held funding with `n_in` above 64 (a corrupted or restored struct) writes past the local `gzt_tx`. Probe RV_NIN (n_in set to 200, ASan build): the program exited 1, but no ASan report matched my filter, and I could not open its full output (`/root/gz/review-wallet-tx/san-probe2.out`) before server access was stopped. So this one is shown by reading the code, not yet by a run.
- Why it matters: the whole point of the gate (note 1.8, 2) is that what is broadcast is exactly the txid the signed tree spends. Today that holds only while nothing touches the struct, and the note itself says C cannot stop that (section 7).
- Fix: in release, run the cap check on `priv_tx`, recompute its txid, and require it to equal both `expect_txid` and `info.txid` before serialising. Wipe `out` on every failure (see L3). Better still, consider signing at release time instead of at build time: the build can still sign, verify and discard to prove signability and fix the size. Then holding or copying a `gzt_funding` yields nothing, and "no signed bytes before release" becomes literally true instead of a convention. The txid does not change: the selection is deterministic and the witness is not part of the txid.

**M2. Two parser rules are not pinned by any test: the builder's survivors tx.c:266 and tx.c:259 are not equivalent mutants.** The note (section 9) files both under "the input has ended anyway". Both claims are wrong:
- `tx.c:266` `if (!get_cs(r, &n)) return GZT_ERR_PARSE;` changed to `return GZT_OK`. `get_cs` also fails on a *non-minimal* compact size that was fully read, and the input has not ended then. The mutant accepts a scriptSig length written `fd 00 00` (input A) and an empty witness item written `fd 00 00` (input A2). Neither serialises back to the same bytes. The real parser gives rc=3 for both; the mutant gives rc=0 for both (`rv_noncanon.c`).
- `tx.c:259` `if (!get_le(r, n, v)) return 0;` changed to `return 1`. A truncated 8-byte compact size leaves the caller's previous count in place. Input B has three inputs, the last witness count is `ff`, and only the four lock-time bytes follow. The mutant accepts it with the stale count 0; the real parser gives rc=3. Non-canonical, and not round-trip identical.
- The current parser is right on all three (and on everything else I tried, see section 4). This is a test gap, not a bug. But these are exactly the canonical-encoding rules on which the "parses implies identical bytes" property rests.
- Fix: add A, A2 and B (and the same forms with `fe`/`ff` prefixes) to `test_boundaries`. My own copies of these two mutants survive the repo's tests again (section 5).

**M3. A factory funding may pay any witness program.** `gzt_funding_build` uses the general destination rule (`gzt_select_coins`, `funding.c:167`): v0 with 20 or 32 bytes, or v1..v16 with 2 to 40 bytes. A factory output is always P2TR (OP_1, 32 bytes). Everything else accepted here is wrong for a factory, and two cases are dangerous:
- v2..v16, and v1 with a length other than 32 or the 2-byte anchor, are anyone-can-spend today. A mistyped or hostile `--to-address` / `--to-script` in the tool (`main.c:192-205`) sends the funding where anyone can take it.
- A 2-byte program (`51 02 xxxx`) with one input and no change gives a 64-byte non-witness transaction. Arithmetic: 4 + 1 + 41 + 1 + (8 + 1 + 4) + 4 = 64, below Bitcoin Core's `MIN_STANDARD_TX_NONWITNESS_SIZE` of 65. The library builds and signs a transaction that no default node relays.
- Fix: `gzt_funding_build` requires exactly `OP_1 0x20 <32 bytes>`. Keep the general rule in `gzt_select_coins` for later payments, and refuse there too any shape whose minimum transaction is under 65 non-witness bytes.

### Low

**L1. The real fee rate can exceed the ceiling, against what the note and header say.** Note 1.5 says "a finished transaction whose real fee rate ... is above the ceiling is refused". 1.7.5 says "Accept it only if fee x 1000 <= ceiling x vsize", then redefines that as `fee <= fee_for_vsize(ceiling, vsize)`, which rounds up.
- Probe: rate = ceiling = 100 sat/kvB, one coin of amount + 12. Result: `rc=0 fee=12 vsize=111 real-rate=108.1 sat/kvB ceiling=100`.
- The excess is below 1 sat in total, so the money involved is trivial. But it is a claim the code does not keep (checklist item 4), and the two sentences of 1.7.5 contradict each other.
- Fix the wording ("at most the fee the ceiling rate gives for that size, rounded up"), or compare `fee * 1000 <= ceiling * vsize`. The latter would make rate = ceiling unusable in the no-change case, so the wording fix is the better one.

**L2. Network types: distinct in name, interchangeable in C.** Checklist 22 asks for arguments that cannot be confused. `gzt_network`, `gzw_network` and `gz_network` are three C enums whose values overlap:
- gzt signet 1 = gzw testnet3 1;
- gzw signet 3 = gzt testnet4 3 = gz signet 3;
- regtest 4 in both gzt and gzw.

Probe `rv_enum.c`: GCC 15 with the project's `-Wall -Wextra` warns (`-Wenum-conversion`) on all four confusions I wrote (constant, initialiser, assignment, argument), and `-Werror` makes them fatal. So inside this build the protection is real. It does not cover `(gzt_network)` casts, plain integers (a stored or parsed value), or compilers or flags that do not enable `-Wenum-conversion`. Clang was not available to check.

Mainnet stays unreachable: gzt has no value 0, and `gzt_network_to_keys` maps only the four listed values (`tx.c:112-121`). A gzt/gzw mix-up between the test networks derives the same keys (coin type 1), so the practical harm today is small.

Fix: wrap `gzt_network` in a one-member struct, as was done for `gzt_feerate`, so a confusion is an error everywhere. Decision 11 is confirmed in intent.

**L3. On `GZT_ERR_BUFFER` the caller's buffer holds almost the whole signed transaction.** `gzt_put` drops only the write that overflows, so earlier writes stay.
- Probe: release with `cap = len - 1`. Result: `rc=12 len_out=0 signature-in-buffer=1 prefix-equal=1`: every byte except the lock time is there.
- This happens only after the txid check has passed, so it is not a way around the gate. It is still signed bytes leaving through an error path.
- Fix: serialise into the local copy's buffer first, or wipe `out[0..cap)` on failure.

**L4. Signed bytes left in dead stack after `gzt_funding_build`.** `funding.c:312` serialises the signed `work` transaction into the 60 KB stack buffer of `gzt_tx_weight` (`tx.c:264`), which is never wiped. `gzt_sign_keypath`'s `sig[64]` (`sighash.c:116`) is not wiped on success either. Probe (release build): after `gzt_funding_build` returned, a later frame's uninitialised stack was scanned. Result: `sig[0] R found in dead stack=1, s found=1`. Signatures are not secret, so this is not a key leak. But the note's rule "no function except gzt_funding_release produces the signed bytes" is meant to cover memory as well. Fix: wipe those buffers, or compute the signed weight from the formula and the witness count instead of serialising.

**L5. Change-index reuse is detected only among offered coins.** Decision 3 (`funding.c:242-243`) refuses a change index equal to an offered coin's. But the tool offers confirmed coins only (`main.c:432-433` skips unconfirmed outputs). So an unconfirmed coin already sitting at `m/86'/1'/0'/1/N` is not seen, and the same change address is used again (checklist 14). Confirm decision 3 and add one of these:
- the tool passes the indexes of unconfirmed coins too;
- the library takes a separate list of used change indexes;
- the node's journal (section 2) owns the rule and the library comment says so.

**L6. Misleading error when funds exist beyond the 64-coin cap.**
- Probe: 4,096 coins of 330 sat (1.35 M sat) and an amount needing 65 coins. Result: `rc=8` (`GZT_ERR_FUNDS`).
- The wallet has the money; the cap stops it. Return `GZT_ERR_LIMIT` when the total of all coins would pay but the 64 largest cannot. Selection is otherwise correct here: 64 dust coins succeed with fee 400 and no change.

**L7. Small claim and coverage corrections (checklist 4, 12).**
- Note 4 says the size formula is checked "for 1..64 inputs". `test_tx.c` steps 1..8, then by 7 (16 sizes), and only with P2TR destinations. My probe covered every witness-program length (v0 20/32; v1..v16 with 2..40 bytes) with 1 to 3 inputs, 1,878 builds, all exact. So the formula is right, but the claim needs narrowing or the test widening.
- Note 2 says "A rebuild after a crash would give another txid". It does only if the coins or rate changed. With the same coins and request the txid is identical, because selection is deterministic and the witness is not in the txid. Probe: two builds with different aux gave different signatures and the same txid. Worth stating, because it is what makes a restart recoverable.
- Note 9 says "None was judged a missing test after round 3": overruled for tx.c:266 and tx.c:259 (M2).
- `account >= 2^31` returns `GZT_ERR_KEY` (from the key library) rather than `GZT_ERR_ARG` (probe `rc=9`); check it next to `change_index` at `funding.c:241`.

**L8. Portability and resources (informational).**
- `test_tx_faults` links with `-Wl,--wrap`, which is GNU ld only (not Apple ld64).
- `check_no_io.py` parses GNU `nm` output and does not expect Mach-O leading underscores. This is inherited from the key library.
- `sizeof(gzt_tx)` is about 34 KB and `gzt_funding` about 38 KB. `gzt_tx_weight` and `hash_form` each put 60 KB on the stack. `gzt_funding_build` peaks around 110 KB of stack before secp256k1's own use: fine on a mobile main thread, worth knowing for worker threads.
- `gzt_funding_release` takes a non-const `gzt_funding *` though it changes nothing.

## Item by item

### 1. Signing correctness

- **SigMsg** (`sighash.c:52-99`): field order, the ANYONECANPAY / NONE / SINGLE branches, `spend_type` 0, the compact-size prefix on `scriptPubKey` in both `sha_scriptpubkeys` and the ACP branch, and `sha_single_output` all match BIP 341. Valid hash types are exactly 0x00..0x03 and 0x81..0x83 (the test sweeps all 256; I re-checked 0x80, 0x04, 0x84 and 0x41). SINGLE without a matching output is refused.
- **Independent check**: my Python re-implementation of BIP 341 (`rv_model.py`, written from the BIP) against `gzt_sighash_keypath` covered 4,000 random transactions:
  - 1 to 64 inputs, 1 to 16 outputs;
  - random version, lock time, sequences;
  - scripts of 0 to 128 bytes, amounts up to 21 M BTC;
  - 11 hash types per input.

  Result: 317,284 comparisons, 0 mismatches (valid types equal, invalid types refused by both). The official BIP 341 key-path vectors (5 whole-transaction hashes; 7 inputs with tweak, tweaked key, SigMsg, SigHash and signature) also pass.
- **Hash types for funding**: only SIGHASH_DEFAULT should be used, and only it is (`sighash.c:127`). It commits to everything, and it gives the 64-byte signature the size formula assumes; ALL would add a byte per input and break the size self-check. Decision 9 confirmed.
- **Tweak**: done by the key library (`gzw_bip86_tweaked_keypair`, which checks the result against the output key). The BIP 86 vectors pass through `gzt_sign_keypath`.
- **Refusal on key mismatch**: two layers.
  - The builder compares the derived script with `coin.script` (`funding.c:290`).
  - `gzt_sign_keypath` requires `OP_1 0x20` and that the key pair's x-only key equals the 32 bytes (`sighash.c:121-126`).

  Tested by the repo, and by my mutants (key-equals-script removed: caught; coin-script check removed: survives, because the second layer catches it, as the builder said).
- **Verify after sign** (`sighash.c:130`): tested with the signer replaced at link time (bit flip and failure); the funding is wiped on either. My mutant removing it was caught.
- **Aux randomness** (decision 8): sound. BIP 340 derives the nonce as a hash of (key xor hash(aux)), the public key and the message. So a repeated aux, across fundings or after a restore, cannot give the same nonce for two different messages. For the same message it gives the same signature, which leaks nothing.
  - Probe: same aux, same funding: identical signatures. Same aux, another funding: different R. Other aux: other signatures, same txid.
  - Deriving per input with SHA-256(aux || i) is harmless and not needed. Zero aux would also be safe (the vectors use it).
  - The aux value is not a one-time secret in the sense of checklist 17. Nothing needs storing, and a restored backup cannot make a nonce repeat.
  - The builder's aux-rule test pins the exact derivation. The `8 -> 9` survivor at `funding.c:156` is equivalent (for i < 64 only byte 0 is non-zero).

### 2. The release gate

- Through the API: only `gzt_funding_release` serialises the signed form; `gzt_funding_build` returns only `info`. On every build failure the struct is wiped (tested, including the signer faults).
- Leak paths that do exist:
  - the public struct, whose members can be read or copied: probe `struct-copy-releases: rc=0 same-bytes=1`. This is documented in note section 7.
  - L3 (partial output on a small buffer, after the gate).
  - L4 (dead stack).
- No debug output: the library prints nothing. The tool prints signed bytes only with `--release` / `--broadcast`.
- Expected-txid check: not sound as written; see M1.

### 3. Fees and sizes

- `gzt_keypath_vsize` (`tx.c:275-285`) is exact for every shape the library builds. The repo checks 16 input counts; my probe checked 1,878 destination shapes. The build also refuses (`GZT_ERR_INTERNAL`) any mismatch between the signed and estimated size.
- The weight formula 3·base + total and vsize = ceil(weight/4) are Core's. Sigop adjustment does not apply (taproot key path has no sigops).
- 0.1 sat/vB (`GZT_FEERATE_TEST_DEFAULT_SAT_PER_KVB` = 100) is defined and is the tool's default. Note that Bitcoin Core relays 0.1 sat/vB by default only from version 30; an older signet backend will refuse it. That is not a library issue.
- The ceiling is applied to the requested rate (`funding.c:166`) and to the real fee: in the no-change case at line 211, and again as a self-check at line 316. The real rate can exceed the ceiling by rounding (L1).
- Server rates above the ceiling are refused, not clamped (`tx.c:137`, tested). Rate 0 is refused; rates above 10^8 sat/kvB are refused.
- Dust:
  - Core's formula `(8 + 1 + len + 67) * 3` is correct for witness outputs: 294 / 330 / 330, and 240 for P2A.
  - Payments below dust are refused; `amount == dust` is accepted, as in Core.
  - Change below 330 is never made. The remainder goes to the fee only within the ceiling, otherwise another coin is taken, else `GZT_ERR_FEE_CEILING`. Probes: change 330 is made; change 329 with ceiling 1000 is refused; with a second coin a change of 5,323 is made.
- Overflow: coin amounts and their total are bounded by 21 M BTC before any sum, and rate and vsize bounds keep products below 2^47. Probe at the maximum rate with 64 coins totalling exactly 21 M BTC: fee 377,700,000, total balanced, no wrap. The repo test covers the `UINT64_MAX` coin.

### 4. The strict parser

- Malformed forms checked by the repo and by me:
  - every truncation;
  - a trailing byte;
  - non-minimal compact sizes at every width (input count);
  - a marker without flag 01, and flag 02;
  - a superfluous witness;
  - zero inputs and zero outputs;
  - a value above 21 M, a sum above 21 M, and a sum that wraps;
  - each cap and cap + 1;
  - exact-size heap buffers under ASan.
- Differential test: my independent strict parser in Python (from note 1.2) against `gzt_tx_parse` on 800,000 inputs, from two seeds. The inputs were random transactions up to the caps, half segwit, with 0 to 3 edits: bit flips, special bytes 00/01/fd/fe/ff/80/40, inserted `fd xx`, truncation, insertion, deletion. Result: 331,163 accepted, 0 accept/reject mismatches, 0 PARSE/LIMIT mismatches, 0 round-trip failures.
- Fuzz on a new seed (0x9b05688c2b3e6c1f): 20,000,000 inputs in the release build (4,705,432 accepted) and 2,000,000 under ASan+UBSan (470,764 accepted). All properties held: round trip, weight bound, legacy re-parse with the same txid.
- valgrind on `test_tx`, `test_tx_vectors` and 20,000 fuzz inputs: no errors.
- The builder's 13 parser survivors, re-checked against the source:

| Survivor | Builder | Reviewer |
|---|---|---|
| tx.c:110 three clamps of `len > 512` | never reached | agree: every caller passes at most 257 bytes |
| tx.c:252 `return 1` and `0->1` (first byte of a compact size missing) | input ended | agree on outcome (0 bytes remain, so the lock time cannot be read); the mutant reads an uninitialised value |
| tx.c:257 `2->3`, `4->5` (width of fd / fe) | widths under the caps | agree for accept/reject (no fd/fe value can pass any cap); only PARSE versus LIMIT can change |
| tx.c:259 `return 1` and `0->1` (truncated body of a compact size) | input ended | **disagree**: input B is accepted (M2) |
| tx.c:266 `return GZT_OK` (failed compact size in a length field) | input ended | **disagree**: inputs A and A2 are accepted (M2) |
| tx.c:267 `>=` (field exactly to the end) | same result | agree: a lock time always follows |
| tx.c:281 `<=` and `2->3` (marker needs two bytes) | same result | agree |

So 9 of the 13 are equivalent and 4 (two pairs) are real gaps. The other survivors I read are equivalent as described, with one note: the 10 "wipe of a local copy removed" survivors are untested by design. L4 is the same family.

### 5. Coin selection

- Determinism: the ordering is total (duplicates are refused first), and the 64-best insertion (`funding.c:184-192`) is right at the boundary. The repo's 2,000-set model test compares the whole selection struct and is order-independent under shuffling. My probe confirms vout is the last tie-break.
- The model is independent enough: own sort, own size arithmetic. It fixes the destination at P2TR, so other destination lengths are covered only by my probe.
- Adversarial sets:
  - many dust coins (L6);
  - exact match (coin = amount + fee: accepted, no change, fee exact; one sat short: `GZT_ERR_FUNDS`);
  - change at 330 and 329 (see 3);
  - a change index equal to an offered coin's, whether selected or not: refused (`rc=1`);
  - funding to our own change script: refused (tested).

### 6. Network type

No mainnet value and no zero; "mainnet" gives `GZT_ERR_MAINNET`; values 0 and 5 are refused (tested); the converter is a table, and the tool's chain commands insist on `GZT_NET_SIGNET`. Confusion with the other two types: L2.

### 7. Claims and decisions

Claim corrections are listed under L1, L4 and L7, and in M1 (note 1.8 "refuses any other" holds only for an untouched struct).

| # | Decision | Verdict |
|---|---|---|
| 1 | funding at 0, change at 1 | confirm for Slice 1 (reveals change; revisit with privacy work) |
| 2 | sequence 0xfffffffe, lock time 0 | confirm; add anti-fee-sniping before mainnet |
| 3 | caller picks change index; refuse an offered coin's | confirm, plus the coverage gap in L5 |
| 4 | witness-program destinations only | confirm for payments; **overrule for the funding**: P2TR only (M3) |
| 5 | largest-first | confirm (deterministic, few inputs); error code per L6 |
| 6 | ceiling is a rate applied to the real rate | confirm, wording per L1 |
| 7 | server rate above ceiling refused, not clamped | confirm |
| 8 | aux per funding, SHA-256(aux‖i) per input | confirm; sound, and reuse is harmless (section 1) |
| 9 | all hash types in sighash, DEFAULT for signing | confirm |
| 10 | caps sized for own transactions and vectors | confirm |
| 11 | separate network type | confirm intent; make it a struct (L2) |
| 12 | rate 0 refused | confirm |

### 8. Mutation testing (reviewer's own)

**Not finished.** I wrote 75 hand-chosen mutants (`tools/rv/rv_mutate.py`) in the security-relevant lines:
- sighash: hash-type checks, spend_type, epoch, tag, committed index, amounts, scripts, ACP fields, key-equals-script, verify-after-sign, DEFAULT versus ALL;
- selection: ordering, rate 0, rate above ceiling, dust, 21 M total, duplicates, change dust, ceiling, fee with or without change, the 64 cut;
- build and release: change-index collision, depth, hardened index, own-change destination, version, sequence, lock time, aux derivation, coin-script check, size and fee self-checks, txid check, state, wipe, signature index, amount, network;
- tx.c: mainnet name, network table, fee rounding, server rate, witness-program rules, dust constant, value and sum limits, minimal compact size, superfluous witness, flag, trailing bytes, zero inputs, field and witness caps, weight, size estimate, segwit form;
- the writer overflow;
- the builder's survivors tx.c:266 and tx.c:259.

The run started detached on the server against the release build. Server access then ended (firewall pause, then permission refusals) before I could read `/root/gz/review-wallet-tx/mut-rel.log`. Survivor counts are therefore not reported here.

What is established without that log:
- the builder's survivors tx.c:266 and tx.c:259 are not equivalent (`rv_noncanon.c`: their mutated parsers accept non-canonical inputs that the real parser refuses);
- 9 of the builder's 13 parser survivors are equivalent (section 4).

Reading the log is the first thing to finish.

### 9. Build hygiene, no-I/O, size

- The release (GCC 15.2, `-Wall -Wextra -Werror`) and ASan+UBSan builds are clean for the project's code. The 3 warnings are in imported secp256k1-zkp (`-Wunterminated-string-initialization`), which may not be edited here.
- All 17 wallet ctest tests pass in both builds, as configured by me.
- The no-I/O check is an allow-list (the key library's script plus 6 named additions). It passes and needs no imported archive, since the tx library pulls none in directly. It has no negative test of its own for the tx library; the key library's negative tests exercise the same script.
- No writable globals.
- Size: about 2,550 lines, of which about 750 source, 300 header, 1,250 tests and 200 vectors and notes. It can be reviewed in one sitting, and the tool is split out. Acceptable under checklist 24.
- Checklist 1 is still not met: the spec says so itself. This review covers the spec too.

## What I did not test

- The result of my 75-mutant run, and of the ASan run of the n_in = 200 probe: both ran or are running on the server, but I could not read their logs (sections 8 and M1).

- Clang and MSVC behaviour for the enum confusion.
- macOS, iOS and Android builds.
- Stack wiping by memory scan beyond probe L4.
- A broadcast to a real signet node (no coins sent, by rule): Core's acceptance of the 64-byte case and of 0.1 sat/vB is from Core's documented policy, not a relay test.
- libFuzzer (not installed).
- The tool's chain commands (the chain port is not on this branch).
- Mutation of the tool itself.
- Restore-from-backup flows (no journal exists yet).
- The builder's full 976-mutant run was not repeated; I re-read its survivor list and ran my own set.
