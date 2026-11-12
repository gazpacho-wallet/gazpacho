# Review: `spec/storage-encryption.md`, drafts 1 and 2, and vectors section E

## Round 2: confirmation of draft 2 (commit `e7bcfaa`)

Read from `specs-slice1` at `e7bcfaa`: `spec/storage-encryption.md` draft 2, `spec/exit.md` draft 1 (5.6, 5.7, 7.1, W1 to W5, 10.4), `spec/local-api.md` draft 3 §4.7, and `tools/spec-vectors.py` sections E and X.

### Verdict, round 2

**Ready to build from**, once the Medium items R2-1 to R2-5 below are folded in. None of them needs a new mechanism. Draft 2 removes the High problems of round 1. The central design move, invariant T (no commitment of the member's own ever enters a bundle), is the right fix and holds for 1.0.0 as specified. What is left:
- the edges of the new pieces: the penalty file has no freshness anchor, deleting the journal and the guard together goes undetected, T is phrased too narrowly for later engines, and the penalty file has no position field for the start rule;
- `spec/local-api.md` draft 3 §4.7 and `spec/exit.md` still describe the draft-1 watcher in several places.

### F1 to F25: status

| # | Status | Evidence |
|---|---|---|
| F1 | **Fixed** (for 1.0.0) | 8.7.2 invariant T and its "never in" list; `exit.md` W2 and X-I4; `watch.key` removed (3.1, 8.7.3, test 22); test 21 hands every old version plus KB to a simulated thief. The scope limit is R2-3 |
| F2 | **Fixed** | 8.7.1 states the watcher cannot finish an exit; `exit.md` 5.6 defines `unlock_by`. `exit.md` 7.1 confirms that early publication moves no deadline earlier, because H_leaf is absolute |
| F3 | **Partly** | 6.2's anchored families now include `round_signed`, own commitment, released revocation and received host revocation; 6.3 step 3 adds B1 and the penalty file; a newer bundle or penalty file is kept as `.newer`. Gaps: the penalty file carries no journal position (R2-4), and the "safe to lose" argument covers member records only (R2-7) |
| F4 | **Fixed** | Moot under T; `made_after_restore_marker`; `exit.md` 5.7 makes publishing a restored commitment the person's choice, never automatic; test 23 |
| F5 | **Fixed** | 8.7.4 rule 6 (claims checked against the chain, never changing state by themselves); separate KWB, KWP, KWL and KA keys under KB (4.4); test 24; the E13 cross-key refusal |
| F6 | **Partly** | Guard created at set-up (7.4); absence means "possibly old" whenever a key file exists. A new hole opened by the creation-order rule is R2-2 |
| F7 | **Fixed, one residue** | Argon2id runs in a short-lived helper process (8.4); the libsodium source behaviour is stated correctly (8.3, sources table); test 11 looks for `B[0][0]`. Residue: the helper's unlocked blocks can still be swapped (R2-6) |
| F8 | **Fixed** | 8.3 restricts the claim to storage-layer secrets and names the core's ordinary-memory keys |
| F9 | **Fixed** | 4.2 has one rule for every slot: ceiling = min(4 GiB, `memlimit_max`, half of physical memory), computed in 64 bits. E4 (m above the ceiling) and E11 (m = 2^32 − 1 KiB, p = 4) are refused before deriving; reproduced |
| F10 | **Fixed in this document**, not yet elsewhere | 8.7.6: one 65-byte header, nothing else in the clear, `counter` listed in 3.2; E12 matches. But `exit.md` 5.6 and `local-api.md` 4.7 still cite a clear `next_action_height` (R2-5) |
| F11 | **Fixed** | 8.7.5 now names sibling griefing; the property is restated; test 19 checks every output against the tree's assignment. T's own wording still says "without loss" (R2-3) |
| F12 | **Fixed** | A 32-byte HMAC commitment under a PK-derived key (4.5, 11), checked before the wrap; test 5 builds a partitioning ciphertext. Checked below: sound |
| F13 | **Fixed** | 5.2: the program's own wrapper over `getrandom`, `getentropy` and `BCryptGenRandom`; `RtlGenRandom` stated correctly |
| F14 | **Fixed** | `keys()` gives each sealing key a nonce key under `label ‖ " nonce"`. I checked that no label in 4.4 ends in " nonce", so no derived key can collide with another; KB's record has its own label (KBK) |
| F15 | **Fixed** | Bellare and Tackmann cited; injectivity of the encoding stated |
| F16 | **Fixed** | The check is dropped |
| F17 | **Fixed** | 11 and E11; the reference returns "empty chunk before the end" |
| F18 | **Fixed** | 4.7: max(stored, calibrated); the words are re-sealed at upgrade |
| F19 | **Fixed** | Median of three |
| F20 | **Partly** | Mode-2 HMAC under KA, and a plain file where KB exists is read as strictest (E14, reproduced). An older *valid* mode-2 file can still be replayed by a folder-only writer to reset the count (R2-9) |
| F21 | **Partly** | The token moved to a runtime directory and is stated as full authority. On Windows the chosen location, the per-user local application data folder, is **inside** the data folder the per-user local application data folder (8.5), so "outside the data folder" is false there (R2-10) |
| F22 | **Handled as far as a spec can** | Both amendments are listed in 18, point 1; they still need the owner |
| F23 | **Fixed** | 13: 1.0.21 or later, from the minisign-checked tarball, `crypto_kdf_hkdf_sha256`, the audit described accurately |
| F24 | **Fixed** | 4.2; break-check 25 |
| F25 | **Fixed** | 5.6's new row; E7h reproduced independently (the batch and mark 2 both fail; the reading stops at 323) |

### New findings, round 2

**Medium**

- **R2-1. The penalty file has no freshness anchor, and its truncation can cost money.** `watch.gzp` is append-only (8.7.6), and the watcher's "refuse to go backwards" rule (8.7.4 rule 7) covers only the bundle's `counter`. Anyone who can write the folder can cut `watch.gzp` at an entry boundary, which is a valid shorter file, or restore an older copy. **KB is not needed** to do either. A sync service's "previous versions" or a system restore does the same by accident. The locked watcher then lacks the penalties for the host's most recent revoked states. A host that publishes one of those while the member stays locked past the revocation window takes the channel balance.

  8.7.6 says a truncated copy "costs protection while locked, not money to an attacker, and is caught at unlock by rule 4". It costs money to the member whenever the unlock comes after the window, and the host is the party that benefits. The 8.7.5 table ("write access ... only dates can be stale") must say this.
  *Change:* keep the penalty file's entry count, or its last offset, in the OS store beside the bundle counter (rule 7 extended), updated with each append. The watcher refuses, and the status reports, a penalty file shorter than that. One small key-store write per host revocation is cheap next to the journal's fsyncs.

- **R2-2. Deleting the journal and the guard together restarts the wallet at epoch 0.** The creation-order rule (7.4) says: "A crash after the key file and before the guard: the next unlock writes the guard, because no journal exists yet." So a key file with no guard and no journal reads as an interrupted set-up. An attacker with write access, or a careless clean-up, who deletes `journal.gzj` and `guard.gzg` gets a fresh guard and an empty journal: `key_epoch` 0, `key_index` from 0. That reuses keys already used under epoch 0, which is exactly what R2 to R5 exist to prevent. Test 8 covers "guard deleted", not "guard and journal deleted".
  *Change:* a key file without a journal always starts as a restore (new epoch, R2). For a genuine set-up crash that costs nothing, since nothing was used under epoch 0. Alternatively, mark "set-up complete" inside the key file's authenticated header once the journal exists. Add the case to test 8.

- **R2-3. Invariant T is worded for revocation, but later engines supersede.** T's escape clause is "if a later engine needs an item that can become **revoked**". The 1.1.0 plans, though, replace states without revoking them:
  - timed layers (Decker-Wattenhofer states, `safety-rule.md` 8: an old state "can reach the chain if it wins the race");
  - the leaf change of `safety-rule.md` 4.2;
  - rolling into the next factory.

  An old bundle holding a superseded timed-layer state lets a KB holder start exactly the race that `THREAT-MODEL.md` §3 lists as a loss for members above their coverage.

  T's sentence "valid to publish at any time without loss to its rightful owners" also contradicts 8.7.5 and `exit.md` 7.1, where siblings pay exit fees. And it is violated in letter by the fee ladder whenever a set-aside fee coin is later released back to general use: an old bundle's highest rung can still burn it, up to 200 sat/vB × package size.
  *Changes:*
  - (a) Reword the trigger as "can become revoked **or superseded**", and say that 1.0.0's "one version per funding output" is the precondition.
  - (b) Reword T as "... cannot move value away from its rightful owner on any output; it can cost fees and off-chain places (8.7.5)".
  - (c) A released fee coin is first spent to a fresh wallet address while unlocked, or the loss bound is stated.

- **R2-4. The start rule's penalty-file test has nothing to compare.** 6.3 step 3 and 8.7.4 rule 4 compare "the penalty file's last entry" with the journal position. But a penalty entry's payload is "one B6 record", and `exit.md`'s type-20 record has no journal `file_id` or mark offset. "Newer than the journal" cannot be decided for it.
  *Change:* each penalty entry carries the journal `file_id` and the sync-mark offset of the batch that recorded the host's revocation. The same applies to `exit.md`'s record table, which still places B6 inside the bundle (type 20), contradicting 8.7.6.

- **R2-5. `local-api.md` draft 3 §4.7 and `exit.md` still describe the draft-1 watcher.** Item by item:
  - **Exits.** The rows "Leaves alone by its dates: Yes, broadcasting the bundle's already-signed exit path" and the lock warning ("will leave them alone by their dates if it must") promise a finished exit. Under draft 2 the watcher publishes only the tree path, and the balance is safe only if the person unlocks by `unlock_by` (`exit.md` 5.6). The warning must carry `unlock_by` and say that the last step needs the passphrase. This is user-facing, so it matters.
  - **Penalties.** "Answers an old state ... with the fully signed responses in the bundle": they are in `watch.gzp`.
  - **`next_action`.** It is described as "the one date stored in the clear". Draft 2 stores nothing in the clear; the watcher serves it from the opened bundle. The locked status also lacks the `unlock_by` field that `exit.md` 5.6 requires.
  - **Names.** `watching.state = locked_watcher` here, `watcher_locked` in `exit.md` and storage 8.6. Pick one.
  - **Rule number.** `bundle_refused` cites "storage 8.7.4 rule 5"; in draft 2 it is rule 7. There is also no status reason for "kept as `.newer`, journal behind" or for "no OS key store" (storage 8.7.3; `bundle_key_unavailable` does not say that the store is absent).
  - **Unlock order.** Local API: storage unlock, *then* the watcher stops. Storage 8.2 and `exit.md` W1: the watcher stops *first*. Also unstated: what happens when the unlock fails (the watcher must restart), and when 6.3 finds the journal behind. 6.3 step 4 keeps the watcher running and does not start the node, but §4.7's steps 2 to 5 always go on to connect the node.
  - **Lock hold.** §4.7 holds the lock only for outstanding partial signatures; `exit.md` 5.6 also holds it while an incoming payment's secret is released and unsettled. This is needed by 1.0.0.

**Low**

- **R2-6. The helper's memory is not locked.** 256 MiB to 1 GiB of Argon2 blocks can reach swap or the Windows pagefile during the helper's life, and process exit does not wipe swap. Add "the helper's blocks in swap" to 8.3's not-defended list next to its crash dump, with the full-disk-encryption advice. On Windows that means BitLocker, because the pagefile is otherwise not encrypted.
- **R2-7. "Families safe to lose" covers member records only.** Host-side families need their own one-line argument, or anchoring: `funding_signed` ("rebroadcast from it"), `ack_received` (H1) and `start_sent`. The channel engine must list payment-preimage records. 6.2 already says it will; name it in `exit.md` 10.1 (CH list).
- **R2-8. Write cost of anchored batches.** A payment is about three anchored batches: own commitment, released revocation, host revocation with a penalty append. With group sync that is roughly two guard replaces (each a temporary write, two fsyncs and a rename), plus one penalty append and its sync, per payment. With `F_FULLFSYNC` on macOS that is tens of milliseconds per payment. That is fine for a member; it is a bottleneck for a host with many channels. Cheaper equivalent: make the high-water mark an **append-only** record, one fsync, instead of an atomic replace. The guard's epoch and index part changes rarely and can keep the replace. Option_data_loss_protect does not make the anchor redundant: an exit at a deadline while the host is unreachable gets no data-loss check.
- **R2-9. Attempts-file replay.** A writer with an older valid mode-2 file can restore it. The fix is cheap: add the file's `counter`, or the KB-store counter of rule 7. The impact is low, since online guessing is bounded by Argon2id anyway.
- **R2-10. Windows token location.** Use a folder outside the per-user local application data folder, for example a per-user runtime subfolder of the temp directory with an owner-only access list, or fix the sentence.
- **R2-11. Rekey and the high-water marks.** 4.8 replaces the journal's `file_id` but does not say that the guard's mark, the bundle's B1 and the penalty file's positions are rewritten in the same switch. As written, the first start after a rekey trips 6.3 step 2 ("`file_id` is not the journal's") and forces a restore. This belongs to open point 5's fault tests, but the rule should be written now.

### The new pieces, attacked

- **Invariant T, item by item (1.0.0).**
  - Tree transactions: fixed at creation; they spend only the funding and tree outputs and pay the tree's assignment. Publishing them early is griefing. `exit.md` 7.1 and section X's arithmetic show that H_leaf is absolute, so nothing is taken earlier.
  - Penalties: they cannot confirm unless the host's revoked commitment is on chain first, and they pay the member.
  - Anchor-only children: keyless; anyone can already build them.
  - Fee rungs: spend only their step's set-aside coin and pay change to the wallet (see R2-3 (c)).
  - B9: txids only.

  No item lets anyone take a penalty against the member. So **T holds for 1.0.0**, with R2-3's wording and scope fixes.
- **The penalty file.** It uses the journal format under KWP with its own `file_id`, so the binding to offset and `file_id` is inherited, and entries cannot be moved or spliced. Old copies are harmless (T). Truncation is not harmless (R2-1). Compaction to a new `file_id` must also update the OS-store count of R2-1.
- **KB subkeys.** KWB (`chain ‖ bundle_id`), KWP and KWL (by `file_id`), KA (by chain) and KBK (from MSK) are all distinct labels. The E13 cross-key refusal reproduces. Sound.
- **The Argon2id helper.** Sound in design: same image, `PR_SET_DUMPABLE` 0 and no core dumps, only PK returns over a pipe, and the OS zeroes pages before reusing them for another process. On Linux, dumpability must be reset *after* `exec` and before reading the pipe, since `execve` restores it; the text implies this, and the code must do it. A helper crash or out-of-memory must be reported as a failure, not counted as a wrong passphrase. Residue: R2-6.
- **Key commitment.** `HMAC-SHA256(derive(PK, "key file commitment", ctx), header)`. Two passphrases opening one file would need equal HMAC outputs under two different keys, which costs about 2^128 work. Since KW is derived from PK, committing to PK commits the wrap key. Testing the commitment needs PK, so it is no faster than one Argon2id. It is checked before the wrap, in constant time. The profile-1 slot does the same over bytes 0 to 83. **Sound.**
- **Parameter ceiling.** Correct and computed before deriving. Note that "half of physical memory" means a profile-1 export at 1 GiB will not open on a device with under 2 GiB; the refusal message says so.
- **Bundle newer than the journal.** Correctly treated as evidence and kept. No false positive on a legitimate crash: the bundle and the guard are replaced only after the batch's mark is synced (7.2), so a synced mark is never cut. The only gaps are R2-4 (penalty file) and R2-11 (rekey).

### Vector results, round 2

All runs were in a temporary detached worktree of `e7bcfaa`, removed afterwards.

1. **`python -I tools/spec-vectors.py`**: exit 0. "storage-encryption.md: section E done" and "exit.md: section X done". E0 to E14 assert, including the new E7h and E14.
2. **My independent rebuild**, updated for draft 2. It again uses only the Python `cryptography` package 46.0.5 (OpenSSL backend) for Argon2id, HKDF, HMAC, SHA-2, ChaCha20 and ChaCha20-Poly1305, with HChaCha20 from the raw keystream, and shares no code with the tool. It reproduces bit for bit:
   - the XChaCha draft vectors, E1, E2 and E2r;
   - E3 (363 bytes, including the commitment key `00dc1f01…`) and E8;
   - E5 (including the KJ nonce key `84d9e143…`);
   - E6a to E6d and E9;
   - BK and EK;
   - E10b, and E10a (428 bytes, against the tool's printout);
   - E12 (138 bytes, KWB `c269df89…`) and E14 (77 bytes);
   - E7h's failure pattern, checked independently.
3. **Not run: libsodium**, not installed (open point 12).

### What I could not check in round 2

- libsodium on any platform.
- `channel.md` (not written), so the channel-side anchored families and the penalty record's final form.
- Whether `exit.md` draft 2 will take over the storage-side corrections that 8.7.6 and the "what it changes elsewhere" table ask of it.

---

## Round 1: draft 1 (commit `b626a9e`)

Reviewer: independent, adversarial applied-cryptography review. I wrote none of the reviewed text or code.
Date: 2026-11-12. Subject: branch `specs-slice1` at commit `b626a9e` (the tip when fetched), files `spec/storage-encryption.md` and `tools/spec-vectors.py` section E. Context read: `spec/journal.md`, `spec/local-api.md` draft 2, `spec/safety-rule.md` (sections 3, 4.3, 9), `docs/THREAT-MODEL.md` (2.7, 3), `docs/ux/decisions.md` (13, 14), `docs/notes/wallet-keys.md` on `main` (there is no `spec/wallet-keys.md` on `main`; the notes file is the only wallet-keys document), and the libsodium source on its `stable` branch.

## Verdict

**Ready after listed changes**, with one part that **needs rework**: section 8.7 (the watch-and-exit bundle).

The core cryptography is sound and correctly specified. Argon2id into HKDF into XChaCha20-Poly1305, the random storage key, wrapping with no verifier, hedged nonces, entry associated data, the STREAM-style export and the domain separation are all right. The vectors reproduce independently. The faults are in what surrounds the cryptography:

- the bundle's contents and its threat analysis (F1, F2, F4, F5);
- the set of batches that rollback detection protects (F3, F6);
- two memory claims that the libsodium source contradicts (F7, F8);
- an unbounded KDF slot on imported exports (F9);
- a format mismatch between the spec and the vector code (F10).

None needs a new primitive. Sections 4, 5, 7, 9, 10 to 13 can be built once the High and Medium items below are folded in. Section 8.7 should be redrafted with `spec/exit.md` before anything is built from it.

## Findings, ranked

### High

**F1. Old bundle copies become toxic once a commitment is revoked. A thief with an old copy and KB does not need write access to cost the member money.**
Section 8.7.4 rule 2 makes sure no bundle written *after* a revocation holds the revoked commitment. But every bundle written *before* it holds a then-current, fully signed commitment that becomes revoked later. The spec itself lists the places where old copies of the data folder survive: a cloud-synchronised folder, a synchronisation service's change history, operating-system backups, "previous versions", VM snapshots (sections 3.2 and 6.4).

Anyone who holds such a copy and KB can take the old commitment out and broadcast it **from their own machine**. The honest host then sweeps the channel with the penalty, and the member loses the channel balance. A dishonest host that obtains the copy gets that money outright.

Getting KB is easy in this design. With the `watch.key` fallback, KB sits in the same folder, so every folder copy includes it. Under DPAPI, any process of that user can unprotect it.

The table in 8.7.5 classifies this attack as needing "write access as the person's own operating-system user". That is wrong: it needs only read access to an old copy and KB, and nothing on the victim's machine is touched, so watcher rule 5 is irrelevant. The claim "whoever holds the files and KB cannot steal" (E-D13, 8.7.5) does not hold for any wallet with channels.
*Changes:*
- (a) Rotate KB at every bundle rewrite that carries a commitment, and destroy the old KB in the OS store. Old bundle copies then need the old KB too.
- (b) Remove the plain `watch.key` fallback, or at least keep it outside the data folder and outside synced locations (see owner choice 8).
- (c) Restate 8.7.5 honestly: "data-folder history plus KB lets an attacker broadcast a revoked commitment of the member; the member loses that channel's balance".
- (d) Add a test: an old bundle version plus KB in a simulated thief's hands, after a revocation. Test 17 covers only bundles written after the release.

**F2. B6 contradicts `safety-rule.md` 4.3: a "fully signed" own commitment does not exist in the standard taproot channel format.**
`safety-rule.md` 4.3 states that a party "never holds a final signature on its own commitment". It holds the peer's partial signature and nonce, and completes its own partial signature at broadcast, which needs its private key. The locked watcher holds no key (8.7.1), so it cannot complete the commitment.

Making B6 work means pre-completing a signature on every commitment while unlocked. That is a signing act per update under the channel format's nonce rules, and it creates the toxic artefacts of F1. This needs `spec/exit.md` and the channel engine to agree before the bundle list is fixed.
*Change:* mark B6's own-commitment part **(open, depends on the channel engine)**. Either specify pre-completion and its nonce reasoning, or have the locked watcher answer withheld closes only through the tree path and the penalty transactions.

**F3. Rollback detection does not cover the batches whose loss costs money in channels: commitment updates and revocations. It also does not cover `round_signed`.**
E-D8 and 6.2 anchor the high-water mark only on batches with `guard` or `exposure` records. A journal cut at an entry boundary after a commitment update or a revocation release reads as clean (E7g's case), and the guard does not catch it.

Two things follow:
- After such a cut the node believes an older commitment is current. On a later force close it broadcasts a revoked state, which the host then penalises.
- A cut after `round_signed` silently removes the held set (C3). `THREAT-MODEL.md` §3 accepts "loss of the held set", but by damage, not by a silent cut that the design claims to detect.

The fix is nearly free. Item B1 of the bundle already carries "the journal `file_id` and sync-mark offset it was made from". 8.7.4 rule 1 already rewrites the bundle before every batch that changes exit data, and rule 2 before every revocation.
*Changes:*
- (a) Add the bundle's B1 to the start rule of 6.3: a bundle whose mark offset is not a valid sync mark in the journal, or is beyond its last mark, means "behind", which leads to the restore path.
- (b) 8.7.4 rule 4 must treat a bundle **newer** than the journal as rollback evidence. Today it only replaces an *older* bundle. Taken literally, it would also overwrite the newer bundle with one built from the rolled-back journal, destroying the evidence and rebuilding a stale exit set.
- (c) Say explicitly which record families are anchored, and why the others are safe to lose.

**F4. After a restore, the bundle builder must not publish commitments from the backup.**
`THREAT-MODEL.md` 2.7 relies on "a restored backup never publishes". The journal and every export carry the member's commitments (11: "every journal entry up to the last valid sync mark"). After an import, the unlocked program builds the bundle from the restored journal (8.7.4 rule 4). The watcher would then broadcast a possibly revoked commitment by its dates, without anyone unlocking.

An old copy returned by the host (`THREAT-MODEL.md` 2.7, last row) turns this into theft by the host.
*Change:* after a restore marker, until each channel is re-established with its peer (data-loss-protect style), the bundle holds tree-path and penalty items only and no own commitment. Add a test for it.

### Medium

**F5. Text written by the locked watcher is merged into the journal, but anyone with KB can forge it.**
`watch.gzl` is sealed under KB and "merged into the journal at the next unlock" (8.7.1, 8.7.4 rule 4). KB is held unattended, so anyone with KB and write access to the folder can fabricate "saw / did" lines. With `watch.key`, that is anyone who can write the folder. Such lines could say that an exit was broadcast, that an outpoint was spent, or that a factory was abandoned. If the merge changes state, the node may stop watching a live factory.
*Change:* the watcher log is untrusted input. On merge, every claim is checked against the chain before it becomes a record; nothing in it may change held, exposed or round state by itself. Also derive separate subkeys from KB for `watch.gzw` and `watch.gzl`. Today one key seals both formats; the associated data differ in length, so nothing cross-opens, but the separation should be by label.

**F6. A deleted guard file plus a journal rolled back to before the first round is not detected.**
6.3 step 1 treats a missing guard as "possibly old" only "on a wallet that has started rounds or allocated keys". That fact comes from the journal, which is exactly what may have been rolled back. Rolling back past the first `key_index` and deleting the guard gives a normal start at key index 0 of epoch 0, so keys get reused.
*Change:* create the guard file with the wallet (set-up step, before the journal's first confirmation), and treat its absence as "possibly old" for **every** wallet whose key file exists. The set-up crash window is handled by the creation order of 7, step 4.

**F7. "libsodium wipes and frees [Argon2id's memory] after each derivation" (8.3) is false, and the leak is worse than stated.**
In libsodium's `argon2.c`, `argon2_hash` sets `context.flags = ARGON2_DEFAULT_FLAGS`, which `argon2.h` defines as 0. `argon2_free_instance` calls `clear_memory(instance, flags & ARGON2_FLAG_CLEAR_MEMORY)`, so the 256 MiB of blocks are **never** zeroed:
- Where mmap is available, they are unmapped (`munmap`).
- On Windows builds without `HAVE_MMAP`, they are freed with `free()` and stay in the process heap.

This matters more than "passphrase-derived blocks". The first block of each lane is `B[l][0] = H'(H0 ‖ 0 ‖ l)`, with `H0 = BLAKE2b(params, passphrase, salt)`. Anyone who gets that one KiB (from a crash dump under WER `LocalDumps`, which 8.5 says it leaves alone, from swap or from the heap) can test passphrase guesses at BLAKE2b speed. Memory hardness is gone.
*Changes:*
- (a) Correct the text.
- (b) Make the implementation wipe: either call the low-level Argon2 with `ARGON2_FLAG_CLEAR_MEMORY` (not exposed by libsodium's public API), or run the derivation in a short-lived child process. On Windows, at least make sure the region is not plain-heap freed.
- (c) Name this in 8.3's "not defended" list if neither is done.
- (d) Test 11 should also search a forced dump for `B[0][0]` taken during unlock.

**F8. "Every key ... held in memory from `sodium_malloc` and nowhere else" (8.3) cannot be true as designed.**
The node "derives keys from [the seed]" (8.1). Per-lobby factory and contribution keys, BIP 32 intermediates and MuSig2 state live in the core and the wallet library. Section 13 forbids `sodium_` symbols there. They also go through OpenSSL's HMAC and PBKDF2 contexts (`wallet-keys.md`: "libcrypto's HMAC, SHA-256 and PBKDF2") and libsecp256k1 objects on the ordinary heap and stack. Test 10 ("a memory scan finds none") is fine while locked, but the claim is about the unlocked process.
*Change:* restrict the claim to "storage-layer secrets (passphrase, PK, MSK, subkeys, seed copy, words)". State that keys derived in the core live in ordinary memory and are wiped by the wallet library's own rules (`wallet-keys.md` 5).

**F9. Imported profile-1 exports have no floor and no ceiling on their KDF parameters.**
4.2's floor and ceiling apply to the key file only. Section 11 says nothing for the export slot, and the reference `open_export` checks neither `kdf`, `p`, nor the range of `t` or `m`. An export file handed to a person (by a host, or by phishing) can set `m` to 2^32 − 1 KiB and stall or kill the program on import. A file with tiny parameters is harmless to secrecy (nothing is returned on failure), but it should be refused for consistency.
*Change:* apply 4.2's rules to every Argon2id slot, before deriving. Additionally compute the ceiling as `min(4 GiB, crypto_pwhash_memlimit_max(), a fraction of physical memory)`. On 32-bit builds libsodium's `MEMLIMIT_MAX` is 2 GiB, and `m × 1024` overflows a 32-bit `size_t` at exactly the stated 4 GiB ceiling.

**F10. The spec and the vector code disagree on the bundle header.**
8.7.6 has a `next_action_height` (`u32`) in the clear header and "ad = the 69 bytes before". The code (`_bh`) builds a 65-byte header with no such field, and E12 is computed that way. My independent rebuild confirms the 138-byte E12 with a 65-byte header.
*Change:* pick one and regenerate E12. If the field stays, list it in 3.2's table of visible fields: it reveals the member's next exit date to anyone with the folder. The bundle's clear `counter` is also not listed there today, though checklist item 3 asks that every byte be either authenticated or listed.

**F11. Bundle threat analysis: broadcasting the exit path harms third parties, and test 19 cannot pass as written.**
B4 contains "every fully signed transaction from the funding output down to the member's own leaf". In a SuperScalar tree those transactions create outputs for other members and for the host. "Every transaction ... pays the member's own outputs or the miners" (8.7.5) is therefore false. So is test 19 ("pays only the member's outputs, the miners, or the fee coins' change").

A KB holder who broadcasts the kickoff early forces the whole subtree on chain. Every sibling then pays exit fees and loses its channel.
*Change:* restate the property as "cannot move value away from its rightful owner on any output". Rewrite test 19 to check every output against the tree's own assignment. Add "griefing of every member under the same subtree" to 8.7.5.

**F12. Tag-as-verifier is not key-committing; give the wrap and the export slot key commitment.**
Poly1305 is not key-committing. A ciphertext can be built that opens under many keys: partitioning oracles (Len, Grubbs, Ristenpart, USENIX Security 2021) and "invisible salamanders" (Albertini et al., USENIX Security 2022).

The setting here: an attacker writes a key file or a profile-1 export whose wrap opens under the keys from k candidate passphrases (k Argon2id computations up front). The attacker then learns from the outcome whether the person's passphrase is among them. The outcome is visible through the program's behaviour, whether the node starts, or the person's report. The spec even gives distinct results: "wrong passphrase or damaged" versus "damaged key file" once the wrap has opened.

The cost to the attacker is high and the leak is small (about log k bits per try, limited by the attempts file). It is not a shortcut against a stolen honest file, so E-D3's claim "no shortcut" stands. But an "elite" design should close it cheaply:
*Change:* store a key-commitment value next to the wrap, for example `C = HMAC-SHA256(derive(PK, "key commitment", ctx), ad)` truncated to 32 bytes, and check it before opening. It costs the same full Argon2id to test, so it is not a fast verifier. The alternative is the zero-block "padding fix" of Albertini et al.

### Low

- **F13. Random-source failure handling.** libsodium's `randombytes_buf` returns `void` and calls `sodium_misuse()`, which aborts, on failure (`randombytes_sysrandom.c`). 7.5's "a storage failure (`gz_runner_storage_failed`)" therefore cannot be implemented over it. Either accept "process aborts, nothing is half-written", which is true because entries are sealed whole before writing, or call `getrandom`/`BCryptGenRandom` directly. Windows uses `RtlGenRandom` (`SystemFunction036`), not `BCryptGenRandom`. The source has no `BCryptGenRandom` path, so correct 5.2 and 8.5.
- **F14. Nonce key.** `nk = HMAC-SHA256(K, label)` uses the AEAD key K itself as an HMAC key. No attack is known, since HMAC-SHA256 and ChaCha20 are unrelated, but it is a cross-primitive key reuse. Derive `nk` in the HKDF table, from the same input keying material under its own label. The same applies to KS sealing both the seed and the future KB record: give KB its own label.
- **F15. Hedging citation.** The construction is the "nonce = PRF(K, R, AD, M)" hedge of Bellare and Tackmann, "Nonce-Based Cryptography: Retaining Security when Randomness Fails" (EUROCRYPT 2016), not SIV. SIV also verifies the synthetic IV. The construction is correct, and its encoding is injective: fixed 32-byte r, length-prefixed AD, plaintext last. It can only ever leak equality of byte-identical (AD, plaintext) pairs when r repeats. Cite Bellare and Tackmann.
- **F16. "If the words are given, BK must equal the slot's" (11).** In the reference `open_export` this check is vacuous: when the seed is given, BK is computed from it, so it always equals itself. The slot is never opened in that branch. Either open both and compare, or drop the sentence.
- **F17. Empty non-final chunks.** "Only the final chunk may be empty", but the reader accepts `n = 40` for a non-final chunk. Refuse it.
- **F18. Passphrase change and parameters.** 4.7 does not say at which Argon2id parameters the new wrap is made. Specify `max(stored, current calibrated default)`, never lower. Parameter upgrade at unlock must also re-seal the words: it can, because PK is still in hand at that point, but the spec should say so, and that it costs a second derivation at the new parameters.
- **F19. Calibration** rests on one timing sample with a 3-second threshold. The spec's own OpenSSL run took about 3 seconds "under load", which would have dropped a capable desktop to 128 MiB. Take the median of three samples. A test system under load at set-up permanently weakens the file, and only the "never downward" upgrade repairs it.
- **F20. Attempts file.** It could be authenticated with KB whenever KB is in an OS store, since the locked program has KB. That costs nothing and stops a folder-only writer from resetting the counter. The current reasoning, "a writer can copy the key file anyway", is right for the offline attack but not for an attacker who can write files and not read them back (for example a sync conflict or a malicious sync peer).
- **F21. Socket token naming and authority.** `local-api.md` draft 2 names it `interface-token`, "new at every start". This spec names it `socket.token`, "made at unlock". The local API also exempts bearer requests from fresh sign-in, so while the wallet is unlocked the file is a full-authority credential. Keep it plain, as proposed, but put it in a per-user runtime directory (`$XDG_RUNTIME_DIR`, a tmpfs; on Windows a non-synced local folder), not in the data folder that sections 3.2 and 6.4 admit may be synchronised.
- **F22. Owner decisions in conflict.**
  - Decision 13 says "A backup export is the file as encrypted on disk", but section 11 defines a separate, re-encrypted format.
  - Decision 14 says that after lock "the program then does nothing until unlocked", but 8.7 has it keep watching.

  Section 8.7's change is right on safety, but both are recorded owner decisions and need the owner's explicit amendment, not only a note to `local-api.md`.
- **F23. libsodium version.** 1.0.18 is from 2019. HKDF arrived in 1.0.19 (2023). 1.0.21 fixes CVE-2025-69277, an incomplete check in `crypto_core_ed25519_is_valid_point`. That function is not used here, but a security wallet should not pin below a security release. Require **≥ 1.0.20, preferably 1.0.21**, built from the signed release tarball (minisign) on every platform rather than the distribution's 1.0.18 static archive. Then drop the hand-written HKDF (4.4), which removes code. The cited audit (Cryptography Engineering, 2017, versions 1.0.12 and 1.0.13) is real, but it predates years of changes; say so rather than "audited".
- **F24. Test-only parameters.** The "test entry point [that] accepts any parameters" (4.2) must be compiled out of release builds. Add a break-check that a release binary refuses E2's key file.
- **F25. Corruption into a silent cut** (checklist item 5): yes, an attacker can do it. Flip a byte in a confirmed entry and in every later sync mark, and the scan sees a torn tail. This is the same as truncation and is caught only for anchored batches. Say so in 5.6, so the answer to item 5 is not read as "no".

## Checked and sound (no change needed)

- **Argon2id use.** Version 0x13, p = 1, no secret or associated data, 16-byte salt, 32-byte output: exactly libsodium's `crypto_pwhash(..., ALG_ARGON2ID13)`. In libsodium's header, `OPSLIMIT_MODERATE` is 3 and `MEMLIMIT_MODERATE` is 268,435,456, matching 256 MiB and 3 passes. `INTERACTIVE` is 64 MiB with **2** passes, so 4.2's "interactive 64 MiB" is right, but the floor's t = 3 is stricter than libsodium's interactive setting, which is fine. libsodium's documentation gives "about 0.7 seconds on a 2.8 GHz Core i7" for moderate and accepts about five seconds for a desktop program entered once per session; both are quoted correctly. libsodium uses one lane; the argument that the attacker's cost does not fall with fewer lanes is right.

  Against RFC 9106 section 4, 256 MiB × 3 is between the SECOND (64 MiB × 3, p = 4) and FIRST (2 GiB × 1) recommendations. The OWASP Password Storage Cheat Sheet's minimum (19 MiB, t = 2, p = 1) is for server-side password storage and is far exceeded.
- **Downgrade by a file with low parameters.** `kdf`, `t`, `m`, `p` and the salt are in the wrap's associated data (bytes 0 to 82). Without the passphrase, an attacker cannot make a file at lower parameters that opens. The floor protects against cost and damage, not secrecy. "Never automatically downward" is the right upgrade rule. E4 exercises the changed-parameter cases.
- **Wrap with no verifier.** Testing a guess costs one full Argon2id. libsodium checks the tag in constant time before decrypting. Nothing cheaper is stored, except F7's leak through Argon2's own memory and F12's key-commitment refinement.
- **XChaCha20-Poly1305.** HChaCha20 over the first 16 nonce bytes, then the IETF construction with nonce `0^4 ‖ n[16..24]`, exactly as draft-irtf-cfrg-xchacha-03 §2.3 and libsodium. A 192-bit random nonce gives a 2^-32 collision chance at about 2^80.5 messages (birthday bound), as stated. The comparison with GCM (SP 800-38D §8.3, at most 2^32 random IVs) and with GCM-SIV (RFC 8452) is accurate.
- **Journal associated data.** `file_id ‖ u64 offset ‖ length ‖ kind ‖ incarnation ‖ sequence` stops moving, replaying, swapping and splicing; the length binds the ciphertext size; KJ also depends on `file_id`. A drop from the middle invalidates every later entry. Truncation at a boundary and whole-file rollback are, honestly, not detectable from the file alone (5.6, 6.1). The torn-tail-versus-corruption rule is unchanged in meaning. The candidate scan range in the code is correct (p ≤ len − 69).
- **Seed-derived keys and domain separation.** KR, KG and BK are HKDF-SHA256 with salt `gazpacho/v1/storage`, that is HMAC-SHA256 keyed with that string, over the 64-byte BIP 39 seed. BIP 32's master derivation is HMAC-SHA512 keyed with `"Bitcoin seed"` (`wallet-keys.md`). The two cannot coincide: different function, different key. No output of the storage tree is ever used as a signing key. Signed protocol messages use BIP 340 tagged hashes with protocol tags (`signing-round.md` §3), a disjoint construction. `info = label ‖ 0x00 ‖ context`, with NUL-free fixed labels, is injective. The labels are all distinct, so I found no cross-protocol risk. Reducing journal recovery to the 24 words is acceptable, as the spec argues: the seed already spends everything.
- **Sealed 24 words under PK, not MSK.** This holds: a running program with MSK cannot open them. The spec is honest that this protects the words, not the money.
- **Exports.** The prefix (magic, format, **profile**, chain, `export_id`, slot) goes into every chunk's associated data together with `u64 index ‖ u8 final`. That is STREAM (Hoang et al. 2015) with per-chunk nonces. Reordering, dropping, repeating, truncation and stripping profile 1's slot to fake profile 2 all fail, as E11 shows. Profile 2 contains nothing a passphrase opens: BK comes only from the seed.
- **Plain attempt counter.** The reasoning is right for the offline threat. Missing or damaged means strictest is correct (see F20 for a cheap improvement).
- **OS-level claims.**
  - `PR_SET_DUMPABLE 0` blocks core files and same-user `ptrace` attach (`prctl(2)`).
  - Per libsodium's documentation, `sodium_malloc` places a guard page after the region, adds one before the canary where supported, calls `mlock`, and excludes the pages from core dumps where `MADV_DONTDUMP`/`MAP_NOCORE` exist. "Guard pages before and after, a canary" is accurate.
  - `VirtualLock` does not keep pages out of the hibernation file, as stated.
  - `CryptProtectMemory(SAME_PROCESS)` needs multiples of 16 bytes; MSK (32) and the seed (64) fit.
  - The spec is honest that Windows and macOS have no same-user anti-debugging. For macOS, add that a hardened-runtime signed build without `get-task-allow` refuses `task_for_pid` from same-user processes.

## Vector results

All runs were in a temporary detached worktree of `origin/specs-slice1` at `b626a9e`, outside the repository, removed afterwards.

1. **`python -I tools/spec-vectors.py`** (Python 3.12.10): exit 0, "section E done". E0 passes: RFC 8439 2.8.2, XChaCha 2.2.1 and A.3.1, RFC 5869 A.1, RFC 9106 5.3. All of E1 to E13 assert and print. Every printed hex block of E3, E5, E6a to E6d, E8, E9 and E10b equals the spec's.
2. **An independent implementation I wrote**, using the Python `cryptography` package 46.0.5 (already installed; OpenSSL backend) for every primitive: `Argon2id`, `HKDF`, `HMAC`, `ChaCha20Poly1305`, and HChaCha20 obtained from `cryptography`'s raw ChaCha20 keystream by subtracting the input state. It shares no code with the tool and reproduces bit for bit:
   - the XChaCha draft's 2.2.1 and A.3.1 vectors;
   - E1, E2 and **E2r** (256 MiB);
   - E3 (key file, 331 bytes) and E8 (passphrase change);
   - E5 (journal header) and the recovery unwrap with the seed;
   - E6a to E6d;
   - E9 (guard);
   - BK and EK;
   - E10b (profile 2) and E10a (profile 1, 428 bytes, compared with the tool's output);
   - E12 (bundle, 138 bytes, 65-byte header; see F10).
3. **OpenSSL 3.5.5 command line** (`openssl kdf ... ARGON2ID`, lanes 1, memcost 262144, iter 3) gives E2r = `acfe7a0e…6433c945`, in about 2.4 s. Caveat: the author's E2r check also used OpenSSL, and `cryptography` also links an OpenSSL, so for Argon2id my cross-check shares a library family with theirs. It does not share code with the Python reference.
4. **Not run: libsodium itself.** It is not installed here, and I did not install packages system-wide. Open point 12 stands. By libsodium's limits (`MEMLIMIT_MIN` 8192 bytes, `OPSLIMIT_MIN` 1), E2's t = 3, m = 64 KiB is accepted by `crypto_pwhash`, so E2 is a valid libsodium vector.

## Views on the eight owner choices

1. **libsodium as a new dependency.** Yes. It is the right library: Argon2id, XChaCha and guarded memory in one place, ISC licence. Pin ≥ 1.0.20 (1.0.21 preferred), built from the verified release on every platform, not the distribution's 1.0.18 (F23).
2. **Argon2id 256 MiB, 3 passes, p = 1, floor 64 MiB / 3.** Yes for the key file. Add a device-aware ceiling (F9) and the same rules for export slots. For **profile-1 exports**, which are opened rarely, use more (1 GiB, libsodium's "sensitive"): libsodium's own guidance allows slower derivation for "restoring a backup", and the export is the one file meant to leave the device.
3. **15 characters minimum and a blocklist.** Yes as a floor. SP 800-63B-4 is written for online verifiers, though, and the offline attack (3.3) is what matters here. Make the generated six words the prominent default, and consider an entropy estimate in the refusal rules. A 15-character person-chosen phrase at 30 to 40 bits falls in days on one GPU, by the spec's own table.
4. **Host copy opens only with the 24 words.** Strongly yes. This is the most important choice in the document, and it is correct.
5. **Profile-1 export carries the words.** Lean **no by default**. It turns a file people will put in cloud storage into a passphrase-protected seed backup: steal the file, crack the passphrase, take the funds. Offer it as an explicit option with the generated passphrase or stronger parameters. Otherwise keep profile 1 as "factories, opens with passphrase or words, no words inside". The 24 words are already the root backup.
6. **Plain socket token.** Acceptable, but move it to a runtime directory outside the data folder (F21).
7. **Unattended unlock (`--passphrase-fd`, service-manager credentials).** Acceptable for host services only. Never offered to members by default; the interface shows it, as proposed.
8. **Bundle on by default, `watch.key` fallback.** Bundle on: yes, once F1 to F5 and F11 are fixed; leaving in time matters more. `watch.key` fallback: **no** in its proposed form, since it is the main enabler of F1 and F5. Where no OS store exists, keep KB outside the data folder in an owner-only per-user location that is excluded from sync, and say plainly in the interface that a copy of both locations gives "griefing and possible loss of channel balance from old copies", not "privacy only".

## What I could not check

- libsodium itself (not installed): E0 to E13 and E2r against `crypto_pwhash` and `crypto_aead_xchacha20poly1305_ietf_*`. The Windows and macOS behaviour of `sodium_malloc`, `VirtualLock` and working sets, and `CryptProtectMemory`, was not exercised.
- Whether libsodium's Windows (MSVC) build defines `HAVE_MMAP`, which decides whether F7's Argon2 memory goes to `free()` or `munmap`. Either way it is not wiped. I read the `stable`-branch source, not a specific release tarball.
- The full text of the 2017 libsodium audit report, beyond its published summary, and the exact XChaCha scope in it.
- The channel engine and `spec/exit.md`, which do not exist yet. F1, F2 and F4 depend on how commitments are actually held.
- Real GPU guessing rates for Argon2id at 256 MiB. The spec's figure is marked as reasoning; I did not measure it.
- The crash-order proofs for rekey (open point 5) and fault tests. These need an implementation.

## Sources

- RFC 9106 (Argon2), §3.1, §4: https://www.rfc-editor.org/rfc/rfc9106
- RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
- draft-irtf-cfrg-xchacha-03: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- NIST SP 800-38D §8.3; SP 800-63B-4 §3.1.1; SP 800-132 §5.1 (as cited by the spec)
- OWASP Password Storage Cheat Sheet (Argon2id minimums): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- libsodium documentation, password hashing: https://doc.libsodium.org/password_hashing/default_phf
- libsodium documentation, secure memory: https://doc.libsodium.org/memory_management
- libsodium source, `stable` branch: `src/libsodium/crypto_pwhash/argon2/argon2.c` (`context.flags = ARGON2_DEFAULT_FLAGS`), `argon2.h` (`ARGON2_DEFAULT_FLAGS (UINT32_C(0))`, `ARGON2_FLAG_CLEAR_MEMORY`), `argon2-core.c` (`argon2_free_instance`, `clear_memory`, mmap/`free` paths), `include/sodium/crypto_pwhash_argon2id.h` (presets and limits), `randombytes/sysrandom/randombytes_sysrandom.c` (`sodium_misuse()` on failure; `RtlGenRandom`): https://github.com/jedisct1/libsodium/tree/stable
- F. Denis, "A vulnerability in libsodium" (CVE-2025-69277, fixed in 1.0.21): https://00f.net/2025/12/30/libsodium-vulnerability/ ; Debian tracker: https://security-tracker.debian.org/CVE-2025-69277
- Cryptography Engineering for Private Internet Access, libsodium 1.0.12/1.0.13 assessment (2017): https://www.privateinternetaccess.com/blog/libsodium-audit-results/
- Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021
- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022
- Bellare, Tackmann, "Nonce-Based Cryptography: Retaining Security when Randomness Fails", EUROCRYPT 2016
- Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015
- Linux `prctl(2)` (`PR_SET_DUMPABLE`), `madvise(2)` (`MADV_DONTDUMP`); Microsoft documentation for `VirtualLock`, `CryptProtectMemory`
