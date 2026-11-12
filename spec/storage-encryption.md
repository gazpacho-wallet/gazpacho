# Storage encryption

Specification draft 3, 2026-11-12. Draft 2 (`e7bcfaa`) was confirmed by the second round of the independent review (verdict "ready to build from, once the Medium items R2-1 to R2-5 are folded in"; round 2 sits above round 1 in the reviewer's file, `review-storage-encryption-d1.md`, whose archived copy in `docs/reviews/` still holds round 1 only). This draft answers R2-1 to R2-11 and the four findings round 2 found only partly fixed (F3, F6, F20, F21), and aligns with `spec/local-api.md` draft 4 and the contradictions that the review of `spec/exit.md` draft 1 listed against this document. Draft 3 has not itself been reviewed. Draft 2 is kept unchanged at `docs/specs-history/storage-encryption-d2.md`, draft 1 at `docs/specs-history/storage-encryption-d1.md`. Items marked **(open)** are listed in section 18; values marked **proposed** are first choices the owner has not confirmed.

**Why it exists.** The owner decided on 2026-11-12 that every file the wallet keeps is encrypted from the start, on test networks too, and that the person signs in by typing the **wallet passphrase**, which unlocks the storage key, as in desktop wallets such as Sparrow (owner decisions 13 and 14, `docs/ux/decisions.md`; `spec/local-api.md`). The bar is "elite cryptography quality". This document is the cryptography: how a passphrase becomes a key, how the journal and the other files are sealed, what a thief with a copy of the files learns, what a locked wallet can still do, and what cannot be defended without state kept elsewhere.

## Changes from draft 2

From round 2 of the review (R2-1 to R2-11, and F3, F6, F20, F21 marked "partly"), the review of `spec/exit.md` draft 1 (its section 4, items 7a to 7d) and the shared decisions taken with `spec/local-api.md` draft 4 and `spec/exit.md` draft 2 (written beside this one).

| Finding | Change | Where |
|---|---|---|
| **R2-1** Medium. The penalty file had no freshness anchor; a cut or older copy loses the newest penalties, which costs the member the channel balance if the unlock comes after the revocation window | The OS key store keeps a **store record** beside KB: the highest bundle `counter` opened, the penalty file's `file_id` and the **number of its last penalty entry**, and the attempts file's counter. The penalty count is updated after each append, before the batch is confirmed. A penalty file whose last entry is below the count is refused as **short**: the watcher still publishes the tree path and the penalties it has, and the status says some answers are missing (`local-api.md` 4.7, reason `penalty_file_short`, `at_risk`). 8.7.5 now says what a cut costs. Vector E13p | 8.7.3, 8.7.4 rules 1, 7, 8.7.5, 8.7.6, 15 |
| **R2-2** Medium. Deleting the journal and the guard together restarted the wallet at epoch 0 | **A key file with no journal always starts as a restore**: a new random epoch, `restored` and `guard` (`journal.md` 8.2), and the guard's epoch list kept if a guard survives. A genuine set-up crash loses nothing by it, since no key was used under epoch 0 before the words were shown. Test 8 gains the case | 7.4, 6.3 step 0, 16 |
| **R2-3** Medium. Invariant T was worded for revocation only; "without loss" contradicted the siblings' fees; a released fee coin left old ladder rungs live | T is reworded: an item may enter only if it can never become **revoked or superseded**, with 1.0.0's one tree version per funding output as the stated precondition; T itself now says an item "cannot move value away from its rightful owner on any output; publishing it can cost fees and off-chain places", and 8.7.5 states the siblings' cost honestly (funds, channel and H_leaf untouched; once the root kickoff is buried they lose the cheap rotation and the whole-factory close and may pay a sweep fee). A set-aside fee coin is **released back to general use only by spending it** while unlocked, which makes every rung that spent it invalid | 8.7.2, 8.7.5 |
| **R2-4** Medium. The start rule's penalty-file test had nothing to compare | Each penalty entry carries the journal `file_id` and the sync-mark offset of the batch that recorded the host's revocation; its sequence number is its count from 1. Vector E13p. `spec/exit.md`'s record table must drop B6 from the bundle's type 20 (listed below) | 8.7.6, 6.3 step 3 |
| **R2-5** Medium. `local-api.md` d3 and `exit.md` still described the draft-1 watcher | Aligned with `local-api.md` draft 4 (written with this draft): the name `watcher_locked`; the locked headlines are `exit.md` 5.6's table with a `waiting_for_unlock` row and an "unlock now" row for a late tree step; `unlock_by` in the locked status and the lock echo; no date in the clear; the unlock order of 8.2; the lock held for released payment secrets | 8.1, 8.2, 8.6, 8.7.1 |
| R2-6 Low. The helper's Argon2 memory could reach swap | The helper asks for all its pages to be locked (`mlockall` on Linux and macOS, `VirtualLock` of its arena on Windows) before it allocates; when that is refused it runs anyway, and 8.3's not-defended list names the residue: the helper's blocks in swap or the pagefile, which full-disk encryption covers (BitLocker on Windows, where the pagefile is otherwise not encrypted). A helper crash or out-of-memory is a failure, never a wrong passphrase | 8.3, 8.4 |
| R2-7 Low. "Families safe to lose" covered member records only | The argument is now general: a cut can lose only batches after the newest anchored batch, because its high-water mark proves the journal reaches that far. Host-side families: `funding_signed` and `start_sent` are **anchored**; `ack_received` is safe to lose (the funding is never signed without it, and a lost one is asked for again from the member's saved bytes). The channel engine's payment-preimage records are named as anchored for `exit.md` 10.1's CH list | 6.2 |
| R2-8 Low. Write cost of anchored batches | The high-water mark moves from the guard file to an **append-only mark file** `mark.gzm`: one sealed 56-byte entry and one sync per anchored batch, instead of a temporary write, two syncs and a rename. The guard keeps epochs, key indexes and rounds started and is replaced only for batches with a `guard` record. Both are equally defeated by an older copy (6.4). Vectors E9 (changed), E9m (new) | 6.2, 6.3, 7, 10, 15 |
| R2-9 Low (F20 partly). An older valid attempts file could be put back | The attempts file carries a counter; its highest value is in the store record; a lower one reads as the strictest state. 85 bytes; vector E14 changed | 12.3, 15 |
| R2-10 Low (F21 partly). The Windows token folder was inside the data folder | The socket token lives in a per-user runtime folder **outside** the data folder on every system: `%TEMP%` (from `GetTempPath2W`) on Windows, owner-only, named by a hash of the data folder's path | 12.2, 8.5 |
| R2-11 Low. Rekey did not say the high-water marks are rewritten | A rekey writes the new journal, the mark file, the bundle and the penalty file under the new identifiers before any rename, keeps the old and the new KB in the store until the switch is complete, and completes or discards the switch at the next start | 4.8 |
| F3 (partly) | Closed by R2-4 and R2-7 | 6.2, 8.7.6 |
| F6 (partly) | Closed by R2-2 | 6.3, 7.4 |
| `exit.md` review 4.7a | 8.7.5's sibling row no longer says siblings "pay exit fees and lose their off-chain places": it says what they lose (R2-3) | 8.7.5 |
| `exit.md` review 4.7b to 4.7d | No change here: penalties stay in `watch.gzp`, no date is in the clear, the name is `watcher_locked`. `exit.md` draft 2 follows (listed below) | 8.7.6 |
| `exit.md` review F4 | B6's second-stage penalties are possible only where `channel.md` fixes the HTLC transactions' txids; otherwise the loss while locked is bounded by the payment outputs of that revoked state, and 8.7.5 says so. A ladder of penalties at several fee rates is allowed under T | 8.7.2, 8.7.5 |
| Shared decision: Slice 1 | **Slice 1 does not build the locked watcher.** A locked Slice 1 wallet reports nobody watching, reason `no_bundle` (`local-api.md` 4.7) | 8.6, 8.7 |
| Shared decision: failed unlock | The unlock order is stated for a wrong passphrase, a journal found behind, and a storage failure: in each the keys are dropped and the watcher runs again | 8.2 |
| Shared decision: Windows key store | KB and the store record live in the Windows Credential Manager (DPAPI-protected by the system), not in a blob in the data folder, so a copy of the data folder never carries them and an older folder copy never rolls the counters back | 8.5, 8.7.3 |
| Vectors | E9 and E10 regenerated; E9m, E13p and E15 (`local-api.md` 7.4's request digest) new; E14 changed | 15 |

## Changes from draft 1

Kept as draft 2 had it; its section, test and vector numbers are draft 2's (draft 3 renumbered the tests of section 16 and split section 10).

| Finding | Change | Where |
|---|---|---|
| **F1** High. Old bundle copies hold commitments that become revoked; a thief with an old copy and KB needs no write access | **The bundle never holds any commitment of the member's own**, current or old, completed or not, nor the host's partial signature on one (`spec/exit.md` W2). Every bundle item is valid in every version ever written: tree transactions fixed at creation, penalties against the host's revoked states, keyless anchor children, fee children of set-aside coins. Invariant **T** states this; an old copy plus KB can grief (publish the tree path early, spend set-aside fee coins on fees) and never publish a revoked state. The plain `watch.key` fallback is **removed**: KB lives only in an operating-system key store, otherwise there is no bundle. KB rotation per rewrite is not needed under T and is made mandatory if T is ever relaxed. Tests 21, 22 | 8.7.2, 8.7.3, 8.7.5, 16 |
| **F2** High. No completed own commitment exists in the taproot channel format | Stated: the watcher **cannot finish an exit**. It publishes the tree path by `leave_by_locked`, answers the host's old states, and the commitment waits for an unlock by `unlock_by` (`spec/exit.md` 5.6). The strip's locked headlines are `spec/exit.md` 5.6's | 8.7.1 |
| **F3** High. Rollback detection misses commitment, revocation and `round_signed` batches | **Anchored batches** are now every batch with a `guard`, `exposure`, `round_signed`, a saved own commitment, a released revocation or a received host revocation; each other record family is shown safe to lose. The bundle's B1 (journal `file_id`, mark offset) joins the start rule; a bundle or penalty file **newer** than the journal is rollback evidence, kept and never overwritten | 6.2, 6.3, 8.7.4 |
| **F4** High. A restore could rebuild a bundle that publishes stale state | Moot under T (no commitment in any bundle); additionally the bundle built after a restore marker carries `made_after_restore_marker`, and `spec/exit.md` 5.7 governs the commitment. Test 23 | 8.7.4 rule 5 |
| **F5** Medium. The watcher's log is merged into the journal, but anyone with KB can forge it | `watch.gzl` is **untrusted input**: every claim is checked against the chain before it becomes a record; nothing in it changes held, exposed, round or channel state by itself. Separate keys under KB by label for bundle, penalty file, log and attempts file | 8.7.4 rule 6, 4.4 |
| **F6** Medium. Deleted guard plus a journal rolled back before the first round is not detected | The guard file is created at set-up, before the journal's first confirmation; its absence means "possibly old" for **every** wallet whose key file exists | 6.3, 7 |
| **F7** Medium. libsodium does not wipe Argon2id's memory; one block gives guesses at BLAKE2b speed | Corrected. The derivation runs in a **short-lived helper process** whose memory the operating system reclaims at exit; the main process never holds Argon2 blocks. A crash dump of the helper during its second of life is named as not defended. Test 11 searches a forced dump for the first block | 8.3, 8.4 |
| **F8** Medium. "Every key in `sodium_malloc`" cannot hold | Restricted to storage-layer secrets (passphrase, PK, MSK, subkeys, the storage layer's copy of the seed, the words). Keys derived in the core and the wallet library live in ordinary memory under `wallet-keys.md` 5's wiping rules | 8.3 |
| **F9** Medium. Export slots have no parameter bounds; `m × 1024` overflows a 32-bit `size_t` | One rule for every Argon2id slot (key file and export), checked before deriving. Ceiling = min(4 GiB, `crypto_pwhash_memlimit_max()`, half of physical memory), computed in 64 bits. Vectors E4 and E11 | 4.2, 11 |
| **F10** Medium. Bundle header in spec and code disagree | One header, 65 bytes, as in the code. `next_action_height` and `unlock_by` are **not** in the clear: the watcher holds KB and serves them; a clear copy would tell anyone with the folder the member's next exit date. The clear `counter` is listed in 3.2 | 8.7.6, 3.2 |
| **F11** Medium. An exit path broadcast harms siblings; test 19 cannot pass | Property restated: "cannot move value away from its rightful owner on any output". Griefing of every member under the same subtree added to 8.7.5. Test 19 checks every output against the tree's own assignment. What `spec/exit.md` must keep saying is listed | 8.7.5, 16, header table |
| **F12** Medium. The wrap is not key-committing | A 32-byte **key commitment** beside every passphrase-derived wrap (key file and export slot), checked before opening; it costs the same Argon2id, so it is not a fast verifier | 4.5, 4.6, 11 |
| F13 Low. `randombytes_buf` aborts; Windows uses `RtlGenRandom` | Storage randomness comes from the program's own wrapper over `getrandom`, `getentropy` and `BCryptGenRandom`, which return errors, so a failure is a storage failure. The `BCryptGenRandom` claim about libsodium is corrected | 5.2, 7, 8.5 |
| F14 Low. Nonce key reuses the AEAD key | Every sealing key has a nonce key from the same input keying material under its own label; KB's record in the key file gets its own label | 4.4, 5.2 |
| F15 Low. Hedging citation | Bellare and Tackmann (EUROCRYPT 2016) cited; the encoding's injectivity stated | 5.2, 2 |
| F16 Low. Vacuous BK equality check | Dropped | 11 |
| F17 Low. Empty non-final chunks accepted | Refused; vector E11 | 11 |
| F18 Low. Parameters on change and upgrade | New wraps use max(stored, calibrated default); an upgrade re-seals the words with PK still in hand, at the cost of a second derivation | 4.7 |
| F19 Low. Calibration from one sample | Median of three | 4.2 |
| F20 Low. Attempts file could be keyed | Keyed under a KB subkey whenever KB is available; a plain file where KB exists is read as the strictest state. Vector E14 | 12.3 |
| F21 Low. Socket token location and authority | Kept plain, moved to a per-user runtime directory outside the data folder; stated as full authority while unlocked | 3.1, 12.2 |
| F22 Low. Two owner decisions conflict with this document | Listed as **owner amendments needed**: decision 13 ("a backup export is the file as encrypted on disk") against section 11's separate format; decision 14 ("after lock the program does nothing") against 8.7's watcher | 18 |
| F23 Low. libsodium version | **1.0.21 or later**, built from the signed release tarball on every platform; `crypto_kdf_hkdf_sha256` used, hand-written HKDF dropped; the 2017 audit described as of 1.0.12 and 1.0.13 only | 13, 4.4 |
| F24 Low. Test entry point | Compiled out of release builds; a break-check proves a release binary refuses E2's key file | 4.2, 16 |
| F25 Low. Corruption made to look like a torn tail | Stated in 5.6: damaging a confirmed entry and every later mark reads as a torn tail; only anchored batches catch it. Vector E7h | 5.6 |
| Reviewer's view, choice 2 | Profile 1 exports use more memory: **1 GiB, 4 passes** (libsodium's "sensitive"), within the ceiling | 11 |
| Reviewer's view, choice 3 | The generated six-word passphrase is the prominent default; an entropy estimate is an open point | 4.1, 14 |
| Reviewer's view, choice 5 | Profile 1 **does not carry the words by default**; carrying them is an explicit option | 11 |
| Reviewer's view, choice 8 | Bundle on; no `watch.key` fallback | 8.7.3 |
| `spec/exit.md` 10.4 | Record layout of `exit.md` 5.6 adopted; B4 tree steps only; B5's dates and constants; B7 is `exit.md` 6.6's ladder, one fee coin per tree step; the payments-in-flight lock rule; rules W1 to W5; the watcher needs the clock and the tip estimate (`exit.md` 4.5); penalties in an **append-only** file of their own (8.7.6) | 8.7 |
| Vectors | E3, E5 to E12 regenerated (key commitment, nonce keys, bundle subkeys); E7h and E14 new; E10 without words | 15 |

**What it changes elsewhere.** Folded in with this draft: `spec/journal.md` draft 3 (sections 2, 2.1, 3, 4, 5, 7, 8.3 and open points 1 and 10 now follow sections 5, 6, 7 and 10 here), `spec/local-api.md` draft 4 (every point below), `docs/notes/wallet-keys.md` section 8 and `docs/THREAT-MODEL.md` 2.7. Still for their own writers:

| Document | Change |
|---|---|
| `spec/local-api.md` (folded in, draft 4) | The operations and the unlock order of 8.2, including a failed unlock and a journal found behind (its `files_behind` state and `start-as-restore` call); the attempts file of 12.3; the passphrase rules of 4.1; the locked watcher's headlines and reasons (8.7.1, 8.7.3); the socket token's location (12.2); the requirements of 8.6, among them dates in the locked status only for connections that passed the same-user check |
| `spec/exit.md` (draft 2, being written beside this) | Already says (its 5.6, W2) that no bundle holds an own commitment. It must keep: T as reworded in 8.7.2 (its X-I4); the bundle layout of 8.7.6 **without** B6 (its record table still carries B6 as type 20) and **without** a clear `next_action_height` (its 5.6 and 10.4 item 3); penalties in the append-only `watch.gzp` with the journal position of 8.7.6 in each entry; the siblings' cost as 8.7.5 states it; `watch.gzl` untrusted on merge (its W3); the unlock order of 8.2; the payment-preimage records as anchored in its 10.1 CH list (6.2); a fee coin released only by spending it (8.7.2); and test 19's output check |
| `spec/safety-rule.md` 11 | The loss bound of an unanswerable second-stage HTLC breach while locked (8.7.5) belongs in its exclusions |
| `docs/ux/decisions.md` 13, 14 | Owner amendments needed (18, point 1) |

## Contents

1. Decisions in one table
2. Sources
3. What is encrypted, and what a copy of the files reveals
4. Keys: the passphrase, Argon2id, the storage key, subkeys, the key file
5. The journal
6. Rollback: what can be detected and what cannot
7. Crash safety
8. Locked and unlocked; keys in memory; the watcher
9. The seed and the 24 words
10. The guard file and the mark file
11. Exports and the host's copy
12. Other files
13. The library
14. What the interface says
15. Test vectors (section E of `tools/spec-vectors.py`)
16. Tests
17. Review checklist
18. Open points

## 1. Decisions in one table

| # | Decision | Why, in one line | Section |
|---|---|---|---|
| E-D1 | **Argon2id** (RFC 9106, version 0x13), 1 lane, **256 MiB, 3 passes** for the key file; **1 GiB, 4 passes** for a profile 1 export; floor 64 MiB and 3 passes; device-aware ceiling; salt 16 random bytes | The RFC's recommended family; above its second recommended setting; libsodium's "moderate" and "sensitive" settings | 4.2 |
| E-D2 | A random 32-byte **storage key** (MSK), wrapped under the passphrase key | Passphrase change and parameter upgrade rewrite 363 bytes, never the journal | 4.3, 4.7 |
| E-D3 | **No verifier**; the wrap's tag is the check, with a **key commitment** beside it | Checking a guess costs a full Argon2id; no partitioning oracle | 4.6 |
| E-D4 | **XChaCha20-Poly1305** for every sealed object | 192-bit nonces; constant time in software everywhere | 5.1 |
| E-D5 | **Hedged nonces** (Bellare and Tackmann): nonce = HMAC(nonce key, 32 random bytes, associated data, plaintext), stored with the ciphertext | Random when the random source works; distinct contents get distinct nonces when it repeats | 5.2 |
| E-D6 | Every journal entry's associated data binds **file id, offset, kind, incarnation, sequence** | No moving, replaying or splicing without failure | 5.4 |
| E-D7 | The storage key is also wrapped in the journal header **under a key from the seed** | The 24 words alone reopen the journal | 5.3 |
| E-D8 | The append-only **mark file**, created at set-up, carries the journal's **high-water mark**, one entry appended before every **anchored batch** is confirmed; the guard file keeps epochs and indexes; counters for the bundle, the penalty file and the attempts file sit in the OS key store beside KB | A cut or rolled-back journal or penalty file is caught wherever its loss could cost money | 6, 8.7.3, 10 |
| E-D9 | The **24 words** are sealed under a key from the passphrase | Revealing them needs the passphrase typed for it | 9 |
| E-D10 | Exports: profile 1 (the person's) opens with the passphrase or the words and **carries the words only if chosen**; profile 2 (the host's copy) opens **only with the words** | The host is an adversary and must never hold anything a passphrase guess opens | 11 |
| E-D11 | **libsodium 1.0.21 or later**, built from the signed release | One library for Argon2id, XChaCha20-Poly1305, HKDF, guarded memory and wiping | 13 |
| E-D12 | Passphrase: NFC, at least **15 characters**, a blocklist, no composition rules; a generated six-word passphrase is the default offer | NIST SP 800-63B-4 as a floor; the offline attack is what matters | 4.1, 14 |
| E-D13 | **A locked wallet keeps watching, publishes its tree path in time and answers the host's old states**, from a watch-and-exit bundle that never holds an own commitment, under a key kept only in the OS key store. It **cannot finish an exit**: the last step needs an unlock by `unlock_by`. Not built in Slice 1 | A restart must not stop the protection; no copy of the bundle, of any age, can publish a revoked state | 8.7 |

## 2. Sources

Checked 2026-11-12 against the documents themselves.

| Short name | Document | Relied on for |
|---|---|---|
| RFC 9106 | Biryukov, Dinu, Khovratovich, Josefsson, "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106, https://www.rfc-editor.org/rfc/rfc9106 | The algorithm (3.1 to 3.5); "16 bytes is RECOMMENDED for password hashing" (3.1); section 4's FIRST RECOMMENDED (t = 1, p = 4, 2 GiB) and SECOND RECOMMENDED (t = 3, p = 4, 64 MiB) settings; the vector of 5.3 |
| RFC 8439 | Nir, Langley, "ChaCha20 and Poly1305 for IETF Protocols", https://www.rfc-editor.org/rfc/rfc8439 | The AEAD (2.8) and its vector (2.8.2); Poly1305's forgery bound |
| XChaCha | Arciszewski, draft-irtf-cfrg-xchacha-03, https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03 | HChaCha20 (2.2, vector 2.2.1); the AEAD (2.3, vector A.3.1); random 192-bit nonces |
| RFC 5869 | Krawczyk, Eronen, "HKDF", https://www.rfc-editor.org/rfc/rfc5869 | Subkeys; vector A.1 |
| RFC 7914 | Percival, Josefsson, "The scrypt Password-Based Key Derivation Function", https://www.rfc-editor.org/rfc/rfc7914 | The alternative considered (4.2) |
| RFC 8452 | Gueron, Langley, Lindell, "AES-GCM-SIV", https://www.rfc-editor.org/rfc/rfc8452 | The misuse-resistant alternative considered (5.1) |
| SP 800-38D | NIST SP 800-38D, section 8.3, https://csrc.nist.gov/pubs/sp/800/38/d/final | Random 96-bit IVs: at most 2^32 invocations per key |
| SP 800-63B-4 | NIST SP 800-63B-4, section 3.1.1 (password verifiers), https://pages.nist.gov/800-63-4/sp800-63b.html | "a minimum of 15 characters" for a single factor; at least 64 allowed; code points counted; NFC before hashing; no composition rules; a blocklist |
| SP 800-132 | NIST SP 800-132, section 5.1, https://csrc.nist.gov/pubs/sp/800/132/final | Salt with at least 128 random bits |
| UAX 15 | Unicode Standard Annex 15, https://www.unicode.org/reports/tr15/ | NFC |
| libsodium docs | https://doc.libsodium.org: "Password hashing" (`password_hashing/default_phf`), "XChaCha20-Poly1305", "Secure memory" (`memory_management`), "HKDF" (`key_derivation/hkdf`) | Presets (moderate 256 MiB about 0.7 s on a 2.8 GHz Core i7; sensitive 1 GiB); "save the actual parameters"; XChaCha's random nonces; `sodium_malloc`, `sodium_mlock`, `sodium_mprotect_noaccess`; `crypto_kdf_hkdf_sha256_*` |
| libsodium source | `stable` branch, https://github.com/jedisct1/libsodium/tree/stable: `crypto_pwhash/argon2/argon2.c` (`context.flags = ARGON2_DEFAULT_FLAGS`, which is 0), `argon2-core.c` (`clear_memory` only with `ARGON2_FLAG_CLEAR_MEMORY`), `randombytes_sysrandom.c` (`sodium_misuse()` on failure; `RtlGenRandom` on Windows) | Section 8.3's Argon2 memory, 5.2's random source (review F7, F13) |
| CVE-2025-69277 | F. Denis, "A vulnerability in libsodium", https://00f.net/2025/12/30/libsodium-vulnerability/ (fixed in 1.0.21) | The version floor (13) |
| Audit libsodium | Cryptography Engineering for Private Internet Access, "Libsodium v1.0.12 and v1.0.13 Security Assessment", 2017, https://www.privateinternetaccess.com/blog/libsodium-audit-results/ | No major findings in those versions; it predates years of changes (13) |
| Audit Monocypher | Cure53, MON-01, 2020, version 3.1.1, https://cure53.de/pentest-report_monocypher.pdf; https://loup-vaillant.fr/articles/monocypher-4 | Its Argon2id came after the audit (13) |
| OpenSSL Argon2 | `EVP_KDF-ARGON2(7)`, https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/ | Argon2id only from OpenSSL 3.2 (13) |
| Hedged | Bellare, Tackmann, "Nonce-Based Cryptography: Retaining Security when Randomness Fails", EUROCRYPT 2016 | The nonce construction of 5.2 |
| Commitment | Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021; Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022 | Key commitment of the wraps (4.6) |
| STREAM | Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015 | Chunked exports (11) |
| Padmé | Nikitin et al., PETS 2019 | Padding (open point 6) |
| OS calls | Linux `mlock(2)`, `madvise(2)`, `prctl(2)`, `setrlimit(2)`, `memfd_secret(2)`, `getrandom(2)`; `getentropy(2)` on macOS; Microsoft `VirtualLock`, `SetProcessWorkingSetSize`, `CryptProtectMemory`, `CryptProtectData`, `BCryptGenRandom`, `MoveFileExW`, `FlushFileBuffers`; Apple `F_FULLFSYNC`, `CSBackupSetItemExcluded`, the hardened runtime | Sections 7 and 8 |

Gazpacho documents used: `spec/journal.md` draft 3, `spec/local-api.md` draft 4, `spec/exit.md` draft 1 and its review (`docs/reviews/review-exit-d1.md`), `spec/safety-rule.md` (sections 4.3, 7, 9, C3 to C7), `spec/signing-round.md` 8 and 12.1, `docs/THREAT-MODEL.md`, `docs/DESIGN.md` 6, 9 and 13, `docs/OPEN-QUESTIONS.md`, `docs/notes/wallet-keys.md`, and on `main`: `CMakeLists.txt`, `wallet/CMakeLists.txt`, `core/superscalar/src/crypto_aead.c`.

**What is already linked** (`main`, 2026-11-12): libsecp256k1-zkp at a pinned commit, and the system's OpenSSL libcrypto (SHA-256, HMAC-SHA512, PBKDF2, RIPEMD-160, and ChaCha20-Poly1305 with a 96-bit nonce in the imported `crypto_aead.c` for BOLT 8). CI has OpenSSL 3.0.13, which has no Argon2id. Nothing else is vendored.

## 3. What is encrypted, and what a copy of the files reveals

### 3.1 The files

In the data folder unless stated.

| File | Holds | Treatment |
|---|---|---|
| `keys.gzk`, the key file | The wrapped storage key, the 24 words, the BIP 39 seed | Sealed (4.5). The only file whose opening needs the passphrase |
| `journal.gzj` | Every record of `journal.md` 9 and the API's records | Header authenticated, every entry sealed (5) |
| `guard.gzg` | Epochs, key indexes, rounds started | Sealed under a key from the seed (10.1) |
| `mark.gzm`, the mark file | The journal's high-water mark, one entry per anchored batch, appended | Sealed entries under a key from MSK (10.2) |
| `watch.gzw`, the watch-and-exit bundle | Tree paths, dates, fee children, known txids (8.7.2) | Sealed under a subkey of KB (8.7.3) |
| `watch.gzp`, the penalty file | Fully signed penalties against the host's revoked states, each with the journal position that recorded it, appended | Sealed entries under another subkey of KB (8.7.6) |
| `watch.gzl`, the watcher's log | What the locked watcher saw and did | Sealed under a third subkey of KB; untrusted on merge (8.7.4) |
| `*.newer` | A bundle or penalty file found newer than the journal, kept as evidence (8.7.4 rule 4) | As the file it was |
| `*.gzb`, exports and the host's copies | The journal's entries, the guard, in profile 1 optionally the words | Sealed (11) |
| `log.gzl`, the program's log | Diagnostic lines | Sealed like the journal (12.1) |
| `attempts.gza` | Count and times of wrong passphrases, a counter | Keyed under a KB subkey where KB is available, otherwise a checksum (12.3) |
| `first-run.html` | The first-run redirect file (`local-api.md` 4.3), only while no wallet exists | **Not encrypted**, owner-only, deleted at first use, expiry, stop and the next start |
| The socket token file | The local socket's bearer token | **Not encrypted**, owner-only, in a per-user runtime folder **outside** the data folder on every system (12.2) |
| `*.tmp`, `*.new` | Partial copies during an atomic replace or a rekey (4.8) | The format of the file they replace |
| Configuration | None: command-line options before unlock, journal records after | No file |

There is **no** `watch.key`: KB lives only in an operating-system key store (8.7.3), with the **store record** of counters beside it (8.7.3); neither is in the data folder.

### 3.2 What a copy of the files reveals

Someone who copies the data folder, once or repeatedly, learns without the passphrase (and without KB):

| Visible | Why |
|---|---|
| That this is Gazpacho, which network, which files belong together | Magic, chain hash and the random `vault_id`, `file_id`, `bundle_id`, `export_id` are clear so a file of another network is refused before anything is asked. They link files to each other and to nothing else |
| The Argon2id parameters and salts | Needed to derive; public by design |
| File sizes; the number, sizes and order of journal entries and penalty entries; the number of anchored batches | Clear lengths for the torn-tail scan. A batch's size hints at its records; the penalty file's entry count (its clear sequence numbers) is about the number of the host's revoked states, so roughly the number of channel updates; the mark file's length counts anchored batches, so roughly rounds and payments. Padding is open point 6 |
| The number of program starts and of batches | Incarnation and sequence are clear and authenticated (5.4) |
| How often the bundle was rewritten | Its clear `counter` (8.7.6) |
| When the program ran and wrote | File times; a synchronisation service's history |
| The number of restores | The guard grows 8 bytes per epoch |
| How many wrong passphrases were typed recently | `attempts.gza` |

It does not learn any record's contents, any key, the words, amounts, hosts, lobbies, dates, outpoints or history. Someone who also has KB (the person's OS account, 8.7.3) learns the bundle's contents: section 8.7.5.

### 3.3 The offline attack

A thief with `keys.gzk` (or a profile 1 export) tests passphrases offline. Each guess costs one Argon2id at the stored parameters: 256 MiB filled and read three times for the key file. As an order of magnitude [reasoning, not measured], a high-end graphics card with 24 GB holds about 90 such computations at once and is memory-bandwidth-bound to some hundreds to a few thousand guesses per second.

| Passphrase | Guesses (about) | At 1,000 guesses per second |
|---|---|---|
| A common or leaked password | In the first million | Minutes. The blocklist refuses these |
| A person-chosen 15-character phrase, typically 30 to 40 bits | 2^30 to 2^40 | Days to decades on one card |
| Six random words from a 7,776-word list (77.5 bits) | 2^77 | Far beyond any attacker |

Hence: the floor rules stop the worst choices, the interface offers the generated passphrase first (14), and the host never receives anything a passphrase opens (11). This holds only while the attacker has no Argon2 block from the program's memory (8.3, F7).

## 4. Keys

### 4.1 The passphrase

- **Normalisation.** NFC (UAX 15), then UTF-8, before anything else (SP 800-63B-4), so the same characters on two keyboards give one key (vector E1). Never trimmed or case-folded.
- **Where.** The interface applies `String.prototype.normalize("NFC")`; the program normalises again with a vendored copy of utf8proc (MIT) so every client gives the same bytes **(open, point 2)**.
- **Rules** at set-up and change (SP 800-63B-4, section 3.1.1): at least **15 code points** after NFC; at most 1,024 bytes; no composition rules; refused if, compared whole and case-insensitively, it is on the bundled blocklist (open point 3), is "gazpacho" or the wallet's name with or without digits, or contains three or more of the wallet's own 24 words in order. Typed twice. The reason for a refusal is said (14). SP 800-63B-4 is written for online verifiers; here these rules are only a floor, and the **generated six-word passphrase is offered first** (14). An entropy estimate in the refusal rules is open point 3.
- **Never stored, never logged.** Its buffers are wiped as soon as the helper process has it (8.4).

### 4.2 Passphrase to key: Argon2id

`PK = Argon2id(password = NFC passphrase in UTF-8, salt, t, m, p = 1, T = 32)`, version 0x13, no secret K and no associated data X: what libsodium's `crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13)` computes with `opslimit = t` and `memlimit = m × 1024`.

| Parameter | Value | Justification |
|---|---|---|
| Function | Argon2id | RFC 9106 section 4 uses it for both recommended settings: data-independent addressing in the first half pass, data-dependent after. scrypt (RFC 7914) was considered: one parameter sets both memory and time, its memory access depends on the password throughout, its RFC gives no parameters for this use, and libsodium's default moved to Argon2id in 1.0.15. libsodium has both, so no dependency argument favours scrypt |
| Memory m, key file | **262,144 KiB (256 MiB)**, **proposed** | The RFC's procedure: as much memory as can be afforded, then the passes. Four times the SECOND RECOMMENDED 64 MiB; libsodium's "moderate". The FIRST RECOMMENDED 2 GiB is too much beside a host service and later phones |
| Passes t, key file | **3** | The SECOND RECOMMENDED value; libsodium's tuning start |
| Profile 1 export | **1,048,576 KiB (1 GiB), 4 passes**, **proposed**, never below the key file's | libsodium's "sensitive"; opened rarely; the one file meant to leave the device (reviewer's view on choice 2). Bounded by the exporting device's ceiling |
| Lanes p | **1** | libsodium has one lane. The attacker's cost per guess is memory × passes and does not fall with fewer lanes. About 0.7 s at 256 MiB on a 2.8 GHz Core i7 (libsodium docs) |
| Salt | **16 bytes**, random, new at every wrap | RFC 9106 3.1; SP 800-132 |
| Output T | 32 bytes | Subkeys by HKDF (4.4) |
| Floor | t ≥ 3, m ≥ 65,536 KiB, `kdf` = 1, p = 1 | The SECOND RECOMMENDED setting. A file below it is refused before deriving |
| Ceiling | t ≤ 16; m ≤ min(4,194,304 KiB, `crypto_pwhash_memlimit_max()` / 1024, half of physical memory), computed in 64 bits, and `m × 1024` must fit `size_t` | A forged file cannot stall or exhaust the program; on 32-bit builds libsodium's limit is 2 GiB and `4 GiB × 1024` would overflow (review F9) |

**One rule for every Argon2id slot.** The floor and ceiling apply, before any derivation, to the key file and to every export slot (11) alike. A slot above the ceiling of this device is refused with "this file needs more memory than this device has; open it on a larger one".

**The test entry point**, which accepts any parameters for vectors (E2), is compiled only into test builds; a break-check proves a release binary refuses E2's key file (test 29).

**Calibration at set-up.** Three timings at the default; if their **median** exceeds 3 s, 131,072 KiB; if that median still exceeds 3 s, the floor, and the interface says the device uses the minimum setting. A device that cannot allocate 64 MiB cannot create a wallet (open point 4, phones). A device calibrated low while loaded is repaired only by the upward upgrade of 4.7.

### 4.3 The storage key

`MSK`, 32 bytes from the random source (5.2), made once with the wallet (or a restore, 9.3). Changing the passphrase or the parameters rewrites only the 363-byte key file (4.7).

### 4.4 Subkeys

```
derive(IKM, label, context) = HKDF-SHA256(salt = "gazpacho/v1/storage", IKM, info = label || 0x00 || context, L = 32)
keys(IKM, label, context)   = ( derive(IKM, label, context), derive(IKM, label || " nonce", context) )
```

Implemented with libsodium's `crypto_kdf_hkdf_sha256_extract` and `_expand` (13). Labels are ASCII without NUL, so `info` is injective. Every key used with `seal` (5.2) comes as a pair from `keys`: the second is its **nonce key**, from the same input keying material under its own label (review F14).

| Key | IKM | Label | Context | Seals |
|---|---|---|---|---|
| — | PK | `key file commitment` | chain, vault_id | Key commitment, not a sealing key (4.6) |
| KW | PK | `key file wrap` | chain, vault_id | MSK in the key file |
| KD | PK | `words` | chain, vault_id | The words' entropy |
| KS | MSK | `node seed` | chain, vault_id | The BIP 39 seed |
| KBK | MSK | `watch key record` | chain, vault_id | KB's recovery copy in the key file (8.7.3; a later format of 4.5) |
| KJ | MSK | `journal` | chain, file_id | Journal header and entries |
| KL | MSK | `log` | chain, file_id of the log | Log entries |
| KH | MSK | `high water` | chain, file_id of the journal | Mark file entries (10.2) |
| KR | seed | `journal recovery` | chain, file_id | MSK in the journal header |
| KG | seed | `guard` | chain | The guard file |
| BK | seed | `backup` | chain | Root of every export (not a sealing key) |
| EK | BK | `export` | chain, export_id | One export's chunks |
| — | PKx | `backup commitment` | chain, export_id | Key commitment of a profile 1 slot |
| KX | PKx | `backup wrap` | chain, export_id | BK in a profile 1 slot |
| KWB | KB | `watch bundle` | chain, bundle_id | The bundle |
| KWP | KB | `watch penalties` | chain, file_id of `watch.gzp` | Penalty file header and entries |
| KWL | KB | `watch log` | chain, file_id of `watch.gzl` | The watcher's log |
| KA | KB | `attempts` | chain | The attempts file's tag (12.3; HMAC key, not a sealing key) |

"seed" is the 64-byte BIP 39 seed (empty BIP 39 passphrase). PKx is Argon2id over the export slot's own salt and parameters. No storage key is ever a signing key; BIP 32's master derivation is HMAC-SHA512 keyed with "Bitcoin seed", a different function and key.

### 4.5 The key file `keys.gzk`

363 bytes, big-endian.

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZKEYFIL` |
| 8 | `format` | 1 | 1 |
| 9 | `chain` | 32 | |
| 41 | `vault_id` | 16 | Random |
| 57 | `kdf` | 1 | 1 = Argon2id 0x13 |
| 58 | `t` | 4 | |
| 62 | `m` | 4 | KiB |
| 66 | `p` | 1 | 1 |
| 67 | `salt` | 16 | |
| 83 | `commitment` | 32 | HMAC-SHA256(derive(PK, `key file commitment`, chain ‖ vault_id), bytes 0..82) |
| 115 | wrapped MSK | 24 + 32 + 16 | `seal(KW, MSK, ad = bytes 0..82)` |
| 187 | words | 24 + 32 + 16 | `seal(KD, entropy, ad = bytes 0..82)` |
| 259 | seed | 24 + 64 + 16 | `seal(KS, seed, ad = bytes 0..56)` |

The seed's associated data stops before the KDF fields, so a passphrase change copies bytes 259 to 362 unchanged (E8).

**Opening:** (1) length, magic, format, chain (a wrong chain is refused before the passphrase is asked); (2) the parameters against 4.2's floor and ceiling; (3) PK in the helper process (8.4); (4) the commitment, in constant time; (5) the wrap with KW; (6) the seed with KS. Failures at 4 or 5 give the one message "wrong passphrase or damaged key file"; a failure at 6 is "damaged key file". The words are opened only by 9.2.

### 4.6 The passphrase check and key commitment

No hash of the passphrase, PK or MSK is stored. A guess is tested by the commitment and the wrap's tag, both of which need the full Argon2id.

**Key commitment** (review F12). Poly1305 is not key-committing: a ciphertext can be built that opens under several keys (Commitment). An attacker who writes a key file or an export whose wrap opens under k candidate passphrases, and watches whether the person's program opens it, would learn whether the passphrase is among them. The 32-byte commitment, an HMAC under a key derived from PK over the header, opens for exactly one PK except with negligible probability, so a file can test one candidate per derivation, as an honest file does. It is not a fast verifier: computing it needs PK.

While unlocked, sign-in and fresh sign-in run the same derivation against the key file on disk and compare the resulting MSK with the one in memory in constant time (`sodium_memcmp`). At most one derivation runs at a time.

### 4.7 Upgrade and passphrase change

- **Parameters of a new wrap**: max(stored, the device's calibrated default), never lower (review F18).
- **Upgrade** after a successful unlock when the stored parameters are below that: new salt, new parameters, a second derivation (about one more second), then the commitment, the wrap **and the words** re-sealed under the new PK; MSK and the seed bytes unchanged.
- **Passphrase change** (fresh sign-in): the old passphrase opens the words and the wrap; the new one, after 4.1's rules, gives a new PK under a new salt; the program writes a new key file with the same `vault_id`, MSK, seed bytes and words. The journal is not touched.
- Both are atomic replaces (7.3).
- A copy of the old key file still opens with the old passphrase and holds the same MSK (E8). If the old passphrase may have leaked with a copy of the files, the person needs a **new storage key** (4.8), and the interface says so.

### 4.8 A new storage key (1.0.0)

Every file that names a journal position or is sealed under a replaced key is rewritten in the same switch (review R2-11); otherwise the first start after a rekey would find the mark file naming another `file_id` (6.3 step 2) and force a restore.

1. Write, each under a temporary name and each synced: `journal.gzj.new` (new `file_id`, entries re-sealed at the same offsets, so every sync mark keeps its offset); `mark.gzm.new` for the new `file_id` under the new KH, with one entry naming the journal's last sync mark; under a **new KB**, `watch.gzw.new` (B1 naming the new `file_id`) and `watch.gzp.new` (a new penalty `file_id`, every entry's journal `file_id` replaced, sequence numbers unchanged); and `keys.gzk.new` (new `vault_id`, the new KB's recovery copy when that format exists).
2. Add the new KB to the OS store as **pending**, beside the current one, with its store record (counters copied, the new penalty `file_id`) and the new `vault_id`.
3. Rename the key file, then the journal, the mark file, the bundle and the penalty file; sync the folder.
4. Make the pending KB current in the store and delete the old one.

On start, a pending KB in the store means a switch was interrupted. If `keys.gzk` already carries the pending `vault_id`, the renames were under way: the start completes the remaining renames from the `.new` files and then step 4. Otherwise no rename happened: the start deletes the `.new` files and the pending KB and goes on from the old set, which was never touched. `.new` files with no pending KB are deleted. The guard file is sealed under a key from the seed and needs no rewrite. Old exports keep their own keys. The crash order is to be proven by fault tests **(open, point 5)**.

## 5. The journal

### 5.1 The AEAD

**XChaCha20-Poly1305**: HChaCha20 over the key and the first 16 nonce bytes, then RFC 8439's ChaCha20-Poly1305 with nonce `0^4 ‖ n[16..24]` (XChaCha 2.3); libsodium's `crypto_aead_xchacha20poly1305_ietf_*`.

| Considered | Against it here |
|---|---|
| AES-256-GCM | Random 96-bit nonces limited to 2^32 per key (SP 800-38D 8.3); a repeat reveals the authentication key; constant time only with AES instructions |
| AES-256-GCM-SIV (RFC 8452) | Misuse-resistant, but not in libsodium, in OpenSSL only from 3.2, and needs AES instructions for constant time. 5.2's hedging gives the property that matters |
| ChaCha20-Poly1305, 96-bit nonces (OpenSSL, linked) | Safe at a journal's volume with random nonces, but no margin; XChaCha's margin costs 16 bytes per entry |

### 5.2 Nonces

```
seal((K, NK), plaintext, ad) = nonce || XChaCha20-Poly1305-Encrypt(K, nonce, plaintext, ad)
nonce = first 24 bytes of HMAC-SHA256(NK, r || u32(len(ad)) || ad || plaintext)
```

`r` is 32 fresh bytes from the **storage random source**: the program's own function over `getrandom(2)` (Linux, blocking until the pool is ready), `getentropy(2)` (macOS) and `BCryptGenRandom(NULL, …, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` (Windows). Each returns an error rather than aborting, so a failure becomes a storage failure (7.5). libsodium's `randombytes_buf` is not used for storage: it aborts on failure, and on Windows it uses `RtlGenRandom` (review F13).

- **With a working source** the nonce is a pseudo-random function of fresh randomness: a random 192-bit nonce (2^80 messages for a 2^-32 collision chance).
- **If the source repeats** (a virtual machine resumed twice, a broken generator), different entries still get different nonces, because the associated data (with the offset) and the plaintext are inputs; only byte-identical (ad, plaintext) pairs repeat, and then the ciphertext is identical too. This is the "nonce = PRF(K, R, AD, M)" hedge of Bellare and Tackmann. The encoding is injective: fixed 32-byte r, length-prefixed ad, plaintext last.
- **Why not counters.** After a torn tail is cut, the next start writes a different incarnation entry at the same offset under the same number (`journal.md` 5). A counter or offset nonce would repeat there.

A reader uses the stored nonce and never recomputes it.

### 5.3 The journal header

Replaces `journal.md` 2.1. 185 bytes, written once.

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZJOURNE` |
| 8 | `format` | 1 | 1 |
| 9 | `chain` | 32 | |
| 41 | `vault_id` | 16 | The key file's |
| 57 | `file_id` | 16 | Random |
| 73 | recovery | 24 + 32 + 16 | `seal(KR, MSK, ad = bytes 0..72)` |
| 145 | header tag | 24 + 16 | `seal(KJ, empty, ad = bytes 0..144)` |

Magic, format and chain are checked before anything is asked; after unlock, the header tag under KJ. A failure there is "this journal is not this wallet's", distinct from corruption. The recovery wrap lets the 24 words alone reopen an intact journal if the key file is lost or the passphrase forgotten (9.3); it weakens nothing, since the seed already spends everything.

### 5.4 Entries

Replaces `journal.md` section 3's framing. Big-endian.

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0 | `length` | `u32` | 57 + payload length. At least 61; exactly 65 for kinds 1 and 3; at most 8,388,665 |
| 4 | `kind` | `u8` | 1 incarnation, 2 batch, 3 sync mark |
| 5 | `incarnation` | `u64` | |
| 13 | `sequence` | `u64` | |
| 21 | `nonce` | 24 | 5.2 |
| 45 | ciphertext | `length` − 57 | The payload of `journal.md` 3.1 to 3.3 |
| 4 + `length` − 16 | `tag` | 16 | |

**Associated data** = `file_id` (16) ‖ `u64` offset of the entry ‖ bytes 0 to 20 of the entry. The offset makes every entry valid only where it was written (E7c, E7e) and self-locating; the file id rejects entries from another journal even under the same storage key (E7d); the clear kind, incarnation and sequence are authenticated (E7b). The tag replaces the 8-byte checksum and detects tampering, which the checksum could not. Incarnation entries and sync marks are 69 bytes.

### 5.5 Reading

`journal.md` section 5 applies with "valid" meaning: the length rules above, a known kind, the tag verifies under KJ at the entry's offset, and a sync mark's decrypted offset equals its own. The torn-tail search tries a 69-byte candidate with `length` 65 and `kind` 3 at each offset after the damage. Order rules are checked on decrypted, authenticated entries.

### 5.6 What is detected, and what is not

| Attack on the journal file | Result |
|---|---|
| Change any byte of an entry | Invalid; corruption before a valid mark, torn tail after the last one (E7a, E7b) |
| Move, swap or replay an entry | Invalid at the new offset (E7c, E7e) |
| Splice an entry from another journal | Invalid (E7d) |
| Drop an entry from the middle | Every later entry fails; corruption if a later mark survives |
| Cut at an entry boundary, or cut inside an entry and remove the rest | A valid shorter journal or a torn tail: **not detectable from the journal alone** (E7g); section 6 |
| **Damage a confirmed entry and every later sync mark** | Reads as a torn tail, so the tail is cut (E7h). It is the same as a cut and is caught only where the high-water mark covers it (section 6). The answer to checklist item 5 is therefore "yes, outside anchored batches" (review F25) |
| Replace the file with an older complete copy | Not detectable from the journal alone; section 6 |
| Replace the header | Fails the header tag, or the recovery wrap names another seed |

## 6. Rollback

### 6.1 The limit

An older copy of a journal, or today's journal cut at an entry boundary, is a valid journal. No cryptography inside the file tells older from current; it needs state the attacker did not also roll back. It matters for safety: an old journal is an unmarked restore (`safety-rule.md` R1); the node would trust a stale key index, stale round records, a stale held set, or an old channel commitment that has since been revoked.

### 6.2 The high-water mark and the anchored batches

The **mark file** `mark.gzm` (10.2; created at set-up, 7.4) holds the journal's high-water mark: for each **anchored batch**, one appended entry naming the current incarnation and the offset of the sync mark covering that batch. The storage layer appends and syncs it after the mark's sync and before confirming the batch (7, step 2). An anchored batch is a batch holding any record of the families below.

| Anchored family | Why its silent loss could cost money |
|---|---|
| `guard` (with `key_index`, `round_started`) | A key or a round identifier used twice (`signing-round.md` 3, R2) |
| `exposure` | A second tree signed on one funding output (C7) |
| `round_signed` | The held set lost (C3): the member could not leave alone |
| `funding_signed` (host) | The host would not know it had signed and perhaps broadcast its funding: it would not rebroadcast it, and could treat the creation as unfunded and release the coins its `funding_plan` holds back while members wait for that funding (review R2-7) |
| `start_sent` (host) | The host could sign a second, different `start` for one ready check, which members record as `host_fault` (`journal.md` 9) |
| A saved own commitment (channel engine) | The node would believe an older commitment is current and, on a later force close, publish a revoked state |
| A released revocation of the member's own commitment | The same, from the other side |
| A received host revocation (and its penalty, CH-5) | A revoked host state could no longer be answered |
| A payment's released or received secret (channel engine) | An incoming payment whose secret was released could not be claimed on chain; to be listed in `spec/exit.md` 10.1's CH list |

**What a cut can lose** (review R2-7). A mark entry proves that the journal reached a sync mark; every batch before that mark is covered by it, whatever its family. So a cut, or an older copy that the mark file catches, can lose only the batches written **after the newest anchored batch**. The families that may sit there, and why each is safe to lose (they are lost at worst, never forged):
- lobby and terms records: a seat may be lost; joining again uses a new key under R2;
- `funding_status`: re-read from the chain;
- `ack_received` (host): the funding is never signed without every ack (H1), and `funding_signed` is anchored, so a lost ack can only be one the funding does not yet rest on; the host asks again and the member resends its saved `round_ack` bytes;
- activity and settings: history only;
- the API's request ids: an id whose action moves money is saved in that action's own batch, which is anchored if the action is;
- `restored` and `key_epoch`: in the same batch as the first `guard` after a restore.

A record family added later is anchored if its loss could make anything be signed or published that should not be; the channel and exit specifications list theirs.

**Cost** (review R2-8). One append of 56 bytes and one sync per anchored batch, after the journal's own two syncs: a few per round and about three per payment (own commitment, released revocation, host revocation with its penalty append), fewer where group syncing (`journal.md` 4) covers several batches with one append. The guard file is replaced (temporary write, two syncs, a rename) only for batches with a `guard` record, which are rare. `option_data_loss_protect` does not make the mark redundant: an exit at a deadline while the host is unreachable gets no data-loss check. To be measured on macOS with `F_FULLFSYNC` and on a host with many channels **(open, point 16)**.

### 6.3 The start rule

After the key file opened (4.5) and before the journal is scanned:

0. **No journal.** A key file with no journal always starts as a **restore** (review R2-2): a new journal, then `journal.md` 8.2's first batch (`key_epoch` with a new random epoch, `restored`, `guard`), a new mark file, and the guard's epoch list kept if a guard file opens. This covers a crash during set-up between the key file and the journal, which costs nothing (no key was used under epoch 0, and the words were not yet shown, 7.4), and a journal and guard deleted together, which would otherwise restart at epoch 0 and reuse its keys.

After the scan and any torn-tail cut, before `gz_node_start`:

1. Open the guard file with KG and the mark file with KH. If either is absent, or the mark file has no valid entry or a damaged one (10.2), and a key file exists, the journal is **possibly old** (review F6).
2. The journal is **behind** if: the mark file names another journal `file_id`; or its newest entry's incarnation is above the journal's highest; or its newest entry's mark offset is not the offset of a valid sync mark of that incarnation in the journal (the set-up entry (0, 0) means "no mark yet" and passes); or the guard's `counter` is above the newest `guard` record's in the journal. A legitimate torn-tail cut never trips this, because a mark entry is written only after its sync mark was synced.
3. The same tests with the bundle's B1 and with the journal position in the penalty file's newest entry (8.7.6): a bundle or penalty file made from a journal position the journal does not reach is evidence the journal is **behind**. That evidence is kept as `.newer`, never overwritten (8.7.4 rule 4).
4. Behind, or possibly old: the node is not started, the keys are dropped and the watcher runs again (8.2), from the `.newer` bundle where one was kept. The interface says (`local-api.md` `files_behind`): "These files are older than this wallet's last saved state. Gazpacho can start them as a restore, with new keys, or stay locked so you can put the newer files back." **Start as a restore** (`local-api.md` `POST /api/v1/wallet/start-as-restore`, with the passphrase) is `journal.md` 8.2's: the program starts on this journal with a restore marker and a new epoch (R2 to R5), the guard keeps its epoch list, the mark file is started again with an entry for the restore batch, and the `.newer` files stay for `spec/exit.md` 5.7 item 4. Staying locked changes nothing on disk.
5. Otherwise the start goes on.

Vector E9m shows E7g's and E7h's journals refused by the mark file.

### 6.4 What remains

- **The whole data folder rolled back** (Time Machine, File History, a VM snapshot, a cloud service's "previous versions") is not detected locally: the journal, the guard and the mark file go back together. This is `journal.md` 8.2's "copy made by other means". The same holds for an older copy of the mark file alone, or one cut back at an entry boundary, which reads as a valid shorter file (E9m).
- **What the store record adds.** The bundle counter, the penalty count and the attempts counter sit in the OS key store (8.7.3), outside the data folder, so a folder rolled back alone is caught for those three (8.7.4 rule 7, 12.3). A rollback of the whole OS account (its key store included), or any process running as the person, defeats them too.
- Done: the data folder sits in the per-user, non-roaming application folder (`%LOCALAPPDATA%`, `~/Library/Application Support`, `$XDG_DATA_HOME`); on macOS it is excluded from Time Machine (`CSBackupSetItemExcluded`); elsewhere the interface says not to restore the folder from a system backup.
- **Proposed further anchors (open, point 7):** the journal's own high-water mark in the store record as well (one store write per anchored batch, to be measured); TPM counters; and, for `safety-rule.md` 9, asking the host at each connection for the newest round, key index and channel state it has seen from this member, and treating "the host knows something newer" as a restore (a lying host can force only a harmless restore). `option_data_loss_protect` (required by `spec/exit.md` 5.7) already covers channels this way.

## 7. Crash safety

Encryption is a step inside `journal.md` 4's step 1; its order rules hold.

1. **Append**: the entry is sealed whole in memory, then written; a torn write fails its tag.
2. **Sync, mark, sync, confirm** as in `journal.md` 4. For an anchored batch, after the mark's sync and before the confirmation, in this order: append and sync the mark file's entry (10.2); replace the guard file if the batch holds a `guard` record; replace the bundle if the batch changes it; append and sync the penalty entry if the batch holds a host revocation, then update the penalty count in the store record (8.7.3). A failure at any of them is a storage failure (5). Nothing outward is released before the confirmation.
3. **Atomic replaces**: `name.tmp` created exclusively, owner-only from creation, synced, renamed over the name, folder synced (POSIX). Windows: `FlushFileBuffers`, then `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. macOS: `F_FULLFSYNC`. **Appends** (journal, mark file, penalty file) cut any torn tail first, then append and sync.
4. **Creation order**: entropy, seed, MSK, `vault_id`, KB; store KB and a fresh store record in the OS store; write `keys.gzk`; write `guard.gzg` (counter 0, no epochs); choose the journal's `file_id` and create `mark.gzm` for it with its set-up entry (0, 0) (temporary name, sync, rename, folder sync); create the journal the same way. A crash anywhere after the key file and before the journal's rename: the next unlock finds a key file with no journal and starts **as a restore** (6.3 step 0; review R2-2), which loses nothing, because no key was used and the words were not yet shown; a stale mark file naming no existing journal is replaced. A journal without a key file: "the key file is missing", and the words reopen it (9.3). The words are shown only after all exist.
5. **Random-source failure** is a storage failure (`gz_runner_storage_failed`); no fallback.
6. **A failed tag is never repaired**: torn tail (cut) or corruption (refused).
7. **No retry** of a failed seal or sync.

`journal.md` tests 7 to 14 and 25 to 27 run unchanged on the encrypted format; J4 and J6 correspond to E7f and E7a.

## 8. Locked and unlocked; keys in memory; the watcher

### 8.1 States

| State | Keys in memory | What runs |
|---|---|---|
| **No wallet** | None | First-run calls only |
| **Locked** (after every start; after "lock the wallet"; after an unlock that did not start the node, 8.2) | Only KWB, KWP, KWL and KA, opened from KB in the OS store. Not the passphrase, PK, MSK, the seed or the words | **The watcher** (8.7), never the node: it cannot read or write the journal and signs nothing. **Slice 1 builds no watcher**: a locked Slice 1 wallet watches nothing and says so (`local-api.md` 4.7, reason `no_bundle`) |
| **Unlocked** | MSK; KJ, KL, KG, KH; the storage layer's copy of the seed; the KB subkeys | The node; the watcher is stopped (`spec/exit.md` W1). Signing out of the browser does not lock |

"Lock the wallet" follows `spec/exit.md` 5.6 and W1: **held** (not refused) while an incoming payment's secret is released and unsettled, after new payments are stopped; held too while partial signatures are out in a round (`local-api.md` 4.7); otherwise the node stops, the bundle and the penalty file are checked current (8.7.4 rule 3), the journal, mark file and log are closed, every key except the KB subkeys is wiped, and the watcher starts.

### 8.2 The operations `local-api.md` uses

| Operation | Does |
|---|---|
| **set up**(passphrase) | 4.1's rules; 7.4's creation order |
| **unlock**(passphrase) | The order below |
| **start as restore**(passphrase) | After an unlock that found the journal behind or possibly old: 6.3 step 4's restore, then the order below from step 4 |
| **check**(passphrase) | While unlocked: 4.6's comparison |
| **drop** | 8.1's lock |
| **words**(passphrase) | 9.2 |

At most one derivation at a time, in the helper process (8.4); at most one queued.

**The unlock order** (`spec/exit.md` W1 and W3; `local-api.md` 4.7 follows it). In Slice 1, which has no watcher, steps 2, 5 and 6 do nothing and "the watcher runs again" means only that the keys are dropped:
1. **Derive and open the key file** (4.5) while the watcher keeps running. A wrong passphrase, a damaged key file or a helper failure changes nothing: the watcher never stopped.
2. **Stop the watcher.** It writes its last `watch.gzl` entry and closes; from here the node and the watcher never run at once.
3. **Open the journal**: header (5.3), scan, the start rule (6.3). If the journal is behind or possibly old (6.3 step 4), or corrupt (`journal.md` 5), or storage fails: wipe every key but the KB subkeys, **start the watcher again** (from the `.newer` bundle where one was kept), and answer with that state. The node is not started.
4. **Start the node** from the journal (`gz_node_start`), connected to nothing yet; then **connect the chain servers**, which every later step needs.
5. **Merge `watch.gzl`** in one batch as untrusted input (8.7.4 rule 6): each claim becomes a record only once the chain confirms it.
6. **If the chain shows the member's own leaf kickoff or leaf transaction confirmed**, the channel output unspent and something to take out (whether the watcher or someone else published them), that batch also records the exit (`spec/exit.md` W3): the channel is frozen and the node completes, saves and broadcasts the commitment as soon as the leaf transaction is confirmed, **first**, before anything else and **whatever the saved pause says** (pause never delays an exit, `spec/exit.md` 5.4). The decision is taken from the chain, never from the log alone.
7. **Apply the saved pause** (`local-api.md` 7.5, 11.3).
8. **Record the dates that passed** while locked (`local-api.md` 4.7).
9. **Connect the hosts.**

A failure after step 4 (a storage failure, a refused step) is the node's ordinary stop (`DESIGN.md` 4): the node stops and is rebuilt from the journal; while it cannot be, the keys are wiped and the watcher runs again, as at a lock.

### 8.3 Memory rules

- **Storage-layer secrets** (the passphrase, PK, MSK, every subkey of 4.4, the storage layer's copy of the seed, the words) live only in memory from `sodium_malloc` (guard pages, a canary, locked pages where allowed) and are `sodium_mprotect_noaccess` between uses. **Keys derived in the core and the wallet library** (factory, contribution and channel keys, BIP 32 intermediates, MuSig2 state, OpenSSL HMAC and PBKDF2 contexts, libsecp256k1 objects) live in ordinary heap and stack memory and are wiped by the wallet library's own rules (`wallet-keys.md` 5); the core may not call libsodium (13). The claim is restricted accordingly (review F8).
- **Wiping.** `sodium_memzero` on every buffer that held a storage-layer secret, at the end of each use and on every error path; request bodies that held a passphrase or words are wiped before they are freed and never copied into a log, an error or an event.
- **Argon2id's memory** (review F7). libsodium's `crypto_pwhash` calls Argon2 with no flags, so its blocks are **not** zeroed: they are unmapped where mmap exists and returned to the heap otherwise. The first block of each lane is a function of the passphrase that lets guesses be tested at BLAKE2b speed, removing the memory hardness. So the derivation runs in a **helper process** (8.4) and never in the main process.
- **Swap.** `sodium_malloc` locks its pages. If locking fails the program carries on and shows "memory not locked", because refusing would stop the watching. Linux raises `RLIMIT_MEMLOCK` to the hard limit; Windows raises the minimum working set. The KDF helper asks for its own pages to be locked (8.4); the flag also turns false when that is refused.
- **Core dumps and debuggers.** Before reading any file: `setrlimit(RLIMIT_CORE, 0)`; Linux `prctl(PR_SET_DUMPABLE, 0)`, which also blocks same-user `ptrace`; `MADV_DONTDUMP` on `sodium_malloc` pages. macOS: `RLIMIT_CORE` 0, and a release signed with the hardened runtime and without `get-task-allow`, so same-user processes cannot obtain its task port.
- **Logs** never contain a key, passphrase, words, nonce input, plaintext record or ciphertext.
- **Not defended:** a same-user attacker while unlocked (process memory, keyloggers), hibernation files and kernel crash dumps, cold-boot attacks, a crash dump of the helper during its second of work, and **the helper's Argon2 blocks in swap or the pagefile** when the system refuses to lock them (review R2-6): 256 MiB to 1 GiB written during the helper's life stays in swap after it exits, and one block lets guesses be tested at BLAKE2b speed (F7). Full-disk encryption covers all of these at rest and is recommended: on Windows that means BitLocker, because the pagefile is otherwise not encrypted; on Linux an encrypted swap; macOS encrypts its swap by default.
- **Later:** Linux `memfd_secret(2)` for MSK and the seed copy **(open, point 8)**.

### 8.4 The passphrase in transit and the helper process

The browser sends the passphrase in a request body over loopback; the program reads it into a `sodium_malloc` buffer (at most 4 KiB), normalises it into another, wipes the first, and starts the **KDF helper**: the same executable in a hidden mode, started with core dumps off and, on Linux, `PR_SET_DUMPABLE` 0, set by the helper itself **after** `execve` (which restores dumpability) and before it reads the pipe. Before allocating, the helper asks for its pages to be locked: `mlockall(MCL_CURRENT | MCL_FUTURE)` on Linux and macOS after raising `RLIMIT_MEMLOCK` to its hard limit, so the blocks `crypto_pwhash` maps later are locked too. Windows has no such call for memory allocated inside libsodium: the helper raises its minimum working set above the derivation's size (`SetProcessWorkingSetSize`), which makes paging unlikely but does not forbid it. Refused or partial locking does not stop it (8.3, "memory not locked", and the not-defended list). The passphrase, salt and parameters go to it over a pipe; it runs `crypto_pwhash` and writes back the 32-byte PK only, then exits. A helper that crashes, runs out of memory or returns nothing is reported as "the passphrase could not be checked" and does **not** count as a wrong passphrase; the operating system reclaims its pages (they are zeroed before any reuse by another process). The main process wipes its copy of the passphrase when the helper has read it. On Windows the helper is a child process of the same image, created suspended with no inherited handles but its pipes. Cost: one process start per derivation, milliseconds beside the derivation's second. The command line reads the passphrase with echo off or from a file descriptor, never from an argument.

### 8.5 Windows specifics

- Data folder under `%LOCALAPPDATA%\Gazpacho`, never roaming or OneDrive-redirected; files created with an owner-only security descriptor and no inherited entries.
- `LockFileEx`, `FlushFileBuffers`, `MoveFileExW` write-through (7).
- Storage randomness from `BCryptGenRandom` (5.2); libsodium itself uses `RtlGenRandom`.
- `VirtualLock` through `sodium_mlock`, with the working-set adjustment; locked pages still reach the hibernation file.
- Crash dumps: the program does not change Windows Error Reporting settings. MSK and the seed copy are also kept encrypted in place between uses with `CryptProtectMemory(…, CRYPTPROTECTMEMORY_SAME_PROCESS)` (sizes are multiples of 16) **(proposed)**.
- KB and the store record in the Credential Manager (`CredWriteW`, a generic credential of the current user, persisted on this machine only), which the system protects with DPAPI and keeps outside the data folder (8.7.3). Draft 2 put a DPAPI blob in `%LOCALAPPDATA%`, where an older copy of the folder tree could put the counters back.
- The socket token in a runtime folder under the user's temporary folder, outside `%LOCALAPPDATA%\Gazpacho` (12.2; review R2-10).

### 8.6 Requirements on `local-api.md`

1. The words calls carry the passphrase in their own body, because the words key is never kept (9.1) **(open, point 9)**.
2. Unlock, check and set-up take a second or more; at most one at a time.
3. `GET /api/v1/status` while locked, with no session, shows the watcher's state (`watching.state`, its reason, the headline) and, **only to a connection that passed the same-user check** (`local-api.md` 3.4) or to the local socket, the dates the watcher reads from the opened bundle: `leave_by_locked`, `unlock_by` and the next action. Nothing date-like, and no count of factories, where the peer check is unavailable. No amounts, outpoints or addresses ever. No date is stored in the clear (8.7.6).
4. The attempts file is 12.3's; the passphrase rules are 4.1's, with 14's refusal reasons.
5. A locked wallet runs the watcher (8.7); it signs nothing new, does not talk to the host, takes part in no round and accepts no payment. **Slice 1 builds no watcher**: its locked status says nobody watches, reason `no_bundle`.
6. The unlock order of 8.2, including the answers for a journal found behind or possibly old (`files_behind`, with the call that starts it as a restore) and for an unlock that fails after the watcher stopped.
7. The locked headlines and reasons of 8.7.1 and 8.7.3.
8. **Unattended unlock** for a host service (`--passphrase-fd`, from a service manager's protected store such as systemd `LoadCredentialEncrypted`), for hosts only, shown in the interface **(open, point 10)**.

### 8.7 Watching while locked: the watch-and-exit bundle

**The hazard.** A locked program cannot read the journal. Without more, a restart while the member is away would stop the watching and the automatic exit the design rests on (`DESIGN.md` 6; `safety-rule.md` 7). The answer is a separate, small sealed file the locked program can read, which `spec/exit.md` 5.6 fills.

#### 8.7.1 What the locked watcher can and cannot do

From `spec/exit.md` 5.6, which this document adopts.

| Can | Cannot |
|---|---|
| Read the bundle and the penalty file with the KB subkeys | Read or write the journal or the key file's secrets |
| Watch every outpoint and txid in them through the bundle's chain servers, with the clock and `spec/exit.md` 4.5's tip estimate | Talk to the host or any peer |
| Publish the member's **tree path** (tree transactions only, kinds 1 to 3) and each step's keyless anchor child by `leave_by_locked`, and climb the pre-signed fee ladder if fee coins were set aside | **Publish the member's commitment**: it holds none (invariant T). Under the taproot channel format the member never holds a final signature on its own commitment (`safety-rule.md` 4.3); completing one needs its key. So the watcher **cannot finish an exit**: the commitment needs an unlock by `unlock_by` |
| Publish a fully signed penalty when a revoked host commitment appears | Sign anything: no new child, fee level, claim or sweep |
| Recognise a co-signed close or rotation close of the exposed set (B9) and recompute its dates | Claim an incoming payment, sweep, or change the bundle |
| Write what it saw and did to `watch.gzl` | Answer any API call but status and sign-in |

**Slice 1 builds none of 8.7** (shared decision with `local-api.md` draft 4 and `spec/exit.md` draft 2): a locked Slice 1 wallet writes no bundle and runs no watcher, and its locked status says nobody watches, reason `no_bundle`. The rest of 8.7 is 1.0.0.

**What the strip says** is `local-api.md` 4.7's headline table: `spec/exit.md` 5.6's rows, first match wins (among them a tree step late while locked: "Unlock now. Leaving a factory is behind and needs a higher fee, which Gazpacho can only pay once unlocked", `at_risk`), extended with rows for a short penalty file (rule 7) and for files behind (6.3), and `doing.params.watcher = waiting_for_unlock` for the row "Unlock now. Only the last step of leaving a factory is left, and it needs your passphrase. After block H_leaf the host can take this balance." Always locked, no amounts; while a bundle is armed `watching.state = watcher_locked` with `unlock_by`. **A locked wallet never leaves in time on its own**: it publishes the tree path and answers the host's old states, and the person must unlock by `unlock_by` to finish.

#### 8.7.2 Contents and invariant T

The records are `spec/exit.md` 5.6's ("Bundle records"); the items, by number:

| Item | What | Note |
|---|---|---|
| B1 | Header: chain, `bundle_id`, `counter`, journal `file_id`, sync-mark offset, `made_at_height`, `constants_version`, `made_after_restore_marker` | 8.7.4 |
| B2 | Chain servers, quorum, tip slack | |
| B3 | Per factory: local number (never the lobby id or host key), funding outpoint, amount, script, state, funding deadline | |
| B4 | **The tree path only**: fully signed tree transactions (fixed kickoff, leaf kickoff, leaf transaction), each with its anchor and keyless anchor-only child | No commitment step |
| B5 | Dates and constants: `d`, `H_leaf`, `last_safe_confirm`, `leave_by`, `leave_by_locked`, `unlock_by`, the commitment's latest send height (a height, never bytes), and B, A, M_safe, M_lag, M_spike, M_locked | `spec/exit.md` 4 |
| B6 | **Penalties only**: per revoked host commitment, the fully signed penalty as a ladder of fee rates (`spec/exit.md` CH-5; every rung pays the member, so the ladder is safe under T), with its trigger txid and send-by delta; second-stage penalties only where `channel.md` fixes the HTLC transactions' txids, otherwise answered after an unlock by `second_stage_unlock_by` (`spec/exit.md` 5.6, review F4) | In the penalty file (8.7.6), never in `watch.gzw` |
| B7 | Fee ladder: per tree step, rungs at package rates 2, 5, 10, 20, 50, 100 and 200 sat/vB above the anchor-only child, each spending **that step's own** set-aside fee coin and paying change to the wallet | `spec/exit.md` 6.6. Off unless fee coins were set aside |
| B8 | The fee coins and the payout destination, for display | |
| B9 | Known txids of the exposed set a host may publish | |

**Never in the bundle or the penalty file:** any key; any revocation secret, secret nonce or payment secret; the words; **any commitment of the member's own, current or old, completed or not, or the host's partial signature or nonce on one**; any unsigned or partly signed transaction; a lobby id; the host's key or address.

**Invariant T** (reworded after review R2-3). *No transaction in any version of the bundle or penalty file ever written can move value away from its rightful owner on any output; publishing it can cost fees and off-chain places (8.7.5).* It holds item by item in 1.0.0:
- tree transactions are fixed at creation, spend only the funding and tree outputs and pay the tree's own assignment; **one version per funding output** is the precondition, so none is ever revoked or superseded;
- a penalty spends only a revoked state the host would have to publish first, and pays the member;
- anchor-only children are keyless and anyone can already build them;
- fee-ladder children spend only their step's set-aside fee coin and pay change to the wallet. A set-aside coin is **released back to general use only by spending it** while unlocked (to a fresh wallet address, or as an input of the person's next on-chain spend, at the person's usual fee rate), which makes every rung that spent it invalid. Until that spend confirms, the coin stays set aside in the wallet's view;
- B9 holds txids only.

No version of the files ever holds anything whose publication lets anyone take a penalty against the member, or start a race against a newer state. **Before any item that can become revoked or superseded may enter the bundle** (a completed own commitment; a 1.1.0 timed-layer state, `safety-rule.md` 8; the leaf change of `safety-rule.md` 4.2; a state carried into the next factory), T no longer holds: the design must first add KB rotation at every rewrite with the old KB destroyed in the OS store, and section 8.7.5 must be redone.

#### 8.7.3 The bundle key KB and the store record

KB is 32 random bytes, made with the wallet, independent of the passphrase and of MSK, kept **only** in an operating-system key store, together with the **store record**: small counters that a copy of the data folder does not carry (review R2-1, R2-9).

| Store record field | Written by | Read by | Rule |
|---|---|---|---|
| `bundle_counter_seen` | The watcher and the node, whenever either opens or writes a bundle | Both | 8.7.4 rule 7 |
| `penalty_file_id`, `penalty_count` | The node, after each penalty append and sync, before the batch is confirmed; and at compaction (8.7.6) | The watcher and the node | 8.7.4 rule 7 |
| `attempts_counter` | Whoever writes the attempts file (12.3) | Whoever reads it | 12.3 |
| `pending` | A rekey (4.8): the new KB, its store record and the new `vault_id` | The start | 4.8 |

| Platform | Store | Unattended at boot |
|---|---|---|
| Windows | Credential Manager (`CredWriteW`, generic credential, current user, persisted on this machine only; DPAPI-protected by the system, outside the data folder) | For a service running as that user |
| macOS | Keychain, "this device only", access limited to the signed program | After login; a system keychain item for a launch daemon |
| Linux desktop | Secret Service (libsecret) | After login |
| Linux server | systemd credential (`LoadCredentialEncrypted`, bound to the TPM where present) for KB; the store record in a file of the service's own state folder outside the data folder (`StateDirectory=`), owner-only, keyed under a KB subkey | Yes |
| None of these | **No bundle.** Locked means not watching (`local-api.md` reason `no_key_store`); the interface says so and offers unattended unlock (8.6 item 8) or keeping the wallet unlocked | — |

A systemd credential is read-only to the service, which is why the server's store record is a separate keyed file there; it is outside the data folder, so a copy or rollback of the data folder alone does not carry it back. There is no plain key file fallback (review F1, F5; the reviewer's view on choice 8). The unlocked program also keeps a recovery copy of KB in the key file, sealed under KBK (a later format of 4.5; until then KB is re-made, and the bundle and penalty file rewritten, when the store has lost it). A rekey (4.8) replaces KB and deletes the old one from the store.

#### 8.7.4 Keeping it current

1. **Written with the journal.** The bundle is rewritten (atomic replace) with a higher `counter`, and B1 naming the journal position, before confirming any batch that changes B2 to B5, B7 to B9: a factory added or ended, `round_signed`, a funding status or dates change, fee coins set aside or spent. A received host revocation **appends** one penalty entry to the penalty file, naming the batch's journal position, syncs it and raises `penalty_count` in the store record, all before its batch is confirmed (7 step 2). Both are part of the anchored batches (6.2).
2. **No revocation rule is needed for the bundle** (draft 1's rule 2 is moot): under T nothing in it is ever revoked or superseded.
3. **At lock** the program checks that the bundle and penalty file reflect the journal's last confirmed batch, and that the store record matches them, before dropping the keys.
4. **At unlock** the program compares B1 and the newest penalty entry's journal position with the journal (6.3 step 3). A bundle or penalty file **older** than the journal is rewritten. One **newer** than the journal is rollback evidence: it is kept (renamed `watch.gzw.newer`, `watch.gzp.newer`), never overwritten by one built from the older journal, and the start goes to 6.3 step 4. The watcher then runs from the kept files (under T any version is safe to publish, and the newer one has the newer dates), and the status says the files are behind (`local-api.md` reason `bundle_kept_as_newer`). Their tree paths and dates may be taken into a new exit plan after the person confirms (`spec/exit.md` 5.7 item 4).
5. **After a restore marker** the bundle is rebuilt from the restored journal with `made_after_restore_marker` set. Under T it holds nothing that publishes stale channel state; `spec/exit.md` 5.7 governs the commitment (asked of the host, never automatic).
6. **The watcher's log is untrusted input** (review F5). Anyone with KB and write access to the folder can forge `watch.gzl`. At unlock (8.2 step 5), in one batch before the host is contacted (`spec/exit.md` W3), each claim is checked against the chain view first: a "broadcast" claim becomes a record only if the transaction is seen; a "spent" claim only if the spend is found and buried as the chain rules require. Nothing in the log changes held, exposed, round or channel state by itself; it can only cause the node to look.
7. **Refusing to go backwards** (extended after review R2-1). The watcher and the node refuse a bundle whose `counter` is below `bundle_counter_seen` (E13), and a penalty file whose `file_id` is not `penalty_file_id` or whose newest penalty entry's number is below `penalty_count` (E13p). For the bundle, under T, this protects only the freshness of dates. For the penalty file it protects money: a **short** penalty file (or one that cannot be opened, or names another `file_id`) is still used for what it holds, and the watcher still publishes the tree path, but the status says some answers are missing (`local-api.md` reason `penalty_file_short`, `at_risk`: "Unlock now: some of Gazpacho's answers to your host's old states are missing from this computer"), and the unlocked node rebuilds the missing entries from the journal at once.

#### 8.7.5 Threat analysis

| An attacker who has | Gains | Cannot |
|---|---|---|
| A copy of the data folder, of any age, without KB | The files' sizes and times | Read them |
| Any copy, of any age, **plus KB** (the person's OS account, or its key store) | **Privacy**: factories, funding outpoints, amounts, tree transactions, the dates, the fee coins and destination, the count of the host's revoked states | **Move value away from its rightful owner on any output** (invariant T): every transaction is fully signed by all its signers, and every output goes to the tree's own assignment, the member's wallet, or miners |
| The same, acting | **Griefing**: publish the member's tree path early. That puts on chain every transaction above the member's leaf. The member's siblings under those levels keep their funds, their channels and their H_leaf untouched (`spec/exit.md` 7.1); once the root kickoff is buried they lose the cheap rotation and the whole-factory close, and may later pay an on-chain sweep fee they would otherwise have avoided. Also: publish the highest fee rungs, spending set-aside fee coins on fees (bounded by those coins); publish penalties, which do nothing unless the host published a revoked state | Publish any commitment of the member's, current or revoked; obtain any key; sign anything |
| Write access to the folder (a sync service, a sync conflict, a folder restored from "previous versions"), with or without KB | **Cut or roll back the penalty file**, which needs no KB. Draft 2 called this harmless; it is not. Without the store record the locked watcher would lack the penalties for the host's newest revoked states, and a host that publishes one of them while the member stays locked past its revocation window takes that channel's balance. **With the store record** the short file is detected and reported `at_risk` (rule 7); the money is still lost if the person does not unlock in time. A bundle replaced by an older one is refused (rule 7; under T only dates could be stale) | Defeat rule 7 without also rolling back the OS key store |
| Write access to the folder plus KB | Forge `watch.gzl` (rule 6: only causes checks) | The same as above |
| The host, while the member is locked, publishing a revoked state and moving its payment outputs to the second stage within one block | The payment outputs of that revoked state, **if the person does not unlock by `second_stage_unlock_by`** (`spec/exit.md` 5.6): where `channel.md` leaves the HTLC transactions' txids unknown in advance, their penalties cannot be pre-signed, and only the unlocked node can answer them (`spec/exit.md` review F4) | The member's own balance output, which the pre-signed penalty takes. The bound belongs in `safety-rule.md` 11 |

The bundle trades this privacy loss and griefing, for anyone holding the person's OS key store, for the safety of a locked wallet watching and publishing its tree path in time. **Proposed default: on.** "Do not watch while locked" is refused while any factory has something to take out, unless the person confirms with the date it puts at risk (`spec/exit.md` W5) **(open, point 15)**.

#### 8.7.6 Formats

**`watch.gzw`**: `magic` ASCII `GZWATCH1` (8); `format` 1 (1); `chain` (32); `bundle_id` (16); `counter` (`u64`); then `seal(KWB, contents, ad = these 65 bytes)`. Contents: `spec/exit.md` 5.6's TLV stream, B1 to B5 and B7 to B9 (no B6). Nothing else is clear: `leave_by_locked`, `unlock_by` and the next action are read by the watcher from the opened contents and served to the local API (8.6 item 3; review F10; `spec/exit.md` 10.4 item 3 asked for clear copies, which would reveal the member's next exit date to anyone with the folder, while the only reader, the watcher, always holds KB). Vectors E12, E13.

**`watch.gzp`, append-only** (`spec/exit.md` 10.4 item 8; review R2-1, R2-4). The bundle would otherwise be rewritten whole at each host revocation, about once per payment, and grow with every penalty. So penalties live in their own file:
- **Header**, 97 bytes: `magic` ASCII `GZPENALT` (8), `format` 1 (1), `chain` (32), `file_id` (16, random), then `seal(KWP, empty, ad = these 57 bytes)`.
- **Entries** in 5.4's framing, sealed under KWP with associated data `file_id ‖ u64 offset ‖ bytes 0 to 20`: kind 2, a **penalty entry**, with incarnation 0 and sequence its number from 1, with no gap; kind 3, a sync mark, as in the journal. No kind 1.
- **A penalty entry's payload** is `spec/exit.md` 5.6's penalty entry, one TLV stream per revoked host commitment, whose type 2 is the journal `file_id` (16) and type 4 the `u64` sync-mark offset of the journal batch that recorded the host's revocation, followed by the factory, the revoked commitment's number, the trigger txid, the send-by delta and the penalty ladder. The journal position is what 6.3 step 3 compares; the sequence number is what rule 7 compares with `penalty_count`.
- Written by appending and syncing the entry and a sync mark, then raising `penalty_count` (7 step 2). A crash after the sync and before the store write leaves the file one ahead of the count, which is harmless and corrected at the next write; torn tails are cut as in the journal.
- Old copies are harmless under T; a short copy is detected by rule 7 (8.7.5). When a channel is closed and its last penalty window has passed, the unlocked program **compacts** the file into a new one (new `file_id`, entries renumbered from 1): it writes and syncs the new file under a temporary name, records its `file_id` and count in the store record as **next**, renames it over `watch.gzp`, and then makes **next** current. A start that finds the file carrying the **next** `file_id` completes that last step; any other `file_id` is refused as short.

Vector E13p.

**`watch.gzl`**: a header like the penalty file's with `magic` ASCII `GZWATLOG`, then 5.4's entry format under KWL with its own `file_id`.

## 9. The seed and the 24 words

### 9.1 Where they are and who can open them

- **The BIP 39 seed** is sealed under KS (from MSK); the node opens it at unlock and derives per-lobby keys from it.
- **The words' entropy** is sealed under KD (from PK). The running program cannot open them; a reveal or check needs the passphrase typed for it.
- This protects the words, not the money: a thief of the unlocked process has the seed. It makes "reveal needs the passphrase" a property of the cryptography and keeps the words out of memory dumps of the running program.

### 9.2 Reveal and check

1. The person asks to see the words or starts the backup check, and types the passphrase.
2. **words**(passphrase): the helper derives PK; the commitment is checked; KD opens the words into a `sodium_malloc` buffer; PK is wiped. A wrong passphrase counts against the attempt limit.
3. The program converts the entropy to words, sends them (reveal) or compares the answers in constant time (check), and wipes everything built from them. `local-api.md` 12.7's interface rules apply.

### 9.3 Restore from the words

- **New device, or no journal:** the 24 words and a new passphrase give a new MSK, `vault_id`, key file, guard and empty journal; the start is a restore (`journal.md` 8.2). Factories come back only from an export (11).
- **Same device, key file lost or passphrase forgotten, journal intact:** the seed opens the journal's recovery wrap (KR); a new key file is written (new passphrase, same MSK and `vault_id`); then 6.3 decides: a journal not behind its mark file and guard starts normally; otherwise it starts as a restore.

## 10. The guard file and the mark file

### 10.1 The guard file

Replaces `journal.md` 8.3's format; its placement and storage duty are unchanged. It is created at set-up (7.4) and replaced before confirming every batch that holds a `guard` record. Draft 2 also carried the journal's high-water mark here and replaced the file before every anchored batch; draft 3 moves the mark to its own append-only file (10.2; review R2-8).

| Offset | Field | Size |
|---|---|---|
| 0 | `magic`, ASCII `GZGUARDE` | 8 |
| 8 | `format`, 1 | 1 |
| 9 | `chain` | 32 |
| 41 | `seal(KG, contents, ad = bytes 0..40)` | 24 + n + 16 |

Contents: `counter` (`u64`), `n_epochs` (`u16`), per epoch `epoch` and `highest_index` (`u32`, `u32`), `rounds_started` (`u64`). KG comes from the seed so the guard stays readable across a restore that makes a new key file. Vector E9.

### 10.2 The mark file

`mark.gzm`, in the data folder beside the journal, outside the journal's backup set like the guard. It holds the journal's high-water mark (6.2).

| Offset | Field | Size |
|---|---|---|
| 0 | `magic`, ASCII `GZMARKS1` | 8 |
| 8 | `format`, 1 | 1 |
| 9 | `chain` | 32 |
| 41 | The journal's `file_id` | 16 |
| 57 + 56k | Entry k: `seal(KH, u64 incarnation ‖ u64 mark_offset, ad = bytes 0..56 ‖ u64 offset of the entry)` | 56 |

- **Entry 0** is written at set-up (7.4) as (0, 0), "no mark yet". Each anchored batch appends one entry naming its incarnation and the offset of the sync mark that covers it, after that mark's sync and before the confirmation (7 step 2).
- **Reading.** Entries are read in order. A trailing piece shorter than 56 bytes, or a last entry that fails its tag, is a torn tail: ignored, and cut before the next append. An entry that fails its tag with a valid entry after it, or entries whose (incarnation, mark_offset) decrease, mean a **damaged** file; no valid entry at all, or no file, means **possibly old** (6.3 step 1). Another journal's `file_id` means **behind**.
- **The newest valid entry** is the high-water mark that 6.3 step 2 tests: its mark offset must be the offset of a valid sync mark of that incarnation in the journal; (0, 0) passes.
- **Why append-only is as strong as a replaced file.** Both are defeated only by putting back an older copy (here, also by cutting at an entry boundary), which needs write access to the folder; neither is detected locally (6.4). The append costs one sync instead of two and a rename.
- **A new journal** (a restore, an import, a rekey) gets a new mark file for its `file_id`, under its own KH.

Vector E9m.

## 11. Exports and the host's copy

`DESIGN.md` 9: the journal is the backup; the person may export it and the host keeps a copy. Two profiles of one format, `.gzb`. (Owner decision 13 says "a backup export is the file as encrypted on disk"; this separate format needs the owner's amendment, open point 1.)

| | Profile 1: the person's export | Profile 2: the host's copy |
|---|---|---|
| Opens with | The passphrase **or** the 24 words | **Only the 24 words** |
| Holds | The journal's entries and the guard; the words' entropy **only if the person chose it** (flag bit 0) | The journal's entries and the guard; never words or seed |
| Restores | Factories, once the words restored the keys; everything from the file and the passphrase if the words were included | Factories, once the words restored the keys |
| Against a thief of the file | The passphrase at 1 GiB, 4 passes (4.2); with the words included, the file is a passphrase-protected seed backup and the interface says so | 256 bits |

**Why the host's copy must not open with the passphrase.** The host keeps every member's copy and is the adversary of `safety-rule.md` 2; a passphrase-opened copy would let it guess passphrases offline and, for a weak one, take the money.

**Format** (big-endian):

| Offset | Field | Size |
|---|---|---|
| 0 | `magic`, ASCII `GZBACKUP` | 8 |
| 8 | `format`, 1 | 1 |
| 9 | `profile`, 1 or 2 | 1 |
| 10 | `chain` | 32 |
| 42 | `export_id`, random | 16 |
| 58 | Profile 1 only: `kdf` 1, `t` 4, `m` 4, `p` 1, `salt` 16 | 26 |
| 84 | Profile 1 only: commitment, HMAC-SHA256(derive(PKx, `backup commitment`, chain ‖ export_id), bytes 0..83) | 32 |
| 116 | Profile 1 only: `seal(KX, BK, ad = bytes 0..83)` | 72 |
| 188 (profile 1) or 58 | Chunks, to the end of the file | |

The slot's parameters are checked against 4.2's floor and ceiling **before** deriving (review F9; E11). Each chunk is `u32 n` then `seal(EK, part, ad = prefix ‖ u64 index ‖ u8 final)`; `prefix` is every byte before the first chunk; `final` is 1 on the last chunk only; a part is at most 65,536 bytes; `n` is 40 to 65,576. Index and final flag stop reordering, dropping, repeating and truncation (STREAM, E11). Only the final chunk may be empty; an empty chunk that is not final is refused (review F17).

Plaintext: `version` (`u8`, 1); `created_ms` (`u64`); `flags` (`u8`; bit 0: the words follow, never in profile 2); the 32-byte entropy if bit 0; `guard_len` (`u32`) and the guard contents; then every journal entry up to the last valid sync mark, as `kind`, `incarnation`, `sequence`, `len`, payload.

**Opening:** with the passphrase, the slot's commitment and wrap give BK; with the words, BK = derive(seed, `backup`, chain). **Import** is a restore (`journal.md` 8.2): a new journal, entries re-sealed, a new mark file, a new key file if none, a restore marker and a new epoch; the bundle built afterwards follows 8.7.4 rule 5. The peer-storage message limit (about 64 KB) is smaller than a journal; carrying the host's copy is the backup specification's (`journal.md` open point 4).

## 12. Other files

### 12.1 The log

`log.gzl`: the journal's format with its own `file_id` and KL; one entry per line; two files of at most 16 MiB in turn. Nothing is written before unlock; the terminal gets only fixed messages without data.

### 12.2 The socket token

The local socket's bearer token file (`local-api.md` 4.6) stays plain and owner-only, made at unlock and deleted at lock and stop, but lives in a **per-user runtime folder outside the data folder** on every system (review F21, R2-10). The folder is named `gazpacho-` followed by the first 16 hex digits of SHA-256 over the data folder's absolute path, so several programs with their own data folders (Slice 1's host and members) never share one, and it sits in:
- Linux: `$XDG_RUNTIME_DIR` (a per-user tmpfs). Where it is unset (a process with no login session), `/tmp/gazpacho-<uid>-<hash>`;
- macOS: the per-user temporary folder (`confstr(_CS_DARWIN_USER_TEMP_DIR)`);
- Windows: the user's temporary folder from `GetTempPath2W` (`GetTempPathW` where that call is missing), which is outside `%LOCALAPPDATA%\Gazpacho` and not synchronised.

The program creates the folder owner-only (POSIX 0700; on Windows an owner-only access list with no inherited entries), and refuses to use one that already exists with another owner, other permissions or a link in its place. While the wallet is unlocked it is a **full-authority credential**, since bearer requests are exempt from fresh sign-in; whoever can read it is the same OS user, who could read process memory anyway. Encrypting it would need the passphrase for every command-line call **(open, point 11)**.

### 12.3 The attempts file

`attempts.gza`, for `local-api.md`'s passphrase limit across restarts. 85 bytes: `magic` ASCII `GZTRIES1` (8); `chain` (32); `counter` (`u64`, raised at every write); `wrong_in_a_row` (`u32`); `last_wrong_s` (`u64`); `blocked_until_s` (`u64`); `mode` (`u8`: 1 checksum, 2 keyed); `check` (16): in mode 2, HMAC-SHA256(KA, the 69 bytes before) truncated; in mode 1, SHA-256 of them truncated. Mode 2 whenever KB is available, which the locked program has (review F20): a folder-only writer (a sync conflict, a malicious sync peer) cannot forge the count. **Replay** (review R2-9): each write also stores its `counter` as `attempts_counter` in the store record (8.7.3), and a file whose counter is below it is read as the strictest state, so an older valid file put back does not reset the count either. A missing or damaged file, a mode 1 file where KB exists, or an older one, is read as the strictest state (`blocked_until_s` = now + 15 minutes). Without a key store (mode 1) replay is not caught; online guessing stays bounded by Argon2id's cost per guess. Vector E14.

## 13. The library

**libsodium, 1.0.21 or later**, **proposed; owner yes needed**: Argon2id (`crypto_pwhash`), XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf_*`), HKDF (`crypto_kdf_hkdf_sha256_*`), HMAC-SHA256 (`crypto_auth_hmacsha256_*`), guarded memory (`sodium_malloc`, `sodium_mprotect_*`, `sodium_mlock`), wiping and constant-time comparison. Storage randomness is the program's own (5.2).

| Option | For | Against |
|---|---|---|
| **libsodium** | Every primitive here plus guarded memory; Argon2id and XChaCha20-Poly1305 are its defaults; ISC licence (MIT-compatible, notice kept in About > Licences); widely deployed | A second cryptography library beside OpenSSL. Its 2017 audit covered 1.0.12 and 1.0.13 only and predates years of changes; this document relies on the vectors and the review, not on the audit |
| OpenSSL only | Already linked; Argon2id, HKDF, ChaCha20-Poly1305, GCM-SIV | Argon2id and GCM-SIV need 3.2 or later (CI has 3.0.13); no XChaCha; coarser memory hardening |
| Monocypher 4 | Two vendored files, CC0/BSD-2 | Argon2id came after the 2020 audit; no memory locking |
| Reference Argon2 and the imported ChaCha20 | No new library | Hand assembly of primitives |

**Version.** 1.0.21 or later: 1.0.18, the long-term distributions' version, dates from 2019 and lacks HKDF, and 1.0.21 fixes CVE-2025-69277 (not in a function used here, but a security wallet does not pin below a security release).

**Build.** On every platform from the **signed release tarball**: its minisign signature checked against the project's published key, its SHA-256 pinned in the repository; built by a CMake `ExternalProject` with the release's own build (autotools on Linux and macOS, the MSVC solution on Windows), linked statically. No distribution package. The program checks `sodium_library_version_major/minor` at run time and calls `sodium_init()` first. CI runs the vectors against it on Linux, macOS and Windows (`OPEN-QUESTIONS.md`: no Windows or macOS CI yet).

**Where it is linked.** Only in the outer layer (storage port and programs). A check refuses any `sodium_` symbol in `gazpacho_core`.

## 14. What the interface says (proposed wording)

**Choosing the passphrase (first run, restore):**
> Gazpacho has made a passphrase for you: *six words*. Write it down with your 24 words, or keep it in a password manager. You will type it each time you open Gazpacho on this computer. It locks every file Gazpacho keeps here.
> [Use these words] [Choose my own]
> (Choose my own:) At least 15 characters. Nobody can recover it for you. If you forget it, your 24 words still bring the wallet back on this computer.

The six words come from a published 7,776-word list that is not the 24-word list (open point 3).

**A refusal:** "This passphrase is too short (12 of 15 characters)." / "This passphrase is too common. Choose another." / "This passphrase uses your 24 words. Choose another."

**Locked:** `local-api.md` 4.7's headlines (`spec/exit.md` 5.6's table, extended). Never "Gazpacho will leave in time": the last step needs the passphrase.

**Files behind:** "These files are older than this wallet's last saved state. Gazpacho can start them as a restore, with new keys, or stay locked so you can put the newer files back." (6.3 step 4)

**Changing it:** "Changing your passphrase protects copies of your files made from now on. Copies made before still open with the old one. If you think someone has both an old copy and your old passphrase, choose New storage key as well."

**Exporting:** "This file opens with your passphrase or your 24 words. It holds your factory history, not your 24 words." With the option chosen: "This file now also holds your 24 words: anyone who guesses your passphrase can take your money. Keep it as safely as the words themselves."

**No key store:** "This computer has no secure key store Gazpacho can use. While Gazpacho is locked, nobody watches your factories. Keep it unlocked while you are in a factory, or unlock it within the safe absence."

**Weak memory protection:** "Your system did not let Gazpacho keep its keys out of the swap file. Full-disk encryption protects against this."

## 15. Test vectors (section E)

Computed by `tools/spec-vectors.py` (`python -I tools/spec-vectors.py`), which prints section E after the earlier sections. Argon2id and XChaCha20-Poly1305 are not in Python's standard library: the tool contains both, written from RFC 9106 and RFC 8439 with the XChaCha draft, and prints nothing unless they reproduce the published vectors (E0). That code is slow and not constant time. The implementation must reproduce every value with libsodium.

Every salt, identifier, key and nonce input is a **test value** (`sha256("gazpacho test " + label)`); the BIP 39 seed is the stand-in `sha512("gazpacho test bip39 seed")`; the chain hash is signet's. Nonce inputs are `sha256("gazpacho test r: " + label)`, with the labels the tool prints.

**E0.** RFC 8439 2.8.2, XChaCha 2.2.1 and A.3.1, RFC 5869 A.1, RFC 9106 5.3 reproduce. (libsodium cannot run RFC 9106 5.3, which uses 4 lanes, a secret and associated data; E2 is the KDF vector it must match.)

**E1.** `gazpacho test passphrase, never for coins: café`, typed with U+00E9 or with `e` + U+0301:

```
67617a706163686f207465737420706173737068726173652c206e6576657220
666f7220636f696e733a20636166c3a9
```

**E2.** Argon2id, t = 3, m = 64 KiB, p = 1, 32 bytes (test parameters, below the floor). Salt `db6c732c92598e0ec4c658b7addec256`. PK `bcc9248a9db077e01fbaa2a93f27041e128273dc0336872fe21f9f69c099904c`. Agrees with OpenSSL 3.5.5 (`openssl kdf … ARGON2ID`), with Node 24's `crypto.argon2Sync`, and, by the reviewer, with the Python `cryptography` package.

**E2r.** The same at t = 3, m = 262,144 KiB: `acfe7a0e9b72c011d3382684f2b9b06a221f61aeb29fe3382299419b6433c945` (the tool with `--slow`, about 30 minutes; OpenSSL; the reviewer's independent implementation). **Still to confirm with libsodium.**

**E3. Key file**, 363 bytes, E1's passphrase, E2's parameters and salt, `vault_id` `58e8eff8fffdf8d50e058079eb041465`, MSK `15a191ff9bc84eb40d4af9e03f98e31cdce1bd0a3cbb543b2ca1cc2664d2e8ba`. Commitment key `00dc1f010ed6a82697cda31c3b9f538df68e56967233bebef437caecf58cbb44`, KW `c5bb964b729d73609b845b8c8620cc14cf9127fd8c15415b726f88727f0acabc`, KD `24487797d030cb76de0290e7fe5590ebcfcd399f5514158e30623e979906b743`, KS `7236c6a1da88ced5cb0de1d17d579e785177081ffe04a80fb3734c5b6288bee1`:

```
475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000
004001db6c732c92598e0ec4c658b7addec256f7ead7e5bfcd58d4590055a6d9
f53000fa10f49bb2d3e546b47c43d7411132c46611fcc062b8f817fd206b6b8d
664d14cb326a638d39a55f6d9725781dfe2ebfda6a10e61ac5ad4e5c89249587
f0b22ee319b1d8722d02b00220f5adf8e344355bf93de8004188451e62b38c7a
eeae8735cd00c056759663ca4f9e4b543981498e14e280f9cbdb3f9828e9a894
de90e7439550bb0901ea3010bbac6feb0fc9571de3fa376d99c2457fb1d33c87
2d91bf5fe219ef90549c9741a9c8ff5a3349af6036691511684a86495d4a227e
5aed0e32ecaffb98c1bfb397f294ee51ea6c5fe6b151809e1e6efd403d50c937
772b94294b517d05166c3977dceea32291a7eefc344ef7d1148b8526d67fbfd3
ff6616110f9ee510357504
```

**E4. Refusals of E3:** passphrase plus a space; m changed to 65 KiB; t changed to 1; a bit of the commitment flipped; a bit of the wrapped MSK flipped (each "wrong passphrase or damaged key file"); a bit of the seed ciphertext flipped ("damaged key file"); the chain changed ("other network", before any derivation); under the release floor, and with m above the ceiling ("parameters refused", before any derivation).

**E5. Journal header**, `file_id` `708bd86b189b2130142ec86d6c5a6f22`, KJ `8b6c75058abb5837cc5d7c069066cc9e4c67d523a725033616515e1cd5843875` (nonce key `84d9e143eb661f2650463cecd21818a6fff19f853343840e6f43d9f9b2cd82d8`), KR `9de84e620aee3a44f7d2d7b7efe872b26c5b4d5f1da2b987011281af4f8676d3`:

```
475a4a4f55524e4501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb041465708bd86b189b21
30142ec86d6c5a6f2280fd61ee3f0cf6d54d3f2e063c41fbc0e0118e7f220b5c
00b31289aaebd4d8be3b480fd9e9ed402953e12c9f4d52e01b84cdb6fdd38872
a35ca8084133fe27e796f5d62cfa19c6203a6b9c9eb29cf9d3ecf44c2a596884
a1b83cc8341546dd0c58f9d91c806318e64fd77992dc9f295f
```

The recovery wrap opens with the seed alone; another MSK or a changed `vault_id` gives "not this wallet's journal"; a changed chain, "other network".

**E6. Entries** after E5. E6a, incarnation 1, clock 1,794,000,000,000 ms, at 185:
```
000000410100000000000000010000000000000000ab03f2e41c35f3f411e16b
07f966d57e2f68ec35d15d7316cc582439dfbbc976e1610451ea22b64eb75f8b
b46c3e4105
```
E6b, sync mark at 254:
```
00000041030000000000000001000000000000000035e109f27d3e86b2c47d3a
156356e63cee6b2525a9bee46fcb931acd0fdf5dc57d617ddd41909630076b05
d75742fdef
```
E6c, batch (1, 1), one record of type `0x7e570001` with bytes `ping`, at 323:
```
000000490200000000000000010000000000000001cc1b5f45edee5cad609902
d8213eb3511c2a3b4cfd360342a18ccd41306b4f1e79fafc5ea879888f042682
7012234a3a348376d6706ad8b2
```
E6d, sync mark at 400:
```
00000041030000000000000001000000000000000060b49aa722550072bc2d42
51164193a739dc6c0a06c579fc2ac9a0c3dfc823bcff8bbe05dad0ac917cf6bc
86ef0b070b
```

**E7. Tampering** with the 469 bytes of E5 + E6:

| | Change | Result |
|---|---|---|
| E7a | One bit of E6c's ciphertext | Corruption at 323, refused |
| E7b | One bit of E6c's clear incarnation | The same |
| E7c | E6c appended again at 469 | Torn tail at 469; never read as a batch |
| E7d | E6c replaced by a batch for another `file_id` under the same MSK | Corruption at 323 |
| E7e | E6c and E6d swapped | Invalid at 323 |
| E7f | The last 3 bytes missing | Torn tail, cut to 400 |
| E7g | Cut at 323 | Clean, last mark 254; caught by E9m |
| E7h | E6c and E6d both damaged | Torn tail at 323; caught by E9m (review F25) |

**E8. Passphrase change** to `gazpacho second test passphrase, never for coins`, salt `sha256("gazpacho test kdf salt 2")[0:16]`. Bytes 0 to 66 and 259 to 362 equal E3's; the journal opens with the new file's MSK; E3 still opens with the old passphrase:

```
475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000
004001a89b97d1d90598f7626e1c0cb87c4db55ed57ddbd2bc56ee1110980436
5268f355c3502d18e0d62498b731f85101a3aecbf4b26db55d28d945dcfb5b20
94f71e0954824cc49ec3f5391a4c39ea2a6e5ccfc774fe02a9eca0f90f61231d
cb173602e3fbfed1c2465a52d5d0a9aab54c22c59dc5dcf4ee98605dc07ba9c8
f242408d37dcd356d0f6f87d6b7139ef2604a1808114f651f2998654960024ec
620e3e862dfb3cc48885cceba7f07e2825ae41ede922dedc23c5a13c4a7864eb
61313b5fe219ef90549c9741a9c8ff5a3349af6036691511684a86495d4a227e
5aed0e32ecaffb98c1bfb397f294ee51ea6c5fe6b151809e1e6efd403d50c937
772b94294b517d05166c3977dceea32291a7eefc344ef7d1148b8526d67fbfd3
ff6616110f9ee510357504
```

**E9. Guard file** (draft 3: no high-water mark, 107 bytes): counter 3; one epoch, 0, highest index 2; one round. KG `339b2585661fdf58c0d401e63d10bb836bb3b272b6b7dbb5f3d9e417fb630deb`:

```
475a47554152444501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e9739881080000002d6aad687f0bd082c4c2cd1b3a4167d014c3cf315f1336
f55a078212f02ac333bf61590500fc429a7ab0284d05a7a28928e97e5a583beb
ef82ee452f294a02eb3ca1
```

**E9m. Mark file** (169 bytes) for E5's journal: the set-up entry (0, 0) at 57, then incarnation 1, sync mark 400, at 113. KH `a441f426101ddffd6caa985201008a86604b9ecd195190faf48a8d14d5ceb084` (nonce key `e09b6279ec4d4e7234af72cd47d36404150c87886c56fb0eb76613939babb37c`); nonce input labels `mark entry 0`, `mark entry 1`:

```
475a4d41524b533101f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e973988108000000708bd86b189b2130142ec86d6c5a6f22a0b0698e035f15
52ef62750af1aef9f023a21555914eec8290b456b8a9dd6cb4f6a092cde0f9e0
23299f404da25a83d7a8970adb034bd7cba0f5665ef7a0d6d955f475d83e23f8
f1e6f884492e105492457783c508d39ef1b552c3da94ab3a6b0ecc6483a01edf
5f6d132bb4b15793d0
```

Against E7g and E7h, offset 400 is not a sync mark of the journal: refused as rolled back (6.3). Against E6 it passes. A torn last entry is ignored; a damaged entry before a valid one, or no valid entry: possibly old; another journal's `file_id`: behind. Cut back to its set-up entry it reads as "no mark yet", an older copy this file cannot detect (6.4).

**E10. Exports**, `export_id` `eba594bd30df323ee7faf88bd4e4bf81`, slot salt `sha256("gazpacho test export kdf salt")[0:16]`, E2's test parameters, created 1,794,000,100,000 ms, flags 0 (no words), body the entries of E6 and the guard of E9. BK `9a4617d2c2e8fb4163ddbe6b6b1968302c0a65114f261b444605aef8cf4e1b00`, EK `e172f2dabc7650d0a79495a05dc2736ae37151ef116fcc2f10dd9d590244ac1f`. E10a (profile 1, slot with commitment, 396 bytes) is printed by the tool. E10b, profile 2, 266 bytes (both changed in draft 3 because E9's guard is shorter):

```
475a4241434b55500102f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c
4225e973988108000000eba594bd30df323ee7faf88bd4e4bf81000000cc217f
eaf9f0202e64dafaea7e9ea793c4a06d67ec5b2d03db2c6c4c7224485ce3eeac
b4177ea62f2e1104847be7a4f0837cbee6573d6cb74a2f294a747e0a7afd9411
f1c64d126d21fe61a4e559c5fbcae529ef03765b5626ec04821de92f99203846
4e8f922a565a3cbe241ef44b299061497e02374aa55f3353b8422c0e73b06eea
c72dbc63e903cceccadb6a8610e4ad4ee764c105db40a71d77f4b418eb70d7f1
82cd650a5f04c3601cd150b5c2a0a4e5a6473bd4048f8ad222d0fe0f7aacecb7
1dbc6869aa241407cff5
```

**E11. Export refusals:** E10a's body in 3 chunks of at most 64 bytes opens; last chunk dropped: "truncated"; chunks 0 and 1 swapped: "damaged"; last chunk repeated: "data after the final chunk"; the slot's memory changed or E8's passphrase: "wrong passphrase"; the slot's memory 2^32 − 1 KiB, or 4 lanes: "parameters refused" before deriving; an empty chunk before the last: refused; other words: "damaged"; E10b with a passphrase: "needs the 24 words".

**E12. Bundle** (65-byte clear header), `bundle_id` `sha256("gazpacho test watch bundle id")[0:16]`, counter 7, KB `5c1756fe3287f99c4c21cc1baba1bbaaf7d277d8049f314831236ceaebc1b6b0`, KWB `c269df89095e6a036a8a3d85616dc6855eda09f4ff55aec973f661c91e45dc0f`, contents one placeholder TLV record (the records are `spec/exit.md`'s; their vectors come with it):

```
475a57415443483101f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000001df1fe044bee7cadf9a1c6611b281f300000000000000
07c7417c3c17ecfc3aac1438892d57c6daf1c89dade8f176b805ebc51a60389f
2820bd70a18ebda5c6d43cdc4bbe498f76c296893b02f7d09e2c3ec4b1661c8f
e743dbf0c8298e2a833a
```

**E13. Bundle refusals:** counter changed: "damaged"; opened after counter 8 was seen: "older than the last bundle seen"; under MSK, or under the watcher log's key KWL: "damaged".

**E13p. Penalty file** (287 bytes), `file_id` `sha256("gazpacho test watch penalty file id")[0:16]`, KWP `2a0704f005aebae1374f0bf40f3ab6fa5b6367a4c1b89c136931d7b34d9df984`: the 97-byte header, one penalty entry (sequence 1) at 97 whose payload is a TLV stream with type 2 = E5's journal `file_id`, type 4 = its sync mark 400, and an odd placeholder record (type 99) standing for `spec/exit.md` 5.6's other penalty fields, then a sync mark at 218; nonce input labels `penalty header`, `penalty entry 1`, `penalty mark 1`:

```
475a50454e414c5401f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e9739881080000005e47c54f7b19f693f8ab7de34451e04b5050680f86443a
01d95ba5b666c8a71df2a29fcee2a9b42273e99bfb097602c1d2eca818fe0f0e
cf0000007502000000000000000000000000000000015ac465de1821283132ae
dcb26810fa7bc4bdf438cc38a2cb24b75c778400452e5a9cfd9dbf4f43279fea
72163d774a4704be8413e35b50b7d5b2edacc52f69060b29d3801f1fd8d549de
529d36977e5027aa2ba3a77647e6c03b529b0ef02d761a82a8c9000000410300
00000000000000000000000000000071982635f8efedb48796e4ec9e406ade24
46b0d263a5b75ac1b9afc55ad6bbd33dd310debf4a7667c44a8ddaf602f1a2
```

With the store record's `penalty_count` at 2, or the file cut back to its header: "shorter than the last count seen"; under MSK: "damaged"; KWB cannot open its entries.

**E14. Attempts file** (85 bytes), mode 2 under KA: counter 9, 6 wrong in a row, last at 1,793,999,990, blocked until 1,794,000,030:

```
475a545249455331f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225
e973988108000000000000000000000900000006000000006aee447600000000
6aee449e02b9767c56a1c173e4d9560cc0e95af2fa
```

With the count rewritten, replaced by a mode 1 file while KB exists, or replaced by an older valid file (counter 8) once the store record holds 9: the strictest state.

**E15. Request digest** (for `local-api.md` 7.4; kept in section E). The body `{"request_id": "e15_test_request_0001", "passphrase": "not digested", "name": "Café ½ 😀 tab<TAB>here", "note": "unit<U+001F>sep \"q\" \\", "confirm_funding_sat": 250000, "draft": {"z": [3, 2, 1], "a": {"b": true, "a": null}}, "été": -7, "Zed": 0}`, with its top-level `passphrase` removed, in RFC 8785 form (197 bytes of UTF-8):

```
7b225a6564223a302c22636f6e6669726d5f66756e64696e675f736174223a32
35303030302c226472616674223a7b2261223a7b2261223a6e756c6c2c226222
3a747275657d2c227a223a5b332c322c315d7d2c226e616d65223a22436166c3
a920c2bd20f09f9880207461625c7468657265222c226e6f7465223a22756e69
745c7530303166736570205c22715c22205c5c222c22726571756573745f6964
223a226531355f746573745f726571756573745f30303031222c22c3a974c3a9
223a2d377d
```

SHA-256 `94f90d8308e1d42c8359dfbed31a81712f3406612fb268a10b41a813d0a73afe`, for any member order and any passphrase value. Python's `json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":"))` gives the same bytes here; it differs from RFC 8785 only for names outside the Basic Multilingual Plane, which this API's ASCII names never are.

## 16. Tests

**Primitives and formats**
1. E0 to E15 and E2r reproduce with libsodium on Linux, macOS and Windows (E15 with the program's own canonical JSON); RFC 5869's SHA-256 vectors through `crypto_kdf_hkdf_sha256`.
2. Every field of every file altered in turn: refused with the stated reason; a damaged length never reads past the file.
3. Floor and ceiling for the key file **and the export slot**: t = 2, m = 65,535, t = 17, m above each of the three ceilings, and on a 32-bit build m = 4 GiB: refused without running Argon2id.
4. Passphrase rules: 14 and 15 code points with a 4-byte character; 1,024 and 1,025 bytes; blocklisted in other case; the wallet's own words; NFC and NFD equal.
5. Key commitment: a key file whose wrap opens under two candidate keys (built with the partitioning construction) is refused for every passphrase except the one its commitment names.

**Journal and rollback**
6. `journal.md` tests 1 to 28 on the encrypted format; E7a to E7h.
7. Hedging: with the random source forced to repeat, two different entries at one offset get different nonces; identical entries identical bytes.
8. Rollback: the journal cut at each entry boundary after each **anchored** family of 6.2 (guard, exposure, `round_signed`, `funding_signed`, `start_sent`, own commitment, released revocation, received host revocation, a released payment secret): refused; a legitimate torn tail after each: accepted; a cut that loses only batches after the newest anchored batch: accepted, and the node rebuilds; the guard file or the mark file deleted on a wallet at key index 0: possibly old (F6); **the journal and the guard deleted together** (and, separately, the journal, the guard and the mark file): the start is a restore with a new non-zero epoch, and no key of epoch 0 is derived again (R2-2); the mark file replaced by an older copy or cut back to an entry boundary: not detected (records the limit).
9. Rollback evidence: a bundle and a penalty file newer than the journal: the start goes to 6.3 step 4 and both are kept as `.newer`, never overwritten; the watcher runs again from them; `start as restore` then starts with a new epoch, a restarted mark file and the `.newer` files still present.
10. Crash at every step of set-up (7.4), passphrase change, parameter upgrade, rekey (4.8, every step and rename) and penalty-file compaction (8.7.6): the next start opens with the old or the new passphrase, never neither; after a rekey crash the files are all old or all new, and the mark file names the journal's `file_id`.
11. **Write cost**: a run of 1,000 simulated payments, counting syncs and renames per anchored batch, on Linux and on macOS with `F_FULLFSYNC` (open point 16).

**Secrets**
12. After a run, the data folder, logs, API answers and events contain none of: the passphrase, PK, MSK, any subkey, the entropy, the words, the seed. A dump forced during and after an unlock contains neither MSK nor the first Argon2 block `B[0][0]` of that derivation (F7); the main process never maps Argon2 memory. With swap enabled and locking refused, the helper reports "memory not locked" (R2-6).
13. With the wallet locked, a memory scan of the process finds none of the storage-layer secrets except the KB subkeys.
14. Wrong passphrase, damaged wrap and wrong network give the stated messages and nothing else; comparisons are constant time. A helper killed mid-derivation, or out of memory: "could not be checked", not counted as wrong.
15. The storage random source failing: a storage failure, nothing half-written.

**Restore and export**
16. Key file deleted, journal intact: the words reopen it through KR; the mark-file and guard checks pass; normal start.
17. Profile 2 never contains the entropy or the seed; profile 1 contains the entropy only with flag bit 0; both open as stated.
18. Import makes a new `file_id`, a new mark file, a restore marker and a new epoch.

**The watcher** (1.0.0; Slice 1 builds none of it, and test 22 below checks its `no_bundle`)
19. The simulator restarts a member and never unlocks it: the watcher publishes the tree path by `leave_by_locked`; a host's revoked state is answered with the penalty; the strip shows `local-api.md` 4.7's headlines and never says the wallet will leave in time by itself; the commitment goes out only after unlock, first, before the host is contacted and whatever the saved pause (8.2; `spec/exit.md` W3).
20. **Outputs**: for every transaction any bundle or penalty file of a run ever held, every output is checked against the tree's own assignment, the member's wallet, the fee coins' change and the penalty's payout: no output pays anyone else (review F11).
21. Every bundle and penalty file a run writes contains none of: any key, revocation secret, preimage, secret nonce, the words, MSK, a host address or key, a lobby id, **any commitment of the member's or the host's partial signature on one** (byte search of every version).
22. No OS key store: no bundle is written, `watch.key` never exists, and the status says nobody watches, reason `no_key_store`. A Slice 1 build: reason `no_bundle` whatever the store.
23. **Old copies** (review F1): every bundle and penalty file version a run ever wrote, plus KB, handed to a simulated thief after several commitment updates and revocations: nothing it can publish is a commitment of the member's, revoked or not, and nothing it can publish lets the host take a penalty; its best result is the griefing of 8.7.5. A fee coin released back to general use: every rung that spent it is invalid once the release confirms (R2-3).
24. **After a restore** (review F4): the bundle rebuilt from an old backup holds no commitment and carries `made_after_restore_marker`; the watcher publishes nothing that is the member's channel state.
25. `watch.gzl` forged with KB (an exit "broadcast", an outpoint "spent", a factory "abandoned"): the merge records nothing the chain does not confirm and changes no held, exposed, round or channel state.
26. **Short penalty file** (R2-1): cut at each entry boundary, and replaced by an older copy, while locked: the watcher reports `penalty_file_short` (`at_risk`) and still publishes the tree path and the penalties it holds; at unlock the node rebuilds the missing entries from the journal. The same with the store record rolled back too: not detected (records the limit).
27. **Unlock failures** (8.2): a wrong passphrase leaves the watcher running throughout; a journal found behind, a corrupt journal and a storage failure each leave the keys wiped and the watcher running again; no later step of the order runs.
28. **Attempts replay** (R2-9): an older valid attempts file put back while the store record holds a higher counter: the strictest state.

**Break-checks**: drop the offset from the entry associated data (E7c and E7e must fail); replace the hedged nonce by a counter (test 7 must fail); drop one anchored family from 6.2 (test 8 must fail); drop the mark-file append from an anchored batch (test 8 must fail); drop rule 7's penalty count (test 26 must fail); start a key file without a journal as a normal start (test 8's R2-2 case must fail); drop the key commitment check (test 5 must fail); let a commitment into the bundle (tests 21 and 23 must fail); remove a `sodium_memzero` (test 12 or 13 must fail); **29.** a release binary given E2's key file refuses it (the test entry point is compiled out, F24).

## 17. Review checklist

1. Is every algorithm used as specified (Argon2id 0x13, p = 1, empty K and X; XChaCha20-Poly1305; HKDF), and do E0 to E15 reproduce with libsodium and the program's canonical JSON?
2. Is any key or nonce key reused across purposes (4.4's table, 5.2)?
3. Is every byte of every file authenticated or listed in 3.2?
4. Can an entry be moved, replayed, dropped from the middle or spliced undetected, in the journal, the mark file or the penalty file?
5. Is the torn-tail versus corruption decision unchanged in meaning, and is 5.6's "yes, outside anchored batches" complete?
6. Does 6.2's list of anchored families include every record whose silent loss could make anything be signed or published wrongly, is the "what a cut can lose" argument right, and does every detected rollback reach the restore path?
7. Does the passphrase check, with the key commitment, give anything cheaper than one Argon2id per candidate?
8. Are the parameters, floor and ceiling right for every slot, and enforced before deriving, including on 32-bit builds?
9. Does the host's copy hold anything a passphrase guess opens?
10. Is every storage-layer secret's lifetime bounded and wiped on every path, and does the helper process keep Argon2 memory out of the main process? Is the swap residue stated correctly?
11. Is every crash order safe (set-up, replaces, appends, rekey, compaction)?
12. Are the Windows and macOS specifics right, including the Credential Manager and the runtime folders?
13. Is libsodium 1.0.21 from the signed tarball acceptable, and is it kept out of the core?
14. Does hedging stay safe when `r` repeats?
15. Does section 14 say what the cryptography does and no more?
16. **Does invariant T, as reworded, hold for every bundle and penalty item, in every version ever written? Can any copy of either, with KB, publish a commitment of the member's or move value from its rightful owner?** Does the locked watcher keep the member safe through `unlock_by`, as `spec/exit.md` 5.6 claims, and is the second-stage bound stated?
17. Is `watch.gzl` treated as untrusted everywhere it is read?
18. Does the store record catch every rollback it claims to (bundle, penalty file, attempts file), and is what it cannot catch stated?

## 18. Open points

1. **The owner's yes** to: libsodium 1.0.21 (13); Argon2id 256 MiB / 3 for the key file, 1 GiB / 4 for profile 1 exports, floor 64 MiB / 3 (4.2); the 15-character floor, the blocklist and the generated passphrase first (4.1, 14); the host's copy openable only with the words (11); profile 1 without the words by default (11); and **two amendments of recorded owner decisions** (review F22), on which `local-api.md` draft 4 now also depends: decision 13's "a backup export is the file as encrypted on disk" becomes section 11's export format, and decision 14's "after lock the program does nothing until unlocked" becomes "after lock only the watcher runs" (8.7; 1.0.0, since Slice 1 builds no watcher).
2. **Unicode normalisation in C**: vendor utf8proc (MIT), or another route.
3. **The blocklist, the word list for generated passphrases, and an entropy estimate** in the refusal rules: which lists, sizes and licences (for example the EFF long list, CC BY 3.0 US).
4. **Phones**: the calibration may reach the floor; whether a phone may go lower.
5. **Rekey** (4.8): the crash order to be proven by fault tests, and whether 1.0.0 needs it.
6. **Padding** of batch and penalty payloads (Padmé), and of the mark file's length.
7. **A rollback anchor for the journal itself outside the data folder**: its high-water mark in the store record (one store write per anchored batch), TPM counters, host-reported state (a change for `safety-rule.md` 9).
8. **`memfd_secret`** and equivalents.
9. **The words calls carry the passphrase** (8.6 item 1), with `local-api.md`.
10. **Unattended unlock** for host services (8.6 item 8).
11. **The socket token** stays a plain owner-only file in the runtime folder (12.2).
12. **libsodium confirmation** of every E vector on the three platforms.
13. Closed: folded into `journal.md` draft 3 (sections 2, 2.1, 3, 7, 8.3).
14. **Independent review** of draft 3 against section 17, with `spec/exit.md` draft 2 and `spec/local-api.md` draft 4; and archiving round 2 of the review in `docs/reviews/`.
15. **The bundle**: on by default (proposed); the refusal of "do not watch while locked" while something is to take out (`spec/exit.md` W5); KB's record in the key file (a later format); the CryptProtectMemory proposal.
16. **The cost of anchored batches** on channel updates, to be measured (test 11), with the mark file of draft 3.
17. **The Linux server's store record** in the service's state folder (8.7.3): whether a credential the service can rewrite, or a TPM counter, should replace it.
18. **Second-stage penalties** while locked: whether `channel.md` fixes the HTLC transactions so their penalties can be pre-signed, or the bound of 8.7.5 is accepted (`spec/exit.md` review F4).
