# The storage journal, first cut

Specification draft 3, 2026-11-12. Draft 3 folds in `spec/storage-encryption.md` draft 3: from the first build every file is encrypted (owner decision 13), so the header, the entry framing, the limits and the guard file below are storage's, and a mark file holds the journal's high-water mark. The write, sync, mark and confirm rules, the order rules, the torn-tail rule and the restore rules are unchanged. Draft 2 corrected draft 1 after the third, joint review of the five Slice 1 specifications (`docs/reviews/spec-review-3.md`), which found its torn-tail rule and its restore section wrong. Neither draft 2 nor draft 3 has itself been reviewed. The file-based journal that slice 1 needs (`docs/SLICES.md`: "A file-based journal"). It implements the storage side of the runner contract in `core/gazpacho/include/gazpacho/runner.h`. Items marked **(open)** are listed at the end. Draft 1's "(prov.)" marks are gone: `safety-rule.md` and `signing-round.md` draft 4 settle them.

## Changes after the code review of the journal (PR 29, review A)

Corrections found by reviewing the code against this text. No new draft number: the formats are unchanged; the start and failure rules are stated as they must be on Linux.

| Finding | Change | Where |
|---|---|---|
| R1 a failed sync, then a start in the same boot | Section 4 said the next start "reads the file from disk". On Linux an ordinary read returns the page cache, which after a failed writeback still holds the bytes that never reached the disk (ext4, XFS). Every start now syncs the file and reads it **from the device** (`posix_fadvise(POSIX_FADV_DONTNEED)`, then `O_DIRECT` where the file system takes it); an in-process restart takes the same path, as there is no other | Sections 4, 5 step 2 |
| R2 import order | An import writes the restore marker **first**, then renames the backup over `journal.gzj`; a crash at either point is safe | Section 8.2 |
| R3 lock | The lock is on `journal.lock`, a file in the data folder that is never replaced or removed, taken before the journal is created, imported or marked | Sections 2, 5 step 1 |
| R4 start counter; no journal | Section 5 step 5 takes contract v2 section 8's text: the start counter on every start, written before the incarnation entry, 2^63 refused. A key file with no journal is marked before the first open | Sections 5, 8.2 |
| R7e hard links | Creation uses `link` and, on file systems without hard links, `rename` under the lock | Section 2.1 |
| Crash model | A power-cut job on a real file system is described, not yet in CI | Section 12, test 34 |

## Changes after cross-spec review 1

Alignment fixes from `docs/reviews/review-cross-spec-1.md`, made in one pass with `spec/exit.md`, `spec/storage-encryption.md`, `spec/local-api.md` and `spec/safety-rule.md`. No new draft number: the formats and rules of draft 3 are unchanged.

| Item | Change | Where |
|---|---|---|
| D13 | **Record type numbers assigned** for `spec/exit.md` 3.4's records: area 0x0007 (Exit) for `exit_plan`, `exit_started`, `exit_step`, `coin_reserved`, `fee_child`, `exit_ended` and `bundle_written`; area 0x0008 (Watch) for `spend_seen` and `response_sent`. All even. Slice 3 | Section 9.1 |
| The API's saved state | **Record type numbers assigned** for every row of `spec/local-api.md` 7.5, in a new area 0x000d (Local API), all even. Slice 1 for the S1 rows, 1.0.0 for the rest. This closes Slice 1 input W3 for the type numbers; the field numbers inside each record stay with the code tables (open point 3) | Section 9.1, open point 9 |
| D3 | Every batch that changes the watch bundle or appends a penalty entry is an anchored batch (storage 6.2), whatever records it holds | Section 4 step 4 |

## Changes in draft 3

| Source | Change | Where |
|---|---|---|
| Owner decision 13; `spec/storage-encryption.md` draft 3 (its "What it changes elsewhere") | Encrypted from Slice 1 on: the 185-byte authenticated header of storage 5.3; entries sealed with XChaCha20-Poly1305 under associated data binding file id, offset, kind, incarnation and sequence (storage 5.4), the 16-byte tag replacing the 8-byte checksum; lengths 61 to 8,388,665, exactly 65 for kinds 1 and 3, so incarnation entries and sync marks are 69 bytes | Sections 2, 2.1, 3, 5, 7 |
| Storage 6.2, 7, 10 | Every **anchored batch** (`guard`, `exposure`, `round_signed`, `funding_signed`, `start_sent`, and the channel engine's commitment, revocation and payment-secret records) appends an entry to the mark file before it is confirmed; the guard file is sealed, created at set-up and replaced only for batches with a `guard` record | Sections 4, 8.3 |
| Storage 6.3 | The start rule: a journal behind its mark file, guard, bundle or penalty file, or possibly old, is not started; it may be started as a restore. A key file with no journal always starts as a restore | Sections 5, 8.2 |
| Vectors | J1 to J6 describe draft 2's clear format and are kept for history only; the encrypted equivalents are storage's E5, E6, E7f (J4) and E7a (J6) | Section 11 |

## Changes after review 3

| Finding | How it was handled | Where |
|---|---|---|
| F2 torn tail cuts confirmed records | A **sync mark** entry after every successful sync is mandatory, and a batch is confirmed only once its mark is synced. On start, an invalid entry before any valid sync mark is **corruption**: the start is refused and the user told. Only bytes after the last sync mark may be cut. The 16 MiB bound no longer decides anything | Sections 3.3, 4, 5; vectors J4 to J6; tests 7 to 10, 25 |
| F3 restore | Section 8 now follows `safety-rule.md` section 9: a 31-bit epoch, 0 at installation, drawn **without** the secret tag at the first start after a restore; no `fresh_start` record; the guard is a record plus a guard file with a stated storage duty | Sections 8, 9 |
| F6 names | `round_ended` has the outcome **dead**; Dead records stay and are no longer consulted | Section 9 |
| F7 C7 record | `exposure` holds the funding transaction and the tree digest; `round_started` holds the tier and item indices; compaction keeps all of them | Sections 9, 13 |
| F9 `start` | New records `start_sent` (host) and `start_received` (member) | Section 9 |
| F13 forced writes | A seat is saved only when its state changes; a member saves a current version only before readying for it | Section 9 |
| F21 minimum entry length | 21, then a length per kind | Section 3 |
| F22 the first batch after a restore | Issued by the runner, as sequence 1 of the first new incarnation, in answer to a restore marker | Section 8 |
| F16 "never confirmed" | Restated: only bytes after the last sync mark are known never to have been confirmed | Section 5 |

## 1. What the runner needs from storage

From `runner.h`, `action.h` and `types.h`:

| Duty | Where it is met here |
|---|---|
| A save is one batch of typed records, stored all or nothing | Section 3: one batch is one sealed entry with one authentication tag |
| Batches become durable in the order they were handed over | Section 4: one file, appended in order, by one writer |
| A confirmation is given only for a batch that is safely stored, and in order | Section 4: confirm only after a successful sync covering the batch, and a second one covering the sync mark after it |
| Batch identifiers are {incarnation, sequence}, issued by the runner, never reused | Section 3: the identifier is written in the entry and checked on reading |
| The incarnation is strictly greater than any before, and durable before the runner is used | Section 5: an incarnation entry, synced at every start |
| A storage failure stops the node | Section 4: any write or sync error calls `gz_runner_storage_failed` |
| On start, the node gets every stored record, oldest first (`gz_node_start`) | Section 6: the reader |

The journal belongs to the outer layer (`DESIGN.md` section 3, L4 ports). It may use operating-system calls; the core may not.

## 2. The file

- **One append-only file per node**, `journal.gzj` in the node's data folder. Bytes are only ever added at the end. The one exception is cutting off a torn tail at start (section 5), which removes only bytes after the last sync mark, which were never confirmed.
- **One writer.** The program takes an exclusive lock (`flock` on POSIX, `LockFileEx` on Windows) on `journal.lock` in the data folder for as long as it runs, and refuses to start if the lock is held. The lock file is created if missing and is never replaced or removed: a lock on `journal.gzj` itself would stay on the old file when the name is replaced (an import, a person's copy, a sync tool), and a second program could lock the new one. It is taken before the journal is created, imported or marked; the journal file is locked too. Two processes appending to one journal would interleave batches, and two live copies of one node is a hazard of its own (`safety-rule.md` section 10, "the same key running on two devices").
- Permissions: readable and writable by the owner only (0600 on POSIX).
- **Encrypted from the first build**, on test networks too (owner decision 13; `spec/storage-encryption.md`, "storage" below). The header is authenticated and every entry is sealed under the journal key KJ, a subkey of the storage key, which is unlocked by the wallet passphrase (storage 4, 5). A locked program cannot read or write the journal.

### 2.1 Header

Written once, when the file is created, then never changed. 185 bytes, storage 5.3's format (draft 2's 48-byte clear header with an 8-byte checksum is withdrawn):

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZJOURNE` |
| 8 | `format` | 1 | 1 |
| 9 | `chain` | 32 | The chain hash of the network (signet: `f61eee3b…08000000`, internal order, as in `terms.md`) |
| 41 | `vault_id` | 16 | The key file's |
| 57 | `file_id` | 16 | Random; bound into every entry's associated data |
| 73 | recovery | 72 | The storage key, sealed under a key from the BIP 39 seed, so the 24 words alone reopen the journal (storage 5.3, 9.3) |
| 145 | header tag | 40 | Sealed empty plaintext under KJ over bytes 0 to 144 |

A program refuses a journal whose `magic` or `format` is wrong, or whose `chain` is not its own network, before asking for anything, so a signet journal can never be opened by a mainnet build, and the other way round (`SLICES.md` rule 3). After unlock it checks the header tag; a failure there is "this journal is not this wallet's", distinct from damage.

Creating the file, under the lock: write the header to a temporary name, sync it, give it the name `journal.gzj` with `link` (which never replaces a file that appeared meanwhile) and remove the temporary name, or, on a file system without hard links (FAT, exFAT, some FUSE and SMB mounts, where `link` fails with `EPERM` or `ENOTSUP`), `rename` it, which the lock makes safe; then sync the folder (POSIX). Without the folder sync the file itself may not survive a power cut.

## 3. Entries

After the header the file is a sequence of entries. ("Entry" is the framed unit in the file. "Record" is the core's `gz_record_t`, a type and bytes, several of which may sit in one batch entry.) The framing is storage 5.4's:

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0 | `length` | `u32` | 57 + the payload's length. At least 61, at most 8,388,665 (section 7); exactly 65 for kinds 1 and 3, at least 61 for kind 2 (review 3, F21: no kind has an empty payload) |
| 4 | `kind` | `u8` | 1 incarnation, 2 batch, 3 sync mark. Any other value: the entry is invalid |
| 5 | `incarnation` | `u64` | |
| 13 | `sequence` | `u64` | 0 in an incarnation entry and a sync mark; the runner's sequence, from 1, in a batch entry |
| 21 | `nonce` | 24 | Storage 5.2's hedged nonce |
| 45 | ciphertext | `length` − 57 | The payload of section 3.1, 3.2 or 3.3, encrypted |
| 4 + `length` − 16 | `tag` | 16 | XChaCha20-Poly1305's tag |

All integers big-endian. The **associated data** of every entry is the header's `file_id`, the entry's own offset in the file as a `u64`, and bytes 0 to 20 of the entry, so an entry is valid only where it was written, only in this journal, and with its clear kind, incarnation and sequence exactly as written (storage 5.4).

**The tag replaces draft 2's checksum.** Draft 2 used the first 8 bytes of SHA-256, which caught a torn write but not an attacker, who could rewrite the checksum too. The tag catches both: a torn or half-written entry fails it, and so does any change by someone without the storage key. What it cannot catch is a whole entry cut off at an entry boundary, or an older copy of the file; section 8.3's mark file and storage 6 cover those where it matters.

### 3.1 Incarnation entry (kind 1)

| Field | Size | Meaning |
|---|---|---|
| `clock_ms` | `u64` | The clock port's time at start, for diagnosis only |

`incarnation` is the new incarnation; `sequence` is 0, a value the runner never issues.

### 3.2 Batch entry (kind 2)

The identifier is the runner's {incarnation, sequence} for this save. The payload is the batch:

| Field | Size | Meaning |
|---|---|---|
| `n_records` | `u32` | 0 or more. A batch with no records is still a batch (`action.h`) |
| per record: `type` | `u32` | `gz_record_t.type` |
| per record: `len` | `u32` | |
| per record: `bytes` | `len` | |

The records must fill the payload exactly; a gap or an overrun makes the entry invalid.

### 3.3 Sync mark (kind 3)

| Field | Size | Meaning |
|---|---|---|
| `offset` | `u64` | The offset in the file at which this mark entry itself begins |

A sync mark is written only **after a sync returned success**, and says: every byte before me reached the disk. Its decrypted `offset` must equal its own position; a mark whose `offset` is anything else is invalid. That makes a mark self-locating: a reader can recognise one anywhere in the file, even past a damaged entry whose length it cannot trust (section 5). `incarnation` is the current incarnation, `sequence` 0. A mark yields no records. It is 69 bytes in the file.

### 3.4 Order rules checked on reading

1. The first entry after the header is an incarnation entry.
2. Incarnation entries have strictly increasing `incarnation`.
3. A batch entry's and a sync mark's `incarnation` equals that of the latest incarnation entry before it.
4. Within one incarnation, batch sequences are 1, 2, 3 … with no gap and no repeat.

A valid entry (tag correct) that breaks one of these is **corruption**, not a torn tail, and the program refuses to start (section 5). The writer checks rules 3 and 4 before it writes, and treats a violation as a storage failure: it means the program around the runner handed over batches wrongly.

## 4. Writing and confirming

One writer, fed in the order the runner's executor receives save actions.

1. **Append** the batch entry, sealed whole in memory first (storage 7 step 1), with ordinary writes. A short write, or any error, is a storage failure.
2. **Sync.** POSIX: `fsync` on the file (on macOS, `fcntl(F_FULLFSYNC)`, because plain `fsync` there does not flush the drive's cache). Windows: `FlushFileBuffers`. The sync must cover every entry appended so far.
3. **Mark**, after the sync returned success: append a sync mark (section 3.3) at the current end of the file, and **sync again**.
4. **Anchor**, for an **anchored batch** (storage 6.2: one holding a `guard`, `exposure`, `round_signed`, `funding_signed` or `start_sent` record, or a channel record the channel engine marks as anchored, and, in 1.0.0, **any batch that changes the watch bundle or appends a penalty entry**, for example a `funding_status` or an `exit_plan` date change), after that second sync: append and sync the mark file's entry (section 8.3); replace the guard file if the batch holds a `guard` record; and, in 1.0.0, replace the watch bundle and append the penalty entry where the batch changes them (storage 7 step 2, 8.7.4). A failure of any of these is a storage failure.
5. **Confirm**, after all of that returned success: `gz_runner_confirm` for each batch the first sync covered, oldest first. Only a confirmation the runner accepts (`GZ_OK`) becomes a `GZ_EVENT_STORAGE_CONFIRMED` event for the node.

**Why two syncs.** A batch is confirmed only when a synced mark after it proves it reached the disk. So every confirmed batch lies before a durable sync mark, and the reader can tell damage to a confirmed entry (before a mark: corruption) from a write that never finished (after the last mark: a torn tail) exactly, whatever the file's size (review 3, F2). Draft 1 inferred this from a size bound, which classified any damage in a small journal, such as every Slice 1 journal, as a torn tail and silently cut confirmed records. The cost is a second small sync per group; the journal writes kilobytes per user action, and group syncing amortises it.

**Group sync.** The writer may append several batch entries and run steps 2 to 5 once for all of them (one mark-file entry covers them all), confirming them in order. The bytes appended since the last successful sync stay below **16 MiB**, unless a single entry is larger by itself, which section 7 forbids; this now only bounds memory and loss on a crash, and the reader no longer relies on it. The runner allows 32 unconfirmed batches.

**Failures.** If a write or a sync fails, the writer calls `gz_runner_storage_failed`, confirms nothing more, writes nothing more, and the program stops the node. It never retries a failed sync and carries on: after a failed `fsync`, ext4 and XFS mark the unwritten pages clean and keep them, with the new bytes, in the page cache, so a second `fsync` succeeds without writing them and an ordinary read still returns them (PostgreSQL's "fsyncgate", 2018; Rebello et al., "Can Applications Recover from fsync Failures?", USENIX ATC 2020). Since Linux 4.13 the error is reported once per open file description, so a later program's `fsync` usually returns 0. The next start, in another process or in the same one (a restart from storage after this failure), therefore must not trust the page cache: it syncs the file, then reads it **from the device** (section 5 step 2), and finds out what survived. Reading the cache instead would give the node a batch that was never durable and append a sync mark after it, which a later power cut turns into corruption.

**Nothing is confirmed early.** A confirmation means the batch, and a sync mark after it, have passed a successful sync. Everything the runner releases after a confirmation (sends, broadcasts, notices) therefore rests on durable data. This is "save before send" at the storage end.

## 5. Starting

In this order. Every step that writes syncs before the next step.

1. Take the lock (`journal.lock`, section 2). Open the file. A data folder with a key file and no journal starts **as a restore** (storage 6.3 step 0; section 8.2): the restore marker is written, the journal is created (section 2.1) and the restore's first batch follows step 5.
2. **Read what the device holds.** Sync the file (refuse to start if that fails), then read it bypassing the page cache: on Linux, `posix_fadvise(POSIX_FADV_DONTNEED)` over the file, which drops clean cached pages and so the pages a failed writeback left, then `O_DIRECT` reads where the file system takes them (a direct read never returns a cached page; ext4 with `data=journal` silently falls back to buffered reads, which is why the `fadvise` comes first; a file system that refuses `O_DIRECT` gets the `fadvise` and an ordinary read). macOS: `F_NOCACHE`. Windows: `FILE_FLAG_NO_BUFFERING` **(open: the Windows port)**. Check the header (section 2.1), after the wallet was unlocked (storage 8.2).
3. **Scan** entries from the start. An entry is **invalid** if its `length` is below 61, above the maximum or wrong for its kind, if fewer bytes remain in the file than it claims, if its `kind` is unknown, if its tag does not verify under KJ with its own offset in the associated data, or if it is a sync mark whose decrypted `offset` is not its own position (storage 5.5). Stop at the first invalid entry, or at the end of the file. Check the order rules (section 3.4) on every valid entry; a violation stops the start (corruption).
4. **Torn tail or corruption.** Let V be the offset just after the last valid entry, and E the end of the file.
   - V = E: the file is clean.
   - V < E: search the bytes from V + 1 to E for a **valid sync mark**: at any offset p, a 69-byte entry with `length` 65, `kind` 3, a tag that verifies at offset p, and a decrypted `offset` = p. A false match would need a forged authentication tag.
     - **None found: a torn tail.** The bytes from V on were appended after the last durable sync mark, so no batch in them was ever confirmed and nothing outside the node depended on them. Cut the file to V and sync.
     - **One found: corruption.** The damaged entry at V lies before a mark that proves it was synced, so it may hold a confirmed batch, a `round_started` or an `exposure` record that a peer has seen. **Refuse to start and tell the user**; never cut it away. The remedy is a restore (section 8), whose new epoch makes it safe (`safety-rule.md` section 9).

   Valid-looking entries after an invalid one, in a torn tail, are dropped with it. A group sync can reach the disk out of order, so a later entry may survive while an earlier one is torn. Keeping the later one would break the order the runner relies on, and it was never confirmed: its mark, if written at all, did not survive.
5. **Incarnation.** Read the start counter (storage 10.3; `docs/notes/contract-v2.md` section 8). New incarnation = 1 + the larger of the highest found in the journal and the counter (the journal alone if the file is missing or damaged), and, while a restore is unanswered, above the restore marker's floor; refuse to start if the result would reach 2^63. Write the counter with it, then append the incarnation entry, sync, append a sync mark, sync. Only then may the runner be created with `gz_runner_init(…, incarnation, …)`. This meets the runner's duty: strictly greater than any before, durable before use. Writing the counter first keeps a restored journal, whose counter is older, from reusing a number used on this device since its backup; it does not defend a snapshot of the whole folder (storage 6.4). An incarnation is consumed even if the program then stops without saving anything; that is harmless.
6. **The start rule** (storage 6.3): the journal is compared with its mark file and guard (section 8.3) and, in 1.0.0, with the watch bundle and the penalty file. A journal **behind** any of them, or **possibly old** (a guard or mark file missing or damaged), is not started: the person may start it as a restore (section 8.2) or put the newer files back (`local-api.md` 4.7).
7. **Read** the records with the reader (section 6) and pass them to `gz_node_start`.

A crash anywhere in steps 4 and 5 is safe. Cutting a torn tail twice cuts nothing the second time. An incarnation entry that was torn is itself cut on the next start (no mark follows it), and the next start writes the same number again; since nothing was issued under it, nothing is reused. An incarnation entry that was synced but whose mark was lost is kept, and the next start uses the next number.

## 6. Reading back

The **reader** walks the valid entries in file order and yields, for each batch entry, its records in the order they were written. Incarnation entries yield nothing. The result is the list `gz_node_start` takes: "the records found in storage, oldest first".

- A record's type follows the odd/even rule of `messages.md` section 4.1 (bit 0 of the 32-bit type): **an unknown even type stops the start**, because a newer program wrote something this one cannot interpret; **an unknown odd type is skipped**. The placeholder test types (`0x7e57xxxx`, `node.h`) are outside this rule and disappear with the placeholder.
- Batch boundaries are not passed to `gz_node_start` today; the records of one batch arrive together and in order, which is all a node needs to rebuild. If a later engine needs the boundaries, the reader can give them without a format change.
- Slice 1 loads every record into memory before `gz_node_start`. At slice 1's sizes (a host and a few members) that is kilobytes to a few megabytes. Snapshots, which bound start-up time and memory, come later (`DESIGN.md` section 9) **(open)**.

## 7. Limits

| Limit | Value | Why |
|---|---|---|
| Largest entry | 8 MiB payload (`length` ≤ 8,388,665 = 8 MiB + 57) | The host's largest slice 1 batch is the signed tree with each member's saved `round_tier_result` and `round_complete` (kept for `round_status_request`, `messages.md` 7.10): at 1,000 members about 2 KB per member, 2 MB, plus a proposal under 400 KB. 8 MiB is three times that. A node never needs a larger batch; a larger `length` on reading is invalid |
| Unsynced bytes | 16 MiB | Two maximum entries. Bounds memory and what a crash can lose; the reader does not rely on it (section 4) |
| File, soft | 768 MiB | The program tells the user and stops opening or joining new lobbies, so a factory under way can finish |
| File, hard | 1 GiB | Below 2^31, so offsets fit in a signed 32-bit `long` on every platform the program targets (Windows `ftell` returns a 32-bit `long`). An append that would pass it is not written: the writer reports a storage failure, and the node stops with "storage full" |

Use per factory, estimated: a host at 1,000 members about 3 MB per signing attempt; a member about 0.5 MB (dominated by the saved proposal). At slice 1's size, a few tens of kilobytes. The hard limit is therefore far away for slice 1; compaction and snapshots are needed before large hosts run for long **(open)**.

When full: nothing is lost, because nothing unconfirmed was released. The node cannot act until space is freed by a later compaction tool **(open)**, or until the user moves to a new journal after the node's factories are closed.

## 8. Restores and the record of rounds started

### 8.1 On one device

The journal is a monotonic record: every round identifier a node ever saved is in it, in order, and is never removed. On start the node builds from it the set of refused round identifiers and the set of funding outpoints with an exposure record (and their tree digests). These two sets are what stop a node contributing twice to one identifier (`signing-round.md` section 3) and signing two trees on one outpoint (`safety-rule.md` C7). Section 5's sync marks make sure damage to them stops the start instead of removing them (review 3, F2).

### 8.2 Across a restore

The backup is a copy of this journal, and the host keeps one. A copy dated before a round lacks that round's records, so a restored node must not rely on them. The rules are `safety-rule.md` section 9; this section says what the journal stores for them.

1. **Epoch 0 at installation.** At the first start of a new journal the node saves `key_epoch` with epoch 0.
2. **A new epoch at the first start after a restore.** The node draws 8 bytes from the randomness port with the **ordinary, untagged** request and takes as the epoch 31 bits of a bijective mix of them with its incarnation (`safety-rule.md` R2), retrying while it is 0, and saves it in `key_epoch`. Mixing in the incarnation, which a restore cannot rewind, keeps a port that repeats after a restore from repeating the epoch. The epoch is saved and backed up, so it is not secret and must not use the secret tag, whose bytes are never journaled (`signing-round.md` section 8; review 3, F3). Every per-lobby key (contribution key, factory key) is derived from the seed, the current epoch and an index (`key_index`), so no key used after the backup can come back. A replayed proposal names a key of the old epoch; the restored node's current key for that lobby is not in it (or it has none), and it refuses with `round_abort` reason 12 (`messages.md` 7.2). A second tree on an old outpoint would need the old aggregate key in its funding script, which C1's check refuses.
3. **No fresh-start confirmation.** Draft 1's `fresh_start` record and its "no creation until the user confirms" rule are withdrawn; the new epoch is the protection. The `restored` record lets the app tell the user, once, that it was restored and which seats were lost.

The index within an epoch is recorded too (`key_index`), so that an ordinary restart never derives the same key twice.

**How a restore is recognised and who writes the first batch.** A restore is an explicit program action: importing a backup file (storage 11), the person starting files found behind as a restore (storage 6.3 step 4; `local-api.md` `start-as-restore`), or the program finding a key file with no journal (storage 6.3 step 0). The program then starts normally (section 5), creating the runner under the new incarnation, and tells the node, **before any other event and before connecting to anyone**, that this start follows a restore (`signing-round.md` section 12.1). The node answers with one save batch, `key_epoch`, `restored` and `guard`, which the runner issues as sequence 1 of that incarnation like any other batch; nothing else is sent until it is confirmed (review 3, F22). A copy of the data folder made by other means is not recognised; that is the "copy of a running program" limit of `signing-round.md` section 8 and is not defended.

**The restore marker and its order.** The program marks a restore in `restore.gzr` beside the journal (outside the backup set), holding the imported journal's highest incarnation (`base`) and the highest the replaced one had used (`floor`). Every start is restored until a batch with sequence 1 of an incarnation above `base` is durable (the restore's first batch); the marker is then removed before that batch is confirmed. **An import writes the marker first, then the file**: under the lock, read the backup (copied first to a temporary name in the data folder), take the floor from the journal it replaces, write and sync the marker, then rename the backup over `journal.gzj` and sync the folder. A crash before the rename leaves the old journal with a marker whose `base` it is already above, so the next start finds the marker answered and removes it (the import did not happen); a crash after it is a marked restore. The other order (file first) has a window in which the backup starts as an ordinary journal and reuses an incarnation. A key file with no journal is marked with `base` 0 before the first start. The new incarnation is taken from the start counter as at every start (section 5 step 5), so it is above every incarnation this device used since the backup. A restore that finds no counter tells the person.

### 8.3 The guard file and the mark file

`safety-rule.md` R6's guard, which detects a stale backup, and the journal's high-water mark, which detects a journal cut back or rolled back (storage 6, 10).

- **Where.** `guard.gzg` and `mark.gzm`, in the program's own data folder **outside** the journal's backup set: a restore replaces `journal.gzj` and never these. The user's export carries a copy of the guard.
- **The guard file's format** is storage 10.1's: a 41-byte clear head (`GZGUARDE`, format, chain), then the contents sealed under a key from the seed (KG), so the guard stays readable across a restore that makes a new key file. Contents:

| Field | Size | Meaning |
|---|---|---|
| `counter` | `u64` | Incremented at every write |
| `n_epochs` | `u16` | Epochs used, oldest first |
| per epoch: `epoch`, `highest_index` | `u32`, `u32` | The highest key index allocated under it |
| `rounds_started` | `u64` | Rounds this node ever started |

- **The mark file's format** is storage 10.2's: a 57-byte clear head naming this journal's `file_id`, then appended 56-byte entries, each the incarnation and the sync-mark offset of one anchored batch, sealed under a key from the storage key (KH). Its first entry, written at set-up, means "no mark yet".
- **Created at set-up**, before the journal (storage 7.4), so a missing file always means something was removed.
- **How the core orders the guard.** The core puts a `guard` record (section 9), holding the guard's contents, in the same save batch as every `key_index` and every `round_started` record. The runner rule then holds every send behind that batch's confirmation, so no new action or port is needed.
- **The storage duty.** For every anchored batch (section 4, step 4), after the batch and its sync mark are synced and before the batch is confirmed, the writer appends and syncs the mark file's entry; for a batch that holds a `guard` record it also replaces the guard file (write `guard.gzg.tmp`, sync it, rename it over `guard.gzg`, sync the folder). A failure of any step is a storage failure (section 4).
- **At start** (section 5, step 6): the journal is **behind** if the mark file names another journal, or its newest entry names a sync mark the journal does not have under that incarnation, or the guard's `counter` is above the newest `guard` record's; it is **possibly old** if either file is missing or damaged while a key file exists. A legitimate torn-tail cut never trips this, because a mark entry is written only after its sync mark was synced. Storage's E9m shows a cut journal refused.
- **On a restore.** Before importing, the program reads `guard.gzg` (or the user's exported copy) and the newest `guard` record in the backup. If the file's `counter` is higher, the backup is stale and the user is told; the restored node keeps the file's epoch list, so keys of later factories can still be derived for the recovery procedure (R7). If there is no guard file, the backup is treated as possibly stale. Either way the restore goes ahead under a new epoch: the guard only detects. A restore starts a new mark file for the journal it produces.
- **What neither detects**: an older copy of the whole data folder, or of the mark file alone, put back by someone who can write the folder (storage 6.4).

## 9. What slice 1 stores

Record types are `u32`. The high 16 bits name an area, the low 16 bits a kind. Every slice 1 type is even (must be understood). Each record's bytes are a TLV stream under the rules of `messages.md` section 4.2, so fields can be added as odd types later; the type numbers inside each record are fixed with the engine's code tables **(open)**. "Saved before" names the outward action that waits for it. Saved message bytes are always the native envelope (`messages.md` section 4: tag, `kind`, `scope`, records). The carrier, type 52791 or the bLIP-56 adapter of `messages.md` section 10, is added when sending, so "resent byte for byte" holds in either carrier.

**Node (0x0004)**

| Type | Record | Contents | Saved before |
|---|---|---|---|
| `0x00040002` | `key_epoch` | The epoch, `u32` below 2^31: 0 at installation, random and non-zero after a restore (section 8.2) | Any key of the epoch is derived |
| `0x00040004` | `key_index` | Highest per-lobby key index allocated in the epoch | The key is used, including in a BOLT 8 handshake (`messages.md` section 2) |
| `0x00040006` | `restored` | Clock, the backup's newest incarnation, whether a guard file was found and whether it was ahead | Anything else after a restore (section 8.2) |
| `0x00040008` | — | Not used (draft 1's `fresh_start`, withdrawn) | — |
| `0x0004000a` | `guard` | The guard contents of section 8.3, without `check` | Same batch as each `key_index` and `round_started`; the guard file is replaced before the batch is confirmed |

**Lobby (0x0001)**

| Type | Record | Kept by | Contents | Saved before |
|---|---|---|---|---|
| `0x00010002` | `lobby_opened` | Host | Outer record, its signature; current values version 1, its signature | The first `terms_offer` |
| `0x00010004` | `terms_version` | Host | A new current record and signature | The `terms_offer` carrying it |
| `0x00010006` | `seat` | Host | Contribution key, factory key, both bindings, seat state, the seat's latest signed `ready` bytes | The `lobby_status` that confirms the change. Saved only when the seat's state changes, within the limits of `messages.md` section 6 (review 3, F13) |
| `0x00010008` | `freeze` | Both | `check_id`, version, current digest, the signed `ready_check` bytes | Host: the first `ready_check`. Member: its `ready` answering it |
| `0x0001000a` | `lobby_ended` | Both | Final state, reason, the signed `cancel` bytes if any | Nothing; for history |
| `0x0001000c` | `terms_received` | Member | Host address and key; outer record and signature; a current record and signature | `join` (the first, with the outer record), and `ready` for a version (that version). A version the member does not ready for is not saved (`terms.md` section 7) |
| `0x0001000e` | `joined` | Member | Lobby id, key epoch and index of its keys, the `join` bytes | `join` |
| `0x00010010` | `ready_sent` | Member | The signed `ready` bytes | `ready` (resent byte for byte) |
| `0x00010012` | `host_fault` | Member | Evidence: two current records under one version, a version after the freeze, or two proposals under one round identifier | `leave`, or nothing (for a proposal) |
| `0x00010014` | `start_sent` | Host | `check_id`, the chosen seats, the signed `start` bytes for each seat | The first `start` of the check; resent from it after `hello` (`messages.md` 6.9) |
| `0x00010016` | `start_received` | Member | The signed `start` bytes | Nothing; consulted when `round_propose` arrives |

**Round (0x0002)**

| Type | Record | Kept by | Contents | Saved before |
|---|---|---|---|---|
| `0x00020002` | `round_started` | Both | Round id, funding outpoint, purpose, attempt, and the tier and item indices the party is about to send nonces for (`signing-round.md` rule S1). Small, never removed: the monotonic record of rounds started | Member: `round_nonces`. Host: `round_propose` (its own nonces are in `round_all_nonces`, which comes later). Same batch as a `guard` record |
| `0x00020004` | `round_proposal` | Both | The signed `round_propose` bytes, as sent or received | Same batch as `round_started`. Kept for evidence and for the rebuild; may be dropped by a later compaction once the round is resolved, because `exposure` keeps what C7 and C4(d) need |
| `0x00020006` | `exposure` | Member | Round id, tier, funding outpoint, **the funding transaction** (as in `round_propose`, without witnesses), **the tree digest** (`messages.md` 7.12), for each item it signs: index, spent outpoint, signature digest; and the signed `round_partial_sigs` bytes | `round_partial_sigs`. **This is the C7 record, written before the first partial signature for that outpoint.** One batch: the record and the bytes it releases. Never compacted away: C7 compares tree digests with it, and C4(d) watches the funding transaction's inputs from it (review 3, F7) |
| `0x00020008` | `round_signed` | Both | Member: final signatures for its items. Host: final signatures for every item, and the signed `round_tier_result` bytes for each member | Member: `round_ack`. Host: the `round_tier_result` messages |
| `0x0002000a` | `round_completed` | Both | Member: the signed `round_complete` and `round_ack` bytes. Host: the signed `round_complete` bytes | Member: `round_ack`. Host: `round_complete` |
| `0x0002000c` | `ack_received` | Host | Member's contribution key, the signed `round_ack` bytes | Signing the funding (H1) |
| `0x0002000e` | `round_ended` | Both | Outcome: aborted, failed, **abandoned** (a funding or unfinished deadline passed), **dead** (a funding input spent by another buried transaction), or live; reason; evidence if any. A later record may move abandoned to live or dead | Nothing; the identifier is already refused by `round_started`. A dead round's records stay in the journal and are no longer consulted (review 3, F6) |

**Funding (0x0003)**

| Type | Record | Kept by | Contents | Saved before |
|---|---|---|---|---|
| `0x00030002` | `funding_plan` | Host | The unsigned funding transaction and the coins it spends, which the wallet now holds back from any other use | `round_started` of the attempt that uses it (the outpoint is in the identifier) |
| `0x00030004` | `funding_signed` | Host | The signed funding transaction | Its broadcast; rebroadcast from it after a restart |
| `0x00030006` | `funding_status` | Both | Txid, state (broadcast, seen, confirmed at height h with n confirmations, buried, reorganised away, input spent elsewhere), height; for the member also the height at which it sent its ack (the start of the funding deadline) | Telling the user; C11's "live" decision is taken from it |

The host keeps the per-member results until the factory's funding output is spent or the creation is dead (`messages.md` 7.6, `safety-rule.md` H12).

### 9.1 Records numbered now for the exit engine and the local API

Numbered after cross-spec review 1, under the same rules: `u32`, the high 16 bits the area of `PROTOCOL.md` 10.4 (0x0007 Exit and 0x0008 Watch are reserved there; 0x000d Local API is new and is to be added to that table), the low 16 bits the kind, numbered 2, 4, 6 … in the order below. **Every one is even** (must be understood): misreading any of them would change what the node signs, publishes, answers or shows, so a program that does not know one stops the start (section 6). Fields are TLV streams under `messages.md` section 4.2; their numbers are fixed with the code tables (open point 3). "Release" is the slice that writes them.

**Exit (0x0007)** (`spec/exit.md` 3.4, which gives each record's fields and the batch it belongs to)

| Type | Record | Contents | Saved before | Release |
|---|---|---|---|---|
| `0x00070002` | `exit_plan` | d; the path's txids in order, which output of each the next spends, anchor output per step; H_leaf; the constants in force; the dates of `spec/exit.md` 4.4; the tip estimate's anchor | The bundle's B4 and B5 are written from it; in the batch that makes the factory live, and again on every date change | Slice 3 |
| `0x00070004` | `exit_started` | Reason; tip estimate, its anchor and the counted view; chain state; the commitment number chosen | The exit's first broadcast; same batch as the channel engine's stop | Slice 3 |
| `0x00070006` | `exit_step` | Step index; txid; `sent`, `confirmed` or `buried` with height, time or block hash; the server results | Each step's first broadcast (`sent`) | Slice 3 |
| `0x00070008` | `coin_reserved` | Wallet outpoints used by a child | That child's broadcast | Slice 3 |
| `0x0007000a` | `fee_child` | Parent txid; child bytes; package rate; fee; which child it replaces | That child's broadcast | Slice 3 |
| `0x0007000c` | `exit_ended` | `ended_how`; amounts recovered from the confirmed transactions | Nothing | Slice 3 |
| `0x0007000e` | `bundle_written` | The bundle counter (storage 8.7.4 rule 4) | Nothing; in the batch that rewrites the bundle | Slice 3 |

**Watch (0x0008)**

| Type | Record | Contents | Saved before | Release |
|---|---|---|---|---|
| `0x00080002` | `spend_seen` | Outpoint; spender txid; classification (`spec/exit.md` section 8) | Any response | Slice 3 (Slice 1.5 for the tree's outputs) |
| `0x00080004` | `response_sent` | Trigger txid; response bytes; deadline | The response's broadcast | Slice 3 |

`exit_plan`, `exit_started`, `exit_step`, `coin_reserved`, `fee_child`, `spend_seen` and `response_sent` are never compacted while their factory is not `ended` or `dead` (`spec/exit.md` 10.3).

**Local API (0x000d)** (`spec/local-api.md` 7.5, which gives each record's contents and the batch it is saved with)

| Type | Record | `local-api.md` 7.5 row | Release |
|---|---|---|---|
| `0x000d0002` | `setup_state` | Setup state | S1 |
| `0x000d0004` | `words_checked` | Words checked | S1 |
| `0x000d0006` | `words_check_attempts` | Words-check attempts | S1 |
| `0x000d0008` | `conditions` | Conditions | S1 |
| `0x000d000a` | `conditions_copy` | Conditions copied at joining (same batch as `joined`) | S1 |
| `0x000d000c` | `pause` | Pause | S1 |
| `0x000d000e` | `local_ids` | Local ids | S1 |
| `0x000d0010` | `known_host` | Known hosts | S1 |
| `0x000d0012` | `activity_entry` | Activity entries | S1 |
| `0x000d0014` | `request_id` | Request ids | S1 |
| `0x000d0016` | `set_aside` | Set-aside funds | S1 |
| `0x000d0018` | `sign_out_setting` | Sign-out setting | 1.0.0 |
| `0x000d001a` | `settings` | Settings | 1.0.0 |
| `0x000d001c` | `review_id_spent` | Review and preview ids spent | 1.0.0 |
| `0x000d001e` | `host_node` | Host-node setting | 1.0.0 |
| `0x000d0020` | `chain_server_added` | User-added chain servers | 1.0.0 |
| `0x000d0022` | `while_closed_report` | While-closed reports | 1.0.0 |

## 10. What is never stored

- **Secret nonces**, MuSig2 secret session state, and the randomness they were made from (`signing-round.md` section 8). Not in any record, not in a payload "for debugging", not in the clear and not encrypted. A node rebuilt from its journal can therefore never recreate one, and a round found in progress is never resumed: it becomes Aborted, or Unfinished if partial signatures were sent (`signing-round.md` section 7).
- **The state of any random generator.** The randomness port reads the operating system at the moment of use in release builds.
- **Private keys and the seed.** They live in the wallet's key file, outside the journal; the journal holds key epochs and indexes, from which keys are derived again. A journal leak therefore reveals the user's history, not their keys.
- **BOLT 8 session keys** and handshake ephemerals.
- **Parts of a split message** (`messages.md` section 5): only whole messages are saved.

A test checks this directly: the simulator records every secret nonce it creates, and after each run the journal file is searched for those exact byte strings. No match is allowed.

## 11. Test vectors

Computed by `tools/spec-vectors.py`. **J1 to J6 are draft 2's clear format, which is not built**: the encrypted journal's vectors are storage's E5 (header), E6 (entries), E7 (tampering; E7f is J4's torn tail and E7a is J6's corruption) and E9m (the mark file). J1 to J6 are kept because the tool still prints them, and because their framing logic (marks, torn tails, order rules) is the same.

**J1. Header, signet.** 48 bytes:

```
475a4a4f55524e4c f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
5477d18c2a8b6425
```

**J2. Incarnation 1, clock 1,794,000,000,000 ms.** 37 bytes:

```
00000019 01 0000000000000001 0000000000000000 000001a1b2bb9400 5ba5a611f1eac4ed
```

**J3. Batch (1, 1) with one record of type `0x7e570001` and bytes `ping`.** 45 bytes:

```
00000021 02 0000000000000001 0000000000000001
00000001 7e570001 00000004 70696e67
ff0269042d9a3f7d
```

**J5. Sync mark** of incarnation 1 at offset 85, just after J2 (the header is 48 bytes). 37 bytes:

```
00000019 03 0000000000000001 0000000000000000 0000000000000055 11b8de34bb2fdb81
```

**J4. Torn tail** (changed after review 3). The header, J2, J5, then J3 without its last 3 bytes: 164 bytes in all. No sync mark follows the damage at offset 122, so the reader cuts the file to 122, keeping J2 and J5, and the next incarnation is 2.

**J6. Corruption** (new). The header, J2, J5, J3 with bit 0 of its byte 25 flipped (the first byte of the record type), then a sync mark at offset 167: 204 bytes. The damaged entry at 122 lies before a valid mark that names its own offset, so the start is **refused**, nothing cut. The second mark is:

```
00000019 03 0000000000000001 0000000000000000 00000000000000a7 aecd69c7d1113773
```

## 12. Tests

**Format**
1. Storage's E5 to E7 and E9m reproduce exactly (J1 to J6 for the tool's history only).
2. Header with a wrong magic or format, the mainnet chain hash, another wallet's `vault_id` or a damaged header tag: refused, with the stated reasons.
3. Every field of an entry altered in turn: `length` 60, 56, 0, the maximum + 1; an incarnation or sync mark with `length` other than 65; unknown `kind`; a sync mark whose decrypted `offset` is not its own; a flipped bit in each region, the clear fields and the nonce included: the entry is invalid.
4. A batch whose records under- or overrun the payload: invalid.
5. Order rules: a batch before any incarnation; an incarnation that does not increase; a batch under an older incarnation; a sequence gap; a repeated sequence. Each, with valid tags: refuses to start.
6. An empty batch is written, synced, confirmed and read back as no records.

**Torn tails and corruption**
7. For every byte offset inside the last entry after the last sync mark, the file cut there: the start cuts the tail, keeps every earlier entry, and the next incarnation is one higher. E7f reproduces.
8. Zero bytes appended after the last sync mark (a file grown but never written): cut as a torn tail.
9. A group of entries after the last mark in which an earlier one is torn and a later one is intact: both dropped.
10. An invalid entry anywhere before a valid sync mark, however close to the end of the file: refused as corruption, nothing cut. E7a reproduces.
25. **Review 3, F2.** A Slice 1 member journal of about 40 KB with a flipped bit in a confirmed `exposure` entry: the start is refused and the user is told; the entry and everything after it are untouched. The same with the bit flipped in the last batch after the last mark: cut as a torn tail.
26. A crash after the first sync and before the mark's sync: the batch is not confirmed, nothing it held back was sent, and on restart the batch is either kept (its mark survived, or no damage) or cut as a torn tail.
27. Rule removed: with the mark written but batches confirmed after the first sync only, test 25 combined with a crash before the mark's sync must show a confirmed record cut. That test must fail.
11. A crash between cutting the tail and writing the incarnation, and in the middle of writing the incarnation: the next start is correct and never repeats an incarnation under which a batch was issued.

**Durability (fault injection in the storage layer)**
12. A failing sync: no confirmation, `gz_runner_storage_failed`, nothing written after it; restart reads only what was synced.
13. A short write and a full disk: as test 12.
14. A crash at every point of a run (after each write, after each sync, after each confirm), with unsynced bytes either lost, kept, or kept out of order: on restart no confirmed batch is missing, and nothing the runner released depends on a missing batch. This is checked by the simulator's invariant "nothing is sent before it is saved".
15. A confirmation from before a restart arrives late: the runner reports `GZ_ERR_STALE_BATCH` and releases nothing (existing runner test, run against the real journal).
16. A second process tries to open a locked journal: refused.
17. Soft and hard limits: at the soft limit the user is told and new lobbies are refused; at the hard limit the append is not written and the node stops; nothing confirmed is lost.

**Records**
18. An unknown even record type: the start stops. An unknown odd type: skipped.
19. Every slice 1 record round-trips through save, crash, restart and reader, and the node rebuilds the same lobby and round state.
20. The member restarts after `round_started` and before `round_nonces`: the identifier is refused, reason 3 is sent. After `exposure` and before `round_partial_sigs` left: the saved bytes are sent, byte for byte, never re-signed.
21. A member with an `exposure` record for an outpoint receives a different round on that outpoint: refused (C7, review 2 N6).
22. Secret nonces: the byte search of section 10 over the journal after every simulator run.
23. Restore (review 2, N1, test 4b): a journal copy from before a creation round is restored; the host replays that round's proposal and proposes a second tree on the same outpoint. Both are refused with reason 12; no key from after the backup is derived again; the first batch of the restored node is `key_epoch` (non-zero), `restored` and `guard`, issued by the runner as sequence 1; nothing is sent before it is confirmed. The epoch is drawn with the untagged request (the simulator's port records the tag).
28. Guard and mark file: with a guard file ahead of the backup, the restore tells the user the backup is stale and keeps the file's epochs; with none, it says "possibly stale". A batch with a `guard` record is not confirmed until the guard file is replaced and synced, and an anchored batch not until its mark-file entry is synced; a failure there is a storage failure. The journal cut back after an anchored batch is not started (storage test 8).
24. Rule removed: with the `exposure` record written after `round_partial_sigs` is sent instead of before, test 21 combined with a crash at that point must show a second tree signed on one outpoint. That test must fail.

**Failed syncs, imports and the folder (code review of PR 29)**
29. A failed sync modelled as Linux fails one (the bytes readable, never durable; a later sync does not write them), for the batch's sync and for its mark's: the next start in the same boot, or the same process restarting, does not give the node the batch that failed, and after a power cut the start after that is not refused. The older model (failed bytes vanish from view) passes too.
30. An import crashed at every point, every settle: the next start is the old journal, not restored, or the backup, restored, and never reuses an incarnation. With the counter, a backup put in place without a marker does not reuse one either.
31. A copy renamed over `journal.gzj` while a program runs does not let a second program in; two first starts at once: the second finds the folder locked; marking or importing while the journal is open is refused.
32. The start counter: above the journal, handed out before the incarnation entry, a failure to write it appends nothing; contract v2's test T8 on the journal alone (backup at 2, five starts, restore: 6); a counter, floor or journal at 2^63 - 1 or above refuses the start. A key file with no journal starts restored.
33. The hard limit with the unsynced bound's extra mark; a guard batch kept across a kill reaches the guard file (not on a restored start, not over a newer or damaged one); a flush with no runner attached refuses and keeps its batches; a flush from the confirmation callback confirms in order; a file system without hard links.

**Power cuts on a real file system (34, not yet in CI).** The memfs crash model settles a crash as LOSE, KEEP or REORDER, and test 29 adds Linux's failed sync; the real-process kill sweep keeps the page cache. Neither cuts the power under a real file system. The job that would: LazyFS (`github.com/dsrhaslab/lazyfs`, a FUSE file system that keeps unsynced writes in its own cache and drops them on command, used to find such bugs in etcd and PostgreSQL), mounted over an ext4 folder: run the kill sweep's workload in it, tell LazyFS to clear its cache at random points instead of a SIGKILL, remount, open, and run the harness's check that no confirmed batch is missing. Or `dm-log-writes` under ext4 and XFS, replaying the log to every flush and FUA and opening the journal at each. Neither fits the existing CI cleanly: both need root, FUSE or device-mapper on the runner, and LazyFS a build from source, so this is meant as a nightly job on the build server rather than a check on every push. Its expected result is test 14's.

## 13. Open points

1. Closed: **encryption at rest** is in from Slice 1 (owner decision 13; open point 10).
2. **Snapshots and compaction**, to bound start-up time, memory and file size. Rule to keep: `round_started`, `exposure` (with its funding transaction and tree digest), `key_epoch`, `key_index` and the newest `guard` records are never compacted away, and neither are sync marks after the newest compaction point.
3. **TLV field numbers inside each record type**, fixed with the engine's code tables.
4. **Backups.** The journal is also the backup (`DESIGN.md` section 9). How it is exported and how a restore is triggered belongs to the backup specification; section 8 states only what a restore must write.
5. Closed: section 8 follows `safety-rule.md` draft 4 section 9.
6. Closed: an unfunded creation is **Abandoned** at the member's funding or unfinished deadline (36 blocks and one signing budget in Slice 1, **proposed, owner to confirm**, `safety-rule.md` section 12) and **Dead** when a funding input is spent elsewhere and buried. Its records stay; neither blocks the member.
7. Closed: the sync mark is mandatory (sections 3.3 to 5).
8. **Linux `fdatasync`** would do instead of `fsync` for appends (it flushes the size change too); `fsync` is specified for simplicity until measured.
9. **API needs** (from `spec/local-api.md` draft 2, section 7.5, after its review found the API's state had no home here, review F11). The local API needs records that are not protocol bytes, in an area of their own. **Their record type numbers are now assigned** (section 9.1, area 0x000d; cross-spec review 1); only their field numbers wait for open point 3 (`OPEN-QUESTIONS.md` W3). What each must hold, and the batch it belongs to:

| Record (working name) | Contents | Saved with, before | Release |
|---|---|---|---|
| Setup state | `created_not_finished` or `ready`; the preset and finding choice | Before `create` and `finish-setup` answer | S1 |
| Words checked | `checked_at` | Before a successful words check answers | S1 |
| Words-check attempts | Time of each check started in the last 24 hours | Before `check-start` answers, so a restart does not reset the limit | S1 |
| Conditions | The member's conditions, preset, version | Before `PUT /conditions` answers; same batch as any `leave` it causes | S1 |
| Conditions copy | Per joined lobby: the conditions, their version and `compare_with` at joining | **Same batch as `joined`**: the ready check and the signing check compare against this copy after a restart | S1 |
| Pause | On or off, since when, the lobby a pause is held for | Before the pause call answers and before any `leave` or `round_abort` it sends; applied on start before any connection | S1 |
| Local ids | Local lobby and factory ids with their fingerprints | With the lobby's first record (`terms_received` or `lobby_opened`), and with the factory's first round record | S1 |
| Known hosts | Key, address, source, time added | Before a discovery query that adds a host answers | S1 |
| Activity entry | Id, time, kind, who decided, rule, params, and an immutable saved copy of terms, fit and conditions | Same batch as the record of the event it describes, where there is one | S1 |
| Request id | Id, method, path, body digest, answer status, the object acted on, time | Same batch as the action's first save | S1 |
| Set-aside funds | Per hosted lobby: amount set aside and the echoed confirmation | Before opening the lobby answers; superseded by `funding_plan` | S1 |
| Settings, review and preview ids spent, host-node setting, user-added chain servers, while-closed reports | As `spec/local-api.md` 7.5 | Before each call answers | 1.0.0 |

None of these holds a key, the seed or the 24 words (section 10). The rule of open point 2 adds: request ids may be compacted only under the lifetime rule of `spec/local-api.md` 7.4, and pause, conditions copies and activity entries never while their lobby or factory is unresolved.
10. **Encryption** (owner decision 13, 2026-11-12: every file encrypted from the start, on test networks too). Folded in with draft 3 from `spec/storage-encryption.md` draft 3 (sections 2, 2.1, 3, 4, 5, 7, 8.3 here): the authenticated header, the sealed entries, the lengths, the mark file and the sealed guard, and the start rule. Still open there and bearing on this document: the measured cost of anchored batches (its point 16), padding (its point 6), a rollback anchor for the journal outside the data folder (its point 7), and libsodium's confirmation of the vectors (its point 12).
