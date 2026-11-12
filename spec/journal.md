# The storage journal, first cut

Specification draft 2, 2026-11-12. Status: draft 1 corrected after the third, joint review of the five Slice 1 specifications (`docs/reviews/spec-review-3.md`), which found its torn-tail rule and its restore section wrong. Draft 2 has not itself been reviewed. The file-based journal that slice 1 needs (`docs/SLICES.md`: "A file-based journal"). It implements the storage side of the runner contract in `core/gazpacho/include/gazpacho/runner.h`. Items marked **(open)** are listed at the end. Draft 1's "(prov.)" marks are gone: `safety-rule.md` and `signing-round.md` draft 4 settle them.

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
| A save is one batch of typed records, stored all or nothing | Section 3: one batch is one entry with one checksum |
| Batches become durable in the order they were handed over | Section 4: one file, appended in order, by one writer |
| A confirmation is given only for a batch that is safely stored, and in order | Section 4: confirm only after a successful sync covering the batch, and a second one covering the sync mark after it |
| Batch identifiers are {incarnation, sequence}, issued by the runner, never reused | Section 3: the identifier is written in the entry and checked on reading |
| The incarnation is strictly greater than any before, and durable before the runner is used | Section 5: an incarnation entry, synced at every start |
| A storage failure stops the node | Section 4: any write or sync error calls `gz_runner_storage_failed` |
| On start, the node gets every stored record, oldest first (`gz_node_start`) | Section 6: the reader |

The journal belongs to the outer layer (`DESIGN.md` section 3, L4 ports). It may use operating-system calls; the core may not.

## 2. The file

- **One append-only file per node**, `journal.gzj` in the node's data folder. Bytes are only ever added at the end. The one exception is cutting off a torn tail at start (section 5), which removes only bytes after the last sync mark, which were never confirmed.
- **One writer.** The program takes an exclusive lock on the file (`flock` on POSIX, `LockFileEx` on Windows) for as long as it runs, and refuses to start if the lock is held. Two processes appending to one journal would interleave batches, and two live copies of one node is a hazard of its own (`safety-rule.md` section 10, "the same key running on two devices").
- Permissions: readable and writable by the owner only (0600 on POSIX). Not encrypted in slice 1 **(open)**.

### 2.1 Header

Written once, when the file is created, then never changed.

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZJOURNL` |
| 8 | `chain` | 32 | The chain hash of the network (signet: `f61eee3b…08000000`, internal order, as in `terms.md`) |
| 40 | `check` | 8 | First 8 bytes of SHA-256 over bytes 0 to 39 |

A program refuses a journal whose `magic` or `check` is wrong, or whose `chain` is not its own network. So a signet journal can never be opened by a mainnet build, and the other way round (`SLICES.md` rule 3).

Creating the file: write the header to a temporary name, sync it, rename it to `journal.gzj`, then sync the folder (POSIX). Without the folder sync the file itself may not survive a power cut.

## 3. Entries

After the header the file is a sequence of entries. ("Entry" is the framed unit in the file. "Record" is the core's `gz_record_t`, a type and bytes, several of which may sit in one batch entry.)

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0 | `length` | `u32` | Number of bytes from `kind` to the end of `payload`. At least 21, at most 8,388,625 (section 7); and exactly 25 for kinds 1 and 3, at least 21 for kind 2 (review 3, F21: no kind has an empty payload) |
| 4 | `kind` | `u8` | 1 incarnation, 2 batch, 3 sync mark. Any other value: the entry is invalid |
| 5 | `incarnation` | `u64` | |
| 13 | `sequence` | `u64` | 0 in an incarnation entry and a sync mark; the runner's sequence, from 1, in a batch entry |
| 21 | `payload` | `length` − 17 | Section 3.1 or 3.2 |
| 4 + `length` | `check` | 8 | First 8 bytes of SHA-256 over every byte of the entry before it (`length` to end of `payload`) |

All integers big-endian.

**Why SHA-256 truncated to 8 bytes.** The checksum must catch a torn or half-written entry, not an attacker (an attacker with the file can rewrite the checksum too; integrity against tampering comes with encryption, **(open)**). SHA-256 is already in the imported, reviewed primitives, so it needs no new code; 8 bytes give a 1 in 2^64 chance that a torn entry passes. A CRC would be faster, but the journal writes kilobytes per user action, not gigabytes, and speed does not matter here.

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

A sync mark is written only **after a sync returned success**, and says: every byte before me reached the disk. Its `offset` must equal its own position; a mark whose `offset` is anything else is invalid. That makes a mark self-locating: a reader can recognise one anywhere in the file, even past a damaged entry whose length it cannot trust (section 5). `incarnation` is the current incarnation, `sequence` 0. A mark yields no records. It is 37 bytes in the file.

### 3.4 Order rules checked on reading

1. The first entry after the header is an incarnation entry.
2. Incarnation entries have strictly increasing `incarnation`.
3. A batch entry's and a sync mark's `incarnation` equals that of the latest incarnation entry before it.
4. Within one incarnation, batch sequences are 1, 2, 3 … with no gap and no repeat.

A valid entry (checksum correct) that breaks one of these is **corruption**, not a torn tail, and the program refuses to start (section 5). The writer checks rules 3 and 4 before it writes, and treats a violation as a storage failure: it means the program around the runner handed over batches wrongly.

## 4. Writing and confirming

One writer, fed in the order the runner's executor receives save actions.

1. **Append** the batch entry with ordinary writes. A short write, or any error, is a storage failure.
2. **Sync.** POSIX: `fsync` on the file (on macOS, `fcntl(F_FULLFSYNC)`, because plain `fsync` there does not flush the drive's cache). Windows: `FlushFileBuffers`. The sync must cover every entry appended so far.
3. **Mark**, after the sync returned success: append a sync mark (section 3.3) at the current end of the file, and **sync again**.
4. **Confirm**, after that second sync returned success: `gz_runner_confirm` for each batch the first sync covered, oldest first. Only a confirmation the runner accepts (`GZ_OK`) becomes a `GZ_EVENT_STORAGE_CONFIRMED` event for the node. If the batch holds a `guard` record, the guard file is replaced first (section 8.3).

**Why two syncs.** A batch is confirmed only when a synced mark after it proves it reached the disk. So every confirmed batch lies before a durable sync mark, and the reader can tell damage to a confirmed entry (before a mark: corruption) from a write that never finished (after the last mark: a torn tail) exactly, whatever the file's size (review 3, F2). Draft 1 inferred this from a size bound, which classified any damage in a small journal, such as every Slice 1 journal, as a torn tail and silently cut confirmed records. The cost is a second small sync per group; the journal writes kilobytes per user action, and group syncing amortises it.

**Group sync.** The writer may append several batch entries and run steps 2 to 4 once for all of them, confirming them in order. The bytes appended since the last successful sync stay below **16 MiB**, unless a single entry is larger by itself, which section 7 forbids; this now only bounds memory and loss on a crash, and the reader no longer relies on it. The runner allows 32 unconfirmed batches.

**Failures.** If a write or a sync fails, the writer calls `gz_runner_storage_failed`, confirms nothing more, writes nothing more, and the program stops the node. It never retries a failed sync and carries on: after a failed `fsync`, Linux may already have dropped the unwritten pages, so a second `fsync` can succeed without the data being there. The next start reads the file from disk and finds out what survived.

**Nothing is confirmed early.** A confirmation means the batch, and a sync mark after it, have passed a successful sync. Everything the runner releases after a confirmation (sends, broadcasts, notices) therefore rests on durable data. This is "save before send" at the storage end.

## 5. Starting

In this order. Every step that writes syncs before the next step.

1. Take the lock. Open the file, or create it (section 2.1) if the data folder has none.
2. Check the header.
3. **Scan** entries from the start. An entry is **invalid** if its `length` is below 21, above the maximum or wrong for its kind, if fewer bytes remain in the file than it claims, if its `check` fails, if its `kind` is unknown, or if it is a sync mark whose `offset` is not its own position. Stop at the first invalid entry, or at the end of the file. Check the order rules (section 3.4) on every valid entry; a violation stops the start (corruption).
4. **Torn tail or corruption.** Let V be the offset just after the last valid entry, and E the end of the file.
   - V = E: the file is clean.
   - V < E: search the bytes from V + 1 to E for a **valid sync mark**: at any offset p, a 37-byte entry with `length` 25, `kind` 3, a correct `check`, and `offset` = p. A false match needs a 64-bit checksum and a self-offset to agree by chance.
     - **None found: a torn tail.** The bytes from V on were appended after the last durable sync mark, so no batch in them was ever confirmed and nothing outside the node depended on them. Cut the file to V and sync.
     - **One found: corruption.** The damaged entry at V lies before a mark that proves it was synced, so it may hold a confirmed batch, a `round_started` or an `exposure` record that a peer has seen. **Refuse to start and tell the user**; never cut it away. The remedy is a restore (section 8), whose new epoch makes it safe (`safety-rule.md` section 9).

   Valid-looking entries after an invalid one, in a torn tail, are dropped with it. A group sync can reach the disk out of order, so a later entry may survive while an earlier one is torn. Keeping the later one would break the order the runner relies on, and it was never confirmed: its mark, if written at all, did not survive.
5. **Incarnation.** New incarnation = 1 + the highest found, or 1 for an empty journal. Append its entry, sync, append a sync mark, sync. Only then may the runner be created with `gz_runner_init(…, incarnation, …)`. This meets the runner's duty: strictly greater than any before, durable before use. An incarnation is consumed even if the program then stops without saving anything; that is harmless.
6. **Read** the records with the reader (section 6) and pass them to `gz_node_start`.

A crash anywhere in steps 4 and 5 is safe. Cutting a torn tail twice cuts nothing the second time. An incarnation entry that was torn is itself cut on the next start (no mark follows it), and the next start writes the same number again; since nothing was issued under it, nothing is reused. An incarnation entry that was synced but whose mark was lost is kept, and the next start uses the next number.

## 6. Reading back

The **reader** walks the valid entries in file order and yields, for each batch entry, its records in the order they were written. Incarnation entries yield nothing. The result is the list `gz_node_start` takes: "the records found in storage, oldest first".

- A record's type follows the odd/even rule of `messages.md` section 4.1 (bit 0 of the 32-bit type): **an unknown even type stops the start**, because a newer program wrote something this one cannot interpret; **an unknown odd type is skipped**. The placeholder test types (`0x7e57xxxx`, `node.h`) are outside this rule and disappear with the placeholder.
- Batch boundaries are not passed to `gz_node_start` today; the records of one batch arrive together and in order, which is all a node needs to rebuild. If a later engine needs the boundaries, the reader can give them without a format change.
- Slice 1 loads every record into memory before `gz_node_start`. At slice 1's sizes (a host and a few members) that is kilobytes to a few megabytes. Snapshots, which bound start-up time and memory, come later (`DESIGN.md` section 9) **(open)**.

## 7. Limits

| Limit | Value | Why |
|---|---|---|
| Largest entry | 8 MiB payload (`length` ≤ 8,388,625 = 8 MiB + 17) | The host's largest slice 1 batch is the signed tree with each member's saved `round_tier_result` and `round_complete` (kept for `round_status_request`, `messages.md` 7.10): at 1,000 members about 2 KB per member, 2 MB, plus a proposal under 400 KB. 8 MiB is three times that. A node never needs a larger batch; a larger `length` on reading is invalid |
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
2. **A new epoch at the first start after a restore.** The node draws a 31-bit epoch from the randomness port with the **ordinary, untagged** request, retrying while it is 0, and saves it in `key_epoch`. The epoch is saved and backed up, so it is not secret and must not use the secret tag, whose bytes are never journaled (`signing-round.md` section 8; review 3, F3). Every per-lobby key (contribution key, factory key) is derived from the seed, the current epoch and an index (`key_index`), so no key used after the backup can come back. A replayed proposal names a key of the old epoch; the restored node's current key for that lobby is not in it (or it has none), and it refuses with `round_abort` reason 12 (`messages.md` 7.2). A second tree on an old outpoint would need the old aggregate key in its funding script, which C1's check refuses.
3. **No fresh-start confirmation.** Draft 1's `fresh_start` record and its "no creation until the user confirms" rule are withdrawn; the new epoch is the protection. The `restored` record lets the app tell the user, once, that it was restored and which seats were lost.

The index within an epoch is recorded too (`key_index`), so that an ordinary restart never derives the same key twice.

**How a restore is recognised and who writes the first batch.** A restore is an explicit program action (importing a backup file as `journal.gzj`). The program then starts normally (section 5), creating the runner under the new incarnation, and tells the node, **before any other event and before connecting to anyone**, that this start follows a restore (`signing-round.md` section 12.1). The node answers with one save batch, `key_epoch`, `restored` and `guard`, which the runner issues as sequence 1 of that incarnation like any other batch; nothing else is sent until it is confirmed (review 3, F22). A copy of the data folder made by other means is not recognised; that is the "copy of a running program" limit of `signing-round.md` section 8 and is not defended.

### 8.3 The guard file

`safety-rule.md` R6's guard, which detects a stale backup.

- **Where.** `guard.gzg`, in the program's own data folder **outside** the journal's backup set: a restore replaces `journal.gzj` and never this file. The user's export carries a copy.
- **Contents.**

| Field | Size | Meaning |
|---|---|---|
| `magic` | 8 | ASCII `GZGUARD1` |
| `chain` | 32 | As in the journal header |
| `counter` | `u64` | Incremented at every write |
| `n_epochs` | `u16` | Epochs used, oldest first |
| per epoch: `epoch`, `highest_index` | `u32`, `u32` | The highest key index allocated under it |
| `rounds_started` | `u64` | Rounds this node ever started |
| `check` | 8 | First 8 bytes of SHA-256 over everything before it |

- **How the core orders it.** The core puts a `guard` record (section 9), holding these contents without `check`, in the same save batch as every `key_index` and every `round_started` record. The runner rule then holds every send behind that batch's confirmation, so no new action or port is needed.
- **The storage duty.** For a batch that holds a `guard` record, the writer appends and syncs the batch and its sync mark as usual, then replaces the guard file (write `guard.gzg.tmp`, sync it, rename it over `guard.gzg`, sync the folder), and only then confirms the batch. A failure of any step is a storage failure (section 4).
- **On a restore.** Before importing, the program reads `guard.gzg` (or the user's exported copy) and the newest `guard` record in the backup. If the file's `counter` is higher, the backup is stale and the user is told; the restored node keeps the file's epoch list, so keys of later factories can still be derived for the recovery procedure (R7). If there is no guard file, the backup is treated as possibly stale. Either way the restore goes ahead under a new epoch: the guard only detects.

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

## 10. What is never stored

- **Secret nonces**, MuSig2 secret session state, and the randomness they were made from (`signing-round.md` section 8). Not in any record, not in a payload "for debugging", not in the clear and not encrypted. A node rebuilt from its journal can therefore never recreate one, and a round found in progress is never resumed: it becomes Aborted, or Unfinished if partial signatures were sent (`signing-round.md` section 7).
- **The state of any random generator.** The randomness port reads the operating system at the moment of use in release builds.
- **Private keys and the seed.** They live in the wallet's key file, outside the journal; the journal holds key epochs and indexes, from which keys are derived again. A journal leak therefore reveals the user's history, not their keys.
- **BOLT 8 session keys** and handshake ephemerals.
- **Parts of a split message** (`messages.md` section 5): only whole messages are saved.

A test checks this directly: the simulator records every secret nonce it creates, and after each run the journal file is searched for those exact byte strings. No match is allowed.

## 11. Test vectors

Computed by `tools/spec-vectors.py`.

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
1. J1 to J6 reproduce exactly.
2. Header with a wrong magic, a wrong check, or the mainnet chain hash: refused.
3. Every field of an entry altered in turn: `length` 20, 16, 0, the maximum + 1; an incarnation or sync mark with `length` other than 25; unknown `kind`; a sync mark whose `offset` is not its own; a flipped bit in each region: the entry is invalid.
4. A batch whose records under- or overrun the payload: invalid.
5. Order rules: a batch before any incarnation; an incarnation that does not increase; a batch under an older incarnation; a sequence gap; a repeated sequence. Each, with valid checksums: refuses to start.
6. An empty batch is written, synced, confirmed and read back as no records.

**Torn tails and corruption**
7. For every byte offset inside the last entry after the last sync mark, the file cut there: the start cuts the tail, keeps every earlier entry, and the next incarnation is one higher. J4 reproduces.
8. Zero bytes appended after the last sync mark (a file grown but never written): cut as a torn tail.
9. A group of entries after the last mark in which an earlier one is torn and a later one is intact: both dropped.
10. An invalid entry anywhere before a valid sync mark, however close to the end of the file: refused as corruption, nothing cut. J6 reproduces.
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
28. Guard: with a guard file ahead of the backup, the restore tells the user the backup is stale and keeps the file's epochs; with none, it says "possibly stale". A batch with a `guard` record is not confirmed until the guard file is replaced and synced; a failure there is a storage failure.
24. Rule removed: with the `exposure` record written after `round_partial_sigs` is sent instead of before, test 21 combined with a crash at that point must show a second tree signed on one outpoint. That test must fail.

## 13. Open points

1. **Encryption at rest** (`DESIGN.md` section 9). Slice 1 runs unencrypted on signet. The plan is an authenticated cipher per entry, whose tag replaces the checksum and also detects tampering; key from the seed.
2. **Snapshots and compaction**, to bound start-up time, memory and file size. Rule to keep: `round_started`, `exposure` (with its funding transaction and tree digest), `key_epoch`, `key_index` and the newest `guard` records are never compacted away, and neither are sync marks after the newest compaction point.
3. **TLV field numbers inside each record type**, fixed with the engine's code tables.
4. **Backups.** The journal is also the backup (`DESIGN.md` section 9). How it is exported and how a restore is triggered belongs to the backup specification; section 8 states only what a restore must write.
5. Closed: section 8 follows `safety-rule.md` draft 4 section 9.
6. Closed: an unfunded creation is **Abandoned** at the member's funding or unfinished deadline (36 blocks and one signing budget in Slice 1, **proposed, owner to confirm**, `safety-rule.md` section 12) and **Dead** when a funding input is spent elsewhere and buried. Its records stay; neither blocks the member.
7. Closed: the sync mark is mandatory (sections 3.3 to 5).
8. **Linux `fdatasync`** would do instead of `fsync` for appends (it flushes the size change too); `fsync` is specified for simplicity until measured.
