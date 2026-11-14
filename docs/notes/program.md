# The `gazpacho` program (stream S11)

Draft 3, 2026-11-13: contract v2 step P3 (`docs/notes/contract-v2.md` section 17), with the fixes from review A of PR 27 (`notes/review-pr27-a.md`; section 10 lists them). Draft 1 (2026-11-12) was answered by contract v2; its fifteen mismatches are in section 7 with where each now stands. Code: `program/`; tests: `tests/program/`.

The program is the only thing around the core that touches storage, the network, the chain, the clock and the user. The core (`core/gazpacho`) decides; the program carries out. This note fixes how, so that every engine plugs into the same loop. It is a walking skeleton: it runs the placeholder node (`node.h`, the ping) end to end over the real runner, the lobby transport (`ports/net/peers.h`) and a journal stand-in, and engines replace the stand-ins as they merge.

## 1. Shape

One process, one thread, one data folder, one node. `gazpacho --data-dir DIR --role host|member`. Host and member are one executable; the role is fixed per data folder at its first start. Two builds of the same sources: `gazpacho` (release: the transport without test kinds, no `--test-*` options) and `gazpacho-test` (the transport built with `GZ_TEST_KINDS`, and the test hooks).

| Piece | File | Replaced or extended by |
|---|---|---|
| Executor loop, timers, start, restart | `program/executor.c` | stays; engines add nothing here |
| Storage interface | `program/store.h` | the journal (S5) and its encryption (S6) implement it |
| Journal stand-in, start counter stand-in, restore marker | `program/journal_standin.c` | S5; the sealed counter `starts.gzs` in P9 |
| Network adapter | `program/net.c` over `ports/net/peers.h` | links, kinds and `CONNECT` in P4; derived keys in P8 |
| Chain adapter | `program/pchain.c` over `ports/chain` (blocking) | the chain worker (P7) |
| User adapter | `program/notify.c` (output lines) | the view and the API server (P5, P6) |
| Data folder, lock, key files | `program/datadir.c` | key file of S6; derived keys (P8) |
| Command line | `program/options.c` | |
| Test traffic | `program/testping.c` (test build only) | removed with the placeholder ping |

## 2. The executor loop

Per incarnation (`gzp_exec_incarnation`), in this order:

1. **Queue every input.** The network adapter starts queueing what the transport reports (section 3). Nothing but its own storage confirmations reaches a starting node.
2. **Open storage and take the fence.** The store settles what an earlier program left pending: each batch is durable or gone for good (the stand-in cuts a torn tail, keeping the cut bytes in `journal.standin.cut-N`, and refuses corruption; a damaged entry with any valid entry after it is corruption, never a tail: review B, B1).
3. **Make the incarnation durable, above every number this folder has used.** N = 1 + max(the journal's highest, the start counter); either at or above 2^63 refuses the start. The counter is written first (tmp, sync, rename, sync the folder), then the incarnation entry, before the runner exists (`runner.h`; contract v2 section 8).
4. **Make the node and the runner.** Fresh, every incarnation. The runner's executor callback is the only place an action is carried out.
5. **Start the node from storage** (the stepped start of `node.h`): call `gz_node_start` while `*more`; between steps give the node the storage confirmations its runner accepts, and nothing else; on `GZ_WAITING` give it the next confirmation (a waiting start with nothing to confirm is a contract mismatch, fatal). The restore marker goes to the start in `gz_storage_reader_t.restored`. Sends the start makes are dropped: no connection has been reported (there is no outbox).
6. **Only now** does the host listen and the member connect; the adapter hands over what it queued (normally nothing), and the loop runs.
7. **The loop.** One `poll()` over the stop pipe (written by the SIGTERM/SIGINT handler) and the transport's descriptors (`gz_peers_pollfds`), until the earliest of the transport's deadline, the reconnect, the next timer, the chain poll and the test traffic; no fixed wake-up. After it: `gz_peers_dispatch`, then **at most 4** of the transport's events (`gz_peers_poll(p, 0, …)`; it does I/O of its own when its queue is empty, so an unbounded drain could last as long as a peer keeps sending), due timers oldest first, the chain tip. What is left waits for the next turn, which `gz_peers_pollfds` makes immediate. So a flooding peer cannot hold the stop pipe, the timers or the chain (review A, M1). Each event: `gz_node_handle`, then `gz_runner_submit` of the list it filled. At every start the node is told the current chain tip (`GZ_CHAIN_NEW_TIP`).

**Saves before sends, confirmations in order once each.** A SAVE in the callback is appended to storage. The confirmation is not given from inside the callback: after each runner call returns, the loop takes durable batches from `complete()`, oldest first, once each, and gives each to `gz_runner_confirm`; only a `GZ_OK` reaches the node as `GZ_EVENT_STORAGE_CONFIRMED`.

**The store is synchronous** (`store.h`): `append` returns durable or failed. An asynchronous journal does not plug in unchanged (review A, M2): it must give the loop a descriptor and a deadline, the stepped start must wait on it for `GZ_WAITING` (stepping the network with every input queued) instead of treating it as fatal, and back-pressure must wait on that descriptor instead of spinning. `store.h` states these as requirements for S5. With the synchronous store a batch still unconfirmed after a drain is a contract breach and fatal.

**A failed append is gone for good** (review A, H1). On Linux a failed `fsync`/`fdatasync` leaves the bytes readable in the page cache while they may be lost on power failure. So the stand-in cuts the file back to its length before the append and syncs the cut before reporting the failure: no begin in the same process can read the batch back, and the in-process restart never resends a reply justified by it. If the cut cannot be made durable either, the store is poisoned: the program exits (status 6) without starting again, and `storage.failed` refuses the next start until a person has removed it. The journal of PR 29 fixes the same thing (its R1).

**Fatal, and the restart from storage.** A refused list, any other runner error, a storage failure (reported with `gz_runner_storage_failed` from inside the callback, so nothing more of the list is handed over), an error from the node, a full timer table, a message too big for the transport: the incarnation ends. `main.c` then closes every connection and the listener without events (`gz_peers_free`, a fresh transport), and runs a new incarnation from step 1: its timer table is empty (the old timers never fire), its watches are forgotten, it listens and connects again only after its start, and peers repair what was lost through their reconnect step. A stop asked for during a restart is honoured before a new start. More than 5 restarts within 10 minutes stops the program (exit 1); faults further apart never add up (review A, M6). A poisoned store is never restarted (exit 6).

**Shutdown** (contract v2 section 4): stop the node (the runner and every held action go with the incarnation); the API server and the chain worker join here with P5 to P7; close every connection without events; close storage; release the folder lock. Each step is an output line that reports the state read from the other resources at that moment (`shutdown connections-closed transport=0 storage=1 lock=1`, …), so a change of order shows. SIGPIPE is ignored: a reader of the output lines that goes away does not stop the program (review A, M4).

**Start order once storage is encrypted (S6, P5).** The journal cannot be read before the storage key is in memory, and the key comes from the passphrase through the local interface: take the folder lock; bring up the interface in the locked state; on unlock open storage (steps 2 and 3); start the node; only then connect.

## 3. How actions and events map to the ports

| Core | Port | What happens |
|---|---|---|
| SAVE | storage | `append()`; confirmation via `complete()` (section 2) |
| SEND | `ports/net/peers.h` | Until P4: the placeholder's bytes as record 1 of the test kind 32767, scope zero (`gazpacho-test` only; the release build drops them). Peer id = first 8 bytes of SHA-256 of the peer's static key. **No outbox**: no live connection, dropped and counted (`send-dropped … why=not-connected`); a refusal on a live connection closes it in the transport (`GZ_PEER_WHY_SEND_REFUSED`); too big is fatal |
| BROADCAST | `ports/chain` | `gz_chain_broadcast`, blocking (P7 moves it to the chain worker); the outcome is written to the output only (`GZ_CHAIN_BROADCAST_RESULT` is P4/P7) |
| WATCH_SCRIPT, WATCH_TX, WATCH_OUTPOINT | `ports/chain` | recorded; events from them are P7's watch loop |
| SET_TIMER, CANCEL_TIMER | the loop | 64 timers on the monotonic clock; setting a set id replaces it; a due timer fires once, never during a start, never into a later incarnation |
| NOTIFY | the user | one output line now; the view and the API with P6 |
| a message of kind 32767 (test build) | `ports/net/peers.h` | `GZ_EVENT_MESSAGE_RECEIVED` with record 1's bytes; any other kind is ignored (and counted in the output) until P4 |
| a connection up or down | `ports/net/peers.h` | `GZ_EVENT_PEER_CONNECTED` / `_DISCONNECTED`; a connection replaced by a newer one from the same key is reported down first (the transport closes it, `GZ_PEER_WHY_REPLACED`) |
| new chain tip | `ports/chain` | `GZ_CHAIN_NEW_TIP`, from a tip poll every `--chain-poll-ms` |
| random port | the OS | `getrandom` at each call, both tags; nothing seeded, buffered, logged or journaled. The transport has its own type (`gz_net_random_t`), given the same source |
| clock port | the OS | wall clock in ms; timers use the monotonic clock |

**The start queue** (contract v2 section 1). While a node starts, the adapter keeps what the transport reports, per connection, and hands it over after the start: a connection's messages only between its own connected and disconnected; a connection that came and went during the start not at all; at most 1 MiB per connection, counting 64 bytes of overhead per message (past that the connection is closed; a member's own connection is then rescheduled); a connection that closes during the start is forgotten at once with what it queued, and the whole queue holds at most 4 MiB, past which the connection that sends is closed (review B, B5). Due timers stay in the table; chain results are not taken; user commands, once there is an interface, are answered `503 node_stopped` (`rebuilding`). Since the host listens and the member connects only after the start, the queue is normally empty; `--test-listen-during-start` with `--test-start-delay-ms` exercises it.

**The member's connection** is the program's stand-in for `CONNECT` (P4): one connection to the pinned host, made after the start, kept with backoff (`--reconnect-ms`, doubling to 60 s), always with the same key.

## 4. Storage

`program/store.h` is the interface the real journal (S5) and storage encryption (S6) will provide: `begin` (fence, start counter, durable incarnation), `next`/`rewind` (the shape of `gz_storage_reader_t`), `append`, `complete`, `restored` (the restore marker), `close`. Today: `journal.standin` (a header, then `INCN` and `BTCH` entries, each with a SHA-256; no encryption, no compaction, everything in memory), `starts.standin` (the start counter, `GZSTART0 <n>`, unsealed; the sealed `starts.gzs` of `storage-encryption.md` 10.3 is P9) and `restore.pending` (the restore marker: present from the moment a backup is put in place until batch 1 of an incarnation begun with it is durable). A missing counter falls back to the journal alone and is reported (on a restore: `counter_found` 0, "the person is told"). The counter covers a restore of the journal alone, not a snapshot of the whole folder (contract v2 section 8).

## 5. Data folder, roles, network, options

- **One program per data folder.** `flock(LOCK_EX|LOCK_NB)` on the folder itself (its own descriptor), so deleting a file in it cannot let a second program in (review A, M3); a second program is refused (exit 3) with the holder's pid, kept in `DIR/lock` for the message only. A crash leaves no stale lock. The folder is created 0700 and refused if others can read it.
- **Identity.** `DIR/identity` holds the role and network written at the first start; another is refused (exit 4).
- **Networks.** signet (default) or testnet4, one per folder; `init` names exactly that chain (`messages.md` 2), so a signet member and a testnet4 host both close over init. Mainnet is refused (exit 2) before any folder is made; a chain server whose block 0 is another network's is refused at start (exit 5).
- **Options.** `--data-dir`, `--role`, `--network`, `--listen ADDR:PORT` (host), `--connect KEY@ADDR:PORT` (member), `--interface-port`, `--no-interface`, `--chain-url`, `--no-chain`, `--chain-poll-ms`, `--check-chain` (read-only check, then stop), transport timers (`--handshake-ms`, `--recv-ms`, `--send-ms`, `--ping-ms`, `--pong-ms`, `--reconnect-ms`, `--max-per-address`). `gazpacho-test` adds `--test-pings`, `--test-ping-ms`, `--test-crash-at-ping`, `--test-storage-fail-at`, `--test-sync-fail-at`, `--test-cut-fail`, `--test-crash-after-counter`, `--test-start-delay-ms`, `--test-listen-during-start`, `--test-restore-from`, `--test-timer-ms`, `--test-burst`, `--test-oversize-send`, `--test-node-error-at`, `--test-node-error-always`, `--test-stop-at-restart`; the release build refuses any `--test-*` without knowing their names, and neither the names, their usage lines, the test timer nor the store's test hooks are compiled into it (review B, B4). Release output lines never carry message bytes: a start's resend shows its length only (B6).
- **Key files (stand-ins).** `transport.key` and `wallet-seed.standin`, 64 hex, mode 0600, unencrypted; derived keys replace them in P8, the key file in S6.

## 6. The core contract

The program builds against `main`'s core only (PR 9 and PR 21 are merged): no probes (contract v2 section 14; `program_no_probes` fails if a `GZP_CORE_*` probe or `GZ_RANDOM_OTHER` comes back). P4 changes the contract the program uses: links instead of `uint64_t` peer ids, SEND and MESSAGE with kind, scope and records, `CONNECT` / `DISCONNECT` / `SET_SEATED`, the placeholder's hello and acknowledgement (`GZPH`, `GZPA`, `PING_ACKED`) and rule 6's reconnect step. Until then the program's test traffic stands in for rule 6: what a peer has not answered is sent again when the connection comes back.

## 7. The mismatches of draft 1, and the Slice 1 attempt

Draft 1 found fifteen; contract v2 decided each. Where they stand after P3:

| # | Mismatch | State |
|---|---|---|
| 1 | Released is not sent | Program side done here: no outbox, refusal closes, start queue, listen after start, restart closes everything and clears timers. Node side (rule 3, `PING_ACKED`) in P4 |
| 2 | Peer identity | Transport side merged (P2: one connection per key, `REPLACED`). Links in P4 |
| 3 | Connect, disconnect, seats | Transport side merged (`gz_peers_close_after_send`, `gz_peers_set_seated_key`). Actions in P4 |
| 4 | One poll loop | Done for the transport here (pollfds/dispatch, the stop pipe). API in P5/P6, chain worker in P7 |
| 5 | The chain view blocks the loop | Still true (`pchain.c` is blocking); P7 |
| 6 | The transport blocks | Done: the program uses only `peers.h`; `conn.h` only in a test client |
| 7 | Kind and scope | Carried by the adapter as test kind 32767 until P4 |
| 8 | A restore rewinds the incarnation | Stand-in counter done here; sealed in P9 |
| 9, 10 | Broadcast outcome, `WATCH_SCRIPT` | P4 / P7 |
| 11 | What the interface reads | P5, P6 |
| 12 | Transport's random type | Merged (P2): `gz_net_random_t` |
| 13 | Member keys | P8 |
| 14 | Two random signatures | Done here: probes removed |
| 15 | Networks | Done: signet or testnet4, one per folder, both sides close over init |

From the Slice 1 attempt (`docs/notes/slice1-attempt.md`, PR 31), the items that land on the program:

- **Item 1, the skeleton cannot host the engines.** Its network half is done here (`peers.h`, one loop, restart path). The composite node (lobby, signing, funding behind `gz_node_handle` / `gz_node_start`) is P4's.
- **Item 12, message shapes.** The lobby emits whole Lightning messages, `peers.h` delivers kind, scope and records, and refusals come out as SEND. The adapter carries only the test kind until P4 gives SEND and MESSAGE their kind, scope and records; the engines then emit that triple, and refusals become `DISCONNECT` (or a refusal action), not SEND.
- **Item 13, seats and closes are notices.** P4's `SET_SEATED` and `DISCONNECT` map to `gz_peers_set_seated_key` and `gz_peers_close_after_send` in `net.c`; the adapter must apply a seat before the member's first message is delivered (seats are re-issued at every start, before the host listens).
- **Item 17, the host's H1 check was not run**, because `gz_tree_h1` needs the scripts of the coins the funding spends, which the wallet library keeps private. Not a program change: H1 should take the `gzt_funding` (or the wallet expose the spent scripts); the program must then refuse to broadcast a funding transaction whose H1 check did not pass (P7 owns broadcasting).

## 8. Integration contract for engine pull requests

Every pull request that adds or changes an engine, a port or a stand-in must:

1. **Plug in through the adapter, not around it.** An engine is reached only through `gz_node_handle` and `gz_node_start`; it emits actions and nothing else. A port lands behind its adapter in `program/` (`store.h` for storage, `net.c` for the network, `pchain.c` for the chain, `notify.c` for the user), gives the loop its descriptors and deadline, and never blocks inside a call the loop makes; nothing it calls from inside the runner's callback may call the runner or the node.
2. **Keep the executor's rules.** Saves before sends; confirmations from storage only, oldest first, once each; the incarnation durable and above the start counter before the runner; nothing but confirmations during a start; listening and connecting after it; timers and watches set again at every start; refusal and storage failure fatal and restarted from storage with every connection closed; no outbox.
3. **Add a multi-process test to `tests/program/`** (the helpers are in `gzp_harness.py`), registered with CTest, on loopback with short timers, running the engine's own messages between separate `gazpacho-test` processes through the real runner and the storage in use, and showing by outcome (what each side ended with, not that a defence fired):
   - the happy path across processes;
   - a crash of each role at the engine's worst point (after a save, before its send), restarted on the same data folder, ending in the right state;
   - a storage failure in the middle, recovered in the same process;
   - a reconnect: what was lost is repaired by the reconnect step, and duplicates and reordering are harmless (`node.h` rules 2 and 6).
4. **Update this note**: sections 1 and 3 for what it replaces, section 7 for any mismatch it fixes or finds.

## 9. Tests

| CTest | Contract v2 | What it shows |
|---|---|---|
| `program_store` | T8 (unit) | the stand-in against the storage contract; the counter, its fallbacks and the 2^63 refusal; the marker; a failed sync cut back and a poisoned store; the scan: a flipped last body byte cut as a torn tail, a repeated batch id, a repeated incarnation entry and a batch of an incarnation never begun refused; a flipped bit in a middle entry's length refused with nothing cut (B1); a short tail and an over-long last head cut and kept in `journal.standin.cut-N`; a batch with sequence 0 and an incarnation entry of 9 bytes refused |
| `program_net` | | record 1 of the carrier's TLV stream, and nothing read past a malformed length |
| `program_options` | | the command line; mainnet refused first |
| `program_two_process` | P3 | a host and two members over `peers.h`: ping/pong through the real runners and journals; the host killed after a ping is durable, its start's resend dropped although the member's connection is up in the start queue, and the loss repaired at reconnect; a member killed and restarted; the start queue (a member that pings during a held start reaches the node only after "ready"; one killed during it is never reported; one that sends 1.2 MB during it is closed and reported only once it comes back; one that sends 4,100 messages of 200 bytes (payload under 1 MiB) is closed only because of the 64 bytes counted per message; a closed member's queued pings dropped when it closes; a timer due during it fires after it); the lock, also with its file deleted; the role check; the shutdown order read from the state |
| `program_storage_failure` | review A | a sync that fails: cut back, restarted in process, never resent, not in the journal; the restart closes the member's connection (seen by the host within 1 s) and it comes back on a new one; the old incarnation's timer never fires after it; a failed cut: exit 6, no restart, the next start refused until `storage.failed` is removed; a node error: fatal, nothing saved after it; a send too big: fatal |
| `program_loop_liveness` | review A | a member flooding the host at 1 ms: the host's 100 ms timer keeps firing, its own pings keep going out, SIGTERM stops it within 1 s; an idle loop's timer fires on time; connects are refused for the whole of a held start and the first one accepted finds "ready" written (listening after the start, from outside; it waits for the listener, not for the line: B3); SIGPIPE on standard output is survived |
| `program_slow_peers` | T6 | a silent TCP client, a byte-a-second act one and a handshake without init each closed at the handshake deadline while a real member connects at once and is answered |
| `program_restore_counter` | T8 | a journal restored alone starts at 6, not 3, with the restore batch first and a non-zero epoch; without the counter, 3 and "the person is told"; stopped between the counter and the incarnation entry, the next start skips the number; 2^63 refuses |
| `program_networks` | T15 | testnet4 host and member ping; a signet member and a testnet4 host both close over init; mainnet exits 2 |
| `program_release_build` | T12 (second half) | the release binary has none of the seeded source, test traffic or store test hooks that the test build has; it holds no test option name, test usage line, test-timer line or payload format; it refuses `--test-*`; and kind 32767 from a test-build member never reaches its node (its journal holds no ping record, where delivery would leave one) |
| `program_start_queue` | review B | review B's own test, as written: a held start with four members (one killed, two over the cap, one of them by the 64-byte overhead); the start's resend dropped; the test timer after the start; a restart's timers |
| `program_restart_slots` | review B | review B's own test: the host restarts in process with two members connected, raw connects take the new transport's first connection numbers, and both members are still answered with no send on a stale slot (M45) |
| `program_chain_stub` | review B | review B's own test, against a loopback Esplora stub: the tip told after every start including an in-process restart; a new tip once, an unchanged one never; mainnet and testnet4 servers refused (needs curl) |
| `program_restart_policy` | review A M6 | a node that fails at every start: five restarts, then exit 1; a stop arriving as an incarnation ends: no new start |
| `program_queue_peers` | review B | two members ping during a held start: each ping record names its sender, nothing reaches the node before its connection's connected (B41, B42); five members together past the 4 MiB queue cap (B5) |
| `program_refusals` | review B | mainnet refused first; a host with `--connect`; a folder or a key file open to others; the reconnect delay back to its first value after a success |
| `program_no_probes` | T14 | no core probe, no `GZ_RANDOM_OTHER` |
| `program_signet_check` | | opt-in (`GZ_LIVE_TESTS`): read-only against public signet servers |

## 10. Review A of PR 27

| Finding | Change |
|---|---|
| H1 a failed sync read back by the in-process restart | The stand-in cuts a failed append back and syncs the cut; if that fails it is poisoned: exit 6, `storage.failed`, no restart. `store.h` states it as a requirement for S5. Tested with `--test-sync-fail-at` / `--test-cut-fail`, and with the reviewer's `fdatasync` shim |
| M1 one busy peer holds the loop | At most 4 transport events per turn: a turn is bounded by about 8 synced saves |
| M2 "plugs in unchanged" | Corrected; what an asynchronous journal needs is in `store.h` |
| M3 the lock file can be deleted | The folder itself is locked |
| M4 SIGPIPE | Ignored |
| M5 checks that could not fail | Release: journal check and real symbols; the restart's closed connection seen by the host; shutdown order read from the state; listening after the start tested from outside |
| M6 restart policy | A 10-minute window; a stop during a restart does not start again |
| L1 start-queue cap | 64 bytes per message counted; a member's closed connection rescheduled; both rules tested |
| L2 dead check | Removed |
| L3 test hooks in release | `gzp_standin_fail_at`, `gzp_standin_put_restore` and the new hooks only in `gazpacho-test`; in the symbol check |
| L4 tip at start | The node is told the tip after every start |
| L5 stand-in journal | Batches of an incarnation never begun refused; the counter written before the journal at set-up; the restore marker written after the restored file |
| L6 coverage | `--test-timer-ms`, `--test-crash-after-counter`, three scan cases, the node-error and too-big tests |
| N1 output lines block | Unchanged (P6 replaces them) |

## 11. Review B of PR 27

| Finding | Change |
|---|---|
| B1 a damaged length cut as a torn tail | An overrunning entry, or a bad last hash, is torn only if no valid entry starts anywhere after it; otherwise open refuses and cuts nothing. A cut tail is first copied to `journal.standin.cut-N` and synced. `store.h` asks the same of S5 |
| B2 fixes with no test that can fail | `program_restart_policy` (M6), `program_chain_stub` (L4), `program_restart_slots` (M45), member 6 on the overhead boundary (the 64 bytes), `program_queue_peers` (B41, B42) |
| B3 liveness part 3 racy | It waits for the listener and then requires "ready" written, instead of reading the line first |
| B4 the test timer in release | The branch, its ids and every `--test-*` name and usage line are test-build only; checked on the release binary's bytes |
| B5 the start queue's memory | A closed connection's queue is freed when it closes; the whole queue is capped at 4 MiB |
| B6 payload bytes in release output | Release logs lengths only |
| B7 smaller gaps | `program_refusals`, `program_net`, four scan cases in `program_store` |
| N3, N4 | 2^63 stated in `store.h`; the lock descriptor closed on the mode refusal |

## 12. P4.1: the composite node behind the loop

P4.1 (`docs/notes/composite-node.md` section 15) puts the composite node (`core/node`) behind `gz_node_start` and `gz_node_handle` and brings contract v2's core changes. The loop itself does not change. What does:

- **The node** is opaque (`gz_node_size()` bytes, made once per process) and is given a configuration: the role, the key port (over the stand-in transport key until P8: every per-lobby key is that key), the funding and signing settings, and in `gazpacho-test` the number of test engines (`--test-engines`, default 1). The release build links `gazpacho_node`, which has no engine yet: a release member's `--connect` is noted and nothing connects until the lobby (P4.2).
- **Lists and the runner** are sized by `node.h`: a list of `GZ_NODE_LIST_ACTIONS` actions and `GZ_NODE_LIST_BYTES` bytes, the runner twice that, the timer table `GZ_NODE_MAX_TIMERS`.
- **Links.** Every event and action names a peer by its link. The adapter keeps one connection per remote key; a link's local key is the transport's key. Output lines still show `peer=` and the first 8 bytes of SHA-256 of the key.
- **Actions.** `SEND` goes out with its kind, scope and records (no more record-1 carrier); `CONNECT` keeps a connection to a host with backoff until a `DISCONNECT` of its link (up to 16 at once; issued again by the node at every start, and forgotten by the adapter at a restart from storage); `DISCONNECT` sends what is queued and closes, or for `why` = refused sends the transport's warning first; `SET_SEATED` marks a key in the transport. `WATCH_SCRIPT` is gone.
- **`--connect`** (test build) is the test engine's `connect` command, given after each start (a target already saved changes nothing): the engine saves the target with a key index pair, then issues `CONNECT`, and issues it again at every start.
- **A node error** prints `node-error engine=0xAAAA status=...` (the engine's area from `gz_node_error_area`) before `fatal why=node-error`; the node is poisoned and never called again, and the program starts a new one from storage.
- **Test traffic** (`program/testping.c`) pings each test engine of the peer (record 3 names the engine); the node's own test engine acknowledges replies and asks with its hello at each connection it made. The start resends nothing (`ready ... resent=0`).
- **New options.** `--max-queue BYTES` (the transport's send queue per connection). `gazpacho-test` adds `--test-engines N`, `--test-dump-journal` (prints each batch and record type, read only, then stops), `--test-drop-kind K` (drops received messages of that kind), `--test-commands` (test commands on standard input: `cmd CODE ARGS-HEX`, `chain-tx TXID CONF`, `tip HEIGHT`, `raw-kind KIND`; a command during a start is answered `503 node_stopped`), `--test-big-reply BYTES`, `--test-crash-after-save K`, `--test-crash-before-confirm K`, `--test-exit-after-send`. In the test build a `NOTIFY` is also shown decoded: `node-log ...`, `command-result id=... status=...`, `view kind=... id=... version=...`.
- **Two lines carry `mono=`**, the machine's monotonic clock in milliseconds (`restart-from-storage` and `closed conn=`), so that a test comparing lines of two processes does not compare the times at which it read them.

Tests added in `tests/program/`: `program_composite` (P4.1's seven cases), `program_resend_on_connect` (T1), `program_links` (T2 steps 1 and 2), `program_envelope` (T7). Two points of contract v2's tests cannot be built as written, because the transport never splits kind 32767: T7's 200,000-byte test reply "as parts" and T1 step 7's 200 KB reply. Both tests use a 60,000-byte reply (whole) instead; a split reply needs a real host-to-member kind, which the lobby brings.
