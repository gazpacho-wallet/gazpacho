# The `gazpacho` program (stream S11)

Draft 2, 2026-11-13: contract v2 step P3 (`docs/notes/contract-v2.md` section 17). Draft 1 (2026-11-12) was answered by contract v2; its fifteen mismatches are in section 7 with where each now stands. Not yet reviewed. Code: `program/`; tests: `tests/program/`.

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
2. **Open storage and take the fence.** The store settles what an earlier program left pending: each batch is durable or gone for good (the stand-in cuts a torn tail and refuses corruption).
3. **Make the incarnation durable, above every number this folder has used.** N = 1 + max(the journal's highest, the start counter); either at or above 2^63 refuses the start. The counter is written first (tmp, sync, rename, sync the folder), then the incarnation entry, before the runner exists (`runner.h`; contract v2 section 8).
4. **Make the node and the runner.** Fresh, every incarnation. The runner's executor callback is the only place an action is carried out.
5. **Start the node from storage** (the stepped start of `node.h`): call `gz_node_start` while `*more`; between steps give the node the storage confirmations its runner accepts, and nothing else; on `GZ_WAITING` give it the next confirmation (a waiting start with nothing to confirm is a contract mismatch, fatal). The restore marker goes to the start in `gz_storage_reader_t.restored`. Sends the start makes are dropped: no connection has been reported (there is no outbox).
6. **Only now** does the host listen and the member connect; the adapter hands over what it queued (normally nothing), and the loop runs.
7. **The loop.** One `poll()` over the stop pipe (written by the SIGTERM/SIGINT handler) and the transport's descriptors (`gz_peers_pollfds`), until the earliest of the transport's deadline, the reconnect, the next timer, the chain poll and the test traffic; no fixed wake-up. After it: `gz_peers_dispatch`, then every event the transport has (`gz_peers_poll(p, 0, …)`), due timers oldest first, the chain tip. Each becomes one event: `gz_node_handle`, then `gz_runner_submit` of the list it filled.

**Saves before sends, confirmations in order once each.** A SAVE in the callback is appended to storage. The confirmation is not given from inside the callback: after each runner call returns, the loop takes durable batches from `complete()`, oldest first, once each, and gives each to `gz_runner_confirm`; only a `GZ_OK` reaches the node as `GZ_EVENT_STORAGE_CONFIRMED`. The stand-in is synchronous; the loop relies only on `complete()`, so a journal that commits in groups plugs in unchanged.

**Back-pressure.** While `gz_runner_unconfirmed()` is above half of `GZ_RUNNER_MAX_UNCONFIRMED`, the loop takes no new outside event (a refused list is fatal). The synchronous stand-in never gets there; S5 must keep the rule.

**Fatal, and the restart from storage.** A refused list, any other runner error, a storage failure (reported with `gz_runner_storage_failed` from inside the callback, so nothing more of the list is handed over), an error from the node, a full timer table, a message too big for the transport: the incarnation ends. `main.c` then closes every connection and the listener without events (`gz_peers_free`, a fresh transport), and runs a new incarnation from step 1: its timer table is empty (the old timers never fire), its watches are forgotten, it listens and connects again only after its start, and peers repair what was lost through their reconnect step. After 5 restarts the program exits 1.

**Shutdown** (contract v2 section 4): stop the node (the runner and every held action go with the incarnation); the API server and the chain worker join here with P5 to P7; close every connection without events; close storage; release the folder lock. Each step is an output line (`shutdown node-stopped`, `connections-closed`, `storage-closed`, `lock-released`).

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

**The start queue** (contract v2 section 1). While a node starts, the adapter keeps what the transport reports, per connection, and hands it over after the start: a connection's messages only between its own connected and disconnected; a connection that came and went during the start not at all; at most 1 MiB of messages per connection (past that the connection is closed). Due timers stay in the table; chain results are not taken; user commands, once there is an interface, are answered `503 node_stopped` (`rebuilding`). Since the host listens and the member connects only after the start, the queue is normally empty; `--test-listen-during-start` with `--test-start-delay-ms` exercises it.

**The member's connection** is the program's stand-in for `CONNECT` (P4): one connection to the pinned host, made after the start, kept with backoff (`--reconnect-ms`, doubling to 60 s), always with the same key.

## 4. Storage

`program/store.h` is the interface the real journal (S5) and storage encryption (S6) will provide: `begin` (fence, start counter, durable incarnation), `next`/`rewind` (the shape of `gz_storage_reader_t`), `append`, `complete`, `restored` (the restore marker), `close`. Today: `journal.standin` (a header, then `INCN` and `BTCH` entries, each with a SHA-256; no encryption, no compaction, everything in memory), `starts.standin` (the start counter, `GZSTART0 <n>`, unsealed; the sealed `starts.gzs` of `storage-encryption.md` 10.3 is P9) and `restore.pending` (the restore marker: present from the moment a backup is put in place until batch 1 of an incarnation begun with it is durable). A missing counter falls back to the journal alone and is reported (on a restore: `counter_found` 0, "the person is told"). The counter covers a restore of the journal alone, not a snapshot of the whole folder (contract v2 section 8).

## 5. Data folder, roles, network, options

- **One program per data folder.** `flock(LOCK_EX|LOCK_NB)` on `DIR/lock`; a second program is refused (exit 3) with the holder's pid. The folder is created 0700 and refused if others can read it.
- **Identity.** `DIR/identity` holds the role and network written at the first start; another is refused (exit 4).
- **Networks.** signet (default) or testnet4, one per folder; `init` names exactly that chain (`messages.md` 2), so a signet member and a testnet4 host both close over init. Mainnet is refused (exit 2) before any folder is made; a chain server whose block 0 is another network's is refused at start (exit 5).
- **Options.** `--data-dir`, `--role`, `--network`, `--listen ADDR:PORT` (host), `--connect KEY@ADDR:PORT` (member), `--interface-port`, `--no-interface`, `--chain-url`, `--no-chain`, `--chain-poll-ms`, `--check-chain` (read-only check, then stop), transport timers (`--handshake-ms`, `--recv-ms`, `--send-ms`, `--ping-ms`, `--pong-ms`, `--reconnect-ms`, `--max-per-address`). `gazpacho-test` adds `--test-pings`, `--test-ping-ms`, `--test-crash-at-ping`, `--test-storage-fail-at`, `--test-start-delay-ms`, `--test-listen-during-start`, `--test-restore-from`; the release build refuses them.
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
| `program_store` | T8 (unit) | the stand-in against the storage contract; the counter, its fallbacks and the 2^63 refusal; the marker |
| `program_options` | | the command line; mainnet refused first |
| `program_two_process` | P3 | a host and two members over `peers.h`: ping/pong through the real runners and journals; the host killed after a ping is durable, its start's resend dropped (no outbox) and the loss repaired at reconnect; a storage failure restarted in-process with every connection closed; a member killed and restarted; the start queue (a member that connects and pings during a held start reaches the node only after "ready"); the lock, the role check, the shutdown order |
| `program_slow_peers` | T6 | a silent TCP client, a byte-a-second act one and a handshake without init each closed at the handshake deadline while a real member connects at once and is answered |
| `program_restore_counter` | T8 | a journal restored alone starts at 6, not 3, with the restore batch first and a non-zero epoch; without the counter, 3 and "the person is told"; 2^63 refuses |
| `program_networks` | T15 | testnet4 host and member ping; a signet member and a testnet4 host both close over init; mainnet exits 2 |
| `program_release_build` | T12 (second half) | the release binary has no seeded source and no test code, refuses `--test-*`, and never delivers kind 32767 |
| `program_no_probes` | T14 | no core probe, no `GZ_RANDOM_OTHER` |
| `program_signet_check` | | opt-in (`GZ_LIVE_TESTS`): read-only against public signet servers |
