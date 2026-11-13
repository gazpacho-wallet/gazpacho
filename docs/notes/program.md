# The `gazpacho` program (stream S11)

Draft 1, 2026-11-12. Not yet reviewed. Code: `program/`; tests: `tests/program/`.

The program is the only thing around the core that touches storage, the network, the chain, the clock and the user. The core (`core/gazpacho`) decides; the program carries out. This note fixes how, so that every engine plugs into the same loop. It is a walking skeleton: it runs the placeholder node (`node.h`, the ping) end to end over the real runner, the merged transport and a journal stand-in, and engines replace the stand-ins as they merge.

## 1. Shape

One process, one thread, one data folder, one node. `gazpacho --data-dir DIR --role host|member`. Host and member are one executable; the role is fixed per data folder at its first start.

| Piece | File | Replaced or extended by |
|---|---|---|
| Executor loop, timers, start, restart | `program/executor.c` | stays; engines add nothing here |
| Storage interface | `program/store.h` | the journal (S5) and its encryption (S6) implement it |
| Journal stand-in | `program/journal_standin.c` | removed when S5 merges |
| Network adapter | `program/net.c` over `ports/net/conn.h` | `ports/net/peers.h` when PR 23 merges |
| Chain adapter | `program/pchain.c` over `ports/chain` | the chain watch loop (S8) |
| User adapter | `program/notify.c` (output lines) | the local API server (PR 26) |
| Data folder, lock, key files | `program/datadir.c` | key file of S6 |
| Command line | `program/options.c` | |
| Test traffic | `program/testping.c` | removed with the placeholder ping |

## 2. The executor loop

Per incarnation (`gzp_exec_incarnation`), in this order:

1. **Open storage and take the fence.** The store settles what an earlier program left pending: each batch is durable or gone for good (the stand-in cuts a torn tail and refuses corruption). Nothing an earlier program wrote can complete later, because that program is gone: the data folder lock says so.
2. **Make the incarnation durable.** `begin()` writes a number strictly greater than any used before for this storage, and syncs it (and the folder), before the runner exists (`runner.h`, the incarnation duty).
3. **Make the node and the runner.** Fresh, every incarnation. The runner's executor callback is the only place an action is carried out.
4. **Start the node from storage, before any other event and before the network is polled.** On `main` this is one `gz_node_start` call with every stored record. With the core follow-up it is the stepped start of `node.h`: call `gz_node_start` while `*more`; between steps give the node the storage confirmations its runner accepts (and nothing else); on `GZ_WAITING` give it the next confirmation. A waiting start with no confirmation to give is a contract mismatch and fatal. The start re-arms timers and re-registers watches: the program forgets both at every incarnation.
5. **Loop.** One `poll()` over the listening socket and every connection, with a timeout no later than the next timer, reconnect, chain poll or test ping, and at most 200 ms (to see a stop). Each outside occurrence becomes one event: `gz_node_handle`, then `gz_runner_submit` of the list it filled.

**Saves before sends, confirmations in order once each.** A SAVE in the callback is appended to storage. The confirmation is not given from inside the callback (the runner refuses re-entry): after each runner call returns, the loop takes durable batches from `complete()`, oldest first, once each, and gives each to `gz_runner_confirm`; only a `GZ_OK` reaches the node as `GZ_EVENT_STORAGE_CONFIRMED`, which may fill another list, and so on until storage has nothing new. The stand-in is synchronous, but the loop relies only on `complete()`, so a journal that commits in groups plugs in unchanged.

**Back-pressure (for an asynchronous journal).** The runner refuses a list whose saves would take its unconfirmed batches above `GZ_RUNNER_MAX_UNCONFIRMED` (32), and a refusal is fatal. The program cannot know how many saves a step will emit, so while `gz_runner_unconfirmed()` is above half the limit the loop stops taking new outside events (it polls storage only). The synchronous stand-in never gets there; S5 must keep this rule.

**Fatal.** A refused list (`GZ_ERR_REFUSED`), any other runner error, a storage failure, an error from the node, a full timer table: the incarnation ends (`GZP_RUN_RESTART`). Nothing more is carried out. `main.c` drops every connection (peers see the loss and send again what was not answered), keeps the outbox, and runs a new incarnation from step 1. After 5 restarts the program exits 1. A storage failure is reported to the runner with `gz_runner_storage_failed` as soon as the runner call returns (on `main` it refuses a call from inside the callback; with the follow-up it is also called inside, which stops the rest of the list at once), and nothing more is appended.

## 3. How actions and events map to the ports

| Core | Port | What happens |
|---|---|---|
| SAVE | storage | `append()`; confirmation via `complete()` (section 2) |
| SEND | `ports/net` | The bytes travel as the body of one odd custom message, type 32771 (a skeleton carrier; the factory envelope, type 52791, with PR 23). Peer id = first 8 bytes of SHA-256 of the peer's 33-byte static key, so it survives restarts of either side. Not connected: kept in order in a bounded outbox (1 MiB), sent when the peer connects |
| BROADCAST | `ports/chain` | `gz_chain_broadcast`; the outcome is written to the output only (no event exists for it) |
| WATCH (`WATCH_SCRIPT`, `WATCH_TX`, `WATCH_OUTPOINT` with the follow-up) | `ports/chain` | recorded; events from them are S8's watch loop, not built |
| SET_TIMER, CANCEL_TIMER | the loop | a table of 64 timers on the monotonic clock; setting a set id replaces it; a due timer fires once as `GZ_EVENT_TIMER_FIRED` |
| NOTIFY | the user | one output line now; `gz_api_notify` through a code-to-topic table with PR 26 |
| received message of type 32771 | `ports/net` | `GZ_EVENT_MESSAGE_RECEIVED`; an unknown even type closes the connection, an unknown odd one is ignored (BOLT 1) |
| connection up or down | `ports/net` | `GZ_EVENT_PEER_CONNECTED` / `_DISCONNECTED` with the follow-up; on `main` only the outbox is flushed |
| new chain tip | `ports/chain` | `GZ_CHAIN_NEW_TIP`, from a tip poll every `--chain-poll-ms` |
| random port | the OS | `getrandom` at each call, both tags (`GZ_RANDOM_SECRET` and ordinary); nothing seeded, buffered, logged or journaled |
| clock port | the OS | wall clock in ms; timers use the monotonic clock instead |

## 4. Storage

`program/store.h` is the interface the real journal (S5) and storage encryption (S6) will provide: `begin` (fence and durable incarnation), `next`/`rewind` (read back, the shape of `gz_storage_reader_t`), `append`, `complete`, `restored` (the restore marker), `close`. Today it is backed by `journal.standin`: a header, then `INCN` (incarnation) and `BTCH` (batch) entries, each with a SHA-256. It has no encryption, no key_epoch, no restore marker (always 0), no compaction, and keeps everything in memory. Its incarnation counter is inside the file, so restoring a backup of it would rewind the counter: the stand-in must never be restored from a copy (`runner.h`, "Restoring a backup is the dangerous case"). S5 and S6 are separate streams and are not built here.

## 5. Data folder, roles, network, options

- **One program per data folder.** `flock(LOCK_EX|LOCK_NB)` on `DIR/lock` for the program's life; a second program is refused (exit 3) with the holder's pid. The folder is created 0700 and refused if others can read it.
- **Identity.** `DIR/identity` holds the role and network written at the first start; another role or network is refused (exit 4).
- **Mainnet is refused** (exit 2) on the command line, before any folder is made, and a chain server whose block 0 is not the configured network's is refused at start (exit 5). Networks: `signet` (default), `testnet4`.
- **Options.** `--data-dir`, `--role`, `--network`, `--listen ADDR:PORT` (host; numeric), `--connect KEY@ADDR:PORT` (member; the `messages.md` section 2 form), `--interface-port`, `--no-interface`, `--chain-url` (one Esplora server for now), `--no-chain`, `--chain-poll-ms`, transport timers, and `--test-*` hooks used only by the tests.
- **Key files (stand-ins).** `transport.key` (BOLT 8 static key) and `wallet-seed.standin` (entropy of the 24 words), 64 hex each, mode 0600, unencrypted until S6. The wallet (`wallet/`) derives the first BIP 86 address at start as a check.
- **Roles.** A host listens and accepts any member key (`transport.md` rule 13); a member keeps one connection to its pinned host, reconnecting every `--reconnect-ms`.

## 6. Contract changes still to come (PR 9 / PR 21)

Built against `main`, ready for the core follow-up. `program/CMakeLists.txt` probes the core's headers and turns on the code for each addition, so the same sources build against either:

| Follow-up change | Probe | What the program does |
|---|---|---|
| Stepped start, `gz_storage_reader_t`, `GZ_WAITING`, `GZ_ERR_CORRUPT` | `GZP_CORE_STEPPED_START` | section 2 step 4; storage is walked through `next`/`rewind` |
| Random port takes a purpose tag | `GZP_CORE_RANDOM_PURPOSE` | the tag is accepted; both read the OS at the call |
| `WATCH_SCRIPT`, `WATCH_TX`, `WATCH_OUTPOINT` | `GZP_CORE_WATCH_TX` | recorded for S8 |
| `GZ_EVENT_PEER_CONNECTED` / `_DISCONNECTED` | `GZP_CORE_PEER_EVENTS` | delivered on connection changes |
| `gz_runner_storage_failed` allowed inside the executor; a bad confirmation fails the runner | none needed | called inside and after; any non-`GZ_OK` confirm is fatal on both |
| The restore marker | none | `store.restored()`; the stand-in always says 0 |

**Start order once storage is encrypted (S6, PR 26).** The journal cannot be read before the storage key is in memory, and the key comes from the passphrase through the local interface. So the order becomes: take the folder lock; bring up the interface in the locked state; on unlock open storage (steps 1 and 2); start the node (step 4); only then connect to peers. Today there is no key and no interface, so storage opens at once.

## 7. Mismatches between the pieces

Found while wiring the merged pieces together (and the open branches they will meet). Each needs a decision or a change in the stream named. Ordered by consequence.

1. **"Released" is not "left", and the placeholder treats it as an acknowledgement** (core, `node.h`). The runner releases a SEND when it hands it to the program; the placeholder then saves a "sent" record as soon as the ping's batch is confirmed. If the peer is not connected at that moment the program can only keep the reply in memory (here, the outbox), and a stop before the peer reconnects loses it for good: the stored "sent" record stops the next start from resending. So the guarantee in `node.h` ("the reply leaves at least once, provided the node goes on running or is started again") does not hold across a disconnection plus a stop. Engines must not do the same: an acknowledgement that matters is the peer's own message, never the runner's release (rule 3 of `node.h` should say so).
2. **Peer identity has three incompatible shapes.** The core names a peer by a `uint64_t`; the transport by its 33-byte static key (and PR 23 by a connection number that is never reused); `messages.md` section 2 gives a member a fresh key per new connection unless it holds a seat. The placeholder stores the peer id with each ping and resends to it after a restart, which only works if the id is stable: the program uses the first 8 bytes of SHA-256 of the static key, and members keep one key. With fresh keys per connection, an engine's resend after a restart would go to an id nobody will ever connect as. Needed (S7 with the core): a defined peer id (key-derived, with the seat key for a seated member), and the rule that engines address resends to seats, not to connections.
3. **The core cannot open, close or choose a key for a connection, nor mark a seat.** Who connects where, with which key index (saved with the guard before the handshake, `messages.md` section 2) and when a connection holds a seat (`gz_peers_set_seated`, PR 23) are engine decisions, but there is no action for them; today the program decides (a member keeps one connection to its pinned host). Needed (core + S4 lobby engine): CONNECT / DISCONNECT / SET_SEATED actions, or a documented rule that the program derives them from engine state it is told about.
4. **One poll loop, but the next ports each own their wait.** `gz_peers_poll(timeout)` (PR 23) and `gz_api_server_poll(timeout)` (PR 26) each block inside and expose no descriptors, and the API server also runs a passphrase thread. Two such calls cannot share one `poll()` without alternating short timeouts (latency, or a busy loop). Needed (S7, S9): an interface that gives the caller its descriptors and next deadline, and a call to make after `poll()`; or one shared event loop the ports register with.
5. **The chain view blocks the loop.** Every `ports/chain` call blocks for up to the backend's timeouts (15 s, three attempts with backoff, `chain_esplora.h`). Inside the one loop that stalls timers and the transport: with PR 23's keep-alive (pong within 30 s) a slow chain server could get every peer disconnected. The skeleton accepts this (one tip poll a minute); S8 must run chain calls off the loop (a worker thread with a result queue, the results turned into events by the loop) or make them non-blocking.
6. **The merged transport blocks too** (`ports/net/conn.h`, its own "Slice 1 limit"): accept with its handshake, connect, and a message once its first byte has arrived each hold the loop for up to their limits. Fine on loopback; PR 23's `peers.h` steps them without blocking and replaces this adapter.
7. **Node messages have no kind or scope.** A SEND carries bytes; the factory envelope (`messages.md` section 3, PR 23's `gz_peers_send`) needs a kind (16 bits) and a 32-byte scope next to the records. Either the core's SEND gains those fields or engines put the envelope header in their bytes and the adapter parses it; the placeholder's "GZPI" bytes are not a Lightning message at all, so the skeleton wraps them in an odd custom type (32771).
8. **The incarnation counter can be rewound by a restore.** `runner.h` (follow-up) asks for the counter to live where restoring a backup cannot rewind it, or for a restored start to use a number above any used since the backup; `ports.h` (follow-up) has the journal write the incarnation inside the journal (`journal.md` section 5), and a backup imported as the journal (section 8.2) brings its old counter back. The program cannot know the numbers used since the backup unless something outside the journal and outside backups records them. Needed (S5/S6): such a record (for example next to the key file), and its use when the restore marker is set. The stand-in has the same weakness and must never be restored from a copy.
9. **No event for a broadcast's outcome.** `GZ_ACTION_BROADCAST` goes out; `event.h` has nothing for "accepted", "already known" or "refused, with the server's reason" (`gz_broadcast_result`). An engine can only infer from watches. Needed (core, S8): a broadcast-result event, or the rule that engines rely on watches alone (and say so in `action.h`).
10. **`WATCH` on `main` asks for a script spend, which the chain view cannot answer directly.** `gz_chain_script_outputs` lists only unspent outputs, so a spend shows only as an output disappearing; telling who spent it needs the outpoint and `gz_chain_outspend`. The follow-up's `WATCH_OUTPOINT` and `WATCH_TX` fit the chain view; `WATCH_SCRIPT` will need the watch loop to remember every outpoint it has seen per script (S8).
11. **The interface reads state the core does not offer.** PR 26's backend answers status facts, wallet state and calls synchronously (`api_backend.h`), and publishes changes as `gz_api_notify(topic, id)` with no payload; the core offers NOTIFY (code, bytes) and an opaque USER_COMMAND, and no way to read its state. Needed (core + S9): either read-only queries on the node, or a defined set of NOTIFY codes whose payloads let the program keep the backend's view; and a mapping from API calls to USER_COMMAND bytes. The API server also checks and creates the data folder itself (`gz_api_config.data_dir`): the program owns the folder and its lock, so the server should be given a folder already checked.
12. **The transport depends on the core's random port type.** `ports/net` takes `gz_random_port_t` from `core/gazpacho/ports.h`, so the follow-up's purpose tag changes the transport too (PR 21 edits `noise.c`). Harmless, but it couples two streams' merge order.
13. **Member keys have no derivation yet.** `messages.md` section 2 derives the member's BOLT 8 key from the seed, the restore epoch and a key index, and leaves the path open; `wallet/` has no function for it. The skeleton keeps a random `transport.key` per data folder.
14. **Networks.** `messages.md` section 2 requires `init` to name the signet chain only; the program, the wallet tools and the chain view also accept testnet4. Slice 1 should settle on signet only, or the spec should allow testnet4.

## 8. Integration contract for engine pull requests

Every pull request that adds or changes an engine, a port or a stand-in must:

1. **Plug in through the adapter, not around it.** An engine is reached only through `gz_node_handle` and `gz_node_start`; it emits actions and nothing else. A port lands behind its adapter in `program/` (`store.h` for storage, `net.c` for the network, `pchain.c` for the chain, `notify.c` for the user) and keeps the loop single-threaded and non-reentrant: nothing it calls from inside the runner's callback may call the runner or the node.
2. **Keep the executor's rules.** Saves before sends; confirmations from storage only, oldest first, once each; the incarnation durable before the runner; the start before any other event; timers and watches set again at every start; refusal and storage failure fatal and restarted from storage.
3. **Add a multi-process test to `tests/program/`**, registered with CTest, on loopback with short timers, that runs the engine's own messages between separate `gazpacho` processes through the real runner and the storage in use, and shows, by outcome (what each side ended with, not that a defence fired):
   - the happy path across processes;
   - a crash of each role at the engine's worst point (after a save, before its send: `--test-crash-*`), restarted on the same data folder, ending in the right state;
   - a storage failure in the middle, recovered in the same process;
   - duplicates and reordering after a reconnect left harmless (`node.h`, rule 2).
4. **Update this note**: sections 1 and 3 for what it replaces, section 7 for any mismatch it fixes or finds.
