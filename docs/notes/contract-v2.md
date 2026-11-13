# Contract v2: the fifteen mismatches resolved

Draft 1, 2026-11-12. Not yet reviewed. Answers section 7 of `docs/notes/program.md` (PR 27, the program skeleton), which found fifteen places where the merged and open pieces do not fit. Each section below gives the decision, why, the exact interface change (header and specification text), the piece that owns it, and the multi-process test in `tests/program/` that proves it. Section 17 orders the work into small pull requests that each land without breaking `main`.

Read against: `core/gazpacho/include/gazpacho/*.h` on `main` (PR 9 and PR 21 merged), `ports/net/` on `main` and on `transport-lobby` (PR 23), `ports/api/` on `api-server` (PR 26), `ports/chain/` on `main`, and `spec/messages.md`, `transport.md`, `local-api.md`, `journal.md`, `storage-encryption.md`, `signing-round.md` 12.1.

Owners, as in the stream list: **core** (`core/gazpacho`), **S2** signing, **S4** lobby engine, **S5** journal, **S6** storage encryption, **S7** transport (PR 23), **S8** chain watch loop, **S9** local API (PR 26), **S11** program (PR 27), **wallet** (`wallet/`).

Spec text applied in this pull request: `messages.md` sections 2, 4.1, 6.2, test 18 and open point 3; `terms.md`'s `chain` term and check 4 (signet or testnet4, as item 15 needs); `signing-round.md` 12.1. Everything else here is the text the owning pull request applies, so that no open branch is edited behind its owner's back (S5 and S6 in particular: PR 25 is open on `storage-encryption.md`).

## 0. The decisions in one table

| # | Mismatch | Decision | Owner | PR (section 17) |
|---|---|---|---|---|
| 1 | "Released" treated as "sent" | Release is hand-over, not delivery. Only the peer's own message is an acknowledgement. Engines resend unacknowledged state at start **and at every `PEER_CONNECTED`**. The program keeps no outbox: a send to a peer that is not connected is dropped. The placeholder gets a peer acknowledgement (`GZPA`) and loses its "sent" record | core, S11 | P4 |
| 2 | Three shapes of peer identity | A peer is named by the **link**: the pair (our 33-byte static key, its 33-byte static key), `gz_link_t`. Stable across restarts because every key is derived (13). One live connection per link; the newer replaces the older. Connection numbers stay inside the transport | core, S7, S11 | P4 |
| 3 | No action to connect, disconnect, choose a key, mark a seat | Three new actions: `CONNECT` (host key, address, our key's epoch and index; **outward**, so it waits for the save of `key_index`), `DISCONNECT`, `SET_SEATED`. Connections are kept until `DISCONNECT` or a stop, and are not kept across a restart: the start asks again, like timers and watches | core, S4, S11 | P4 |
| 4 | One poll loop, ports that block in their own | Every port that waits exposes its descriptors and next deadline and is stepped after the caller's `poll()`: `gz_peers_pollfds`/`gz_peers_dispatch`, `gz_api_server_pollfds`/`gz_api_server_dispatch`, `gz_chainw_fd`. The API's passphrase thread stays; its rule is tightened | S7, S9, S8, S11 | P2, P3, P5, P6, P7 |
| 5 | Chain calls block the loop up to 45 s | The chain view runs on **one worker thread** (`gz_chainw`) with request and result queues and a wake descriptor. The loop never calls `ports/chain` itself. Results carry a generation, so nothing from before a restart is delivered | S8, S11 | P7 |
| 6 | The merged transport blocks | The program uses only `ports/net/peers.h` (PR 23). `conn.h` stays for `gz-net` and tests | S7, S11 | P2, P3 |
| 7 | `SEND` has no kind or scope | `SEND` and `MESSAGE_RECEIVED` carry the envelope's fields: `kind` (`u16`), `scope` (32 bytes), `records` (the TLV stream). The program passes them to `gz_peers_send`, which splits. The placeholder uses kind **32767**, reserved for test builds | core, S7, S11 | P2, P4 |
| 8 | A restore rewinds the incarnation counter | An **incarnation floor** file, `floor.gzf`, outside the journal's backup set and sealed under a key from the seed. Every start writes the new incarnation there before the runner exists; every start takes 1 + max(journal's highest, floor) | S5, S6, S11 | P9 |
| 9 | No broadcast-outcome event | A chain event `GZ_CHAIN_BROADCAST_RESULT` (accepted, refused, unreachable), **advisory only**: never stored as proof, never final. Watches stay the only truth | core, S8 | P4, P7 |
| 10 | `WATCH_SCRIPT` fits the chain view poorly | **Retired.** `gz_action_list_add` refuses it; the number stays reserved. Slice 1 needs only `WATCH_TX` and `WATCH_OUTPOINT`, which the chain view answers directly | core, S8 | P4 |
| 11 | The API reads state the core does not offer; the server makes the data folder | No queries on the node. The program keeps a **view**, fed only by `NOTIFY` actions with a defined framing (released after saves, so the view shows only durable state), re-emitted by every start; the backend reads the view on the loop thread. Changing calls become `USER_COMMAND`s answered `202` with a request id; their outcome is a `NOTIFY`. The server is handed a folder the program has checked and locked, and creates nothing | core, S9, S11 | P5, P6 |
| 12 | Transport depends on the core's random port type | `ports/net` gets its own type, `gz_net_random_t` (`fill(ctx, out, len)`, every draw a one-time secret), and includes no core header. A check enforces it | S7 | P2 |
| 13 | No member key derivation | `m / 254315617' / coin' / 0' / epoch' / index'` for per-lobby keys (contribution key at `index`, factory key at `index` + 1), `m / 254315617' / coin' / 1' / 0'` for the host's long-term key; `gzw_lobby_key` and `gzw_host_key` in `wallet/`. **Proposed, owner to confirm** | wallet, S11 | P8 |
| 14 | Two random port signatures | Settled on `main`: PR 21's enum won (`gz_random_purpose_t`, `GZ_RANDOM_ORDINARY` = 0, `GZ_RANDOM_SECRET` = 1, `fill(ctx, purpose, out, len)`). The program drops its probes and builds against `main` only | S11 | P3 |
| 15 | `init` names signet only, tools accept testnet4 | `init`'s `networks` holds exactly one chain hash, the network the party was set up for: **signet or testnet4**. Applied in `messages.md` section 2 | spec (here), S7 | P1, P2 |

## 1. "Released" is not "sent"

**Decision.** A runner release means the program has the action, nothing more. A released send can be lost: the peer is not connected, the connection drops with bytes queued, the program stops. So:

- **Node rule 3 (amended).** The acknowledgement that stops a resend is always a message from the peer, received and saved. Never the runner's release, never a storage confirmation of one's own batch.
- **Node rule 6 (new).** At `GZ_EVENT_PEER_CONNECTED` for a link, an engine resends, from stored bytes, everything addressed to that link with no stored acknowledgement. Together with rule 1 (resend at start) this is the whole delivery guarantee.
- **The program keeps no outbox.** A `SEND` for a link with no live connection is dropped and counted (`dropped_unconnected`), and so is one the transport refuses (queue full). Keeping it in memory gave a delivery that a stop silently undid; dropping it makes the engine's resend the only path, so it is the path every test exercises.

This is how the specifications already work: `messages.md` section 6 resends state after every `hello`, and 6/7.10 has the member resend `round_partial_sigs` after reconnecting. BOLT 2's `channel_reestablish` is the same pattern: delivery is re-established per connection, not assumed from the sender's side.

**Interface change.** `node.h`, "What every engine's start step must do", rule 3 becomes:

> 3. Store, as records, the acknowledgements that matter. Anything not in storage is not known after a restart, and will be sent again. **An acknowledgement is a message from the peer, saved when it arrives.** That the runner released a send, or that storage confirmed the batch it followed, says only that the program has the message; the program may drop it (the peer is not connected) and a stop loses whatever it had not written to a socket. No engine may save "sent" for anything it must deliver.

and a new rule 6 (the old 4 and 5 keep their numbers):

> 6. At `GZ_EVENT_PEER_CONNECTED` for a link, resend, from the stored bytes, every message for that link with no stored acknowledgement, in the order first sent. The program keeps nothing for a peer that is not connected (`docs/notes/contract-v2.md` section 1).

"What the placeholder guarantees" becomes:

> At least once, to a peer that comes back. If the record of a ping is durable, the reply reaches that link at least once, provided the node goes on running or is started again and the peer connects again with the same keys. The member answers each reply with an acknowledgement (`GZPA` and the serial); the host saves a `GZ_RECORD_TEST_PING_ACKED` record when one arrives. At start, and at every `GZ_EVENT_PEER_CONNECTED`, the host resends, oldest first, every reply on that link with no stored acknowledgement.

`GZ_RECORD_TEST_PING_SENT` (0x7e570002) is withdrawn and `GZ_RECORD_TEST_PING_ACKED` (0x7e570004: one or more 8-byte big-endian serials) replaces it. The start no longer saves anything but the restore batch, so its `GZ_WAITING` path for "sent" records goes; `GZ_WAITING` itself stays in the contract for engines.

`program/net.h`: `GZP_OUTBOX_MAX_BYTES`, `gzp_out_t` and the outbox fields go; `gzp_net_send` returns 0 (handed to the transport) or 1 (dropped: not connected, or refused); `gzp_net_drop_all` no longer "keeps the outbox".

**Owner.** core (node.h text, node.c placeholder, simulator), S11 (net adapter).

**Test T1, `program_resend_on_connect`.** A host and one member.
1. The member sends ping 1 and exits at once (`--test-exit-after-send`); the host saves the ping, its reply is released and dropped (output line `send dropped: not connected`).
2. The host is killed (SIGKILL) and restarted on its folder. The member is started again. On `PEER_CONNECTED` the host resends reply 1; the member receives it and answers `GZPA 1`; the host saves the acknowledgement.
3. The host is restarted once more: it sends nothing on the member's link (no `send` line), because the acknowledgement is stored.
4. Repeat with the host not restarted, only the member: the resend comes from `PEER_CONNECTED` alone.
Outcome checked: the member's received serials include 1, the host's journal holds `PING_ACKED 1`, and the last start sent no reply.

## 2. Peer identity

**Decision.** The core names a peer by the **link**, the pair of static keys of a connection:

- the remote key proves who the peer is (BOLT 8; `transport.md` rule 13);
- the local key is needed as well, because a member may hold two connections to one host with different keys of its own: one for a lobby where it has a seat, one fresh to read the host's listings (`messages.md` section 2). Naming the host alone would not say which connection a `join` or a `ready` belongs to.

Both keys are derived from the seed (section 13), so a link is the same after a restart of either side, and an engine's stored resends find it again. A 64-bit hash (the skeleton's choice) is not used: a 33-byte key is what the specifications, the transport and the signatures all use, it cannot collide, and no table from hash to key is needed. PR 23's connection number stays inside the program's net adapter.

**One live connection per link.** A second connection with the same pair replaces the first: the program closes the older, delivers `PEER_DISCONNECTED` for it, then `PEER_CONNECTED` for the newer. (Lightning implementations do the same on a reconnect from a known node id.)

**Interface change.** `types.h`:

```c
/* A node id: a 33-byte compressed secp256k1 public key, the BOLT 8 static
 * key (BOLT 1's node_id). */
#define GZ_NODE_ID_LEN 33
typedef struct { uint8_t key[GZ_NODE_ID_LEN]; } gz_node_id_t;

/* A link: one connection's two static keys. The only name the core has for a
 * peer. `local` is our key on it (the host's long-term key on the host side;
 * a per-lobby key on a member's side, messages.md section 2); `remote` is the
 * key the handshake proved. Both are derived from seeds, so a link is the
 * same after either side restarts. At most one connection per link is live. */
typedef struct { gz_node_id_t local; gz_node_id_t remote; } gz_link_t;
```

Every `uint64_t peer_id` in `action.h` and `event.h` becomes `gz_link_t link` (section 3 and 7 give the structs). The placeholder's ping record carries the link instead of the 8-byte id: clock (8), link (66), serial (8), payload; `GZ_PING_RECORD_HEADER` becomes 82.

**Rule for engines** (added to `node.h`, after rule 6): *An engine addresses what it resends after a restart to a link it has stored: a member to (its seat's key, the host's key), a host to (its key, the seat's contribution key). Never to a connection, and never to a key it has not stored.*

**Owner.** core (types, events, actions, placeholder), S11 (adapter maps connection numbers to links), S7 (nothing new: events already carry `node_id`; the program reads the local key from what it passed to `gz_peers_connect`, or the listener's key).

**Test T2, `program_links`.** A host and two members, A and B.
1. A pings; the host is killed after the ping is durable and before the reply leaves (`--test-crash-after-save`); restarted, it resends to A's link when A reconnects; B never receives A's reply.
2. A connects a second time with the same keys while the first connection is open: the host's output shows `disconnected` for the old connection then `connected` for the new, and exactly one reply per ping reaches A.
3. A opens a second connection with a fresh key to the same host (section 3's `CONNECT` with another index): the host sees two links; a reply addressed to one never arrives on the other.

## 3. Connect, disconnect, choose a key, mark a seat

**Decision.** These are engine decisions, so they are actions:

- **`CONNECT`**: keep a connection to `host` at `address`, using our key (`key_epoch`, `key_index`). It is **outward**: it reveals our key to someone else, so it waits for every save before it, which is how `messages.md` section 2's "saved (with the guard) before the handshake" is enforced: the engine puts the `key_index` and `guard` save first, then `CONNECT`, and the runner holds the handshake until the save is confirmed. The program derives the secret key from the seed (section 13), makes the connection, and reconnects with backoff (1 s doubling to 60 s) while the action stands. Each connection up or down is a `PEER_CONNECTED` / `PEER_DISCONNECTED` event. A second `CONNECT` with the same host and key replaces the address.
- **`DISCONNECT`**: close every connection on `link` and stop keeping it. Not outward (closing reveals nothing), but ordered: rule 3 of `runner.h` keeps it behind a send listed before it.
- **`SET_SEATED`**: the host marks a link as holding a seat, or no longer (PR 23's `gz_peers_set_seated`: a seated connection is never evicted for a newcomer). Not outward.

Like timers and watches, connections are not kept across a restart: at start an engine issues `CONNECT` again for every link it still needs, and `SET_SEATED` again for every seat. The host's **listening** stays program configuration (`--listen`), because it needs no engine decision and no key choice; which members to accept stays `transport.md` rule 13 (any key in Slice 1).

**Interface change.** `action.h`, enum (appended, so existing numbers do not move):

```c
    GZ_ACTION_CONNECT,       /* keep a connection to a host, with one of our keys */
    GZ_ACTION_DISCONNECT,    /* close a link and stop keeping it */
    GZ_ACTION_SET_SEATED     /* host: a link holds a seat, or no longer does */
```

union members:

```c
        /* CONNECT: outward. `address` is "host:port", numeric (transport.md:
         * no name lookup), at most 64 bytes. Our key is the per-lobby key
         * (key_epoch, key_index) of contract-v2.md section 13. */
        struct { gz_node_id_t host; gz_bytes_t address; uint32_t key_epoch; uint32_t key_index; } connect;
        struct { gz_link_t link; } disconnect;                       /* DISCONNECT */
        struct { gz_link_t link; int seated; } set_seated;           /* SET_SEATED */
```

`gz_action_is_outward`: send, broadcast, notify **and connect**. `gz_action_list_add` refuses an empty or over-long address, or `seated` other than 0 or 1.

A paragraph after WATCHES:

> CONNECTIONS. A CONNECT stands until a DISCONNECT for its link or the end of the node's program; the program reconnects while it stands. Connections are not kept across a restart: at start a node issues CONNECT again for every link it needs, and SET_SEATED again for every seat. CONNECT is outward because the handshake shows our key: the save of the key's index (messages.md section 2) must come before it in the list, and the runner holds the handshake until that save is confirmed.

`event.h`, peer events:

```c
        /* PEER_CONNECTED, PEER_DISCONNECTED. `outbound`: 1 if we connected
         * (then key_epoch and key_index name our key, as in the CONNECT);
         * 0 if we accepted. */
        struct { gz_link_t link; int outbound; uint32_t key_epoch; uint32_t key_index; } peer;
```

**Placeholder.** The member's target, now given by the test as a `USER_COMMAND` ("connect KEY@ADDR:PORT", saved with a key index) instead of the program's `--connect`, is re-issued as `CONNECT` at every start; the host issues `SET_SEATED` for a link at its first ping. `--connect` stays as a test convenience that submits that command at the first start.

**Owner.** core (actions), S4 (the lobby engine is the first real user), S11 (the program carries them out over `gz_peers_connect`, `gz_peers_close`, `gz_peers_set_seated`).

**Test T3, `program_connect_actions`.**
1. A member is killed after its `key_index` batch is handed to storage and before it is confirmed (`--test-crash-before-confirm`), several times. The host's log of keys seen is a subset of the keys whose index is durable in the member's journal (read with `gazpacho --test-dump-journal`): no handshake ever used an unsaved key.
2. The member restarted reconnects with the same key; the host sees the same link.
3. A `DISCONNECT` user command: the connection closes and is not made again until a new `CONNECT`.
4. The host run with `max_conns` 2: one seated member and two unseated newcomers; the seated one is never evicted, an unseated one is.

## 4. One poll loop

**Decision.** One thread runs the loop; every port that waits gives the loop its descriptors and its next deadline, and is stepped after the loop's `poll()`. No port blocks inside a call the loop makes. The program's timeout is the earliest of: the ports' deadlines, the node's timers, and a 200 ms ceiling (to see a stop request). Two threads remain, both outside the node:

- the API server's **passphrase thread** (Argon2id takes about a second by design, `storage-encryption.md` 4.2): it already wakes the loop through its `done_pipe`, which becomes one of the server's descriptors;
- the **chain worker** (section 5).

Neither touches the node, the runner or storage. Each hands results to the loop, which turns them into events.

**Interface change.** PR 23, `peers.h`:

```c
/* One loop for everything. Writes the descriptors this object waits on (with
 * their events) to fds[0..cap) and returns how many, at most
 * gz_peers_max_fds(p); sets *timeout_ms to the time until its next deadline
 * (a handshake, ping, pong, message or send limit), or -1 for none. The
 * descriptors are valid until the next call of any gz_peers_ function. */
size_t gz_peers_max_fds(const gz_peers_t *p);
size_t gz_peers_pollfds(gz_peers_t *p, struct pollfd *fds, size_t cap, int *timeout_ms);
/* After the caller's poll(): act on fds[0..n) as written by the last
 * gz_peers_pollfds, with revents filled, and on every deadline that has
 * passed. Never blocks. Events are then taken with gz_peers_poll(p, 0, ev)
 * until it returns 0. */
void gz_peers_dispatch(gz_peers_t *p, const struct pollfd *fds, size_t n);
```

`gz_peers_poll(p, 0, ev)` is guaranteed not to block. Its blocking form stays for `gz-net` and the tests.

PR 26, `api.h`:

```c
/* As gz_peers_pollfds: the listeners, the connections, the wake pipe and the
 * derivation thread's done pipe; *timeout_ms the next head, body, idle,
 * keep-alive or merge deadline. */
size_t gz_api_server_max_fds(const gz_api_server *srv);
size_t gz_api_server_pollfds(gz_api_server *srv, struct pollfd *fds, size_t cap, int *timeout_ms);
/* After poll(): serve what is ready, answer finished passphrase jobs, send
 * merged events. Never blocks. Loop thread only. */
int gz_api_server_dispatch(gz_api_server *srv, const struct pollfd *fds, size_t n);
```

`gz_api_server_run` and `gz_api_server_poll` stay for the server's own tests. `api_backend.h`, the "Threads" paragraph becomes:

> Threads. passphrase_op runs on the server's derivation thread, at most one at a time, and only derives: it turns the passphrase (and words) into a key or a result and touches nothing the loop thread uses: not the node, the runner, storage or the view. passphrase_done, on the loop thread, installs what it produced (opens storage, starts the node). Every other entry runs on the loop thread.

S8, `gz_chainw_fd` (section 5).

The program's loop (`program/executor.c`), per turn: collect descriptors from `gzp_net` (over `gz_peers`), the API server and the chain worker; `poll()` until the earliest deadline; dispatch each; drain `gz_peers_poll(p, 0, …)`, finished chain results and due timers, each becoming one event (`gz_node_handle`, `gz_runner_submit`, confirmations as in program.md section 2).

**Owner.** S7 (PR 23), S9 (PR 26), S8, S11.

**Test T4, `program_one_loop`.** A host with the interface on and two members pinging every 100 ms (`--test-ping-ms 100`), shortened keep-alive (ping 1 s, pong 2 s).
1. While a client signs in five times in a row (a real Argon2id derivation on the thread, with the test passphrase from the test fixture), every pong arrives within 300 ms of its ping and no connection closes.
2. An event-stream client stays open throughout and receives each `status` change.
3. Idle for 5 s with nothing to do, the host's CPU time (from `/proc/<pid>/stat`) stays under 100 ms: no busy loop.

## 5. The chain view off the loop

**Decision.** `ports/chain` stays blocking: its timeouts, retries and server comparison are right where they are. S8's watch loop runs it on **one worker thread**, behind queues. The loop submits requests (watches, broadcasts, the tip poll) without blocking and takes results when the worker's descriptor is readable. A watch loop on its own thread also keeps a slow server from delaying the next tip check of a fast one inside the comparing backend's own sequence.

Every request carries the generation the loop gave at `gz_chainw_reset`; the worker drops results of an older generation. A restart from storage calls `gz_chainw_reset`, so no report from before the restart reaches the new node, which sets its watches again (`action.h`, WATCHES).

**Interface change.** New header `ports/chain/include/gazpacho/chain_watch.h` (S8). It includes no core header (the program converts):

```c
typedef struct gz_chainw gz_chainw;

typedef struct gz_chainw_config {
  gz_chain *chain;              /* owned by the worker from here on */
  uint32_t tip_poll_ms;         /* 60,000 */
  size_t max_requests;          /* queued, not yet taken by the worker (1,024) */
  size_t max_results;           /* waiting for the loop (4,096) */
} gz_chainw_config;

/* Starts the worker. NULL on failure. */
gz_chainw *gz_chainw_new(const gz_chainw_config *cfg);
/* Readable while results wait. */
int gz_chainw_fd(const gz_chainw *w);
/* Forget every watch and pending request; results of earlier generations are
 * dropped. Returns the new generation. */
uint64_t gz_chainw_reset(gz_chainw *w);
/* Never block. 0 queued; -1 the request queue is full (fatal for the
 * incarnation, as a full timer table is). txids in hashing order. */
int gz_chainw_watch_tx(gz_chainw *w, const uint8_t txid[32], uint32_t depth);
int gz_chainw_watch_outpoint(gz_chainw *w, const uint8_t txid[32], uint32_t vout, uint32_t depth);
int gz_chainw_broadcast(gz_chainw *w, const uint8_t *raw, size_t len);

typedef enum gz_chainw_kind {
  GZ_CHAINW_TIP = 1, GZ_CHAINW_TX_CONFIRMED, GZ_CHAINW_TX_UNCONFIRMED,
  GZ_CHAINW_OUTPOINT_SPENT, GZ_CHAINW_BROADCAST, GZ_CHAINW_SOURCES
} gz_chainw_kind;

typedef struct gz_chainw_result {
  gz_chainw_kind kind;
  uint64_t generation;
  uint8_t txid[32];             /* watched tx, spender, or broadcast tx */
  uint8_t outpoint_txid[32];
  uint32_t outpoint_vout;
  uint32_t confirmations, height;
  gz_broadcast_result broadcast;/* GZ_CHAINW_BROADCAST */
  gz_chain_result sources;      /* GZ_CHAINW_SOURCES: agree, lag, disagree, unreachable */
} gz_chainw_result;

/* 1 and *out, or 0 when nothing waits. Never blocks. */
int gz_chainw_take(gz_chainw *w, gz_chainw_result *out);
/* Stops the worker (waits at most one request's timeouts) and frees. */
void gz_chainw_free(gz_chainw *w);
```

The worker answers `WATCH_TX` and `WATCH_OUTPOINT` exactly as `action.h` WATCHES says (`gz_chain_tx_status`, `gz_chain_outspend`, and the tip to count confirmations and see reorganisations). `GZ_CHAINW_SOURCES` feeds the API's chain state (`local-api.md` 11.2) and never reaches the node.

`program/pchain.c` becomes the converter: results to `gz_chain_event_t`, `BROADCAST` and `WATCH_*` actions to requests.

**Owner.** S8 (worker and header), S11 (adapter).

**Test T5, `program_chain_stall`.** The local test server (`ports/chain/tests/local_server.py`) made to answer every request after 20 s. A host and a member with the shortened keep-alive of T4 and a 500 ms test timer. Over 40 s: no connection closes, every ping is answered within 300 ms, the timer fires every 500 ms within 50 ms. Then the server answers again: the tip arrives as `GZ_CHAIN_NEW_TIP`. A restart from storage in the middle (`--test-fail-storage-at`) delivers no chain result of the old generation (counted by output line).

## 6. The merged transport blocks

**Decision.** The program carries out network actions only through `ports/net/peers.h` (PR 23), whose handshakes and messages are stepped without blocking, and through section 4's descriptors. `ports/net/conn.h` keeps its blocking calls for `gz-net` and the transport's tests; nothing in `program/` includes it. `transport.md`'s "Limits of this cut" (the open choice between a stepped handshake and connection threads) is closed by PR 23: stepped, one `poll`.

**Interface change.** None beyond section 4. `program/net.c` is rewritten over `gz_peers_*`; `gz_conn_*` leaves the program. PR 23 updates `transport.md` "Limits of this cut" to say the first limit is gone for `peers.h`.

**Owner.** S7, S11.

**Test T6, `program_slow_peers`.** Against a host: one TCP client that connects and sends nothing, one that sends act one a byte per second, one that completes the handshake and never sends `init`. A real member connecting meanwhile is connected within 1 s and gets every pong; each slow client is closed at its deadline (`GZ_PEER_WHY_TIMEOUT_HANDSHAKE`), seen in the host's output.

## 7. Kind and scope on messages

**Decision.** The core speaks the envelope. A node message is (`kind`, `scope`, `records`), exactly the triple `messages.md` section 5 defines; the program adds the protocol tag and type 52791, and `gz_peers_send` splits large ones (host to member only). Receiving, the transport has already checked the envelope, the kind's direction, the record table and reassembled parts (`envelope.h`), and the event gives the same triple. Putting the header in the engine's bytes instead would make the program parse a header the transport has just built, and would let an engine send a kind the transport's checks have not seen.

The placeholder needs a kind that is not a protocol message. **Kind 32767** (`0x7fff`, odd) is reserved for test traffic: scope all zero, records any valid TLV stream, either direction, never split; release builds never send it, and, being odd, a receiver that does not know it ignores it. `envelope.c` knows it only when built with `GZ_TEST_KINDS` (the program's test build and the tests); a release build ignores it like any unknown odd kind. The placeholder's bytes become one odd record, type 1, holding `GZPI` / `GZPO` / `GZPA` and the payload.

**Interface change.** `action.h`:

```c
        /* SEND: one factory message (messages.md sections 3 to 5). `records`
         * is the TLV stream; the program adds the protocol tag, and the
         * transport splits it when it is over 65,495 bytes (host to member
         * only). */
        struct { gz_link_t link; uint16_t kind; uint8_t scope[32]; gz_bytes_t records; } send;
```

`gz_action_list_add` refuses kind 0 and kind 2 (`part`, the transport's own), and records over 1,048,576 bytes.

`event.h`:

```c
        /* MESSAGE_RECEIVED: a whole factory message the transport has
         * checked (envelope.h: header, direction, record table, parts put
         * back together). */
        struct { gz_link_t link; uint16_t kind; uint8_t scope[32]; gz_bytes_t records; } message;
```

`envelope.h` (PR 23): `#define GZ_ENV_KIND_TEST 32767` under `#ifdef GZ_TEST_KINDS`, with its table entry (scope zero, any direction, no required record). `messages.md` 4.1 gets the row (applied here).

**Owner.** core, S7, S11.

**Test T7, `program_envelope`.** Pings travel as kind 32767 through `gz_peers_send` and arrive with kind and scope intact. A raw client (`gz-net`) sends an unknown even kind: the host closes it. An unknown odd kind: ignored, connection kept. A host test reply of 200,000 bytes (`--test-big-reply`) reaches the member whole, as parts, and the member's acknowledgement comes back.

## 8. A restore rewinds the incarnation

**Decision.** The incarnation must never repeat for a data folder, even across a restore: the runner's duty (`runner.h`) and the restore epoch and every nonce input that mixes it in (`ports.h`, `safety-rule.md` R2) rest on it. A restore replaces `journal.gzj` with a copy that carries the old counter. The mark file does not help (a restore starts a new one, and it is sealed under the storage key, which a restore from the words does not have). So the counter's high-water mark gets its own small file, beside the guard and like it:

- **`floor.gzf`**, in the data folder, outside the journal's backup set; a restore never replaces it.
- Sealed under a key from the **seed**, as the guard is (KG's derivation with its own label), so a restore from the words, which makes a new key file, can still read it.
- **Every start** (`journal.md` section 5 step 5): new incarnation N = 1 + max(highest in the journal, the floor, 0 if the file is missing); write `floor.gzf` with N (write `floor.gzf.tmp`, sync, rename, sync the folder); then append and sync the incarnation entry and its mark as today. A crash between the two steps skips a number, which is harmless.
- **A restore** starts the same way, so its first incarnation is above every one used on this device since the backup, whatever the backup holds.
- **Missing file**: on an ordinary start it is written again from the journal (nothing lost: the journal itself holds the highest). On a restore it means another device or a removed file; the journal's own counter is used, and the start says so in the `restored` record (`floor_found` 0). A copy of the whole folder put back by someone who can write it is not defended, as for the guard (storage 6.4).

**Interface change.** `journal.md` (S5):

- section 5, step 5 replaced by: "**Incarnation.** Read the floor file (storage 10.3). New incarnation = 1 + the larger of the highest found in the journal and the floor (0 if the file is missing or damaged). Write the floor file with it, then append the incarnation entry, sync, append a sync mark, sync. Only then may the runner be created. Writing the floor first keeps a restored journal, whose counter is older, from ever reusing a number used on this device since its backup (`runner.h`, restoring a backup)."
- section 8.2, "How a restore is recognised": add "The new incarnation is taken from the floor as at every start (section 5 step 5), so it is above every incarnation this device used since the backup."
- section 9: the `restored` record (`0x00040006`) gains `floor_found` (`u8`).

`storage-encryption.md` (S6), new 10.3:

> ### 10.3 The floor file
>
> `floor.gzf`, beside the guard, outside the journal's backup set: the highest incarnation this device has used for this wallet.
>
> | Offset | Field | Size |
> |---|---|---|
> | 0 | `magic`, ASCII `GZFLOOR1` | 8 |
> | 8 | `format`, 1 | 1 |
> | 9 | `chain` | 32 |
> | 41 | `seal(KF, u64 floor, ad = bytes 0..40)` | 24 + 8 + 16 |
>
> KF is derived from the seed like KG, with the label `gazpacho/floor`, so a restore from the words can read it. Replaced (write `floor.gzf.tmp`, sync, rename, sync the folder) at every start, before the incarnation entry. A file that fails its tag is treated as missing.

and a row in 3.1's file table, 6.3 step 0 unchanged, and a vector E9f.

`program/store.h` (S11): `begin` documents the floor; the stand-in implements it with a plain `floor.standin` (no seal) so the test runs before S5.

**Owner.** S5 (journal text and code), S6 (format, KF, vector), S11 (stand-in, test).

**Test T8, `program_restore_floor`.** A member runs to incarnation 2 and its journal is copied aside (the backup). It is restarted three more times (incarnation 5). The copy is put back as a restore (`--test-restore-from FILE`, which sets the restore marker). The restored start's incarnation is 6, not 3; its first batch is the restore batch; its restore epoch differs from the original's; pings before and after are answered. Variant: `floor.standin` removed before the restore: incarnation 3, and the `restored` record says `floor_found` 0.

## 9. The outcome of a broadcast

**Decision.** A chain event reports each broadcast's outcome, as **advice**: it lets an engine tell the user at once that a server refused a transaction (and why), or retry later when none could be reached. It is never proof and never final: one server's refusal is not another's, an accepted transaction can still be replaced or dropped, and the event is lost with a restart (the worker's generation). What a transaction actually did is learnt only from `WATCH_TX` and `WATCH_OUTPOINT`, which an engine sets for anything whose fate matters. The chain view already computes it (`gz_broadcast_result`), so the cost is one more event kind.

**Interface change.** `event.h`:

```c
    GZ_CHAIN_BROADCAST_RESULT  /* advice about a BROADCAST: accepted, refused or not sent */

/* Outcome of a broadcast (GZ_CHAIN_BROADCAST_RESULT). Advice only: never
 * stored as proof, never final; watches are the only truth (action.h). */
typedef enum {
    GZ_BROADCAST_ACCEPTED = 1,  /* a server took it, or already had it */
    GZ_BROADCAST_REFUSED,       /* every server that answered refused it; `reason` says why */
    GZ_BROADCAST_UNREACHABLE    /* no server answered */
} gz_broadcast_outcome_t;
```

`gz_chain_event_t` gains `gz_broadcast_outcome_t outcome;` and `gz_bytes_t reason;` (printable ASCII, at most 127 bytes, the server's words); `txid` holds the broadcast transaction's txid, computed by the program from the bytes sent. `action.h`, BROADCAST: "Its outcome comes back as a GZ_CHAIN_BROADCAST_RESULT event, which is advice (event.h). Broadcasting a transaction does not watch it."

**Owner.** core, S8 (worker result), S11 (conversion).

**Test T9, `program_broadcast_result`.** The local test server set to accept, then to answer "already known", then to refuse with a reason, then to be down. A test user command broadcasts a transaction each time; the node's notices show accepted, accepted, refused with the server's reason, unreachable. A restart from storage while a broadcast is outstanding: no result reaches the new incarnation.

## 10. `WATCH_SCRIPT`

**Decision.** Retire it. The chain view lists a script's *unspent* outputs, so a spend shows only as an output vanishing, and naming the spender needs every outpoint ever seen; that is the watch loop keeping history per script for an action nobody uses. Slice 1's watches are the funding txid (`WATCH_TX`, C11) and the funding inputs (`WATCH_OUTPOINT`, C4(d) and Dead); every later need found so far is an outpoint the engine already knows (it had to see the output to care about its spend). Receiving to an address of the wallet is the wallet's own scan, not a core watch. A watch on a script can return later as a new action with a meaning the chain view can answer.

**Interface change.** `action.h`: `GZ_ACTION_WATCH_SCRIPT` keeps its value (4) with the comment `/* retired in contract v2: refused */`; the union member `watch_script` goes; `gz_action_list_add` returns `GZ_ERR_ARGUMENT` for it; WATCHES drops its paragraph. `event.h`: `GZ_CHAIN_SCRIPT_SPENT` keeps its value (1) as `/* retired */`, and `script` leaves `gz_chain_event_t`. The runner's unknown-kind check refuses it too.

**Owner.** core, S8 (implements none of it).

**Test T10, `program_watches`** (and the core unit tests for the refusal). The local test server plays: a funding-like transaction unconfirmed, then confirmed, then buried to depth 3; a reorganisation that removes it; an input of it spent in the mempool, then confirmed. A test user command sets `WATCH_TX` (depth 3) and `WATCH_OUTPOINT` (depth 1). The node's notices show confirmations 1, 2, 3, then unconfirmed, then confirmed again; the spend with 0 then 1 confirmation. A restart from storage re-sets both watches at start and reports the current state again.

## 11. What the interface reads

**Decision.** The node offers no reads. A read would be a call into the core outside an event, from code that runs while a list is being carried out, and it would show state that may not be durable. Instead:

- **The view.** The program keeps a table, the view: for each (object kind, id), the latest bytes a `NOTIFY` gave. `NOTIFY` is outward, so the runner releases it only after the saves before it are confirmed: **the view shows only durable state.** The backend reads the view on the loop thread, synchronously, as `api_backend.h` wants.
- **Rebuilt at every start.** New node rule 7: a start emits a `NOTIFY` for every view object the engine has (like timers and watches, rule 4). When the start is complete the program sends the API topic `reset` (`local-api.md` 10.2: "after the core was rebuilt from storage").
- **Framing of `NOTIFY`.** `code` says what the bytes are; bytes are a TLV stream (BOLT 1 rules, `messages.md` 4.2):

| `code` | Meaning | Records |
|---|---|---|
| `0x00010000` + k | A view object of kind k (registry below) | 0 `id`, 1 to 64 bytes of printable ASCII (the local id of `local-api.md` 7.3), required; 2 `gone`, empty, when the object is removed; then the object's fields from type 4, defined with the object |
| `0x00020000` | The outcome of a user command | 0 `request_id` (`u64`), required; 2 `error` (an error code of `local-api.md` 8.1, ASCII), absent on success; 4 `params` (a JSON object, ASCII) |
| `0x00030000` | A line for the log (`storage-encryption.md` 12.1) | 0 `text`, printable ASCII, never a secret |

View object kinds (k), with the API topic each feeds: 1 `status` (no id), 2 `lobby`, 3 `host_lobby`, 4 `factory`, 5 `wallet`, 6 `activity`, 7 `attention`, 8 `doing`, 9 `connection` (`GET /connections`). The fields of each are defined in the pull request of the engine that first emits it, with the mapping to the `local-api.md` answer it fills; the program's backend turns them into JSON and calls `gz_api_notify(topic, id)`.

- **Calls.** A call that only reads is answered from the view. A call that changes anything (`join`, `ready`, `leave`, `host/open`, `host/start`, `host/cancel`, seat removal, conditions, pause, lock) is checked against the view, then submitted as a `GZ_EVENT_USER_COMMAND` and answered **202** with `{"request_id": …}`; its outcome arrives as a command-result `NOTIFY` and the topic it changed. `USER_COMMAND` bytes are a TLV stream: 0 `request_id` (`u64`, required), 2 `command` (`u16`, required, the registry `GZ_CMD_*` in a new `core/gazpacho/include/gazpacho/command.h`, one per call of `api_backend.h`'s `gz_api_call_id` that changes state), then the call's arguments from type 4.
- **The data folder.** The program owns it: it creates it (0700), refuses it if others can read it, and holds `DIR/lock` (program.md section 5). The API server is given that folder and creates or checks nothing; it only places its own files (the redirect file) in it.

**Interface change.** `action.h`, NOTIFY:

```c
        /* NOTIFY: outward. `bytes` is a TLV stream framed by `code`
         * (contract-v2.md section 11): a view object, a command's outcome, or
         * a log line. The program keeps the latest view object per (code, id)
         * and shows nothing else to the interface. */
        struct { uint32_t code; gz_bytes_t bytes; } notify;
```

(the struct is unchanged; the comment is the contract). `event.h`, `user`: comment becomes `/* USER_COMMAND: a TLV stream, command.h */`. New `command.h` with `GZ_NOTIFY_VIEW(k)`, `GZ_NOTIFY_COMMAND_RESULT`, `GZ_NOTIFY_LOG`, the view kinds and `GZ_CMD_*`. `node.h` rule 7:

> 7. Emit, at start, a NOTIFY for every view object it has (contract-v2.md section 11): the program forgets the view when it stops.

`api.h` (PR 26):

```c
    const char *data_dir;      /* required: a folder the program has made, checked
                                  (0700, owned by this user) and locked; the server
                                  creates and checks nothing, and only writes its own
                                  files in it */
```

and `server.c` loses its `mkdir`. `api_backend.h`: the `call` paragraph adds "A call that changes state answers 202 with a request id once it is submitted; its outcome is published later (topic and the command's own)". The "Threads" paragraph is section 4's.

**Owner.** core (`command.h`, rule 7), S9 (folder, 202, thread rule), S11 (view, backend, command mapping); each engine (S4 first) defines its view objects' fields.

**Test T11, `program_view`.** A host with the interface; a client signed in with the test passphrase.
1. A member pings: the event stream shows the `status` topic and `GET /status` shows the new ping count (the placeholder's view object, kind 1).
2. The host is killed after the ping is durable and before the notice is released (`--test-crash-after-save`). Restarted: the stream shows `reset`, and `/status` shows the count including that ping, from the start's notices.
3. A changing call (`POST /pause`, the placeholder's test command) answers 202 with a request id; the command-result notice arrives and the topic changes.
4. The program started on a folder with mode 0755 refuses before the server exists; the server never creates the folder (started on a missing folder by the test harness directly, it refuses).

## 12. The transport's random type

**Decision.** `ports/net` needs randomness for one thing, BOLT 8 ephemeral keys, which are one-time secrets and never leave the transport. It gets its own one-line type and includes no core header, so the core's contract can change without touching the transport, and the transport (with `gz-net`) builds without the core. The program passes a function that reads the operating system at each call (`transport.md` rule 9 and decision 12).

**Interface change.** PR 23, `noise.h`:

```c
/* Randomness for ephemeral keys: `fill` writes `len` unpredictable bytes read
 * from the operating system at the call. Every draw is a one-time secret; the
 * transport never stores, logs or sends it. Cannot fail: a port that cannot
 * read the system's randomness ends the program (transport.md decision 12). */
typedef struct {
    void (*fill)(void *ctx, uint8_t *out, size_t len);
    void *ctx;
} gz_net_random_t;
```

`gz_random_port_t` becomes `gz_net_random_t` in `noise.h`, `conn.h`, `peers.h`, `noise.c`, `conn.c`, `peers.c`, `tools/gz-net`; `#include "gazpacho/ports.h"` leaves `noise.h`. `transport.md`'s "Pieces" row for `noise.c` says "a callback (`gz_net_random_t`)". `tools/check-core-isolation.sh` gains the reverse check: nothing under `ports/net/` includes `gazpacho/` core headers.

PR 23 is based on `main` before PR 9 and calls `fill(ctx, out, len)` (three arguments); `main`'s `noise.c` calls `fill(ctx, GZ_RANDOM_SECRET, out, len)`. Rebasing PR 23 onto `main` with this change resolves both at once.

**Owner.** S7.

**Test T12.** A CTest build check, `net_no_core_headers`: `ports/net` and `gz-net` compile with an include path that has no `core/gazpacho/include`. In `program_two_process`, the transport's randomness is the program's OS function (no seeded path exists in a release build; checked by the symbol list as the core's isolation check does).

## 13. Member keys

**Decision.** Keys under BIP 32, hardened all the way, below a purpose of Gazpacho's own:

| Key | Path |
|---|---|
| Per-lobby key: BOLT 8 static key and contribution key (`messages.md` 2, `signing-round.md` 2) | `m / 254315617' / coin' / 0' / epoch' / index'` |
| Its factory key | the same with `index + 1` (`signing-round.md` section 2: "derived at the next index") |
| The host's long-term key (BOLT 8, terms, host messages) | `m / 254315617' / coin' / 1' / 0'` |

- **254315617** is the first four bytes of `SHA256("gazpacho keys")` (`8f 28 8c 61`) with the top bit cleared: a reproducible random pick, like type 52791, so it collides with no BIP 43 purpose in use. `coin` is BIP 44's: 1 on every test network (`gzw_network_coin_type`), so test keys are never main-network keys.
- `epoch` is the 31-bit restore epoch (`safety-rule.md` R2: "31 bits fit a hardened BIP 32 index"); `index` the 31-bit `key_index`.
- **Hardened everywhere** because these are secret keys used one by one, never an account whose public children anyone needs: a leaked child secret then reveals nothing about its siblings.
- An invalid child (BIP 32's rare case, `GZW_REASON_INVALID_CHILD`) is skipped: the engine takes the next index and saves it, as `wallet-keys.md` says for addresses. For a per-lobby key the next free pair is (`index` + 2, `index` + 3).
- The host key does not change with the restore epoch: members pin it, and a restored host is the same host.

**Interface change.** `wallet/include/wallet_keys.h`:

```c
/* Gazpacho's key purpose: SHA256("gazpacho keys")[0..4] & 0x7fffffff. */
#define GZW_GAZPACHO_PURPOSE 254315617u

/* The per-lobby key at m/254315617'/coin'/0'/epoch'/index' (contract-v2.md
 * section 13): its secret key and 33-byte public key. epoch and index below
 * 2^31. 0 on success; on failure *reason says why, GZW_REASON_INVALID_CHILD
 * meaning "take the next index". The caller wipes seckey32. */
int gzw_lobby_key(const secp256k1_context *ctx, const gzw_xprv *master, gzw_network net,
                  uint32_t epoch, uint32_t index, unsigned char seckey32[32],
                  unsigned char pub33[33], gzw_reason *reason);

/* The host's long-term key at m/254315617'/coin'/1'/0'. As above. */
int gzw_host_key(const secp256k1_context *ctx, const gzw_xprv *master, gzw_network net,
                 unsigned char seckey32[32], unsigned char pub33[33], gzw_reason *reason);
```

Test vectors from the BIP 32 test seed, generated by `tools/spec-vectors.py` and cross-checked against an independent BIP 32 implementation, in `wallet/vectors/`. `messages.md` section 2, "Member key", names the path (applied here, marked **proposed, owner to confirm**).

The program derives the key when it carries out a `CONNECT` (section 3) and wipes it once handed to `gz_peers_connect`; `transport.key` and `wallet-seed.standin` give way to the seed (and to `keys.gzk` once S6 lands).

**Owner.** wallet; S11 (use).

**Test T13, `program_derived_keys`.** A member and a host from known test words. The host's key printed at start equals `gzw_host_key`'s vector, before and after a restart. The member's first link uses (epoch 0, index 0)'s key; restarted, the same; after a restore (T8's harness) the epoch changes and the host sees a new key, which finds no seat (a new link).

## 14. The random port's signature

**Decision.** Settled on `main` (PR 21 merged after PR 9): `fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)` with `GZ_RANDOM_ORDINARY` = 0 and `GZ_RANDOM_SECRET` = 1. `GZ_RANDOM_OTHER` and the `uint32_t` form are gone. Nothing changes in the core. The program drops every core probe (`GZP_CORE_STEPPED_START`, `GZP_CORE_RANDOM_PURPOSE`, `GZP_CORE_RANDOM_ENUM`, `GZP_CORE_PEER_EVENTS`, `GZP_CORE_READER_RESTORED`, `GZP_CORE_WATCH_TX`) and builds against `main` only; `program.md` section 6 becomes one paragraph saying so. With section 12 the transport no longer sees this type at all.

**Interface change.** None in the core. `program/CMakeLists.txt` and the `#if` blocks go.

**Owner.** S11.

**Test T14.** `program_two_process` unchanged and passing on `main` with the probes removed; the build fails if anything still names `GZ_RANDOM_OTHER` (a grep in the CTest build check).

## 15. Networks

**Decision.** Slice 1 runs on signet or testnet4, one per data folder, never mainnet. `init` names exactly that one network. BOLT 1 lets a node list several chains and close on no common one; a Gazpacho program runs one, so it lists one and closes on anything else, including a list with more than one chain. Mainnet stays refused before anything starts (`SLICES.md` rule 3; program exit 2).

**Interface change.** `messages.md` section 2, "First message" (applied here):

> BOLT 1 `init`. `networks` must contain exactly one chain hash, that of the network this party was set up for: signet or testnet4. A party whose peer names another chain, several, or none closes the connection. The chain hash is BOLT 0's: the hash of the network's block 0.

PR 23, `peers.h`: the `chain` comment becomes `/* init's networks: exactly this chain (signet or testnet4) */`; `gz_peers_new` refuses the main network's hash. PR 26: the default interface port per network (39735 is signet's) needs a testnet4 value in `local-api.md` 3.1 (see section 18).

**Owner.** spec (here); S7.

**Test T15, `program_networks`.** A testnet4 host and a testnet4 member connect and ping. A signet member to the testnet4 host: both sides close with `GZ_PEER_WHY_INIT`. `--network mainnet` exits 2 before any file is made (already in `program_options`).

## 16. What every engine now does at start

`node.h`'s list after this contract, for reference: 1 resend unacknowledged, 2 safe twice and out of order, 3 the acknowledgement is the peer's saved message, 4 timers and watches again, 5 the restore batch first, **6 resend on `PEER_CONNECTED`**, **7 the view again**, and the addressing rule of section 2; plus **`CONNECT` and `SET_SEATED` again** for every link and seat it still needs (section 3).

## 17. The pull requests, in order

Each lands on `main` alone and leaves it building and green. Reviews per the ledger.

| PR | Contents | Mismatches | Owner | Depends on |
|---|---|---|---|---|
| **P1** | This note; `messages.md` 2 (networks, member key path), 4.1 (kind 32767), 6.2 and open point 3; `terms.md` chain; `signing-round.md` 12.1 rows | decisions for all; text for 13, 15, 7 | program S11 (author), owner review | — |
| **P2** | PR 23 rebased onto `main`: `gz_net_random_t`, no core header (12); `gz_peers_pollfds`/`dispatch` (4); test kind under `GZ_TEST_KINDS` (7); one network, mainnet refused (15); `transport.md` limits updated (6); test T12 | 4, 6, 7, 12, 15 | S7 | P1 |
| **P3** | PR 27 rebased onto `main` with P2: probes removed (14); `program/net.c` over `peers.h` (6); one loop over the net descriptors (4); placeholder bytes carried in kind 32767 by the adapter until P4; PR 26 not yet wired. Tests T6, T12, T14, T15 and the existing `program_two_process` | 4, 6, 14, 15 | S11 | P2 |
| **P4** | Core contract v2 with the program and the simulator in the same change: `gz_link_t`, `SEND`/`MESSAGE` with kind, scope, records, `CONNECT`/`DISCONNECT`/`SET_SEATED`, `GZ_CHAIN_BROADCAST_RESULT`, `WATCH_SCRIPT` retired, node rules 3, 6, 7, the placeholder's acknowledgement; outbox removed. Tests T1, T2, T3, T7 | 1, 2, 3, 7, 9 (event), 10 | core (S11 for `program/`) | P3 |
| **P5** | PR 26 rebased: `gz_api_server_pollfds`/`dispatch`, data folder given not made, thread rule, 202 for changing calls | 4, 11 (server side) | S9 | P1 |
| **P6** | Program wires the API: the view, `command.h`, the backend over the view, `reset` after start. Test T4, T11 | 4, 11 | S11 (core for `command.h`) | P4, P5 |
| **P7** | Chain worker `chain_watch.h` (S8) and `program/pchain.c` over it. Tests T5, T9, T10 | 5, 9, 10 | S8 (S11 for `program/`) | P4 |
| **P8** | `gzw_lobby_key`, `gzw_host_key`, vectors; the program derives keys for `CONNECT` and the host key; stand-in key files removed. Test T13 | 13 | wallet (S11 for `program/`) | P4; owner's confirmation of the path |
| **P9** | Floor file: `journal.md` 5, 8.2, 9 and `storage-encryption.md` 10.3 text (with PR 25 or after it), the stand-in's `floor.standin`. Test T8 | 8 | S5, S6 (S11 for the stand-in) | P4 (T8 uses the placeholder's restore path), PR 25 for the sealed form |

P2 and P5 can go in parallel after P1; P7 and P8 in parallel after P4. P4 is the only change to the core and the only one that touches open engine branches (PR 15 signing, PR 24 tree): they rebase onto it, and the signing engine's first use of `SEND` uses kinds 64 to 81 directly.

## 18. For the owner

1. **The key path** of section 13 (purpose 254315617, hardened, host key on its own branch). Marked proposed in `messages.md`.
2. **No outbox** (section 1): a message for a peer that is not connected is dropped, and delivery rests on resends at start and at reconnect. This is stricter than the skeleton and matches the specifications; it means an engine bug that forgets a resend shows in tests instead of being hidden by the outbox.
3. **`WATCH_SCRIPT` retired** (section 10), with no Slice 1 user.
4. **A new file in the data folder**, `floor.gzf` (section 8), beside the guard and the mark file, outside the backup set. S6's PR 25 is open on the same specification.
5. **Kind 32767** reserved in the protocol for test traffic (section 7), in the namespace that will be shared with SuperScalar (`PROTOCOL.md`).
6. **The interface port for testnet4**: `local-api.md` 3.1 gives 39735 for signet only.
7. `program.md` section 6 says PR 21 is not merged; it is. P3 updates the note.
