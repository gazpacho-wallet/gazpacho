# Contract v2: the fifteen mismatches resolved

Draft 2, 2026-11-12. Draft 1 answered section 7 of `docs/notes/program.md` (PR 27, the program skeleton; that note reaches `main` with P3), which found fifteen places where the merged and open pieces do not fit. Draft 2 answers the review of PR 28 (`notes/review-pr28.md`, findings 1.1 to 5); section 19 lists what changed. Each section below gives the decision, why, the exact interface change (header and specification text), the piece that owns it, and the multi-process test in `tests/program/` that proves it. Section 17 orders the work into small pull requests that each land without breaking `main`.

Read against: `core/gazpacho/include/gazpacho/*.h` on `main` (PR 9 and PR 21 merged), `ports/net/` on `main` and on `transport-lobby` (PR 23), `ports/api/` on `api-server` (PR 26), `ports/chain/` on `main`, `core/signing/` on `signing-core` (PR 15), and `spec/messages.md`, `transport.md`, `local-api.md`, `journal.md`, `storage-encryption.md`, `safety-rule.md`, `exit.md`, `signing-round.md` 12.1.

Owners, as in the stream list: **core** (`core/gazpacho`), **S2** signing, **S4** lobby engine, **S5** journal, **S6** storage encryption, **S7** transport (PR 23), **S8** chain watch loop, **S9** local API (PR 26), **S11** program (PR 27), **wallet** (`wallet/`).

Spec text applied in this pull request: `messages.md` sections 2, 4.1, 6.2, test 18 and open point 3; `terms.md`'s `chain` term and check 4 (signet or testnet4, as item 15 needs); `signing-round.md` 12.1. Everything else here is the text the owning pull request applies, so that no open branch is edited behind its owner's back (S5 and S6 in particular: PR 25 is open on `storage-encryption.md`).

## 0. The decisions in one table

| # | Mismatch | Decision | Owner | PR (section 17) |
|---|---|---|---|---|
| 1 | "Released" treated as "sent" | Release is hand-over, not delivery; only the peer's own saved message is an acknowledgement. No outbox. **A send the transport refuses on a live connection closes the connection**, so every loss coincides with a reconnect; too-big is fatal for the incarnation. Peer events are queued during a start; the host listens only after it; a restart from storage closes every connection | core, S7, S11 | P2, P3, P4 |
| 2 | Three shapes of peer identity | A peer is named by the **link**: (our 33-byte static key, its 33-byte static key), `gz_link_t`. One live connection per link; **the transport** replaces an older connection from the same proven key before admission, and the program reports the older one's loss | core, S7, S11 | P2, P4 |
| 3 | No action to connect, disconnect, choose a key, mark a seat | `CONNECT` (outward: waits for the save of the key's index pair), `DISCONNECT` (**flushes, then closes, with an event**), `SET_SEATED` (a property of the remote key, applied at admission). Re-issued at every start. At `PEER_CONNECTED` an engine **carries out the protocol's reconnect step** (`messages.md` 6: the member asks, the host answers), with limits kept per link | core, S4, S7, S11 | P2, P4 |
| 4 | One poll loop, ports that block in their own | Every port that waits exposes descriptors and a deadline and is stepped after the one `poll()`. The passphrase thread only derives; every file write is on the loop thread; jobs carry a generation | S7, S9, S8, S11 | P2, P3, P5, P6, P7 |
| 5 | Chain calls block the loop up to 45 s | One chain worker thread (`gz_chainw`) with queues and a wake descriptor; it **never drops a watch report** (blocks when the result queue is full, coalesces tips); interruptible shutdown; libcurl set up and torn down on the loop thread | S8, S11 | P7 |
| 6 | The merged transport blocks | The program uses only `ports/net/peers.h`. `conn.h` stays for `gz-net` and tests | S7, S11 | P2, P3 |
| 7 | `SEND` has no kind or scope | `SEND` and `MESSAGE_RECEIVED` carry `kind`, `scope`, `records`; the transport splits. Kind **32767** reserved for test builds | core, S7, S11 | P2, P4 |
| 8 | A restore rewinds the incarnation | A **start counter** file, `starts.gzs`, outside the journal's backup set, sealed under a key from the seed, created at set-up. Every start takes 1 + max(journal, counter) and writes it first. It covers **a restore of the journal alone**, not a snapshot of the whole folder or machine | S5, S6, S11 | stand-in P3, sealed P9 |
| 9 | No broadcast-outcome event | `GZ_CHAIN_BROADCAST_RESULT`, aggregate and **advisory only**; per-server results (`exit.md` 3.2, 10.5) deferred | core, S8 | P4, P7 |
| 10 | `WATCH_SCRIPT` fits the chain view poorly | **Retired**; the number stays reserved | core, S8 | P4 |
| 11 | The API reads state the core does not offer; the server makes the data folder | No reads on the node; a program-held **view** fed by `NOTIFY`s that follow their saves, re-emitted at start. Acting calls follow `local-api.md` 7.4/7.5: **client-chosen `request_id`** saved in the action's first batch, the HTTP answer **held until the command-result `NOTIFY`**. The server is given a checked, locked folder | core, S9, S11 | P5, P6 |
| 12 | Transport depends on the core's random port type | `gz_net_random_t` in `ports/net`; no core header there | S7 | P2 |
| 13 | No member key derivation | `m / 254315617' / net' / 0' / epoch' / index'`, allocated **in pairs** (contribution key at `index`, factory key at `index + 1`); host key at `m / 254315617' / net' / 1' / k'`; a network level so one seed is unlinkable across signet and testnet4; every invalid-child case defined. **Proposed, owner to confirm** | wallet, S11 | P8 |
| 14 | Two random port signatures | Settled on `main` (PR 21's enum). The program drops its probes | S11 | P3 |
| 15 | `init` names signet only | One chain hash, **signet or testnet4**. Applied in `messages.md` 2 | spec (here), S7 | P1, P2 |

## 1. "Released" is not "sent"

**Decision.** A runner release means the program has the action, nothing more. A released send can be lost: the peer is not connected, the connection drops with bytes queued, the program stops. Four rules make every loss repairable:

- **Node rule 3 (amended).** The acknowledgement that stops a resend is always a message from the peer, received and saved. Never the runner's release, never a storage confirmation of one's own batch.
- **No outbox.** A `SEND` for a link with no live connection is dropped and counted (`dropped_unconnected`). Keeping it in memory gave a delivery that a stop silently undid.
- **A loss on a live connection closes it** (transport requirement for P2, carried out by the adapter in P3). `messages.md` section 2 rests every duplicate and loss argument on "BOLT 8 delivers messages in order and without loss while a connection lasts". So the program never lets a connection last past a loss: any refusal by `gz_peers_send` on a live connection closes that connection and the adapter delivers `PEER_DISCONNECTED`. A lost message then always coincides with a reconnect, and the reconnect step (section 3) repairs it. Per refusal:
  - `GZ_PEERS_ERR_FULL` (queue over `max_queue`): close. `max_queue` must hold at least twice the largest set a host answers one reconnect with (`messages.md` 6 and 7.10: `terms_offer`, `lobby_status`, `start`, `round_propose` under 400 KB, `round_all_nonces` about 260 KB, `round_tier_result`, `round_complete`): the default 4 MiB covers Slice 1 at 1,000 members, and P2's tests show it. Otherwise close-on-full would loop.
  - `GZ_PEERS_ERR_TOO_BIG`: an engine bug (a member message over 65,495 bytes, or anything over 1 MiB). **Fatal for the incarnation**, like a refused list, not "dropped and counted". The core cannot check it, because it does not know which side it is.
  - `GZ_PEERS_ERR_NOT_READY` cannot happen for a link the core knows (the adapter delivers `PEER_CONNECTED` only after the transport's `CONNECTED`); if it does, it is treated as not connected.
  - `GZ_PEERS_ERR_NO_CONN` (closed meanwhile): not connected; the `PEER_DISCONNECTED` is on its way.
- **Starts and restarts** (program requirement, P3):
  - **Peer events are queued during a start.** `node.h` lets a starting node receive only its storage confirmations. The program holds every peer event that arrives meanwhile, in order (connections and disconnections coalesced per link to the last state; messages kept, at most 1 MiB per link, past which that connection is closed), and delivers them once a start call has set `*more` to 0.
  - **The host listens only after its start is complete**, and a member's connections exist only after its start has issued `CONNECT`, so in the normal case nothing is queued at all.
  - **A restart from storage inside one process closes every connection** (`gzp_net_drop_all`), clears the timer table (the old incarnation's timers never fire into the new node) and resets the chain worker's generation (section 5). The new node's start issues `CONNECT` again; the members of a host reconnect by themselves. Resends then happen on the following `PEER_CONNECTED`, through the reconnect step.

Timer-driven resends stay allowed and are a good second line: PR 15's signing engine resends on ticks (`resend_ticks`). Rule 6 (section 3) is the floor, not the only path.

**Interface change.** `node.h`, "What every engine's start step must do", rule 3 becomes:

> 3. Store, as records, the acknowledgements that matter. Anything not in storage is not known after a restart, and will be sent again. **An acknowledgement is a message from the peer, saved when it arrives.** That the runner released a send, or that storage confirmed the batch it followed, says only that the program has the message: the program drops a send to a peer that is not connected, and a stop loses whatever it had not written to a socket. The program never lets a connection outlive a lost message (contract-v2.md section 1), so every loss is followed by a PEER_DISCONNECTED and, when the peer is back, a PEER_CONNECTED. No engine may save "sent" for anything it must deliver.

"What the placeholder guarantees" becomes:

> At least once, to a peer that comes back. If the record of a ping is durable, the reply reaches that link at least once, provided the node goes on running or is started again and the peer connects again with the same keys. The placeholder follows the pull model of rule 6: at PEER_CONNECTED the member sends a hello (`GZPH`); the host answers a hello, at most once a second per link, with every reply on that link that has no stored acknowledgement, oldest first; the member answers each reply with an acknowledgement (`GZPA` and the serial), which the host saves as a GZ_RECORD_TEST_PING_ACKED record.

`GZ_RECORD_TEST_PING_SENT` (0x7e570002) is withdrawn and `GZ_RECORD_TEST_PING_ACKED` (0x7e570004: one or more 8-byte big-endian serials) replaces it. The start no longer saves anything but the restore batch, so its `GZ_WAITING` path for "sent" records goes; `GZ_WAITING` itself stays in the contract for engines.

`program/net.h`: the outbox goes; `gzp_net_send` returns 0 (handed to the transport), 1 (dropped: not connected) or -1 (too big: fatal); a full queue closes the connection.

**Owner.** core (node.h text, node.c placeholder, simulator), S7 (`max_queue` sizing and its test), S11 (adapter, start queue, restart).

**Test T1, `program_resend_on_connect`.** A host and one member.
1. The member sends ping 1 and exits at once (`--test-exit-after-send`); the host saves the ping, its reply is released and dropped (output line `send dropped: not connected`).
2. The host is killed (SIGKILL) and restarted. The member is started again; at `PEER_CONNECTED` it sends `GZPH`; the host answers with reply 1; the member acknowledges; the host saves `PING_ACKED 1`.
3. The host is restarted once more: after the member's hello it sends no reply (the acknowledgement is stored).
4. The same with only the member restarted.
5. **During a start**: the host is started with a start slowed to 2 s (`--test-start-delay-ms 2000`) while the member reconnects in a loop: the host's first `PEER_CONNECTED` reaches the node after the start (output order), and reply 1 still arrives.
6. **Restart in one process**: the host's storage fails once (`--test-fail-storage-at`); the host closes every connection, starts incarnation n + 1, the member reconnects and the unacknowledged reply arrives.
7. **Full queue**: a host with `max_queue` set to 64 KiB and a test reply of 200 KB: the connection closes, the member reconnects, and after `max_queue` is restored the reply arrives.

## 2. Peer identity

**Decision.** The core names a peer by the **link**, the pair of static keys of a connection:

- the remote key proves who the peer is (BOLT 8; `transport.md` rule 13);
- the local key is needed as well, because a member may hold two connections to one host with different keys of its own: one for a lobby where it has a seat, one fresh to read the host's listings (`messages.md` section 2).

Both keys are derived from the seed (section 13), so a link is the same after a restart of either side, and an engine's stored resends find it again. No 64-bit hash: a 33-byte key is what the specifications, the transport and the signatures use, it cannot collide, and no table is needed. PR 23's connection number stays inside the program's net adapter.

**One live connection per link, decided in the transport.** On the host side every accepted connection has the same local key, so a link is the remote key. PR 23 decides eviction and `GZ_PEER_WHY_FULL` before the program sees a newcomer, so the replacement must be decided there too: once a handshake proves a node id that an established accepted connection already has, `peers.c` closes the older connection (a `CLOSED` event, new `GZ_PEER_WHY_REPLACED`) **before** the admission checks, so a seated member whose old connection is half-open is never refused `FULL` while it waits for the pong timeout. The program turns that `CLOSED` into `PEER_DISCONNECTED` for the old connection, then gives `PEER_CONNECTED` for the new. On the member side the program makes every outbound connection itself and keeps at most one per `CONNECT`.

Only the key's holder can replace its own connection: Noise XK proves the initiator's static key in act three, bound to the responder's ephemeral key, so no replay; the member pins the host. Two copies of one wallet will replace each other in a loop: the transport counts replacements per key (`gz_peers_stats_t.replaced`) and the program shows a key replaced more than 10 times in 10 minutes as an attention item ("two copies of this wallet may be running", `safety-rule.md` section 10).

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

Every `uint64_t peer_id` in `action.h` and `event.h` becomes `gz_link_t link` (sections 3 and 7 give the structs). The placeholder's ping record carries the link: clock (8), link (66), serial (8), payload; `GZ_PING_RECORD_HEADER` becomes 82.

PR 23, `peers.h`: `GZ_PEER_WHY_REPLACED` ("a newer connection proved the same key"), the replacement rule above in the header comment, and `replaced` in `gz_peers_stats_t`.

**Rule for engines** (added to `node.h`): *An engine addresses what it resends after a restart to a link it has stored: a member to (its seat's key, the host's key), a host to (its key, the seat's contribution key). Never to a connection, and never to a key it has not stored.*

**Owner.** core (types, events, actions, placeholder), S7 (replacement before admission), S11 (adapter).

**Test T2, `program_links`** (P4; step 3 in P8). A host and two members, A and B.
1. A pings; the host is killed after the ping is durable and before the reply leaves (`--test-crash-after-save`); restarted, it answers A's hello on A's link; B never receives A's reply.
2. A connects a second time with the same keys while the first connection is open, with the host's every slot seated: the host's output shows `disconnected` (replaced) for the old connection then `connected` for the new, no `FULL` refusal, and exactly one reply per ping reaches A.
3. (P8, once keys are derived) A opens a second connection with a fresh index pair to the same host: the host sees two links; a reply addressed to one never arrives on the other.

## 3. Connect, disconnect, seats, and the reconnect step

**Decision.** These are engine decisions, so they are actions:

- **`CONNECT`**: keep a connection to `host` at `address`, using our key (`key_epoch`, `key_index`). It is **outward**: it reveals our key, so it waits for every save before it. That enforces `messages.md` section 2's "saved (with the guard) before the handshake": the engine puts the `key_index` and `guard` save first, then `CONNECT`, and the runner holds the handshake until the save is confirmed. The program derives the secret key (section 13), connects, and reconnects with backoff (1 s doubling to 60 s) while the action stands, **always with the same key**: a fresh index is allocated per `CONNECT`, not per TCP connection. A second `CONNECT` with the same host and key replaces the address.
- **`DISCONNECT`**: stop keeping `link`, **send what is already queued on it, then close** (within the send limit, 10 s), and deliver `PEER_DISCONNECTED`. A `DISCONNECT` listed after a final `SEND` (a `leave`, a `round_abort`) therefore never loses it. PR 23 adds `gz_peers_close_after_send` for this (like `gz_peers_refuse` without the warning); `gz_peers_close` (drop everything, no event) is used only for a restart from storage and at shutdown, where the adapter reports nothing to a node that no longer exists. Not outward, but ordered: `runner.h` rule 3 keeps it behind a send listed before it.
- **`SET_SEATED`**: the host marks the member's key as holding a seat, or no longer. A seat belongs to a **key**, not to a connection: `SET_SEATED` is re-issued at start, before any member has reconnected, and must survive a replacement (section 2) with no moment in which the seat is evictable. PR 23 keeps a set of seated keys and applies it at admission: `gz_peers_set_seated_key(p, node_id, seated)` replaces `gz_peers_set_seated(p, conn, seated)`.

Like timers and watches, connections and seats are not kept across a restart: at start an engine issues `CONNECT` again for every link it needs and `SET_SEATED` again for every seat. **A saved pause is applied before any `CONNECT`** (`local-api.md` 4.7 step 7: "before the node connects to any host"): with connecting an engine action, this is the engine's duty at start. The host's **listening** stays program configuration (`--listen`), opened after the start (section 1); which members to accept stays `transport.md` rule 13.

**Node rule 6: the reconnect step.** At `GZ_EVENT_PEER_CONNECTED` for a link an engine carries out **the protocol's reconnect step** for that link. It does not push everything unacknowledged: most host messages have no acknowledgement (`terms_offer`, `lobby_status`, `start`, `round_tier_result`, `round_complete`) and `messages.md` 6 makes them **pull**. BOLT 2's `channel_reestablish` is likewise a negotiated resend. For the Slice 1 engines:

| Side | At `PEER_CONNECTED` | Resends, and why |
|---|---|---|
| Member | Sends `hello` with the lobby's scope (scope zero on a browsing connection); if it has sent partial signatures and lacks the result, its saved `round_partial_sigs` bytes; then `round_status_request` for an unresolved round (`messages.md` 6, 7.10) | Its own saved state messages (`join`, `ready`, `unready`, `leave`) only when the host's `lobby_status` shows a seat state other than the saved one: lobby messages state a state, so one resend makes them agree and the next status shows no difference |
| Host | Nothing until the member speaks | Answers `hello` with `terms_offer`, `lobby_status` and, while Signing and the seat was chosen, its saved signed `start`; answers `round_status_request` with its saved `round_tier_result` / `round_complete`. It never pushes a resend on connect |

**Why nothing loops.** The host only answers; the member asks once per connection; the member's reconnects back off (1 s doubling to 60 s); a state resend happens only on a mismatch, and the host's answer to it removes the mismatch. **The limits of `messages.md` 6.1 and 7.10 are kept per link, not per connection** (one `hello` answer a second, one status answer per round per 10 s, 20 ignored `hello`s): a member that reconnects in a loop cannot reset them. They live in the engine's memory (a restart of the host resets them, and a restart costs far more than a reconnect).

**Interface change.** `action.h`, enum (appended, so existing numbers do not move):

```c
    GZ_ACTION_CONNECT,       /* keep a connection to a host, with one of our keys */
    GZ_ACTION_DISCONNECT,    /* flush, close a link and stop keeping it */
    GZ_ACTION_SET_SEATED     /* host: a member's key holds a seat, or no longer does */
```

union members:

```c
        /* CONNECT: outward. `address` is "host:port", numeric (transport.md:
         * no name lookup), at most 64 bytes. Our key is the per-lobby key
         * (key_epoch, key_index) of contract-v2.md section 13; the program
         * reconnects with that same key while the action stands. */
        struct { gz_node_id_t host; gz_bytes_t address; uint32_t key_epoch; uint32_t key_index; } connect;
        /* DISCONNECT: what is queued on the link is sent, then it is closed;
         * a PEER_DISCONNECTED follows. */
        struct { gz_link_t link; } disconnect;
        /* SET_SEATED: a property of the member's key, kept by the transport
         * across its connections; set again at every start. */
        struct { gz_node_id_t member; int seated; } set_seated;
```

`gz_action_is_outward`: send, broadcast, notify **and connect**. `gz_action_list_add` refuses an empty or over-long address, or `seated` other than 0 or 1.

A paragraph after WATCHES:

> CONNECTIONS. A CONNECT stands until a DISCONNECT for its link or the end of the node's program; the program reconnects with the same key while it stands. Connections and seats are not kept across a restart: at start a node applies a saved pause, then issues CONNECT for every link it needs and SET_SEATED for every seat. CONNECT is outward because the handshake shows our key: the save of the key's index pair (messages.md section 2) must come before it in the list, and the runner holds the handshake until that save is confirmed.

`event.h`, peer events:

```c
        /* PEER_CONNECTED, PEER_DISCONNECTED. `outbound`: 1 if we connected
         * (then key_epoch and key_index name our key, as in the CONNECT);
         * 0 if we accepted. */
        struct { gz_link_t link; int outbound; uint32_t key_epoch; uint32_t key_index; } peer;
```

`node.h` rule 6:

> 6. At GZ_EVENT_PEER_CONNECTED for a link, carry out the protocol's reconnect step for that link (messages.md section 6: the member asks with `hello`, resends its saved partial signatures and asks for the round's status; the host answers and pushes nothing). Keep the protocol's rate limits per link, not per connection. Resend a stored state message only when the peer's answer shows it lacks that state.

**Placeholder.** The member's target is given by a test `USER_COMMAND` ("connect KEY@ADDR:PORT", saved with a key index pair) and re-issued as `CONNECT` at every start; `--connect` submits that command at the first start. The host issues `SET_SEATED` for a member's key at its first ping.

**Owner.** core (actions, rule 6), S4 (the lobby engine is the first real user), S7 (`gz_peers_close_after_send`, seated keys), S11.

**Test T3, `program_connect_actions`** (P8: it needs keys derived from (epoch, index); P4 has only the stand-in key file).
1. A member is killed after its `key_index` batch is handed to storage and before it is confirmed (`--test-crash-before-confirm`), several times. The host's log of keys seen is a subset of the key pairs whose index is durable in the member's journal (`gazpacho --test-dump-journal`): no handshake ever used an unsaved key.
2. The member restarted reconnects with the same key; the host sees the same link.
3. A test command sends a final message then `DISCONNECT`: the host receives the message, then sees the connection close; it is not made again until a new `CONNECT`.
4. The host run with `max_conns` 2: one seated member and two unseated newcomers; the seated one is never evicted, an unseated one is; the seated member reconnecting while its old connection is half-open is admitted at once (replacement, section 2).
5. A member reconnecting in a loop every 100 ms for 10 s gets at most one `hello` answer a second in total, counted across its connections.

## 4. One poll loop

**Decision.** One thread runs the loop; every port that waits gives the loop its descriptors and its next deadline, and is stepped after the loop's `poll()`. No port blocks inside a call the loop makes. The loop's timeout is the earliest of the ports' deadlines and the node's timers; a stop request (SIGTERM, SIGINT) is seen through a **self-pipe** written by the signal handler, so no fixed ceiling is needed. Two threads remain, both outside the node, and neither touches the node, the runner, storage, the view or any file:

- the API server's **passphrase thread** (Argon2id takes about a second by design, `storage-encryption.md` 4.2), which wakes the loop through its `done_pipe`, one of the server's descriptors;
- the **chain worker** (section 5).

**The passphrase thread only derives.** `passphrase_op` turns a passphrase (and words) into keys or a result. Everything that writes, including the key file, the guard, the start counter, the mark file and the first journal of `CREATE`, `RESTORE` and `START_AS_RESTORE`, moves to `passphrase_done` on the loop thread. Every job carries the **generation** the server had when it was queued; a lock, a stop or a restart of the node increments it, and a job that finishes under an older generation is wiped and discarded with "not checked" (503) rather than installed.

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

`gz_peers_poll(p, 0, ev)` is guaranteed not to block; its blocking form stays for `gz-net` and the tests.

PR 26, `api.h`:

```c
/* As gz_peers_pollfds: the listeners, the connections, the wake pipe and the
 * derivation thread's done pipe; *timeout_ms the next head, body, idle,
 * keep-alive, merge or held-answer deadline. */
size_t gz_api_server_max_fds(const gz_api_server *srv);
size_t gz_api_server_pollfds(gz_api_server *srv, struct pollfd *fds, size_t cap, int *timeout_ms);
/* After poll(): serve what is ready, finish passphrase jobs of the current
 * generation, send merged events. Never blocks. Loop thread only. */
int gz_api_server_dispatch(gz_api_server *srv, const struct pollfd *fds, size_t n);
/* A lock, a stop or a restart of the node: jobs queued or running before this
 * are discarded when they finish. Loop thread only. */
void gz_api_server_new_generation(gz_api_server *srv);
```

`api_backend.h`, the "Threads" paragraph becomes:

> Threads. passphrase_op runs on the server's derivation thread, at most one at a time, and only derives: it turns the passphrase (and words) into keys or a result, writes no file and touches nothing the loop thread uses (the node, the runner, storage, the view). passphrase_done, on the loop thread, installs what it produced: it writes the key file, guard, start counter and first journal for create, restore and start-as-restore, opens storage and starts the node. A job queued before gz_api_server_new_generation is discarded when it finishes, its secrets wiped. Every other entry runs on the loop thread.

S8, `gz_chainw_fd` (section 5).

**The loop** (`program/executor.c`), per turn: collect descriptors from `gzp_net` (over `gz_peers`), the API server, the chain worker and the stop pipe; `poll()` until the earliest deadline; dispatch each; drain `gz_peers_poll(p, 0, …)`, chain results and due timers, each becoming one event (or queued during a start, section 1).

**Shutdown order** (P3, extended in P5 to P7): stop the API listeners and refuse new requests; stop the node (held actions die with the runner, which is safe: none was given to the executor); join the derivation thread (its job discarded); stop and join the chain worker; close every connection without events; close storage; release the folder lock.

**Owner.** S7 (PR 23), S9 (PR 26), S8, S11.

**Test T4, `program_one_loop`** (P6). A host with the interface on and two members pinging every 100 ms, shortened keep-alive (ping 1 s, pong 2 s).
1. While a client signs in five times in a row (a real Argon2id derivation on the thread, with the test passphrase from the test fixture), every pong arrives within 300 ms of its ping and no connection closes.
2. An event-stream client stays open throughout and receives each `status` change.
3. Idle for 5 s, the host's CPU time (from `/proc/<pid>/stat`) stays under 100 ms: no busy loop.
4. A lock during a sign-in: the job's result is discarded (503), nothing is installed.
5. SIGTERM: the program exits 0 within 2 s, in the order above (output lines).

## 5. The chain view off the loop

**Decision.** `ports/chain` stays blocking: its timeouts, retries and server comparison are right where they are. S8's watch loop runs it on **one worker thread**, behind queues. The loop submits requests without blocking and takes results when the worker's descriptor is readable.

- **Generation.** Every result carries the generation of the last `gz_chainw_reset`. `gz_chainw_take` drops results of an older generation, under the same mutex as `reset`; `reset` also purges every queued request and result and drains the wake descriptor, so the loop does not spin on a stale wake-up (T4). A restart from storage calls `gz_chainw_reset`; the new node sets its watches again.
- **Never drop a watch report.** Watches report only on a change (`action.h`: a count from 1 to `depth`, a spend first seen), so a lost `TX_CONFIRMED` or `OUTPOINT_SPENT` is never repeated and an engine would miss a burial or a spend. When the result queue is full the worker **waits** for room (on a condition variable the loop signals from `gz_chainw_take`); it checks nothing meanwhile, which only delays reports. Tip results are **coalesced**: a tip waiting in the queue is replaced by a newer one, and `GZ_CHAINW_SOURCES` likewise. A full request queue is fatal for the incarnation, as a full timer table is.
- **Shutdown.** `gz_chainw_free` sets an abort flag and wakes the worker; the HTTP layer checks the flag in libcurl's progress callback (`CURLOPT_XFERINFOFUNCTION`, aborting the transfer), and the retry backoff in `http_curl.c` sleeps on a condition variable with a deadline instead of `nanosleep`, so the worker stops within about 100 ms instead of a request's timeouts plus backoff.
- **libcurl's global state.** `gz_http_curl_create` calls `curl_global_init` and destroy calls `curl_global_cleanup`, which are not thread-safe in older libcurl. The loop thread creates the `gz_chain` before any thread starts and destroys it after joining the worker; the worker only uses it. (`CURLOPT_NOSIGNAL` is already set.)
- **Broadcast results are aggregate in Slice 1.** `exit.md` 3.2 asks for per-server results (accepted, already known, refused with reason) and 10.5 for per-server tips and broadcasts. The worker gives one result per broadcast (section 9) and keeps the comparing backend's per-server report (`gz_multi_last_report`) in the result for the program's log; the per-server form for engines is deferred to the exit engine.

**Interface change.** New header `ports/chain/include/gazpacho/chain_watch.h` (S8). It includes no core header (the program converts):

```c
typedef struct gz_chainw gz_chainw;

typedef struct gz_chainw_config {
  gz_chain *chain;              /* created by the loop thread before this call, used only by
                                   the worker, destroyed by the loop thread after gz_chainw_free */
  uint32_t tip_poll_ms;         /* 60,000 */
  size_t max_requests;          /* queued, not yet taken by the worker (1,024) */
  size_t max_results;           /* waiting for the loop (4,096); when full the worker waits */
} gz_chainw_config;

/* Starts the worker. NULL on failure. */
gz_chainw *gz_chainw_new(const gz_chainw_config *cfg);
/* Readable while results wait. */
int gz_chainw_fd(const gz_chainw *w);
/* Forget every watch, queued request and queued result, drain the wake
 * descriptor; results of earlier generations are dropped. Returns the new
 * generation. */
uint64_t gz_chainw_reset(gz_chainw *w);
/* Never block. 0 queued; -1 the request queue is full (fatal for the
 * incarnation). txids in hashing order. */
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
  gz_broadcast_result broadcast;/* GZ_CHAINW_BROADCAST: the aggregate */
  gz_chain_result sources;      /* GZ_CHAINW_SOURCES: agree, lag, disagree, unreachable */
} gz_chainw_result;

/* 1 and *out (a result of the current generation), or 0 when nothing waits.
 * Never blocks; makes room for a waiting worker. */
int gz_chainw_take(gz_chainw *w, gz_chainw_result *out);
/* Aborts the transfer in progress, stops and joins the worker, frees. Does
 * not destroy the chain. */
void gz_chainw_free(gz_chainw *w);
```

The worker answers `WATCH_TX` and `WATCH_OUTPOINT` exactly as `action.h` WATCHES says (`gz_chain_tx_status`, `gz_chain_outspend`, and the tip to count confirmations and see reorganisations). `GZ_CHAINW_SOURCES` feeds the API's chain state (`local-api.md` 11.2) and never reaches the node. `ports/chain/http_curl.c` gains the abort flag and the interruptible backoff. `program/pchain.c` becomes the converter.

**Owner.** S8 (worker, header, HTTP changes), S11 (adapter).

**Test T5, `program_chain_stall`** (P7). The local test server (`ports/chain/tests/local_server.py`) made to answer every request after 20 s. A host and a member with the shortened keep-alive of T4 and a 500 ms test timer. Over 40 s: no connection closes, every ping is answered within 300 ms, the timer fires every 500 ms within 50 ms. Then the server answers again: the tip arrives as `GZ_CHAIN_NEW_TIP`. A restart from storage in the middle delivers no chain result of the old generation. SIGTERM while a request is outstanding: the program exits within 2 s. With `max_results` 2 and ten watches confirmed in one block, all ten reports arrive.

## 6. The merged transport blocks

**Decision.** The program carries out network actions only through `ports/net/peers.h` (PR 23), whose handshakes and messages are stepped without blocking, and through section 4's descriptors. `ports/net/conn.h` keeps its blocking calls for `gz-net` and the transport's tests; nothing in `program/` includes it. `transport.md`'s "Limits of this cut" (the open choice between a stepped handshake and connection threads) is closed by PR 23: stepped, one `poll`.

**Interface change.** None beyond section 4. `program/net.c` is rewritten over `gz_peers_*`. PR 23 updates `transport.md` "Limits of this cut" to say the first limit is gone for `peers.h`.

**Owner.** S7, S11.

**Test T6, `program_slow_peers`** (P3). Against a host: one TCP client that connects and sends nothing, one that sends act one a byte per second, one that completes the handshake and never sends `init`. A real member connecting meanwhile is connected within 1 s and gets every pong; each slow client is closed at its deadline (`GZ_PEER_WHY_TIMEOUT_HANDSHAKE`), seen in the host's output.

## 7. Kind and scope on messages

**Decision.** The core speaks the envelope. A node message is (`kind`, `scope`, `records`), exactly the triple `messages.md` section 5 defines; the program adds the protocol tag and type 52791, and `gz_peers_send` splits large ones (host to member only). Receiving, the transport has already checked the envelope, the kind's direction, the record table and reassembled parts (`envelope.h`), and the event gives the same triple. An engine that signs a message computes `msg_hash` over `protocol || kind || scope || records` (`messages.md` 4.3), so it uses the protocol bytes `67 7a 66 01` itself even though the program writes them on the wire.

The placeholder needs a kind that is not a protocol message. **Kind 32767** (`0x7fff`, odd) is reserved for test traffic: scope all zero, records any valid TLV stream, either direction, never split; release builds never send it, and, being odd, a receiver that does not know it ignores it. `envelope.c` knows it only when built with `GZ_TEST_KINDS`; a release build ignores it like any unknown odd kind. The placeholder's bytes become one odd record, type 1, holding `GZPI` / `GZPO` / `GZPA` / `GZPH` and the payload.

**Interface change.** `action.h`:

```c
        /* SEND: one factory message (messages.md sections 3 to 5). `records`
         * is the TLV stream; the program adds the protocol tag, and the
         * transport splits it when it is over 65,495 bytes (host to member
         * only; a member message over 65,495 bytes is fatal for the
         * incarnation, contract-v2.md section 1). */
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

**Test T7, `program_envelope`** (P4). Pings travel as kind 32767 through `gz_peers_send` and arrive with kind and scope intact. A raw client (`gz-net`) sends an unknown even kind: the host closes it. An unknown odd kind: ignored, connection kept. A host test reply of 200,000 bytes (`--test-big-reply`) reaches the member whole, as parts, and the member's acknowledgement comes back. A member test message of 70,000 bytes: the member's incarnation ends (fatal), as section 1 says.

## 8. A restore rewinds the incarnation

**Decision.** The incarnation must never repeat for a data folder: the runner's duty (`runner.h`) and the restore epoch and every nonce input that mixes it in (`ports.h`, `safety-rule.md` R2) rest on it. A restore replaces `journal.gzj` with a copy that carries the old counter. The mark file does not help (a restore starts a new one, and it is sealed under the storage key, which a restore from the words does not have). So the counter's high-water mark gets its own small file, beside the guard and like it:

- **`starts.gzs`, the start counter** (not "floor": storage 4.1 already uses that word for the passphrase and Argon2id floors), in the data folder, outside the journal's backup set; a restore never replaces it.
- **Created at set-up**, before the journal, like the guard and the mark file (storage 7.4), so a missing file always means something was removed.
- Sealed under a key from the **seed**, as the guard is, so a restore from the words, which makes a new key file, can still read it. In storage 4.4's table: **KC**, IKM seed, label `start counter`, context chain.
- **Every start** (`journal.md` section 5 step 5): new incarnation N = 1 + max(highest in the journal, the counter); a counter or journal value at or above 2^63 refuses the start (no overflow, and a stand-in's unsealed value cannot wrap it). Write `starts.gzs` with N (write `starts.gzs.tmp`, sync, rename, sync the folder); then append and sync the incarnation entry and its mark as today. A crash between the two skips a number, which is harmless.
- **A restore** starts the same way, so its first incarnation is above every one used on this device since the backup.
- **Missing or damaged file.** On an ordinary start the journal alone gives the number, the file is written again, and the person is told once that it was missing. On a restore it means another device or a removed file: the journal's counter is used, the `restored` record says `counter_found` 0, and **the person is told** (the restore screen and an attention item), because the restore is then protected only by the epoch's random draw.

**What it covers, exactly.** A restore **of the journal alone**: importing a backup file (storage 11), starting files found behind as a restore, or a key file with no journal. It does **not** cover a snapshot of the whole data folder or of the machine (a virtual machine restored, a disk image put back): that rolls back `starts.gzs` with the journal, guard and mark file, and storage 6.4 already says such a rollback is not detected. There the only protection of the restore epoch is its 31-bit random draw, and a port that repeats after a snapshot (`ports.h`) defeats the incarnation's part of it. `safety-rule.md` R2's sentence "a restore cannot rewind it" is narrowed accordingly (text below).

**Interface change.** `journal.md` (S5):

- section 5, step 5 replaced by: "**Incarnation.** Read the start counter (storage 10.3). New incarnation = 1 + the larger of the highest found in the journal and the counter (the journal alone if the file is missing or damaged; refuse to start if either is at or above 2^63). Write the counter with it, then append the incarnation entry, sync, append a sync mark, sync. Only then may the runner be created. Writing the counter first keeps a restored journal, whose counter is older, from reusing a number used on this device since its backup. It does not defend a snapshot of the whole folder (storage 6.4)."
- section 8.2, "How a restore is recognised": add "The new incarnation is taken from the start counter as at every start (section 5 step 5), so it is above every incarnation this device used since the backup. A restore that finds no counter tells the person."
- section 9: the `restored` record (`0x00040006`) gains `counter_found` (`u8`).

`storage-encryption.md` (S6), new 10.3, a row KC in 4.4's table, the file in 3.1's table and in set-up (7.4), and a vector E9c:

> ### 10.3 The start counter
>
> `starts.gzs`, beside the guard, outside the journal's backup set, created at set-up: the highest incarnation this device has used for this wallet.
>
> | Offset | Field | Size |
> |---|---|---|
> | 0 | `magic`, ASCII `GZSTART1` | 8 |
> | 8 | `format`, 1 | 1 |
> | 9 | `chain` | 32 |
> | 41 | `seal(KC, u64 counter, ad = bytes 0..40)` | 24 + 8 + 16 |
>
> KC = keys(seed, `start counter`, chain) (4.4), so a restore from the words can read it. Replaced (write `starts.gzs.tmp`, sync, rename, sync the folder) at every start, before the incarnation entry. A file that fails its tag is treated as missing.

`safety-rule.md` R2, the sentence "The incarnation never repeats and a restore cannot rewind it (`runner.h`)" becomes: "The incarnation never repeats on one device, and a restore of the journal alone cannot rewind it (the start counter, `journal.md` section 5); a snapshot of the whole folder or machine can, and then only the random draw protects the epoch."

`program/store.h` (S11): `begin` documents the counter; the stand-in implements it with a plain `starts.standin` (no seal).

**Order.** The stand-in counter and its test land **in P3**, with the program, so `main` never has a program whose restore path rewinds the incarnation; the sealed form lands in P9 with or after PR 25. **No signing engine (PR 15) merges before P3.**

**Owner.** S5 (journal text and code), S6 (format, KC, vector), S11 (stand-in, test), S2 (merge order).

**Test T8, `program_restore_counter`** (P3). A member runs to incarnation 2 and its journal is copied aside (the backup). It is restarted three more times (incarnation 5). The copy is put back as a restore (`--test-restore-from FILE`, which sets the restore marker). The restored start's incarnation is 6, not 3; its first batch is the restore batch; its restore epoch differs from the original's; pings before and after are answered. Variants: `starts.standin` removed before the restore: incarnation 3, `counter_found` 0, and the output says the person is told; a counter of 2^63 written into the stand-in: the start refuses.

## 9. The outcome of a broadcast

**Decision.** A chain event reports each broadcast's outcome, as **advice**: it lets an engine tell the user at once that the servers refused a transaction (and why), or retry later when none could be reached. It is never proof and never final: one server's refusal is not another's, an accepted transaction can still be replaced or dropped, and the event is lost with a restart (the worker's generation). What a transaction actually did is learnt only from `WATCH_TX` and `WATCH_OUTPOINT`. It is one aggregate per broadcast; per-server results are deferred (section 5).

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

`gz_chain_event_t` gains `gz_broadcast_outcome_t outcome;` and `gz_bytes_t reason;` (printable ASCII, at most 127 bytes, the first refusing server's words); `txid` holds the broadcast transaction's txid, computed by the program from the bytes sent. `action.h`, BROADCAST: "Its outcome comes back as a GZ_CHAIN_BROADCAST_RESULT event, which is advice (event.h). Broadcasting a transaction does not watch it."

**Owner.** core, S8 (worker result), S11 (conversion).

**Test T9, `program_broadcast_result`** (P7). The local test server set to accept, then to answer "already known", then to refuse with a reason, then to be down. A test user command broadcasts a transaction each time; the node's notices show accepted, accepted, refused with the server's reason, unreachable. A restart from storage while a broadcast is outstanding: no result reaches the new incarnation.

## 10. `WATCH_SCRIPT`

**Decision.** Retire it. The chain view lists a script's *unspent* outputs, so a spend shows only as an output vanishing, and naming the spender needs every outpoint ever seen. Slice 1's watches are the funding txid (`WATCH_TX`, C11) and the funding inputs (`WATCH_OUTPOINT`, C4(d) and Dead); `exit.md` 3.2 and 8 already watch "by outpoint and by txid, never by script". Receiving to an address of the wallet is the wallet's own scan, not a core watch.

**Interface change.** `action.h`: `GZ_ACTION_WATCH_SCRIPT` keeps its value (4) with the comment `/* retired in contract v2: refused */`; the union member `watch_script` goes; `gz_action_list_add` returns `GZ_ERR_ARGUMENT` for it; WATCHES drops its paragraph. `event.h`: `GZ_CHAIN_SCRIPT_SPENT` keeps its value (1) as `/* retired */`, and `script` leaves `gz_chain_event_t`. The runner's unknown-kind check refuses it too.

**Owner.** core, S8 (implements none of it).

**Test T10, `program_watches`** (P7; the refusal in the core unit tests, P4). The local test server plays: a funding-like transaction unconfirmed, then confirmed, then buried to depth 3; a reorganisation that removes it; an input of it spent in the mempool, then confirmed. A test user command sets `WATCH_TX` (depth 3) and `WATCH_OUTPOINT` (depth 1). The node's notices show confirmations 1, 2, 3, then unconfirmed, then confirmed again; the spend with 0 then 1 confirmation. A restart from storage re-sets both watches at start and reports the current state again.

## 11. What the interface reads

**Decision.** The node offers no reads: a read would be a call into the core outside an event, and could show state that is not durable. Instead:

- **The view.** The program keeps a table: for each (object kind, id), the latest bytes a `NOTIFY` gave. The backend reads it on the loop thread, synchronously, as `api_backend.h` wants.
- **Durable, by a node rule.** `NOTIFY` is outward, so the runner releases it only after the saves listed before it. New node rule 8 makes that cover what it shows: *a view `NOTIFY` comes after, in its list, the save of the state it shows.* The simulator checks it: after a crash at any point, the view rebuilt by the next start is never older than any view object the previous run released. Two kinds are **live facts**, not durable, and are labelled so: `connection` (kind 9) and the chain heights in `status`, which the program fills itself from the transport and the chain worker, not from the node.
- **Rebuilt at every start.** Node rule 7: a start emits a `NOTIFY` for every view object it has. After a restart from storage inside one process the program **clears the view**, and the backend answers as `local-api.md` already says for a core being rebuilt (`wallet = node_stopped`, `doing.code = node_stopped`, calls `503 node_stopped` with reason `rebuilding`) until the start's notices are in; then the program sends the API topic `reset` (`local-api.md` 10.2).
- **History is not re-emitted.** `activity` (kind 6) grows without bound, so the view keeps only the newest 50 entries, emitted at start. Older pages are read by the program from its own journal: `activity_entry` records (`0x000d0012`, `local-api.md` 7.5) are durable by definition, the program indexes them as it appends them, and the backend pages through that index. This is the program reading storage it owns, not the node; it is the one exception, and it is limited to record types `local-api.md` 7.5 defines for the API. (To confirm in P6.)
- **Framing of `NOTIFY`.** `code` says what the bytes are; bytes are a TLV stream (BOLT 1 rules, `messages.md` 4.2):

| `code` | Meaning | Records |
|---|---|---|
| `0x00010000` + k | A view object of kind k (registry below) | 0 `id`, 1 to 64 bytes of printable ASCII (the local id of `local-api.md` 7.3), required; 2 `gone`, empty, when the object is removed; then the object's fields from type 4, defined with the object |
| `0x00020000` | The outcome of a user command | 0 `request_id` (the client's, ASCII), required; 2 `status` (`u16`: 200, 202, or the error status); 4 `error` (an error code of `local-api.md` 8.1, ASCII), absent on success; 6 `object` (the acted-on object's kind and local id); 8 `params` (a JSON object, ASCII) |
| `0x00030000` | A line for the log (`storage-encryption.md` 12.1) | 0 `text`, printable ASCII, never a secret |

View object kinds (k), with the API topic each feeds: 1 `status` (no id), 2 `lobby`, 3 `host_lobby`, 4 `factory`, 5 `wallet`, 6 `activity`, 7 `attention`, 8 `doing`, 9 `connection` (live). The fields of each are defined in the pull request of the engine that first emits it, with the mapping to the `local-api.md` answer it fills.

- **Acting calls follow `local-api.md` 7.4 and 7.5**, which already define them:
  - The **client** chooses the `request_id` (16 to 64 characters). The server computes the body digest (RFC 8785, passphrase removed) and the program submits a `GZ_EVENT_USER_COMMAND` carrying the `request_id`, method, path (local ids filled in), digest, command and arguments.
  - **The engine**, not the view, does every check that answers 409 (`request_id_reused`, `changed_elsewhere` against `based_on_version`, `review_expired`), and replays a known id from its saved status. A check against the view is only a fast path for obviously bad calls.
  - The engine saves the `request_id` record (`0x000d0014`) **in the same batch as the action's first save**, and then emits the command-result `NOTIFY`, which the runner releases only after that batch is confirmed.
  - **The server holds the HTTP answer until that `NOTIFY` arrives**, then answers its status (200 when the outcome is known, 202 when it depends on other parties, the error otherwise), as 7.4 says: "an action answers when the core has taken it and every save it asked for is confirmed". PR 26 already holds answers for passphrase jobs. A `PUT /pause` that answered is therefore paused.
  - If the node restarts meanwhile, the server answers `503 node_stopped` (reason `rebuilding`, `local-api.md` 8.1); if no outcome comes within 30 s, `503 node_busy` (a code P5 adds to 8.1). Either way the client retries **with the same `request_id`**: 7.4 makes that safe (a replay if the first was saved, a first call if not). The server never answers success before the save.
- **The data folder.** The program owns it: it creates it (0700), refuses it if others can read it, and holds `DIR/lock`. The API server is given that folder and creates or checks nothing; it writes only its own files there (the redirect file, `interface.sock`, `attempts.gza`).

**Interface change.** `action.h`, NOTIFY:

```c
        /* NOTIFY: outward. `bytes` is a TLV stream framed by `code`
         * (contract-v2.md section 11): a view object, a command's outcome, or
         * a log line. A view object follows, in its list, the save of the
         * state it shows (node.h rule 8). */
        struct { uint32_t code; gz_bytes_t bytes; } notify;
```

`event.h`, `user`: `/* USER_COMMAND: a TLV stream, command.h: request_id, method, path, digest, command, arguments */`. New `core/gazpacho/include/gazpacho/command.h` with `GZ_NOTIFY_VIEW(k)`, `GZ_NOTIFY_COMMAND_RESULT`, `GZ_NOTIFY_LOG`, the view kinds, and the `USER_COMMAND` records: 0 `request_id` (ASCII, required), 2 `method` (ASCII), 4 `path` (ASCII), 6 `digest` (32), 8 `command` (`u16`, `GZ_CMD_*`, one per acting call of `api_backend.h`'s `gz_api_call_id`), then arguments from type 10. `node.h` rules 7 and 8:

> 7. Emit, at start, a NOTIFY for every view object it has (contract-v2.md section 11): the program forgets the view when it stops.
> 8. Put a view NOTIFY after the save of the state it shows, in the same list, and a command's outcome after the save of its `request_id` record.

`api.h` (PR 26):

```c
    const char *data_dir;      /* required: a folder the program has made, checked
                                  (0700, owned by this user) and locked; the server
                                  creates and checks nothing, and writes only its own
                                  files in it (redirect file, interface.sock, attempts.gza) */
```

and `server.c` loses its `mkdir`. `api_backend.h`: a call that acts is handed to the backend with its digest and answered when the backend completes it (a new `call_done(srv, handle, status, body)` from the loop thread), not from `call`'s return value; the 30 s limit and the 503 as above. The "Threads" paragraph is section 4's.

**Owner.** core (`command.h`, rules 7 and 8, the simulator invariant), S9 (folder, held answers, digest, thread rule), S11 (view, backend, history index); each engine (S4 first) defines its view objects' fields.

**Test T11, `program_view`** (P6). A host with the interface; a client signed in with the test passphrase.
1. A member pings: the event stream shows `status`, and `GET /status` shows the new ping count (the placeholder's view object).
2. The host is killed after the ping is durable and before the notice is released (`--test-crash-after-save`). Restarted: the stream shows `reset`, and `/status` shows the count including that ping.
3. `PUT /pause` (the placeholder's test command) with a `request_id`: the answer comes only after the `request_id` batch is durable (the host killed before the confirmation: the client gets no 200, and its retry with the same id after the restart acts once). The same id with another body: 409 `request_id_reused`.
4. A restart from storage in one process: between the failure and `reset`, `/status` says `node_stopped` and calls answer `503 node_stopped` (`rebuilding`).
5. The program started on a folder with mode 0755 refuses before the server exists; the server started on a missing folder by the test harness refuses and creates nothing.

## 12. The transport's random type

**Decision.** `ports/net` needs randomness for one thing, BOLT 8 ephemeral keys, which are one-time secrets and never leave the transport. It gets its own one-line type and includes no core header, so the core's contract can change without touching the transport. The program passes a function that reads the operating system at each call (`transport.md` rule 9 and decision 12).

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

`gz_random_port_t` becomes `gz_net_random_t` in `noise.h`, `conn.h`, `peers.h`, `noise.c`, `conn.c`, `peers.c`, `tools/gz-net`; `#include "gazpacho/ports.h"` leaves `noise.h`. `transport.md`'s "Pieces" row for `noise.c` says "a callback (`gz_net_random_t`)". `tools/check-core-isolation.sh` gains the reverse check: nothing under `ports/net/` includes core headers.

PR 23 is based on `main` before PR 9 and calls `fill(ctx, out, len)`; `main`'s `noise.c` calls `fill(ctx, GZ_RANDOM_SECRET, out, len)`. Rebasing PR 23 onto `main` with this change resolves both.

**Owner.** S7.

**Test T12.** P2: a CTest build check, `net_no_core_headers`: `ports/net` and `gz-net` compile with an include path that has no `core/gazpacho/include`. P3 (it needs the program): the release `gazpacho` binary's symbol list has no seeded random source and no `GZ_ENV_KIND_TEST` table entry, so kind 32767 is never delivered outside test builds.

## 13. Member keys

**Decision.** Keys under BIP 32, hardened all the way, below a purpose of Gazpacho's own, with a network level:

| Key | Path |
|---|---|
| Per-lobby key: BOLT 8 static key and contribution key (`messages.md` 2, `signing-round.md` 2) | `m / 254315617' / net' / 0' / epoch' / index'` |
| Its factory key | the same with `index + 1` |
| The host's long-term key (BOLT 8, terms, host messages) | `m / 254315617' / net' / 1' / k'`, k the first valid of 0, 1, 2, … |

- **254315617** is the first four bytes of `SHA256("gazpacho keys")` (`8f 28 8c 61`) with the top bit cleared: a reproducible random pick, like type 52791. It is not one of BIP 43's own purposes (44, 45, 48, 49, 84, 86, 87), nor LND's 1017 or Eclair's 46 and 47. It has **not** been checked against SLIP-0043's registry (which could not be read when this was written); checking it and registering the purpose there is a follow-up for P8.
- **`net`** separates the networks: 0 main (reserved; never derived while mainnet is refused), 1 testnet4, 2 signet, 3 testnet3 (unused). BIP 44's coin type is 1 on every test network, so a coin-type level would give one seed the same host key and the same member keys on signet and testnet4, linkable across networks and one key in two factories. A level of our own keeps them apart.
- `epoch` is the 31-bit restore epoch (`safety-rule.md` R2: "31 bits fit a hardened BIP 32 index"); `index` the 31-bit `key_index`.
- **Allocated in pairs.** Every fresh allocation reserves two indexes, (i, i + 1): the contribution key at i, the factory key at i + 1. A fresh index that later becomes a lobby key (`signing-round.md` 2) thus never takes the previous lobby's factory key, which would put one key in two roles and link two lobbies. `key_index` records the highest index allocated, i + 1; the next pair starts at i + 2; i + 1 is below 2^31. The guard's `highest_index` is the same value.
- **Hardened everywhere**, because these are secret keys used one by one, never an account whose public children anyone needs: a leaked child secret reveals nothing about its siblings, and nothing under `m/86'` reaches them. Storage keys are HKDF over the seed (storage 4.4), not BIP 32, so they are separate too.
- **Invalid children** (BIP 32's rare case, about 1 in 2^127 per step, `GZW_REASON_INVALID_CHILD`), so the rule is total:
  - at `index` or at `index + 1`: the whole pair is skipped and the next pair allocated and saved (the skipped pair is never used);
  - at `epoch'`: every index under it fails; the node draws a new epoch as at a restore (R2) and saves it in `key_epoch`, also for epoch 0 of a new installation;
  - at `net'`, `0'` or `1'` above it: the seed cannot be used for Gazpacho; set-up refuses it and asks for new words (the chance is negligible);
  - the host key: k is the first of 0, 1, 2, … that is valid, found the same way at every start, so the host stores nothing.
- The host key does not change with the restore epoch: members pin it, and a restored host is the same host.

**Interface change.** `wallet/include/gazpacho/wallet_keys.h`:

```c
/* Gazpacho's key purpose: SHA256("gazpacho keys")[0..4] & 0x7fffffff. */
#define GZW_GAZPACHO_PURPOSE 254315617u

/* The network level below the purpose (contract-v2.md section 13). Returns 0
 * and *out, or -1 for mainnet and an invalid network. */
int gzw_gazpacho_net_level(gzw_network net, uint32_t *out);

/* The per-lobby key at m/254315617'/net'/0'/epoch'/index' (contract-v2.md
 * section 13): its secret key and 33-byte public key. epoch below 2^31, index
 * below 2^31 - 1 (its pair's factory key is at index + 1). 0 on success; on
 * failure *reason says why: GZW_REASON_INVALID_CHILD at the last level means
 * "skip this pair", and *level says which level failed. The caller wipes
 * seckey32. */
int gzw_lobby_key(const secp256k1_context *ctx, const gzw_xprv *master, gzw_network net,
                  uint32_t epoch, uint32_t index, unsigned char seckey32[32],
                  unsigned char pub33[33], unsigned *level, gzw_reason *reason);

/* The host's long-term key at m/254315617'/net'/1'/k' for the first valid k;
 * *k_out says which. As above. */
int gzw_host_key(const secp256k1_context *ctx, const gzw_xprv *master, gzw_network net,
                 unsigned char seckey32[32], unsigned char pub33[33], uint32_t *k_out,
                 gzw_reason *reason);
```

Test vectors from the BIP 32 test seed, generated by `tools/spec-vectors.py` and cross-checked against an independent BIP 32 implementation, in `wallet/vectors/`; the invalid-child cases forced as in `test_wallet_rare.c`. `messages.md` section 2, "Member key", names the path and the pairs (applied here, marked **proposed, owner to confirm**).

The program derives the key when it carries out a `CONNECT` (section 3) and wipes it once handed to `gz_peers_connect`; `transport.key` and `wallet-seed.standin` give way to the seed (and to `keys.gzk` once S6 lands).

**Owner.** wallet; S11 (use).

**Test T13, `program_derived_keys`** (P8). A host and members from known test words. The host's key printed at start equals `gzw_host_key`'s vector, before and after a restart, and differs between a signet and a testnet4 folder made from the same words. The member's first link uses (epoch 0, index 0)'s key and its `key_index` record says 1; a second `CONNECT` uses index 2; restarted, the same keys; after a restore (T8's harness) the epoch changes and the host sees a new key, which finds no seat. T2 step 3 and T3 run here too.

## 14. The random port's signature

**Decision.** Settled on `main` (PR 21 merged after PR 9): `fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)` with `GZ_RANDOM_ORDINARY` = 0 and `GZ_RANDOM_SECRET` = 1. Nothing changes in the core. The program drops every core probe (`GZP_CORE_STEPPED_START`, `GZP_CORE_RANDOM_PURPOSE`, `GZP_CORE_RANDOM_ENUM`, `GZP_CORE_PEER_EVENTS`, `GZP_CORE_READER_RESTORED`, `GZP_CORE_WATCH_TX`) and builds against `main` only; `program.md` section 6 becomes one paragraph saying so (it still says PR 21 is not merged).

**Interface change.** None in the core. `program/CMakeLists.txt` and the `#if` blocks go.

**Owner.** S11.

**Test T14** (P3). `program_two_process` passing on `main` with the probes removed; the build check fails if anything still names `GZ_RANDOM_OTHER`.

## 15. Networks

**Decision.** Slice 1 runs on signet or testnet4, one per data folder, never mainnet. `init` names exactly that one network. BOLT 1 lets a node list several chains and only allows closing when there is no common one; a Gazpacho program runs one network, so it lists one and closes on anything else, including a list of several. This is stricter than BOLT 1 and holds for native Gazpacho connections only: through the bLIP-56 adapter (`messages.md` section 10, not in Slice 1) the connection's `init` belongs to a Lightning node, which may list several chains; there the rule is section 10's, and the factory messages carry their chain in the terms (`terms.md` `chain`). Mainnet stays refused before anything starts (`SLICES.md` rule 3; program exit 2). The interface's default ports per network are already in `local-api.md` 3.1 (39735 signet, 39736 testnet4).

**Interface change.** `messages.md` section 2, "First message" (applied here):

> BOLT 1 `init`. `networks` must contain exactly one chain hash, that of the network this party was set up for: signet or testnet4. A party whose peer names another chain, several, or none closes the connection. The chain hash is BOLT 0's: the hash of the network's block 0.

PR 23, `peers.h`: the `chain` comment becomes `/* init's networks: exactly this chain (signet or testnet4) */`; `gz_peers_new` refuses the main network's hash.

**Owner.** spec (here); S7.

**Test T15, `program_networks`** (P3). A testnet4 host and a testnet4 member connect and ping. A signet member to the testnet4 host: both sides close with `GZ_PEER_WHY_INIT`. `--network mainnet` exits 2 before any file is made.

## 16. What every engine now does at start, and after

`node.h`'s list after this contract: 1 resend unacknowledged (from stored bytes), 2 safe twice and out of order, 3 the acknowledgement is the peer's saved message, 4 timers and watches again, 5 the restore batch first, **6 the reconnect step at `PEER_CONNECTED`, limits per link**, **7 the view again**, **8 view and command notices after their saves**, and the addressing rule of section 2; plus, at start, **apply a saved pause, then `CONNECT` and `SET_SEATED` again** for every link and seat it still needs (section 3).

## 17. The pull requests, in order

Each lands on `main` alone and leaves it building and green, **including the `handbook up to date` check**: every PR that changes a document rebuilds `docs/handbook.html` (`python3 tools/build-handbook.py`). Reviews per the ledger.

| PR | Contents | Mismatches | Owner | Depends on |
|---|---|---|---|---|
| **P1** | This note; `messages.md` 2 (networks, member key path and pairs, fresh index per `CONNECT`), 4.1 (kind 32767), 6.2 and open point 3; `terms.md` chain; `signing-round.md` 12.1 rows; the handbook | decisions for all; text for 7, 13, 15 | S11 (author), owner review | — |
| **P2** | PR 23 rebased onto `main`: `gz_net_random_t`, no core header (12); `gz_peers_pollfds`/`dispatch` (4); test kind under `GZ_TEST_KINDS` (7); one network, mainnet refused (15); `transport.md` limits updated (6); replacement before admission, `GZ_PEER_WHY_REPLACED`, seated keys, `gz_peers_close_after_send` (2, 3); `max_queue` sized for a reconnect answer, with a test (1); test T12 (build half) | 1, 2, 3, 4, 6, 7, 12, 15 | S7 | P1 |
| **P3** | PR 27 rebased onto P2: probes removed (14); `program/net.c` over `peers.h` (6); one loop with the stop pipe (4); refusal closes the connection, no outbox, start queue, listen after start, restart closes everything and clears timers (1); placeholder bytes carried in kind 32767 by the adapter until P4; **the stand-in start counter** (8); shutdown order. Tests T6, T8, T12 (symbol half), T14, T15 and `program_two_process` | 1, 4, 6, 8, 14, 15 | S11 | P2 |
| **P4** | Core contract v2 with the program and the simulator in the same change: `gz_link_t`; `SEND`/`MESSAGE` with kind, scope, records; `CONNECT`/`DISCONNECT`/`SET_SEATED`; `GZ_CHAIN_BROADCAST_RESULT`; `WATCH_SCRIPT` retired; node rules 3, 6, 7, 8 and the simulator's view invariant; the placeholder's hello and acknowledgement. Tests T1, T2 steps 1 and 2, T7 | 1, 2, 3, 7, 9 (event), 10 | core (S11 for `program/`) | P3 |
| **P5** | PR 26 rebased: `gz_api_server_pollfds`/`dispatch`, generations for passphrase jobs, file writes on the loop thread, folder given not made, held answers with the digest and `call_done` | 4, 11 (server side) | S9 | P1 |
| **P6** | Program wires the API: the view, `command.h`, the backend over the view, the activity index, `reset` after start, `request_id` handling in the placeholder. Tests T4, T11 | 4, 11 | S11 (core for `command.h`) | P4, P5 |
| **P7** | Chain worker `chain_watch.h` with the HTTP abort and backoff changes (S8), and `program/pchain.c` over it. Tests T5, T9, T10 | 5, 9, 10 | S8 (S11 for `program/`) | P4 |
| **P8** | `gzw_lobby_key`, `gzw_host_key`, `gzw_gazpacho_net_level`, vectors; the SLIP-0043 check and registration request; the program derives keys for `CONNECT` and the host key, allocates pairs; stand-in key files removed. Tests T13, T2 step 3, T3 | 2, 3, 13 | wallet (S11 for `program/`) | P4; owner's confirmation of the path |
| **P9** | The sealed start counter: `journal.md` 5, 8.2, 9, `storage-encryption.md` 3.1, 4.4, 7.4, 10.3 and E9c, `safety-rule.md` R2 sentence (with PR 25 or after it); the program's storage uses it | 8 | S5, S6 (S11 for `program/`) | P3, PR 25 |

P2 and P5 can go in parallel after P1; P7 and P8 in parallel after P4. P4 is the only change to the core, and it touches the open engine branches:

- **PR 15 (signing)** puts its own header (`'G' 'S'`, kind, id) inside the send bytes and names participants by `uint64_t peer`. Its rebase onto P4 is a **rewrite of its message layer**: kinds 64 to 81 of `messages.md` 4.1 through `SEND`'s kind, the lobby's scope, links for participants, the reconnect step of rule 6 (its `resend_ticks` timer resends stay). Plan it as its own review round. It merges after P3 (section 8) and after P4.
- **PR 24 (tree)** uses no messages and rebases with little change.

## 18. For the owner

1. **The key path** of section 13 (purpose 254315617, a network level, pairs, hardened, the host key on its own branch). Marked proposed in `messages.md`. Registering the purpose in SLIP-0043 is a public step: the owner decides when.
2. **No outbox, and a refused send closes the connection** (section 1): delivery rests on the reconnect step and the start's resends. This is stricter than the skeleton and matches the specifications.
3. **`WATCH_SCRIPT` retired** (section 10), with no Slice 1 user.
4. **A new file in the data folder**, `starts.gzs` (section 8), beside the guard and the mark file, outside the backup set; and the narrowed R2 sentence: a whole-folder or machine snapshot is not defended. S6's PR 25 is open on the same specification.
5. **Kind 32767** reserved in the protocol for test traffic (section 7), in the namespace that will be shared with SuperScalar (`PROTOCOL.md`).
6. **Activity history read from the journal by the program** (section 11), the one exception to "no reads".

## 19. Changes in draft 2 (review of PR 28)

| Finding | Change | Where |
|---|---|---|
| 1.1 drops on a live connection | Any refusal closes the connection; too-big fatal; `max_queue` sized for a reconnect answer; timer resends allowed | 1; P2, P3 |
| 1.2 events during a start; in-process restart | Peer events queued during a start; host listens after it; restart closes connections and clears timers; T1 steps 5 and 6 | 1; P3 |
| 1.3 rule 6 an amplifier | Rule 6 is the protocol's reconnect step (pull); which side resends what; limits per link; why nothing loops; placeholder `GZPH` | 3, 1; T3 step 5 |
| 1.4 202 against `local-api.md` 7.4 | Client `request_id`, digest, saved in the first batch, answer held until the command-result notice; 503 and a same-id retry past 30 s; 409 checks in the engine; the program `u64` id removed | 11 |
| 1.5 `DISCONNECT` drops the last message | Flush then close, with an event; `gz_peers_close_after_send`; the adapter reports replaced connections | 3, 2 |
| 1.6 the counter and snapshots | Covers a restore of the journal alone, not a whole-folder or machine snapshot; R2 sentence narrowed; `signing-round.md` 12.1 row fixed | 8; `signing-round.md` |
| 2 keys | Pairs reserved; invalid child at every level; a network level (signet and testnet4 apart); header path; SLIP-0043 follow-up; fresh index per `CONNECT` | 13; `messages.md` 2 |
| 2 counter | Renamed (start counter, `starts.gzs`), created at set-up, overflow refused, missing counter shown to the person, stand-in moved to P3, PR 15 after P3; KC in 4.4's label style | 8, 17 |
| 2 transport | Replacement and seats in `peers.c` before admission; replacement counted; T12 proves the test kind off; the adapter case of "several chains" | 2, 3, 12, 15 |
| 2 chain worker | Never drops a report (waits, coalesces tips); generation checked in `take`, `reset` purges and drains; interruptible shutdown; libcurl on the loop thread; per-server results deferred | 5, 9 |
| 2 passphrase thread | File writes on the loop thread; jobs carry a generation | 4 |
| 2 view | Rule 8 and a simulator invariant; live facts labelled; activity paged from the journal; view cleared on restart; the server's own files | 11 |
| 3 consistency | 39736 exists (request dropped); T2 step 3 and T3 to P8; T12 split P2/P3; PR 15's rewrite planned; `program.md` reaches `main` with P3; the protocol bytes in `msg_hash` | 2, 3, 7, 12, 15, 17 |
| 4 missing | Timers cleared on restart; pause before connecting; shutdown order | 1, 3, 4 |
| 5 minor | Self-pipe for stops; too-big fatal in the program | 4, 1 |
| CI | Handbook rebuilt; every later P does the same | 17 |
