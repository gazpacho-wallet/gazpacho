# The composite node (contract v2, step P4)

Draft 2, 2026-11-13, amended the same day with two owner decisions (host funding AUTO by default; 8 open and 64 ended lobbies) and the member signing default, "unlock once at join", which the owner then confirmed. A follow-up adds understudies (owner, 1.0.0) and answers the confirmation round of review A (R1 to R12); section 19 lists both. This note fixes how the engines sit behind the one node interface, `gz_node_start` and `gz_node_handle`. Today that node is the placeholder ping. Slice 1 needs a lobby, a signing engine and a funding engine behind it, and later channels and exits. The Slice 1 attempt (`docs/notes/slice1-attempt.md`, item 1) glued them together outside the node. This note replaces that glue with a design a builder can code without further decisions.

Draft 2 answers review A of PR 37 (findings A1 to A19) and three owner decisions: several lobbies at once in Slice 1; host accountability approved for 1.0.0 (not designed here, but not blocked); host funding and member signing configurable. Section 17 lists every change.

Read against: `docs/notes/contract-v2.md` (P4 and sections 1 to 3, 7, 9 to 11); `docs/notes/program.md` on `program-skeleton` (PR 27); `core/gazpacho` `node.h`, `runner.h`, `action.h`, `event.h`, `ports.h` on `main`; `lobby.h`, `lobby_handoff.h`, `member.c` and `docs/notes/lobby.md` on `lobby` (PR 30); `signing.h`, `signing.c`, `signing_node.h`, `signing_outcome.h` and `lobby_outcome.c` on `signing-vectors` (PR 36, stacked on PRs 32 to 35); `spec/messages.md`, `journal.md`, `signing-round.md`, `safety-rule.md`, `terms.md`, `local-api.md` (4.7, 11.3); `docs/notes/slice1-attempt.md` items 1, 12, 13 and 17; reviewer B's review of PR 30 (B1 to B4); reviewer A's review of the signing engine (F1 to F6); the lobby accountability research of 2026-11-13.

## 0. The decisions in one table

| # | Question | Decision | Section |
|---|---|---|---|
| 1 | Where the composite lives | A new library, `core/node`, implements `gz_node_init`, `gz_node_start` and `gz_node_handle`. `core/gazpacho` keeps the contract only. The placeholder ping becomes the **test engine**, built only into test builds | 2 |
| 2 | Engine identity | Each engine is named by its **journal area**: Lobby 0x0001, Round (signing) 0x0002, Funding 0x0003, Node 0x0004, Local API 0x000d, Test 0x7e57. The same number tags its records, its timers and its commands. Area 0xffff is reserved | 2 |
| 3 | Several lobbies | Up to `GZ_NODE_MAX_SLOTS` (8) lobbies at once per wallet, each in its own **slot**, with a generation. **Every Lobby record carries its scope.** Signing and funding are node-wide; C7 and C10 stay node-wide | 2, 7.3 |
| 4 | Links | `gz_link_t` everywhere, **derived from keys, never stored on its own**. On the host, each connection is **bound** to one slot by the node part | 3 |
| 5 | Routing | By **kind** to an engine family, by **scope** to a slot (or, for round kinds, to the signing engine while it holds any round under that scope), then the **link** is checked | 4, 5 |
| 6 | Actions | SEND with kind, scope and records; CONNECT; DISCONNECT with an appended `why`; SET_SEATED. **A refusal is DISCONNECT `refused`, never a SEND** | 6 |
| 7 | Errors | **Peers, the chain, the wallet and the person never cause a node error.** Those become outcomes, refusals, counted drops or notices. An error means a bug; it is fatal for the whole node, which then refuses every later call | 8 |
| 8 | Timers | The composite packs (area, slot generation, own id) into every timer id, and cancels a slot's timers when the slot is freed | 7.1 |
| 9 | Storage | One writer per record type. Engines read their own area and named areas of others, read only | 7.3 |
| 10 | Atomic hand-offs | **The composite brackets every cross-engine hand-off** and merges all saves made inside the bracket into one batch, itself. Engines need not keep any order for it | 7.4 |
| 11 | Outcomes | Every `round_ended` outcome, per role, maps to one lobby result. A disagreement found at start is **repaired**, never refused | 9.3, 10 |
| 12 | Start | Load every engine (no actions), then resume **one engine per call**: restore batch, pause, node, signing, lobby, funding, test, view | 10 |
| 13 | A round outlives its lobby | A slot stays **Closing** only while news may still be in flight: until Live, Dead, or the members' deadlines plus a grace after a failed lobby. Round messages route by scope without any slot; late `hello`s are answered from an index of ended lobbies. **Live factories never hold slots** | 2.4, 4, 11 |
| 14 | Keys | The signing engine gets keys **per round** through a key hook, by scope. A proposal before `start` finds them too | 2.5 |
| 15 | Configurable funding and signing | `host_funding` AUTO (the default, owner) or CONFIRM. `member_signing` AUTO, WHEN_UNLOCKED (a node-wide gate) or AT_JOIN (a **per-lobby gate** opened when the person marks ready; **the default**, owner). A closed gate means not answering the ready check | 12 |
| 16 | Bad host | Gates by link, scope and slot state from P4.1 and P4.2; the signing engine checks a proposal only against the lobby's **accepted record** | 13 |
| 17 | H1 | **The wallet exposes the spent scripts.** H1 stays a pure `core/tree` function. H1 runs **before** the lobby saves Funding | 14 |
| 18 | Understudies | A new attempt under the same check with a changed participant set; keys fixed per seat; standby order saved | 9.6 |
| 19 | Code steps | P4.1 to P4.7, each with a multi-process test in `tests/program/` | 15 |

## 1. What is given

The coordinator decided four rules before this note. They are applied throughout and gathered in 9.5.

1. Once the lobby hands a round to the signing engine, the signing engine alone owns the signing budget.
2. The lobby saves the signing outcome.
3. Handing the signing engine a check it already finished is ignored, so the hand-off is idempotent.
4. A chosen seat's keys are fixed until its round ends.

The owner decided since draft 1:

- **Several lobbies at once** in Slice 1, per wallet. There are no legacy journals, so every Lobby record gains a scope field now.
- **Host accountability** (signed seat receipts, the signer-choice rule in the terms, signed removal notices, signed lobby-wide counts) is approved for 1.0.0. It is not designed here. Section 16 lists what the composite keeps open for it.
- **Host funding defaults to AUTO**, on by default; CONFIRM is a setting (12.1).
- **Member signing defaults to AT_JOIN**, "unlock once at join"; AUTO and WHEN_UNLOCKED are settings (12.2).
- **Understudies are in 1.0.0**: standby seats that answered the check replace a no-show at the check, and a member who drops mid-signing, in a new attempt under the same check (9.6).

Contract v2 already decided the types used here: `gz_link_t`, SEND and MESSAGE_RECEIVED with kind, scope and records, CONNECT, DISCONNECT, SET_SEATED, `GZ_CHAIN_BROADCAST_RESULT`, node rules 3, 6, 7 and 8. This note changes them only by one appended field on DISCONNECT (section 6) and the `node.h` error text (section 8).

## 2. Shape

### 2.1 Where the code lives

- `core/gazpacho` keeps the contract: types, actions, events, ports, runner, `command.h`, and a new small `envelope.h`. Its `node.h` loses the placeholder. The node's functions are declared there and implemented in `core/node`.
- **`core/node`** (new, library `gazpacho_node`) implements the node. It depends on the contract and on the engine libraries. No engine depends on it. The isolation check covers it like any core library.
- The placeholder ping moves to `core/node/test_engine.c` as the **test engine**. It is compiled only with `GZ_TEST_KINDS`, like kind 32767. The simulator and `program/` link `gazpacho_node`.

### 2.2 The node

```c
/* core/gazpacho/include/gazpacho/node.h after P4.1 */
typedef struct gz_node gz_node_t;            /* opaque; gz_node_size() bytes, caller-allocated */
size_t gz_node_size(void);

/* The list one node call may fill, at most: the sum of every engine's worst
 * step (section 8.3). The program gives lists of this size and sizes its
 * runner to hold one such list. */
#define GZ_NODE_LIST_ACTIONS  /* computed in core/node, static assertion */
#define GZ_NODE_LIST_BYTES    /* computed in core/node, static assertion */

typedef enum { GZ_HOST_FUNDING_AUTO = 0, GZ_HOST_FUNDING_CONFIRM } gz_host_funding_t;
typedef enum { GZ_MEMBER_SIGNING_AT_JOIN = 0,       /* the default (owner): unlock once at join, 12.2 */
               GZ_MEMBER_SIGNING_AUTO, GZ_MEMBER_SIGNING_WHEN_UNLOCKED } gz_member_signing_t;

typedef struct {
    int host;                                /* 1: host, 0: member; fixed per data folder */
    const secp256k1_context *secp;           /* with a non-aborting illegal callback */
    gz_key_port_t keys;                      /* per-lobby keys and the host key (2.5) */
    gz_wallet_port_t wallet;                 /* host funding (14); all NULL on a member */
    gz_host_funding_t host_funding;          /* section 12; AUTO by default (owner) */
    gz_member_signing_t member_signing;      /* section 12 */
    uint32_t test_engines;                   /* test builds only: 0, 1 or 2 test engines */
} gz_node_config_t;

gz_status_t gz_node_init(gz_node_t *n, const gz_ports_t *ports, const gz_node_config_t *cfg,
                         uint64_t incarnation);
gz_status_t gz_node_start(gz_node_t *n, const gz_storage_reader_t *storage,
                          gz_action_list_t *out, int *more);
gz_status_t gz_node_handle(gz_node_t *n, const gz_event_t *ev, gz_action_list_t *out);
```

The program's loop does not change: it calls these functions and submits the list. The two settings come from the program's options now and from the local API's `settings` record (`journal.md` 9.1) when P6 lands; a change of setting reaches the node as a user command.

### 2.3 Engines

Inside the composite each engine has the same small interface (`core/node/engine.h`, internal):

```c
typedef struct {
    uint16_t area;                         /* its journal area: also its timer and command tag */
    const uint16_t *reads; size_t n_reads; /* areas its load reads, its own first */
    gz_status_t (*load)(void *e, const gz_record_t *rec, gz_batch_id_t at);  /* memory only */
    gz_status_t (*resume)(void *e, gz_action_list_t *out, int *more);       /* the start's actions */
    gz_status_t (*handle)(void *e, const gz_event_t *ev, gz_action_list_t *out);
    size_t max_step_actions, max_step_bytes; /* its worst step (8.3) */
} gz_engine_ops_t;
```

| Engine | Area | Instances | Wraps |
|---|---|---|---|
| Node (keys, guard, slots, connection binding, tombstones, restore batch, the signing gate) | 0x0004 | 1, part of the composite | new, `core/node/keys.c`, `slots.c` |
| Local API (pause, request ids, settings) | 0x000d | 1, part of the composite | P6; in P4 only the pause |
| Lobby | 0x0001 | one per slot | `gz_lobby_host_t` or `gz_lobby_member_t` (PR 30) |
| Signing | 0x0002 | 1 | `gz_sign_t` (PRs 32 to 36) |
| Funding | 0x0003 | 1 | new in P4.5, `core/funding` |
| Test | 0x7e57 (and 0x7e58) | 0 to 2, test builds | the placeholder ping |
| Later: channels, exit, watch | 0x0005, 0x0007, 0x0008 | per factory, or 1 | Slice 2 and 3 |

### 2.4 Slots

A **slot** is one lobby this wallet takes part in: its scope, its lobby engine instance, its keys, and its generation. Up to `GZ_NODE_MAX_SLOTS` (8, owner decision) slots are Open at once. Opening a ninth is a refused command, not an error. Both caps here are constants that can be raised later without a format change.

**States.**

| State | Meaning | Ends when |
|---|---|---|
| Open | The lobby runs | The lobby ends (Cancelled, Failed, left, removed), the factory goes live, or the member never got in (6.2 refused terms, the host unreachable past the invitation's limit, the person gave up) |
| Closing | The lobby is over (`slot_closed` saved), but a member may still lack the lobby's final news | The first of: the factory is Live (Active is final news); it is Dead; or, after a Failed, Cancelled or left lobby, the later of the members' unfinished deadline (one signing budget) and funding deadline (36 blocks after the ack in Slice 1, plus the burial depth), plus `GZ_NODE_CLOSING_GRACE_BLOCKS` (6) |
| Free | Forgotten in memory, but still answered from the index of ended lobbies (below) | |

- A slot's **serial** counts every `slot_opened` this wallet ever saved, from 1. Its **generation** is the serial's low 16 bits. The composite never opens a slot whose generation equals that of a slot in use; it takes the next serial instead.
- **Closing is derived, not saved.** At load, a slot with `slot_closed` is Closing if its end condition above has not passed (the funding engine says Live or Dead; the tip and the clock say the deadlines), else Free.
- In Closing, the lobby engine instance is freed. What the slot keeps is small:
  - Member: the link (from its keys), and the CONNECT stands (11.2).
  - Host: a **tombstone**: scope, final lobby state, reason, the saved signed `cancel` envelope (from `lobby_ended`, which the node part reads), and room for each seat's last signed receipt once accountability lands (16).
- Closing slots are capped at `GZ_NODE_MAX_TOMBSTONES` (64, owner decision). At the cap, the oldest Closing slot becomes Free early; its late `hello`s are then answered from the index. Nothing is refused.
- **Live factories never hold slots** (R1). After Live, the factory belongs to the funding engine, and in Slice 2 to the channel engine, which keeps its own links per factory and does not inherit the lobby slot.
- **The index of ended lobbies.** The node part loads, from every `slot_closed` and `lobby_ended`, a compact entry per ended lobby: scope, final state, reason (35 bytes), and, for the newest 256, the saved signed `cancel`. A late `hello` for a Free scope is answered from it: `lobby_status` with the final state and reason, then the `cancel` if kept. The node never reads storage after its start, so this index is the journal's end records, loaded at start and kept current.
- **H12 needs no slot.** Round messages route to the signing engine by scope whenever it holds any round under that scope (section 4), resolved rounds included. The signing engine keeps resolved rounds' result bytes on disk and loads them when a status request names the round (signing F3's fix).

**C7 and C10 stay node-wide.** The signing engine checks every proposal against the exposure records and unresolved outpoints of every lobby, open or closed.

### 2.5 Keys

The node part owns key allocation, because the guard must ride in the same batch as every `key_index` and every `round_started` (`journal.md` 8.3).

- `gz_key_port_t` (program-supplied): `pub(epoch, index, pub33)`, `secret(epoch, index, sec32)` (the caller wipes it), `host_pub(pub33)`. P4 implements it over the stand-in key file; P8 derives from the seed (contract v2 section 13).
- Opening a slot allocates an index pair (contribution key at i, factory key at i + 1) and saves `key_index`, `guard` and `slot_opened`. The host does the same for its own factory key in each lobby.
- The node part keeps a table from scope to (epoch, index) for every slot in use, Open or Closing.
- **The lobby** gets public keys and signs through `gz_lobby_crypto_t`, which the composite implements over the key port for the slot's pair.
- **The signing engine gets keys per round** (A5). `gz_sign_set_keys` and the engine-wide keypair go. The engine calls a hook when it needs a secret:

```c
/* In gz_sign_config_t. Fills the factory and contribution keypairs this party
 * uses for the round under `scope`. 1 on success; 0 if no key is available (no
 * slot for the scope, a key of another epoch, or, with AT_JOIN, no scoped
 * secret for that scope and terms: 12.2). The hook never looks at a gate.
 * The engine wipes the keypairs as soon as the operation is done. */
int (*keys)(void *ctx, const uint8_t scope[32], secp256k1_keypair *factory,
            secp256k1_keypair *contribution);
```

  The gates act only through the lobby's `may_answer` (12.2); `gz_lobby_member_accepted` already refuses an unanswered check, so the hook need not (R9). The hook works with or without a `start`, for a closing slot's old round (to sign its `round_abort`), and for several lobbies at once. A return of 0 is not an error: the engine answers as the round's state requires (it ignores a new proposal, or answers `round_abort` with its saved bytes where it has them). Rule 4 holds by construction: a slot's keys never change.

## 3. Links

`gz_link_t` replaces every `uint64_t` peer id in events, actions and engines (contract v2 section 2). **A link is derived from keys the engine already holds, never kept as a separate table.**

| Side | Speaking to | Link (local, remote) |
|---|---|---|
| Host | a member | (host key, the seat's contribution key) |
| Member | its host, for a slot | (its contribution key for the slot, the pinned host key) |
| Member | its host, for a round whose slot is closing | (the round's own contribution key, participant 0's key), both from the saved round |

- The signing engine's `peer[]` array goes. The host addresses participant j at (host key, participant j's contribution key). A member addresses only participant 0.
- Contribution keys are per lobby, so on both sides a link belongs to at most one slot.

**Binding connections to slots on the host.** Several lobbies share the host's key, so a new connection does not say which lobby it is for. The node part binds it:

- A connection whose remote key holds a seat in a slot (the composite saw that slot's SET_SEATED) is bound to that slot at once.
- Any other connection is **unbound**. The node part keeps it: at most 16 unbound connections, the oldest silent one pushed out first (reviewer B, B7), closed after 60 s without a message. These are the lobby's own numbers, moved up to the node part.
- An unbound connection's first message with a nonzero scope binds it to that scope's slot. The composite then gives that slot's lobby a PEER_CONNECTED for the link, then the message.
- A bound link that sends another nonzero scope is refused (DISCONNECT `refused`).
- A scope-zero `hello` on any connection is answered by every listed host slot (at most 4 offers, 6.1), with the node part's per-link limits (one answer a second, closed after 20 ignored `hello`s in 10 minutes). With no listed lobby, nothing is answered.
- PEER_DISCONNECTED goes to the bound slot's lobby, if any.

The lobby's connection table then sees only its own links, and its caps stay as they are.

## 4. Routing messages

A MESSAGE_RECEIVED carries (link, kind, scope, records). The transport has already checked the protocol bytes, the direction, the record table, and reassembled parts. Kind 2 (`part`) never reaches the core.

**1. By kind, to an engine family.**

| Kinds | Engine |
|---|---|
| 16 to 63 (lobby range; 36 is reserved for the receipt of 1.0.0) | lobby |
| 64 to 80 | signing |
| 81 (`factory_funded`) | funding: counted, nothing acted on |
| 32767 | test (test builds only) |
| 128 to 159 (discovery) | dropped and counted (never worth a disconnect) |
| anything else | dropped and counted (the transport has applied the odd/even rule) |

**2. By scope.**

| Case | Host | Member |
|---|---|---|
| Lobby kind, scope of an Open slot | that slot's lobby (after binding, section 3) | that slot's lobby |
| Lobby kind, scope of a Closing slot, or of an ended lobby in the index | the tombstone or the index: `hello` gets `lobby_status` with the final state and reason, then the saved `cancel`; anything else is dropped | dropped and counted |
| Lobby kind, scope zero | `hello` only: the listing (section 3) | dropped and counted |
| Lobby kind, unknown scope | `hello`: `lobby_status` with state 0 (`gz_lobby_host_unknown`), under the node part's per-link limits (A16); else dropped | dropped and counted |
| Round kind, scope under which the signing engine holds any round | the signing engine | the signing engine |
| Round kind, scope of an Open slot whose lobby has answered a check (member) or sent a `start` (host) | the signing engine | the signing engine |
| Round kind, any other scope | dropped and counted | dropped and counted |

**3. The link is checked.**

- Member, lobby kind: the link must be the slot's link. Member, round kind: the link must be the slot's link, or a held round's link under that scope. Otherwise the message is dropped and the connection refused (DISCONNECT `refused`).
- Host: a lobby message's link must be bound to the slot (section 3). A round message's remote key must be a participant of a round under that scope; the signing engine checks this. A connection whose key is a participant of a held round counts as seated for the node part's unbound caps (never pushed out first), with no SET_SEATED.

`gz_sign_node_wants` (PR 36) is replaced by these tables.

## 5. Routing other events

| Event | Goes to |
|---|---|
| PEER_CONNECTED, PEER_DISCONNECTED | Member: the slot whose link it is (its lobby, then signing, in that order: `hello` first, then saved `round_partial_sigs` and `round_status_request`, contract v2 rule 6); for a Closing slot's link, signing only. Host: section 3's binding, then the bound slot's lobby, then signing. Then funding and test |
| TIMER_FIRED | the engine and slot named by the timer id (7.1); the engine gets its own id back |
| GZ_CHAIN NEW_TIP | signing, funding, test. Lobbies take no tips |
| GZ_CHAIN TX and OUTPOINT reports | every engine registered for that txid or outpoint (7.2) |
| GZ_CHAIN BROADCAST_RESULT | the funding engine (the only engine allowed to BROADCAST, 6) |
| USER_COMMAND | by command code. `command.h` reserves a range per area: 0x01xx lobby (the object's local id names the slot), 0x03xx funding, 0x04xx node (the signing gate, 12), 0x0dxx local API, 0x7exx test. An unknown code is answered with the command-result notice `unknown_command` |
| STORAGE_CONFIRMED | the engines whose records were in that batch (7.5) |

## 6. Actions and their mapping

Engines emit contract v2 actions directly. The composite rewrites timer ids (7.1), brackets and merges saves (7.4), dedupes watches (7.2), and refuses a BROADCAST from any engine but funding (a bug: fatal).

| Engine emits | Contract action | Program does (`program/net.c`, `pchain.c`) |
|---|---|---|
| a message | `SEND {link, kind, scope, records}` | `gz_peers_send` with the protocol tag and type 52791; split host to member |
| keep a connection (member, at slot open, at every start, while a slot is Open or Closing) | `CONNECT {host, address, key_epoch, key_index}` | connect once the save before it is confirmed; reconnect with the same key |
| refuse a peer | `DISCONNECT {link, why = GZ_DISCONNECT_REFUSED}` | `gz_peers_refuse`: BOLT 1 `warning` with a fixed text, then close |
| close an idle or unseated connection | `DISCONNECT {link, why = GZ_DISCONNECT_IDLE}` | `gz_peers_close_after_send` |
| stop keeping a connection (the slot is Free) | `DISCONNECT {link, why = GZ_DISCONNECT_DONE}` | `gz_peers_close_after_send` |
| a seat held, or no longer | `SET_SEATED {member, seated}` | `gz_peers_set_seated_key`, applied before the member's first message is delivered |
| a funding transaction | `BROADCAST` | the chain worker (P7) |
| a view change, a command outcome, a log line | `NOTIFY` (contract v2 section 11) | the view (P6); an output line before |

**DISCONNECT gains one appended field**, `uint16_t why` (`GZ_DISCONNECT_DONE` 0, `_REFUSED` 1, `_IDLE` 2, `_HOST_FAULT` 3). It chooses between the warning and a quiet close, and names the cause in the log. DISCONNECT stays ordered, not outward.

What goes:

- The lobby's whole Lightning messages. The lobby encodes records and signs `msg_hash` over `67 7a 66 01 || kind || scope || records` itself (contract v2 section 7).
- The lobby's BOLT 1 `warning` sends. The transport sends the warning for a refusal.
- `GZ_NOTE_CLOSE` and `GZ_NOTE_SEATED` (slice1-attempt item 13). The lobby's other notices stay, as view notices for P6.
- The lobby's `part` code (`gz_part_*`): the transport splits and reassembles.
- The signing engine's envelope parsing of SEND bytes.

**Saved messages stay envelopes** (`journal.md` 9: tag, kind, scope, records). `core/gazpacho/envelope.h` gives `gz_env_join(kind, scope, records, out)` and `gz_env_split(envelope, &kind, scope, &records)`, so resends stay byte for byte.

## 7. Shared state

### 7.1 Timers

- An engine sets timers with its own ids, each below 2^32. The lobby's are `0x4c000001` to `0x4c000006`; the signing engine's is `0x5347`; the funding engine has one tick timer and keeps its deadlines in records (A18).
- After each engine call the composite rewrites the engine's SET_TIMER and CANCEL_TIMER ids: area in the top 16 bits, the slot's **generation** in the next 16 (0 for node-wide engines), the engine's id in the low 32. Area 0xffff is reserved (the program's test timers live there).
- On TIMER_FIRED it decodes the id and passes the low 32 bits to that engine and slot. An id whose slot generation is not in use is dropped.
- When a slot is closed (its lobby instance freed) the composite appends a CANCEL_TIMER for every timer id it rewrote for that slot and has not seen fire or cancelled. So a later lobby never gets an earlier lobby's timer, even within one incarnation.
- An engine id at or above 2^32 is a bug (fatal).
- The program's table holds 64 timers. Budget: lobby 6 per slot (48 for 8 slots), node part 2 (the unbound-connection idle timer, and the continuation timer of 8.3), signing 1, funding 1, API 2, test 4 each (8 with two test engines): 62. A static assertion keeps the sum at or below 64. Each slot added costs 6 more timers, so raising `GZ_NODE_MAX_SLOTS` means raising the table (R8).

### 7.2 Watches

- The composite keeps a registry: for each (WATCH_TX, txid) or (WATCH_OUTPOINT, outpoint), the engines that asked and the largest depth asked.
- The first request issues the action. A later request with a larger depth issues it again with that depth. Other repeats issue nothing.
- Reports go to every engine in the set. Each engine ignores what it no longer needs.
- The registry is memory only. Rule 4 makes every engine set its watches again at start.
- In Slice 1 only the funding engine watches. The registry is kept, small, because channels and exits will share outpoints with funding; P4.1 tests it with the two test engines.

### 7.3 Storage

**Records are already namespaced** by area (the high 16 bits of a type). The composite adds: **each record type has exactly one writer**, the engine that makes its bytes.

| Area | Writer | Read by (at load) |
|---|---|---|
| Node 0x0004 | the node part: `key_epoch`, `key_index`, `restored`, `guard`, `slot_opened`, `slot_closed` | node |
| Lobby 0x0001 | the lobby engine | lobby (per scope, Open slots only); node (read only: `lobby_ended`, for tombstones) |
| Round 0x0002 | the signing engine | signing; funding (read only: `round_proposal`, `exposure`, `round_completed`, `ack_received`, `round_ended`) |
| Funding 0x0003 | the funding engine, including `funding_status` on the member | funding |
| Local API 0x000d | the API part (P6) | API |
| Test 0x7e57, 0x7e58 | the test engines | test |

- **`guard`** is made by the node part. The signing engine only places it, through its `guard` hook, in the batch of each `round_started` (A17).
- **The signing engine stops writing `funding_status`** (`0x00030006`). The ack tip is already field 8 of `round_completed`. The funding engine starts the member's funding deadline from it, and its first `funding_status` is the one `journal.md`'s anchored-batch note refers to (that line is updated in P4.5).
- A record of an area no engine reads is refused at load with `GZ_ERR_CORRUPT`: every Slice 1 type is even.

**Every Lobby record carries its scope** as its first field (owner decision; there are no legacy journals). The load routes each Lobby record by scope to the slot's lobby. No record belongs to a slot by position. This lands in P4.2 with the lobby's TLV fields (`journal.md` open point 3 is settled for the Lobby area there).

**Two new Node records** (registered in `journal.md` 9 by P4.2):

| Type | Record | Contents | Saved |
|---|---|---|---|
| `0x0004000c` | `slot_opened` | serial (`u32`), scope (32), role, host key (33), host address, key epoch (`u32`), key index (`u32`, the pair's first) | In the slot's first batch, with `key_index` and `guard` (7.5) |
| `0x0004000e` | `slot_closed` | serial, final state (`u8`: 0 never joined, then the lobby states 4 Funding, 5 Active, 6 Cancelled, 7 Failed), reason (`u16`) | In the batch that ends the lobby, makes the factory live, or gives the slot up |

**Each engine reads through a filtered reader.** The composite walks storage once and dispatches each record, in journal order, to the engines that read its area, with its batch id.

### 7.4 Atomic hand-offs: the bracket

Atomicity is a mechanism of the composite, not a convention of the engines (A3).

- `core/node/handoff.c` makes every cross-engine call inside a **bracket**: it records the list's length before the call, makes the calls of that hand-off (one engine calling the next through the composite's hooks), and closes the bracket.
- On closing, every SAVE appended inside the bracket is merged into **one SAVE at the position of the first one**. Records keep their order. The primitive is `gz_action_list_merge_saves(list, from, to)` in `core/gazpacho/action.c`.
- **Why moving a save earlier is always safe.** A send waits for every save before it. Moving a later save ahead of a send only makes that send wait longer; it never lets a send overtake its own save. Contract v2 forbids saving "sent" records, so no save depends on a send having been released. Timers, watches, CANCEL_TIMER, DISCONNECT and SET_SEATED that end up after the merged save are only delayed, which is always allowed.
- **In test builds** the composite also checks that no outward action sat between two saves of one bracket before the merge, and fails loudly if one did. That catches an engine that sends before it saves, which the merge would hide by delaying the send.
- Within one engine's own step (no hand-off), the composite merges adjacent saves only. Engines that need atomicity across two of their own saves put the records in one SAVE themselves.

The brackets, and the one batch each makes:

| Bracket | Records, in order | Why one batch |
|---|---|---|
| Restore (start) | `key_epoch`, `restored`, `guard` | Node rule 5: alone and first |
| Slot open, host | `key_index`, `guard`, `slot_opened`, `lobby_opened` | The factory key's index before the key is used; the slot and its lobby together |
| Slot open, member | `key_index`, `guard`, `slot_opened`; then CONNECT | The key is saved before the handshake shows it. `terms_received` comes later, after the host's `terms_offer` (A6) |
| Attempt, host | `funding_plan`, `round_started`, `round_proposal`, `guard` | The plan before `round_started`; the guard with every `round_started` |
| Outcome Funding, host | `ack_received` (last), `lobby_state` Funding (and, with `host_funding` AUTO, `funding_signed`) | Rule 2. H1 has passed before the bracket (14) |
| Outcome Retry or Failed, host | `round_ended`, `lobby_state` Open, or `lobby_ended` Failed and `slot_closed` | Rule 2 |
| Outcome Retry with understudies, host (9.6) | `round_ended`, `start_sent` for attempt n + 1, `funding_plan`, `round_started`, `round_proposal`, `guard` | The new attempt starts in the step that ends the old one |
| Funding awaiting the person, host (CONFIRM) | `ack_received` (last), `lobby_state` Funding, `funding_status` "awaiting confirmation" | R10 |
| Outcome, member | `round_completed` with the ack, `lobby_state` Funding; or `round_ended`, `lobby_state` Open | Rule 2, on the member too (B2) |
| Cancel in flight, host | `lobby_ended`, `round_ended` failed, `slot_closed` | A9: a cancel never leaves a round running |
| Cancel received, member | `lobby_ended`, `slot_closed` (the signing engine erases its secret nonces in memory and keeps its records) | 6.10 |
| Live | `funding_status` buried, `round_ended` live (member), `lobby_state` Active, `slot_closed` | One step: C11, the round resolved, Active, the slot closed |
| Dead or abandoned | `funding_status`, `round_ended` dead or abandoned, `lobby_ended`, `slot_closed` | The same |
| Command (P6) | `request_id`, the action's first save | Contract v2 section 11 |

The host's `start` hand-off is two batches, and need not be one. The lobby saves `start_sent` and sends the starts; the attempt bracket follows. Journal order gives a prefix after any crash: `start_sent` without a round means "begin again" at resume, which is safe because the signing engine has saved nothing for that check.

### 7.5 Confirmations

- The composite keeps a queue, in submission order, of a bit mask per SAVE it returned: the engines whose records are in it. Confirmations arrive in order (`runner.h`), so the head of the queue says who gets each STORAGE_CONFIRMED.
- **Confirmations are per merged batch.** No engine may assume one confirmation per SAVE it emitted. The test engine counts batches, not saves.
- During the start, a batch made in signing's resume or a repair can hold a lobby's records while that lobby is loaded but not yet resumed. Its confirmation for that lobby is held by the composite and given after the lobby's resume, in order. The lobby uses no confirmations today, so this only keeps the rule simple for later engines (R4).

## 8. Errors

### 8.1 The engine rule

Added to `node.h` and `core/node/engine.h`:

> An engine returns an error only for a bug, or for exhausted fixed memory that its own caps should have prevented. A condition that a peer, the chain, the wallet port, the key port or a user command can cause is never an error. It returns `GZ_OK` with one of: a refusal (DISCONNECT `refused`, or a refusing message such as `round_abort`); an outcome (9.3); a counted drop; a notice (a view object, an attention item, a command result).

Known violations, each a task of the named step:

| Where | Today | Becomes | Step |
|---|---|---|---|
| `gz_sign_begin`: builder refuses, proposal does not encode | `GZ_ERR_ARGUMENT` | outcome Failed (deterministic: the frozen terms will not build) | P4.3 |
| `gz_sign_begin`: a round still Active | `GZ_ERR_ARGUMENT` | only one Active round **per scope** (H8); another scope may run. A second begin for the same scope is ignored | P4.3 |
| `gz_sign_begin`: `max_attempts` reached | `GZ_ERR_ARGUMENT` | `max_attempts` is removed: the budget is time (9.4) | P4.3 |
| `adopt` or `take_slot` finds no room (signing F2, F3) | `GZ_ERR_NO_SPACE`, `GZ_ERR_CORRUPT` at load | outcome Retry with nobody blamed for a new attempt; at load, resolved rounds kept on disk only (F2 and F3's fixes). **F2 and F3 are prerequisites of P4.3** | P4.3 |
| `gz_sign_resolve` on a round not found or already resolved | `GZ_ERR_ARGUMENT` | a counted no-op | P4.3 |
| The key hook returns 0 | none yet | as 2.5 | P4.3 |
| Wallet port `plan`, `sign`, `hold` fail (no coins, coins spent, wallet unreachable) | (new) | outcome Failed (cancel reason 3) with an attention notice; `release(plan)` | P4.5 |
| A list too small | `GZ_ERR_NO_SPACE` | impossible by sizing (8.3) | P4.1 |
| `host_fail` saves `round_ended`, sends the aborts, then reports | trips the test-build bracket check (7.4) | **reordered**: save, report (the outcome bracket), then the aborts. A named task, not only a rebase | P4.3 |

### 8.2 When an error happens

- **Fatal for the whole node.** The engines share one runner, one guard and one key table, so the others cannot carry on.
- **The composite rolls back the list** to its length before the call, so nothing of that step is submitted.
- **The composite poisons itself.** Every later call returns `GZ_ERR_FAILED`. `node.h` changes to say: "On any error other than `GZ_WAITING`, the node must not be used again; the program starts a new one from storage." The list is as it was; the node is not. This is how signing F1 (memory advanced past a refused step) is closed: never by retrying the event.
- **The program restarts from storage**, as today (`program.md` section 2). More than 5 restarts in 10 minutes exits 1. Because of 8.1, only a bug can reach that limit.
- **A log line** names the engine and status (`node-error engine=0x0002 status=...`).

### 8.3 Sizing the list

- Each engine declares its worst step as two constants: actions and bytes. The composite's `GZ_NODE_LIST_ACTIONS` and `GZ_NODE_LIST_BYTES` are the sum over the engines one event can reach, with a static assertion.
- **One state change per event (R3).** Each engine changes the state of at most one slot or one round per event. Everything else that is due waits for the next tick, round-robin:
  - the signing tick runs at most one round's deadline action (a failed step, an expired budget, Unfinished, Abandoned) and one round's resends;
  - the funding tick runs at most one factory's change (a deadline, a burial, a Dead); a NEW_TIP only records the tip and arms the tick;
  - a command that touches several slots (the pause of `local-api.md` 11.3) acts on one slot per call: the node part sets its continuation timer at 0 ms and goes on at the next turn of the loop;
  - an event reaches at most one slot's lobby (sections 3 and 5).
  So every engine counts once in the sum, whatever the number of slots and rounds. The delay this adds is at most one tick per waiting round or factory.
- **The lobby:** 256 actions, 512 KiB (a new current version to every seat).
- **The signing engine:** bounded per step, which P4.3 makes true (above). With round-robin, each round is visited once every `GZ_NODE_MAX_SLOTS` ticks, so `tick_ms` is set such that `GZ_NODE_MAX_SLOTS` × `resend_ticks` × `tick_ms` is below the shortest step timeout (60 s), with a static assertion (R12). Its memory is bounded: at most `GZ_NODE_MAX_SLOTS` Active rounds in full (about 0.5 MB each, with MuSig2 sessions); every other unresolved round is kept compact, its saved bytes and C10 outpoints only, at most 64 (R12). Its worst step is then one round's largest message to every member plus its saves: (`GZ_SIGN_MAX_PARTICIPANTS` − 1) × `GZ_SIGN_MAX_MSG` plus the records.
- **The funding engine:** one broadcast, a few watches, its records.
- **The node part and the brackets:** a few saves, CONNECTs for every slot at start (start steps are separate calls, 10).
- The program gives lists of this size and sizes its runner's held bytes to hold at least one full list, so a list is never refused for size.

## 9. Hand-offs and deadlines

### 9.1 The chain

```
host:    lobby --start--> funding.plan --> signing.begin --...--> outcome --> lobby + funding
                                                                    funding --H1, (confirm), broadcast, burial--> lobby (Active)
member:  lobby (accepted check) --> signing --...--> outcome (ack) --> lobby + funding
                                                                    funding --C11 live / dead / abandoned--> signing.resolve + lobby
later:   funding (live) --> channels (Slice 2)
```

Hand-offs live in `core/node/handoff.c`. Engines never call each other: each hook is a function pointer the composite fills, and each call is bracketed (7.4).

### 9.2 Each hand-off

**Host, lobby to signing (`begin`).** The bracket:

1. the funding engine's `plan(scope, check, participants, amount, script, previous)`: a new unbroadcast funding transaction, which spends an input of the previous attempt's if any partial signature was released (H11). It appends `funding_plan`. A wallet failure gives outcome Failed (8.1);
2. the adapter builds the `gz_tree_proposal_t` from the hand-off and the plan (slice1-attempt items 6 and 16);
3. `gz_sign_begin` with `budget_end_ms` (9.4). It appends `round_started`, `round_proposal`, `guard`, then `round_propose` to each member.

The signing engine's `retry` hook is always "no further attempt": every new attempt is the lobby's decision. After a Retry the lobby either starts attempt n + 1 under the same check with understudies (9.6), or goes back to Open for a new ready check.

**Member, lobby to signing.** `round_propose` may come before, after or without `start` (6.9, 7.2). The member's hand-off is a query:

- `gz_lobby_member_accepted(m, check_id, gz_lobby_handoff_t *out)` replaces `gz_lobby_member_may_sign`. It returns 1, and fills the whole hand-off (frozen records and signatures, pinned key, frozen digest and version, limits), **only** for the newest check the member answered, if it is not withdrawn (unready since), its newest saved `start` for that check (by attempt) does not have role 2, and that attempt is not spent (no saved outcome for it) (A8). A later `start` with role 1 for the same check, in a higher attempt, makes a standby that was not chosen eligible (9.6).
- The signing engine's builder calls it for the proposal's `check_id`, and checks the proposal only against what it returns (section 13).
- `begin` on the member saves nothing and sets nothing (keys come from the hook, 2.5). A `begin` for a (check, attempt) the engine finished is ignored (rule 3).

**Lobby to signing, `cancel` (A9).**

- Host: the person cancels (reason 2) while a round is in flight. The start deadline does not act once a start was sent; the budget governs then (9.4, R6). The bracket: `lobby_ended`, the signing engine's `round_ended` failed for that scope's Active round, `slot_closed`; then `cancel` to every seat and `round_abort` to the round's members.
- Member: a received `cancel`. The bracket: `lobby_ended`, `slot_closed`. The signing engine erases its secret nonces for that scope and keeps its records; a round with partial signatures out stays unresolved, so the slot is Closing (2.4).

**Lobby to signing, `member_left`.** Host only: a chosen seat's `leave` while Signing. While the leaving member still owes nonces or partial signatures, the signing engine treats it as silent at once: the attempt fails without waiting for a step timeout (the member is blamed), and Retry follows in one bracket. Once it has sent all its partial signatures, the round goes on; a missing ack still fails it at the step timeout, as today (R7).

**Signing to lobby and funding (`outcome`, both roles).** The hook fires on both roles. The adapter calls the slot's `gz_lobby_*_round_result`, then the funding engine, in one bracket. The full map is 9.3.

**Funding to signing and lobby.** On the member the funding engine decides C11 and C4(d) from chain facts, then calls `gz_sign_resolve` (live, dead, abandoned) and the lobby's round result. On the host, burial gives Active, and the host's funding deadline gives the abandoned path (14.3). Each is one bracket (Live, or Dead or abandoned, in 7.4).

**Later, funding to channels.** One more hook, `funding.live(outpoint, tree)`, called in the Live bracket.

### 9.3 Every outcome, mapped to a lobby result (A2)

| Signing or funding outcome | Host lobby result | Member lobby result |
|---|---|---|
| Host: every ack (round Done) | Funding (after H1, 14) | |
| Member: its own ack sent (round Complete) | | Funding |
| Attempt failed, members blamed (bad or missing nonces, partial signatures or acks; `member_left`) | Retry, blamed seats named | Retry (the start is spent) |
| Attempt failed, nobody blamed (no room, a refusal that may pass next time) | Retry, nobody blamed | Retry |
| Builder refusal at begin (deterministic) | Failed: cancel reason 3 | |
| Budget spent with a round in flight | Failed: cancel reason 3 | waits for the host's `cancel` |
| Member: Aborted, any reason (its own refusal, the host's abort, reason 3 after a restart, the key hook returning 0) | | Retry |
| Member: Unfinished (no result within the step timeout), or its ack refused (`may_ack` 0) | | Retry at once. The round stays unresolved for C10 and C11; the slot is still Open, so this does not block the next check (C10) |
| Member: Unfinished then Abandoned | | nothing more if the lobby has moved on; Retry if it is still Signing |
| Member: Complete then Abandoned (funding deadline passed) | | Failed (reason 4, below); slot closed |
| Dead (a funding input spent elsewhere and buried) | Failed (reason 4); slot closed | Failed (reason 4); slot closed |
| Host: its funding deadline passed (14.3) | Failed (reason 4); slot closed | |
| Live (funding buried) | Active; slot closed | Active; slot closed |
| Host abandoned (14.3), then the funding was buried before the spend-back | the factory is live: the funding engine takes it as Live (and hands it on in Slice 2); the lobby's history stays Failed, with a "funded late" notice | C11's late-funding rule: live if the member holds the whole tree and C5 and C8 pass again, else it stays abandoned; the same notice |
| Host abandoned, the spend-back buried | nothing more (already Failed); the plan's coins are back | Dead (C4(d)), if not already |

`messages.md` 6.10 gains cancel reason 4, "the funding did not confirm" (P4.5). The host sends it to every seat when its funding deadline passes or the funding is dead. A member that never gets it reaches the same result at its own deadline.

### 9.4 Who owns each deadline

| Deadline | Owner | Notes |
|---|---|---|
| Lobby deadline (start rule) | lobby | Set in every state up to Signing, again in `resume` and at Retry. A deadline already past fires at once (B4, A19) |
| Ready window, status pacing, join retries | lobby | As today |
| Idle and unbound connections (host) | node part | Section 3 |
| Signing budget, no round in flight (Open or a check after a Retry) | lobby | `GZ_LOBBY_TIMER_BUDGET`, armed only in these states; at expiry `cancel` reason 3 |
| Signing budget, a round in flight | **signing** | The hand-off carries `budget_end_ms` (Unix ms). At expiry the engine fails the attempt and reports Failed. A round Done has reported Funding and is past the budget's reach. A `begin` past the budget reports Failed at once. **The engine does not save `budget_end_ms`**: a restarted host fails every in-flight attempt (H13), so no round crosses a restart with a budget; whoever changes H13 must save it (A19) |
| Step timeouts, resends, member's unfinished deadline | signing | As today |
| Member's funding deadline (from the ack tip; 36 blocks in Slice 1, `terms.md`) | funding | Abandoned through `gz_sign_resolve` |
| Host's funding deadline, broadcast and rebroadcast, burial, C4(d) | funding | One tick timer; deadlines kept in records |

### 9.5 The four rules, and B1 to B4

| Rule or finding | Where |
|---|---|
| Rule 1, the budget | 9.4. Funding and Failed both come from the signing engine, in order, never both (B3). The remaining race, a person's cancel during a round, is the cancel bracket of 9.2 |
| Rule 2, the lobby saves the outcome | 9.2, 9.3, 7.4. The member gains `lobby_state` (`0x00010018`, now "Both"). Its `resume` skips a spent start (B2, fix (a)) |
| Rule 3, a finished check is ignored | The signing engine maps `check_id` to rounds through the saved `round_proposal`. A `begin` for a (check, attempt) whose round has ended, or is Done or Complete, appends nothing; a higher attempt under the same check is a new hand-off (9.6). The test world's stub asserts it (B2, fix (b)) |
| Rule 4, keys fixed | The host refuses a `join` from a key whose seat is chosen in the current attempt (B1), with seat state 7; it may join again after the outcome. Keys are found per round by scope (2.5), and a slot's keys never change. With understudies the rule holds **per seat**: each seat signs every attempt it is in with its own fixed keys; a dropped seat's round ends, and only then may it rejoin (9.6) |
| B4 | 9.4, first row |

### 9.6 Understudies (1.0.0)

Standby seats (lobby decision 1) that answered the ready check replace other seats automatically.

**At the ready check, a no-show.** Already the lobby's choice at the window's end: the answered seats, cut to the target in the order of the terms' signer-choice rule, include answered standbys after the seats ahead of them. The composite needs nothing new.

**Mid-signing, a member who drops.** The signing engine reports Retry with the blamed seats (9.3). In the same outcome bracket the host's lobby:

1. takes the chosen seats that were not blamed, and adds answered, unchosen seats in **standby order** (join order) until the target is met again;
2. checks every member's limits against the new set: each seat's `min_members` hint against the new count; a seat whose hint fails is dropped from the set, not forced, and the next standby is tried;
3. if at least `minimum` remain and the budget is not spent: saves `start_sent` for **attempt n + 1 under the same check**, with the new set, and hands off at once (the "Outcome Retry with understudies" bracket of 7.4). Every chosen seat gets a new signed `start` naming the attempt; the new funding plan follows H11; every participant makes fresh nonces (S2, a new round identifier);
4. otherwise it falls back to today's path: Open and a new ready check, or Failed if the budget is spent.

Each member re-checks the new set in its own builder: the member count against its conditions, the amounts and the fees of the rebuilt tree (C8). A member whose limits fail answers `round_abort` with the reason; the host blames it in that attempt and drops it, as above.

**What the composite and the hand-off need.**

- **A participant set that changes between attempts under one check.** The hand-off carries (check, attempt, participants). Rule 3 is keyed on (check, attempt). The signing engine already makes a new round per attempt.
- **The member's accepted record** follows the newest `start` for the check by attempt (9.2). A standby that got role 2 in attempt 1 and role 1 in attempt 2 is accepted for attempt 2. A member that got a start for attempt 1 and was dropped gets role 2 for attempt 2 and is not accepted.
- **AT_JOIN.** A per-lobby gate is opened for a check (scope and frozen digest), and the scoped secret lives until the check's last attempt ends, so an understudy attempt seconds later needs nobody to type anything (12.2).
- **Keys fixed per seat** (rule 4, B1). A standby signs with its own seat's keys, fixed since its join. A seat chosen in any attempt of the running check cannot rejoin until its round ends.
- **Standby order is saved** for the 1.0.0 receipts: `start_sent` gains the attempt number and, for each attempt, the chosen set and the standby queue (contribution keys, in order) at that moment. Every seat's join sequence is already in its `seat` record. A receipt can then sign "standby position k at attempt n".
- **Spec changes** (P4.7): `messages.md` 6.9, `start` gains `attempt` and the rule "a later attempt under the same check replaces the earlier `start`"; 6.8, standbys answer checks; 7.2's accepted-check rule follows the newest start. `journal.md` 9: `start_sent`'s new fields.

## 10. The stepped start

`gz_node_start` keeps `node.h`'s stepped contract. **One engine's resume per call.** A call either appends actions and returns `GZ_OK` with `*more` set, or appends nothing and returns `GZ_WAITING` (A12).

**Phase 1, load (no actions).** The first call takes the fence and walks storage once (7.3). Each engine's load order after the walk: node (epochs, highest index, guard counter, slots and their states), API (pause, settings), lobby (each Open slot, by scope), signing (rounds, exposures, known identifiers), funding (plans, statuses), test. Then:

- the composite derives each slot's state (Open, Closing, Free; 2.4);
- **the repair check**: for each Open slot whose lobby disagrees with the final outcome the signing or funding engine holds for its check (a lobby in Signing for an ended round, in Funding for a live or dead factory), the composite marks a repair. A repair is not an error. It is counted and logged (`repair scope=... outcome=...`), and tests assert that a normal run never needs one.

**Phase 2, resume.** In this order, each over one or more calls:

1. **Restore batch.** With the restore marker, the node part appends `key_epoch`, `restored`, `guard` alone (node rule 5).
2. **Pause** (`local-api.md` 11.3). A saved pause is applied before any CONNECT: a member slot that 11.3 makes leave gets its `leave`; nothing new is joined or readied; a held round runs to its end. A paused host runs no ready check.
3. **Node.** Re-binds nothing (connections come after the start). Re-arms its idle timer.
4. **Signing.** `gz_sign_resume`: a member answers per item (S2); a host fails every unfinished attempt (H13). Each outcome goes through 9.3's map to the slot's lobby (loaded, not yet resumed), in a bracket.
5. **Repairs.** For each repair marked in phase 1, the outcome is given again to the lobby through the idempotent `round_result`, in a bracket of its own.
6. **Lobbies**, one slot per call: SET_SEATED for every seat (host); CONNECT (member, Open and Closing slots); timers, the deadline in every state up to Signing (B4); the hand-off again with `resume` = 1 for a check still in Signing. The signing engine ignores a check it finished or holds as running.
7. **Funding.** Watches again; `hold(plan)` for every plan not released (14.2); a rebroadcast of a saved `funding_signed` not yet seen confirmed; the notice "confirm funding" again for a plan awaiting the person (12).
8. **Test.** The placeholder's resends.
9. **View** (P6, node rule 7). A NOTIFY for every view object.

**Why signing resumes before the lobby.** A restarted host must fail its unfinished attempt (H13) before the lobby re-hands the check. With signing first, the lobby sees the Retry and re-hands nothing.

The signing engine's `gz_sign_start` is split into `gz_sign_load` (per record) and `gz_sign_resume`. The lobby already has `restore` (per record) and `resume`.

## 11. A round outlives its lobby (A4)

### 11.1 The host

- A Closing slot's tombstone answers `hello` for its scope: `lobby_status` with the final state and reason (6.7), then the saved signed `cancel` if there is one. A member that lost the `cancel` with a connection learns it on reconnect. A member one block behind the host's burial gets Active, never "no such lobby".
- Round kinds under that scope still go to the signing engine (section 4), so `round_status_request` is answered with the saved results, or `round_abort` with the reason for a failed round (7.10, H12).
- SET_SEATED for the round's members stays until the slot is Free, so their reconnects are admitted.
- When the slot is Free (Live, Dead, or the deadlines plus the grace passed), late `hello`s are answered from the index of ended lobbies (2.4), and status requests still reach the signing engine by scope (H12).

### 11.2 The member

- Its CONNECT stands while the slot is Closing (2.4): a bounded time, ending at Live, Dead, or its own deadlines plus the grace. After Live, a member's link to that host is the channel engine's business (Slice 2).
- At each reconnect the signing engine resends its saved `round_partial_sigs` (if any) and sends `round_status_request` (7.10).
- Lobby kinds under a Closing scope are dropped: the lobby is over.
- When the slot becomes Free, the composite appends DISCONNECT `done`. By then the member's own rounds under the scope are resolved by its deadlines.

## 12. Configurable funding and signing

Both are settings, not protocol. The only message change is the `unready` reason "locked" (12.2).

### 12.1 Host funding: AUTO or CONFIRM

- **AUTO is the default and is on unless the host changes the setting** (owner decision). CONFIRM stays a setting.
- The setting in force is copied into each `funding_plan` when the attempt begins. A change later does not affect an attempt under way.
- **AUTO:** at the Funding outcome the funding engine runs H1, signs, saves `funding_signed` in the outcome bracket, and broadcasts.
- **CONFIRM:** at the Funding outcome the funding engine runs the parts of H1 that need no signature (every tree signature verifies, every ack, the plan equals the proposal's funding, every input segwit), saves `lobby_state` Funding and a `funding_status` with the new state "awaiting confirmation" (the funding engine's own record, R10), and emits an attention notice. The person confirms with a command (0x03xx, a fresh sign-in at the API, `local-api.md` 4.8). Then: sign, the full H1, `funding_signed`, broadcast. The host's funding deadline (14.3) keeps running; if it passes first, the abandoned path runs.
- After a restart the notice is emitted again (10, step 7).

### 12.2 Member signing: AUTO, WHEN_UNLOCKED or AT_JOIN

There are two kinds of **signing gate**, both in memory only, both closed at every start:

- **The node-wide gate.** Opened by an "unlock signing" command; closed by "lock signing", by the API's sign-out, and at every start.
- **A per-lobby gate**, one per slot. Opened by the person's own "ready" for that lobby, given with the passphrase. It carries what it was opened for: the scope and the current values digest the person readied for. It closes when that check's last attempt ends (the lobby leaves Signing for Funding, Open or its end; understudy attempts under the same check keep it open, 9.6), when the slot is freed, at every start, and on "lock signing".

The three settings:

| `member_signing` | Gate the slot uses | The person does |
|---|---|---|
| AUTO | none: always open | nothing after joining |
| WHEN_UNLOCKED | the node-wide gate | unlocks signing for a session |
| **AT_JOIN (the default, confirmed by the owner)** | that slot's per-lobby gate | enters the passphrase once, when marking ready in that lobby |

**AT_JOIN, "unlock once at join".**

- When the person marks ready with the passphrase, the program derives that lobby's two signing keys (contribution and factory, from the slot's epoch and index) and hands only those to the key port as a **scoped secret**: valid for that scope and that current values digest. The main wallet stays locked: no other key is derived or held.
- The key hook (2.5) returns the keys only if the round's scope matches and the round's frozen terms digest equals the one the gate was opened for. A proposal under other terms gets no keys (and is refused anyway by C8a).
- When the gate closes, the composite calls the key port's `forget(scope)`, which wipes the scoped secret. An understudy attempt under the same check keeps it (9.6). A new ready check after a Retry to Open needs the person to ready again (proposed; owner to confirm).
- The gate is a policy flag; the scoped secret is real key protection: with AT_JOIN the key port does not hold that lobby's keys before the person readies. Protecting keys at rest for WHEN_UNLOCKED is the key port's matter (P8).
- After a restart the per-lobby gate is closed and the scoped secret gone. The lobby treats the seat as locked (below) until the person readies again. A round with partial signatures out is held for signing (`local-api.md` 4.7); its `round_abort` and saved resends need no new secret.
- Key port addition: `scoped_secret(scope, terms_digest, factory_sec, contribution_sec)` and `forget(scope)`. The key hook reads the scoped secret first.

**Common rules for every gate.**

- **A closed gate takes the seat out of the count (R5).** The member's lobby gets a hook `may_answer(ctx, scope)`. When it returns 0 and the seat is Ready, the lobby sends `unready` with a new reason 3, "locked" (`messages.md` 6.5), at once and again when a `ready_check` arrives. It is not the person's own unready (lobby decision 15 does not apply), and the change limit never swallows it (B6). A notice says "unlock to take part". When the gate opens, the composite calls `gz_lobby_member_gate_opened()`, and the lobby sends `ready` again (before the freeze for the latest values; after it, the plain ready for the frozen version that 6.4 allows). So a host never runs a check that locked seats would make fail.
- **A check already answered runs to its end.** Closing the node-wide gate after the answer does not withdraw it. The key hook still returns the round's keys until that round ends, as `local-api.md` 4.7 and 11.3 already hold the lock and the pause for a round with partial signatures out ("held for signing"). This applies to the whole round, from the answer, so that a lock does not cost the other members an attempt.
- A proposal for a check answered while a gate was open is signed even if the node-wide gate is closed now. A proposal for a check not answered is ignored (13).

## 13. The member against a bad host

The member's engines refuse anything outside what the member accepted.

**Layer 1, the composite's gates** (P4.1 for the routing, P4.2 for the member's links; A15):

- No slot and no held round under the scope: dropped.
- The link must be the slot's link, or a held round's link. Otherwise dropped, and the connection refused.
- The scope must be an Open slot's (lobby kinds) or one under which a round is held or a check was answered (round kinds). Anything else is dropped and counted. No scope-zero message is taken.

**Layer 2, the accepted record.** The signing engine checks a proposal only against `gz_lobby_member_accepted` (9.2), never against what the proposal says of itself.

- A `check_id` it did not answer, that is withdrawn, not chosen (role 2) or spent: **ignored**, as 7.2's table says. No `round_abort`, which would hand a hostile host a signed answer for nothing (A8).
- An accepted check, but terms digests that differ from the frozen ones (C8a), the member's keys missing or twice (C7, S5), a participant count that does not match the shape, a value outside the member's limits (C8), or C7 or C10 failing against every lobby's records: `round_abort` with the reason. Nothing is signed.
- A tier result that names another member's final signature in place of the member's own (signing F6): refused.

**Layer 3, the funding engine.** It watches only the txid and inputs in the member's own `exposure` records, and decides C11 from chain facts alone. `factory_funded` is counted and ignored.

**Host faults.** Two current records under one version, a change after the freeze, or two proposals under one round identifier are saved as `host_fault`; the member leaves, or keeps the evidence. Nothing new is signed.

## 14. The H1 boundary

**Decision: the wallet exposes the spent scripts. H1 does not take the funding object.**

Why: a `gz_tree_h1` that took `gzt_funding` would make the core depend on `wallet/`. And `funding_plan` must hold "the coins it spends" anyway (`journal.md` 9), to run H1 after a restart and to rebroadcast.

### 14.1 The wallet port

`gz_wallet_port_t` (program-supplied, over `wallet/`):

- `plan(amount, script, must_spend, out_plan)`: the unsigned transaction and every input's (outpoint, amount, script);
- `sign(plan, out_tx)`: the signed bytes;
- `hold(plan)`: hold back the plan's coins again (after a restart; the wallet's hold is in its memory only) (A11);
- `release(plan)`: free the coins of a plan that will never be funded.

Every failure is an outcome, never an error (8.1). `wallet/` adds `gzt_funding_unsigned()` and `gzt_funding_prevout(f, i, &amount, script, &len)`.

### 14.2 H1, before the lobby saves Funding

At the host's Funding outcome, **before** the bracket that saves `lobby_state` Funding (A10), the funding engine runs `gz_tree_h1(signed, prevouts, tree, acks, proposal_funding)`. It checks:

- every tree transaction is signed and verifies;
- an ack from every chosen member;
- the signed transaction, without witnesses, equals **both** the funding in the saved `round_proposal` (record 18, what the members signed against) **and** `funding_plan` (A11);
- every input spends a segwit output, from the saved scripts (the host's own wallet's word, which is the host's own trust).

If H1 fails: the outcome to the lobby is Failed (cancel reason 3), `release(plan)` is called, an attention notice is emitted, and the slot closes. Nothing is broadcast.

Only the funding engine may emit BROADCAST. The composite knows each action's engine and treats a BROADCAST from any other engine as a bug (A11).

The fee rate of the funding transaction is the host's setting, default 0.1 sat/vB.

### 14.3 The host's funding deadline

- The host abandons a funding that is not buried by its own deadline: the latest member funding deadline the terms allow (36 blocks after the ack in Slice 1) plus the burial depth.
- At that point the lobby ends Failed (reason 4), `cancel` reason 4 goes to every seat, and the slot closes.
- To keep its coins safe, the host then spends one of the funding's inputs back to its own wallet. Once that is buried, every member's records for the factory end under C4(d).
- **Its fee is the minimum that can replace the funding** (R2): the funding's absolute fee plus the incremental relay fee times the spend-back's own size. With the funding at 0.1 sat/vB this is about 0.1 sat/vB above it, which keeps the owner's rule of always paying the lowest fee that works. If the funding has already left every mempool, the spend-back pays the host's ordinary rate (0.1 sat/vB).
- **An explicit exception to H16.** H16 forbids replacing the funding by fee to speed it up. Abandoning is the one case where the host replaces it on purpose, with a transaction that pays nothing to the factory. `safety-rule.md` H16 gains that sentence (P4.5).
- The funding engine watches the funding outpoint and the spend-back until one of the two is buried. Both results have rows in 9.3.
- With CONFIRM and a funding never signed, the spend-back (at the ordinary rate, nothing to replace) is still made at the deadline: it is the only way to end the members' records early under C4(d).
- A broadcast at 0.1 sat/vB that is slow to confirm is exactly the case this covers.

## 15. The code steps

Contract v2 named P4 as one pull request. It is split here into seven, each landing on `main` alone, green, with the handbook rebuilt where a chapter changed. Each test is a multi-process test in `tests/program/` on loopback with short timers, through the real runner and the storage in use (`program.md` section 8). Each shows by outcome: the happy path, a crash of each role at its worst point, a storage failure recovered in process, and a reconnect. **Every test also asserts that no `node-error` and no `repair` line appears**, unless the case is about them.

| Step | Contents | Depends on |
|---|---|---|
| **P4.1** | Contract v2's core changes (links, SEND and MESSAGE with kind, scope and records, CONNECT, DISCONNECT with `why`, SET_SEATED, BROADCAST_RESULT, WATCH_SCRIPT retired, rules 3, 6, 7, 8); the `node.h` error text; `envelope.h`; `core/node`: routing (section 4, layer 1 of 13), connection binding, timer packing with generations, the watch registry, brackets and merges, the confirmation queue, the two-phase start, rollback and poison, list sizing; the test engine; the simulator on the composite | P3 (PR 27) |
| **P4.2** | The lobby on the composite: the scope field in every Lobby record, links, kind and scope, DISCONNECT and SET_SEATED actions, `part` code removed, connection caps for unbound links moved to the node part, `slot_opened` and `slot_closed`, tombstones, `gz_lobby_host_unknown`, `gz_lobby_member_accepted`, `may_answer` and the signing gate, member `lobby_state`; B1 to B4; the budget as in 9.4; a test-only signing stand-in | P4.1, PR 30 |
| **P4.3** | The signing engine on the composite (PRs 32 to 36 rebased). **Prerequisites: signing F2 and F3 fixed.** Links from keys, `peer[]` gone, kind and scope, `gz_sign_load` and `gz_sign_resume`, the key hook, the outcome on both roles, `budget_end_ms`, one Active round per scope, `max_attempts` removed, begin refusals as outcomes, `resolve` no-op, finished checks ignored, the builder over `gz_lobby_member_accepted`, one state change and one round's resends per tick with the `tick_ms` assertion, compact unresolved rounds, **the reorder of `host_fail`** (8.1), `funding_status` no longer written, `cancel` and `member_left`; the host attempt bracket with a test funding plan | P4.2, PRs 32 to 36, F2, F3 |
| **P4.4** | The hostile-host test step: `--test-evil-host MODE` in the test build, and the long randomized run | P4.3 |
| **P4.5** | The funding engine (`core/funding`), the wallet port and accessors, H1 before the lobby's save, AUTO and CONFIRM, burial, C11, C4(d), both funding deadlines, cancel reason 4, the spend-back at the minimum replacement fee and H16's exception, late burial, the slot end conditions Live and Dead and the index of ended lobbies | P4.3, P7, wallet accessors |
| **P4.6** | Slice 1 end to end: on the local test chain, and on signet opt in | P4.5, P8 |
| **P4.7** | Understudies (1.0.0, a follow-up step): the lobby's attempt n + 1 under one check, eligibility re-check, `start` with `attempt`, `start_sent`'s new fields, the member's accepted record by newest start; the spec changes of 9.6 | P4.3, P4.5 |

### P4.1, `program_composite`

Plus contract v2's T1 `program_resend_on_connect`, T2 steps 1 and 2 `program_links`, and T7 `program_envelope`. A host and a member, each with two test engines (`--test-engines 2`, areas 0x7e57 and 0x7e58).

1. Both engines ping and get replies; each engine's records carry its own area; each engine's timer (both use id 1) fires only into its own engine.
2. A test command makes engine A save, set a timer, and hand off to engine B, which saves. One batch holds both records (`gazpacho --test-dump-journal`). Killed at every point around it (`--test-crash-after-save`, `--test-crash-before-confirm`), the restarted node holds both or neither. A variant where engine A sends between its saves trips the test-build check.
3. `--test-node-error-at` in engine B: the node restarts from storage; a call after the error in the same incarnation gets `GZ_ERR_FAILED` (a unit test); nothing of the failed step is in the journal.
4. A scope-valid lobby kind for a scope with no slot, from the member's host: dropped and counted on the member (A15). On the host, a member's `hello` for an unknown scope gets state 0, and 30 such `hello`s in a second get one answer a second.
5. Slot generations: a test command opens a slot whose engine sets a 10 s timer, closes it, opens another; the first timer never fires into the second.
6. Both test engines watch the same txid at depths 1 and 3: one watch, both get the reports.
7. A storage failure in the middle: one in-process restart; timers fire only after the new start.

### P4.2, `program_lobby`

One host process with two lobbies at once, three members, one of them in both lobbies, plus one member whose conditions refuse the terms. Signing is the test stand-in (`--test-sign-outcome funding|retry|failed|unfinished`, test build only).

1. Happy path in both lobbies at once: seats, ready check, freeze, `start`; the stand-in reports Funding; every lobby shows Funding. The member in both lobbies uses two keys and two links. The host's SET_SEATED precedes each member's first delivered message.
2. Crashes: the host killed after `start_sent` and before the starts leave; a member killed after `start_received`. Each restarts and the hand-off is called again, once.
3. The stand-in reports Retry, then the member restarts: it does not hand off its spent start (B2). The host restarted in Signing, then Retry, after the deadline passed during Signing: cancel reason 1 at once (B4).
4. A chosen member leaves in Signing and joins again with the same contribution key: refused (B1).
5. Budget: Retry, then the budget ends while Open: cancel reason 3 by the lobby.
6. The person cancels during a round: one batch with `lobby_ended`, the stand-in's `round_ended`, `slot_closed`.
7. A member with `member_signing` WHEN_UNLOCKED and the gate closed sends `unready` reason 3 and is not counted; unlocked, it readies again. A host whose minimum is met only with locked members never starts a check (R5). A member with AT_JOIN in two lobbies readies in one with the passphrase: only that lobby answers its check; after its round ends the scoped secret is gone (the test key port reports `forget`), and after a restart the lobby waits for the person again.
8. A hostile raw client sends an invalid `join` three times: closed with a warning (DISCONNECT `refused`). Seventeen silent connections: the oldest silent one is pushed out, a seated member is never refused.
9. A member that missed the `cancel` (dropped by `--test-drop-kind 34`) reconnects to the host's tombstone and ends Cancelled with the reason.
10. A storage failure and a reconnect: the member's `hello` gets the full state; nothing is saved twice.

### P4.3, `program_signing`

A host and three members, two lobbies at once on the host; funding from a test wallet port with fixed fake prevouts; no chain.

1. Happy path to every ack in both lobbies: Funding on every side, in the same batch as `ack_received` (host) or `round_completed` (member).
2. The host killed after `round_started` and before `round_propose` leaves: on restart it fails the attempt (H13); Retry; a new attempt completes.
3. A member killed after `exposure` and before `round_partial_sigs` leaves: it resends the saved bytes after `hello`; the round completes.
4. Signing F1's list: the host and a member killed at every save point of a round (`--test-crash-after-save N` for each N); every case ends in a restart with no partial signature sent without its exposure record (the host's log of received partial signatures against the member's journal).
5. A member killed in the nonce phase: it aborts (S2); the host retries without it, on a new funding outpoint (H11).
6. The budget ends in the nonce phase: Failed, cancel reason 3, no exposure.
7. A proposal without `start` (`messages.md` test 54, `--test-drop-kind 32`): the member signs, with the keys the hook finds.
8. Unfinished: the host withholds the tier result (`--test-withhold-result`): the member goes to Retry and answers the next check; the old round stays unresolved; the slot stays Open.
9. `round_status_request` after the lobby Failed: answered with `round_abort` and the reason (7.10, H12).
10. A finished check handed again (a host restart right after Funding): nothing new in the journal.
11. A storage failure on the host mid-round; a member reconnect in the partial-signature phase.
12. Eight lobbies on one host with their step deadlines due in one tick (`--test-same-deadline`): every round fails in turn over the next ticks, each in its own bracket, with no `node-error`; each round's resend interval stays below the step timeout (R3, R12).
13. A chosen member leaves after sending all its partial signatures: the round goes on; it fails only at the step timeout if the ack never comes (R7).

### P4.4, `program_bad_host`

One honest member against `gazpacho-test --test-evil-host MODE`. One CTest case per mode. In every case the member's journal holds no `exposure` record, no `round_partial_sigs` leaves it, and no `node-error` line appears.

- `wrong-scope`, `other-link`, `before-freeze`: round messages under another scope, on another connection, before any check was answered.
- `unanswered-check`, `withdrawn-check`, `not-chosen-check`, `spent-check`: a proposal for a check the member must ignore (A8).
- `changed-terms`, `other-key`: refused with `round_abort`.
- `two-proposals`: the second is evidence (`host_fault`).
- `foreign-final`: a tier result naming another member's final signature (signing F6).
- `after-close`: round messages after the slot closed and its rounds resolved.
- `cancel-after-partials`: a cancel after the member's partial signatures, then status requests: the member keeps the round and gets its answer (A4).
- `state-zero`: `lobby_status` state 0 in answer to `hello` while the member is in Funding: the member stays in Funding.
- `lying-funded`: `factory_funded` for a txid never broadcast.
- **`random`**: a long randomized run (default 10 minutes, a seed printed) of valid, malformed, replayed and reordered messages from a host that has the member's real keys and lobby. It asserts no `node-error`, no `repair`, and no signature on anything outside the accepted record.

The test file's header names, for each of `messages.md` tests 18 to 21, 26, 28, 31, 34, 37, 38, 52 and 53, the engine suite or the mode that covers it.

### P4.5, `program_funding`

A host and three members against the local test chain server (`ports/chain/tests/local_server.py`).

1. AUTO: every ack, H1, one broadcast, three confirmations; Active everywhere; the slot closed; C11 live.
2. CONFIRM: the host waits; the notice survives a restart; the person confirms; the funding goes out. A second run where the host's deadline passes first: abandoned, coins spent back.
3. The host killed after `funding_signed` and before the broadcast: it rebroadcasts. The host restarted with a plan held: `hold` is called and a send of the person's own cannot take those coins.
4. H1 made to fail (`--test-h1-break prevout`): no broadcast; lobby Failed reason 3; the plan released.
5. The wallet port reports no coins at plan time: outcome Failed with a notice, no `node-error`.
6. The host never broadcasts: each member's deadline passes: Abandoned, slot closed. The host's own deadline: reason 4 to every seat; the spend-back buried; members go Dead.
7. A member one block behind the host's burial reconnects: Active from the tombstone, then live by its own chain view.
8. A member killed while the funding confirms; a reorganisation that removes the funding before burial; a storage failure on a member at burial.
9. With `--test-max-tombstones 2`: five factories made live one after another, then a new lobby opens; late `hello`s for the oldest scopes are answered from the index (R1).
10. Abandon with the funding still in the mempool at 0.1 sat/vB: the spend-back replaces it (the local test server applies the replacement rule) and is buried; members go Dead. A variant where the funding is buried first: the host takes the factory as live with the "funded late" notice; members apply C11's late rule (R2).
11. A failed lobby: the host's slot leaves Closing at the members' deadlines plus the grace; a member that reconnects later still gets the final state and the `cancel` from the index.

### P4.6, `program_slice1` and `program_slice1_signet`

On the local test chain always, and on signet opt in (`GZ_LIVE_TESTS`), with the test coins and 0.1 sat/vB. A host with two lobbies, four members (one in both lobbies, one refusing), from `--role` to Active, then every process restarted once with nothing lost.

### P4.7, `program_understudies`

A host with target 3 and two standby seats, five members (three seats, two standbys), on the local test chain.

1. **A no-show at the ready check.** One of the three seats does not answer (`--test-no-answer`). The first answered standby is chosen in its place; the round completes; the factory goes live with that standby.
2. **A drop mid-signing.** A chosen member is killed after the nonces. The attempt fails with it blamed; in the same step the host starts attempt 2 under the same check with the first answered standby; every participant makes fresh nonces; the new funding plan follows H11 if partial signatures were out; the factory goes live. The journal's `start_sent` shows attempts 1 and 2 with the standby queue each time.
3. **A limit fails on the new set.** One remaining member's `min_members` hint is above the new count: it is dropped, not forced, and the next standby is tried; with none left and below `minimum`, the lobby goes back to Open.
4. **AT_JOIN members** across the swap: nobody is asked for the passphrase again within the check; a restart of the host during attempt 2 fails it (H13) and the lobby goes back to Open.
5. **The dropped member** restarts with its keys and tries to rejoin during the check: refused (B1); after the outcome it may join again.
6. A storage failure on the host between the two attempts' saves; the restarted host holds either both or neither (one bracket).

## 16. What the composite keeps open for host accountability

Signed seat receipts, the signer-choice rule in the terms, signed removal notices and signed lobby-wide counts are approved for 1.0.0. They are lobby work. The composite blocks none of them:

- **New lobby kinds** route without a change: the lobby range is 16 to 63 (the receipt is planned as kind 36).
- **New lobby records** (a member's saved receipts, event numbers in the host's records) are Lobby-area records with a scope field, written and read by the lobby engine. Nothing in the composite reads Lobby records except `lobby_ended` for tombstones.
- **Event numbers** are saved in the same record as the change they number, which the lobby does inside its own save; no cross-engine batch is needed.
- **`start` carrying counts and the rule** is the lobby's encoding. The member's check of the rule runs in the lobby on a role-2 `start`; its result is a lobby notice, and a breach is a `host_fault`.
- **Tombstones** keep room for each seat's last receipt and the removal notices, so a host can resend them after the lobby ended.
- **The signing engine** depends on the lobby only through `gz_lobby_member_accepted`; a role-2 check is already excluded there.
- **Standby order and attempts** are saved in `start_sent` (9.6), so receipts can sign standby positions and the signer-choice rule check can replay each attempt's choice.

## 17. For the owner

Decided since draft 2 (owner):

- **Host funding defaults to AUTO**, on by default; CONFIRM stays a setting (12.1).
- **Member signing defaults to AT_JOIN**, "unlock once at join": a per-lobby gate opened at ready, keys scoped to that lobby and its terms and wiped when the check's last attempt ends. AUTO and WHEN_UNLOCKED remain options (12.2).
- **Understudies in 1.0.0** (9.6, P4.7).
- **8 Open lobbies and 64 ended lobbies whose rounds are still held**, per wallet, as constants `GZ_NODE_MAX_SLOTS` and `GZ_NODE_MAX_TOMBSTONES` that can be raised later (2.4).

Still open, with the owner:

- **Within AT_JOIN, whether a new ready check after a Retry needs the person again.** Proposed: yes. Understudy attempts under the same check do not (9.6).
- **The grace after a failed lobby** before a slot is freed: proposed 6 blocks (2.4).

## 18. What changes on open branches

| Branch | Change |
|---|---|
| `program-skeleton` (PR 27) | Links the composite; lists and runner sized to `GZ_NODE_LIST_*`; DISCONNECT `why` mapped to `gz_peers_refuse` or `gz_peers_close_after_send`; a node error is fatal and the old node is never called again; `--test-engines`, `--test-dump-journal`, `--test-drop-kind`. Lands as P3 first, then takes P4.1 |
| `lobby` (PR 30) | B1 to B4 (9.5); the scope field in every record; actions instead of `GZ_NOTE_CLOSE`, `GZ_NOTE_SEATED` and warnings; kind, scope and records; `part` code removed; unbound-connection caps move to the node part; `gz_lobby_member_accepted`; `gz_lobby_host_unknown`; `may_answer` and `gate_opened`; member `lobby_state`; budget timer only with no round in flight; the deadline fires at once if already past. `docs/notes/lobby.md` decisions 3, 4, 12, 19, 20, 23 and 26 updated |
| `signing` to `signing-vectors` (PRs 32 to 36) | F2 and F3 first; `signing_node.h` replaced by the composite's engine ops; `gz_sign_load`, `gz_sign_resume`; the key hook in place of the engine-wide keypair; `peer[]` gone; the outcome on both roles; `budget_end_ms`; one Active round per scope; `max_attempts` gone; refusals as outcomes; `resolve` no-op; finished checks ignored; one round per tick; `funding_status` no longer written; `cancel` and `member_left`; `lobby_outcome.c` moves into `core/node/handoff.c` |
| `journal` (PR 29) | Nothing in the format. The program's storage feeds the composite's one walk |
| `spec/journal.md` | `slot_opened`, `slot_closed`; the scope field in every Lobby record; `lobby_state` kept by both; `funding_status` written by the funding engine only, and the anchored-batch note moved to its first write. P4.2 and P4.5 |
| `spec/messages.md` | Cancel reason 4 (6.10); unready reason 3 "locked" (6.5); the lobby kind range 16 to 63 (4.1); `start` with `attempt`, standbys answering checks, the accepted check by newest start (6.8, 6.9, 7.2). P4.5, P4.2, P4.7 |
| `spec/safety-rule.md` | H16's exception for abandoning. P4.5 |
| `docs/notes/contract-v2.md` | Section 17's P4 row points here; DISCONNECT's `why` in section 3. P4.1 |

## 19. Changes in draft 2

| Finding or decision | Change | Where |
|---|---|---|
| A1 errors as a kill switch | The engine rule; the table of violations as tasks; signing F2 and F3 prerequisites of P4.3; list sizing with a static assertion and one round per signing tick; the randomized hostile run; every test asserts no `node-error` | 8, 15 |
| A2 the CORRUPT cross-check | The full outcome map, per role; the check replaced by a counted, logged repair at resume | 9.3, 10 |
| A3 atomicity by adjacency | Brackets in `handoff.c` merge every save of a hand-off at the first save's position; why that is safe; a test-build check; P4.1 test 2 with a timer between the saves | 7.4, 15 |
| A4 a round outlives its slot | Closing slots; round routing by scope while rounds are held; the member's CONNECT kept; host tombstones; P4.2 test 9, P4.3 test 9, P4.4 modes, P4.5 test 7 | 2.4, 4, 11, 15 |
| A5 keys at `begin` only | A key hook per round, by scope; P4.3 test 7 | 2.5 |
| A6 the member's slot-open batch | `terms_received` later; `slot_closed` state 0 "never joined", with when it happens | 2.4, 7.3, 7.4 |
| A7 slot reuse in timer ids | Generations; the composite cancels a freed slot's timers; area 0xffff reserved | 2.4, 7.1 |
| A8 the accepted record | Newest answered check only, not withdrawn, not role 2, not spent; an unanswered check is ignored, as 7.2 says | 9.2, 13 |
| A9 `cancel` and `member_left` | Both wired, with their batches | 9.2, 7.4 |
| A10 a stuck host | H1 before the lobby's save; a host funding deadline; the spend-back; cancel reason 4 | 14, 9.3 |
| A11 H1 trust gaps | Compare with `round_proposal` record 18 and the plan; `hold(plan)` at resume; BROADCAST only from funding, enforced by the composite | 14, 6 |
| A12 `node.h` misquoted | `node.h` changed; the node poisons itself; one engine per start call | 8.2, 10 |
| A13 confirmations after merges | Per merged batch; only resumed engines own batches | 7.5 |
| A14 the hostile host's modes | Ten more modes, the randomized run, the `messages.md` test list, signing F1's crash list in P4.3 | 15 |
| A15 step order | Layer 1 in P4.1 and P4.2; P4.1 test 4 replaced | 13, 15 |
| A16 unknown-scope `hello` | Per-link limits in the node part | 3, 4 |
| A17 the `guard` writer | Made by the node part, placed by signing | 7.3 |
| A18 simplifications | The watch registry kept and tested; masks kept for the test engine and merged batches; funding uses one tick timer | 7.1, 7.2, 7.5 |
| A19 small omissions | Rule 7 in the resume order; why `budget_end_ms` is not saved; a past deadline fires at once; what pause suppresses; scope-zero `hello` with no listed lobby answers nothing | 9.4, 10, 3 |
| Owner: several lobbies | Slots with generations, Open and Closing; a scope in every Lobby record; connection binding on the host; one Active round per scope; C7 and C10 node-wide | 2.4, 3, 7.3 |
| Owner: accountability for 1.0.0 | What the composite keeps open | 16 |
| Owner: funding and signing configurable | `host_funding` and `member_signing`, the signing gate | 12 |
| Amendment: owner decisions | Host funding AUTO by default; 8 and 64 as raisable constants; the per-lobby gate, and AT_JOIN as the member default (confirmed by the owner) | 2.2, 2.4, 12, 17 |
| Follow-up: understudies (owner, 1.0.0) | Attempt n + 1 under one check with a changed set; limits re-checked, failing members dropped; keys fixed per seat; standby order in `start_sent`; P4.7 and its test | 9.6, 15 |
| Follow-up: AT_JOIN confirmed | The default; the scoped secret lives for the check's attempts | 1, 12.2, 17 |
| R1 Closing too long | Closing ends at Live, Dead, or the members' deadlines plus a grace; the cap frees early instead of refusing; an index of ended lobbies answers late `hello`s; H12 by scope without slots; live factories hold no slots; P4.5 tests 9 and 11 | 2.4, 11, 15 |
| R2 the spend-back | The minimum replacement fee; H16's exception; watched until one is buried; late-burial rows; kept for CONFIRM; P4.5 test 10 | 14.3, 9.3 |
| R3 events touching many slots | One state change per event per engine, the rest round-robin; the pause one slot per call; P4.3 test 12 | 8.3 |
| R4 confirmations during the start | Held for a lobby until its resume | 7.5 |
| R5 locked members | `unready` reason 3 "locked", `ready` again when unlocked; P4.2 test 7 | 12.2 |
| R6 deadline in flight | Removed from the cancel bracket | 9.2 |
| R7 `member_left` | Blamed only while it owes nonces or partial signatures; P4.3 test 13 | 9.2 |
| R8 timers | The node part's 2 counted; 6 per slot added | 7.1 |
| R9 hook and gate | The hook never looks at a gate | 2.5 |
| R10 CONFIRM's record | `funding_status` "awaiting confirmation" in the bracket | 12.1, 7.4 |
| R11 the AUTO default | Stated in 1, 12.1, 17 | 1, 12.1, 17 |
| R12 signing memory and resends | Active rounds in full, the rest compact (64); the `tick_ms` assertion | 8.3 |
| `host_fail` reorder | A named P4.3 task | 8.1, 15 |
