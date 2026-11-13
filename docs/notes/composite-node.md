# The composite node (contract v2, step P4)

Draft 1, 2026-11-13. This note fixes how the engines sit behind the one node interface, `gz_node_start` and `gz_node_handle`. Today that node is the placeholder ping. Slice 1 needs a lobby, a signing engine and a funding engine behind it, and later channels and exits. The Slice 1 attempt (`docs/notes/slice1-attempt.md`, item 1) glued them together outside the node. This note replaces that glue with a design a builder can code without further decisions.

Read against: `docs/notes/contract-v2.md` (P4 and sections 1 to 3, 7, 9 to 11); `docs/notes/program.md` on `program-skeleton` (PR 27); `core/gazpacho` `node.h`, `runner.h`, `action.h`, `event.h`, `ports.h` on `main`; `lobby.h`, `lobby_handoff.h` and `docs/notes/lobby.md` on `lobby` (PR 30, head `8915ae5`); `signing.h`, `signing_node.h`, `signing_outcome.h`, `signing_node.c` and `lobby_outcome.c` on `signing-vectors` (PR 36, stacked on PRs 32 to 35); `spec/messages.md`, `spec/journal.md`, `spec/signing-round.md`, `spec/safety-rule.md`; `docs/notes/slice1-attempt.md` items 1, 12, 13 and 17; reviewer B's review of PR 30 (findings B1 to B4).

## 0. The decisions in one table

| # | Question | Decision | Section |
|---|---|---|---|
| 1 | Where the composite lives | A new library, `core/node`, that implements `gz_node_init`, `gz_node_start` and `gz_node_handle`. `core/gazpacho` keeps the contract only. The placeholder ping becomes the **test engine**, built only into test builds | 2 |
| 2 | Engine identity | Each engine is named by its **journal area**: Lobby 0x0001, Round (signing) 0x0002, Funding 0x0003, Node 0x0004, Local API 0x000d, Test 0x7e57. The same number names its records, its timers and its commands | 2 |
| 3 | How many lobbies | One **slot** in Slice 1: at most one lobby in progress per data folder. The signing and funding engines are node-wide | 2, 14 |
| 4 | Links | `gz_link_t` everywhere. A link is **derived from keys, never stored on its own**: host to member is (host key, contribution key); member to host is (contribution key, pinned host key). `peer[]` and every `uint64_t` peer id go | 3 |
| 5 | Message routing | By **kind** to an engine family, then by **scope** to the slot, then the **link** is checked against the slot. Peer events go to every engine in a fixed order | 4, 5 |
| 6 | Actions | Engines emit contract v2 actions directly: SEND with kind, scope and records; CONNECT; DISCONNECT (with a `why`); SET_SEATED. `GZ_NOTE_CLOSE` and `GZ_NOTE_SEATED` go. **A refusal is DISCONNECT with `why` refused, never a SEND** | 6 |
| 7 | Timers | Engines use their own ids below 2^32. The composite rewrites every SET_TIMER and CANCEL_TIMER id to area, slot and id packed in 16, 16 and 32 bits, and strips it on TIMER_FIRED. No engine can fire another's timer | 7.1 |
| 8 | Watches | A registry in the composite: one chain watch per (kind, txid or outpoint), reports fanned out to every engine that asked | 7.2 |
| 9 | Storage | Records are namespaced by area already. **Each record type has exactly one writer engine.** Each engine reads its own area, and may read named areas of others, read only | 7.3 |
| 10 | Atomic hand-offs | **Adjacent saves in one step are merged into one batch.** An engine that hands off calls the next engine right after its own save and before its own sends. The outcome of a round, and the factory going live, are each one batch | 7.4 |
| 11 | Start order | Two phases. **Load** (records into memory, no actions): node, API, lobby, signing, funding, test. **Resume** (actions): restore batch, pause, node, signing, lobby, funding, test | 8 |
| 12 | Hand-offs | lobby → funding plan → signing (host); lobby → signing (member); signing → lobby and funding (outcome, both roles); funding → signing and lobby (live, dead, abandoned). Each deadline has one owner (table in 9.3) | 9 |
| 13 | Coordinator's four rules | Applied: signing alone owns the budget once a round is handed; the lobby saves the outcome, on both sides; a hand-off of a finished check is ignored; a chosen seat's keys are fixed until its round ends | 9.4 |
| 14 | Fatal errors | Any engine error is fatal for the **whole** node. The composite rolls the list back to its length before the step and returns the error. The program restarts from storage, as today | 10 |
| 15 | Bad host | The member's composite gates every message by link, scope and slot state. The member's signing engine checks a proposal only against the **accepted record** the lobby gives it, never against the proposal's own claims | 11 |
| 16 | H1 | **The wallet exposes the spent scripts.** H1 stays a pure `core/tree` function over data. The funding engine gets the coins through a wallet port, saves them in `funding_plan`, and runs H1 before BROADCAST | 12 |
| 17 | Code steps | P4.1 to P4.6, each with its multi-process test in `tests/program/` | 13 |

## 1. What is given

The coordinator decided four rules before this note. They are applied throughout and gathered in 9.4.

1. Once the lobby hands a round to the signing engine, the signing engine alone owns the signing budget.
2. The lobby saves the signing outcome.
3. Handing the signing engine a check it already finished is ignored, so the hand-off is idempotent.
4. A chosen seat's keys are fixed until its round ends.

Contract v2 already decided the types this note uses: `gz_link_t`, SEND and MESSAGE_RECEIVED with kind, scope and records, CONNECT, DISCONNECT, SET_SEATED, `GZ_CHAIN_BROADCAST_RESULT`, node rules 3, 6, 7 and 8. This note does not change them, except one appended field on DISCONNECT (section 6).

## 2. Shape

### 2.1 Where the code lives

- `core/gazpacho` keeps the contract: types, actions, events, ports, runner, `command.h`. Its `node.h` loses the placeholder. The node's three functions are declared there and implemented elsewhere.
- **`core/node`** (new, library `gazpacho_node`) implements `gz_node_init`, `gz_node_start` and `gz_node_handle`. It depends on the contract and on the engine libraries. No engine depends on it. The isolation check covers it like any core library.
- The placeholder ping moves to `core/node/test_engine.c` as the **test engine**. It is compiled only with `GZ_TEST_KINDS`, like kind 32767. The simulator and `program/` link `gazpacho_node`.

### 2.2 The node

```c
/* core/gazpacho/include/gazpacho/node.h after P4.1 */
typedef struct gz_node gz_node_t;            /* opaque; gz_node_size() bytes, caller-allocated */
size_t gz_node_size(void);

typedef struct {
    int host;                                /* 1: host, 0: member; fixed per data folder */
    const secp256k1_context *secp;           /* with a non-aborting illegal callback */
    gz_key_port_t keys;                      /* per-lobby keys and the host key (2.4) */
    gz_wallet_port_t wallet;                 /* host funding (12); all NULL on a member */
    gz_lobby_crypto_t crypto;                /* the lobby's signing port, over `keys` */
    uint32_t test_engines;                   /* test builds only: how many test engines (0, 1 or 2) */
} gz_node_config_t;

gz_status_t gz_node_init(gz_node_t *n, const gz_ports_t *ports, const gz_node_config_t *cfg,
                         uint64_t incarnation);
/* As today: the stepped start (section 8) and one event at a time. */
gz_status_t gz_node_start(gz_node_t *n, const gz_storage_reader_t *storage,
                          gz_action_list_t *out, int *more);
gz_status_t gz_node_handle(gz_node_t *n, const gz_event_t *ev, gz_action_list_t *out);
```

The program's loop does not change. It still calls these three functions and submits the list.

### 2.3 Engines and the slot

Inside the composite each engine has the same small interface (`core/node/engine.h`, internal):

```c
typedef struct {
    uint16_t area;                         /* its journal area: also its timer and command tag */
    const uint16_t *reads; size_t n_reads; /* areas its load reads, its own first */
    gz_status_t (*load)(void *e, const gz_record_t *rec, gz_batch_id_t at);  /* memory only */
    gz_status_t (*resume)(void *e, gz_action_list_t *out, int *more);       /* the start's actions */
    gz_status_t (*handle)(void *e, const gz_event_t *ev, gz_action_list_t *out);
} gz_engine_ops_t;
```

| Engine | Area | Instances | Wraps |
|---|---|---|---|
| Node (keys, guard, slots, restore batch) | 0x0004 | 1, part of the composite | new, `core/node/keys.c` |
| Local API (pause, request ids, conditions) | 0x000d | 1, part of the composite | P6; in P4 only the pause |
| Lobby | 0x0001 | one per slot | `gz_lobby_host_t` or `gz_lobby_member_t` (PR 30) |
| Signing | 0x0002 | 1 | `gz_sign_t` (PRs 32 to 36) |
| Funding | 0x0003 | 1 | new in P4.5, `core/funding` |
| Test | 0x7e57 (and 0x7e58 for a second one) | 0 to 2, test builds | the placeholder ping |
| Later: channels, exit, watch | 0x0005, 0x0007, 0x0008 | per factory, or 1 | Slice 2 and 3 |

**A slot** is one lobby in progress: its scope, the lobby engine instance, and the keys it uses. Slice 1 has one slot (`GZ_NODE_MAX_SLOTS` 1; owner question 1). The signing and funding engines are node-wide because their safety records span every lobby: C7's exposure records and C10's unresolved outpoints must be checked across all of them.

A slot opens when the host opens a lobby, or the member accepts an invitation. It closes when its lobby ends (Cancelled, Failed, left, removed) or when its factory is live (the member's C11, the host's burial). After it closes, the signing and funding engines keep their records of that factory; the lobby instance is freed.

### 2.4 Keys

The composite's node part owns key allocation, because the guard must ride in the same batch as every `key_index` and every `round_started` (`journal.md` 8.3).

- `gz_key_port_t` (program-supplied): `pub(epoch, index, pub33)`, `secret(epoch, index, sec32)` (the caller wipes it), `host_pub(pub33)`. P4 implements it over the stand-in key file; P8 derives from the seed (contract v2 section 13).
- Opening a slot allocates an index pair (contribution key at i, factory key at i + 1) and saves `key_index` and `guard` in the slot's first batch. The host does the same for its own factory key in a lobby.
- The lobby gets public keys and signs through `gz_lobby_crypto_t`, which the composite implements over the key port for the slot's pair.
- The signing engine gets the slot's secrets at the hand-off, through a new `gz_sign_set_keys(e, factory_sec, contribution_sec)`. They stay fixed until that round ends (rule 4) and are wiped when it ends.

## 3. Links

`gz_link_t` replaces every `uint64_t` peer id in events, actions and engines (contract v2 section 2). The rule is: **a link is derived from keys the engine already holds, never kept as a separate table.**

| Side | Speaking to | Link (local, remote) |
|---|---|---|
| Host | a member | (host key, the seat's contribution key) |
| Member | its host | (its contribution key for the slot, the pinned host key) |

Consequences:

- The signing engine's `peer[]` array goes. The host addresses participant j at (host key, participant j's contribution key). A member addresses only participant 0, the host. The other participants need no address (slice1-attempt item 11).
- The lobby's connection table keys connections by link instead of by peer id. The host's link table (hello limits) is already per key.
- A message on a link the receiving engine cannot derive is not for it (section 11).
- Several connections of one link never coexist (the transport replaces the older). So "the link" is enough to address a resend after a restart.

## 4. Routing messages

A MESSAGE_RECEIVED carries (link, kind, scope, records). The transport has already checked the protocol bytes, the direction, the record table, and reassembled parts. Kind 2 (`part`) never reaches the core. The composite routes in three steps.

**1. By kind, to an engine family.**

| Kinds | Engine |
|---|---|
| 16 to 34 | lobby |
| 64 to 80 | signing |
| 81 (`factory_funded`) | funding (a hint; the member counts it and acts on nothing) |
| 32767 | test (test builds only) |
| anything else | dropped and counted (the transport has applied the odd/even rule) |

**2. By scope, to the slot.**

- A lobby or round message whose scope is the open slot's goes to that slot (lobby) or to the signing engine with the slot named.
- Host, scope zero: only `hello` is valid. It goes to the slot's lobby, which answers with its listing (`messages.md` 6.1).
- Host, a scope with no open slot: a `hello` is answered by `gz_lobby_host_unknown()`, a small stateless helper in the lobby library that sends `lobby_status` with state 0 (6.1). Anything else is dropped and counted.
- Member, any scope other than the open slot's, including zero: dropped and counted. A Slice 1 member never browses.
- Signing, a scope whose slot has not reached the ready check: dropped and counted.

**3. The link is checked against the slot.**

- Member: the link must be the slot's link (section 3). Otherwise the message is dropped, and the connection is closed with DISCONNECT why `refused`.
- Host: a lobby message may come on any link; the lobby checks seats itself. A round message must come on a link whose remote key is a participant of a round the signing engine holds for that scope; the engine checks this, the composite does not.

`gz_sign_node_wants` (PR 36) is replaced by this table. Engines no longer test kinds themselves.

## 5. Routing other events

| Event | Goes to |
|---|---|
| PEER_CONNECTED, PEER_DISCONNECTED | every engine, in the order lobby, signing, funding, test. Order matters for the member's reconnect step: the lobby's `hello` is appended first, then signing's saved `round_partial_sigs` and `round_status_request` (`messages.md` 6, contract v2 rule 6) |
| TIMER_FIRED | the engine and slot named by the timer id's top bits (7.1); the engine gets its own id back |
| GZ_CHAIN NEW_TIP | every engine, same order |
| GZ_CHAIN TX and OUTPOINT reports | every engine registered for that txid or outpoint (7.2) |
| GZ_CHAIN BROADCAST_RESULT | the engine that issued the BROADCAST with that txid (the funding engine in Slice 1) |
| USER_COMMAND | by command code. `command.h` reserves a range per area: 0x01xx lobby (the object's local id names the slot), 0x03xx funding, 0x0dxx local API, 0x7exx test. An unknown code is answered with the command-result notice `unknown_command` |
| STORAGE_CONFIRMED | the engines whose records were in that batch (7.4) |

## 6. Actions and their mapping

Engines emit contract v2 actions directly. The composite rewrites only timer ids (7.1), merges adjacent saves (7.4) and dedupes watches (7.2).

| Engine emits | Contract action | Program does (P4, `program/net.c`) |
|---|---|---|
| a message | `SEND {link, kind, scope, records}` | `gz_peers_send` with the protocol tag and type 52791 added; split host to member |
| keep a connection (member, at slot open and at every start) | `CONNECT {host, address, key_epoch, key_index}` | connect after the save before it is confirmed; reconnect with the same key |
| refuse a peer | `DISCONNECT {link, why = GZ_DISCONNECT_REFUSED}` | `gz_peers_refuse`: BOLT 1 `warning` with a fixed text, then close |
| close an idle or unseated connection | `DISCONNECT {link, why = GZ_DISCONNECT_IDLE}` | `gz_peers_close_after_send` |
| stop keeping a connection (left, slot closed) | `DISCONNECT {link, why = GZ_DISCONNECT_DONE}` | `gz_peers_close_after_send` |
| a seat held, or no longer | `SET_SEATED {member, seated}` | `gz_peers_set_seated_key`, applied before the member's first message is delivered |
| a view change or a command outcome | `NOTIFY` (contract v2 section 11) | the view (P6); an output line before |

**DISCONNECT gains one appended field**, `uint16_t why` (`GZ_DISCONNECT_DONE` 0, `_REFUSED` 1, `_IDLE` 2, `_HOST_FAULT` 3). It chooses between the warning and a quiet close, and names the cause in the log. It changes nothing in the runner: DISCONNECT stays ordered, not outward.

What goes:

- The lobby's whole Lightning messages. The lobby encodes records and signs `msg_hash` over `67 7a 66 01 || kind || scope || records` itself (contract v2 section 7).
- The lobby's BOLT 1 `warning` sends. The transport sends the warning for a refusal.
- `GZ_NOTE_CLOSE` and `GZ_NOTE_SEATED` (slice1-attempt item 13). The lobby's other notices stay, as view notices for P6.
- The lobby's `part` code (`gz_part_*`): the transport splits and reassembles.
- The signing engine's envelope parsing of SEND bytes.

**Saved messages stay envelopes** (`journal.md` 9: tag, kind, scope, records). Two helpers in `core/gazpacho/envelope.h` (new, small) let an engine move between a saved envelope and a SEND: `gz_env_join(kind, scope, records, out)` and `gz_env_split(envelope, &kind, scope, &records)`. Resends are then byte for byte, as before.

## 7. Shared state

### 7.1 Timers

- An engine sets timers with its own ids, each below 2^32. The lobby's are `0x4c000001` to `0x4c000006`; the signing engine's is `0x5347`.
- After each engine call the composite rewrites the SET_TIMER and CANCEL_TIMER actions the engine appended: `id' = (uint64_t)area << 48 | (uint64_t)slot << 32 | id`. Node-wide engines use slot 0.
- On TIMER_FIRED it decodes the top bits, finds the engine and slot, and passes the low 32 bits. An id whose engine or slot is unknown (a slot closed meanwhile) is dropped.
- An engine id at or above 2^32 is a bug: the composite returns `GZ_ERR_ARGUMENT`, which is fatal (section 10).
- The program's table holds 64 timers. Budgets: lobby 8 per slot, signing 1, funding 4, API 2, test 4 each. A static assertion in `core/node` keeps the sum at or below 48.

### 7.2 Watches

- The composite keeps a registry: for each (WATCH_TX, txid) or (WATCH_OUTPOINT, outpoint), the set of engines that asked and the largest depth asked.
- The first request issues the action. A later request with a larger depth issues it again with that depth (the program replaces a watch with the same key). Other repeats issue nothing.
- Reports go to every engine in the set. Each engine ignores what it no longer needs.
- The registry is memory only. Contract v2 rule 4 already makes every engine set its watches again at start, so the registry is rebuilt by the resume phase.
- There is no "stop watching" action. A watch nobody needs any more ends at the next restart. Slice 1 watches a few txids per factory, so this costs nothing.

### 7.3 Storage

**Records are already namespaced**: the high 16 bits of a record type are its area (`journal.md` 9). The composite adds one rule: **each record type has exactly one writer.**

| Area | Writer | Read by (at load) |
|---|---|---|
| Node 0x0004 | the composite's node part: `key_epoch`, `key_index`, `restored`, `guard`, and two new records below | node |
| Lobby 0x0001 | the lobby engine | lobby (only the open slot's records) |
| Round 0x0002 | the signing engine | signing; funding (read only: `round_proposal`, `exposure`, `round_completed`, `ack_received`, `round_ended`) |
| Funding 0x0003 | the funding engine, including `funding_status` on the member | funding |
| Local API 0x000d | the composite's API part (P6) | API |
| Test 0x7e57, 0x7e58 | the test engines | test |

- **One change to the signing engine:** it stops writing `funding_status` (`0x00030006`). The ack tip it needs is already field 8 of `round_completed`. The funding engine starts the member's funding deadline from it.
- A record of an area no engine reads is refused at load with `GZ_ERR_CORRUPT`: every Slice 1 type is even (must be understood, `journal.md` 9.1).

**Two new Node records** (registered in `journal.md` 9 by P4.2):

| Type | Record | Contents | Saved |
|---|---|---|---|
| `0x0004000c` | `slot_opened` | slot number (`u32`, counting from 1), scope (32), role, key epoch (`u32`), key index (`u32`, the pair's first) | In the slot's first batch, with `key_index` and `guard`, and with `lobby_opened` (host) or the first `terms_received` (member) |
| `0x0004000e` | `slot_closed` | slot number, final lobby state (`u8`) | In the batch that ends the lobby or makes the factory live |

**Which lobby records belong to which slot.** Lobby records carry no scope today. With one slot open at a time, every Lobby-area record between `slot_opened` and its `slot_closed` belongs to that slot. At load the composite gives the lobby engine only the records of the slot still open. This is exact because only the lobby engine writes Lobby records and only while its slot is open. **Before `GZ_NODE_MAX_SLOTS` goes above 1, every Lobby record must gain a `scope` field** (a TLV field, once `journal.md` open point 3 fixes field numbers).

**Each engine reads through a filtered reader.** The composite wraps the start's `gz_storage_reader_t`. Each engine's `load` sees, in journal order, only the records of the areas it reads, each with its batch id. One pass over storage serves every engine: the composite walks it once and dispatches each record.

### 7.4 Batches across engines

**The merge rule.** In the list one step returns, two or more SAVE actions with nothing between them are merged by the composite into one SAVE. One SAVE is one journal batch, so its records become durable together or not at all. A send that waited for the last of them waits for the merged one, so the runner's rule is unchanged. A new helper does it: `gz_action_list_merge_saves(list, from_index)` in `core/gazpacho/action.c`.

**The hand-off rule.** An engine that hands off appends its own SAVE, then calls the next engine, then appends its own sends. The next engine appends its SAVE first. So the saves are adjacent and merge.

**Confirmations.** The composite keeps a queue, in submission order, of the engines whose records are in each SAVE it returned (a 16-bit mask per batch, `GZ_RUNNER_MAX_UNCONFIRMED` deep). Confirmations arrive in order (`runner.h`), so the head of the queue says who gets each STORAGE_CONFIRMED.

**The batches that cross engines in Slice 1:**

| Batch | Records, in order | Why one batch |
|---|---|---|
| Restore | `key_epoch`, `restored`, `guard` | Node rule 5: alone and first |
| Slot open, host | `key_index`, `guard`, `slot_opened`, `lobby_opened` | The factory key's index is saved before the key is used; the slot and its lobby begin together |
| Slot open, member | `key_index`, `guard`, `slot_opened`, `terms_received` | The same, and the key is saved before the CONNECT that shows it |
| Attempt, host | `funding_plan`, `round_started`, `round_proposal`, `guard` | `journal.md` 9: the plan before `round_started`; the guard with every `round_started` |
| Outcome Funding, host | `ack_received` (last), `lobby_state` Funding, `funding_signed` | The lobby saves the outcome (rule 2) in the batch that proves it; H1 runs before `funding_signed` is made (section 12); then BROADCAST |
| Outcome Retry or Failed, host | `round_ended`, `lobby_state` Open, or `lobby_ended` Failed | Rule 2. The `cancel` sends follow |
| Outcome, member | `round_completed` and the ack, `lobby_state` Funding; or `round_ended`, `lobby_state` Open | Rule 2, on the member too (B2) |
| Live | `funding_status` buried, `round_ended` live (member), `lobby_state` Active, `slot_closed` | One step: C11 decided, the round resolved, the lobby shown Active, the slot closed |
| Dead or abandoned (member) | `funding_status`, `round_ended` dead or abandoned, `lobby_ended`, `slot_closed` | The same |
| Command (P6) | `request_id`, the action's first save | Contract v2 section 11 |

The host's `start` hand-off is not one batch, and need not be. The lobby saves `start_sent`, sends the starts, then hands off; the funding plan and round records follow in the next batch. Journal order gives a prefix after any crash: `start_sent` without a round means "begin again" (`resume` = 1), which is safe because the signing engine has saved nothing for that check.

**Why the outcome must be one batch.** If `round_ended` were durable and the lobby's state were not, a restarted lobby would still say Signing for a check the signing engine has finished. Rule 3 makes the repeated hand-off a no-op, so the lobby would never learn the outcome. One batch makes this state impossible. The composite checks it at the end of load: a lobby in Signing whose check the signing engine has ended is `GZ_ERR_CORRUPT`.

## 8. The stepped start

`gz_node_start` keeps `node.h`'s stepped contract. Inside, it runs two phases.

**Phase 1, load (no actions).** The composite takes the fence, then walks storage once. Each record goes to the engines that read its area (7.3), in journal order. Load order for the engines' own setup after the walk: node (epochs, highest index, guard counter, slots), API (pause), lobby (the open slot), signing (rounds, exposures, known identifiers), funding (plans, statuses), test. Load never appends an action. Then the composite runs the cross-check of 7.4.

**Phase 2, resume (actions).** One engine at a time, each possibly over several calls (`*more`), in this order:

1. **Restore batch.** With the restore marker, the node part appends `key_epoch`, `restored`, `guard` alone, and the call returns with `*more` = 1 (node rule 5). The signing engine's own check for this (`signing_node.c`) moves into the composite.
2. **Pause.** A saved pause is applied before any CONNECT (contract v2 section 3).
3. **Node.** Nothing to send. It gives each later engine its keys: the slot's public keys to the lobby, the slot's secrets to the signing engine if a round with those keys is unresolved.
4. **Signing.** `gz_sign_resume`: a member answers per item (S2): Aborted or Unfinished, saved partial signatures resent later at reconnect. A host fails an unfinished attempt (H13). Each outcome goes to the slot's lobby (loaded, not yet resumed) through the outcome path of 9.2, in the same batch.
5. **Lobby.** `gz_lobby_*_resume`: SET_SEATED for every seat (host); CONNECT (member); its timers, including the deadline in every state up to Signing (B4); and the hand-off again with `resume` = 1 for a check still in Signing. The signing engine ignores a check it finished (rule 3) and a check it holds as running.
6. **Funding.** Watches again (funding txid to burial, each funding input); the host rebroadcasts a saved `funding_signed` whose txid is not yet seen confirmed.
7. **Test.** The placeholder's resends.

**Waiting.** If an engine's resume returns `GZ_WAITING` (it needs a confirmation first, `node.h` rule 3), the composite returns `GZ_WAITING`. The next call continues that same engine. Only the test engine waits today.

**Why signing resumes before the lobby.** A restarted host must fail its unfinished attempt (H13) before the lobby re-hands the check. Otherwise the lobby's `resume` = 1 would reach a round that is about to be failed. With signing first, the lobby sees the Retry outcome, returns to Open, and re-hands nothing.

The signing engine's `gz_sign_start` is split into `gz_sign_load` (per record) and `gz_sign_resume`. The lobby already has `restore` (per record) and `resume`.

## 9. Hand-offs and deadlines

### 9.1 The chain of hand-offs

```
host:    lobby --start--> funding.plan --> signing.begin --...--> outcome --> lobby + funding
                                                                         funding --broadcast, burial--> lobby (Active)
member:  lobby --start or accepted check--> signing --...--> outcome (ack) --> lobby + funding
                                                                         funding --C11 live / dead / abandoned--> signing.resolve + lobby
later:   funding (live) --> channels (Slice 2): the channel engine takes the factory from the funding engine
```

The hand-offs live in `core/node/handoff.c`. The engines do not call each other. Each engine's hook is a function pointer the composite fills.

### 9.2 Each hand-off

**Host, lobby to signing.** The lobby calls `signing.begin(handoff)` (`lobby_handoff.h`). The composite's adapter:

1. calls the funding engine's `plan(check, participants, amount, script, previous)`: a new unbroadcast funding transaction, which spends an input of the previous attempt's if any partial signature was released (H11). It appends `funding_plan`;
2. builds the `gz_tree_proposal_t` from the hand-off and the plan (slice1-attempt item 6 and 16);
3. sets the signing engine's keys (rule 4) and calls `gz_sign_begin` with `budget_end_ms` (9.3). It appends `round_started`, `round_proposal`, `guard` (merged with the plan), then `round_propose` to each member.

The signing engine's `retry` hook is always "no further attempt": every new attempt goes through the lobby (Retry, back to Open, a new ready check, a new start). So the lobby sees every attempt, and only one path makes one.

**Member, lobby to signing.** The member's signing engine may receive `round_propose` before, after or without `start` (`messages.md` 6.9, 7.2). So the member hand-off is a query, not a push:

- `gz_lobby_member_may_sign` is replaced by `gz_lobby_member_accepted(m, check_id, gz_lobby_handoff_t *out)`. It returns 1 and fills the whole hand-off (frozen records and signatures, pinned key, frozen digest and version, limits, own keys) only if the member answered that check and is still ready for it.
- The signing engine's builder calls it for the proposal's `check_id`, and checks the proposal only against what it returns (section 11).
- `begin` on the member then only sets the keys and notes the check; it saves nothing. A `begin` for a check the engine finished is ignored (rule 3).

**Signing to lobby and funding (both roles).** The signing engine's `outcome` hook fires on both roles now (it is host-only today). The adapter calls `gz_lobby_*_round_result` for the slot, then the funding engine. Each appends its save; they merge (7.4).

| Outcome | Host | Member |
|---|---|---|
| Funding (every ack / own ack sent) | lobby saves Funding; funding runs H1, signs, saves `funding_signed`, BROADCAST, watches | lobby saves Funding (B2); funding starts the funding deadline from the ack tip and watches the txid and the inputs |
| Retry | lobby saves Open with the failed seats; their keys are free again (rule 4) | lobby saves Open; its `start` is spent |
| Failed (the budget) | lobby ends with `cancel` reason 3 | waits for the host's `cancel` |

**Funding to signing and lobby.** On the member the funding engine decides C11 and C4(d) from chain facts, then calls `gz_sign_resolve` (live, dead, abandoned) and the lobby's round result (Active, or the lobby's end). On the host, burial gives Active. The batch is "Live" or "Dead or abandoned" of 7.4.

**Later, funding to channels.** When the channel engine arrives, the live factory moves from the funding engine to it, keyed by funding outpoint. This note fixes only the shape: one more hook, `funding.live(outpoint, tree)`, called in the Live batch.

### 9.3 Who owns each deadline

| Deadline | Owner | Notes |
|---|---|---|
| Lobby deadline (start rule, `terms.md`) | lobby | Set in every state up to Signing, again in `resume` and after Retry (B4) |
| Ready window, status pacing, idle and unseated closes, join retries | lobby | As today |
| Signing budget, before the first start | none | It begins at the first `start` (`start_sent` field) |
| Signing budget, no round in flight (Open or a check after a Retry) | lobby | `GZ_LOBBY_TIMER_BUDGET`, armed only in these states. At expiry: `cancel` reason 3 |
| Signing budget, a round in flight | **signing** | The hand-off carries `budget_end_ms` (Unix ms). At expiry the engine fails the attempt and reports Failed. A round already Done (every ack) has reported Funding and is past the budget's reach. `begin` past the budget reports Failed at once, saving nothing else |
| Step timeouts, resends, member's unfinished deadline | signing | As today |
| Member's funding deadline (from the ack tip) | funding | Resolves Abandoned through `gz_sign_resolve` |
| Host's funding broadcast and rebroadcast | funding | |
| Burial depth and C4(d) | funding | Through the watch registry |

### 9.4 The four rules, and B1 to B4

| Rule or finding | Where it is carried out |
|---|---|
| Rule 1, the budget | 9.3. The lobby's budget timer is disarmed when it hands a round off, and armed again only on Retry. B3's race is gone: Funding and Failed both come from the signing engine, in order, never both |
| Rule 2, the lobby saves the outcome | 9.2 and 7.4. The member gains `lobby_state` (`0x00010018`, now "Both" in `journal.md` 9.1) for Funding, Active and Open-after-Retry. The member's `resume` skips a spent start. This is B2's fix (a) |
| Rule 3, a finished check is ignored | The signing engine maps `check_id` to its rounds through the saved `round_proposal` (record 4 of `round_propose`). A `begin` for a check whose newest round has ended, or is Done or Complete, appends nothing. The test world's stub asserts it (B2's fix (b), both) |
| Rule 4, keys fixed | The host refuses a `join` from a key whose seat is chosen in the current attempt (B1's fix), with seat state 7. It may join again after the outcome. The composite sets the signing keys only at the hand-off and wipes them when the round ends |
| B4 | 9.3, first row |

## 10. Fatal errors

- **Any engine error is fatal for the whole node.** An engine call that returns anything but `GZ_OK` (or `GZ_WAITING` in the start) may have changed that engine's memory. The engines share one runner, one guard and one set of keys, so the others cannot carry on safely either.
- **The composite rolls back the list.** It remembers the list's `count` and `used` before the step and restores them before returning the error. So nothing of the failed step is submitted, and `node.h`'s promise ("on any error `actions_out` is exactly as it was") holds.
- **The program restarts from storage**, as today (`program.md` section 2): every connection closed, the timer table cleared, a new incarnation. Peers repair what was lost through the reconnect step.
- **A crash loop stops the program.** More than 5 restarts in 10 minutes exits 1, as today. The composite prints which engine failed and its status (`node-error engine=0x0002 status=...`), so the person or the tests can see it. An engine that fails at every start stops the whole wallet: that is deliberate, because a wallet that cannot run its signing engine must not keep showing lobbies as if all were well.
- **Not errors:** a command refused now (`GZ_NOTE_COMMAND_REFUSED`), a message dropped by routing, an outcome in the wrong state. These return `GZ_OK`.
- **Fatal in a hook.** An error returned by a hook (`begin`, `outcome`, `plan`) is the caller's error, and so fatal like any other.

## 11. The member against a bad host

The member's engines refuse anything outside what the member accepted. There are three layers.

**Layer 1, the composite's gates (before any engine).**

- The slot must exist. No slot: every message is dropped.
- The link must be the slot's link: (own contribution key, pinned host key). Anything else is dropped and the connection closed (DISCONNECT why `refused`).
- The scope must be the slot's. Anything else is dropped and counted. A Slice 1 member accepts no scope-zero message.
- A round message (64 to 80) is passed on only once the lobby has answered a ready check in this slot (`freeze` saved). Before that it is dropped and counted.

**Layer 2, the accepted record.** The signing engine checks a proposal only against `gz_lobby_member_accepted` (9.2), never against what the proposal says about itself. It refuses with `round_abort`, and signs nothing, when:

- the `check_id` was not answered, or was withdrawn (unready since);
- the terms digests differ from the frozen ones (C8a);
- the participant count differs from what the proposal's own shape fields need, or the member's keys are not in the list exactly once (C7 "fresh funding output", S5);
- any rebuilt value is outside the member's own limits (C8), or C7 or C10 fails against the exposure records of every lobby.

**Layer 3, the funding engine.** It watches only the txid and inputs named in the member's own `exposure` record, and decides C11 from chain facts alone. `factory_funded` (kind 81) is counted and ignored.

**Host faults.** Two current records under one version, a change after the freeze, or two proposals under one round identifier are saved as `host_fault`, and the member leaves (lobby) or keeps the evidence (signing). Neither makes the member sign anything new.

## 12. The H1 boundary

**Decision: the wallet exposes the spent scripts. H1 does not take the funding object.**

Why:

- `core/tree` is a core library. A `gz_tree_h1` that took `gzt_funding` would make the core depend on `wallet/`, the wrong way.
- The journal already says `funding_plan` holds "the coins it spends" (`journal.md` 9). The funding engine must save them anyway, to run H1 again after a restart and to rebroadcast.

What changes:

- `wallet/`: `gzt_funding_unsigned(f, &tx, &len)` (slice1-attempt item 16) and `gzt_funding_prevout(f, i, &amount, script, &script_len)` for each input. Read only; the private fields stay private.
- The funding engine (core, sans-I/O) reaches the wallet through `gz_wallet_port_t`, which the program supplies over `wallet/`: `plan(amount, script, must_spend, out_plan)` returns the unsigned transaction and every input's (outpoint, amount, script); `sign(plan, out_tx)` returns the signed bytes; `release(plan)` frees the coins of a plan that will never be funded.
- Before BROADCAST the funding engine runs `gz_tree_h1(signed, prevouts, tree, acks)`. H1 checks: every tree transaction is signed and verifies; an ack from every chosen member; the signed transaction is exactly the planned one (same txid); every input spends a segwit output (from the saved scripts). If H1 fails, no BROADCAST, a log line and an attention notice. The program's broadcast path accepts a funding transaction only from the funding engine.
- The fee rate of the funding transaction is the host's setting, default 0.1 sat/vB.

## 13. The code steps

Contract v2 named P4 as one pull request. It is split here into six, each landing on `main` alone, green, with the handbook rebuilt. Each test is a multi-process test in `tests/program/` on loopback with short timers, through the real runner and the storage in use (`program.md` section 8), and shows by outcome: the happy path, a crash of each role at its worst point, a storage failure recovered in process, and a reconnect.

| Step | Contents | Depends on |
|---|---|---|
| **P4.1** | Contract v2's core changes (links, SEND and MESSAGE with kind, scope and records, CONNECT, DISCONNECT with `why`, SET_SEATED, BROADCAST_RESULT, WATCH_SCRIPT retired, rules 3, 6, 7, 8); `envelope.h` helpers; `core/node` with the routing table, timer rewriting, watch registry, save merging, confirmation queue, two-phase start, rollback on error; the test engine (the placeholder, now hello and acknowledgement); the simulator on the composite | P3 (PR 27) |
| **P4.2** | The lobby on the composite: links, kind and scope, DISCONNECT and SET_SEATED actions, `part` code removed, `slot_opened` and `slot_closed`, `gz_lobby_host_unknown`, `gz_lobby_member_accepted`, member `lobby_state`; B1 to B4; the budget as in 9.3; a test-only signing stand-in | P4.1, PR 30 |
| **P4.3** | The signing engine on the composite (PRs 32 to 36 rebased): links from keys, `peer[]` gone, kind and scope, `gz_sign_load` and `gz_sign_resume`, `gz_sign_set_keys`, the outcome on both roles, `budget_end_ms`, finished checks ignored, the builder over `gz_lobby_member_accepted`, `funding_status` no longer written; the host hand-off adapter with a test funding plan | P4.2, PRs 32 to 36 |
| **P4.4** | The member's gates (layer 1 of section 11) and a hostile host in the test build (`--test-evil-host MODE`) | P4.3 |
| **P4.5** | The funding engine (`core/funding`), the wallet port and accessors, H1 before broadcast, burial, C11, C4(d), abandon; Active and the slot's close | P4.3, P7, wallet accessors |
| **P4.6** | Slice 1 end to end: host and members through formation to a buried funding, on the local test chain; and the same on signet, opt in | P4.5, P8 |

The tests:

**P4.1, `program_composite`** (plus contract v2's T1 `program_resend_on_connect`, T2 steps 1 and 2 `program_links`, and T7 `program_envelope`). A host and a member, each with two test engines (`--test-engines 2`, areas 0x7e57 and 0x7e58).

1. Both engines ping and get replies; each engine's records carry its own area; each engine's timer (both use id 1) fires only into its own engine.
2. A test command makes engine A save and hand off to engine B in one step: one batch holds both records (`gazpacho --test-dump-journal`). Killed at every point around that batch (`--test-crash-after-save`, `--test-crash-before-confirm`), the restarted node holds both records or neither.
3. `--test-node-error-at` in engine B: the whole node restarts from storage; engine A's unconfirmed reply is resent at reconnect; nothing of the failed step is in the journal.
4. A message of kind 32767 with a nonzero scope, and one on a link with no slot (member side): dropped and counted, and the member's connection is closed.
5. A storage failure in the middle: one in-process restart; both engines' timers fire only after the new start.

**P4.2, `program_lobby`.** A host and three members, plus one whose conditions refuse the terms. Signing is the test stand-in (`--test-sign-outcome funding|retry|failed`, test build only).

1. Happy path: seats, ready check, freeze, `start` to three chosen seats; the stand-in reports Funding; every lobby shows Funding; the host's `SET_SEATED` precedes each member's first delivered message.
2. Crashes: the host killed after `start_sent` and before the starts leave; a member killed after `start_received`. Each restarts and the hand-off is called again with `resume` = 1, once.
3. The stand-in reports Retry, then the member restarts: it does not hand off its spent start (B2). The host restarted in Signing, then Retry, then the deadline passes: cancel reason 1, not 3 (B4).
4. A chosen member leaves in Signing and joins again with the same contribution key: refused (B1).
5. Budget: Retry, then the budget ends while Open: cancel reason 3 by the lobby. With a round in flight the stand-in's budget expiry gives Failed, and a late Funding is impossible (B3).
6. A refusal: a hostile raw client sends an invalid `join` three times: the host closes it with a warning (DISCONNECT why `refused`); it never SENDs a warning itself.
7. A storage failure and a reconnect: the member's `hello` gets the full state, and nothing is saved twice.

**P4.3, `program_signing`.** A host and three members; funding from a test wallet port with fixed fake prevouts; no chain.

1. Happy path to every ack: Funding on every side, in the same batch as `ack_received` (host) or `round_completed` (member).
2. The host killed after `round_started` and before `round_propose` leaves: on restart it fails the attempt (H13), the lobby goes to Retry, a new check and a new attempt complete.
3. A member killed after `exposure` and before `round_partial_sigs` leaves: on restart it resends the saved bytes after `hello`; the round completes.
4. A member killed in the nonce phase: it aborts (S2); the host retries without it, on a new funding outpoint (H11, seen in the plan).
5. The budget ends in the nonce phase: Failed, cancel reason 3 everywhere, no member exposure.
6. A finished check handed again (a host restart right after Funding): nothing new in the journal.
7. A storage failure on the host mid-round; a member reconnect in the partial-signature phase.

**P4.4, `program_bad_host`.** One honest member against `gazpacho-test --test-evil-host MODE`. Each mode is one CTest case. In every case the member's journal holds no `exposure` record and no `round_partial_sigs` leaves it (a byte count from the host's log).

- `wrong-scope`: round messages under another scope.
- `unanswered-check`: a proposal for a check the member never answered.
- `withdrawn-check`: a proposal after the member unreadied.
- `changed-terms`: a proposal whose current digest differs from the frozen one.
- `other-key`: a proposal that leaves out the member's key, or names it twice.
- `two-proposals`: two proposals under one round identifier: the second is evidence (`host_fault`).
- `other-link`: round messages on a second connection with another key: dropped, connection closed.
- `lying-funded`: `factory_funded` for a txid never broadcast: the member stays Funding.

**P4.5, `program_funding`.** A host and three members against the local test chain server (`ports/chain/tests/local_server.py`).

1. Happy path: every ack, H1 passes, one broadcast, three confirmations; the host and every member show Active; the slot is closed; the members' C11 says live.
2. The host killed after `funding_signed` and before the broadcast: restarted, it rebroadcasts from the saved bytes.
3. H1 made to fail (`--test-h1-break prevout`): no broadcast, an attention notice.
4. The host never broadcasts: each member's funding deadline passes: Abandoned, the slot closed.
5. An input of the funding spent by another transaction, buried: Dead on every member.
6. A member killed while the funding confirms: on restart its watches come back and it reaches live.
7. A storage failure on a member at burial; a reorganisation that removes the funding before burial.

**P4.6, `program_slice1`** on the local test chain (always), and **`program_slice1_signet`** opt in (`GZ_LIVE_TESTS`), with the test coins and the fee rate 0.1 sat/vB. A host, three members and one refusing member, from `--role` to Active, then every process restarted once with nothing lost.

## 14. For the owner

Two questions. Everything else in this note is decided.

**Q1. How many lobbies at once in Slice 1?**

A slot is one lobby in progress. The signing and funding engines already handle many factories.

- (a) **One lobby in progress per wallet.** A member can join another once the first is Active or has ended. Simple records, simple tests. Lobby records need no scope field yet.
- (b) Several at once. Every Lobby record needs a scope field first (section 7.3), and the tests grow with every combination.

**Recommendation: (a)** for Slice 1. The composite is written for a slot table, so (b) later is a size change plus the scope field.

**Q2. Should the host fund automatically once H1 passes?**

The Slice 1 attempt waited for a hand-made gate file before broadcasting.

- (a) **Automatically**, as soon as H1 passes. Members' signing budget and funding deadline keep running while a person decides, so waiting can lose the factory.
- (b) Ask the person each time, in the interface.
- (c) A host setting, default automatic.

**Recommendation: (a)** on signet and testnet4 now; (c) before any real money, with the default still automatic.

## 15. What changes on open branches

| Branch | Change |
|---|---|
| `program-skeleton` (PR 27) | Links the composite instead of the placeholder node; DISCONNECT `why` mapped to `gz_peers_refuse` or `gz_peers_close_after_send`; `--test-engines`, `--test-dump-journal`. Lands as P3 first, then takes P4.1 |
| `lobby` (PR 30) | B1 to B4 as in 9.4; actions instead of `GZ_NOTE_CLOSE`, `GZ_NOTE_SEATED` and warnings; kind, scope and records; `part` code removed; `gz_lobby_member_accepted` replaces `gz_lobby_member_may_sign`; `gz_lobby_host_unknown`; member `lobby_state`; budget timer only with no round in flight. `docs/notes/lobby.md` decisions 3, 4, 20, 23 and 26 updated |
| `signing` to `signing-vectors` (PRs 32 to 36) | `signing_node.h` replaced by the composite's engine ops; `gz_sign_load`, `gz_sign_resume`, `gz_sign_set_keys`; `peer[]` gone; the outcome on both roles, called right after its save; `budget_end_ms`; finished checks ignored; `funding_status` no longer written; `lobby_outcome.c` moves into `core/node/handoff.c` |
| `journal` (PR 29) | Nothing in the format. The program's storage feeds the composite's one walk |
| `spec/journal.md` | `slot_opened`, `slot_closed` in section 9; `lobby_state` kept by both; `funding_status` written by the funding engine only. Applied by P4.2 |
| `docs/notes/contract-v2.md` | Section 17's P4 row points here; DISCONNECT's `why` added to section 3. Applied by P4.1 |
