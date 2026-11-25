# View objects and the local-API engine (step P6a)

The composite node offers no reads (contract-v2.md section 11). It emits each view object as a `NOTIFY` whenever the object changes, after the saves of the state it shows (node rule 8), and every object again at each start (node rule 7, composite-node.md section 10, step 9). The program keeps the newest bytes of each (kind, id). The API server answers `spec/local-api.md` (draft 5) from them.

This note says, for each field of the answers the API server builds from the view, which record of which object carries it, or where it comes from when the core does not hold it. Field numbers and codes are in `core/gazpacho/include/gazpacho/view.h`. Code: `core/node/view.c` (the objects) and `core/node/api.c` (the engine).

## 1. Framing and versions

- Every object is a TLV stream: 0 `id`, 2 `gone` (empty) when the object is removed, 4 `version` (u64), then the fields below. Integers are big-endian, times are Unix milliseconds, and a field is absent when its value is null.
- `version` is the node's incarnation in the high 32 bits and a counter of this run in the low 32. It grows with every emission, and a start's objects are always newer than anything an earlier run released.
- An object is emitted only when its fields differ from the last emission (a 64-bit hash of the fields). Every object is emitted again at a start, after the lobbies have resumed. The ended lobbies of the host's index go 64 per call, then one slot per call, then the status, so that each step stays within the node part's step (8.3).
- **Ids.**
  - A lobby's id is its local id (local-api.md 7.3): `lob_` followed by 16 hex digits. They come from the random port, mixed with the slot serial so that two slots never share one.
  - The id is saved in record `0x000d000e` `local_ids`, in the slot's first batch, with `slot_opened` and `lobby_opened`.
  - The status object's id is `status`.
  - An attention item's id is `att_` followed by the lobby's local id.
- **Ended lobbies.**
  - When a lobby ends, its last object is emitted before its slot is freed, and the program keeps it.
  - At a start, a host emits a short object for each ended lobby still in its index (the newest 256): fingerprint, stage, end reason.
  - A member keeps no index, so a member's ended lobbies are not emitted again after a restart. The API server answers them from its activity entries (P6b), or `404`.

## 2. `GET /api/v1/lobbies/{id}`: kind 2, `lobby`

| `local-api.md` 14.1 field | Record | How |
|---|---|---|
| `id` | 0 | The local id |
| `fingerprint` | 6 `GZ_VLB_FINGERPRINT` | 32 bytes, as 64 hex |
| `name`, `host.alias` | 22 `GZ_VLB_OUTER` | Decode the outer rules (core/tree `gz_terms_decode_outer`): `alias`, `description`; `by: "host"`, `checked: false` |
| `host.key` | 8 `GZ_VLB_HOST_KEY` | 33 bytes, as 66 hex |
| `host.address` | 10 `GZ_VLB_HOST_ADDRESS` | ASCII, as given at join |
| `source`, `listed` | none | The program's discovery (S1: `direct_query`); `listed` is the discovery answer's |
| `stage` | 12 `GZ_VLB_STAGE` | 0 `unknown`, 1 `open`, 2 `ready_check`, 3 `signing`, 4 `funding`, 5 `active`, 6 `cancelled`, 7 `failed` (the member's view, from the host's last `lobby_status`) |
| `terms` | 22, 24, 26, 28 | The outer rules and the current values as signed, with their signatures; the API server decodes them (13.3) |
| `fit` | 32 `GZ_VLB_FIT` + the conditions | The class (0 `fits`, 1 `fits_now_only`, 2 `does_not_fit`); for a class other than `fits`, the first failing term (terms.md type) and its two values. The full 13.4 rows come from the API server's own fit check with the member's conditions |
| `start_rule` | 22 | From the outer rules: `target`, `minimum`, `deadline`, `on_shortfall` |
| `counts` | none (P6b) | The member holds no counts; `lobby_status` carries them and P6b keeps them |
| `you.seat` | 14 `GZ_VLB_SEAT` | 0 `none`, 1 `joined_not_ready`, 2 `ready`, 3 `chosen`, 4 `not_chosen`, 5 `left`, 6 `removed`, 7 `refused_by_host`, 8 `joining` |
| `you.ready_for_version` | 16 | u32, present while ready |
| `you.counted` | 20, 14 | `false` while 20 `GZ_VLB_LOCKED_SINCE` is present or the seat is not `ready`; `fit.counted_from` is the API server's |
| `you.gate` | 18 `GZ_VLB_GATE` | `kind` (0 `none`, 1 `node`, 2 `per_lobby`), `state` (1 `open`), `since_at` (ms / 1000), `opened_for_digest` (32, present for an open per-lobby gate whose seat is ready for the current values). Absent when `you.seat` is `none` |
| `you.standby` | none | `null` in Slice 1 |
| `you.outcome` | 34 `GZ_VLB_OUTCOME` | u8 code, u16 reason: 1 `refused_at_check`, 3 `refused_by_host`, 4 `removed`, 5 `left`, 6 `cancelled`, 8 `not_chosen`, 12 `started`. With `refused_at_check`, `failures` comes from 32 (`which: "conditions"`). The round outcomes (2, 7, 9 to 11) come with the signing engine (P4.3) under these numbers |
| `round` | 36 `GZ_VLB_ROUND` | The saved round outcome only (4 Funding, 5 Active); the member's round states are the signing engine's (P4.3) |
| `funding`, `factory_id` | none | Funding engine (P4.5) |
| `members`, `terms_change`, `accountability` | none | `null` in Slice 1, except `terms_change`, which the API server derives from successive versions of 26 |
| `doing` (status 11.1 `lobbies[].code`) | 38 `GZ_VLB_DOING` | `GZ_DOING_*`, named in view.h after 11.2's values |
| `since_at` | 40 `GZ_VLB_SINCE` | When stage, seat or doing last changed (memory: a start sets it to the start's time) |
| left or held by the pause | 42 `GZ_VLB_PAUSED` | 1 while the pause holds this lobby's round (`pause.lobby_ids`) |
| frozen values | 30 `GZ_VLB_FROZEN` | Version and digest frozen by the ready check |

## 3. `GET /api/v1/host/lobbies/{id}`: kind 3, `host_lobby`

| `local-api.md` 15.3 field | Record | How |
|---|---|---|
| `id`, `fingerprint` | 0, 6 | |
| `name`, `terms` | 10, 12, 14, 16 | The outer rules and the current values as signed |
| `stage` | 8 | As for kind 2 |
| `counts` | 18 `GZ_VHL_COUNTS` | u16 `joined`, `ready` (ready for the current values), `locked`, `refused` |
| `seats[]` | 20 `GZ_VHL_SEATS` | Entries of 52 bytes, in order of joining: contribution key (33; the seat id is the API server's: 16 hex of its SHA-256), state (seat values of 14.1 plus 9 `locked` and 10 `refused`), flags (1 locked, 2 refused, 4 chosen, 8 answered the check, 16 connected), refusal reason (u16, the protocol reason), refusal stage (1 `open`, 2 `ready_check`, 3 `signing`: the host's state when the refusal came), join order (u64), ready version (u32), `min_members` (u16) |
| `seats[].refusal` | 20 | `at_stage` and `protocol_reason` from the entry; `which: "conditions"` for reason 1; `condition`, `yours`, `offered` stay `null` until messages carry them (24.2 item 33); `signed: false` (an `unready` or `leave`); `activity_id` with P6b |
| `seats[].can_remove` | 8 | `true` while the stage is `open` |
| `can_start_now`, `start_blocked_by` | 18, 10, 34 | The API server applies the start rule (`gz_lobby_start_rule`) to the counts and the outer rules; `paused` when 34 is present. `POST …/start` is `0x0109` (section 6, "Early start") |
| `funding.set_aside_sat` | 38 `GZ_VHL_SET_ASIDE` | u64, the funding engine's `gz_fund_set_aside_sat` of the outer rules: the factory output at the member count, from the minimum to the target, that needs the most (the target for every shape so far, and so the opening preview's `funding_at_target_sat`; test `test_api_start_guard`). It is what `POST …/start` echoes as `confirm_funding_max_sat`. **The network fee is on top**: the interface shows it as "plus the network fee", and a free-funds check (`funds_short`, `set_aside_elsewhere_sat`, P4.5) counts the set-aside plus a fee bound for the funding transaction (its largest plan at the funding fee rate), never the set-aside alone. Absent when no amount can be confirmed |
| `funding` (the rest), `funding_tx`, `factory_id` | none | P4.5 |
| `round` | 28 `GZ_VHL_ROUND` | A start was sent (u8) and the signing budget's start (u64 ms); the attempt's states are P4.3's |
| `listing` | 22 `GZ_VHL_LISTED` | `published: ["direct_query"]` when listed |
| `standby` | 24 `GZ_VHL_STANDBYS` | The number of standby seats offered; `null` in Slice 1 |
| `accountability` | none | `null` in Slice 1 |
| ended | 26 `GZ_VHL_END_REASON` | The cancel reason, once ended |

## 4. `GET /api/v1/status`: kind 1, `status`

| `local-api.md` 11.1 field | Record | How |
|---|---|---|
| `pause` | 8, 10 | `state` (0 `off`, 1 `on`, 2 `held_for_signing`), `since_at`, `lobby_ids` (comma-separated local ids) |
| `lobbies[]` | 18 `GZ_VST_LOBBIES` | Per entry: role (1 `joined`, 2 `hosted`), stage, code, `since_at`, the local id |
| `doing` | 16 `GZ_VST_DOING` | The code, role, `since_at` and lobby of the slot with the highest code; `paused` or none without a lobby |
| `GET /api/v1/signing` | 12 `GZ_VST_SIGNING`, 14 | `member_signing` in force (0 `at_join`, 1 `auto`, 2 `when_unlocked`), `pending` (0xff: `null`), `version`, `host_funding`; `node_gate` from 14 under `when_unlocked` |
| left-out lobbies | 20 | The number of lobbies left out at this start (review B of PR 44, H1), with their attention items |
| `GET /api/v1/conditions`: `version`, `preset`, the compared `conditions` | 22 `GZ_VST_CONDITIONS`, 24 `GZ_VST_PRESET` | 22: u32 `version`, then the conditions in `0x0d03`'s encoding (section 6); absent until the person first saves them. 24: the preset's id; absent for `custom`. The other members of 13.1 (`limits`, `presets`, `fit_summary`, `copied_into`, the fields Slice 1 does not compare) are the API server's |
| `wallet`, `network`, `lock`, `connection`, `watching`, `money`, `next_date`, `auto_join`, `hosting`, `while_closed` | none | The program's and the other engines' (P5, P4.5, chain) |

## 5. `attention[]`: kind 7

Each item is one object; `gone` removes it. Records: 6 code, 8 the lobby's local id, 10 `since_at`, 14 count. Codes: 1 `unlock_to_take_part` (a member's seat is locked by its gate, 14.3 rule 4), 2 `lobby_left_out` (keys not given at this start), 3 `member_refused` (a host: the number of refused seats).

- **No fingerprint** (7.3: never in an event). An item's id is `att_` and the lobby's local id; field 12 is not used. Every lobby slot has a local id: from its open, or, for a slot opened before the engine, one made and saved at the start that finds it without one.

## 6. The API engine (area 0x000d)

- **Commands.**
  - `0x0d01` pause: 12 `on`, u8 1 or 0 (`400 bad_value` otherwise).
  - `0x0d02` set signing: 12 `member_signing` (u8), 14 `based_on_version` (u32), 16 `confirm_member_signing` (u8). It is **the one command that sets the signing mode** (W11, coordinator decision K19): `PUT /api/v1/signing` uses it and nothing else. PR 52's `0x0403` is handled apart; a runtime switch, if open point 46 decides one, becomes an "apply now" path of `0x0d02`.
  - `0x0d03` set conditions: 12 the conditions (the encoding `LOBBY_JOIN` and `slot_opened` use, `core/node/lobbyslot.c`: current_only u8, the ready hint u16, then the limits; empty: no limits), 14 `based_on_version` (u32), 16 `confirm_loosens` (the codes of what the change loosens, one byte each, increasing), 18 `preset` (ASCII, 1 to 16 of `a-z` and `_`; absent: `custom`). `PUT /api/v1/conditions` uses it.
  - The lobby's `0x0109` start (`node.h`): 12 scope, 14 `confirm_funding_max_sat` (u64). `POST /api/v1/host/lobbies/{id}/start` uses it.
  - Any other `0x0dxx` is answered `404 unknown_command`.
- **Result notice** (`GZ_NOTIFY_COMMAND_RESULT`): 0 request id, 2 status, 4 error code, 6 `GZ_RESULT_REC_OBJECT` (the acted-on lobby's local id), 8 `GZ_RESULT_REC_PARAMS` (JSON: `params`, or the extra members of the answer).
- **What the API server sends** (W12, for PR 51). The engine side is complete; the server needs only to send these commands and read the view:
  - every outward call: `request_id`, method, the path with its local ids filled in, and the RFC 8785 digest with the top-level `passphrase` removed (fields 0, 2, 4, 6), then the command (8) and its arguments; a `lob_` id resolved to the scope (field 12) from the view object's field 6, `404` for an id the view does not hold;
  - `PUT /pause`: `0x0d01` with an internal id and **no digest** (11.3 has no `request_id`); the fresh sign-in and `confirm: "resume"` for a resume are the server's;
  - `PUT /signing`: `0x0d02` after the fresh sign-in, **with a digest** and, for `auto`, field 16 = 1;
  - `PUT /conditions`: `0x0d03` **with a digest** (and, since 13.2 has no `request_id`, an internal id, as for `PUT /signing`); for a change that loosens anything, after the fresh sign-in, with `confirm_loosens` mapped to field 16's codes (`profiles` 8, `min_members` 12, `min_life_blocks` and `max_life_blocks` 26, `min_channel_sat` 30, the tree fee rate 32, an adjustable maximum its type, 64 and up, `compare_with` 1, the ready hint 2). `POST /conditions/preview` sends nothing: the server computes `loosens` with the same rules, and the core's 409 gives its own list;
  - `POST …/start`: `0x0109` after the fresh sign-in, **with a digest**, field 14 the person's `confirm_funding_max_sat`;
  - a replay's body is built from the object's **current** state and the result's field 6.
- **Request ids** (7.4). A command that carries a digest (record 6) is an API request:
  - **Validation.** Its id must have 16 to 64 characters of `[A-Za-z0-9_-]`, its method at most 16 and its path at most 192 printable characters without `"` or `\`; otherwise `400 bad_value`. The load checks a saved record the same way.
  - **Replay.** The same id with the same method, path and digest answers the saved status and error code, with `params {"replayed":true}` and `object` set to the local id, and does nothing. After a restart the object is still there (record field 12).
  - **Reuse.** The same id with another request answers `409 request_id_reused` with `params.first`.
  - **Saving.** A request that saved something gets record `0x000d0014` right after its first save, in the same batch, before its result notice: 12 the object, 14 created, 15 the error code. A request that saved nothing keeps no id.
  - **Keeping** (7.4). An id is kept until its object has ended and 30 days have passed: a request with no object (pause, signing) from its making, a lobby from its slot's end (an end before this start counts from this start). The table holds 512 (64 calls for each of the 8 lobbies). A new request that finds every id still kept answers `503 node_busy` and does nothing; no id is ever dropped early.
  - **Not requests.** Commands without a digest (the program's own, tests') keep no id.
- **Pause** (11.3). The record `0x000d000c` is saved before anything the pause does.
  - **Members**, by 11.3's table:
    - **Held**: a lobby whose round has partial signatures out (the signing engine's fact; until P4.3 none in a release build, and in test builds the stand-in's `GZ_TEST_SIGN_PARTIALS`). The pause is `held_for_signing` with those lobbies, answer `202`. When a held round ends (Funding, a Retry, a failure, the lobby's end) its lobby leaves the hold and the pause is saved again, `on` when none is left; a lobby back before Signing is then left.
    - **Unchanged**: Awaiting funding and Live.
    - **Left** (`leave` reason 2): every other lobby, joined or still joining, ready or in a check; after a `round_abort` where its round had begun.
    - The answer's `params`: `left_lobbies`, `aborted_lobbies`, `held_lobbies` (local ids). `join` and `ready` answer `409 paused`.
  - **Hosts.** A host runs no ready check while paused and cancels at the deadline with reason 2, through the host's new `paused` port. Pausing off applies the start rule again.
  - **Restarts.** A saved pause is in force from the load: no lobby joins or readies. Each member lobby is dealt with in its own resume step, after its CONNECT; one whose seat the host holds is left once its link is up, so that the leave reaches the host.
- **Signing setting** (14.3).
  - **Saving.** Record `0x000d0024` holds `member_signing`, `host_funding` and `version`. Checks in order: a value outside 0 to 2 or no version, `400 bad_value`; `when_unlocked`, `501 not_in_this_release`; to `auto`, a command without a digest (not the API server's `PUT /signing`), `403 fresh_sign_in_needed`, and field 16 not 1, `409 confirm_mismatch`; a wrong `based_on_version`, `409 changed_elsewhere`. A narrowing to `at_join` needs neither digest nor echo.
  - **Taking effect.** The saved value is in force from the next start: it replaces the configuration's at load, and the result says `takes_effect: "next_start"`.
  - **One source of truth** (H3). `gz_node_member_signing(node)` gives the value in force once the start's first call has walked storage. The program reads it there, before it hands that call's list to the runner and before any key secret is asked for, logs `member-signing in-force=… option=…`, and sets its key routing from it, not from `opt.member_signing`. With PR 53 that is one line where the executor logs the value: `gzp_keys_set_role(ex->keys, ex->opt->role == GZP_ROLE_HOST, ex->member_signing == GZ_MEMBER_SIGNING_AT_JOIN)`; `port_secret` reads `scoped_only` at each call, so the routing follows from the first resume step on. `program_signing_setting` checks it with a host and three members across restarts.

- **Conditions** (13.2). Record `0x000d0008` holds the conditions as field 12 gave them, the `version`, the preset and, in field 8, the version of the last save that tightened anything (at most the version). A slot whose `slot_opened` 24 is above the loaded version is a corrupt journal.
  - **Checks, in order.** Conditions that do not decode, no version, or a bad preset: `400 bad_value`. A change that loosens anything against the saved conditions (no saved conditions: no limits, so the first save loosens nothing): without a digest `403 fresh_sign_in_needed`; field 16 not exactly the list of what it loosens, `409 confirm_mismatch` with `params.loosens` (the codes); field 16 not empty when nothing loosens is a mismatch too. A wrong `based_on_version`, `409 changed_elsewhere`. A lobby it would leave whose round is on (a start with role 1 for its answered check, a round in the signing engine, partial signatures out), `409 signing_now` with `params.lobby_ids`, and nothing is saved: no conditions change ever drops a lobby whose partial signatures may be out.
  - **The copying rule.** Each lobby keeps the conditions it was joined with (`slot_opened` field 20, with field 24 the saved conditions' version then); the ready check and the signing check compare against that copy, so a loosening changes no joined lobby. A join that names no conditions copies the saved ones. A join that names its own, looser than the saved ones, is the person's, freshly: an API request (`403 fresh_sign_in_needed`) with `LOBBY_JOIN` field 22 exactly what it loosens (`409 confirm_mismatch`, `params.loosens`); its copy then holds until the saved conditions next change.
  - **Which lobbies a change reaches.** Only a change that tightens something (the old conditions loosen against the new), and only the lobbies joined before it (`slot_opened` 24 below its version). The same conditions saved anew, or a loosening, reach none: a lobby joined with confirmed looser conditions keeps them.
  - **Tightening.** After the save, every member lobby whose latest values fit the new conditions worse than they fit its copy (a plain ready down to "fits only now" under the default option, or to "does not fit", or the first down to the second) is left before its round: `leave` reason 1, with `GZ_NOTE_REFUSED` (`gz_lobby_member_tighten`). The host sees a refusal at its stage (15.3, `seats[].refusal`), not a member that left by choice. The leaves of connected lobbies are in the batch of the save (journal.md 9). A lobby whose link is down is left once it is up, so that the leave reaches the host, and at every start from the saved record; one whose round is on (see above; only possible across a restart) is left if its round comes back to Open, never during it.
  - **The answer.** `200`, `params` `{"version": N, "left_lobbies": [...]}` (local ids). The status object's 22 and 24 follow it.
- **Early start** (15.2). `0x0109`, the person's "start now": the ready check begins at once, exactly as the start rule begins it (the freeze saved before the first check), only while the lobby is Open. It spends what opening set aside, so it is an API request only.
  - **Checks, in order.** No field 14: `400 bad_request`. No digest: `403 fresh_sign_in_needed`. Not Open: `409 not_open`. Field 14 not the funding engine's set-aside amount (`gz_fund_set_aside_sat`, the host view's 38; the network fee is on top): `409 confirm_mismatch` with `params.set_aside_sat`. Paused: `409 paused` (11.3). Fewer ready than the minimum, counted as the start rule counts them (ready for the current values, connected, with a `min_members` a start can meet): `409 below_minimum` with `params.ready` and `params.minimum`. After a ready check that ended without a start, until a seat changes (the rule's failed-check guard, decision 8): `409 refused_now`. `funds_short` (the set-aside plus a fee bound, above) and `chain_in_doubt` are the funding engine's and the chain view's (P4.5).
  - **The consent's record.** The amount the person consented to at opening is not saved as a number (record `0x000d0016` is reserved): it follows from the terms in `lobby_opened`. A later release that changes `gz_tree_params` must therefore save it before it changes the rule, or an open lobby's start could echo an amount other than the one shown at opening.
  - **The answer.** `202`, `params {"stage":"ready_check"}`; the request id is in the batch of the freeze. A check that ends without a start returns the lobby to Open, under the rule again.

## 7. Not in P6a

- The member's counts.
- The round states.
- Funding.
- Activity entries.
- Refusal values on the host's side, which need protocol support (24.2 item 33).
- Standby seats.
- Accountability.
- `not_unlocked_in_time`.

These belong to P4.3, P4.5 and P6b, each under the numbers reserved above.
