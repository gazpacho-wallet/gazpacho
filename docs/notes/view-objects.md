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
| `seats[]` | 20 `GZ_VHL_SEATS` | Entries of 52 bytes, in order of joining: contribution key (33; the seat id is the API server's: 16 hex of its SHA-256), state (seat values of 14.1 plus 9 `locked` and 10 `refused`), flags (1 locked, 2 refused, 4 chosen, 8 answered the check, 16 connected), refusal reason (u16, the protocol reason), refusal stage (1 `open`, 2 `ready_check`; `signing` comes with P4.3), join order (u64), ready version (u32), `min_members` (u16) |
| `seats[].refusal` | 20 | `at_stage` and `protocol_reason` from the entry; `which: "conditions"` for reason 1; `condition`, `yours`, `offered` stay `null` until messages carry them (24.2 item 33); `signed: false` (an `unready` or `leave`); `activity_id` with P6b |
| `seats[].can_remove` | 8 | `true` while the stage is `open` |
| `can_start_now`, `start_blocked_by` | 18, 10, 34 | The API server applies the start rule (`gz_lobby_start_rule`) to the counts and the outer rules; `paused` when 34 is present |
| `funding`, `funding_tx`, `factory_id` | none | P4.5 |
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
| `wallet`, `network`, `lock`, `connection`, `watching`, `money`, `next_date`, `auto_join`, `hosting`, `while_closed` | none | The program's and the other engines' (P5, P4.5, chain) |

## 5. `attention[]`: kind 7

Each item is one object; `gone` removes it. Records: 6 code, 8 the lobby's local id, 10 `since_at`, 12 fingerprint, 14 count. Codes: 1 `unlock_to_take_part` (a member's seat is locked by its gate, 14.3 rule 4), 2 `lobby_left_out` (keys not given at this start), 3 `member_refused` (a host: the number of refused seats).

## 6. The API engine (area 0x000d)

- **Commands.**
  - `0x0d01` pause: 12 `on`, u8 1 or 0.
  - `0x0d02` set signing: 12 `member_signing` (u8), 14 `based_on_version` (u32).
  - Any other `0x0dxx` is answered `404 unknown_command`.
- **Request ids** (7.4). A command that carries a digest (record 6) is an API request:
  - **Validation.** Its id must have 16 to 64 characters of `[A-Za-z0-9_-]`; otherwise `400 bad_value`.
  - **Replay.** The same id with the same method, path and digest answers the saved status, with `params {"replayed":true}` and `object` set to the local id, and does nothing.
  - **Reuse.** The same id with another request answers `409 request_id_reused` with `params.first`.
  - **Saving.** A request that saved something gets record `0x000d0014` right after its first save, in the same batch, before its result notice. A request that saved nothing keeps no id.
  - **Memory.** The engine keeps the newest 128 ids.
  - **Not requests.** Commands without a digest (the program's own, tests') keep no id.
- **Pause** (11.3). The record `0x000d000c` is saved before anything the pause does.
  - **Members.** A member's lobby whose round was handed over holds the pause (`held_for_signing`), and the others are left (`leave` reason 2). `join` and `ready` then answer `409 paused`.
  - **Hosts.** A host runs no ready check while paused and cancels at the deadline with reason 2, through the host's new `paused` port. Pausing off applies the start rule again.
  - **Restarts.** A saved pause is in force from the load, before any CONNECT.
- **Signing setting** (14.3).
  - **Saving.** Record `0x000d0024` holds `member_signing`, `host_funding` and `version`. A wrong `based_on_version` answers `409 changed_elsewhere`.
  - **Taking effect.** The saved value is in force from the next start: it replaces the configuration's at load, and the result says `takes_effect: "next_start"`.

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
