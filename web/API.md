# The local API the screens use

A proposal, written from the screens' side. The prototype implements it with fake data in `js/api-mock.js`. The real implementation is the C program answering on the local machine. Nothing here is built yet; shapes should change where the core disagrees, and this file with them.

## Ground rules

- The screens call functions on one object, `window.gzApi`. Every function returns a Promise. A later `api-client.js` turns each into one HTTP request to the local program; the suggested path is given with each function. All paths are under `/api/v1`.
- Requests and answers are JSON. Field names are `snake_case`.
- **Amounts** are whole satoshis in fields ending `_sat`. **Fee rates** are parts per million in fields ending `_ppm`. **Times** are Unix seconds in fields ending `_at`. **Block heights** end `_height`; **lengths in blocks** end `_blocks`.
- **The program decides; the screens show.** Checks against the member's conditions, the schedule, whether a payment is allowed: all are computed by the core and returned as codes and numbers. The screens hold the wording. No rule is re-implemented in JavaScript.
- **Keys, recovery phrases after first run, and channel state never appear in any answer.** The one exception is `createWallet`, which returns the new recovery phrase once.
- **Errors.** A failed call rejects with an `Error` that has `code` (a stable word, listed with each function) and `message` (a plain sentence that can be shown as it is). Over HTTP: a non-2xx status with `{ "code": "...", "message": "..." }`. `unreachable` is used by the client when the program does not answer.
- **Access.** As `DESIGN.md` section 13 says: local machine only, a start-up token, and refusal of requests from other sites. The client sends the token with every request; how it gets the token is not designed here.

## Live updates

### `subscribe(callback)` → `unsubscribe()`

`GET /api/v1/events` as a server-sent event stream.

Calls `callback({ topic, at })` whenever something changed. The event says only which area changed; the screen then asks again for what it shows. This keeps one source of truth and makes a missed event harmless.

| Topic | Something changed in |
|---|---|
| `status` | `getStatus` (including the attention list) |
| `chain` | the chain tip or the state of the chain servers |
| `lobby` | any lobby: members, readiness, stage, terms |
| `conditions` | the member's conditions, or whether they are locked |
| `factory` | a factory: state, balances, exit progress, rotation |
| `schedule` | the dates in `getSchedule` |
| `payments` | payments or invoices |
| `wallet` | the on-chain wallet |
| `settings` | settings, backup times, server checks |
| `reset` | everything; draw again from nothing (the mock sends it when the demo state changes; the real program after a restart) |

## Status

### `getStatus()`

`GET /api/v1/status`

```json
{
  "prototype": true,
  "version": "prototype",
  "network": "signet",
  "test_coins": true,
  "wallet_exists": true,
  "roles": { "member": true, "host": false },
  "chain": { "state": "ok", "height": 330437 },
  "member": { "lobby_id": null, "factory_id": "factory-tomato-12" },
  "host": { "lobby_id": null, "factory_id": null },
  "attention": [ { "code": "sign_rotation", "level": "urgent", "params": { "blocks_left": 244 } } ]
}
```

- `chain.state`: `ok`, `disagree` (servers report different chains; nothing is treated as newly confirmed and nothing is published), `offline`.
- `attention`: what needs the person, most important first. `level` is `urgent`, `warn` or `info`.

| `code` | `params` | Meaning |
|---|---|---|
| `chain_disagree` | | Chain servers disagree |
| `host_gone` | `host`, `last_seen_at` | The member's host is not answering |
| `sign_rotation` | `blocks_left` | The factory is winding down; move to the next |
| `exit_running` | | Leaving alone is under way |
| `exit_done` | `amount_sat` | Leaving alone has finished |
| `reserve_low` | `recommended_sat` | On-chain reserve below the recommendation |
| `lobby_not_ready` | `lobby_id`, `name` | In a lobby but not ready (conditions or block list) |
| `lobby_signing` | `lobby_id`, `name` | Keep the app open: signing |
| `lobby_funding` | `lobby_id`, `name` | Waiting for the funding confirmation |
| `host_can_start` | `name` | The host's lobby has reached its minimum |
| `host_node_missing` | | Host mode is on with no Lightning node linked |

The mock adds `chain.seconds_per_block_here`; the real program would not.

## First run

### `createWallet()`

`POST /api/v1/wallet/create` → `{ "recovery_phrase": ["word", "..."] }`

Makes new keys and returns the phrase once. The wallet is not in use until `finishSetup`. The mock returns the word "example" twelve times.

### `restoreWallet({ recovery_phrase, backup_file_name })`

`POST /api/v1/wallet/restore` → `{ "on_chain_restored": true, "channels_restored": false }`

`recovery_phrase` is one string of words. The backup file itself would be uploaded in the request body; the mock takes only its name. Errors: `bad_phrase`.

A wallet restored from a backup is marked so that it never publishes its own channel state.

### `finishSetup({ roles: { member, host } })`

`POST /api/v1/wallet/finish-setup` → `{ "ok": true }`. Errors: `no_wallet`, `no_role`.

### `setRoles({ member, host })`

`PUT /api/v1/roles` → the roles. Errors: `no_role`.

## Conditions

### `getConditions()`

`GET /api/v1/conditions`

```json
{
  "conditions": {
    "min_members": 20,
    "min_channel_sat": 200000,
    "max_join_fee_sat": 2000,
    "max_payment_fee_ppm": 1000,
    "max_liquidity_fee_ppm": 5000,
    "profiles": ["safety", "standard", "starter"],
    "max_exit_blocks": 1008
  },
  "locked_by_lobby": null,
  "limits": { "min_members": [2, 512], "max_exit_blocks": [0, 3456] },
  "profiles": ["safety", "standard", "starter", "circle"]
}
```

`locked_by_lobby` is `{ id, name }` while the member is in a lobby.

### `saveConditions(conditions)`

`PUT /api/v1/conditions` → the saved conditions. Errors: `locked` (in a lobby), `no_profile`, `bad_value`.

## Lobbies

A lobby object, as `listLobbies` returns it:

```json
{
  "id": "lobby-tomato",
  "name": "Tomato Garden, daily factory",
  "role": "member",
  "host": { "name": "Tomato Garden", "factories_funded": 12 },
  "profile": "standard",
  "listed": true,
  "access": "open",
  "stage": "open",
  "terms": {
    "version": 1,
    "channel_size_sat": 500000,
    "spare_liquidity_sat": 250000,
    "join_fee_sat": 1000,
    "payment_fee_ppm": 500,
    "liquidity_fee_ppm": 3000,
    "lifetime_blocks": 4752,
    "timed_levels": 2,
    "exit_blocks": 864,
    "newcomer_seats_pct": 100
  },
  "terms_change": null,
  "start_rule": { "target": 50, "minimum": 30, "deadline_at": 1794441600, "on_shortfall": "cancel" },
  "switches": { "names": true, "chat": false, "rule_requests": true },
  "counts": { "present": 37, "ready": 37 },
  "check": { "ok": true, "failures": [], "counted_from": 30 },
  "you": { "joined": false, "ready": false, "counted": false, "blocked_someone": false },
  "signing": null,
  "funding": null,
  "outcome": null,
  "factory_id": null
}
```

- `role`: `member` (someone else's lobby) or `host` (this wallet's own).
- `profile`: `safety`, `standard`, `starter`, `circle`. `access`: `open`, `invitation`.
- `stage`: `open`, `ready_check`, `signing`, `funding`, `active`, `cancelled`, `failed`.
- `start_rule.on_shortfall`: `cancel` or `carry_over`.
- `terms_change`: `{ version, at, changes: [{ field, from, to }] }` when the host changed the terms after the member joined.
- `check`: the terms against the member's conditions (the locked copy if joined, the saved ones otherwise). Each failure is `{ condition, yours, offered }`, where `condition` is the name of a field in the conditions. `counted_from` is the number of ready members from which this member is counted (the larger of the lobby's minimum and the member's own).
- `you.ready` is false when a condition fails or someone on the member's block list is present. `you.counted` is false while fewer than `counted_from` are ready.
- `signing`: `{ attempt, max_attempts, step, signed, of }`, `step` being `nonces`, `signatures` or `done`.
- `funding`: `{ txid, confirmations, confirmations_needed, amount_sat }`.
- `outcome`: `too_few`, `started_without_you`, or null.

### `listLobbies()`

`GET /api/v1/lobbies` → an array of lobby objects: every listed lobby the program knows of, plus any the member is in. The host's own lobby is not in this list.

### `getLobby(id)`

`GET /api/v1/lobbies/{id}` → a lobby object, plus:

- `members`: `[{ id, name, ready, you, blocked, identity }]`, or `null` when the host has switched names off (the host always gets the list). `identity` is null or `{ kind, label, verified }`, `kind` being `nostr`, `node` or `text`.
- `host_view` (host's own lobby only): `{ can_start_now, funding_now_sat, funding_at_target_sat, wallet_sat }`.

Errors: `not_found`.

### `openInvitation(link)`

`POST /api/v1/invitations` with `{ link }` → `{ "lobby_id": "..." }`. Reads an invitation link (the text inside the QR code) and makes that lobby known. Errors: `bad_invitation`.

### `joinLobby(id, conditions)`

`POST /api/v1/lobbies/{id}/join` with the conditions to lock in → the lobby as `getLobby` gives it.

Errors: `not_open`, `already_in_lobby`, `already_in_factory` (a limit of the prototype, not of the design), `needs_invitation`, `conditions_not_met`, `not_found`.

### `leaveLobby(id)`

`POST /api/v1/lobbies/{id}/leave` → `{ "ok": true }`. Errors: `not_joined`, `too_late` (the factory is signed).

### `setBlocked(lobbyId, memberId, blocked)`

`PUT /api/v1/lobbies/{id}/members/{member_id}/blocked` with `{ blocked }` → `{ "ok": true }`. The member's personal block list: the app will not sign a factory that includes a blocked seat.

## Hosting a lobby

### `previewTerms(terms)`

`POST /api/v1/host/preview` → what the terms would mean, without opening anything.

`terms` (also the argument of `createLobby`):

```json
{
  "name": "My first lobby", "profile": "standard",
  "target": 50, "minimum": 30, "deadline_minutes": 180, "on_shortfall": "cancel",
  "channel_size_sat": 500000, "spare_liquidity_sat": 250000,
  "join_fee_sat": 1000, "payment_fee_ppm": 500, "liquidity_fee_ppm": 3000,
  "lifetime_days": 33, "timed_levels": 2,
  "listed": true, "access": "open",
  "names": true, "chat": false, "rule_requests": false
}
```

Answer:

```json
{
  "terms": { "...": "as in a lobby object" },
  "exit_blocks": 864,
  "usable_blocks": 3312,
  "wind_down_by_blocks": 3744,
  "funding_at_target_sat": 37500000,
  "funding_at_minimum_sat": 22500000,
  "chain_fee_estimate_sat": 1000,
  "wallet_sat": 42000000,
  "wallet_covers_target": true,
  "wallet_covers_minimum": true,
  "host_node_linked": true,
  "problems": [ { "field": "target", "code": "target_below_minimum" } ]
}
```

`problems[].code`: `minimum_too_small`, `target_below_minimum`, `target_too_large`, `channel_too_small`, `deadline_missing`, `name_missing`, `lifetime_too_short`.

### `createLobby(terms)`

`POST /api/v1/host/lobbies` → the new lobby as `getLobby` gives it. Errors: `not_host`, `already_hosting`, `bad_terms`.

### `removeMember(lobbyId, memberId)`

`DELETE /api/v1/lobbies/{id}/members/{member_id}` → `{ "ok": true }`. Errors: `not_host`, `not_open`.

### `startLobbyNow(lobbyId)`

`POST /api/v1/lobbies/{id}/start` → `{ "ok": true }`. Allowed once the minimum is ready. Errors: `not_host`, `below_minimum`.

### `cancelLobby(lobbyId)`

`DELETE /api/v1/lobbies/{id}` → `{ "ok": true }`. Errors: `not_host`, `too_late` (already funded).

## Factory

### `getFactory(id)`

`GET /api/v1/factories/{id}`

```json
{
  "id": "factory-tomato-12",
  "name": "Tomato Garden, factory 12",
  "role": "member",
  "state": "active",
  "host": { "name": "Tomato Garden", "online": true, "last_seen_at": 1794434400 },
  "members": 50,
  "terms": { "...": "as in a lobby object" },
  "created_height": 329437,
  "rotation_opens_height": 332749,
  "auto_exit_height": 333181,
  "expiry_height": 334189,
  "funding": { "txid": "…", "confirmations": 1006, "amount_sat": 37500000 },
  "channel": { "capacity_sat": 500000, "balance_sat": 182400, "receivable_sat": 317600, "spare_liquidity_sat": 250000 },
  "tree": {
    "levels": [ { "kind": "fixed", "width": 7, "delay_blocks": 0 }, { "kind": "timed", "width": 4, "delay_blocks": 432 }, { "kind": "timed", "width": 2, "delay_blocks": 432 } ],
    "path": [ { "level": 1, "kind": "fixed", "width": 7, "index": 1, "delay_blocks": 0, "members_below": 8 } ],
    "members_per_leaf": 1
  },
  "exit": { "blocks": 864, "timed_levels": 2, "fee_sat": 1200, "fee_paid_from": "host_side", "reserve_recommended_sat": 20000, "transactions": 4 },
  "exit_progress": null,
  "rotation": null,
  "next_factory": null,
  "host_view": null
}
```

- `state`: `active`, `winding_down`, `host_gone`, `exiting`, `closed`.
- `tree.levels` describes the whole tree, root first. `tree.path` is this member's own branch, one entry per level: which of `width` branches is theirs (`index`), the waiting period before it can be published, and how many members sit below it. The last entry is the member's leaf.
- `exit`: what leaving alone would involve now. `blocks` is the total waiting time.
- `exit_progress` (while `exiting` or `closed`): `{ started_height, amount_sat, fee_sat, blocks_left, done, steps }`. Each step is `{ id, kind, level, wait_blocks, wait_blocks_left, state, txid, confirmations }` with `kind` `tree`, `leaf` or `channel` and `state` `pending`, `waiting`, `published` or `confirmed`.
- `rotation` (while moving to the next factory): `{ step }`, `signing` then `moving`.
- `next_factory` (while winding down, once the host offers one): `{ name, members, channel_size_sat, join_fee_sat, within_conditions }`.
- `host_view` (the host's own factory; `channel` is then null): `{ funded_sat, spare_total_sat, members_online, wind_down_by_height }`.

Errors: `not_found`.

### `getSchedule()`

`GET /api/v1/schedule` → the dates by which the member must act, from the schedule engine.

```json
{
  "height": 330437,
  "factory_id": "factory-tomato-12",
  "most_urgent": "open_app",
  "items": [
    { "id": "open_app", "due_height": 332453, "blocks_left": 2016, "state": "ok" },
    { "id": "sign_rotation", "due_height": 333181, "blocks_left": 2744, "state": "not_yet",
      "opens_height": 332749, "opens_in_blocks": 2312, "can_sign_now": false },
    { "id": "expiry", "due_height": 334189, "blocks_left": 3752, "state": "ok",
      "auto_exit_height": 333181, "auto_exit_in_blocks": 2744, "exit_blocks": 864 }
  ]
}
```

`state`: `ok`, `soon`, `urgent`, `not_yet`. `items` is empty when the member is in no factory. `most_urgent` is the id the Home screen makes prominent.

### `startExit(factoryId)`

`POST /api/v1/factories/{id}/exit` → the `exit_progress` object. Starts leaving alone; cannot be undone. Errors: `host_factory`, `already_exiting`, `chain_disagree`, `not_found`.

### `moveToNextFactory(factoryId)`

`POST /api/v1/factories/{id}/rotate` → `{ "ok": true }`; progress then shows in `rotation`. Errors: `not_winding_down`.

## Pay and receive

### `decodeInvoice(text)`

`POST /api/v1/payments/decode` with `{ invoice }`. Reads an invoice and says whether it could be paid now, without paying.

```json
{
  "valid": true, "can_pay": true, "reason": null,
  "amount_sat": 2500, "description": "Example purchase", "payee": "02…",
  "fee_max_sat": 3, "deadline_blocks": 1008, "expires_at": 1794438000, "balance_sat": 182400
}
```

`reason` when it cannot be paid: `empty`, `not_an_invoice`, `wrong_network`, `no_channel`, `host_offline`, `not_enough_balance`, `too_close_to_end`. `deadline_blocks` is the payment's final deadline: the factory's exit time plus a margin.

### `payInvoice(text)`

`POST /api/v1/payments` with `{ invoice }` → the payment (see `listPayments`), in state `pending`. Rejects with the same codes as `decodeInvoice`'s `reason`.

### `createInvoice({ amount_sat, description })`

`POST /api/v1/invoices` → `{ id, amount_sat, description, invoice, state, created_at, expires_at }`, `state` being `waiting`, `paid` or `expired`. Errors: `no_channel`, `host_offline`, `bad_amount`, `above_receivable`.

### `getInvoice(id)`

`GET /api/v1/invoices/{id}` → the same object. Errors: `not_found`.

### `listPayments()`

`GET /api/v1/payments`

```json
{
  "channel": { "balance_sat": 182400, "receivable_sat": 317600, "host_online": true, "factory_id": "factory-tomato-12" },
  "payments": [
    { "id": "pay-3", "direction": "sent", "amount_sat": 21000, "fee_sat": 11, "description": "Coffee beans",
      "state": "done", "at": 1794429000, "reason": null }
  ]
}
```

`channel` is null when there is no usable channel. `direction`: `sent`, `received`. `state`: `pending`, `done`, `failed`. Newest first. Paging will be needed and is not designed.

## On-chain wallet

### `getWallet()`

`GET /api/v1/wallet`

```json
{
  "confirmed_sat": 48000, "unconfirmed_sat": 0, "reserve_recommended_sat": 20000,
  "address": "tb1q…", "chain_state": "ok",
  "transactions": [ { "txid": "…", "kind": "received", "amount_sat": 48000, "confirmations": 310, "at": 1794261600, "note": "" } ]
}
```

`kind`: `received`, `sent`, `factory_funding`, `factory_exit`.

### `newAddress()`

`POST /api/v1/wallet/address` → `{ "address": "tb1q…" }`.

Sending on chain is not in the prototype and has no call yet.

## Settings

### `getSettings()`

`GET /api/v1/settings`

```json
{
  "chain": {
    "mode": "public",
    "state": "ok",
    "independent_operators": 2,
    "servers": [ { "id": "mempool-http", "name": "mempool.space", "operator": "mempool.space", "protocol": "http",
                   "address": "https://mempool.space/signet/api", "state": "ok", "height": 330437, "checked_at": 1794434400 } ],
    "own_server": { "address": "" },
    "own_node": { "address": "", "user": "" }
  },
  "host_node": { "kind": "lnd", "address": "", "access_file": "", "linked": false },
  "backup": { "last_export_at": null, "host_copy_at": 1794433500 },
  "reminders": { "warn_days_before": 3, "channels": [ { "id": "in_app", "available": true, "on": true } ] },
  "network": { "current": "signet", "choices": [ { "id": "mainnet", "available": false, "reason": "switched_off_in_release" } ] },
  "roles": { "member": true, "host": false }
}
```

- `chain.mode`: `public`, `own_server`, `own_node`. Server `state`: `ok`, `behind`, `offline`, `disagrees`. `protocol`: `http`, `electrum`.
- `host_node.kind`: `lnd`, `cln`. `access_file` is a path on the machine; its contents never reach the browser.
- `reminders.channels[].id`: `in_app`, `nostr`, `email`, `phone`.
- `network.choices[].reason`: `one_operator`, `switched_off_in_release`, or null.

### `saveSettings(patch)`

`PATCH /api/v1/settings` → the settings as `getSettings` gives them. `patch` may hold any of:

- `chain`: `{ mode, own_server: { address }, own_node: { address, user } }`
- `host_node`: `{ kind, address, access_file }` (clears `linked` until tested again)
- `reminders`: `{ warn_days_before }`
- `network`: `"signet"` or `"testnet4"`

Errors: `address_missing`, `bad_value`, `network_unavailable`, `network_busy` (in a lobby or factory).

### `checkChainServers()`

`POST /api/v1/settings/chain/check` → `{ state, servers }`. Asks every server again now.

### `testHostNode()`

`POST /api/v1/settings/host-node/test` → `{ "linked": true, "operations": [ { "id": "pay", "ok": true } ] }`, with one entry each for `pay`, `hold`, `settle`, `cancel`. Errors: `address_missing`.

### `exportBackup()`

`POST /api/v1/backup/export` → `{ file_name, bytes, exported_at }`. The real call would answer with the encrypted file itself as a download.

## Not covered yet

Calls the screens will need and the prototype marks "not in the prototype": sending on chain; closing a factory together with the host; buying receiving room from the host's spare liquidity; a member's request to change a lobby's rules; lobby chat; changing a lobby's terms; winding a factory down and opening the next lobby; a host's view of its members; the password for the user's own Bitcoin node; scanning a QR code.

Not designed here: how the browser gets the start-up token; paging of long lists; how a restored wallet reports its state while it waits for the host.
