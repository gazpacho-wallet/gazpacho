# Slice 1 screens and the calls behind them

The screens Slice 1 ships with, as built in `web/` (layout concept H), and the local API calls and events each one uses. Redone on 15 November 2026 against `spec/local-api.md` draft 4 (with the fixes of cross-spec review 1); the earlier version of this table was keyed to draft 1. For the person who wires the real program to the API (P6) and for anyone changing a screen.

Rules that hold for every screen:

- **The program decides; the screens show** (spec section 1). Every sentence on a screen is chosen from a code and numbers the program returned. The wording tables are in `web/js/words.js`. A code without wording is shown as "unknown state", never as success (section 6).
- **Calls are the ones in section 2.1 and no others.** The interface invents none. Where a screen needs something the spec does not have, it is listed under "Gaps" at the end and the screen does without.
- **Every call goes through `web/js/api.js`**: a same-origin `fetch()` with a relative address, the session token in the `X-Gazpacho-Session` header, `X-Gazpacho-User: 1` only within two seconds of the person touching the page, and never on a request made because an event arrived (4.7, 10.2).
- **Events say which area changed** (10.2). The column "Redrawn on" gives the topics that make a screen ask again. A screen with a form in it is not redrawn under the person's typing; it asks again when they act.

## Always present

| Part | What it shows | Calls | Redrawn on |
|---|---|---|---|
| Network marker | "Signet: test coins, no value" | `GET /version`, then `GET /status` → `network` | `status` |
| Strip sentence | One sentence per `doing.code` (11.2), with a link to the lobby or factory it names | `GET /status` → `doing` | `status`, `chain`, `wallet`, `reset` |
| Pause, Resume, "Pausing…" | `pause.state`: `off`, `on`, `held_for_signing` | `PUT /pause` (`{ on: true }`; `{ on: false, confirm: "resume" }`, kind B) → `left_lobbies`, `held_lobby` | `status` |
| Chain chip | `connection.chain.state` and height | `GET /status` | `status`, `chain` |
| Watching chip | `watching.state` | `GET /status` | `status` |
| Next date chip | `next_date` with what happens at zero | `GET /status` | `status` |
| Hosting chip | only when `hosting` is not null | `GET /status` → `hosting` | `status` |
| Live updates chip | following, reconnecting, too many windows, stopped | the stream's own state (10.3) | — |
| At-risk bars | every `attention` item of tier `at_risk`; a held lock; weak memory protection | `GET /status` → `attention`, `lock`, `interface.memory_locked` | `status` |
| The stream | | `GET /events`, read with `fetch()`; `Last-Event-ID` on a reconnect; reconnects after 2, 4, 8 … 60 s; never after a `4xx`; `429` not retried | — |
| Other tabs | hand-over of a normal session; "signed out"; relayed events when this tab has no stream | `BroadcastChannel` `gazpacho-session-<port>`: `ask`, `offer`, `signed_out`, `leader`, `leader_gone`, `event` (4.4) | — |

The strip's sentences, by `doing.code`: `no_wallet`, `restoring`, `node_stopped`, `signing`, `signing_unfinished`, `chain_in_doubt`, `awaiting_funding`, `paused`, `ready_check`, `in_lobby_not_ready`, `in_lobby_not_counted`, `in_lobby_waiting`, `creation_dead`, `creation_abandoned`, `refused`, `refused_by_host`, `lobby_cancelled`, `not_chosen`, `idle_in_factory`, `idle_no_factory`. `files_behind` and `wallet_locked` are shown on the gate screens below, not in the strip. The 1.0.0 codes have no wording yet and would show as "unknown state".

## Getting in

| Screen | State | What it shows | Calls |
|---|---|---|---|
| Start-up | every load | version and network check; **refuses mainnet** | `GET /version`, `GET /session` |
| No wallet, no start link | `wallet: none`, not signed in | "Open Gazpacho from the program", the first-run code field | `POST /session/start` with `{ code }` → `bad_code`, `code_expired`, `too_many_attempts`, `rate_limited` |
| First run from the program | the fragment `#start=<43 characters>` | the token is read, taken out of the address, and sent once | `POST /session/start` with `{ start_token }` → a setup session |
| Hijack warning | `token_used` or `wallet_exists` within 10 minutes of `first_run_launched_at` | the warning of 4.3, in place of every other screen | `GET /session` → `first_run_launched_at` |
| Sign in / Unlock | a wallet exists, not signed in | the passphrase field; the locked headline; "the wallet is still unlocked" when only this browser is signed out | `GET /status` (locked shape, no session) → `watching.headline`; `POST /session` → `wrong_passphrase`, `rate_limited` (`retry_after_s`), `passphrase_not_checked`, `node_stopped` |
| Files older than the wallet | session kind `files_behind` | start as a restore (the passphrase, in a dialog), or stay locked | `POST /wallet/start-as-restore` (`confirm: "restore_new_keys"`, kind A); `DELETE /session` |
| Passphrase again (dialog) | any kind B call answered `fresh_sign_in_needed` | the passphrase; then the same request is sent again | `POST /session/fresh` |

## First run

Never asks "member or host" (decision 4). Steps are numbered on the screen.

| Step | What it shows | Calls |
|---|---|---|
| 1. Make a wallet, or bring one back | the two choices; the networks, with mainnet "switched off in this release" | `GET /wallet/setup` → `state`, `network`, `networks` |
| 1b. Restore | 24 fields, one per word, with matching words offered from the 24-word list in the page | none until step 2 |
| 2. Choose your passphrase | six generated words first (typed once to confirm), or the person's own (at least 15 characters, typed twice, with a live count) | `POST /wallet/create` (`confirm: "create_wallet"`, `passphrase`, `confirm_passphrase`) → `words`; or `POST /wallet/restore` (`words`, `passphrase`, `confirm_passphrase`) → `restoring`; errors `weak_passphrase` (`reason`, `length`, `minimum`), `passphrases_differ`, `bad_words` (`position` or `reason: "checksum"`), `rate_limited` |
| 3. Write down the 24 words | not in the page until "Show the words"; out of the page while the tab is hidden; "Show again"; cleared on Done, on leaving, on `pagehide` and `freeze`, and after 10 minutes | the `create` answer; later only `POST /wallet/phrase/reveal` (`confirm: "show_words"`, `passphrase`) |
| 3 (resumed) | setup was left unfinished (a closed tab, a restart): show the words again, check them, or go on | `GET /wallet/setup` → `created_not_finished`; `GET /backup` → `words.checked_at` |
| 4. Check the words | three positions, three fields, the passphrase; "Skip for now" | `POST /wallet/phrase/check-start` → `check_id`, `positions`, `checks_left_today`; `POST /wallet/phrase/check` (`check_id`, `passphrase`, `words`) → `ok`. A failed check never says which word; the session has ended, so the sign-in screen follows |
| 5. Say what you will accept | the presets and every number each sets | `GET /conditions` → `presets`; `POST /wallet/finish-setup` (`preset`, `find: "browse"`) |
| 6. Find a lobby, or host one | the doors; the dedication line | none |
| Restoring (on Home) | "Your balance is not confirmed yet"; coins found; factories not known and not watched | `GET /wallet/restore`; redrawn on `wallet`, `status` |

## Home

| Part | What it shows | Calls | Redrawn on |
|---|---|---|---|
| My money | on chain and free; set aside for hosting; inside factories (0 in Slice 1, said so); in factories I host | `GET /status` → `money` | `status`, `wallet`, `chain` |
| Figures in doubt | "These figures may be old", with the height | `money.chain_view = in_doubt`, `money.as_of_height` | `status`, `chain` |
| What the app is doing | the strip's sentence, larger | `GET /status` → `doing` | `status` |
| My lobbies and factories | every lobby with a seat, every hosted lobby, every factory (several at once, decision 16b) | `GET /lobbies?show=all`, `GET /host/lobbies`, `GET /factories` | `lobby`, `host_lobby`, `factory` |
| To do | attention items in tiers, each with its way out | `GET /status` → `attention` (`words_not_checked`, `refused_to_sign`, `host_can_start`, the chain codes, `signing_unfinished`, `restored_factories_unknown`, …) | `status` |
| Latest activity | three entries | `GET /activity?limit=3` | `activity` |

## Conditions

| State | What it shows | Calls |
|---|---|---|
| The limits | the nine limits Slice 1 compares (13.1), with the program's bounds; the presets | `GET /conditions` → `conditions`, `limits`, `presets`, `fit_summary`, `copied_into`, `editable`, `version` |
| As the numbers are typed | how many lobbies fit; the limit that excludes most; lobbies the app would leave; what loosens | `POST /conditions/preview` → `fit_summary`, `would_leave`, `loosens`, `problems` |
| Save | saved; saved and left lobbies; the passphrase again when it loosens | `PUT /conditions` (`conditions`, `based_on_version`, `preset`, `confirm_loosens`; kind B when it loosens) → `left_lobbies`; errors `changed_elsewhere`, `signing_now`, `below_floor`, `confirm_mismatch`, `bad_value` |

## Lobbies

| Screen | State | What it shows | Calls | Redrawn on |
|---|---|---|---|---|
| Lobbies | add a host by its address | the host's answer, or why not | `POST /discovery/query` (`host`) → `query_id`; `GET /discovery/queries/{id}` until `answered` or `failed` (`host_unreachable`, `key_mismatch`, `timed_out`); errors `bad_host_address`, `wrong_network`, `rate_limited` | `discovery` |
| Lobbies | the list | fits first; "does not fit" and "fits only now" together, each with the failing rows and both numbers | `GET /lobbies?show=all&sort=fit` | `lobby`, `conditions` |
| Lobby | not joined | the sealed terms (the host's words quoted as the host's); the fit check row by row; review and join, with the consent notice; Join off, with the reason, when it does not fit | `GET /lobbies/{id}` → `terms` (13.3), `fit` (13.4), `start_rule`, `counts`, `you`; `POST /lobbies/{id}/join` (`request_id`, `seen_current_digest`, `ready: true`) → `conditions_not_met`, `fits_only_now`, `terms_changed`, `already_in_lobby`, `paused`, `chain_in_doubt`, `not_open`, `host_unreachable`, `lobby_full` | `lobby`, `status`, `conditions` |
| Lobby | joined, waiting | the seat, counted or not, ready of target, the start rule and its deadline with "at zero"; ready / not ready; leave | `PUT /lobbies/{id}/ready`, `POST /lobbies/{id}/leave` (`too_late` once signatures are out) | `lobby`, `status` |
| Lobby | the signing moment | the round's state; signatures done of total; the program's own checks as a checklist | `GET /lobbies/{id}` → `round` (`state`, `signatures`, `checks`) | `lobby` |
| Lobby | outcomes | one wording per `you.outcome.code`: `refused_at_check` (both numbers; "nothing was signed"), `aborted_before_signatures`, `refused_by_host`, `not_chosen`, `cancelled` (`not_your_doing`), `left`, `removed`, `signing_unfinished` (never "nothing was signed"; `unfinished_deadline`; `cancel_received`), `abandoned` (`still_watched`), `dead`, `started` | `GET /lobbies/{id}` → `you.outcome`, `round` | `lobby`, `status` |
| Lobby | waiting for funding | funding state, confirmations of needed, the deadline, the way to the factory | `GET /lobbies/{id}` → `funding`, `factory_id` | `lobby` |

## Hosting

| Screen | State | What it shows | Calls | Redrawn on |
|---|---|---|---|---|
| Hosting | always there | coins free and set aside; my lobbies; "Write terms" | `GET /host/lobbies`, `GET /wallet` | `host_lobby`, `status`, `wallet` |
| Write terms | the form and the program's preview | problems; funding at the minimum and the target; whether the wallet covers it; the dates; the terms as members will see them; whether it can be opened and why not | `POST /host/preview` (the draft of 15.1) → `draft_digest`, `as_members_see_it`, `funding_at_*`, `covers`, `dates`, `host_deadlines`, `problems`, `can_open`, `cannot_open_because` | — |
| Write terms | sign and open | the amount set aside and the consent, then the passphrase in the request | `POST /host/lobbies` (`request_id`, `draft`, `draft_digest`, `confirm_funding_sat`, `passphrase`; kind A) → `draft_changed`, `confirm_mismatch`, `wrong_passphrase`, the `cannot_open_because` values | — |
| My lobby | open | ready of target; "starts by itself"; Start now on or off with the reason; cancel | `GET /host/lobbies/{id}` → `counts`, `can_start_now`, `start_blocked_by`, `funding`; `POST …/start` (`confirm_funding_max_sat`, kind B); `POST …/cancel` → `too_late` | `host_lobby`, `status` |
| My lobby | seats | each seat and its state; remove before the ready check | `seats[]`; `DELETE /host/lobbies/{id}/seats/{seat}` (`confirm_seat`, kind B) → `frozen` | `host_lobby` |
| My lobby | signing and funding | the host's round; funding published by the program itself, last (decision 16a); the way to the factory | `round`, `funding_tx`, `factory_id` | `host_lobby`, `factory` |

## The factory

| State | What it shows | Calls | Redrawn on |
|---|---|---|---|
| Waiting for funding; live; other states by name | "Not live yet" until `state = live`; funding amount, state, confirmations of needed; what is mine here (nothing, in Slice 1); the tree in words; the host; the terms; the saved copy | `GET /factories/{id}` → `state`, `role`, `members`, `funding`, `tree`, `host_view`, `channel`, `terms`, `saved_copy_activity_id` | `factory`, `status` |
| Dates | each date with what happens at zero and where it comes from | `GET /factories/{id}/dates` (`funding_deadline`, `factory_ends`) | `factory` |

## Activity

| State | What it shows | Calls | Redrawn on |
|---|---|---|---|
| The list | everything; done by the app alone; refusals. Each with who decided and under which rule; a refusal with both numbers | `GET /activity?show=…` | `activity` |
| A saved copy | the terms, the fit check and the conditions as they were | `GET /activity/{id}` → `saved_copy` | — |

## Settings

| Part | What it shows | Calls | Redrawn on |
|---|---|---|---|
| The 24 words | checked or not; show them (the passphrase typed for that request); check them | `GET /backup` → `words`; `POST /wallet/phrase/reveal`; `…/check-start`; `…/check` | `status` |
| On chain | free, unconfirmed, set aside, coins; a new address | `GET /wallet`; `POST /wallet/address` | `wallet` |
| Watching | who watches | `GET /status` → `watching` | `status` |
| Connections | chain servers with operator and state; hosts the app knows | `GET /settings/connections` | `chain`, `settings` |
| Sign out and lock | sign out; sign out everywhere; lock, with the warning that fits (nobody watches while locked, in every Slice 1 build) | `DELETE /session`; `POST /session/revoke-all` (`confirm: "revoke_all"`, kind B); `POST /wallet/lock` (`confirm: "lock_wallet"`, and `confirm_locked: "nobody_watching"` while anything needs watching, kind B) → `hosting_lobby_open`, or `lock.state = held_for_signing` | `status` |
| About | version; dedication; credits; licences | `GET /version`; the texts are held by the interface | — |

## Errors every screen can meet

| Answer | What the interface does |
|---|---|
| `401 not_signed_in` | Drops its token, tells the other tabs, shows the sign-in screen |
| `423 wallet_locked` | The same, with the unlock screen and the locked headline |
| A `session` event | The same; the stream is closed and not reopened |
| `403 fresh_sign_in_needed` | Asks for the passphrase, calls `POST /session/fresh`, sends the same request again |
| `429 rate_limited` | Says how long to wait and holds the button for that long |
| `503 node_busy` | Says the last request is still being saved; "Try again" sends the same `request_id` (7.4), so it cannot act twice. While a call is in flight the screen is not redrawn under it |
| `503 node_stopped` | Says the node is starting again from its files |
| `409 confirm_mismatch`, `changed_elsewhere`, `draft_changed`, `terms_changed` | Says nothing was done, and shows the current values again |
| No answer at all | "Gazpacho is not answering", with "Try again"; the live-updates chip says what is shown may be old |
| An unknown code or state | "unknown state (code)"; never a success wording |

## Gaps

Places where the spec lacks something a Slice 1 screen needs, or says something an owner decision has since changed. None was filled by inventing a call. The numbers are used in `docs/handoff/2026-11-15-interface-wiring.md`.

1. **Several lobbies at once** (owner decision 16b, 13 November). The spec still has Slice 1's one-lobby rule: `already_in_lobby` (14.2), `already_hosting` and `cannot_open_because` (15.1), 24.2 item 9. The screens are built for several of each (lists everywhere, no "the lobby"); the two errors keep their wording for as long as the program sends them. Two things several lobbies need that the status lacks: `doing` names one lobby, chosen by priority, and nothing says whether `doing.lobby_id` (or an attention item's `lobby_id`) is a lobby joined or a lobby hosted. The interface tries `GET /lobbies/{id}` and then `GET /host/lobbies/{id}`.
2. **Member signing modes** (owner decision 16d: C, "unlock once when I join", is the default; A and B are options). The API has no place for them: `join` takes no passphrase and no mode; no call sets a default mode (Settings are 1.0.0); there is no state for "waiting for your passphrase" (mode B) in `you.seat`, `doing.code` or attention, and no call to give the passphrase when the lobby fills; nothing reports "not unlocked, so counted as not answering the ready check". What is built is what the API does today: joining is the consent and the app then signs by itself, which is mode A's behaviour. The join screen says exactly that. Needed: a mode on `join` (and what a host allows, if hosts may restrict it), the passphrase in the `join` request for C (kind A), a `doing.code` and attention item for B with a call that carries the passphrase, and an outcome for "did not unlock in time".
3. **The suggested passphrase** (owner: six generated words offered first; `spec/storage-encryption.md` 14: "Gazpacho has made a passphrase for you"). No call returns one. The interface makes the six words itself, with the browser's random source, from the same EFF list the program holds (`web/js/eff.js`, generated from `ports/storage/crypto/sc_wordlist.c` and checked equal by a test). To decide: keep it in the page, or add a setup-session call.
4. **The host cannot see why a member left at signing.** `seats[].state` has only the seat values of 14.1, and the host's `round.state = failed` carries only `silent` and `invalid` counts. A member whose own check fails sends `round_abort` and shows on the host's screen as `left`, with the lobby Open again. "A member whose conditions are not met is seen to refuse" is therefore complete on the member's screen (both numbers, the failed check, the saved copy) and partial on the host's ("a member left at its own check").
5. **No `doing.code` for "removed by the host"** (the outcome `removed` exists; 11.2 has `refused_by_host` only). The strip falls back to the next code. Open since the draft 1 table.
6. **"Your lobby starts soon"** has no Slice 1 attention code (`date_near` is 1.0.0). The next-date chip shows the date; nothing announces it.
7. **Standby seats** (`you.standby`, the host's `standby`) are answered `null` until the protocol has their messages (2.1, provisional). No screen shows them yet, and there is no `doing.code` for standing by.
8. **The SharedWorker and the page's content-security policy.** 10.3 asks for the stream in a `SharedWorker`; 5.4's policy for the pages has `require-trusted-types-for 'script'; trusted-types 'none'`. In Chromium a worker's address is a Trusted Types sink, so with no policy allowed the page cannot create the worker at all (recorded by `tests/web/quality.spec.mjs`). The interface therefore uses 10.3's other path on every browser: each tab opens the stream itself, a tab answered `429 too_many_streams` follows the events another tab relays, and takes over on `leader_gone`. The spec should either name a Trusted Types policy for the worker's address or drop the worker.
9. **After a restore, what `GET /wallet/setup` says next** is not stated: 12.1 lists `restoring` but not whether a restored wallet then needs `finish-setup` (a preset). The interface handles both: `created_not_finished` leads to the preset step, `ready` to Home.
10. **Lobby rows.** 14.2 says a row carries `fit.class` and "the failing rows' terms" without giving their shape. The interface reads `fit.rows` when present.
11. **Why a session ended** is not said: the `session` event has no reason, and `{ "ok": false }` from the words check does not say the session is now over (12.3 does). The sign-in screen can only say "this session ended" and read `GET /session` for locked or not.
12. **The delay after a wrong passphrase** is learnt only by trying again: `wrong_passphrase` carries no `retry_after_s`.
13. **Copying an address.** `POST /wallet/address` is Slice 1 (a host must receive coins), but 5.4 allows no copy control and sets `clipboard-write=()`, saying an address copy "is a change to this spec". The address is shown as text the person selects by hand.
14. **About.** `GET /about` is 1.0.0, so the interface holds the dedication line, the credits and a licence note itself (decision 7 allows that for Slice 1).
