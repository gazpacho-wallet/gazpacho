# Slice 1 screens and the calls behind them

The screen set Slice 1 is wired to: `docs/ux/concept-h-slice1.html` (concept H after the fix round, 12 Nov 2026). This table is for the person wiring it to the program. For each screen and state it gives the data the screen shows and the local API call that supplies it.

**The call names are provisional.** They come from `spec/local-api.md` draft 1 (branch `specs-slice1`). Draft 2 is being written; where this table needs something draft 1 does not have, it says so under "Gaps for draft 2" at the end.

## How to use the mock-up

- Open the file from disk. It makes no network requests.
- The bar above the mock-up has a **Slice 1 / 1.0.0** switch. Slice 1 shows only what Slice 1 builds. 1.0.0 adds the screens of the later slices of the first release. Everything marked 1.1.0 (buying receiving room, splicing, channels opened on demand, shared leaves, coverage, payout addresses per factory, several factories at once, standing rules) is on no Slice 1 or 1.0.0 screen, not shown greyed. It appears only in **Preview: coming in 1.1.0**, a separate set of screens (`data-pv="1"`, ids `scr-pv-*`) with its own purple accent and banner, based on `docs/MULTI-FACTORY.md`. Nothing in the preview is wired for Slice 1; its calls (`GET /api/v1/stack`, `POST /api/v1/moves/preview`, `POST /api/v1/moves`, `GET`/`PUT /api/v1/rules`, the receiving-room calls) are the proposals in that document and in local API section 17.
- In the markup, an element with `data-r="1"` is 1.0.0-only. An element with `data-when="…"` is shown for the states named; the state names below are the values the screen needs from the program.
- **Moments** and **Jump to a scenario** open any state from a clean start. **How it works**, **Hosting tour** and **Rolling forward (1.1.0)** are guided walks for showing the product to people; with the demo banner and the **Words** glossary they are demo-only and are not wired.
- Dashed "Mock-up control" boxes stand in for things the program does by itself. They are not built.
- The interface holds the wording. The program returns codes and numbers (local API section 1, "The program decides; the screens show"). Every countdown shows what happens at zero; the program supplies it in `at_zero` (section 7.2).

## Always present

| Part | State | Data | Call (draft 1) | Mark |
|---|---|---|---|---|
| Signet marker | always | network | `GET /api/v1/status` → `network` | S1 |
| Pause / Resume | `pause.state` = `off`, `on`, `held_for_signing` | pause state; lobbies left | `GET /api/v1/status` → `pause`; `PUT /api/v1/pause` → `left_lobbies` | S1 |
| Strip sentence | one per `doing.code` (table below) | code, params | `GET /api/v1/status` → `doing` | S1 |
| Chain chip | `agree`, `disagree`, `one_source`, `unreachable`, `offline_by_choice` | servers agreeing, operators, height, since | `GET /api/v1/status` → `connection.chain` | S1 |
| Watching chip | `nothing_to_watch`, `this_app`, `nobody_offline`, `nobody_chain_in_doubt`; with `open_by` in 1.0.0 | who, health, open-by date | `GET /api/v1/status` → `watching` | S1 |
| Next date chip | the most urgent date | a date (7.2) | `GET /api/v1/status` → `next_date` | S1 |
| Hosting chip | only when hosting | lobbies open, factories, next date | `GET /api/v1/status` → `hosting` (null until hosting) | S1 |
| Automatic joining chip | `off`, `looking_*`, `budget_used` | state, params | `GET /api/v1/status` → `auto_join` | 1.0.0 |
| At-risk bars | `chain_disagree`, `chain_one_source`, `signing_unfinished` (S1); `nobody_watching` (1.0.0) | attention items, tier `at_risk` | `GET /api/v1/status` → `attention` | S1 |
| Act-now bar | `move_last_try` | tier `act_now`, `due` | `GET /api/v1/status` → `attention` | 1.0.0 |
| Live updates | any | which area changed | `GET /api/v1/events` (server-sent events); then re-read that area | S1 |
| Phone tabs | Home, Lobbies, Conditions, Hosting, Activity (Slice 1); Pay added and Activity moved to the header in 1.0.0 | where Hosting sits on a phone | `GET /api/v1/settings/application` → `hosting_place_on_phones` | S1 tab; 1.0.0 setting |

### Strip sentence for each `doing.code`

| Screen state (`data-when` "story") | `doing.code` | Wording rule |
|---|---|---|
| `nowallet` | `no_wallet` | |
| `new`, `leftpaused` (after resume) | `idle_no_factory` | "You cannot pay or receive until you are in a live one" |
| `waiting` | `in_lobby_waiting` | counts, start rule, deadline with outcome at zero |
| `notcounted` | `in_lobby_not_counted` | ready of needed |
| `standby` | none yet (gap 3) | |
| `signing` | `signing` | "Keep the app open"; Pause takes effect when signing ends |
| `unfinished` | `signing_unfinished` (purpose `start`) | never "nothing was signed"; not live |
| `funding` | `awaiting_funding` | "Not live yet" |
| `refused` | `refused` | both numbers; "Nothing was signed. Nothing moved." |
| `cancelled` | `lobby_cancelled` | "Not your doing" when `not_your_doing` |
| `notchosen` | `not_chosen` | "Not your doing" |
| `removed` | none yet (gap 8) | host's reason as quoted host text |
| `abandoned` | `creation_abandoned` | "You owe nothing and are owed nothing" |
| `live` | `idle_in_factory` | |
| alert `risk`, `onesource` | `chain_in_doubt` | never "has not moved" |
| alert `hostsilent` | attention `host_not_answering` | Important, no date |
| alert `soon` | attention `date_near` (gap 6) | Heads-up, told once |
| `paused` | `paused` | |
| 1.0.0: `behind`, `leaving`, alert `deadline` | `left_behind`, `leaving_alone`, attention `move_last_try` | "while it is running and has coins for fees" |

## Access and first run

| Screen | State | Data | Call (draft 1) | Mark |
|---|---|---|---|---|
| Sign in | signed out | session state | `GET /api/v1/session` | S1 |
| Sign in | code typed | the code | `POST /api/v1/session`; errors `bad_code`, `code_expired`, `too_many_attempts`, `rate_limited` | S1 |
| Sign in | locked | | `POST /api/v1/session/unlock` | S1 |
| Settings, Application | lock now, sign out, sign out everywhere | | `POST /api/v1/session/lock`, `DELETE /api/v1/session`, `POST /api/v1/session/revoke-all` (fresh sign-in) | S1, revoke-all 1.0.0 |
| First run, step 1 | make or restore; networks offered | setup state, networks and why unavailable | `GET /api/v1/wallet/setup` | S1 |
| First run, step 1 | restore from 24 words | words typed; first bad position or checksum | `POST /api/v1/wallet/restore` → `bad_words` | **1.0.0 in draft 1** (gap 2) |
| First run, step 2 | the 24 words, veiled until "Show" | the words | `POST /api/v1/wallet/create` → `words` (the only answer that carries them without a fresh sign-in) | S1 |
| First run, step 3 | check three words; mismatch; skip | positions; ok or not | `POST /api/v1/wallet/phrase/check-start`, `POST /api/v1/wallet/phrase/check` | S1 (gap 1) |
| First run, step 4 | preset | presets and every number they set; fit count | `GET /api/v1/conditions` → `presets`, `fit_summary` | S1 |
| First run, step 5 | two doors, dedication line | | `POST /api/v1/wallet/finish-setup` (`find: "browse"` in S1) | S1 |
| About | Dedication, Credits, Licences | texts | `GET /api/v1/about` | 1.0.0 in draft 1; the interface can hold the texts in Slice 1 |

Key handling, on every screen that shows the words:
- The words are in the page only while shown: the interface writes them into the page on "Show", removes them on "Hide", on leaving the screen, and after 2 minutes. Never in a URL, an event, browser storage or a log (local API 5.5).
- No copy button, nothing placed on the clipboard; the word list is not selectable.
- A failed check says only that the words do not match. It never says which position was wrong (owner decision; see gap 1).
- Later reveals (Settings, Wallet) need a fresh sign-in: `POST /api/v1/session/fresh`, then `POST /api/v1/wallet/phrase/reveal`.

## Home

| State | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Before any factory; in a lobby; waiting for funding; live; signing did not finish | `money` (on chain free, set aside, inside factories), `doing`, `attention`, `next_date` | `GET /api/v1/status` | S1 |
| My lobbies and factories card | lobby row or factory with its dates | `GET /api/v1/lobbies` (the one with `you.seat` not `none`), `GET /api/v1/factories` | S1 |
| Hosting section (only when hosting) | host lobby stage and counts | `GET /api/v1/host/lobbies` | S1 |
| To do, in tiers | attention items: `words_not_checked`, `host_not_answering`, `host_can_start`, `refused_to_sign`, the at-risk codes | `GET /api/v1/status` → `attention` | S1 |
| Latest activity | three entries | `GET /api/v1/activity?limit=3` | S1 |
| "Find a lobby" and "Host a lobby" side by side, for every wallet; "Host your first lobby" offered once the first factory is live (no role question anywhere) | whether this wallet hosts anything; whether a factory is live | `GET /api/v1/status` → `hosting`, `doing.code` | S1 |
| Figures while the chain view is in doubt | last trusted height | `money.chain_view = in_doubt`, `money.as_of_height` | S1 |
| 1.0.0: can send, can receive, take out alone, while closed | | `money.*`, `take_out_alone`, `GET /api/v1/while-closed/{id}` | 1.0.0 |

## Conditions

| State | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Preset table and limits | conditions, version, presets, limits | `GET /api/v1/conditions` | S1 |
| Live count and "the limit that excludes most" as you type | fit summary, `excluded_most_by` | `POST /api/v1/conditions/preview` | S1 |
| Save; saved; saved and left a lobby; refused during signing | new conditions; lobbies left with the failing rows | `PUT /api/v1/conditions` → `left_lobbies`; error `signing_now` | S1 |
| Hosts I avoid | list | inside the conditions object (`hosts_avoided`) | S1 |
| 1.0.0: people blocked, how I appear, moving | | same object | 1.0.0 |
| Automatic joining | standing permission, budget, instructions and their history | `GET /api/v1/conditions` (13.6), `GET /api/v1/activity?show=by_app` | 1.0.0 |

## Finding a lobby and joining

| Screen | State | Data | Call (draft 1) | Mark |
|---|---|---|---|---|
| Lobbies | add a host by address: found, no answer, wrong key, wrong network | lobbies found | `POST /api/v1/discovery/query` → `bad_host_address`, `host_unreachable`, `key_mismatch`, `wrong_network`, `rate_limited`; then `discovery` events | S1 |
| Lobbies | the list, fits first; "does not fit" and "fits only now" listed together with the failing rows | rows with `fit.class` and failures | `GET /api/v1/lobbies?show=all&sort=…` | S1 |
| Lobbies | open an invitation | | `POST /api/v1/invitations` | 1.0.0 |
| Lobby | sealed terms, fingerprint, ranges, standby seats, who may join, host's note as quoted host text | the terms object | `GET /api/v1/lobbies/{id}` → `terms` (13.3) | S1 |
| Lobby | fit check, row by row, both numbers on a failing row | fit | `GET /api/v1/lobbies/{id}` → `fit` (13.4) | S1 |
| Lobby | does not fit: Join disabled with the reason | | `fit.class = does_not_fit` | S1 |
| Review and join (terms at commitment) | costs at most, fees, what you get, start rule, end date; consent notice; fit check; Join after the fit check | lobby object, current digest | `GET /api/v1/lobbies/{id}` | S1 |
| Review and join | the host moved a value | the change | `POST /api/v1/lobbies/{id}/join` → `terms_changed`, or the `terms_change` field | S1 |
| Review and join | Join | | `POST /api/v1/lobbies/{id}/join` with `seen_current_digest`, `ready: true`; errors `conditions_not_met`, `fits_only_now`, `already_in_lobby`, `paused`, `chain_in_doubt`, `host_unreachable`, `lobby_full` | S1 |
| Joined | waiting, not counted yet | counts, `counted_from`, conditions copied at | `GET /api/v1/lobbies/{id}` → `counts`, `you`, `fit.counted_from` | S1 |
| Joined | on standby | standby position | none yet (gap 3) | 1.0.0 |
| Joined | leave | | `POST /api/v1/lobbies/{id}/leave` | S1 |
| Joined | signing, as a checklist | the app's own checks; signatures done of total | `GET /api/v1/lobbies/{id}` → `round` (`checks`, `signatures`) | S1 |
| Joined | refused at the check, with both numbers and next step | outcome and failures | `you.outcome.code = refused_at_check`, `failures` | S1 |
| Joined | signing did not finish | sent at, last heard, checked to height, settle deadline | `you.outcome.code = signing_unfinished`, `round.state = unfinished`, `round.unfinished_deadline` | S1 |
| Joined | cancelled, not chosen, removed by the host, abandoned | outcome, reason, host's reason text | `you.outcome` (`cancelled` with `not_your_doing`, `not_chosen`, `removed`, `abandoned`) | S1 |
| Joined | waiting for funding | funding txid, confirmations of needed, deadline | `GET /api/v1/lobbies/{id}` → `funding` | S1 |
| Joined | live | factory id | `you.outcome.code = started`, `factory_id` | S1 |
| Joined | paused: left before the start | | `PUT /api/v1/pause` → `left_lobbies`; `you.outcome.code = left`, reason `paused` | S1 |

## The live factory

| State | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Waiting for funding, live, did not finish, abandoned | state, funding (txid, confirmations, needed, height), tree (levels, path), members, saved copy of the terms | `GET /api/v1/factories/{id}` | S1 |
| The dates, each with "at zero" and "Where this date comes from" | `factory_ends`, funding deadline | `GET /api/v1/factories/{id}/dates` (S1 returns these two) | S1 |
| Terms I joined under (a saved copy that never changes) | saved copy | `GET /api/v1/activity/{saved_copy_activity_id}` | S1 |
| 1.0.0: open the app by, move window, start leaving alone; money here; what can go wrong | | `dates` with provenance, `channel`, `exit`, `trouble` | 1.0.0 |
| 1.0.0: Move (before, window open, failed before signatures, did not finish, moved, left behind) | | `GET`/`POST /api/v1/factories/{id}/move` | 1.0.0 |
| 1.0.0: Leave alone (estimate, under way, done) | | `POST …/leave-alone/preview`, `POST …/leave-alone` (fresh sign-in), `GET …/leave-alone` | 1.0.0 |

## On chain

| State | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Balance free and set aside; coins | | `GET /api/v1/wallet` | S1 |
| Show a new address | address | `POST /api/v1/wallet/address` | S1 |
| 1.0.0: send, review, sent | | `POST /api/v1/wallet/send/preview`, `POST /api/v1/wallet/send` (fresh sign-in) | 1.0.0 |
| 1.0.0: transactions; a stuck one; speed up through pay-to-anchor | | `GET /api/v1/wallet/transactions`, `POST …/speed-up/preview`, `POST …/speed-up` | 1.0.0 |

## Hosting

| Screen | State | Data | Call (draft 1) | Mark |
|---|---|---|---|---|
| Hosting | starting page (nothing hosted): what hosting needs, funds against the wallet | wallet free | `GET /api/v1/wallet`; `status.hosting = null` | S1 |
| Hosting | overview: money from the one wallet, next sentence, my lobby, my record | | `GET /api/v1/host/lobbies`, `GET /api/v1/wallet` | S1 |
| Write terms | form and live preview as members will see it (ranges, base, standby seats, who can find it); funding at minimum and target; problems; can or cannot open | preview | `POST /api/v1/host/preview` → `as_members_see_it`, `funding_at_*`, `problems`, `cannot_open_because` | S1 |
| Write terms | sign and open | the host lobby | `POST /api/v1/host/lobbies` with `draft_digest` | S1 |
| My lobby | open, below the minimum (Start disabled with the reason) | counts, `can_start_now`, `start_blocked_by` | `GET /api/v1/host/lobbies/{id}` | S1 |
| My lobby | invite | invitation text | `POST /api/v1/host/lobbies/{id}/invitations` | 1.0.0 (gap 4) |
| My lobby | remove a seat before the ready check, with a reason | | `DELETE /api/v1/host/lobbies/{id}/seats/{seat}`; `frozen` after the ready check | 1.0.0 (gap 5) |
| My lobby | standby list | standbys in order | none yet (gap 3) | 1.0.0 |
| My lobby | can start; Start | | `POST /api/v1/host/lobbies/{id}/start` → `below_minimum`, `funds_short`, `chain_in_doubt` | S1 |
| My lobby | cancel; too late to cancel once signing began | | `POST /api/v1/host/lobbies/{id}/cancel` → `too_late` | S1 |
| My lobby | ready check, signing, silent seats (the app's observation, not proof), funding last, live | round state and counts, funding tx | `GET /api/v1/host/lobbies/{id}` → `round` (`collecting_*`, `failed` with `silent`), `funding_tx` | S1 |
| 1.0.0: factories (ladder), one factory, earnings, setup (node, limits, backup) | | | `GET /api/v1/host/factories`, `…/{id}`, `GET /api/v1/host/earnings`, `GET`/`PATCH /api/v1/host/setup`, `PUT /api/v1/host/node` | 1.0.0 |

## Activity

| State | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Everything, done by the app alone, refusals (payments in 1.0.0) | entries with who decided and the rule | `GET /api/v1/activity?show=…` | S1 |
| A saved copy | terms, fit and conditions as they were | `GET /api/v1/activity/{id}` | S1 |
| 1.0.0: while the app was closed, with what was checked | | `GET /api/v1/while-closed/{id}` | 1.0.0 |

## Settings

| Screen | Data | Call (draft 1) | Mark |
|---|---|---|---|
| Settings index | | none (static) | S1 |
| Wallet: the words, checked or not; show (fresh sign-in); check again | | `GET /api/v1/backup` (words part in S1), `POST /api/v1/session/fresh`, `POST /api/v1/wallet/phrase/reveal`, `…/check-start`, `…/check` | S1 |
| Wallet: factory backup, restore | | `GET /api/v1/backup`, `POST /api/v1/backup/export`, `…/import`, `…/ask-host`, `GET /api/v1/backup/restore` | 1.0.0 |
| Wallet options: routing limit, fee rate, network, remove the wallet | | `GET`/`PATCH /api/v1/settings/wallet`, `POST /api/v1/wallet/remove` | 1.0.0 |
| Watching: now; mine inside a factory (nothing in Slice 1) | | `GET /api/v1/status` → `watching` | S1 |
| Watching: safe absence, coins for fees, choices, going offline | | `GET`/`PATCH /api/v1/settings/watching`, `POST /api/v1/settings/watching/offline`, `fee_cover` | 1.0.0 |
| Connections: chain servers and their states, known hosts | | `GET /api/v1/settings/connections` | S1 (read) |
| Connections: add or remove a server, check now, Nostr listings | | `POST`/`DELETE …/servers`, `POST …/check`, `PATCH` | 1.0.0 |
| Application: display, hosting on a phone, lock, logs | | `GET`/`PATCH /api/v1/settings/application`, `GET /api/v1/logs` | 1.0.0 (the interface can keep display choices itself in Slice 1) |

## Gaps for draft 2 of the local API

1. **The words check must not say which word was wrong.** Draft 1's `POST /api/v1/wallet/phrase/check` answers `wrong_positions`. The owner's rule is that a check never reveals which words are wrong. Answer `{ "ok": false, "tries_left": 2 }` only; the interface already ignores the positions.
2. **Restore in Slice 1.** First run offers restore, but `POST /api/v1/wallet/restore` is marked 1.0.0. Mark it S1 (keys and on-chain coins only; factories still need a backup, 1.0.0).
3. **Standby seats** (decision 10) have no call, field or status: a `standby` count in the terms, a `you.seat = "standby"` value with a position, a `doing.code` for it, and the host's ordered standby list in the host lobby object. `messages.md` section 9 lists standby seats as having no messages yet.
4. **Invitation-only lobbies.** `terms.md` draft 2 reserves record type 38 (invitation-only), and a 1.0.0 app refuses a lobby carrying it. The screens use the existing route instead: an unlisted lobby (`listed: false`) reached only through an invitation. `POST /api/v1/host/lobbies/{id}/invitations` and `POST /api/v1/invitations` are 1.0.0, and `SLICES.md` leaves invitations out of Slice 1. If invitation-only lobbies are meant to protect free seats in Slice 1's runs, both calls move to S1.
5. **Removing a seat** is 1.0.0 in draft 1, but decision 10 makes host removal part of how free seats are protected. Decide whether Slice 1 needs it.
6. **"Deadline near" in Slice 1** uses attention `date_near` (heads-up, told once), marked 1.0.0. The lobby-starts-soon reminder needs it in Slice 1.
7. **Funding figures.** Draft 1's examples give 22,500,000 sats at a minimum of 30 members with 500,000-sat channels, which matches concept H's 750,000 per member (channel plus spare liquidity). Spare liquidity is 1.1.0; without it the figures are 15,000,000 at 30 and 25,000,000 at 50, as the screens show.
8. **`doing.code` for "removed by the host"** is missing (the outcome `removed` exists). Add `removed_by_host`, with the host's reason as `{ text, by: "host" }`.
9. **Watching with a factory but no channel.** In Slice 1 a member is in a live factory with nothing of its own inside. Say which `watching.state` applies (the screens show "this app, while it runs" and "nothing of yours inside") and that `open_by` is absent.
10. **Speed-up** appears twice (sections 16.4 and 18) with different paths for the same action; keep the section 18 pair.
11. **Preset numbers under decision 9.** With fixed levels only, leaving alone takes days rather than about a week, so the screens use 3, 5 and 7 days for Cautious, Everyday and Wide. Still open (critique question 13).
12. **Safe absence under decision 9** is the channel's revocation wait, which the channel specification has not set. The 1.0.0 screens use a placeholder of 1,008 blocks less a 288-block margin, tagged open; `open_by` provenance `revocation_window_less_margin` already exists.
