# Hand-off: the interface wired to the local API (S10)

15 November 2026. Written so that another team can take this over without the people who built it. It is an internal note, not a request to SuperScalar.

**In one paragraph.** The local web interface (layout concept H) now lives in the repository under `web/`, is compiled into the API server, and does every Slice 1 action through the real local API (`spec/local-api.md` draft 4): first run, the 24 words and their check, the passphrase, sign-in and lock, the status strip and the live event stream, conditions, finding and joining a lobby, the waiting view, the signing moment and its refusals, hosting, the factory, and the error states. Behind the API there is still only the fake backend (`gz-api-fake`), extended with a "story" so that a lobby really moves through ready check, signing, funding and live. The program wired to the API (P6) replaces the fake; no screen should need to change for that, and where one does, the fault is listed here or the spec is.

## What is built

| Piece | Where | Notes |
|---|---|---|
| The interface | `web/index.html`, `web/app.css`, `web/js/*.js` | Plain HTML, CSS and JavaScript. No framework, no build step, no dependency. Classic scripts sharing one global, `window.gz` |
| Serving it | `ports/api/embed.cmake`, `ports/api/static.c`, the file list in `ports/api/CMakeLists.txt` | The listed files become `static_files.c` at build time (plain CMake, no other tool); `static.c` serves exactly those paths from memory |
| The fake's story | `ports/api/fake/fake_backend.c` (`story_*`, `gz_fake_cmd`), `tools/gz-api-fake/main.c` (`--story`, `--auto-ms`, `--held-ms`, `--fresh-ms`, `--idle-ms`) | TEST ONLY. Without `--story` the fake answers exactly as before, and the server's own tests are unchanged |
| Screens and their calls | `docs/ux/slice1-screens.md` | Redone against draft 4: every screen, its calls, the event topics that redraw it, and 15 gaps |
| Browser tests | `tests/web/*.spec.mjs` (31 tests), `tests/web/check_static.py` | Against `gz-api-fake` through the real HTTP server |
| CI | job "interface in a browser" in `.github/workflows/ci.yml`; CTest `web_static_check` | The job also runs `tests/api/browser/`, which no job ran before |

How the interface is put together (`web/js`):

| File | What it holds |
|---|---|
| `util.js` | Building DOM nodes (`h`), numbers and dates, request ids, wiping arrays that held secrets |
| `words.js` | All wording: one table per enumeration of the spec, the strip's sentence per `doing.code`, error texts per code. A code without wording shows as "unknown state" |
| `api.js` | The only file that calls `fetch()`. The session token, `X-Gazpacho-User`, the fresh-sign-in retry, the event stream, the `BroadcastChannel` messages of 4.4 |
| `ui.js` | Notices, the passphrase dialog, the sealed terms card, the fit table, dates |
| `access.js` | First run, the 24 words shown and typed, the backup check, sign-in, files-behind |
| `home.js`, `conditions.js`, `lobbies.js`, `host.js`, `factory.js`, `settings.js` | One screen or a few each (`settings.js` also holds Activity and About) |
| `app.js` | Start-up, the gate, the strip, the router, live redraws |
| `bip39.js`, `eff.js` | Generated word lists (`tools/gen-interface-wordlists.py`), checked equal to the program's |

A screen is `{ title, nav, topics, render(params) }` in `gz.screens`; `render` returns a Promise of a node. An event whose topic is in `topics` redraws the screen without moving focus or scroll; a message an action just left on screen is carried over the redraw; a screen with a form in it has no topics, so nothing is redrawn under the person's typing.

## How to run it

On the build server or in CI, never on a workstation holding a wallet.

```
cmake -B build && cmake --build build --target gz-api-fake
./build/ports/api/gz-api-fake --data-dir ./gz-demo-data --story --auto-ms 3000
```

Open the file it names (the first-run redirect file) in a browser on the same machine, or reach its port through an SSH tunnel whose local port equals the program's (`spec/local-api.md` 3.3). `--auto-ms 3000` moves the story on every three seconds; without it, type `step` (and the other lines listed at `gz_fake_cmd` in `ports/api/fake/fake_backend.h`) into the program's standard input. A `--locked --fresh-attempts` run starts with a wallet whose passphrase is the fixture in `fake_backend.h`.

The tests: `tests/web/README.md`. In short, `cd tests/web && npm ci && npx playwright install chromium && GZ_API_FAKE=<built gz-api-fake> npx playwright test`.

After changing a file in `web/`, build again: the files are compiled in. A new file must be added to `GZ_INTERFACE_FILES` in `ports/api/CMakeLists.txt` and to `index.html`; `web_static_check` fails if the two lists differ.

## Security rules the interface keeps, and where each is checked

| Rule | How | Checked by |
|---|---|---|
| No inline script, style or handler; no `eval`; no HTML sink | Everything is built with `gz.util.h`; the server's page policy (5.4) stays as it was, Trusted Types included | `check_static.py`; `quality.spec.mjs` (the policy header; an `innerHTML` assignment throws; no policy report in any test) |
| No external resource of any kind | Every address in `web/` is a path on the program's own origin | `check_static.py`; the page fixture in every test; `quality.spec.mjs` with a second loopback server that must hear nothing |
| The session token as 4.4 says | `sessionStorage` and one closure in `api.js`; only in the `X-Gazpacho-Session` header; never a cookie, a URL or `localStorage` | `first-run.spec.mjs`, `quality.spec.mjs` |
| The 24 words and the passphrase | Never logged (no `console` anywhere), never in page storage, the title or a URL; fields emptied as soon as a request is sent; the words not in the page until asked for, out of it while the tab is hidden, wiped on Done, on leaving, on `pagehide` and `freeze`, and at 10 minutes | `first-run.spec.mjs` ("the 24 words leave the page"), `signin.spec.mjs` (`passphraseNowhere`) |
| Copy and paste of the words | No copy control; the shown words are `user-select: none` and their `copy` event is cancelled; word fields carry `autocomplete`, `autocorrect`, `autocapitalize` off and `spellcheck="false"`; matching words are offered by the page from the 24-word list | `first-run.spec.mjs` |
| Every value from the API escaped | Inserted as text; text written by other people (`{ text, by }`) inside `<bdi>`, never a link | `flows.spec.mjs` (a lobby named `<script>…` shows as text; no dialog, no script element) |
| Mainnet refused | The interface stops at start-up unless `GET /version` names signet or testnet4 | `quality.spec.mjs` |
| The start token | Read from the fragment once at load, taken out of the address at once, presented only if it has the token's exact form | `first-run.spec.mjs` |

What the page cannot do is in the spec's own list (12.7, "What these rules do not stop"): JavaScript cannot erase a string, so "wiped" means every reference this page holds is dropped.

## Changes to the API server, for a browser-security review

The brief was to keep these small and to flag them. There are two, plus two test adjustments.

1. **Static files from `web/`** (`ports/api/static.c`, `embed.cmake`, `internal.h`, two call sites in `route.c`). `gz_static_lookup` now also returns a `Content-Type` header line, which `route.c` passes to `gz_respond` as its extra header. Needed because every answer says `X-Content-Type-Options: nosniff`, and a browser refuses a script or a stylesheet without its type. Scripts and stylesheets are served as any non-page answer: `Cross-Origin-Resource-Policy: same-origin`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store`. Only `/` and `/index.html` get the page headers. The path match is still exact, the table is still compiled in, and a query string still answers 404. To review: that nothing in the table can be reached by another spelling of a path; that `text/javascript; charset=utf-8` and `text/css; charset=utf-8` are the types wanted; that `no-store` on scripts is wanted (it costs a re-fetch per load and nothing else on loopback).
2. **`held_ms` had no default** (`ports/api/server.c`, one line). `gz_api_limits.held_ms` was the one limit that zero did not turn into the spec's value, so with a default configuration a held acting call was answered `503 node_busy` at once instead of after 30 s. The server's own test sets the field, so it did not show. P6 would have met it on the first slow save.
3. **`tests/api/browser/api-browser.spec.mjs`**, two tests adjusted because the page served at `/` is now the interface: the first-run test now expects the interface to have presented the start token itself (the second presentation answers `token_used`), and the `BroadcastChannel` test now counts only the other port's message (the interface on that page speaks on the channel too).

Not changed, but found while wiring; for the API server's owners:

- **`first_run_launched_at` is `null` once a wallet exists** (`route.c`, `GET /session`). 4.3 asks the interface to show the hijack warning when it "gets `wallet_exists` while it holds no session" within 10 minutes of the launch; with the field gone at that moment the interface cannot tell the 10 minutes, and shows the ordinary sign-in screen instead. The `token_used` half of the rule works and is tested.
- **A page under 5.4's policy cannot create the `SharedWorker` of 10.3** (gap 8 below). Recorded by a test annotation in `quality.spec.mjs`: `new SharedWorker(...)` throws `TypeError` in Chromium.

## What is stubbed, simplified or not built

| Item | State |
|---|---|
| The backend | The fake. Its story is linear and its numbers are invented (`fake_backend.c` says where). Everything "works end to end" only as far as the fake is like the program |
| One stream per browser | Not the `SharedWorker` (it cannot be created, gap 8). Each tab opens the stream; a tab answered `429 too_many_streams` follows events relayed by another tab over the `BroadcastChannel`, and opens its own on `leader_gone`. There is no election beyond that, so two tabs of one session may both hold a stream (the cap is two per session) |
| Member signing modes A, B, C | Not on any screen: the API has no place for them (gap 2). What is built is the API's behaviour: joining is the consent, then the app signs by itself |
| `X-Gazpacho-User` | Sent when the person touched the page in the last two seconds, and never on a request made because an event arrived. The spec's wording is "only from handlers of input events"; this is an approximation of it that needs no flag at every call site |
| Lists | The first page only (`limit` default). No "more" control for lobbies, activity or coins; cursors are not used yet |
| Standby seats, invitations, automatic joining, Settings writes, payments, leaving alone | Not in Slice 1 or answered `null`; no screen |
| Password-manager guidance (12.7) and the "sign-in phrase" idea | Not on the passphrase screens yet. The fields carry the `autocomplete` values 12.7 names |
| About | The dedication line, credits and a licence note, held by the interface (gap 14). The full dedication text and licence texts are not shown |
| Browsers | Chromium only has been run. `GZ_BROWSERS=chromium,firefox,webkit` is wired in the Playwright config but Firefox and WebKit are not installed on the build server or in the CI job |
| Accessibility | Checked by test: a label on every field, a name on every control, one `h1` per screen, focus rings, keyboard sign-in and dialogs, no sideways scroll at 360 px, computed contrast of the main text colours in light and dark. Not done: a run with a screen reader, and a full contrast audit of every colour pair |
| Theme | The switch keeps its choice in `localStorage` (`gz-theme`), the one thing the interface stores there. The sign-out answer's `Clear-Site-Data` may clear it |

## The API gaps found

The full list, with what each screen does meanwhile, is "Gaps" in `docs/ux/slice1-screens.md`. The ones that need a decision before P6, in order of weight:

1. **Several lobbies at once** (owner decision 16b) is not in the spec yet: `already_in_lobby`, `already_hosting`, and a status whose `doing` names one lobby without saying whether it is joined or hosted (gap 1).
2. **Member signing modes** (owner decision 16d, C the default) have no call, field or state (gap 2). This is the largest: the default the owner chose cannot be offered.
3. **The suggested six-word passphrase** has no call; the interface makes it itself from the same list as the program's (gap 3). Fine if the owner agrees that the page may generate it.
4. **The host cannot see that a member refused**, only that it left (gap 4).
5. **The `SharedWorker` against the page policy** (gap 8), and **`first_run_launched_at`** (above).
6. Smaller: no `doing.code` for "removed by the host" (5); no Slice 1 "starts soon" heads-up (6); what follows `restoring` in `GET /wallet/setup` (9); the shape of a lobby row's failing terms (10); why a session ended (11); the delay after a wrong passphrase (12); copying an address (13); the hijack warning after `wallet_exists` (15).

## What the P6 wiring must provide

The interface reads only the API, so this is a list of what the backend behind `gazpacho/api_backend.h` must answer for the screens to keep working. Everything here is in the spec unless marked "read if present".

- **Events for every change the screens follow**, by `gz_api_notify`: `lobby` (with the lobby's id) for seats, counts, stage, round and outcome; `host_lobby`; `factory`; `status` whenever `doing`, `attention`, `pause`, `money` or `hosting` changes; `chain`; `wallet` (also when a restore finishes); `activity`; `discovery` (with the query's id). The screens do not poll, except `GET /discovery/queries/{id}` once a second while a query is asking. A missed `status` event leaves the strip stale until the next one or a reconnect.
- **Status facts**: one or more `doing` candidates with their `lobby_id`; the params the wording uses, read if present: `ready`, `target`, `minimum` (`in_lobby_waiting`), `confirmations`, `needed`, `factory_id` (`awaiting_funding`, `idle_in_factory`: the strip links to the factory when `factory_id` is there), `failures` (`refused`), `still_watched` (`creation_abandoned`). Attention items with `lobby_id` or `factory_id`; `refused_to_sign` with `params.activity_id`, which Home links to. `next_date`, `hosting`, the money fields.
- **The lobby object in full** (14.1): `terms` with `current.digest` (the join's echo), `fit` with `rows` and `counted_from`, `start_rule` with its deadline as a date, `counts`, `you` (seat, counted, outcome with `failures`, `not_your_doing`, `cancel_received`, `still_watched`), `round` with `state`, `signatures` and the program's `checks`, `funding` with its deadline, `factory_id`.
- **The host's lobby object** (15.3): `can_start_now` and `start_blocked_by`, `seats` with `can_remove`, `round`, `funding`, `funding_tx`, `factory_id`.
- **The factory object and its dates** (16.1, 16.2), with `saved_copy_activity_id` naming an activity entry that `GET /activity/{id}` answers with its `saved_copy`.
- **Acting calls held until their save is confirmed**, with request ids that replay (contract-v2 section 11). The interface sends the same `request_id` again after `node_busy`, `node_stopped` and a lost connection, and a new one after any other outcome.
- **The words calls** as 12.3 says, including that a failed check ends the session, and `GET /backup` → `words.checked_at`, which decides where a resumed setup starts.
- **Restore**: `GET /wallet/restore`, a `wallet` event when it finishes, and then `GET /wallet/setup` saying `created_not_finished` (the interface asks for a preset) or `ready` (gap 9).
- **Text by other people** already passed through the server's filter (5.6); the interface adds `<bdi>` and never makes a link.
- **Nothing extra for the interface's own state**: it keeps none on the program's side.

## Checks before this is called done for Slice 1

- Run the same Playwright flows against the real program on signet (the walkthrough of 23.1 item 1), with a host and three members each in a browser. The tests are written against the fake's ids and numbers (`lob_7k2q`, 30 of 50, 3 confirmations); they need a second set of expectations, not a second set of tests.
- Run `tests/web` in Firefox and WebKit, and the browser items of 23.6 that need the interface (T3, T7, T8, T9, T13).
- A browser-security review of the two server changes above and of `web/js/api.js`.
- The owner's yes to the wording in `web/js/words.js` (it follows `docs/ux/` and the spec's proposed strings; it has not been read by the owner as a whole).
