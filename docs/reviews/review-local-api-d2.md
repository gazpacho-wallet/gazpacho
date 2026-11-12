# Review of `spec/local-api.md`, draft 2

Reviewed 2026-11-12, from `origin/specs-slice1` at commit `7aedcf4`. Independent and adversarial; the reviewer wrote none of the specification. Read on the same branch: `spec/local-api.md` (draft 2, the subject), `docs/reviews/review-local-api-d1.md` (round 1), `docs/specs-history/local-api-d1.md` (draft 1), `docs/ux/decisions.md` (decisions 11 to 14), `docs/THREAT-MODEL.md`, `spec/journal.md`, `spec/signing-round.md` (section 7), `spec/safety-rule.md` (C11, section 12), `docs/DESIGN.md` sections 6, 9 and 13, `docs/notes/wallet-keys.md` section 8. `docs/reviews/ux-critique.md` was consulted only for the rules the spec quotes.

Local notes, not posted anywhere.

## Verdict

**Ready after listed changes.** Draft 2 answers round 1 well: every High finding is fixed, and most of the Medium and Low ones. The no-cookie session in `sessionStorage` with a custom header is the right transport, and the browser claims it rests on hold against the standards. The normative chain-view table, the `doing.code` priority, the outcome rule from the member's own `exposure` record and the non-oracle words check are all sound.

The owner's decisions 13 and 14 added a passphrase and a locked state. That layer is where the new problems are. Five must be settled before Slice 1's sign-in and setup code is written:

1. **N1.** `spec/storage-encryption.md` does not exist. `journal.md`, the threat model and `wallet-keys.md` still say Slice 1 is unencrypted, with a key derived from the seed. Sign-in, create, restore, unlock and the attempt counter all depend on that missing spec, so a builder must guess.
2. **N2.** A locked wallet stops watching, and every restart locks it, including a crash, a reboot or an update. Nothing makes that stop visible to a person who is not looking at the page. While locked, the program cannot even know the deadlines it ought to show. The locked status shape also drops the `watching` and `doing` values the strip needs.
3. **N3.** The first-run start token goes into the browser launcher's command line. On Linux the command line is readable by every local user by default, so another user can race the person to create a wallet whose words that user knows.
4. **N6.** The setup session is undefined against fresh sign-in. `create` and `restore` are listed as needing a fresh sign-in before any passphrase exists, and whether the backup check right after creation counts as fresh is not stated.
5. **N8.** Two status values can reassure when they must not. `creation_abandoned` stops being sticky after 24 hours while `still_watched` is true. Section 22 still says "A locked app still signs".

N4 (the passphrase is now the only barrier for other operating-system users over TCP) and N5 (fresh sign-in is a 5-minute window, not tied to one action) should be fixed in Slice 1 too, because both concern who can reveal the words.

---

## 1. Round-1 findings: status

| # | Round 1 | Status | Evidence in draft 2 |
|---|---|---|---|
| F1 | Cookie reaches every loopback port | **Fixed** | 4.4: "The program never sets a cookie, and ignores every `Cookie` header"; the token is returned in the body (4.5, `POST /session`), kept in `sessionStorage`, sent as `X-Gazpacho-Session`; `GET /session` "Never returns a secret"; the check value is gone; tests 23.2 items 33, 34. New risks of the hand-over: N7 |
| F2 | Words check was an oracle | **Fixed** | 12.3: `ok` only, fresh sign-in on `check-start`, "At most 3 checks in any 24 hours per wallet, saved in the journal", a failed check ends the session, new positions each time; 7.5 row "Words-check attempts"; test 23.2 item 35 |
| F3 | "Cancelled" after partial signatures | **Fixed** | 14.1, "How the outcome is decided": from the member's own `exposure` record, "in any attempt of this lobby"; `cancel_received`; `doing.code` 25 restricted; section 22 row; test 23.1 item 12 (including the second-attempt case) |
| F4 | Host node could send any file anywhere (1.0.0) | **Fixed** | 15.5: fresh sign-in, `confirm_address`, regular file outside the data folder, form and size checks, certificate pinned, `test` takes no address or path, "No other call reads a path". Residual (Low): the checks must be re-run when the file is "re-read at start", and the file should be opened without following a link swapped in after the check (open, then `fstat` the descriptor) |
| F5 | Fresh sign-in missing on spends and trust changes | **Fixed** | 4.8: one rule and a table, including `POST /host/lobbies` with `confirm_funding_sat`, `start`, resume, loosening, chain servers, watching; 20.3: a user-added server's operator is always `you`, and trust needs a built-in server. The window design is weak, see N5 |
| F6 | `request_id` unbound and forgotten | **Fixed**, two Low residuals (N12) | 7.4: keyed with method, path and body digest, `409 request_id_reused`, saved "in the same journal batch as the first save the action makes", kept 30 days after the object ends; review ids single-use and saved as spent |
| F7 | Chain view, watching, `doing` not mapped | **Fixed**, one residual (N8) | 11.2: normative chain-state table, "Exactly one value; when several hold, the first in this table wins", every at-risk value above `paused`, `held_for_signing` shown as `signing`; `forming_sat`; `still_watched`; 11.5 splits `while_closed` with a precedence. Residual: sticky expiry of `creation_abandoned` |
| F8 | Private-network claim out of date | **Fixed** | 5.3, "Local Network Access ... Nothing here depends on it"; unspecified-address `Host` in test 23.2 item 2; item 10 rewritten |
| F9 | Idle lock never fired | **Fixed** | 4.7 and 10.2: only `X-Gazpacho-User: 1` from input handlers refreshes the timer; test 23.2 item 19 |
| F10 | Stream reconnect loops | **Fixed** | 10.3: one stream per browser (`SharedWorker` or an elected tab), `429 too_many_streams` not retried, "Nothing is closed to make room"; the reader is `fetch()`, which has no automatic reconnect. Implementation note: N11 |
| F11 | API state had no home | **Partly fixed** | 7.5 names every record and its batch; `journal.md` open point 9 mirrors it; pause applied before any connection. Record types and fields still wait for W3, which is acceptable. But the home is an encrypted journal whose encryption spec does not exist, and `journal.md` itself still says "Slice 1 runs unencrypted" (N1) |
| F12 | Fake interface, sign-in denial | **Partly fixed** | 5.7 accepts squatting and states the words defence; the 4.3 counters count only requests that passed `Host`, `Origin`, content type and fetch metadata; denial is accepted. Not covered: the passphrase, which a fake page asks for first and which is now the master secret against other local users (N4) |
| F13 | Words in the browser vs `DESIGN.md` | **Fixed by owner decision 12**; rules in 12.7 | `DESIGN.md` section 13 updated. Several rules cannot be enforced as written, see N9 |
| F14 | C parser, no fuzzing | **Fixed** | 3.1, "The parser"; 64 header lines; 23.5 |
| F15 | Unencrypted export | **Fixed** | 12.6: only "as encrypted on disk"; `409 export_needs_encryption` until then (1, 12.6). The export is now guarded only by the passphrase and the key derivation (N16) |
| F16 | Fingerprints in URL paths | **Fixed**, one stale sentence | 7.3 local `lob_`/`fac_` ids; 5.5; 10.2 "`id` is always a local id". Stale: the intro of section 15 still says "Lobby identifiers are the same fingerprints as in section 14" |
| F17 | `no-referrer` gives `Origin: null` | **Fixed** | 5.2 last point; 5.4 `Referrer-Policy: same-origin`; test 23.2 item 36 |
| F18 | Headers on every response | **Fixed** | 5.4, "On every response ... error answers ... alike" |
| F19 | Duplicate and planted cookies | **Fixed (moot)** | 4.4; test 23.2 items 8, 34 |
| F20 | Format characters | **Fixed** | 5.6: category Cf dropped, `<bdi>`/`unicode-bidi: isolate`, never a link, `host.address` validated |
| F21 | Bearer and fresh sign-in | **Fixed** | 4.6: socket only (`400 bearer_not_on_tcp`), exempt from fresh sign-in but not from the echo, `revoke-all` rotates the token; locked: bearer reaches only `wallet/unlock` |
| F22 | Statements stronger than sources | **Fixed** | 5.3, the per-caller wall table; 5.7, "nothing more" removed; 3.1, the port argument corrected |
| F23 | Windows | **Deferred, as agreed** (1.0.0) | 3.2; 24.2 items 4, 5 |
| F24 | Consistency | **Fixed** | 2.1 lists lock, revoke-all and the S1 parts of backup and dates; `refused_by_host`; sticky lifetimes; discovery `202` at once; the 10 s limit marked as this API's own; `you.standby` reserved; 11.3 pause table |

| Slice 1 gap | Status | Where |
|---|---|---|
| G1 Where API state is saved | Fixed in the API, not yet buildable (N1) | 7.5 |
| G2 How the start happens | Fixed | 15.2, "Starting" |
| G3 Session transport | Fixed | 4.4, 10.1 |
| G4 Words in the browser | Fixed (decision 12) | 12.7 |
| G5 Slice 1 money and factory values | Fixed | 11.1 paragraph after the example, 11.2 money table, 16.1 "Slice 1 values" |
| G6 Confirmations for live | Fixed (floor proposed) | 16.1 `funding.needed` |
| G7 Host's tree | Fixed | 16.1 `host_view.tree` |
| G8 Slice 1 defaults | Fixed | 4.7 (15 min), 18 (100 sat/kvB), 3.1 (IPv6 on) |
| G9 Pause boundaries | Fixed | 11.3 table |
| G10 Discovery timing | Fixed | 21 |
| G11 Several programs on one machine | Fixed | 3.1 `--data-dir`, ports for the walkthrough |
| G12 Doing priority, chain mapping | Fixed | 11.2 |
| G13 Sticky codes | Fixed, with residual N8 | 11.2 |
| G14 `request_id` storage | Fixed | 7.4, 7.5 |

---

## 2. New findings, ranked

Severity: **High** (a false safety statement, the words or a wallet obtainable by someone else, or a Slice 1 builder cannot proceed); **Medium** (weakens a defence, or a builder must guess); **Low**. "S1" or "1.0.0" says when it bites.

### N1. High, S1 (blocks building). The sign-in layer rests on a specification that does not exist and on documents that contradict it

**Evidence.** 4 says the API uses three operations of `spec/storage-encryption.md`, "being written". That file is not on `origin/specs-slice1`. The spec also leans on it for:
- `weak_passphrase` and its rules (12.2);
- "its small unencrypted file for the attempt delay" (4.3; 24.2 item 7);
- the offline strength (5.7);
- the export format (12.6);
- how `POST /session` checks a passphrase against "the unlocked storage" (4.3 step 4).

Meanwhile, on the same branch:
- `journal.md` section 2: "Not encrypted in slice 1 **(open)**".
- `journal.md` open point 1: "Slice 1 runs unencrypted on signet ... key from the seed". A key from the seed is not a passphrase key; if the seed is used, the passphrase must wrap it, and the seed must then sit in a file that is itself passphrase-encrypted.
- `wallet-keys.md` section 8: "The phrase file is plain text".
- `THREAT-MODEL.md` 2.7: "the journal is **not** encrypted in Slice 1".

**Why it matters.** Owner decision 13 makes encryption a Slice 1 requirement. The API's locked state, sign-in, create, restore and unlock cannot be implemented, or tested, without the key derivation, the passphrase check, the unencrypted counter file and the key-file format.

**Fix.** Write `spec/storage-encryption.md` before the session code. At minimum it needs:
- the key derivation and its parameters (a memory-hard function, Argon2id);
- how a wrong passphrase is detected;
- whether the seed or phrase file sits under the same key;
- the counter file's format, and what happens when it is missing;
- minimum passphrase strength.

Update `journal.md` section 2 and open point 1, `wallet-keys.md` section 8 and `THREAT-MODEL.md` 2.7 in the same change.

### N2. High (1.0.0), Medium (S1). A locked wallet stops watching, every restart locks it, and the person who is not looking is never told

**Evidence.**
- 4.7: locked, the program "**Stops acting**: it can neither read nor write its journal, so it saves nothing, signs nothing, answers nothing and leaves nothing alone until unlocked. It keeps no outside connection open."
- 4.2: "A restart locks the wallet". 4.7: "After a restart the wallet is locked until the passphrase is typed". Decision 14: "lock: the key is dropped from memory, and the program then does nothing until unlocked".
- 4.7: the lock button shows "Unlock it before …" with the earliest `watching.open_by`.
- 4.7: while locked, `GET /status` answers only `{ "wallet": "locked", "network" }`.

**Problems.**
1. **Unplanned restarts are silent stops.** A crash, an out-of-memory kill, a reboot after an update or a power cut leaves the program running and locked. Nothing is watched, and nothing answers an old state or leaves alone in time. The only signals are the locked page, which nobody has open, and a terminal line, which a service has no reader for.
   - In 1.0.0 that is the main way a member loses money: threat model 2.4 rests on the safe absence, and an absence the person does not know about is not a choice.
   - In Slice 1 it stops C4(d)/C11 watching of an Unfinished or Awaiting-funding creation and lets the 36-block funding deadline pass unobserved.
   - A host that is locked cannot rebroadcast its funding (`journal.md` `funding_signed`), cancel at a deadline, or answer `hello`.
2. **The locked page cannot know the deadlines.** They are in the encrypted journal. After a restart, "Unlock it before …" has no date to show. The spec does not say what the locked page then says.
3. **The locked status shape loses values the strip needs.** 11.2 says the locked state gives `watching.state = nobody_locked` and `doing.code = wallet_locked`, and section 22 relies on distinct values. But the locked `GET /status` carries neither field, so the strip has nothing to render. Also, `lock_held` (4.5, 4.7) appears in no status field, and `POST /wallet/lock` ends "Every session" even when held. The person is then signed out, cannot see the round, and believes the wallet is locked when it is not.
4. **Deadlines that pass while locked.** The spec does not say what happens to them at unlock. They include:
   - a hosted lobby's deadline (15.2: "Cancels the lobby");
   - a funding deadline (Abandoned);
   - an unfinished deadline;
   - sticky-code lifetimes.
   Nor does it say that a saved pause is applied at unlock, rather than "on start" (7.5), since the journal is unreadable at start.
5. **Should lock be allowed with deadlines?** A deliberate lock while a factory is live, Awaiting funding or `still_watched` is the same hazard as "go offline", which the spec treats as a trust change needing a fresh sign-in and `confirm: "nobody_watching"` (4.8, 20.2). Lock needs only `confirm: "lock_wallet"`.

**Fix.**
- Give the locked `GET /status` a fixed shape: `{ "wallet": "locked", "network", "watching": { "state": "nobody_locked" }, "doing": { "code": "wallet_locked" }, "known_deadline": null | { "height", "at_estimate", "since": "lock" } }`. While the process has kept running since a deliberate lock, it remembers the earliest `open_by` in memory. After a restart it is `null`, and the page says "Gazpacho cannot see your dates until you unlock it. Until then nothing is watched."
- Add `lock_pending` (or `wallet: "lock_held"` with `lobby_id`) to `GET /session` and the locked status, and keep sessions alive until the key is actually dropped.
- Treat lock like going offline when anything needs watching: fresh sign-in plus `confirm: "nobody_watching"` and an echo of the earliest date. Or refuse it within the `act_now` window of any date.
- State the unlock sequence: apply the saved pause, apply deadlines that passed (cancel, abandon, sticky expiry), then connect.
- Raise unplanned restarts to the owner as a decision. Options:
  - (a) accept, and say on every "keep the app open" sentence that a restart needs the passphrase;
  - (b) an optional unattended unlock (key in the operating system's keyring, or a key file), with its risk stated;
  - (c) a small unencrypted "deadline hint" file holding only the earliest height, so the locked page and an operating-system notification can warn. This leaks that the user has a factory.
  Section 22 needs a row: "Locked: nobody is watching", with `nobody_locked`, not to be confused with `this_app`.

### N3. Medium-High, S1. The start token is exposed in the browser launcher's command line, and a hijacked first run is not detected

**Evidence.**
- 4.3, first run, step 1: "it opens the default browser itself at `http://127.0.0.1:<port>/#start=<start token>`".
- 4.3: "Why a token in a URL is allowed here".
- 5.7: other users "cannot create or restore a wallet without the first-run token".
- Test 23.2 item 37.

**Why it fails.** On Linux, opening a URL runs `xdg-open` (often a shell script) and then the browser with the URL as an argument. A running browser is handed the URL by a short-lived second process. Every one of those processes has the full URL, fragment included, in `/proc/<pid>/cmdline`. With the default `hidepid=0`, every local user can read it (proc(5): mode 0 is "the traditional behavior, and the default"; only mode 1 protects "/proc/pid/cmdline").

A process of another user that polls `/proc` catches the token and posts `POST /api/v1/session/start` before the interface has loaded its script, then calls `create` or `restore` with words and a passphrase of its own. The person's tab then fails. If the interface only says "Open Gazpacho from the program", the person may restart, see a passphrase prompt, assume they mistyped, and later fund a wallet whose words the attacker holds. On macOS, `ps` behaviour for other users' arguments was not checked; on Windows other standard users normally cannot read another user's process command line.

The other channels the brief asked about matter less, because the token is one-use, 10 minutes, and only usable on this machine:
- **History and sync.** Recorded before `replaceState`. Usable only if not yet spent: the page failed to load, or was closed.
- **Extensions.** Those with the `tabs` or `history` permission see URLs with fragments (5.7 accepts extensions).
- **Screen sharing.** The address bar shows it briefly.
- **Referrer.** None: Fetch strips the fragment when it computes a referrer.
- **Crash reports.** A renderer crash report may carry the tab's URL; not checked.

A web page cannot race for it. It cannot read another tab's URL, and it cannot post to `session/start` without passing the `Origin`, content-type and preflight walls.

**Fix.**
- Open the browser on a **redirect file**: a 0600 HTML file in the 0700 data folder that sets `location.replace("http://127.0.0.1:<port>/#start=…")`, deleted after first use. Only the file path is on the command line. Jupyter Server does exactly this for its launch token (`ServerApp.use_redirect_file`). Note that a `file:` page is a different origin with `Origin: null`, which is why it must redirect, not post.
- Start listening before launching the browser.
- Spend the token on its first use, successful or not.
- Make a hijack loud. When `session/start` answers `wallet_exists` or `token_used` within 10 minutes of a launch, the interface says "Someone else used this program's start link. Do not use this wallet: stop the program and delete its data folder", and the program prints when the token was used.
- Add these to test 23.2 item 37, and add a second-user `/proc` poller to the test.

### N4. Medium, S1. The passphrase is the only barrier between other operating-system users and the 24 words, and the anti-phishing defence covers only the words

**Evidence.**
- 5.7: other operating-system users "can connect to `127.0.0.1`. They get the passphrase page and nothing else without the passphrase".
- 5.7, port squatting: "the words are typed into the interface only on two screens".
- 12.7: `autocomplete="current-password"` (D14).

**Why it matters.** Over TCP, any local process that knows the passphrase gets a normal session and, with `session/fresh`, `phrase/reveal`. A squatter on 39735 while Gazpacho is stopped is the same origin, so a password manager fills it and the person types the passphrase into the first screen as usual. A look-alike page on another port can do the same. The words-only defence does not apply to the passphrase.

**Fix.**
- **Same-user check on the TCP socket.** On accept, find the owner of the peer socket and refuse other users: Linux `NETLINK_SOCK_DIAG` (or the uid column of `/proc/net/tcp`); Windows `GetExtendedTcpTable` with the owning process, then its token's user. The browser and an SSH tunnel's forwarding process both run as the user. This turns 5.7's "other operating-system users" row into a defended row and removes their denial of sign-in.
- **A sign-in phrase.** Optionally (1.0.0), a phrase chosen at setup and kept in a 0600 file outside the encrypted store, shown above the passphrase field. A squatter of another user cannot read it.
- **Password-manager guidance.** The setting near D14 should say that browser managers match the exact origin, port included, so they refuse to fill another port. A third-party manager on "base domain" matching may ignore the port; Bitwarden documents port matching only for its "Host" option, and Android clients "cannot currently match URIs based on port".

### N5. Medium, S1. Fresh sign-in is a 5-minute window shared by every sensitive call; the echo cannot stop a script in the page

**Evidence.** 4.8: "Fresh sign-in = the passphrase typed again in the last 5 minutes (... or the sign-in itself)". Within that window every call of the 4.8 table is open: `phrase/reveal`, opening a hosted lobby, start, resume, loosening, and in 1.0.0 send, pay and leave alone.

**Problems.**
- A person who signs in and steps away for a minute leaves `reveal` one click away. The sign-in itself counts as fresh.
- An injected script, which the spec defends against only by CSP and no-HTML-sinks (4.4), can fill every echo field with the values it reads from the preview. Echoes catch client bugs and stale previews, not a hostile page.
- Under N4, a phished passphrase grants the window anyway.

**Fix.** For the words (`reveal`, `check-start`) and for spends (`POST /host/lobbies`, and in 1.0.0 `wallet/send`, `payments`, `leave-alone`, `force-*`), put the passphrase **in the request itself**, checked under the 4.3 limits, so there is no window. Or have `session/fresh` return a one-use confirmation id bound to (method, path, echo values), valid for 60 s. Keep the 5-minute window for the reversible trust changes (resume, loosening). State that the sign-in itself does not count as fresh for `reveal`.

### N6. Medium, S1. The setup session and fresh sign-in are undefined

**Evidence.**
- 4.8 table: "The 24 words: `wallet/create`, `phrase/reveal`, `phrase/check-start`, `wallet/restore` | S1 | ... `check-start` and `restore` need none beyond the fresh sign-in".
- 4.3: `create` and `restore` run in the setup session, before any passphrase exists.
- 12.3: `check-start` needs a fresh sign-in, and the flow wants the check "right after the words were shown" (12.7).

**Gap.** A builder cannot tell whether:
- the setup session is fresh;
- the passphrase sent in `create`/`restore` starts a fresh window;
- the session "becomes an ordinary one" (4.3 step 3) keeps that window.

As written, `create` and `restore` are impossible (no passphrase to be fresh with).

**Fix.** State it. The setup session is exempt from fresh sign-in for `create`, `restore` and `finish-setup`. The `create`/`restore` request's passphrase counts as a fresh sign-in for the next 5 minutes, which covers the immediate check. `reveal` needs a new passphrase entry (N5). Also say what happens to the setup session if the person closes the tab between `create` and `finish-setup`: the wallet then exists, so no start token is accepted, and normal passphrase sign-in must lead back to `created_not_finished`.

### N7. Medium, 1.0.0 (tunnel). The `BroadcastChannel` hand-over gives the live token to any page of the same origin, and with the tunnel port that may be someone else's page

**Evidence.**
- 4.4: "A new tab asks over a `BroadcastChannel` named `gazpacho-session` whether an open tab holds a session"; "only same-origin pages receive the message".
- 3.3, tunnel risks: "could, if the tunnel is later reopened, find the interface's storage of a still-open tab".

**Analysis.** The claim is right. HTML delivers a `BroadcastChannel` message only to globals whose storage key equals the sender's, which for a first-party page means the same origin. So other loopback ports cannot listen.

The tunnel case is worse than 3.3 says. The program keeps running on the server, so the session stays valid. While the tunnel is down, any service on the viewing machine at `localhost:<n>` is that origin. Its page posts on `gazpacho-session`, and the still-open interface tab answers with a **live** token. That page's server, a local process on the viewing machine, can use the token as soon as the tunnel is back, for every non-fresh call: join and ready (D4), leave, cancel a hosted lobby, pause.

The same holds for a squatter on the program's own port, but there the program has stopped and the sessions died with it, so it is harmless.

**Fix.**
- Do not hand over sessions when `interface.tunnel_port` is set (each tab signs in).
- Bind a session to the `Host` value it was created under, and refuse it under any other.
- End sessions created through the tunnel port when the program sees no connection from it for some minutes.
- The interface should answer a hand-over only to a requester that has also connected to the interface's `SharedWorker`. That does not stop a same-origin page, and is not a substitute.

### N8. Medium, S1. Two status values reassure when they must not

1. **`creation_abandoned` expires while still watched.**
   - 11.2: sticky codes "Each is shown for **24 hours** ... or until the member joins another lobby", "then the next applicable value shows".
   - For a member whose only history is an abandoned creation with `still_watched: true`, the next value is `idle_no_factory` ("Not in a factory. 'You cannot pay or receive until you are in a live one'").
   - But C11 says that creation can still go live, and 16.1 says "The interface never says 'over' or 'ended' while it is `true`".
   - Fix: `creation_abandoned` is not sticky while `still_watched` is true; it stays at priority 22 until `dead` or `live`, or until the cut-off of 24.2 item 19.
2. **Section 22, row "A locked app still signs".** It reads "`session.state = locked`; pause unaffected". This is draft 1's meaning, where lock was a sign-out. In draft 2 the field does not exist, and a locked wallet signs nothing. The row now states the opposite of 4.7 in the table the contract test (23.4) checks against. Fix: replace it with "Signed out, the app still signs: `GET /session` `signed_in: false` with `wallet: unlocked`", and add the `nobody_locked` row of N2.
3. **Not mapped.** The `watching.state` value is not mapped for `wallet = restoring` (state it: `nobody_chain_in_doubt` while scanning, or a new value). `lock_held` has no `doing` value (N2).

### N9. Medium-Low, S1. The 24-word rules promise more than a browser can deliver

**Claims and limits.**
- **"hides them again after 2 minutes on screen" (12.7, D9).** Writing 24 words by hand, and checking them, takes most people several minutes. A timer that hides them mid-writing pushes people towards a screenshot, the very copy the rules try to prevent. Better: shown until the person presses Done, hidden on `visibilitychange` and `pagehide`, with a 10-minute ceiling and "Show again" inside the creation flow without a new passphrase.
- **"No clipboard copy": `clipboard-write=()` in `Permissions-Policy`.** That policy governs the asynchronous Clipboard API in Chromium-based browsers. Firefox does not act on the `Permissions-Policy` header (to verify against MDN's compatibility data), and the policy does not govern the user's own selection and copy. What actually stops a copy is `user-select: none` and the absence of a button. Reword 12.7 and test 23.3 item 5 to that, and do not claim the header denies copying.
- **"overwritten and released ... does nothing that would copy it further".** Honest about strings. But other copies outlive the page's arrays:
  - the `fetch()` response body and `JSON.parse` results are immutable strings the page cannot wipe;
  - input elements keep their value in the renderer, and an `<input>`'s value is a DOM string;
  - DevTools, when open, keeps every response body;
  - the page is served `Cache-Control: no-cache`, not `no-store` (5.4), so it is eligible for the back/forward cache with its DOM intact;
  - crash minidumps of the renderer can contain heap pages.
  Add these to "What these rules do not stop", clear the words on `pagehide`/`freeze` as well as on hide, and consider `no-store` for `/`.
- **Typed words and session restore.** HTML says that with `autocomplete="off"` "values are reset when reactivating a document" and the user agent "should not remember the control's data". Crash or session restore of tabs is not covered by that sentence. It needs a browser test (section 4, test T7).
- **Spell-check.** `spellcheck="false"` stops the browser's own service. Writing-assistant extensions are covered by the extension row of 5.7; no action needed.

### N10. Low, S1. `Clear-Site-Data` is assumed to work on `http://127.0.0.1`

4.4 and 4.5 send `Clear-Site-Data: "cache", "storage"` on sign-out. The W3C draft clears `localStorage`, `sessionStorage`, IndexedDB and service workers for the origin. Two catches:
- It acts only when the response URL is "a priori authenticated", a term it borrows from Mixed Content. Loopback HTTP is potentially trustworthy, but each browser's implementation should be tested.
- `"storage"` clears every tab of the origin, which is what the shared session wants. `"cache"` may be slow (the draft warns of a linear scan).

The interface already removes the token itself, so nothing depends on the header. Say so, and keep the header as a second wall.

### N11. Low, S1. Implementation notes for the `SharedWorker` stream

- Workers have no `sessionStorage`; tabs must post the token to the worker, which then holds it for as long as any tab lives. State that, and that sign-out tells the worker.
- The pages are served `Cross-Origin-Embedder-Policy: require-corp` (5.4), and the worker script is not. Serve the same COEP on the worker script and test creation in Chrome, Firefox and Safari.
- `SharedWorker` is missing in some mobile browsers; the elected-tab fallback covers them.

### N12. Low, S1. `request_id` details

- 7.4 says a replay "returns the first answer (status and body)", but 7.5 saves "answer status, the local id of the object". After a restart the body cannot be the first one. State that a replay after a restart answers the saved status with the object's current state.
- "re-encoded canonically (object keys sorted by code point, no insignificant white space, numbers as integers)" leaves string escaping open: `"é"` and `"é"` give different bytes. Name RFC 8785 (JSON Canonicalization Scheme), or say strings are re-encoded with minimal escaping.

### N13. Low, S1. Passphrase limits: say where they bite

- Check the per-second limit **before** running the key derivation. A memory-hard derivation started by 32 connections at once would otherwise be a memory exhaustion.
- State that `session/fresh`, `POST /session`, `wallet/unlock` and the passphrase fields of `create`/`restore` share one counter.
- Say what a missing or unreadable counter file means. As written a restart could reset it if the file is gone; only the same user can delete it, so this is accepted under 5.7, but say so.
- Say what the ninth session does (4.2, "At most 8"): refused, or the oldest ends.

### N14. Low. Cross-references and stale text

- 15, intro: "Lobby identifiers are the same fingerprints as in section 14". Should be local ids (F16).
- 4.4 and 5.3: "storage of this origin only (4.3)". The rule is in 4.4.
- 5.2: "Bearer requests (4.5)". 4.6.
- 7.4: "The echo fields of 4.6". 4.8.
- 23 intro names "Items 23.2.4, 33, 34 ...". Fine, but item 37 (first run) and item 19 (lock) also rest on untested browser behaviour and should be run first too.

### N15. Low, S1. `Sec-Fetch-Site: same-site` refused on `GET /`

5.2 accepts `none` and `same-origin` for pages. A link to the interface from another local page, such as a dashboard of local services, is `same-site` and gets `403`. That is the right choice, because it stops a local page from opening the interface with a crafted fragment. But the error answer should be a plain page saying "Type the address yourself", not a bare `403`.

### N16. Low, 1.0.0. The exported backup is protected by the passphrase alone

12.6 exports the journal "as encrypted on disk" into a downloads folder "often synchronised to a cloud service". The 4.3 rate limits do not apply offline, so its protection is the passphrase and the key derivation (5.7). Changing the passphrase (1.0.0) does not re-protect exports already made. State both next to the export button, and have `storage-encryption.md` set a minimum strength and the derivation's cost (N1).

---

## 3. The design questions in the brief

**`sessionStorage` and a header, against cookies.**
- *Script injection.* An `HttpOnly` cookie could not be read by script; the token can. But a script running in the page can act with either, while the page is open. The extra power reading gives is taking the token elsewhere, and under this CSP that is still possible: `connect-src 'self'` does not stop a top-level navigation or `window.open` to an attacker's address. The token is only usable from loopback, by a local process, which 5.7 already leaves undefended (other users excepted, N4). Net: no worse than a cookie, and much better against other ports.
- *Extensions.* Content scripts can read the page's storage, and an extension with the `cookies` permission can read cookies. Equal.
- *Other origins on other ports.* They cannot read `sessionStorage`, because it belongs to the window's origin. They cannot send the header without a preflight, which is refused. They cannot hear the `BroadcastChannel`, because of the storage key. Holds; tunnel caveat in N7.
- *Duplicate tab.* Copies the token (MDN). Harmless.

**Event stream with `fetch()`.** Sound, and better than `EventSource`. It needs no secret in the URL and has no automatic reconnect to loop. `Last-Event-ID` sent as an ordinary same-origin header is fine. Background-tab freezing will pause the reader; the 64 KiB rule and `reset` already handle that.

**Passphrase sign-in.**
- *Limits across restarts.* Kept in an unencrypted file (4.3). That is the only possible place, since the journal cannot be read before unlock. Its format is unspecified (N1, N13).
- *Offline guessing.* Bounded only by the derivation (N1, N16).
- *Autofill.* Browser managers bind to the exact origin, which helps against other ports. A squatter on the same port defeats them (N4).
- *Tunnel port.* A second origin to phish and to hand sessions over on (N7).

**Start token in the fragment.** See N3. The fragment is the right place for a URL secret, since it is never in the request, a log or a `Referer`. The weak point is how the URL reaches the browser.

**Idle sign-out against lock.** Idle signing out and keeping the key (D13) is right. Lock is a safety action presented as a privacy action, and the strip cannot state its effect after a restart (N2). Lock should be refused, or need the same fresh confirmation as going offline, while anything needs watching.

**24 words.** N9.

**Fresh sign-in plus echo.** N5.

**`request_id` persistence.** Sound (F6); N12.

**Binding status tables.**
- *Complete and mutually exclusive.* For the unlocked states, yes. The chain table is total, and `doing` has a total order. `watching.state` has stated precedences (`nobody_locked` over all, `nobody_offline` over `nobody_chain_in_doubt`, `nothing_to_watch` over the chain states).
- *Gaps.* `restoring` has no `watching.state`; `lock_held` has no value (N8, N2).
- *Never reassuring when not protected.* Two failures: the expiring `creation_abandoned` and the stale section 22 row (N8). One more: the locked status that carries no watching value at all (N2).

---

## 4. Browser-behaviour claims: checked, and the tests still needed

Checked against the documents (2026-11-12):

| Claim in the spec | Holds? | Source |
|---|---|---|
| Cookies are not isolated by port (4.4) | Yes | RFC 6265 section 8.5 |
| `SameSite` and "same site" ignore the port (4.4, 5.2) | Yes | HTML "same site"; RFC 6265bis |
| `sessionStorage` belongs to the window's origin, port included; copied into a new auxiliary browsing context (top table) | Yes: "Returns the Storage object associated with that window's origin's session storage area"; "After creating a new auxiliary browsing context and document, the session storage is copied over". When the area is deleted is not normative in the spec; MDN states the tab-close behaviour | HTML Web storage; MDN `sessionStorage` |
| `BroadcastChannel` reaches only same-origin pages (4.4) | Yes, by storage key: destinations whose "storage key for non-storage purposes ... equals sourceStorageKey". No security note in the spec | HTML web messaging, 9.5 |
| `EventSource` cannot set headers (10.1) | Yes, `EventSourceInit` has only `withCredentials` | HTML SSE |
| Custom headers and JSON force a preflight (5.3) | Yes; the safelist is `Accept`, `Accept-Language`, `Content-Language`, `Content-Type` (three values), `Range` | Fetch |
| `Origin` kept under `Referrer-Policy: same-origin` for `cors` mode (5.2) | Yes; `null` only for non-`cors` unsafe requests under `no-referrer` | Fetch, "append a request `Origin` header" |
| `same-site` for another port in `Sec-Fetch-Site` (5.2) | Yes | W3C Fetch Metadata |
| Local Network Access applies only when crossing into a more private space; PNA preflights "were never enforced as a blocking requirement" (5.3) | Yes (no Chrome version is named in the guide) | Chrome for Developers, Local Network Access |
| The fragment is not sent in the request, and never in `Referer` (4.3) | Yes | RFC 9110 / RFC 3986 (the request target has no fragment); Fetch, "strip url for use as a referrer" |
| `Clear-Site-Data: "storage"` clears `sessionStorage` (4.4) | Yes for the origin, all browsing contexts; only for "a priori authenticated" response URLs | W3C Clear Site Data |
| `autocomplete="off"` keeps word fields out of the browser's memory (12.7) | Partly: "should not remember the control's data", "values are reset when reactivating a document"; crash or session restore not addressed | HTML forms, autofill |
| Other users cannot obtain the start token (5.7) | **No** on Linux by default (N3) | proc(5), `hidepid` |
| `clipboard-write=()` denies copying (12.7, 23.3 item 5) | **Partly**: async Clipboard API in Chromium only | MDN `Permissions-Policy` (to verify per browser) |

Tests to run with Playwright and by hand before the session code is merged, in addition to the spec's 23.2 items 4, 32 to 34 and 36:

- **T1** `sessionStorage` isolation between `127.0.0.1:39735` and `127.0.0.1:8080`, and between `127.0.0.1`, `localhost` and `[::1]` at the same port (three origins: three separate sign-ins, expected). Duplicate-tab copy; `window.open` with and without `noopener`.
- **T2** `BroadcastChannel`: a page on another port gets nothing. With `--tunnel-port`: tunnel down, a test server on the viewing side at that port asks on `gazpacho-session`. With the N7 fix, no token is handed over.
- **T3** The `fetch()` stream in a `SharedWorker` created from a COEP `require-corp` page, in Chrome, Firefox and Safari; the elected-tab fallback; `429` not retried; tab freezing and the `reset` that follows.
- **T4** `Clear-Site-Data` on an `http://127.0.0.1` response in each browser: is `sessionStorage` emptied in every tab?
- **T5** First run: after `replaceState`, inspect the history database, session-restore files, synced open tabs and `Referer` of every request for the token. Repeat with the page failing to load (program not yet listening): the token must not be usable later.
- **T6** First run on Linux with a second user polling `/proc/*/cmdline`, with the browser already running and not running. Without the redirect file of N3 the token is expected to be caught; with it, it must not be.
- **T7** Restore screen: type words, then kill the browser and restore tabs. Check the field values and search the profile folder's session files for the words. Repeat for back/forward navigation (bfcache).
- **T8** Password managers: Chrome, Firefox and Safari built-ins, and Bitwarden with default matching. Does each offer the Gazpacho passphrase on another loopback port?
- **T9** `Permissions-Policy: clipboard-write=()` in each browser: is `navigator.clipboard.writeText` refused? Can the shown words be selected and copied by keyboard?
- **T10** Fetch metadata sent by current Safari on every call (5.2 relies on CORP where it is absent).
- **T11** The interface's own page on loopback reaching its own API raises no Local Network Access prompt in Chrome.

---

## 5. Slice 1 completeness: what a builder must still guess

1. **The whole storage-encryption layer** (N1). Key derivation, the wrong-passphrase check, the key-file and seed arrangement, the counter file, passphrase strength. This blocks sign-in, create, restore and unlock.
2. **The locked state's answers** (N2). The locked `GET /status` shape with `watching` and `doing`, `lock_held` in session and status, what the locked page says after a restart, and the unlock sequence: pause first, then passed deadlines, then connecting.
3. **The setup session against fresh sign-in** (N6), and the path back to `created_not_finished` after a closed tab.
4. **How the browser is opened at first run** (N3): redirect file, ordering, what the interface says when the token was already used.
5. **The hand-over and worker protocol.** The messages on `gazpacho-session` and to the `SharedWorker` (who asks, who answers, what the answer holds, what sign-out sends). This is interface-internal, but two people building tabs and worker will otherwise build two protocols.
6. **`request_id` replay body after a restart and canonical JSON** (N12).
7. **The ninth session, and the shared passphrase counter** (N13).
8. **`creation_abandoned` while `still_watched`** (N8), and `watching.state` for `restoring`.
9. **Pause applied at unlock**, not at start: 7.5 says "On start, a saved `on` is applied before the program connects to anyone". A locked program cannot read it at start; it is not connecting either, but the rule should say "at unlock".

Everything else in table 2.1 can be built as written: version, events, status (unlocked), conditions, discovery by address, lobbies, hosting, factories, funding wallet, activity.

---

## 6. The defaults D2 to D16

| # | Default | View |
|---|---|---|
| D2 | No cookie; `sessionStorage` and the header; hand-over over `BroadcastChannel` | **Accept**, but no hand-over when the tunnel port is set, and a session bound to its `Host` (N7) |
| D3 | Idle sign-out 15 minutes | **Accept** |
| D4 | `join` and `ready` without fresh sign-in | **Accept for Slice 1** (members spend no coins; the echo and conditions bound what a join can sign); revisit in 1.0.0 if joining fees come from the member's balance |
| D5 | Every Lightning payment needs a fresh sign-in | **Accept**, and make it per payment with the passphrase in the request, not a 5-minute window (N5) |
| D6 | Resume needs a fresh sign-in; pause never | **Accept** |
| D7 | Bearer only on the local socket | **Accept** |
| D8 | 3 words checks in 24 hours, `ok` only, a failure ends the session | **Accept** |
| D9 | Words shown at most 2 minutes, no clipboard copy | **Change**: no copy, yes; but shown until Done, hidden on tab hide, 10-minute ceiling, "Show again" within creation (N9) |
| D10 | Sticky codes 24 hours or until the next join | **Accept**, except `creation_abandoned` while `still_watched` (N8) |
| D11 | Request ids 30 days; review ids 10 minutes | **Accept** |
| D12 | A user-added server is operator `you`; trust needs a built-in server | **Accept**; it is what makes the two-operator rule mean something |
| D13 | Idle never locks the wallet; lock is deliberate and held during signing | **Accept the idle half; change the lock half**: lock with anything to watch needs the same fresh confirmation as going offline, and unplanned restarts need an owner decision (N2) |
| D14 | Password managers may fill the passphrase | **Accept**, with the guidance of N4: browser managers match the exact origin, port included; third-party managers should be set to exact host matching |
| D15 | One attempt a second, doubling delay to 15 minutes after 5 wrong, kept across restarts | **Accept**, with the limit checked before the key derivation and one counter for every passphrase call (N13) |
| D16 | Start token in the fragment of the address the program opens | **Change the delivery, keep the fragment**: open through a 0600 redirect file so the token is never on a command line; spend it on first use; word a hijack loudly (N3) |

---

## 7. What I could not check

- **No browser or HTTP test was run.** Every browser statement rests on the documents cited; section 4 lists the tests that would confirm them.
- **`spec/storage-encryption.md` does not exist**, so the passphrase layer was reviewed only as an interface.
- **Not verified:**
  - whether macOS shows other users' process arguments;
  - whether Chrome's crash reports carry the tab URL with its fragment;
  - whether Chrome's history and tab sync keep the fragment after `replaceState`;
  - Firefox's and Safari's current handling of `Permissions-Policy` and `Clear-Site-Data` on loopback HTTP;
  - whether the Chromium password manager's realm includes the port. This is believed from its `signon_realm` definition; T8 settles it.
- **The Jupyter redirect-file precedent** (`ServerApp.use_redirect_file`) is cited from memory of its documentation, not re-read today.
- **The same-user peer check (N4)** was not prototyped. Its cost on macOS (no single call) was not assessed; Slice 1 is Linux.
- **Not read in full:** `LOBBY.md`, `messages.md`, `discovery.md`, `concept-h-recommended.html`. Claims the spec attributes to them were taken as stated.
- **The 1.0.0 payment, move and leave-alone calls** were read only for the fresh-sign-in and echo rules.

## 8. Sources

- RFC 6265, section 8.5: https://www.rfc-editor.org/rfc/rfc6265#section-8.5
- RFC 6265bis: https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
- RFC 9110, section 7.1 (request target), and RFC 3986, section 3.5 (fragment): https://www.rfc-editor.org/rfc/rfc9110 , https://www.rfc-editor.org/rfc/rfc3986#section-3.5
- HTML, Web storage: https://html.spec.whatwg.org/multipage/webstorage.html
- HTML, Broadcasting to other browsing contexts: https://html.spec.whatwg.org/multipage/web-messaging.html
- HTML, Server-sent events: https://html.spec.whatwg.org/multipage/server-sent-events.html
- HTML, autofill (`autocomplete="off"`): https://html.spec.whatwg.org/multipage/form-control-infrastructure.html
- HTML, origins and "same site": https://html.spec.whatwg.org/multipage/browsers.html#origin
- Fetch: https://fetch.spec.whatwg.org/
- W3C Fetch Metadata Request Headers: https://w3c.github.io/webappsec-fetch-metadata/
- W3C Clear Site Data: https://w3c.github.io/webappsec-clear-site-data/
- W3C Secure Contexts: https://w3c.github.io/webappsec-secure-contexts/
- Chrome for Developers, Local Network Access: https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access
- MDN, `Window.sessionStorage`: https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage
- MDN, `Permissions-Policy` and `clipboard-write`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
- proc(5), `hidepid`: https://man7.org/linux/man-pages/man5/proc.5.html
- Bitwarden, URI match detection: https://bitwarden.com/help/uri-match-detection/
- Jupyter Server configuration, `ServerApp.use_redirect_file`: https://jupyter-server.readthedocs.io/en/latest/other/full-config.html
- RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- Linux `sock_diag(7)`: https://man7.org/linux/man-pages/man7/sock_diag.7.html ; Windows `GetExtendedTcpTable`: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
