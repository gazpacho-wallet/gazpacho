# Review of `spec/local-api.md`, draft 1

Reviewed 2026-11-12, from `origin/specs-slice1` at commit `8447ea3`. Independent and adversarial; the reviewer wrote none of the specification. Context read on the same branch: `docs/SLICE1-WORK.md`, `docs/SLICES.md`, `docs/ux/decisions.md`, `docs/THREAT-MODEL.md`, `docs/DESIGN.md` section 13, `docs/reviews/ux-critique.md` (sections 3, 4, 7, H.3 to H.10), `spec/messages.md` sections 6 and 7.9 to 7.11, `spec/terms.md` sections 3 and 5 to 10, `spec/journal.md` sections 8 to 10 and 13, `spec/signing-round.md` sections 7 and 10, `spec/safety-rule.md` (C11, section 12 line), `spec/discovery.md` sections 14 and 14.1, `docs/notes/wallet-keys.md` section 8, and the prototype's `web/API.md` on `origin/ui-prototype`.

## Verdict

**Ready after listed changes.** The overall shape is sound and better than most local-wallet APIs: an exact `Host` allow-list against DNS rebinding, no CORS at all, JSON-only bodies, a custom check header, fetch-metadata checks, `Cross-Origin-Resource-Policy` on API answers, server-sent events instead of WebSocket, a strict CSP with Trusted Types, no secrets in URLs, and a deliberate effort to give every safety state its own value. The browser-behaviour claims are mostly right.

But four findings must be fixed before the program is built against it, because each one either hands a session to another party or lets the interface say something false about money:

1. The session cookie is sent by the browser to **every** port on `127.0.0.1`, so any other local web service the person opens receives it, and with it can fetch the check value (F1).
2. The 24-word check is an oracle that recovers the words without the fresh sign-in that showing them requires (F2).
3. A lobby cancelled after the member's partial signatures went out is reported as "nothing was signed" (F3).
4. The Slice 1 subset depends on stored state (conditions and their copies, activity entries with saved copies, pause) that `journal.md` has no records for (F11), so the program cannot be built "without guessing".

With F1 to F3, F5, F7, F9 and F11 fixed and the Slice 1 gaps of section 3 closed, it is buildable for Slice 1. F4 and the other 1.0.0 findings must be fixed before the calls they concern are built.

---

## 1. Findings, ranked

Severity: **High** (a session, the words, or a false safety statement), **Medium** (weakens a defence, or a Slice 1 builder must guess), **Low** (inconsistency, hardening, wording). "S1" or "1.0.0" says when it bites.

### F1. High, S1. The session cookie reaches every other port on loopback, and `GET /api/v1/session` turns it into a full session

**Evidence.** Section 4.3: `Set-Cookie: gz_session_39735=…; Path=/; HttpOnly; SameSite=Strict`, no `Domain`. Section 4.3 says the port in the name "avoids collisions; it does not stop that application from sending requests here". Section 4.4: `GET /api/v1/session` with a valid cookie answers `"check": "<value>"`. Section 5.7 says another local web application "can still see that the port answers".

**Why it is wrong.** Cookies are scoped to a host, not to a host and port: "Cookies do not provide isolation by port. If a cookie is readable by a service running on one port, the cookie is also readable by a service running on another port of the same server" (RFC 6265 section 8.5). So the browser attaches `gz_session_39735` to every request it makes to `127.0.0.1` on any port: a development server, a notebook server, a sync tool's web page, or a server started by another operating-system user on the same machine. `HttpOnly` only stops page script; the other server reads the `Cookie` header directly. `SameSite=Strict` does not help, because other ports are the same site (HTML, "same site", is scheme and registrable domain or host, with no port); it only stops the cookie on navigations started from cross-site pages.

That server, now holding the cookie value, needs no browser: it sends `GET /api/v1/session` with `Host: 127.0.0.1:39735` and the cookie, receives the check value, and from then on passes the `Host`, `Origin` (any value it likes), content-type and check-header walls, because those walls only constrain browsers. It has a complete non-fresh session: join lobbies, loosen conditions, open a hosted lobby that sets aside on-chain funds (F5), start the phrase-check oracle (F2), go offline (1.0.0, F5), and so on. Many local tools log request headers, so the cookie also ends up in other programs' logs, against rule 5.5.

The section 5.7 row that accepts "another local web application" is therefore understated: it does not just see that the port answers; it holds the credential.

**Fix.** Do not use an ambient, port-blind cookie as the credential.
- Preferred: the session secret is returned once in the body of `POST /api/v1/session`, kept in `sessionStorage` (origin-scoped, so isolated by port: HTML, Web Storage, "origin") or only in memory, and sent on every request as a header (for example `X-Gazpacho-Session`). A custom header also forces a preflight across origins (Fetch, "CORS-safelisted request-header"), so CSRF protection stays, and the check header becomes unnecessary. `EventSource` cannot set headers: serve the stream to a `fetch()` reader (a `ReadableStream`), or authenticate the stream with a one-use, short-lived stream ticket obtained by a `POST` and sent in the first message, never in the URL.
- If a cookie is kept: `GET /api/v1/session` must never return the check value; return it only in the `POST /api/v1/session` and `unlock` answers and keep it in `sessionStorage`. That still leaves every `GET` (status, lobbies, activity, wallet coins and addresses) readable by the other port's server, so the first option is better.
- Either way, rewrite section 4.3's "The port is in the name" paragraph and section 5.7's row, and add tests: a server on another loopback port receives no Gazpacho credential when the browser visits it (23.2), and a replayed cookie alone gives nothing.

Sources: RFC 6265 section 8.5; HTML Living Standard, "same site"; RFC 6265bis (draft-ietf-httpbis-rfc6265bis), SameSite and "same-site" request definitions; HTML Living Standard, Web Storage (`sessionStorage` is per origin, and an origin includes the port).

### F2. High, S1. The phrase check recovers the 24 words without a fresh sign-in

**Evidence.** Section 12.3: `POST /api/v1/wallet/phrase/check-start` (no fresh sign-in) answers random `positions`; `POST /api/v1/wallet/phrase/check` answers `{ "ok": false, "wrong_positions": [14] }`; "Three tries per `check_id`"; no limit on `check_id`s; available at any time while `words_not_checked` stands, and nothing says it stops afterwards. `reveal` needs a fresh sign-in "because they reveal keys" (4.6).

**Attack.** Each answer says, per position, whether the guess was right. Guess one word from the 2,048-word list per position, three positions a try, three tries a check, unlimited checks: each word falls to at most 2,048 guesses, so about 24 × 2,048 / 3 ≈ 16,000 guesses, about 5,500 checks, a few minutes without a rate limit. The last word needs only 8 candidates once 23 are known (BIP 39 checksum). Anyone with a non-fresh session (an unattended browser with "never lock", a session obtained by F1) gets the words, which fresh sign-in was meant to prevent.

**Fix.** Any of: require a fresh sign-in for `check-start`; answer only `ok: true|false` for the whole set; cap checks per wallet (for example 3 `check_id`s a day, and none after `words.checked_at` is set unless the person asks again with a fresh sign-in); count failures and lock the session after a few. Add a test: no sequence of non-fresh calls returns information about any word.

### F3. High, S1. "Cancelled" is reported as "nothing was signed" even when partial signatures went out

**Evidence.** Section 14.1, `you.outcome`: `cancelled` with `reason` `signing_budget_spent` is marked "Nothing was signed? Yes". Section 11.2, `doing.code = lobby_cancelled`: "Cancelled before any signature", reasons including `signing_budget_spent`. Section 22 lists `lobby_cancelled` among "the only places 'nothing was signed; nothing moved' is allowed".

**Why it is wrong.** `messages.md` 6.10: `cancel` reason 3 is "signing failed within its time budget", and "A `cancel` does not undo partial signatures already sent. A member with an unresolved creation round keeps watching that round's funding outpoint". `signing-round.md` section 7: once any partial signature is sent, every failure leads to Unfinished, and a host's `round_abort` "changes nothing". So a member can receive a valid `cancel` while Unfinished. The API would show the reassuring outcome the critique forbids (critique section 4, point 2; H.5).

**Fix.** The outcome is decided by the member's round state, not by the host's message: if any partial signature was sent in any attempt of the lobby, the outcome is `signing_unfinished`, then `abandoned` or `dead`, with `cancel_received: { reason }` as extra information. `lobby_cancelled` and `cancelled` are only reachable with no partial signature ever sent. Add a section 22 row and a contract test: `cancel` reason 3 after `round_partial_sigs` yields `signing_unfinished`.

### F4. High, 1.0.0. The host-node settings can send any local file to any address

**Evidence.** Section 15.4: `PUT /api/v1/host/node` takes `{ "kind", "address", "access_file" }`, "`access_file` is a path on this machine; its contents never reach the browser"; `POST /api/v1/host/node/test` connects. No fresh sign-in.

**Attack.** With any session (F1, an unattended browser), set `address` to a server the attacker runs and `access_file` to the wallet's phrase file, the start-up token file or the journal, then call `test`. The program reads the file and presents its contents to the attacker's server as the node credential (an LND macaroon travels in a request header; a CLN rune likewise). The contents never reach the browser, but they reach the attacker. The phrase file is plain text (`docs/notes/wallet-keys.md` section 8).

**Fix.** Fresh sign-in for `PUT /host/node` and `test`; refuse any path inside the program's data folder and any file that is not a regular file of the expected form (macaroon or rune syntax, size limit); show the address and require confirmation before the first connection; never send file bytes before the server proves it is the configured node (TLS certificate pinned from the node's own certificate file). The same review applies to every call that takes a path or an address (`POST /discovery/query`, `POST /settings/connections/servers`).

### F5. Medium, S1 and 1.0.0. Fresh sign-in is missing on actions that spend or expose money

**Evidence.** Section 4.6 requires a fresh sign-in for "sending coins on chain" and "starting to leave a factory alone". `POST /api/v1/host/lobbies` (S1) "sets aside the funding at the target" (37,500,000 sats in the example) and leads, through `start` (S1), to signing and broadcasting a funding transaction, with no fresh sign-in and no amount confirmation in the request. In 1.0.0: `POST /settings/connections/servers`, `DELETE …/servers/{id}` and `PATCH chain.mode` change the chain view; `POST /settings/watching/offline` and `who_watches: nobody` turn watching off; none need a fresh sign-in.

**Why it matters.** Funding a factory is the largest on-chain spend the program makes. The chain-view rules are "not a setting" (section 20), but a session can replace both public servers with two the attacker runs, as long as they claim two operators; section 20.3 does not say how the operator of a user-added server is known. A controlled chain view, or going offline, hides an old-state publication (threat model 2.4).

**Fix.** Fresh sign-in, and the total in the request (`"confirm_funding_sat"`), for opening a hosted lobby; fresh sign-in for every chain-server and watching change; define how an operator is established for a user-added server (it cannot be the user's word alone if the two-operator rule is to mean anything).

### F6. Medium, S1. `request_id` is not bound to the request, and is forgotten at restart

**Evidence.** Section 7.4: "The same `request_id` again returns the first answer and does nothing new. The program keeps request ids for the run."

**Problems.**
- Nothing ties a `request_id` to the call. A client bug, or two tabs sharing a generator, that sends the same id to `join` lobby A and then `join` lobby B gets A's answer for B and B is silently not joined; the same for `open` and `start`.
- "For the run" is unsafe for outward actions: the program saves and sends, then crashes before answering; the interface retries after the restart with the same id; the program has forgotten it and acts again. `DESIGN.md`'s "save before send" protects the protocol, not the API's idempotency. In Slice 1 `already_in_lobby` and `already_hosting` mask this; in 1.0.0 (several lobbies, `wallet/send`, `invoices`, `payments`) it gives double effects unless every such call is also bound to a single-use review id that is saved as spent.
- `create` is "sent once" by `request_id`; a different id gives `wallet_exists`. Fine, but it shows the ids are per-call in practice.

**Fix.** Key the store by (method, path pattern, `request_id`) and keep a hash of the body; the same key with a different body answers `409 request_id_reused`. Save the ids of outward actions in the journal with the action's result, or require a saved single-use `review_id`/`preview_id` for every outward 1.0.0 action and say how long each lives (section 16.3, 17, 18 give none).

### F7. Medium, S1. The chain-view, watching and "doing" values are not fully mapped, so the strip can be reassuring when it must not be

**Evidence and gaps.**
- `money.chain_view` is `trusted` or `in_doubt`, but section 11.2 does not say which `connection.chain.state` values give which. `catching_up` ("nothing is treated as newly confirmed yet"), `lagging`, `unreachable` and `offline_by_choice` are not mapped. Section 22 lists only `disagree | one_source | unreachable`. The critique's rule (section 4, "Your money has not moved" when servers disagree) needs a total mapping; figures while `offline_by_choice` or `catching_up` are stale and must be `in_doubt`.
- `watching.state` `nobody_chain_in_doubt` is defined as "the chain view is in doubt" without saying which chain states; `unreachable` and `one_source` should both give it; `offline_by_choice` must give `nobody_offline` and win over the other.
- `doing.code` is "one value at a time, the most important first", but the order is not stated as normative. Read as the table order, `chain_in_doubt` and `paused` outrank `signing_unfinished`, so a member who paused with signatures out sees "Paused" on the strip while the at-risk item sits in the attention list. At-risk states should outrank `paused`, and `held_for_signing` should show `signing`.
- Nothing says whether `money` counts a factory in `awaiting_funding` (C11: not live, no paying or receiving). `can_send_sat` and `inside_factories_sat` must exclude it, or show it apart.
- `abandoned` (14.1, 16.1) "Records kept; nothing is owed" omits that an abandoned creation can still become live (`safety-rule.md` C11; `signing-round.md` section 7, "Funding buried later → Live"). The interface needs a `still_watched: true` flag so it never says "over".
- `while_closed.verdict` is one value but `found`, `beyond_safe_absence` and `could_not_check` can all hold at once; give the precedence or make them separate fields.

**Fix.** A normative table from `connection.chain.state` to `chain_view` and `watching.state`; a normative priority order for `doing.code` with every at-risk value above `paused`; a rule for money in `awaiting_funding`; the flag on `abandoned`; precedence for `while_closed`. Add each to section 22 and to the contract test 23.4.

### F8. Medium, S1. The private-network claim is out of date, and loopback-to-loopback is never covered

**Evidence.** Section 5.3: "a browser's private-network check from a public page fails"; test 23.2.10: "A private-network-access preflight from a public origin: no allow header; the browser blocks the request".

**Why.** Chrome replaced Private Network Access preflights with Local Network Access, a permission prompt (`loopback-network` for public or local origins reaching the IPv4 loopback range, `::1` and `localhost`). Chrome's guidance says PNA preflights "were never enforced as a blocking requirement" and should not be relied on. A person can grant the permission to a site, and the check does not apply at all from one loopback origin to another (the F1 case). Firefox and Safari have their own, different rules.

**Fix.** Remove the sentence and test 23.2.10, or reword: "Browsers may additionally prompt before a public page reaches loopback; nothing here depends on it." Keep the other walls, which are correct. Optionally note the unspecified-address route: browsers have sent requests to the IPv4 unspecified (all-zeros) address, which reach loopback listeners on Linux and macOS; the exact `Host` check refuses them, because the `Host` value is that literal, so add it to test 23.2.2.

Sources: Chrome for Developers, "Local Network Access"; blink-dev "Intent to Ship: Local network access restrictions"; Oligo Security's 2024 write-up on the unspecified-address route (link in section 5).

### F9. Medium, S1. The idle lock never fires in practice

**Evidence.** Section 4.6: "Idle means no request from that session other than the event stream." Section 11.1: the interface calls `GET /status` "at start and on every `status` event"; section 10.2: every event makes the interface ask again.

**Why.** Events arrive with every chain tip and every lobby count change, and each one produces a `GET` from the open tab. An unattended browser therefore never becomes idle, which defeats the lock (and makes "lock after 15 minutes" a false promise in Settings).

**Fix.** Count only requests the interface marks as user-initiated (a header such as `X-Gazpacho-User: 1`, set only from input-event handlers), or have the interface report its last input time and let the program lock on it. State in the spec which calls refresh the idle timer. Test: with events flowing and no input, the session locks on time.

### F10. Medium, S1. The event-stream caps cause reconnect loops and use up the browser's connections

**Evidence.** Section 10.3: "At most 4 streams per session; a fifth closes the oldest", "`retry: 2000`"; section 10.1 counts one connection per tab out of six.

**Why.** An `EventSource` whose connection is closed reconnects after the retry time; only a non-200 answer (the introduction names 204) stops it (HTML, server-sent events). With five tabs, the oldest is closed, reconnects in 2 s and closes the next oldest, for ever. Four streams also take four of the six HTTP/1.1 connections the browser allows per host, leaving two for every API call of every tab; a fifth tab's calls queue behind them. The HTML specification itself warns about per-server connection limits and suggests one shared worker.

**Fix.** Answer a stream over the cap with `204` (or `429` with a body the interface understands), and have the interface hold one stream for all tabs in a `SharedWorker` (allowed by `script-src 'self'`, as `worker-src` falls back to it) or elect a leader tab with `BroadcastChannel`. Test 23.2.32 then expects no reconnect loop.

Source: HTML Living Standard, server-sent events (reconnection, "status is not 200", the 204 note and the per-server connection note).

### F11. Medium, S1. The API's state has no home in the journal

**Evidence.** Slice 1 calls need: the member's conditions with a `version` (13.1, `based_on_version`), the copy of conditions made at joining (13.2, "the copying rule", and test 23.1.2, which refuses at signing against the copy), activity entries with immutable saved copies of terms, fit and conditions (19, critique rule 19), the pause state (11.3), the setup state and `words.checked_at` (12.1, 12.5), the idle-lock setting, and the known-host list that `discovery/query` adds to (2.1). `journal.md` section 9 has none of these (its lobby records are protocol bytes; `lobby_ended` is "for history"). Section 24 point 14 opens only the activity part.

**Why it matters.** "Can the program be built from the Slice 1 subset without guessing?" No: each builder will invent a store. Two are safety-relevant. If Pause is not saved, a restart silently resumes joining and signing. If the conditions copy is not saved with `joined`, a restart compares the tree at signing with the loosened current conditions, and test 23.1.2 fails.

**Fix.** Either add journal records (conditions version, conditions copy saved in the `joined` batch, pause on/off, activity entry, setup state) or name a second store with the same save-before-answer rule. State that Pause survives a restart.

### F12. Medium, S1. Fake interface and sign-in denial by another local user

- **Port squatting.** Section 3.1 refuses to pick another port because "a bookmark would then open whatever else is listening, which could be a program pretending to be Gazpacho". A fixed, published port has the same problem: when Gazpacho is not running, any user can bind `127.0.0.1:39735` (ports above 1023 need no privilege on POSIX; `SO_EXCLUSIVEADDRUSE` on Windows does not prevent an earlier binding) and serve a copy of the interface that asks for the 24 words ("restore" or "check your words"). Add this to section 5.7 as accepted, and make the interface's one defence explicit: the words are never typed into the interface except on the restore screen of an empty wallet, and the program's own terminal output says when the port is taken.
- **Sign-in denial.** "One sign-in attempt per second per program, whatever the source. After 5 wrong codes in a row, every unused code is cancelled." Any local process, including another user's, can send five wrong codes a few times a minute and keep the person locked out for ever, and can keep the per-second slot busy. State that the attempt counter counts only requests that passed the `Host`, `Origin`, content-type and fetch-metadata checks (a web page then cannot touch it), and accept or address that a local process can still deny sign-in (for example, count failures per connection source and keep codes minted after the last failure valid).
- **Connection slots.** 32 connections with a 10 s header timeout and 60 s idle timeout can be held by any local process. Accepted, but say so.

### F13. Medium, S1 decision. The 24 words in the browser contradict `DESIGN.md`

`DESIGN.md` section 13: "Keys and channel state never enter the browser." The words are the keys. Section 1 of the API carves out an exception and section 24 point 6 leaves the choice to the owner, but `create` and `reveal` are S1, so the decision blocks Slice 1. If the browser keeps them, add interface rules the API depends on: `autocomplete="off"`, `spellcheck="false"` and `autocapitalize="off"` on every word field (browser enhanced spell-check services send field text to a server), words removed from the DOM and from JavaScript variables when the screen closes or the session locks, no copy-to-clipboard button, and `Clear-Site-Data: "cache", "storage"` on sign-out and `revoke-all`.

### F14. Medium, S1. An HTTP server and JSON parser written in C, with no fuzzing in the tests

The program parses untrusted bytes from any local process and any web page (requests that are later refused are still parsed). Section 23 tests named malformed cases but no fuzzing. Add: a vetted HTTP parser (or one with a published fuzzing record), coverage-guided fuzzing of request-line, header and JSON parsing under sanitizers in CI, and a limit on the number of headers, not only their total size.

### F15. Medium, 1.0.0. The unencrypted backup export

Section 12.6: export is 1.0.0 and "Unencrypted in Slice 1; the interface must say so". The two marks disagree. `journal.md` section 10 keeps keys out of the journal, so the export holds no seed, but it holds the held set of signed transactions, the history and every network address of hosts. Through the browser it lands in a downloads folder that is often synchronised to a cloud service. Either ship export only with encryption (journal open point 1) or drop "in Slice 1" and mark it 1.0.0 behind the encryption decision.

### F16. Medium, S1. Unlisted lobby identifiers are in URL paths, against sections 5.5 and 7.3

Sections 5.5 and 7.3: an unlisted lobby's fingerprint "is a capability" and "travels only in bodies, never in this API's URLs". But every lobby call puts it in the path (`/api/v1/lobbies/{id}`, `…/join`, `…/ready`, `…/leave`, `/host/lobbies/{id}`), and events carry it in their data. Paths of `fetch()` calls are not browser history, and the access log keeps patterns only, so the risk is small; the contradiction is the problem. Either drop the claim and accept the identifier in paths (justifying it), or address lobbies by a local opaque id and keep the fingerprint in bodies only.

### F17. Low, S1. `Referrer-Policy: no-referrer` can turn the interface's own `Origin` into `null`

The Fetch standard's "append a request `Origin` header": for a request whose method is not `GET` or `HEAD` and whose mode is not `cors`, a referrer policy of `no-referrer` sets the serialised origin to `null`. `fetch()` defaults to mode `cors`, so the interface works as long as it never uses `mode: "same-origin"` or a form; with either, every unsafe call is refused by section 5.2. Either state "the interface's requests use `fetch()` in its default mode" or use `Referrer-Policy: same-origin`, which keeps the real `Origin` on same-origin requests and sends no referrer elsewhere. Test 23.2.7 (no `Origin` refused) plus a positive test of every unsafe call from the real interface catches it.

Source: Fetch Living Standard, "append a request `Origin` header".

### F18. Low, S1. Headers on every response, not only on pages and API answers

Section 5.4 puts CSP, `frame-ancestors` and COOP on `/` and `/index.html`, and CORP on API answers. Static scripts, styles, images and error answers (`404`, `421`, `403`) get none. Put `Cross-Origin-Resource-Policy: same-origin`, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on every response. CORP on static files also stops a cross-origin `<img>` from fingerprinting Gazpacho in browsers that send no fetch metadata (Safari before 16.4), and it is the defence that holds when `Sec-Fetch-*` is absent (section 5.2 says "when present").

Sources: Fetch Living Standard, "Cross-Origin-Resource-Policy"; W3C Fetch Metadata Request Headers; MDN, `Sec-Fetch-Site` browser compatibility.

### F19. Low, S1. Duplicate and planted cookies

Another port can set a cookie with the same name (by `Set-Cookie`, not by script, since a non-HTTP API cannot overwrite an `HttpOnly` cookie, RFC 6265bis cookie storage model) or one with a longer `Path`, which the browser sends first. Say what the program does with two `gz_session_<port>` cookies (refuse with `400`), that sign-in ignores any incoming cookie and always mints a new one, and that a cookie-jar overflow from another port can sign the person out (accepted). Moot if F1 removes the cookie.

### F20. Low, S1. Text from other people: format characters

Section 5.6 drops control characters other than newline. Also drop or isolate Unicode format characters (bidirectional overrides and isolates, zero-width characters, category Cf), and require the interface to render every `{text, by}` inside an isolating element (`<bdi>` or `unicode-bidi: isolate`) and never to turn it into a link. Otherwise a host alias can reorder the text around it, including numbers. `host.address` comes from the host or a listing in 1.0.0 (Nostr `addr`) and is returned as a bare string; validate it to the grammar of section 21 or wrap it.

### F21. Low, S1. Bearer clients and fresh sign-in

Section 4.5 does not say whether a bearer-token client must make a fresh sign-in for the calls of section 4.6. It cannot (it has no session). Say that bearer requests are exempt, because a holder of the token file is the same operating-system user, and that `revoke-all` rotates the token. Also state whether bearer requests are accepted on the TCP port or only on the local socket; accepting them only on the socket removes one way to use a stolen token file from a sandboxed process with network but not socket access.

### F22. Low, S1. Statements stronger than the sources

- Section 5.3, "Four walls ... Each test in section 23.2 removes one and expects a refusal from the others as well." For a same-site page on another port `SameSite` is not a wall, and for `GET` neither content type nor check header is. The tests should say which walls apply to which origin.
- Section 4.2, "An attacker who can read the person's terminal can read the token file too." Not for terminal scroll-back captured by multiplexers, screen sharing or remote-desktop recordings; the one-use and 10-minute limits are the real defence. Reword.
- Section 5.7, "it reveals that a port is open, nothing more": the `421` with no content and the timing of refusals also identify the program. Accepted; reword.
- Section 3.1's argument against picking another port (F12).
- Section 5.3's private-network sentence (F8).

### F23. Low, S1. Windows

- Double-click start: the console window shows the code, and closing it stops the program. Started at login, from a shortcut set to run minimised, or by a launcher without a console, no code is printed and the person must open a terminal for `gazpacho sign-in-code`. Section 24 point 4 is right to leave it open; until it is decided, Windows is not usable by a non-technical person. A native message box or tray item that shows a code on request would keep codes out of URLs.
- `gazpacho open` on Windows prints a code into a console that closes when it exits; it must wait for a key, or show the code another way.
- AF_UNIX sockets on Windows: whether connect honours the socket file's access list as POSIX honours mode 0600 was not verified here (section 4 of this review). Named pipes take an explicit security descriptor and are the safer default until it is.
- The token file's access list must be set when the file is created (a protected DACL for the user only), not tightened afterwards.
Slice 1 runs on the build server (`SLICES.md`, "Where slices run"), so these are 1.0.0 items, not Slice 1 blockers.

### F24. Low. Smaller consistency points

- Section 4.4 marks `POST /session/lock` and `POST /session/revoke-all` S1; the Slice 1 table 2.1 omits them. `GET /api/v1/backup` and `GET /api/v1/factories/{id}/dates` are marked 1.0.0 but say what "S1 returns". Put every S1 call in table 2.1.
- `you.outcome` has no value for `refused_by_host` (seat state 7), though `you.seat` has it.
- `doing.code` values such as `refused` and `lobby_cancelled` have no stated lifetime: how long does the strip show them?
- `POST /api/v1/discovery/query` answers `202` "then `discovery` events; the answer holds `{ query_id, lobbies }` when the host answered within 30 s". Say whether the call blocks up to 30 s or returns at once.
- The "once per 10 s" limit on person-initiated queries is the API's own; `discovery.md` DQ2 gives only "once per node per hour, 32 nodes per hour". Record it in `discovery.md` or mark it proposed.
- Owner decision 10 mentions standby seats; the API has no field for them (1.0.0).
- The pause sends `leave` reason 2 ("user", `messages.md` 6.6); state which lobby stages count as "not started" (Open and Ready check; and a seat that received `start` role 1 but no `round_propose`?), and whether a member in Nonces sent aborts (nothing signed yet) rather than holding the pause.

### Checked and correct

These claims were checked against primary sources and hold:
- The exact `Host` allow-list defeats DNS rebinding, including for static files (the rebound page's requests carry its own name).
- `SameSite` does not separate ports; other ports are same-site, and `Sec-Fetch-Site` reports `same-site` for them (HTML "same site"; W3C Fetch Metadata).
- `application/json`, `application/octet-stream` and a custom header force a preflight across origins; `text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data` do not (Fetch, "CORS-safelisted request-header"). Answering `OPTIONS` with `405` and sending no `Access-Control-*` header blocks every cross-origin request that needs a preflight.
- `Cross-Origin-Resource-Policy: same-origin` blocks no-cors cross-origin reads of API answers (Fetch, CORP check).
- `EventSource` is a potential-CORS request; cross-origin it needs CORS, so with no CORS headers it fails (HTML, server-sent events). Choosing it over WebSocket removes the cross-site WebSocket hijacking class.
- `http://127.0.0.1` and `http://[::1]` are potentially trustworthy, so secure contexts (W3C Secure Contexts). Browser handling of `Secure` cookies on loopback differs (Chrome and Firefox accept them, Safari does not), as section 4.3 says.
- `require-trusted-types-for 'script'; trusted-types 'none'` is valid and makes string assignments to `innerHTML` throw where Trusted Types are supported (Chrome and Edge for years, Safari 26, Firefox recently; Baseline in 2026 according to web.dev). The interface must not depend on it, and section 5.4 does not.
- 32^10 = 2^50, so the sign-in code is 50 bits; with one guess a second and five wrong guesses cancelling every code, guessing is not a practical attack.

---

## 2. Wallet-safety questions asked in the brief

**Can any sequence of calls make the wallet sign something the member did not consent to?** Not through the protocol checks: joining needs `seen_current_digest`, which commits to the outer rules (`terms.md` section 6), the round identifier commits to the frozen digest (`terms.md` section 10), and the tree is checked at signing against the conditions. The terms-digest check on join is sound. What is weaker is who can give consent: any session can loosen conditions and join (F5), open a hosted lobby that spends on-chain funds without a fresh sign-in (F5), and a session is obtainable by another local service (F1). Joining is consent by design (options map); that design needs the session to be the person's.

**A misleading safety status?** Yes in three places: cancel after partial signatures (F3), incomplete chain-view mapping and `doing` priority (F7), and `abandoned` without "still watched" (F7).

**Leak of the 24 words, keys or the journal?** The words, through the check oracle (F2) and, in 1.0.0, any local file through the host-node test (F4). The journal through an unencrypted export (F15). Keys never cross the API except as the words.

**Idempotency.** Not sound as written (F6).

**Status values complete and mutually exclusive?** The coverage of section 22 is good and matches `signing-round.md` section 7 state for state. Gaps: F3, F7, `refused_by_host` (F24), and the absence of a normative priority for the single `doing.code`.

---

## 3. Slice 1 gaps: what a builder must still guess

1. **Where the API's own state is saved** (F11): conditions and version, the copy made at joining, pause, setup state and words checked, activity entries with saved copies, the known-host list. And that Pause survives a restart.
2. **How the start happens.** `messages.md` 6.8 sends `ready_check` "when the start rule is met"; the API has `POST /host/lobbies/{id}/start` and an attention item `host_can_start`. Does the host program start by itself at the target and at the deadline with at least the minimum, or only when the person presses Start? Both, with which precedence?
3. **The session transport after F1**, and how the event stream authenticates.
4. **The decision on the words in the browser** (F13; section 24 point 6), since `create` and `reveal` are S1.
5. **Slice 1 values of the money and factory fields** when Slice 1 has no channels: `money.can_send_sat`, `can_receive_sat`, `take_out_alone`, `factory.channel` (said to be `null`), `factory.exit`, `factory.dates`, `while_closed` (1.0.0, but `status.while_closed` is in the S1 status example).
6. **Which confirmations make a factory live**: `funding.needed` is 3 in the examples; `safety-rule.md` section 12 proposes burial at 3 blocks and C11 speaks of "the member's chosen depth". Say that `needed` = the larger of the program's floor and the member's copied `min_confirmations`, and what the host uses.
7. **The host's view of the tree.** The Slice 1 screen "shows the lobby, the tree and the confirmation" (`SLICES.md`). `factory.tree.path` is a member's path; the host's factory object (`host_view`) has no tree.
8. **Defaults** that Settings would set but Settings is 1.0.0: idle-lock time in Slice 1, the funding transaction's fee rate (the owner's 0.1 sat/vB, `100`), whether `ipv6` is on.
9. **Pause boundaries** (F24, last point) and what `held_for_signing` covers.
10. **`discovery/query` timing** (F24).
11. **Several programs on one machine** (Slice 1 runs a host and three members): the data-folder flag is not named; the default port is per network, so every instance needs `--interface-port` or `--no-interface`. Say so in section 3.1 and in the walkthrough.
12. **The doing-code priority order** and the chain-view mapping (F7), needed by the strip from the first build.
13. **Sticky outcome codes**: how long `refused`, `lobby_cancelled`, `not_chosen` stay in `doing` (F24).
14. **`request_id` storage and scope** (F6).

Everything else in the Slice 1 table (session calls, version, events, status, keys, conditions, discovery by address, lobbies, hosting, factories, funding wallet, activity) is specified well enough to build, once the items above are settled.

---

## 4. What I could not check

- No browser or HTTP test was run; every browser-behaviour statement here rests on the specifications and vendor documentation cited, not on experiment. In particular F1's cookie behaviour, F10's reconnect loop and F17's `Origin: null` case should be confirmed with Playwright in Chrome, Firefox and Safari before the fixes are chosen.
- Whether Windows AF_UNIX sockets enforce the socket file's access list on connect, and the exact behaviour of console programs started by double-click (F23).
- The first Firefox version with Trusted Types (sources disagree, 145 to 148) and the exact Safari version that added `Sec-Fetch-*` headers (16.4 from memory).
- Chrome's current per-host connection limit for HTTP/1.1 (six, from memory and MDN's `EventSource` note).
- `docs/ux/concept-h-recommended.html`, `docs/ux/options-map.html`, `LOBBY.md`, `transport.md` and the rest of `safety-rule.md` were not read in full; claims the API attributes to them (the copying rule, "never a setting", rule 21) were taken as stated.
- Whether the prototype's `gz.util.h` really inserts all text as text.
- The 1.0.0 payment, move and leave-alone calls were read for security, not for completeness against the engines they depend on, which are not specified yet.

## 5. Sources

- RFC 6265, HTTP State Management Mechanism, section 8.5 "Weak Confidentiality": https://www.rfc-editor.org/rfc/rfc6265#section-8.5
- RFC 6265bis (draft-ietf-httpbis-rfc6265bis), SameSite, same-site requests and the storage model's `HttpOnly` rule: https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
- HTML Living Standard, "same site": https://html.spec.whatwg.org/multipage/browsers.html#same-site
- HTML Living Standard, server-sent events: https://html.spec.whatwg.org/multipage/server-sent-events.html
- HTML Living Standard, Web Storage: https://html.spec.whatwg.org/multipage/webstorage.html
- Fetch Living Standard, "append a request `Origin` header", "CORS-safelisted request-header", "Cross-Origin-Resource-Policy": https://fetch.spec.whatwg.org/
- W3C Fetch Metadata Request Headers: https://w3c.github.io/webappsec-fetch-metadata/
- W3C Secure Contexts, "Is origin potentially trustworthy?": https://w3c.github.io/webappsec-secure-contexts/
- Chrome for Developers, Local Network Access: https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access
- blink-dev, Intent to Ship: Local network access restrictions: https://groups.google.com/a/chromium.org/g/blink-dev/c/cwu_RUmBpzY
- Chrome for Developers, Private Network Access: introducing preflights (superseded): https://developer.chrome.com/blog/private-network-access-preflight
- Oligo Security, write-up on browsers reaching loopback through the unspecified address (2024): https://www.oligo.security/blog/
- web.dev, Trusted Types (browser support): https://web.dev/articles/trusted-types
- MDN, `Sec-Fetch-Site`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site
- MDN, `EventSource`: https://developer.mozilla.org/en-US/docs/Web/API/EventSource
- Secure cookies on localhost: Mozilla bug 1618113 (Firefox 75) and httpwg/http-extensions issue 2605: https://github.com/httpwg/http-extensions/issues/2605
- BIP 39 (checksum in the last word): https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
