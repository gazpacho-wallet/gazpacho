# The local API: program to interface

Specification draft 4, 2026-11-12. Draft 3 (`8e4f9cb`) was reviewed independently (`docs/reviews/review-local-api-d3.md`, verdict "ready after listed changes, and a short list"); this draft answers its findings R1 to R12, aligns section 4.7 and the locked state with `spec/storage-encryption.md` draft 3 and with `spec/exit.md` 5.6 (draft 2), and fixes the contradictions the review of `spec/exit.md` draft 1 listed against this document (`docs/reviews/review-exit-d1.md`, section 4 item 6). Draft 4 has not itself been reviewed on its own; it was read with its companions by the cross-specification review 1 (`docs/reviews/review-cross-spec-1.md`), whose fixes are applied below ("Changes after cross-spec review 1"). Draft 3 is kept unchanged at `docs/specs-history/local-api-d3.md`, draft 2 at `docs/specs-history/local-api-d2.md`, draft 1 at `docs/specs-history/local-api-d1.md`. The table "Changes from draft 3", below, maps each finding to its change; the tables for drafts 2 and 1 are kept as those drafts had them.

It replaces the prototype's proposal (`web/API.md` on branch `ui-prototype`), which was written from the screens' side and left the start-up token, paging and the restored wallet undesigned.

This is the interface between the `gazpacho` program (C; host and member in one, with no role question, owner decision 4) and its local web interface (concept H, `docs/ux/concept-h-recommended.html`). The program serves the interface and answers this API. Nothing else talks to it in 1.0.0 except the program's own command line and the test harness.

Items marked **(open)** are listed in section 24. Values marked **proposed** are first choices the owner has not confirmed. Items marked **default, owner to confirm** are conservative choices Slice 1 builds against now; each is listed in section 24.1 with what changes if the owner chooses otherwise.

**Sources.** `web/API.md` and `web/README.md` (`ui-prototype`); `docs/ux/options-map.html` and `docs/ux/concept-h-recommended.html` (`ux-concepts`); `docs/ux/decisions.md`, `docs/SLICE1-WORK.md`, `docs/SLICES.md`, `docs/DESIGN.md`, `docs/THREAT-MODEL.md`, `docs/reviews/ux-critique.md`, `docs/reviews/review-local-api-d1.md`, `docs/reviews/review-local-api-d2.md`, `spec/storage-encryption.md` (draft 3), `spec/exit.md` (draft 2, and the review of draft 1), `docs/reviews/review-local-api-d3.md`, `docs/reviews/review-cross-spec-1.md`, `spec/messages.md`, `spec/terms.md`, `spec/journal.md`, `spec/signing-round.md`, `spec/safety-rule.md`, `spec/discovery.md` (`specs-slice1`).

**Web standards cited** (checked 2026-11-12 against the documents themselves, not from memory):

| Short name | Document | What this specification relies on |
|---|---|---|
| RFC 6265 8.5 | RFC 6265, HTTP State Management Mechanism, section 8.5 "Weak Confidentiality", https://www.rfc-editor.org/rfc/rfc6265#section-8.5 | "Cookies do not provide isolation by port": a cookie readable by a service on one port is readable by a service on another port of the same host. Hence no cookie at all (4.3) |
| RFC 6265bis | draft-ietf-httpbis-rfc6265bis, https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/ | `SameSite` is decided by site, and a site ignores the port; so `SameSite=Strict` does not separate two loopback ports |
| HTML origin | HTML Living Standard, "Origins", https://html.spec.whatwg.org/multipage/browsers.html#origin | An origin is a tuple of scheme, host and port; two origins are same origin only if scheme, host and port are equal; "same site" ignores the port |
| HTML storage | HTML Living Standard, "Web storage", https://html.spec.whatwg.org/multipage/webstorage.html | `sessionStorage` is the session storage area of the window's origin (port included), per top-level browsing context; it is copied into a new auxiliary browsing context (a window opened by the page) |
| HTML messaging | HTML Living Standard, "Broadcasting to other browsing contexts", https://html.spec.whatwg.org/multipage/web-messaging.html | A `BroadcastChannel` message reaches only contexts with the sender's storage key, so only pages of the same origin |
| HTML SSE | HTML Living Standard, "Server-sent events", https://html.spec.whatwg.org/multipage/server-sent-events.html | `EventSource` takes no request headers other than its own (`EventSourceInit` has only `withCredentials`); a status other than 200 fails the connection without a reconnect; the note on per-server connection limits and a shared worker |
| Fetch | Fetch Living Standard, https://fetch.spec.whatwg.org/ | "CORS-safelisted request-header" names only `Accept`, `Accept-Language`, `Content-Language`, `Content-Type` (three values) and `Range`, so any other header forces a preflight across origins; "append a request `Origin` header": a non-`cors` request that is not `GET` or `HEAD` gets `Origin: null` under `no-referrer` |
| Fetch Metadata | W3C Fetch Metadata Request Headers, https://w3c.github.io/webappsec-fetch-metadata/ | `Sec-Fetch-Site` and `Sec-Fetch-Dest`; `same-site` for another port of the same host |
| MDN storage | MDN, `Window.sessionStorage`, https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage | Practical behaviour: partitioned by origin and tab, survives reloads, cleared when the tab closes; a page opened by another page starts with a copy |
| Chrome LNA | Chrome for Developers, "Local Network Access", https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access | A permission prompt (`loopback-network`) for public or local pages reaching loopback; it applies only when a request crosses into a more private address space; Private Network Access preflights "were never enforced as a blocking requirement" |

Added in draft 3 (each checked 2026-11-12 against the document itself):

| Short name | Document | What this specification relies on |
|---|---|---|
| RFC 8785 | Rundgren, Jordan, Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, https://www.rfc-editor.org/rfc/rfc8785 | The canonical form behind the request digest (7.4): I-JSON input, no duplicate names (3.1); strings with only the control characters, `"` and `\` escaped, the short forms `\b \t \n \f \r`, everything else as itself, lone surrogates an error (its section on strings); numbers as ECMAScript writes them (its section on numbers); object members sorted by their names' **UTF-16 code units** as unsigned integers, recursively, array order kept (3.2.3) |
| Fetch Metadata, navigation | W3C Fetch Metadata Request Headers, "Sec-Fetch-Site", https://w3c.github.io/webappsec-fetch-metadata/ | `none` only for a navigation "explicitly caused by a user's interaction with the user agent" (typing, a bookmark); otherwise each URL of the request is compared with the request's origin. With HTML's definitions an opaque origin (a `file:` page) is same site with nothing but itself, so a navigation started by the first-run redirect file (4.3) is expected to arrive `cross-site`; test 23.6 item T5 confirms it per browser |
| proc(5) | Linux `proc(5)`, mount option `hidepid`, https://man7.org/linux/man-pages/man5/proc.5.html | Mode 0, "Everybody may access all /proc/pid directories", is "the traditional behavior, and the default"; only mode 1 or 2 stops other users reading files such as `/proc/pid/cmdline`. Hence the redirect file (4.3) |
| sock_diag(7) | Linux `sock_diag(7)`, https://man7.org/linux/man-pages/man7/sock_diag.7.html | `NETLINK_SOCK_DIAG` (named so since Linux 3.3; its predecessor `NETLINK_INET_DIAG` since 2.6.14) looks up a TCP socket by source and destination address and port; the answer's `idiag_uid` "is the socket owner UID". The page says nothing about which users may query; the program queries only its own connections' peers (3.4) |
| proc_pid_net(5) | Linux `proc_pid_net(5)`, https://man7.org/linux/man-pages/man5/proc_pid_net.5.html | `/proc/net/tcp`: "The "uid" field holds the effective UID of the creator of the socket". The fallback of 3.4 |
| unix(7) | Linux `unix(7)`, `SO_PEERCRED`, https://man7.org/linux/man-pages/man7/unix.7.html | Returns the peer's `pid`, `uid`, `gid` "in effect at the time of the call to connect(2), listen(2), or socketpair(2)". The local socket's user check (3.2) |
| getpeereid(3) | FreeBSD `getpeereid(3)`, https://man.freebsd.org/cgi/man.cgi?query=getpeereid&sektion=3 | The peer's effective user and group of "a connected Unix-domain socket", as at its `connect(2)`. The same check on the BSDs and macOS (3.2) |
| GetExtendedTcpTable | Microsoft, `GetExtendedTcpTable`, https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable | With `TCP_TABLE_OWNER_PID_CONNECTIONS` and `AF_INET` or `AF_INET6`, rows of `MIB_TCPTABLE_OWNER_PID` / `MIB_TCP6TABLE_OWNER_PID` give each endpoint's local and remote address and port and the owning process id. Windows Vista and later |
| OpenProcessToken | Microsoft, `OpenProcessToken`, https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken | The process handle needs `PROCESS_QUERY_LIMITED_INFORMATION`; "If the process being checked was started by a different account, the checking process needs to have the SE_DEBUG_NAME privilege enabled". So, for the program, failing to open the token is itself the sign of another account (3.4) |
| Jupyter redirect | Jupyter Server configuration, `ServerApp.use_redirect_file`, https://jupyter-server.readthedocs.io/en/latest/other/full-config.html | Default `True`: launching the browser by a redirect file "prevented the authentication token used to launch the browser from being visible"; `False` launches "by using a URL and visible token (as before)". The precedent for 4.3 |
| MDN Clipboard | MDN, "Clipboard API", Security considerations, https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API ; MDN browser-compat-data, `http/headers/Permissions-Policy.json`, https://github.com/mdn/browser-compat-data/blob/main/http/headers/Permissions-Policy.json | In Chromium, writing needs the `clipboard-write` permission or transient activation; in Firefox and Safari, transient activation only, and the `clipboard-write` permission is "not supported (and not planned to be supported)". The compatibility data lists the `Permissions-Policy` header and its `clipboard-write` feature in Chrome from 85, and as not supported in Firefox (bug 1531012) and Safari. So the header limits only Chromium's asynchronous Clipboard API (12.7) |
| Chrome bfcache no-store | Chrome for Developers, "Back/forward cache for Cache-Control: no-store pages", https://developer.chrome.com/docs/web-platform/bfcache-ccns ; web.dev, "Back/forward cache", https://web.dev/articles/bfcache | Chrome has been rolling out back/forward caching of `no-store` pages (experiments from Chrome 116, "expected to reach 100% in March and April 2025"); such a page is evicted when a `fetch` from it returns `Cache-Control: no-store`, or on cookie changes, and is kept 3 minutes; other browsers may still refuse such pages. `pagehide` fires "when a page unloads or when the browser tries to put it in the bfcache"; the `freeze` event is "only supported in Chromium-based browsers" (12.7) |
| HTML autofill | HTML Living Standard, "Autofill", https://html.spec.whatwg.org/multipage/form-control-infrastructure.html | For `autocomplete="off"`: "the user agent should not remember the control's data, and should not offer past values to the user", and "values are reset when reactivating a document". Crash and session restore are not addressed (12.7, test T7) |
| Clear Site Data | W3C Clear Site Data, https://w3c.github.io/webappsec-clear-site-data/ | Acted on only for a response with the credentials flag whose URL is "a priori authenticated" (a term from Mixed Content); `"storage"` clears every session storage area of the origin in the user agent, every tab included. A second wall only (4.4) |
| Bitwarden matching | Bitwarden, "URI match detection", https://bitwarden.com/help/uri-match-detection/ | Its "Host" option matches "the hostname and (if specified) port"; "Android Password Manager clients cannot currently match URIs based on port or path" (12.7) |

## Changes after cross-spec review 1

Alignment fixes from `docs/reviews/review-cross-spec-1.md`, made in one pass with `spec/exit.md`, `spec/storage-encryption.md`, `spec/safety-rule.md` and `spec/journal.md`. No new draft number: the design is unchanged; only where the documents disagreed.

| Item | Change | Where |
|---|---|---|
| D1 | A short, damaged or unrecognised penalty file never gives `nobody_locked`: `watcher_locked`, reason `penalty_file_short` (`at_risk`), the watcher using what the file holds. `spec/exit.md` now says the same, so 24.2 item 31 is closed | 4.7, 23.2 item 43, 24.2 item 31 |
| D4, D5 | **The lock echo `confirm_unlock_by_height` is required only when an `unlock_by` exists** (something to take out); otherwise `confirm_locked` alone. `watching.unlock_by` is `null` when nothing is to take out; draft 4's "otherwise the earliest `open_by`" is withdrawn. **Slice 1 therefore needs only `confirm_locked`.** Inside `WARN_LEAD` of `leave_by` the warning is the stronger one | 4.5, 4.7, 4.8, 11.1, 23.2 item 19, 24.1 D13 |
| Slice 1 and the key store | Slice 1 has **no OS key store requirement**: it makes no KB and no store record, and its attempts file uses the plain-checksum mode (storage 12.3); the keyed mode starts once a bundle exists (1.0.0) | 4.7, 24.2 item 24 |
| D6 | While locked with the chain view in doubt, `watching.state` stays `watcher_locked`, reason `chain_in_doubt`: the watcher still acts on `spec/exit.md` 4.5's estimate. `nobody_chain_in_doubt` is for the unlocked node | 4.7, 11.2 |
| D8 | `spec/exit.md` 10.2's attention codes (`exit_needs_fee_coin`, `payments_stopped_for_exit`, `exit_step_late`, `exit_step_held_back`, `exit_fee_budget_reached`, `exit_missed`, `funding_double_spent`, `restored_commitment_choice`, `unexplained_spend`), `creation_dead`'s `params.cause` and `ended_how = void_funding` are folded in (1.0.0); 24.2 item 28 is closed | 11.2, 11.4, 16.1, 22, 24.2 item 28 |
| D9 | The factory object's example has `exit.transactions: 5` at depth 2 and `exit.blocks: 66`; the rule (d + 3; the lead E − `leave_by`) is stated | 16.1 |
| D10 | 16.2's provenance example uses 7.2's code `leaf_timeout_less_burial_exit_margin` and inputs; 7.2's example uses signet's burial of 3 | 7.2, 16.2 |
| D11 | 16.3 holds the one list of step states and kinds, which `spec/exit.md` 2 cites; `waiting` is defined | 16.3 |
| D13 and the API's saved state | Record type numbers assigned in `journal.md` 9.1, area 0x000d (Local API), for every row of 7.5; Slice 1 input W3 is closed for the type numbers (the field numbers stay with the code tables) | 7.5 |
| D15 | The locked headlines name `leave_by_locked`, the date the locked status carries | 4.7 |
| D16 | The headline code `nobody_watching` is renamed **`nobody_watching_locked`**, so the code `nobody_watching` means only the attention item (`at_risk`), raised alongside | 4.7, 22 |
| Locked-member gap (review section 4 step 6) | New headline row **`host_closed`**, first in the table: the host closed the channel with its own current commitment (S4, or H17 at `host_force_by`) while locked; `doing.params.watcher = host_closed` | 4.7, 11.2, 22, 23.2 item 42 |
| Stale references | Exit draft 2 named as written; the draft-2 change table marked superseded; pause applied at step 7 of 4.7, not step 3; `lock_after_idle_s` renamed `sign_out_after_idle_s` (idle never locks); "every call but the five of 4.7"; the calls allowed on the socket while locked listed the same way in 4.6, 4.7 and 23.2 item 21 | Header, 4.6, 4.7, 7.5, 11.3, 20.4, 23.1 item 22, 23.2 item 21 |

## Changes from draft 3

From `docs/reviews/review-local-api-d3.md` (R1 to R12, and its section 4 table), the contradictions that `docs/reviews/review-exit-d1.md` section 4 item 6 lists against this document, and the decisions shared with `spec/storage-encryption.md` draft 3 and `spec/exit.md` draft 2. "Storage" below now means storage draft 3.

| Finding | Change | Where |
|---|---|---|
| **R1** High in 1.0.0 (wording written now). The locked wallet was described as finishing an exit | **A locked wallet never leaves in time on its own**: it publishes the tree path and answers the host's old states, and the person must unlock by `unlock_by` to finish. The 4.7 table, the lock warning, the locked page, 11.2 and section 22 say so. The locked headlines are `spec/exit.md` 5.6's table, first match wins, with its `waiting_for_unlock` row and its "unlock now" row for a tree step late while locked (`tree_step_late`), extended here with rows for a short penalty file, for files behind and for nobody watching in 1.0.0; each row has a code and a tier in `watching.headline`. `doing.params.watcher` gains `publishing_tree_steps` (draft 3's `leaving_alone`) and `waiting_for_unlock`. The locked status carries `unlock_by`; the lock confirmation echoes it (`confirm_unlock_by_height`, replacing `confirm_open_by_height`); `next_action.what` no longer has `starts_leaving_alone`. In Slice 1, which has no channels, there is no `unlock_by` and nothing promises an exit | 4.5, 4.7, 4.8, 7.2, 11.2, 22 |
| **R2** Medium. Draft 3 followed storage draft 1 | Every row of the review's table: no `watch.key` (no key store means no bundle: reason `no_key_store`); the socket token in a per-user runtime folder outside the data folder (storage 12.2); no date in the clear, the watcher serves them from the opened bundle; the name **`watcher_locked`** everywhere; the watcher's log is untrusted input, and if the watcher published tree steps the commitment goes out first, before any host is contacted and whatever the pause; the lock is **held** (`held_for_payment`, 1.0.0), not refused, while an incoming payment's secret is released and unsettled. References name storage draft 3; the owner amendments of decisions 13 and 14 that this API depends on are listed as pending (24.2 item 7) | 3.2, 4.2, 4.5, 4.7, 11.2, 24.2 |
| **R3** Medium. Storage's rollback start rule had no API answer | New `wallet = files_behind` (`params.cause`: `behind`, `possibly_old`), `doing.code = files_behind` at priority 1a, a session of kind `files_behind`, and `POST /api/v1/wallet/start-as-restore` (S1, kind A, `confirm: "restore_new_keys"`), which leads into `journal.md` 8.2. Staying locked is the other choice. The watcher runs meanwhile (1.0.0). A section 22 row: never "your wallet is fine" | 4.3, 4.5, 4.7, 8.1, 11.2, 22 |
| **R4** Medium, 1.0.0 desktop. Snap browsers cannot open a redirect file under `~/.local/share` | On Linux the program reads the default browser's desktop entry; for a snap or Flatpak browser it writes the redirect file in an owner-only, non-hidden folder that confinement lets the browser read (the download folder), or goes straight to the code flow. The code is shown by a desktop notification sent over D-Bus by the program itself, **never by running `notify-send` with the code as an argument**, or by `gazpacho first-run-code`. A stale `first-run.html` is deleted at every start. T6 names snap Firefox and snap Chromium | 4.3, 23.6 T6 |
| **R5** Low-Medium. Any website could drive the start-token counter | The 256-bit start token has **no wrong-attempt counter**: a wrong token is refused and counts nothing. The interface presents a fragment only if it has the token's exact form (43 base64url characters). Only typed codes count toward the code limit | 4.2, 4.3, 5.2 |
| **R6** Low-Medium. The locked status showed dates and counts where no peer check runs | The locked status carries dates and counts only on a connection that passed the same-user check, on the local socket, or to a session; where `peer_check = unavailable` it carries the state, the reason and the headline only (`dates_hidden: true`) | 4.7 |
| **R7** Low, 1.0.0 tunnel. A same-origin page could attach to the SharedWorker | No SharedWorker while the tunnel port is set (every tab its own stream). In every case the worker serves a port only after that port presented a session token the program accepts, and ignores `token` and `sign_out` from any other port | 4.4, 10.3 |
| **R8** Low. Same-user check edges | macOS: the `libproc` approach recorded for 24.2 item 26. Windows: an elevated browser of the same account is expected to be **refused (fail closed)**, and test 45 says so; the PID race is closed by re-reading the table after opening the process and comparing its creation time with the accept. A container port or any root-owned forwarder is refused as another account; a program running as root treats every other user as another account | 3.4, 23.2 item 45 |
| **R9** Low. Setup session lifetime | Stated: it ends at idle sign-out or stop like any session; ended before `create`, the plain address says "Start Gazpacho again, or type the code it prints", and `gazpacho first-run-code` or a restart gives a new way in | 4.3 |
| **R10** Low. RFC 8785 details | "The **top-level** `passphrase` member"; UTF-16 order equals byte order for this API's ASCII names; vector E15 in `tools/spec-vectors.py` (kept in section E) | 7.4, 23.1 item 18 |
| **R11** Low (scope). Does Slice 1 build the watcher? | **No.** A locked Slice 1 wallet reports `watching.state = nobody_locked`, reason `no_bundle`, and test 41 expects that | 4.7, 23.2 items 41 to 43 |
| **R12** Low. Small points | 24.2 item 23 cross-references `spec/exit.md` 9.4 for the host's signed funding; "maximum privacy" (`watch_while_locked: false`) is refused while something is to take out unless confirmed with the date it puts at risk (`spec/exit.md` W5), in 20.2 and 4.8 | 4.8, 20.2, 24.1 D17, 24.2 |
| Section 3 notes | A stale redirect file is deleted at start; a junk token answers `bad_code`, never `token_used`, so it raises no hijack warning | 4.3 |
| `exit.md` review 4.6a | `nobody_locked` stays, for the watcher off or unable to run; `watcher_locked` is the running watcher | 11.2 |
| `exit.md` review 4.6c | `branch_partly_on_chain` is `important` in 1.0.0, with no timed steps | 11.4 |
| `exit.md` review 4.6d | The provenance code of `start_leaving_by` is `leaf_timeout_less_burial_exit_margin`, with `spec/exit.md` 4.4's inputs | 7.2 |
| `exit.md` review 4.6e, 4.6f | `lock.state = held_for_payment`; no clear date | 4.5, 4.7 |
| Shared decision: unlock order | 4.7's sequence is storage 8.2's: the derivation while the watcher runs; stop the watcher; the journal and its start rule; the node from the journal and the chain servers; the log merged as untrusted input; the commitment first if tree steps were published; then the pause, the dates that passed, the hosts. A failed unlock and a journal found behind each leave the watcher running | 4.7 |

## Changes from draft 2

Kept as draft 3 had it, as history: the rows N2 and "Storage's requirements" describe draft 3's watcher ("keeps watching and leaving alone", `locked_watcher`, a clear date) and are **superseded by draft 4's 4.7**. Every new finding (N1 to N16), the residuals the review noted against round-1 findings, every Slice 1 gap of its section 5, and its section 6 on the defaults, from `docs/reviews/review-local-api-d2.md`. Draft 2: `docs/specs-history/local-api-d2.md`. "Storage" below means `spec/storage-encryption.md` draft 1.

| Finding | Change | Where |
|---|---|---|
| N1 High. The sign-in layer rested on a specification that did not exist | `spec/storage-encryption.md` now exists (draft 1, unreviewed). This draft uses its five operations (set up, unlock, check, drop, words; storage 8.2), its passphrase rules (storage 4.1: NFC, at least 15 code points, at most 1,024 bytes, a blocklist, no composition rules), its attempts file `attempts.gza` (storage 12.3: a missing or damaged file is the strictest state), its export format (storage 11) and its watch-and-exit bundle (storage 8.7). Every "being written" is gone. `journal.md` section 2 and open point 1, `wallet-keys.md` section 8 and `THREAT-MODEL.md` 2.7 still say Slice 1 is unencrypted; storage's table "What it changes elsewhere" names each change, for those documents' writers (24.2 item 22) | 4, 4.2, 4.3, 12.2, 12.4, 12.6, 24.2 items 7, 22 |
| N2 High (1.0.0), Medium (S1). A locked wallet stopped watching; restarts lock; nobody is told | **A locked wallet keeps watching and leaving alone** from the sealed watch-and-exit bundle (storage 8.7, E-D13): it watches, answers an old state and leaves alone by its dates with transactions that are already fully signed, and pays fees only with already-signed fee children. It signs nothing new, does not answer the host, joins nothing, takes part in no round and takes no payment. The 4.7 table says exactly that. Storage 8.7 is itself being redrafted after its first review; this API's shape does not depend on which already-signed transactions the bundle can finally hold (4.7). The locked `GET /status` has a fixed shape carrying `watching` and `doing`, the number of factories watched and the next height at which the watcher acts (the one date readable before unlocking, storage 8.7.6), and nothing else: no amounts, outpoints or addresses (storage 8.6 item 3). New `watching.state` value `locked_watcher`; `nobody_locked` now means locked **and** the watcher is not running, with a reason. `lock_held` appears in `GET /session` and status as `lock`, and sessions live until the key is actually dropped. Locking while anything needs watching needs the same confirmation as going offline: a fresh sign-in, a confirm string, and an echo of the earliest date, with the warning saying what locked still does. The unlock sequence is stated (merge the watcher's log, apply the saved pause, record passed dates, then connect). A restart is no longer a silent stop while the watcher runs; what remains (a host service that must also sign after a reboot; a platform without a key store for the bundle key) is in 24.2 items 23 and 24 | 4.2, 4.5, 4.7, 7.5, 11.1, 11.2, 11.3, 20.2, 22, 23.2 items 19, 41 to 44 |
| N3 Medium-High. The start token on the browser launcher's command line | The program **opens the browser on a redirect file**: an owner-only HTML file in the owner-only data folder, holding a `<meta http-equiv="refresh">` and a link to the address with the token in its fragment, so only the file's path is on any command line (Jupyter Redirect). It listens before it launches. The token is **spent at its first presentation**, whatever follows, and the file is deleted then or when the token expires. A start link already used, or a wallet that appeared, within the token's 10 minutes is worded loudly in the page and in the terminal ("Someone may have used this program's start link …"). `GET /` accepts the redirect's `cross-site` top-level navigation only while no wallet exists. With 3.4, another user cannot even connect where the operating system can tell. Tests: a second user polling every process's command line catches nothing | 3.4, 4.3, 5.2, 23.2 item 37, 23.6 items T5, T6 |
| N4 Medium. The passphrase was the only barrier against other operating-system users | **Same-user check on every TCP connection** where the operating system can tell: Linux `NETLINK_SOCK_DIAG` (fallback `/proc/net/tcp`), Windows `GetExtendedTcpTable` then the owning process's token. A connection from another user, or one whose owner cannot be found, is checked at accept, before any byte of the request is read, and gets a fixed `403` answer, code `other_user`, then the connection is closed. Honest fallbacks: macOS and any system where the lookup is unavailable say so in status (`interface.peer_check`) and the terminal, and the passphrase is then the barrier, as in draft 2. The local socket checks `SO_PEERCRED` / `getpeereid` as a third wall. Password-manager guidance is added to 12.7; an optional sign-in phrase against a squatting page is recorded for 1.0.0 (24.2 item 25) | 3.2, 3.4, 5.3, 5.7, 12.7, 23.2 items 31, 45 |
| N5 Medium. Fresh sign-in was a 5-minute window shared by every sensitive call | Two kinds of confirmation. **Passphrase in the request** (no window, nothing left open): the words calls, opening a hosted lobby, and in 1.0.0 every spend (send, speed-up, payments, leave alone, force-path, force-close), export, replace, remove and passphrase change. The passphrase is checked under the one counter of 4.3 and never enters the request digest. **The 5-minute window** stays only for reversible trust changes (resume, loosening, chain servers, watching, lock while watched, and the like). The sign-in itself still opens the window, which now gives nothing irreversible. Echoes are stated to catch client bugs and stale previews, not a hostile script | 4.8, 7.4, 12.3, 12.6, 15.2, 16.3, 17, 18 |
| N6 Medium. The setup session against fresh sign-in | Stated: the setup session needs no fresh sign-in for `create`, `restore` and `finish-setup`, which carry the passphrase being set; after `create` or `restore` the session is an ordinary one whose window starts then. The words calls always carry the passphrase (storage 9.1: the words are sealed under a key from the passphrase), so the check right after creation asks for it once more, with the three words. A tab closed between `create` and `finish-setup` leaves a wallet in `created_not_finished`; no start token is accepted any more, and a normal passphrase sign-in leads back into setup | 4.3 "The setup session", 12.2, 12.3 |
| N7 Medium (1.0.0, tunnel). The `BroadcastChannel` hand-over gave a live token to any same-origin page | No hand-over while `interface.tunnel_port` is set: every tab signs in. Every session is **bound to the `Host` it was created under** and refused under any other. Sessions created under the tunnel port end when no request has named that port for 2 minutes (**proposed**). The hand-over and worker messages are now specified (4.4) | 3.3, 4.4, 23.6 item T2 |
| N8 Medium. Two status values reassured when they must not | `creation_abandoned` is **not sticky while `still_watched` is true**: it stays at its priority until the creation is `dead` or `live`. Section 22's stale row "A locked app still signs" replaced by the signed-out row and two locked rows. `watching.state` for `restoring` is the new `nobody_restoring` (the restored wallet does not know its factories), with an S1 attention item; `lock_held` is the `lock` field | 11.2, 11.4, 12.4, 22 |
| N9 Medium-Low. The 24-word rules promised more than a browser delivers | D9 changed as the reviewer proposed: shown **until the person presses Done**, hidden when the tab is hidden (and shown again by "Show again" while the screen is open), a **10-minute ceiling**, cleared on `pagehide`, `freeze`, Done, the ceiling, sign-out and lock. No clipboard copy: what stops a copy is `user-select: none` and no copy control; `clipboard-write=()` is kept but stated to limit only Chromium's asynchronous Clipboard API (MDN Clipboard). "What these rules do not stop" lists the copies a page cannot wipe (response bodies and parsed strings, input values, DevTools, the back/forward cache, crash dumps). `/` is now served `no-store`. Session restore of typed words is a browser test (T7) | 5.4, 12.7, 23.3 item 5, 23.6 items T7, T9 |
| N10 Low. `Clear-Site-Data` on loopback | Kept as a second wall; the interface removes the token itself and nothing depends on the header | 4.4, 23.6 item T4 |
| N11 Low. The `SharedWorker` stream | Tabs post the token to the worker, which holds it while any tab lives; sign-out tells the worker; the worker script is served with the same `Cross-Origin-Embedder-Policy` and `Cross-Origin-Resource-Policy` as the pages; a browser without `SharedWorker` uses the elected tab | 4.4, 5.4, 10.3, 23.6 item T3 |
| N12 Low. `request_id` details | A replay after a restart answers the saved status with the object's current state (the body is not saved). The digest is SHA-256 over the body in **RFC 8785** canonical form with the `request_id` kept and the `passphrase` member removed | 7.4, 7.5 |
| N13 Low. Passphrase limits | **One counter and one slot for every call that runs the key derivation**, checked **before** the derivation; one derivation at a time and at most one queued (storage 8.2); the counter lives in `attempts.gza`, and a missing or damaged file is the strictest state (storage 12.3). The ninth sign-in ends the session unused longest | 4.2, 4.3 "Attempt limits", 23.2 items 17, 46 |
| N14 Low. Cross-references and stale text | Section 15's intro says local ids; the references to 4.3, 4.5 and 4.6 that should name 4.4, 4.6 and 4.8 are corrected throughout; "Draft 2 had 'no secret in any URL'" now says draft 1; 23's first-to-run list includes items 19 and 37 | 4.3, 5.2, 5.3, 7.4, 10.1, 10.3, 14.2, 15, 15.4, 23 |
| N15 Low. `same-site` refused on `GET /` | Still refused, now with a plain page "Open Gazpacho by typing its address yourself", not a bare `403` | 5.2 |
| N16 Low (1.0.0). The export is protected by the passphrase alone | Stated next to the export: offline, only the passphrase and the export's own key derivation protect it, and a later passphrase change does not re-protect exports already made (storage 4.7, 11, 14) | 12.6 |
| F4 residual (Low, 1.0.0) | The host-node file checks are re-run whenever the file is re-read, and each file is opened without following a link and then checked through its open descriptor | 15.5 |
| F16 residual | Section 15's intro (N14) | 15 |
| Gaps 1 to 4, 6 to 8 (review section 5) | 1: storage now exists (N1). 2: the locked status shape, `lock`, the locked page's words and the unlock sequence (N2). 3: the setup session and the closed-tab path (N6). 4: the redirect file, the order, the hijack wording (N3). 6: replay after restart, RFC 8785 (N12). 7: the ninth session and the one counter (N13). 8: `creation_abandoned` while still watched, `nobody_restoring` (N8) | As in those rows |
| Gap 5. The hand-over and worker protocol | Specified (4.4) | 4.4 |
| Gap 9. Pause applied at unlock | 7.5 and 11.3 say "at unlock" | 7.5, 11.3 |
| D2 | Accepted with N7: no hand-over when the tunnel port is set; every session bound to its `Host` | 4.4, 24.1 |
| D5 | Changed: every Lightning payment carries the passphrase in its request (N5), not a 5-minute window | 4.8, 17, 24.1 |
| D9 | Changed as N9 | 12.7, 24.1 |
| D13 | Idle never locks (kept). Lock while anything needs watching needs the offline-style confirmation, and says what the watcher still does (N2) | 4.7, 24.1 |
| D14 | Kept, with the guidance of N4 | 12.7, 24.1 |
| D15 | Kept, with N13 | 4.3, 24.1 |
| D16 | Changed: the fragment stays; the delivery is the redirect file (N3) | 4.3, 24.1 |
| Storage's requirements on this API (storage 8.6, and its notes for this document) | 4.7 says a locked wallet keeps watching and leaving alone; the 4.2 table no longer drops the key at `revoke-all` (which keeps the wallet unlocked, as 4.5 and 4.9 always said); reveal and the backup check carry the passphrase in their own body; status while locked shows no amounts, outpoints or addresses; derivations answer when done, one at a time; the socket token exists only while unlocked (storage 12.2), so a locked or new program answers its few socket calls without one | 3.2, 4.2, 4.6, 4.7, 4.9, 12.3 |
| Owner decision 10, provisional for Slice 1 (owner's yes pending): seat removal and standby seats | Host seat removal before the ready check is S1 (provisional); `you.standby` and the host's standby seats are S1 (provisional), their protocol messages still to come (`messages.md` section 9 lists standby seats as having none). Invitation-only lobbies (decision 10) stay 1.0.0: `terms.md` still reserves type 38 | 2.1, 13.3, 14.1, 15.2, 15.3, 24.2 item 21 |

## Changes from draft 1

Every finding (F1 to F24) and every Slice 1 gap (G1 to G14, the numbered list of the review's section 3) of `docs/reviews/review-local-api-d1.md`. Draft 1: `docs/specs-history/local-api-d1.md`.

| Finding | Change | Where |
|---|---|---|
| F1 High. Session cookie reaches every loopback port; `GET /session` returned the check value | **No cookie at all.** The session token is returned once, in the body of the sign-in answer, kept by the interface in `sessionStorage` (per origin, so per port, and per tab), and sent as the header `X-Gazpacho-Session` on every call. `GET /session` never returns a secret. The check value and `X-Gazpacho-Check` are gone: the session header is itself a non-safelisted header, so a cross-origin request with it needs a preflight, which is refused. The event stream is read with `fetch()` and the same header, not `EventSource`. Any `Cookie` header is ignored and never logged. Kept unchanged under the passphrase sign-in of owner decision 14. Tests: a server on another loopback port receives no Gazpacho credential; a replayed request without the header gets nothing | 4.4, 4.5, 5.3, 5.7, 10.1, 10.3, 23.2 items 4, 8, 33, 34 |
| F2 High. The phrase check was an oracle | The check answers only `ok: true` or `false` for the whole set, never which position was wrong; `check-start` needs a fresh sign-in; at most 3 checks in any 24 hours per wallet, one answer each, counted in the journal so a restart does not reset them; a failed check locks the session; new random positions for every check. Test: no sequence of calls without a fresh sign-in returns any information about any word | 12.3, 7.5, 23.2 item 35 |
| F3 High. "Cancelled" reported as "nothing was signed" after partial signatures | `you.outcome` and `doing.code` are decided from the member's **own round state** (its `exposure` and `round_ended` records), never from the host's message. If any partial signature was sent in any attempt of the lobby, the outcome is `signing_unfinished`, then `abandoned`, `dead` or `started`, and the host's `cancel` appears only as `cancel_received: { reason }`. `cancelled` and `lobby_cancelled` are reachable only when no partial signature was ever sent. New section 22 row; contract test | 11.2, 14.1, 22, 23.1 item 12 |
| F4 High (1.0.0). Host-node settings could send any local file to any address | `PUT /host/node` needs a fresh sign-in and echoes the address; the files must be regular files outside the program's data folder, of the expected form and size; the node's TLS certificate is pinned from its own certificate file; the credential is sent only after that pinned handshake succeeds, and only to the saved address. `test` takes no address or path: it uses only the saved setting. No other call reads a path; calls that take an address send no credential | 15.4, 15.5 |
| F5 Medium. Fresh sign-in missing on actions that spend or expose money | One rule: **every call that moves money or changes whom the program trusts needs a fresh sign-in and an explicit echo** of the amount or target the person saw. Table of every such call, including opening a hosted lobby (`confirm_funding_sat`), starting it, chain-server and watching changes, resuming from pause and loosening conditions. A user-added chain server counts as the person's own operator, never as a second public one | 4.6, 13.2, 15.2, 20.2, 20.3 |
| F6 Medium. `request_id` not bound to the request, forgotten at restart | A `request_id` is bound to method, path and a digest of the body; reuse with any of them different answers `409 request_id_reused`. Ids of outward calls are saved in the journal with the action's first save, so a retry after a restart answers the saved result instead of acting again. Review and preview ids are single-use and saved as spent | 7.4, 7.5 |
| F7 Medium. Chain-view, watching and `doing` not fully mapped | A normative table from `connection.chain.state` to `money.chain_view`, `watching.state` and whether signing may happen; a normative priority order for `doing.code`, every at-risk value above `paused`, `held_for_signing` shown as `signing`; money in `awaiting_funding` counted apart (`forming_sat`); `still_watched` on every abandoned creation; `while_closed` split into separate fields with a stated precedence for the headline | 11.2, 11.5, 14.1, 16.1, 22 |
| F8 Medium. Private-network claim out of date | Sentence and test removed. Text now: browsers may also ask the person before a public page reaches loopback (Chrome's Local Network Access); nothing here depends on it, and it does not apply between two loopback origins. The unspecified-address route added to the `Host` test | 5.3, 23.2 items 2 and 10 |
| F9 Medium. The idle lock never fired | Only requests marked `X-Gazpacho-User: 1`, which the interface sets only from input-event handlers, refresh the idle timer. Background refreshes after events never do. Test: with events flowing and no input, the browser is signed out on time. Idle signs the browser out; it never drops the key (4.7) | 4.7, 23.2 item 19 |
| F10 Medium. Event-stream caps caused reconnect loops | One stream per browser, held in a `SharedWorker` or by one tab elected over `BroadcastChannel`; a stream over the cap is answered `429 too_many_streams` and the interface does not retry it; the fetch reader has no automatic reconnect to loop | 10.1, 10.3, 23.2 item 32 |
| F11 Medium. The API's state had no home in the journal | Section 7.5 names exactly what must be saved for this API and with which batch; Pause survives a restart; the same list is added to `journal.md` as the open point "API needs". No field numbers are invented (Slice 1 input W3) | 7.5, 11.3; `journal.md` section 13 |
| F12 Medium. Fake interface and sign-in denial by another local user | Port squatting accepted in 5.7, with the interface's defence stated: the words are asked for on two screens only (restore of a wallet that does not exist yet, and the check right after they were shown), and every words screen says so. The sign-in attempt counter counts only requests that passed the `Host`, `Origin`, content-type and fetch-metadata checks; wrong passphrases raise a delay (and five wrong first-run codes cancel only the codes that existed then); denial by a local process and the 32 connection slots are accepted and stated | 4.2, 5.7 |
| F13 Medium, owner decision. The 24 words in the browser | **Decided by the owner** (decision 12, 2026-11-12, received during this revision): the words may appear in the browser, under "typical rules for key handling for wallets". Draft 2 had first kept `DESIGN.md` section 13 as the default (words in a terminal only); that default is replaced, and `DESIGN.md` section 13 now says so. Section 12.7 states the rules concretely: loopback only; shown at creation and on reveal after a fresh sign-in; never in URLs, logs, events, caches (`no-store`) or page storage; no clipboard copy by default; cleared from the page after display; the check never says which position is wrong; attempt limits; the program wipes its copies after use; word fields without autocomplete, autocorrect or spell-check | 1, 12, 12.7, 23.3 items 5 and 6, 24.1 D1 |
| F14 Medium. C parser with no fuzzing | A parser with a published fuzzing record, coverage-guided fuzzing of request line, headers and JSON under sanitizers in CI, a limit of 64 headers | 3.1, 23.5 |
| F15 Medium. Unencrypted backup export | Export ships only with encryption at rest (`journal.md` open point 1); until then it answers `409 export_needs_encryption`. "Unencrypted in Slice 1" removed | 1, 12.6 |
| F16 Medium. Unlisted lobby identifiers in URL paths | Lobbies and factories are addressed by a **local opaque id** (`lob_…`, `fac_…`) in paths, events and attention items; the rules fingerprint travels only in bodies (`fingerprint`) | 5.5, 7.3, 10.2, 14, 15, 16 |
| F17 Low. `Referrer-Policy: no-referrer` and `Origin: null` | `Referrer-Policy: same-origin`, and the interface's requests use `fetch()` in its default mode, never a form or `mode: "same-origin"`. Test: every unsafe call from the real interface succeeds | 5.4, 23.2 item 36 |
| F18 Low. Headers only on pages and API answers | `Cross-Origin-Resource-Policy`, `X-Content-Type-Options` and a `default-src 'none'; frame-ancestors 'none'` policy on every response, error answers and static files included | 5.4 |
| F19 Low. Duplicate and planted cookies | Moot: no cookie is set or read. Stated, with a test | 4.3, 23.2 item 34 |
| F20 Low. Format characters in text from other people | Unicode format characters (category Cf, bidirectional controls and zero-width characters among them) are dropped; the interface renders every `{ text, by }` inside an isolating element and never as a link; host addresses are validated against the grammar of section 21 | 5.6, 14.1 |
| F21 Low. Bearer clients and fresh sign-in | Bearer requests are accepted on the local socket only, never on the TCP port; they are exempt from fresh sign-in (the holder of the token file is the same operating-system user); `revoke-all` rotates the token | 4.5, 4.6 |
| F22 Low. Statements stronger than the sources | "Four walls" replaced by a table of which wall applies to which kind of caller; the terminal sentence reworded; "nothing more" corrected; the port argument of 3.1 corrected | 3.1, 4.2, 5.3, 5.7 |
| F23 Low (1.0.0). Windows | Recorded as 1.0.0 items: a code without a console, `gazpacho open` waiting for a key, a named pipe as the default local socket on Windows until AF_UNIX access lists are verified, the token file's access list set at creation | 3.2, 4.1, 24.2 items 4 and 5 |
| F24 Low. Consistency | Every S1 call in table 2.1 (lock, revoke-all, the S1 parts of backup and dates, the discovery query state); `refused_by_host` outcome; stated lifetimes of sticky codes; `discovery/query` returns at once; the 10 s limit marked as this API's own; a reserved place for standby seats; the pause boundaries | 2.1, 11.2, 11.3, 14.1, 21 |
| Owner decision 11 (2026-11-12): Slice 1 ships with the interface | Every Slice 1 action is reachable through the API and the interface, restore and the backup check included; the command line is for start-up and diagnostics; the walkthrough runs through the interface | 2, 2.1, 3.1, 3.2, 12, 23.1 item 1 |
| Owner decision 13 (2026-11-12): files encrypted from the start, also on test networks | The API handles a locked wallet: the program starts locked, does nothing until the passphrase unlocks the storage key, and says so (`wallet = locked`, `watching.state = nobody_locked`, `doing.code = wallet_locked`, `423 wallet_locked`); backup export is the file as encrypted on disk. The cryptography is left to `spec/storage-encryption.md` | 4, 11.2, 12.6 |
| Owner decision 14 (2026-11-12): sign-in like a desktop wallet | Sign-in is the wallet passphrase, checked by unlocking the storage, rate-limited; first run is protected by a one-use start token in the fragment of the address the program opens itself, with a terminal code as the headless fallback; fresh sign-in is the passphrase again; locking drops the key. Section 4.1 explains why a browser interface needs more than a desktop program. Sign-in codes for every sign-in, `unlock` by code and `sign-in-codes` are gone | 4, 12.2, 12.4, 12.7, 23.2 items 17 to 21, 37 to 39 |
| Owner, 2026-11-12: ports and the tunnel | 39735 and 39736 accepted; one optional extra tunnel port, off by default, risks stated | 3.1, 3.3, 23.2 item 40 |
| Owner, 2026-11-12: one lobby each, limits editable | One joined and one hosted lobby at a time in Slice 1; the copying rule accepted | 13.2, 14.2, 15.1, 24.2 |
| G1 Where the API's state is saved | Section 7.5 | 7.5 |
| G2 How the start happens | The host's program applies the start rule by itself (`LOBBY.md`); `start` is only an early start; precedence stated | 15.2 |
| G3 Session transport after F1 | Section 4 | 4 |
| G4 The words in the browser | Owner decision 12; rules in 12.7 | 12.7, 24.1 D1 |
| G5 Slice 1 values of money and factory fields | Stated per field | 11.2, 16.1 |
| G6 Which confirmations make a factory live | `needed` = the larger of the program's floor (3 on signet, proposed) and the member's copied `min_confirmations`; the host uses the floor | 16.1 |
| G7 The host's view of the tree | `host_view.tree` added | 16.1 |
| G8 Slice 1 defaults | Idle sign-out 15 minutes; funding fee rate 100 sat/kvB (0.1 sat/vB); IPv6 on when `::1` exists | 4.7, 18, 3.1 |
| G9 Pause boundaries and `held_for_signing` | Stated per member round state | 11.3 |
| G10 `discovery/query` timing | Returns `202` at once; state at `GET /discovery/queries/{id}` | 21 |
| G11 Several programs on one machine | `--data-dir` and `--interface-port` or `--no-interface`, stated for the walkthrough | 3.1 |
| G12 Doing priority and chain mapping | 11.2 | 11.2 |
| G13 Sticky outcome codes | 24 hours or until the next join, never above a live state | 11.2 |
| G14 `request_id` storage and scope | 7.4, 7.5 | 7.4, 7.5 |

## Contents

1. Ground rules
2. Release marks and the Slice 1 subset
3. Transport
4. Authentication
5. Browser security
6. Versioning
7. Conventions: fields, units, identifiers, text from other people
8. Errors
9. Pagination
10. The event stream
11. Status and the always-present strip
12. First run, wallet keys, backup and restore
13. Conditions and terms
14. Lobbies
15. Hosting
16. Factories
17. Payments
18. On-chain wallet
19. Activity record
20. Settings by scope
21. Discovery
22. Status values the safety wording needs
23. Tests
24. Open points

---

## 1. Ground rules

These carry over from the prototype and from `DESIGN.md` section 13.

| Rule | Meaning |
|---|---|
| **The program decides; the screens show** | Fit checks, dates, whether a payment may go, which item is most urgent: all computed by the core and returned as codes and numbers. The interface holds the wording. No rule is re-implemented in JavaScript |
| **Keys and channel state never enter the browser, except the 24 words under fixed rules** | No private key, seed, nonce, channel state, signed transaction or journal record crosses this API. The one exception is the 24 words (owner decision 12, 2026-11-12; `DESIGN.md` section 13 updated): shown over loopback only, at creation and, with the passphrase typed for that request, on reveal; typed for the backup check and for a restore; never in a URL, log, event, cache or page storage; cleared from the page after use; wiped from the program's memory after use (section 12.7). The backup file is exported only once it is encrypted (12.6) |
| **Loopback only** | The program listens on the local machine only. There is no remote access in 1.0.0 (section 3) |
| **No secrets in URLs or logs** | The passphrase, tokens, codes and backup bytes travel only in request and response bodies or in a request header named for them (`X-Gazpacho-Session`, `Authorization` on the local socket). Never in a path, a query string, a cookie, a log line or an event. One exception, by owner decision 14: the first-run start token, in the fragment of the address written in the program's owner-only redirect file, which the browser is opened on, so it is on no command line; spent at first use, only while no wallet exists (4.3, 5.5) |
| **One API for every client** | The interface, the command line and the test harness use the same calls. The command line authenticates differently (section 4.6) |
| **A status is never softened** | Every state the safety wording must distinguish has its own value (section 22). The API never merges "did not sign" with "signing did not finish", or "nobody is watching" with "watching". Each enumeration's values are complete and mutually exclusive; where several could hold at once, a stated priority picks one and the others stay visible as separate fields |
| **The member's own records decide** | What the API says about the member's signatures and money is computed from the member's own saved records (`journal.md`), never from a message of the host's. A host's message can add information (`cancel_received`), never remove a warning |
| **Moving money or trust needs the person, freshly** | Every call that spends, shows the words or cannot be undone carries the passphrase in its own request; every call that changes whom the program trusts needs a fresh sign-in. Both need an echo of the amount or target the person was shown (section 4.8) |
| **Only the person's own operating-system account connects** | Where the operating system can say who owns a connection, the program refuses every other account before reading a byte (3.4) |

---

## 2. Release marks and the Slice 1 subset

Every call and every reserved field carries one mark.

| Mark | Meaning |
|---|---|
| **S1** | Slice 1's minimum. The program and the interface build these first. Slice 1 is done when one host and at least three members, each a separate process, form a factory on signet twice from a clean start, and a member whose conditions are not met is seen to refuse (`SLICES.md`). **Slice 1 ships with the interface** (owner decision 11, 2026-11-12): every Slice 1 action (creating or restoring a wallet, the backup check, conditions, finding and joining a lobby, hosting a lobby, the signing moment and refusals, the live factory) is done through these calls from the interface. The command line is for start-up and diagnostics only |
| **1.0.0** | In the first release, after Slice 1. Built with the engine that needs it (payments with Slice 2, leaving alone with Slice 3, rotation with M4) |
| **1.1.0 reserved** | Path and field names are fixed now, so the interface can keep its hidden place for them (decision 3). The program answers `501` with code `not_in_this_release` and `params.release = "1.1.0"` |
| **later reserved** | As 1.1.0, with `params.release = "later"` |

### 2.1 The Slice 1 subset in one table

| Area | Calls | Why Slice 1 needs it |
|---|---|---|
| Session and unlocking | `GET /api/v1/session`, `POST /api/v1/session/start` (first run), `POST /api/v1/session` (passphrase), `POST /api/v1/session/fresh`, `DELETE /api/v1/session`, `POST /api/v1/wallet/lock`, `POST /api/v1/session/revoke-all`, `POST /api/v1/wallet/start-as-restore` (files older than the last saved state, 4.7); for the command line only, `POST /api/v1/wallet/unlock` and `POST /api/v1/first-run-codes` | Nothing else works without an unlocked wallet and a session (owner decisions 13, 14) |
| Version | `GET /api/v1/version` | The interface checks it matches |
| Events | `GET /api/v1/events` | Signing takes seconds; the screen must follow it live |
| Status | `GET /api/v1/status`, `PUT /api/v1/pause` | The strip is on every screen. Pause must work from the first build |
| Keys | `GET /api/v1/wallet/setup`, `POST /api/v1/wallet/create`, `POST /api/v1/wallet/phrase/reveal`, `POST /api/v1/wallet/phrase/check-start`, `POST /api/v1/wallet/phrase/check`, `POST /api/v1/wallet/restore`, `GET /api/v1/wallet/restore`, `POST /api/v1/wallet/finish-setup` | A member needs keys to join; a host to sign terms and fund. Creating, checking and restoring are done in the interface (owner decision 11) |
| Backup state | `GET /api/v1/backup`, the `words` part only | The `words_not_checked` item needs `words.checked_at` |
| Conditions | `GET /api/v1/conditions`, `POST /api/v1/conditions/preview`, `PUT /api/v1/conditions` | "A member whose conditions are not met is seen to refuse" |
| Finding the host | `POST /api/v1/discovery/query`, `GET /api/v1/discovery/queries/{id}`, `GET /api/v1/settings/connections` (read only: chain servers and known hosts) | Slice 1 has no Nostr: "the member is given the host's address directly". A query by address also adds the host to the known list |
| Lobbies | `GET /api/v1/lobbies`, `GET /api/v1/lobbies/{id}`, `POST /api/v1/lobbies/{id}/join`, `PUT /api/v1/lobbies/{id}/ready`, `POST /api/v1/lobbies/{id}/leave`; `you.standby` (**provisional**, below) | Join and ready |
| Hosting | `POST /api/v1/host/preview`, `POST /api/v1/host/lobbies`, `GET /api/v1/host/lobbies`, `GET /api/v1/host/lobbies/{id}`, `POST /api/v1/host/lobbies/{id}/start`, `POST /api/v1/host/lobbies/{id}/cancel`; `DELETE /api/v1/host/lobbies/{id}/seats/{seat}` and the standby seats of the host's view (**provisional**, below) | Open and start; removing a seat before the start |
| Factories | `GET /api/v1/factories`, `GET /api/v1/factories/{id}`, `GET /api/v1/factories/{id}/dates` (S1: `factory_ends` and `funding_deadline` only) | "The screen shows the lobby, the tree and the confirmation" |
| Funding | `GET /api/v1/wallet`, `POST /api/v1/wallet/address` | The host receives signet coins and funds last; the funding's confirmations show in the factory |
| Record | `GET /api/v1/activity`, `GET /api/v1/activity/{id}` | The refusal, with its two numbers, is seen afterwards |

Everything else is 1.0.0 or reserved. A call marked "1.0.0" elsewhere in this document is not in Slice 1 even where it says what a partial answer would hold; this table is the whole Slice 1 list.

**Provisional for Slice 1** (owner decision 10, applied to Slice 1 on 2026-11-12 with the owner's yes pending): host removal of a seat before the ready check, and standby seats. Removal uses an existing seat state (`messages.md` seat state 6, "removed"), so it can be built now. Standby seats have no protocol messages yet (`messages.md` section 9), so Slice 1 builds the API shape (14.1 `you.standby`, 15.3 `standby`) and the program answers every standby value as `null` until those messages exist. If the owner says no, both move back to 1.0.0 and nothing else changes. Every **status value** of section 22 exists from Slice 1 on, even where Slice 1 cannot reach it, so the interface's tables are written once.

---

## 3. Transport

### 3.1 HTTP on loopback

- **HTTP/1.1** with JSON bodies (RFC 8259, UTF-8). No HTTP/2, no TLS: traffic on the loopback interface never leaves the machine, and a certificate for `127.0.0.1` would teach users to click through warnings.
- The program **listens on `127.0.0.1` only**, and also on `::1` when the machine has it (a second socket; on by default, Slice 1 included). Never on the unspecified (all-interfaces) address, for IPv4 or IPv6, or on any other interface address.
- **Port:** **39735** on signet and **39736** on testnet4 (accepted by the owner, 2026-11-12), so two networks can run side by side. Set with `--interface-port` or Settings, Application (section 20.4; takes effect at the next start).
- **Data folder:** `--data-dir <folder>` names the folder that holds the journal, the key file, the guard and mark files, the watcher's files and the local socket; the socket token lives outside it (4.2, storage 12.2). One program per data folder: the journal's lock refuses a second (`journal.md` section 2).
- **Several programs on one machine** (Slice 1 runs a host and three members, each a separate process, on one build server): each needs its own `--data-dir` and either its own `--interface-port` or `--no-interface`. The walkthrough (23.1 item 1), which runs through the interface (owner decision 11), starts the host on the default port and each member on a port of its own (for example 39745, 39746, 39747). Automated runs may start members with `--no-interface` and drive them over their local sockets, with the same calls.
- **Binding rules.**

| Case | What the program does |
|---|---|
| The configured address is not a loopback literal (`127.0.0.1`, `::1`) | Refuses to start, and says why. There is no flag to override this in 1.0.0 |
| The port is in use | Refuses to start the interface and says so in its terminal output, naming the port. It never picks another port by itself, so the address a person has bookmarked never silently becomes another program's. This does not stop another program from taking the port while Gazpacho is not running and pretending to be it; that is accepted, with the defence stated in 5.7 |
| `SO_REUSEADDR`/`SO_REUSEPORT` | Not set on POSIX. On Windows the socket is opened with `SO_EXCLUSIVEADDRUSE`, so no other process can bind the same port alongside it while Gazpacho holds it (it does not stop a process that bound the port first) |
| `--no-interface` | No listening socket at all. The command line still works over the local socket (3.2) |

- **Limits** (proposed): 32 open connections; at most 64 header lines; request line and headers 16 KiB; JSON body 64 KiB; backup upload 16 MiB (section 12.6); headers must arrive within 10 s and a body within 30 s; idle keep-alive connections closed after 60 s. Past a limit the connection is closed, or answered `413`/`431`. Any local process can hold the 32 connections open within these timeouts and so deny the interface; that is accepted (5.7).
- **The parser.** The request line and headers are parsed by an HTTP/1.1 parser with a published fuzzing record (for example one fuzzed continuously in OSS-Fuzz), not one written for this program; JSON likewise, or a small parser written here and fuzzed as section 23.5 requires. Requests that are later refused are still parsed, so the parser faces every local process and every web page.
- Request bodies need `Content-Length`. `Transfer-Encoding: chunked` in a request is refused with `411`; a request with both is refused with `400` (no request smuggling through a proxy that is not supposed to exist).
- `Connection: Upgrade` (WebSocket or anything else) is refused with `400`, code `no_upgrade`.

### 3.2 The local socket, for the command line

- On POSIX, the program also listens on a Unix-domain socket, `interface.sock` in its data folder, inside a folder readable by the owner only (mode 0700; the socket 0600). On Windows (1.0.0; Slice 1 runs on the Linux build server), a named pipe created with an explicit security descriptor that allows the owner only, until it is verified that an AF_UNIX socket's access list is enforced on connect as POSIX enforces mode 0600 **(open, 24.2 item 5)**.
- It speaks exactly the same HTTP/1.1 API. The `Host` header must be `localhost`. Browsers cannot reach it.
- **The peer's user is checked.** On accept, the program reads the connecting process's user (`SO_PEERCRED` on Linux, unix(7); `getpeereid` on the BSDs and macOS) and closes any connection from another user, `root` included, before reading a byte. With the folder's mode 0700 this is a second wall beside the first.
- While the wallet is **unlocked**, every request on it needs the socket token (section 4.6). The token file exists only while the wallet is unlocked (storage 12.2: made at unlock, deleted at lock and stop), so while **no wallet exists** or the wallet is **locked** the socket answers exactly these calls without a token, and refuses every other with `401`: `GET /api/v1/version`, `GET /api/v1/status`, `POST /api/v1/wallet/unlock` (which needs the passphrase), while the files are behind `POST /api/v1/wallet/start-as-restore` (which needs it too, 4.7) and, with no wallet, `POST /api/v1/first-run-codes`. Only the person's own account reaches the socket (folder mode and the peer check), and that account can already read every file the program keeps (5.7), so nothing is lost.
- It is the **only** place the socket token is accepted (4.6), and the socket token never unlocks a wallet by itself.
- The command line is for start-up and diagnostics (owner decision 11). Every Slice 1 action is reachable through the interface; the command line and the test harness use the same calls over this socket.

### 3.3 What remote viewing means in 1.0.0

There is none. A person who runs Gazpacho on a server and looks at it from another machine (as Slice 1 does on the build server, `SLICES.md`) uses an SSH tunnel that ends on the server's loopback. To the program that is a loopback connection, and every rule here applies unchanged, including the `Host` check.

**An optional extra port for a tunnel** (owner, 2026-11-12). By default the tunnel's local port must equal the program's port. A person may set **one** extra port, `--tunnel-port <n>` or Settings, Application, `interface.tunnel_port` (1.0.0; fresh sign-in), **off by default**. When set, the `Host` check (5.1) also accepts `127.0.0.1:<n>`, `localhost:<n>` and `[::1]:<n>`, and the `Origin` check accepts the matching `http://` origins. The program still listens only on its own port; the extra port only names what the far end of the tunnel is called. The risks, which the setting states next to it:
- **Another service on the viewing machine.** Whatever web page is served at `localhost:<n>` on the machine with the browser becomes the same origin as the interface while the tunnel is down. Draft 2 understated this (review N7): the program keeps running on the server, so a still-open tab's session stays valid, and a page of that origin could have asked the tab for it over the hand-over channel. So, while the tunnel port is set: **no session is ever handed between tabs** (each tab signs in, 4.4); every session is bound to the `Host` it was created under (4.2) and refused under any other; and a session created under the tunnel port **ends when, for 2 minutes, no request naming that port has arrived and no event stream naming it has been open** (**proposed**; an open tab keeps its stream open while the tunnel is up, 10.3, and a tunnel that drops closes it). Choose a port nothing else uses, and close the interface's tabs when the tunnel closes.
- **Another service on the program's machine at that port** gains nothing from the setting (its requests are still checked like any local process's), but a person who confuses the two ports may type the passphrase into the wrong page.
- **A tunnel opened to all interfaces** (an SSH `-L` without a loopback bind address and with gateway ports allowed) lets other machines reach the interface. Gazpacho cannot see this; the setting says to bind the tunnel to loopback.
- Off again by clearing the setting; it takes effect at the next start.

With an SSH tunnel, the connection reaching the program comes from the SSH server's process that forwards it. In OpenSSH this is expected to be the logged-in user's own session process, so that the same-user check of 3.4 passes for the person's own tunnel and refuses another account's. That was not checked against OpenSSH's documentation for this draft; test 23.2 item 45 confirms it on the build server before anything relies on it.

### 3.4 Who may connect: the same-user check

Draft 2 left other operating-system users on the same machine with only the passphrase between them and the 24 words (review N4). Now, **on every accepted TCP connection, before reading a byte**, the program asks the operating system which account owns the other end, and refuses every account but its own: a fixed `403` answer, code `other_user`, then the connection is closed. A loopback connection has both ends on this machine, so the other end is a socket the system can name.

| System | How | When the owner cannot be found |
|---|---|---|
| Linux (Slice 1) | `NETLINK_SOCK_DIAG` with `inet_diag_req_v2`, asking for the TCP socket whose source is the peer's address and port and whose destination is the program's; the answer's `idiag_uid` is that socket's owner (sock_diag(7)). Fallback when the netlink family is unavailable: the `uid` column of `/proc/net/tcp` or `/proc/net/tcp6` for the row with the peer's local address and port (proc_pid_net(5)) | Refused, as another user: a peer that closed before the lookup, or a socket the system does not list, is not served |
| Windows (1.0.0) | `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_CONNECTIONS` for `AF_INET` and `AF_INET6`, the row whose local endpoint is the peer's, then that process's token (`OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`, `OpenProcessToken`, the token's user) compared with the program's own (GetExtendedTcpTable; OpenProcessToken). Then the table is read again: the row must still name that process, and the process's creation time (`GetProcessTimes`) must precede the accept, which closes the race in which the process exits and its id is reused (review R8) | Refused. Opening another account's process token needs a privilege the program does not hold (OpenProcessToken), so a failure is itself the sign of another account. **An elevated browser of the same account** may also be refused by this rule; that is the expected outcome (fail closed), not a fault: the interface is used from a browser that is not elevated (review R8; test 23.2 item 45) |
| macOS, other systems | No check yet. The review of draft 3 (R8) names an approach for macOS: `proc_listpids` over the program's own user, then `proc_pidfdinfo` with `PROC_PIDFDSOCKETINFO` to find the process holding the peer's socket; `libproc` lists only processes the caller may inspect, so "not found among my own processes" can be refused. To be assessed (24.2 item 26) | Not applicable |

**Honest fallbacks.** Where no check runs (macOS, a Linux system where neither the netlink family nor `/proc/net` can be read, for example in some containers), the program says so once in its terminal and in status (`interface.peer_check`: `same_user_only`, `unavailable`), and the interface's Settings, Application shows "Other accounts on this computer can reach Gazpacho's page; your passphrase is what keeps them out". The passphrase and its attempt limits (4.3) are then the barrier, as in draft 2. Nothing else changes.

**What it does and does not do.**
- It turns 5.7's "other operating-system users" row from "the passphrase only" into a defended row, removes their denial of sign-in, and stops another user taking the first-run start token even if they read it (4.3).
- It does not separate programs of the same user: that account is the boundary (5.7).
- `root` (or an administrator) is another account to this check, and can defeat it anyway; that is accepted. So is any forwarder that runs as root or as a service account: a port published from a container (`docker-proxy`), a system `socat`, a root-owned proxy. Their connections are refused as another account's (review R8).
- A program that itself runs as `root` (a build server may) treats every other user as another account; test 23.2 item 45's `root` case cannot be run there.
- The lookup costs a system call per connection. Connections are few (one browser, 32 at most, 3.1).

---

## 4. Authentication

Sign-in works as in professional desktop wallets (owner decision 14, 2026-11-12, citing Sparrow): the person unlocks with the **wallet passphrase**, which is also what decrypts the program's files (owner decision 13: files are encrypted from the start, on test networks too). The cryptography (how the passphrase becomes the storage key, the cipher, the file formats) is `spec/storage-encryption.md`'s (draft 3, "storage" below). This section uses six of its operations (storage 8.2): **set up** (passphrase rules, then the key file and the journal), **unlock** (passphrase in; storage key in memory, or "wrong passphrase" out, or "these files are older than this wallet's last saved state"), **start as restore** (after that answer, with the passphrase again), **check** (while unlocked: is this the passphrase?), **drop** (lock), and **words** (the passphrase opens the 24 words for one reveal or one check). Each runs Argon2id, about a second at the default (storage 4.2), one at a time on a thread of its own, at most one queued. A call that runs one answers when it finishes; the interface shows "Checking…" meanwhile, and the 10 s and 30 s limits of 3.1 apply to receiving the request, not to the answer.

### 4.1 Why a browser interface needs more than a desktop wallet does

Sparrow is a desktop program: its window is drawn by the program itself, and nothing else on the machine can type into it. Gazpacho's window is a web page, and the program behind it answers HTTP on loopback. **Every other web page open in the same browser can send requests to loopback**, and every other program on the machine can too. A passphrase alone would therefore not be enough: a page on any site could post guesses, or post requests with a session it somehow obtained, and before any passphrase exists anyone who reached the port first could create or restore a wallet. So, on top of the passphrase, the program refuses requests that are not from its own page (section 5: exact `Host`, `Origin`, fetch metadata, no CORS, JSON only), keeps the session token where no other port's page can read it (4.4; review F1), rate-limits passphrase attempts, and protects the first run with a start token only the program's own browser launch carries (4.3).

### 4.2 The pieces

| Piece | What it is | Lives | Lifetime |
|---|---|---|---|
| **Wallet passphrase** | Chosen by the person at first run (12.2, 12.4), under storage 4.1's rules: normalised to NFC, at least 15 code points, at most 1,024 bytes of UTF-8, not on the blocklist, not "gazpacho" or the wallet's name, not three or more of the wallet's own words in order; no composition rules | Only in the person's head. The program receives it in a request body, uses it for one derivation, and wipes it (storage 8.4; 12.7's rules apply to it as to the words). Never stored, logged, put in a digest, or sent anywhere | Until the person changes it (1.0.0, `POST /api/v1/wallet/passphrase`, the old passphrase in the request) |
| **Storage key** (MSK, storage 4.3) | Random, wrapped under a key derived from the passphrase | The program's memory, only while the wallet is unlocked | Dropped at lock and at stop. **Kept at `revoke-all`**, which signs everyone out but leaves the wallet unlocked (4.5, 4.9; draft 2's table said otherwise) |
| **Bundle key** (KB, storage 8.7.3) | Random, independent of the passphrase | Only the operating system's key store, with storage's store record of counters beside it, and the program's memory, locked or not. There is no file fallback: with no key store there is no bundle, and a locked wallet watches nothing (reason `no_key_store`, 4.7) | For the wallet's life. It opens only the watch-and-exit bundle, the penalty file, the watcher's log and the attempts file's tag (4.7). 1.0.0: Slice 1 builds no watcher |
| **Start token** | 32 random bytes, base64url (43 characters), made only while **no wallet exists** | The program's memory, and the fragment of the address in the redirect file the program opens in the browser (4.3) | **Spent at its first presentation**, whatever follows; 10 minutes. A new one, and a new redirect file, at every first-run launch. **No wrong-attempt counter** (review R5): a wrong token is refused and counts nothing |
| **First-run code** | 10 characters from a 32-letter alphabet, `ABCDE-FGHJK` (50 bits). The fallback when the program cannot open a browser (headless, a server reached through a tunnel) | The program's memory; printed to the terminal | One use, 10 minutes, at most 3 unused; only while no wallet exists |
| **Socket token** | 32 random bytes, file `socket.token` in a per-user runtime folder **outside** the data folder (storage 12.2: `$XDG_RUNTIME_DIR`, the macOS per-user temporary folder, the Windows user temporary folder; a subfolder named by a hash of the data folder's path; folder owner-only, file POSIX 0600 or an owner-only access list set at creation) | For the command line and the test harness on the local socket only (4.6) | **Made at unlock, deleted at lock and at stop** (storage 12.2); rotated by `revoke-all`. None exists while the wallet is locked or absent (3.2) |
| **Session token** | 32 random bytes, base64url, sent as the header `X-Gazpacho-Session` | The program's memory, with the `Host` value it was created under; the interface keeps it in `sessionStorage` and memory, never in a cookie, `localStorage`, markup or a URL (4.4) | Until sign-out, idle sign-out, the key actually being dropped at lock, or program stop. Valid only under its own `Host` (`401 not_signed_in` under another). Three kinds: `setup` (4.3), `files_behind` (4.7) and `normal`. **At most 8**: a ninth sign-in ends the session unused for longest, because tabs closed without signing out leave sessions until their idle sign-out, and refusing would lock the person out; ending one needs the passphrase, so it is no denial by anyone else |

Nothing about sessions is saved to disk. A restart locks the wallet and signs everyone out; the watcher (4.7) runs while it is locked.

### 4.3 Getting in

**Normal sign-in (a wallet exists).**
1. The program starts with the wallet **locked**: it holds no storage key, so it cannot read its journal and does nothing for the person yet (4.7). It prints the plain address, with nothing secret in it.
2. The interface shows one field: the wallet passphrase. The person types it; the interface sends `POST /api/v1/session` with `{ "passphrase": "…" }`.
3. The program unlocks the storage with it. On success it starts the core from the journal, starts a session and answers with the session token **in the body**. On failure: `401 wrong_passphrase`.
4. If the wallet is already unlocked (another tab, or a signed-out browser while the program kept running), the passphrase is checked against the unlocked storage in the same way and a new session is started; the key is not unlocked twice.

**First run (no wallet, no passphrase yet).** Nothing protects the port except who gets there first, so the program makes sure that is the person. Draft 2 opened the browser at the address with the token in it; on Linux that address then sat on the command line of the launcher and the browser, which every local user can read by default (proc(5): `hidepid` mode 0 "is the traditional behavior, and the default"; review N3). Now:
1. At every start the program first deletes any `first-run.html`, and any `gazpacho-first-run-*` folder of its own (below), left by an earlier run (a crash between writing and deleting it would otherwise leave a spent token on disk). It starts listening (3.1), then makes the start token and writes the **redirect file** `first-run.html` in its data folder (folder 0700, file 0600; on Windows an owner-only access list set at creation). The file holds no script, only `<meta http-equiv="refresh" content="0;url=http://127.0.0.1:<port>/#start=<start token>">` and the same address as a link, for a browser that ignores the refresh.
2. It opens the default browser **on the file's path**. Only the path, which reveals nothing, is on any command line; the token is inside a file only the person's account can read. Jupyter Server launches its browser the same way by default (`ServerApp.use_redirect_file`, Jupyter redirect).
   - **Confined browsers** (review R4). On Linux the data folder is under `~/.local/share`, and snap-packaged browsers, Ubuntu's default Firefox among them, cannot read files under hidden folders of the home directory (Launchpad bug 1959417, cited by the review); Jupyter's users met exactly this. So on Linux the program reads the default browser's desktop entry (`xdg-settings get default-web-browser`, then the entry's location): an entry from snapd's or Flatpak's exported applications means a confined browser. For one, the redirect file goes instead into a new owner-only folder `gazpacho-first-run-<random>` in the person's download folder (`xdg-user-dir DOWNLOAD`), which is not hidden and which snap's `home` interface and the usual Flatpak browser permission are expected to allow (test 23.6 item T6 confirms it per package), and that folder is deleted with the file. Where the folder cannot be made, or the browser's package is not recognised as one that can read it, the program opens the browser on the plain address and uses the code flow (below).
   - **The code, without a command line.** When the code flow is used and standard output is not a terminal (a program started from a desktop menu), the program shows the code in a desktop notification that it sends itself over the session D-Bus (`org.freedesktop.Notifications`). It **never runs `notify-send` or any other program with the code as an argument**, which would put the code in `/proc/*/cmdline` again. Without a notification service the code is printed only to a terminal, or given by `gazpacho first-run-code` over the local socket.
3. The token is in the **fragment**. A browser never sends the fragment in the HTTP request (it is not part of the request target), so it never reaches the program's request line, any proxy or any access log. The interface reads it at load, at once replaces the address with the plain one (`history.replaceState`), and sends the token in the body of `POST /api/v1/session/start` with `{ "start_token": "…" }`.
4. **The token is spent at its first presentation**, whether or not that session then creates a wallet, and the program deletes the redirect file at once. It also deletes the file when the token expires (10 minutes) and at stop. A second presentation answers `409 token_used` with `params.used_at`.
5. The program answers a **setup session** (below).
6. A page opened any other way while no wallet exists, including another browser, another user's page, or a bookmark, sees "Open Gazpacho from the program, or type the code it printed" and can do nothing.

**A hijacked first run is said loudly.** If, within 10 minutes of the program opening the browser, the interface presents a start token and gets `token_used`, or gets `wallet_exists` while it holds no session, it shows, in place of every other screen:

> Someone may have used this program's start link before you. If you did not just set up Gazpacho in another tab or window, do not use this wallet and do not send coins to it. Stop Gazpacho and delete its data folder, then start again.

and the program prints to its terminal when the token was used, and whether that request came from this account (3.4). Where the same-user check runs, another account cannot connect at all, so this guards against a program of the person's own account, or a system without the check.

**Fallback for headless use.** When the program cannot open a browser (no display, a server viewed through a tunnel, a service), it prints a first-run code to its terminal if standard output is a terminal, and `gazpacho first-run-code` prints a new one over the local socket. The person types it in the page; `POST /api/v1/session/start` with `{ "code": "ABCDE-FGHJK" }` gives the same setup session. No redirect file is written in this case.

**Why a token in a URL is allowed here, and only here.** Draft 1 had "no secret in any URL" (5.5). The owner's design needs one: only the start token, only in the fragment, spent at first use, 10 minutes, valid only while no wallet exists, and removed from the address bar at load. What remains is that the browser may have recorded the address with its fragment in history (or synced history) before the interface replaced it, and that an extension with access to tabs or history sees it; by then the token is spent, and once a wallet exists no start token is accepted at all. A test (23.3 item 3) checks that no other URL ever carries a secret.

**The setup session** (review N6). `POST /api/v1/session/start` answers a session of kind `setup`.
- It can call only: `GET /api/v1/wallet/setup`, `POST /api/v1/wallet/create`, `POST /api/v1/wallet/restore`, `GET /api/v1/wallet/restore`, `POST /api/v1/wallet/finish-setup`, the words calls of 12.3, `GET /api/v1/status`, `GET /api/v1/events`, `GET` and `DELETE /api/v1/session`. Anything else: `403 not_setup_call`.
- It needs **no fresh sign-in** for `create`, `restore` and `finish-setup`: no passphrase exists before them, and `create` and `restore` carry the passphrase being set.
- When `create` or `restore` succeeds, the session becomes `kind: normal`, and its fresh-sign-in window (4.8) starts at that moment, as if the passphrase had just been typed, because it just was.
- The **words calls are never covered by any window**: they carry the passphrase in their own body (12.3; storage 9.1, the words are sealed under a key from the passphrase). So the backup check right after creation asks for the passphrase once more, with the three words.
- **Its lifetime** (review R9) is any session's: it ends at idle sign-out (15 minutes without input, 4.7), at sign-out and at stop. If it ends **before** `create` or `restore`, the start token is already spent, so the plain address says "Start Gazpacho again, or type the code it prints": a restart makes a new token and redirect file, and `gazpacho first-run-code` gives a code over the local socket. After `create` it is an ordinary session, below.
- **A tab closed between `create` and `finish-setup`**: the wallet exists and is unlocked, `setup.state = created_not_finished` (7.5), and no start token or code is accepted any more. The plain address shows the passphrase field; a normal sign-in (`POST /api/v1/session`) leads the interface back into setup at `finish-setup`, and the words are shown again only by `reveal`. The same after a restart in between, with the unlock first.

**Attempt limits** (review N13). One rule for every call that runs the key derivation, so that no call is a cheaper oracle than another and no flood exhausts memory:
- **Which calls.** `POST /api/v1/session`, `POST /api/v1/session/fresh`, `POST /api/v1/wallet/unlock`, the words calls (12.3), every call that carries the passphrase in its request (4.8), and `create`, `restore` and the passphrase change (which set one).
- **Order.** `Host` (5.1), `Origin` and fetch metadata (5.2), content type (5.3) and the session or setup checks run first; a request refused by any of them touches no counter, so a page on any other origin, another loopback port included, cannot. Then, **before any derivation is started**: the attempts file's delay, then the slot. **One derivation runs at a time and at most one waits** (storage 8.2): a request that finds both taken answers `429 rate_limited`, `params.retry_after_s = 1`, without counting as wrong. So 32 connections sending passphrases at once start one derivation, not 32.
- **One counter for all of them**, kept in `attempts.gza` outside the encrypted store (storage 12.3: a count of wrong passphrases in a row, the last wrong time, and the time until which attempts are refused). One attempt per second; after 5 wrong in a row the delay doubles with each further wrong attempt, up to 15 minutes (**proposed**, D15). A right passphrase resets it. `create` and `restore` take the slot but cannot be wrong.
- **A missing or damaged attempts file is the strictest state** (storage 12.3): attempts are refused for 15 minutes from the moment it was found missing. Deleting it therefore never resets the limit; only the person's own account can delete it anyway (5.7).
- **Start token**: no counter at all (review R5). A cross-site navigation to `GET /` is allowed while no wallet exists (5.2), so any web page could make the interface present junk five times; with a counter that would cancel the codes. The token cannot be guessed (256 bits), so a wrong one is refused with `bad_code` and changes nothing, and only the real token's first presentation spends it. The interface presents a fragment only if it has the token's exact form (43 base64url characters), and otherwise ignores it.
- **First-run codes**, which arrive only as typed input: one attempt per second; 5 wrong in a row cancel every code that existed then. They run no derivation and have their own counter.
- Wrong attempts are logged as a count only. When they arrive faster than a person types, the program prints to its terminal that wrong passphrases are arriving from another program.
- A local process of the person's own account can still slow sign-in by sending wrong passphrases, because the delay is per program; where the same-user check does not run (3.4), so can another account's. Accepted (5.7).
- The passphrase's strength against offline guessing of a stolen file is storage's (its key derivation and the rules of storage 4.1), not this API's.

### 4.4 The session token, and why there is no cookie

**The program never sets a cookie, and ignores every `Cookie` header.** A browser sends cookies for `127.0.0.1` to every port of the host ("cookies do not provide isolation by port", RFC 6265 8.5), and `SameSite` does not separate ports either, because a site ignores the port (HTML origin; RFC 6265bis). A cookie would reach every other web server the person opens on loopback, which could replay it (review F1).

- The interface keeps the session token in **`sessionStorage`**, which belongs to the window's origin, port included (HTML storage; HTML origin), so a page on another port cannot read it. It is per tab, survives a reload and is cleared when the tab closes (MDN storage). Not in `localStorage`, a cookie, markup or a URL.
- A new tab asks over a `BroadcastChannel` whether an open tab holds a session; only same-origin pages receive the message (HTML messaging). If none answers within 500 ms, it shows the passphrase field. **No hand-over at all while the tunnel port is set** (3.3; review N7): a page of the same origin may then be another service's, so every tab signs in. The interface learns this from `GET /api/v1/session` (`handover: false`).
- Every API call except `GET /api/v1/session`, `GET /api/v1/version`, `POST /api/v1/session` and `POST /api/v1/session/start` carries `X-Gazpacho-Session`. (`GET /api/v1/status` also answers without one while the wallet is locked, with the locked shape of 4.7 only.) A non-safelisted header forces a cross-origin preflight (Fetch), which is refused (5.3).
- A session is valid only under the `Host` value it was created under (4.2), so a token taken from the `127.0.0.1` origin is refused under `localhost` or under the tunnel port.
- Script inside the interface's own origin can read the token; the defence is the content-security policy and the no-HTML-sinks rule (5.4).
- Sign-out and lock: the interface removes the token from storage, memory and its shared worker, and tells the other tabs (below). The answer also carries `Clear-Site-Data: "cache", "storage"`, as a **second wall only**: the specification it comes from acts only on responses it calls "a priori authenticated", and whether each browser honours it on `http://127.0.0.1` is a test (23.6 item T4). Nothing depends on it (review N10).
- Another server on loopback that the person visits receives no Gazpacho credential, and a replayed request without the header reaches only the four calls above and static files (tests 23.2 items 33, 34).

**The hand-over and worker messages** (review section 5, gap 5). Interface-internal, fixed here so that the tabs and the worker are built to one protocol. The channel is named `gazpacho-session-<port>`; every message is an object with a `type`.

| Message | From, to | Fields | Meaning |
|---|---|---|---|
| `ask` | New tab, channel | `nonce` (16 random bytes, hex) | "Does any tab hold a session?" Never sent while `handover` is `false` |
| `offer` | A tab with a session, channel | `nonce` (the asker's), `session` | Sent only in answer to an `ask` received within the last second, and only while that tab's session is `normal` (never a setup session). The asker takes the first `offer` whose nonce is its own and checks it with `GET /api/v1/session` before showing anything |
| `signed_out` | Any tab, channel | | The session ended (sign-out, idle, lock, a `session` event, any `401`). Every tab drops its copy and shows the passphrase field |
| `leader`, `leader_gone` | The tab holding the stream, channel | `tab` (random id) | Only where there is no `SharedWorker` (10.3): which tab holds the event stream; another tab takes over on `leader_gone` or after 30 s without a relayed event or keep-alive |
| `event` | The stream holder, channel or worker port | `topic`, `id`, `seq` | One relayed event (10.2), never content |
| `token` | Tab, worker port | `session` | A worker has no `sessionStorage`; each tab posts its token as the first message on its port. The worker checks it with `GET /api/v1/session` (`signed_in: true`) before it serves that port, and keeps the newest **checked** token in memory while any checked port is connected |
| `sign_out` | Tab, worker port | | From a checked port only: the worker drops the token and closes the stream |
| `stream_state` | Worker, every port | `state`: `open`, `reconnecting`, `stopped`, `too_many` | So every tab can show "following the app" or not (10.3) |

The worker's script is served with the same `Cross-Origin-Embedder-Policy` and `Cross-Origin-Resource-Policy` headers as the pages (5.4), so a page under `require-corp` can create it in whichever way each browser requires (review N11; test 23.6 item T3). A browser without `SharedWorker` uses the elected tab.

**The worker trusts no port by default** (review R7). Any page of the same origin can attach to the running worker with `new SharedWorker(<its URL>)`, because a worker instance is matched by origin, script URL and name, and with the tunnel port set and the tunnel down such a page may be another service's. So the worker relays `event` and `stream_state` only to ports that presented a token it checked, and ignores every message, `token` and `sign_out` included, from a port that has not. A port that presents a token the program refuses is dropped. And **while the tunnel port is set no SharedWorker is used at all**: each tab holds its own stream for its own session (10.3), as it already signs in on its own (no hand-over).

### 4.5 Session calls

All **S1**.

| Call | Request | Answer | Errors |
|---|---|---|---|
| `GET /api/v1/session` | | `{ "wallet": "none"\|"locked"\|"files_behind"\|"unlocked", "signed_in": false, "handover": true\|false, "first_run_launched_at": null\|… }`, or with a valid session `{ "wallet": "unlocked"\|"files_behind", "signed_in": true, "kind": "setup"\|"files_behind"\|"normal", "session_no": 3, "fresh_until_at", "idle_sign_out_at", "started_at", "handover", "lock": null\|{ "state": "held_for_signing"\|"held_for_payment", "lobby_id", "since_at" } }`. `handover` is `false` while the tunnel port is set (4.4). `first_run_launched_at` is when the program opened the browser at first run, so the interface can word a hijack (4.3). Never returns a secret | |
| `POST /api/v1/session/start` | `{ "start_token": "…" }` or `{ "code": "ABCDE-FGHJK" }` | `200`, `{ "session": "<token>", "kind": "setup" }` | `wallet_exists` (no start token is accepted once a wallet exists), `token_used` (`params.used_at`), `bad_code`, `code_expired`, `too_many_attempts`, `rate_limited` |
| `POST /api/v1/session` | `{ "passphrase": "…" }` | `200`, `{ "session": "<token>", … the fields of GET }`. Unlocks the wallet if it was locked (the unlock order of 4.7); otherwise runs storage's **check**. When the unlock finds the files older than the wallet's last saved state (storage 6.3 step 4), the answer is still `200`, with a session of **kind `files_behind`**, `wallet: "files_behind"` and `params.cause`: `behind` or `possibly_old` (4.7). The wallet stays locked (the keys are dropped again, and the watcher runs, 1.0.0) | `wrong_passphrase`, `rate_limited` (`params.retry_after_s`), `no_wallet`, `passphrase_not_checked` (the derivation failed, for example out of memory; not counted as wrong, storage 8.4), `node_stopped` (`journal_corrupt` or `storage_failed` found at unlock; the wallet stays locked, 4.7) |
| `POST /api/v1/session/fresh` | `{ "passphrase": "…" }` | `{ "fresh_until_at": … }` | `wrong_passphrase`, `rate_limited` |
| `DELETE /api/v1/session` | | `204`, `Clear-Site-Data`. Signs this browser out; the wallet stays unlocked and keeps working | |
| `POST /api/v1/wallet/lock` | `{ "confirm": "lock_wallet" }`, and while anything needs watching also `"confirm_locked"`: `"watcher_only"` while a watcher will run, or `"nobody_watching"` when none will (the watcher off, no key store, and every Slice 1 build); and, **only when `watching.unlock_by` is not `null`** (something to take out, 1.0.0), `"confirm_unlock_by_height"`: the `watching.unlock_by.due_height` the warning showed (4.7). Slice 1 never sends it. Fresh sign-in while anything needs watching | `202`, `{ "wallet": "locked" }`, or `{ "lock": { "state": "held_for_signing", "lobby_id" } }` while partial signatures are out, or (1.0.0) `{ "lock": { "state": "held_for_payment" } }` while an incoming payment's secret is released and the payment is not settled (4.7). Sessions end when the key is actually dropped, not before | `fresh_sign_in_needed`, `confirm_mismatch`, `hosting_lobby_open` (`params.lobby_id`: cancel it first, 4.7) |
| `POST /api/v1/session/revoke-all` | `{ "confirm": "revoke_all" }` | `204`. Every session ends, every code and start token is cancelled, the socket token is rotated. **The wallet stays unlocked and the storage key is kept.** Fresh sign-in | `fresh_sign_in_needed` |
| `POST /api/v1/wallet/start-as-restore` (S1) | `{ "confirm": "restore_new_keys", "passphrase": "…" }` (4.8, kind A), from a `files_behind` session or on the local socket | `202`, `{ "wallet": "restoring" }`. Storage's **start as restore** (storage 6.3 step 4, 8.2): the program starts on these files with a restore marker and a new epoch (`journal.md` 8.2), keeps the guard's epochs and any `.newer` watcher files, and goes on with the unlock order of 4.7 from step 4. The session becomes `normal`. Factories from the files are `restoring_unconfirmed` until their hosts or the chain show current data (12.6), and lost seats are listed (`restored_seats_lost`) | `wrong_passphrase`, `rate_limited`, `confirm_mismatch`, `not_files_behind` (the wallet is not in that state) |

### 4.6 The command line and the test harness

- A client that is not a browser sends `Authorization: Bearer <socket token>` **on the local socket only**; on the TCP port it is refused (`400 bearer_not_on_tcp`). With `Origin`: `403 forbidden_origin`. With a session header too: `400 two_credentials`.
- While the wallet is locked there is no socket token (4.2, storage 12.2): the socket answers `GET /api/v1/status`, `GET /api/v1/version` and `POST /api/v1/wallet/unlock` with `{ "passphrase" }` without one (3.2), under the limits of 4.3, and, while the wallet is `files_behind`, `POST /api/v1/wallet/start-as-restore` with the passphrase. So nothing on the socket unlocks a wallet without the passphrase. `POST /api/v1/wallet/unlock` answers `200 { "wallet": "unlocked" }`, or `409 files_behind` with `params.cause` when storage found the files older than the wallet's last saved state (4.7). The test harness unlocks headless members this way, with the passphrase from its own fixture files; the command line reads it from the terminal with echo off or from a file descriptor, never from an argument (storage 8.4).
- Bearer requests need no fresh sign-in (the token holder is the same operating-system user, 5.7). They still need every echo field of 4.8, and every call that carries the passphrase in its request (4.8, kind A) needs it on the socket too: for the words that is the cryptography (storage 9.1), and for spends it keeps one rule for every client.
- `POST /api/v1/first-run-codes` makes a first-run code while no wallet exists, over the local socket only and without a token (none exists yet, 3.2); `wallet_exists` otherwise; from a browser session, refused.
- The command line is for start-up and diagnostics (owner decision 11).

### 4.7 Lock, idle and what keeps running

Draft 2 had a locked wallet "stop acting": no watching, no answering an old state, no leaving alone, until someone typed the passphrase, and every restart (a crash, an update, a power cut) locked it (review N2). Storage removes most of that hazard in 1.0.0 (storage 8.7, E-D13): the unlocked program keeps a small sealed **watch-and-exit bundle** and an append-only **penalty file**, under a bundle key that the locked program can use without the passphrase, and a locked program runs a **watcher** over them. The watcher **cannot finish an exit** (storage 8.7.1; `spec/exit.md` 5.6): under the taproot channel format the member never holds a final signature on its own commitment, and no bundle ever holds one, so the last step of leaving a factory needs the passphrase. Draft 3 said the opposite in several places (review R1).

**Slice 1 builds no watcher** (review R11; storage 8.7). A locked Slice 1 wallet watches nothing: `watching.state = nobody_locked`, reason `no_bundle`, and the lock is confirmed like going offline, with `confirm_locked` alone (Slice 1 has no `unlock_by`). **Slice 1 has no operating-system key store requirement**: it makes no bundle key KB and no store record, so it runs the same on a headless server without a Secret Service or systemd credential; its attempts file uses the plain-checksum mode of storage 12.3, and the keyed mode starts once a bundle exists (1.0.0). Everything below about the watcher is 1.0.0; every status value exists from Slice 1 on (2.1).

So signing out, locking and stopping are three different things:

| | **Signing out** (idle, or the person) | **Locked** (after every start, or "Lock the wallet"), 1.0.0 with the watcher | **Stopped** (the program is not running) |
|---|---|---|---|
| Keys in memory | All (storage key, seed) | **Only the bundle key's subkeys** (storage 8.1). Not the passphrase, not the storage key, not the seed | None |
| Watches its factories and the funding of unresolved creations | Yes (the node) | **Yes** (the watcher, from the bundle's outpoints) | No |
| Answers an old state of the host's | Yes | **Yes**, with the fully signed penalties in the penalty file, never a new signature; the penalties a short file lacks are missing (storage 8.7.4 rule 7) | No |
| Leaves a factory alone by its dates | Yes, to the end | **Starts, but cannot finish**: publishes the **tree path only**, by `leave_by_locked`; the last step, the commitment, needs the passphrase **by `unlock_by`**; after block H_leaf the host can take that balance | No |
| Pays fees | Yes | Only the pre-signed fee children of the tree steps, at their fixed rates, and only if fee coins were set aside (storage 8.7.2 item B7) | No |
| Signs anything new: a round, a channel update, a new fee level, a move, the commitment | Yes, for lobbies already joined | **No** | No |
| Talks to the host or any Lightning peer; joins, readies, hosts, answers `hello` | Yes | **No** | No |
| Takes or makes payments | Yes (1.0.0) | **No** | No |
| Reads or writes the journal | Yes | No: what the watcher sees and does goes to its own sealed log, which the next unlock treats as untrusted (below) | No |
| The API | Everything, to a signed-in session | Over TCP: `GET /api/v1/status` (the locked shape below), `GET /api/v1/version`, `GET /api/v1/session`, `POST /api/v1/session` (which unlocks), and from a `files_behind` session its calls (below). On the local socket, without a token: `GET /api/v1/status`, `GET /api/v1/version`, `POST /api/v1/wallet/unlock`, and while `files_behind` `POST /api/v1/wallet/start-as-restore` (4.6). Every other call `423 wallet_locked` | Nothing |
| The browser | Needs the passphrase again | Needs the passphrase again, which unlocks | — |

What goes into the bundle and the penalty file is storage 8.7.2's list (items B1 to B9) and `spec/exit.md` 5.6's records. Not in either, and so stopped while locked: **moving to the next factory** (it needs new signatures), the **commitment** step of leaving, claiming payments, and the host's own duties (answering members, running a ready check, rebroadcasting a funding it signed, cancelling a lobby at its deadline). Whether a host's signed funding belongs in the bundle is `spec/exit.md` 9.4's (24.2 item 23).

**Idle sign-out** (Slice 1: 15 minutes without input, **default, owner to confirm**; 1.0.0 Settings: never, 15 minutes, 1 hour). Only requests with `X-Gazpacho-User: 1`, set only from handlers of the person's input events, refresh the timer; event-driven refreshes never do (review F9). Idle **signs the browser out; it never locks the wallet** (D13, accepted by the review): a locked wallet takes no part in rounds, moves or payments, and cannot finish an exit, and a timer must not cause that unseen.

**Locking the wallet** is a deliberate button in Settings, never in the strip. Its effects on lobbies are those of pause (11.3) first: it leaves every lobby where it has sent nothing in a round. The lock is then **held**, not refused, while either of these lasts, and sessions stay valid until the key is actually dropped, so the person still sees why:
- partial signatures are out in an unresolved round: `lock.state = held_for_signing` in `GET /session` and in status, until the round ends;
- (1.0.0) an incoming payment's secret has been released and the host has not yet removed the payment by an irrevocable update: `lock.state = held_for_payment`, after new payments are stopped and incoming payments not yet fulfilled are failed back (`spec/exit.md` 5.6; storage 8.1). Outgoing payments do not hold it.

A lock while this program hosts an **Open** lobby answers `409 hosting_lobby_open`: a locked host cannot answer its members or cancel at the deadline, so the person cancels the lobby first (**proposed**).

**Locking while anything needs watching** (`watching.state` other than `nothing_to_watch`) is treated like going offline (4.8, 20.2; review N2): it needs a fresh sign-in and `confirm_locked`. **Only when something is to take out**, that is when `watching.unlock_by` is not `null`, it also needs `confirm_unlock_by_height`, echoing `watching.unlock_by` (a date, 7.2, kind `unlock_by`) as the warning showed it (cross-spec review D4, D5). `unlock_by` is `spec/exit.md` 5.6's: the last height at which an unlock still lets the node finish leaving with every margin, the minimum over the factories that have something to take out and over incoming payments whose secret is released. Where nothing is to take out (every Slice 1 wallet, whose members are owed nothing) it is `null`, and the lock takes `confirm_locked` alone. The warning says exactly what locked still does (review R1):

> While locked, Gazpacho keeps watching your factories. If a factory's date comes, it publishes the first steps of leaving without you, but the last step needs your passphrase: unlock before block [unlock_by] (about [date]). After block [H_leaf] the host can take that balance. While locked it will not move you to the next factory, answer your host, take part in signing, or send or receive payments.

When the tip is already within `WARN_LEAD` of a factory's `leave_by` (`spec/exit.md` 5.6), the warning starts with the stronger sentence: "Leaving a factory alone starts while Gazpacho is locked, at block [leave_by_locked]. Its last step needs your passphrase before block [unlock_by]." With nothing to take out, the sentences naming [unlock_by] and [H_leaf] are left out.

When no watcher will run (Slice 1, the watcher off, no key store), the confirm string is `nobody_watching` and the warning is the one for going offline: "While locked, nobody watches your factories and nothing leaves in time. Unlock before block [unlock_by] (about [date])." With no `unlock_by` (every Slice 1 wallet), the second sentence is "Nothing of yours is inside them to take out; Gazpacho checks what happened when you unlock."

**The locked status.** `GET /api/v1/status` while locked answers this shape and nothing else. Any local process of the person's account can ask, so it holds no amounts, outpoints, addresses, host keys or lobby ids (storage 8.6 item 3). Nothing in it is read from a clear field on disk: no date is stored in the clear (storage 8.7.6); the watcher reads `leave_by_locked`, `unlock_by` and the next action from the opened bundle and serves them here.

```json
{
  "wallet": "locked",
  "network": { "id": "signet", "test_coins": true },
  "lock": { "since": "start", "since_at": 1794434000 },
  "watching": {
    "state": "watcher_locked",
    "reason": null,
    "headline": { "code": "unlock_before", "tier": "important" },
    "dates_hidden": false,
    "factories_watched": 2,
    "leave_by_locked": { "height": 333100, "at_estimate": 1796335200 },
    "unlock_by": { "height": 333130, "at_estimate": 1796353200 },
    "next_action": { "height": 333100, "at_estimate": 1796335200, "what": "publishes_tree_steps" },
    "health": "up_to_date",
    "last_check_height": 330437
  },
  "doing": { "code": "wallet_locked", "params": { "watcher": "watching" } },
  "connection": { "chain": { "state": "agree", "height": 330437 } },
  "interface": { "peer_check": "same_user_only" }
}
```

- `lock.since`: `start` (locked since the program started, a restart included) or `lock` (the person locked it).
- **Who sees the dates** (review R6). `factories_watched`, `leave_by_locked`, `unlock_by`, `next_action` and `last_check_height` are given only to a connection that passed the same-user check (3.4), to the local socket (whose peer is checked, 3.2), or to a session (a `files_behind` session, below). Where `interface.peer_check` is `unavailable` (macOS today), any local account could ask, so a connection without a session gets `dates_hidden: true` and none of those fields: only `wallet`, `network`, `lock`, `watching.state`, `watching.reason`, `watching.headline`, `doing` and `interface`. The page then says "Unlock to see the dates". The chain tip in `connection.chain` is public and stays.
- `watching.state` (11.2): `watcher_locked` whenever the watcher runs, also with the chain view in doubt, when its `reason` is `chain_in_doubt` (the watcher still acts on `spec/exit.md` 4.5's estimate, which advances with the clock; cross-spec review D6); `nobody_locked` when it does not run; `nothing_to_watch` when the bundle holds no factory and no unresolved creation.
- `watching.reason`: with `nobody_locked`, why nobody watches: `no_bundle` (no bundle was written: **every Slice 1 build**, whatever the key store, R11), `no_key_store` (this computer has no operating-system key store Gazpacho can use, so no bundle exists; storage 8.7.3), `watcher_off` (the person's choice, 1.0.0), `bundle_key_unavailable` (the key store exists but did not give the bundle key, for example before the person has logged in), `bundle_refused` (the bundle is older than one already seen, or damaged; storage 8.7.4 rule 7). With `watcher_locked`, what limits it, the first that applies: `penalty_file_short` (the penalty file is shorter than the count the key store holds, damaged, or of another `file_id`, so some answers to old states are missing; it is still used for what it holds, and the watcher keeps going; storage 8.7.4 rule 7), `bundle_kept_as_newer` (the last unlock found the journal behind and kept the newer bundle, which the watcher now runs from; storage 8.7.4 rule 4), `chain_in_doubt` (the chain view is in doubt; above), or `null`. A penalty file is never a reason for `nobody_locked`; only a refused **bundle** is.
- `next_action`: the next height at which the watcher acts, and what it does then: `publishes_tree_steps`, `funding_deadline_passes`, `unfinished_deadline_passes`, `unlock_by_passes`. Never "leaves": the watcher does not finish an exit.
- `doing.params.watcher`: `watching`; `publishing_tree_steps` (it has broadcast a tree step of a factory, draft 3's `leaving_alone`); `waiting_for_unlock` (every tree step is out and only the commitment is left, which needs the passphrase); `host_closed` (the host's own current commitment of the channel is confirmed, `spec/exit.md` class S4: the balance waits in the member's output, with no deadline, for the unlock); `answering_old_state` (it has broadcast a penalty); `paying_fee` (it has broadcast a fee child); `off`. Once anything has been broadcast it stays shown until the unlock has checked the watcher's log.
- **`watching.headline`**, a code and a tier, is what the locked page and the program's terminal say, from these fields only. It is `spec/exit.md` 5.6's table, first match wins, with the rows this API adds marked:

| Code | Case | Headline (interface wording) | Tier |
|---|---|---|---|
| `host_closed` (added; cross-spec review, section 4 step 6) | Every channel with something to take out was closed by the host's own current commitment (`spec/exit.md` class S4: H-a, L-b, or H17 at `host_force_by`), so its balance waits in the member's output with no deadline | "The host closed this channel. Your balance waits for you; unlock to collect it." With an incoming payment whose secret was released and which is not settled, it adds: "Unlock before block [unlock_by], or a payment you received may be lost." | `important`; `at_risk` with such a payment |
| `deadline_passed_while_locked` | H_leaf passed while locked, with something to take out | "Unlock. A factory's deadline passed while Gazpacho was locked; it will check what happened." | `at_risk` |
| `past_unlock_by` | The tip is past `unlock_by` | "Unlock at once. It may already be too late to leave a factory in time." | `at_risk` |
| `tree_step_late` | A tree step is past its `step_due` (no fee coin, a fee spike, or another party's child on its anchor; `spec/exit.md` review F6) | "Unlock now. Leaving a factory is behind and needs a higher fee, which Gazpacho can only pay once unlocked. Unlock before block [unlock_by] at the latest." (`unlock_by` from the steps still missing) | `at_risk` |
| `second_stage_after_breach` | A host second-stage payment transaction appeared after a breach | "Unlock before block [unlock_by]. The host published an old state and moved payments out of it; answering that needs your passphrase." | `at_risk` |
| `payment_secret_released` | An incoming payment's secret was released and the payment is not settled | "Unlock before block [unlock_by], or a payment you received may be lost." | `at_risk` |
| `waiting_for_unlock` | Tree steps done, waiting for the unlock (`doing.params.watcher = waiting_for_unlock`) | "Unlock now. Only the last step of leaving a factory is left, and it needs your passphrase. After block [H_leaf] the host can take this balance." | `at_risk` |
| `publishing_tree_steps` | The watcher is publishing tree steps, on time | "Locked and leaving a factory alone. The tree steps go out without you; the last step needs your passphrase. Unlock before block [unlock_by]." | `at_risk` |
| `penalty_file_short` (added; storage R2-1) | `watching.reason = penalty_file_short` | "Unlock now. Some of Gazpacho's answers to your host's old states are missing from this computer." | `at_risk` |
| `old_state_answered` | A revoked host state appeared and the penalty went out | "Locked. The host published an old state and Gazpacho answered it. Unlock to see." | `at_risk` until seen |
| `files_behind` (added; review R3) | `wallet = files_behind` (below) | "These files are older than this wallet's last saved state. Unlock to choose: start them as a restore, with new keys, or stay locked so you can put the newer files back." | `at_risk` |
| `nobody_watching_at_risk` | `nobody_locked` and the program knows something is to take out (the person chose "maximum privacy", `spec/exit.md` W5) | "Locked. Nothing is watched. Unlock before block [leave_by_locked], or a factory balance is at risk." | `at_risk` |
| `nobody_watching_locked` (added; draft 4 called it `nobody_watching`, which is also an attention code, cross-spec review D16) | `nobody_locked` in 1.0.0 and the program cannot tell what is to take out (no key store, the bundle key unavailable, the bundle refused) | "Gazpacho is locked, and nobody watches your factories while it is locked. Unlock to watch them." | `important` |
| `unlock_before` | Something to take out; the tip is before `leave_by_locked` | "Locked. Gazpacho is still watching. Unlock before block [leave_by_locked]; by block [unlock_by] at the very latest, if Gazpacho keeps running: leaving a factory alone needs your passphrase for its last step." | `important` |
| `nothing_needs_you` | Nothing to take out anywhere, which includes **every Slice 1 wallet** (members are owed nothing, `spec/exit.md` 5.1) | "Locked. Gazpacho is still watching. Nothing needs you now." With `nobody_locked` (every Slice 1 build): "Locked. Nothing needs you now. Nothing is watched while Gazpacho is locked." With `nothing_to_watch`: "Locked. Nothing needs watching." | — |

  `[leave_by_locked]` is the locked status's `leave_by_locked` (equal to `leave_by` while `spec/exit.md`'s M_locked is 0, as on signet; cross-spec review D15). Where `dates_hidden` is true, or no bundle is open, the bracketed heights are left out of the wording, never guessed. While `host_closed` holds for one factory and a later row for another, the later row's case is judged without the closed channel, whose balance has no deadline. In Slice 1, which has no channels, the reachable rows are `files_behind` and `nothing_needs_you`, the latter with `watching.state = nobody_locked`, reason `no_bundle`, which the page also shows; no Slice 1 string promises an exit or says anything is watched.

**Files older than the wallet's last saved state** (review R3; storage 6.3 step 4). When an unlock finds the journal **behind** its mark file, guard, bundle or penalty file, or **possibly old** (a guard or mark file missing or damaged while a key file exists), storage does not start the node. The answer to `POST /api/v1/session` is a session of kind `files_behind`; `wallet = files_behind`, with `params.cause` `behind` or `possibly_old`; the keys are dropped again and, in 1.0.0, the watcher runs (from the newer bundle where one was kept); status has the locked shape with `wallet: "files_behind"` and `files_behind: { "cause" }`, and `doing.code = files_behind` (11.2). A `files_behind` session may call only `GET /api/v1/status`, `GET /api/v1/events`, `GET` and `DELETE /api/v1/session`, and `POST /api/v1/wallet/start-as-restore`; anything else answers `403 not_files_behind_call`. The person chooses:
- **Start as a restore** (`POST /api/v1/wallet/start-as-restore`, kind A, `confirm: "restore_new_keys"`): `journal.md` 8.2's restore on these files, with a new epoch, so no key used after them can come back; the factories they hold come back `restoring_unconfirmed` (12.6).
- **Stay locked**: sign out, or close the page. Nothing on disk changes, so the person can put the newer files back (from their own copy) and unlock again.

The interface never says the wallet is fine while `files_behind` holds (section 22). A key file with **no journal** is not this case: storage always starts it as a restore by itself (storage 6.3 step 0), and status then shows `restoring`.

**Unlocking** (`POST /api/v1/session` or, on the socket, `POST /api/v1/wallet/unlock`) follows storage 8.2's order (`spec/exit.md` W1 and W3; review R2):
1. **The derivation and the key file**, while the watcher keeps running. A wrong passphrase (`401`), a derivation that fails (`passphrase_not_checked`) or a damaged key file changes nothing: the watcher never stopped.
2. **The watcher stops** and writes its last log entry. From here the node and the watcher never run at once.
3. **The journal and storage's start rule** (storage 6.3). Files behind or possibly old: the answer above. A corrupt journal or a storage failure: `503 node_stopped` (`journal_corrupt`, `storage_failed`), status `wallet = node_stopped` in the locked shape. In either case the keys are dropped and the watcher runs again (1.0.0) before the answer.
4. **The node starts** from the journal, connected to nothing; then the **chain servers connect**.
5. **The watcher's log is merged** in one batch as **untrusted input** (storage 8.7.4 rule 6): a claim that something was broadcast or spent becomes a record, and an activity entry, only once the chain view confirms it; nothing in the log changes held, exposed, round or channel state by itself.
6. **If the chain shows the member's own leaf kickoff or leaf transaction confirmed**, with the channel output unspent and something to take out (`spec/exit.md` W3; the decision is taken from the chain, never from the log alone), that batch records the exit and freezes the channel, and the node completes, saves and broadcasts the **commitment first**, as soon as the leaf transaction is confirmed, before any host is contacted and **whatever the saved pause says** (pause never stops or delays an exit, `spec/exit.md` 5.4, 11.3).
7. **The saved pause** (7.5) is applied, before anything connects to a host (11.3).
8. **Dates that passed while locked** are recorded by height: a hosted lobby's deadline, a funding deadline, an unfinished deadline, sticky-code lifetimes (computed from their activity entries, 11.2). Each takes its effect as the rules say once the chain view is trusted, as at any start; a hosted lobby whose deadline passed is cancelled (`cancel` reason 1 or 2) when its members can next be reached.
9. **The hosts connect**, and a `reset` event is sent.

A failure after step 4 is the node's ordinary stop (`node_stopped`, 8.1): the node is rebuilt from the journal; while it cannot be, the keys are dropped and the watcher runs again, as at a lock.

**Stopping the program** stops the watcher too: nothing watches until it runs again. Every "keep the app open" sentence stays true in that sense; "open" now includes "running, even locked", and a locked program still needs the person by `unlock_by`.

- **Pause** can be set while signed out only by signing in; a locked wallet already signs and joins nothing.

### 4.8 Fresh sign-in and the echo

Draft 2 had one kind: a 5-minute window, opened by any passphrase entry including the sign-in, shared by every sensitive call. A person who signed in and stepped away left the words one click away (review N5). Now there are two kinds.

**Kind A, the passphrase in the request.** The call itself carries `"passphrase": "…"`. The program checks it (storage's **check**, or **words** for the words) under the one counter and slot of 4.3, then acts; nothing is left open afterwards. A wrong passphrase answers `401 wrong_passphrase`, counts as wrong, does nothing, and leaves the session as it was. Kind A is for every call that **spends**, **shows or reads the words**, or **cannot be undone**.

**Kind B, a fresh sign-in.** The passphrase typed in the last 5 minutes (`POST /api/v1/session/fresh`, the sign-in itself, or `create`/`restore`, 4.3). Without one the call answers `403 fresh_sign_in_needed` and the interface asks for the passphrase. Kind B is for **reversible changes of whom or what the program trusts or listens to**: each can be put back, and none spends or shows a secret. Kind A calls never use the window.

**Both kinds need an echo**: a request field repeating the amount, address, value or target the person was shown. A mismatch answers `409 confirm_mismatch` with both values in `params` and does nothing. An echo catches a client bug or a stale preview; it does not stop a hostile script in the page, which can read the preview and fill the echo (review N5). Against that the defences are the content-security policy and the no-HTML-sinks rule (5.4), and, for kind A, that the script would need the passphrase.

| Call | Release | Kind | Echo | Why |
|---|---|---|---|---|
| `POST /api/v1/host/lobbies` (open a hosted lobby) | S1 | A | `confirm_funding_sat`: the preview's `funding_at_target_sat`; and `draft_digest` | Sets aside the funding and is the consent to spend it when the start rule is met, the largest spend the program makes |
| `POST /api/v1/wallet/phrase/reveal`, `POST /api/v1/wallet/phrase/check` | S1 | A | `confirm: "show_words"` (reveal); `check_id` (check) | They open the words, which are sealed under a key from the passphrase (storage 9.1) |
| `POST /api/v1/wallet/create`, `POST /api/v1/wallet/restore` | S1 | Setup session (4.3) | `confirm: "create_wallet"`; the passphrase twice | They set the passphrase |
| `POST /api/v1/host/lobbies/{id}/start` | S1 | B | `confirm_funding_max_sat`: the lobby's `set_aside_sat` | An early start of a spend already consented to at opening; the automatic start needs nothing (15.2) |
| `PUT /api/v1/pause` with `{ "on": false }` (resume) | S1 | B | `confirm: "resume"` | Turns joining and signing back on. Pausing needs neither |
| `PUT /api/v1/conditions` when it loosens any value | S1 | B | `confirm_loosens`: the list of loosened fields the preview returned (13.2) | Widens what the app signs without asking |
| `POST /api/v1/session/revoke-all` | S1 | B | `confirm: "revoke_all"` | Signs everyone out |
| `POST /api/v1/wallet/lock` while anything needs watching | S1 | B | `confirm_locked`; and `confirm_unlock_by_height` only when `watching.unlock_by` is not `null` (1.0.0; never in Slice 1; 4.7) | Like going offline: the program then signs, moves and answers the host no more, and cannot finish an exit |
| `POST /api/v1/wallet/start-as-restore` | S1 | A | `confirm: "restore_new_keys"` | Starts files older than the wallet's last saved state as a restore, under a new epoch; cannot be undone (4.7) |
| `DELETE /api/v1/host/lobbies/{id}/seats/{seat}` | S1 (provisional) | B | `confirm_seat`: the seat id | Removes a member before the start (15.2) |
| `POST /api/v1/wallet/passphrase` (change it) | 1.0.0 | A (the old passphrase) | The new passphrase twice | It is the key to every file |
| `POST /api/v1/wallet/send` | 1.0.0 | A | `confirm_amount_sat`, `confirm_address`, and the `review_id` | Spends coins |
| `POST /api/v1/wallet/transactions/{txid}/speed-up` | 1.0.0 | A | `confirm_fee_sat`, `review_id` | Spends coins |
| `POST /api/v1/payments` | 1.0.0 | A, **every payment** (D5) | `confirm_amount_sat`, `confirm_total_max_sat`, `review_id` | Spends channel balance |
| `POST /api/v1/factories/{id}/leave-alone` | 1.0.0 | A | `preview_id`, `confirm: "leave_alone"`, `confirm_amount_sat_estimate` | Cannot be undone |
| `POST /api/v1/host/factories/{id}/force-path`, `…/force-close` | 1.0.0 | A | `preview_id`, `confirm_cost_sat` | Spends on chain |
| `POST /api/v1/backup/export` | 1.0.0 | A | `confirm: "export_backup"` | The file holds the words' entropy and opens with the passphrase (12.6; storage 11) |
| `POST /api/v1/wallet/replace`, `/remove` | 1.0.0 | A | `confirm` strings | They replace or remove keys |
| `POST /api/v1/factories/{id}/move` with `decision: "move"` | 1.0.0 | B | `seen_current_digest` | Moves the balance into a new factory under new terms, the same consent as joining |
| `POST /api/v1/backup/import`, `/ask-host`; `PUT /api/v1/backup/host-copy` with `on: true` | 1.0.0 | B | `confirm` strings | They replace the record of every factory, or send it to a host (which can open it only with the words, storage 11) |
| `PATCH /api/v1/settings/wallet` `network`; `PATCH /api/v1/settings/application` `interface` and `tunnel_port` | 1.0.0 | B | The new value, twice (`network` and `confirm_network`) | They change what the program is |
| `POST`/`DELETE /api/v1/settings/connections/servers`, `PATCH` `chain.mode`, `POST`/`DELETE /api/v1/settings/connections/hosts` | 1.0.0 | B | `confirm_address` or the server's id | They change the chain view or the hosts the app talks to (threat model 2.4) |
| `POST /api/v1/settings/watching/offline`; `PATCH` `who_watches`; the watcher's "maximum privacy" switch (`watch_while_locked: false`) | 1.0.0 | B | `confirm: "nobody_watching"` when watching stops; for `watch_while_locked: false` while any factory has something to take out, also `confirm_leave_by_height`, the earliest `leave_by` it puts at risk (`spec/exit.md` W5; review R12) | Watching off hides an old-state publication |
| `PUT /api/v1/host/node`, `POST /api/v1/host/node/test`, `DELETE /api/v1/host/node` | 1.0.0 | B | `confirm_address` | Sends a node credential (15.5) |
| `PATCH /api/v1/host/setup` raising `max_per_factory_sat` or `max_total_sat`, or changing the host key | 1.0.0 | B | The new values | Raises what hosting may spend |
| Automatic joining: `finish-setup` with `find` other than `browse`, and any change to a standing instruction or its budget | 1.0.0 | B | `confirm_budget` | A standing instruction joins, and so signs, without asking |

**The passphrase in a request is never kept.** It is removed before the request digest is computed (7.4), wiped after its one derivation (storage 8.4), and a replay of a kind A request by its `request_id` returns the saved answer without running the derivation, because a replay does nothing new and its answer shows only what a `GET` would (7.4).

**Not in the table, on purpose.** `join` and `ready` (S1) need no fresh sign-in: they spend none of the member's coins in 1.0.0, and their echo is `seen_current_digest`, the exact terms the person reviewed (14.2). Whether a stolen session's ability to join is acceptable is **default, owner to confirm** (24.1 D4). Pausing, tightening conditions, leaving a lobby, cancelling one's own hosted lobby and signing out also need none: each only reduces what the program does.

### 4.9 Rotation and revocation

| Event | Storage key | Socket token | Sessions | Codes and start tokens |
|---|---|---|---|---|
| Program start | Not in memory (locked; the watcher runs in 1.0.0, 4.7) | None until unlock (storage 12.2) | None survive | None survive; a start token and its redirect file only if no wallet exists |
| Unlock | In memory | New; file written | The unlocking session starts | Unchanged |
| Unlock that finds the files behind (4.7) | Dropped again | None | A `files_behind` session starts | Unchanged |
| `start-as-restore` | In memory | New; file written | The `files_behind` session becomes normal | Unchanged |
| `revoke-all` | **Kept** | New; file rewritten | All end; streams closed | All cancelled |
| Lock | Dropped when the key is actually dropped (after a held round or payment, 4.7) | Deleted | All end at that moment | Unchanged |
| Idle or sign-out | Kept | Unchanged | That one ends | Unchanged |
| A ninth sign-in | Kept | Unchanged | The session unused longest ends (4.2) | Unchanged |
| A failed words check (12.3) | Kept | Unchanged | That session ends | Unchanged |
| A start token presented | — | — | — | That token spent; its redirect file deleted. A wrong token: nothing changes (4.3) |
| Wallet created or restored | Unlocked | New; file written | The setup session becomes normal | Every start token and first-run code cancelled for good |

There is no call that returns the socket token or the passphrase.

---

## 5. Browser security

The threat: a web page from anywhere, open in the same browser as the interface, tries to read from or act on this API; or another web server on loopback, which the person visits, tries to obtain a credential; or a hostile name, description or note written by a host or member tries to run as script inside the interface.

### 5.1 Host check, against DNS rebinding

Every request's `Host` header must be exactly one of:

| Socket | Allowed `Host` |
|---|---|
| TCP | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` |
| Local socket | `localhost` |

Anything else, a missing `Host`, or two `Host` headers: `421 Misdirected Request`, code `bad_host`, with no other content. This is checked before anything else, including static files. A page on `rebind.attacker.example` whose name has been pointed at `127.0.0.1` sends `Host: rebind.attacker.example:39735` and is refused. A page that addresses the IPv4 unspecified (all-zeros) address, which some systems route to loopback listeners, sends that literal as its `Host` and is refused the same way (test 23.2 item 2).

### 5.2 Origin and fetch metadata

- **Every request that is not `GET` or `HEAD` must carry `Origin`**, and it must equal `http://` followed by the request's `Host` value. `Origin: null`, another port, `https`, or a missing `Origin` on a session request: `403`, code `forbidden_origin`. Bearer requests (4.6) must carry no `Origin`.
- **`GET` and `HEAD`** with an `Origin` header follow the same rule.
- **`Sec-Fetch-Site`**, when present: API calls need `same-origin`; static files and `GET /` also accept `none` (the person typed the address). `same-site` is refused: other ports on `127.0.0.1` are "same site" to a browser (HTML origin; Fetch Metadata). `cross-site` is refused, with one exception below.
- **A refused page is a plain page, not a bare `403`** (review N15). `GET /` refused by fetch metadata answers `403` with a small static page, under the headers of 5.4, saying: "Open Gazpacho by typing its address yourself: http://127.0.0.1:<port>/". Refusing a link from another local page stays right: it stops a local page from opening the interface with a fragment of its choosing.
- **The first-run exception.** The redirect file of 4.3 is a `file:` page, whose origin is opaque, so the navigation it starts is expected to arrive with `Sec-Fetch-Site: cross-site` (Fetch Metadata, navigation). **While no wallet exists**, and only then, `GET /` also accepts `cross-site` when the request is a top-level navigation (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`). The page it loads holds no data; a start token in its fragment works only if it is this program's unspent token, and a wrong one counts nothing (4.3, review R5), so a web page that navigates there with junk gains nothing and cancels nothing; framing is refused (5.4). Once a wallet exists the exception ends. Test 23.6 item T5 records what each browser actually sends.
- **`Sec-Fetch-Dest`** on `GET /api/v1/…`, when present, must be `empty` (a `fetch()` call). An `<img>`, `<script>` or `<iframe>` pointing at an API path is refused with `403`.
- These headers are absent in some browsers (older Safari among them). Nothing depends on them alone: `Cross-Origin-Resource-Policy` on every response (5.4) and the session header (5.3) hold without them.
- **The interface's requests use `fetch()` in its default mode** (`cors`), never an HTML form and never `mode: "same-origin"`. With `Referrer-Policy: same-origin` (5.4) the browser then always sends the interface's real origin (Fetch, "append a request `Origin` header"; review F17).

### 5.3 No CORS, and the CSRF defence

- **No CORS at all.** No response ever carries an `Access-Control-Allow-*` header, including `Access-Control-Allow-Private-Network`. `OPTIONS` is answered `405`, code `no_cors`. So a cross-origin request that needs a preflight never reaches a handler.
- **The session header.** Every API call except the four that need no session (4.4) carries `X-Gazpacho-Session`. A header outside the CORS-safelisted list (`Accept`, `Accept-Language`, `Content-Language`, `Content-Type` with three values, `Range`; Fetch) forces a preflight across origins, so a page on another origin, another loopback port included, cannot send it; and it cannot learn the value, which lives in storage of this origin only (4.4). Missing or unknown: `401`, `not_signed_in`.
- **JSON only.** A request with a body must have `Content-Type: application/json` (an optional `charset=utf-8` is allowed), except the backup import, which must be `application/octet-stream`. Both force a preflight across origins. `text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data` (the types an HTML form can send without a preflight) are refused with `415`, code `bad_content_type`, before the body is read.
- **`GET` changes nothing**, anywhere in this API. Showing the 24 words is a `POST` for this reason too.
- **Local Network Access.** Browsers may also ask the person before a public page reaches loopback (Chrome's Local Network Access permission, `loopback-network`; Chrome LNA). Nothing here depends on it: a person can grant it, it does not apply between two loopback origins, and other browsers have different rules. The older Private Network Access preflights "were never enforced as a blocking requirement" (Chrome LNA) and are not used.

**Which wall applies to which caller.** Draft 1 said "four walls, each test removes one". That was stronger than the sources (review F22): several walls do not apply to some callers. The real table:

| Caller | `Host` check | `Origin` / fetch metadata | Content type | Session header | What stops it |
|---|---|---|---|---|---|
| A page on a public site, `GET` | Applies | `Sec-Fetch-Site: cross-site` refused; CORP blocks no-cors reads | Not applicable | Cannot send it without a refused preflight | Same-origin policy, CORP, the header |
| A page on a public site, unsafe method | Applies | Refused | Refused unless JSON, and JSON needs a refused preflight | As above | Each of the three |
| A page on another loopback port (same site) | Passes (its requests name this port) | `same-site` and its own origin refused | As above | As above; it cannot read the value (4.4) | `Origin`, fetch metadata, the header |
| A rebinding page | Refused | | | | `Host` |
| A process of another operating-system account | Not reached | | | | The same-user check (3.4), before any byte is read, where the system can tell; otherwise as the next row, with the passphrase as its barrier |
| A local process of the person's own account, not a browser | Passes (it writes any `Host`) | Passes (it writes any `Origin`, or none) | Passes | Needs the secret, which it cannot obtain from a browser any more | The session secret only. Not defended (5.7) |

### 5.4 Headers

**On every response**, static files, API answers and error answers (`404`, `405`, `421`, `403`, …) alike:

```
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
```

and, on every response that is not one of the interface's pages:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

CORP on static files also stops a cross-origin `<img>` or `<script>` from reading or fingerprinting them in browsers that send no fetch metadata (Fetch, "Cross-Origin-Resource-Policy").

**On the interface's pages** (`/`, `/index.html`), in addition:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self';
  form-action 'none'; frame-ancestors 'none'; base-uri 'none';
  require-trusted-types-for 'script'; trusted-types 'none'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
X-Frame-Options: DENY
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), payment=(), clipboard-write=()
Cache-Control: no-store
```

- `Cache-Control: no-store` on the pages (draft 2 had `no-cache`; review N9), so that a page that showed the words is not kept for back and forward navigation in browsers that refuse such pages. Chrome may now keep a `no-store` page, but evicts it when a `fetch` from it returned `no-store`, which every API answer here does (Chrome bfcache no-store). The interface clears the words on `pagehide` regardless (12.7); neither is relied on alone.
- The shared worker's script (10.3) is served with the pages' `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, `Cache-Control` and content-security policy (review N11).

- `Referrer-Policy: same-origin` (draft 1 had `no-referrer`): no referrer leaves the origin, and same-origin requests keep their real `Origin` header (5.2).
- **No inline script and no inline style**, as the prototype already requires (`web/README.md`). No `unsafe-inline`, no `unsafe-eval`, no `data:` or `blob:` sources. QR codes are drawn as SVG elements built through the DOM. `worker-src 'self'` allows the interface's own shared worker (10.3).
- **Trusted Types with no policy** makes `innerHTML` and similar sinks throw in browsers that support it. The prototype already inserts all text as text (`gz.util.h`). The interface must not depend on it.
- `camera=()` until QR scanning arrives (later reserved). `clipboard-write=()` limits only Chromium's asynchronous Clipboard API: Firefox and Safari do not act on the `Permissions-Policy` header and have no `clipboard-write` permission (MDN Clipboard), and no browser lets it govern the person's own selection and copy. What keeps the words off the clipboard is that the interface has no copy control for anything secret and marks the words `user-select: none` (12.7). Copying an address or an invoice, when those screens arrive, is a change to this spec. Turning either on is a change to this spec.
- Every API response also: `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`.
- **Static files** are compiled into the program. No file is read from disk at request time, so there is no path to traverse. Unknown paths answer `404`. A test build may serve from a folder (`--interface-dir`), refused in release builds.

### 5.5 No secrets in URLs or logs

| Rule | How it is enforced |
|---|---|
| Paths hold local identifiers only: local lobby and factory ids, payment and activity ids. None of them grants anything, and none is a rules fingerprint (7.3) | Review rule; a test checks that no path the interface requests holds 64 hex characters |
| A query string holds paging cursors, filters and sort orders only. A fragment holds nothing, except the first-run start token in the one address the program writes into its redirect file (4.3) | A query parameter named `token`, `code`, `phrase`, `words`, `seed`, `key`, `password`, `invoice`, `session` or `backup` is refused with `400`, code `secret_in_url`, and its value is not logged |
| The access log records time, method, the path **pattern** (`/api/v1/lobbies/{id}`), status, duration and session number | No headers, no bodies, no query values. A test searches every log written during a Slice 1 run for every secret the run made (23.3) |
| Error messages never quote the request | `message` is fixed text per code |
| The event stream carries topics and local identifiers only | Section 10 |
| Invitations hold an unlisted lobby's rules fingerprint, which is a capability (`messages.md` 6.1) | Fingerprints travel in bodies only (`fingerprint` fields), never in this API's URLs or events (review F16) |

### 5.6 Text written by other people

Hosts write lobby names, aliases, descriptions and notes; members may write display names. The API returns each such string as an object, never as a bare string:

```json
{ "text": "Tomato Garden, daily factory", "by": "host", "checked": false }
```

- `by` is `host`, `member`, `sender` (an invoice's note) or `you`. `checked` is always `false` for text: the program checks signatures, not meaning. The interface quotes it as text written by that party, never in the app's voice (critique, section 3).
- The program limits these strings to their protocol sizes, drops control characters other than newline, and drops every Unicode **format character** (general category Cf: the bidirectional embeddings, overrides and isolates, the directional marks, zero-width characters and the like), so a host alias cannot reorder the text or the numbers around it. Emoji joined by a zero-width joiner then show as separate pictures; that is accepted.
- The interface renders every `{ text, by }` inside an isolating element (`<bdi>`, or `unicode-bidi: isolate`), as text, and **never turns it into a link**.
- Host addresses (`host.address`) are not free text: the program validates them against the grammar of section 21 (a DNS name, an IPv4 or bracketed IPv6 literal, or an onion name, then `:` and a port) and drops a lobby or listing whose address does not match.

### 5.7 What this does not defend

| Not defended | Why |
|---|---|
| Another program running as the same user | It can read the token file, the key file and the journal directly. Operating-system accounts are the boundary |
| A browser extension with access to all sites | It runs inside the page. Users should not run such extensions with a wallet open |
| A page or a local process learning that Gazpacho is running | Refusals take time, and a `421` with no content, the answer of `GET /api/v1/version` and static files identify the program. Accepted: they show that Gazpacho runs, and which version, but no data of the person's |
| Another local web application the person visits, on another port | Same site to the browser, so `SameSite` would not stop it. It receives no Gazpacho credential (4.4), cannot read answers (CORP, same-origin policy) and cannot send the session header (5.3). It can see that the port answers, and, like any local process, deny sign-in (below) |
| **A program squatting the port** while Gazpacho is not running, serving a copy of the interface | Any user can bind a port above 1023 while it is free. The defences: the program says in its terminal when its port is taken (3.1); the words are typed into the interface only on two screens, the restore screen of a wallet that does not exist yet and the backup check right after the words were shown (12.7), and the interface says so on every screen that shows them ("Gazpacho asks for your words only when you restore, or right after showing them to you") |
| **Denial of sign-in and of connections by a local process** | Any local process of the person's own account, and of another account where the same-user check does not run (3.4), can send wrong passphrases continuously (raising the delay, 4.3) or wrong first-run codes, keep the per-second attempt slot busy, or hold the 32 connections open within their timeouts (3.1). Where the check runs, another account's connections are closed at accept, though they still take a connection slot for that moment. Accepted; the program says in its terminal that wrong passphrases arrive, and sign-in works again once the flood stops and the delay has passed |
| **A squatter's page asking for the passphrase** | A program squatting the port while Gazpacho is stopped is the same origin, so a browser's password manager fills the passphrase there as usual (review N4). The words defence (above) does not cover the passphrase. Against another account on a system with the same-user check, the squatter learns a passphrase it cannot use over the network, since its own account cannot connect to the real program; it could still try it against a copy of the files, which needs read access to the data folder. Against a program of the person's own account, nothing helps (first row). An optional sign-in phrase shown above the passphrase field is recorded for 1.0.0 (24.2 item 25) |
| A shoulder-surfer reading the passphrase or a first-run code | The passphrase field is a password field; a code is one use and 10 minutes |
| An offline attack on a stolen, encrypted data folder | The passphrase's strength and the key derivation of `spec/storage-encryption.md` |
| A shoulder-surfer or screen recorder reading the 24 words while shown | The interface shows them only on request, with the passphrase typed for that request, with a warning to check that nobody watches and nothing records (12.7) |

**Other operating-system users on the same machine.** Where the same-user check runs (3.4; Linux in Slice 1, Windows in 1.0.0), their connections are refused before a byte is read: they get nothing, cannot deny sign-in, and cannot use a start token even if they saw one (test 23.2 items 31, 45). Where it does not run (macOS, and systems where the lookup is unavailable, which status reports), they get the passphrase page and nothing else without the passphrase, and cannot create or restore a wallet without the first-run token or code (test 23.2 item 37); the token reaches them on no command line (4.3).

---

## 6. Versioning

- Every call is under `/api/v1`. The `1` changes only for a change that breaks existing clients; then both versions are served for one release.
- `GET /api/v1/version` (**S1**; no session needed, no other data):

```json
{ "api": "1.0", "program": "0.1.0", "network": "signet", "run_id": "7c1e9a04" }
```

- `api` is `major.minor`. A minor step adds calls, fields, enumeration values or event topics. It never removes or renames them and never changes a field's meaning or unit.
- **Unknown values.** The interface is compiled into the same program, so in normal use the two always match. A client that meets an unknown enumeration value shows it as "unknown state" with a link to Activity, never as success, and never as one of the reassuring values (`fits`, `live`, `this_app`, `done`).
- **Unknown fields** in an answer are ignored by clients. **Unknown fields in a request** are refused (`400`, `unknown_field`, with `field`), so a client bug shows at once instead of being silently dropped.
- `run_id` changes at every program start. The interface reloads itself when it sees a new `run_id` with a different `program` version (an upgrade under it).

---

## 7. Conventions

### 7.1 Fields and units

From the prototype, extended.

| Suffix | Meaning |
|---|---|
| `_sat` | Whole satoshis |
| `_msat` | Millisatoshis. A value that can exceed 2^53 − 1 is sent as a **decimal string**; all other integers are JSON numbers |
| `_ppm` | Parts per million (the proportional Lightning fee: BOLT 7's `fee_proportional_millionths`) |
| `_sat_per_kvb` | On-chain fee rate in satoshis per 1,000 vbytes, as in `terms.md` (the owner's 0.1 sat/vB is `100`) |
| `_at` | Unix seconds. Calendar times derived from heights are estimates and are named `_at_estimate` |
| `_height` | Block height |
| `_blocks` | A length in blocks |
| `_ms`, `_s` | Durations |

- Names are `snake_case`. Enumerations are lowercase words with underscores.
- `null` means "not applicable now". A missing field in an answer is a client error to report, not a value.
- JSON numbers in requests must be integers within ±(2^53 − 1). Objects nested deeper than 16 levels, duplicate keys and invalid UTF-8 are refused (`bad_json`).

### 7.2 A date

Every date the interface shows comes as one shape, because every countdown must say what happens at zero (options map, "rules for any layout") and every factory date can say where it comes from (concept H, borrowed from C).

```json
{
  "kind": "start_leaving_by",
  "due_height": 334114,
  "blocks_left": 3677,
  "due_at_estimate": 1796640590,
  "at_zero": { "code": "starts_leaving_alone", "needs": ["app_running", "fee_coins"] },
  "source": "worked_out",
  "provenance": {
    "code": "leaf_timeout_less_burial_exit_margin",
    "inputs": { "end_height": 334180, "leaf_depth": 2, "burial": 3, "steps_missing": 5, "allowance": 6, "margins": 14 }
  },
  "state": "ok"
}
```

| Field | Values |
|---|---|
| `kind` | `open_app_by`, `unlock_by` (1.0.0: the last height at which an unlock still lets the node finish leaving, `spec/exit.md` 5.6; 4.7), `lobby_starts_by`, `ready_check_answer_by`, `signing_ends_by`, `funding_deadline`, `unfinished_deadline`, `move_window_opens`, `move_try`, `move_by`, `start_leaving_by`, `leave_step_due`, `factory_ends`, `payment_back_by`, `invoice_expires`, `listing_renew_by` (host), `host_fund_by` (host), `host_online_for_try` (host) |
| `at_zero.code` | What happens at zero: `nobody_answers_old_state`, `lobby_applies_start_rule`, `lobby_cancelled`, `round_abandoned`, `last_try_passes`, `next_date_takes_over`, `starts_leaving_alone`, `step_deadline_passes`, `factory_end_rule_applies`, `invoice_unpayable`, `listing_drops`, `lobby_cancelled_by_host_absence` |
| `at_zero.needs` | What the outcome depends on: `app_running`, `fee_coins`, `host_answers`, `watcher` (later). Empty when nothing is needed |
| `source` | `signed_term` (the date follows from the host's signed terms) or `worked_out` (this program computed it) |
| `provenance.code` | `term_start_plus_life`, `term_window_before_end`, `leaf_timeout_less_burial_exit_margin` (`spec/exit.md` 4.4: the leaf's timeout H_leaf = E − 10·d, less the burial, the allowance for the missing steps and the margins; draft 3's `end_less_exit_less_margin`), `unlock_by_from_last_safe_confirm`, `revocation_window_less_margin`, `ack_height_plus_deadline`, `signing_budget_from_sent`, `invoice_expiry`, `payment_deadline` |
| `state` | `not_yet`, `ok`, `soon`, `urgent`, `passed` |

The example is signet's (`spec/exit.md` 4.3: B = 3, A = 6, M = 14): H_leaf = 334,180 − 10·2 = 334,160, and `leave_by` = 334,160 − (3 − 1) − 5·6 − 14 = 334,114, at tip 330,437.

`open_app_by` always includes a margin below the safe absence (critique H.3: "well within a day", never the whole window).

### 7.3 Identifiers

| Thing | Identifier | Example |
|---|---|---|
| Lobby | A **local opaque id**, `lob_` and 1 to 60 characters `[A-Za-z0-9_-]`, made by this program at first sight of the lobby. It is the `{id}` of every lobby path, the `lobby_id` of every field and event, and the `id` of the lobby object | `lob_7k2q` |
| Lobby rules fingerprint | `outer_digest`, 64 hex (`terms.md` section 6). Appears only in body fields named `fingerprint`, never in a path, a query string or an event. For an unlisted lobby it is a capability (`messages.md` 6.1) | `7f3a…c21e` |
| Factory | A local opaque id, `fac_…`, made when this program first saves the factory's round. The factory's object carries the fingerprint of the lobby it came from (`fingerprint`). One lobby makes at most one factory; a move goes to a new lobby with a new fingerprint | `fac_2d91` |
| Short fingerprint | First 4 and last 4 hex characters, for display. Never used to look anything up | `7f3a…c21e` |
| Seat (host view) | 16 hex, local to the host's program | |
| Host | `host_key`, 66 hex. Public, and the same for every lobby of that host | |
| Payment, invoice, activity entry, request id | Opaque, 1 to 64 characters `[A-Za-z0-9_-]`, local to this program | `pay_3`, `act_1182` |
| Transaction | txid, 64 hex. Public once broadcast | |

- Local ids of lobbies the member joined or hosts, and of every factory, are saved (7.5) and stay the same across restarts. A lobby that was only seen in a list gets its id for the run; after a restart it gets a new one when it is seen again, and an old id answers `404 not_found`.
- A local id never encodes the fingerprint (it is random), so a path or a log line reveals nothing about an unlisted lobby (review F16).

### 7.4 Requests that act

**`request_id`.** A call that sends something outward (join, ready, leave, open a lobby, start, cancel, pay, send coins, leave alone, move) takes a `request_id` chosen by the client, 16 to 64 characters `[A-Za-z0-9_-]` (the interface uses 128 random bits).

- **Bound to the request.** The program keys each id by itself and stores with it the method, the path (with its local ids filled in) and a **digest of the body**: SHA-256 of the body in the canonical form of **RFC 8785** (JSON Canonicalization Scheme; review N12): object members sorted by their names' UTF-16 code units, recursively; strings with only the control characters, `"` and `\` escaped, using `\b \t \n \f \r` where they apply and lowercase `\u00xx` otherwise, every other character as itself; numbers as ECMAScript writes them, which for this API's integers (7.1) is plain decimal; no white space. The `request_id` member is included. **The top-level `passphrase` member, where a call has one (4.8), is removed first** (a member of that name inside a nested object is not touched, and no call has one), so no digest of a passphrase is ever stored (a stored fast hash would be an offline oracle). The parser already refuses what RFC 8785 cannot encode (duplicate names, lone surrogates, numbers outside ±(2^53 − 1); 7.1). Every member name of this API is ASCII, for which ordering by UTF-16 code units is ordering by byte, so the program needs no UTF-16 sorting; only string **values** carry other characters, and they are written as themselves in UTF-8. Vector E15 of `tools/spec-vectors.py` (non-ASCII values, a `\u001f` control character, nested objects, the `passphrase` removed) gives the canonical bytes and the digest (review R10). The interface never needs to compute the digest. Request ids are unique across the whole API, not per path.
- **The same id, method, path and digest again** returns the first answer (status and body, with `"replayed": true` added) and does nothing new. A replay runs no key derivation (4.8).
- **After a restart** only the answer's status and the acted-on object's local id were saved (7.5), not the body. A replay then answers the saved status with the object's **current** state and `"replayed": true` (review N12).
- **The same id with a different method, path or digest** answers `409`, code `request_id_reused`, with `params.first` naming the first call's method and path pattern, and does nothing. So a client bug that reuses an id for a second lobby can never be answered with the first lobby's result.
- **Saved across restarts.** For every outward call, the record of the id (7.5) is saved **in the same journal batch as the first save the action makes**, so it is durable before anything is sent (`DESIGN.md` section 4). A retry after a crash and restart then finds the id and answers from the saved status and the object's current state, or, if the outcome is still pending, with `202` and the current state of the object, `"replayed": true`. A call that failed before any save leaves no id; retrying it acts as a first call.
- **How long ids are kept:** until the object they act on has ended (lobby ended, payment settled or failed, factory ended) and 30 days have passed (**proposed**). After that the same id is a new call. Ids are small; compaction may drop them only under this rule.

**Review and preview ids** (1.0.0: `review_id`, `preview_id`): made by a preview call, valid for 10 minutes (**proposed**), single-use, bound to the exact values the preview showed. Using one saves it as spent in the same batch as the action (7.5); a spent or expired id answers `409 review_expired` or `preview_expired`. The echo fields of 4.8 are compared with the values bound to the id.

**`based_on_version`.** A call that changes a stored object takes `based_on_version` (the object's `version` from the last read). If the object changed since, `409`, code `changed_elsewhere`. This protects against two browser tabs. Versions are saved with the object (7.5), so they survive a restart.

**Answers.** An action answers when the core has taken it and every save it asked for is confirmed (`DESIGN.md` section 4: save before send). It answers `202 Accepted` with the object's state when the outcome depends on other parties (`joining`, `starting`), and `200` when the outcome is already known. The final outcome arrives through the event stream.

### 7.5 What the program saves for this API

The API needs state that is not protocol bytes. Draft 1 left it without a home (review F11). It is saved **in the journal** (`journal.md`), under the journal's rules: one batch, all or nothing, confirmed before the answer and before anything it releases. It belongs to an area of its own, **0x000d (Local API)**, separate from the lobby, round and funding areas. Each row's **record type number** is in the table below and in `journal.md` 9.1, which assigns them (cross-spec review D13); every one is even, so a program that cannot interpret one refuses to start rather than skip it. The TLV field numbers inside each record are fixed with the engine's code tables (`journal.md` open point 3; Slice 1 input W3 now covers only those).

| What | Record type |
|---|---|
| Setup state | `0x000d0002` `setup_state` |
| Words checked | `0x000d0004` `words_checked` |
| Words-check attempts | `0x000d0006` `words_check_attempts` |
| Conditions | `0x000d0008` `conditions` |
| Conditions copied at joining | `0x000d000a` `conditions_copy` |
| Pause | `0x000d000c` `pause` |
| Local ids | `0x000d000e` `local_ids` |
| Known hosts | `0x000d0010` `known_host` |
| Activity entries | `0x000d0012` `activity_entry` |
| Request ids | `0x000d0014` `request_id` |
| Set-aside funds | `0x000d0016` `set_aside` |
| Sign-out setting (1.0.0) | `0x000d0018` `sign_out_setting` |
| Settings (1.0.0) | `0x000d001a` `settings` |
| Review and preview ids spent (1.0.0) | `0x000d001c` `review_id_spent` |
| Host-node setting (1.0.0) | `0x000d001e` `host_node` |
| User-added chain servers (1.0.0) | `0x000d0020` `chain_server_added` |
| While-closed reports (1.0.0) | `0x000d0022` `while_closed_report` | Nothing here is a key: the 24 words and the seed stay in the key file (`journal.md` section 10).

| What | Contents | Saved with, and before | Release |
|---|---|---|---|
| **Setup state** | `created_not_finished` or `ready`; the preset and the finding choice of `finish-setup` | Before `create` and `finish-setup` answer | S1 |
| **Words checked** | `checked_at`, or none | Before `phrase/check` answers `ok: true` | S1 |
| **Words-check attempts** | The time of each check made in the last 24 hours (12.3) | Before `check` compares the words, once the passphrase has opened them, so a restart never resets the limit | S1 |
| **Conditions** | The member's full conditions, `preset`, `version` | Before `PUT /conditions` answers; in the same batch as any `leave` it causes | S1 |
| **Conditions copied at joining** | For each joined lobby: the conditions, their `version` and `compare_with`, as they were at joining | **In the same batch as the lobby's `joined` record** (`journal.md` section 9). The fit check at the ready check and at signing uses this copy, never today's conditions (13.2; test 23.1 item 2) | S1 |
| **Pause** | `on` or `off`, `since_at`, and the lobby a pause is held for (`held_for_signing`) | Before `PUT /pause` answers, and before any `leave` or `round_abort` the pause sends. A locked program cannot read it, and joins and signs nothing anyway (4.7); **at unlock**, a saved `on` is applied **before the node connects to any host** (4.7, step 7), so a restart never resumes joining or signing (11.3) | S1 |
| **Local ids** | For each lobby joined or hosted and each factory: local id, fingerprint | With the lobby's first record (`terms_received` or `lobby_opened`), and with the factory's first round record | S1 |
| **Known hosts** | Key, address, source (`built_in`, `added`, `invitation`), `added_at` | Before `discovery/query` answers, when the query adds a host | S1 |
| **Activity entries** | Id, time, kind, who decided, rule, params, and the **saved copy** (terms object, fit check, conditions as copied), never changed afterwards (section 19) | In the same batch as the record of the event it describes, where there is one (for a refusal, with the round's `round_ended` or the lobby's `leave`); otherwise alone, before the event is shown | S1 |
| **Request ids** | `request_id`, method, path, body digest, answer status, the local id of the object it acted on, `created_at` | In the same batch as the action's first save (7.4) | S1 |
| **Set-aside funds** | For each hosted lobby: the amount set aside and the echoed `confirm_funding_sat` | Before `POST /host/lobbies` answers; replaced by `funding_plan` when the attempt starts | S1 |
| **Sign-out setting** | `sign_out_after_idle_s` (idle signs the browser out and never locks, 4.7; draft 4 called it `lock_after_idle_s`) | Before the settings call answers (1.0.0; Slice 1 uses the fixed default and saves nothing) | 1.0.0 |
| **Settings** | Every field of section 20 that is not computed | Before the `PATCH` answers | 1.0.0 |
| **Review and preview ids spent** | Id, spent or expired | In the same batch as the action that uses it | 1.0.0 |
| **Host-node setting** | Kind, address, the two file paths, the pinned certificate digest (15.5) | Before `PUT /host/node` answers | 1.0.0 |
| **User-added chain servers** | Address, protocol, `added_at`; their operator is always "you" (20.3) | Before the call answers | 1.0.0 |
| **While-closed reports** | Id, heights checked, findings, `seen` | When the program starts after being closed | 1.0.0 |

Not saved: sessions, codes, start tokens, the socket token (4.2), the passphrase and the storage key, paging cursors (9), event sequence numbers (10). They end with the run. The attempts file, the watch-and-exit bundle and the penalty file are storage's (storage 12.3, 8.7), not journal records of this API; at unlock the watcher's log becomes activity entries only for what the chain confirms (4.7, step 5).

---

## 8. Errors

A failed call answers a non-2xx status with:

```json
{ "code": "conditions_not_met", "message": "This lobby does not fit your conditions.", "field": null, "params": { "failures": [ { "condition": "max_joining_fee_sat", "yours": 2000, "offered": 5000 } ] } }
```

- `code` is stable and listed. The interface chooses the words from `code` and `params`. `message` is fixed English for logs and for clients without their own wording.
- `field` names the request field at fault, as a JSON pointer (`/conditions/min_members`), or is `null`.
- `params` holds the numbers. A refusal always carries both numbers (the member's limit and the offered value).

### 8.1 General codes

| HTTP | Code | When |
|---|---|---|
| 400 | `bad_json` | Not valid JSON, duplicate keys, too deep, number out of range |
| 400 | `bad_value` | A field's value is outside its rules (`field` set) |
| 400 | `unknown_field` | A request field this version does not know |
| 400 | `missing_field` | |
| 400 | `secret_in_url` | Section 5.5 |
| 400 | `two_credentials`, `bearer_not_on_tcp`, `no_upgrade` | Sections 4.6, 3.1 |
| 401 | `not_signed_in` | No session header or token, or an unknown one |
| 401 | `wrong_passphrase` | Section 4.3 |
| 423 | `wallet_locked` | The wallet is locked (4.7) |
| 403 | `other_user` | The connection belongs to another operating-system account (3.4). Fixed text; the connection is closed |
| 403 | `not_setup_call` | A setup session called something outside the first-run calls (4.3) |
| 403 | `not_files_behind_call` | A `files_behind` session called something outside its calls (4.7) |
| 409 | `files_behind` | On the local socket, `POST /api/v1/wallet/unlock` found the files older than the wallet's last saved state (4.7); `params.cause`: `behind`, `possibly_old` |
| 409 | `not_files_behind` | `start-as-restore` while the wallet is not `files_behind` (4.5) |
| 503 | `passphrase_not_checked` | The key derivation failed (the helper crashed or ran out of memory, storage 8.4). Not counted as a wrong passphrase; try again |
| 409 | `something_to_take_out` | "Maximum privacy" without `confirm_leave_by_height` while a factory has something to take out (20.2; `spec/exit.md` W5) |
| 409 | `token_used` | The start token was already presented (4.3); `params.used_at` |
| 409 | `hosting_lobby_open` | Lock refused while this program hosts an Open lobby (4.7); `params.lobby_id` |
| 400 | `weak_passphrase`, `passphrases_differ` | Storage 4.1's rules; `params.reason`: `too_short` (with `params.length` and `params.minimum`), `too_long`, `too_common`, `names_the_wallet`, `uses_the_words` |
| 403 | `forbidden_origin` | Section 5 |
| 403 | `fresh_sign_in_needed` | Section 4.8 |
| 409 | `confirm_mismatch` | An echo field (4.8) differs from what the program would do; `params` holds both values |
| 409 | `request_id_reused` | Section 7.4 |
| 409 | `review_expired`, `preview_expired` | Section 7.4 |
| 429 | `too_many_streams` | Section 10.3. The interface does not retry it |
| 404 | `not_found` | Unknown path or identifier |
| 405 | `method_not_allowed`, `no_cors` | |
| 409 | `changed_elsewhere` | `based_on_version` is old |
| 409 | `paused` | The action would join or sign something new while paused |
| 409 | `signing_now` | Conditions, pause or the network cannot change during the seconds of signing |
| 409 | `chain_in_doubt` | The chain servers disagree, or fewer than two answer; the action needs a trusted chain view |
| 409 | `no_wallet`, `wallet_restoring` | The wallet does not exist yet, or is waiting for current data after a restore |
| 411, 413, 415, 421, 431 | `length_required`, `too_large`, `bad_content_type`, `bad_host`, `headers_too_large` | Sections 3, 5 |
| 429 | `rate_limited` | `params.retry_after_s` |
| 501 | `not_in_this_release` | `params.release`: `1.1.0` or `later` |
| 503 | `node_stopped` | The core stopped after a storage failure or a refused step, and is being rebuilt from storage (`DESIGN.md` section 4), or an unlock found the journal corrupt or storage failing (4.7, step 3; the wallet stays locked). `params.reason`: `storage_failed`, `storage_full`, `journal_corrupt`, `rebuilding`; `stopping` while the program shuts down (contract-v2 section 4) |
| 503 | `node_busy` | An acting call had no outcome within 30 s: its save is not confirmed yet, and the command may still be alive. Retry with the same `request_id` (7.4): a retry while the first is pending is held for the same outcome (contract-v2 section 11) |
| 500 | `internal` | A bug. The log has a reference number; `params.ref` gives it |

Call-specific codes are listed with each call.

---

## 9. Pagination

Long lists (lobbies, activity, payments, on-chain transactions, auto-join history, host join requests, logs) are paged by cursor.

- Request: `?limit=50&cursor=<opaque>`. `limit` 1 to 200, default 50.
- Answer: `{ "items": [ … ], "next_cursor": "…" | null, "as_of": { "height": 330437, "at": 1794434400 } }`.
- Newest first unless the call says otherwise.
- A cursor names the last item returned, not a position, so items added meanwhile do not shift a page. A cursor stays valid for the program run; after a restart, `400`, code `cursor_expired`, and the client starts again.
- Filters and sort orders are query parameters listed with each call; a cursor is valid only with the same filters.

---

## 10. The event stream

### 10.1 A server-sent event stream, read with `fetch()`

`GET /api/v1/events` (**S1**) answers a stream in the server-sent events format (`text/event-stream`). The interface reads it with `fetch()` and the response body's `ReadableStream`, sending `X-Gazpacho-Session` like every other call. It does **not** use `EventSource`: `EventSource` cannot send request headers other than its own (its options hold only `withCredentials`; HTML SSE), so it could only be authenticated by a cookie or a secret in the URL, and both are refused here (4.4, 5.5).

| | This stream | WebSocket |
|---|---|---|
| Direction needed | Program to interface only. Every action is an ordinary request | Two-way; the second direction is unused |
| Security | An ordinary `GET` under every rule of section 5: session header, `Host`, `Origin`, fetch metadata | Not covered by the same-origin policy: any page can open one and must be refused by a separate `Origin` check (cross-site WebSocket hijacking) |
| Code in the C program | A response that stays open and writes lines | An upgrade handshake, frame parser, masking, ping and close: more parsing of untrusted input in C |
| Reconnects | Written in the interface, with the `Last-Event-ID` request header set by the interface; no automatic reconnect that could loop | Written by hand |
| Cost | One HTTP/1.1 connection for the whole browser (10.3) | One connection |

WebSocket is not offered (3.1 refuses upgrades).

### 10.2 What an event says

As in the prototype: an event says **which area changed**, never the new content. The interface then asks for what it shows. One source of truth, and a missed event is harmless.

```
id: 7c1e9a04-1532
event: change
data: {"topic":"lobby","id":"lob_7k2q","seq":1532}

```

`id` is always a local id (7.3), never a rules fingerprint.

| Topic | `id` | Something changed in |
|---|---|---|
| `status` | | `GET /status`: the strip, attention, money |
| `session` | | This session was locked, revoked or ended. The stream closes after it |
| `chain` | | The chain tip or the state of the chain servers |
| `lobby` | lobby | A lobby: members, readiness, stage, terms version, the member's own seat or round |
| `host_lobby` | lobby | A lobby this program hosts |
| `conditions` | | Conditions, presets, fit summary, automatic joining |
| `factory` | factory | A factory: state, funding, dates, exit, move |
| `payments` | | Payments or invoices |
| `wallet` | | On-chain coins and transactions, and wallet setup or restore progress |
| `activity` | | A new activity entry |
| `discovery` | query | The lobby list, the host list, or the state of a discovery query (21) |
| `settings` | | Any settings scope, backup times, server checks |
| `hosting` | | Hosting overview, ladder, earnings, setup |
| `reset` | | Everything: draw again from nothing (after a restore, after the core was rebuilt from storage, or when the client is too far behind) |

A request the interface makes **because an event arrived** never carries `X-Gazpacho-User` (4.7), so events never keep a session awake.

### 10.3 Order, reconnects, limits

- `seq` rises by one for every event in a run. The event `id` is `<run_id>-<seq>`.
- The program keeps the last 256 events. On reconnect with `Last-Event-ID`: if the run is the same and the events are still held, it replays them; otherwise it sends one `reset`.
- A comment line (`: keep-alive`) every 15 s, so a dead connection is noticed.
- Events of one topic and id are merged: at most one per 250 ms, the latest wins (a busy lobby changes counts many times a second).
- **One stream for the whole browser.** The interface holds the stream in a `SharedWorker` where the browser has one, and otherwise in one tab chosen over the `BroadcastChannel` of 4.4, which relays each event to the other tabs; when that tab closes, another takes over. The messages are 4.4's. A worker has no `sessionStorage`, so each tab posts its token to it, the worker holds it in memory while any tab is connected, and sign-out in any tab tells it (`sign_out`). **With the tunnel port set no SharedWorker is used**: each tab holds its own stream for its own session (4.4, review R7), within the caps below. Without it, the worker serves only ports that presented a token it checked (4.4). Browsers limit connections per host (six for HTTP/1.1 in common browsers; the HTML SSE note warns of exactly this and suggests a shared worker), so a stream per tab would leave too few for the calls.
- **Caps:** at most 2 streams per session and 8 in all. A stream over the cap is answered `429`, code `too_many_streams`, before any event; the interface shows "Too many windows are following this app" and does not retry it by itself. Nothing is closed to make room, so no two streams can push each other out in a loop (review F10).
- **Reconnects** by the interface: after a network error or the end of the stream, again after 2 s, then 4, 8, up to 60 s; never after a `4xx` answer; after `401` it shows the sign-in field.
- Signing never waits for a slow stream. A stream whose unsent data passes 64 KiB is closed; its reconnect gets `reset`.

---

## 11. Status and the always-present strip

### 11.1 `GET /api/v1/status` (S1)

One call gives everything that is on every screen: the strip, the attention list, "my money" and the network marker. The interface calls it at start and on every `status` event (without `X-Gazpacho-User`, 4.7).

```json
{
  "version": 412,
  "network": { "id": "signet", "test_coins": true },
  "wallet": "ready",
  "pause": { "state": "off", "since_at": null, "lobby_id": null },
  "lock": null,
  "interface": { "peer_check": "same_user_only", "memory_locked": true },
  "doing": { "code": "in_lobby_waiting", "lobby_id": "lob_7k2q", "params": { "ready": 38, "target": 50, "minimum": 30 }, "since_at": 1794434000 },
  "connection": {
    "chain": { "state": "agree", "height": 330437, "servers_agreeing": 2, "operators": 2, "since_at": 1794431000 },
    "host_links": [ { "host_key": "02…", "state": "connected", "last_heard_at": 1794434390 } ],
    "offline_by_choice": false
  },
  "watching": {
    "state": "this_app",
    "health": "up_to_date",
    "last_check_height": 330437,
    "last_check_at": 1794434280,
    "safe_absence_blocks": 2016,
    "open_by": { "...": "a date (7.2), kind open_app_by" },
    "unlock_by": { "...": "a date (7.2), kind unlock_by, or null" },
    "factories_watched": 1
  },
  "next_date": { "...": "a date (7.2)" },
  "auto_join": { "state": "off" },
  "hosting": null,
  "money": {
    "can_send_sat": 182400,
    "can_receive_sat": 317600,
    "take_out_alone": { "amount_sat_estimate": 181200, "fee_sat_estimate": 1200, "blocks": 864, "needs": ["app_running", "fee_coins"] },
    "on_chain_free_sat": 48000,
    "set_aside_sat": 0,
    "inside_factories_sat": 182400,
    "forming_sat": 0,
    "hosted_factories_sat": 0,
    "covered_sat": null,
    "as_of_height": 330437,
    "chain_view": "trusted"
  },
  "attention": [ ],
  "while_closed": null
}
```

The example shows a 1.0.0 member with a live channel. **In Slice 1**, which has no channels: `can_send_sat` and `can_receive_sat` are `0`, `take_out_alone` is `null`, `inside_factories_sat` is `0` for a member (members bring no coins in 1.0.0), and `while_closed` is `null` (11.5 is 1.0.0).

- `lock`: `null`, or `{ "state": "held_for_signing", "lobby_id", "since_at" }` while a lock waits for a round to end, or (1.0.0) `{ "state": "held_for_payment", "since_at" }` while it waits for an incoming payment whose secret was released (4.7). While the wallet is locked or `files_behind`, status has the locked shape of 4.7 instead of this one.
- `watching.unlock_by`: the date the lock warning names and the lock echoes (4.7): `spec/exit.md` 5.6's `unlock_by` where something is to take out (1.0.0); otherwise `null`, and then the lock needs no `confirm_unlock_by_height` (cross-spec review D4). Always `null` in Slice 1.
- `interface.peer_check`: `same_user_only` or `unavailable` (3.4). `interface.memory_locked`: `false` when the system refused to keep keys out of swap (storage 8.3); the interface then shows storage 14's "Weak memory protection" line.

### 11.2 The strip's parts and their values

**`wallet`**

| Value | Meaning |
|---|---|
| `none` | No wallet yet: first run |
| `created_not_finished` | Keys made; setup not finished |
| `ready` | |
| `locked` | The wallet exists and its storage key is not in memory (after a start, or locked by the person). In 1.0.0 the watcher may be watching, publishing tree paths and answering old states from already-signed transactions; it never finishes an exit, and nothing new is signed, joined, paid or answered until the passphrase is typed (4.7). Slice 1 has no watcher |
| `files_behind` | An unlock found the files older than the wallet's last saved state, or possibly old (storage 6.3 step 4; `params.cause`). The keys are dropped again; nothing is started until the person starts the files as a restore or puts the newer files back (4.7). Never "your wallet is fine" |
| `restoring` | Restored; waiting for the host or the chain to show current data. Balances are not confirmed and nothing can be paid or received |
| `node_stopped` | The core stopped (storage failure, refused step, corrupt journal) and is being rebuilt, or cannot start. `doing` says which |

**`pause.state`**

| Value | Meaning |
|---|---|
| `off` | |
| `on` | Signs nothing new and joins nothing until resumed. It left the lobbies where it had sent nothing in a round (11.3). Dates still apply and watching goes on |
| `held_for_signing` | The person pressed Pause while this member's partial signatures were out in a round that had not ended. It takes effect when that round ends. `lobby_id` names it |

**The chain view, normatively.** Every other part of the status follows from `connection.chain.state` by this table, and by nothing else. The values are mutually exclusive: exactly one holds at any time.

| `connection.chain.state` | Meaning | `money.chain_view` | `watching.state` (when something needs watching) | Signing, and treating anything as newly confirmed | `doing.code` it can give |
|---|---|---|---|---|---|
| `agree` | At least two servers of two different operators, at least one of them from the built-in list (20.3), agree on the tip and none of those is behind | `trusted` | `this_app` | Allowed | — |
| `lagging` | As `agree`, and some other server is behind by `params.blocks`. Only reported while two agreeing servers of two operators remain; otherwise the state is `one_source` | `trusted` | `this_app` | Allowed | — |
| `catching_up` | Servers are still loading after a start or a reconnect; the app has not yet compared two tips | `in_doubt` | `nobody_chain_in_doubt` | Not allowed | `chain_in_doubt` |
| `one_source` | Only one server, or only one operator, answers at the tip. The app cannot compare | `in_doubt` | `nobody_chain_in_doubt` | Not allowed | `chain_in_doubt` |
| `disagree` | Servers report different chains. `since_at` | `in_doubt` | `nobody_chain_in_doubt` | Not allowed | `chain_in_doubt` |
| `unreachable` | No server answers | `in_doubt` | `nobody_chain_in_doubt` | Not allowed | `chain_in_doubt` |
| `offline_by_choice` | The person chose to go offline (Settings, Watching; 1.0.0) | `in_doubt` | `nobody_offline`, which wins over `nobody_chain_in_doubt` | Not allowed | `chain_in_doubt` |

`watching.state` is `nothing_to_watch` only when this program has no factory in any state other than `ended` and `dead`, no hosted factory, and no unresolved round, an abandoned creation counted as unresolved while `still_watched` is true (16.1). Then it is `nothing_to_watch` whatever the chain state, because nothing needs watching; `money.chain_view` still follows the table.

**`watching.state` precedence, first match wins:** `nobody_locked`; `nobody_restoring`; `nothing_to_watch`; `nobody_offline`; then, while locked, `watcher_locked` (with `reason = chain_in_doubt` where the chain table gives `nobody_chain_in_doubt`: the watcher still acts on its clock-advanced estimate, cross-spec review D6); while unlocked, `nobody_chain_in_doubt` (the chain table), then `this_app`. While locked, "this program has no factory …" is judged from the bundle (4.7), since the journal cannot be read.

**`doing.code`**: what the app is doing and why. **Exactly one value; when several hold, the first in this table wins.** The order is normative (review F7): every value that means money or signatures are at risk, or that the person must keep the app open, comes before `paused`, so a pause never hides it. The others still appear where they belong (attention list, lobby, factory).

| Priority | Value | Meaning | Reachable in |
|---|---|---|---|
| 1 | `node_stopped` | See `wallet`; `params.reason` as in 8.1 | S1 |
| 1a | `files_behind` | See `wallet`; `params.cause`. Shown on the locked page with the headline `files_behind` (4.7) | S1 |
| 1b | `wallet_locked` | The wallet is locked: nothing new is signed, joined, paid or answered until the passphrase is typed, and no exit is finished. `params.watcher` says what the watcher does (`watching`, `publishing_tree_steps`, `waiting_for_unlock`, `host_closed`, `answering_old_state`, `paying_fee`, `off`; 4.7), `watching.state` whether anything is watched and `watching.headline` what to say. Shown on the locked page, whose status has only the locked shape | S1 |
| 2 | `no_wallet` | First run | S1 |
| 3 | `restoring` | Waiting for current data after a restore | S1 |
| 4 | `answering_old_state` | An old state was published and the app sent the answer; it is not confirmed yet | 1.0.0 |
| 5 | `signing` | Keep the app open; seconds. `params.of`, `params.done` (signatures). Also shown while `pause.state` is `held_for_signing` | S1 |
| 6 | `moving` | A move try is being signed | 1.0.0 |
| 7 | `signing_unfinished` | The app sent its signatures and no result came back. It treats both outcomes as possible and keeps watching until settled. `params.purpose`: `start` or `move`; `params.cancel_received` if the host sent `cancel` (14.1) | S1 (start) |
| 8 | `move_unfinished` | Same as `signing_unfinished`, for a move. Payments in the old factory are paused until it settles | 1.0.0 |
| 9 | `leaving_alone` | Step by step; the app must run until it ends | 1.0.0 |
| 10 | `left_behind` | The group moved on without this member; the app starts or has started leaving alone | 1.0.0 |
| 11 | `chain_in_doubt` | See the table above. Signing stopped | S1 |
| 12 | `awaiting_funding` | Signed; waiting for the host's funding to reach its confirmations. Not live yet | S1 |
| 13 | `paused` | | S1 |
| 14 | `ready_check` | The start rule was met; the ready check is under way | S1 |
| 15 | `in_lobby_not_ready` | Joined but not ready. `params.reasons`: `conditions_fail`, `blocked_member_present`, `user_choice`, `terms_moved_outside` | S1 |
| 16 | `in_lobby_not_counted` | Ready, but fewer than `counted_from` are ready, so this member will not be chosen yet | S1 |
| 17 | `in_lobby_waiting` | Ready, waiting for the start | S1 |
| 18 | `looking_tell`, `looking_join` | Automatic joining is looking | 1.0.0 |
| 19 | `looking_nothing_fits` | Nothing listed fits; `params.excluded_most_by` with both numbers | 1.0.0 |
| 20 | `budget_used` | Automatic joining's budget is used up; waiting | 1.0.0 |
| 21 | `creation_dead` | Sticky (below). The funding can never exist: one of its inputs was spent elsewhere and buried. `params.cause` (1.0.0): `input_spent_elsewhere`, or `funding_replaced` (the host replaced its own funding transaction, `spec/exit.md` 6.7: "The host replaced its funding transaction. The tree you signed can never be used. Nothing was owed.") | S1 |
| 22 | `creation_abandoned` | Signatures went out, but the factory was not funded in time or the result never came. Records kept; nothing is owed. **Still watched**: `params.still_watched` (16.1); the interface never says it is over while that is `true`. **Sticky only once `still_watched` is `false`**; while it is `true` the code holds at this priority until the creation is `dead` or `live` (review N8) | S1 |
| 23 | `refused` | Sticky. Did not sign. Refused at the check, before any nonce or signature. Nothing was signed; nothing moved. `params.failures` with both numbers | S1 |
| 24 | `refused_by_host` | Sticky. The host refused this member's seat (seat state 7). Nothing was signed | S1 |
| 25 | `lobby_cancelled` | Sticky. The lobby was cancelled **and this member had sent no partial signature in any attempt of it** (14.1). `params.reason`: `deadline_below_minimum`, `host_choice`, `signing_budget_spent`. With a partial signature out, the code is `signing_unfinished` (7) or `creation_abandoned` instead, never this | S1 |
| 26 | `not_chosen` | Sticky. The lobby started without this member (its minimum, or the target cut) | S1 |
| 27 | `idle_in_factory` | Live; nothing to do now | S1 |
| 28 | `idle_no_factory` | Not in a factory. "You cannot pay or receive until you are in a live one" | S1 |

**Sticky codes** (21 to 26) report an outcome. Each is shown for **24 hours** from its activity entry, or until the member joins another lobby, whichever comes first (**proposed**), and only when nothing above it holds; then the next applicable value shows. **Exception:** `creation_abandoned` does not expire, and is not displaced by joining another lobby, while its `still_watched` is `true`, because the next value would otherwise be `idle_no_factory` ("Not in a factory") for a creation that can still go live (`safety-rule.md` C11; review N8). How long `still_watched` lasts when the funding never appears is 24.2 item 19. Their lifetime is computed from the saved activity entry, so it survives a restart. The outcome itself stays in the lobby object and in Activity for good.

**`connection.host_links[].state`**: `connected`, `connecting`, `not_answering` (with `last_heard_at`), `offline_by_choice`.

**`watching.state`** (who watches) and **`watching.health`**

| `state` | Meaning |
|---|---|
| `this_app` | This app, only while it runs, unlocked |
| `watcher_locked` | This app, **locked** (1.0.0): the watcher watches, publishes the tree path by `leave_by_locked` and answers the host's old states with already-signed transactions only. It **cannot finish an exit**: the last step needs an unlock by `unlock_by`. It does not move to the next factory, answer the host, sign or take payments (4.7). `reason`: `null`, `penalty_file_short`, `bundle_kept_as_newer` or `chain_in_doubt` (4.7). Only while the program runs. Draft 3 called it `locked_watcher` |
| `nobody_locked` | **Nobody is watching**: the wallet is locked and no watcher runs; `reason` says why (`no_bundle`, which every Slice 1 build reports; `no_key_store`; `watcher_off`; `bundle_key_unavailable`; `bundle_refused`; 4.7). Wins over every other value |
| `nobody_restoring` | **Nobody is watching the factories this wallet may have been in**: it was restored from its words and does not know them; they come back only from a backup (12.4, 12.6). While `wallet = restoring`. Wins over every value but `nobody_locked` |
| `nobody_offline` | **Nobody is watching**: offline by choice. The app cannot answer an old state, move, start leaving alone or receive. The safe absence keeps counting |
| `nobody_chain_in_doubt` | Nobody can watch: the chain view is in doubt (`catching_up`, `one_source`, `disagree` or `unreachable`; table above). Unlocked only; a locked watcher keeps `watcher_locked` with `reason = chain_in_doubt` |
| `nothing_to_watch` | No factory, no hosted factory and no unresolved round (rule above). Nothing needs watching |
| `own_machine` | later reserved: a second machine of the person's |
| `watcher` | later reserved: a watcher holding ready-made answers, never keys |

| `health` | Meaning |
|---|---|
| `up_to_date` | Last check at the tip |
| `behind` | Last check more than 6 blocks or 30 minutes ago while running (`params.minutes`) |
| `unreachable` | later reserved, for a separate watcher |
| `not_applicable` | With `nobody_*` and `nothing_to_watch`. `watcher_locked` uses `up_to_date` and `behind` like `this_app` |

**`auto_join.state`**: `off`, `looking_tell`, `looking_join`, `looking_nothing_fits`, `budget_used`, `in_lobby`, `paused`. With `params.listed`, `params.fit`, `params.budget`. 1.0.0; S1 always returns `off`.

**`hosting`**: `null` until this program has a lobby or factory of its own (decision 4: the strip shows hosting only then). Otherwise `{ "lobbies_open": 1, "factories": 2, "next_date": { a date } }`.

**`money`**

| Field | Meaning | Slice 1 |
|---|---|---|
| `can_send_sat` | Balance in channels of **live** factories only (sum over channels, decision 5) | `0` |
| `can_receive_sat` | Receiving room left, live factories only | `0` |
| `take_out_alone` | Estimate of what leaving alone would give now, its fee, its length, and what it needs (`app_running`, `fee_coins`). `null` when nothing of the member's is inside a live factory | `null` |
| `on_chain_free_sat` | On chain and free | As the wallet |
| `set_aside_sat` | Held back for a lobby this program hosts (decision 6: one wallet, with an amount set aside) | As the wallet |
| `inside_factories_sat` | The member's balance in **live** factories | `0` |
| `forming_sat` | The member's balance in factories that are `awaiting_funding` (C11: not live, no paying or receiving). Never added to `can_send_sat` or `inside_factories_sat` | `0` |
| `hosted_factories_sat` | The host's own coins in factories it hosts, from broadcast of the funding on, until they come back. Never part of the member's figures | The funding amount |
| `covered_sat` | **1.1.0 reserved**: the covered amount under limited coverage (decision 5). Always `null` in 1.0.0 | `null` |
| `as_of_height` | The chain height these figures are for | |
| `chain_view` | `trusted` or `in_doubt`, by the table above. When `in_doubt` the figures are the last trusted ones, and the interface must not say that money "has not moved" (critique, section 4) | |

### 11.3 Pause

`PUT /api/v1/pause` (**S1**), `{ "on": true }`, or `{ "on": false, "confirm": "resume" }`. Pausing needs no fresh sign-in; resuming needs one (4.8). A locked wallet already joins and signs nothing (4.7).

**What pausing does, by where this member stands in each lobby** (review F24, G9). "Sent nothing in a round" means no nonce and no partial signature for any round of that lobby.

| Member's position (`messages.md` section 6, `signing-round.md` section 7) | On pause |
|---|---|
| Joined or Ready, lobby Open | Leaves: `leave` with reason 2 ("user"). `you.outcome = left`, `reason: paused` |
| In a ready check (answered or not) | Leaves as above; a `ready` already sent is overtaken by the `leave` |
| Chosen (`start` role 1 received), no `round_propose` yet | Leaves as above. Nothing was sent in a round |
| Not chosen (`start` role 2) | Leaves as above |
| Checking a proposal, or Nonces sent, with no partial signature ever sent in the lobby | Sends `round_abort` for its items, then `leave` reason 2. The round becomes Aborted; nothing was signed (`aborted_before_signatures`) |
| Signed (any tier), Complete, or Unfinished: partial signatures are out | **Held**: `pause.state = held_for_signing` with this lobby, answer `202`. The round runs to its end, because stopping cannot call signatures back and would only make it Unfinished (`signing-round.md` section 7). The pause takes effect when the round reaches Live, Awaiting funding, Unfinished's end, Abandoned or Dead. Nothing new is signed in any other lobby meanwhile |
| Awaiting funding, Live, Abandoned | Unchanged. Watching goes on |

- **While on:** the app signs nothing new, joins nothing, readies for nothing; `join` and `ready` answer `409 paused`. Watching, answering an old state, moves already agreed, and leaving alone before an end date go on: those protect the member.
- **A hosted lobby while paused:** the host's program runs no ready check, by the start rule or by `start`; the lobby stays Open, and at its deadline it is cancelled (`cancel` reason 2, host's choice) if the pause is still on. A hosted round already under way runs to its end, like a member's held round.
- **Pause survives a restart.** It is saved before the answer and before any `leave` or `round_abort` it sends (7.5); **at unlock** (every restart starts locked) a saved `on` is applied before the node connects to any host (4.7, step 7).
- Answer: `{ "pause": {…}, "left_lobbies": ["lob_7k2q"], "aborted_lobbies": [], "held_lobby": null }`.

### 11.4 Attention

`attention` lists what needs the person, most important first. Each item:

```json
{ "id": "att_88", "tier": "act_now", "code": "move_last_try", "due": { "...": "a date" }, "factory_id": "fac_2d91", "params": { } }
```

**Tiers** (concept H, rule 21 of the consent checklist):

| Tier | Rule |
|---|---|
| `at_risk` | Stays on every screen until fixed. No date needed |
| `act_now` | Only for an action with a date: `due` is never `null` |
| `important` | |
| `recommended` | |
| `heads_up` | Told once |
| `record` | Silent; in Activity. The app did the thing itself |

**Codes**

| Code | Tier | Params | Release |
|---|---|---|---|
| `chain_disagree` | at_risk | `since_at`, `servers` | S1 |
| `chain_one_source` | at_risk | `since_at` | S1 |
| `chain_unreachable` | at_risk | `since_at` | S1 |
| `chain_catching_up` | important | `since_at`. Becomes `chain_one_source` if it lasts more than 10 minutes (**proposed**) | S1 |
| `signing_unfinished` | at_risk | `lobby_id`, `purpose`, `sent_at`, `last_heard_at`, `checked_to_height`, `cancel_received` (`null` or `{ reason }`) | S1 |
| `node_stopped` | at_risk | `reason` | S1 |
| `nobody_watching` | at_risk | `safe_absence_blocks`. Raised alongside the locked headlines `nobody_watching_locked` and `nobody_watching_at_risk`, which are different codes (4.7; cross-spec review D16) | 1.0.0 |
| `watching_behind` | at_risk | `minutes` | 1.0.0 |
| `funding_reorganised` | at_risk | `factory_id` | 1.0.0 |
| `old_state_published` | at_risk | `factory_id`, `answer` (`sent`, `confirmed`, `buried`) | 1.0.0 |
| `branch_partly_on_chain` | important | `factory_id`: a neighbour left alone, so shared levels above this member are on chain. In 1.0.0 trees there are no timed steps, so nothing starts counting; the cheap rotation and the whole-factory close are gone once the root kickoff is buried (`spec/exit.md` 7.1) | 1.0.0 |
| `move_last_try` | act_now | `factory_id`, `due` | 1.0.0 |
| `leave_step_due` | act_now | `factory_id`, `due` | 1.0.0 |
| `open_app_by` | act_now | `due` (only when close) | 1.0.0 |
| `host_not_answering` | important | `host_key`, `since_at` | S1 |
| `payments_paused_by_host` | important | `factory_id`; no date (never `act_now`) | 1.0.0 |
| `factory_backup_missing`, `factory_backup_old` | important | `factory_id`, `last_at` | 1.0.0 |
| `words_not_checked` | important | | S1 |
| `restored_factories_unknown` | important | Raised by a restore from the words (12.4): factories this wallet was in are neither known nor watched until a backup is imported. Cleared by an import (1.0.0); in Slice 1 it stays | S1 |
| `storage_nearly_full` | important | `used_bytes` (soft limit, `journal.md` section 7) | S1 |
| `restored_seats_lost` | important | `lobbies` | 1.0.0 |
| `terms_changed` | heads_up | `lobby_id`, `from_version`, `to_version` | S1 |
| `date_near` | heads_up | `due` | 1.0.0 |
| `refused_to_sign` | record | `lobby_id`, `activity_id` | S1 |
| `use_own_chain_server`, `choose_watching` | recommended | | 1.0.0 |
| `host_can_start` | important | `lobby_id` (host) | S1 |
| `host_funds_short` | important | `lobby_id`, `need_sat`, `have_sat` (host) | S1 |
| `host_members_not_moved` | important | `factory_id`, `count`, `due` (host) | 1.0.0 |
| `host_listing_renew` | important | `lobby_id`, `due` (host) | 1.0.0 |
| `host_node_missing` | important | Only while hosting needs one (host) | 1.0.0 |
| `exit_needs_fee_coin` | important while `leave_by` is more than `WARN_LEAD` away, `at_risk` after | `factory_id`, `fee_sat_estimate`: the path would not confirm at the mempool floor with anchor-only children and there is no on-chain coin (`spec/exit.md` 6.5) | 1.0.0 |
| `payments_stopped_for_exit` | important | `factory_id`, `since_height`: `payments_stop_at` reached (`spec/exit.md` 4.4) | 1.0.0 |
| `exit_step_late` | at_risk | `factory_id`, `step`, `due`, `helps` (`add_fee_coin`, `keep_app_running`): a step not confirmed by its `step_due` | 1.0.0 |
| `exit_step_held_back` | at_risk | `factory_id`, `step`, `outbid_sat`: another party's child on the step's anchor that the member cannot out-pay (`spec/exit.md` 6.4 rule 5) | 1.0.0 |
| `exit_fee_budget_reached` | act_now | `factory_id`, `due` (the step's due), `budget_sat` | 1.0.0 |
| `exit_missed` | at_risk until seen | `factory_id`, `amount_lost_sat`: H_leaf + 1 passed without the commitment buried, and the host swept | 1.0.0 |
| `funding_double_spent` | at_risk until seen | `factory_id`, `amount_lost_sat`: a funding input of a live factory spent by another buried transaction; the tree is void (`ended_how = void_funding`) | 1.0.0 |
| `restored_commitment_choice` | at_risk | `factory_id`, `due` (`host_force_by`): a restored member whose host has not closed (`spec/exit.md` 5.7) | 1.0.0 |
| `unexplained_spend` | at_risk | `factory_id`, `txid`: a watched output spent in a way only the member's key allows (`spec/exit.md` class S8); payments stopped | 1.0.0 |

`DELETE /api/v1/attention/{id}` (1.0.0) dismisses a `heads_up` or `recommended` item. Other tiers clear only when their cause does; dismissing them answers `409`, code `cannot_dismiss`.

### 11.5 While the app was closed

`GET /api/v1/while-closed/{id}` (1.0.0) and `POST /api/v1/while-closed/{id}/seen`. In Slice 1, `status.while_closed` is `null`; in 1.0.0 it is `{ "id": "wc_19", "seen": false }` or `null`.

```json
{
  "id": "wc_19",
  "closed_at": 1794394800, "opened_at": 1794427200,
  "beyond_safe_absence": false,
  "checked": "all",
  "checked_from_height": 330383, "checked_to_height": 330437,
  "found": [],
  "dates_passed": [],
  "could_not": ["receive", "watch"],
  "verdict": "nothing_found"
}
```

The facts are **separate fields**, because several can hold at once (review F7):

| Field | Values |
|---|---|
| `found` | The items found (old state published, funding reorganised, a date passed with its outcome, …), each `{ "code", "factory_id", "at_height" }`. Empty when none |
| `checked` | `all` (every block from `checked_from_height` to the tip was checked with a trusted chain view), `partly` (some, because the chain view went into doubt; `checked_to_height` says how far), `not_yet` (the chain view is in doubt now; nothing checked yet) |
| `beyond_safe_absence` | `true` when the app was closed longer than the safe absence |
| `dates_passed` | Dates of 7.2 that passed while closed |

`verdict` is only the headline, computed from those fields by this **precedence**, first match wins:

1. `found`, when `found` is not empty;
2. `could_not_check`, when `checked` is `partly` or `not_yet`;
3. `beyond_safe_absence`, when that field is `true`;
4. `nothing_found` otherwise. The interface then says "Nothing appears to have gone wrong while you were away", with what was checked (critique H.3).

The interface shows every field that holds, not only the headline: a `found` report that was also only partly checked says both. Never "nothing is lost".

---

## 12. First run, wallet keys, backup and restore

The 24 words may appear in the interface (owner decision 12, 2026-11-12, "follow typical rules for key handling for wallets"), under the rules of 12.7, which every call in this section obeys. Creating, checking and restoring are done in the interface in Slice 1 (owner decision 11).

### 12.1 Setup state

`GET /api/v1/wallet/setup` (**S1**)

```json
{ "state": "none", "network": "signet", "networks": [ { "id": "signet", "available": true }, { "id": "testnet4", "available": false, "reason": "one_operator" }, { "id": "mainnet", "available": false, "reason": "switched_off_in_release" } ], "words": 24 }
```

`state`: `none`, `created_not_finished`, `ready`, `restoring`. There is no role question (decision 4): setup never asks "member or host?". The state is saved (7.5).

### 12.2 Making keys

`POST /api/v1/wallet/create` (**S1**), `{ "confirm": "create_wallet", "passphrase": "…", "confirm_passphrase": "…" }`, with the setup session of 4.3. The passphrase becomes the wallet passphrase: the program sets up the encrypted storage with it (storage **set up**, 8.2), so every file is encrypted from the first write (owner decision 13). Its rules are storage 4.1's (4.2 above: NFC, at least 15 code points, at most 1,024 bytes, the blocklist, not the wallet's name or "gazpacho", not three or more of the wallet's own words in order; no composition rules). The interface normalises to NFC before sending and the program normalises again. A refusal answers `weak_passphrase` with `params.reason` and the counts (8.1), or `passphrases_differ`; the interface uses storage 14's wording ("This passphrase is too short (12 of 15 characters).") and offers "Suggest one" (storage 14). The words check of storage 4.1 runs against the words just made, before they are shown. The answer comes when the derivation and both files are written (about a second, 4).

```json
{ "words": ["…", "… 24 words"], "shown_until": "this_answer" }
```

- The program writes the key file and then the journal before answering (storage 7, step 4: the words are shown only after both exist), then wipes its own copies (12.7).
- **Sent once.** A second `create` answers `409 wallet_exists`, without words. Calls that carry the words take no `request_id`: an id store would have to keep the answer or a digest of the words (7.4), and neither may be kept. After a lost answer the person uses `reveal`, with the passphrase.
- After the answer the session is `normal` and its fresh-sign-in window starts (4.3, "The setup session").
- Errors: `wallet_exists`, `weak_passphrase`, `passphrases_differ`, `not_setup_session`, `rate_limited` (4.3).
- The interface says that the passphrase cannot be recovered: without it the files cannot be opened, and only the 24 words restore the wallet (12.4).

### 12.3 The 24 words

| Call | Release | Request | Answer | Notes |
|---|---|---|---|---|
| `POST /api/v1/wallet/phrase/reveal` | S1 | `{ "confirm": "show_words", "passphrase": "…" }` | `{ "words": [ … ] }` | **The passphrase in the request** (4.8, kind A). It runs storage's **words** operation: one derivation opens the words, which are sent and wiped (storage 9.2). No window covers it, the sign-in included |
| `POST /api/v1/wallet/phrase/check-start` | S1 | `{}` | `{ "check_id": "…", "positions": [3, 14, 22], "checks_left_today": 2, "expires_at" }` | A session only. The program chooses 3 positions at random and opens nothing: the positions are not secret, and starting a check costs nothing. A `check_id` lasts 10 minutes; a new `check-start` replaces any unused one |
| `POST /api/v1/wallet/phrase/check` | S1 | `{ "check_id", "passphrase": "…", "words": ["…", "…", "…"] }` | `{ "ok": true, "checked_at": … }` or `{ "ok": false }` | **The passphrase in the request** (kind A), carried by the call that compares, so the words are open only for the length of this one call (storage 9.2 step 3). **One answer per `check_id`**, which is then spent |
| `POST /api/v1/wallet/finish-setup` | S1 | `{ "preset": "everyday", "find": "browse" }` | `{ "state": "ready" }` | `preset`: `cautious`, `everyday`, `wide` (section 13.2). `find`: `browse`, `tell_me`, `join_for_me` (the last two set automatic joining, 1.0.0, with a fresh sign-in, 4.8; S1 accepts `browse` only). Errors: `no_wallet` |

**The backup check is not an oracle** (review F2). Draft 1 answered which positions were wrong, without a fresh sign-in and without a limit, which recovered the words in a few thousand guesses. Now:
- The answer says only `ok: true` or `ok: false` for the three words together, **never which position was wrong**. The interface says "One or more words did not match. Look at your written words again."
- A check carries the passphrase, so a session left open cannot make one (draft 2 asked for a fresh sign-in at `check-start`; storage 9.1 makes the passphrase a property of the cryptography instead).
- **The order inside `check`**: the passphrase limits of 4.3; then the daily limit below (refused before any derivation); then the derivation. A wrong passphrase answers `401 wrong_passphrase`, counts against the passphrase, **not** against the daily checks, and leaves the `check_id` usable. A right one saves the attempt (7.5) before the words are compared.
- **At most 3 checks in any 24 hours per wallet**, saved in the journal (7.5) so a restart does not reset them; a fourth answers `429 rate_limited` with `params.retry_after_s`.
- A failed check **ends the session** (4.9): the next check needs the passphrase again.
- The positions are new for every check, so answers from different checks cannot be combined about one position.
- With these limits a guesser learns one bit per check about three random positions, three times a day: nothing usable against 2,048 choices per word.

Test 23.2 item 35: no sequence of calls without the passphrase returns any information about any word, and no sequence of calls with it returns which position failed.

Words not yet written down raise `words_not_checked` (important). The interface may skip checking; the item stays until a check succeeds.

### 12.4 Restore from the words

`POST /api/v1/wallet/restore` (**S1**), `{ "words": ["…", "… 24 words"], "passphrase": "…", "confirm_passphrase": "…" }`, with the setup session of 4.3. The passphrase is new: it encrypts the restored wallet's files and need not be the old one. It follows storage 4.1's rules as at creation (12.2), and the session becomes `normal` when the call succeeds (4.3).

- Allowed only when no wallet exists (`setup.state = none`). Over an existing wallet: `POST /api/v1/wallet/replace` (1.0.0, `{ "confirm": "replace_wallet", "passphrase" }`, 4.8 kind A).
- Brings back keys and on-chain coins. Factories need a backup (12.6; 1.0.0). Answer `202`, `{ "state": "restoring" }`; the program writes the key file, marks the start as a restore (`journal.md` section 8.2: a new epoch), and scans the chain for the wallet's coins.
- `GET /api/v1/wallet/restore` (**S1**): `{ "state": "scanning_chain"\|"waiting_for_host"\|"done", "on_chain_found_sat": 48000, "factories": "need_backup"\|"restored"\|"none", "lost_seats": [ { "lobby_id", "name" } ] }`. While `scanning_chain` the wallet is `restoring` (11.2), `watching.state` is `nobody_restoring`, and nothing can be paid, joined or hosted (`wallet_restoring`). A restore from the words knows no factory, so attention `restored_factories_unknown` (11.4) stays until a backup is imported (1.0.0): the interface must never say that nothing needs watching because none is known.
- Errors: `bad_words` (`params.position` of the first word that is not in the word list, or `params.reason = "checksum"`: these describe what the person typed, not a stored secret), `wallet_exists`.

### 12.5 Backup state

`GET /api/v1/backup` (1.0.0; **S1 returns the `words` part only**)

```json
{
  "words": { "checked_at": 1793620800, "checks_left_today": 3 },
  "host_copy": { "on": true, "last_sent_at": 1794434520, "readable_by_host": false },
  "file": { "last_saved_at": null, "older_than_state": true, "factories_not_covered": ["fac_2d91"] },
  "guard": { "present": true }
}
```

`PUT /api/v1/backup/host-copy` (1.0.0), `{ "on": true, "confirm": "send_to_host" }`, fresh sign-in. Peer storage is not in Slice 1 (`messages.md` section 9).

### 12.6 Export and import

| Call | Release | Request | Answer |
|---|---|---|---|
| `POST /api/v1/backup/export` | 1.0.0 | `{ "confirm": "export_backup", "passphrase": "…" }` (4.8, kind A) | `200`, `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="gazpacho-signet-<date>.gzb"`: storage 11's profile 1 export, the journal's entries, the guard and the words' entropy, sealed, opening with the passphrase or the 24 words, at the key file's derivation cost or higher. Never a decrypted copy: the journal holds the held signed transactions, the history and every host's network address, and a downloads folder is often synchronised to a cloud service (review F15) |
| `POST /api/v1/backup/import` | 1.0.0 | Body: the file, `application/octet-stream`, at most 16 MiB | `{ "restore_id": "…", "stale": "no"\|"yes"\|"unknown", "lost_seats": [ { "lobby_id", "name" } ] }`. Fresh sign-in. The program checks the guard (`journal.md` section 8.3), imports the journal, restarts its core under a new epoch, and sends `reset` |
| `POST /api/v1/backup/ask-host` | 1.0.0 | `{ "host_key", "confirm": "ask_host" }` | `202`; the host's copy, when it arrives, is imported as above. Fresh sign-in |
| `GET /api/v1/backup/restore` | 1.0.0 | | `{ "state": "waiting_for_host"\|"waiting_for_chain"\|"done", "factories": [ { "id", "state": "restoring_unconfirmed"\|"current" } ] }` |

**What protects an exported file** (review N16). Once the file has left the program, no attempt limit applies: its only protection is the passphrase and the export's own key derivation (storage 3.3, 11). And a later passphrase change does not re-protect exports already made: they still open with the old passphrase (storage 4.7). The export button says both, in storage 14's words: "This file opens with your passphrase or your 24 words. Keep it as safely as your words: anyone who guesses your passphrase can use it." and "Changing your passphrase later does not change files you have already exported." The host's copy is storage 11's profile 2, which opens only with the words.

**A restored wallet never publishes from the backup** (`DESIGN.md` section 6). While waiting, every factory from the backup has state `restoring_unconfirmed` (section 16), its balance is not confirmed, and payments and leaving alone are refused with `wallet_restoring`. What the app may do if the host never answers is not decided **(open; critique question 15)**.

### 12.7 Rules for the 24 words

These hold for every call and screen that carries the words: `create`, `reveal`, `check` and `restore`. Each rule has a test (23.3).

**Where they may travel**
- **Over loopback only**, which is all this program serves (3.1), on the TCP socket to the interface and on the local socket to the command line.
- **Only in the bodies** of those four calls' requests or answers. Never in a path, a query string, a header, a cookie, an event, an error message, an activity entry, a log line or the `request_id` store (7.4; those calls take no id).
- Answers carrying them: `Cache-Control: no-store`, so no browser or proxy cache keeps them (5.4; test 23.3 item 4).

**When they are shown**
- At creation, in the `create` answer, once; and after that only by `reveal`, which carries the passphrase and the person's explicit request (12.3).
- The interface shows them only on their own screen, with a warning to make sure nobody is watching and nothing is recording the screen. Draft 2 hid them after 2 minutes; writing 24 words by hand and checking them takes most people longer, and a timer that hides them mid-writing pushes people towards a screenshot (review N9). Now (D9):
  - **shown until the person presses Done**;
  - **hidden** (the text nodes removed, the screen's variable kept) when the tab is hidden (`visibilitychange` to `hidden`), and shown again by "Show again" on the same screen, without a new request, while the screen is open;
  - **cleared** (the variable's array overwritten and released, below) on Done, on `pagehide`, on `freeze` where the browser has it (web.dev: Chromium only), when the screen closes, on sign-out and on lock, and at a **ceiling of 10 minutes** after they arrived (**proposed**). After that, showing them again is a new `reveal` with the passphrase.

**How the interface handles them**
- **Never kept in page storage**: not in `sessionStorage`, `localStorage`, IndexedDB, the cache API, a cookie, the history state, the page title or a URL. Only in text nodes while shown and in one variable of the screen that shows or collects them.
- **Cleared from the page after use**, at the moments above: the text nodes are removed, input fields emptied, and the variable's array overwritten and released. JavaScript cannot guarantee that a string is erased from memory; the interface drops every reference so it can be collected, and does nothing that would copy it further. The same clearing applies to the typed words of the check and restore screens on `pagehide` and `freeze`.
- **No clipboard copy**: no copy control of any kind, and `user-select: none` on the shown words. Those two are what keep the words off the clipboard. `clipboard-write=()` in the permissions policy (5.4) stays, but it limits only Chromium's asynchronous Clipboard API; Firefox and Safari do not act on the header (MDN Clipboard), and no browser lets it govern the person's own selection and copy (review N9). A person who selects the words with the keyboard or the developer tools can still copy them; the screen says to write them by hand. Writing them down by hand is the backup.
- **Word fields** (check and restore): one field per word, `autocomplete="off"`, `autocorrect="off"`, `autocapitalize="off"`, `spellcheck="false"` (a browser's enhanced spell-check service can send field text to a server), no browser password-manager hints, and an in-page list of matching words from the BIP 39 list instead of the browser's suggestions.
- **Asked for in two places only**: the restore screen, when no wallet exists, and the backup check, right after the words were shown or from the backup screen. Every screen that shows or asks for them says so (the defence against a fake interface on the port, 5.7).
- No word ever appears in an error the interface reports to anyone or anything, in a crash report, or in the console.

**How the program handles them**
- The words, the entropy and the seed derived from them are held in buffers that are **wiped** (with a wipe the compiler cannot remove, such as `explicit_bzero` or `SecureZeroMemory`) as soon as the call is answered: the request body, the parsed JSON values, the answer buffer after it is sent, and the key derivation's work space.
- Where the operating system allows, those buffers are locked out of swap (`mlock`, `VirtualLock`) while in use (**proposed**; best effort).
- They are never written anywhere but the key file (`wallet-keys.md` section 8), and never logged (test 23.3 item 1 searches every log, event and answer for them).
- Attempt limits: the backup check, 12.3; passphrase and codes, 4.3.

**The wallet passphrase** follows the same rules as the words, except that it is never shown: only in the bodies of the session, create, restore, unlock, change calls and the calls of 4.8 kind A; never logged, stored, cached, kept in page storage or put in a digest (7.4); its fields are password fields (`type="password"`, `autocomplete="new-password"` when set and `"current-password"` when typed, so a password manager can fill it: **default, owner to confirm**, 24.1 D14); normalised to NFC before sending (storage 4.1); the field is cleared as soon as the request is sent; wiped by the program after use (storage 8.4). No call answers with it.

**Password managers** (D14, with review N4's guidance). Settings, Application and the help on the passphrase screen say: a browser's own password manager offers a saved password only on the exact address it was saved for, port included, so it will not fill Gazpacho's passphrase into a page on another port (to be confirmed per browser, test 23.6 item T8). A separate password manager may match by domain only and ignore the port: set it to match the exact host and port (Bitwarden, for example, documents port matching only for its "Host" option, and says its Android clients "cannot currently match URIs based on port or path"; Bitwarden matching). No manager can tell a program squatting Gazpacho's own port while Gazpacho is stopped from Gazpacho itself (5.7).

**What these rules do not stop**, as for every software wallet: a browser extension with access to all sites, malware running as the same user, and a camera or a screen recorder pointed at the screen while the words are shown (5.7). Nor these copies, which outlive the page's own clearing (review N9):
- the `fetch()` response body and the strings `JSON.parse` made from it, which the page cannot overwrite;
- the values of input elements, held by the browser's renderer as strings;
- the developer tools, when open, which keep every response body;
- a page kept for back and forward navigation (reduced by `no-store` on the pages, 5.4, and the clearing on `pagehide`);
- crash reports and memory dumps of the browser, which can contain its heap;
- a browser's own session restore after a crash, for typed words (HTML asks that `autocomplete="off"` values be reset "when reactivating a document", which does not settle crash restore; test 23.6 item T7).

### 12.8 Removing the wallet

`POST /api/v1/wallet/remove` (1.0.0), `{ "confirm": "remove_wallet", "passphrase" }` (4.8, kind A). Refused with `409`, code `funds_inside`, while any factory holds a balance or a creation round is unresolved, unless `{ "confirm": "remove_wallet_with_funds_inside" }`; the answer then lists what would be lost without the words and a backup.

---

## 13. Conditions and terms

Two sides of one comparison (options map, scopes 1 and 2). They are never editable in the same place: conditions are written here; terms are read-only everywhere except where a host writes its own (section 15).

### 13.1 `GET /api/v1/conditions` (S1)

```json
{
  "version": 7,
  "preset": "everyday",
  "conditions": {
    "profiles": ["safety", "standard"],
    "min_members": 20,
    "min_channel_sat": 200000,
    "max_joining_fee_sat": 2000,
    "max_fee_base_msat": 2000,
    "max_fee_ppm": 1000,
    "max_receiving_room_fee_ppm": null,
    "min_life_blocks": 1008,
    "max_life_blocks": 6480,
    "max_exit_blocks": 1008,
    "min_confirmations": 3,
    "payment_sizes_sat": { "min": 100, "max": 200000 },
    "max_move_fee_sat": null,
    "seat_cost": "none",
    "compare_with": "whole_range",
    "host_min_factories_funded": 0,
    "host_proof_required": false,
    "hosts_trusted": [],
    "hosts_avoided": [],
    "people_blocked": [],
    "appear_as": "temporary_name",
    "move_to_next": "by_itself_if_fits"
  },
  "limits": { "min_members": [2, 512], "min_confirmations": [2, 100], "max_exit_blocks": [144, 4320] },
  "presets": [ { "id": "cautious", "conditions": { "…": "every number it sets" } }, { "id": "everyday", "…": "…" }, { "id": "wide", "…": "…" } ],
  "fit_summary": { "listed": 14, "fit": 3, "fits_only_now": 1, "excluded_most_by": { "condition": "max_joining_fee_sat", "yours": 2000, "lobbies_excluded": 6 } },
  "copied_into": [ { "lobby_id": "lob_7k2q", "copied_at": 1794427320, "version": 6 } ],
  "editable": true
}
```

- **Presets** (concept H: `cautious`, `everyday`, `wide`) are starting sets for the member's conditions. "Profile" means only the host's lobby type (`safety`, `standard`, `starter`, `circle`). Changing any number makes `preset` `custom`. The numbers behind each preset are **(open; critique question 13)**; the program is their one source.
- `compare_with`: `whole_range` (default, decision 1) or `current_value` (the looser choice: ready while the current value fits; un-ready when it moves outside).
- `editable` is `false` only during the seconds of signing (`signing_now`).
- Fields marked 1.1.0 (`max_receiving_room_fee_ppm`) or open (`max_move_fee_sat`, `seat_cost`, `host_proof_required`) are present and `null` or default. S1 compares `profiles`, `min_members`, `min_channel_sat`, `max_joining_fee_sat`, `max_fee_base_msat`, `max_fee_ppm`, `min_life_blocks`, `max_life_blocks`, `max_exit_blocks` and `min_confirmations`: the terms Slice 1's record carries (`terms.md` section 3).
- `people_blocked`, `hosts_trusted`, `hosts_avoided`, `appear_as`: 1.0.0. `appear_as`: `temporary_name`, `nostr_key` (later reserved), `free_text` (later reserved).
- The routing limit is **not** here; it is in Settings, Wallet (critique question 12).

### 13.2 Preview and save

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `POST /api/v1/conditions/preview` | S1 | `{ "conditions": {…} }` | `{ "fit_summary", "would_leave": [ { "lobby_id", "failures" } ], "loosens": ["max_joining_fee_sat"], "problems": [ { "field", "code" } ] }`. Changes nothing. `loosens` lists every field whose new value lets the app sign something the current conditions would refuse (a higher maximum, a lower minimum, a wider list, `compare_with` changed to `current_value`), computed by the program. The interface calls it as the person types (the live "why" line) | `bad_value` |
| `PUT /api/v1/conditions` | S1 | `{ "conditions": {…}, "based_on_version": 7, "preset": "custom", "confirm_loosens": ["max_joining_fee_sat"] }` | The new `GET` answer, plus `left_lobbies` | `changed_elsewhere`, `bad_value`, `signing_now`, `below_floor` (`min_confirmations` under the app's floor), `fresh_sign_in_needed` and `confirm_mismatch` (below) |

**Loosening needs the person, freshly** (4.8). When the program's own comparison finds that the new conditions loosen any value, the call needs a fresh sign-in, and `confirm_loosens` must list exactly the loosened fields (`confirm_mismatch` otherwise). Tightening, or a change that loosens nothing, needs neither; `confirm_loosens` is then `[]` or absent.

**The copying rule** (accepted by the owner for Slice 1, 2026-11-12: limits stay editable; tightening leaves a joined lobby that no longer fits, loosening affects only future joins): conditions are copied into a lobby at the moment of joining. The copy is saved in the same journal batch as the `joined` record (7.5), so after a restart the ready check and the signing check compare against the copy, not against conditions loosened since. Tightening them later makes the app leave a joined lobby that no longer fits, before it starts, and say so (`left_lobbies`). Loosening them applies to future joins only. Values are checked again at the ready check, against the real tree at signing (C8), and at each move.

### 13.3 The terms object (the host's, sealed)

Every place that shows a lobby's or factory's terms returns this shape. It is built from the two signed records of `terms.md` and never edited.

```json
{
  "fingerprint": "7f3a…(64 hex)",
  "fingerprint_short": "7f3a…c21e",
  "host": { "key": "02…", "alias": { "text": "Tomato Garden", "by": "host", "checked": false } },
  "signatures_checked": true,
  "outer": {
    "chain": "signet",
    "profile": "standard",
    "target": 50, "minimum": 30, "deadline_at": 1794441600, "on_shortfall": "cancel",
    "ready_window_ms": 60000, "signing_budget_ms": 600000, "step_timeout_ms": 60000,
    "lifetime_blocks": 4752, "winddown_blocks": 432,
    "channel_sat": 500000,
    "tree_feerate_sat_per_kvb": 100,
    "switches": { "names": false, "chat": false, "rule_requests": false },
    "shape": [ { "max_members": 4, "interior": [], "leaf": "one_member" }, { "max_members": 16, "interior": [4], "leaf": "one_member" } ],
    "description": { "text": "…", "by": "host", "checked": false }
  },
  "ranges": {
    "joining_fee_sat": { "min": 500, "max": 1500 },
    "fee_base_msat": { "min": 1000, "max": 1000 },
    "fee_ppm": { "min": 300, "max": 800 }
  },
  "current": { "version": 3, "digest": "…", "values": { "joining_fee_sat": 1000, "fee_base_msat": 1000, "fee_ppm": 500 } },
  "frozen": null,
  "derived": {
    "exit_blocks": 864,
    "depth": 2,
    "funding_at_minimum_sat": 22500000,
    "funding_at_target_sat": 37500000
  },
  "reserved": { "receiving_room_fee_ppm": null, "joining_fee_chain_share": null, "newcomer_seats_pct": null, "invitation_only": null }
}
```

- `frozen`: `null` before the ready check; then `{ "version", "digest", "at", "check_id" }`. After it, `current` equals the frozen values and nothing moves (`terms.md` section 8).
- A range whose `min` equals its `max` is a fixed value; the interface shows it without "may move".
- `derived` is computed by the program from the terms (`terms.md` section 4.2), never by the interface.
- `reserved` names the record types `terms.md` reserves (70, 72, 36, 38). An offer that carries any of them is refused by a program built to `terms.md` draft 2, so they are `null` until `terms.md` makes a type valid. Invitation-only lobbies (type 38) are part of 1.0.0 by owner decision 10, so `invitation_only` is expected to become a real term in 1.0.0, when `terms.md` and the invitation messages define it (24.2 item 8).
- `GET /api/v1/lobbies/{id}/terms/sealed` (1.0.0) returns the four signed byte strings as hex, for "Read the sealed terms" and for anyone who wants to check the signatures elsewhere. They are public records, not secrets.

### 13.4 The fit check

Returned with every lobby and every saved copy.

```json
{
  "class": "fits",
  "compared_with": "whole_range",
  "conditions_version": 7,
  "rows": [
    { "term": "profile", "offered": "standard", "yours": ["safety", "standard"], "result": "fits" },
    { "term": "members", "offered": { "minimum": 30, "target": 50 }, "yours": 20, "result": "fits" },
    { "term": "joining_fee_sat", "offered": { "min": 500, "max": 1500, "now": 1000 }, "yours": 2000, "result": "fits" },
    { "term": "life_blocks", "offered": 4752, "yours": { "min": 1008, "max": 6480 }, "result": "fits" }
  ],
  "counted_from": 30
}
```

| Field | Values |
|---|---|
| `class` | `fits`, `fits_only_now`, `does_not_fit` (`terms.md` section 9). `fits_only_now` is listed with the lobbies that do not fit and is not counted in `fit_summary.fit` (decision 6) |
| `rows[].result` | `fits`, `fits_now_only` (the current value fits; the range does not), `fails`, `not_compared` (a 1.1.0 or open term absent from these terms) |
| `rows[].term` | `profile`, `members` (compared with the signed **minimum**, critique question 5), `channel_sat`, `joining_fee_sat`, `fee` (base and proportion together), `life_blocks`, `exit_blocks`, `confirmations`, `payment_sizes`, `host_record`, `host_avoided`, `people_blocked`, `move_fee`, `seat_cost`, `receiving_room_fee` (1.1.0) |
| `counted_from` | The number of ready members from which this member is counted: the larger of the lobby's minimum and the member's own |

---

## 14. Lobbies

### 14.1 The lobby object

`GET /api/v1/lobbies` returns rows; `GET /api/v1/lobbies/{id}` the full object.

```json
{
  "id": "lob_7k2q",
  "fingerprint": "7f3a…(64 hex)",
  "name": { "text": "Tomato Garden, daily factory", "by": "host", "checked": false },
  "host": { "key": "02…", "alias": { "text": "Tomato Garden", "by": "host", "checked": false }, "address": "tomato.example:9735", "record": null },
  "source": "direct_query",
  "listed": true,
  "stage": "open",
  "terms": { "...": "13.3" },
  "fit": { "...": "13.4" },
  "start_rule": { "target": 50, "minimum": 30, "deadline": { "...": "a date, kind lobby_starts_by" }, "on_shortfall": "cancel" },
  "counts": { "joined": 38, "ready": 38 },
  "you": {
    "seat": "ready",
    "ready_for_version": 3,
    "counted": true,
    "conditions_copied_at": 1794427320,
    "appear_as": { "text": "Lemon-39", "by": "you", "checked": false },
    "standby": null,
    "outcome": null
  },
  "round": null,
  "funding": null,
  "factory_id": null,
  "members": null,
  "terms_change": null
}
```

| Field | Values |
|---|---|
| `id`, `fingerprint` | The local id (7.3), used in paths; the rules fingerprint, in this body only |
| `host.address` | Validated against section 21's grammar before the lobby is kept (5.6) |
| `source` | `direct_query`, `invitation` (1.0.0), `nostr` (1.0.0), `beacon` (later reserved), `typed_address` |
| `stage` | `open`, `ready_check`, `signing`, `funding`, `active`, `cancelled`, `failed`, `unknown` (`messages.md` section 6, lobby states 0 to 7) |
| `you.seat` | `none`, `joining` (sent, no answer yet), `joined_not_ready`, `ready`, `chosen`, `not_chosen`, `left`, `removed`, `refused_by_host` (`messages.md` seat states 0 to 7, plus `joining`) |
| `you.counted` | `false` while fewer than `fit.counted_from` are ready |
| `you.standby` | Standby seats (owner decision 10; **S1, provisional**, 2.1): `null`, or `{ "position": 2, "of": 4, "since_at" }` while this member waits as a standby for a seat that becomes free before the ready check. `you.seat` is then `joined_not_ready` or `ready` as for any seat, and `you.counted` is `false`. The program answers `null` until the protocol has standby messages (`messages.md` section 9) |
| `you.outcome` | `null`, or an object below |
| `round` | `null`, or the member's creation round below |
| `funding` | `null`, or `{ "txid", "state", "confirmations", "needed", "deadline": { a date, kind funding_deadline }, "amount_sat" }` |
| `members` | `null` when the host shows no names (always in Slice 1); otherwise `[ { "seat", "name": { text }, "ready", "you", "blocked" } ]` (1.0.0) |
| `terms_change` | `null`, or `{ "from_version", "to_version", "at", "changes": [ { "term", "from", "to" } ], "effect": "still_fits"\|"unreadied"\|"left" }` |

**`you.outcome`**: what happened to this member in this lobby. Each value is distinct because the wording differs (section 22).

**How the outcome is decided** (review F3). From the member's **own saved round state** (`journal.md` records `round_started`, `exposure`, `round_ended`; `signing-round.md` section 7), never from a host's message:

1. If the member saved an `exposure` record, that is sent a partial signature, **in any attempt of this lobby**, the outcome is the state of that round: `signing_unfinished` while it is Unfinished, then `abandoned`, `dead` or `started`. A `cancel` or `round_abort` from the host changes nothing (`messages.md` 6.10: "A `cancel` does not undo partial signatures already sent"; `signing-round.md` section 7: a `round_abort` to a member in Signed or Unfinished "changes nothing"). It is shown only as `cancel_received: { "reason" }` on the outcome, for information.
2. Otherwise, the first that applies of: `refused_at_check`, `aborted_before_signatures`, `refused_by_host`, `removed`, `left`, `cancelled`, `not_chosen`.

So `cancelled` (and `doing.code = lobby_cancelled`) can only be reached by a member that never sent a partial signature in the lobby. Test 23.1 item 12.

| `code` | Meaning | "Nothing was signed"? |
|---|---|---|
| `refused_at_check` | The app refused before any nonce or signature. `failures` with both numbers; `which`: `conditions`, `safety_check`, `fingerprint_differs`, `values_differ_from_frozen` | Yes |
| `aborted_before_signatures` | The round stopped after nonces but before any partial signature (`signing-round.md`: Aborted). `reason` from `messages.md` 7.9 | Yes |
| `refused_by_host` | The host refused this member's seat (seat state 7). `reason` from `lobby_status` | Yes |
| `not_chosen` | Ready, but the start went ahead without this member | Yes |
| `cancelled` | The lobby was cancelled **and no partial signature was ever sent in it**. `reason`: `deadline_below_minimum`, `host_choice`, `signing_budget_spent`. `not_your_doing: true` unless the member's own leave caused it | Yes |
| `left` | The member left before sending anything in a round. `reason`: `user`, `paused`, `conditions_tightened`, `host_fault_seen` (with `activity_id` for the evidence) | Yes |
| `removed` | The host removed this seat before the ready check | Yes |
| `signing_unfinished` | Partial signatures went out; no result came back. Both outcomes stay possible. `cancel_received` if the host sent `cancel` | **No** |
| `abandoned` | Unfinished or unfunded past its deadline. Records kept; the member owes and is owed nothing. **`still_watched: true`** while the funding could still appear: an abandoned creation becomes live if its funding is buried later and the time checks pass again (`safety-rule.md` C11; `signing-round.md` section 7). The interface never says it is over while `still_watched` is `true` | **No** |
| `dead` | A funding input was spent elsewhere and buried; the factory can never exist. `still_watched: false` | **No** |
| `started` | Signed and complete; see `funding` and `factory_id` | **No** |

A member who leaves (or pauses) after sending partial signatures keeps the round's outcome (`signing_unfinished` and onwards), never `left` (`messages.md` 6.6).

**`round`** (the member's creation round, `signing-round.md` section 7):

```json
{ "state": "signed", "attempt": 1, "signatures": { "done": 11, "of": 17 }, "sent_at": 1794434404, "last_heard_at": 1794434404, "checked_to_height": 330449, "unfinished_deadline": { "...": "a date" }, "checks": [ { "check": "fingerprint_same", "ok": true }, { "check": "frozen_values_inside_limits", "ok": true }, { "check": "tree_inside_conditions", "ok": true, "params": { "members": 50 } }, { "check": "safety_checks", "ok": true } ] }
```

`state`: `checking`, `nonces_sent`, `signed`, `complete`, `awaiting_funding`, `live`, `aborted`, `unfinished`, `abandoned`, `dead`. These are exactly the member states of `signing-round.md` section 7, so the interface can show the signing checklist (concept H, borrowed from E) from the program's own checks.

### 14.2 Calls

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `GET /api/v1/lobbies` | S1 | `?show=fits\|all&sort=fit\|start\|joining_fee\|channel&cursor&limit` | Page of rows: `id`, `fingerprint`, `name`, `host`, `source`, `stage`, `fit.class`, the failing rows' terms, `counts`, `start_rule`, `terms.outer.channel_sat`, `terms.ranges.joining_fee_sat`, `derived.exit_blocks`, `you.seat`. Includes every lobby the program knows and every lobby the member is in; not the program's own hosted lobbies (section 15) | |
| `GET /api/v1/lobbies/{id}` | S1 | | The lobby object | `not_found` |
| `POST /api/v1/lobbies/{id}/join` | S1 | `{ "request_id", "seen_current_digest": "…", "ready": true }` | `202`, the lobby object with `you.seat = "joining"` | `not_open`, `conditions_not_met` (with failures), `fits_only_now` (the member did not choose the looser comparison), `terms_changed` (the digest the person reviewed is no longer current: show the change, then ask again), `already_in_lobby` (S1 allows one joined lobby at a time, owner 2026-11-12), `paused`, `chain_in_doubt`, `needs_invitation`, `host_unreachable`, `lobby_full`, `host_avoided`, `wallet_restoring` |
| `PUT /api/v1/lobbies/{id}/ready` | S1 | `{ "request_id", "ready": true\|false, "seen_current_digest" }` | `202`, the lobby object | `not_joined`, `conditions_not_met`, `terms_changed`, `too_late` (a round is under way), `paused` (for `true`) |
| `POST /api/v1/lobbies/{id}/leave` | S1 | `{ "request_id" }` | `202`, the lobby object | `not_joined`, `too_late` (partial signatures are out: the member may stop looking, but the round stays Unfinished; the answer carries `round`) |
| `PUT /api/v1/lobbies/{id}/members/{seat}/blocked` | 1.0.0 | `{ "blocked": true }` | The member row | `names_off`, `not_joined` |
| `POST /api/v1/invitations` | 1.0.0 | `{ "text": "<the link or QR text>" }` | `{ "lobby_id" }`; the lobby is fetched and appears in the list | `bad_invitation`, `wrong_network` |
| `GET /api/v1/lobbies/{id}/terms/sealed` | 1.0.0 | | 13.3 | |
| `POST /api/v1/lobbies/{id}/rule-request` | later reserved | | | |
| `GET /api/v1/lobbies/{id}/chat` | later reserved | | | |

**Joining is consent.** `seen_current_digest` must be the `terms.current.digest` the person reviewed. When the lobby starts, the app signs without asking (options map, "never a setting"). If anything differs at signing from what was reviewed (fingerprint, values outside the frozen ones, the tree against the conditions, any safety check), it refuses before sending anything. `seen_current_digest` is the join's echo (4.8); joining needs no fresh sign-in, because it spends none of the member's coins in 1.0.0 (default D4, 24.1).

---

## 15. Hosting

Hosting is always available (decision 4). Every call here acts on lobbies and factories **this program hosts**. Lobbies and factories are addressed by the same local ids as in section 14 (`lob_…`, `fac_…`, 7.3); the rules fingerprint appears only in body fields named `fingerprint`.

### 15.1 Writing terms, with a preview

`POST /api/v1/host/preview` (**S1**) takes a draft and changes nothing.

Draft:

```json
{
  "name": "My first lobby",
  "description": "Weekdays only.",
  "profile": "standard",
  "target": 50, "minimum": 30, "deadline_at": 1794528000, "on_shortfall": "cancel",
  "ready_window_ms": 60000, "signing_budget_ms": 600000, "step_timeout_ms": 60000,
  "lifetime_blocks": 4752, "winddown_blocks": 432,
  "channel_sat": 500000, "tree_feerate_sat_per_kvb": 100,
  "shape": "default",
  "joining_fee_sat": { "now": 1000, "min": 500, "max": 1500 },
  "fee_base_msat": { "now": 1000, "min": 1000, "max": 1000 },
  "fee_ppm": { "now": 500, "min": 300, "max": 800 },
  "listed": true,
  "switches": { "names": false, "chat": false, "rule_requests": false },
  "reserved": { "spare_liquidity_sat": null, "receiving_room_fee_ppm": null, "admission": null, "newcomer_seats_pct": null, "invitation_only": null, "move_window": null }
}
```

Answer:

```json
{
  "draft_digest": "…",
  "as_members_see_it": { "...": "a terms object (13.3), fingerprint null, signatures_checked false" },
  "funding_at_minimum_sat": 22500000,
  "funding_at_target_sat": 37500000,
  "chain_fee_estimate_sat": 1000,
  "wallet_free_sat": 42000000,
  "set_aside_elsewhere_sat": 0,
  "covers": { "minimum": true, "target": true },
  "dates": [ { "...": "dates (7.2): lobby_starts_by, move_window_opens, factory_ends" } ],
  "host_deadlines": [ { "...": "dates: host_fund_by, host_online_for_try" } ],
  "problems": [ { "field": "/target", "code": "target_below_minimum" } ],
  "can_open": false,
  "cannot_open_because": ["funds_short"]
}
```

| `problems[].code` | Meaning |
|---|---|
| `name_missing`, `deadline_missing`, `deadline_past` | |
| `minimum_too_small`, `target_below_minimum`, `target_too_large` | Bounds of `terms.md` section 3 |
| `channel_too_small`, `life_too_short`, `budget_below_step` | |
| `range_inverted`, `now_outside_range` | |
| `shape_invalid` | The shape table fails `terms.md` section 4.3 for some member count |
| `profile_not_in_slice` | Slice 1 accepts Standard only |
| `on_shortfall_not_in_slice` | Slice 1 accepts `cancel` only |
| `reserved_term_set` | A `reserved` field is not `null` |

`cannot_open_because`: `problems`, `funds_short`, `no_wallet`, `chain_in_doubt`, `already_hosting` (S1 allows one hosted lobby at a time, owner 2026-11-12), `host_node_missing` (1.0.0, once payments need the host's Lightning node; not in Slice 1).

`shape`: `default` lets the program choose shapes by `terms.md` section 4 and the scale-check rules (`DESIGN.md` section 7); an explicit table is accepted in the same form as `outer.shape`.

### 15.2 Opening, running and ending a lobby

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `POST /api/v1/host/lobbies` | S1 | `{ "request_id", "draft": {…}, "draft_digest": "…", "confirm_funding_sat": 37500000, "passphrase": "…" }`. **The passphrase in the request** (4.8, kind A) | `201`, the host's lobby object (15.3). The program signs the outer rules and current values version 1, saves them (`lobby_opened`, with the set-aside amount, 7.5) and starts answering `hello`. Opening sets aside the funding at the target, and is the host's consent to spend up to that amount when the start rule is met | `draft_changed` (the draft does not match the digest that was previewed), `confirm_mismatch` (`confirm_funding_sat` is not the preview's `funding_at_target_sat`), `wrong_passphrase`, `rate_limited`, every `cannot_open_because` value |
| `GET /api/v1/host/lobbies` | S1 | `?state=open\|funding\|running\|ended&cursor` | Page of host lobby rows | |
| `GET /api/v1/host/lobbies/{id}` | S1 | | 15.3 | `not_found`, `not_host` |
| `POST /api/v1/host/lobbies/{id}/start` | S1 | `{ "request_id", "confirm_funding_max_sat": 37500000 }`. **Fresh sign-in** (4.8). An **early** start only (below) | `202`, `stage: "ready_check"` | `below_minimum` (`params.ready`, `params.minimum`), `not_open`, `funds_short`, `chain_in_doubt`, `paused`, `confirm_mismatch`, `fresh_sign_in_needed` |
| `POST /api/v1/host/lobbies/{id}/cancel` | S1 | `{ "request_id" }` | `202`, `stage: "cancelled"`; set-aside funds are free again | `too_late` (signing has begun: a round runs to its end within its budget; the host cannot take back what members signed) |
| `POST /api/v1/host/lobbies/{id}/values` | 1.0.0 | `{ "request_id", "based_on_version": 3, "values": { "joining_fee_sat": 1200 } }` | The lobby, with the new current version, signed and sent to every seat | `frozen`, `outside_range`, `changed_elsewhere` |
| `DELETE /api/v1/host/lobbies/{id}/seats/{seat}` | S1 (**provisional**, 2.1) | `{ "request_id", "confirm_seat": "<the seat>", "reason": "…" }` in body. Fresh sign-in (4.8, kind B) | `202`; the seat goes to state 6, "removed" (`messages.md`), the member is told through `lobby_status`, and, once standby seats have their messages, the first standby takes the place | `frozen` (no removal after the ready check, critique H.3), `not_host`, `confirm_mismatch`, `fresh_sign_in_needed` |
| `POST /api/v1/host/lobbies/{id}/invitations` | 1.0.0 | `{ "expires_at": … }` | `{ "text": "…", "qr_svg_data": "…" }`: the link and the QR's contents. Their exact form and expiry are **(open)** | `not_host` |
| `GET /api/v1/host/lobbies/{id}/requests` | 1.0.0 | `?cursor` | Page of `{ "id", "who": { "kind": "temporary"\|"nostr_key", "label" }, "asked_at", "note": { "text", "by": "you" } }` | |
| `POST /api/v1/host/lobbies/{id}/requests/{rid}/approve` | 1.0.0 | `{}` | `204` | `not_waiting` |
| `POST /api/v1/host/lobbies/{id}/requests/{rid}/refuse` | 1.0.0 | `{ "reason": "…" }` | `204` | |
| `PUT /api/v1/host/lists` | 1.0.0 | `{ "always_allow": ["key"], "always_refuse": ["key"] }` | The lists | |
| `PUT /api/v1/host/notes/{key}` | 1.0.0 | `{ "text": "…" }` (kept on this machine only) | | |

Join requests need admission by approval, which has no protocol messages yet (`messages.md` section 9: "Invitations, identities … no messages yet"). The calls are fixed now; they work once the protocol has them **(open)**.

**Starting** (review gap G2). The host's program applies the start rule **by itself** (`LOBBY.md`, "Start rule"; `messages.md` 6.8, "sent when the start rule is met"), with no call from the interface:

| Situation | What the host's program does |
|---|---|
| Ready seats reach the target | Runs the ready check at once |
| The deadline arrives with at least the minimum ready | Runs the ready check at the deadline |
| The deadline arrives below the minimum | Cancels the lobby (`cancel` reason 1; `on_shortfall` is `cancel` only in Slice 1) and frees the set-aside funds |
| The person presses Start, with at least the minimum ready, before the target and the deadline | Runs the ready check now (`POST …/start`, an early start; attention `host_can_start` says it is possible) |
| Pause is on | Runs no ready check, by the rule or by `start`; at the deadline the lobby is cancelled (11.3) |
| The chain view is in doubt at the moment the rule is met | Waits; runs the check as soon as the view is trusted, or cancels at the deadline if it never is |

The automatic start needs no fresh sign-in: the person consented to the spend, with its amount echoed, when opening. After a ready check that does not lead to a start, the lobby returns to Open and the same rule applies again (`messages.md` 6.9). A host never signs funding before every member's signed tree is complete and verified (H1). The ready check is followed by signing and funding by themselves, shown in `stage`, `round` and `funding`.

### 15.3 The host's lobby object

```json
{
  "id": "lob_4c08",
  "fingerprint": "4c08…(64 hex)",
  "name": { "text": "My first lobby", "by": "you", "checked": false },
  "stage": "open",
  "terms": { "...": "13.3, as signed" },
  "counts": { "joined": 22, "ready": 22 },
  "can_start_now": false,
  "start_blocked_by": ["below_minimum"],
  "funding": { "needed_at_minimum_sat": 22500000, "needed_at_target_sat": 37500000, "set_aside_sat": 37500000, "wallet_free_sat": 4500000 },
  "seats": [ { "seat": "a19c…", "name": { "text": "Fig-12", "by": "member", "checked": false }, "state": "ready", "joined_at": … } ],
  "round": { "state": "collecting_nonces", "attempt": 1, "answered": 20, "of": 22, "silent": 2 },
  "listing": { "published": ["direct_query"], "renew_by": null },
  "funding_tx": null,
  "factory_id": null
}
```

- `round.state` (host, `signing-round.md` section 7): `collecting_nonces`, `collecting_signatures`, `tier_result`, `complete`, `collecting_acks`, `funding`, `funded`, `failed` (with `params.silent` and `params.invalid` counts; the host's claim that a member was silent is shown as a claim only, threat model 2.1).
- `seats[].state` uses the seat values of 14.1 from the host's side. `seats[].can_remove` is `true` before the ready check (15.2, provisional S1).
- `standby` (**S1, provisional**, 2.1): `null`, or `{ "waiting": 3, "seats": [ { "seat", "name", "since_at" } ] }`. `null` until the protocol has standby messages.
- `funding_tx`: `{ "txid", "state", "confirmations", "needed", "broadcast_at" }`.

### 15.4 Host factories, setup and earnings

| Call | Release | Notes |
|---|---|---|
| `GET /api/v1/host/factories` | 1.0.0 | The ladder: each factory with `state`, members, funds in it, next date. S1 shows the hosted factory through `GET /api/v1/factories/{id}` |
| `GET /api/v1/host/factories/{id}` | 1.0.0 | Members not moved, silent members, deadlines the host must meet (dates), funds, fee funds held ready, changes left |
| `POST /api/v1/host/factories/{id}/force-path` | 1.0.0 | `{ "seat", "preview_id", "confirm_cost_sat", "passphrase" }`. Preview first: `POST …/force-path/preview` gives cost and time. The passphrase in the request (4.8, kind A) |
| `POST /api/v1/host/factories/{id}/wind-down` | 1.0.0 | With rotation (M4) |
| `POST /api/v1/host/factories/{id}/force-close` | 1.0.0 | Preview, then `{ "preview_id", "confirm_cost_sat", "passphrase" }` (4.8, kind A) |
| `POST /api/v1/host/factories/{id}/sell-room` | 1.1.0 reserved | Sales of receiving room |
| `GET /api/v1/host/earnings` | 1.0.0 | `?period=30d\|factory\|all`. Fees received, on-chain costs, idle funds. "Spare liquidity not yet sold" is a 1.1.0 field, `null` in 1.0.0 |
| `GET /api/v1/host/setup`, `PATCH /api/v1/host/setup` | 1.0.0 | Host name, publish record, contact address, funds limits (`max_per_factory_sat`, `max_total_sat`), public address, saved terms templates. The host key cannot change while a lobby or factory is open (`key_in_use`). Raising a funds limit or changing the key needs a fresh sign-in and the new values echoed (4.8) |
| `PUT /api/v1/host/node`, `POST /api/v1/host/node/test`, `DELETE /api/v1/host/node` | 1.0.0 | The host's Lightning node, under the rules of 15.5. Fresh sign-in. Not in Slice 1 |
| `PUT /api/v1/host/schedule` | later reserved | Open a lobby by itself on a schedule |
| `POST /api/v1/host/backup` | 1.0.0 | The host's own backup, as 12.6's export. The passphrase in the request (4.8, kind A) |

### 15.5 The host's Lightning node (1.0.0)

Draft 1 let any session point the program at any file and any address and then "test" it, which would send the file's bytes, a phrase file or the journal among them, to whoever runs that address (review F4). The rules now:

| Call | Request | Answer | Errors |
|---|---|---|---|
| `PUT /api/v1/host/node` | `{ "kind": "lnd"\|"cln", "address": "<host>:<port>", "confirm_address": "<the same>", "access_file": "<path>", "certificate_file": "<path>" }`. Fresh sign-in | `{ "kind", "address", "certificate_sha256", "access": "macaroon"\|"rune", "saved_at" }`. Neither file's contents ever reach the browser | `confirm_mismatch`, `bad_address`, `file_refused` (`params.reason`, below), `fresh_sign_in_needed` |
| `POST /api/v1/host/node/test` | `{ "confirm_address": "<the saved address>" }`. **No address and no path**: only the saved setting is used. Fresh sign-in | One entry each for `pay`, `hold`, `settle`, `cancel` | `no_node_saved`, `certificate_mismatch`, `confirm_mismatch` |
| `DELETE /api/v1/host/node` | `{ "confirm_address" }`. Fresh sign-in | `204` | |

- **Which files may be read.** Each path must resolve, after following links, to a **regular file** owned by the user and **outside the program's data folder** and outside the folder of the key file; it must be at most 16 KiB; and its contents must have the expected form: for `lnd`, a binary macaroon (version byte 2) and a PEM certificate; for `cln`, a rune in base64url and a PEM certificate. Otherwise `file_refused`, with `params.reason` one of `not_regular`, `inside_data_folder`, `too_large`, `wrong_form`, `not_owner`. The file is read when the setting is saved; its contents are kept in memory only and re-read at unlock. **Every read, the first and each re-read, runs every check again** (review residual of F4), and checks the file it actually opened: the path is resolved once (following links, as above), the resolved path is opened without following a final link (for example `O_NOFOLLOW` on POSIX), and owner, type and size are taken from the open descriptor (`fstat`, or its Windows equivalent), so a link swapped in after the check is never read.
- **Where the credential may go.** Only to the saved address, and only after a TLS handshake whose server certificate is exactly the one in the saved `certificate_file` (pinned by its SHA-256). A handshake that fails the pin sends nothing and answers `certificate_mismatch`. So the credential never reaches any address the person did not confirm with a fresh sign-in, and never a server that cannot prove it is that node.
- **No other call reads a path.** `POST /api/v1/discovery/query` and `POST /api/v1/settings/connections/servers` take an address, never a path, and send no stored credential to it: a discovery query is a BOLT 8 handshake and lobby messages (`discovery.md`), a chain-server check is a public request. Both reveal this machine's network address to the address given, as the interface says (section 21).

---

## 16. Factories

### 16.1 The factory object

`GET /api/v1/factories` (**S1**): every factory this program is in or hosts, live and past, newest first, paged. `GET /api/v1/factories/{id}` (**S1**):

```json
{
  "id": "fac_2d91",
  "fingerprint": "2d91…(64 hex)",
  "lobby_id": "lob_2d91",
  "name": { "text": "Tomato Garden, factory 12", "by": "host", "checked": false },
  "role": "member",
  "state": "live",
  "host": { "key": "02…", "alias": { "text": "Tomato Garden", "by": "host", "checked": false }, "link": "connected", "last_heard_at": 1794434390 },
  "members": 50,
  "terms": { "...": "13.3, frozen" },
  "saved_copy_activity_id": "act_1001",
  "funding": { "txid": "…", "vout": 0, "amount_sat": 37500000, "state": "buried", "confirmations": 1006, "needed": 3, "height": 329431 },
  "tree": {
    "depth": 2,
    "levels": [ { "kind": "fixed", "width": 4 }, { "kind": "fixed", "width": 2 } ],
    "path": [ { "level": 1, "index": 1, "of": 4, "members_below": 13 }, { "level": 2, "index": 0, "of": 2, "members_below": 1 } ],
    "leaf": "one_member"
  },
  "channel": { "capacity_sat": 500000, "balance_sat": 182400, "receivable_sat": 317600, "covered_sat": null },
  "channels": null,
  "dates": [ { "...": "dates (7.2): open_app_by, move_window_opens, move_by, start_leaving_by, factory_ends" } ],
  "exit": { "amount_sat_estimate": 181200, "fee_sat_estimate": 1200, "blocks": 66, "transactions": 5, "needs": ["app_running", "fee_coins"], "fee_paid_from": "anchors" },
  "exit_progress": null,
  "move": null,
  "unfinished_round": null,
  "trouble": [],
  "host_view": null
}
```

**`state`**

| Value | Meaning | Release |
|---|---|---|
| `awaiting_funding` | Signed; the funding is not buried yet. Not live: no paying or receiving (C11) | S1 |
| `live` | The funding is buried to `needed` confirmations as seen by two servers, and the app holds the whole signed tree | S1 |
| `funding_reorganised` | Was live; the funding was un-confirmed by a reorganisation. Signing stopped until it is buried again | S1 (value) |
| `abandoned` | Never funded in time, or the result never came; nothing owed. Carries `still_watched` (below) | S1 |
| `dead` | Can never be funded | S1 |
| `restoring_unconfirmed` | From a backup; waiting for current data. Balance not confirmed | 1.0.0 |
| `winding_down` | The move window is open or near | 1.0.0 |
| `host_not_answering` | | 1.0.0 |
| `moving` | A move try is under way | 1.0.0 |
| `move_unfinished` | A move try's signatures went out and no result came back | 1.0.0 |
| `left_behind` | The group moved on without this member | 1.0.0 |
| `exiting` | Leaving alone, step by step | 1.0.0 |
| `ended` | Over. `ended_how`: `all_signed_close`, `moved`, `left_alone`, `host_timeout` (Slice 1's signet recovery, `safety-rule.md` section 12 point 2), `forced_by_host`, `void_funding` (a funding input of a live factory spent elsewhere and buried, `spec/exit.md` 7 C-h; 1.0.0) | S1 (`host_timeout`) |

- **`funding.needed`** (review gap G6): for a member, the larger of the program's floor and the member's `min_confirmations` **as copied at joining** (7.5). The floor is 3 blocks on signet, seen by both chain servers of the chain view (`safety-rule.md` section 12 point 3, **proposed, owner to confirm**, `OPEN-QUESTIONS.md` A4). For the host, which does not know members' conditions, the floor. `live` is reached at `needed`, never earlier.
- **`still_watched`** on `abandoned`: `true` while the funding could still appear and make the creation live (`safety-rule.md` C11), that is until a funding input is spent elsewhere and buried (then `dead`) or the factory goes live. The interface never says "over" or "ended" while it is `true`. It is part of what `watching.state` counts (11.2).
- **`exit`** (1.0.0): `transactions` is the path's length n = d + 3 (`spec/exit.md` 4.2: d fixed kickoffs, the leaf kickoff, the leaf transaction, the commitment), counting steps already on chain; `blocks` is the lead E − `leave_by` (`spec/exit.md` 4.4). The example is depth 2 under T1 on signet: 5 transactions, 66 blocks (`spec/exit.md` 4.6; cross-spec review D9).
- **Slice 1 values** (review gap G5): `channel` is `null` (no channels); `exit` is `null` (nothing of the member's to take out); `exit_progress`, `move` are `null`; `dates` holds `factory_ends` and, while awaiting funding, `funding_deadline`; for the host, `host_view` holds the tree (below) and the funding.
- `funding.state`: `not_broadcast`, `broadcast`, `seen`, `confirming`, `buried`, `reorganised_away`, `input_spent_elsewhere` (`journal.md` record `funding_status`).
- `tree.levels[].kind` is always `fixed` in 1.0.0 (decision 9: advanceless). `timed` is a 1.1.0 value.
- `channels` is **1.1.0 reserved**: several channels in one factory (decision 5). `null` in 1.0.0; `channel` holds the one channel. Slice 1 has no channels: `channel` is `null`.
- `covered_sat`: 1.1.0 reserved, `null`.
- `trouble[]`: `{ "code", "at", "params" }` with `code` `old_state_published` (`answer`: `sent`, `confirmed`, `buried`), `host_caught_cheating`, `branch_partly_on_chain`, `funding_reorganised`, `host_fault_evidence` (two values under one version, or a version after the freeze). Answering is not winning: `answer` says how far it got.
- `unfinished_round`: `null`, or `{ "purpose": "start"\|"move", "sent_at", "last_heard_at", "checked_to_height", "both_outcomes_watched": true, "deadline": { a date }, "payments_paused": true }`.
- `host_view` (a factory this program hosts; then `channel` and `tree.path` are `null`): `{ "funded_sat", "members_online", "members_moved", "fee_funds_ready_sat", "deadlines": [ dates ], "tree": { "depth", "levels", "leaves", "leaf", "members" } }`. `host_view.tree` is the whole tree's shape, without any member's path, so the host's Slice 1 screen can show "the lobby, the tree and the confirmation" (`SLICES.md`; review gap G7).

### 16.2 Dates and "where this date comes from"

`GET /api/v1/factories/{id}/dates` (**S1** for `factory_ends` and `funding_deadline`; every other kind 1.0.0) returns the factory's dates in the shape of 7.2, with `provenance` filled. The interface's "Where this date comes from" link shows `source` and `provenance`. Example provenance for "start leaving alone by": `leaf_timeout_less_burial_exit_margin` (7.2) with the inputs `end_height`, `leaf_depth`, `burial`, `steps_missing`, `allowance` and `margins`: `leave_by` = H_leaf − (`burial` − 1) − `steps_missing`·`allowance` − `margins`, with H_leaf = `end_height` − 10·`leaf_depth` (`spec/exit.md` 4.4). `margins` includes the member's extra margin (20.2). The example of 7.2 gives 334,114 (cross-spec review D10).

`GET /api/v1/schedule` (1.0.0) gives every date across all factories, most urgent first, with `most_urgent` naming the one the home screen makes prominent.

### 16.3 Leaving alone

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `POST /api/v1/factories/{id}/leave-alone/preview` | 1.0.0 | `{}` | `{ "preview_id", "amount_sat_estimate", "fee_sat_estimate", "blocks", "done_by": { a date }, "destination": "this_wallet", "stops": ["payments"], "needs": ["app_running", "fee_coins"], "fee_coins_sat": 48000, "fee_cover": "enough"\|"short"\|"none", "cheaper_ways": ["move_with_host"] }` | `host_factory`, `already_exiting`, `wallet_restoring` |
| `POST /api/v1/factories/{id}/leave-alone` | 1.0.0 | `{ "request_id", "preview_id", "confirm": "leave_alone", "confirm_amount_sat_estimate", "passphrase": "…" }` (4.8, kind A) | `202`, `exit_progress` | `preview_expired`, `confirm_mismatch`, `chain_in_doubt`, `already_exiting`, `wrong_passphrase` |
| `GET /api/v1/factories/{id}/leave-alone` | 1.0.0 | | `exit_progress`: `{ "started_height", "amount_sat", "fee_sat_so_far", "blocks_left", "steps": [ { "kind": "tree"\|"leaf_kickoff"\|"leaf"\|"channel"\|"sweep", "state": "pending"\|"waiting"\|"due"\|"sent"\|"confirmed"\|"buried", "txid", "wait": { a date, kind leave_step_due } } ], "done": false }` | |

**The one list of step kinds and states** (`spec/exit.md` 2 cites it; cross-spec review D11). `kind`: `tree`, a fixed kickoff (the bundle's kind 1); `leaf_kickoff`, the leaf's kickoff (kind 2); `leaf`, the leaf transaction (kind 3); `channel`, the member's commitment (never in the bundle); `sweep`, the member's own sweeps and payment claims after the commitment. `state`: `pending`, the exit has not reached the step; `waiting`, reached, but its parent is not yet confirmed by any server, so it cannot be sent; `due`, its parent is confirmed and it is to be sent now; `sent`; `confirmed`; `buried`.

`fee_cover` is how the API reports "coins for fees": no reserve is required or recommended in 1.0.0 (decision 6), but leaving alone still pays fees. Its exact rule against `safety-rule.md` C3 is **(open; critique H.7)**.

### 16.4 Moving to the next factory

| Call | Release | Notes |
|---|---|---|
| `GET /api/v1/factories/{id}/move` | 1.0.0 | `{ "state": "before_window"\|"window_open"\|"trying"\|"unfinished"\|"moved"\|"left_behind"\|"will_not_move", "tries": [ { a date, kind move_try, "result": null\|"moved"\|"failed_before_signatures"\|"unfinished"\|"app_not_running" } ], "next": { "terms": { 13.3 }, "fit": { 13.4 } }, "choice": "by_itself_if_fits"\|"ask"\|"never" }` |
| `POST /api/v1/factories/{id}/move` | 1.0.0 | `{ "request_id", "decision": "move"\|"do_not_move", "seen_current_digest" }`. Only when the choice is `ask`. `move` needs a fresh sign-in (4.8). The move happens at the next try, not at once, and the answer says when |
| `POST /api/v1/wallet/transactions/{txid}/speed-up` | 1.0.0 | Raise a stuck transaction's fee through its pay-to-anchor output (decision 6). Section 18 |

`will_not_move` means the next factory's terms do not fit, or the choice is `never`: the app does not move and will start leaving alone by the date in `dates`.

---

## 17. Payments

All **1.0.0** (Slice 2), except buying receiving room (**1.1.0 reserved**).

| Call | Request | Answer | Errors |
|---|---|---|---|
| `POST /api/v1/payments/decode` | `{ "invoice": "…" }` | `{ "valid", "can_pay", "reason", "amount_sat", "note": { "text", "by": "sender" }, "payee", "fee": { "host_fee_sat", "route_fee_max_sat", "total_max_sat", "routing_limit_ppm" }, "back_by": { a date, kind payment_back_by }, "expires_at", "can_send_sat", "review_id" }` | |
| `POST /api/v1/payments` | `{ "request_id", "invoice", "review_id", "confirm_amount_sat", "confirm_total_max_sat", "passphrase": "…" }`. The passphrase in the request for **every** payment (4.8, kind A; D5) | `202`, the payment | Same codes as `reason`; `review_expired`, `confirm_mismatch`, `wrong_passphrase`, `rate_limited` |
| `GET /api/v1/payments` | `?direction=sent\|received&state=&cursor` | `{ "channel": { "can_send_sat", "can_receive_sat", "host_online" } \| null, "items": [ payments ], "next_cursor" }` | |
| `GET /api/v1/payments/{id}` | | The payment | `not_found` |
| `POST /api/v1/invoices` | `{ "request_id", "amount_sat", "note", "expires_in_s": 3600\|86400\|604800 }` | `{ "id", "invoice", "amount_sat", "state", "expires": { a date } }` | `no_channel`, `host_offline`, `bad_amount`, `above_receivable` (with both numbers), `not_live` |
| `GET /api/v1/invoices/{id}` | | The invoice | |
| `POST /api/v1/receiving-room/quote`, `POST /api/v1/receiving-room/buy`, `GET`/`PUT /api/v1/receiving-room/auto` | | `501`, `not_in_this_release`, release `1.1.0` | |

- `reason` (why it cannot be paid): `empty`, `not_an_invoice`, `wrong_network`, `expired`, `no_channel`, `not_live`, `host_offline`, `not_enough_balance`, `too_close_to_end` (the deadline would pass the exit time plus margin, `safety-rule.md` section 7), `above_payment_max`, `below_payment_min`, `over_routing_limit` (with `fee_sat` and `limit_sat`), `payments_paused_by_host`, `round_unfinished` (payments paused while a round is unsettled), `chain_in_doubt`, `wallet_restoring`.
- Payment `state`: `pending`, `done`, `failed`, `stuck` (held past its expected time). A pending or stuck payment carries `back_by` and `may_need_chain: true` when the host does not cooperate (critique question 14: no return date is promised beyond that).
- The routing limit (most the member pays to route one payment) is in Settings, Wallet. The host's payment fee is a condition. The two never share a field name.
- The interface must say that receiving needs the app open; `POST /invoices` returns `needs: ["app_running"]`.

---

## 18. On-chain wallet

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `GET /api/v1/wallet` | S1 | | `{ "free_sat", "unconfirmed_sat", "set_aside_sat", "set_aside_for": [ { "lobby_id", "amount_sat" } ], "coins": [ { "txid", "vout", "amount_sat", "confirmations", "received_at", "held_for": null\|"lobby" } ], "as_of_height", "chain_view": "trusted"\|"in_doubt" }`. `coins` holds the first 50; more through `GET /api/v1/wallet/coins?cursor` | |
| `POST /api/v1/wallet/address` | S1 | `{}` | `{ "address": "tb1p…" }`. A new address each time | `no_wallet` |
| `GET /api/v1/wallet/transactions` | 1.0.0 | `?cursor` | Page of `{ "txid", "kind": "received"\|"sent"\|"factory_funding"\|"factory_exit"\|"host_recovery"\|"fee_bump", "amount_sat", "fee_sat", "confirmations", "at", "factory_id" }` | |
| `POST /api/v1/wallet/send/preview` | 1.0.0 | `{ "address", "amount_sat"\|"all": true, "fee_rate_sat_per_kvb": null }` | `{ "review_id", "amount_sat", "fee_sat", "fee_rate_sat_per_kvb", "left_free_sat", "touches_set_aside": false }` | `bad_address`, `wrong_network`, `not_enough`, `would_use_set_aside` |
| `POST /api/v1/wallet/send` | 1.0.0 | `{ "request_id", "review_id", "confirm_amount_sat", "confirm_address", "passphrase": "…" }` (4.8, kind A) | `202`, `{ "txid" }` | `review_expired`, `confirm_mismatch`, `chain_in_doubt`, `wrong_passphrase` |
| `POST /api/v1/wallet/transactions/{txid}/speed-up/preview`, `POST …/speed-up` | 1.0.0 | `{ "fee_rate_sat_per_kvb" }`, then `{ "request_id", "review_id", "confirm_fee_sat", "passphrase": "…" }` (kind A) | Child pays through the pay-to-anchor output | `no_anchor`, `already_confirmed` |
| `PUT /api/v1/wallet/payout` | 1.1.0 reserved | Per-factory derived address (decision 6) | | |
| `PUT /api/v1/wallet/payout/outside` | later reserved | Outside wallet, proven before use | | |

The default fee rate on test networks is 0.1 sat/vB (`100`), set in Settings, Wallet (1.0.0). **Slice 1** uses 100 sat/kvB, fixed, for the funding transaction and every wallet transaction (review gap G8), and the terms' `tree_feerate_sat_per_kvb` defaults to 100 in the host preview. The program never spends set-aside coins for anything but the lobby they are held for.

---

## 19. Activity record

What happened, newest first: payments, and everything the app did by itself, with who decided and the rule that allowed it (concept H, from C).

| Call | Release | Request | Answer |
|---|---|---|---|
| `GET /api/v1/activity` | S1 | `?show=all\|payments\|by_app\|refusals&cursor&limit` | Page of entries |
| `GET /api/v1/activity/{id}` | S1 | | The entry with its saved copy |

```json
{
  "id": "act_1182",
  "at": 1794426000,
  "kind": "refused",
  "lobby_id": "lob_b19d",
  "factory_id": null,
  "who_decided": "the_app",
  "rule": { "code": "my_conditions", "params": { "conditions_version": 7 } },
  "params": { "failures": [ { "condition": "max_joining_fee_sat", "yours": 2000, "offered": 5000 } ], "nothing_signed": true },
  "saved_copy": {
    "saved_at": 1794426000,
    "terms": { "...": "13.3, as it was" },
    "fit": { "...": "13.4, as it was" },
    "conditions": { "...": "as copied then" }
  }
}
```

- **A saved copy never changes.** It is stored when the entry is made, not rebuilt from today's lobby or today's conditions (critique rule 19).
- `who_decided`: `you`, `the_app`, `the_host`, `the_sender`, `the_chain`, `all_members`.
- `rule.code`: `my_conditions`, `my_standing_instruction` (automatic joining, with the instruction's id), `joining_was_consent`, `fixed_safety_check`, `routing_limit`, `room_to_receive`, `confirmations_required`, `factory_terms`, `start_rule`, `pause`.

**`kind`**

| Value | Release |
|---|---|
| `wallet_created`, `words_checked`, `lobby_found`, `joined`, `readied`, `unreadied`, `left`, `removed_by_host`, `refused`, `aborted_before_signatures`, `not_chosen`, `lobby_cancelled`, `signed`, `signing_unfinished`, `creation_abandoned`, `creation_dead`, `factory_live`, `funding_reorganised`, `host_fault_evidence`, `paused`, `resumed`, `lobby_opened` (host), `values_moved` (host), `ready_check_run` (host), `funded` (host), `host_recovered` (host), `received_coins`, `sent_coins` | S1 |
| `paid`, `received`, `payment_failed`, `invoice_made`, `moved`, `move_tried`, `move_unfinished`, `left_behind`, `leave_alone_started`, `leave_alone_step`, `leave_alone_done`, `old_state_answered`, `factory_ended`, `while_closed`, `restored`, `backup_exported`, `auto_join_told`, `auto_join_joined`, `auto_join_refused`, `settings_changed`, `offline`, `online`, `signed_in`, `revoked_all` | 1.0.0 |
| `room_bought` | 1.1.0 reserved |

Entries and their saved copies are saved in the journal as section 7.5 says, in the same batch as the record of the event they describe; `journal.md` lists them under its open point "API needs" until their record types are numbered (Slice 1 input W3). `nothing_signed` in `params` is computed by the rule of 14.1, from the member's own round records.

---

## 20. Settings by scope

Four scopes, as concept H's Settings: Wallet, Watching, Connections, Application. Conditions and lobby terms are **not** settings (options map, "never a setting"). Each scope is one `GET` and one `PATCH`; a `PATCH` names only the fields it changes and carries `based_on_version`.

Nothing in any scope switches off a safety check, the two-server rule, saving before sending, answering an old state, leaving before the end, or the refusal of mainnet. A request that tries answers `400`, code `not_a_setting`.

### 20.1 Wallet: `GET`/`PATCH /api/v1/settings/wallet` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `routing_limit_ppm` | 0 to 50,000 | The most the member pays to route one payment |
| `fee_rate` | `{ "mode": "automatic"\|"fixed", "sat_per_kvb": 100 }` | Test networks default to fixed 100 (0.1 sat/vB) |
| `network` | `signet`, `testnet4` | Fresh sign-in, with `confirm_network` repeating the value. Refused with `network_busy` while in a lobby or factory; `network_unavailable` for testnet4 until it has two operators; mainnet is never accepted. The program restarts on the new network's data folder |

### 20.2 Watching: `GET`/`PATCH /api/v1/settings/watching` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `who_watches` | `nobody`, `this_app`; `own_machine` and `watcher` later reserved | Fresh sign-in; `nobody` also needs `confirm: "nobody_watching"` |
| `extra_margin_blocks` | 0 and up | Added above the app's own margin. Cannot go below 0 |
| `warn_days_before` | 0 to 30 | |
| `reminders` | `[ { "id": "in_app", "on": true } ]`; `nostr`, `email`, `phone` later reserved | |
| Read-only: `safe_absence_blocks`, `state`, `health`, `planned_alerts` | | Status, computed |

`POST /api/v1/settings/watching/offline` (1.0.0), `{ "on": true, "confirm": "nobody_watching" }` or `{ "on": false }`, fresh sign-in either way. Going offline stops every outside connection; `watching.state` becomes `nobody_offline` and `connection.chain.state` `offline_by_choice`. It is a deliberate button in Watching, never a one-tap switch in the strip (critique, rule table). **Locking the wallet** while anything needs watching is confirmed the same way (4.7), with `confirm_locked` naming what the watcher still does. The watcher's "maximum privacy" switch (storage 8.7.5: off means a locked wallet watches nothing) is a field here, `watch_while_locked` (1.0.0, `true` by default, **open**, owner decision), with `confirm: "nobody_watching"` to turn it off. **While any factory has something to take out** it is refused (`409 something_to_take_out`) unless the request also carries `confirm_leave_by_height`, the earliest `leave_by` it puts at risk, which the warning names (`spec/exit.md` W5; review R12).

### 20.3 Connections: `GET`/`PATCH /api/v1/settings/connections` (S1 read; 1.0.0 write)

```json
{
  "version": 3,
  "chain": {
    "mode": "public",
    "servers": [ { "id": "s1", "name": "signet-a.example", "operator": "Operator A", "protocol": "http", "state": "ok", "height": 330437, "checked_at": … } ],
    "own_server": null,
    "own_node": null
  },
  "listings": { "nostr": { "on": false }, "relays": [ { "id": "r1", "url": "wss://relay-one.example", "state": "ok" } ] },
  "hosts": [ { "key": "02…", "address": "tomato.example:9735", "source": "built_in"\|"added"\|"invitation" } ],
  "privacy": { "route": "direct" }
}
```

| Call | Release | Notes |
|---|---|---|
| `POST /api/v1/settings/connections/servers` | 1.0.0 | Add a server `{ "address", "confirm_address", "protocol" }`. Fresh sign-in. Tested before saving. Its operator is always `you` (below) |
| `DELETE /api/v1/settings/connections/servers/{id}` | 1.0.0 | `{ "confirm_id" }`, fresh sign-in. Refused with `min_two_operators` if it would leave fewer than two operators under the rule below |
| `POST /api/v1/settings/connections/check` | 1.0.0 | Asks every server again now. `{ "state", "servers" }` |
| `PATCH` `chain.mode` | 1.0.0 | `public`, `own_server`, `own_node`. Fresh sign-in. Own server or node is still compared with a public server from another operator |
| `PATCH` `listings` | 1.0.0 | Nostr annex on or off; relays (at least 3 when on, `discovery.md` 17.1) |
| `POST`/`DELETE /api/v1/settings/connections/hosts` | 1.0.0 | The editable host list (`discovery.md` 14.1). Fresh sign-in, `confirm_address`. In Slice 1 a host enters the list through `POST /api/v1/discovery/query`, which the person starts with the host's key and address typed in |
| `PATCH` `privacy.route` | `tor` later reserved | |

Server `state`: `ok`, `catching_up`, `lagging`, `disagrees`, `unreachable`.

**How an operator is established** (review F5). The two-operator rule must not rest on the person's word, or on a session's: one session could otherwise replace both public servers with two servers one party runs.
- A **built-in** server's operator is the one named in the program's built-in list (`docs/CHAIN-SERVERS.md`), fixed at build time.
- Every server the person adds, an own server and an own node included, has the operator **`you`**, one operator for all of them, whatever name it is given.
- The chain view counts as two operators only when the agreeing servers include **at least one built-in server**, and at least two distinct operators in all (11.2, `agree`). So the person's own servers can add a second view, never replace the public one, and a session that adds servers cannot make a view of its own choosing trusted.

### 20.4 Application: `GET`/`PATCH /api/v1/settings/application` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `units` | `sat`, `btc` | |
| `fiat` | `off`; currencies later reserved | Shows nothing on test networks |
| `theme` | `system`, `light`, `dark` | |
| `language` | `en` | |
| `sign_out_after_idle_s` | `null` (never), 900, 3600 | Idle **sign-out** (4.7); idle never locks. Draft 4 called it `lock_after_idle_s`. Slice 1 has no Settings call and uses 900 |
| `interface` | `{ "port": 39735, "ipv6": true, "tunnel_port": null }` | Fresh sign-in, with the new value echoed; takes effect at the next start. The address is not a field: loopback only. `tunnel_port` (3.3): while set, no session hand-over between tabs (4.4). Read-only beside it: `peer_check` (3.4) |
| `hosting_place_on_phones` | `tab`, `header_until_hosting` | Decision 6 |

| Call | Release | Notes |
|---|---|---|
| `GET /api/v1/about` | 1.0.0 | `{ "version", "dedication": "…", "credits": [ … ], "licences": [ { "name", "text" } ] }` (decision 7) |
| `GET /api/v1/logs` | 1.0.0 | `?cursor&level=info\|warn\|error`. The program's own log lines, which hold no secrets (5.5) |
| `GET /api/v1/glossary` | later reserved | The interface holds the words in 1.0.0 |

---

## 21. Discovery

The demo wallet's path is design C (`discovery.md` section 14.1): the built-in, editable host list; invitations; optionally Nostr listings; direct queries over BOLT 8 (`lobby_index_request`, then `listing_request`, then `hello`). No beacons, overlay or store nodes in 1.0.0's demo.

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `GET /api/v1/discovery` | 1.0.0 | | `{ "hosts_known": 6, "polling": "on"\|"off", "last_refresh_at", "nostr": "off"\|"on"\|"no_relays", "sources": [ { "kind", "state" } ], "privacy_note": "direct" }` | |
| `POST /api/v1/discovery/query` | S1 | `{ "host": "<key>@<address>:<port>" }`, or `{ "host": "<key>" }` for a known host | `202` **at once**, `{ "query_id": "q_12", "state": "asking" }`. The query runs in the background; `discovery` events (with the query's id) say when it changes | `bad_host_address`, `wrong_network`, `rate_limited` (below) |
| `GET /api/v1/discovery/queries/{id}` | S1 | | `{ "query_id", "state": "asking"\|"answered"\|"failed", "lobbies": [ local ids ], "failed_because": null\|"host_unreachable"\|"key_mismatch"\|"timed_out", "asked_at", "answered_at" }`. `key_mismatch`: the connection's key is not the one given. `timed_out` after 30 s without an answer. Kept for the run | `not_found` |
| `POST /api/v1/discovery/refresh` | 1.0.0 | `{}` | `202`. Polls the host list within DQ2's limits, and Nostr if on | `rate_limited` |
| Nostr annex on/off | 1.0.0 | `PATCH /api/v1/settings/connections` with `listings.nostr.on` | | |
| `GET /api/v1/discovery/hosts` | later reserved | Store nodes' `host_list` (design D) | | |

- **Rate limits.** Queries the program makes by itself follow `discovery.md` DQ2's informative defaults (at most once per host per hour, at most 32 hosts per hour). A query the person starts is allowed once per 10 s per host: that limit is **this API's own, proposed**, not part of DQ2, and is to be recorded in `discovery.md` when that specification is next revised.
- A query by key and address adds the host to the known list (saved, 7.5) once it answers with the given key.
- Every lobby found is checked in full before it is shown (`terms.md` section 7); a listing that fails is dropped and counted in `sources[].dropped`.
- Withdrawals are applied wherever they come from (`discovery.md` 5.3).
- The interface must say that asking a host shows it this machine's network address unless Tor is used (later reserved). `privacy_note` is `direct` until then.
- `address` here is a DNS name, an IPv4 or bracketed IPv6 literal, or an onion name, as in `discovery.md` 17. The interface never invents one.

---

## 22. Status values the safety wording needs

The critique (`docs/reviews/ux-critique.md` sections 4 and H.3 to H.7) lists sentences the interface must be able to say and others it must never say. Each needs a value the program reports, distinct from its neighbours. This table is the check.

| Wording need (critique) | Distinct value | Must not be confused with |
|---|---|---|
| "Signing did not finish": signatures went out, no result | `doing.code = signing_unfinished`; `you.outcome.code = signing_unfinished`; `round.state = unfinished`; attention `signing_unfinished` | `refused_at_check`, `aborted_before_signatures`, `refused_by_host`, `lobby_cancelled`/`cancelled` (the only places "nothing was signed; nothing moved" is allowed, and `cancelled` only when no partial signature was ever sent in the lobby) |
| A move try that did not finish | `move_unfinished` (doing, factory state, move state) | A failed try before signatures (`move.tries[].result = failed_before_signatures`) |
| Live only when the funding is buried and the tree is held (C11) | `awaiting_funding` against `live` | "If the host publishes the funding, it goes live" has no value: publishing is `funding.state = broadcast`, not live |
| A host's `cancel` after this member's partial signatures went out | `you.outcome.code = signing_unfinished` (then `abandoned`, `dead` or `started`) with `cancel_received: { reason }`; `doing.code = signing_unfinished`. Decided from the member's own `exposure` record (14.1) | `cancelled`, `lobby_cancelled` |
| Unfinished start that never gets funded | `creation_abandoned`, `creation_dead` | `lobby_cancelled` |
| An abandoned creation can still go live | `still_watched = true` on the outcome, the factory and `doing.params`; `doing.code = creation_abandoned` does not expire while it holds (11.2) | "Over", "ended", `dead`; `idle_no_factory` |
| A factory being formed is not money one can use | `money.forming_sat`, apart from `can_send_sat` and `inside_factories_sat` | Live balance |
| "Nobody is watching" | `watching.state = nobody_offline` | `this_app`; `nothing_to_watch` (no factory: nothing needs watching) |
| Locked, still watching (1.0.0): "It still watches and starts leaving by its dates, but cannot finish leaving, move, answer your host, sign or pay; unlock by [unlock_by]" | `wallet = locked`; `watching.state = watcher_locked`; `doing.code = wallet_locked` with `params.watcher`; `watching.headline`; `watching.unlock_by` (4.7) | `this_app` (unlocked, which also finishes exits, moves and answers the host); `nobody_locked`. Never "leaves in time" |
| Locked, nobody watching (every Slice 1 build) | `watching.state = nobody_locked` with `reason` (`no_bundle`, `no_key_store`, ...); `doing.params.watcher = off`; headline `nothing_needs_you` (Slice 1 wording) or `nobody_watching_locked` | `watcher_locked`; `this_app`; `nothing_to_watch` |
| The host closed the channel while locked: the balance waits, with no deadline (1.0.0) | `doing.params.watcher = host_closed`; headline `host_closed` | `waiting_for_unlock` ("after block H_leaf the host can take this balance", no longer true once the host's commitment confirmed) |
| Leaving alone cannot be paid for, is late, is held back, or was missed (1.0.0) | Attention `exit_needs_fee_coin`, `exit_step_late`, `exit_step_held_back`, `exit_fee_budget_reached`, `exit_missed` (11.4) | `leave_step_due`; one another |
| A void tree after a live factory's funding was double-spent (1.0.0) | `ended_how = void_funding`; attention `funding_double_spent` | `host_timeout`; `creation_dead` (never live) |
| What a locked watcher has done | `doing.params.watcher` = `publishing_tree_steps`, `waiting_for_unlock`, `answering_old_state`, `paying_fee`, kept until unlock | `watching` |
| Only the last step is left, and it needs the passphrase | `doing.params.watcher = waiting_for_unlock`; headline `waiting_for_unlock` (`at_risk`) | `publishing_tree_steps`; any wording that says the exit is done |
| Files older than the wallet's last saved state: never "your wallet is fine" | `wallet = files_behind` with `params.cause`; `doing.code = files_behind`; headline `files_behind` | `locked`; `ready` |
| Some answers to old states are missing while locked | `watching.reason = penalty_file_short`; headline `penalty_file_short` | `watcher_locked` with `reason: null` |
| A restored wallet does not know its factories | `watching.state = nobody_restoring`; attention `restored_factories_unknown` | `nothing_to_watch` |
| Nobody can watch because the chain view is in doubt | `watching.state = nobody_chain_in_doubt` | `nobody_offline` |
| Watching has fallen behind | `watching.health = behind` | `up_to_date` |
| "Open it again well within a day" | `watching.open_by` (a date with the margin already taken off), `safe_absence_blocks` | The whole safe absence |
| "Only while it is running and has coins for fees" | `at_zero.needs = ["app_running", "fee_coins"]`; `exit.needs`; `fee_cover` | A date with no conditions |
| "Your money has not moved" must not be said when the chain view is in doubt | `money.chain_view = in_doubt`, which holds for `connection.chain.state` = `catching_up`, `one_source`, `disagree`, `unreachable` and `offline_by_choice` (the normative table of 11.2) | `trusted`, which holds only for `agree` and `lagging` |
| Servers disagree against only one answering | `disagree` against `one_source` against `unreachable` | Each other |
| "Answering is not winning" | `trouble[].answer = sent \| confirmed \| buried` | A single "answered" |
| Left behind | `left_behind` (doing, factory state, move state) | `will_not_move` (the app chose not to move because terms do not fit) |
| "Nothing appears to have gone wrong while you were away. Check below." | `while_closed.verdict = nothing_found`, which needs `found` empty, `checked = all` and `beyond_safe_absence = false` (11.5) | `found`, `could_not_check`, `beyond_safe_absence`, each also shown on its own field |
| Restore: "Your balance is not confirmed yet" | `wallet = restoring`; factory `restoring_unconfirmed` | `live` |
| "Payments are paused by the host … no date" | Attention `payments_paused_by_host`, tier `important`, never `act_now` | `round_unfinished` (paused by the app itself) |
| A pending payment with an uncooperative host | Payment `state = stuck`, `may_need_chain = true` | `pending` with a promised date |
| Fits only now | `fit.class = fits_only_now`, not counted in `fit_summary.fit` | `fits` |
| Ready but not counted | `doing.code = in_lobby_not_counted`; `you.counted = false` | `in_lobby_waiting` |
| Cancelled: not your doing | `you.outcome.not_your_doing = true` | `left` |
| A refusal with both numbers | `failures[] = { condition, yours, offered }` everywhere a refusal appears | A bare code |
| Pause is held while signatures are out | `pause.state = held_for_signing`; `doing.code = signing` | `off`, `on`; `doing.code = paused` |
| Paused, with something at risk | `doing.code` priority (11.2): every at-risk value outranks `paused` | `paused` hiding an unfinished round |
| Signed out, the app still signs and watches | `GET /session` `signed_in: false` with `wallet: unlocked`; `watching.state` as unlocked (review N8: draft 2's row "A locked app still signs" stated the opposite of 4.7) | `wallet = locked` |
| A lock waits for a round to end, or for a received payment to settle | `lock.state = held_for_signing` with `lobby_id`, or `held_for_payment` (1.0.0), in `GET /session` and status; sessions still valid | `wallet = locked` |
| A host's claim that a member was silent | `round.state = failed` with counts, shown as the host's claim | A finding by the app |
| Host-written text in the app's voice | `{ text, by: "host", checked: false }` on every such string | Plain strings |
| Required only with a date | Attention tier `act_now` always has `due` | `important` |
| The core stopped | `wallet = node_stopped`, `doing.code = node_stopped`, `503 node_stopped` | A blank screen |

A contract test (23.4) checks that every value in this table can be produced by the simulator and is rendered by the interface with its own wording.

---

## 23. Tests

No browser or operating-system test was run for drafts 3 and 4 either: the behaviour below rests on the documents cited at the top. Items 23.2.4, 33, 34 (the session transport), 32 (streams), 36 (`Origin` under the referrer policy), 19 (lock and idle), 37 (first run), 45 (the same-user check) and 48 to 51 (draft 4's first-run, worker and confined-browser items), and every item of 23.6, are to be run first, with Playwright in Chrome, Firefox and Safari and by hand on the build server, before the program's session code is merged.

### 23.1 Functional

1. Every call in section 2.1 works against the simulator, and Slice 1's walkthrough runs **through the interface alone** (owner decision 11): create a wallet and see the words; the backup check; host opens (the passphrase in the request, funding echoed); three members query the host by address, join and ready; the start rule starts the lobby; signing; funding; live after `needed` confirmations. Twice from a clean start. A restore from the words on a fresh data folder brings back the on-chain coins.
2. A member whose conditions are not met: `join` answers `conditions_not_met` with both numbers; with conditions loosened after joining a lobby whose tree at signing breaks the conditions **as copied at joining**, `you.outcome = refused_at_check` and an activity entry with a saved copy. The same with a restart between the loosening and the signing: still refused (the copy is in the journal, 7.5).
3. `seen_current_digest` older than the current version: `terms_changed`; nothing is sent.
4. The copying rule: tightening conditions while joined leaves the lobby (`left_lobbies`); loosening changes nothing joined. Loosening without a fresh sign-in: `fresh_sign_in_needed`; with a wrong `confirm_loosens`: `confirm_mismatch`.
5. `request_id` repeated on join, open, start, cancel, send, pay: one effect, same answer with `replayed: true`. The same id on a different path, or on the same path with a different body: `409 request_id_reused`, nothing done. The same id after a crash between the save and the answer, and a restart: one effect, the saved answer.
6. `based_on_version` stale: `changed_elsewhere`.
7. Pause, for each row of the table in 11.3: the stated `leave`, `round_abort` or hold; `join` and `ready` answer `paused`; with partial signatures out the answer is `held_for_signing` and `doing.code = signing`, and the pause takes effect when the round ends. **Pause on, restart: still on, and nothing is joined or signed after the restart.** Resume without a fresh sign-in: refused.
8. Every reserved call answers `501` with the right release.
9. Paging: insert entries between two pages; no duplicate and no gap. Cursor after restart: `cursor_expired`.
10. Restore from a backup file (1.0.0): import a stale backup (guard ahead): `stale = yes`, `lost_seats` listed, `reset` event, factories `restoring_unconfirmed`.
11. Unknown request field: `unknown_field`. Unknown enumeration value in a mocked answer: the interface shows "unknown state", never success.
12. **Review F3.** A member sends `round_partial_sigs`; the host then sends `cancel` reason 3: `you.outcome.code = signing_unfinished` with `cancel_received.reason = signing_budget_spent`, `doing.code = signing_unfinished`, attention `signing_unfinished`; never `cancelled` or "nothing was signed". The same in a second attempt of a lobby whose first attempt released partial signatures. And `cancel` reason 3 to a member that sent only nonces: `cancelled`, "nothing was signed".
13. **Chain mapping.** For each value of `connection.chain.state`, the simulator produces exactly the `money.chain_view`, `watching.state`, signing permission and `doing.code` of the table in 11.2; `offline_by_choice` gives `nobody_offline`. A chain view of two user-added servers never reaches `agree`.
14. **Doing priority.** Every pair of `doing.code` values that can hold together, the higher in 11.2's order shows; in particular, paused with an unfinished round shows `signing_unfinished`. Sticky codes end after 24 hours or at the next join, also across a restart.
15. **Abandoned and still watched.** An abandoned creation whose funding is buried later goes live when the time checks pass; while abandoned, `still_watched` is `true` and `watching.state` is not `nothing_to_watch`.
16. **Start rule.** Target reached: ready check at once without any call; deadline with at least the minimum: ready check; below: cancel; `start` before the target with at least the minimum: early start; while paused: no check, cancel at the deadline.
17. **Echo, passphrase and fresh sign-in.** Every kind B call in the table of 4.8: refused without a fresh sign-in, refused with a wrong echo, accepted with both; over the local socket with the bearer token, accepted without a fresh sign-in but still refused with a wrong echo. Every kind A call: refused without the passphrase in the request **even within 5 minutes of a sign-in or `session/fresh`**, refused with a wrong passphrase (counted) or a wrong echo, accepted with both; the same on the local socket. A kind A request replayed by its `request_id` answers the saved result and runs no derivation.
18. **Request digest** (7.4): two bodies that differ only in member order, white space or escaping (`"é"` against `"\u00e9"`) give the same digest; RFC 8785's own examples reproduce; vector E15 reproduces (canonical bytes and digest); two kind A bodies that differ only in the top-level `passphrase` give the same digest; no byte of any passphrase, nor its SHA-256, appears in the request-id store.
19. **Setup session** (4.3): a setup session calling anything outside its list answers `not_setup_call`; after `create` the session is normal and a kind B call within 5 minutes needs no `session/fresh`; `reveal` and `check` right after `create` still need the passphrase. Close the tab between `create` and `finish-setup`, reopen the plain address: passphrase sign-in, then `finish-setup` works; no start token or code is accepted. The same with a restart in between.
20. **Unlock order** (4.7): a wrong passphrase leaves the watcher running throughout (1.0.0); with a saved pause on, a restart and unlock: no host connection is opened before the pause is applied; with the watcher having published a tree step, the commitment is broadcast before any host connection, also with the pause on; a forged log entry ("broadcast", "spent") that the chain does not confirm makes no record and no activity entry; a hosted lobby whose deadline passed while locked is cancelled once its members can be reached; a funding deadline that passed while locked gives `abandoned` once the chain view is trusted; the watcher's confirmed broadcasts appear in Activity.
21. **`creation_abandoned` while still watched** (11.2): 25 hours after an abandoned creation with `still_watched: true`, with nothing above it holding, `doing.code` is still `creation_abandoned`, never `idle_no_factory`; after joining another lobby and leaving it, again `creation_abandoned`. Once `still_watched` turns `false`, the 24-hour rule applies.
22. **Files behind** (4.7, review R3): with the mark file or guard deleted, and separately with the journal cut back after an anchored batch, `POST /session` with the right passphrase answers a `files_behind` session; status has the locked shape with `wallet = files_behind` and `doing.code = files_behind`; every call but the five of 4.7 answers `not_files_behind_call`; `start-as-restore` without the passphrase or with the wrong confirm is refused; with both it answers `restoring` and the next key derived is of a new epoch; signing out instead leaves every file byte for byte as it was. On the socket, `POST /wallet/unlock` answers `409 files_behind`. A key file with no journal starts as a restore without asking.

### 23.2 Hostile browser and network

Run with Playwright and a raw HTTP client. Each expects the stated refusal, and no handler runs (the core sees no event).

1. `Host: rebind.attacker.example:39735` (DNS rebinding): `421 bad_host`, also for `GET /` and static files.
2. Missing `Host`; two `Host` headers; `Host: 127.0.0.1` without the port; `Host: 127.0.0.1:39736`; a `Host` naming the IPv4 unspecified (all-zeros) address with the right port: `421`.
3. A page on another origin `fetch`es `POST /api/v1/lobbies/{id}/join` with `mode: "no-cors"` and `text/plain`: refused (`415`, and `403` for `Origin`); nothing joined.
4. The same from a page on `http://127.0.0.1:8080` (same site, other port), with and without trying to add `X-Gazpacho-Session`: refused by `Origin`, fetch metadata and the refused preflight; that page cannot read the interface's `sessionStorage`.
5. An HTML form posting `application/x-www-form-urlencoded` and `multipart/form-data` to every unsafe endpoint: `415`.
6. `Origin: null` (a sandboxed iframe, a `file://` page): `403`.
7. Unsafe request with a valid session header and no `Origin`: `403`.
8. Valid `Origin`, missing or wrong `X-Gazpacho-Session`: `401 not_signed_in`. Any `Cookie` header, including a valid-looking `gz_session_39735`, grants nothing and appears in no log.
9. `OPTIONS` preflight to every path: `405`; no response anywhere carries `Access-Control-Allow-*` (scan every response of a full run).
10. A public page that reaches loopback in a browser with Local Network Access, the permission granted: still refused by the other checks (items 3, 5, 11). Nothing depends on the permission prompt.
11. `<img src>`, `<script src>`, `<iframe src>` and `<link rel=prefetch>` pointing at API paths and at static files from another origin: blocked by fetch metadata where sent and by `Cross-Origin-Resource-Policy` where not; no data in any response.
12. Cross-origin `fetch()` of `/api/v1/events`: fails; the program counts no stream. A same-origin `EventSource` (no session header): `401`.
13. A WebSocket handshake to any path: `400 no_upgrade`.
14. The interface framed by another origin: blocked by `frame-ancestors 'none'` and `X-Frame-Options`.
15. Script injection: a host alias, lobby name, description, member name and invoice note set to `<img src=x onerror=…>`, `<script>…</script>`, `javascript:` links, and text with bidirectional overrides and zero-width characters. The page shows the text, isolated, with the format characters gone; no script runs; no link is made; no CSP violation from the interface's own code.
16. The interface's files contain no inline script, no inline style, no `eval`, no `innerHTML` (static check, as the prototype's).
17. Sign-in: a wrong passphrase answers `wrong_passphrase`; more than one attempt a second is `rate_limited`; after 5 wrong in a row the delay doubles up to 15 minutes, and a restart keeps the delay; with `attempts.gza` deleted, attempts are refused for 15 minutes. Wrong passphrases sent to `session/fresh`, `wallet/unlock`, `reveal` and `check` raise the same counter. Requests refused by `Host`, `Origin`, content type or fetch metadata do not count. First-run codes: 5 wrong cancel the codes that existed then; a used or expired code fails.
18. A session token from a stopped run: `401`, and the wallet is locked (`423 wallet_locked` for every data call until the passphrase is typed). After `revoke-all`: every session `401`, every stream closed with a `session` event, the socket token file changed, `Clear-Site-Data` sent, the wallet still unlocked and working, the storage key still in memory.
19. **Idle sign-out** (review F9): with events flowing, background refreshes running and no input, the browser is signed out at 15 minutes; data calls answer `401`, the stream closes, the wallet stays unlocked and the core still signs a lobby the member joined. **Lock**: `POST /wallet/lock` drops the key (a memory search of a test build finds no storage key afterwards), the node stops (in 1.0.0 the watcher starts), and with partial signatures out the answer carries `lock.state = held_for_signing`, the sessions stay valid until the round ends, and only then do they end; in 1.0.0, with an incoming payment's secret released and unsettled, `held_for_payment` likewise, never a refusal. Lock while anything needs watching without a fresh sign-in or `confirm_locked`: refused; with something to take out (1.0.0), also without the right `confirm_unlock_by_height`: refused. In Slice 1, with an awaiting-funding or live factory, `confirm_locked: "nobody_watching"` alone is accepted and a `confirm_unlock_by_height` is not asked for. Lock while hosting an Open lobby: `hosting_lobby_open`.
20. Fresh sign-in: every kind B call of 4.8's table answers `fresh_sign_in_needed` after 5 minutes.
21. Socket token with an `Origin` header: `403`. With a session header too: `400`. On the TCP port: `400 bearer_not_on_tcp`. With the wallet locked, no token file exists, and the socket answers only `GET /status`, `GET /version` and `POST /wallet/unlock`, which needs the passphrase, and, while `files_behind`, `POST /wallet/start-as-restore` with the passphrase (4.6); every other call `401`. A connection to the socket from another user: closed at accept. A browser session calling `POST /api/v1/first-run-codes`: refused.
22. Query strings `?token=…`, `?code=…`, `?phrase=…`, `?session=…`: `400 secret_in_url`, and the value is in no log.
23. Path traversal on static files (`/../journal.gzj`, `/%2e%2e/`, `/..%5c`, overlong UTF-8): `404`.
24. Request smuggling: `Transfer-Encoding: chunked` alone `411`; with `Content-Length` `400`.
25. Slow headers (one byte a second): closed at 10 s. 33rd connection: refused. 65 header lines: refused. 70 KiB JSON body: `413`. 20 KiB of headers: `431`.
26. JSON: duplicate keys, 17 levels deep, `2^53` as a number, invalid UTF-8, a lone surrogate: `400 bad_json`.
27. Configured listen address set to the unspecified address (IPv4 or IPv6) or to a LAN address: the program refuses to start. A connection to the machine's non-loopback addresses on the port: refused by the operating system.
28. The port taken by another process: the program refuses to start the interface and says so; it does not pick another port.
29. Static content cannot be fetched with `Sec-Fetch-Site: cross-site`; `GET /` with `none` works.
30. A `same-site` API request (another port on `127.0.0.1`): `403`.
31. A second operating-system user connects to the port: on Linux, `403 other_user` before any byte is read, for every path, `GET /` and the API alike, also during first run; with the check made unavailable (a test switch that hides `/proc/net` and the netlink family), status says `peer_check: unavailable` and that user gets the sign-in page and `401` everywhere else. In both cases that user cannot read the token file, the redirect file or the local socket.
32. **Streams** (review F10): five tabs open; one stream in all (shared worker or elected tab), every tab updated; a third stream for one session answers `429 too_many_streams` and is not retried; no connection is closed to make room; closing the stream's tab moves it to another tab.
33. **Another loopback server** (review F1): a test server on another port of `127.0.0.1` records every request header it receives while the person, signed in to Gazpacho, browses pages it serves, in the same browser: no Gazpacho credential appears (no cookie, no session secret).
34. **Replay** (review F1, F19): every request header the browser sends to Gazpacho, replayed by a raw client without `X-Gazpacho-Session`: nothing but `{ "signed_in": false }`, the version and static files. A `Set-Cookie` from another port for `127.0.0.1` changes nothing.
35. **Words check** (review F2, N5): a script with a session, a fresh sign-in, but no passphrase tries `check-start`, `check` and `reveal` in every order: positions only, no answer about any word, no words. With the passphrase: answers carry only `ok`; a wrong passphrase leaves the daily count unchanged; the fourth check in 24 hours is `rate_limited` before any derivation, also after a restart; a failed check ends the session.
36. **`Origin` from the real interface** (review F17): every unsafe call the interface makes, recorded by Playwright, carries the interface's own `Origin` and succeeds.
37. **First run** (owner decision 14, review N3): with no wallet, the program listens, writes the redirect file (mode 0600 in a 0700 folder), and opens the browser on the file's path; the interface removes the fragment from the address bar at load; no request line, access-log line or proxy log holds the token; **a second user polling every process's command line (`/proc/*/cmdline`) throughout, with the browser already running and not running, never sees the token**; the token works once, and its second presentation answers `token_used` and makes the interface show the hijack warning; the redirect file is gone after the first presentation, after 10 minutes, and after stop; a page opened at the plain address in another browser, or by another operating-system user, can neither create nor restore a wallet without the token or a first-run code; once a wallet exists, `POST /session/start` answers `wallet_exists` for any token or code, and within 10 minutes of the launch the interface shows the hijack warning.
38. **Passphrase in the browser**: the passphrase field is a password field; after sign-in the DOM, `sessionStorage`, `localStorage`, IndexedDB, the cache API and the history state hold no passphrase; no answer and no log holds it.
39. **Fresh sign-in by passphrase**: every kind B call of 4.8's table refused 5 minutes after the last passphrase entry, accepted after `POST /session/fresh` with the passphrase.
40. **Tunnel port** (3.3): off by default, a `Host` naming another port is refused; with `--tunnel-port` set, that port and only that port is accepted too, in `Host` and `Origin`; `GET /session` says `handover: false`; a session made under one `Host` is refused under another; a session made under the tunnel port ends 2 minutes after its last request and stream.
41. **Locked status** (4.7; review R11): in **Slice 1**, after a restart with an awaiting-funding factory, `GET /status` without a session has exactly the locked shape, `watching.state = nobody_locked`, `reason = no_bundle`, headline `nothing_needs_you` with its Slice 1 wording; no Slice 1 answer or string says the wallet will leave in time. In 1.0.0, with a live factory: `watching.state = watcher_locked`; `factories_watched`, `unlock_by` and `next_action.height` equal the bundle's to a connection that passed the same-user check; with the peer check made unavailable, the same request gets `dates_hidden: true` and none of those fields (review R6). In both, a byte search finds no amount, outpoint, txid, address, host key or lobby id, and no data file holds a clear date.
42. **The watcher acts** (1.0.0; storage test 19): the simulator restarts a member and never unlocks it; at `leave_by_locked` the tree path is broadcast and `doing.params.watcher` becomes `publishing_tree_steps`, then `waiting_for_unlock` with the headline `waiting_for_unlock`; the commitment is never broadcast while locked; past `unlock_by` the headline is `past_unlock_by`; a tree step held below its step date gives `tree_step_late`; the host publishing its own current commitment of the channel while locked gives `doing.params.watcher = host_closed` and the headline `host_closed`, never `waiting_for_unlock`, and the balance is swept at the next unlock; at the next unlock Activity shows each broadcast the chain confirms.
43. **Nobody watching while locked** (1.0.0): with no key store, with the bundle key made unavailable, and with the bundle replaced by an older one, `watching.state = nobody_locked` with `no_key_store`, `bundle_key_unavailable` and `bundle_refused`, and the locked page says "nobody watches"; with the penalty file cut at an entry boundary, damaged, or of another `file_id`, `watcher_locked` with `penalty_file_short` and that headline, and the watcher still publishes the tree path and the penalties it holds (`spec/exit.md` 5.6 agrees); with the chain view in doubt while locked, `watcher_locked` with `chain_in_doubt`.
44. **Unlock order**: see 23.1 item 20.
45. **Same-user check** (3.4): on the build server, connections from the person's browser and from the person's own SSH tunnel are served; a connection from another account (a test user running `curl`), from `root` and through a root-owned forwarder (a `socat` run as root) gets `403 other_user` and is closed before any byte is read; a peer that connects and closes at once is not served; Windows (1.0.0) the same through `GetExtendedTcpTable`, with a non-elevated browser served and an **elevated browser of the same account refused** (fail closed; review R8), and a peer whose process id was reused between the table read and the token check refused.
46. **Derivation flood** (4.3): 32 connections send `POST /session` with passphrases at once; at most one derivation runs and one waits (a test build counts them); the others answer `rate_limited` without being counted as wrong; memory stays below one derivation's use plus a fixed margin.
47. **Ninth session**: eight sessions open; a ninth sign-in succeeds and the session unused longest answers `401`.
48. **Start token without a counter** (review R5): a page on another site navigates a window to the plain address with five junk fragments, of the token's form and not: nothing is counted, no code is cancelled, no hijack warning appears, and the real token then works; a fragment not of the token's form is never presented. Five wrong typed codes still cancel the codes.
49. **The worker trusts no port** (review R7): a same-origin test page attaches to the running `SharedWorker` and posts `token` with junk and `sign_out`: it receives no `event` or `stream_state`, and the stream and the held token are unchanged; with the tunnel port set no `SharedWorker` is created.
50. **Setup session ended before `create`** (review R9): idle sign-out of a setup session, then the plain address shows "Start Gazpacho again, or type the code it prints"; `gazpacho first-run-code` gives a code that works.
51. **Confined browser** (review R4): on Ubuntu with snap Firefox as the default browser, the redirect file is written in the download folder's owner-only first-run folder and opens; with that folder made impossible, the code flow is used and the code reaches a desktop notification; at no time does any process's command line hold the code or the token.

### 23.3 Secrets never leak

1. After a full Slice 1 run plus each 1.0.0 flow, search the access log, the program log, the terminal output (when not a terminal), every event sent, every `GET` answer, the request-id store, the watch-and-exit bundle and its log (decrypted), the attempts file and the journal (decrypted) for: the wallet passphrase and its SHA-256, the storage key, the socket token, every start token and first-run code, every session token, each of the 24 words in sequence, and the backup bytes. No match is allowed. (The words appear only in the answers of `create` and `reveal` and the requests of `check` and `restore`.)
2. The socket token file and the redirect file have mode 0600 (POSIX) or an owner-only access list set at creation (Windows); the token file exists only while the wallet is unlocked, and the redirect file is gone after the first presentation of its token, its expiry, or a stop. No command line of any process the program starts (the browser launcher included) holds a token, a code or a passphrase.
3. Every URL the interface ever requests (recorded by Playwright) has no fragment, no query parameter outside the allowed list, and no 64-hex segment. The only address carrying a secret is the one in the first-run redirect file, and only in its fragment.
4. `Cache-Control: no-store` on every API answer; the browser's disk cache holds no API answer after a run.
5. **The words in the browser** (12.7): the words stay shown past 2 minutes until Done; after the tab is hidden the DOM holds no word and "Show again" brings them back; after Done, `pagehide`, the 10-minute ceiling, sign-out or lock, the DOM holds no word and the screen's variable is gone, and `sessionStorage`, `localStorage`, IndexedDB, the cache API and the history state hold none; the word fields carry `autocomplete="off"`, `autocorrect="off"`, `autocapitalize="off"` and `spellcheck="false"`; no copy control exists and the shown words are `user-select: none`; the page is served `Cache-Control: no-store`. The permissions policy names `clipboard-write=()`, and the test records, per browser, whether `navigator.clipboard.writeText` is refused (23.6 item T9) without counting it as the defence.
6. **The words in the program** (12.7): in a test build, the buffers that held the words, the entropy and the seed are zero after `create`, `reveal`, `check` and `restore` answer (checked by a hook in the test build, and by a memory search of a core dump taken right after the call).

### 23.4 Contract

1. Every enumeration value in this document exists in the program's code tables, and every one is produced by at least one simulator scenario (section 22 in particular).
2. The interface renders every value with its own wording; a value without wording fails the build.
3. `GET /api/v1/version` matches the interface's compiled-in version.
4. The interface's screens use only the calls listed here (the prototype's rule: "screens use only `window.gzApi`").
5. The tables of 11.2 (chain view, `doing.code` order) and 14.1 (outcome rule) are code tables the program and the interface both read, not copies.

### 23.5 Parser fuzzing

1. The HTTP request line and header parser, the JSON parser, the event-stream writer's input (the event records) and the backup import's framing are fuzzed coverage-guided (libFuzzer or AFL++) under AddressSanitizer and UndefinedBehaviorSanitizer in CI, for a fixed time on every pull request and longer in a nightly run.
2. Seeds include every malformed case of 23.2 items 23 to 26.
3. A crash, a leak or a sanitizer report fails the build; each found input is added to the seeds.

### 23.6 Browser and operating-system behaviour to confirm

The second review's list (its section 4), kept under its names T1 to T11 and extended. Each records what the browser or system actually does; where the result differs from what this document expects, the document changes before the code relies on it.

- **T1** `sessionStorage` isolation between `127.0.0.1:39735` and `127.0.0.1:8080`, and between `127.0.0.1`, `localhost` and `[::1]` at one port (three origins, three sign-ins expected). Duplicate-tab copy; `window.open` with and without `noopener`.
- **T2** `BroadcastChannel`: a page on another port gets nothing. With the tunnel port set and the tunnel down, a test server on the viewing machine at that port posts `ask` on the channel: no `offer` comes (4.4).
- **T3** The `fetch()` stream in a `SharedWorker` created from a page under `require-corp`, with the worker script served as 5.4 says, in Chrome, Firefox and Safari; the elected-tab fallback; `429` not retried; tab freezing and the `reset` after it; a same-origin page attaching to the running worker gets nothing (4.4, review R7).
- **T4** `Clear-Site-Data` on an `http://127.0.0.1` answer in each browser: is `sessionStorage` emptied in every tab? (Nothing depends on it, 4.4.)
- **T5** First run: the `Sec-Fetch-Site`, `Sec-Fetch-Mode` and `Sec-Fetch-Dest` each browser sends for the navigation started by the redirect file (expected `cross-site`, `navigate`, `document`; 5.2); then, after `replaceState`, the history database, session-restore files, synced open tabs and the `Referer` of every request, searched for the token. Repeat with the page failing to load (program not yet listening): the token must not be usable later.
- **T6** First run on Linux with a second user polling `/proc/*/cmdline`, with the browser already running and not running: the token must never appear (it would without the redirect file). Also, by name: **snap Firefox and snap Chromium** (Ubuntu's defaults), a Flatpak Firefox, and a distribution-packaged Firefox: which can open the redirect file from the data folder, which from the download folder's first-run folder, and that the code flow works for the rest; record each result (review R4).
- **T7** Restore screen: type words, then kill the browser and restore tabs; check the field values and search the profile folder's session files for the words. Repeat for back and forward navigation.
- **T8** Password managers: Chrome, Firefox and Safari built-ins, and Bitwarden with default matching. Does each offer the Gazpacho passphrase on another loopback port?
- **T9** `Permissions-Policy: clipboard-write=()` in each browser: is `navigator.clipboard.writeText` refused? Can the shown words be selected and copied by keyboard despite `user-select: none`?
- **T10** Fetch metadata sent by current Safari on every call (5.2 relies on CORP where it is absent).
- **T11** The interface's own page on loopback reaching its own API raises no Local Network Access prompt in Chrome.
- **T12** The same-user check (3.4) on Linux kernels the build server and CI run, with the netlink family available and, separately, only `/proc/net/tcp`; the OpenSSH forwarding process's account for a tunnel (3.3).
- **T13** Chrome's back/forward cache with the pages served `no-store` and the words screen open: the page is not restored with words in it (5.4, 12.7).

---

## 24. Open points

### 24.1 Defaults Slice 1 builds against, for the owner's yes

| # | Default | If the owner chooses otherwise |
|---|---|---|
| D1 | **Answered by the owner** (decision 12, 2026-11-12): the 24 words may appear in the browser under the rules of 12.7. Draft 2 first carried the conservative default of `DESIGN.md` section 13 (words only in a terminal); the owner replaced it | — |
| D2 | **No cookie; the session token in `sessionStorage` and the `X-Gazpacho-Session` header**; a new tab takes the session from an open tab over `BroadcastChannel` (4.4), **except while the tunnel port is set**; every session bound to its `Host` (review N7; accepted by the second review with these two changes) | Memory only (sign in again on every reload) is stricter; a cookie is refused by review F1 |
| D3 | **Idle sign-out 15 minutes** in Slice 1 (4.7). Accepted by the second review | Any value; "never" stays available in 1.0.0 Settings |
| D4 | **`join` and `ready` need no fresh sign-in**, their echo being `seen_current_digest` (4.8, 14.2). Accepted for Slice 1 by the second review; to revisit in 1.0.0 if joining fees come from the member's balance | A fresh sign-in on join would protect against a session someone else picked up, at the cost of the passphrase for every lobby |
| D5 | **Every Lightning payment carries the passphrase in its own request** (1.0.0; 4.8 kind A). Changed from draft 2's 5-minute window on the second review's advice (N5) | A limit below which payments skip it, which reopens a window for small amounts |
| D6 | **Resume from pause needs a fresh sign-in (the passphrase); pause never does** (11.3) | Resume without the passphrase |
| D7 | **Bearer only on the local socket** (4.6) | Bearer on TCP too would let a sandboxed process use a copied token file |
| D8 | **The words check: 3 checks in 24 hours, `ok` only, a failed check locks the session** (12.3) | Fewer or more checks; never which position |
| D9 | **Words shown until Done, hidden while the tab is hidden, cleared at a 10-minute ceiling and on `pagehide`; no clipboard copy** (12.7). Changed from draft 2's 2 minutes on the second review's advice (N9) | A shorter ceiling; a copy button is against the owner's "no clipboard copy by default" |
| D10 | **Sticky outcome codes for 24 hours or until the next join** (11.2) | Any time |
| D11 | **Request ids kept 30 days after their object ends; review and preview ids 10 minutes** (7.4) | Any values; shorter request-id lifetimes reopen the double-effect risk |
| D12 | **A user-added chain server is the operator `you`; trust needs a built-in server among the agreeing ones** (20.3) | Letting the person vouch for an operator weakens the two-operator rule |
| D13 | **Idle signs the browser out and never locks the wallet**; locking is a deliberate button, held while signatures are out or (1.0.0) a received payment is unsettled, and **while anything needs watching it needs the same confirmation as going offline**, echoing `unlock_by` when one exists (never in Slice 1), with a warning that says what the locked watcher still does and that it cannot finish leaving (4.7; reviews N2, R1) | An idle lock would leave the wallet out of rounds, moves and payments without the person noticing, even with the watcher |
| D14 | **Password managers may fill the passphrase** (`autocomplete` set on the field, 12.7), with the guidance of 12.7 on exact host-and-port matching. Accepted by the second review | `autocomplete="off"`: every entry typed by hand |
| D15 | **Passphrase attempts: one a second, then a delay doubling to 15 minutes after 5 wrong, kept across restarts in `attempts.gza`; one counter for every call that runs the derivation, checked before it runs** (4.3). Accepted by the second review with that last part | Other numbers; the offline strength is storage's |
| D16 | **The first-run start token in the fragment of the address, delivered through an owner-only redirect file so it is on no command line; spent at first presentation; a hijack worded loudly** (4.3; review N3) | Only the terminal code, at the cost of an extra step for every new user |
| D17 | **The watcher runs while locked, on by default, from 1.0.0** (4.7; storage 8.7, its open point 15; Slice 1 builds none, review R11); "maximum privacy" (no watching while locked) is a 1.0.0 setting with the offline warning, refused while something is to take out unless confirmed with the `leave_by` it puts at risk (20.2; `spec/exit.md` W5; review R12) | Off by default: a restart would again stop all watching unseen |
| D18 | **Kind A (the passphrase in the request) covers opening a hosted lobby in Slice 1**, besides the words; the early start stays kind B (4.8) | Opening by window (kind B), which is draft 2's rule |
| D19 | **The ninth sign-in ends the session unused longest** (4.2) | Refuse the ninth, which a few tabs closed without signing out would turn into a lock-out until idle sign-out |
| D20 | **Lock refused while hosting an Open lobby** (4.7) | Lock cancels the hosted lobby first, which acts on the person's behalf without asking |

### 24.2 Other open points

1. Closed: ports 39735 (signet) and 39736 (testnet4), accepted by the owner.
2. Closed: one optional extra tunnel port, off by default, with its risks stated (3.3).
3. **First-run code and start token** lifetimes (10 minutes), the code's length (50 bits) and attempt limit (5): proposed.
4. **No browser launch on Windows** (1.0.0; review F23): started at login, from a shortcut set to run minimised, or by a launcher, the program may not be able to open the browser at first run, and then prints the first-run code to a console that may not exist. Normal sign-in (the passphrase) is unaffected. A native message box or tray item that opens the first-run address would keep the code out of sight. Until decided, a first run on Windows needs the program started from a console.
5. **The local socket on Windows** (1.0.0): a named pipe with an owner-only security descriptor by default; AF_UNIX only once its access list is shown to be enforced on connect.
6. Closed: the words in the browser (owner decision 12; D1).
7. Closed: the wallet passphrase is the sign-in and decrypts the files from the start (owner decisions 13, 14). The cryptography is `spec/storage-encryption.md` draft 3 (not yet reviewed; draft 2 was confirmed by its review's second round); the API uses its six operations (4), its unlock order (4.7), its passphrase rules (4.1), its attempts file (12.3) and, in 1.0.0, its watcher (8.7). Its own open points bear on this document: the owner's yes to libsodium, Argon2id at 256 MiB and the 15-character minimum (its point 1); **two owner amendments still pending** on which this API now depends, decision 13's export format and decision 14's "after lock only the watcher runs" (its point 1); NFC in C (point 2); the blocklist and suggestion word list (point 3); the plain socket token (point 11). If storage changes under review, this document follows.
8. **Join requests, admission by approval and invitation-only lobbies** have no protocol messages yet. Invitation-only lobbies are 1.0.0 by owner decision 10, and need `terms.md` type 38 made valid; invitations' form and expiry are not designed.
9. Closed for Slice 1: one joined lobby and one hosted lobby at a time (owner, 2026-11-12). 1.0.0 allows several (options map, "several factories"); request ids already guard against the double effects several lobbies would allow (7.4).
10. **The unfinished round**: what the app does with payments, and what it says, if a creation is never funded or a move try never settles (critique question 9, H.5). The API reports the state; the behaviour is the signing round's to decide.
11. **Fee cover**: `fee_cover`'s rule, given no reserve in 1.0.0 (decision 6) and `safety-rule.md` C3 (critique H.7).
12. **"Open the app by" margin**: how much below the safe absence (critique H.3).
13. **The preset numbers** (critique question 13), and the member's default conditions (`OPEN-QUESTIONS.md` W1).
14. Closed in draft 2: the activity history and every other piece of saved API state have a home (7.5); their record type numbers are now assigned (7.5; `journal.md` 9.1), and only their field numbers wait for W3.
15. **Restore when the host never answers** (critique question 15).
16. Closed for Slice 1: the copying rule is accepted (owner, 2026-11-12).
17. **Hosting schedule, Tor, Nostr reminders, fiat display, a second watching machine**: later; reserved names only.
18. **The threat model** (`docs/THREAT-MODEL.md`) has no row for the local interface. Section 5.7 is the draft of that row; it now includes the same-user check (3.4) and the locked watcher (4.7). Its section 2.7 now says the files are encrypted from Slice 1 on.
19. **How long an abandoned creation stays `still_watched`** when its funding never appears and no input is ever spent: until the user removes it, or a cut-off (16.1).
20. **The 10-second limit on person-started discovery queries** is this API's own (21); to be recorded in `discovery.md`.
21. **Seat removal and standby seats in Slice 1** (owner decision 10, applied to Slice 1 provisionally, the owner's yes pending; 2.1). Removal is buildable now (seat state 6). Standby seats need protocol messages (`messages.md` section 9); until then the API's shape exists and answers `null`. Recommendation: confirm removal for Slice 1 now; keep standby's shape in Slice 1 but its behaviour with the 1.0.0 lobby work, unless the messages are written for Slice 1 too.
22. Closed: the documents that said Slice 1 is unencrypted (`journal.md` sections 2 and 13, `docs/notes/wallet-keys.md` section 8, `docs/THREAT-MODEL.md` 2.7) were updated with storage draft 3.
23. **What the locked watcher does not cover** (1.0.0): the commitment step of leaving (it needs the passphrase by `unlock_by`), moves to the next factory (new signatures), the host's duties (answering members, a ready check, cancelling at a deadline), and rebroadcasting a host's own signed funding. Whether that funding belongs in the bundle is `spec/exit.md` 9.4's (review R12); the recommendation stays to put it in (it is fully signed and pays only the factory). Payments in flight are settled: a lock is **held** while an incoming payment's secret is released and unsettled (4.7), never refused; moves stay out (they need signing by nature).
24. **A host service after a reboot** must sign and route, which the watcher cannot; it needs an unattended unlock. Storage proposes `--passphrase-fd` from a service manager's protected store (storage 8.6 item 8, its open point 10), owner decision. Recommendation: accept for hosts in 1.0.0 with the interface saying "This computer unlocks Gazpacho by itself". Slice 1's members have no watcher (4.7): a restarted Slice 1 member watches nothing until the passphrase is typed, which the locked page says (`nobody_locked`, reason `no_bundle`). Slice 1 needs no OS key store at all (4.7; storage 8.7.3, 12.3).
25. **A sign-in phrase against a squatting page** (review N4, 1.0.0): a phrase chosen at setup, kept in an owner-only file outside the encrypted store, shown above the passphrase field, which another account's squatter cannot read. Recommendation: build it in 1.0.0 for systems without the same-user check (macOS) and as an option elsewhere; it does not help against a squatter of the person's own account.
26. **The same-user check on macOS** (3.4): not assessed. The review of draft 3 (R8) proposes `libproc`: `proc_listpids` over the program's own user, then `proc_pidfdinfo` with `PROC_PIDFDSOCKETINFO`, refusing a peer found in none of the user's own processes. Recommendation: assess it before 1.0.0 ships on macOS; until then status and Settings say the check is unavailable, and the locked status hides its dates (4.7).
27. **Lifetimes proposed in draft 3**: the tunnel-port session end after 2 minutes (3.3), the words ceiling of 10 minutes (12.7), a `check_id`'s 10 minutes (12.3).
28. Closed after cross-spec review 1 (D8): `spec/exit.md` 10.2's other new values are folded in: the attention codes `exit_needs_fee_coin`, `payments_stopped_for_exit`, `exit_step_late`, `exit_step_held_back`, `exit_fee_budget_reached`, `exit_missed`, `funding_double_spent`, `restored_commitment_choice`, `unexplained_spend` (11.4); `creation_dead`'s `params.cause` (11.2); `ended_how = void_funding` and the factory object's exit fields (16.1). Their wording is proposed, like every string of section 22.
29. **Confined browsers** (4.3, review R4): whether the download folder is readable by every common snap and Flatpak browser package (test 23.6 item T6), and what to do on Linux desktops where it is not (the code flow then, always).
30. **Headline wording** (4.7): the table's strings are proposed; the owner's yes to them, as to every string of section 22.
31. Closed after cross-spec review 1 (D1): a short, damaged or unrecognised penalty file is used for what it holds, the watcher keeps going, and status reports `watcher_locked` with `penalty_file_short` (`at_risk`), in storage 8.7.4 rule 7, `spec/exit.md` 5.6 and here alike. Only a refused bundle gives `nobody_locked`.
