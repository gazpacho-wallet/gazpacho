# The local API: program to interface

Specification draft 1, 2026-11-12. Not reviewed. It replaces the prototype's proposal (`web/API.md` on branch `ui-prototype`), which was written from the screens' side and left the start-up token, paging and the restored wallet undesigned.

This is the interface between the `gazpacho` program (C; host and member in one, with no role question, owner decision 4) and its local web interface (concept H, `docs/ux/concept-h-recommended.html`). The program serves the interface and answers this API. Nothing else talks to it in 1.0.0 except the program's own command line and the test harness.

Items marked **(open)** are listed in section 24. Values marked **proposed** are first choices the owner has not confirmed.

**Sources.** `web/API.md` and `web/README.md` (`ui-prototype`); `docs/ux/options-map.html` and `docs/ux/concept-h-recommended.html` (`ux-concepts`); `docs/ux/decisions.md`, `docs/SLICE1-WORK.md`, `docs/SLICES.md`, `docs/DESIGN.md`, `docs/THREAT-MODEL.md`, `docs/reviews/ux-critique.md`, `spec/messages.md`, `spec/terms.md`, `spec/journal.md`, `spec/signing-round.md`, `spec/safety-rule.md`, `spec/discovery.md` (`specs-slice1`).

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
| **Keys and channel state never enter the browser** | No private key, seed, nonce, channel state, signed transaction or journal record crosses this API. Two exceptions, both deliberate and both behind a fresh sign-in (section 4.6): the 24 words, when the user asks to see or write them down, and the backup file (not yet encrypted in Slice 1), when the user exports it |
| **Loopback only** | The program listens on the local machine only. There is no remote access in 1.0.0 (section 3) |
| **No secrets in URLs or logs** | Tokens, sign-in codes, words and backup bytes travel only in request and response bodies or in a cookie. Never in a path, a query string, a fragment, a log line or an event (section 5.5) |
| **One API for every client** | The interface, the command line and the test harness use the same calls. The command line authenticates differently (section 4.5) |
| **A status is never softened** | Every state the safety wording must distinguish has its own value (section 22). The API never merges "did not sign" with "signing did not finish", or "nobody is watching" with "watching" |

---

## 2. Release marks and the Slice 1 subset

Every call and every reserved field carries one mark.

| Mark | Meaning |
|---|---|
| **S1** | Slice 1's minimum. The program and the interface build these first. Slice 1 is done when one host and at least three members, each a separate process, form a factory on signet twice from a clean start, and a member whose conditions are not met is seen to refuse (`SLICES.md`) |
| **1.0.0** | In the first release, after Slice 1. Built with the engine that needs it (payments with Slice 2, leaving alone with Slice 3, rotation with M4) |
| **1.1.0 reserved** | Path and field names are fixed now, so the interface can keep its hidden place for them (decision 3). The program answers `501` with code `not_in_this_release` and `params.release = "1.1.0"` |
| **later reserved** | As 1.1.0, with `params.release = "later"` |

### 2.1 The Slice 1 subset in one table

| Area | Calls | Why Slice 1 needs it |
|---|---|---|
| Session | `POST /api/v1/session`, `GET /api/v1/session`, `DELETE /api/v1/session`, `POST /api/v1/session/unlock`, `POST /api/v1/session/fresh`, `POST /api/v1/sign-in-codes` (command line only) | Nothing else works without a session |
| Version | `GET /api/v1/version` | The interface checks it matches |
| Events | `GET /api/v1/events` | Signing takes seconds; the screen must follow it live |
| Status | `GET /api/v1/status`, `PUT /api/v1/pause` | The strip is on every screen. Pause must work from the first build |
| Keys | `GET /api/v1/wallet/setup`, `POST /api/v1/wallet/create`, `POST /api/v1/wallet/phrase/reveal`, `POST /api/v1/wallet/phrase/check-start`, `POST /api/v1/wallet/phrase/check`, `POST /api/v1/wallet/finish-setup` | A member needs keys to join; a host to sign terms and fund |
| Conditions | `GET /api/v1/conditions`, `POST /api/v1/conditions/preview`, `PUT /api/v1/conditions` | "A member whose conditions are not met is seen to refuse" |
| Finding the host | `POST /api/v1/discovery/query`, `GET /api/v1/settings/connections` (read only: chain servers and known hosts) | Slice 1 has no Nostr: "the member is given the host's address directly". A query by address also adds the host to the known list |
| Lobbies | `GET /api/v1/lobbies`, `GET /api/v1/lobbies/{id}`, `POST /api/v1/lobbies/{id}/join`, `PUT /api/v1/lobbies/{id}/ready`, `POST /api/v1/lobbies/{id}/leave` | Join and ready |
| Hosting | `POST /api/v1/host/preview`, `POST /api/v1/host/lobbies`, `GET /api/v1/host/lobbies`, `GET /api/v1/host/lobbies/{id}`, `POST /api/v1/host/lobbies/{id}/start`, `POST /api/v1/host/lobbies/{id}/cancel` | Open and start |
| Factories | `GET /api/v1/factories`, `GET /api/v1/factories/{id}` | "The screen shows the lobby, the tree and the confirmation" |
| Funding | `GET /api/v1/wallet`, `POST /api/v1/wallet/address` | The host receives signet coins and funds last; the funding's confirmations show in the factory |
| Record | `GET /api/v1/activity`, `GET /api/v1/activity/{id}` | The refusal, with its two numbers, is seen afterwards |

Everything else is 1.0.0 or reserved. Every **status value** of section 22 exists from Slice 1 on, even where Slice 1 cannot reach it, so the interface's tables are written once.

---

## 3. Transport

### 3.1 HTTP on loopback

- **HTTP/1.1** with JSON bodies (RFC 8259, UTF-8). No HTTP/2, no TLS: traffic on the loopback interface never leaves the machine, and a certificate for `127.0.0.1` would teach users to click through warnings.
- The program **listens on `127.0.0.1` only**, and also on `::1` when the machine has it (a second socket). Never on the unspecified (all-interfaces) address, for IPv4 or IPv6, or on any other interface address.
- **Port:** proposed default **39735** on signet and **39736** on testnet4 **(open)**, so two networks can run side by side. Set with `--interface-port` or Settings, Application (section 20.4; takes effect at the next start).
- **Binding rules.**

| Case | What the program does |
|---|---|
| The configured address is not a loopback literal (`127.0.0.1`, `::1`) | Refuses to start, and says why. There is no flag to override this in 1.0.0 |
| The port is in use | Refuses to start the interface and says so. It never picks another port by itself: a bookmark would then open whatever else is listening, which could be a program pretending to be Gazpacho |
| `SO_REUSEADDR`/`SO_REUSEPORT` | Not set on POSIX. On Windows the socket is opened with `SO_EXCLUSIVEADDRUSE`, so no other process can bind the same port alongside it |
| `--no-interface` | No listening socket at all. The command line still works over the local socket (3.2) |

- **Limits** (proposed): 32 open connections; request line and headers 16 KiB; JSON body 64 KiB; backup upload 16 MiB (section 12.6); headers must arrive within 10 s and a body within 30 s; idle keep-alive connections closed after 60 s. Past a limit the connection is closed, or answered `413`/`431`.
- Request bodies need `Content-Length`. `Transfer-Encoding: chunked` in a request is refused with `411`; a request with both is refused with `400` (no request smuggling through a proxy that is not supposed to exist).
- `Connection: Upgrade` (WebSocket or anything else) is refused with `400`, code `no_upgrade`.

### 3.2 The local socket, for the command line

- On POSIX, the program also listens on a Unix-domain socket, `interface.sock` in its data folder, inside a folder readable by the owner only (mode 0700; the socket 0600). On Windows, an AF_UNIX socket in the data folder, whose access list allows the owner only **(open: AF_UNIX against a named pipe on older Windows)**.
- It speaks exactly the same HTTP/1.1 API. The `Host` header must be `localhost`. Browsers cannot reach it.
- Every request on it still needs the start-up token (section 4.5). The folder permissions are a second wall, not the first.

### 3.3 What remote viewing means in 1.0.0

There is none. A person who runs Gazpacho on a server and looks at it from another machine (as Slice 1 does on the build server, `SLICES.md`) uses an SSH tunnel that ends on the server's loopback. To the program that is a loopback connection, and every rule here applies unchanged, including the `Host` check: the tunnel's local port must equal the program's port **(open: allow a configured second port)**.

---

## 4. Authentication

### 4.1 The pieces

| Piece | What it is | Lives | Lifetime |
|---|---|---|---|
| **Start-up token** | 32 random bytes from the operating system, written as 43 characters of base64url | The program's memory, and the file `interface-token` in the data folder (POSIX mode 0600; Windows: owner-only access list), so the same user's command line can read it | Made fresh at every start. Rotated on demand (4.7). The file is deleted on a clean stop |
| **Sign-in code** | 10 characters from a 32-letter alphabet without look-alikes, shown as `ABCDE-FGHJK` (50 bits) | The program's memory | One use. 10 minutes. At most 3 unused at a time |
| **Session** | 32 random bytes, sent by the browser as the cookie `gz_session_<port>` | The program's memory only | Until sign-out, rotation, idle lock (4.6) or program stop. At most 8 at a time; the oldest ends when a ninth starts |
| **Session check value** | 32 random bytes, base64url, one per session | The program's memory; the interface keeps it in a JavaScript variable only | As the session |

Nothing about sessions is saved to disk. A restart signs everyone out.

### 4.2 How the browser gets in, safely

The browser never receives the start-up token. It receives a session in exchange for a sign-in code that a person typed.

1. The program starts. If its standard output is a terminal, it prints the address and one sign-in code:
   ```
   Gazpacho interface: http://127.0.0.1:39735
   Sign-in code (one use, 10 minutes): ABCDE-FGHJK
   ```
   If standard output is not a terminal (a service, a redirect to a file), **no code is printed**, so a code never lands in a log.
2. A person opens the address. The interface loads (static files need no session) and calls `GET /api/v1/session`, which says "not signed in". The interface shows one field: the sign-in code.
3. The person types the code. The interface sends `POST /api/v1/session` with `{ "code": "ABCDE-FGHJK" }`.
4. The program checks the code, uses it up, starts a session, and answers with `Set-Cookie` and, in the body, the session check value.
5. From then on the browser sends the cookie automatically, and the interface adds the session check value as the header `X-Gazpacho-Check` on every request that changes something (section 5.3).

A new code at any time: `gazpacho sign-in-code` (prints one; reads the token file and asks the running program over the local socket), or `gazpacho open` (prints one and opens the default browser at the plain address, with nothing secret in it).

**Why not put a code in the address** (`http://127.0.0.1:39735/#code=…`, as some local tools do): addresses end up in browser history, synced history, screenshots, shell history and crash reports. A one-use code would be spent by then, but the rule "no secret in any URL" is simpler to test than "no live secret in any URL", so it holds without exceptions.

**Why typing is enough.** 50 bits, one use, 10 minutes, and the attempt limits below. An attacker who can read the person's terminal can read the token file too; that is the "same user" limit of section 5.7.

**Attempt limits.** One sign-in attempt per second per program, whatever the source. After 5 wrong codes in a row, every unused code is cancelled and the person needs a new one. Wrong attempts are logged as a count, never with the text typed.

### 4.3 The cookie

```
Set-Cookie: gz_session_39735=<base64url>; Path=/; HttpOnly; SameSite=Strict
```

- `HttpOnly`: page script cannot read it, so a script injection cannot copy it out.
- `SameSite=Strict`: other sites' pages do not send it.
- No `Domain`: host-only.
- No `Secure`: the scheme is `http`. Browsers treat `http://127.0.0.1` as a secure context, but their handling of `Secure` cookies on it has differed; the defences below do not depend on it.
- No `Max-Age`: it ends with the browser session, and the program forgets it at the latest when it stops.
- **The port is in the name.** Cookies do not separate ports: another web application on the same machine, on another port, shares the cookie jar for `127.0.0.1`. The port in the name avoids collisions; it does not stop that application from sending requests here. Section 5 does.

### 4.4 Session calls

All **S1**.

| Call | Request | Answer | Errors |
|---|---|---|---|
| `GET /api/v1/session` | | `{ "signed_in": false }`, or `{ "signed_in": true, "state": "open"\|"locked", "check": "<value>", "fresh_until_at": 1794434400, "lock_after_idle_s": 900, "started_at": … }`. Needs no session; never returns anything else to a caller without one | |
| `POST /api/v1/session` | `{ "code": "ABCDE-FGHJK" }` (dash and case ignored) | `200`, `Set-Cookie`, and the same body as `GET` | `bad_code`, `code_expired`, `too_many_attempts`, `rate_limited` |
| `POST /api/v1/session/unlock` | `{ "code": … }` | Session open again, fresh (4.6) | As above |
| `POST /api/v1/session/fresh` | `{ "code": … }` | `{ "fresh_until_at": … }` | As above |
| `POST /api/v1/session/lock` | | `{ "state": "locked" }` | |
| `DELETE /api/v1/session` | | `204`; cookie cleared | |
| `POST /api/v1/session/revoke-all` | `{ "confirm": "revoke_all" }` | `204`. Every session ends, every code is cancelled, the start-up token is rotated and its file rewritten. Needs a fresh session | `fresh_sign_in_needed` |

### 4.5 The command line and the test harness

- A client that is not a browser sends `Authorization: Bearer <start-up token>`, read from the token file. No cookie, no session check value.
- A request carrying both `Authorization` and a session cookie is refused (`400`, `two_credentials`).
- A request carrying `Authorization` and an `Origin` header is refused (`403`, `forbidden_origin`): browsers send `Origin`, and no web page should ever hold the token.
- `POST /api/v1/sign-in-codes` (bearer only, **S1**) makes a new sign-in code: `{ "code": "ABCDE-FGHJK", "expires_at": … }`. A session cookie is refused here: a browser session must not mint codes for other browsers.

### 4.6 Lock, idle and fresh sign-in

- **Idle lock.** Settings, Application, "Lock after being idle for": never, 15 minutes or 1 hour (concept H). Idle means no request from that session other than the event stream. A locked session answers `401` with code `locked` to every call except `GET /api/v1/session`, `POST /api/v1/session/unlock` and `DELETE /api/v1/session`; its event stream receives a `session` event and is closed.
- **A lock is not a pause.** A locked app still watches, still answers, and still signs for lobbies the person joined. The interface must say so (concept H, Settings, Application). Pause is section 11.3.
- **Fresh sign-in.** Some calls need a session that entered a sign-in code in the last 5 minutes (`fresh_until_at`). Without one they answer `403`, code `fresh_sign_in_needed`, and the interface asks for a code (`POST /api/v1/session/fresh`).

| Calls that need a fresh sign-in | Why |
|---|---|
| Showing the 24 words; exporting a backup; importing a backup; restoring over a wallet; removing the wallet | They reveal or replace keys |
| Changing the network; changing the interface port | They change what the program is |
| `revoke-all` | It signs everyone out |
| Starting to leave a factory alone; sending coins on chain | Cannot be undone |

A wallet passphrase (lock with a password the program can check, and encryption at rest) is not in Slice 1: the journal is not encrypted yet (`journal.md` open point 1). When it arrives, a fresh sign-in also asks for it **(open)**.

### 4.7 Rotation and revocation

| Event | Token | Sessions | Codes |
|---|---|---|---|
| Program start | New | None survive | None survive |
| `revoke-all` | New; file rewritten | All end; event streams closed | All cancelled |
| Settings, Application, "Make a new one" (the start-up token) | Same as `revoke-all` | | |
| 5 wrong codes in a row | Unchanged | Unchanged | All cancelled |
| Sign-out | Unchanged | That one ends | Unchanged |

There is no call that returns the start-up token. Concept H's "Show" button for the token is replaced by "Show a sign-in code", which calls nothing new: the code is printed by the command line, not by the browser.

---

## 5. Browser security

The threat: a web page from anywhere, open in the same browser as the interface, tries to read from or act on this API. Or a hostile name, description or note written by a host or member tries to run as script inside the interface.

### 5.1 Host check, against DNS rebinding

Every request's `Host` header must be exactly one of:

| Socket | Allowed `Host` |
|---|---|
| TCP | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` |
| Local socket | `localhost` |

Anything else, a missing `Host`, or two `Host` headers: `421 Misdirected Request`, code `bad_host`, with no other content. This is checked before anything else, including static files. A page on `rebind.attacker.example` whose name has been pointed at `127.0.0.1` sends `Host: rebind.attacker.example:39735` and is refused.

### 5.2 Origin and fetch metadata

- **Every request that is not `GET` or `HEAD` must carry `Origin`**, and it must equal `http://` followed by the request's `Host` value. `Origin: null`, another port, `https`, or a missing `Origin` on a session request: `403`, code `forbidden_origin`. Bearer requests (4.5) must carry no `Origin`.
- **`GET` and `HEAD`** with an `Origin` header follow the same rule.
- **`Sec-Fetch-Site`**, when present: API calls need `same-origin`; static files and `GET /` also accept `none` (the person typed the address). `same-site` is refused: other ports on `127.0.0.1` are "same site" to a browser. `cross-site` is refused.
- **`Sec-Fetch-Dest`** on `GET /api/v1/…`, when present, must be `empty` (fetch, or the event stream). An `<img>`, `<script>` or `<iframe>` pointing at an API path is refused with `403`.

### 5.3 No CORS, and the CSRF defence

- **No CORS at all.** No response ever carries an `Access-Control-Allow-*` header, including `Access-Control-Allow-Private-Network`. `OPTIONS` is answered `405`, code `no_cors`. So a cross-origin request that needs a preflight never reaches a handler, and a browser's private-network check from a public page fails.
- **JSON only.** A request with a body must have `Content-Type: application/json` (an optional `charset=utf-8` is allowed), except the backup import, which must be `application/octet-stream`. Both force a preflight across origins. `text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data` (the types an HTML form can send without a preflight) are refused with `415`, code `bad_content_type`, before the body is read.
- **Session check header.** Every session request other than `GET` and `HEAD` carries `X-Gazpacho-Check` equal to the session's check value. Missing or wrong: `403`, code `bad_check`. A page on another origin, including another port on `127.0.0.1`, cannot read the value, because `GET /api/v1/session` is same-origin only.
- **`GET` changes nothing**, anywhere in this API. Showing the 24 words is a `POST` for this reason too.

Four walls: `SameSite=Strict`, the `Origin` check, the content type, the check header. Each test in section 23.2 removes one and expects a refusal from the others as well.

### 5.4 The interface's own headers

Every response for the interface's pages (`/`, `/index.html`):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self';
  form-action 'none'; frame-ancestors 'none'; base-uri 'none';
  require-trusted-types-for 'script'; trusted-types 'none'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), payment=()
Cache-Control: no-cache
```

- **No inline script and no inline style**, as the prototype already requires (`web/README.md`). No `unsafe-inline`, no `unsafe-eval`, no `data:` or `blob:` sources. QR codes are drawn as SVG elements built through the DOM.
- **Trusted Types with no policy** makes `innerHTML` and similar sinks throw in browsers that support it. The prototype already inserts all text as text (`gz.util.h`).
- `camera=()` until QR scanning arrives (later reserved). Turning it on is a change to this spec.
- Every API response: `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`.
- **Static files** are compiled into the program. No file is read from disk at request time, so there is no path to traverse. Unknown paths answer `404`. A test build may serve from a folder (`--interface-dir`), refused in release builds.

### 5.5 No secrets in URLs or logs

| Rule | How it is enforced |
|---|---|
| Paths hold identifiers only: lobby fingerprints, factory identifiers, payment and activity ids. None of them grants anything | Review rule; the identifiers are listed in 7.3 |
| A query string holds paging cursors, filters and sort orders only | A query parameter named `token`, `code`, `phrase`, `words`, `seed`, `key`, `password`, `invoice` or `backup` is refused with `400`, code `secret_in_url`, and its value is not logged |
| The access log records time, method, the path **pattern** (`/api/v1/lobbies/{id}`), status, duration and session number (a counter, not the cookie) | No headers, no bodies, no query values. A test searches every log written during a Slice 1 run for every secret the run made (23.3) |
| Error messages never quote the request | `message` is fixed text per code |
| The event stream carries topics and identifiers only | Section 10 |
| Invitations hold an unlisted lobby's identifier, which is a capability (`messages.md` 6.1) | They travel in bodies only, never in this API's URLs |

### 5.6 Text written by other people

Hosts write lobby names, aliases, descriptions and notes; members may write display names. The API returns each such string as an object, never as a bare string:

```json
{ "text": "Tomato Garden, daily factory", "by": "host", "checked": false }
```

`by` is `host`, `member`, `sender` (an invoice's note) or `you`. `checked` is always `false` for text: the program checks signatures, not meaning. The interface quotes it as text written by that party, never in the app's voice (critique, section 3). The program limits these strings to their protocol sizes, drops control characters other than newline, and never interprets them.

### 5.7 What this does not defend

| Not defended | Why |
|---|---|
| Another program running as the same user | It can read the token file, the key file and the journal directly. Operating-system accounts are the boundary |
| A browser extension with access to all sites | It runs inside the page. Users should not run such extensions with a wallet open |
| A page learning that Gazpacho is running (timing a refused request) | Refusals still take time. Accepted; it reveals that a port is open, nothing more |
| Another local web application the person visits, on another port | Same site to the browser, so `SameSite` does not stop it; the `Origin`, check-header and content-type walls do. It can still see that the port answers |
| A shoulder-surfer reading a sign-in code | One use and 10 minutes |

Other operating-system users on the same machine can connect to `127.0.0.1`. They get the sign-in page and nothing else without a code (test 23.2, item 31).

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
  "due_height": 333172,
  "blocks_left": 2735,
  "due_at_estimate": 1796378400,
  "at_zero": { "code": "starts_leaving_alone", "needs": ["app_running", "fee_coins"] },
  "source": "worked_out",
  "provenance": {
    "code": "end_less_exit_less_margin",
    "inputs": { "end_height": 334180, "exit_blocks": 864, "margin_blocks": 144, "extra_margin_blocks": 0 }
  },
  "state": "ok"
}
```

| Field | Values |
|---|---|
| `kind` | `open_app_by`, `lobby_starts_by`, `ready_check_answer_by`, `signing_ends_by`, `funding_deadline`, `unfinished_deadline`, `move_window_opens`, `move_try`, `move_by`, `start_leaving_by`, `leave_step_due`, `factory_ends`, `payment_back_by`, `invoice_expires`, `listing_renew_by` (host), `host_fund_by` (host), `host_online_for_try` (host) |
| `at_zero.code` | What happens at zero: `nobody_answers_old_state`, `lobby_applies_start_rule`, `lobby_cancelled`, `round_abandoned`, `last_try_passes`, `next_date_takes_over`, `starts_leaving_alone`, `step_deadline_passes`, `factory_end_rule_applies`, `invoice_unpayable`, `listing_drops`, `lobby_cancelled_by_host_absence` |
| `at_zero.needs` | What the outcome depends on: `app_running`, `fee_coins`, `host_answers`, `watcher` (later). Empty when nothing is needed |
| `source` | `signed_term` (the date follows from the host's signed terms) or `worked_out` (this program computed it) |
| `provenance.code` | `term_start_plus_life`, `term_window_before_end`, `end_less_exit_less_margin`, `revocation_window_less_margin`, `ack_height_plus_deadline`, `signing_budget_from_sent`, `invoice_expiry`, `payment_deadline` |
| `state` | `not_yet`, `ok`, `soon`, `urgent`, `passed` |

`open_app_by` always includes a margin below the safe absence (critique H.3: "well within a day", never the whole window).

### 7.3 Identifiers

| Thing | Identifier | Example |
|---|---|---|
| Lobby | Its rules fingerprint: `outer_digest`, 64 hex (`terms.md` section 6) | `7f3a…c21e` |
| Factory | The fingerprint of the lobby it came from. One lobby makes at most one factory; a move goes to a new lobby with a new fingerprint | same as its lobby |
| Short fingerprint | First 4 and last 4 hex characters, for display. Never used to look anything up | `7f3a…c21e` |
| Seat (host view) | 16 hex, local to the host's program | |
| Host | `host_key`, 66 hex | |
| Payment, invoice, activity entry, request id | Opaque, 1 to 64 characters `[A-Za-z0-9_-]`, local to this program | `pay_3`, `act_1182` |
| Transaction | txid, 64 hex | |

None of these grants anything except an unlisted lobby's fingerprint, which travels only in bodies (5.5).

### 7.4 Requests that act

- A call that sends something outward (join, ready, open a lobby, start, pay, send coins, leave alone) takes a `request_id` chosen by the client. The same `request_id` again returns the first answer and does nothing new. The program keeps request ids for the run.
- A call that changes a stored object takes `based_on_version` (the object's `version` from the last read). If the object changed since, `409`, code `changed_elsewhere`. This protects against two browser tabs.
- An action answers when the core has taken it and every save it asked for is confirmed (`DESIGN.md` section 4: save before send). It answers `202 Accepted` with the object's state when the outcome depends on other parties (`joining`, `starting`), and `200` when the outcome is already known. The final outcome arrives through the event stream.

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
| 400 | `two_credentials`, `no_upgrade` | Sections 4.5, 3.1 |
| 401 | `not_signed_in` | No session or token, or an unknown one |
| 401 | `locked` | Section 4.6 |
| 403 | `forbidden_origin`, `bad_check` | Section 5 |
| 403 | `fresh_sign_in_needed` | Section 4.6 |
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
| 503 | `node_stopped` | The core stopped after a storage failure or a refused step, and is being rebuilt from storage (`DESIGN.md` section 4). `params.reason`: `storage_failed`, `storage_full`, `journal_corrupt`, `rebuilding` |
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

### 10.1 Server-sent events, not WebSocket

`GET /api/v1/events` (**S1**) is a server-sent event stream (`text/event-stream`).

| | Server-sent events | WebSocket |
|---|---|---|
| Direction needed | Program to interface only. Every action is an ordinary request | Two-way; the second direction is unused |
| Security | An ordinary `GET` under every rule of section 5: cookie, `Host`, `Origin`, fetch metadata | Not covered by the same-origin policy: any page can open one and must be refused by a separate `Origin` check (cross-site WebSocket hijacking) |
| Code in the C program | A response that stays open and writes lines | An upgrade handshake, frame parser, masking, ping and close: more parsing of untrusted input in C |
| Reconnects | Built into the browser, with `Last-Event-ID` | Written by hand |
| Cost | One HTTP/1.1 connection per tab, out of the browser's six per host | One connection |

Server-sent events give everything needed with less attack surface. WebSocket is not offered (3.1 refuses upgrades).

### 10.2 What an event says

As in the prototype: an event says **which area changed**, never the new content. The interface then asks for what it shows. One source of truth, and a missed event is harmless.

```
id: 7c1e9a04-1532
event: change
data: {"topic":"lobby","id":"7f3a…(64 hex)","seq":1532}

```

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
| `wallet` | | On-chain coins and transactions |
| `activity` | | A new activity entry |
| `discovery` | | The lobby list or the host list |
| `settings` | | Any settings scope, backup times, server checks |
| `hosting` | | Hosting overview, ladder, earnings, setup |
| `reset` | | Everything: draw again from nothing (after a restore, after the core was rebuilt from storage, or when the client is too far behind) |

### 10.3 Order, reconnects, limits

- `seq` rises by one for every event in a run. The event `id` is `<run_id>-<seq>`.
- The program keeps the last 256 events. On reconnect with `Last-Event-ID`: if the run is the same and the events are still held, it replays them; otherwise it sends one `reset`.
- A comment line (`: keep-alive`) every 15 s, so a dead connection is noticed. `retry: 2000` asks the browser to wait 2 s before reconnecting.
- Events of one topic and id are merged: at most one per 250 ms, the latest wins (a busy lobby changes counts many times a second).
- At most 4 streams per session; a fifth closes the oldest. At most 16 in all.
- Signing never waits for a slow stream. A stream whose unsent data passes 64 KiB is closed; its reconnect gets `reset`.

---

## 11. Status and the always-present strip

### 11.1 `GET /api/v1/status` (S1)

One call gives everything that is on every screen: the strip, the attention list, "my money" and the network marker. The interface calls it at start and on every `status` event.

```json
{
  "version": 412,
  "network": { "id": "signet", "test_coins": true },
  "wallet": "ready",
  "pause": { "state": "off", "since_at": null },
  "doing": { "code": "in_lobby_waiting", "lobby_id": "7f3a…", "params": { "ready": 38, "target": 50, "minimum": 30 } },
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
    "covered_sat": null,
    "as_of_height": 330437,
    "chain_view": "trusted"
  },
  "attention": [ ],
  "while_closed": { "id": "wc_19", "seen": false }
}
```

### 11.2 The strip's parts and their values

**`wallet`**

| Value | Meaning |
|---|---|
| `none` | No wallet yet: first run |
| `created_not_finished` | Keys made; setup not finished |
| `ready` | |
| `restoring` | Restored; waiting for the host or the chain to show current data. Balances are not confirmed and nothing can be paid or received |
| `node_stopped` | The core stopped (storage failure, refused step, corrupt journal) and is being rebuilt, or cannot start. `doing` says which |

**`pause.state`**

| Value | Meaning |
|---|---|
| `off` | |
| `on` | Signs nothing new and joins nothing until resumed. It left the lobbies that had not started. Dates still apply and watching goes on |
| `held_for_signing` | The person pressed Pause during the seconds of signing. It takes effect when signing ends. `params.lobby_id` |

**`doing.code`**: what the app is doing and why. One value at a time, the most important first.

| Value | Meaning | Reachable in |
|---|---|---|
| `no_wallet` | First run | S1 |
| `node_stopped` | See `wallet`; `params.reason` as in 8.1 | S1 |
| `restoring` | Waiting for current data after a restore | 1.0.0 |
| `chain_in_doubt` | Servers disagree, or fewer than two answer. Signing stopped | S1 |
| `paused` | | S1 |
| `signing` | Keep the app open; seconds. `params.of`, `params.done` (signatures) | S1 |
| `signing_unfinished` | The app sent its signatures and no result came back. It treats both outcomes as possible and keeps watching until settled. `params.purpose`: `start` or `move` | S1 (start) |
| `awaiting_funding` | Signed; waiting for the host's funding to reach its confirmations. Not live yet | S1 |
| `ready_check` | The start rule was met; the ready check is under way | S1 |
| `in_lobby_waiting` | Ready, waiting for the start | S1 |
| `in_lobby_not_ready` | Joined but not ready. `params.reasons`: `conditions_fail`, `blocked_member_present`, `user_choice`, `terms_moved_outside` | S1 |
| `in_lobby_not_counted` | Ready, but fewer than `counted_from` are ready, so this member will not be chosen yet | S1 |
| `refused` | Did not sign. Refused at the check, before any signature. Nothing was signed; nothing moved. `params.failures` with both numbers | S1 |
| `lobby_cancelled` | Cancelled before any signature. `params.reason`: `deadline_below_minimum`, `host_choice`, `signing_budget_spent` | S1 |
| `not_chosen` | The lobby started without this member (its minimum, or the target cut) | S1 |
| `creation_abandoned` | Signatures went out, but the factory was not funded in time or the result never came. Records kept; nothing is owed | S1 |
| `creation_dead` | The funding can never exist: one of its inputs was spent elsewhere and buried | S1 |
| `moving` | A move try is being signed | 1.0.0 |
| `move_unfinished` | Same as `signing_unfinished`, for a move. Payments in the old factory are paused until it settles | 1.0.0 |
| `left_behind` | The group moved on without this member; the app starts or has started leaving alone | 1.0.0 |
| `leaving_alone` | Step by step; the app must run until it ends | 1.0.0 |
| `answering_old_state` | An old state was published and the app sent the answer; it is not confirmed yet | 1.0.0 |
| `looking_tell`, `looking_join` | Automatic joining is looking | 1.0.0 |
| `looking_nothing_fits` | Nothing listed fits; `params.excluded_most_by` with both numbers | 1.0.0 |
| `budget_used` | Automatic joining's budget is used up; waiting | 1.0.0 |
| `idle_in_factory` | Live; nothing to do now | S1 |
| `idle_no_factory` | Not in a factory. "You cannot pay or receive until you are in a live one" | S1 |

**`connection.chain.state`**

| Value | Meaning |
|---|---|
| `agree` | At least two servers from two operators agree and are not behind |
| `catching_up` | Servers are still loading; nothing is treated as newly confirmed yet |
| `lagging` | One server is behind by `params.blocks`; the others agree |
| `one_source` | Only one server answers. The app cannot compare, so it signs nothing and treats nothing as newly confirmed |
| `disagree` | Servers report different chains. Signing stopped. `since_at` |
| `unreachable` | No server answers |
| `offline_by_choice` | The person chose to go offline (Settings, Watching) |

**`connection.host_links[].state`**: `connected`, `connecting`, `not_answering` (with `last_heard_at`), `offline_by_choice`.

**`watching.state`** (who watches) and **`watching.health`**

| `state` | Meaning |
|---|---|
| `this_app` | This app, only while it runs |
| `nobody_offline` | **Nobody is watching**: offline by choice. The app cannot answer an old state, move, start leaving alone or receive. The safe absence keeps counting |
| `nobody_chain_in_doubt` | Nobody can watch: the chain view is in doubt |
| `nothing_to_watch` | No factory and no unfinished round. Nothing needs watching |
| `own_machine` | later reserved: a second machine of the person's |
| `watcher` | later reserved: a watcher holding ready-made answers, never keys |

| `health` | Meaning |
|---|---|
| `up_to_date` | Last check at the tip |
| `behind` | Last check more than 6 blocks or 30 minutes ago while running (`params.minutes`) |
| `unreachable` | later reserved, for a separate watcher |
| `not_applicable` | With `nobody_*` and `nothing_to_watch` |

**`auto_join.state`**: `off`, `looking_tell`, `looking_join`, `looking_nothing_fits`, `budget_used`, `in_lobby`, `paused`. With `params.listed`, `params.fit`, `params.budget` (section 13.6). 1.0.0; S1 always returns `off`.

**`hosting`**: `null` until this program has a lobby or factory of its own (decision 4: the strip shows hosting only then). Otherwise `{ "lobbies_open": 1, "factories": 2, "next_date": { a date } }`.

**`money`**

| Field | Meaning |
|---|---|
| `can_send_sat` | Balance in channels (sum over channels, decision 5) |
| `can_receive_sat` | Receiving room left |
| `take_out_alone` | Estimate of what leaving alone would give now, its fee, its length, and what it needs (`app_running`, `fee_coins`). `null` when nothing is inside a factory |
| `on_chain_free_sat` | On chain and free |
| `set_aside_sat` | Held back for a lobby this program hosts (decision 6: one wallet, with an amount set aside) |
| `inside_factories_sat` | |
| `covered_sat` | **1.1.0 reserved**: the covered amount under limited coverage (decision 5). Always `null` in 1.0.0 |
| `as_of_height` | The chain height these figures are for |
| `chain_view` | `trusted`, or `in_doubt`. When `in_doubt` the figures are the last trusted ones, and the interface must not say that money "has not moved" (critique, section 4) |

### 11.3 Pause

`PUT /api/v1/pause` (**S1**), `{ "on": true }` or `{ "on": false }`.

- **On:** the app signs nothing new, joins nothing, readies for nothing, and leaves every lobby that has not started (sending `leave` with reason 2). Watching, answering an old state, moves already agreed, and leaving alone before an end date go on: those protect the member.
- **During the seconds of signing**, the answer is `202` with `pause.state = "held_for_signing"`: stopping half-way would hold up every other member, and once partial signatures are out nothing can call them back (`signing-round.md` section 7). Pause takes effect when the round ends.
- Answer: the `pause` object, and the lobbies it left: `{ "pause": {…}, "left_lobbies": ["7f3a…"] }`.

### 11.4 Attention

`attention` lists what needs the person, most important first. Each item:

```json
{ "id": "att_88", "tier": "act_now", "code": "move_last_try", "due": { "...": "a date" }, "factory_id": "2d91…", "params": { } }
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
| `signing_unfinished` | at_risk | `lobby_id`, `purpose`, `sent_at`, `last_heard_at`, `checked_to_height` | S1 |
| `node_stopped` | at_risk | `reason` | S1 |
| `nobody_watching` | at_risk | `safe_absence_blocks` | 1.0.0 |
| `watching_behind` | at_risk | `minutes` | 1.0.0 |
| `funding_reorganised` | at_risk | `factory_id` | 1.0.0 |
| `old_state_published` | at_risk | `factory_id`, `answer` (`sent`, `confirmed`, `buried`) | 1.0.0 |
| `branch_partly_on_chain` | at_risk | `factory_id`: a neighbour left alone; timed steps on the path start counting | 1.0.0 |
| `move_last_try` | act_now | `factory_id`, `due` | 1.0.0 |
| `leave_step_due` | act_now | `factory_id`, `due` | 1.0.0 |
| `open_app_by` | act_now | `due` (only when close) | 1.0.0 |
| `host_not_answering` | important | `host_key`, `since_at` | S1 |
| `payments_paused_by_host` | important | `factory_id`; no date (never `act_now`) | 1.0.0 |
| `factory_backup_missing`, `factory_backup_old` | important | `factory_id`, `last_at` | 1.0.0 |
| `words_not_checked` | important | | S1 |
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

`DELETE /api/v1/attention/{id}` (1.0.0) dismisses a `heads_up` or `recommended` item. Other tiers clear only when their cause does; dismissing them answers `409`, code `cannot_dismiss`.

### 11.5 While the app was closed

`GET /api/v1/while-closed/{id}` (1.0.0) and `POST /api/v1/while-closed/{id}/seen`.

```json
{
  "id": "wc_19",
  "closed_at": 1794394800, "opened_at": 1794427200,
  "within_safe_absence": true,
  "checked_from_height": 330383, "checked_to_height": 330437,
  "verdict": "nothing_found",
  "found": [],
  "dates_passed": [],
  "could_not": ["receive", "watch"]
}
```

`verdict`: `nothing_found` (the interface says "Nothing appears to have gone wrong while you were away", with what was checked, critique H.3), `found` (items listed), `could_not_check` (the chain view is in doubt; checked later), `beyond_safe_absence` (closed longer than the safe absence; what was checked is still listed). Never "nothing is lost".

---

## 12. First run, wallet keys, backup and restore

### 12.1 Setup state

`GET /api/v1/wallet/setup` (**S1**)

```json
{ "state": "none", "network": "signet", "networks": [ { "id": "signet", "available": true }, { "id": "testnet4", "available": false, "reason": "one_operator" }, { "id": "mainnet", "available": false, "reason": "switched_off_in_release" } ], "words": 24 }
```

`state`: `none`, `created_not_finished`, `ready`, `restoring`. There is no role question (decision 4): setup never asks "member or host?".

### 12.2 Making keys

`POST /api/v1/wallet/create` (**S1**), `{ "request_id": "…" }`.

```json
{ "words": ["…", "… 24 words"], "shown_until": "this_answer" }
```

- The only answer that carries the words without a fresh sign-in, because there is nothing to protect yet. It is sent once: a repeated `request_id` answers `409`, code `already_created`, without the words.
- The program writes the key file before answering (`wallet-keys.md` section 8).
- Errors: `wallet_exists`.

### 12.3 The 24 words

| Call | Release | Request | Answer | Notes |
|---|---|---|---|---|
| `POST /api/v1/wallet/phrase/reveal` | S1 | `{}` | `{ "words": [ … ] }` | Fresh sign-in. `POST`, `no-store`, never in an event |
| `POST /api/v1/wallet/phrase/check-start` | S1 | `{}` | `{ "check_id": "…", "positions": [3, 14, 22] }` | The program chooses the positions |
| `POST /api/v1/wallet/phrase/check` | S1 | `{ "check_id", "words": ["…", "…", "…"] }` | `{ "ok": true, "checked_at": … }` or `{ "ok": false, "wrong_positions": [14] }` | Three tries per `check_id` |
| `POST /api/v1/wallet/finish-setup` | S1 | `{ "preset": "everyday", "find": "browse" }` | `{ "state": "ready" }` | `preset`: `cautious`, `everyday`, `wide` (section 13.2). `find`: `browse`, `tell_me`, `join_for_me` (the last two set automatic joining, 1.0.0; S1 accepts `browse` only). Errors: `no_wallet` |

Words not yet written down raise `words_not_checked` (important). The interface may skip checking; the item stays.

### 12.4 Restore from the words

`POST /api/v1/wallet/restore` (1.0.0), `{ "words": "word word …", "request_id" }`.

- Brings back keys and on-chain coins. Factories need a backup (12.6). Answer: `{ "on_chain_found_sat": 48000, "factories": "need_backup" }`.
- Allowed only when no wallet exists. Over an existing wallet: `POST /api/v1/wallet/replace` (fresh sign-in, `{ "confirm": "replace_wallet" }`).
- Errors: `bad_words` (with `params.position` of the first word not in the list, or `checksum`), `wallet_exists`.

### 12.5 Backup state

`GET /api/v1/backup` (1.0.0; S1 returns the words part only)

```json
{
  "words": { "checked_at": 1793620800 },
  "host_copy": { "on": true, "last_sent_at": 1794434520, "readable_by_host": false },
  "file": { "last_saved_at": null, "older_than_state": true, "factories_not_covered": ["2d91…"] },
  "guard": { "present": true }
}
```

`PUT /api/v1/backup/host-copy` (1.0.0), `{ "on": true }`. Peer storage is not in Slice 1 (`messages.md` section 9).

### 12.6 Export and import

| Call | Release | Request | Answer |
|---|---|---|---|
| `POST /api/v1/backup/export` | 1.0.0 | `{}` | `200`, `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="gazpacho-signet-<date>.gzb"`, the journal and the guard (`journal.md` section 8). Fresh sign-in. Unencrypted in Slice 1; the interface must say so |
| `POST /api/v1/backup/import` | 1.0.0 | Body: the file, `application/octet-stream`, at most 16 MiB | `{ "restore_id": "…", "stale": "no"\|"yes"\|"unknown", "lost_seats": [ { "lobby_id", "name" } ] }`. Fresh sign-in. The program checks the guard (`journal.md` section 8.3), imports the journal, restarts its core under a new epoch, and sends `reset` |
| `POST /api/v1/backup/ask-host` | 1.0.0 | `{ "host_key" }` | `202`; the host's copy, when it arrives, is imported as above |
| `GET /api/v1/backup/restore` | 1.0.0 | | `{ "state": "waiting_for_host"\|"waiting_for_chain"\|"done", "factories": [ { "id", "state": "restoring_unconfirmed"\|"current" } ] }` |

**A restored wallet never publishes from the backup** (`DESIGN.md` section 6). While waiting, every factory from the backup has state `restoring_unconfirmed` (section 16), its balance is not confirmed, and payments and leaving alone are refused with `wallet_restoring`. What the app may do if the host never answers is not decided **(open; critique question 15)**.

### 12.7 Removing the wallet

`POST /api/v1/wallet/remove` (1.0.0), `{ "confirm": "remove_wallet" }`, fresh sign-in. Refused with `409`, code `funds_inside`, while any factory holds a balance or a creation round is unresolved, unless `{ "confirm": "remove_wallet_with_funds_inside" }`; the answer then lists what would be lost without the words and a backup.

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
  "copied_into": [ { "lobby_id": "7f3a…", "copied_at": 1794427320 } ],
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
| `POST /api/v1/conditions/preview` | S1 | `{ "conditions": {…} }` | `{ "fit_summary", "would_leave": [ { "lobby_id", "failures" } ], "problems": [ { "field", "code" } ] }`. Changes nothing. The interface calls it as the person types (the live "why" line) | `bad_value` |
| `PUT /api/v1/conditions` | S1 | `{ "conditions": {…}, "based_on_version": 7, "preset": "custom" }` | The new `GET` answer, plus `left_lobbies` | `changed_elsewhere`, `bad_value`, `signing_now`, `below_floor` (`min_confirmations` under the app's floor) |

**The copying rule** (proposed, options map; concept H marks it open): conditions are copied into a lobby at the moment of joining. Tightening them later makes the app leave a joined lobby that no longer fits, before it starts, and say so (`left_lobbies`). Loosening them applies to future joins only. Values are checked again at the ready check, against the real tree at signing (C8), and at each move.

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
- `reserved` names the record types `terms.md` reserves (70, 72, 36, 38). An offer that carries any of them is refused by a 1.0.0 program, so in 1.0.0 they are always `null`.
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
  "id": "7f3a…",
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
| `source` | `direct_query`, `invitation` (1.0.0), `nostr` (1.0.0), `beacon` (later reserved), `typed_address` |
| `stage` | `open`, `ready_check`, `signing`, `funding`, `active`, `cancelled`, `failed`, `unknown` (`messages.md` section 6, lobby states 0 to 7) |
| `you.seat` | `none`, `joining` (sent, no answer yet), `joined_not_ready`, `ready`, `chosen`, `not_chosen`, `left`, `removed`, `refused_by_host` (`messages.md` seat states 0 to 7, plus `joining`) |
| `you.counted` | `false` while fewer than `fit.counted_from` are ready |
| `you.outcome` | `null`, or an object below |
| `round` | `null`, or the member's creation round below |
| `funding` | `null`, or `{ "txid", "state", "confirmations", "needed", "deadline": { a date, kind funding_deadline }, "amount_sat" }` |
| `members` | `null` when the host shows no names (always in Slice 1); otherwise `[ { "seat", "name": { text }, "ready", "you", "blocked" } ]` (1.0.0) |
| `terms_change` | `null`, or `{ "from_version", "to_version", "at", "changes": [ { "term", "from", "to" } ], "effect": "still_fits"\|"unreadied"\|"left" }` |

**`you.outcome`**: what happened to this member in this lobby. Each value is distinct because the wording differs (section 22).

| `code` | Meaning | "Nothing was signed"? |
|---|---|---|
| `refused_at_check` | The app refused before any nonce or signature. `failures` with both numbers; `which`: `conditions`, `safety_check`, `fingerprint_differs`, `values_differ_from_frozen` | Yes |
| `aborted_before_signatures` | The round stopped after nonces but before any partial signature (`signing-round.md`: Aborted). `reason` from `messages.md` 7.9 | Yes |
| `not_chosen` | Ready, but the start went ahead without this member | Yes |
| `cancelled` | The lobby was cancelled. `reason`: `deadline_below_minimum`, `host_choice`, `signing_budget_spent`. `not_your_doing: true` unless the member's own leave caused it | Yes |
| `left` | The member left. `reason`: `user`, `paused`, `conditions_tightened`, `host_fault_seen` (with `activity_id` for the evidence) | Yes |
| `removed` | The host removed this seat before the ready check | Yes |
| `signing_unfinished` | Partial signatures went out; no result came back. Both outcomes stay possible | **No** |
| `abandoned` | Unfinished or unfunded past its deadline. Records kept; the member owes and is owed nothing | **No** |
| `dead` | A funding input was spent elsewhere and buried; the factory can never exist | **No** |
| `started` | Signed and complete; see `funding` and `factory_id` | **No** |

**`round`** (the member's creation round, `signing-round.md` section 7):

```json
{ "state": "signed", "attempt": 1, "signatures": { "done": 11, "of": 17 }, "sent_at": 1794434404, "last_heard_at": 1794434404, "checked_to_height": 330449, "unfinished_deadline": { "...": "a date" }, "checks": [ { "check": "fingerprint_same", "ok": true }, { "check": "frozen_values_inside_limits", "ok": true }, { "check": "tree_inside_conditions", "ok": true, "params": { "members": 50 } }, { "check": "safety_checks", "ok": true } ] }
```

`state`: `checking`, `nonces_sent`, `signed`, `complete`, `awaiting_funding`, `live`, `aborted`, `unfinished`, `abandoned`, `dead`. These are exactly the member states of `signing-round.md` section 7, so the interface can show the signing checklist (concept H, borrowed from E) from the program's own checks.

### 14.2 Calls

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `GET /api/v1/lobbies` | S1 | `?show=fits\|all&sort=fit\|start\|joining_fee\|channel&cursor&limit` | Page of rows: `id`, `name`, `host`, `source`, `stage`, `fit.class`, the failing rows' terms, `counts`, `start_rule`, `terms.outer.channel_sat`, `terms.ranges.joining_fee_sat`, `derived.exit_blocks`, `you.seat`. Includes every lobby the program knows and every lobby the member is in; not the program's own hosted lobbies (section 15) | |
| `GET /api/v1/lobbies/{id}` | S1 | | The lobby object | `not_found` |
| `POST /api/v1/lobbies/{id}/join` | S1 | `{ "request_id", "seen_current_digest": "…", "ready": true }` | `202`, the lobby object with `you.seat = "joining"` | `not_open`, `conditions_not_met` (with failures), `fits_only_now` (the member did not choose the looser comparison), `terms_changed` (the digest the person reviewed is no longer current: show the change, then ask again), `already_in_lobby` (S1 allows one lobby at a time **(open)**), `paused`, `chain_in_doubt`, `needs_invitation`, `host_unreachable`, `lobby_full`, `host_avoided`, `wallet_restoring` |
| `PUT /api/v1/lobbies/{id}/ready` | S1 | `{ "request_id", "ready": true\|false, "seen_current_digest" }` | `202`, the lobby object | `not_joined`, `conditions_not_met`, `terms_changed`, `too_late` (a round is under way), `paused` (for `true`) |
| `POST /api/v1/lobbies/{id}/leave` | S1 | `{ "request_id" }` | `202`, the lobby object | `not_joined`, `too_late` (partial signatures are out: the member may stop looking, but the round stays Unfinished; the answer carries `round`) |
| `PUT /api/v1/lobbies/{id}/members/{seat}/blocked` | 1.0.0 | `{ "blocked": true }` | The member row | `names_off`, `not_joined` |
| `POST /api/v1/invitations` | 1.0.0 | `{ "text": "<the link or QR text>" }` | `{ "lobby_id" }`; the lobby is fetched and appears in the list | `bad_invitation`, `wrong_network` |
| `GET /api/v1/lobbies/{id}/terms/sealed` | 1.0.0 | | 13.3 | |
| `POST /api/v1/lobbies/{id}/rule-request` | later reserved | | | |
| `GET /api/v1/lobbies/{id}/chat` | later reserved | | | |

**Joining is consent.** `seen_current_digest` must be the `terms.current.digest` the person reviewed. When the lobby starts, the app signs without asking (options map, "never a setting"). If anything differs at signing from what was reviewed (fingerprint, values outside the frozen ones, the tree against the conditions, any safety check), it refuses before sending anything.

---

## 15. Hosting

Hosting is always available (decision 4). Every call here acts on lobbies and factories **this program hosts**. Lobby identifiers are the same fingerprints as in section 14.

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

`cannot_open_because`: `problems`, `funds_short`, `no_wallet`, `chain_in_doubt`, `already_hosting` (S1 allows one hosted lobby at a time **(open)**), `host_node_missing` (1.0.0, once payments need the host's Lightning node; not in Slice 1).

`shape`: `default` lets the program choose shapes by `terms.md` section 4 and the scale-check rules (`DESIGN.md` section 7); an explicit table is accepted in the same form as `outer.shape`.

### 15.2 Opening, running and ending a lobby

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `POST /api/v1/host/lobbies` | S1 | `{ "request_id", "draft": {…}, "draft_digest": "…" }` | `201`, the host's lobby object (15.3). The program signs the outer rules and current values version 1, saves them (`lobby_opened`) and starts answering `hello`. Opening sets aside the funding at the target | `draft_changed` (the draft does not match the digest that was previewed), every `cannot_open_because` value |
| `GET /api/v1/host/lobbies` | S1 | `?state=open\|funding\|running\|ended&cursor` | Page of host lobby rows | |
| `GET /api/v1/host/lobbies/{id}` | S1 | | 15.3 | `not_found`, `not_host` |
| `POST /api/v1/host/lobbies/{id}/start` | S1 | `{ "request_id" }` | `202`, `stage: "ready_check"` | `below_minimum` (`params.ready`, `params.minimum`), `not_open`, `funds_short`, `chain_in_doubt` |
| `POST /api/v1/host/lobbies/{id}/cancel` | S1 | `{ "request_id" }` | `202`, `stage: "cancelled"`; set-aside funds are free again | `too_late` (signing has begun: a round runs to its end within its budget; the host cannot take back what members signed) |
| `POST /api/v1/host/lobbies/{id}/values` | 1.0.0 | `{ "request_id", "based_on_version": 3, "values": { "joining_fee_sat": 1200 } }` | The lobby, with the new current version, signed and sent to every seat | `frozen`, `outside_range`, `changed_elsewhere` |
| `DELETE /api/v1/host/lobbies/{id}/seats/{seat}` | 1.0.0 | `{ "reason": "…" }` in body | `204` | `frozen` (no removal after the ready check, critique H.3) |
| `POST /api/v1/host/lobbies/{id}/invitations` | 1.0.0 | `{ "expires_at": … }` | `{ "text": "…", "qr_svg_data": "…" }`: the link and the QR's contents. Their exact form and expiry are **(open)** | `not_host` |
| `GET /api/v1/host/lobbies/{id}/requests` | 1.0.0 | `?cursor` | Page of `{ "id", "who": { "kind": "temporary"\|"nostr_key", "label" }, "asked_at", "note": { "text", "by": "you" } }` | |
| `POST /api/v1/host/lobbies/{id}/requests/{rid}/approve` | 1.0.0 | `{}` | `204` | `not_waiting` |
| `POST /api/v1/host/lobbies/{id}/requests/{rid}/refuse` | 1.0.0 | `{ "reason": "…" }` | `204` | |
| `PUT /api/v1/host/lists` | 1.0.0 | `{ "always_allow": ["key"], "always_refuse": ["key"] }` | The lists | |
| `PUT /api/v1/host/notes/{key}` | 1.0.0 | `{ "text": "…" }` (kept on this machine only) | | |

Join requests need admission by approval, which has no protocol messages yet (`messages.md` section 9: "Invitations, identities … no messages yet"). The calls are fixed now; they work once the protocol has them **(open)**.

**Starting.** A host never signs funding before every member's signed tree is complete and verified (H1). `start` only runs the ready check; signing and funding follow by themselves and show in `stage`, `round` and `funding`.

### 15.3 The host's lobby object

```json
{
  "id": "4c08…",
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
- `seats[].state` uses the seat values of 14.1 from the host's side.
- `funding_tx`: `{ "txid", "state", "confirmations", "needed", "broadcast_at" }`.

### 15.4 Host factories, setup and earnings

| Call | Release | Notes |
|---|---|---|
| `GET /api/v1/host/factories` | 1.0.0 | The ladder: each factory with `state`, members, funds in it, next date. S1 shows the hosted factory through `GET /api/v1/factories/{id}` |
| `GET /api/v1/host/factories/{id}` | 1.0.0 | Members not moved, silent members, deadlines the host must meet (dates), funds, fee funds held ready, changes left |
| `POST /api/v1/host/factories/{id}/force-path` | 1.0.0 | `{ "seat", "preview_id" }`. Preview first: `POST …/force-path/preview` gives cost and time. Fresh sign-in |
| `POST /api/v1/host/factories/{id}/wind-down` | 1.0.0 | With rotation (M4) |
| `POST /api/v1/host/factories/{id}/force-close` | 1.0.0 | Preview, then fresh sign-in |
| `POST /api/v1/host/factories/{id}/sell-room` | 1.1.0 reserved | Sales of receiving room |
| `GET /api/v1/host/earnings` | 1.0.0 | `?period=30d\|factory\|all`. Fees received, on-chain costs, idle funds. "Spare liquidity not yet sold" is a 1.1.0 field, `null` in 1.0.0 |
| `GET /api/v1/host/setup`, `PATCH /api/v1/host/setup` | 1.0.0 | Host name, publish record, contact address, funds limits (`max_per_factory_sat`, `max_total_sat`), public address, saved terms templates. The host key cannot change while a lobby or factory is open (`key_in_use`) |
| `PUT /api/v1/host/node`, `POST /api/v1/host/node/test`, `DELETE /api/v1/host/node` | 1.0.0 | `{ "kind": "lnd"\|"cln", "address", "access_file" }`. `access_file` is a path on this machine; its contents never reach the browser. The test answers one entry each for `pay`, `hold`, `settle`, `cancel`. Not in Slice 1 |
| `PUT /api/v1/host/schedule` | later reserved | Open a lobby by itself on a schedule |
| `POST /api/v1/host/backup` | 1.0.0 | The host's own backup, as 12.6. Fresh sign-in |

---

## 16. Factories

### 16.1 The factory object

`GET /api/v1/factories` (**S1**): every factory this program is in or hosts, live and past, newest first, paged. `GET /api/v1/factories/{id}` (**S1**):

```json
{
  "id": "2d91…",
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
  "exit": { "amount_sat_estimate": 181200, "fee_sat_estimate": 1200, "blocks": 864, "transactions": 4, "needs": ["app_running", "fee_coins"], "fee_paid_from": "anchors" },
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
| `abandoned` | Never funded in time; nothing owed | S1 |
| `dead` | Can never be funded | S1 |
| `restoring_unconfirmed` | From a backup; waiting for current data. Balance not confirmed | 1.0.0 |
| `winding_down` | The move window is open or near | 1.0.0 |
| `host_not_answering` | | 1.0.0 |
| `moving` | A move try is under way | 1.0.0 |
| `move_unfinished` | A move try's signatures went out and no result came back | 1.0.0 |
| `left_behind` | The group moved on without this member | 1.0.0 |
| `exiting` | Leaving alone, step by step | 1.0.0 |
| `ended` | Over. `ended_how`: `all_signed_close`, `moved`, `left_alone`, `host_timeout` (Slice 1's signet recovery, `safety-rule.md` section 12 point 2), `forced_by_host` | S1 (`host_timeout`) |

- `funding.state`: `not_broadcast`, `broadcast`, `seen`, `confirming`, `buried`, `reorganised_away`, `input_spent_elsewhere` (`journal.md` record `funding_status`).
- `tree.levels[].kind` is always `fixed` in 1.0.0 (decision 9: advanceless). `timed` is a 1.1.0 value.
- `channels` is **1.1.0 reserved**: several channels in one factory (decision 5). `null` in 1.0.0; `channel` holds the one channel. Slice 1 has no channels: `channel` is `null`.
- `covered_sat`: 1.1.0 reserved, `null`.
- `trouble[]`: `{ "code", "at", "params" }` with `code` `old_state_published` (`answer`: `sent`, `confirmed`, `buried`), `host_caught_cheating`, `branch_partly_on_chain`, `funding_reorganised`, `host_fault_evidence` (two values under one version, or a version after the freeze). Answering is not winning: `answer` says how far it got.
- `unfinished_round`: `null`, or `{ "purpose": "start"\|"move", "sent_at", "last_heard_at", "checked_to_height", "both_outcomes_watched": true, "deadline": { a date }, "payments_paused": true }`.
- `host_view` (a factory this program hosts; then `channel` is `null`): `{ "funded_sat", "members_online", "members_moved", "fee_funds_ready_sat", "deadlines": [ dates ] }`.

### 16.2 Dates and "where this date comes from"

`GET /api/v1/factories/{id}/dates` (1.0.0; S1 returns `factory_ends` and the funding deadline) returns the factory's dates in the shape of 7.2, with `provenance` filled. The interface's "Where this date comes from" link shows `source` and `provenance`. Example provenance for "start leaving alone by": `end_less_exit_less_margin` with the end height, the exit blocks summed from the path (`safety-rule.md` section 7, including the confirmation allowance per transaction), the app's margin and the member's extra margin.

`GET /api/v1/schedule` (1.0.0) gives every date across all factories, most urgent first, with `most_urgent` naming the one the home screen makes prominent.

### 16.3 Leaving alone

| Call | Release | Request | Answer | Errors |
|---|---|---|---|---|
| `POST /api/v1/factories/{id}/leave-alone/preview` | 1.0.0 | `{}` | `{ "preview_id", "amount_sat_estimate", "fee_sat_estimate", "blocks", "done_by": { a date }, "destination": "this_wallet", "stops": ["payments"], "needs": ["app_running", "fee_coins"], "fee_coins_sat": 48000, "fee_cover": "enough"\|"short"\|"none", "cheaper_ways": ["move_with_host"] }` | `host_factory`, `already_exiting`, `wallet_restoring` |
| `POST /api/v1/factories/{id}/leave-alone` | 1.0.0 | `{ "request_id", "preview_id", "confirm": "leave_alone" }` | `202`, `exit_progress` | `preview_expired`, `chain_in_doubt`, `already_exiting`. Fresh sign-in |
| `GET /api/v1/factories/{id}/leave-alone` | 1.0.0 | | `exit_progress`: `{ "started_height", "amount_sat", "fee_sat_so_far", "blocks_left", "steps": [ { "kind": "tree"\|"leaf"\|"channel"\|"sweep", "state": "pending"\|"waiting"\|"due"\|"sent"\|"confirmed"\|"buried", "txid", "wait": { a date, kind leave_step_due } } ], "done": false }` | |

`fee_cover` is how the API reports "coins for fees": no reserve is required or recommended in 1.0.0 (decision 6), but leaving alone still pays fees. Its exact rule against `safety-rule.md` C3 is **(open; critique H.7)**.

### 16.4 Moving to the next factory

| Call | Release | Notes |
|---|---|---|
| `GET /api/v1/factories/{id}/move` | 1.0.0 | `{ "state": "before_window"\|"window_open"\|"trying"\|"unfinished"\|"moved"\|"left_behind"\|"will_not_move", "tries": [ { a date, kind move_try, "result": null\|"moved"\|"failed_before_signatures"\|"unfinished"\|"app_not_running" } ], "next": { "terms": { 13.3 }, "fit": { 13.4 } }, "choice": "by_itself_if_fits"\|"ask"\|"never" }` |
| `POST /api/v1/factories/{id}/move` | 1.0.0 | `{ "request_id", "decision": "move"\|"do_not_move", "seen_current_digest" }`. Only when the choice is `ask`. The move happens at the next try, not at once, and the answer says when |
| `POST /api/v1/wallet/transactions/{txid}/speed-up` | 1.0.0 | Raise a stuck transaction's fee through its pay-to-anchor output (decision 6). Section 18 |

`will_not_move` means the next factory's terms do not fit, or the choice is `never`: the app does not move and will start leaving alone by the date in `dates`.

---

## 17. Payments

All **1.0.0** (Slice 2), except buying receiving room (**1.1.0 reserved**).

| Call | Request | Answer | Errors |
|---|---|---|---|
| `POST /api/v1/payments/decode` | `{ "invoice": "…" }` | `{ "valid", "can_pay", "reason", "amount_sat", "note": { "text", "by": "sender" }, "payee", "fee": { "host_fee_sat", "route_fee_max_sat", "total_max_sat", "routing_limit_ppm" }, "back_by": { a date, kind payment_back_by }, "expires_at", "can_send_sat", "review_id" }` | |
| `POST /api/v1/payments` | `{ "request_id", "invoice", "review_id" }` | `202`, the payment | Same codes as `reason` |
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
| `POST /api/v1/wallet/send` | 1.0.0 | `{ "request_id", "review_id" }` | `202`, `{ "txid" }`. Fresh sign-in | `review_expired`, `chain_in_doubt` |
| `POST /api/v1/wallet/transactions/{txid}/speed-up/preview`, `POST …/speed-up` | 1.0.0 | `{ "fee_rate_sat_per_kvb" }`, then `{ "request_id", "review_id" }` | Child pays through the pay-to-anchor output | `no_anchor`, `already_confirmed` |
| `PUT /api/v1/wallet/payout` | 1.1.0 reserved | Per-factory derived address (decision 6) | | |
| `PUT /api/v1/wallet/payout/outside` | later reserved | Outside wallet, proven before use | | |

The default fee rate on test networks is 0.1 sat/vB (`100`), set in Settings, Wallet. The program never spends set-aside coins for anything but the lobby they are held for.

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
  "lobby_id": "b19d…",
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

The journal has no record area for this history yet (`journal.md` section 9 has `lobby_ended` "for history" only). The program needs one **(open)**.

---

## 20. Settings by scope

Four scopes, as concept H's Settings: Wallet, Watching, Connections, Application. Conditions and lobby terms are **not** settings (options map, "never a setting"). Each scope is one `GET` and one `PATCH`; a `PATCH` names only the fields it changes and carries `based_on_version`.

Nothing in any scope switches off a safety check, the two-server rule, saving before sending, answering an old state, leaving before the end, or the refusal of mainnet. A request that tries answers `400`, code `not_a_setting`.

### 20.1 Wallet: `GET`/`PATCH /api/v1/settings/wallet` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `routing_limit_ppm` | 0 to 50,000 | The most the member pays to route one payment |
| `fee_rate` | `{ "mode": "automatic"\|"fixed", "sat_per_kvb": 100 }` | Test networks default to fixed 100 (0.1 sat/vB) |
| `network` | `signet`, `testnet4` | Fresh sign-in. Refused with `network_busy` while in a lobby or factory; `network_unavailable` for testnet4 until it has two operators; mainnet is never accepted. The program restarts on the new network's data folder |

### 20.2 Watching: `GET`/`PATCH /api/v1/settings/watching` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `who_watches` | `nobody`, `this_app`; `own_machine` and `watcher` later reserved | |
| `extra_margin_blocks` | 0 and up | Added above the app's own margin. Cannot go below 0 |
| `warn_days_before` | 0 to 30 | |
| `reminders` | `[ { "id": "in_app", "on": true } ]`; `nostr`, `email`, `phone` later reserved | |
| Read-only: `safe_absence_blocks`, `state`, `health`, `planned_alerts` | | Status, computed |

`POST /api/v1/settings/watching/offline` (1.0.0), `{ "on": true, "confirm": "nobody_watching" }` or `{ "on": false }`. Going offline stops every outside connection; `watching.state` becomes `nobody_offline` and `connection.chain.state` `offline_by_choice`. It is a deliberate button in Watching, never a one-tap switch in the strip (critique, rule table).

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
| `POST /api/v1/settings/connections/servers` | 1.0.0 | Add a server `{ "address", "protocol" }`. Tested before saving |
| `DELETE /api/v1/settings/connections/servers/{id}` | 1.0.0 | Refused with `min_two_operators` if it would leave fewer than two servers from two operators |
| `POST /api/v1/settings/connections/check` | 1.0.0 | Asks every server again now. `{ "state", "servers" }` |
| `PATCH` `chain.mode` | 1.0.0 | `public`, `own_server`, `own_node`. Own server or node is still compared with a public server from another operator |
| `PATCH` `listings` | 1.0.0 | Nostr annex on or off; relays (at least 3 when on, `discovery.md` 17.1) |
| `POST`/`DELETE /api/v1/settings/connections/hosts` | 1.0.0 | The editable host list (`discovery.md` 14.1). In Slice 1 a host enters the list through `POST /api/v1/discovery/query` |
| `PATCH` `privacy.route` | `tor` later reserved | |

Server `state`: `ok`, `catching_up`, `lagging`, `disagrees`, `unreachable`.

### 20.4 Application: `GET`/`PATCH /api/v1/settings/application` (1.0.0)

| Field | Values | Notes |
|---|---|---|
| `units` | `sat`, `btc` | |
| `fiat` | `off`; currencies later reserved | Shows nothing on test networks |
| `theme` | `system`, `light`, `dark` | |
| `language` | `en` | |
| `lock_after_idle_s` | `null` (never), 900, 3600 | Section 4.6 |
| `interface` | `{ "port": 39735, "ipv6": true }` | Fresh sign-in; takes effect at the next start. The address is not a field: loopback only |
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
| `POST /api/v1/discovery/query` | S1 | `{ "host": "<key>@<address>:<port>" }`, or `{ "host": "<key>" }` for a known host | `202`, then `discovery` events; the answer holds `{ "query_id", "lobbies": [ ids ] }` when the host answered within 30 s | `bad_host_address`, `host_unreachable`, `key_mismatch` (the connection's key is not the one given), `wrong_network`, `rate_limited` (DQ2: at most once per host per hour unless the person asks; then once per 10 s) |
| `POST /api/v1/discovery/refresh` | 1.0.0 | `{}` | `202`. Polls the host list within DQ2's limits, and Nostr if on | `rate_limited` |
| Nostr annex on/off | 1.0.0 | `PATCH /api/v1/settings/connections` with `listings.nostr.on` | | |
| `GET /api/v1/discovery/hosts` | later reserved | Store nodes' `host_list` (design D) | | |

- Every lobby found is checked in full before it is shown (`terms.md` section 7); a listing that fails is dropped and counted in `sources[].dropped`.
- Withdrawals are applied wherever they come from (`discovery.md` 5.3).
- The interface must say that asking a host shows it this machine's network address unless Tor is used (later reserved). `privacy_note` is `direct` until then.
- `address` here is a DNS name, an IPv4 or bracketed IPv6 literal, or an onion name, as in `discovery.md` 17. The interface never invents one.

---

## 22. Status values the safety wording needs

The critique (`docs/reviews/ux-critique.md` sections 4 and H.3 to H.7) lists sentences the interface must be able to say and others it must never say. Each needs a value the program reports, distinct from its neighbours. This table is the check.

| Wording need (critique) | Distinct value | Must not be confused with |
|---|---|---|
| "Signing did not finish": signatures went out, no result | `doing.code = signing_unfinished`; `you.outcome.code = signing_unfinished`; `round.state = unfinished`; attention `signing_unfinished` | `refused_at_check`, `aborted_before_signatures`, `lobby_cancelled` (the only places "nothing was signed; nothing moved" is allowed) |
| A move try that did not finish | `move_unfinished` (doing, factory state, move state) | A failed try before signatures (`move.tries[].result = failed_before_signatures`) |
| Live only when the funding is buried and the tree is held (C11) | `awaiting_funding` against `live` | "If the host publishes the funding, it goes live" has no value: publishing is `funding.state = broadcast`, not live |
| Unfinished start that never gets funded | `creation_abandoned`, `creation_dead` | `lobby_cancelled` |
| "Nobody is watching" | `watching.state = nobody_offline` | `this_app`; `nothing_to_watch` (no factory: nothing needs watching) |
| Nobody can watch because the chain view is in doubt | `watching.state = nobody_chain_in_doubt` | `nobody_offline` |
| Watching has fallen behind | `watching.health = behind` | `up_to_date` |
| "Open it again well within a day" | `watching.open_by` (a date with the margin already taken off), `safe_absence_blocks` | The whole safe absence |
| "Only while it is running and has coins for fees" | `at_zero.needs = ["app_running", "fee_coins"]`; `exit.needs`; `fee_cover` | A date with no conditions |
| "Your money has not moved" must not be said when the chain view is in doubt | `money.chain_view = in_doubt`; `connection.chain.state = disagree \| one_source \| unreachable` | `trusted` |
| Servers disagree against only one answering | `disagree` against `one_source` against `unreachable` | Each other |
| "Answering is not winning" | `trouble[].answer = sent \| confirmed \| buried` | A single "answered" |
| Left behind | `left_behind` (doing, factory state, move state) | `will_not_move` (the app chose not to move because terms do not fit) |
| "Nothing appears to have gone wrong while you were away. Check below." | `while_closed.verdict = nothing_found`, with `checked_from_height` and `checked_to_height` | `beyond_safe_absence`, `could_not_check` |
| Restore: "Your balance is not confirmed yet" | `wallet = restoring`; factory `restoring_unconfirmed` | `live` |
| "Payments are paused by the host … no date" | Attention `payments_paused_by_host`, tier `important`, never `act_now` | `round_unfinished` (paused by the app itself) |
| A pending payment with an uncooperative host | Payment `state = stuck`, `may_need_chain = true` | `pending` with a promised date |
| Fits only now | `fit.class = fits_only_now`, not counted in `fit_summary.fit` | `fits` |
| Ready but not counted | `doing.code = in_lobby_not_counted`; `you.counted = false` | `in_lobby_waiting` |
| Cancelled: not your doing | `you.outcome.not_your_doing = true` | `left` |
| A refusal with both numbers | `failures[] = { condition, yours, offered }` everywhere a refusal appears | A bare code |
| Pause is off for the seconds of signing | `pause.state = held_for_signing` | `off`, `on` |
| A locked app still signs | `session.state = locked`; pause unaffected | `pause.state = on` |
| A host's claim that a member was silent | `round.state = failed` with counts, shown as the host's claim | A finding by the app |
| Host-written text in the app's voice | `{ text, by: "host", checked: false }` on every such string | Plain strings |
| Required only with a date | Attention tier `act_now` always has `due` | `important` |
| The core stopped | `wallet = node_stopped`, `doing.code = node_stopped`, `503 node_stopped` | A blank screen |

A contract test (23.4) checks that every value in this table can be produced by the simulator and is rendered by the interface with its own wording.

---

## 23. Tests

### 23.1 Functional

1. Every call in section 2.1 works against the simulator, and Slice 1's walkthrough runs through the interface alone: host opens; three members query the host by address, join and ready; start; signing; funding; live after 3 confirmations. Twice from a clean start.
2. A member whose conditions are not met: `join` answers `conditions_not_met` with both numbers; with conditions loosened after joining a lobby whose tree at signing breaks them, `you.outcome = refused_at_check` and an activity entry with a saved copy.
3. `seen_current_digest` older than the current version: `terms_changed`; nothing is sent.
4. The copying rule: tightening conditions while joined leaves the lobby (`left_lobbies`); loosening changes nothing joined.
5. `request_id` repeated on join, open, start, send: one effect, same answer.
6. `based_on_version` stale: `changed_elsewhere`.
7. Pause: leaves unstarted lobbies; `join` and `ready` answer `paused`; during signing answers `held_for_signing` and takes effect after.
8. Every reserved call answers `501` with the right release.
9. Paging: insert entries between two pages; no duplicate and no gap. Cursor after restart: `cursor_expired`.
10. Restore (1.0.0): import a stale backup (guard ahead): `stale = yes`, `lost_seats` listed, `reset` event, factories `restoring_unconfirmed`.
11. Unknown request field: `unknown_field`. Unknown enumeration value in a mocked answer: the interface shows "unknown state", never success.

### 23.2 Hostile browser and network

Run with Playwright and a raw HTTP client. Each expects the stated refusal, and no handler runs (the core sees no event).

1. `Host: rebind.attacker.example:39735` (DNS rebinding): `421 bad_host`, also for `GET /` and static files.
2. Missing `Host`; two `Host` headers; `Host: 127.0.0.1` without the port; `Host: 127.0.0.1:39736`: `421`.
3. A page on another origin `fetch`es `POST /api/v1/lobbies/{id}/join` with `mode: "no-cors"` and `text/plain`: refused (`415`, and `403` for `Origin`); nothing joined.
4. The same from a page on `http://127.0.0.1:8080` (same site, other port): refused by `Origin` and the check header.
5. An HTML form posting `application/x-www-form-urlencoded` and `multipart/form-data` to every unsafe endpoint: `415`.
6. `Origin: null` (a sandboxed iframe, a `file://` page): `403`.
7. Unsafe request with a valid cookie and no `Origin`: `403`.
8. Valid cookie and `Origin`, missing or wrong `X-Gazpacho-Check`: `403 bad_check`.
9. `OPTIONS` preflight to every path: `405`; no response anywhere carries `Access-Control-Allow-*` (scan every response of a full run).
10. A private-network-access preflight from a public origin: no allow header; the browser blocks the request.
11. `<img src>`, `<script src>`, `<iframe src>` and `<link rel=prefetch>` pointing at API paths from another origin: `403` by fetch metadata; no data in any response.
12. Cross-origin `new EventSource("http://127.0.0.1:39735/api/v1/events")`: fails; the program counts no stream.
13. A WebSocket handshake to any path: `400 no_upgrade`.
14. The interface framed by another origin: blocked by `frame-ancestors 'none'` and `X-Frame-Options`.
15. Script injection: a host alias, lobby name, description, member name and invoice note set to `<img src=x onerror=…>`, `<script>…</script>` and `javascript:` links. The page shows the text; no script runs; no CSP violation from the interface's own code (the CSP report count from the interface's own code is zero).
16. The interface's files contain no inline script, no inline style, no `eval`, no `innerHTML` (static check, as the prototype's).
17. Sign-in: wrong code 5 times cancels every code; the right code afterwards fails; a used code fails; an expired code fails; more than one attempt a second is `rate_limited`.
18. Cookie from a stopped run: `401`. After `revoke-all`: every session `401`, every stream closed with a `session` event, the token file changed.
19. Idle lock: after the idle time, data calls answer `locked`, the stream closes, and the core still signs a lobby the member joined (the lock is not a pause).
20. Fresh sign-in: revealing the words, export, import, network change, leaving alone, sending: `fresh_sign_in_needed` after 5 minutes.
21. Bearer token with an `Origin` header: `403`. Bearer plus cookie: `400`. A browser session calling `POST /api/v1/sign-in-codes`: refused.
22. Query strings `?token=…`, `?code=…`, `?phrase=…`: `400 secret_in_url`, and the value is in no log.
23. Path traversal on static files (`/../journal.gzj`, `/%2e%2e/`, `/..%5c`, overlong UTF-8): `404`.
24. Request smuggling: `Transfer-Encoding: chunked` alone `411`; with `Content-Length` `400`.
25. Slow headers (one byte a second): closed at 10 s. 33rd connection: refused. 70 KiB JSON body: `413`. 20 KiB of headers: `431`.
26. JSON: duplicate keys, 17 levels deep, `2^53` as a number, invalid UTF-8, a lone surrogate: `400 bad_json`.
27. Configured listen address set to the unspecified address (IPv4 or IPv6) or to a LAN address: the program refuses to start. A connection to the machine's non-loopback addresses on the port: refused by the operating system.
28. The port taken by another process: the program refuses to start the interface and says so; it does not pick another port.
29. Static content cannot be fetched with `Sec-Fetch-Site: cross-site`; `GET /` with `none` works.
30. A `same-site` API request (another port on `127.0.0.1`): `403`.
31. A second operating-system user connects to the port: gets the sign-in page and `401` everywhere else; cannot read the token file or the local socket.
32. Two browser tabs: both work; four streams per session; a fifth closes the oldest.

### 23.3 Secrets never leak

1. After a full Slice 1 run plus each 1.0.0 flow, search the access log, the program log, the terminal output (when not a terminal), every event sent and every `GET` answer for: the start-up token, every sign-in code, every session cookie value, every check value, each of the 24 words in sequence, and the backup bytes. No match is allowed. (The words appear only in the answers of `create` and `reveal`.)
2. The token file has mode 0600 (POSIX) or an owner-only access list (Windows); it is gone after a clean stop.
3. Every URL the interface ever requests (recorded by Playwright) has no fragment and no query parameter outside the allowed list.
4. `Cache-Control: no-store` on every API answer; the browser's disk cache holds no API answer after a run.

### 23.4 Contract

1. Every enumeration value in this document exists in the program's code tables, and every one is produced by at least one simulator scenario (section 22 in particular).
2. The interface renders every value with its own wording; a value without wording fails the build.
3. `GET /api/v1/version` matches the interface's compiled-in version.
4. The interface's screens use only the calls listed here (the prototype's rule: "screens use only `window.gzApi`").

---

## 24. Open points

1. **Default ports** 39735 (signet) and 39736 (testnet4): proposed.
2. **SSH tunnels on another local port** fail the `Host` check. Allow a configured second port, or document "same port only"?
3. **Sign-in code** length (10 characters, 50 bits), lifetime (10 minutes) and attempt limit (5): proposed.
4. **No terminal**: when the program runs as a service, the code comes only from `gazpacho sign-in-code`. Is that enough for a Windows user who starts Gazpacho by double-clicking (a console window shows the code)?
5. **The local socket on Windows**: AF_UNIX (Windows 10 1803 and later) or a named pipe.
6. **The words in the browser.** The design shows them in the interface. An alternative is to show them only in the terminal. Owner to choose.
7. **A wallet passphrase**, with encryption at rest (`journal.md` open point 1). Until it exists, a fresh sign-in is the only second step.
8. **Join requests and admission by approval** have no protocol messages yet. Invitations' form and expiry are not designed.
9. **One lobby at a time** for a member, and one hosted lobby at a time, in Slice 1 (`already_in_lobby`, `already_hosting`). 1.0.0 allows several (options map, "several factories").
10. **The unfinished round**: what the app does with payments, and what it says, if a creation is never funded or a move try never settles (critique question 9, H.5). The API reports the state; the behaviour is the signing round's to decide.
11. **Fee cover**: `fee_cover`'s rule, given no reserve in 1.0.0 (decision 6) and `safety-rule.md` C3 (critique H.7).
12. **"Open the app by" margin**: how much below the safe absence (critique H.3).
13. **The preset numbers** (critique question 13).
14. **An activity history area in the journal**, for entries and their saved copies (section 19).
15. **Restore when the host never answers** (critique question 15).
16. **Conditions copied at joining**: the rule is proposed, not final (options map).
17. **Hosting schedule, Tor, Nostr reminders, fiat display, a second watching machine**: later; reserved names only.
18. **The threat model** (`docs/THREAT-MODEL.md`) has no row for the local interface. Section 5.7 is the draft of that row.
