# Review of `spec/local-api.md`, draft 3 (confirmation round)

Reviewed 2026-11-12, from `origin/specs-slice1` at commit `8e4f9cb` (local API draft 3), read beside `e7bcfaa` (`spec/storage-encryption.md` draft 2) and `b797334` (`spec/exit.md` draft 1). Independent and adversarial; the reviewer wrote none of these. It checks draft 3 against `notes/review-local-api-d2.md` (N1 to N16, the section 5 gaps, the section 6 defaults) and attacks what draft 3 adds. Local notes, not posted anywhere.

## Verdict

**Ready after listed changes, and a short list.** Draft 3 answers nearly everything:
- Fixed: the redirect file, the same-user check, the two kinds of confirmation, the setup session, the tunnel rules, the sticky-code exception, the 24-word rules and the RFC 8785 digest.
- What remains is mostly one problem. Section 4.7 was written against storage **draft 1**. Storage **draft 2** and `exit.md` 5.6 changed what a locked wallet can do: it **cannot finish an exit**. As a result, the locked-state wording in draft 3 now reassures where it must not, and several names, fields and file locations disagree across the three documents.

**Can Slice 1 be built from it?** Yes, for everything except the edges of the locked state and first run, once R2, R3 and R11 below are settled. They are small: one alignment pass of 4.7 and 4.2 with storage draft 2, an API answer for storage's rollback start rule, and a decision on whether Slice 1 builds the watcher at all. R1 is a wording fix that must be made now, because the interface's tables are written once (2.1), even though it bites only in 1.0.0. R4 (snap browsers) does not touch Slice 1, which runs headless on a server, but it must be fixed before 1.0.0 on Ubuntu desktops.

---

## 1. Round-2 findings and gaps: status

| # | Status | Evidence in draft 3 |
|---|---|---|
| N1 Missing storage spec, contradicting documents | **Partly fixed** | Storage exists and 4, 4.2 and 4.3 use its operations, passphrase rules and attempts file. But draft 3 cites storage draft 1 throughout, and draft 2 has since changed things the API states: R2. `journal.md` section 2 and open point 1, `wallet-keys.md` 8 and `THREAT-MODEL.md` 2.7 still say Slice 1 is unencrypted, now only listed (24.2 item 22) |
| N2 Locked wallet stops watching | **Partly fixed** | The watcher, the locked shape, the `lock` field in session and status, the offline-style lock confirmation and the unlock sequence are all there (4.5, 4.7). But the watcher's powers and the locked wording go beyond storage d2 8.7.1 and `exit.md` 5.6 (R1), `unlock_by` is missing, the lock echo uses the wrong date, and the unlock sequence omits W3 and treating the log as untrusted (R2) |
| N3 Start token on the command line | **Fixed in design**, residuals R4 and R5 | 4.3 steps 1 to 4: redirect file `first-run.html` (0600 in a 0700 folder), listen before launch, "spent at its first presentation", file deleted then; hijack wording; `first_run_launched_at`; 23.3 item 2 checks no command line holds a token |
| N4 Passphrase the only barrier against other accounts | **Fixed on Linux and Windows**; honest fallback elsewhere; residual R8 | 3.4: `NETLINK_SOCK_DIAG` then `/proc/net/tcp`; `GetExtendedTcpTable` then `OpenProcessToken`; refused before a byte is read; `interface.peer_check`; Settings wording; 3.2 `SO_PEERCRED`/`getpeereid` on the socket |
| N5 One 5-minute window | **Fixed** | 4.8, kinds A and B: the words, opening a hosted lobby and every 1.0.0 spend carry the passphrase; the window covers only reversible trust changes; echoes stated as bug catchers |
| N6 Setup session | **Fixed**, residual R9 | 4.3 "The setup session": call list, `not_setup_call`, no fresh sign-in for create, restore and finish-setup, window starts at create/restore, words always carry the passphrase, the closed-tab path; test 23.1 item 19 |
| N7 Hand-over to any same-origin page | **Fixed**, residual R7 | 3.3 and 4.4: no hand-over while the tunnel port is set (`handover: false`), sessions bound to their `Host`, tunnel sessions end after 2 minutes unseen; `offer` only in answer to a nonce-bearing `ask`, never for a setup session |
| N8 Reassuring status values | **Fixed** | 11.2 priority 22 and the sticky exception; section 22's rows replaced; `nobody_restoring` with `restored_factories_unknown`; test 23.1 item 21 |
| N9 24-word rules | **Fixed** | 12.7, D9: until Done, hidden while the tab is hidden, 10-minute ceiling, cleared on `pagehide` and `freeze`; the `clipboard-write` limit stated; uncopiable remains listed; `/` served `no-store`; T7, T9, T13 |
| N10 `Clear-Site-Data` | **Fixed** | 4.4 "second wall only"; T4 |
| N11 SharedWorker | **Fixed** | 4.4 `token` and `sign_out` messages; COEP and CORP on the worker script |
| N12 `request_id` | **Fixed**, residual R10 | 7.4: RFC 8785, `passphrase` removed before digesting, replay after restart answers current state |
| N13 Passphrase limits | **Fixed** | 4.3 "Attempt limits": one counter and one slot for every derivation, checked first, one running and one waiting; missing file is the strictest state; test 23.2 item 46. Start-token counter: R5 |
| N14 Cross-references | **Fixed** | 15's intro now says local ids; the references to 4.4, 4.6 and 4.8 are corrected |
| N15 Bare `403` | **Fixed** | 5.2, the plain refusal page |
| N16 Export protected only by the passphrase | **Fixed** | 12.6 states it |
| F4 residual | **Fixed** | 15.5: re-checked on every re-read, opened without following links, checked through the descriptor |
| Gap 1 Storage layer | **Partly** | As N1 and R2, R3 |
| Gap 2 Locked answers and unlock order | **Partly** | As N2 and R1, R2 |
| Gap 3 Setup session | **Fixed** | 4.3 |
| Gap 4 First-run launch | **Fixed**, residuals R4, R5 | 4.3, 5.2 |
| Gap 5 Hand-over and worker protocol | **Fixed** | 4.4 message table |
| Gap 6 Replay and canonical JSON | **Fixed** | 7.4 |
| Gap 7 Ninth session, one counter | **Fixed** | 4.2, 4.3; D19 |
| Gap 8 Abandoned while watched, restoring | **Fixed** | 11.2, 12.4 |
| Gap 9 Pause at unlock | **Fixed** | 4.7 step 3, 7.5, 11.3 |

Default changes from round 2: **D2**, **D5**, **D9**, **D16** applied as proposed. **D13** applied, but its warning text is now wrong (R1).

---

## 2. Remaining and new findings, ranked

### R1. High in 1.0.0 (wording written now). The locked wallet is described as finishing an exit; storage d2 and `exit.md` say it cannot

**Evidence.**
- Local API 4.7 table, "Leaves alone by its dates": "**Yes**, broadcasting the bundle's already-signed exit path at its dates".
- The lock warning: "will leave them alone by their dates if it must, using transactions it has already signed".
- The locked page: "It still watches 2 factories, and leaves them alone at block 333172 (about [date]) unless you unlock it first".
- Section 22: "It still watches and leaves in time".
- 11.2 `locked_watcher`: "the watcher watches and leaves alone by the dates".
- `next_action.what` includes `starts_leaving_alone`.

**What the other two documents now say.**
- Storage d2 8.7.1 (its F2): the watcher "**cannot finish an exit**: the commitment needs an unlock by `unlock_by`".
- `exit.md` 5.6: the watcher publishes only the tree path, so it "cannot by itself stop the host's timeout at H_leaf". The headline once the tree steps are out is "Unlock now. Only the last step of leaving a factory is left, and it needs your passphrase. After block H_leaf the host can take this balance."

Draft 3 covers this with a hedge ("with whatever already-signed transactions the bundle holds"). But the strings and the 4.7 table say the opposite, and a member who reads "leaves them alone ... unless you unlock" may stay locked through H_leaf and lose the balance.

**Fix.**
- Replace the 4.7 row with: "Starts leaving alone by its dates, publishing the **tree path only**; the last step (the commitment) needs the passphrase by `unlock_by`; after H_leaf the host can take the balance."
- Adopt `exit.md` 5.6's headline table as the locked page's wording, first match wins.
- Add `unlock_by` (height and estimate) to the locked status.
- Add `doing.params.watcher = waiting_for_unlock` once the tree steps are out, and attention tiers matching 5.6 (`at_risk` cases).
- Rewrite the lock warning to name `unlock_by`.
- Change the lock echo from `confirm_open_by_height` to `confirm_unlock_by_height` (`exit.md` 5.6: "allowed with a warning naming `unlock_by`").
- In Slice 1, which has no channels, `unlock_by` is `null` and the headline is the creation case. The strings still must not promise an exit.

### R2. Medium, S1. Draft 3 follows storage draft 1; draft 2 changed six things the API states

| Draft 3 says | Storage d2 / `exit.md` 5.6 says | Change |
|---|---|---|
| KB in "the operating system's key store (or `watch.key` where there is none)" (4.2) | The `watch.key` fallback is **removed**; with no key store there is **no bundle**, and locked means not watching (8.7.3) | Drop `watch.key`. Add `reason: no_key_store` to `nobody_locked`, with the offer of unattended unlock or staying unlocked (storage 8.7.3, 8.6 item 6) |
| `socket.token` "in the data folder" (4.2; 23.3 item 2) | In a **per-user runtime directory outside the data folder** (12.2) | Move it |
| `next_action` "is the bundle's `next_action_height` ... the one date stored in the clear" (4.7) | **Not in the clear**; the watcher serves it from the opened bundle (8.7.6, F10). `exit.md` 5.6 and 10.2 still say "clear", and storage lists that as a change `exit.md` must make | Say "served by the watcher"; the value is unchanged. Note R6 |
| `watching.state = locked_watcher` | `watcher_locked` (`exit.md` 5.6, 10.2; storage 8.7.1) | Pick one name in all three documents |
| Unlock step 2: the log is "merged into the journal in one batch ... What it broadcast becomes activity entries" | `watch.gzl` is **untrusted input**: each claim is checked against the chain before it becomes a record (8.7.4 rule 6); W3: if the watcher broadcast a tree step, the node completes and broadcasts the commitment **at once, before contacting the host** | Activity entries only from chain-confirmed claims. Insert W3 between "chain servers connect" and "hosts connect" in step 5, and state that pause does not delay it (`exit.md` 5.4) |
| Lock error `payments_in_flight` "if `spec/exit.md` so decides"; 24.2 item 23 recommends refusing | **Held**, not refused, while an incoming payment's secret is released and unsettled; new payments stop first (`exit.md` 5.6; storage 8.1) | `lock.state = held_for_payment` (1.0.0); drop the refusal recommendation |

Also: the API's references to "storage draft 1" (top matter, 4, 24.2 item 7) should name draft 2. Storage 18.1 asks for **owner amendments** of decisions 13 and 14 ("after lock only the watcher runs"; the export format); the API now depends on both and should say they are pending.

### R3. Medium, S1. Storage's rollback start rule has no API answer

Storage d2 6.3 step 4: when the journal is "behind" or "possibly old", "the node is not started. 'These files are older than this wallet's last saved state. Gazpacho can start them as a restore, with new keys, or stop.'"

`POST /api/v1/session` (an unlock) then has no defined answer, and `wallet`, `doing` and `node_stopped`'s reasons (8.1: `storage_failed`, `storage_full`, `journal_corrupt`, `rebuilding`) have no value for it. Nor is there a call for the person's choice.

Since storage is in Slice 1, the program can reach this state from the first build. It is easily triggered: a deleted guard file reads as "possibly old" for every wallet (storage 6.3 step 1, F6).

**Fix.**
- Add `wallet = files_behind`, with `params.cause` set to `behind` or `possibly_old`, and `doing.code` of the same name at priority 1.
- Add `POST /api/v1/wallet/start-as-restore`, kind A, with `confirm: "restore_new_keys"`, which leads into `journal.md` 8.2.
- Keep the watcher running meanwhile (storage 6.3 step 4).
- Add a section 22 row: "never 'your wallet is fine'".

### R4. Medium, 1.0.0 desktop. The redirect file cannot be opened by snap browsers, Ubuntu's default

The data folder is under `$XDG_DATA_HOME`, that is `~/.local/share` (storage 6.4). Snap-packaged browsers cannot read files under hidden folders such as `~/.local/share`: Launchpad bug 1959417, "browsers and other apps packaged as snaps can't read files under ~/.local/share/". The same applies to `/tmp` and `~/.cache` (bug 1972762). Jupyter's redirect file hit exactly this, and the common workaround users were told was `use_redirect_file = False`, which brings back the visible token. Firefox is a snap by default on Ubuntu.

Draft 3's step 2 says "Whether any common browser package is confined this way is not known". It is known. The person then sees a browser error page, not Gazpacho. A first-run code is printed "when standard output is a terminal", which a program started from a desktop menu does not have.

**Fix.**
- Detect a confined default browser, for example a `.desktop` handler from `/snap` or a Flatpak, and in that case write the redirect file in an owner-only, **non-hidden** folder the browser can read, such as a 0700 folder under the home directory deleted after use. Or go straight to the code flow.
- Make the plain address's first-run page offer "type the code", with the code shown by the program in a way that is not a command line. A desktop notification sent by running `notify-send <code>` would put the code in `/proc/*/cmdline` again; send it over D-Bus directly or not at all.
- T6 should name snap Firefox and snap Chromium, and record the result.

### R5. Low-Medium, S1. The first-run `cross-site` exception lets any website drive the start-token counter

5.2 accepts a `cross-site` top-level navigation to `GET /` while no wallet exists. 4.3: "Start token and codes: one attempt per second; 5 wrong in a row cancel every code that existed then".

Any web page the person visits during first run can navigate a window to `http://127.0.0.1:<port>/#start=<junk>` five times. The interface, which is the program's own page, presents the junk with a correct `Origin`, so every wall passes and each counts as wrong. That cancels the codes, and if the start token is among "every code", the token too. Before draft 3 a cross-site navigation was refused.

**Fix.** A 256-bit start token cannot be guessed, so give it **no wrong-attempt counter**: a wrong token is simply refused, and only the real token's first presentation spends it. Have the interface present a fragment only if it has the token's exact form (43 base64url characters). Count only typed codes, which arrive by user input, toward the code limit.

### R6. Low-Medium. The locked status reveals dates and counts to other accounts where the peer check is unavailable

Storage d2 moved `next_action_height` and `unlock_by` out of the clear because a clear copy "would reveal the member's next exit date to anyone with the folder". The API serves both, plus `factories_watched`, to any connection without a session (4.7).

- On Linux, the peer check limits this to the person's own account, which can reach KB anyway. Nothing is lost.
- On macOS, where 3.4 runs no check, any local account can read them.

**Fix.** When `interface.peer_check = unavailable`, the unauthenticated locked status carries the headline tier and `watching.state` only. The heights appear after sign-in, or to the local socket, which is checked by `getpeereid`.

### R7. Low, 1.0.0 (tunnel). The SharedWorker is still reachable by a same-origin page

With the tunnel port set and the tunnel down, a page of another service at that origin can run `new SharedWorker('<the interface's worker URL>')`. That attaches to the **running** instance, because instances are keyed by origin, script URL and name, and the script is not fetched again. The page then receives `event` relays (topics and local ids) and can post `sign_out` or a `token` that the worker "keeps ... the newest", which is a denial of service.

**Fix.** Use no SharedWorker while the tunnel port is set (per-tab streams, as for the hand-over). Or have the worker accept `token` and `sign_out` only from ports that presented the current token, and relay only to those ports.

### R8. Low. The same-user check: three edges

- **macOS** is not hopeless. `libproc` (`proc_listpids` over the program's own user, then `proc_pidfdinfo` with `PROC_PIDFDSOCKETINFO`) lists only processes the caller may inspect, so "the peer's tuple belongs to one of my own processes" is answerable, and "not found" can be refused. Assess it for 24.2 item 26.
- **Windows elevation.** Opening the token of an **elevated** process of the same account from a non-elevated program may be denied, so 3.4's rule "a failure is itself the sign of another account" would refuse an elevated browser. Test 23.2 item 45 mentions "an elevated and a non-elevated browser" without saying which outcome is expected; say "refused, fail closed", or design for it. PID reuse between the table lookup and `OpenProcess` is a small race; compare the process creation time.
- **Root and proxies.** A port published from a container, or any root-owned forwarder (`docker-proxy`, a system `socat`), is refused as another account; say so. If the program itself runs as root, as a build server may, "another account" includes every user and the `root` case of test 45 cannot be run there.

The OpenSSH claim (3.3: the forwarding process runs as the logged-in user) is consistent with privilege separation. T12 is the right check.

### R9. Low, S1. Setup session lifetime

4.3 does not say how long a setup session lives, or what happens if it ends (idle sign-out, tab closed) **before** `create`. The start token is already spent, so the plain address offers nothing. The way back is a restart, which makes a new token, or `gazpacho first-run-code` over the socket. State it, and word it on the page ("Start Gazpacho again, or type the code it prints").

### R10. Low, S1. RFC 8785 details

- Say "the **top-level** `passphrase` member".
- Add one vector to `tools/spec-vectors.py`, for example a body with a non-ASCII name, a `\u001f` control character and nested objects, with its canonical bytes and SHA-256. C implementations of JCS are rare, and integers-only (7.1) makes a small one easy to get right and easy to get subtly wrong.
- Sorting by UTF-16 code units equals byte order for this API's ASCII names. Say so, so a builder does not implement UTF-16 sorting needlessly.

### R11. Low, S1 (scope). Does Slice 1 build the watcher?

4.7 says Slice 1's watcher watches unresolved creations, and lists `no_bundle` "for example a Slice 1 build before `spec/exit.md`'s records exist". Test 23.2 item 41 expects `locked_watcher` after a restart with an awaiting-funding factory.

On a Linux server, KB needs a systemd credential (storage 8.7.3); a harness started without a unit has no key store, so no bundle. Decide one of:
- (a) Slice 1 builds the bundle for creations, with KB from a systemd credential, and test 41 runs under a unit;
- (b) Slice 1 ships `nobody_locked`, with reason `no_bundle` or `no_key_store`, and test 41 expects that.

Either is honest. The specification must pick one.

### R12. Low. Other small points

- 24.2 item 23 also recommends putting the host's signed funding in the bundle. `exit.md` 9.4 owns that; cross-reference it.
- D17 says "on by default". Storage 8.7.5 and `exit.md` W5 add that "maximum privacy" is refused while something is to take out unless the person confirms with the date. Mirror W5 in 20.2 and the 4.8 table.

---

## 3. The new pieces, attacked

**Redirect file.**
- It removes the command-line exposure (proc(5); the Jupyter precedent holds).
- The `<meta http-equiv="refresh">` from a `file:` page is a top-level navigation with an opaque initiator, so `cross-site`, `navigate`, `document` is the expected metadata (5.2). T5 is the right test.
- Weak points: snap and Flatpak browsers (R4) and the counter (R5).
- The file holds the token in clear on disk for up to 10 minutes, and is deleted at stop. Also delete any stale `first-run.html` at **start**, before writing a new one: a crash between write and delete leaves the old one.

**Same-user check.** Sound where it runs, with the right fail-closed default; R8 gives the edges. It also makes 5.7's "other accounts" row true and defeats the cross-account first-run race on Linux, even without the redirect file.

**Kind A against kind B.** Correct split. Nothing irreversible stays under a window. The words check counts a wrong passphrase against the passphrase counter, not the daily check limit (12.3), which is right. Replay of a kind A request runs no derivation and answers only what a `GET` would; harmless. A kind A request with a stolen session still needs the passphrase, under the one counter.

**Setup session.** Complete except its lifetime (R9). Hijack detection now uses `first_run_launched_at`. A junk token (R5) gives `bad_code`, not `token_used`, so it does not raise a false hijack warning. It should stay that way.

**Tunnel rules.** Correct: per-tab storage plus no hand-over means another page of the same origin cannot read the token. The remaining hole is the SharedWorker (R7). The 2-minute session end is a reasonable bound.

**Locked status and lock confirmation.** The shape is right: no amounts, outpoints, ids or keys. But it lacks `unlock_by` and the headlines (R1), the state name differs (R2), it over-exposes where there is no peer check (R6), and the confirmation echoes `open_by` where `exit.md` names `unlock_by` (R1).

**RFC 8785 digest.** The right choice: integers-only and refused duplicates make it straightforward. R10.

---

## 4. Section 4.7 against storage d2 8.7 and `exit.md` 5.6

| Point | Local API 4.7 | Storage d2 8.7 / `exit.md` 5.6 | Agrees? |
|---|---|---|---|
| Keys while locked | Only KB | KB subkeys only (8.1) | Yes |
| Watches outpoints and txids | Yes | Yes | Yes |
| Answers a host's old state | Yes, with fully signed responses | Penalties against revoked host commitments, if CH-5 holds | Yes, with that condition stated |
| Leaves alone | "Yes" | **Tree path only; cannot finish; host may take the balance after H_leaf** | **No** (R1) |
| Fees | Only pre-signed fee children | The ladder for tree steps only, off unless fee coins were set aside | Mostly; say "tree steps only" |
| Signs, talks to host, payments | No | No | Yes |
| Journal | Not read; log merged at unlock | Log is **untrusted**, chain-checked; W3 commitment first | **Partly** (R2) |
| Headline date | `next_action` | `unlock_by` plus the headline table | **No** (R1) |
| State name | `locked_watcher` | `watcher_locked` | **No** (R2) |
| Next date in the clear | "Stored in the clear" | Not in the clear (storage); clear (`exit.md`, to be changed) | **No**, three-way (R2) |
| No key store | `watch.key` fallback | No bundle | **No** (R2) |
| Lock with payments in flight | Refused, "if exit decides" | Held | **No** (R2) |
| "Maximum privacy" | 1.0.0 setting with the offline warning | Refused while something is to take out, unless confirmed with the date (W5) | Partly (R12) |
| Lock near `leave_by` | Fresh sign-in plus `open_by` echo | Allowed with a warning naming `unlock_by` | **No** (R1) |

---

## 5. Defaults added in draft 3

| # | Default | View |
|---|---|---|
| D17 | Watcher on by default while locked | **Accept**; add W5's refusal of "maximum privacy" while something is to take out (R12), and state Slice 1's choice (R11) |
| D18 | Opening a hosted lobby is kind A | **Accept** |
| D19 | The ninth sign-in ends the session unused longest | **Accept**; ending one needs the passphrase, so it is no outside denial |
| D20 | Lock refused while hosting an Open lobby | **Accept** |

---

## 6. What I could not check

- **No browser or operating-system test was run.** T1 to T13 remain.
- **Not verified:**
  - whether Windows denies `OpenProcessToken` on an elevated process of the same account from a non-elevated one;
  - the macOS `libproc` approach;
  - the claim in the Microsoft documentation that 3.4 quotes about `SE_DEBUG_NAME`.
- **Snap Firefox's behaviour** rests on the Launchpad bug and Jupyter users' reports, not a test.
- **`exit.md` and storage d2** were read only for the parts that bear on 4.7. Neither has been reviewed.

## 7. Sources

- Launchpad bug 1959417, snap browsers cannot read files under `~/.local/share/`: https://bugs.launchpad.net/ubuntu/+source/chromium-browser/+bug/1959417
- Launchpad bug 1972762, Firefox snap will not open files in `/tmp` or `~/.cache`: https://lists.ubuntu.com/archives/ubuntu-mozillateam-bugs/2022-August/176184.html
- Jupyter users on the redirect file and snap Firefox: https://discourse.jupyter.org/t/i-cant-open-jupyter-in-my-browser/15306 ; https://groups.google.com/g/sage-support/c/22Uj6xrP8zo
- Jupyter Server configuration, `ServerApp.use_redirect_file`: https://jupyter-server.readthedocs.io/en/latest/other/full-config.html
- proc(5), `hidepid`: https://man7.org/linux/man-pages/man5/proc.5.html
- sock_diag(7): https://man7.org/linux/man-pages/man7/sock_diag.7.html
- RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- W3C Fetch Metadata Request Headers: https://w3c.github.io/webappsec-fetch-metadata/
- HTML, Web workers (SharedWorker instance matching by origin, URL and name): https://html.spec.whatwg.org/multipage/workers.html
- Microsoft, `GetExtendedTcpTable` and `OpenProcessToken`: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable ; https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
