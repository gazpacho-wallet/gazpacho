# Review of PR 10, round 2: transport fixes (commit 872202f on 772b795)

*Archived 2026-11-12. The copy first archived here was **unfinished**: its verdict, new findings and mutation counts were blank. The verdict "merge" reached the coordinator first in the reviewer's message. This is the reviewer's finished file, taken from the coordinator's notes. Server folders are named in words, under the rule against local paths.*

Independent review of the fix commit "Transport: fixes after the review of PR 10", against my first review (`review-pr10-transport.md`, findings F1 to F10). Date 2026-11-12.

Where: on the build server, a copy of the builder's tree in a folder on the build server. That tree carries the old commit IDs (5d850c2, 36e9c0d); I checked that every file under `ports/`, `tests/net/`, `tools/`, `spec/transport.md` and `CMakeLists.txt` is identical to `origin/transport` (the listing of those paths, blob IDs included, hashes the same on both sides). Locally I read `git diff 772b795..origin/transport` only; no branch was checked out. Nothing pushed, committed or posted. My files are in a folder on the build server, logs in a folder on the build server.

## Verdict

**Merge.** Every must-fix finding of round one (F1 to F6) is fixed with a test that fails without the fix, and F7 to F10 are fixed too. F2 is fixed in the form I asked for: the stall remains by design, and the decision is now recorded. My first-round tests and my independent Python peer pass against the new code, the builder's tests now kill every one of my round-one survivors that was a real gap, and none of my 26 new mutants of the fix code shows a protection gap that matters.

What is left is small and need not hold the merge: the wipe test checks how many bytes are wiped but not which bytes (N1, three surviving mutants), a CRLF key file is never tested (N2), and a few nits. The spec can be marked as reviewed once the owner agrees (last section).

## What I ran

| What | Result |
|---|---|
| Plain build and ASan+UBSan build, `-DGZ_INTEROP_PY=ON` | both build, 0 warnings in new code |
| `ctest -R net`, both builds (now 8 net tests, including `net_wipes` and the opt-in `net_interop_py`) | all pass |
| `ctest`, everything, plain build | 27 of 27 pass |
| valgrind (`--track-origins`, leak check) on `test_net_noise`, `test_net_wipes`, `test_net_conn`, `test_net_frame 2000` | 0 errors, 0 leaks |
| `gcc -fanalyzer -Wshadow -Wformat=2 -Wnull-dereference -O2` on `noise.c`, `frame.c`, `conn.c`, `gz-net.c` | 0 warnings |
| My first-round extra tests (`review_extra.c`, 1,375 checks; only change: the new `gz_conn_accept` arguments), both builds | pass |
| My Python BOLT 8 peer against the new `gz-net`, both roles, 1,200 messages each way, both builds | pass |
| `conn.c` compiled as if `MSG_NOSIGNAL` were missing (Linux has no `SO_NOSIGPIPE`) | stops with the new `#error`, as the spec says |
| The `SO_NOSIGPIPE` branch compiled on Linux with a stand-in option name, `-Wall -Wextra -Werror -pedantic` | compiles |
| Fuzzing under ASan+UBSan, new seeds: `fuzz_tlv` 20,000,000 inputs (seed 99991), `fuzz_noise` 2,000,000 (seed 31337) | clean |
| Mutation testing (builder's runner, 217 mutants: the builder's 121, my 70 from round one, 26 new ones of the fix code) | 189 killed, 23 survive, 5 of my old ones no longer apply (the code they targeted was rewritten). Of the 23: 13 equivalent (4 of them the `EINTR` pair, which appear in both lists), 3 the wipe-target gap (N1), 7 small or unreachable. My extra tests kill none of the 23 |
| clang | still not installed on the build server: no clang build, no libFuzzer |

## Status of each finding

| Finding | Status | Evidence |
|---|---|---|
| F1 receive rotation untested | **fixed** | `test_noise.c` `test_rotation_order`: both sides send 600 before either reads; checks `res.rck`/`res.rk` against BOLT 8's rotation vector and `ini.rck`/`ini.rk` against one HKDF of the final keys. The mutant `r-decrypt-body-uses-sck` is now in `mutants.txt` and killed (mutation section). My Python peer is in the tree as an opt-in test, with credit; it passes |
| F2 one silent peer stalls the host | **fixed as a decision** (the stall itself remains, by design) | the handshake deadline now starts at the connection, and waiting for one has its own `accept_ms` (`conn.c` accept; tested by `late_slow`: 400 ms late plus a 300 ms act one fits a 500 ms handshake). The blocking accept is recorded in the spec's new "Limits of this cut" with the two ways out, choice open. That is what I asked for |
| F3 host accepts any key | **fixed** | required member check (section above), spec rule 13 |
| F4 protections without negative tests | **fixed**, apart from two mutants that are equivalent on Linux | new tests for each: member-side handshake timeout, SIGPIPE at default, send deadline and full buffers, every call in every phase (`test_phases`, 6 × 8 refusals), the body sharing the message's deadline (`body_trickle`: header slow, body fast, too late in all; this is the test my R10 could not be), EINTR in `poll`, `gz-net` closing on unknown even (with a separate peer that tells a close from a timeout, which my test did not), ignoring unknown odd, refusing a wrong pong. Each of my round-one survivors is now in `mutants.txt` by name |
| F5 spec claims too much | **fixed** | numeric addresses only; `SO_NOSIGPIPE` or `#error`; handshake timeout "counted from the connection"; pin check labelled in code and spec as a guard that cannot fail; `remote_static` described as a query in `noise.h` and decision 1 |
| F6 loose parsing in `gz-net` | **fixed** | strict hex table (upper and lower case), exact lengths, key file of exactly 64 digits and an optional `\n` or `\r\n`, numbers with no sign, no trailing text, in range. Each of my examples (`+28d7…`, `" -1-1…"`, `12abc`, `+5`, `0`, `3x`) has a test |
| F7 randomness failures | **fixed in the tool** | `/dev/urandom` opened once; a failed read aborts. The port still cannot report failure; recorded as decision 12, left to the core. Nit in new findings |
| F8 copying a state | **fixed in documentation** | `noise.h` and spec rule 14. No mechanism stops a copy; acceptable |
| F9 descriptors | **fixed** | `FD_CLOEXEC` on every socket (tested on the accepted and listening sockets); `live` marker: accept or connect on an open `gz_conn_t` returns `GZ_CONN_ERR_BUSY` and leaves it working (tested), closing a zeroed one closes nothing even if `fd` names a real descriptor (tested). My R15: no leak |
| F10 nits | **fixed** | seed wiped, `clock_gettime` checked (abort), `remote_static` wording; the pong check now has a test |

## The five points I was asked to look at

### The member check argument of `gz_conn_accept`

`gz_conn_accept(..., gz_conn_member_fn is_member, void *member_ctx)` (`conn.h`, `conn.c` accept). Checked:

- It is required: `NULL` returns `GZ_CONN_ERR_ARGS` before anything is done (tested, `test_conn.c` `test_member_check`). A caller cannot forget it silently; slice 1's choice to accept anyone is now visible at every call site as `gz_conn_any_member`.
- It is called once, with the key the handshake proved (`gz_noise_remote_static` after act three), after the handshake and before any message is read. A refusal goes through `die()`: socket closed, state wiped, `GZ_CONN_ERR_NOT_MEMBER`. Tested: the check sees exactly the member's key, is called once, and the member sees the close.
- `member_ctx` is passed through unchanged (tested by the counter in `refuse_member`).
- The spec's rule 13 says what identifies a member (its static key only) and why slice 1 accepts any key. That answers F3.

One remark, not a defect: the check runs after the host has answered act one and spent its ECDH work, so a non-member costs the host a full handshake. That is inherent to Noise_XK (the member's key arrives in act three) and is fine.

### Numeric-only addresses

`resolve()` now sets `AI_NUMERICHOST | AI_NUMERICSERV` for both listen and connect, so `getaddrinfo` never does a name lookup and the spec's "every wait on the network is a poll against a deadline" is now true (the one unbounded wait, for a connection with `accept_ms` 0, is stated as such). Tested by the builder: `localhost` is refused by both `gz_conn_connect` and `gz_conn_listen`. Nit: the error is `GZ_CONN_ERR_SOCKET`, shown by `gz-net` as "socket error" or "cannot listen"; a distinct error or a word in the message ("not a numeric address") would save someone a puzzled minute.

### The `SO_NOSIGPIPE` fallback

`conn.c` now uses `MSG_NOSIGNAL` where defined, otherwise sets `SO_NOSIGPIPE` on every socket in `prepare_socket()` (listening, accepted and connecting sockets alike), and otherwise stops the build with `#error`. I checked both ends on Linux: with `MSG_NOSIGNAL` hidden the file stops at the `#error`; with a stand-in option in place of `SO_NOSIGPIPE` the fallback branch compiles cleanly under `-Werror -pedantic`. The accepted socket gets the option itself rather than relying on inheritance, which is right. The tests now leave SIGPIPE at its default in the host process (`test_no_sigpipe`, and `gz-net` no longer ignores it), so the protection is really exercised on Linux.

Unverified, and worth one line in the spec: on macOS, `_POSIX_C_SOURCE=200809L` (set at the top of `conn.c`) may hide `SO_NOSIGPIPE` unless `_DARWIN_C_SOURCE` is also defined; whether recent macOS exposes `MSG_NOSIGNAL` in that mode I have not checked. If neither is visible the build stops at the `#error`, which is the safe failure the builder chose, and the fix is to define `_DARWIN_C_SOURCE` there.

### The wipe-counting test

`tests/net/test_wipes.c`, linked with `--wrap=OPENSSL_cleanse,--wrap=HMAC`. It records the size of every wipe, in order, per call, and compares them with sequences written from the rules (HKDF: 32, 33, 32, 32; mixing a key: those then 32 for the ECDH output; act three adds the split and the four handshake secrets). It also makes HMAC fail at each of the 24 HMAC calls of a handshake and checks that the failing side is dead and all-zero, and makes the rotation's HMAC fail after a good MAC on each side and checks that the body is wiped and the state is dead. This is good work and better than what I suggested. It reaches the six survivors of round one that needed wipe observation or fault injection (section on mutation).

Its limit: it checks how many bytes are wiped and in what order, not which buffer. A wipe moved to the wrong buffer of the same size passes (see new finding N1 and the mutation section).

### The claim that two EINTR mutants cannot be tested on Linux

The builder's new `test_interrupted_waits` delivers SIGALRM every 5 ms, handler installed without `SA_RESTART`, while a peer sends a message a byte every 20 ms, and checks that the message arrives and that more than 50 signals came. That kills the `poll` mutant (`r-poll-eintr-fatal`). The two that survive are `r-recv-eintr-fatal` and `r-send-eintr-fatal`.

I agree with the claim. Every socket in `conn.c` is non-blocking, so `recv` and `send` never sleep; on Linux a signal can interrupt only a sleeping system call, and a non-blocking socket call that cannot proceed returns `EAGAIN` instead. All the waiting happens in `poll`, which the test interrupts. So on Linux these two mutants are equivalent, not untested. Keep the two `EINTR` lines anyway: they cost nothing, and POSIX allows `EINTR` from `recv` and `send` in general. The same reasoning covers `accept` on the non-blocking listening socket. Record them in `mutants.txt` (or the report) as "equivalent on Linux", so later readers do not take them for gaps.

## New findings

None is a defect in the transport's behaviour; all are test gaps or nits.

### N1. Low-medium (tests). The wipe test does not check which buffer is wiped

`test_wipes.c` records the size of each `OPENSSL_cleanse` call, not what it cleared. Three of my mutants survive every test, including mine:

- `w2-hkdf-o2-wrong-buffer`: HKDF wipes `o1` twice and leaves the second output block `o2` (a copy of `temp_k` or of a new key) on the stack;
- `w2-hkdf-prk-wipes-junk`: HKDF wipes a fresh 32-byte local and leaves the PRK on the stack;
- `w2-mix-key-wipes-junk`: mixing a key wipes a fresh local and leaves the ECDH output `ss` on the stack.

Each produces the same sizes in the same order. The code today wipes the right buffers (I read every call), so this is about the test protecting them. Fix: have `__wrap_OPENSSL_cleanse` also record a few bytes of the buffer before clearing it, and compare them with values known in advance. BOLT 8's initiator vector gives every ECDH output (`ss`) and every `temp_k`, and the PRK of each HKDF is one HMAC of known inputs, so the expected contents of each wipe in the handshake can be written into the test. That would kill all three.

### N2. Low (tests). A key file ending in `\r\n` is never tested

`load_key` strips an optional `\r` before the `\n` (spec decision 10 says "an optional line end"), but removing that line survives (`g2-crlf-not-stripped`). Add one key file written with `\r\n` to `test_gz_net.sh`.

### N3. Nit. `gz-net` keeps a stdio buffer of random bytes

`/dev/urandom` is opened with `fopen`, so the first `fread` pulls a full stdio buffer (typically 4 KiB) and keeps it in the process for its lifetime: future ephemeral keys sit in memory before they are used, and none of it is wiped at exit. Harmless for a test tool, but the pattern should not be copied into the wallet. Use `getrandom()` (Linux) or `getentropy()`, or at least `setvbuf(urandom, NULL, _IONBF, 0)`. The abort on a failed read cannot be tested without making `/dev/urandom` fail (`g2-urandom-failure-ignored` survives); `getrandom` would also make that path simpler. The wipe of the 32-byte seed is likewise not observable from outside (`g2-seed-not-wiped`).

### N4. Nit. Close-on-exec is set after the socket is made

`prepare_socket` sets `FD_CLOEXEC` with `fcntl` after `socket()` and `accept()`. In a single-threaded program that is fine. The open choice in the spec's "Limits" includes threads; in a threaded host another thread could `fork` and `exec` between the two calls. If that option is chosen, use `SOCK_CLOEXEC | SOCK_NONBLOCK` on `socket` and `accept4` (Linux and the BSDs have both), keeping `fcntl` as the fallback.

### N5. Nit. A name is reported as a socket error

With numeric addresses only, `gz-net connect --host localhost` fails with "socket error" and `listen` with "cannot listen on localhost:…". A word saying the address must be numeric would help. Similarly, `gz_conn_send` on a never-opened, zeroed `gz_conn_t` returns `GZ_CONN_ERR_CLOSED` as it should, but no test does it (`s2-send-ignores-live` survives: with that check removed the call returns `GZ_CONN_ERR_CRYPTO` and sends nothing, so the only difference is the error code).

### N6. Note. The Python interoperability test is off by default

`net_interop_py` runs only with `-DGZ_INTEROP_PY=ON`. F1 no longer depends on it (`test_rotation_order` covers it in the default suite), but it remains the only judge of this code that was written apart from it. Turn it on wherever Python's `cryptography` is installed (it is on the build server) and in the automated checks before merge.

## Mutation testing

Method: the builder's new runner (`tools/mutate-net.py`, which now also builds `test_wipes` with the `--wrap` link options and `net_peer` for `gz-net`'s tests), copied with two changes: the mutant file comes from an environment variable, and, on a second pass over the survivors, my tests are added (`review_extra.c` and my Python interop). Every mutant is applied to a scratch copy, everything is rebuilt and every test run; the baseline passed in each of the four runs.

Mutants: the builder's 121 (`tests/net/mutants.txt`, up from 87, including my round-one survivors by name), my 70 from round one, and 26 new ones aimed at the fix (`gen_mutants2.py`: wipe targets, the member check, the accept and handshake deadlines, the socket preparation and the `SO_NOSIGPIPE` switch, the `live` marker, and the new parsing in `gz-net`). 217 in all.

| List | Mutants | Killed | Survived | Not applied |
|---|---|---|---|---|
| Builder's | 121 | 118 | 3: `pin-compare-gone`, `r-recv-eintr-fatal`, `r-send-eintr-fatal` | 0 |
| Mine, round one | 70 | 55 | 10 | 5 (the lines they changed were rewritten: `r-nosignal-off`, `r-listen-blocking`, `r-accept-blocking`, `r-close-fd-not-reset`, `r-connect-soerror-ignored`; the builder's list has its own versions of the first and covers the rest) |
| Mine, new | 26 | 16 | 10 | 0 |
| **All** | **217** | **189** | **23** | **5** |

The builder's own count matches mine: the only survivors of its list are the guard that cannot fail and the two `EINTR` lines that are equivalent on Linux. `mix-key-keeps-ss`, which survived round one, is now killed by the wipe test, as are the four HKDF wipe removals and `r-body-step-fail-no-wipe`.

Killed among the new mutants (and by what): the member check shown our own key, given a null context, or refusing without closing (conn); `gz_conn_any_member` refusing (conn, gz_net); `accept_ms` 0 meaning "at once" (gz_net), `accept_ms` ignored (conn, by timeout), the handshake deadline not restarted at the connection (conn); the accepted socket not prepared (conn); the `MSG_NOSIGNAL` branch switched off (the compiler: `#error`); names looked up (conn); `live` not cleared on close (conn, gz_net); the failed-decryption wipe removed (noise); `ss` not wiped (wipes); upper-case hex refused, `--count 0` accepted, `gz-net listen` with no member check (gz_net).

The 23 survivors:

| Mutant | Verdict |
|---|---|
| `pin-compare-gone`, `r-pin-after-act3-sent` | equivalent: the guard cannot fail (spec rule 8 now says so) |
| `r-recv-eintr-fatal`, `r-send-eintr-fatal` (each in both lists) | equivalent on Linux: non-blocking `recv` and `send` never sleep, so never return `EINTR` (section above) |
| `r-decrypt-hdr-uses-sck`, `r-encrypt-hdr-uses-rck` | equivalent: rotation always falls on the body's step |
| `r-nonce-2-bytes` | equivalent: nonces never exceed 999 |
| `r-finish-no-nonce-reset` | equivalent: nonces are already zero |
| `r-pub-of-no-verify` | equivalent: `secp256k1_ec_pubkey_create` checks the key too |
| `r-recv-out-cap-gone` | equivalent at the API: `decrypt_body` refuses the same case |
| `s2-connect-timeout-continues` | equivalent now: a numeric address gives exactly one address to try |
| `s2-remote-static-ignores-live` | equivalent: a closed or never-opened state is dead, so `remote_static` refuses anyway |
| `s2-passive-off` | equivalent for every caller: `AI_PASSIVE` matters only with a null host, which nothing passes |
| `w2-hkdf-o2-wrong-buffer`, `w2-hkdf-prk-wipes-junk`, `w2-mix-key-wipes-junk` | **real gap**, N1 |
| `g2-crlf-not-stripped` | real gap, small, N2 |
| `s2-send-ignores-live` | real gap, cosmetic (error code only), N5 |
| `r-accept-econnaborted-fatal` | not reachable on demand (a connection reset between `poll` and `accept`) |
| `g2-urandom-failure-ignored`, `g2-seed-not-wiped` | not observable without fault injection, N3 |

So: 13 equivalent, 3 the wipe-target gap, 7 small or unreachable. My round-one extra tests kill none of the 23: everything they used to catch is now caught by the builder's own tests.

## Can my review count as the review of `spec/transport.md` draft 2?

Yes, with two conditions, for the owner to confirm.

Between the two rounds I have read every section of draft 2 against BOLT 8, BOLT 1, the checklist and the code: scope, pieces, what is stored and the crash behaviour (nothing is stored; a crash loses the connection and nothing else, which satisfies checklist item 2), rules 1 to 14, timeouts, the new "Limits of this cut", decisions 1 to 12, and the test list. I wrote none of it. Every claim I tested held, and the claims I found too strong in draft 1 (F5) are corrected in draft 2. That is the substance of checklist item 1's review.

The conditions:

1. **It is a review after the code, not before.** Item 1 says code is not started from an unreviewed specification; for this piece it was. That cannot be repaired now; record it as an exception, as with the pull request's size (item 24).
2. **The spec should record the outcome.** Its header still says that whether this counts "is for the owner to confirm", and the decisions section still says "To be confirmed or overruled in review". Once the owner agrees, mark draft 2 as reviewed (naming both review notes), mark decisions 1 to 12 as confirmed (my first review confirmed 1 to 10; 11 and 12 are new and I confirm them too), and keep the one open choice in "Limits" (step-wise handshake or capped threads/processes) explicitly open, since neither review decided it.

## What I did not test

- No clang build, no libFuzzer, no clang sanitizers (not installed on the build server).
- No non-Linux system: the `SO_NOSIGPIPE` branch was only compiled (with a stand-in option name), never run; whether macOS exposes `MSG_NOSIGNAL` or `SO_NOSIGPIPE` under `_POSIX_C_SOURCE=200809L` without `_DARWIN_C_SOURCE` is unverified. If it exposes neither, the build stops at the `#error`, which is the safe outcome.
- No real Lightning implementation (not allowed).
- `EINTR` from `recv` or `send`, and `ECONNABORTED` from `accept` (see the EINTR point).
- IPv6, and hosts with several addresses.
- Whether the compiler keeps every stack wipe: the wipe test counts calls to `OPENSSL_cleanse`, which is what the binary does, but it does not check which buffer each call clears (see new findings).
- Many members on one host (the host still serves one at a time, by decision).
