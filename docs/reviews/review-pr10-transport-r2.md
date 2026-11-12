# Review of PR 10, round 2: transport fixes (commit 872202f on 772b795)

*Archived 2026-11-12 as found: **unfinished**. The verdict, the new findings and the mutation results were never written in; the placeholders below mark where they belong. The status of findings F1 to F10 and the five checked points are complete. See `README.md` in this folder.*

Independent review of the fix commit "Transport: fixes after the review of PR 10", against my first review (`docs/reviews/review-pr10-transport.md`, findings F1 to F10). Date 2026-11-12.

Where: on the build server, a copy of the builder's tree in (a local folder). That tree carries the old commit IDs (5d850c2, 36e9c0d); I checked that every file under `ports/`, `tests/net/`, `tools/`, `spec/transport.md` and `CMakeLists.txt` is identical to `origin/transport` (the listing of those paths, blob IDs included, hashes the same on both sides). Locally I read `git diff 772b795..origin/transport` only; no branch was checked out. Nothing pushed, committed or posted. My files and logs are kept on the build server, in (a local folder).

## Verdict

__VERDICT__

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
| Mutation testing | __MUTCOUNTS__ |
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

__NEW__

## Mutation testing

__MUTATION__

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
