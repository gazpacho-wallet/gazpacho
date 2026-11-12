# Review of PR 10: transport (BOLT 8 and BOLT 1), branch `transport`, commit 5d850c2

Independent, adversarial review. I did not write this code. Date 2026-11-12.

Scope: `ports/net/noise.c`, `frame.c`, `conn.c` and their headers, `tools/gz-net/gz-net.c`, `spec/transport.md`, the tests in `tests/net/`, `tools/mutate-net.py` and `tests/net/mutants.txt`, the CMake changes. Read against `docs/ENGINEERING-CHECKLIST.md` (all 26 items), BOLT 8 (`08-transport.md`, all 16 named vectors) and BOLT 1 (`01-messaging.md`, Appendices A, B and C).

Work location: a copy of the builder's tree at `/root/gz/review-transport/gazpacho` on the build server (HEAD 5d850c2, identical to the branch). Nothing pushed, committed or posted. My test files are kept on the server in `/root/gz/review-transport/extra/` (`review_extra.c`, `bolt8_peer.py`, `review_py.sh`, `gen_mutants.py`, `run1.sh`, `run2.sh`), with logs in `/root/gz/review-transport/logs/`.

## Verdict

**Merge after fixes.** The cryptography is correct and the parsing is strict; I found no way to break a connection's confidentiality or authentication, no way to make a member talk to an unpinned key, no memory error and no leak. What must change before merge is small and mostly tests and wording:

1. A test that sees the receiving direction's rotation (F1): today the receive key could rotate with the wrong chaining key and every test would still pass.
2. The missing negative tests of F4: member-side handshake timeout, SIGPIPE with its default action, send timeout and full socket buffers, handshake-phase refusals, the body deadline, `EINTR`. My `review_extra.c` has most of them ready to adapt.
3. Spec: the host's duty to check the member's key (F3), the decision on the host's blocking accept (F2), and the three sentences that claim more than the code (F5).
4. Strict hex and number parsing in `gz-net` (F6).

F7 to F10 can follow in a later change. No need to split the pull request now (section 7).

## What I ran, with counts

| What | Result |
|---|---|
| Plain build (gcc 15.2, OpenSSL 3.5.5, secp256k1-zkp 6152622) | builds; 0 warnings in new code (the 3 warnings are in imported secp256k1-zkp) |
| AddressSanitizer + UBSan build (`GZ_SANITIZE=ON`) | builds; 0 warnings in new code |
| `ctest -R net`, both builds | 6 of 6 pass |
| `ctest`, everything, plain build | 25 of 25 pass (no regression elsewhere) |
| valgrind memcheck (`--track-origins`, leak check) on `test_net_noise`, `test_net_frame 2000`, `test_net_conn`, `fuzz_noise 3000`, `fuzz_tlv 20000` | 0 errors, 0 leaks |
| `gcc -fanalyzer -Wshadow -Wformat=2 -Wcast-qual -Wnull-dereference -Wconversion -D_FORTIFY_SOURCE=3 -O2` on the three library files | 0 warnings |
| `noise.c`, `frame.c` as strict C11 `-pedantic -Werror` with no POSIX macros | compile; their objects reference only OpenSSL, libsecp256k1, `memcpy`, `memmove` (no system calls) |
| Reviewer's extra tests (`review_extra.c`, 1,375 checks: phases, off-curve keys, rotation order, TLV type 0, eight connection cases), both builds | all pass on the unmodified code |
| Independent BOLT 8 peer in Python (`bolt8_peer.py`, written from the BOLT text; pure-Python secp256k1, ChaCha20-Poly1305 from `cryptography`) | reproduces the initiator vectors and all six message vectors; interoperates with `gz-net` as member (1,200 pings, then an unknown odd message ignored and an unknown even message closing the connection) and as host (1,200 pings from `gz-net connect`), both builds |
| Mutation testing | builder's 87 mutants: 85 killed, 2 survive (as reported). My 70: 38 killed by the builder's tests, 32 survive; with my tests added, 10 more killed, 22 survive. Of the 24 left in all: 9 equivalent, 6 need wipe observation or fault injection, 9 real gaps. Section 6 |
| Fuzzing, other seeds, longer, under ASan+UBSan | `fuzz_tlv` 30,000,000 inputs (seed 424242), `fuzz_noise` 3,000,000 inputs (seed 777): no crash, no sanitizer report, every assertion held (the default `ctest` runs are 200,000 inputs with the fixed seed) |
| clang | not installed on the build server; no libFuzzer or clang sanitizer run was possible |

## Findings, by severity

None of the findings is a cryptographic error in the code. The handshake, the key derivations, the nonce encoding and the rotation are correct as written: they match every BOLT 8 vector and they interoperate with an implementation I wrote separately from the BOLT text, past rotation in both directions in both roles. The problems are in what the tests can see, in the host side's shape, and in a few claims.

### F1. Medium. The receiving direction's key rotation is not tested; a wrong chaining key there passes every test

`gz_noise_decrypt_body` rotates `rk` with `rck` (`noise.c:364`). Change that `rck` to `sck` and every builder test still passes (mutant `r-decrypt-body-uses-sck`, survivor; section 6). Why nothing notices:

- The BOLT 8 message vector has only the initiator sending, so the responder's `sck` is still equal to its `rck` (both the final `ck`) when the receiving key first rotates. `test_noise.c:208` checks `res->rk` after that rotation; with the wrong chaining key it has the same value.
- The connection test (`test_conn.c:82-89`, `:188-191`) and `gz-net` send strictly alternating traffic between two copies of the same code. With the fault in both copies, both sides make the same mistake in the same order and stay in agreement. The counters at `test_conn.c:191` do not look at keys.

The code is right today: my Python peer, written from the BOLT text, interoperates 1,200 messages each way in both roles. But a real Lightning node would cut a broken Gazpacho off after 500 messages each way, and nothing in the suite would say so. The spec's test list promises "rotation exactly at message 500 and not 499, in both directions".

Fix: a test in which the two sides rotate in a different order, for example both send 600 messages before either reads (my `t_rotation_order` in `review_extra.c` kills the mutant), and check `rck` and `rk` against values computed independently. Better still, keep an independent model in the suite (a small one like my `bolt8_peer.py`, or vectors computed from one) so the two copies of the same code are not each other's only judge.

### F2. Medium (design, slice 1 tolerable). The host is stalled by any one silent peer

`gz_conn_accept` waits for a connection and then runs the whole handshake in one blocking call (`conn.c:155-183`), with a 10 s deadline (30 s in `gz-net`). A peer that opens TCP and sends nothing, or sends act one a byte at a time, holds the host for the full deadline; done in a loop, it keeps every member out indefinitely. There is no concurrency in the layer to soften this. For slice 1's tool this is acceptable; for a host serving members it is not. Record a decision now: either a step-wise, non-blocking handshake API (the state machine already allows it) driven by one `poll` over many connections, or a thread or process per connection with a cap. The accept deadline including the wait for a connection (section 5) is part of the same problem.

### F3. Medium (spec gap). The host accepts any member key

The responder finishes the handshake with whatever static key the member presents (`conn.c:181`); `conn.h` only says "The member's key is then in `remote_static`". Nothing in `spec/transport.md` says that the host must check that key against its members before acting on any message, and `gz-net listen` answers anyone. Add a rule to the spec (and preferably an allow-list check, or a mandatory callback, in `gz_conn_accept`, so that a caller cannot forget it). This is the host-side half of pinning.

### F4. Medium-low (tests). Several protections have no test that fails without them

Confirmed by surviving mutants (section 6), each killed by one of my tests in `review_extra.c`:

- the member side's handshake deadline (`r-member-act2-no-deadline`): the builder tests timeouts only on the host side; a member facing a silent host is untested (my R16);
- `MSG_NOSIGNAL` (`r-nosignal-off`): every builder test ignores SIGPIPE first, so the flag is never needed (my R12, which leaves SIGPIPE at its default);
- the send deadline (`r-send-deadline-1000x`) and `EAGAIN` on write (`r-write-eagain-fatal`): no test sends more than the socket buffers hold (my R13, R14);
- encrypting during the handshake (`r-ready-in-r-sent2`): the builder checks only `R_START`; in `R_SENT2` a mutant encrypts with the zero `sk` (my R1);
- receive rotation (F1).

Still open after my tests, and needing new ones: the body read sharing the message's deadline (`r-recv-body-fresh-deadline`; the builder's trickle test is cut off during the header, and my R10 sends the header at once, so neither can tell), `EINTR` on `poll`, `recv` and `send` (three mutants), and in `gz-net` the close on an unknown even message and the pong sequence check.

Checklist item 6 asks for exactly these negative tests. Adding my cases (or equivalents) plus the four above leaves only equivalent mutants and the secret wipes, which a `--wrap=OPENSSL_cleanse` test could reach (section 6).

### F5. Low (claims). Three sentences in the spec say more than the code does

Details in section 5: DNS is not bounded by any deadline; `MSG_NOSIGNAL` silently becomes 0 where missing; the accept deadline includes waiting for a connection. Also `gz_noise_remote_static`'s non-fatal refusal against decision 1, and the pin check presented as a check when it cannot fail. Checklist item 4.

### F6. Low. `gz-net` parses hex loosely

`hex_decode` uses `sscanf("%2x")` (`gz-net.c:37-46`), which accepts a sign and leading spaces. Shown on the server: `gz-net connect --pin +28d7500d...` (a `+` in place of the leading `0`) is accepted and connects to `028d7500...` ("ok 1"); a key file of `" -1-1-1..."` is accepted as some key and the listener starts. For the pin this fails safe (a different key just fails the handshake), but checklist 20 asks for strict parsing of input, and a mistyped key file silently becomes a different key. `--port`, `--accept` and `--count` use `strtol` without checking the end (`--port 12abc` is port 12). Parse with a strict hex table and check `strtol`'s end pointer.

### F7. Low. Randomness failures cannot be reported

`gz_random_port_t.fill` returns nothing. `gz-net`'s `urandom_fill` (`gz-net.c:29-35`) opens `/dev/urandom` on every call and on failure fills zeros: for ephemeral keys this fails closed (eight zero draws, then `GZ_NOISE_ERR_RANDOM`), but the context-randomisation seed silently becomes zero. Use `getrandom()` (or `getentropy`) with a checked result in the tool; consider, at the core's port level, letting `fill` fail.

### F8. Low. A copied `gz_noise_t` reuses nonces

The state is a public struct (visible for the vector tests). Copying it and encrypting from both copies sends two messages under the same key and nonce, which breaks ChaCha20-Poly1305. The fuzz target does exactly this every iteration (harmless with throwaway keys). Say in `noise.h` that a state must never be copied, or make it opaque with a test-only accessor.

### F9. Low. Descriptor handling

No `SOCK_CLOEXEC`/`FD_CLOEXEC` on any socket (`conn.c:136`, `:170`, `:199`), so a host that starts another program leaks its connections into it. `conn_init` sets `c->fd = -1` without closing an open descriptor, so reusing an open `gz_conn_t` for a new accept or connect leaks a socket. No leak in normal use (my R15: 7 descriptors before and after 40 connections).

### F10. Nits

- `gz-net` does not wipe the 32-byte seed for `secp256k1_context_randomize` (`gz-net.c:224`).
- `gz-net connect` compares each pong's sequence number with the ping's (`gz-net.c:198`), but no test ever sends a wrong one, so removing the comparison survives (`g-pong-seq-unchecked`). Tool only.
- `clock_gettime`'s result is unchecked (`conn.c:32`).
- A non-blocking listening socket is not needed with `poll` before `accept` (`r-listen-blocking` is equivalent), but it does protect against the classic race where the connection is reset between `poll` and `accept`; keep it and say why.

## 1. Cryptographic correctness against BOLT 8

Checked step by step against the BOLT text, not only against the vectors.

| BOLT 8 step | Code | Verdict |
|---|---|---|
| `h = SHA-256(protocolName)`, `ck = h`, `h = SHA-256(h ‖ prologue)` | `noise.c:154-157` | correct; name and prologue strings exact |
| initiator mixes `rs`, responder mixes `ls.pub` | `noise.c:170`, `:180` | correct |
| act one: `h ‖ e.pub`, `es = ECDH(e, rs)`, `ck, temp_k1 = HKDF(ck, es)`, `c = encryptWithAD(temp_k1, 0, h, "")`, `h ‖ c` | `noise.c:188-201` | correct |
| act two: same shape, `ee = ECDH(e, re)` | `noise.c:252-259` (writer), `:261-268` (reader) | correct |
| act three: `c = encryptWithAD(temp_k2, 1, h, s.pub)`, `h ‖ c`, `se = ECDH(s, re)`, `ck, temp_k3 = HKDF(ck, se)`, `t = encryptWithAD(temp_k3, 0, h, "")`, `sk, rk = HKDF(ck, "")` | `noise.c:270-285` | correct, nonce 1 for `c` and 0 for `t` |
| responder act three: decrypt `rs` (nonce 1), `h ‖ c`, `se = ECDH(e, rs)`, MAC `t`, `rk, sk = HKDF(ck, "")` | `noise.c:287-303` | correct; `rs` is parsed (compressed only) inside `ecdh()` |
| `sck = rck = ck`, `sn = rn = 0` | `noise.c:222-232` | correct |
| ECDH = SHA-256 of the compressed shared point | libsecp256k1's default hash, `noise.c:119-126` | correct (the default `secp256k1_ecdh_hash_function_sha256` hashes the version byte `0x02 | (y & 1)` and `x`, which is the compressed point) |
| HKDF: RFC 5869, empty `info`, two blocks | `noise.c:53-72` | correct; aliasing of `out1` with `salt` (`ck`) is safe because the outputs are written last |
| nonce: 32 zero bits then 64-bit little-endian | `noise.c:83` | correct |
| length: 2 bytes big-endian, encrypted with its own nonce, then the body with the next | `noise.c:332-338`, `:349-351` | correct; the sender steps the nonce between header and body (mutant `r-encrypt-nonce-reuse` is killed) |
| rotation: after 1000 uses of a key, `ck', k' = HKDF(ck, k)`, `n = 0`, each direction with its own `ck` | `noise.c:313-318`, called with `sck`/`sk` for sending and `rck`/`rk` for receiving | correct. **The receiving direction's use of `rck` is not tested by the builder's tests** (finding F1) |
| act lengths 50, 50, 66; version 0; key parse; MAC; refusal kills | `noise.c:209-217`, `:292-299` | correct, and in the BOLT's order |
| MAC comparison constant-time | OpenSSL's ChaCha20-Poly1305 compares the tag with `CRYPTO_memcmp` | correct |
| pin comparison | `conn.c:236`, `CRYPTO_memcmp` | correct, but it cannot fail (section 2, F5) |

Malformed acts. Every act refuses a wrong length, a non-zero version, an invalid key and a bad MAC, and is dead and all-zero afterwards: the builder's tests check this for every BOLT failure vector plus lengths 0, 49, 51 and 67. I added off-curve keys (`02 ‖ x` with `x = 5`, whose `x³+7` is not a square; `x = p`; `x = 2²⁵⁶-1`; all zero): all refused with `GZ_NOISE_ERR_PUBKEY` and the state wiped. I also added every out-of-order call in every phase: encrypting or decrypting in any of the six handshake phases, reading act two before writing act one, writing act one twice, reading act three before writing act two. All refused. (Before my tests, a mutant letting `gz_noise_encrypt` run in `R_SENT2` with the still-zero `sk` survived: F4.)

Ephemeral key and the 8-draw retry. `make_ephemeral` (`noise.c:136-144`) draws 32 bytes from the port, checks with `secp256k1_ec_seckey_verify` (inside `pub_of`), and retries up to 8 times. Tested by the builder: always-zero, always-above-order, one bad then good (the act is then the vector's). Correct. The port's `fill` returns nothing, so a failing source cannot say so (F7).

Nonce reuse under one key. Each direction's nonce only goes up, is reset only together with a key change, never exceeds 999, and every error kills the state (so a failed encryption is never retried with the same nonce). The header and body use consecutive nonces. I found no path that reuses a nonce under one key inside the library. Outside it: `gz_noise_t` is a public, copyable struct, and two copies encrypt with the same key and nonces; the builder's own fuzz target copies the ready state every iteration (`fuzz_noise.c:59-60`), harmless there with throwaway keys (F8).

Secrets wiped on every path. I followed every return in `noise.c`:

- `fail()` wipes the whole state on every refusal, including the caller's own mistakes; `gz_noise_wipe` wipes `sizeof *st`, which covers `ls_priv`, `e_priv`, `ck`, `temp_k`, `sk`, `rk`, `sck`, `rck`. Tested (`check_dead` asserts the whole struct is zero).
- After the handshake, `finish()` wipes `ck`, `temp_k`, `e_priv`, `ls_priv`. Tested.
- HKDF wipes `prk`, `t`, `o1`, `o2` (`noise.c:67-70`). Not testable from outside; mutants removing each wipe survive (expected, see section 6).
- The shared secret `ss` (the one the builder says is not wipe-tested): on the success path `mix_key` wipes it immediately after the HKDF (`noise.c:132`), whether or not the HKDF succeeded. On the failure paths before `mix_key`, `ss` holds nothing secret: `ecdh()` returns before calling libsecp256k1 if the key does not parse, and libsecp256k1's `secp256k1_ecdh` only fails for an invalid secret scalar, in which case it hashes the public point times one. Our secret scalars are always valid (checked when made). So `ss` is wiped on every path where it is secret. Confirmed by reading; mutants removing the wipe survive, as the builder reported.
- `aead()` wipes the output of a failed decryption (`noise.c:99`); tested for the body (`test_noise.c:313`). The `EVP_CIPHER_CTX` key schedule is cleansed by `EVP_CIPHER_CTX_free`; OpenSSL 3's one-shot `HMAC()` frees (and cleanses) its context.
- `decrypt_body` wipes `out` if the rotation fails after a good MAC (`noise.c:365`): unreachable without a crypto failure; a mutant removing it survives.
- `conn.c`: `gz_conn_close` wipes the noise state and the 64 KiB buffer, on every error (via `die`). Tested by the builder. The act buffers on the stack hold only public bytes.
- `gz-net`: wipes the key and the key file's line; it does not wipe the 32-byte context-randomisation seed (`gz-net.c:224, 244`; low).

Inside libsecp256k1 (imported, not changed) the ECDH intermediate `x`, `y` are cleared with plain `memset`, which a compiler may drop. Out of scope for this PR (checklist 19: report upstream if anyone cares; newer libsecp256k1 uses its own clearing function).

## 2. Pinning

Can a member be made to talk to an unpinned key? I found no path.

- The only member entry point is `gz_conn_connect`, which takes `pinned_host` and passes it as `rs` to `gz_noise_init_initiator` (`conn.c:228`). There is no unpinned mode.
- `st->rs` on the initiator is written once, at `noise.c:169`, and is otherwise only written by `gz_noise_act3_read` (`noise.c:294`), which the phase check confines to the responder (`R_SENT2`).
- Act two's MAC is made with `temp_k2`, derived from a chaining key that contains `es = ECDH(e, rs)`. Only the holder of `rs`'s secret key can compute `es`, so act two cannot pass from a host without the pinned key. Act one already fails at an honest wrong host (tested by the builder: the host refuses act one with a MAC error, and the member sees the close, having received nothing).
- The member sends nothing after act one unless act two passes; act three carries the member's static key encrypted under a key the impostor cannot have.

Is the explicit pin check (`conn.c:236`) redundant? Yes. It compares `st->rs` with `pinned_host`, and `st->rs` is a copy of `pinned_host` made at `noise.c:169`; it cannot fail unless the noise code is changed. The builder's mutant `pin-compare-gone` survives, and so does mine that moves the check after act three is sent (`r-pin-after-act3-sent`), because the check can never fail. Recommendation: section 5, decision 8.

What the pin does not cover: the host side has no pin at all. `gz_conn_accept` completes with any member key (F3).

## 3. Hostile input and denial of service

Results of my connection tests (`review_extra.c`, forked processes on the local machine, both builds):

| Case | Result |
|---|---|
| R10 header sent at once, body a byte every 100 ms, `recv_ms` 1000 | `timed out` after 1,000 ms: a peer trickling the body is cut off (the builder's trickle test only reaches the header). This test cannot tell one deadline from a fresh one for the body (section 6) |
| R11 member half-closes (`SHUT_WR`) after a message | host reads the message, its reply still reaches the member, the next read is `closed by peer` |
| R12 SIGPIPE left at its default in the host process; peer closes; host sends | `socket error` on the 2nd send, process alive (MSG_NOSIGNAL works on Linux) |
| R13 twenty 65,535-byte messages to a member that reads slowly | all arrive intact: partial writes and `EAGAIN` on write are handled |
| R14 65,535-byte messages to a member that never reads, `send_ms` 500 | `timed out` after 39 messages (2.5 MB buffered) and 504 ms; connection closed and wiped |
| R15 30 refused connects and 10 completed connections | 7 descriptors before, 7 after: no leak |
| R16 member against a host that accepts TCP but never answers act one, `handshake_ms` 700 | `timed out` after 701 ms (the builder tests timeouts only on the host side) |
| R17 act one a byte every 100 ms, `handshake_ms` 1000 | `timed out` within the deadline |

Length caps come before any use: the body length is known only after the header MAC passes, then checked against `max_msg` and `out_cap` before the body is read (`conn.c:267-269`, tested by the builder at 100, 199 and exactly 200). There is no allocation anywhere; each `gz_conn_t` carries one fixed 65,569-byte buffer.

`EINTR`: handled for `poll`, `recv`, `send`, `accept` by reading the code; not exercised by any test (mutants survive, section 6). `connect` on a non-blocking socket is not retried on `EINTR`, which is practically unreachable.

A peer flooding valid messages: nothing in the transport limits the rate; each `gz_conn_recv` returns one message, so the caller sets the pace. Acceptable for the transport, but the host program will need a per-member budget.

Denial of service on the host: see F2 (one silent peer stalls the whole host).

## 4. TLV and BigSize strictness against BOLT 1

Every BOLT 1 reader rule is implemented:

| BOLT 1 rule | Code | Tested |
|---|---|---|
| zero bytes left before a type: stop | `frame.c:105` | yes |
| type or length not minimal: fail | `gz_bigsize_read` `frame.c:21` | yes (vectors) |
| types not strictly increasing, including duplicates: fail | `frame.c:114` | yes (vectors, model) |
| length past the end: fail | `frame.c:115` | yes |
| known type: the caller's checker; wrong length: fail | `frame.c:121` | yes |
| unknown even: fail; unknown odd: skip | `frame.c:124-127` | yes |
| BigSize: canonical minimums 0xfd, 0x10000, 0x100000000; truncation | `frame.c:16-21` | yes (all 18 vectors) |
| truncated integers: no leading zero; zero is empty | `gz_tu_read` | yes |
| message: 2-byte big-endian type; unknown odd ignored, unknown even closes | `frame.c:61-86` | yes; and in `gz-net` by my Python peer |

All Appendix A, B and C vectors are in `test_frame.c`, including both appending rules. The randomised model test is independent of the code and compares records in order. The writer refuses out-of-order types and a full buffer.

A known type 0 as the first record (BOLT 1's own n2 namespace has `tlv1` at type 0) appears in no named test, but the TLV fuzz target knows type 0, and the mutants that drop the `started` flag in the reader or the writer are killed. My `t_tlv_type0` adds it as a named case; worth copying so the protection does not depend on the fuzzer's luck.

## 5. Claims versus code, and the builder's decisions

Claims that are not true as written (checklist 4):

- spec, "Timeouts": "every wait is a `poll` against a deadline". `getaddrinfo` (`conn.c:134`, `:195`) is a wait with no deadline when the host is a name; `AI_NUMERICHOST` is not set. Either set it (the spec says the address is given by hand) or say that name resolution is not bounded.
- spec, "Timeouts": "Writes use `MSG_NOSIGNAL`." Where the system has none, `conn.c:17-19` silently uses 0, and a peer's close then kills the program with SIGPIPE unless the program ignores it. The comment says so; the spec and `conn.h` do not. macOS has no `MSG_NOSIGNAL` but has `SO_NOSIGPIPE`.
- spec, "Timeouts": "The whole handshake must finish within the handshake timeout." In `gz_conn_accept` the deadline starts before waiting for the connection (`conn.c:164`), so a member that connects late gets what is left. `conn.h` says this correctly; the spec does not. And in `gz-net listen`, an accept that waits 30 s with nobody connecting counts as a failure and uses up one of the `--accept N` turns.
- `noise.h`: "After any error the state is dead". True, but `gz_noise_remote_static` called during the handshake returns `GZ_NOISE_ERR_STATE` without killing the state, which contradicts decision 1 ("every refusal is final, including ... a call out of order"). Harmless; make the wording or the code agree.
- spec rule 8: "the connection layer also compares the finished handshake's remote key with the pin". True, but it cannot fail (section 2); say so.
- spec, test list: "rotation exactly at message 500 and not 499, in both directions". Only the sending side's rotation is checked at the exact message (`test_noise.c:190-208`); the other direction is checked only by counters after 601 round trips (`test_conn.c:191`), which cannot see the chaining key used (F1).
- Commit message: "every BOLT 8 vector byte for byte (15 named vectors plus the message-encryption vector ...)". True; I checked the list against BOLT 8's appendix.

The builder's decisions where the documents are silent:

| # | Decision | My view |
|---|---|---|
| 1 | every refusal final, including the caller's mistakes | confirm; fix the `remote_static` exception's wording |
| 2 | order of checks: length, version, key, MAC | confirm; it is BOLT 8's order |
| 3 | up to 8 draws for an ephemeral key | confirm (a valid draw fails with probability about 2⁻¹²⁸; 8 only matters for a broken source, and then it fails closed) |
| 4 | HKDF written out over OpenSSL HMAC; ChaCha20-Poly1305 and SHA-256 from OpenSSL EVP; SuperScalar not linked | confirm |
| 5 | ECDH from libsecp256k1's ECDH module | confirm; its default hash is exactly BOLT 8's (checked against my separate implementation) |
| 6 | handshake secrets wiped after act three; session keys and both public keys kept | confirm |
| 7 | receive timeout covers one whole message from when its first byte is awaited, so an idle connection also times out (30 s) | confirm for slice 1 only. A member that is idle 30 s is cut off. Before members stay connected, split an idle timeout (waiting for the first byte) from the per-message deadline, and add BOLT 1 ping and pong |
| 8 | the explicit pin comparison is kept though it cannot fail | confirm keeping it, but label it in the code and the spec as an unreachable guard; it cannot have the negative test checklist item 6 asks for without a test-only hook, so record the exception. The real protection (act two's MAC) is what must stay tested, and is |
| 9 | `gz-net` message type 32769 with a TLV stream | confirm |
| 10 | static key read from a file of 64 hex digits | confirm, but parse it strictly (F6) and consider refusing a file readable by others |

Decisions the builder made without listing them (checklist 25), to confirm or overrule:

- The host authorises nobody: any member key completes the handshake (F3).
- Accept and handshake are one blocking call (F2).
- `gz_noise_t` is a public struct that may be copied (F8).
- Sockets are made without `SOCK_CLOEXEC`/`FD_CLOEXEC`, so they leak into any program the host starts.
- `gz_conn_accept` and `gz_conn_connect` set `c->fd = -1` without closing a descriptor already there; reusing an open `gz_conn_t` leaks its socket.
- `gz-net` reads randomness by opening `/dev/urandom` for every call and fills zeros on failure.

## 6. Mutation testing

Method: the builder's own runner (`tools/mutate-net.py`), copied as `/root/gz/review-transport/mutate-review.py` with two changes: the mutant file comes from an environment variable, and optionally my tests are added (`review_extra.c`, and the Python interop through `review_py.sh`). Each mutant is applied to a scratch copy, the library and every test are rebuilt, and every test is run. Baseline passed in every run.

**The builder's list** (`tests/net/mutants.txt`, 87 mutants): 85 killed, 2 survived, `pin-compare-gone` and `mix-key-keeps-ss`. This reproduces what the builder reports. Both survivors are explained in sections 1 and 2 (a check that cannot fail; a wipe that cannot be observed from outside).

**My list** (70 mutants in security-relevant lines, generated by `gen_mutants.py`: 36 in `noise.c`, 13 in `frame.c`, 18 in `conn.c`, 3 in `gz-net.c`): against the builder's tests, 38 killed and 32 survived. Re-run with my tests added, 10 more are killed and 22 survive.

Survivors of the builder's tests that my tests kill (real gaps in the builder's tests, F1 and F4):

| Mutant | What it breaks | Killed by |
|---|---|---|
| `r-decrypt-body-uses-sck` | receive rotation with the sending chaining key | my rotation-order test and the Python interop |
| `r-ready-in-r-sent2` | encryption allowed before act three is read (zero key) | my phase test |
| `r-act2-read-any-phase`, `r-act2-write-any-phase`, `r-act3-read-any-phase` | acts accepted out of order (they then fail later on a zero key, so this is defence in depth) | my phase test |
| `r-nosignal-off` | SIGPIPE kills the program when the peer closes | my R12 |
| `r-write-eagain-fatal` | a full socket buffer is a fatal error | my R13 |
| `r-send-deadline-1000x` | the send deadline is effectively gone | my R14 |
| `r-member-act2-no-deadline` | a member waits forever for a silent host | my R16 |
| `g-unknown-odd-closes` | `gz-net` closes on an unknown odd message, against BOLT 1 | the Python interop |

The 24 that survive everything (22 of mine, 2 of the builder's):

| Mutant | Kind | Comment |
|---|---|---|
| `r-decrypt-hdr-uses-sck`, `r-encrypt-hdr-uses-rck` | equivalent | the step after a header never rotates: a message uses an even then an odd nonce, so 1000 is always reached by the body's step |
| `r-nonce-2-bytes` | equivalent | nonces never exceed 999, so bytes 2 to 7 are always zero |
| `r-finish-no-nonce-reset` | equivalent | `sn` and `rn` are already zero from `init_common`'s `memset` |
| `r-pub-of-no-verify` | equivalent | `secp256k1_ec_pubkey_create` checks the secret key too |
| `r-recv-out-cap-gone` | equivalent at the API | `gz_noise_decrypt_body` refuses the small buffer with the same result; only where the refusal happens changes |
| `pin-compare-gone`, `r-pin-after-act3-sent` | equivalent by construction | the pin check cannot fail (section 2) |
| `r-listen-blocking` | equivalent in tests | protects the race where a connection is reset between `poll` and `accept`; not reproducible on demand |
| `mix-key-keeps-ss`, `r-ecdh-ss-not-wiped-act3w`, `r-hkdf-prk-not-wiped`, `r-hkdf-t-not-wiped`, `r-hkdf-o2-not-wiped` | not observable by the current tests | stack copies of secrets. They can be made testable: link a test with `-Wl,--wrap=OPENSSL_cleanse` and assert the number and sizes of wipes per handshake, so a removed wipe is noticed |
| `r-body-step-fail-no-wipe` | needs fault injection | reachable only if HMAC fails after a good MAC; the same `--wrap` approach on `HMAC` would reach it |
| `r-poll-eintr-fatal`, `r-recv-eintr-fatal`, `r-send-eintr-fatal` | real gap | no test delivers a signal during a wait. Add one: an interval timer whose handler is installed without `SA_RESTART`, firing during a slow peer's message |
| `r-accept-econnaborted-fatal` | real gap, hard to reach | a connection reset between `poll` and `accept`; low value |
| `r-connect-soerror-ignored` | real gap, low | with one address the error just shows up at the first write; with a name that has several addresses, the next address would not be tried. No test uses a name |
| `r-recv-body-fresh-deadline` | real gap, **my test misses it too** | my R10 sends the header at once, so a body deadline started after the header is no later than the message deadline. A test must trickle the header to near the deadline and then the body; from reading, `conn.c:261, 266, 269` use one deadline, so the code is right |
| `r-noise-err-not-reset` | real gap, cosmetic | a second connection on the same `gz_conn_t` can report the previous connection's reason |
| `g-unknown-even-ignored` | real gap, **my test misses it too** | my Python peer treats a 20 s silence as a close. On the unmodified code `gz-net` does close (it then reports `done 1200` and exits); a test must tell a close from a timeout |
| `g-pong-seq-unchecked` | real gap, tool only | no test sends a wrong sequence number |

So, of 157 mutants in all, 133 are killed by the builder's tests plus mine, 9 survivors are equivalent, 6 need wipe observation or fault injection, and 9 are real gaps (3 of them EINTR). Two of my frame mutants that drop the `started` flag (`r-tlv-started-1`, `r-writer-started-ignored`) were killed by the builder's tests. I could not fetch the log line naming the killing test (the server stopped accepting connections at the end; the line is in `/root/gz/review-transport/logs/mut-review-*.log`), but the TLV fuzz target is the only builder test whose known set includes type 0, so it is almost certainly that.

## 7. Build hygiene, portability, size

- Hygiene: new code builds with `-Wall -Wextra -Werror -pedantic -Wvla` under C11 without extensions; clean under the extra warnings and `-fanalyzer` listed above, under ASan and UBSan, and under valgrind. `noise.c` and `frame.c` contain no system calls and compile as strict C11 with no POSIX macros. CMake wires all four net tests and both fuzz targets into `ctest`.
- clang: not available on the build server, so neither a clang build nor libFuzzer was tried. The fuzz targets are written to the libFuzzer interface and should link with `-fsanitize=fuzzer` unchanged; untested.
- Portability of `conn.c`: POSIX only, as the spec says. On macOS and other BSDs it compiles, but `MSG_NOSIGNAL` becomes 0 (SIGPIPE, see section 5); use `SO_NOSIGPIPE` where it exists, or make ignoring SIGPIPE a documented duty of the program and test it. Defining `_POSIX_C_SOURCE` alone may hide `SO_NOSIGPIPE` on macOS (needs `_DARWIN_C_SOURCE`). Windows: `conn.c` cannot be carried over; Winsock needs `SOCKET` (not `int`, and the public `gz_conn_t.fd` is `int`), `closesocket`, `WSAPoll` or `select`, `WSAGetLastError`, `ioctlsocket` for non-blocking, `QueryPerformanceCounter` or `GetTickCount64` for the clock. Plan a second `conn_win.c` behind the same header, and change `fd` to an opaque handle before callers depend on it. `noise.c` and `frame.c` are portable as they are (OpenSSL and libsecp256k1 exist on Windows). The CMake flags (`-Wall -Wextra -Werror`) are gcc/clang-only; MSVC would need its own set.
- Size: 3,134 added lines in 19 files, against checklist 24's guide of 2,500. The library is about 1,120 lines; the rest is tests (about 1,420), the tool (260), the mutation runner (141) and the spec. There is a clean split: `frame.c` (with `test_frame.c`, `fuzz_tlv.c`) depends on nothing else; `noise.c` (with its tests and fuzz target) is the second piece; `conn.c`, `gz-net` and the connection tests are the third. My view: do not split it now. It was reviewed in one sitting and splitting after the review would cost another round without improving anything; the fixes below are small. Record it as an exception to item 24, and split along those lines next time.
- Spec review (checklist 1): the spec says it is not yet reviewed. This review covers it (sections 1-5); if that counts as the spec review, the spec's header should be updated when the fixes go in.

## What I did not test

- No clang build, no libFuzzer, no clang sanitizers (not installed).
- No interoperation with a real Lightning implementation (forbidden by the rules of this review). My Python peer is independent of the code but was written by one person from the same BOLT text; it is not a substitute for a test against lnd, CLN, LDK or Eclair. BOLT 1's `init` is not sent, so real nodes would close the connection anyway.
- `EINTR` on any call (no signal injection), `ECONNABORTED` on accept, `connect` to a multi-address name, IPv6, DNS. The mutants for these survive.
- Crypto library failures (OpenSSL or libsecp256k1 returning an error): the `GZ_NOISE_ERR_CRYPTO` paths and the wipe after a failed rotation are unreachable without fault injection.
- Whether stack copies of secrets (HKDF intermediates, `ss`) are really cleared in the compiled code: checked by reading only.
- Timing side channels beyond reading that comparisons use OpenSSL's constant-time functions.
- Non-Linux systems (no macOS, BSD or Windows machine used).
- Many concurrent members against one host (the host has no concurrency to test).
