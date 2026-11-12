# Transport, first cut (draft 2, reviewed)

The connection between Gazpacho programs for slice 1: Lightning's encrypted, authenticated connection (BOLT 8) carrying Lightning's message format (BOLT 1). Draft 1 was written 2026-11-11 before the code. Draft 2 (2026-11-12) answers the independent review of pull request 10 (`notes/review-pr10-transport.md`, findings F1 to F10).

**Reviewed.** The two rounds of that review (`notes/review-pr10-transport.md` and `notes/review-pr10-transport-r2.md`) count as this specification's review under checklist item 1 (decided 2026-11-12). **Exception to item 1:** the specification was reviewed after the code was written, not before; that cannot be repaired for this piece and is recorded here, as is the pull request's size (item 24). Small changes after the second round (findings N1 to N6) are noted where they apply.

## Scope

- Slice 1 only: a member connects directly to the host's address (given to it by hand) and pins the host's key. No Nostr, no address gossip, no `init` exchange, no ping and pong of BOLT 1's types 18 and 19, no reconnection logic.
- The transport lives outside the core, in `ports/net/`. The core never calls it. A program moves bytes between the transport and the core's send actions and message events.

## Pieces

| File | What it is | Input or output |
|---|---|---|
| `ports/net/noise.c` | BOLT 8 state machine: the three acts, then encrypt and decrypt with key rotation | None. Bytes in, bytes out. Randomness comes from a callback (`gz_random_port_t`, the core's own port type) |
| `ports/net/frame.c` | BOLT 1 message framing, BigSize, a strict TLV reader and writer, truncated integers | None |
| `ports/net/conn.c` | POSIX TCP: listen, accept, connect, with timeouts and a size cap, driving the state machine | Sockets and the monotonic clock |
| `tools/gz-net/gz-net.c` | `listen` and `connect`: handshake, then a ping and pong of custom message type 32769 | The above, and the system's randomness (`getrandom` on Linux, `getentropy` elsewhere; a failure ends the program) |

Cryptography: ECDH from libsecp256k1's ECDH module, whose default hash is SHA-256 of the compressed shared point, exactly BOLT 8's `ECDH`. ChaCha20-Poly1305, SHA-256 and HMAC-SHA256 from OpenSSL's libcrypto, as the imported code already uses. HKDF is the two HMAC steps of RFC 5869 written out (extract, then two blocks of expand with empty `info`), because BOLT 8 gives the intermediate values to check them against.

## What is stored, in what order, crashes

The transport stores nothing. All its state is in memory: handshake hashes and keys, then the two directions' keys, chaining keys and nonces. On a crash, or any error, the connection is gone and a new one starts from a fresh handshake with fresh ephemeral keys. Nothing is resumed. Messages in flight are lost; the core's rule of resending what is saved and not acknowledged (checklist item 16) covers that, not the transport.

The static key a program uses is supplied by its caller. `gz-net` reads it from a file named on the command line, or makes a throwaway one; key storage for real programs belongs to the wallet keys work.

## Rules

1. Acts are exactly 50, 50 and 66 bytes. Any other length is refused.
2. A version byte other than 0 is refused, before anything else in the act is looked at.
3. A public key that does not parse as a compressed secp256k1 point is refused.
4. A failed MAC on any act, length header or message is refused.
5. After any refusal the state is dead: every later call fails, and all keys in it are wiped.
6. Each direction rotates its key when its nonce reaches 1000 (after 500 messages): `ck', k' = HKDF(ck, k)`, nonce back to 0.
7. A message is at most 65,535 bytes. The sender refuses to encrypt more. The receiver reads the length only after its MAC checks, and the connection layer refuses a length above its configured cap (at most 65,535) before reading the body.
8. The member side is always the initiator and is given the host's key. The handshake itself fails if the host does not hold that key: act two's MAC depends on it. That is the pin. The connection layer then compares the handshake's remote key with the pin, but this is a guard that cannot fail while the member is the initiator (the remote key is the pin itself); it has no negative test, and none is possible without a test-only hook.
9. Ephemeral keys come from the randomness callback. A value that is not a valid secret key is drawn again, at most 8 times, then the act fails.
10. Secrets (static and ephemeral secret keys, temporary keys, ECDH outputs, session keys, chaining keys, decrypted bytes of a refused message) are wiped on every exit path. Comparisons of MACs are OpenSSL's constant-time ones; the pinned-key comparison uses `CRYPTO_memcmp` too, though a public key is not secret.
11. Messages: at least 2 bytes (the type). Unknown odd type: ignore. Unknown even type: close.
12. TLV streams: types and lengths minimally encoded BigSize; types strictly increasing; a length past the end fails; a known type is checked by the caller's checker; an unknown even type fails; an unknown odd type is skipped. A writer refuses types out of order and anything past its buffer.
13. The host's side of pinning. A member is identified by its static key, the one its handshake proves it holds; nothing else (an address, a name) identifies it. `gz_conn_accept` requires a member check, called with that key once the handshake is complete and before any message is read; a refusal closes the connection. In slice 1 the host accepts every key (`gz_conn_any_member`), because members are not known in advance: the key a member connects with is the key it joins the lobby with, and from then on the lobby and the factory know the member by that key. A program that knows its members (a host after the lobby closes, or a later slice with invitations) passes a check that compares the key with its list.
14. A state is never copied while in use: two copies would encrypt under the same key and nonces.

## Timeouts and the connection layer

Sockets are non-blocking and close-on-exec, set in the same call that makes them (`SOCK_CLOEXEC | SOCK_NONBLOCK` on `socket`, and `accept4`) where the system has those, so no other thread can start a program between the two; elsewhere `fcntl` sets both just after (N4). Every wait on the network is a `poll` against a deadline from the monotonic clock, and a `poll`, `recv` or `send` interrupted by a signal is resumed. Addresses must be numeric (`AI_NUMERICHOST`): no name is looked up, because name resolution could not be bounded by a deadline. A name is refused with its own error, "address must be numeric" (N5). Waiting for a connection has its own limit (`accept_ms`; none by default). The handshake must finish within the handshake timeout (default 10 s), counted from the connection. A message, header and body together, must arrive whole within the receive timeout (default 30 s) from when its first byte is awaited, so a peer that trickles bytes is cut off. A write that cannot finish within the send timeout fails.

A peer's close never raises SIGPIPE: writes use `MSG_NOSIGNAL` where the system has it, otherwise each socket gets `SO_NOSIGPIPE`; a system with neither does not build `conn.c` (it stops with an error rather than fall back silently). The tests run with SIGPIPE at its default action.

## Limits of this cut

- Accept and handshake are one blocking call. While a peer is in its handshake the host serves nobody else, so one silent or slow peer holds the host for up to the handshake timeout, and a peer that does so again and again keeps members out. Acceptable for slice 1, where a host waits for a few members it is told about; not for a host serving members. Before that: a step-wise handshake driven by one `poll` over many connections (the state machine already allows it), or a capped number of connection threads or processes. Decided 2026-11-12 after review finding F2. **Open:** which of the two is not decided; neither review round decided it, and it must be decided before a host serves members. If threads are chosen, the atomic close-on-exec above matters.
- The idle timeout and the per-message deadline are the same timeout. A member idle for 30 s is cut off. Before members stay connected, split the two and add BOLT 1's ping and pong.
- POSIX only. Windows needs its own `conn` behind the same header (and `fd` as an opaque handle).

## Decisions where BOLT 8, BOLT 1 and our documents are silent

All twelve were confirmed by the review of PR 10 (decisions 1 to 10 in round 1, 11 and 12 in round 2). The one open design choice is under "Limits of this cut".

1. Every refusal is final for the state, including the caller's own mistakes (a message over 65,535 bytes, a too-small output buffer, a call out of order). Simpler to reason about than a mix of fatal and recoverable errors. `gz_noise_remote_static` is a query, not a refusal: before the handshake ends it answers "not yet" and changes nothing.
2. Order of checks in an act: length, then version, then key, then MAC, matching the order of the BOLT 8 failure vectors.
3. Ephemeral keys: up to 8 draws from the randomness port before giving up.
4. HKDF and HMAC are written out over OpenSSL's one-shot HMAC; ChaCha20-Poly1305 and SHA-256 are OpenSSL's EVP, as in the imported `crypto_aead.c`. The imported code itself is not called, so the transport does not link the SuperScalar library.
5. ECDH uses libsecp256k1's ECDH module (already enabled in the pinned build) rather than a hand-written multiply and hash.
6. Keys after the handshake: the chaining key, temporary key, ephemeral secret and our static secret are wiped as soon as act three is done; the session keys and the two public keys stay.
7. The connection layer's receive timeout covers one whole message from when its first byte is awaited, so an idle connection also times out (30 s by default). Keep-alive belongs to the caller (BOLT 1's ping and pong are not in this cut).
8. The member is always the initiator and the host always the responder, so the pin is the handshake's own `rs`. The explicit comparison after act two cannot fail while that holds; it is kept as a guard against a later change, and labelled as such in the code (rule 8).
9. `gz-net`'s custom message 32769 carries a TLV stream (type 1: kind, 1 ping or 2 pong; type 3: sequence number, tu64). Odd, so other software ignores it.
10. A static key is read from a file of exactly 64 hex digits and an optional line end, never from the command line, so it does not appear in process listings. Pins, ports and counts are parsed strictly too: anything else in them is refused.
11. A `gz_conn_t` starts zeroed and is reusable after it is closed. Accept or connect on one that is still open is refused and leaves it working (it would otherwise leak its socket). Closing a zeroed one closes no descriptor.
12. The randomness port cannot report a failure, so `gz-net` ends the program if the system's randomness cannot be read rather than continue with weak values. It reads with `getrandom` (or `getentropy`), so no buffer of future key bytes stays in the process (N3). Letting the core's port report failures is left to the core.

## Tests, listed before the code

BOLT 8 vectors, byte for byte: initiator success (act one, act three, the intermediate `h`, `ck` and temporary keys, and the final `sk`, `rk`); initiator act two: short read, bad version, bad key, bad MAC; responder success (act two, `rk`, `sk`, the recovered `rs`); responder act one: short read, bad version, bad key, bad MAC; responder act three: bad version, short read, bad ciphertext MAC, bad `rs`, bad MAC; message encryption outputs 0, 1, 500, 501, 1000, 1001 and both rotation HKDF outputs, and the receiver decrypting all 1002.

BOLT 1 vectors: BigSize decoding (18) and encoding (8); TLV decoding failures, successes and stream failures from Appendix B, with the n1 and n2 namespaces written in the test; Appendix C's `init` extensions; appending each invalid stream to each valid stream fails; appending a higher-numbered valid stream to a lower one succeeds.

Hostile and boundary cases: acts one byte short and one byte long; calls out of order; every call after a failure; bad MAC on a length header and on a body; body given with the wrong length; a 65,536-byte message refused by the sender; a length above the cap refused by the connection before the body is read; rotation exactly at message 500 and not 499, in both directions; a randomness callback that gives only invalid keys; keys wiped after success and after failure.

Connection, between local processes: handshake and ping-pong; a wrong pin refused with nothing sent after act one; a silent peer timed out; a truncated act; a peer that closes mid-message; an oversize length from an authenticated peer.

Added in draft 2 (review of PR 10): both sides sending 600 messages before either reads, so the two directions rotate in a different order (F1); every call in every handshake phase refused; the member check seeing the key and its refusal closing the connection; the handshake deadline starting at the connection; a member facing a silent host; the body sharing the message's deadline; SIGPIPE at its default with a closed peer; a slow reader getting twenty full-size messages and a reader that never reads cut off by the send deadline; a signal every 5 ms during a slow message; reuse of an open connection; close-on-exec; names refused; `gz-net` closing on an unknown even message, ignoring an unknown odd one, refusing a wrong pong, and refusing loose keys, pins and numbers; every wipe of a stack secret counted (the transport wipes through one function, `gz_net_wipe` in `ports/net/wipe.c`, which the test wraps; wrapping `OPENSSL_cleanse` itself would also catch a static libcrypto's own wipes, as the MemorySanitizer build showed), and HMAC made to fail at each of its calls in a handshake and in a rotation. Opt-in (`-DGZ_INTEROP_PY=ON`, needs Python's `cryptography`): `gz-net` against the reviewer's independent Python BOLT 8 peer, as host and as member, 1,200 pings each way (past rotation), so two copies of this code are not each other's only judge. **It should run in the automated checks** (N6): the CI hardening work is to turn it on wherever Python's `cryptography` is installed, including before every merge.

Added after round 2 (N1, N2, N5): the wipe test checks which buffer each wipe clears, not only how many bytes, by comparing the wiped bytes with values from the BOLT 8 vectors (every ECDH output, chaining key, temporary key and session key, each HKDF's PRK and its T block, and the handshake secrets); a key file ending in CRLF reads as the same key; a name is refused as "address must be numeric" by the library and by `gz-net`; send, receive and remote_static on a never-opened connection say it is closed; the member's, host's and listening sockets are checked to be close-on-exec and non-blocking.

A randomised TLV test against an independent model: a generator that builds streams record by record and knows whether it broke one, compared with the parser's verdict and the records it returns, in order.

Fuzz targets, written for libFuzzer and also built with a plain driver for the build server (which has no clang): the decrypting reader, and the TLV parser.

Mutation run: a list of deliberate small faults in `ports/net/`, each built and tested in a scratch copy, reporting which no test catches.
