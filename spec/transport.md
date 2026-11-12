# Transport, first cut (draft 1, not yet reviewed)

The connection between Gazpacho programs for slice 1: Lightning's encrypted, authenticated connection (BOLT 8) carrying Lightning's message format (BOLT 1). Written 2026-11-11 before the code. Not yet reviewed by someone who did not write it (checklist item 1): that review is still owed.

## Scope

- Slice 1 only: a member connects directly to the host's address (given to it by hand) and pins the host's key. No Nostr, no address gossip, no `init` exchange, no ping and pong of BOLT 1's types 18 and 19, no reconnection logic.
- The transport lives outside the core, in `ports/net/`. The core never calls it. A program moves bytes between the transport and the core's send actions and message events.

## Pieces

| File | What it is | Input or output |
|---|---|---|
| `ports/net/noise.c` | BOLT 8 state machine: the three acts, then encrypt and decrypt with key rotation | None. Bytes in, bytes out. Randomness comes from a callback (`gz_random_port_t`, the core's own port type) |
| `ports/net/frame.c` | BOLT 1 message framing, BigSize, a strict TLV reader and writer, truncated integers | None |
| `ports/net/conn.c` | POSIX TCP: listen, accept, connect, with timeouts and a size cap, driving the state machine | Sockets and the monotonic clock |
| `tools/gz-net/gz-net.c` | `listen` and `connect`: handshake, then a ping and pong of custom message type 32769 | The above, `/dev/urandom` |

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
8. The member side is always the initiator and is given the host's key. The handshake itself fails if the host does not hold that key (act two's MAC depends on it); the connection layer also compares the finished handshake's remote key with the pin.
9. Ephemeral keys come from the randomness callback. A value that is not a valid secret key is drawn again, at most 8 times, then the act fails.
10. Secrets (static and ephemeral secret keys, temporary keys, ECDH outputs, session keys, chaining keys, decrypted bytes of a refused message) are wiped on every exit path. Comparisons of MACs are OpenSSL's constant-time ones; the pinned-key comparison uses `CRYPTO_memcmp` too, though a public key is not secret.
11. Messages: at least 2 bytes (the type). Unknown odd type: ignore. Unknown even type: close.
12. TLV streams: types and lengths minimally encoded BigSize; types strictly increasing; a length past the end fails; a known type is checked by the caller's checker; an unknown even type fails; an unknown odd type is skipped. A writer refuses types out of order and anything past its buffer.

## Timeouts and the connection layer

Sockets are non-blocking and every wait is a `poll` against a deadline from the monotonic clock. The whole handshake must finish within the handshake timeout (default 10 s). A message, once its first byte is awaited, must arrive whole within the receive timeout (default 30 s), so a peer that trickles bytes is cut off. A write that cannot finish within the send timeout fails. Writes use `MSG_NOSIGNAL`.

## Decisions where BOLT 8, BOLT 1 and our documents are silent

To be confirmed or overruled in review.

1. Every refusal is final for the state, including the caller's own mistakes (a message over 65,535 bytes, a too-small output buffer, a call out of order). Simpler to reason about than a mix of fatal and recoverable errors.
2. Order of checks in an act: length, then version, then key, then MAC, matching the order of the BOLT 8 failure vectors.
3. Ephemeral keys: up to 8 draws from the randomness port before giving up.
4. HKDF and HMAC are written out over OpenSSL's one-shot HMAC; ChaCha20-Poly1305 and SHA-256 are OpenSSL's EVP, as in the imported `crypto_aead.c`. The imported code itself is not called, so the transport does not link the SuperScalar library.
5. ECDH uses libsecp256k1's ECDH module (already enabled in the pinned build) rather than a hand-written multiply and hash.
6. Keys after the handshake: the chaining key, temporary key, ephemeral secret and our static secret are wiped as soon as act three is done; the session keys and the two public keys stay.
7. The connection layer's receive timeout covers one whole message from when its first byte is awaited, so an idle connection also times out (30 s by default). Keep-alive belongs to the caller (BOLT 1's ping and pong are not in this cut).
8. The member is always the initiator and the host always the responder, so the pin is the handshake's own `rs`. The explicit comparison after act two cannot fail while that holds; it is kept as a guard against a later change.
9. `gz-net`'s custom message 32769 carries a TLV stream (type 1: kind, 1 ping or 2 pong; type 3: sequence number, tu64). Odd, so other software ignores it.
10. A static key is read from a file of 64 hex digits, never from the command line, so it does not appear in process listings.

## Tests, listed before the code

BOLT 8 vectors, byte for byte: initiator success (act one, act three, the intermediate `h`, `ck` and temporary keys, and the final `sk`, `rk`); initiator act two: short read, bad version, bad key, bad MAC; responder success (act two, `rk`, `sk`, the recovered `rs`); responder act one: short read, bad version, bad key, bad MAC; responder act three: bad version, short read, bad ciphertext MAC, bad `rs`, bad MAC; message encryption outputs 0, 1, 500, 501, 1000, 1001 and both rotation HKDF outputs, and the receiver decrypting all 1002.

BOLT 1 vectors: BigSize decoding (18) and encoding (8); TLV decoding failures, successes and stream failures from Appendix B, with the n1 and n2 namespaces written in the test; Appendix C's `init` extensions; appending each invalid stream to each valid stream fails; appending a higher-numbered valid stream to a lower one succeeds.

Hostile and boundary cases: acts one byte short and one byte long; calls out of order; every call after a failure; bad MAC on a length header and on a body; body given with the wrong length; a 65,536-byte message refused by the sender; a length above the cap refused by the connection before the body is read; rotation exactly at message 500 and not 499, in both directions; a randomness callback that gives only invalid keys; keys wiped after success and after failure.

Connection, between local processes: handshake and ping-pong; a wrong pin refused with nothing sent after act one; a silent peer timed out; a truncated act; a peer that closes mid-message; an oversize length from an authenticated peer.

A randomised TLV test against an independent model: a generator that builds streams record by record and knows whether it broke one, compared with the parser's verdict and the records it returns, in order.

Fuzz targets, written for libFuzzer and also built with a plain driver for the build server (which has no clang): the decrypting reader, and the TLV parser.

Mutation run: a list of deliberate small faults in `ports/net/`, each built and tested in a scratch copy, reporting which no test catches.
