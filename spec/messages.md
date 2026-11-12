# Factory messages

Specification draft 2, 2026-11-12. Status: draft 1 brought fully in line with `signing-round.md` and `safety-rule.md` draft 4 after the third, joint review (`notes/spec-review-3.md`). Draft 2 has not itself been reviewed. Written for slice 1 (form a factory on signet). It gives the exact encoding of every message of `signing-round.md` section 4 for the creation round, and the lobby's messages. Items marked **(open)** are listed at the end. Draft 1's "(prov.)" marks are gone: every one is now settled by `signing-round.md` draft 4. Values marked **proposed, owner to confirm** are Slice 1 choices the owner has not objected to and has not yet confirmed.

## Changes after review 3

| Finding | How it was handled | Where |
|---|---|---|
| F1, F4, F17 shape, amounts, fixed levels | `funding_amount`, `fee_per_tx_sat` and `fixed_levels` must equal the values `terms.md` section 4.2 derives; T1-dependent vectors M1 and M3 regenerated | 7.2, 11 |
| F3 restore | Member keys under the 31-bit restore epoch; reason 12 has one meaning, "the proposal lacks my current key for this lobby"; no fresh-start confirmation | 2, 7.2, 7.9, test 52 |
| F5 placement | Record 26 removed: placement is fixed by `signing-round.md` 4.1, value 0, and is never sent | 7.2, 9 |
| F6 names | "Dead" for a funding input spent elsewhere, "Abandoned" for a passed deadline, everywhere | 7.9, test 35 |
| F7 tree digest | Defined, for C7's record | 7.12 |
| F9 lost `start` | `start` is signed, saved by both sides and resent after `hello`; a valid proposal for an answered check stands on its own | 6, 6.9, 7.2 |
| F10 same identifier, other bytes | The case table is keyed on `round_id`; a differing copy is kept as evidence; contribution keys are inside the identifier | 7.1, 7.2 |
| F11 keep-alive | 30 s against a step timeout of at least 60 s (`terms.md` section 3) | 2 |
| F12 key before the lobby | Fresh key index per new connection, bound at `join` | 2 |
| F13 forced writes | Limits on seat changes per seat and per connection; a seat change returning to a saved state is not saved; a global limit on scope-zero `hello` answers | 6.1, 6.3 to 6.6 |
| F14 `round_abort` items | Optional odd records `tier` and `items`; Slice 1 aborts whole rounds only | 7.9 |
| F18 512 limit | One wording, with `safety-rule.md` C8; Slice 1 sends no hashes | 7.2, test 39 |
| F19 stale text | 4.3's discussion of draft 2 removed; 7.2's "provisional" removed; open points 4, 5, 13, 15 closed | 4.3, 7, 13 |
| F20 signer selection | Restated as repeated removal | 6.9 |
| F24 anchors | `tree_anchors` must be 1 | 7.2 |
| F26 resend after reconnect | The member resends saved `round_partial_sigs` after `hello` | 6, 7.10 |
| F28 protocol id | The 4-byte tag stays in Slice 1, stated as a fixed alias of the protocol id | 4.3 |
| Missing tags | A table of every tag, including `nonce-extra` and the new `tree` | 1 |
| Slice 1 values | No distribution transaction (record 44 refused); layer step and states fixed at 144 and 4 (**proposed, owner to confirm**) | 7.2, 9 |

Related: `terms.md` (the host terms record carried by `terms_offer`), `signing-round.md` (what the round messages mean), `safety-rule.md` (what a member checks before it contributes), `journal.md` (what is saved before each message is sent).

## 1. Conventions

- All integers are unsigned and big-endian, as in BOLT 1. `u8`, `u16`, `u32`, `u64` are 1, 2, 4 and 8 bytes.
- `point`: a 33-byte compressed public key. Used for every key that is also a Lightning node key or a MuSig2 participant key (BIP 327 takes 33-byte individual keys).
- `sig`: a 64-byte BIP 340 signature. A `point` signs as its x coordinate (BIP 340 ignores parity).
- `sha256`: 32 bytes. `txid`: 32 bytes in the order they appear inside a spending input (internal order, not the order a block explorer shows).
- `outpoint`: `txid` then `u32` output index. 36 bytes. The index is big-endian here, unlike inside a transaction, so that one rule holds for the whole document.
- `TH(tag, bytes)` is the BIP 340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || bytes)`. Every tag starts with `gazpacho/`. A tag is never reused for a second meaning. The tags in use:

| Tag | Over | Defined in |
|---|---|---|
| `gazpacho/msg` | A signed message | 4.3 |
| `gazpacho/part` | The body of a split message | 5 |
| `gazpacho/bind` | Lobby, factory key, contribution key | 6.3 |
| `gazpacho/round_id` | The round identifier's preimage | 7.1 |
| `gazpacho/tree` | The tree digest's preimage | 7.12 |
| `gazpacho/nonce` | Round, tier, index, public nonce | 7.3 |
| `gazpacho/nonce-extra` | Round, tier, index: the extra input of the nonce function | `signing-round.md` section 8 |
| `gazpacho/nonceset` | One item's nonces in signer order | 7.5 |
| `gazpacho/held` | The member's final signatures | 7.8 |
| `gazpacho/terms/outer`, `gazpacho/terms/current` | The two terms records | `terms.md` section 6 |
- "Refuse" means: do not act on the message, send a BOLT 1 `warning` (channel_id all zero, a short ASCII reason), and close the connection. This matches BOLT 1, which closes the connection on an unknown even message and on a known message that is too short.
- "Ignore" means: do not act on it, send nothing, keep the connection.

## 2. Connection

| Item | Rule | Why |
|---|---|---|
| Transport | BOLT 8 (Noise XK) over TCP | Decided in `RECORD.md` section 6. XK needs the responder's static key before the handshake, which is exactly a pinned host key |
| Host key | The host's long-term key is its BOLT 8 static key. The member is given `<host point, 66 hex>@<address>:<port>` and refuses a handshake that does not match | One key to pin, check and show. The same key signs the terms (`terms.md`) and every host message, so the key the member connected to is the key that bound itself to the terms |
| Member key | A BOLT 8 static key derived from the member's seed, its current restore epoch (31 bits; 0 for the original installation, `safety-rule.md` R2) and a key index (`journal.md` section 8; the derivation path itself belongs in the wallet specification, **(open)**). **Which index:** a connection for a lobby where the member has a seat uses that seat's key; any other new connection gets a fresh index, saved (with the guard) before the handshake, and if the member joins a lobby on it, that key becomes the lobby's key (`signing-round.md` section 2). It is also the member's **contribution key** | Identity is new per lobby by default (`LOBBY.md`). Deriving it means a restarted member reconnects with the same key and finds its seat. A restored member derives under a new epoch, so it has no old seat: it joins again |
| First message | BOLT 1 `init`. `networks` must contain the signet chain hash and nothing else; otherwise close | Slices refuse to start on mainnet (`SLICES.md` rule 3) |
| Feature bit | The factory messages need none: a member that sends them to a node that does not speak them is simply ignored, because the message type is odd. A build that includes discovery (`discovery.md` design C, the demo wallet) sets `factory_capable`, candidate bit 449, in `init` (`discovery.md` 3); a build without discovery sets nothing. Bit 271 of bLIP-56 is set only by builds that offer the adapter of section 10 | Slice 1 needs no negotiation. The adapter, when offered, uses bLIP-56's bit (bLIP 2: bits 0 to 255 are kept for BOLTs) |
| Keep-alive | BOLT 1 `ping`/`pong`, a `ping` every 15 seconds of silence. A side that gets no `pong` within 30 seconds closes the connection | BOLT 1 allows closing. The shortest step timeout a host may set is 60 s (`terms.md` section 3), twice this, so a dead connection is noticed and replaced within one step (review 3, F11) |
| Size | A Lightning message is at most 65,535 bytes, its 2-byte type included (BOLT 1 and BOLT 8) | Hence section 5 |

BOLT 8 delivers messages in order and without loss while a connection lasts. Every duplicate this document deals with therefore comes from a reconnect or a restart, never from the transport.

## 3. The custom message type

All factory messages use one Lightning message type: **52791** (0xce37).

- Derivation: the first two bytes of `SHA256("gazpacho factory message")` are 0x4e37; OR-ing with 0x8001 puts the value in the custom range (32,768 to 65,535) and makes it odd. BOLT 1 says a custom type should be picked at random to avoid collisions; this is a reproducible random pick. `tools/spec-vectors.py` prints it.
- Odd, so a node that does not know it ignores it (BOLT 1: "MUST ignore the received message") instead of closing the connection. A Gazpacho connection stays an ordinary Lightning connection.
- Checked on 2026-11-11 against the bLIP 2 registry of custom types: not assigned (37913 belongs to bLIP 50, 63497 to 65535 to bLIP 17). Not checked against unregistered experiments **(open)**.
- For peers that speak bLIP-56, the same messages can travel inside its `factory_piggyback` instead (section 10). Slice 1 does not use that.

## 4. The envelope

The payload of a type-52791 message:

| Offset | Field | Size | Rule |
|---|---|---|---|
| 0 | `protocol` | 4 | The bytes `67 7a 66 01` ("gzf" and 1). Anything else: ignore, and send a `warning` once per connection |
| 4 | `kind` | `u16` | Section 4.1 |
| 6 | `scope` | 32 | The lobby identifier: the outer terms digest (`terms.md` section 6). All zero only in `hello` and in the discovery kinds 128 to 159 (`discovery.md`), which belong to no lobby |
| 38 | `records` | rest | A BOLT 1 TLV stream (section 4.2) |

Sizes: the envelope is at most 65,533 bytes (65,535 less the 2-byte type), so `records` is at most **65,495 bytes**.

Why a `protocol` field when Lightning uses no version numbers: it is not a version that is negotiated. Changes are made the Lightning way, with odd and even kinds and records. The four bytes exist so that another application that happened to pick type 52791 is told apart from us with certainty 1 in 2^32, and so that a future format that cannot be expressed with the odd/even rule gets a clean refusal (`67 7a 66 02`) instead of a misparse.

### 4.1 Kinds, and the odd/even rule

`kind` follows BOLT 1's rule for message types. **Even: the receiver must understand it.** An unknown even kind is refused. **Odd: optional.** An unknown odd kind is ignored. Every kind slice 1 depends on is even.

| Kind | Name | From → to | Section | Slice 1 |
|---|---|---|---|---|
| 2 | `part` | either | 5 | Host → member only |
| 16 | `hello` | member → host | 6.1 | Yes |
| 18 | `terms_offer` | host → member | 6.2 | Yes |
| 20 | `join` | member → host | 6.3 | Yes |
| 22 | `ready` | member → host | 6.4 | Yes |
| 24 | `unready` | member → host | 6.5 | Yes |
| 26 | `leave` | member → host | 6.6 | Yes |
| 28 | `lobby_status` | host → member | 6.7 | Yes |
| 30 | `ready_check` | host → member | 6.8 | Yes |
| 32 | `start` | host → member | 6.9 | Yes |
| 34 | `cancel` | host → member | 6.10 | Yes |
| 64 | `round_propose` | host → member | 7.2 | Yes |
| 66 | `round_nonces` | member → host | 7.3 | Yes |
| 68 | `round_all_nonces` | host → member | 7.4 | Yes |
| 70 | `round_partial_sigs` | member → host | 7.5 | Yes |
| 72 | `round_tier_result` | host → member | 7.6 | Yes |
| 74 | `round_complete` | host → member | 7.7 | Yes |
| 76 | `round_ack` | member → host | 7.8 | Yes |
| 78 | `round_abort` | either | 7.9 | Yes |
| 80 | `round_status_request` | member → host | 7.10 | Yes |
| 81 | `factory_funded` | host → member | 7.11 | Optional hint |

Kinds 128 to 159 are reserved for discovery and defined in `discovery.md`; they always carry an all-zero `scope`. **Discovery is never worth a disconnect:** for kinds 128 to 159 every case this document would "refuse" (a nonzero `scope`, malformed records, an unknown even record, the wrong direction) is **ignored** instead, and `discovery.md` 8.7 says what else a receiver may do. This overrides sections 1, 4.2 and 4.1's direction rule for those kinds only.

Numbering: lobby kinds from 16, round kinds from 64, discovery kinds from 128, so each group has room for more than twenty additions without interleaving. 0 is never used, so an all-zero envelope is invalid.

A kind sent in the wrong direction (for example `ready` from the host) is refused, except a discovery kind, which is ignored (above).

### 4.2 Records

`records` is a BOLT 1 TLV stream, read with BOLT 1's rules:

- `type` and `length` are BigSize and must be minimally encoded; otherwise refuse.
- Types strictly increase; a repeat or a decrease is refused.
- A `length` past the end of the stream is refused.
- **An unknown even type is refused. An unknown odd type is skipped.**

Gazpacho adds:

- **Every field is a record.** There are no fixed fields after the envelope header, so the odd/even rule applies to every field.
- Every record listed as **required** for a message must be present; a missing one is refused.
- A record's value has the exact size given in its table, or, for a list, a whole number of entries between the stated bounds. Anything else is refused.
- **Record type 240 is the signature**, when a message has one. It must be the last record. Nothing may follow it, even odd records; a message with records after 240 is refused. 240 is the start of BOLT 12's signature range, so the number is familiar; Gazpacho uses one signature only.
- Odd record types 1 to 239 are free for optional extensions. They are covered by the signature.

### 4.3 Signatures on messages

For a signed message, the signer signs

```
msg_hash = TH("gazpacho/msg", protocol || kind || scope || every record byte before record 240)
```

as a BIP 340 message of 32 bytes, and puts the 64-byte signature in record 240. `kind` and `scope` are inside the hash, so a signed `ready` can never be replayed as another kind or into another lobby.

Which key signs:

| Sender | Key |
|---|---|
| Host | The host's long-term key (= its BOLT 8 key). Also the host's contribution key: it signs the host's own nonces (section 7.4). It is never a factory key |
| Member | The member's contribution key (= its BOLT 8 key for this lobby) |
| Factory key | Besides group-signature items, signs one thing only: its half of the binding in `join` (section 6.3) |

The factory key signs group-signature items and one binding statement, each under its own tag or digest (`signing-round.md` section 2); the tag `gazpacho/bind` keeps the statement apart from every transaction digest.

**The 4-byte tag is a fixed alias of the protocol identifier.** `protocol` (`67 7a 66 01`) stands for exactly one protocol and major version, the one section 10.3 names `factory_protocol_id`; the mapping is one to one (section 10.2). It is **not a security parameter**: domain separation comes from the tags of `TH`, and a short field in a preimage gives a forger nothing. Slice 1 signs the 4-byte tag, here and in the round identifier (7.1). Signing the 32-byte `factory_protocol_id` instead is deferred: it will be done in one change together with renaming every `gazpacho/…` tag to the agreed namespace, with new vectors, once the shared tag namespace is agreed with SuperScalar (review 3, F28). The protocol id itself is decided (owner, 2026-11-12; 10.3). Until the rename, nothing about the protocol name enters any signature.

## 5. Splitting a large message

A message whose `records` would exceed 65,495 bytes is sent as **parts**. Splitting is done below the meaning of the message: the receiver puts the parts back together and then reads the result exactly as if it had arrived whole, signature included.

The whole message is the triple (`kind`, `scope`, `body`), where `body` is the TLV stream it would have carried.

`part` (kind 2) records, all required:

| Type | Field | Size | Meaning |
|---|---|---|---|
| 2 | `transfer_id` | 32 | `TH("gazpacho/part", u16 inner_kind || body)` |
| 4 | `inner_kind` | `u16` | The kind of the whole message. Must not be 2 |
| 6 | `total_len` | `u32` | Length of `body` |
| 8 | `index` | `u16` | 0 to `count` − 1 |
| 10 | `count` | `u16` | ceil(`total_len` / 65,000), at least 2 |
| 12 | `data` | 1 to 65,000 | Bytes `index` × 65,000 up to (`index` + 1) × 65,000 of `body`, or to its end |

The part's `scope` equals the whole message's `scope`.

**Why 65,000.** A part's records other than `data` take 56 bytes (34 + 4 + 6 + 4 + 4, plus 4 bytes of type and BigSize length for `data`). 65,495 − 56 = 65,439 bytes are free; 65,000 is a round figure that leaves 439 bytes for future odd records. Requiring every part but the last to be full makes `count` a function of `total_len`, so it can be checked.

**Bounds.**

| Bound | Value | Why |
|---|---|---|
| Largest whole message, host → member | 1,048,576 bytes (1 MiB), so `count` ≤ 17 | The largest slice 1 messages are `round_propose` (194 bytes per participant plus node hashes and the funding transaction: under 400 KB at 1,001 participants, section 7.2) and `round_all_nonces` (130 bytes per signer per item; `signing-round.md` estimates 130 KB per member at 512 members, so about 260 KB at 1,000). 1 MiB is about two and a half times the larger, at the 1,000-member size that has been built |
| Largest whole message, member → host | 65,495 bytes: **members send no parts in slice 1** | A member's largest message is `round_nonces`: 134 bytes per item, at most 256 items, 34,304 bytes. A host refuses a `part` from a member. Evidence in `round_abort` will need parts later **(open)** |
| Transfers in progress | One per direction per connection | The sender sends every part of one transfer before it starts the next. Other messages may come between parts |
| Reassembly memory | At most 1 MiB per connection, freed when the transfer completes, fails or the connection drops | Follows from the two bounds above |

**Receiving.**

1. A part with `count` or `total_len` outside the bounds, `count` not equal to ceil(`total_len` / 65,000), `index` ≥ `count`, or `data` of the wrong length for its index: refuse.
2. The first part seen opens the transfer. It need not be index 0.
3. A part with the transfer's `transfer_id` and an index already held: if `data` is byte-for-byte the same, ignore it; if not, refuse.
4. A part with another `transfer_id` while a transfer is open: drop the open transfer (the sender restarted it) and open the new one.
5. When every index is held: check that the joined length is `total_len` and that `TH("gazpacho/part", inner_kind || body)` equals `transfer_id`. On a mismatch, refuse. Otherwise handle (`inner_kind`, `scope`, `body`) as one message.
6. Parts are never saved. A transfer left incomplete when the connection drops is gone; the sender sends the whole message again after reconnecting.

`transfer_id` gives integrity for the joined bytes and a name for the transfer. It is not authentication: the message inside carries its own signature, or the signatures of what it carries.

A message that fits in one envelope is never split.

## 6. Lobby messages

### Seats and reconnects

- A member's **seat** in a lobby is named by its contribution key, which is its BOLT 8 key for that lobby. A member that reconnects with the same key finds the same seat.
- Lobby messages state a **state**, not a change: "I am ready for version 3", "I have left". Receiving one twice changes nothing. This is how every lobby message survives a reconnect or a restart, as `ENGINEERING-CHECKLIST.md` item 16 requires.
- After every (re)connect the member sends `hello` with the lobby's scope, and the host answers with the full current state (`terms_offer`, `lobby_status`, and, while the lobby is Signing and the seat was chosen, the saved signed `start`). Nothing in the lobby relies on a message from an earlier connection having arrived.
- A member with an unresolved round also, after `hello`: resends its saved `round_partial_sigs` bytes if it has sent partial signatures and lacks the result (rule S3; review 3, F26), then sends `round_status_request` (7.10).
- **Limits on state changes** (review 3, F13; first guesses, open point 11). The host saves a seat change only when the seat's state actually changes; a message that returns a seat to the state it already has saved (a duplicate `ready` for the same version, `unready` when Joined) is answered and not saved. Per seat, at most 10 saved changes in any 10 minutes; past that the host ignores the seat's changes and may remove it (state 6). Per connection, at most one `join`; per lobby, at most 4 × `target` seats ever created, and at most one creation per second. A `leave` then `join` with the same key counts against both.

Lobby states (host side; shown to members in `lobby_status`):

| Value | State | Joins | Values may change |
|---|---|---|---|
| 0 | Unknown (no such lobby) | | |
| 1 | Open | Yes | Until the first ready check |
| 2 | Ready check | No | No |
| 3 | Signing | No | No |
| 4 | Funding | No | No |
| 5 | Active | No | No |
| 6 | Cancelled | No | No |
| 7 | Failed | No | No |

After a ready check that does not lead to a start, the lobby returns to Open. Its values stay frozen (`terms.md` section 8).

Seat states, as the host reports them to the seat's owner:

| Value | State |
|---|---|
| 0 | None (this key has no seat) |
| 1 | Joined, not ready |
| 2 | Ready (for the latest version) |
| 3 | Chosen to sign |
| 4 | Not chosen in this start |
| 5 | Left |
| 6 | Removed by the host |
| 7 | Refused |

### 6.1 `hello` (16), member → host

Sent first after `init`, and after every reconnect.

| Type | Field | Size | Required |
|---|---|---|---|
| — | none | | |

- `scope` all zero: the host answers with one `terms_offer` for each **listed** lobby it has open, at most 4 (the same cap as a host's live listings in `discovery.md`). An unlisted lobby is never named in this answer; a member reaches it only with its identifier, from an invitation. A slice 1 host has one. Finding lobbies without connecting first is specified in `discovery.md` (beacons, store nodes, the pool request, the Nostr annex); this answer serves a member already connected to the host.
- `scope` a lobby identifier: the host answers with that lobby's `terms_offer`, then `lobby_status` for this key's seat. For an unknown lobby, `lobby_status` with lobby state 0 alone.
- Duplicates: answered again, at most once per second per connection; more are ignored. A connection that sends more than 20 ignored `hello`s is closed. One `hello` per connection is normal; the limits stop a peer from making the host send terms in a loop. Answers to scope-zero `hello`s are also limited across all connections to 4 per second (review 3, F13: up to 16 offers of about 5 KB each per small request).

### 6.2 `terms_offer` (18), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `outer` | 1 to 4,096 | Yes. The outer rules record (`terms.md` section 3) |
| 4 | `outer_sig` | 64 | Yes |
| 6 | `current` | 1 to 1,024 | Yes. The current values record (`terms.md` section 5) |
| 8 | `current_sig` | 64 | Yes |

Unsigned as a message: each record carries its own signature, made over its digest (`terms.md` section 6), so it can be shown to anyone later.

Valid when: `TH("gazpacho/terms/outer", outer)` equals `scope`; both records decode under `terms.md`'s rules; both signatures verify under the record's `host_key`; that key equals the pinned BOLT 8 key; the chain is signet.

When sent: in answer to `hello`, and to every connected seat whenever the host signs a new current version.

Receiver:

| Case | Action |
|---|---|
| A new lobby | Show it; compare it with the member's conditions (`terms.md` section 9) |
| Same version, same bytes | Duplicate: ignore |
| Higher version, lobby not frozen | Accept. If the member is ready and the new values fail its conditions, send `unready` |
| Lower version than one already accepted | Out of order or replayed: ignore |
| Same version, different bytes, both validly signed | The host signed two values under one version. Keep both as evidence, send `leave`, record it in the history |
| Any new version after the lobby froze | The host broke the freeze. Keep it as evidence, send `leave`, record it |
| Invalid | Refuse |

### 6.3 `join` (20), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `factory_key` | 33 | Yes. The member's MuSig2 key for this factory |
| 4 | `bind_by_factory` | 64 | Yes. By the factory key over `binding = TH("gazpacho/bind", scope || factory_key || contribution_key)`, with the contribution key as a 33-byte `point` |
| 6 | `bind_by_contribution` | 64 | Yes. By the contribution key over the same `binding` (two-way binding, `signing-round.md` section 2) |
| 7 | `display_name` | 1 to 32 bytes UTF-8 | No. Not used in slice 1; the host drops it if names are switched off |

The binding is two-way: the factory key vouches for the contribution key and the contribution key for the factory key, so no seat can claim another party's key of either kind. Both signatures travel to every signer in `round_propose`, so anyone can check them. The contribution key is the per-lobby BOLT 8 key, never the member's long-lived identity, so publishing the binding in evidence links nothing beyond this lobby (review 2, N17).

Valid when: the lobby is Open; both binding signatures verify; no other seat uses this factory key or this contribution key (`signing-round.md` section 2: a list with a key twice is refused); neither is the host's; seats taken are fewer than the target.

Host: creates the seat (saved before it answers, within the limits of "Seats and reconnects") and sends `lobby_status`. If invalid, it sends `lobby_status` with seat state 7 and a reason, and keeps the connection.

Duplicates: the same factory key for an existing seat changes nothing and is answered with `lobby_status`. A different factory key for an existing seat is refused (state 7). A member that wants a new factory key leaves and joins again.

### 6.4 `ready` (22), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `outer_digest` | 32 | Yes. Must equal `scope` |
| 4 | `current_version` | `u32` | Yes |
| 6 | `current_digest` | 32 | Yes |
| 8 | `check_id` | 32 | Only in answer to a `ready_check`, then required |
| 11 | `min_members` | `u16` | No. The member's own smallest acceptable number of members, host not counted |
| 240 | `sig` | 64 | Yes. Contribution key |

The member names both digests (owner decision 1): the outer rules it accepted and the exact values it is ready for. Its signature lets the host, and anyone the host shows it to, see what this seat agreed to.

`min_members` is odd: a host that ignores it loses nothing safety-wise, because the member's app checks the real member count at signing and refuses there. A slice 1 host honours it when it chooses the signers (`LOBBY.md`: "each member's own minimum is respected").

Valid when: the seat is Joined or Ready; `current_version` and `current_digest` are the host's latest (after a freeze, the frozen ones); the signature verifies.

Host:

| Case | Action |
|---|---|
| Names the latest values | Seat becomes Ready (saved). Answer `lobby_status` |
| Names an older version | A race with a new `terms_offer`. Seat stays or becomes Joined. Answer `lobby_status`, which carries the latest version |
| Carries a `check_id` that is the open check's | Recorded as this seat's answer to the check |
| Carries another `check_id` | Late or stale: treated as a `ready` without `check_id` |
| Duplicate | No change; answer `lobby_status` |

### 6.5 `unready` (24), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 1 | `reason` | `u16` | No. 1 conditions no longer met, 2 user's choice |

Valid while the seat exists and no round is under way for it. Host: seat becomes Joined; answer `lobby_status`. Duplicate: no change.

During a ready check, an `unready` withdraws the seat from that check. Once the member has received `round_propose`, `unready` is ignored; it uses `round_abort` instead.

### 6.6 `leave` (26), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 1 | `reason` | `u16` | No. 1 conditions, 2 user, 3 host fault seen |

Host: seat becomes Left (saved); answer `lobby_status`. A later `join` from the same key while the lobby is Open creates the seat again. Duplicate: no change.

A member in a round sends `round_abort` before `leave`. A member that has sent partial signatures may still leave the lobby screen, but its round stays as `signing-round.md` section 7 says: nothing moves it to Aborted.

### 6.7 `lobby_status` (28), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `lobby_state` | `u8` | Yes. Table above |
| 4 | `seat_state` | `u8` | Yes. Table above, for the receiving connection's key |
| 6 | `current_version` | `u32` | Yes. Latest, or frozen |
| 8 | `joined` | `u16` | Yes. Seats in Joined or Ready |
| 10 | `ready` | `u16` | Yes. Seats in Ready |
| 13 | `reason` | `u16` | No. Why a seat was refused or removed, or why the lobby ended (section 7.9's codes) |

Unsigned. It tells the member where it stands; nothing that touches money depends on it.

Sent: in answer to `hello`, `join`, `ready`, `unready`, `leave`; to every seat when a count or the lobby state changes, at most once per second per seat (counts change often in a busy lobby; one a second is enough for a screen).

Receiver: the newest wins. BOLT 8 keeps order inside a connection; after a reconnect the first status follows the new `hello`, so an older one cannot arrive later. A `current_version` higher than the member's accepted version makes the member send `hello` to fetch the terms.

Even though unsigned, it is kind 28 (even): a member that cannot read its seat state cannot take part.

### 6.8 `ready_check` (30), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `check_id` | 32 | Yes. Fresh random bytes from the host |
| 4 | `current_version` | `u32` | Yes |
| 6 | `current_digest` | 32 | Yes |
| 8 | `answer_within_ms` | `u32` | Yes. Must equal the terms' ready window |
| 240 | `sig` | 64 | Yes. Host's long-term key |

**This message freezes the current values** (`terms.md` section 8). The host saves the freeze before it sends the first `ready_check` of a lobby. Signed so the member holds the host's own statement of what was frozen.

Sent when the start rule is met: to every seat in Joined or Ready.

Member: if the version and digest are the latest it accepted (or its frozen ones) and its conditions hold, it saves the freeze and answers `ready` with `check_id`, within `answer_within_ms` on its own clock. If they are not the latest it accepted, it sends `hello` to fetch terms, then answers or not. If the lobby was already frozen at other values, that is a fault: keep the evidence, `leave`.

Duplicates: the same `check_id` again: answer again with the same saved `ready` bytes. A new `check_id` with the same frozen values: a new attempt; answer it. 32 random bytes so that an answer to an old check is never taken for an answer to a new one.

### 6.9 `start` (32), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `check_id` | 32 | Yes. The check this start follows |
| 4 | `role` | `u8` | Yes. 1 chosen to sign, 2 not chosen |
| 6 | `signers` | `u16` | Yes. Number of participants, host included |
| 240 | `sig` | 64 | Yes. Host's long-term key |

**Signed, saved and resent** (draft 2; review 3, F9). The host saves every `start` of a check (`journal.md` record `start_sent`) before sending the first, and resends a chosen seat's saved bytes after that seat's `hello` while the lobby is Signing. The member saves a received `start` (`start_received`) and keeps it with the check it answered. So a reconnect or a member restart between `start` and `round_propose` costs nothing. In addition, a member accepts a validly signed `round_propose` whose `check_id` it answered even without a `start`: the proposal is signed and carries everything (7.2).

Sent after the ready window closes, to every seat that answered the check. The host chooses the signers: every seat that answered, cut to the target in order of joining; then, **repeatedly, every chosen seat whose `min_members` exceeds the current number of chosen seats is dropped**, until no such seat remains (dropping seats can only lower the count, so this ends). If fewer than the minimum remain, the host sends no `start`; the lobby goes back to Open, or is cancelled if the deadline has passed.

Member with role 1: waits for `round_propose`, up to the terms' step timeout. Member with role 2: back to Ready; a later check may choose it. Duplicate: ignore.

### 6.10 `cancel` (34), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `reason` | `u16` | Yes. 1 deadline below the minimum, 2 host's choice, 3 signing failed within its time budget |
| 240 | `sig` | 64 | Yes. Host's long-term key |

Ends the lobby. Signed so that a member's history can show the host's own reason. The member saves the end, erases any secret nonces, and keeps every round identifier it saved (they stay refused). Duplicate: ignore.

A `cancel` does not undo partial signatures already sent. A member with an unresolved creation round keeps watching that round's funding outpoint, as section 7.9 says.

## 7. Signing round messages

These encode the messages of `signing-round.md` section 4 for slice 1's one purpose, **creation**, as a "creation, tree only" profile: one tier (index 0) holding the tree transactions and nothing else. Slice 1 has no channel engine, so the creation tier holds no channel states (`signing-round.md` section 15). Slice 1 signs no distribution transaction (record 44 below; **proposed, owner to confirm**).

General rules:

- Every round message carries `round_id`. A message whose `round_id` the receiver does not know is ignored, with the exceptions in 7.2 and 7.9.
- **Item indices are unique within a round**, across all tiers: 0, 1, 2 … in tier order. Nonces and partial signatures are always named by (round, tier, item).
- **A party never sends two different nonces, or two different partial signatures, for one (round, item).** Saved messages are resent byte for byte.
- **A member's state is kept per tier.** A member reaches Aborted only if it has sent no partial signature in the round; otherwise the round is Unfinished, with its exposure recorded. Slice 1 has one tier, so per-round and per-tier coincide, but the encoding carries `tier` everywhere so that later rounds need no new format.
- **After any partial signature has been released in an attempt, the next attempt uses a new funding outpoint** (the host builds a new, unbroadcast funding transaction that spends an input of the previous one). A member refuses a different tree on an outpoint for which it holds an exposure record (`safety-rule.md` C7): one whose tree digest (7.12) differs from the recorded one.
- **Every case is keyed on `round_id`** (`signing-round.md` rule S6), never on a message's bytes alone.

### 7.1 The round identifier

`round_id = TH("gazpacho/round_id", preimage)`, where the preimage is these fields in this order:

| Field | Size | From |
|---|---|---|
| `protocol` | 4 | `67 7a 66 01` ("protocol name and version") |
| `chain` | 32 | The outer terms' chain hash |
| `host_key` | 33 | The outer terms' host key |
| `outer_digest` | 32 | The lobby identifier |
| `terms_digest` | 32 | The frozen current-values digest (`terms.md` section 6). It already includes the outer digest; both are listed, as `signing-round.md` section 3 decides, at a cost of 32 bytes once |
| `funding` | 36 | `outpoint` |
| `funding_amount` | `u64` | Satoshis |
| `n_participants` | `u16` | 2 to 1,001 |
| `participants` | 33 each | Factory keys in tree order, host first |
| `contribution_keys` | 33 each | The participants' contribution keys, in the same order (draft 2; review 3, F10) |
| `purpose` | `u8` | 1 creation (2 leaf change, 3 layer update, 4 close, 5 rotation: later) |
| `n_tiers` | `u8` | 1 in slice 1 |
| `tier_sizes` | `u32` each | Number of items in each tier, in tier order |
| `n_items` | `u32` | Sum of `tier_sizes` |
| per item, in index order | | |
| — `index` | `u32` | 0, 1, 2 …, unique in the round |
| — `spent` | 36 | `outpoint` the item's input spends |
| — `sighash` | 32 | The BIP 341 signature digest the member computed itself |
| — `mode` | `u8` | 0 key path, 1 script path |
| — `mode_data` | 32 | Key path: the taproot tweak applied to the aggregate key. Script path: the tapleaf hash |
| — `n_signers` | `u16` | |
| — `signers` | `u16` each | Positions in `participants`, increasing |
| `host_random` | 32 | From `round_propose` |

Each party computes it from transactions it built itself. The proposal parameters of 7.2 are not listed separately: every one that can change the transactions' bytes does so through the signature digests, which are inside; those that change no byte (layer step and states under fixed levels) are fixed in Slice 1. Signers are named by position, which is equivalent to listing keys because the participant list is inside the hash, and is 31 bytes shorter per signer. The fields of 7.2 outside the identifier (`check_id`, `attempt`, `terms_version`, the deadlines, the bindings) can differ between two copies of one proposal; rule S6 treats such copies as the same proposal and keeps the second as evidence.

A useful property, kept from draft 2 (review 2, "What draft 2 gets right"): a member whose tree differs from another signer's computes a different identifier, so the other signers' nonce signatures fail against its identifier at step 5, before any partial signature.

Vectors: **(open)** until the tree builder runs in the signing engine; a round identifier vector needs real items.

### 7.2 `round_propose` (64), host → member

The proposal carries every parameter the member rebuilds the tree from, as `signing-round.md` section 4.1 lists them; record numbers are kept stable so that rows can be added as new even types. A field whose value section 4.1 fixes, or `terms.md` section 4.2 derives from the terms, must have exactly that value; otherwise the member refuses with reason 9.

| Type | Field | Size | Required | Member's check |
|---|---|---|---|---|
| 2 | `round_id` | 32 | Yes | Equals its own computation |
| 4 | `check_id` | 32 | Yes | A check it answered, for which it holds no saved `start` with role 2 (6.9) |
| 6 | `purpose` | `u8` | Yes | 1 |
| 7 | `attempt` | `u16` | No | Display only |
| 8 | `terms_version` | `u32` | Yes | Its frozen version |
| 10 | `terms_digest` | 32 | Yes | Its frozen current digest, the one named in its own `ready` (N11's check C8a) |
| 12 | `funding` | 36 | Yes | Its txid equals the txid of `funding_tx`; no exposure record for this outpoint with another tree (C7, N6) |
| 14 | `funding_amount` | `u64` | Yes | Equals that output's amount in `funding_tx`, and the terms' funding rule R(root) for this tree (`terms.md` section 4.2) |
| 16 | `funding_script` | 34 | Yes | `OP_1 0x20 <32 bytes>`: the BIP 86 key of the MuSig2 aggregate of the participant keys in order. The imported `factory_set_funding` takes it on trust, so the member checks it |
| 18 | `funding_tx` | 60 to 100,000 | Yes | The host's unsigned funding transaction, no witnesses. It fixes the txid before signing and lets the member see its inputs spent elsewhere (N16). 100,000 bytes: a standard transaction is at most 400,000 weight units, and a witness-free transaction weighs 4 units per byte |
| 20 | `participants` | 194 each, 2 to 1,001 | Yes | Per participant: factory key (33), contribution key (33), `bind_by_factory` (64), `bind_by_contribution` (64). Host first. Every key distinct; its own entry present exactly once; both bindings verify (6.3) |
| 22 | `tier_sizes` | `u32` each, 1 to 8 | Yes | Equals its own rebuild |
| 24 | `end_height` | `u32` | Yes | The tree's absolute end height (the import's `cltv_timeout`, from which every host-only timeout is derived). Within 6 blocks of its own tip + `lifetime_blocks` + `winddown_blocks` from the terms. 6 blocks (about an hour) allows for chain views a little apart. C8: the leaf's timeout leaves the exit time plus margin |
| 28 | `tree_anchors` | `u8` | Yes | **1**: anchors are always on in 1.0.0 (`signing-round.md` 4.1, owner decision 6) |
| 30 | `fee_per_tx_sat` | `u64` | Yes | Exactly ⌈`tree_feerate` × V / 1000⌉, V the largest signed virtual size of any tree transaction (`terms.md` section 4.2); at most its own ceiling |
| 32 | `lstock_delay` | `u32` | Yes | The spare-liquidity delay, in blocks. Inside its conditions |
| 34 | `lstock_hashes` | 36 each, 0 to 4,096 | Yes | Per tree node: node index (`u32`), the host's spare-liquidity hash (32). Each hash used once (C8). A tree in which any node with index 512 or more carries a hash is refused, because the import ignores the hash there (`safety-rule.md` C8, same wording). **Slice 1: empty** (no penalties) |
| 36 | `fixed_levels` | `u8` | Yes | The import's `static_threshold_depth`: tree depths 0 to `fixed_levels` − 1 are fixed (kickoff-only, no relative timelock; they keep the host-only absolute timeout). Must equal **D**, the depth of the deepest leaf by `terms.md` section 4.2's split rule, so that every interior node is fixed (1.0.0) |
| 38 | `k` | `u8` | Yes | Members per sub-factory. 1 (owner decision 5) |
| 40 | `layer_step` | `u16` | Yes | Blocks per state step of a timed layer. Slice 1: **144** (changes no byte while every level is fixed; fixed so that one tree has one encoding) |
| 42 | `layer_states` | `u16` | Yes | States per timed layer. Slice 1: **4**, as above |
| 44 | `distribution` | | No | The funding-level distribution transaction: lock time (`u32`), then outputs, each amount (`u64`), script length (`u8`, at most 34), script. **Not in Slice 1** (**proposed, owner to confirm**): a Slice 1 member refuses a proposal that carries it. Even: a member that does not understand it refuses |
| 46 | `host_random` | 32 | Yes | Fresh per attempt |
| 48 | `nonces_due_ms` | `u32` | Yes | At most the terms' step timeout |
| 50 | `sigs_due_ms` | `u32` | Yes | At most the terms' step timeout |
| 240 | `sig` | 64 | Yes | Host's long-term key |

Record 26 (`placement` in draft 1) is not used: placement is fixed by `signing-round.md` section 4.1 at the import's `PLACEMENT_SEQUENTIAL` (value 0) and written by the engine; it is never sent (review 3, F5). A proposal carrying record 26 is refused as an unknown even record.

The tree's shape is not repeated: the member takes the shape table's entry for the number of members from the outer rules (`terms.md` section 4). The split of each leaf between channel and spare liquidity is fixed by the import (half each) and is checked by rebuilding. After building, the member checks that every leaf is a one-member pseudo-Spilman leaf (`safety-rule.md` C8).

Size: 194 bytes × 1,001 participants is 194,194 bytes; with 2,000 node hashes (72,000 bytes) and a large funding transaction the proposal stays under 400 KB, inside the 1 MiB bound of section 5. A proposal is a single envelope up to roughly 300 participants.

Member, in this order: verify the host's signature; look up `round_id` (the table below, first row that applies); verify everything above; compute `round_id`; run the safe-to-sign checks; **save the round identifier with the proposal's bytes** (`journal.md`); then generate nonces and send `round_nonces`. If `round_id` differs: `round_abort` reason 2, nothing saved that allows a contribution. If a check fails: reason 1, 9, 11 or 12.

Every row is keyed on `round_id` (`signing-round.md` rule S6). "Saved" means the member holds a `round_started` record for it.

| Case | Action |
|---|---|
| A saved `round_id`, **whatever the other bytes**, member in Nonces sent | Resend the same `round_nonces` bytes it holds in memory. If the proposal's bytes differ from the saved ones, keep the new copy as evidence; never a new nonce |
| A saved `round_id`, holding no secret nonces and having sent no partial signature (it restarted) | `round_abort` reason 3. Never contribute again to that identifier |
| A saved `round_id` the member has sent partial signatures for | Resend the saved `round_partial_sigs` bytes; state stays Unfinished |
| A saved `round_id` in any other state (Complete, Awaiting funding, Abandoned, Dead, Aborted) | Answer as the state requires (resend the saved ack, or `round_abort` with the recorded reason); nothing new |
| A new `round_id` whose participant list lacks, exactly once, the member's **current** key for this lobby (factory and contribution key), or for a lobby where it has no current-epoch seat | `round_abort` reason 12. This is how a replayed proposal after a restore is refused (`safety-rule.md` C7, R4) |
| A new `round_id` touching an output in an unresolved round (C10: for creation, the same funding outpoint or tree) | `round_abort` reason 6 |
| A new `round_id` on a funding outpoint with an exposure record and another tree digest | `round_abort` reason 11 (C7) |
| A new `round_id` whose `check_id` the member never answered | Ignore |

### 7.3 `round_nonces` (66), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `tier` | `u8` | Yes |
| 6 | `nonces` | 134 each, 1 to 256 | Yes. Per item: `index` (`u32`), public nonce (66, BIP 327 form), `nonce_sig` (64) |

`nonce_sig` is by the member's contribution key over

```
TH("gazpacho/nonce", round_id || u8 tier || u32 index || public nonce)
```

The tier is inside (`signing-round.md` section 4). It is the signature the host forwards and the evidence of `signing-round.md` section 9. Because indices are unique in the round, two different nonces under one (round, index) are always equivocation, never an honest tier 2. The message has no signature record: each entry is signed, and the connection is authenticated.

The entries are exactly the member's items in the tier (those whose signers include it), in increasing index. 256 is far above the 17 to 20 items a member signs at 512 members and leaves room for the eight-level limit of the imported code plus channel and payout items later.

Host: checks the round, the tier, the item set, each nonce's form (parsed before it reaches the signature library, `signing-round.md` section 12) and each `nonce_sig`. Fills one slot per (member, item); a filled slot is never filled again.

| Case | Action |
|---|---|
| Duplicate, same bytes | Ignore |
| A different nonce for a filled slot, both validly signed | Proof that the member signed two nonces. Remove it from the attempt; keep the evidence |
| After `round_all_nonces` went out | Ignore |
| Invalid | Remove the member from the attempt; `round_abort` reason 5 to it |

### 7.4 `round_all_nonces` (68), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `tier` | `u8` | Yes |
| 6 | `items` | blocks, 1 to 256 | Yes. Per item: `index` (`u32`), `n_signers` (`u16`), then per signer in the item's signer order: public nonce (66) and `nonce_sig` (64) |

No signature record: what it carries is signed by each nonce's owner. The host's own nonces are signed by its long-term key in the same way. So a member that receives a malformed set cannot show a third party that the host sent it (review 2, N15); it can only refuse.

Sent when every chosen signer's nonces for the tier have arrived. If someone failed, the host sends `round_abort` reason 4 to everyone and starts a new attempt without them. No partial signature has been released yet, so the new attempt may reuse the funding outpoint (N6 applies only after partial signatures).

Member: checks that the blocks cover exactly its items; that `n_signers` and the order match its own rebuild; that every `nonce_sig` verifies under the signer's contribution key; and that its own nonces are present and unchanged. Then it runs the checks again, **saves the exposure record (C7) together with the `round_partial_sigs` bytes, as one batch**, and sends them only when that batch is confirmed (`journal.md`). This is the record N6 asks for: made durably before the first partial signature for that funding outpoint.

| Case | Action |
|---|---|
| The member is in Nonces sent | Proceed as above |
| A second copy with the same bytes | Resend the saved `round_partial_sigs` bytes |
| A second copy with different bytes | Rejected (`signing-round.md` section 4). Keep it; stay in the current state |
| A nonce of the member's own changed, or a signature fails | `round_abort` reason 5; erase secret nonces; Aborted (no partial signature was sent) |
| Before the member sent its nonces | Ignore |

### 7.5 `round_partial_sigs` (70), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `tier` | `u8` | Yes |
| 6 | `partials` | 68 each, 1 to 256 | Yes. Per item: `index` (`u32`), partial signature (32), `nonce_set_digest` (32) |
| 240 | `sig` | 64 | Yes. Contribution key |

`nonce_set_digest = TH("gazpacho/nonceset", every signer's public nonce for the item, in signer order, 66 bytes each)` (`signing-round.md` section 4).

Host: verifies each partial signature as it arrives (`musig_verify_partial_sig`, H2). It tracks one slot per (member, item), because the import's partial-signature counter double-counts as its nonce counter does (review 2, N13.1).

| Case | Action |
|---|---|
| Duplicate, same bytes | Ignore |
| Different bytes for the same round and tier | Keep the first valid one; keep the other as evidence |
| Invalid | Remove the member; new attempt **on a new funding outpoint** (others have released partial signatures) |

### 7.6 `round_tier_result` (72), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `tier` | `u8` | Yes |
| 6 | `finals` | 68 each, 1 to 256 | Yes. Per member item: `index` (`u32`), final signature (64) |
| 7 | `all_partials` | | No. Every signer's partial signatures for the last tier of a layer update (`signing-round.md` section 5). **Not in slice 1**; encoding **(open)** |
| 240 | `sig` | 64 | Yes. Host's long-term key |

The host saves these bytes for each member and keeps them until the factory's funding output is spent or the creation is Dead (`safety-rule.md` H12), so it can answer `round_status_request`.

Member: checks each final signature against the transaction it built, from the transaction's bytes (the import does not verify, review 2 N13.8); saves the signed items. Duplicate, same bytes: ignore. Different and valid: impossible for the same nonces and message, so it is a fault; keep the evidence. Invalid: record the host's fault; the round stays Unfinished. For creation nothing is at stake until the funding is buried (C11).

### 7.7 `round_complete` (74), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 3 | `payouts` | | No. **Not in slice 1** |
| 5 | `penalties` | | No. **Not in slice 1** |
| 240 | `sig` | 64 | Yes. Host's long-term key |

For a one-tier creation round without channels, the final signatures in `round_tier_result` are everything the member's exit relies on, so `round_complete` closes the round and asks for the acknowledgement. `payouts` and `penalties` are odd only because slice 1 never sends them; when defined they must become even types, since a member must not ignore them **(open)**. Review 2 (N16) suggests carrying the unsigned funding transaction here; this draft carries it in `round_propose` instead, so the member checks the txid before it contributes.

Valid only after a valid `round_tier_result` for every tier. Saved by the host with the tier results. Member: saves Complete, then sends `round_ack`. Duplicate: resend the saved ack.

### 7.8 `round_ack` (76), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `held_digest` | 32 | Yes. `TH("gazpacho/held", for each of the member's items in index order: u32 index || final signature)` |
| 240 | `sig` | 64 | Yes. Contribution key |

Sent after the member has verified and stored `round_complete` and every tier result (`signing-round.md` section 6, step 9). It is the host's trigger to fund last: `safety-rule.md` H1 lets the host fund only after every member has acknowledged holding the result. Signed, and naming what the member holds, so the host can show that each member held its signed path before the funding was signed.

Host: checks `held_digest` against the finals it sent that member; records the ack (saved). When every chosen member has acked, it signs and broadcasts the funding transaction from `round_propose`, unchanged. Duplicate: ignore. A digest that does not match: the member holds something else; resend the saved results and wait.

### 7.9 `round_abort` (78), either way

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |
| 4 | `reason` | `u16` | Yes |
| 5 | `evidence` | | No. **Not in slice 1**; encoding **(open)**. Ignored if received |
| 7 | `detail` | 1 to 256 bytes ASCII | No. For logs only; never shown as fact |
| 9 | `tier` | `u8` | No. The tier the abort concerns, if not the whole round (`signing-round.md` section 4). **Not sent in Slice 1**, which aborts whole rounds only |
| 11 | `items` | `u32` each, 1 to 256 | No. The item indices it concerns, with `tier`. Not sent in Slice 1. Odd: a receiver that ignores them treats the abort as one for the whole round, which is the safe reading for the sender's own items |
| 240 | `sig` | 64 | Yes. Sender's contribution or long-term key |

Reasons:

| Code | Meaning |
|---|---|
| 1 | The safe-to-sign checks failed |
| 2 | The rebuilt round identifier differs from the host's |
| 3 | Restarted: this identifier was saved and its nonces are gone |
| 4 | A deadline passed |
| 5 | An invalid message (signature, nonce, partial signature) |
| 6 | Another round touches the same output |
| 7 | The member was removed from this attempt |
| 8 | The lobby was cancelled |
| 9 | The tree does not meet the member's conditions |
| 10 | Too few signers remain |
| 11 | The funding outpoint already carries another tree this party signed for (another tree digest, `safety-rule.md` C7) |
| 12 | The participant list lacks this member's current key for this lobby (`safety-rule.md` C7, "Fresh funding output"); among other cases, a proposal replayed to a restored member |

An unknown code is read as "other". Codes are listed, not open-ended, so that a history can count them. Sent to a `round_id` the receiver does not know, a `round_abort` is ignored.

| Member's state | On a host's `round_abort` |
|---|---|
| No partial signature sent in this round | Erase secret nonces; Aborted; the identifier stays refused |
| A partial signature sent | Record it, change nothing: Unfinished (`signing-round.md` section 7). For creation the member keeps watching the funding txid and every input outpoint of `funding_tx` (`signing-round.md` section 12.1). If one of those inputs is spent by another buried transaction, the funding can never exist and the round is **Dead**; if the unfinished deadline passes first, it is **Abandoned** |

The host, on a member's `round_abort`: removes the member from the attempt and runs a new attempt within the signing budget, on a new funding outpoint if any partial signature was released. Duplicates: ignore.

### 7.10 `round_status_request` (80), member → host

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `round_id` | 32 | Yes |

Sent by a member whose round is Unfinished or Complete-but-unfunded, after every reconnect, after `hello` and after resending any saved `round_partial_sigs` (section 6, "Seats and reconnects"). The host answers with the saved bytes it holds for that member and round: every `round_tier_result`, then `round_complete`. If the round failed, it answers `round_abort` with the reason. If it knows no such round, it ignores the request. Unsigned: it asks for nothing new. At most one answer per round per 10 seconds per connection; a member needs one.

### 7.11 `factory_funded` (81), host → member

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `funding_txid` | 32 | Yes. Must equal the round's funding txid |

Odd and unsigned: a hint that the host has broadcast. The member never relies on it. It learns that the funding confirmed from its own chain view (C11), watching the exact output, amount and script of its held tree. Duplicate: ignore.

### 7.12 The tree digest

C7's record names a tree by this digest (`safety-rule.md` C7; `journal.md` record `exposure`). Two trees are the same if and only if their digests are equal.

`tree_digest = TH("gazpacho/tree", preimage)`, where the preimage is these fields of 7.1, in 7.1's order and encoding: `chain`, `funding`, `funding_amount`, `n_participants`, `participants` (factory keys), `n_items`, and for every item `index`, `spent`, `sighash`, `mode`, `mode_data`, `n_signers`, `signers`.

Left out on purpose: the protocol tag, the host key, both terms digests, the contribution keys, the purpose, the tier structure and `host_random`. None of them changes a transaction; `host_random` changes with every attempt, so the round identifier cannot serve as C7's name for a tree. The sighashes commit to every amount, script, output, lock time and sequence (BIP 341), so equal digests mean equal transactions with equal signer sets and modes.

Vectors: **(open)**, like 7.1's, until the tree builder runs in the engine.

## 8. Duplicates and order, in one table

| Message | Duplicate (same bytes) | Out of order |
|---|---|---|
| `hello` | Answered, rate-limited | Not possible: always first |
| `terms_offer` | Ignore | Older version ignored; same version with other bytes is a fault |
| `join` | Answered with status | Before the terms are known: the member cannot form the binding; host refuses an unknown scope |
| `ready` | Answered with status | Names an older version: seat Joined |
| `unready`, `leave` | No change | Applied whenever the seat exists |
| `lobby_status` | Newest wins | Not possible within a connection |
| `ready_check` | Same saved `ready` bytes resent | A new `check_id` is a new attempt |
| `start` | Ignore (already saved) | Unknown `check_id`: ignore. Resent by the host after `hello` while Signing |
| `cancel` | Ignore | Always applies |
| `round_propose` | Keyed on `round_id`, whatever the other bytes: resend nonces from memory; after a restart abort reason 3, or resend saved partial signatures if any were sent; a differing copy is kept as evidence | For a check the member never answered: ignore. Without `start` but for an answered check: accepted (6.9) |
| `round_nonces` | Ignore | After distribution: ignore |
| `round_all_nonces` | Resend saved partial signatures | Before nonces were sent: ignore; different bytes: evidence |
| `round_partial_sigs` | Ignore | Keep the first valid |
| `round_tier_result` | Ignore | Before partial signatures were sent: ignore |
| `round_complete` | Resend the ack | Before the tier result: ignore |
| `round_ack` | Ignore | Before `round_complete`: ignore; a wrong `held_digest`: results resent |
| `round_status_request` | Answered, rate-limited | Answered with whatever saved results exist |
| `round_abort` | Ignore | See 7.9 |
| `factory_funded` | Ignore | Hint only |

## 9. Not needed in slice 1

- Kinds: none of the above is unused, but `part` flows host → member only, and `factory_funded` is optional.
- Records: `display_name` (6.3); `evidence` (7.9); `all_partials` (7.6); `payouts` and `penalties` (7.7); `distribution` (7.2) unless the owner decides the creation round signs it.
- Parameters that are fixed at one value in slice 1 but still carried, so the format does not change later: `k` = 1, `tree_anchors` = 1, `lstock_hashes` empty, `layer_step` = 144 and `layer_states` = 4 (no byte depends on them while every level is fixed). Placement is not carried at all (7.2).
- Purposes other than creation; tiers other than 0.
- Invitations, identities, chat, rule-change requests, standby seats, carry-over: no messages yet.
- Peer storage (`peer_storage`, `peer_storage_retrieval`) for member backups: standard BOLT messages, not factory messages, and not in slice 1.

## 10. bLIP-56 adapter (not used in slice 1)

Sections 3 and 4 are the specification: factory messages travel in Lightning message type 52791, with the 38-byte header. This section defines a second **carrier** for exactly the same messages, for peers that speak the pluggable channel factories proposal, bLIP-56 (open pull request lightning/blips#56 by ZmnSCPxj, one commit, December 2024; read in full on 2026-11-12). Slice 1 never uses it: a slice 1 node does not set bit 271 and never sends a `supported_factory_protocols` message, so the condition below is never met.

### 10.1 When the adapter is used

On one connection, the adapter is used **if and only if** all of these hold:

1. both sides set feature bit 271 (`pluggable_channel_factories`) in `init`, or the peer sets the compulsory bit 270;
2. both sides have sent `supported_factory_protocols` (submessage 2, TLV 512), as bLIP-56 requires after `init`;
3. each side's list contains our `factory_protocol_id` (10.3).

Otherwise type 52791 is used. A sender sends nothing in either carrier before it knows which applies: on a connection where both set bit 271, that means waiting for the peer's `supported_factory_protocols`.

| Peer | Carrier |
|---|---|
| Sets neither 270 nor 271 | Native, type 52791 |
| Sets 271, and lists our id | Adapter |
| Sets 271, but its list lacks our id (or is empty) | **Native, type 52791.** The peer speaks bLIP-56 for other factory protocols, or none; bLIP-56 forbids sending it a piggyback with our id. If the peer does not speak Gazpacho's messages either, it ignores 52791 (odd), and the member's `hello` times out with "host does not speak this factory protocol" |
| Sets 270 (compulsory) and lists our id | Adapter |

A receiver accepts a message in either carrier on any connection where that carrier is valid under bLIP-56 or BOLT 1 (a `factory_piggyback` only where it advertised our id). Both carriers yield the same bytes, so accepting both costs nothing and avoids a failure during an upgrade.

### 10.2 The mapping

A native message is `type (52791) || tag (67 7a 66 01) || kind || scope || records`. Its **inner bytes** are `kind || scope || records`.

| Direction | Rule |
|---|---|
| Native → adapter | Drop the type and the 4-byte tag. Send a Lightning message of type 32800, `factory_submessage_id` 4 (`factory_piggyback`), and the TLV stream: TLV 0 = `factory_protocol_id` (32 bytes), TLV 1024 = the inner bytes |
| Adapter → native | Check TLV 0 equals our `factory_protocol_id` and TLV 1024 is present (bLIP-56: otherwise `warning` and close). Prepend the tag `67 7a 66 01` to TLV 1024's value. The result is the native envelope, read by sections 4 to 7 unchanged |

`factory_protocol_id` and the tag stand for the same thing, the protocol and its major version, so the mapping is one to one. A future tag `67 7a 66 02` would map to the id of "SuperScalar/2".

**Signatures do not change.** Every signature in this document (section 4.3's `msg_hash`, the binding, nonce signatures, the round identifier of 7.1, the terms digests) is computed over the **native** form, with the 4-byte tag, whichever carrier delivered the message. The adapter only re-wraps bytes; it never signs, and a receiver always rebuilds the native form before it checks anything. Vector M3 (section 11) is vector M1 through the adapter, with the same signature.

Saved bytes (`journal.md`) are always the native envelope. The carrier is chosen when sending, per connection, so a message saved on one connection can be resent byte for byte on a later connection in the other carrier.

### 10.3 Our `factory_protocol_id`: decided (owner, 2026-11-12)

```
factory_protocol_id = SHA256("SuperScalar/1")
                    = c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1
```

- bLIP-56 recommends "the SHA-256 of the concatenation of the channel factory protocol name and major version".
- The name proposed is **SuperScalar**, not Gazpacho: this document is meant to be offered to the SuperScalar repository as the shared format (`DESIGN.md` section 8), and a factory protocol named for the factory lets every program that speaks the format interoperate.
- Major version **1**, matching the tag's last byte.
- The `/` separator is our choice; bLIP-56 says only "concatenation", and a separator keeps "Name1" + "2" apart from "Name" + "12".
- **Decided (owner, 2026-11-12; `docs/ux/decisions.md` decision 8):** the shared protocol identifier is SHA-256 of the UTF-8 bytes "SuperScalar/1", the value above. superscalar-cln currently uses a different value and will be updated. It interoperates only if the reference also uses this payload format; today it speaks its own private format of about 100 message types. The tag rename and the switch of signed preimages to the 32-byte id (4.3) remain a separate change, done together, with new vectors.

### 10.4 Sizes inside the piggyback

The adapter costs 44 bytes around the inner bytes: type (2), submessage id (2), TLV 0 (1 + 1 + 32), and TLV 1024's header (3 bytes of BigSize type `fd 04 00`, 3 bytes of BigSize length for 253 bytes or more). So:

| | Native (type 52791) | Adapter (bLIP-56) |
|---|---|---|
| Overhead before `kind` | 6 bytes (type, tag) | 44 bytes |
| Largest `records` in one message | 65,495 bytes | **65,457 bytes** (65,535 − 44 − 34) |
| Free for `data` in one `part` | 65,439 bytes | 65,401 bytes |

`part`'s 65,000-byte data size (section 5) fits both, so a part's bytes are the same in either carrier. Only the threshold differs: through the adapter, a message whose records are between 65,458 and 65,495 bytes is split into parts, where natively it would travel whole. Since a split message is put back together before anything is checked, this changes nothing above section 5.

### 10.5 Relation to bLIP-56

**Taken as written, for the adapter:** message type 32800 (`factory_message_id`); the `u16` submessage id with "it's okay to be odd"; submessages 2 (`supported_factory_protocols`, TLV 512) and 4 (`factory_piggyback`, TLV 0 and TLV 1024) with their requirements; feature bit 271; the rule for forming the protocol id.

**Not used in slice 1:** the adapter itself; the `open_channel` TLV `channel_in_factory` (65600: protocol id, `factory_instance_id`, `factory_early_warning_time`) and its changes to `funding_created`, `channel_ready` and `update_add_htlc`; the factory change flow (submessages 6 `factory_change_init`, 8 `factory_change_ack`, 10 `factory_change_funding`, 12 `factory_change_continue`, 14 `factory_change_locked`, and the batched `commitment_signed` around them); the early-warning time.

**From slice 2,** the channel engine may use `channel_in_factory` to open each member's channel on its leaf, and the change flow for every change that moves a channel's funding outpoint, which a layer update does for every channel below it (`safety-rule.md` section 4). The multiparty round that produces the new tree stays a factory message, as bLIP-56 intends ("the plugin MAY use `factory_piggyback` messages to exchange the necessary cryptographic data"). What `factory_instance_id` is for Gazpacho (the lobby identifier, or a digest of the funding outpoint) is decided then **(open)**.

**Gaps, for later amendment proposals** (nothing is to be posted; the owner decides):

1. **Taproot channel nonces.** The change flow reuses splicing's `commitment_signed` with `batch`, one signature per funding outpoint. Lightning's taproot channel format, which Gazpacho uses, signs commitments with MuSig2 and needs nonces per commitment and per outpoint. bLIP-56 predates that format and does not say how nonces for post-change outpoints are exchanged (around `factory_change_funding`, and on `channel_reestablish`). Review 2's N9 is the same problem from the round's side.
2. **Factory creation and multiparty rounds** are not covered; bLIP-56 handles two-party channels inside a factory and leaves everything multiparty to the plugin payload. That is by design, and it is why sections 4 to 7 exist; it also means two implementations of "SuperScalar/1" agree only if they share this payload format.
3. **The even message type.** 32800 is even, so a node that does not know it closes the connection (BOLT 1), and it may only be sent after the feature bit is negotiated. Our native type is odd so that it can be sent to anyone and ignored by those who do not understand it. The adapter therefore depends on the negotiation of 10.1; the native carrier does not.
4. **The "forget a channel" instruction.** bLIP-56 lets the plugin tell the node to forget a channel at any time, after which the node "MUST treat the forgotten channel as successfully closed with deep confirmation" and should erase its revocation data. For Gazpacho that is safe only when every anchor of that channel is dead in the sense of `safety-rule.md` C4(d). The channel engine must never issue it otherwise, and the amendment should say that the plugin carries this duty.
5. **Numbers reserved only in the open pull request.** 32800, bits 270/271 and TLV 65600 appear in the pull request's change to bLIP 2, not in the merged registry (read on 2026-11-11). They may change before merging **(open)**.
6. Smaller: a second `supported_factory_protocols` on one connection is unspecified (this document reads it as replacing the first); the relation of `factory_early_warning_time` to a factory's exit time is not stated.

## 11. Test vectors

Computed by `tools/spec-vectors.py`. **All keys are test keys** derived from public strings (`terms.md` section 11). Never use them for coins. M1 and M3 changed after review 3, because they depend on T1's digest; M0 and M2 did not.

**M1. A `ready` for the lobby of vector T1 at the values of T2, without a ready check.** Member 1's contribution key `024322bd904fa9770421b0b48f08e961d473f3ee9a36a5bc85fa3cac30fa2e15ae`, factory key `0223a26c411e719d542783e3bb05fa00a467fb73227d495ab89734fef0ecec3974`, auxiliary randomness 32 zero bytes.

```
binding               = 47cc4207f628d147d528abc4dfab2c393e208dfcfa550789540bddd09259007e
bind_by_factory       = 64c9b7016f2484c6d4e162a02e701bc3cad8f7741a2ab2f07a2ad32fac0d0932
                        bb7e4286df722cbe5147a72425fe9a58fd4afe37357f843ee6d0eb1aa9946cea
bind_by_contribution  = 20e17a88512a7899a72ecfa56bc456a12a71012cc2a1f2b5b77bc2c4143b3eb8
                        676168a973998b2fdb71d2d8284b9a9e0adf8f2927815ae965398cf4c8184813
msg_hash              = 683a9673360b942f37224c92dfeb58765fc9085e14bae4c6120b46c5be42f8d0
Lightning message, 180 bytes (type, protocol, kind, scope, records 2, 4, 6, 240):
ce37 677a6601 0016 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
0220 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
0404 00000001
0620 d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942
f040 7eb07e7116d893db0aa57ca3c88fd1b7c67aeb5a0772923c08a4f10350197cbc
     08c19ce8d566df618ab0df88d9773f5089c63b83d4fc99636a5ba7f433762627
```

**M2. Splitting.** A body of 76,800 bytes (the bytes 0 to 255 repeated 300 times) of kind 68 becomes 2 parts: 65,000 and 11,800 bytes of data, Lightning messages of 65,096 and 11,896 bytes. `transfer_id = fcb2c91358d5559e25feace2ed8a1562324ec95032f4c514435b5bd2f152a668`.

**M3. M1 through the bLIP-56 adapter** (section 10). Same signature as M1; 216 bytes:

```
8020 0004                    type 32800, factory_piggyback
00 20 c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1
                             TLV 0: factory_protocol_id = SHA256("SuperScalar/1")
fd0400 ae                    TLV 1024, length 174: M1 without its type and tag
  0016 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
  0220 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
  0404 00000001
  0620 d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942
  f040 7eb07e7116d893db0aa57ca3c88fd1b7c67aeb5a0772923c08a4f10350197cbc
       08c19ce8d566df618ab0df88d9773f5089c63b83d4fc99636a5ba7f433762627
```

M2's two parts are 65,134 and 11,934 bytes through the adapter. `supported_factory_protocols` naming only our id is 40 bytes: `8020 0002 fd0200 20 c3a082d0…61c842f1`.

## 12. Tests

Decoders are generated from the tables in this document (`DESIGN.md` section 8), and every decoder is fuzzed.

**Encoding**
1. Every vector in section 11 encodes and decodes to the same bytes.
2. Round trip of every kind with every optional record present and absent.
3. Non-minimal BigSize type or length; types repeated or decreasing; length past the end; empty stream where records are required: each refused.
4. Unknown even record in each kind: refused. Unknown odd record: skipped, and covered by the signature (a changed odd record fails the signature).
5. A record after 240: refused. Record 240 missing from a signed kind: refused.
6. Each fixed-size field one byte short and one byte long; a list one byte off a whole entry; a list above its bound.
7. Unknown even kind: refused. Unknown odd kind: ignored and the connection kept. Wrong `protocol`: ignored with one warning. A kind in the wrong direction: refused (a discovery kind 128 to 159: ignored, connection kept).
8. A message of exactly 65,535 bytes is accepted; the sender never builds one larger.

**Splitting**
9. Parts in order, reverse order and random order reassemble. A message just under the limit is not split; one byte over is split into 2.
10. `count` inconsistent with `total_len`; `index` ≥ `count`; a short middle part; a long last part; `total_len` above 1 MiB; `inner_kind` 2: each refused.
11. The same part twice: ignored. The same index with different data: refused. A wrong `transfer_id` at completion: refused.
12. A new transfer while one is open: the old one dropped. A connection dropped mid-transfer: nothing kept; the resent whole message is accepted.
13. A host receiving a `part` from a member: refused.
14. Memory: a peer that opens a transfer and never finishes holds at most 1 MiB, released on disconnect.

**Lobby, honest**
15. One host, three members: hello, terms, join, ready, ready check, start, round, funded, active. Twice in a row from a clean start.
16. The host moves the joining fee inside its range; a member whose limit covers the whole range stays ready; a "fits only now" member is unreadied when the value leaves its limit.
17. A member restarts in every lobby state and reconnects with the same derived key: it finds its seat, and receiving every lobby message again changes nothing.

**Lobby, hostile**
18. Terms signed by a key other than the pinned one; scope not equal to the outer digest; chain not signet; current value outside its range: each refused, nothing saved.
19. Two different current records with the same version: the member leaves with both as evidence.
20. A new version after the first ready check: the member leaves with evidence.
21. `ready_check` with values other than the latest accepted: the member fetches terms and does not answer with the unchecked values.
22. A join with another seat's factory key, the host's factory key, or a bad binding: refused.
23. A `ready` naming an old version during a version change: seat stays Joined; never counted ready for the new version.
24. A stale `check_id`: not counted in the current check.
25. `hello` flood: answered at most once a second; closed after 20 ignored.
26. A `start` that names a check the member did not answer: ignored.

**Round, honest and hostile**
27. Every message of section 7 dropped, delayed, duplicated and reordered at each step (`signing-round.md` section 16, test 2).
28. Host's `round_id` differs from the member's rebuild: member sends reason 2 and saves nothing that lets it contribute.
29. A proposal whose frozen digest differs from the member's: refused before saving.
30. Duplicate participant keys; a participant without a valid binding; the member's key missing or twice: refused.
31. A second `round_all_nonces` with one nonce changed: rejected, kept as evidence. The member's own nonce changed: abort reason 5.
32. A member sends two validly signed different nonces for one item: the host removes it and the evidence verifies with a separate checker.
33. A bad partial signature: the host names that member; the evidence verifies; an honest member cannot be framed.
34. `round_abort` sent to a member after it sent partial signatures: no state change.
35. A host that never sends `round_complete`, or never funds: the member loses nothing and stays watching; at the unfinished or funding deadline the round is Abandoned; when an input of `funding_tx` is spent elsewhere and buried, the round is Dead. Neither blocks the next attempt (C10).
36. The host funds before every ack: caught by the simulator's H1 invariant. An ack with a wrong `held_digest`: the host does not count it.
37. Each proposal parameter of 7.2 changed in turn on one member's copy (end height, anchors, fee, delay, one node hash, fixed levels, K, layer step and states, funding amount, funding script, funding transaction): the member's identifier differs, or its check refuses, before any partial signature. A proposal carrying record 26: refused.
38. A funding script that is not the BIP 86 key of the ordered aggregate, with everything else consistent: refused.
39. A tree in which a node with index 512 or more carries a spare-liquidity hash: refused while the imported hash limit stands. A Slice 1 proposal with any hash: refused.
40. Two nonces for items with the same index in different tiers cannot occur: indices are unique in a round, and the tier is inside the signed nonce hash. A test builds a two-tier round and checks that no two signed nonce hashes of one member coincide.
41. A failure in the partial-signature step, then a retry: the host uses a new funding outpoint; a retry on the old outpoint with another tree is refused with reason 11 (review 2, N6).
42. A member whose round is Unfinished reconnects and sends `round_status_request`: it receives the saved tier result and `round_complete` byte for byte, and acks.
43. A join whose contribution key is another seat's, or whose `bind_by_contribution` fails: refused.

**bLIP-56 adapter (when built; not slice 1)**
44. Vector M3 maps to M1 and back, byte for byte, and M1's signature verifies on the message rebuilt from M3.
45. Carrier choice for each row of the table in 10.1, including a peer with bit 271 and an empty list, and one with bit 271 whose list lacks our id: the native type is used.
46. A `factory_piggyback` without TLV 0 or TLV 1024, or with an id we did not advertise: `warning` and close.
47. A message with records of 65,458 to 65,495 bytes: whole natively, in parts through the adapter; the same message is read either way.
48. A message saved on a native connection is resent on an adapter connection after a reconnect, and the other way round: the receiver sees identical native bytes.
49. A slice 1 build never sets bit 271 and never sends type 32800.

**Crash**
50. Member crashes after saving the round identifier and before sending nonces; after sending nonces; after saving the exposure and before sending partial signatures; after the tier result and before the ack. On restart: reason 3 where it holds no nonces; the saved partial signature bytes resent where it has them; never a second contribution to one identifier.
51. Host crashes at each step: a new attempt with a new `host_random`, so a new identifier, and a new funding outpoint if any partial signature had been released.
52. A member restored from a backup older than an unfinished creation round receives that round's proposal again, and a second tree on the same outpoint: both refused with reason 12, because neither names its current key; no second nonce is signed for the old identifier (review 2, N1, test 4b).
53. A second `round_propose` with a saved `round_id` and other `check_id`, deadlines or attempt, sent to a member in Nonces sent: the same `round_nonces` bytes are resent, no new nonce is generated, and the copy is kept as evidence (F10).
54. The connection drops between `start` and `round_propose`, and the member restarts: after `hello` the host resends the saved `start`, the member takes part. With `start` withheld, a signed proposal for the answered check is still accepted (F9).
55. A member reconnects while the host still collects partial signatures: it resends its saved `round_partial_sigs`, and the round completes (F26).
56. A seat loops `ready`/`unready` and `leave`/`join` as fast as it can: the host's journal grows by at most the stated limits (F13).

## 13. Open points

1. Closed: **feature bit.** The factory messages need none; the adapter (section 10) uses bLIP-56's bit 271. Discovery uses one bit of our own, `factory_capable` (candidate 448/449, sent odd 449), set in `init` by every build that includes discovery (section 2; `discovery.md` section 3, rule 1); a build without discovery sets no bit. There is no separate hosting bit.
2. **Custom type collisions** with unregistered experiments: check the list BOLT 1 points to, and consider registering 52791 in bLIP 2.
3. **Member key derivation path** per lobby (contribution key, factory key): belongs in the wallet specification. Its inputs are settled: seed, restore epoch (31 bits, a hardened BIP 32 index) and key index (section 2).
4. Closed: Slice 1 signs the tree only (`signing-round.md` section 15).
5. Closed: `round_ack` and `round_status_request` match `signing-round.md` draft 4.
6. **Evidence encoding** in `round_abort`, and parts from members once evidence exists.
7. **`all_partials`, `payouts`, `penalties`**: encodings, and making them even when defined.
8. **The host's own binding**: the host is a participant with its own factory key; this document makes it sign a binding to its long-term key like any member. Confirm.
9. **Using the BOLT 8 key for BIP 340 signatures.** Lightning already signs with node keys (BOLT 7 with ECDSA, BOLT 12 with BIP 340). No proof was looked for that ECDH in Noise and Schnorr signatures under one key are safe together. A separate host signing key bound by a statement is the alternative.
10. **Signers chosen in order of joining** (6.9) is a simple fair rule, not decided.
11. **Rate and size limits** (one status a second, 4 lobbies, 20 hellos, 4 scope-zero answers a second, 10 seat changes per 10 minutes, 4 × target seats) are first guesses to be measured. Known weakness (confirmation review): seats cost nothing and a member key is fresh per connection, so one peer can use up the lobby-wide seat cap (32 creations for T1) in about half a minute and block joining. Money is not at risk; liveness is. It ties to the open owner question of a seat cost or deposit; until then a host may run invitation-only lobbies.
12. **bLIP-56.** Read in full on 2026-11-12 from the open pull request; the native envelope is kept and bLIP-56 is an adapter (section 10). Its numbers are reserved only in the open pull request, and its gaps (10.5) are candidates for amendment proposals at the owner's decision; nothing is to be posted on the pull request.
13. Closed: the parameter table (7.2) follows `signing-round.md` draft 4 section 4.1. Lobby-constant values stay proposal fields; the fee rule is `terms.md` section 4.2's.
14. **The distribution transaction** is not signed in Slice 1 and the host recovers its coins by its timeouts (`safety-rule.md` section 12) — **proposed, owner to confirm**. Record 44 is reserved and even.
15. Closed: both digests are in the round identifier (`signing-round.md` section 3).
16. **The 512-node limit** comes from a defect in the import (N13.3) and caps slice 1 at roughly 128 members until fixed upstream. Slice 1 needs only four participants.
17. **The funding transaction travels in `round_propose`**, not in `round_complete` as review 2 N16 suggests, so the txid is checked before any contribution.
18. Closed: **the protocol id** is SHA-256 of "SuperScalar/1", decided (owner, 2026-11-12) (10.3); superscalar-cln currently uses a different value and will be updated. Still open: renaming the tags and switching signed preimages from the 4-byte tag to the 32-byte id, in one change (4.3).
19. **`factory_instance_id`** for slice 2's `channel_in_factory`.
