# The SuperScalar factory protocol: map

Map draft 1, 2026-11-12. Status: not reviewed. This document is the map of the whole protocol a SuperScalar channel factory speaks, from the first connection to the last payout, as Gazpacho specifies it. It is a map, not a specification. It fixes the structure, the layers, every message family over a factory's life, the number ranges, and which document and which slice or release specifies each part. The detail lives in the specifications it points to.

It is written to be portable: a second implementation should be able to read this map, find every document it needs, and know which numbers are taken. It is meant to be offered to the SuperScalar reference as the shared standard. Nothing here is agreed with the SuperScalar session yet (section 11), and nothing here is to be posted anywhere without the owner (section 12).

**Nothing in this map changes Slice 1.** Every number that `messages.md`, `terms.md`, `signing-round.md` and `journal.md` use today keeps its value. Where this map proposes a rule for later numbers, it says "proposed".

Documents it maps (drafts as of 2026-11-12; the five Slice 1 specifications are being revised as this is written):

| Document | What it is |
|---|---|
| `transport.md` | The transport profile of BOLT 8 and BOLT 1. **In preparation; not in the tree when this map was written.** Until it exists, `messages.md` section 2 is the profile |
| `messages.md` | The envelope, splitting, the bLIP-56 adapter, the lobby and signing-round messages |
| `terms.md` | The signed host terms record: outer rules, ranges, current values, freeze |
| `signing-round.md` | The multi-party MuSig2 signing round and proof of fault |
| `safety-rule.md` | The checks a member (and a host) runs before it signs. The acceptance rules of this map point here |
| `journal.md` | Gazpacho's storage. **Not part of the shared protocol** (section 9) |
| `notes/channel-groundwork.md` | Groundwork for the channel specification (`channel.md`, not written) |
| `discovery.md` | Discovery: the feature bit, listing, queries, lobby beacon, overlay links, store nodes and the pool request, anchors, overlay peering (informative), Nostr annex (section 7) |
| `notes/discovery-research.md` | Research behind `discovery.md` |

Words: **host** is the party that funds and coordinates (the SuperScalar papers say LSP); **member** is a party with a channel in the factory (the papers say client). "Specified" means a draft exists that fixes the bytes. "Reserved" means the numbers are kept and nothing else.

## 1. The layers in one table

| Layer | Name | Covers | Taken from Lightning | Who else could reuse it |
|---|---|---|---|---|
| 0 | Transport | Encrypted, authenticated connection; first message; keep-alive; size limit | BOLT 8 and BOLT 1, unchanged. Not ours | Already everyone's |
| 1 | Envelope | One odd custom message type, a header, TLV records, signatures, splitting; a second carrier through bLIP-56 | BOLT 1 message shape, TLV rules, odd/even rule; bLIP-56's piggyback | Any multi-party protocol that runs over Lightning peer connections, including other factory designs |
| 2 | Group coordination | Sessions (lobbies), signed terms with ranges and freeze, readiness and consent, the MuSig2 signing round, proof of fault, discovery requests answered by a host | BOLT 1 TLV rules; BIP 327, BIP 340 | Any n-of-n MuSig2 coordinator: other factory designs, batched channel opens, coinjoin-style rounds. Written so it can be its own library (`LOBBY.md`, `DESIGN.md` section 3) |
| 3 | SuperScalar operations | Tree parameters, creation, liquidity sales, layer updates, moving to the next factory, cooperative close, exits, end-date payouts, watch hand-off, backups | Peer storage messages for backups | The SuperScalar reference and any other SuperScalar implementation |
| 4 | Channels inside a factory | Standard taproot channels on a leaf output; the factory-change flow; the early warning time for payments | BOLT 2, 3, 5 and the simple taproot channel extension unchanged; bLIP-56's opening marker and change flow | Any Lightning node that implements bLIP-56 as the "base node software" (LND, Core Lightning, Eclair, LDK) |
| 5 | Discovery | How a member finds a host and its lobbies | Gossip feature bits (one candidate path) | Any host, directory or client, factory-based or not |

Layers 1 and 2 know nothing about trees. Layer 3 is the only layer that knows SuperScalar. Layer 4 is Lightning's own channel with a few rules added. That split is the point of the map: each layer can be adopted without the layers above it.

## 2. Layer 0: transport

**Not ours.** `transport.md` profiles it; until that document exists, `messages.md` section 2 holds the profile.

| Item | Rule today | Source |
|---|---|---|
| Transport | BOLT 8 (Noise XK) over TCP. WebSocket where needed, which is not standardised | `messages.md` 2, `DESIGN.md` 8 |
| Host key | The host's long-term key is its BOLT 8 static key, pinned by the member | `messages.md` 2 |
| Member key | A fresh BOLT 8 key per lobby, derived from the seed; it is also the member's contribution key | `messages.md` 2; derivation path open |
| First message | BOLT 1 `init`; `networks` names the one chain the build runs on (signet in every slice) | `messages.md` 2 |
| Keep-alive | BOLT 1 `ping`/`pong`; no answer in 30 s closes | `messages.md` 2 |
| Size | 65,535 bytes per message, type included | BOLT 1, BOLT 8 |
| Ordering | In order and without loss within one connection; every duplicate comes from a reconnect or a restart | BOLT 8 |

Portable documents needed: `transport.md` (profile, with the pinned-key rule and the per-lobby key rule). No vectors of our own: BOLT 8 has its own.

## 3. Layer 1: the envelope

**What it covers.** One Lightning message type carries every factory message. The payload is a 38-byte header and a TLV stream.

| Part | Value | Where specified |
|---|---|---|
| Message type | **52791** (0xce37), odd, in the custom range. Derived from `SHA256("gazpacho factory message")` | `messages.md` 3 |
| `protocol` | 4 bytes `67 7a 66 01` ("gzf", 1). A fixed alias of the protocol and its major version; not a version that is negotiated, and not a security parameter (review 3, F28) | `messages.md` 4 |
| `kind` | `u16`, odd/even as BOLT 1 message types: unknown even refused, unknown odd ignored | `messages.md` 4.1 |
| `scope` | 32 bytes: the lobby identifier, which is the outer terms digest (the terms' fingerprint). All zero only in `hello` | `messages.md` 4, `terms.md` 6 |
| Records | BOLT 1 TLV, minimal BigSize, strictly increasing; every field is a record | `messages.md` 4.2 |
| Signature | Record 240, last, BIP 340 over `TH("gazpacho/msg", protocol ‖ kind ‖ scope ‖ records before 240)` | `messages.md` 4.3 |
| Splitting | Kind 2 `part`, 65,000-byte pieces, whole message at most 1 MiB, reassembled before anything is checked | `messages.md` 5 |
| Second carrier | bLIP-56 `factory_piggyback` (type 32800, submessage 4), used only when both sides negotiate it. Signatures are always over the native form | `messages.md` 10 |

**Taken from Lightning:** the message shape, the custom type range, TLV encoding and the odd/even rule (BOLT 1); the piggyback and protocol id rule (bLIP-56).

**Who else could reuse it:** any protocol that wants signed, splittable, scoped messages inside an ordinary Lightning connection. Only the 4-byte `protocol` value and the tag strings are ours.

### 3.1 The path towards a core, even-typed part of Lightning

The owner would like channel factories to become a core, even-typed part of Lightning one day. This map records the path. It changes nothing in Slice 1.

| Stage | Carrier | Message type | Negotiation | State |
|---|---|---|---|---|
| A. Now (Slice 1, 1.0.0) | Native | 52791, odd custom type | None. A node that does not speak it ignores it | Specified |
| B. Peer speaks bLIP-56 | Adapter | 32800, even, `factory_piggyback` | Feature bit 271 (or compulsory 270) and our id in `supported_factory_protocols` | Specified in `messages.md` 10; not built; bLIP-56 numbers are reserved only in its open pull request |
| C. Our own feature bit | Native | 52791 | An odd bit of our own in `init` and `node_announcement` (section 8.3) | Candidate 448/449 picked (`discovery.md` 3); not registered |
| D. A BOLT | Core | Even type or types below 32,768, assigned by the BOLT | A BOLT feature bit below 256 | Not started. Needs public proposals; only the owner can start them (section 12) |

Why the stages are in this order. An odd type can be sent to anyone, so stage A needs no agreement with anyone. An even type means "you must understand this", so it may only be sent after negotiation: that is what stages B and D add. A core protocol is even by nature, which is why it comes last, after the format has been proven and agreed.

What stays the same at every stage: the inner bytes (`kind`, `scope`, records), the signing form (the native form with the 4-byte `protocol`), the tags, and every saved record. A message signed at stage A verifies unchanged at stage D. That property must be kept by whoever writes stage D: either the BOLT keeps the native form as the signing form, or the one rename of section 11 (tags and protocol id) happens before any stage beyond A is shipped.

**Portable documents needed:** `messages.md` sections 1 to 5 and 10 (formats, splitting state machine, acceptance rules), vectors M1, M2, M3. **Proposed:** move these sections into their own `envelope.md` when the format is offered as shared, so that layer 1 can be adopted alone.

## 4. Layer 2: group coordination

Application-agnostic. Intended as a separate library: it runs a group of parties from "a host offers terms" to "every party holds group signatures on a set of items", and can prove who broke a round. It does not know what a tree is. It asks the application (layer 3) two things: does this party accept these terms, and are these items safe to sign.

| Part | What it does | Specified in | State |
|---|---|---|---|
| Sessions (lobbies) | Seats named by contribution key; states, not changes, so every message survives a reconnect; start rule with target, minimum and deadline | `messages.md` 6, `LOBBY.md` | Specified for Slice 1 |
| Signed terms | Two records: outer rules (fixed; their digest is the lobby's identity and fingerprint) and current values (versioned, inside signed ranges). Canonical TLV encoding | `terms.md` | Specified (draft 2) |
| Freeze | The first ready check freezes the current values for every later check and attempt | `terms.md` 8, `messages.md` 6.8 | Specified |
| Readiness and consent | A `ready` names both digests and is signed by the member; the member's own limits are compared with the whole range by default | `terms.md` 9, `messages.md` 6.4 | Specified |
| Signing round | Propose, nonces, all nonces, partial signatures, tier result, complete, acknowledge, status request, abort. Rules S1 to S5. One round engine for every purpose | `signing-round.md`, `messages.md` 7 | Specified for creation |
| Proof of fault | What a third party can check, what it cannot | `signing-round.md` 9 | Design specified; evidence encoding open |
| Discovery requests | A member asks a host which lobbies it has; the host answers with signed listings | `discovery.md` 6; seed in `messages.md` 6.1 | Specified (draft 3) |

**Taken from Lightning:** TLV rules. From Bitcoin: BIP 327 (MuSig2), BIP 340 (signatures and tagged hashes).

**Who else could reuse it:** any coordinator of large n-of-n MuSig2 signatures. Only n-of-n: the design refuses threshold keys for shared money (`LOBBY.md`).

### 4.1 Where layer 3 leaks into layer 2 today

Slice 1 was written for one application, so some layer 3 items sit in layer 2 messages. They keep their numbers. The library will treat them as application data passed through to layer 3.

| Item | Where | Treatment in the library |
|---|---|---|
| Lobby states 4 Funding and 5 Active | `lobby_status` | "Application phase" states |
| `round_propose` records 12 to 50 (funding, tree parameters, spare-liquidity hashes, K, layer settings, distribution) | `messages.md` 7.2 | Application parameters, handed to layer 3, which rebuilds the items |
| `purpose` codes | Round identifier, `round_propose` | A registry owned by layer 3 (section 10.5) |
| `round_complete` records 3 `payouts` and 5 `penalties` | `messages.md` 7.7 | Application records |
| `factory_funded` (kind 81) | Round range | A layer 3 hint numbered in the round range for Slice 1 |
| Abort reasons 9 and 11 | `round_abort` | Application reasons in the generic list |
| Terms types 24 to 32 (shape, lifetime, wind-down, channel size, tree fee rate) and 64 to 68 (fees) | `terms.md` 3 | Application terms; the library refuses any unknown even type and asks the application to judge known ones |

**Proposed rule for new numbers** (not Slice 1): in a layer 2 message, record types 2 to 63 belong to layer 2, and 64 to 239 carry application records that the library passes to layer 3 to judge. The odd/even rule applies unchanged: an application record with an even type that layer 3 does not know refuses the message.

**Portable documents needed:** `terms.md` (format, freeze state machine, comparison rules, vectors T1 to T6); `messages.md` 6 to 8 (lobby and round formats, duplicate and order table); `signing-round.md` (state machines, rules S1 to S5, fault table); an evidence encoding (open); `discovery.md` section 6 for the direct request. Vectors still missing: the round identifier, the nonce signature, the nonce-set and held digests, evidence.

## 5. Layer 3: SuperScalar operations

Everything that knows the tree. Every operation that needs group signatures runs a layer 2 signing round with its own `purpose`; layer 3 adds the parameters, the items, the acceptance rules, and any messages around the round.

| Operation | What it is | Round purpose | Specified in | Release |
|---|---|---|---|---|
| Tree parameters | The shape table, the split rule, fixed levels D, fee per transaction, funding amount; every setting that changes a transaction's bytes | — | `terms.md` 4, `signing-round.md` 4.1 and 13 | Slice 1 |
| Creation | Tree built by every party from terms plus proposal; host funds last after every member's ack | 1 | `signing-round.md`, `messages.md` 7, `safety-rule.md` | Slice 1 (1.0.0) |
| Liquidity sale | **A sale creates a new channel** for the buyer from the shared spare liquidity; existing channels never move. Shared leaves (K > 1) arrive with it. Coverage shown to the member | 2 ("leaf change") | Not specified (`signing-round.md` 14.1, `safety-rule.md` 4.2) | 1.1.0 (owner decision 5) |
| Layer update | Re-signing a timed layer; every channel below gets a new anchor | 3 | Not specified (`signing-round.md` 14.2, 14.3) | M4 |
| Moving to the next factory | Pay across over Lightning, or close into the new factory's funding. Partial moves fall back to paying across | 5 | Not specified (`signing-round.md` 5) | M4 |
| Cooperative close | One tier spending the funding output | 4 | Not specified (`signing-round.md` 5) | Slice 1 option (owner decision open, `safety-rule.md` 12), else M4 |
| Exit coordination | Notices around a unilateral exit; the host forcing out a silent member before payouts (H6); the recovery procedure after a restore (C12) | Proposed 6 for a recovery close | Not specified | Slice 3 (M3); recovery with the exit engine |
| End-date payouts | Pre-signed payouts to members at the end date; payout destinations per member (owner decision 6: one wallet in 1.0.0; derived addresses per factory in 1.1.0; outside wallets later, proven before use) | Signed inside creation, update and move rounds as items | Not specified; waits for SuperScalar's payout series (`docs/handoff/2026-11-11-end-date-payout.md`) | Before mainnet; release not fixed |
| Watch hand-off | Handing pre-signed responses, never keys, to a watcher | — | Not specified (`AWAY.md`, issue 2) | Watch engine M3; outside watcher later |
| Backups | The member's encrypted backup held by the host through Lightning's peer storage messages; restore epochs | — | `safety-rule.md` 9 (rules); export and format not specified | Release not fixed |

**Taken from Lightning:** peer storage for backups (`peer_storage`, `peer_storage_retrieval`). Everything else here is new.

**Who else could reuse it:** any SuperScalar implementation. It is the part that must be agreed with the SuperScalar reference for two implementations to share a factory.

**Portable documents needed:** for each operation, a format (its messages and its round profile: items, tiers, parameters), a state machine, acceptance rules (in `safety-rule.md` or a profile of it) and vectors. To write: `tree.md` (shape and build rules, with tree vectors built by the reference), `sale.md`, `layer-update.md`, `move.md`, `close.md`, `exit.md`, `payout.md`, `watch.md`, `backup.md`. Today only creation has all four, in draft.

## 6. Layer 4: channels inside a factory

A member's channel is a standard Lightning taproot channel whose funding output is a leaf output that may never reach the chain.

| Part | Rule | Source | State |
|---|---|---|---|
| Channel messages | BOLT 2 unchanged: opening, normal operation, `channel_reestablish`, closing. **Payments are BOLT 2 and are not ours** | BOLT 2 | Not ours |
| Channel format | Simple taproot channels (bits 80/81) with `option_scid_alias` and `option_zeroconf`; never announced | BOLT taproot extension; `notes/channel-groundwork.md` 1.1 | To specify in `channel.md` |
| Marking a channel as in a factory | bLIP-56's `open_channel` TLV `channel_in_factory` (65600): protocol id, instance id, early warning time | bLIP-56 | Planned from Slice 2; `factory_instance_id` open |
| Factory-change flow | bLIP-56's idea: quiesce, agree the new funding outpoint, sign the first commitment on it with the same number, sign the factory state, batch both outpoints, lock. **Plus taproot nonces for the new outpoint**, which bLIP-56 does not cover | bLIP-56; BOLT 2 splicing; `notes/channel-groundwork.md` 2.3 | To specify; needed by layer updates and moves (sales in 1.1.0 open a new channel instead of moving one) |
| Early warning time | Every HTLC's expiry at least height + early warning + 1; computed from the real exit time, not from the import's under-reporting function | bLIP-56; `safety-rule.md` 7 | To specify; Slice 2 |
| Commitment nonces | Under the channel format's own rules, outside the round's rules | `signing-round.md` 14.2, `safety-rule.md` 4.3 | Requirement stated |

**Who else could reuse it:** any base node that implements bLIP-56, if the taproot-nonce gap is closed in bLIP-56 itself (section 12).

**Portable documents needed:** `channel.md` (outline in `notes/channel-groundwork.md` part 3), with the BOLT vectors and our own vectors for opening on a leaf and for the change flow.

## 7. Layer 5: discovery

**Specified in `discovery.md`** (draft 3, 2026-11-12, not reviewed), written from the owner's decisions (`docs/research/ideas-ledger.md` section A), `docs/research/peering-research.md`, `docs/research/discovery-research.md` and the review of draft 2 (`notes/review-discovery-d2.md`). Its section 0 maps every finding of that review to how draft 3 handles it. Summary:

| Part | What | Carrier | `discovery.md` |
|---|---|---|---|
| Feature bit | **One** bit, `factory_capable`, on every Gazpacho node, advertised **odd**: BOLT 7 makes nodes shun an unknown even bit in `node_announcement`. No hosting bit: a host is whoever sends beacons | `init`, `node_announcement` | 3 |
| Host card | **Withdrawn** in draft 2. Its numbers are reserved only | — | 4 |
| Listing and withdrawal | The outer terms record plus host key, start height, expiry, optional anchor, signature; and a signed, final **withdrawal** that hides every copy of an ended lobby. Identical bytes on every carrier. The per-host cap keeps the latest start, so replays cannot hide new lobbies | Query answers; store nodes; Nostr | 5 |
| Queries | Index and listing, request and answer | Onion messages with a blinded reply path; native kinds | 6 |
| Host list | A trusted full node's signed, chain-anchored entries: can be hidden, not forged | Native; onion | 7 |
| Lobby beacon | 166-byte signed "host H has lobby L open", with two proposed filter fields; no terms; unknown odd records relayed. Sequence = height × 16 + counter. Accepted only from hosts in the graph that meet a **price** (half-capacity of channels at least 144 blocks old ≥ `unit` / 4, the same as Nostr's anchor rule); at most 8 new numbers per 144-block window, counted in any order; seen only when accepted; withdrawals held as tombstones; lower id wins on one sequence; orphan pool; relayed at once, rate-limited per link. Reject stops discovery on a connection, never closes it | Native, overlay links | 8 |
| Anchors and caps | Channel or coin; required on Nostr only; at most 4 listings per host; relays and wallets may only tighten | Inside listings | 9 |
| Overlay links | `overlay_init` carries the per-connection **lobby store flag**; `beacon_filter` turns relay on or off | Native | 10 |
| Store nodes and pool | Store nodes fetch, keep and serve listings. Fetch order: a store peer first (answer or `listing_not_held` at once), then the host after a random delay. `pool_request` for catch-up and light clients | Native; onion | 11 |
| Overlay peering | Self-selection from the gossip graph, address groups, 6 links, mix with a store node, anchors, rotation, scouts, local scoring. **Informative** | Local policy | 13 |
| Bootstrapping | Degrades to direct queries (design C) | Native | 14 |
| Reserved | Have-summaries, store-to-store sync, bundled host proofs; scoring never on the wire | — | 15 |
| Nostr annex | One addressable kind, NIP-32 labels, NIP-40 expiry; conditions for retiring it. **Informative** | Nostr | 17 |

**Every path carries the same signed terms record**: the listing's `outer` is byte for byte what `terms_offer` carries, and its digest is the `scope` of `hello` and `join`. Nothing in a listing is trusted until `terms.md` section 7 passes; the real protection stays the check at signing (C8).

Numbers (all **candidates**, not final; `discovery.md` section 2 gives how each is chosen and checked):

| Item | Candidate |
|---|---|
| Native kinds | 129 to 147 odd, 153, 155; 149, 151, 157, 159 reserved; in range 128 to 159 (section 10.1). The research's 35 to 53 are **not** used: they lie in the session range |
| Feature bit | 448/449 `factory_capable` (section 8.3). Draft 1's 450/451 is free again |
| Onion payload types | 106369 to 106385 odd |
| Nostr kind | 31867 listing |
| Reserved only | Card TLV 118685 in `node_announcement`; Nostr kind 37329; tag `gazpacho/card` |
| Tags | `gazpacho/listing`, `gazpacho/withdrawal`, `gazpacho/index`, `gazpacho/anchor`, `gazpacho/beacon` (section 8.2) |
| Journal area | 0x000c (section 10.4), unchanged |

Release plan (`discovery.md` section 18): the signet demo wallet ships **design C** exactly as `discovery.md` 14.1 fixes it: the bit plus direct queries, with links, QR, the built-in list, listings and withdrawals, and Nostr with coin anchors, and no store machinery; next, before mainnet, **design D**: beacons, overlay and client links, store nodes, the pool request, the host list and light clients over direct connections; later, onion queries and the reserved items.

## 8. Registries

### 8.1 Every message family over a factory's life

Kind ranges are in section 10.1. "Acceptance rules" names the checks a receiver must run before it acts or signs; C and H numbers are `safety-rule.md`, S numbers are `signing-round.md` section 3. The odd/even meaning is that of `messages.md` 4.1 everywhere.

| Family | Layer | Kinds | Acceptance rules | Specified by (document; slice or release) | State today |
|---|---|---|---|---|---|
| Envelope utilities | 1 | 2 `part`; 1 to 15 | `messages.md` 5 receiving rules; reassemble before checking | `messages.md` 5; Slice 1 | 2 specified (host → member only in Slice 1); rest reserved |
| Errors and notices | 1, 2 | BOLT 1 `warning` for every refusal; reason codes inside messages (section 10.6); 3 to 15 reserved for a factory-level notice | Nothing that touches money depends on one; reasons are never shown as fact | `messages.md` 1, 6.7, 6.10, 7.9; Slice 1 | Reason codes specified; notice kinds reserved |
| Session (lobby) | 2 | 16 to 34; 35 to 63 | `terms.md` 7 on every terms record; freeze (`terms.md` 8); C8a | `messages.md` 6, `terms.md`; Slice 1 | Specified 16 to 34. Reserved: invitations, identity proofs, chat, rule-change requests, standby seats, carry-over, deposits |
| Signing round | 2 | 64 to 80; 82 to 127 | S1 to S5; C1 to C8a, C10, C12; host H1, H2, H8, H11 to H13 | `signing-round.md`, `messages.md` 7; Slice 1 | Specified for creation. Reserved: evidence and challenge, `all_partials` for the last tier of a layer update, per-member digests (`signing-round.md` 14.3) |
| Discovery | 2, 5 | 129 to 147 odd, 153, 155 specified; 149, 151, 157, 159 reserved; even kinds not used; never refused (`messages.md` 4.1) | `discovery.md` 5.2 (L1 to L8), 5.3 (W1 to W7), 6.4 to 6.5 (H1 to H6, Q1 to Q5), 8.3 (B1 to B10), 8.4 (orphans), 8.7 (Reject and Ignore), 9.2 (A1 to A7), 10.1 (I1 to I6), 11 (S1 to S8, G1 to G7, PL1 to PL6); then `terms.md` 7; nothing in a listing is trusted | `discovery.md`; design C in the signet demo (its 14.1), design D before mainnet (its section 18) | Specified (draft 3), not reviewed |
| Creation | 3 | Uses 16 to 80; 81 `factory_funded`; 256 to 319 for life-cycle messages after creation | C1 to C12; H1, H2, H8, H11 to H13 | `signing-round.md` 4.1, 15; `terms.md` 4; Slice 1 | Specified |
| Payments | 4 | BOLT 2, **not ours** | C13; C9; `safety-rule.md` 7 (accepting a payment); early warning | `channel.md`; Slice 2 | Not ours; `channel.md` to write |
| Channel opening and factory change | 4 | bLIP-56 TLV 65600 and submessages 6 to 14 through the adapter; native equivalents 1024 to 1151 | `safety-rule.md` 4.1 rules 1 to 5, 4.3; C6; C9 | `channel.md`; opening Slice 2, change M4 | Reserved |
| Leaf change and sale | 3 | 320 to 383; purpose 2 | `safety-rule.md` 4.2 requirements (second-spend guard on the shared stock, penalty not firing on honest exits, owed and exit value with several channels, coverage); C3 to C7; C9; C13 | `sale.md`; 1.1.0 | Reserved |
| Layer update | 3 | 384 to 447; purpose 3 | `signing-round.md` 14.2, 14.3; `safety-rule.md` 4.1, 8; C4; C6; C9 | `layer-update.md`; M4 | Reserved |
| Move to the next factory | 3 | 448 to 511; purpose 5 | Owed table, rotation rows (`safety-rule.md` 5); C3; C7; C10 | `move.md`; M4 | Reserved |
| Cooperative close | 3 | 512 to 575; purpose 4 | C2 (paid to a script the member derived); C4; C7 (two spends of one output); C9; C13 | `close.md`; Slice 1 if the owner adds it, else M4 | Reserved |
| Exit and recovery | 3 | 576 to 639; purpose 6 proposed for a recovery close | C5; `safety-rule.md` 7; C12; H6 | `exit.md`; Slice 3 (M3) | Reserved |
| End-date payout and destinations | 3 | 640 to 703; `round_propose` record 44 `distribution` and `round_complete` record 3 `payouts` already reserved | C5 (competing claims); C8 (distribution row); `safety-rule.md` 6 item 7; H6; a destination proven before use (owner decision 6) | `payout.md`; before mainnet | Reserved |
| Watch hand-off | 3 | 704 to 767 | `safety-rule.md` 4.1 rule 3 (every old anchor watched), 8, 11; never hand over keys (`AWAY.md`) | `watch.md`; M3, outside watcher later | Reserved |
| Backup | 3 | BOLT 1 `peer_storage` and `peer_storage_retrieval` (not ours); 768 to 831 for backup notices | `safety-rule.md` 9, R1 to R7; C12 | `backup.md`; release not fixed | Reserved |

### 8.2 Tagged-hash tags and other fixed strings

`TH(tag, bytes)` is BIP 340's tagged hash. A tag is never reused for a second meaning. Every tag is registered here before it is used. All tags will be renamed together if a shared prefix is agreed (section 11).

| Tag | Meaning | Layer | Defined in | State |
|---|---|---|---|---|
| `gazpacho/msg` | Hash a message signature covers | 1 | `messages.md` 4.3 | Specified |
| `gazpacho/part` | `transfer_id` of a split message | 1 | `messages.md` 5 | Specified |
| `gazpacho/terms/outer` | Outer terms digest; the lobby identifier | 2 | `terms.md` 6 | Specified |
| `gazpacho/terms/current` | Current values digest | 2 | `terms.md` 6 | Specified |
| `gazpacho/bind` | Two-way binding of factory key and contribution key | 2 | `messages.md` 6.3, `signing-round.md` 2 | Specified |
| `gazpacho/round_id` | Round identifier | 2 | `messages.md` 7.1 | Specified; no vector yet |
| `gazpacho/nonce` | A member's signature on its public nonce | 2 | `messages.md` 7.3 | Specified; no vector yet |
| `gazpacho/nonceset` | Digest of the nonce set a partial signature used | 2 | `messages.md` 7.5 | Specified; no vector yet |
| `gazpacho/held` | What a member holds, in `round_ack` | 2 | `messages.md` 7.8 | Specified; no vector yet |
| `gazpacho/nonce-extra` | Extra input to nonce generation (local; never on the wire) | 2 | `signing-round.md` 8 | Specified |
| `gazpacho/tree` | Digest of a tree for the C7 record (review 3, F7) | 3 | Not defined | Name reserved |
| `gazpacho/evidence` | Digest of a fault evidence bundle | 2 | Not defined | Name reserved |
| `gazpacho/listing` | Digest a listing signature covers | 5 | `discovery.md` 5.1 | Specified |
| `gazpacho/withdrawal` | Digest a listing withdrawal (tombstone) signature covers | 5 | `discovery.md` 5.3 | Specified (draft 3) |
| `gazpacho/index` | Digest a lobby index signature covers | 5 | `discovery.md` 6.1 | Specified |
| `gazpacho/card` | Was the digest of a signed host card | 5 | `discovery.md` 4 | **Reserved**: the card is withdrawn in draft 2; the tag is never reused |
| `gazpacho/anchor` | A coin anchor statement | 5 | `discovery.md` 9.1 | Specified |
| `gazpacho/beacon` | A lobby beacon; also its deduplication id | 5 | `discovery.md` 8.1 | Specified |

Other fixed strings, which are plain SHA-256 inputs, not tags:

| String | Use | Defined in |
|---|---|---|
| `gazpacho factory message` | Derivation of type 52791 (the number is what matters, not the string) | `messages.md` 3 |
| `SuperScalar/1` | The shared protocol identifier, `SHA256("SuperScalar/1")` = `c3a082d0…c842f1`, also bLIP-56's `factory_protocol_id`. Decided (owner, 2026-11-12) | `messages.md` 10.3 |
| `gazpacho test key: <label>`, `gazpacho test lobby salt` | Test keys and salt for vectors. Never for coins | `terms.md` 11 |

### 8.3 Feature bits

| Bit | Meaning | Status | Needed for |
|---|---|---|---|
| None | The factory messages negotiate nothing; type 52791 is odd. A build without discovery sets no bit | Specified | Slice 1 |
| 270/271 | bLIP-56 `pluggable_channel_factories` | Reserved only in bLIP-56's open pull request; may change before merging | The adapter (stage B) |
| 448/449 (candidate), sent odd 449 | `factory_capable`: speaks the factory protocol natively; set by every Gazpacho build that includes discovery (from the demo wallet, design C). The only discovery bit: a host is whoever sends beacons or lists lobbies | **Candidate, not final**; checks in `discovery.md` 2 | Stage C; discovery |
| 450/451 | Draft 1's `factory_host` | **Removed** in `discovery.md` draft 2; free, not reserved | — |
| 80/81 | `option_simple_taproot` | BOLT extension; read 2026-11-11 | Layer 4 |
| 46/47, 50/51 | `option_scid_alias`, `option_zeroconf` | BOLT 9; read 2026-11-11 | Layer 4 |
| 34/35 | Quiescence (`stfu`) | BOLT 2; read 2026-11-11 | Factory change |
| 62/63 | `option_splice` | BOLT 2; read 2026-11-11 | Only if the change flow reuses splice messages |
| Peer storage pair | `option_provide_storage` | **Number not checked today**; read BOLT 9 before use | Backups |

How our bit must be chosen:

1. From the bLIP range: bLIP 2 keeps bits 0 to 255 for BOLTs, so ours is 256 or above.
2. An even/odd pair, advertised odd ("it's okay to be odd") so that a node that does not know it is not refused.
3. Checked, on the day it is picked, against the bLIP 2 registry as merged, against the bits in every open bLIPs and BOLTs pull request (bLIP-56's 270/271 among them), and against known unregistered uses in the code of LND, Core Lightning, Eclair and LDK. The check and its date are recorded here.
4. Registered in bLIP 2 only through a public proposal, which only the owner can authorise (section 12). Until then the bit is used only on signet and only by builds that say it is unregistered.

The same procedure applies to our custom type 52791: checked against the bLIP 2 registry on 2026-11-11 (not assigned); not yet checked against unregistered experiments (`messages.md` open point 2).

## 9. What is protocol and what is Gazpacho's own

| Part | Shared protocol? | Why |
|---|---|---|
| Layers 0 to 5 as above | Yes | Two implementations need them to talk |
| Acceptance rules (`safety-rule.md`) | Required for safety, not for talking | A peer that skips them can still talk, but its user can lose money. A conformance suite tests them (section 9.1) |
| Persistence duties: what must be durable before each message is sent (save before send; the exposure record before the first partial signature; never storing secret nonces) | Yes, as obligations | Every implementation needs them for rules S1 to S3 and C7. The obligations belong in the operation specifications |
| `journal.md`: file layout, entries, record type numbers | **No** | Gazpacho's storage. Another implementation stores what it likes, provided it meets the obligations |
| Local web interface, ports, programs | No | Gazpacho's own |

### 9.1 Conformance vector sets

| Set | Covers | Layer | Where | State |
|---|---|---|---|---|
| T1 to T6 | Terms encoding, digests, signatures, refusals, comparison | 2 | `terms.md` 11 | Specified (draft 2) |
| T7 | The tree T1 builds | 3 | `terms.md` 11 | Specified |
| M1 | A signed message and the binding | 1, 2 | `messages.md` 11 | Specified |
| M2 | Splitting | 1 | `messages.md` 11 | Specified |
| M3 | The bLIP-56 adapter, same signature as M1 | 1 | `messages.md` 11 | Specified |
| R | Round identifier preimage and hash for a real tree | 2 | — | Open: needs the tree builder in the engine |
| N | `nonce_sig`, `nonceset`, `held` | 2 | — | Open |
| E | Fault evidence that a separate checker accepts or rejects | 2 | — | Open: encoding open |
| TB | Byte-identical tree transactions for each shape and member count, built by the reference | 3 | `terms.md` 4.2 build-server table (partial) | Partial |
| S | A hostile-host suite: one refused proposal per check in `safety-rule.md`, and the honest case accepted | 3 | Test lists in `safety-rule.md` 13, `messages.md` 12 | Listed as tests; **proposed** to publish as portable cases |
| CH | Taproot channel vectors (the BOLT's own) plus opening on a leaf and the change flow | 4 | — | Open |
| D0 to D23 | Candidate numbers, coin anchors (plain and BIP 86), listing and withdrawal, queries on both carriers, Nostr content, beacon and beacon withdrawal, filter, refusals, `overlay_init` (store and client), pool request, answer and continuation, `listing_not_held`; and, run in arrival order by a reference reader, the cap, the one-sequence tie-break, churn, tombstones, view-dependent ignores and the listing reader (D1 and D3 withdrawn) | 5 | `discovery.md` 20 | Specified (draft 3); channel anchor and host list entry open |
| J1 to J4 | The journal file | — | `journal.md` 11 | Gazpacho-internal; not conformance |

### 9.2 Documents each layer needs to be portable

| Layer | Formats | State machines | Acceptance rules | Vectors | Missing |
|---|---|---|---|---|---|
| 0 | `transport.md` | BOLT 8 | Pinned key, network, keep-alive | BOLT 8's | `transport.md` itself |
| 1 | `messages.md` 1 to 5, 10 | Reassembly (`messages.md` 5); carrier choice (10.1) | `messages.md` 4, 5, 10 | M1 to M3 | A stand-alone `envelope.md` (proposed) |
| 2 | `terms.md`; `messages.md` 6, 7 | Lobby and seat states (`messages.md` 6); round states per tier (`signing-round.md` 7) | `terms.md` 7 to 9; S1 to S5; fault table (`signing-round.md` 9) | T1 to T6, M1 | Evidence encoding; R, N, E vectors; `discovery.md` request part |
| 3 | `signing-round.md` 4.1 and 15 (creation profile); `terms.md` 4 | Creation states (`signing-round.md` 7) | `safety-rule.md` | T7, TB (partial) | `tree.md`, `sale.md`, `layer-update.md`, `move.md`, `close.md`, `exit.md`, `payout.md`, `watch.md`, `backup.md`; S suite |
| 4 | BOLT 2, 3, 5, taproot extension; bLIP-56 | BOLT 2; change flow | `safety-rule.md` 4; C9; C13 | BOLT's; CH | `channel.md` |
| 5 | `discovery.md`; terms record (`terms.md`) | Beacon acceptance and relay (`discovery.md` 8); overlay links (10); store nodes, fetch order and pool (11) | `discovery.md` 5.2, 5.3, 6, 8.3, 8.4, 8.7, 9, 10.1, 11; `terms.md` 7 | D0 to D23 | Channel-anchor and host-list vectors |

## 10. Number ranges

### 10.1 Envelope kinds (`u16`)

Every number Slice 1 uses is unchanged. Each range holds odd and even kinds; even must be understood, odd may be ignored.

| Range | Layer | Family | Used today | State |
|---|---|---|---|---|
| 0 | — | Never used, so an all-zero envelope is invalid | — | Fixed |
| 1 to 15 | 1 | Envelope utilities and factory-level notices | 2 `part` | 2 specified; 1, 3 to 15 reserved |
| 16 to 63 | 2 | Session (lobby) | 16 `hello`, 18 `terms_offer`, 20 `join`, 22 `ready`, 24 `unready`, 26 `leave`, 28 `lobby_status`, 30 `ready_check`, 32 `start`, 34 `cancel` | Specified; 35 to 63 reserved |
| 64 to 127 | 2 | Signing round | 64 `round_propose`, 66 `round_nonces`, 68 `round_all_nonces`, 70 `round_partial_sigs`, 72 `round_tier_result`, 74 `round_complete`, 76 `round_ack`, 78 `round_abort`, 80 `round_status_request`; 81 `factory_funded` (a layer 3 hint, numbered here in Slice 1) | Specified; 82 to 127 reserved |
| 128 to 159 | 2, 5 | Discovery (`discovery.md` 6.3) | 129 `lobby_index_request`, 131 `lobby_index`, 133 `listing_request`, 135 `listing`, 137 `host_list_request`, 139 `host_list`, 141 `lobby_beacon`, 143 `beacon_filter`, 145 `pool_request`, 147 `pool`, 153 `overlay_init` (lobby store flag), 155 `listing_not_held` | Specified (draft 3). Reserved without format: 149 `beacon_summary`, 151 store-to-store sync, 157 bundled host proofs, 159 a future beacon version. Even kinds not used; discovery kinds are ignored, never refused (`messages.md` 4.1) |
| 160 to 255 | 2 | Further group coordination (host proofs, identity proofs, deposits) | — | Reserved |
| 256 to 319 | 3 | Factory life cycle after creation (status on reconnect, wind-down notices) | — | Reserved |
| 320 to 383 | 3 | Leaf change and liquidity sales | — | Reserved, 1.1.0 |
| 384 to 447 | 3 | Layer updates | — | Reserved |
| 448 to 511 | 3 | Moving to the next factory | — | Reserved |
| 512 to 575 | 3 | Cooperative close | — | Reserved |
| 576 to 639 | 3 | Exit coordination and recovery | — | Reserved |
| 640 to 703 | 3 | End-date payouts and payout destinations | — | Reserved |
| 704 to 767 | 3 | Watch hand-off | — | Reserved |
| 768 to 831 | 3 | Backup | — | Reserved |
| 832 to 1023 | 3 | Further SuperScalar operations | — | Reserved |
| 1024 to 1151 | 4 | Channel inside a factory, native carrier (factory change with taproot nonces, early warning) | — | Reserved |
| 1152 to 32767 | — | Unallocated; allocated only through this registry | — | Reserved |
| 32768 to 65535 | — | Private and experimental. Never part of the shared standard; never sent by a release build to another implementation | — | Reserved for experiments |

Within a range, numbers are given in order, even before odd for messages a party depends on, as Slice 1 did. A family that outgrows its range takes a new block from 1152 upwards; it never takes numbers from a neighbour.

### 10.2 Record types inside factory messages

| Types | Meaning | State |
|---|---|---|
| 0 | Not used | Fixed |
| 1 to 239 | Fields of the message, per its table; odd optional, even required to be understood | Specified per message |
| 240 | The signature, last | Specified |
| 241 and up | **Proposed:** never used in any factory message, signed or not, so that any message can gain a signature later without renumbering. No Slice 1 message uses them | Proposed |

Proposed split for new records in layer 2 messages: 2 to 63 for layer 2, 64 to 239 for application records (section 4.1). Existing numbers stay.

### 10.3 Terms record types

| Types | Outer record | Current record | Layer of today's types |
|---|---|---|---|
| 1 to 63 | Fixed terms and display text | Only 2 `outer_digest` and 4 `version` | 2: chain, host key, salt, profile, target, minimum, deadline, shortfall, windows and timeouts, switches. 3: shape table (24), lifetime (26), wind-down (28), `channel_sat` (30), tree fee rate (32) |
| 64 to 127 | Adjustable terms as ranges | Their values | 3: joining fee (64), base fee (66), proportional fee (68) |
| 128 and up | Invalid in draft 2 | Invalid | Reserved |

Reserved even types not valid in draft 2: 36 (share of seats for members who bring nothing), 38 (invitation only), 70 (chain-cost joining fee), 72 (fee for extra receiving room, 1.1.0). New types for channels, timed layers, payouts and deposits arrive with their releases.

### 10.4 Gazpacho journal record areas (internal, listed for completeness)

`u32` types, high 16 bits an area. Not part of the shared protocol.

| Area | Use | State |
|---|---|---|
| 0x0001 | Lobby | Specified |
| 0x0002 | Round | Specified |
| 0x0003 | Funding | Specified |
| 0x0004 | Node (key epochs, restore) | Specified |
| 0x0005 | Channel | Reserved |
| 0x0006 | Payment | Reserved |
| 0x0007 | Exit | Reserved |
| 0x0008 | Watch | Reserved |
| 0x0009 | Payout | Reserved |
| 0x000a | Sale | Reserved |
| 0x000b | Backup | Reserved |
| 0x000c | Discovery | Reserved |
| 0x7e57 | Test placeholder; goes with the placeholder | Temporary |

Journal entry kinds: 1 incarnation, 2 batch (`journal.md` 3).

### 10.5 Round purposes (`u8`, inside the round identifier)

| Code | Purpose | State |
|---|---|---|
| 1 | Creation | Specified |
| 2 | Leaf change; in 1.1.0 a sale that creates a new channel | Reserved |
| 3 | Layer update | Reserved |
| 4 | Cooperative close | Reserved |
| 5 | Rotation (moving to the next factory by closing into it) | Reserved |
| 6 | Recovery close after a restore (C12) | Proposed |
| 7 to 255 | Unallocated | Reserved |

### 10.6 Reason codes

| Registry | Codes in use | Proposed for new codes |
|---|---|---|
| `round_abort` reasons (`u16`) | 1 to 12 (`messages.md` 7.9) | 13 to 127 generic (layer 2); 128 to 255 operation-specific (layer 3); unknown read as "other" |
| `cancel` reasons | 1 to 3 | Next free number |
| `unready`, `leave` reasons | 1 to 2, 1 to 3 | Next free number |
| Lobby states, seat states (`u8`) | 0 to 7 each | Next free number |

### 10.7 bLIP-56 numbers used by the adapter (not ours)

| Number | Meaning |
|---|---|
| Type 32800 | `factory_message_id` |
| Submessages 2, 4, 6, 8, 10, 12, 14 | `supported_factory_protocols`, `factory_piggyback`, `factory_change_init`, `factory_change_ack`, `factory_change_funding`, `factory_change_continue`, `factory_change_locked` |
| TLV 0, 512, 1024, 1536, 2560, 3072, 3584 | Protocol id, supported ids, piggyback payload, change, change funding, continue, locked |
| `open_channel` TLV 65600 | `channel_in_factory` |
| Bits 270/271 | `pluggable_channel_factories` |

All are reserved only in the open bLIP-56 pull request, not in the merged registry (`messages.md` 10.5 item 5).

## 11. To agree with the SuperScalar session

These change bytes in every signed vector, so they are done once, together, with new vectors, before any stage beyond A ships. Slice 1 keeps today's values until then.

| Item | Today | To agree |
|---|---|---|
| Protocol name and id string | **Decided (owner, 2026-11-12):** `factory_protocol_id = SHA256("SuperScalar/1")` = `c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1` (`messages.md` 10.3) | Nothing left to agree on the id. superscalar-cln currently uses a different value and will be updated |
| Member placement | **Gazpacho uses sequential placement** (the import's value 0, no timezone buckets), for privacy: placement reveals nothing about members (owner, 2026-11-12; `signing-round.md` 4.1) | That the reference's placement setter offers value 0 |
| The 4-byte `protocol` value | `67 7a 66 01` ("gzf", 1) | Keep, or a neutral value. Whether signatures cover the 32-byte id instead (review 3, F28: neutral for security; decide with the rename) |
| Tag prefix | `gazpacho/` | A shared prefix for every tag in section 8.2, renamed in one change. The terms digests, and so every lobby identifier, change with it |
| Numbering | Type 52791; kinds, records, purposes, reasons as section 10 | That this map's ranges are the shared registry, and who keeps it |
| Payload format | Gazpacho's envelope | Whether the reference adopts it in place of its own private format (about 100 message types) |
| Tree build rules | The import's behaviour written out (`terms.md` 4) | That the reference's builder is the source of tree vectors, and the requests already sent (placement setter, layer-counter bound, mirror hashes, split by subtree size, payout destination per member, caller-supplied channel script) |
| End-date payouts | Not specified | Their design, which belongs to the reference |
| `factory_instance_id` | Open | Lobby identifier, or a digest of the funding outpoint |
| Our feature bit | Candidate 448/449 (`discovery.md` 3), unregistered | One pair for both implementations (section 8.3) |

## 12. Needs a public proposal (owner only)

Nothing below is to be posted, opened or commented on without the owner. Drafts stay local.

| Proposal | Where it would go | What it would say |
|---|---|---|
| Register custom type 52791 | bLIP 2 registry | That the type is taken |
| Our feature bit | bLIP 2 registry, by a bLIP | Its meaning (section 8.3) |
| bLIP-56 amendments | The bLIP-56 pull request | Taproot nonces for post-change outpoints and on reconnect; the plugin's duty before "forget a channel"; that multiparty rounds are the plugin's payload by design; the even type and its negotiation; a second `supported_factory_protocols`; the early warning time against the factory's exit time (`messages.md` 10.5) |
| The SuperScalar payload format | A bLIP of its own | Layers 1 to 3 of this map, once agreed with the reference |
| Discovery | A bLIP for the one bit and the onion payload types; a NIP for the listing kind | From `discovery.md` |
| Factories as a core part of Lightning | A BOLT | Stage D of section 3.1. The owner's long-term aim; not started |

## 13. Open points

1. **`transport.md`** does not exist yet; this map relies on `messages.md` section 2 until it does.
2. **Discovery** is specified in `discovery.md` draft 3 (section 7); its numbers are candidates and its open points are its section 22.
3. **The kind ranges of section 10.1** are this map's proposal. They keep every Slice 1 number and must be confirmed by the owner and agreed with the SuperScalar session.
4. **Records 241 and up** never used (10.2), and the 2 to 63 / 64 to 239 split for new records in layer 2 messages (4.1): proposed.
5. **Purpose 6** for a recovery close: proposed; the recovery procedure is not specified (C12).
6. **Factory scope after creation.** Later messages use the lobby identifier as `scope`, one lobby giving one factory. A move to the next factory opens a new lobby with its own terms, hence a new scope. To confirm when the move is specified.
7. **The peer storage messages and feature bit** were not re-read today; check BOLT 1 and BOLT 9 before the backup specification.
8. **Watchers.** No merged BOLT specifies watchtowers. The hand-off format is ours to write.
9. **A stand-alone `envelope.md`** and a layer 2 library specification separated from the SuperScalar profile: proposed, after Slice 1.
