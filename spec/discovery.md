# Discovery: finding hosts and their lobbies

Specification draft 1, 2026-11-12. Status: not reviewed. Written from `notes/discovery-research.md` (Part B, rule set B8) and the owner's decisions of 2026-11-12, including two later changes from the owner: the **lobby beacon** push layer is specified in full (section 8), and overlay links follow a **mix** rule (section 8.5). Items marked **(open)** are listed in section 18. Numbers marked **candidate** are reproducible random picks that are **not final**: section 2 says how each final number is chosen and checked.

Conventions (integers, `point`, `sig`, `outpoint`, `TH`, "refuse", "ignore") are those of `messages.md` section 1. TLV encoding is canonical as in `terms.md` section 2: minimal BigSize, strictly increasing types, fixed widths, unknown even types invalid, unknown odd types skipped but covered by any signature. Words: **host**, **member** as in `PROTOCOL.md`. **Listed** lobby: a lobby the host chooses to make public. Circle lobbies (profile 4) are never listed.

## 1. The design in one table

The owner's decisions, which this document specifies:

1. Gossip says only **who hosts**: two odd feature bits and an optional static host card. No per-lobby data ever goes through BOLT 7 gossip.
2. Live lobbies are **asked for**, never flooded: terms come only as a signed listing, in answer to a query.
3. The **lobby beacon** is the one push: a ~150-byte signed note "this host has a new lobby open", with no terms, relayed among factory-capable nodes only.
4. **Collecting** other hosts' lobbies is off by default.
5. **Nostr** is an optional annex for light clients.

| Layer | What | Carrier | Changes | Section |
|---|---|---|---|---|
| Capability | `factory_capable` (every Gazpacho node), `factory_host` (hosts only) | Odd feature bits in `init` and `node_announcement` | Rarely | 3 |
| Host card | Protocol id, channel sizes, usual schedule, profiles, name | Optional `node_announcement` TLV; the same bytes in query answers and on Nostr | At most once a day | 4 |
| Listing | One signed record per lobby: the outer terms record plus host key, start height, expiry, optional anchor, signature | Query answers; Nostr. **Identical bytes on every carrier** | Once per lobby | 5 |
| Queries | `lobby_index_request`/`lobby_index`, `listing_request`/`listing` | Onion messages with a blinded reply path; native messages as fallback | Per question | 6 |
| Host list | `host_list_request`/`host_list` from a trusted full node | Native; onion | Rarely | 7 |
| Beacon | "Host H has opened lobby L, until height d" | Native message among factory-capable overlay peers | Per lobby | 8 |
| Anchors | A channel or a coin backing a listing | Inside a listing or card | While unspent | 9 |
| Live state, joining, signing | `terms_offer`, `lobby_status`, `join`, rounds | Direct BOLT 8 connection only | Often | `messages.md` 6, 7 |

**What protects a member is unchanged.** Nothing found through discovery is trusted. A member joins with `hello` whose `scope` is the listing's `outer_digest`; the `terms_offer` it gets is checked by `terms.md` section 7 in full, and the tree is checked at signing (`safety-rule.md` C8). Discovery can waste a query; it cannot cost money.

## 2. Numbers: how each is chosen and checked

Every number here is a candidate printed by `tools/spec-vectors.py` (vector D0). None is final. A final number is chosen **on the day it is first used outside a private test**, by the procedure below, and the check and its date are written into `PROTOCOL.md` section 8.3 or 10.

| Item | Candidate | Range rule | Checks before it is final |
|---|---|---|---|
| `factory_capable` bit pair | **448/449** (advertise 449) | 256 to 511, from one pick `SHA256("gazpacho feature bits")`; the two pairs adjacent. Below 512 keeps the feature field at most 64 bytes (bit 451 gives 57; LSPS's 729 gives 92) | (a) bLIP 2 feature-bit table as merged; (b) every open pull request in lightning/bolts and lightning/blips (bLIP-56's 270/271 among them); (c) known unregistered uses in LND (`lnwire/features.go`), Core Lightning (`common/features.h`), Eclair (`Features.scala`), LDK (`features.rs`); (d) the experimental "+100" copies of pending bits. Next candidates if taken: 452 to 455, 456 to 459 |
| `factory_host` bit pair | **450/451** (advertise 451) | Same pick | Same |
| Card TLV type in `node_announcement` | **118685** | Odd, above 65,536 (bLIP 2's range for TLVs a bLIP adds to BOLT messages) | bLIP 2 table; bolts#1153 (type 5); CLN's type 1; Eclair's 1339; open pull requests |
| Onion payload types | **106369, 106371, 106373, 106375, 106377, 106379** | Odd, one block of 64 above 65,600 | bLIP 2 onion-message table (bLIP-32 has 65536, 65538, 65550); BOLT 12's payload types; open pull requests; LDK, CLN, Eclair, LND handlers |
| Native kinds | **129 to 143, odd** (section 6.3) | `PROTOCOL.md` 10.1 range 128 to 159 | None outside this project: kinds live inside type 52791 |
| Nostr kinds | **31867** (listing), **37329** (card) | Addressable, 30000 to 39999 | The NIPs repository kind table on the day; known uses Soup 38099 and 38101, NIP-69 38383 to 38389, publsp 39735, NIP-29 39000 to 39009, NIP-51 30000 to 30030 and the others listed in the tool (recalled, **not verified today**) |
| Tags | `gazpacho/listing`, `gazpacho/index`, `gazpacho/card`, `gazpacho/anchor`, `gazpacho/beacon` | `PROTOCOL.md` 8.2 | Registered there before use |

Until a number is registered (only through a public proposal, which only the owner can authorise), it is used **only on signet** and only by builds that say it is unregistered.

### 2.1 Reconciling the research's kinds with the map

The research draft (B8, D4 F1, D7, D9) proposed native kinds 35 to 41 (relay) and 43 to 53 (queries, host list). Those numbers lie in `PROTOCOL.md`'s session range 16 to 63, whose free part 35 to 63 is **reserved for session additions** (invitations, identity proofs, chat, standby seats). `PROTOCOL.md` did **not** reserve 43 to 49 for discovery; it reserved **128 to 159**. This document therefore uses 128 to 159 and leaves 35 to 63 to the session family. The research's numbers are not used anywhere.

## 3. Feature bits

| Name | Pair (candidate) | Bit sent | Contexts | Who sets it | Meaning |
|---|---|---|---|---|---|
| `factory_capable` | 448/449 | **449, odd** | `init`, `node_announcement` | Every Gazpacho node, member or host | Speaks the SuperScalar factory protocol natively on type 52791 (`PROTOCOL.md` 3.1, stage C); answers or relays discovery messages as section 8 says |
| `factory_host` | 450/451 | **451, odd** | `init`, `node_announcement` | Hosts only | Offers listed lobbies; answers the queries of section 6 |

Rules:

1. A node that sets `factory_host` MUST set `factory_capable`. A reader that sees `factory_host` without `factory_capable` ignores both.
2. A member MUST NOT set `factory_host` (LSPS's bit 729 has the same rule). Hosting is a separate thing a person turns on (owner decision 4: anyone may host; the bit follows what the node does, not who the person is).
3. A node that sets `factory_host` MUST answer section 6 queries over a direct connection, and by onion message if it also sets `option_onion_messages` (38/39).
4. Nothing that touches money depends on a bit. A wrong bit costs a wasted connection.
5. A node with no announced channel has no `node_announcement`; it sets the bits in `init` only.

### 3.1 Why both bits must be odd

Read from BOLT 7 on 2026-11-12:

- Its rationale says `node_announcement` feature bits "will be propagated normally". So ordinary Lightning nodes relay announcements that carry bits they do not know. This is how factory-capable nodes **find each other through the plain network**, with nobody else needing to understand the bits (section 8.5).
- But for an unknown **even** bit in `node_announcement`, a receiver "SHOULD NOT connect to the node" and "MUST NOT route a payment through the node".

So an even bit would cut a host off from the network. **Both bits are advertised odd** (449, 451) until a merged standard makes them universally understood. The even halves (448, 450) are kept so the pairs follow BOLT 9, and are never set.

## 4. The host card

Optional. Static and **advisory**: never terms.

### 4.1 Contents

A TLV stream, canonical, **at most 256 bytes**.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `protocol_id` | 32 | The factory protocol: `SHA256("SuperScalar/1")` (`messages.md` 10.3, open) |
| 4 | `card_height` | `u32` | Block height when this card was made. Section 4.3 |
| 6 | `channel_range` | 16 | Smallest and largest `channel_sat` the host usually offers, `u64` each; smallest ≤ largest |
| 8 | `schedule` | 4 | Usual lobby opening in minutes after 00:00 UTC (`u16`, 0 to 1,439) and cadence in hours (`u16`, 1 to 720); both `0xFFFF` = irregular |
| 10 | `profiles` | `u8` | Bitmap of profiles the host lists: bit 0 Safety, bit 1 Standard, bit 2 Starter. Bit 3 (Circle) and bits 4 to 7 must be 0 |
| 11 | `name` | 1 to 32 | UTF-8, display only |

All even fields are required. A card with an unknown even type is ignored as a card; the announcement carrying it is not affected.

### 4.2 Where it travels

| Carrier | Form | Signed by |
|---|---|---|
| `node_announcement` | One TLV record of type **118685** (candidate) appended after `addresses`, value = the card | The announcement's own signature, which covers appended fields (BOLT 7) |
| `lobby_index` (6.2) | Record 10 of the index, value = the card | `index_sig` |
| Nostr, `host_list` | The **signed card** (4.4) | `card_sig` |

The card bytes (types 2 to 11) are identical in all three.

**Honest caveat.** `node_announcement` has **no TLV stream in the BOLTs**; BOLT 7 only says fields may be added in future, and lets a receiver decline to queue an announcement longer than expected. CLN and Eclair already append TLVs of their own; LDK relays at most 1,024 unknown extra bytes and its Rapid Gossip Sync drops them; whether every implementation relays unknown appended bytes is **not verified**. So the card in gossip is **best-effort**. **The bit is what is relied on.** The card must always also be obtainable from `lobby_index` and, where the host publishes there, from Nostr.

### 4.3 Change rate

- A host SHOULD NOT change its card more than once in 24 hours (LSPS1's `get_info` rule). Any change in gossip is a new `node_announcement`, so it is also subject to that message's own rate limits and pruning.
- A reader keeps the card with the highest `card_height` it has accepted for a host. It **ignores** a card whose `card_height` is less than 144 above the one it holds, unless the bytes are identical. So the once-a-day rule is checkable by any reader, on every carrier.
- `card_height` more than 6 above the reader's tip: ignore.

### 4.4 The signed card

Off gossip, the card is wrapped so it can be checked without the announcement.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | |
| 4 | `host_key` | 33 | The host's node key |
| 6 | `card` | 1 to 256 | Section 4.1 |
| 8 | `anchor` | 1 to 600 | Section 9. **Required on Nostr**; optional elsewhere |
| 240 | `card_sig` | 64 | BIP 340 by `host_key` over `TH("gazpacho/card", every byte before record 240)` |

At most 1,000 bytes.

## 5. The listing

### 5.1 Record

Exactly the outer terms record plus host key, start height, expiry, optional anchor and signature. A TLV stream, canonical.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_key` | 33 | Equals the outer record's `host_key` (`terms.md` type 4) |
| 4 | `outer` | 1 to 4,096 | The outer terms record, byte for byte what `terms_offer` carries |
| 6 | `start_height` | `u32` | The height from which the listing is valid |
| 8 | `expiry_height` | `u32` | `start_height` ≤ `expiry_height` ≤ `start_height` + 1,008 |
| 10 | `anchor` | 1 to 600 | Optional. Section 9. Required on Nostr |
| 240 | `listing_sig` | 64 | BIP 340 by `host_key` over `listing_digest = TH("gazpacho/listing", every byte before record 240)` |

- **Size:** at most **4,817 bytes**, the sum of every record's maximum (vector D4). Draft 1 defines no odd records; unknown odd records are skipped, covered by the signature and counted in the limit.
- **No chain field:** the chain is the outer record's type 2.
- **`listing_id`** is the `outer_digest`. It names the lobby; `listing_digest` names one signed version of its listing.
- **No `outer_sig`:** `listing_sig` already commits to the outer bytes under its own tag. The `outer_sig` arrives in `terms_offer` before the member joins (open point 3).
- **One listing, every carrier.** A host makes one listing per listed lobby and serves those bytes in `listing` answers (onion and native), on Nostr and through any later carrier. If it publishes on Nostr, that listing has an anchor, and the same anchored bytes are what queries return.
- **Live** while the reader's tip is below `expiry_height` and the reader's clock is before the outer `deadline`.
- **Withdrawal:** the same listing re-signed with `expiry_height` = `start_height`. A host may shorten a listing, never lengthen it (rule L6).

### 5.2 What a reader checks

In this order. Any failure: drop the listing, never show or forward it.

| Rule | Check |
|---|---|
| L1 | It decodes canonically within 4,817 bytes; records 2, 4, 6, 8 and 240 present |
| L2 | `outer` decodes under `terms.md` section 2 and passes `terms.md` section 7 steps 4 and 5 (chain, every bound, the shape check). Step 3's pinned-key check is replaced by L3; steps 6 to 8 concern the current record, which a listing does not carry |
| L3 | `host_key` equals the outer record's `host_key`; `listing_sig` verifies under it |
| L4 | `start_height` ≤ tip + 6; `start_height` ≤ `expiry_height` ≤ `start_height` + 1,008; live (5.1) |
| L5 | If `anchor` is present it passes section 9; if the carrier requires one (Nostr) it is present |
| L6 | Two valid listings with the same `listing_id` and different bytes: keep the one with the smaller `expiry_height`; on a tie, the smaller `listing_digest` |
| L7 | At most 4 live listings per `host_key` (rule A4); on Nostr, at most the anchor's allowance (A3). Over a cap, keep the earliest `start_height`, ties by smaller `listing_id` (A5) |
| L8 | Local policy may drop more, never accept more (A7) |

Then the listing is shown, compared with the member's conditions by `terms.md` section 9 on its outer record (ranges are compared whole; current values are not known yet), and nothing in it is trusted.

## 6. Queries

Four messages. **The record bytes are the same on both carriers.** Answers carry signed records, so the messages themselves are unsigned, as `terms_offer` is.

### 6.1 Records

**`lobby_index_request`**, asker → host:

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 3 | `profiles` | `u8` | No. Bitmap as in 4.1; the host lists only those profiles |

**`lobby_index`**, host → asker: one record, type 2 `index` (1 to 640 bytes), the signed **index record**:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | Equals the request's |
| 4 | `host_key` | 33 | The host's node key |
| 6 | `as_of_height` | `u32` | The host's tip when answering |
| 8 | `entries` | 0 to 196 | 0 to 4 entries of 49 bytes: `outer_digest` (32), `deadline` (`u64`, Unix seconds), `profile` (`u8`), `channel_sat` (`u64`). Distinct digests, in increasing `outer_digest` order. Values copied from the outer record |
| 10 | `card` | 1 to 256 | Optional. The host card (4.1) |
| 240 | `index_sig` | 64 | BIP 340 by `host_key` over `TH("gazpacho/index", every byte before record 240)` |

An empty `entries` record (length 0) means "no listed lobby now".

**`listing_request`**, asker → host:

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 4 | `outer_digest` | 32 | Yes |

**`listing`**, host → asker: exactly one of

| Type | Field | Size | Meaning |
|---|---|---|---|
| 2 | `listing` | 1 to 4,817 | The listing record (section 5) |
| 4 | `unknown` | 32 | The requested `outer_digest`: no such listed lobby |

### 6.2 Onion carrier (preferred)

| Rule | Text |
|---|---|
| O1 | Each message is a BOLT 4 onion message whose final hop's `onionmsg_tlv` holds exactly one payload field: type `lobby_index_request` 106369, `lobby_index` 106371, `listing_request` 106373, `listing` 106375 (candidates), value = the records of 6.1. BOLT 4: a message with more than one payload field is ignored |
| O2 | A request MUST carry `reply_path`. The asker puts its own `path_id` in its blinded path and accepts only an answer that arrives along that path with that `path_id` (BOLT 4: replies not using the exact path are ignored, against probing). The host MUST answer along `reply_path` only |
| O3 | Requests SHOULD be 1,366-byte onions. `lobby_index` (records at most 645 bytes) SHOULD fit 1,366; `listing` uses 32,834 bytes. Larger onions reduce the anonymity set (BOLT 4) |
| O4 | The asker SHOULD use a first hop other than the host, and a fresh reply path per request. Through the host itself the query hides nothing |
| O5 | To reach a host in gossip, route to its node key. A host not in gossip is reached by a blinded contact from an invitation (11.1) |
| O6 | Onion messages are unreliable. No answer in 30 s: retry once through another first hop, then fall back to 6.3 |
| O7 | The first hop must accept onion messages from the asker. LND by default drops them from peers without a fully open channel; CLN, Eclair and LDK accept them by default. A new user with no channel picks such a node or falls back to 6.3 |

### 6.3 Native carrier (fallback)

The same records in an ordinary type-52791 envelope (`messages.md` 4), with **`scope` all zero**.

| Kind | Name | From → to |
|---|---|---|
| 129 | `lobby_index_request` | asker → host |
| 131 | `lobby_index` | host → asker |
| 133 | `listing_request` | asker → host |
| 135 | `listing` | host → asker |
| 137 | `host_list_request` | asker → trusted node (7) |
| 139 | `host_list` | trusted node → asker (7) |
| 141 | `lobby_beacon` | factory-capable node → factory-capable node (8) |
| 143 | `beacon_filter` | factory-capable node → factory-capable node (8) |
| 145 to 159 odd | Reserved for discovery | |
| 128 to 158 even | Not used. Discovery must be safe to send to anyone and safe to ignore | |

Every discovery kind is **odd**: a node that does not know it ignores it and keeps the connection. A kind sent in the wrong direction is ignored, not refused (discovery is never worth a disconnect).

| Rule | Text |
|---|---|
| F1 | `hello` with scope zero stays as `messages.md` 6.1 specifies, returning `terms_offer`s; but it MUST list only listed lobbies, at most 4 (section 15) |
| F2 | The asker SHOULD use a fresh BOLT 8 key per query session (not a seat key) and SHOULD connect over Tor where available. Without Tor the host learns the asker's address |
| F3 | No answer in 30 s: give up on that host for 10 minutes |

### 6.4 Host rules (both carriers)

| Rule | Text |
|---|---|
| H1 | Answers list only the host's own **listed** lobbies in state Open, at most 4. Unlisted lobbies never appear. A started or cancelled lobby is withdrawn (5.1) and dropped from the index |
| H2 | Per source, at most 1 `lobby_index_request` and 4 `listing_request`s per 10 s; at most 50 queries per second in total. Beyond that, drop silently (BOLT 4 allows dropping). The source is the incoming peer for onion messages and the connection for native ones |
| H3 | The host MUST NOT answer differently depending on who asks, beyond refusing. (Detectable by comparing with Nostr or another asker) |
| H4 | `lobby_index` and `listing` answers carry the signed records, so they can be relayed or shown later without trusting the carrier |
| H5 | A host never sends `lobby_index` or `listing` unasked. Its lobbies reach others only as answers and as beacons (8) |
| H6 | A request whose `chain` is not the host's: ignored |

### 6.5 Asker rules

| Rule | Text |
|---|---|
| Q1 | `lobby_index`: the index decodes canonically within 640 bytes; `chain` equals the request's; `host_key` equals the node queried (onion: the node routed to, or the key named with the blinded contact; native: the connection's BOLT 8 key); `index_sig` verifies; `as_of_height` within 6 blocks of the asker's tip; entries as in 6.1. Otherwise drop |
| Q2 | Index entries are **hints**. The asker fetches a listing before showing anything as a lobby |
| Q3 | A card inside the index is accepted under 4.3; a bad card is dropped alone |
| Q4 | `listing`: exactly one of records 2 or 4. A listing passes 5.2 and its `outer_digest` equals the one requested and its `host_key` the host queried. `unknown` with another digest: drop |
| Q5 | Answers not asked for, or after 30 s: drop |

## 7. Host list from a trusted full node (optional)

For a light client whose own node, or current host, holds the gossip graph.

**`host_list_request`**: 2 `chain` (32, required); 3 `skip` (`u16`, optional, entries to skip for paging).

**`host_list`**: 2 `chain`; 4 `entries`, 0 to 64 entries, each `u16` length, a `node_announcement` exactly as gossiped (its 2-byte type included) that sets `factory_host`, `u16` length, and one `channel_announcement` exactly as gossiped in which that node is `node_id_1` or `node_id_2`; 5 `more` (`u8` 1, optional: further entries exist). At most 60,000 bytes natively, at most 30,000 bytes by onion message (payload type 106379, request 106377, candidates).

- **Hidden, never forged.** Every entry carries gossip's own signatures and a chain anchor. The answering node can leave hosts out; it cannot invent one.
- Asker checks per entry: the `node_announcement` signature (BOLT 7); bits 449 and 451 set; the `channel_announcement`'s four signatures; the node is one of its two nodes; then the channel as an anchor (section 9, type 2). A failed entry is dropped, the rest kept.
- Rates: an answering node answers at most 1 request per 10 s per source.
- Never automatic: a wallet asks only a node its user named.

## 8. The lobby beacon

The one push. It says only "**this host has a new lobby open**". No terms, no fill level, no seats.

### 8.1 Record

`lobby_beacon` (kind 141), records:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_id` | 33 | The host's node key (= `host_key`, = its BOLT 8 key) |
| 4 | `outer_digest` | 32 | The lobby's identifier |
| 6 | `open_height` | `u32` | Height at which the lobby opened |
| 8 | `deadline_height` | `u32` | `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008. The beacon expires here |
| 10 | `sequence` | `u32` | Per host, strictly increasing over all its beacons |
| 240 | `beacon_sig` | 64 | BIP 340 by `host_id` over `beacon_id = TH("gazpacho/beacon", every byte before record 240)` |

153 bytes of records (vector D7); 193 bytes as a Lightning message. No other records are defined; any extra record, odd included, makes the beacon invalid (a beacon is relayed, so it must not carry padding).

- `beacon_id` is also the deduplication key. It is a digest of the content, so two signatures over one content are one beacon.
- **Withdrawal:** a beacon with the same `outer_digest`, a higher `sequence`, and `deadline_height` = `open_height`. It replaces the old one and expires at once; relays forward it so the withdrawal spreads.
- The beacon's `deadline_height` is the host's estimate of the outer `deadline` (Unix seconds). The listing's own liveness rule (5.1) decides; the beacon is only a pointer.

### 8.2 Who sends and who receives

- Only a node that sets `factory_host` originates beacons, one per newly opened **listed** lobby, at most one new beacon (new `sequence`) per hour. Withdrawals count.
- Beacons travel only between nodes whose `init` set `factory_capable`, over **overlay links** (8.5). A node never sends a beacon to a peer that did not set `factory_capable` in `init`. Ordinary Lightning nodes never see beacons: they are not overlay peers, and BOLT implementations do not relay unknown custom messages anyway.
- **Relayed by default.** Every factory-capable node **that holds a gossip graph** relays valid beacons to its overlay peers. A node without a graph does not relay.
- **Stored and acted on only by nodes that opt in** (the "collect lobbies" setting, off by default, section 10). A relay that has not opted in keeps beacons only in memory (8.6), fetches nothing, shows nothing, writes nothing to disk.

### 8.3 Acceptance rules

A relay runs these on every received beacon, in order. "Drop" means: do not store, do not relay, send nothing.

| Rule | Check | On failure |
|---|---|---|
| B1 | Records decode canonically; exactly records 2, 4, 6, 8, 10, 240 | Drop; counts as invalid (8.7) |
| B2 | `beacon_id` already in the seen-set (8.6) | Drop silently (duplicate) |
| B3 | `host_id` is in the receiver's gossip graph: it has a `node_announcement` tied to a known channel, and that announcement sets 449 and 451 | Drop silently; **not** invalid (graphs differ between nodes) |
| B4 | `beacon_sig` verifies under `host_id` | Drop; invalid |
| B5 | `open_height` ≤ tip + 6; `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008; `deadline_height` > tip, unless it is a withdrawal of a beacon held | Drop; invalid if the height bounds fail, silent if merely expired |
| B6 | `sequence` greater than the held beacon for the same (`host_id`, `outer_digest`), if any | Drop silently (older) |
| B7 | **Rate:** if `sequence` is greater than every sequence held or remembered for this host, it is a new beacon; accept at most one new beacon per host per **3,000 s** of the receiver's clock (hosts send at most one per 3,600 s; the margin absorbs clock and propagation differences) | Drop silently |
| B8 | **Active cap:** at most 4 active beacons per host. A fifth: keep the 4 with the highest `sequence`; if the newcomer is the lowest, drop it | Evict or drop silently |

Then: add `beacon_id` to the seen-set, hold the beacon, and queue it for relay (8.4). A beacon that replaces another (B6) replaces it in the held set.

### 8.4 Relay

- Queued beacons are flushed every 60 s (gossip's pace), to every overlay peer whose `beacon_filter` matches (section 10), except the peer it came from.
- A host sends its **own** beacons to its overlay peers at once, whether or not they have sent a filter (BOLT 7 sends a node's own gossip regardless of filters).
- Per peer, a node sends at most 50 beacons per minute and accepts at most 50 per minute; more are dropped.
- After a filter arrives, the node sends the held beacons that match it (the backlog), then new ones as they come.

### 8.5 The overlay

Each factory-capable node with a gossip graph keeps **4 to 8 outbound overlay links** to other factory-capable nodes, plus its ordinary Lightning peers. It accepts at most 16 inbound overlay links. Overlay links are plain BOLT 8 connections, usually without a channel.

**Bootstrap.** Candidates are read from the gossip graph: announced nodes whose `node_announcement` sets bit 449 and lists a reachable address. Ordinary nodes relay those announcements without understanding the bit (section 3.1), so factory-capable nodes find each other through the plain network.

**Mix** (eclipse resistance, as Bitcoin Core spreads outbound peers across network groups; and keeping hosts from silencing rivals):

| Rule | Text | Why |
|---|---|---|
| X1 | At least half of the outbound overlay links go to factory-capable nodes that do **not** set `factory_host` (member nodes) | Members have no reason to filter rival hosts' beacons. A host could quietly drop a competitor's beacon; a relay mostly made of hosts would let a few large hosts censor the rest |
| X2 | At most 2 links go to nodes that set `factory_host` | Same |
| X3 | At most 2 links within one /16 IPv4 range, one /32 IPv6 range, or the Tor-only group (all nodes announcing only Tor addresses count as one group) | An attacker who controls one address range cannot take every link (Bitcoin Core's netgroup rule) |
| X4 | Choose at random among the candidates that keep X1 to X3 | No one can predict the links |
| X5 | Every 4 hours, re-read the graph: replace any link that now breaks X1 to X3, and replace one link chosen at random | Rotation limits a slow eclipse |
| X6 | A link that fails the keep-alive (`messages.md` 2) or closes is replaced at once. A link that forwarded no beacon for 24 hours while other links did is replaced | Silent links are replaced |
| X7 | If too few candidates exist to keep the mix, fill with what exists, keep trying at each refresh, and never drop below the links already held to fill a rule | Early on there are few capable nodes |

Overlay links carry only discovery messages and keep-alive. They never carry lobby or round messages.

### 8.6 Seen-set and held set

- **Seen-set:** the `beacon_id`s accepted, each with its `deadline_height`, for deduplication. Size: `min(65,536, max(1,024, 8 × H))` entries, where H is the number of nodes in the receiver's graph that set 451. Eight per host covers the 4 active beacons plus the replaced ones within a lifetime, at one new beacon per hour (B7 and B8 bound what can be accepted). An entry leaves at its `deadline_height`, or, when full, oldest first. 40 bytes per entry: at most 2.6 MB (vector D10).
- **Held set:** the active beacons, at most 4 per host, 153 bytes each: at most 4 × H × 153 bytes (612 KB for 1,000 hosts).
- A node also remembers, per host, the highest `sequence` seen and the time of the last new beacon (for B6 and B7), until 1,008 blocks after that beacon's `deadline_height`.

### 8.7 Misbehaving peers

- Invalid beacons (B1, B4, B5 height bounds) from one peer: after 10 in any 10 minutes, close the overlay link and do not pick that peer for 24 hours.
- A peer that sends beacons without having set `factory_capable`: ignore them.
- B3, B6, B7 and B8 drops are never held against a peer: they come from honest differences in graphs and timing.

### 8.8 What an interested node does

A node that has opted in (section 10) and receives a beacon that passed 8.3:

1. Waits a random 0 to 120 s, so a new lobby does not draw every collector at the same second.
2. Asks the host `listing_request(outer_digest)`, by onion message (6.2) or natively (6.3). At most one query per beacon; the host's H2 limits still apply.
3. Accepts the answer under 6.5 Q4 and 5.2; the listing's `host_key` must equal `host_id` and its `listing_id` the beacon's `outer_digest`.
4. Stores the listing until its `expiry_height` or the outer `deadline`, whichever comes first, within its local budget (A7). A later withdrawal beacon removes it.
5. A host that does not answer: the beacon is kept until it expires; nothing is shown.

## 9. Anchors and caps

An anchor is a chain-backed proof that makes spam cost locked coins. It replaces the coordinator of soup-rendezvous: each wallet checks it through a chain server.

### 9.1 Encoding

The `anchor` value is a TLV stream with exactly one kind:

| Type | Field | Size | Kind |
|---|---|---|---|
| 2 | `channel_announcement` | 1 to 600 | Channel: a full BOLT 7 `channel_announcement` without its 2-byte type, in which `host_key` is `node_id_1` or `node_id_2` |
| 4 | `coin_outpoint` | 36 | Coin |
| 6 | `coin_valid_until` | `u32` | Coin: last height at which the statement holds |
| 8 | `coin_sig` | 64 | Coin: BIP 340 by the output key Q over `TH("gazpacho/anchor", chain ‖ host_key ‖ coin_outpoint ‖ u32 coin_valid_until)` |

A coin anchor has records 4, 6 and 8; a channel anchor record 2 alone. Anything else is invalid. Draft 1 accepts coin anchors only on P2TR key-path outputs (script `5120 ‖ Q`), so Q is read from the chain and no key field is needed. Other script types (BIP 322) are open point 6. Naming `host_key` in the coin statement means nobody can borrow another host's coin.

### 9.2 Checks

| Rule | Check |
|---|---|
| A1 | Channel: four signatures; then through a chain server: `short_channel_id` → txid (Electrum `blockchain.transaction.id_from_pos`, or Esplora `/block-height/:h` then `/block/:hash/txid/:i`); the output is the P2WSH 2-of-2 of the two bitcoin keys; unspent (Esplora `/tx/:txid/outspend/:vout`); at least 6 confirmations. A full node may check its graph instead. Value V = half the output's value (half for each node). Coin: `coin_sig` verifies under the output's Q; unspent; at least 6 confirmations; `coin_valid_until` ≥ the backed listing's `expiry_height` and > tip. Value V = the output's value |
| A2 | A failed anchor drops the listing or card. "Unspent" is re-checked before showing a listing whose anchor was last checked more than 144 blocks ago; results are cached for 144 blocks |
| A3 | **Allowance** per anchor: 0 if V < `unit` / 4; otherwise `min(4, max(1, floor(V / unit)))` live listings. `unit` is 1,000,000 sat on mainnet, 10,000 on signet (minimum anchor 250,000 and 2,500). The research's formula `min(4, floor(V / unit))` gave 0 at its own minimum anchor; the `max(1, …)` reconciles it with "one listing per unit, minimum a quarter unit" |
| A4 | At most **4 live listings per `host_key`**, on every path |
| A5 | Over A3 or A4: keep the earliest `start_height`, ties by smaller `listing_id`; drop the rest |
| A6 | One anchor, one host. Two `host_key`s presenting the same anchor while both listings are live: drop both |
| A7 | **Relays and wallets may only tighten** A3 and A4: a budget, ranking by weight `V × min(confirmations, 1,008) / 1,008`, and when full a rolling minimum (drop the lowest weight; refuse below 1.1 × it; the minimum halves every 12 hours, as Bitcoin Core's mempool minimum fee does). They never accept beyond A3 or A4 |

### 9.3 Where anchors are required

| Path | Anchor | Why |
|---|---|---|
| Bit and card in gossip | No | Gossip is the anchor: a node is in it only with a funded, announced channel |
| Beacons | No | B3: only from a node in the receiver's graph with the host bit |
| Query to a known host | Optional | The asker chose the host; H1 caps the answer at 4 |
| Invitation, QR, built-in list | No | The user chose the host |
| **Nostr** (listing and card) | **Required** | Anyone can publish anything there for free |

## 10. Subscription: nothing about others unless asked

Modelled on BOLT 7's `gossip_timestamp_filter`: a node sends no gossip it did not generate until the peer sends a filter; a new filter replaces the old; a filter matching nothing turns relaying off; a node's own gossip is sent regardless.

**`beacon_filter`** (kind 143), records, all required:

| Type | Field | Size |
|---|---|---|
| 2 | `chain` | 32 |
| 4 | `first_height` | `u32` |
| 6 | `height_range` | `u32` |

- A beacon matches if `first_height` ≤ `open_height` < `first_height` + `height_range` (computed without overflow).
- Before a peer's first filter, a node sends it **only its own** beacons. After it, the matching beacons.
- A new filter replaces the previous one. (`0xFFFFFFFF`, 0) means "send me nothing" (vector D10). At most one filter per minute per peer; more are ignored.
- **Relaying by default** means: a factory-capable node with a graph sends every overlay peer the filter (0, `0xFFFFFFFF`) when the link opens. A node that does not want to relay sends (`0xFFFFFFFF`, 0) and forwards nothing.
- **Collecting is separate and off by default.** The "collect lobbies" setting decides whether a node stores beacons beyond memory and acts on them (8.8), and whether a wallet subscribes to Nostr listings. The filter only governs what flows.
- In the core: **no node ever sends listings or lobby indexes about other hosts.** Only beacons, which carry no terms, are relayed.

## 11. Light clients

A light client has a chain server but no gossip graph. It finds hosts by any of these; none needs a coordinator.

| Path | How | What the client checks |
|---|---|---|
| Invitation or QR | `<host_key, 66 hex>@<address>:<port>` (`messages.md` 2), optionally followed by `#<outer_digest, 64 hex>` to name a lobby. A host not in gossip may give a blinded contact instead **(open, point 8)** | The handshake matches the key; then queries and `terms.md` 7 |
| Built-in list | Shipped per network: entries `host_key`, address, optional label. The user can add, remove and edit entries. Never changed remotely without the user's action | Same |
| Nostr | Section 13 | Listing (5.2), anchor (9) |
| Trusted full node | `host_list_request` to the user's own node or current host (7) | Gossip signatures and channel anchors: entries can be hidden but not forged |
| Beacons | A light client does not relay. It MAY receive beacons from one trusted node of its own (sending it a `beacon_filter`); it cannot run B3, so it checks B1, B4 to B8 and trusts that node for B3 | As 8.8 |

## 12. Privacy

| What | Who learns what | Advice |
|---|---|---|
| Onion query | The host learns that someone asked, not who. Lost if the first hop is the host | First hop other than the host; fresh reply path each time (O4) |
| Large onion answers | 32,834-byte onions have a smaller anonymity set | Requests and indexes in 1,366 bytes |
| Native query | The host learns the interest, and the address without Tor | Fresh BOLT 8 key per session; Tor (F2) |
| `factory_capable` in `init` | Every peer learns "this is a Gazpacho wallet" | Members use a fresh key per lobby and per query session, so the bit links nothing beyond one connection |
| `factory_capable` in `node_announcement` | The whole network learns the node runs Gazpacho | Only nodes that choose to be announced; needed for the overlay |
| Beacons | Relays learn which hosts open lobbies, which is public by design. They learn nothing about members | Beacons carry no terms and no counts |
| Anchor checks | The chain server learns which outpoints interested the wallet | Tor or the wallet's own server; cache 144 blocks |
| Coin anchor | Publishes one host coin and its value | Use a dedicated coin |
| Card name | Public | Display only; may be left out |
| Nostr reading | Nothing to the host; the relay sees the subscription | Tor; several relays |
| Answers | Never say who joined or how many (`messages.md` live state stays direct) | H3: same answer for everyone |

## 13. Nostr annex (informative, optional)

Validity never depends on Nostr. The annex fixes kinds and tags so wallets interoperate, as NIP-69 did for peer-to-peer orders.

**Listing event**, addressable, kind **31867** (candidate):

| Field | Value |
|---|---|
| `content` | Base64 (RFC 4648, with padding) of the listing record, **with an anchor** |
| `d` | `listing_id`, 64 lowercase hex |
| `expiration` (NIP-40) | Unix seconds: the smaller of the outer `deadline` and publish time + (`expiry_height` − tip at publishing) × 600 |
| `L` / `l` (NIP-32 labels, namespace `gazpacho`) | `["L","gazpacho"]`, `["l","<network>","gazpacho"]` with `signet` or `mainnet`, `["l","<profile>","gazpacho"]` with `safety`, `standard` or `starter`, `["l","anchor-coin" or "anchor-channel","gazpacho"]` |
| `host` | `host_key`, 66 hex (not indexed by relays; for clients) |

**Host card event**, addressable, kind **37329** (candidate): `content` = base64 of the signed card (4.4) **with an anchor**; `d` = `host_key` hex; labels as above without profile; `expiration` = publish time + 30 days. Republished when the card changes, at most daily.

Rules:

- **Any Nostr key may publish either event.** Readers MUST verify the inner record and its anchor and MUST ignore the Nostr author for validity. The same listing from several authors is one listing (`listing_id`, then L6).
- **Expiry:** relays and clients SHOULD drop expired events (NIP-40 is not a guarantee); readers also apply L4 themselves.
- **Withdrawal:** publish the withdrawal listing (5.1) under the same `d`; it replaces the event, and L6 makes it win wherever both are seen.
- **Caps:** A3 to A7 in full. A relay or wallet may tighten, never loosen.
- Kinds and labels are not registered; a NIP is a public proposal for the owner to decide.

## 14. Slice and release

| Item | Signet demo (first) | Next, before mainnet | Later |
|---|---|---|---|
| Join by link or QR | Yes | | |
| Built-in, editable host list | Yes | | |
| Feature bits (candidates, unregistered) | Yes: every Gazpacho node sets 449; the demo host sets 451 | | Final numbers, registered by a bLIP (owner) |
| Host card | On the demo host, in `node_announcement` and `lobby_index` | | |
| Direct (native) queries, kinds 129 to 135 | **Yes, primary** | | |
| Onion-message queries (6.2) | No: needs Sphinx onions, route blinding and reply paths in the core, unless the host runs inside a node that has them | **Yes** | |
| Lobby beacon and overlay (8, 10) | No | **Yes** | |
| Nostr listings and cards, with coin anchors (signet unit 10,000 sat) | Yes, read and publish | | NIP (owner) |
| Channel anchors | Optional (signet demo hosts may have no public channel) | Yes | Taproot channels when taproot gossip merges |
| `host_list_request` from a trusted node | No | No | Yes |
| Collecting other hosts' lobbies | Off; not offered | Offered, off by default | |

Bits and queries come first because they are small and change nothing for anyone else. The beacon and overlay come next: they need enough factory-capable nodes in the graph to be useful. Nostr stays in the demo as the light-client path, as the research planned.

## 15. Changes this needs in other documents (not made here)

| Document | Change |
|---|---|
| `messages.md` 4 | `scope` all zero "only in `hello`" becomes "in `hello` and in discovery kinds 128 to 159" |
| `messages.md` 6.1 | Scope-zero `hello` lists only **listed** lobbies, at most 4 (H1), instead of every open lobby up to 16 |
| `messages.md` 2 and open point 1 | Answered: a bit of our own is needed, two in fact (section 3); members set 449 in `init` |
| `LOBBY.md` "What is public" | Gains the beacon, the onion query, the card and anchors |
| `terms.md` open point 7 | Answered: the listing carries the same bytes (5.1) |

## 16. Test vectors

Computed by `tools/spec-vectors.py` (run with `python -I tools/spec-vectors.py`). Test keys as `terms.md` section 11; the extra test keys are `host coin` and `other host`. **Never use them for coins.** Auxiliary randomness 32 zero bytes. Every vector depends on T1's `outer_digest` `75e970b6…f0a424f2`, signet, tip 290,000, and on the candidate numbers of D0: a change of either changes the bytes, and the vectors are regenerated.

**D0. Candidates** (section 2): bits 448/449 and 450/451 (features field with bit 451: 57 bytes); onion types 106369 to 106379 odd; card TLV 118685; Nostr kinds 31867, 37329.

**D1. Host card** of the test host: protocol id `SHA256("SuperScalar/1")`, `card_height` 290,000, channel range 100,000 to 100,000, schedule 00:00 every 24 h, profiles Standard, name "Gazpacho test host".

```
card, 87 bytes:
0220c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c8
42f1040400046cd0061000000000000186a000000000000186a0080400000018
0a01020b1247617a706163686f207465737420686f7374
appended to node_announcement as TLV 118685, 93 bytes:
fe0001cf9d57 || card
```

**D2. Coin anchor.** Output key Q = `7623edf9580bec93335131c7e0d085ba224d2c0a74566ba105654049d0b5b137` (secret `SHA256("gazpacho test key: host coin")` mod n, used directly as Q); outpoint txid `SHA256("gazpacho test coin txid")`, index 0; `coin_valid_until` 291,008.

```
anchor_digest = cd85b08e27342c96496fe3b24687dc9526589452467a6acd0bd4bee43d6138d0
anchor value, 110 bytes:
0424151f73e48f9bc78a94686e9aeb373dcba70e326588a4262b993cb40de4c7
11c1000000000604000470c00840dc45f44c60d5a3e849471f1f02d487ac13d1
1351876ee006a9c17741f0dd4442b69da472d6c32638fa51ab16679102e72788
4f0d961f21a8669695d95e5a555f
```

Allowances at the signet unit: 2,499 sat → 0; 2,500 → 1; 19,999 → 1; 20,000 → 2; 100,000 → 4.

**D3. Signed card** (4.4) with D1 and D2: `card_digest = 055f1df6ad0c11b718f73ac10a83d4350f319e0145d38b0e70f1d6fab42470ff`; 336 bytes; `card_sig = 4296affe5785798c623b30f4e5c5cdbeb2d38c0450dc3d387673e1819df3a8b9f471fdd69f41c8452e28cff3825029053841c0bb6270597260ee308eabc563e2`.

**D4. Listing** of lobby T1, `start_height` 290,000, `expiry_height` 290,144, with D2:

```
listing_digest = c31b4bc7a6db26eabb8c8e3e7c92149214ab364aab7fc2a5c238fb5f16d08b06
listing, 452 bytes:
022102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473
34915604e1 || T1 outer record (225 bytes) ||
060400046cd0080400046d600a6e || D2 anchor value (110 bytes) ||
f04011f57a568a04f5ad16628447aff60954aedc6be72c005fb57a44612609cf
b248ef5cd0ee86a5962c49c84707af3d86b85b6f31f4255b40c20229d7074a78
ba9d
```

D4w, the withdrawal (expiry 290,000): `listing_digest = 420dfc0c023b5ec8f56f8f77c6ec7b9e75df39be6fc00b147dcd64ee614a2b24`. D4x, **refuse**: expiry 291,009 (start + 1,009), validly signed, fails L4. Largest possible listing: 4,817 bytes.

**D5. Queries.**

```
lobby_index_request records, 34 bytes: 0220 || signet chain hash
native, kind 129, 74 bytes:
ce37677a6601 0081 00…00 (32) 0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
onion payload field, type 106369, 40 bytes:
fe00019f81 22 0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
index_digest = 8dfeabb7d014bce371d93a822bbbf2d8d681ecb74cf5437cb83cb08b2d31b2ae
index record, 281 bytes (chain, host_key, as_of 290,000, one T1 entry, D1 card, sig):
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e
3473349156060400046cd0083175e970b6d95c7de97bf35f67033e2c9f55de1e
a54beecb8431419659f0a424f2000000006af501800200000000000186a00a57
|| D1 card ||
f0409f4db1c5bf29c4ff8326bdc02151344b07d9c52fe88ed6eb3dad3499e004
fc04c24d2b15c17a4a2e47451966aa67e893da57a46c63bf3e3d100f589250fc
81a7
lobby_index records, 285 bytes: 02fd0119 || index record (native message 325 bytes)
listing_request records, 68 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659
f0a424f2
listing answer records, 456 bytes: 02fd01c4 || D4 (native 496 bytes; onion payload field 464 bytes)
listing answer "unknown": 0420d0d4162d5064aa52a4ff1e44baaecb8fbd96c19e4923a87bbdffcdeb5c02a6dd
```

The tool asserts that the native and onion forms end in the same record bytes.

**D6. Nostr content.** Listing event `d` = `75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2`, `content` = base64 of D4, beginning `AiECuN1zml0rBwn+xc6k6E63gRuQTM+HHHehp4seNHM0kVYE4QIg9h7uO2Oj` and ending `CAinXB0p4up0=` (604 characters). Card event `d` = `02b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156`, content base64 of D3 (448 characters). Event ids and Nostr signatures depend on the author and the time and are not vectors.

**D7. Beacon** for lobby T1, open 290,000, deadline 290,144, sequence 1:

```
beacon_id = 38c0f34c49fc7ec38be1d789af0dcd9934f97c2070c5a81806dfbf066e46fd7a
records, 153 bytes:
022102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473
349156042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb84314196
59f0a424f2060400046cd0080400046d600a0400000001f04087463e13f8fde8
35635454f0ab145e2adfaf93c276f4b1235409b37cfc3c46acf5b7bfd0d05433
871e22c511e4864fe2e8dcb2c62ee3530b1313677dd1938e6a
native lobby_beacon, kind 141, 193 bytes: ce37 677a6601 008d 00…00 (32) || records
```

**D8. Withdrawal** of D7: sequence 2, deadline 290,000: `beacon_id = 2962e05b712a326e7e696b8b854ed52a4f379f2269603b4a68a847fd14ccc00e`, `beacon_sig = b1e92a3c8305924f51d5e17f5962396c8c00309aca9a60a1ce46717069b042aac6eb32e4af7c15e2badd3336a7ab04be5040b139f32392372d7346656eb546b8`.

**D9. Refuse:** D7's records with a signature by test key `other host`: B4 fails.

**D10. `beacon_filter`.** "Everything" (0, `0xFFFFFFFF`), native kind 143, 86 bytes: `ce37677a6601008f` ‖ 32 zero bytes ‖ `0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881080000000404000000000604ffffffff`. "Nothing" (off) records: `0220f61eee3b…08000000 0404ffffffff 060400000000`. Seen-set sizes: 10 hosts → 1,024 entries (41 KB); 1,000 → 8,000 (320 KB); 10,000 → 65,536 (2.6 MB).

**D11. Refuse:** D2's `coin_sig` presented in a listing by host key `other host`: the anchor statement names another key and the signature fails (A1). This is the "nobody can borrow a coin" rule.

**D12.** Five beacons of one host, sequences 1 to 5, different lobbies: the held set keeps sequences 2 to 5 (B8).

Not yet vectors **(open, point 10)**: a channel anchor and a `host_list` entry, which need real BOLT 7 messages with ECDSA signatures; the plan is to take them from BOLT 7's own test data or a signet node.

## 17. Tests

Decoders are generated from the tables and fuzzed, as in `messages.md` 12.

**Encoding**
1. D1 to D10 encode to exactly the bytes above; digests and signatures match.
2. Each record: non-minimal BigSize, types out of order or repeated, a fixed-width field one byte short or long, a length past the end: refused (dropped).
3. A card of 257 bytes; a listing of 4,818 bytes; an index of 641 bytes or with 5 entries or a 48-byte entry; a beacon with an extra odd record: each dropped.
4. An unknown even type in a card: the card ignored, the announcement kept. In a listing or index: dropped.

**Feature bits**
5. A host announces 449 and 451: an LND, CLN, Eclair and LDK node each keep connecting to it and routing through it, and relay its announcement (section 3.1). The same host announcing the even bit 450 instead: it is shunned (shows why odd is required).
6. A node with 451 and not 449: both ignored. A member build never sets 451.

**Card**
7. A card replaced after 100 blocks: the reader keeps the old one; after 144: the new one. Identical bytes resent: accepted.
8. A peer that strips the card TLV from the announcement: the reader still gets the card from `lobby_index`; nothing depends on it.

**Listing (hostile host or carrier)**
9. Listing signed by another key; `host_key` not equal to the outer record's; outer record with a bad shape, a mainnet chain on a signet build, or a bound broken: dropped (L2, L3).
10. D4x (expiry beyond start + 1,008); start more than 6 blocks ahead; expired; past the outer deadline: dropped or not shown (L4).
11. Two listings with one `listing_id`: the shorter expiry wins, everywhere it is seen (L6). The host re-signs a longer one after a withdrawal: the withdrawal still wins where both are seen.
12. A host with 5 live listings: only the 4 earliest shown (L7, A4).
13. A listing whose outer record differs by one byte from the `terms_offer` received after `hello`: impossible by digest; the test checks the member compares `scope` and refuses a mismatched offer (`terms.md` 7 step 2).

**Queries**
14. Honest: index then listing, by onion and natively; the record bytes are identical in both.
15. An answer arriving on another reply path, or with another `path_id`: ignored (O2). An unasked `listing`: dropped (Q5).
16. `lobby_index` signed by another key; `as_of_height` 7 blocks off; entries not sorted or repeated: dropped (Q1).
17. `listing` with both records 2 and 4, or with a listing for another digest: dropped (Q4).
18. Rate: a source sending 10 index requests in 10 s gets 1 answer; 100 sources at once: at most 50 answers a second in total (H2).
19. Unlisted and Circle lobbies never appear in any answer or in scope-zero `hello` (H1, F1).
20. Onion to an LND first hop without a channel: dropped; the asker falls back to native after the retry (O6, O7).

**Anchors**
21. Coin anchor unspent with 6 confirmations: accepted; with 5: dropped; spent after acceptance: dropped at the next 144-block check (A1, A2).
22. D11 borrowed coin: dropped. One anchor under two live host keys: both dropped (A6).
23. Allowances of D2 at the edges; an anchor of 2,499 sat on signet: listing dropped (A3).
24. A Nostr listing without an anchor: dropped. A relay policy that accepts 5 listings for a 4-listing anchor: the wallet still shows 4 (A7: only tighten).
25. Channel anchor whose output is not the P2WSH 2-of-2 of the two bitcoin keys, or in which `host_key` is neither node: dropped.

**Beacon (honest)**
26. A host opens a lobby: its beacon reaches every factory-capable node in a test overlay of 30 nodes within three flushes; an opted-in node fetches the listing once and stores it until expiry; a relay that has not opted in stores nothing on disk and fetches nothing.
27. Withdrawal D8 spreads and removes the stored listing.
28. A new node opens links, sends the filter, and receives the backlog of active beacons.

**Beacon (hostile)**
29. A beacon from a node not in the graph, or in the graph without 451: not relayed, not held against the peer (B3).
30. D9 forged signature; open height 7 ahead; deadline more than 1,008 after open: dropped and counted; 10 in 10 minutes: link closed (B4, B5, 8.7).
31. A host sending 2 new beacons within an hour: the second is not relayed by any honest relay (B7). Sent at 3,600 s intervals: relayed despite clock skew of a few minutes.
32. A host with 5 active beacons: D12's eviction everywhere (B8).
33. Replay of an older sequence after a newer one: dropped (B6). The same beacon from 8 peers: relayed once (B2).
34. Seen-set flooding: a peer sends 100,000 distinct valid-looking beacons from hosts not in the graph: none held, memory unchanged (B3 runs before storage). From one real host: at most one new per hour accepted.
35. A peer that never set `factory_capable` sends beacons: ignored. An ordinary Lightning node connected to a factory-capable node never receives a beacon.
36. A filter of "nothing": the peer receives no beacons except the sender's own. Filters sent 10 times a minute: one honoured.

**Overlay**
37. Selection keeps X1 to X3 when candidates allow; with only hosts available it fills (X7) and moves to members when they appear at the next refresh.
38. Eclipse attempt: an attacker announces 200 factory-capable nodes in one /16: at most 2 links go to them (X3). An attacker controlling every host: at most 2 links, half the links still to members (X1, X2).
39. A link silent for 24 hours while others forward beacons is replaced; a dead link at once (X6). One random link is rotated every 4 hours (X5).

**Host list**
40. A trusted node's answer with one entry forged (bad signature) and one hidden: the forged one dropped, the rest kept; the client cannot tell about the hidden one, which is the stated limit.

**Privacy**
41. A query through the host as first hop is logged as "no privacy gain" in the test report; a query through another first hop with a fresh reply path each time: the host cannot link two queries by path.
42. The asker's native query uses a key never used for a seat.

## 18. Open points

1. **Final numbers** for both bit pairs, the card TLV, the onion payload types and the Nostr kinds: chosen and checked by section 2 on the day of first use beyond signet; registration needs public proposals (a bLIP; a NIP), which only the owner can authorise. Nothing is to be posted.
2. **The beacon depends on the overlay.** Lightning implementations do not relay unknown messages, so beacons spread only if enough announced factory-capable nodes form the overlay. Members are often unannounced phones and cannot be overlay candidates, so X1 may be hard to meet early (X7). Light clients still rely on a node of their own or on Nostr; the beacon does not reach them otherwise.
3. **`outer_sig` in the listing.** Left out (5.1); adding it (66 bytes) would let a reader run `terms.md` section 7 step 3 unchanged on the outer record alone.
4. **Relays may need channel-less inbound connections.** LND limits inbound peers without channels; whether that blocks overlay links to LND-based Gazpacho hosts is not checked.
5. **Card relay** by every implementation is not verified (4.2). The card stays best-effort.
6. **Coin anchors other than P2TR key path** (BIP 322 for P2WPKH and others): not in draft 1.
7. **Proposed numbers to tune on signet:** 4 listings and 4 beacons per host, one beacon an hour (3,000 s at receivers), 1,008-block lifetimes, 1,000,000 / 10,000 sat units, H2 rates, 4 to 8 overlay links and the mix, 4-hour refresh, seen-set sizing, 0 to 120 s jitter.
8. **Blinded contacts** for hosts not in gossip: format inside invitations and listings not specified (the research's `blinded_contact` record was left out of the listing to keep it to the owner's field list).
9. **`messages.md` changes** of section 15 (scope zero for discovery kinds; at most 4 listed lobbies in scope-zero `hello`) are needed before the native queries ship.
10. **Missing vectors:** a channel anchor and a `host_list` entry (real BOLT 7 messages with ECDSA signatures).
11. **Taproot channels** cannot be channel anchors until taproot gossip (bolts#1059) merges; until then a host with only taproot channels uses a coin anchor.
12. **A host could censor its own rivals** only on links it holds; X1 and X2 bound that, but a network where most capable nodes are hosts weakens it. Measure on signet.
