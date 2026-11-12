# Discovery: finding hosts and their lobbies

Specification draft 2, 2026-11-12. Status: not reviewed. Draft 2 applies the owner's discovery decisions (ideas ledger, `notes/ideas-ledger.md` section A, rows A1 to A12, with A6 in its final form) and the peering research (`notes/peering-research.md`, cited as **PR** with its part: PR B3, PR F9). Background: `notes/discovery-research.md` (cited as **DR**). Items marked **(open)** are listed in section 22. Numbers marked **candidate** are reproducible random picks that are **not final** (section 2). Fields and numbers marked **proposed** wait for the owner.

Conventions (integers, `point`, `sig`, `outpoint`, `TH`, "refuse", "ignore") are those of `messages.md` section 1. TLV encoding is canonical as in `terms.md` section 2: minimal BigSize, strictly increasing types, fixed widths, unknown even types invalid, unknown odd types skipped but covered by any signature. Words: **host**, **member** as in `PROTOCOL.md`. **Listed** lobby: a lobby the host chooses to make public. Circle lobbies (profile 4) are never listed. **F node**: a node that sets the factory feature bit (section 3).

**Normative and informative.** Sections 3 to 12, 14 and 15 are normative: two implementations need them to work together. Section 13 (overlay peering) and section 17 (Nostr) are **informative**: their numbers are recommended defaults, and peers need not agree on them (PR F2).

## 0. Changes from draft 1

| # | Change | Where | Source |
|---|---|---|---|
| 1 | **One feature bit**, `factory_capable` 448/449 (sent odd, 449). The `factory_host` pair 450/451 is removed and free again | 2, 3 | Ledger A1 |
| 2 | **A host is whoever sends beacons.** No hosting flag. Before beacons ship, a host is a node whose lobby index is not empty | 3, 8.2 | Ledger A1; PR B1 (E3) |
| 3 | **Host card withdrawn.** Its `node_announcement` TLV 118685, Nostr kind 37329, tag `gazpacho/card` and index record 10 are reserved only, never sent. Vectors D1 and D3 withdrawn | 4 | Ledger A2 |
| 4 | `lobby_index` no longer carries a card; vector D5 changed | 6.1 | Ledger A2 |
| 5 | Beacon gains two **proposed** filter fields: `profile` and `channel_sat`. 166 bytes of records, 206 on the wire. D7 to D9 changed | 8.1 | Ledger A4; PR F4 |
| 6 | Beacons are accepted only from nodes in the gossip graph **with the bit and a channel**. No proof is needed besides the graph | 8.3 (B7), 9.3 | Ledger A1, A8 |
| 7 | **"Seen" only after the signature verifies.** An invalid copy never blocks the valid one | 8.3 (B5), 8.6 | PR F9 |
| 8 | **Orphan pool:** a valid beacon whose host is not yet in the graph waits, 8 per link, 64 in total, 20 minutes | 8.4 | PR F6 |
| 9 | **Two beacons, one sequence:** keep the lower `beacon_id`, so every node converges | 8.3 (B8) | PR F9; PR A3b (Delving 2105) |
| 10 | Churn limit: at most 8 new sequence numbers per host per 144 blocks, replacing "one per hour, 3,000 s" | 8.3 (B9) | PR B8 (R2) |
| 11 | **Immediate relay** to every overlay link, replacing the 60-second flush. Per-link "known" set; outgoing queue at most 64 | 8.5 | Ledger A6; PR F2, F3, B8 (L2) |
| 12 | Per-link rate limit: 1 beacon a second, bursts of 20, replacing 50 a minute | 8.5 | PR B8 (R3) |
| 13 | Host rebroadcast: own live beacons to each new link, and to all links every 6 to 12 h | 8.5 | PR F8 |
| 14 | Misbehaviour in two classes, **Reject** (close the link, 24 h back-off) and **Ignore** (no penalty), replacing "10 invalid in 10 minutes" | 8.7 | PR F15 |
| 15 | **`overlay_init`** (kind 153): the per-connection **lobby store flag**, sent once before any beacon | 10.1 | Ledger A6; PR F13 |
| 16 | **Store nodes** and their duties: fetch every listing, keep it until expiry, serve peers, answer pool requests, keep their store across restarts | 11.1 | Ledger A6; PR F2, F5, F7 |
| 17 | **Fetch order:** a store peer first, which answers at once with the listing or **`listing_not_held`** (kind 155); then the host after a random 0 to 60 s. Store nodes wait a random 0 to 60 s first. Replaces "0 to 120 s, then the host" | 11.2 | Ledger A5, A6; PR F1, F3 |
| 18 | **Pool request** (`pool_request` / `pool`, kinds 145 / 147), direct and by onion message, filtered, paged, once per connection and per hour. The catch-up and light-client path | 11.4 | Ledger A3; PR F4, F14, B10 |
| 19 | `beacon_filter` no longer triggers a backlog. Catch-up comes only from the pool request | 10.2 | PR B8 (C1), F4 |
| 20 | Host query limits kept; limits added for store nodes and pool answers | 6.4, 11 | Ledger A7 |
| 21 | **Overlay peering is informative**, with the research's numbers: 6 links (4 to 8), at least 3 outbound, mix with at least one store node, anchors, daily rotation, hourly scout, local scoring. Replaces draft 1's normative X1 to X7 | 13 | Ledger A10; PR B, F2 |
| 22 | **Bootstrapping degrades to direct queries** (design C). Every F node answers `lobby_index_request` | 14 | PR B9, C |
| 23 | **Reserved:** have-summaries (149), store-to-store sync (151), bundled host proofs (157), sketch reconciliation. **Never on the wire:** scoring | 15 | Ledger A6; PR F2 |
| 24 | Nostr annex: listing event only. Retirement criteria N1 to N7, informative | 17 | Ledger A11; PR D |
| 25 | **Release table:** design C (bit and direct queries) first, in the demo wallet with Nostr; design D (beacons, store nodes, overlay) next | 18 | PR C; ledger A6 |
| 26 | `host_list`: entries carry bit 449; optional `keys` record to ask about named nodes (D19) | 7 | Ledger A1; PR B10 step 4 |
| 27 | Light clients use the pool request to 1 or 2 store nodes, replacing "beacons from one trusted node" | 12 | Ledger A3, A6; PR B10 |
| 28 | Onion payload types 106381, 106383, 106385 appended | 2, 6.2 | Follows from 17 and 18 |
| 29 | Sections renumbered: overlay links 10, store nodes and pool 11, light clients 12, peering 13, bootstrapping 14, reserved 15 | All | Editorial |

Kept from draft 1: the listing (5), the queries and host rules (6), anchors and caps (9), the beacon record's first five fields, 4 live beacons per host, 1,008-block lifetimes, `beacon_filter`'s format, "collecting is off by default; relaying is on" (ledger A12), odd numbers only (ledger A9).

## 1. The design in one table

The owner's decisions, which this document specifies:

1. Gossip says only **who is factory-capable**: one odd feature bit. No per-lobby data ever goes through BOLT 7 gossip.
2. Terms come only as a **signed listing**, asked for, never flooded.
3. The **lobby beacon** is the one push: a 166-byte signed note "this host has a lobby open", with no terms, relayed at once among F nodes.
4. **Store nodes**, which opt in, fetch and serve listings, so most askers never touch the host.
5. **Collecting** other hosts' lobbies is off by default; **relaying** beacons is on by default (ledger A12).
6. **Nostr** is an optional annex, with conditions for retiring it.

| Layer | What | Carrier | Changes | Section |
|---|---|---|---|---|
| Capability | `factory_capable` on every Gazpacho node | Odd feature bit 449 in `init` and `node_announcement` | Rarely | 3 |
| Listing | One signed record per lobby: the outer terms record plus host key, start height, expiry, optional anchor, signature | Query answers; store nodes; Nostr. **Identical bytes on every carrier** | Once per lobby | 5 |
| Queries | `lobby_index_request`/`lobby_index`, `listing_request`/`listing` | Onion messages with a blinded reply path; native messages | Per question | 6 |
| Host list | `host_list_request`/`host_list` from a trusted full node | Native; onion | Rarely | 7 |
| Beacon | "Host H has lobby L open until height d", with profile and channel size | Native, over overlay links | Per lobby | 8 |
| Anchors | A channel or a coin backing a listing | Inside a listing | While unspent | 9 |
| Overlay links | `overlay_init` (store flag), `beacon_filter` | Native, BOLT 8 connections between F nodes | Per connection | 10 |
| Store and pool | Store nodes; fetch order; `listing_not_held`; `pool_request`/`pool` | Native; onion | Per beacon; per catch-up | 11 |
| Peering | Which F nodes to link to | Local policy (informative) | Daily | 13 |
| Live state, joining, signing | `terms_offer`, `lobby_status`, `join`, rounds | Direct BOLT 8 connection only | Often | `messages.md` 6, 7 |

**What protects a member is unchanged.** Nothing found through discovery is trusted. A member joins with `hello` whose `scope` is the listing's `outer_digest`; the `terms_offer` it gets is checked by `terms.md` section 7 in full, and the tree is checked at signing (`safety-rule.md` C8). Discovery can waste a query; it cannot cost money.

## 2. Numbers: how each is chosen and checked

Every number here is a candidate printed by `tools/spec-vectors.py` (vector D0). None is final. A final number is chosen **on the day it is first used outside a private test**, by the procedure below, and the check and its date are written into `PROTOCOL.md` section 8.3 or 10.

| Item | Candidate | Range rule | Checks before it is final |
|---|---|---|---|
| `factory_capable` bit pair | **448/449** (advertise 449) | 256 to 511, from one pick `SHA256("gazpacho feature bits")` over 4-aligned blocks (kept from draft 1 so the number stays). Below 512 keeps the feature field at most 64 bytes (bit 449 gives 57) | (a) bLIP 2 feature-bit table as merged; (b) every open pull request in lightning/bolts and lightning/blips (bLIP-56's 270/271 among them); (c) known unregistered uses in LND (`lnwire/features.go`), Core Lightning (`common/features.h`), Eclair (`Features.scala`), LDK (`features.rs`); (d) the experimental "+100" copies of pending bits. Next candidates if taken: 452/453, 456/457 |
| Onion payload types | **106369 to 106385, odd** (nine) | Odd, one block of 64 above 65,600 | bLIP 2 onion-message table (bLIP-32 has 65536, 65538, 65550); BOLT 12's payload types; open pull requests; LDK, CLN, Eclair, LND handlers |
| Native kinds | **129 to 147 odd, 153, 155**; 149, 151, 157 reserved (section 6.3) | `PROTOCOL.md` 10.1 range 128 to 159 | None outside this project: kinds live inside type 52791 |
| Nostr kind | **31867** (listing) | Addressable, 30000 to 39999 | The NIPs repository kind table on the day; known uses Soup 38099 and 38101, NIP-69 38383 to 38389, publsp 39735, NIP-29 39000 to 39009, NIP-51 30000 to 30030 and the others listed in the tool (recalled, **not verified today**) |
| Tags | `gazpacho/listing`, `gazpacho/index`, `gazpacho/anchor`, `gazpacho/beacon` | `PROTOCOL.md` 8.2 | Registered there before use |
| **Reserved only** | Card TLV **118685**; Nostr kind **37329**; tag `gazpacho/card`; index record 10 | Kept so they are never reused for something else | None: never sent |

Until a number is registered (only through a public proposal, which only the owner can authorise), it is used **only on signet** and only by builds that say it is unregistered.

### 2.1 Why 128 to 159

The research draft (DR B8) proposed native kinds 35 to 53. Those lie in `PROTOCOL.md`'s session range 16 to 63, whose free part is reserved for session additions. `PROTOCOL.md` reserved **128 to 159** for discovery, so this document uses that range. The research's numbers are not used anywhere.

## 3. The feature bit

| Name | Pair (candidate) | Bit sent | Contexts | Who sets it | Meaning |
|---|---|---|---|---|---|
| `factory_capable` | 448/449 | **449, odd** | `init`, `node_announcement` | Every Gazpacho node, member or host | Speaks the SuperScalar factory protocol natively on type 52791 (`PROTOCOL.md` 3.1, stage C); takes part in discovery as this document says |

Rules:

1. Every Gazpacho node sets 449 in `init`. A node with an announced channel also sets it in `node_announcement`.
2. **There is no hosting bit.** A **host** is a node that sends beacons (section 8). Before beacons ship (design C, section 14), a host is a node whose `lobby_index` is not empty. Anyone may host (owner decision 4); hosting shows in what a node does, not in a flag.
3. An F node SHOULD answer `lobby_index_request` over a direct connection, with an empty index if it hosts nothing (section 14).
4. A node with a live beacon, or a non-empty index, MUST answer section 6 queries for its own lobbies over a direct connection, and by onion message if it also sets `option_onion_messages` (38/39).
5. Nothing that touches money depends on the bit. A wrong bit costs a wasted connection.
6. A node with no announced channel has no `node_announcement`. It sets the bit in `init` only, and its beacons are not accepted by others (B7). It reaches members by invitation, the built-in list or Nostr.

### 3.1 Why the bit must be odd

Read from BOLT 7 on 2026-11-12:

- Its rationale says `node_announcement` feature bits "will be propagated normally". So ordinary Lightning nodes relay announcements that carry bits they do not know. This is how F nodes **find each other through the plain network**, with nobody else needing to understand the bit.
- For an unknown **even** bit in `node_announcement`, a receiver "SHOULD NOT connect to the node" and "MUST NOT route a payment through the node".

So an even bit would cut a host off from the network. **The bit is advertised odd** (449) until a merged standard makes it universally understood. The even half (448) is kept so the pair follows BOLT 9, and is never set (ledger A9).

## 4. The host card: withdrawn

Draft 1 had an optional static "host card" in `node_announcement`. Draft 2 removes it (ledger A2):

- `node_announcement` has no TLV stream in the BOLTs, so the card was best-effort at most.
- Liquidity ads, the nearest precedent, has been unmerged for about five years.
- The beacon's filter fields (8.1) and the index (6.1) carry what a reader needs.

**Reserved only, never sent:** `node_announcement` TLV type 118685, Nostr kind 37329, tag `gazpacho/card`, and record type 10 of the index record. A reader treats a record 10 in an index as an unknown even type (the index is dropped).

## 5. The listing

Unchanged from draft 1.

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

- **Size:** at most **4,817 bytes**, the sum of every record's maximum (vector D4). No odd records are defined; unknown odd records are skipped, covered by the signature and counted in the limit.
- **No chain field:** the chain is the outer record's type 2.
- **`listing_id`** is the `outer_digest`. It names the lobby; `listing_digest` names one signed version of its listing.
- **No `outer_sig`:** `listing_sig` already commits to the outer bytes under its own tag (open point 4).
- **One listing, every carrier.** A host makes one listing per listed lobby and serves those bytes in `listing` answers (onion and native), through store nodes, on Nostr and through any later carrier. If it publishes on Nostr, that listing has an anchor, and the same anchored bytes are what queries return.
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

Four messages between an asker and a host. **The record bytes are the same on both carriers.** Answers carry signed records, so the messages themselves are unsigned, as `terms_offer` is.

### 6.1 Records

**`lobby_index_request`**, asker → host:

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 3 | `profiles` | `u8` | No. Bitmap: bit (p − 1) for profile p (bit 0 Safety, bit 1 Standard, bit 2 Starter; bits 3 to 7 zero). The host lists only those profiles |

**`lobby_index`**, host → asker: one record, type 2 `index` (1 to 640 bytes), the signed **index record**:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | Equals the request's |
| 4 | `host_key` | 33 | The host's node key |
| 6 | `as_of_height` | `u32` | The host's tip when answering |
| 8 | `entries` | 0 to 196 | 0 to 4 entries of 49 bytes: `outer_digest` (32), `deadline` (`u64`, Unix seconds), `profile` (`u8`), `channel_sat` (`u64`). Distinct digests, in increasing `outer_digest` order. Values copied from the outer record |
| 10 | — | — | **Reserved** (draft 1's card). Never sent |
| 240 | `index_sig` | 64 | BIP 340 by `host_key` over `TH("gazpacho/index", every byte before record 240)` |

An empty `entries` record (length 0) means "no listed lobby now".

**`listing_request`**, asker → host or store node:

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 4 | `outer_digest` | 32 | Yes |

**`listing`**, host or store node → asker: exactly one of

| Type | Field | Size | Meaning |
|---|---|---|---|
| 2 | `listing` | 1 to 4,817 | The listing record (section 5) |
| 4 | `unknown` | 32 | The requested `outer_digest`: **from the host only**, "no such listed lobby" |

A store node that does not hold a listing answers `listing_not_held` instead (11.3).

### 6.2 Onion carrier

| Rule | Text |
|---|---|
| O1 | Each message is a BOLT 4 onion message whose final hop's `onionmsg_tlv` holds exactly one payload field. Types (candidates): `lobby_index_request` 106369, `lobby_index` 106371, `listing_request` 106373, `listing` 106375, `host_list_request` 106377, `host_list` 106379, `pool_request` 106381, `pool` 106383, `listing_not_held` 106385. Value = the records of this document. BOLT 4: a message with more than one payload field is ignored |
| O2 | A request MUST carry `reply_path`. The asker puts its own `path_id` in its blinded path and accepts only an answer that arrives along that path with that `path_id` (BOLT 4: replies not using the exact path are ignored, against probing). The answerer MUST answer along `reply_path` only |
| O3 | Requests SHOULD be 1,366-byte onions. `lobby_index` (records at most 645 bytes) SHOULD fit 1,366; `listing` and `pool` use 32,834 bytes. Larger onions reduce the anonymity set (BOLT 4) |
| O4 | The asker SHOULD use a first hop other than the node it asks, and a fresh reply path per request. Through the answerer itself the query hides nothing |
| O5 | To reach a node in gossip, route to its node key. A host not in gossip is reached by a blinded contact from an invitation (12) |
| O6 | Onion messages are unreliable. No answer in 30 s: retry once through another first hop, then fall back to 6.3 |
| O7 | The first hop must accept onion messages from the asker. LND by default drops them from peers without a fully open channel; CLN, Eclair and LDK accept them by default. A new user with no channel picks such a node or falls back to 6.3 |

### 6.3 Native carrier

The same records in an ordinary type-52791 envelope (`messages.md` 4), with **`scope` all zero**.

| Kind | Name | From → to | Section |
|---|---|---|---|
| 129 | `lobby_index_request` | asker → host | 6 |
| 131 | `lobby_index` | host → asker | 6 |
| 133 | `listing_request` | asker → host or store node | 6, 11 |
| 135 | `listing` | host or store node → asker | 6, 11 |
| 137 | `host_list_request` | asker → trusted node | 7 |
| 139 | `host_list` | trusted node → asker | 7 |
| 141 | `lobby_beacon` | F node → F node, overlay link | 8 |
| 143 | `beacon_filter` | F node → F node, overlay link | 10.2 |
| 145 | `pool_request` | asker → F node | 11.4 |
| 147 | `pool` | F node → asker | 11.4 |
| 149 | `beacon_summary` | **Reserved**, no format | 15 |
| 151 | Store-to-store sync | **Reserved**, no format | 15 |
| 153 | `overlay_init` | F node → F node, first on an overlay link | 10.1 |
| 155 | `listing_not_held` | store node → asker | 11.3 |
| 157 | Bundled host proofs | **Reserved**, no format | 15 |
| 159 | Reserved for discovery | | |
| 128 to 158 even | Not used. Discovery must be safe to send to anyone and safe to ignore | | |

Every discovery kind is **odd**: a node that does not know it ignores it and keeps the connection. A kind sent in the wrong direction is ignored, not refused (discovery is never worth a disconnect).

| Rule | Text |
|---|---|
| F1 | `hello` with scope zero stays as `messages.md` 6.1 specifies, returning `terms_offer`s; but it MUST list only listed lobbies, at most 4 (section 19) |
| F2 | The asker SHOULD use a fresh BOLT 8 key per query session (not a seat key) and SHOULD connect over Tor where available. Without Tor the answerer learns the asker's address |
| F3 | No answer in 30 s: give up on that node for 10 minutes |

### 6.4 Host rules (both carriers)

| Rule | Text |
|---|---|
| H1 | Answers list only the host's own **listed** lobbies in state Open, at most 4. Unlisted lobbies never appear. A started or cancelled lobby is withdrawn (5.1, 8.1) and dropped from the index |
| H2 | Per source, at most 1 `lobby_index_request` and 4 `listing_request`s per 10 s; at most 50 queries per second in total. Beyond that, drop silently (BOLT 4 allows dropping). The source is the incoming peer for onion messages and the connection for native ones (ledger A7) |
| H3 | The host MUST NOT answer differently depending on who asks, beyond refusing. (Detectable by comparing with a store node, Nostr or another asker) |
| H4 | `lobby_index` and `listing` answers carry the signed records, so they can be relayed or shown later without trusting the carrier |
| H5 | A host never sends `lobby_index` or `listing` unasked. Its lobbies reach others only as answers, through store nodes, and as beacons (8) |
| H6 | A request whose `chain` is not the host's: ignored |

### 6.5 Asker rules

| Rule | Text |
|---|---|
| Q1 | `lobby_index`: the index decodes canonically within 640 bytes; `chain` equals the request's; `host_key` equals the node queried (onion: the node routed to, or the key named with the blinded contact; native: the connection's BOLT 8 key); `index_sig` verifies; `as_of_height` within 6 blocks of the asker's tip; entries as in 6.1. Otherwise drop |
| Q2 | Index entries are **hints**. The asker fetches a listing before showing anything as a lobby |
| Q3 | (Draft 1's card rule: withdrawn) |
| Q4 | `listing`: exactly one of records 2 or 4. A listing passes 5.2, its `outer_digest` equals the one requested, and its `host_key` equals the host's (the host queried, or the beacon's `host_id` when it came from a store node). `unknown` with another digest, or `unknown` from a node that is not the host: drop |
| Q5 | Answers not asked for, or after 30 s: drop |

## 7. Host list from a trusted full node (optional)

For a light client whose own node, or current host, holds the gossip graph.

**`host_list_request`**: 2 `chain` (32, required); 3 `skip` (`u16`, optional, entries to skip for paging); 5 `keys` (33 × 1 to 64, optional: answer only for these node keys; vector D19).

**`host_list`**: 2 `chain`; 4 `entries`, 0 to 64 entries, each `u16` length, a `node_announcement` exactly as gossiped (its 2-byte type included) that sets bit 449, `u16` length, and one `channel_announcement` exactly as gossiped in which that node is `node_id_1` or `node_id_2`; 5 `more` (`u8` 1, optional: further entries exist). At most 60,000 bytes natively, at most 30,000 bytes by onion message (payload type 106379, request 106377, candidates).

- **Hidden, never forged.** Every entry carries gossip's own signatures and a chain anchor. The answering node can leave nodes out; it cannot invent one.
- Without `keys`, the answering node SHOULD list first the nodes that sign live beacons it holds (the hosts).
- Asker checks per entry: the `node_announcement` signature (BOLT 7); bit 449 set; the `channel_announcement`'s four signatures; the node is one of its two nodes; then the channel as an anchor (section 9, type 2). A failed entry is dropped, the rest kept.
- Rates: an answering node answers at most 1 request per 10 s per source.
- Never automatic: a wallet asks only a node its user named, or a store node it already uses for pool requests (12).

## 8. The lobby beacon

The one push. It says only "**this host has a lobby open**", plus two filter fields. No terms, no fill level, no seats.

### 8.1 Record

`lobby_beacon` (kind 141), records:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_id` | 33 | The host's node key (= `host_key`, = its BOLT 8 key) |
| 4 | `outer_digest` | 32 | The lobby's identifier |
| 6 | `open_height` | `u32` | Height at which the lobby opened |
| 8 | `deadline_height` | `u32` | `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008. The beacon expires here |
| 10 | `sequence` | `u32` | Per host, strictly increasing over all its beacons |
| 12 | `profile` | `u8` | **Proposed.** The outer record's profile: 1 Safety, 2 Standard, 3 Starter. 4 (Circle) and other values are invalid |
| 14 | `channel_sat` | `u64` | **Proposed.** The outer record's `channel_sat` (`terms.md` type 30); at least 1 |
| 240 | `beacon_sig` | 64 | BIP 340 by `host_id` over `beacon_id = TH("gazpacho/beacon", every byte before record 240)` |

**166 bytes** of records (vector D7); **206 bytes** as a Lightning message. No other records are defined; any extra record, odd included, makes the beacon invalid (a beacon is relayed, so it must not carry padding).

- `beacon_id` is the deduplication key. It is a digest of the content, so two signatures over one content are one beacon. It commits to every field, so two different beacons never share an id (PR F9, F11).
- **Filter fields.** `profile` and `channel_sat` let most nodes skip a beacon without fetching anything (ledger A4). They are copied from the outer record; a reader that fetches the listing checks they match (11.2). A third field is open point 2.
- **Withdrawal:** a beacon with the same `outer_digest`, a higher `sequence`, and `deadline_height` = `open_height`. It replaces the old one and expires at once; relays forward it so the withdrawal spreads.
- The beacon's `deadline_height` is the host's estimate of the outer `deadline` (Unix seconds). The listing's own liveness rule (5.1) decides; the beacon is only a pointer.

### 8.2 Roles

| Role | Who | What it does | Default |
|---|---|---|---|
| **Host** | Any F node that sends beacons | Sends one beacon per newly opened **listed** lobby, and a withdrawal when the lobby starts or is cancelled. Answers section 6 queries for its lobbies. Re-sends its live beacons (8.5) | When its user hosts |
| **Relay** | Every F node that holds a gossip graph | Accepts beacons (8.3), relays them at once (8.5), holds them in memory, answers pool requests on its overlay links (11.4) | **On** (ledger A12) |
| **Store node** | A relay whose user turns storing on | Also fetches every listing, keeps it until expiry, serves it, answers pool requests by onion message too, keeps its store across restarts (11.1) | **Off** |
| **Interested node** | Any node whose user browses or turns on "collect lobbies" | Fetches the listings it wants by the fetch order (11.2), shows them | **Off** (ledger A12) |
| **Light client** | A node with no gossip graph | Uses the pool request to 1 or 2 store nodes (12). Never relays | — |

- A host sends at most 8 new `sequence` numbers per 144 blocks (withdrawals count). Receivers enforce it (B9).
- Beacons travel only over **overlay links** (section 10): connections between two nodes that both set 449 in `init` and sent `overlay_init`. Ordinary Lightning nodes never see beacons: they are not overlay peers, and BOLT implementations do not relay unknown custom messages anyway.
- **No proof besides the graph** (ledger A8). A beacon is accepted only from a host that is in the receiver's gossip graph with the bit and a channel (B7). That channel is the anchor. Coin and channel proofs are needed only on Nostr (9.3).
- A relay that is not a store node keeps beacons only in memory (8.6), fetches nothing unless its user is interested, shows nothing and writes nothing to disk.

### 8.3 Acceptance rules

A node runs these on every beacon it receives, in order, whether by relay or in a `pool` answer. **Reject** and **Ignore** are the two classes of 8.7. "Hold" means: keep in the held set (8.6) and relay (8.5).

| Rule | Check | On failure |
|---|---|---|
| B1 | It arrived on an overlay link (10), or in a `pool` answer this node asked for | Ignore |
| B2 | Records decode canonically; exactly records 2, 4, 6, 8, 10, 12, 14, 240; `profile` is 1, 2 or 3; `channel_sat` ≥ 1 | **Reject** |
| B3 | `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008 | **Reject** |
| B4 | `beacon_id` already in the seen-set (8.6) | Ignore (duplicate) |
| B5 | `beacon_sig` verifies under `host_id`. **Only a beacon that passes B5 may enter the seen-set.** An invalid copy never blocks a valid one (PR F9) | **Reject** |
| B6 | `open_height` ≤ tip + 6. `deadline_height` > tip, unless it is a withdrawal of a beacon held | Ignore (ahead of this node's chain, or expired) |
| B7 | `host_id` is in the receiver's gossip graph: it has a `node_announcement` that sets 449, and it is a node of at least one known `channel_announcement` | Hold as an **orphan** (8.4). Not a fault: gossip arrives at different times |
| B8 | **Sequence.** (a) Same `host_id` and `outer_digest` as a held beacon: `sequence` must be higher; the newcomer replaces it. (b) Same `host_id` and same `sequence` as a held beacon, different `beacon_id`: keep the beacon with the **lower `beacon_id`**, so every node converges (vector D17) | (a) Ignore (older). (b) Ignore the higher id; if the newcomer is lower, it replaces the held one |
| B9 | **Churn.** If `sequence` is higher than every sequence held or remembered for this host, it is a new number. At most **8** new numbers per host per **144** blocks | Ignore |
| B10 | **Cap.** At most 4 live beacons per host. A fifth: keep the 4 with the highest `sequence`; if the newcomer is the lowest, drop it (vector D12) | Evict, or Ignore the newcomer |

Then: hold the beacon and relay it (8.5). Every beacon that passed B5, held or not, enters the seen-set, so it is not checked again.

### 8.4 Orphans

A beacon may arrive before its host's `node_announcement` or channel: gossip takes minutes to reach most nodes (PR A3b, F6).

| Rule | Text |
|---|---|
| R-O1 | A beacon that passes B1 to B6 and fails only B7 is held as an **orphan**. It does not enter the seen-set, is not relayed, and does not count against the sender |
| R-O2 | Bounds: at most **8** orphans per link, at most **64** in total, each for at most **20 minutes** (vector D18) |
| R-O3 | Over 8 on one link: evict that link's oldest. Over 64 in total: evict the oldest orphan of the link holding the most. No link can evict another link's orphans while holding fewer |
| R-O4 | On each new `node_announcement` or `channel_announcement`, re-check orphans whose `host_id` it names. One that now passes B7 continues at B8 |
| R-O5 | Two copies of one orphan (same `beacon_id`) are one orphan |

### 8.5 Relay

| Rule | Text |
|---|---|
| RL1 | **Immediately** after holding a beacon, a node sends it to every overlay link whose `beacon_filter` matches (10.2), except the link it came from and any link known to have it (ledger A6) |
| RL2 | **Known set.** Per link, a node remembers the `beacon_id`s it sent to or received from that link, at least while they are held, and never sends a beacon to a link known to have it (PR F2) |
| RL3 | **Outgoing queue** per link: at most 64 beacons waiting. Beyond that, drop the oldest waiting |
| RL4 | **Per-link rate.** A node accepts at most **1 beacon a second** from one link, with bursts of up to **20** (a token bucket). More are ignored. A node never sends faster than this, so an honest sender is never over it (PR B8, R3) |
| RL5 | **Own beacons.** A host sends each new beacon of its own to all its overlay links at once, whatever their filter (BOLT 7 sends a node's own gossip regardless of filters; gossipsub's flood publishing) |
| RL6 | **Rebroadcast.** A host SHOULD send its live beacons to each new overlay link, and to all its links at a random time every **6 to 12 hours**. Duplicates stop at the first hop (B4) (PR F8) |
| RL7 | No announcement-then-fetch, no batching and no random delay on the beacon path: beacons are small and their origin is public (PR B8, L4 and L5). The random delays belong to fetching listings (11.2) |

### 8.6 Seen-set, held set, memory, persistence

- **Seen-set:** the `beacon_id`s that passed B5, each with its `deadline_height`. Size: `min(65,536, max(1,024, 8 × F))` entries, where F is the number of nodes in the receiver's graph that set 449. An entry leaves at its `deadline_height`, or, when full, oldest first. Losing an entry early is harmless: a copy that comes back is checked again and dropped by B8. 40 bytes per entry: at most 2.6 MB (vector D10).
- **Held set:** the live beacons, at most 4 per host, 166 bytes each: at most 4 × hosts × 166 bytes (664 KB at 1,000 hosts).
- **Per host:** the highest `sequence` seen and the heights of the new numbers in the last 144 blocks (B8, B9), kept until 1,008 blocks after that host's last beacon's `deadline_height`.
- **Persistence (store nodes).** A store node SHOULD keep its held beacons, its listings and the per-host memory across restarts, as Bitcoin Core keeps its mempool (PR F7). On start it drops expired entries and re-checks every host against the graph (B7); one that fails is dropped, not orphaned. Other relays MAY do the same.

### 8.7 Misbehaving peers

Two classes, as gossipsub's Reject and Ignore (PR F15):

| Class | Cases | What the receiver does |
|---|---|---|
| **Reject** | B2 (malformed), B3 (lifetime over 1,008 blocks), B5 (bad signature), in a beacon or in a `pool` answer | Close the overlay link. Do not link to that peer again for **24 hours** |
| **Ignore** | B1, B4, B6, B8, B9, B10, orphans, over the per-link rate (RL4), a discovery kind before `overlay_init` | Drop silently. Never held against the peer: these come from honest differences in graphs, tips and timing |

The Reject cases are checks that do not depend on the receiver's view: an honest relay never forwards such a beacon, because it runs the same checks first.

## 9. Anchors and caps

Unchanged from draft 1 except 9.3. An anchor is a chain-backed proof that makes spam cost locked coins. It replaces the coordinator of soup-rendezvous: each wallet checks it through a chain server.

### 9.1 Encoding

The `anchor` value is a TLV stream with exactly one kind:

| Type | Field | Size | Kind |
|---|---|---|---|
| 2 | `channel_announcement` | 1 to 600 | Channel: a full BOLT 7 `channel_announcement` without its 2-byte type, in which `host_key` is `node_id_1` or `node_id_2` |
| 4 | `coin_outpoint` | 36 | Coin |
| 6 | `coin_valid_until` | `u32` | Coin: last height at which the statement holds |
| 8 | `coin_sig` | 64 | Coin: BIP 340 by the output key Q over `TH("gazpacho/anchor", chain ‖ host_key ‖ coin_outpoint ‖ u32 coin_valid_until)` |

A coin anchor has records 4, 6 and 8; a channel anchor record 2 alone. Anything else is invalid. Coin anchors are accepted only on P2TR key-path outputs (script `5120 ‖ Q`), so Q is read from the chain and no key field is needed. Other script types (BIP 322) are open point 6. Naming `host_key` in the coin statement means nobody can borrow another host's coin.

### 9.2 Checks

| Rule | Check |
|---|---|
| A1 | Channel: four signatures; then through a chain server: `short_channel_id` → txid (Electrum `blockchain.transaction.id_from_pos`, or Esplora `/block-height/:h` then `/block/:hash/txid/:i`); the output is the P2WSH 2-of-2 of the two bitcoin keys; unspent (Esplora `/tx/:txid/outspend/:vout`); at least 6 confirmations. A full node may check its graph instead. Value V = half the output's value (half for each node). Coin: `coin_sig` verifies under the output's Q; unspent; at least 6 confirmations; `coin_valid_until` ≥ the backed listing's `expiry_height` and > tip. Value V = the output's value |
| A2 | A failed anchor drops the listing. "Unspent" is re-checked before showing a listing whose anchor was last checked more than 144 blocks ago; results are cached for 144 blocks |
| A3 | **Allowance** per anchor: 0 if V < `unit` / 4; otherwise `min(4, max(1, floor(V / unit)))` live listings. `unit` is 1,000,000 sat on mainnet, 10,000 on signet (minimum anchor 250,000 and 2,500) |
| A4 | At most **4 live listings per `host_key`**, on every path |
| A5 | Over A3 or A4: keep the earliest `start_height`, ties by smaller `listing_id`; drop the rest |
| A6 | One anchor, one host. Two `host_key`s presenting the same anchor while both listings are live: drop both |
| A7 | **Relays and wallets may only tighten** A3 and A4: a budget, ranking by weight `V × min(confirmations, 1,008) / 1,008`, and when full a rolling minimum (drop the lowest weight; refuse below 1.1 × it; the minimum halves every 12 hours, as Bitcoin Core's mempool minimum fee does). They never accept beyond A3 or A4 |

### 9.3 Where anchors are required

| Path | Anchor | Why |
|---|---|---|
| Bit in gossip | No | Gossip is the anchor: a node is in it only with a funded, announced channel |
| Beacons and `pool` answers | **No** | B7: only from a node in the receiver's graph with the bit and a channel (ledger A8). A light client checks the same through `host_list` (12) |
| Listings from a store node | Optional | The listing is signed by the host named in a beacon the asker accepted |
| Query to a known host | Optional | The asker chose the host; H1 caps the answer at 4 |
| Invitation, QR, built-in list | No | The user chose the host |
| **Nostr** | **Required** | Anyone can publish anything there for free |

## 10. Overlay links

An **overlay link** is a BOLT 8 connection between two nodes that both set 449 in `init`, usually without a channel. It carries discovery messages and keep-alive only, never lobby or round messages. Which nodes to link to is local policy; section 13 recommends how.

### 10.1 `overlay_init`: the lobby store flag

`overlay_init` (kind 153) is the factory handshake of an overlay link. It works like the relay flag in Bitcoin's `version` message, which blocks-only nodes have used since 2012 (ledger A6; PR F13).

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | The node's chain |
| 4 | `store` | `u8` | 1: this node is a store node (11.1). 0: it is not. Other values invalid |

| Rule | Text |
|---|---|
| I1 | Each side sends `overlay_init` once, as its first discovery message on the connection, before any `beacon_filter`, beacon or `pool_request` |
| I2 | The flag cannot change on a connection. A second `overlay_init` is ignored. To change the flag, a node reconnects |
| I3 | `lobby_beacon`, `beacon_filter`, `pool_request` and `pool` received on a connection before the peer's `overlay_init` are ignored. The query kinds 129 to 139 and `listing_not_held` (155) need no `overlay_init`: direct queries work on any connection (section 14) |
| I4 | A wrong `chain` or an invalid `store` value: ignore the message and do not use the connection as an overlay link |
| I5 | A node that sends `store` = 1 MUST meet the duties of 11.1 for the whole connection |
| I6 | A light client sends `store` = 0 and the filter "nothing" (10.2); it may then send `pool_request` |

Vector D13.

### 10.2 `beacon_filter`: what flows on a link

Modelled on BOLT 7's `gossip_timestamp_filter`: a node sends no gossip it did not generate until the peer sends a filter; a new filter replaces the old; a filter matching nothing turns relaying off; a node's own gossip is sent regardless. Format unchanged from draft 1.

**`beacon_filter`** (kind 143), records, all required:

| Type | Field | Size |
|---|---|---|
| 2 | `chain` | 32 |
| 4 | `first_height` | `u32` |
| 6 | `height_range` | `u32` |

- A beacon matches if `first_height` ≤ `open_height` < `first_height` + `height_range` (computed without overflow).
- Before a peer's first filter, a node sends it **only its own** beacons. After it, the matching beacons as they are held (RL1).
- **No backlog.** A filter governs live relay only. Beacons held before the filter are caught up by `pool_request` (11.4).
- A new filter replaces the previous one. (`0xFFFFFFFF`, 0) means "send me nothing" (vector D10). At most one filter per minute per peer; more are ignored.
- **Relaying by default:** a relay sends (0, `0xFFFFFFFF`) after `overlay_init`. A node that does not want to relay sends (`0xFFFFFFFF`, 0) and forwards nothing.
- Relay links carry every valid beacon. Interest filters (profile, channel size) belong to the pool request only, so the overlay never splits by interest (PR F4).
- **No node ever sends listings or lobby indexes about other hosts unasked.** Only beacons, which carry no terms, are pushed. Store nodes send listings only as answers.

## 11. Store nodes, fetching a listing, and the pool request

### 11.1 Store-node duties

A store node is a relay that sent `store` = 1. While the connection lasts it MUST:

| Duty | Rule |
|---|---|
| S1 Fetch | For every beacon it holds (not orphans), fetch the listing by the fetch order (11.2), after an initial uniform random **0 to 60 s** delay, so a host is not hit by every store node at once (PR F3) |
| S2 Check | Accept a listing only if it passes 5.2, its `host_key` equals the beacon's `host_id`, its `listing_id` the beacon's `outer_digest`, and the outer record's profile and `channel_sat` equal the beacon's. A listing that fails is not stored; the beacon stays held |
| S3 Keep | Keep the listing until its `expiry_height`, the outer `deadline`, or a withdrawal beacon, whichever comes first. The store is bounded by the beacon caps: at most 4 listings per host |
| S4 Serve | Answer every `listing_request` at once: the listing if it holds it, else `listing_not_held` (11.3). Never wait to fetch first |
| S5 Pool | Answer `pool_request` over overlay links and by onion message (11.4) |
| S6 Persist | SHOULD keep its store across restarts (8.6) |
| S7 Limits | Per link, at most 16 `listing_request`s in flight and 20 per 10 s; more are dropped silently. By onion message, H2's limits apply |

A store node MAY cap its store. When full, it evicts first the listings of the host with the most stored listings, then the nearest deadline. It never evicts to make room for a host that already has 4 (PR F5).

### 11.2 Fetching a listing: the fetch order

Any node that wants a listing (a store node by S1, an interested node when its user wants one) fetches it so:

| Rule | Text |
|---|---|
| G1 | **One source at a time.** At most one fetch per beacon in progress |
| G2 | **Store peers first.** Ask a store peer this node is linked to; outbound links before inbound. At most 2 store peers per listing |
| G3 | A store peer answers at once. On `listing_not_held`, or 30 s without an answer, go to the next source |
| G4 | **The host last.** Wait a uniform random **0 to 60 s**, then ask the host with `listing_request`, by onion message (6.2) or natively (6.3). The host's H2 limits apply (ledger A5) |
| G5 | Check the listing as S2. A failed listing from a store peer: try the next source. From the host: give up on this beacon |
| G6 | At most 16 `listing_request`s in flight per peer |
| G7 | A host that does not answer: the beacon is kept until it expires; nothing is shown |

Why this order: a store peer answers from memory and the host never learns who asked. The random wait before the host spreads load and gives store nodes time to fetch first (ledger A5, A6).

### 11.3 `listing_not_held`

`listing_not_held` (kind 155; onion payload type 106385), store node → asker. "I do not hold this listing." It says nothing about whether the lobby exists.

| Type | Field | Size |
|---|---|---|
| 2 | `chain` | 32 |
| 4 | `outer_digest` | 32 (the one requested) |

- Sent only as an answer to `listing_request`. Unasked, or for another digest: ignored.
- A node that is neither the lobby's host nor a store node MAY answer `listing_not_held`, or ignore the request.
- A host answers its own lobbies with `listing` (record 2 or 4), never with `listing_not_held`.

Vector D16.

### 11.4 The pool request

A node asks an F node for the live beacons it holds (ledger A3). Precedents: Lightning's gossip queries, Bitcoin's `mempool` message (BIP 35), gossipsub's IHAVE/IWANT. Uses: catch-up after being offline, a new overlay link, and the light-client path. Beacons are signed, so the answering node can withhold beacons but not forge them.

**`pool_request`** (kind 145; onion payload type 106381), asker → F node:

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 3 | `profiles` | `u8` | No. Bitmap as in 6.1: send only beacons whose `profile` bit is set |
| 5 | `channel_range` | 16 | No. `u64` smallest, `u64` largest `channel_sat`, smallest ≤ largest: send only beacons with `channel_sat` in the range |
| 7 | `after` | 33 | No. Page cursor: send only beacons whose `host_id` is greater than this key |

**`pool`** (kind 147; onion payload type 106383), F node → asker:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | Equals the request's |
| 4 | `beacons` | 0 or more | Entries, each `u16` length then the beacon's records (166 bytes today). In increasing `host_id`, then increasing `sequence`. All of one host's matching beacons are in the same page |
| 5 | `next` | 33 | Present when more matching beacons remain: the last `host_id` in this page. The asker sends it as `after` |

| Rule | Text |
|---|---|
| PL1 | The answer holds only beacons the answerer holds (not orphans), live at its tip, matching every filter field given. No filter field: every live beacon |
| PL2 | Page size: records at most **60,000 bytes** natively, at most **30,000 bytes** by onion message (178 beacons at 168 bytes each; vector D15) |
| PL3 | **Rates** (PR F14). Over an overlay link: one request per connection, and at most one an hour per peer. By onion message: at most one per 60 s per incoming peer. A request with `after` that follows the previous page within 60 s continues that request and does not count again. More are dropped silently |
| PL4 | Store nodes MUST answer, on both carriers. Other relays SHOULD answer over overlay links and MAY answer by onion message |
| PL5 | The asker runs 8.3 on every beacon in the answer. A light client, which cannot run B7, checks the host as 12 says |
| PL6 | Catch-up: a relay sends `pool_request` with no filter on each new overlay link, after `overlay_init` and `beacon_filter` |

Size: about 2 live beacons per host, 168 bytes each: about 34 KB at 100 hosts, 336 KB at 1,000 (several pages).

## 12. Light clients

A light client has a chain server but no gossip graph. It finds hosts by any of these; none needs a coordinator.

| Path | How | What the client checks |
|---|---|---|
| Invitation or QR | `<host_key, 66 hex>@<address>:<port>` (`messages.md` 2), optionally followed by `#<outer_digest, 64 hex>` to name a lobby. A host not in gossip may give a blinded contact instead **(open, point 8)** | The handshake matches the key; then queries and `terms.md` 7 |
| Built-in list | Shipped per network: entries `host_key`, address, optional label. The user can add, remove and edit entries. Never changed remotely without the user's action | Same |
| **Store nodes** | Steps below | Each beacon fully; each new host through `host_list` |
| Nostr | Section 17 | Listing (5.2), anchor (9) |
| Trusted full node | `host_list_request` to the user's own node or current host (7) | Gossip signatures and channel anchors: entries can be hidden but not forged |

**Through store nodes** (PR B10):

1. **Choose 1 or 2 store nodes**: from the built-in list, the current host, or an invitation. At least one should not be a host. One honest source is enough, because the data is signed (BIP 157's reasoning).
2. **Send `pool_request`** with the user's filter, by onion message through the client's own channel peer with a fresh blinded reply path, or over a direct connection (over Tor where possible) after `overlay_init` with `store` = 0 and the filter "nothing". The store node learns that someone asked, not who (onion), or the asker's address (direct, without Tor).
3. **Check each beacon**: B2 to B6 and B8 to B10 against the chain server's tip.
4. **Check each new host** with `host_list_request` naming its key (7, D19) to the same store node or another: the `node_announcement` with bit 449 and one `channel_announcement`; signatures; then the channel's output through the chain server (2 or 3 lookups). Cache for 144 blocks. A client that skips this trusts the store node for B7, and says so in its interface.
5. **Merge** answers from all sources.
6. **Fetch listings** it wants from the same store node (`listing_request`), and the host only if the store node answers `listing_not_held`.
7. **Then** query the chosen host for live state (`hello`) and join directly.

A light client never relays.

## 13. Overlay peering (informative)

**This section is informative.** Peers need not agree on it; its numbers are recommended defaults, from the peering research (PR B1 to B9). Bitcoin keeps the same kind of policy out of its BIPs, in code. Every number is **proposed** and to be tuned on signet.

**The idea.** Choose overlay peers yourself, from the Lightning gossip graph, under Bitcoin-style slot and diversity rules, and keep them with gossipsub-style local scoring. The graph already lists every F node, and each entry cost a funded, announced channel. So there is no random walk, no peer exchange and no topic registration.

### 13.1 Who may be a peer

| Rule | Text |
|---|---|
| E1 | **Eligible:** in the local gossip graph, sets 449, has an address this node can reach, and its oldest announced channel is at least **1,008 blocks** old (the age floor) |
| E2 | While fewer than **16** nodes meet E1, the age floor drops to **144 blocks**; while fewer than **8**, to 0 |
| E3 | A **host**, for the mix rule, signs at least one live beacon this node holds or has seen in the last 1,008 blocks |
| E4 | Eligibility is checked again when the link opens: the peer must send `overlay_init` within 30 s. A peer whose current announcement has lost the bit is dropped |
| E5 | **Self-selection from the graph only.** Never take candidates from peers; no peer exchange. An optional built-in seed list is used only until gossip is synced |

### 13.2 How to pick

| Rule | Text |
|---|---|
| P1 | Group eligible nodes by **address group**: IPv4 /16; IPv6 /32; the AS number when an AS map is loaded; Tor v3 by Bitcoin Core's grouping of onion addresses |
| P2 | **Address group first:** choose a group uniformly at random among groups with an eligible node not yet linked, then a node uniformly in it. Sybils packed into one range get one ticket per draw |
| P3 | Prefer a node with which this node already has a channel, for at most 2 slots |
| P4 | Do not weight by channel capacity: it would make large hosts the centre of the overlay |

### 13.3 Slots

| Name | Value | From |
|---|---|---|
| Target links | **6** | gossipsub's default 6; Lighthouse 5 |
| Low / high | **4 / 8** | The owner's 4 to 8 |
| Outbound minimum, opened by this node | **3** | gossipsub `D_out`: below the low mark and at most half the target |
| Anchors kept across restarts | **2** outbound links | Bitcoin `anchors.dat` |
| Scout | **1** short link every **60 min** (exponential delay) and on waking | Bitcoin's feeler and extra block-relay link, scaled to beacon rate |
| Overlay links are **in addition** to channel peers | — | Bitcoin's full-RBF and Libre Relay slots were added, not taken from the normal ones |

- Inbound links count toward the high mark. At 8, accept a new inbound link only if it fills a missing mix requirement; otherwise send the filter "nothing" and close.
- A node never needs more than 8 channel-less connections for the overlay, well under LDK's 2,500, Eclair's 64 and LND's 100 limits.

### 13.4 The mix rule

| Rule | Text |
|---|---|
| M1 | At least **half** the links go to F nodes that are not hosts (E3) |
| M2 | At most **2** links go to hosts |
| M3 | At least **1** outbound link (2 when available) goes to a **store node**, learned from `overlay_init` |
| M4 | When too few non-hosts exist for M1, fill with hosts, each in a distinct address group, and scout every **20 min** instead of 60. The mix is a target that degrades, never a hard stop |

Why: a host has a motive to drop a rival's beacon. Neutral relays dilute that motive. Two host links are enough for spread, because each host sends its own beacons to all its links (RL5).

### 13.5 Diversity

- **V1.** Outbound links: one per address group.
- **V2.** All links: at most **2** per address group.
- **V3.** At most 1 link to nodes known to share an operator. Advisory.

### 13.6 Local scoring

**Local only, never sent, never shared** (section 15). Per link, over a 7-day window.

| Term | Sign | Rule |
|---|---|---|
| First delivery | + | +1 for each valid beacon this link delivered first; capped at +20; decays 1% an hour |
| Missed delivery | − | −1 for each beacon that a scout or another link delivered and this link, linked since before the beacon's `open_height`, never sent within 10 min. Counted only after 20 beacons in the window |
| Invalid | Reject (8.7) | The link is closed at once with a 24 h back-off |
| Behaviour | − (squared) | Over the per-link rate (RL4), reconnecting during back-off, filter churn |
| Store peer | − | A store peer that answers `listing_not_held` for listings it should hold (beacons more than 10 min old). A node MAY de-prefer it |

- **K1.** Below zero: drop the link (send the filter "nothing").
- **K2.** Above the high mark: never break the outbound minimum, the mix rule or anchors; keep the **4** best scores; drop at random among the rest.
- **K3.** Protect the 2 anchors and the link with the most first deliveries.

### 13.7 Rotation, scouts, anchors

| Rule | Text |
|---|---|
| T1 | **Daily rotation:** once every **24 h**, at a random time, replace one outbound link that is neither an anchor nor protected (K3) |
| T2 | **Hourly scout:** every **60 min** (exponential) and on waking from sleep or a restart, open a short link to an eligible node drawn as in P2 from groups not already linked; send `pool_request` (11.4); close. Beacons the scout had that the overlay did not deliver count against the links that should have had them. A scout that delivered a new beacon replaces the worst-scoring non-anchor outbound link |
| T3 | **Anchors:** on clean shutdown, save the 2 best outbound links; reconnect them first |
| C3 | Catch up from **2** peers in different address groups, at least one a store node |

### 13.8 Bandwidth

Assuming 1.5 new beacons per host a day, 6 links each delivering every beacon, 206 bytes on the wire, 168 bytes per pool entry:

| Hosts | Beacons a day | Received per node a day | Full catch-up |
|---|---|---|---|
| 10 | about 15 | about 19 KB | about 3 KB |
| 100 | about 150 | about 185 KB | about 34 KB |
| 1,000 | about 1,500 | about 1.9 MB | about 336 KB |

A store node also fetches one listing per beacon: at most 4,817 bytes, typically about 0.5 KB. At 1,000 hosts that is under 1 MB a day, and a store of at most about 4,000 live listings, at most 19 MB. For comparison, Lightning gossip is about 103 MB of unique data a day (DR A1).

## 14. Bootstrapping, and direct queries (design C)

Discovery must work with a handful of F nodes, and with none on the overlay. It then **degrades to design C**: the bit plus direct queries (PR B9, C).

| Rule | Text |
|---|---|
| DQ1 | Every F node SHOULD answer `lobby_index_request` over a direct connection; one that hosts nothing answers an empty index. A host MUST answer (3, rule 4) |
| DQ2 | A wallet that has no beacons for its interest (no overlay links, fewer than 8 F nodes in its graph, or a light client with no store node) sends `lobby_index_request` directly to the F nodes it knows: its built-in list, invitations, and, with a graph, the nodes in it that set 449. **Proposed:** at most once per node per hour, and at most 32 nodes per hour |
| DQ3 | Index entries are hints (Q2): the wallet fetches listings with `listing_request` before showing a lobby |
| DQ4 | Once beacons arrive, the wallet stops polling hosts and uses the beacons, store nodes and the fetch order (11.2) |

| F nodes in the graph | Behaviour (informative) |
|---|---|
| Fewer than 8 | Link to all of them (a full mesh). Members mostly query each host directly (DQ2). The overlay costs nothing and exercises the code |
| 8 to 50 | Normal rules with the relaxed age floor (E2). M4 may apply, with scouts every 20 min |
| More than 50 | Full rules of section 13 |

- Partitions heal by themselves: scouts and rotations draw from the whole graph, not from overlay neighbours.
- The real dependency is a complete gossip graph. A node that has synced gossip from 3 to 5 peers sees every F node. Before that it uses the built-in list.
- Lightning DNS seeds cannot filter by feature bit (BOLT 10). Not needed: gossip is enough.
- **Early honest caveat.** At first almost every F node will be a host run by Gazpacho or early partners. The overlay then adds little over querying each host. It exists so discovery keeps working with hundreds of hosts.

## 15. Reserved, and never on the wire

**Reserved:** a kind number and one sentence, no format (PR F2). Each is specified only when its trigger is reached, without changing anything above.

| Item | Number | What it would be | When |
|---|---|---|---|
| Have-summaries | Kind **149** `beacon_summary` | Per host: a short key prefix, the highest sequence held, a short prefix of that beacon's id (about 16 bytes a host), so a peer sends only newer or different beacons. The id prefix catches two beacons with one sequence | Above about 500 hosts (PR B8, C2) |
| Store-to-store sync | Kind **151** | Store nodes bring each other's listings up to date. Per-host version vectors first | When store nodes are many (PR F16) |
| Sketch reconciliation | No number; through 149 or 151 | Erlay-style minisketch or Negentropy range reconciliation. Short ids must commit to content; decode cost must be bounded | Above about 10,000 hosts (PR F11) |
| Bundled host proofs | Kind **157** | A beacon sent with its host's `node_announcement` and a channel, like package relay | Only if orphans (8.4) prove common (PR F10) |

**Never on the wire:** scoring of links and of store nodes. It is local, as in gossipsub ("never shared") and Bitcoin. This document says only that a node MAY de-prefer a store peer that answers `listing_not_held` for listings it should hold (13.6).

## 16. Privacy

| What | Who learns what | Advice |
|---|---|---|
| Onion query or pool request | The answerer learns that someone asked, not who. Lost if the first hop is the answerer | First hop other than the answerer; fresh reply path each time (O4) |
| Large onion answers | 32,834-byte onions have a smaller anonymity set | Requests in 1,366 bytes |
| Native query | The answerer learns the interest, and the address without Tor | Fresh BOLT 8 key per session; Tor (F2) |
| Pool filter | The answerer learns the asker's interest (profiles, channel size) | Onion; or ask with no filter and filter locally |
| Listing fetch from a store peer | The store peer learns which lobbies interest the asker; the host learns nothing | The fetch order (11.2) puts store peers first for this reason |
| Bit in `init` | Every peer learns "this is a Gazpacho node" | Members use a fresh key per lobby and per query session, so the bit links nothing beyond one connection |
| Bit in `node_announcement` | The whole network learns the node runs Gazpacho | Only nodes that choose to be announced; needed for the overlay |
| Store flag | Overlay peers learn the node stores | Only on overlay links |
| Beacons | Relays learn which hosts open lobbies, with profile and channel size: public by design. They learn nothing about members | Beacons carry no terms and no counts |
| Anchor checks | The chain server learns which outpoints interested the wallet | Tor or the wallet's own server; cache 144 blocks |
| Coin anchor | Publishes one host coin and its value | Use a dedicated coin |
| Nostr reading | Nothing to the host; the relay sees the subscription | Tor; several relays |
| Answers | Never say who joined or how many (`messages.md` live state stays direct) | H3: same answer for everyone |

## 17. Nostr annex (informative, optional)

Validity never depends on Nostr. The annex fixes a kind and tags so wallets interoperate, as NIP-69 did for peer-to-peer orders.

**Listing event**, addressable, kind **31867** (candidate):

| Field | Value |
|---|---|
| `content` | Base64 (RFC 4648, with padding) of the listing record, **with an anchor** |
| `d` | `listing_id`, 64 lowercase hex |
| `expiration` (NIP-40) | Unix seconds: the smaller of the outer `deadline` and publish time + (`expiry_height` − tip at publishing) × 600 |
| `L` / `l` (NIP-32 labels, namespace `gazpacho`) | `["L","gazpacho"]`, `["l","<network>","gazpacho"]` with `signet` or `mainnet`, `["l","<profile>","gazpacho"]` with `safety`, `standard` or `starter`, `["l","anchor-coin" or "anchor-channel","gazpacho"]` |
| `host` | `host_key`, 66 hex (not indexed by relays; for clients) |

Draft 1's host card event (kind 37329) is withdrawn; the kind is reserved (section 4).

Rules:

- **Any Nostr key may publish the event.** Readers MUST verify the inner record and its anchor and MUST ignore the Nostr author for validity. The same listing from several authors is one listing (`listing_id`, then L6).
- **Expiry:** relays and clients SHOULD drop expired events (NIP-40 is not a guarantee); readers also apply L4 themselves.
- **Withdrawal:** publish the withdrawal listing (5.1) under the same `d`; it replaces the event, and L6 makes it win wherever both are seen.
- **Caps:** A3 to A7 in full. A relay or wallet may tighten, never loosen.
- The kind and labels are not registered; a NIP is a public proposal for the owner to decide.

### 17.1 Why Nostr stays, for now

Nostr does five things the overlay cannot (PR D1): it lists hosts outside gossip (taproot-only or unannounced channels); it serves a fresh phone with no channel over a websocket; it fails independently of Lightning; it can carry whole listings; and its relays keep data while hosts and members are offline.

### 17.2 Conditions for retiring the annex (informative)

From PR D3. **All** must hold for **six consecutive months**, measured by a monitor (a full overlay node plus a light-client probe):

| # | Condition | Threshold |
|---|---|---|
| N1 | Overlay size | At least 30 F nodes in gossip, from at least 10 operators, in at least 10 address groups |
| N2 | Store nodes | At least 5 answering pool and listing requests, from at least 3 operators, none over a third |
| N3 | Completeness | At least 99% of beacons seen by the full node reach the light-client probe within 10 min, over 30 days |
| N4 | Light-client path | At least 99% of onion queries from a phone through an ordinary LSP answered within 30 s with retries |
| N5 | Hosts outside gossip | Taproot gossip deployed in at least 2 implementations, or under 5% of hosts listed only on Nostr |
| N6 | New users | A fresh install finds lobbies with Nostr off: built-in store nodes plus a direct (Tor) connection |
| N7 | Availability | At least 3 store nodes up at every sample over 90 days |

Recommendation (PR D4): keep Nostr as an optional fallback now. When design D ships, wallets use the overlay first and Nostr second. When N1 to N7 hold for six months, the annex becomes "off by default, out of the main text"; wallets may still read it. Do not expect that before taproot gossip ships (N5). Retiring needs no format change: the signed listing is the same on every path.

## 18. Release

| Release | Design | What ships | What does not |
|---|---|---|---|
| **Demo wallet** (signet, first) | **C**: bit plus direct queries | Join by link or QR. Built-in, editable host list. Bit 449 on every Gazpacho node (candidate, unregistered). Direct native queries, kinds 129 to 135, as the main path, with every F node answering `lobby_index_request` (14). **Nostr** listings with coin anchors, read and publish (signet unit 10,000 sat). Channel anchors optional | No beacons, store nodes or overlay: the demo needs no store machinery (ledger A6). No onion queries. No `host_list`. Collecting off and not offered |
| **Next** (before mainnet) | **D**: beacons, store nodes, overlay | Beacons (8) and overlay links (10), store nodes and the fetch order (11), the pool request, native and onion. Onion-message queries (6.2). Overlay peering (13). Wallets use the overlay first and Nostr second. Collecting offered, off by default; storing offered, off by default. Channel anchors | |
| **Later** | | `host_list_request` from a trusted node. Final numbers registered (owner). Reserved items when their triggers are reached (15). Nostr retired when N1 to N7 hold (17.2). Taproot channel anchors when taproot gossip merges | |

Why this order: C is small and changes nothing for anyone else, and it is what D degrades to anyway (14). D needs enough F nodes in the graph to be worth it (PR C: "C, core; ship first. D, target design").

## 19. Changes this needs in other documents

| Document | Change | State |
|---|---|---|
| `messages.md` 4 | `scope` all zero in `hello` and in discovery kinds 128 to 159 | Done |
| `messages.md` 6.1 | Scope-zero `hello` lists only **listed** lobbies, at most 4 (H1), instead of up to 16; drop "Listing belongs to Nostr later" | **Not done** (open point 9) |
| `messages.md` open point 1 | Answered: one bit of our own, `factory_capable`; members set 449 in `init` (section 3) | Done |
| `PROTOCOL.md` 7, 8, 9, 10 | One bit; card reserved; new kinds 145, 147, 153, 155; reserved 149, 151, 157 | Done |
| `DESIGN.md` 11, `KNOWLEDGE-BASE.md` 5 | Listings no longer "on Nostr" only | Done |
| `LOBBY.md` "What is public" | Gains the beacon, the onion query, store nodes, the pool request and anchors | Not done |
| `terms.md` open point 7 | Answered: the listing carries the same bytes (5.1) | Not done |

## 20. Test vectors

Computed by `tools/spec-vectors.py` (run with `python -I tools/spec-vectors.py`). Test keys as `terms.md` section 11; the extra test keys are `host coin` and `other host`. **Never use them for coins.** Auxiliary randomness 32 zero bytes. Every vector depends on T1's `outer_digest` `75e970b6…f0a424f2`, signet, tip 290,000, and on the candidate numbers of D0: a change of either changes the bytes, and the vectors are regenerated.

Changed in draft 2: D0, D5, D7, D8, D9. New: D13 to D19. Withdrawn: D1, D3 (the card). Unchanged: D2, D4, D6, D10, D11, D12.

**D0. Candidates** (section 2): bit 448/449 (features field with bit 449: 57 bytes); onion types 106369 to 106385 odd; native kinds 145, 147, 153, 155, reserved 149, 151, 157; Nostr listing kind 31867. Reserved only: card TLV 118685, Nostr kind 37329.

**D1.** Withdrawn (host card).

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

**D3.** Withdrawn (signed host card).

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

**D5. Queries.** The index record no longer carries a card.

```
lobby_index_request records, 34 bytes: 0220 || signet chain hash
native, kind 129, 74 bytes:
ce37677a6601 0081 00…00 (32) 0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
onion payload field, type 106369, 40 bytes:
fe00019f81 22 0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
index_digest = fbaa6c4d52499b52cc466a804957e27f3ecdc550f9d48e03c9e0a6905d4ae93b
index record, 192 bytes (chain, host_key, as_of 290,000, one T1 entry, sig):
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e
3473349156060400046cd0083175e970b6d95c7de97bf35f67033e2c9f55de1e
a54beecb8431419659f0a424f2000000006af501800200000000000186a0f040
46d41d6a629e2a116e39aca95c56c399a743baed5ef2b5b94f468b610acf3daf
e70ba57689efa21ced4ec72d2008a2feb01eeb085bb2c5c9d93dc930c6c34ae8
lobby_index records, 194 bytes: 02c0 || index record (native message 234 bytes)
listing_request records, 68 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659
f0a424f2
listing answer records, 456 bytes: 02fd01c4 || D4 (native 496 bytes; onion payload field 464 bytes)
listing answer "unknown": 0420d0d4162d5064aa52a4ff1e44baaecb8fbd96c19e4923a87bbdffcdeb5c02a6dd
```

The tool asserts that the native and onion forms end in the same record bytes.

**D6. Nostr content.** Listing event `d` = `75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2`, `content` = base64 of D4, beginning `AiECuN1zml0rBwn+xc6k6E63gRuQTM+HHHehp4seNHM0kVYE4QIg9h7uO2Oj` and ending `CAinXB0p4up0=` (604 characters). No card event. Event ids and Nostr signatures depend on the author and the time and are not vectors.

**D7. Beacon** for lobby T1, open 290,000, deadline 290,144, sequence 1, profile 2 (Standard), `channel_sat` 100,000:

```
beacon_id = 7f25917dabb16e21d704d6e8eea407b832959cd2bdfe01815176f2607c295a92
records, 166 bytes:
022102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473
349156042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb84314196
59f0a424f2060400046cd0080400046d600a04000000010c01020e0800000000
000186a0f0407e351d368a5127c77f17d599b216c6e3532ff321f1070d5d0913
70b415ad48cda6244cf3783e35c27ed6a649207359ed70f138f1e4578b019d86
da042cfb9417
native lobby_beacon, kind 141, 206 bytes: ce37 677a6601 008d 00…00 (32) || records
```

**D8. Withdrawal** of D7: sequence 2, deadline 290,000, same profile and channel: `beacon_id = b20f1a4a7b6086ac881f1b2990708eefdde35aa92a224800759f7a7c98e54f45`, `beacon_sig = 031c5bfb35c45030aa19e8fa7f24587bf928e7445f889af49a23ff3595b86d67f7f11d6999e754e1a49fbae721e08119b916ac7e417da89a182ecdbb08b683c6`.

**D9. Refuse:** D7's records with a signature by test key `other host`: B5 fails (Reject). Its `beacon_id` does not enter the seen-set, so the genuine D7 arriving afterwards is accepted.

**D10. `beacon_filter`.** "Everything" (0, `0xFFFFFFFF`), native kind 143, 86 bytes: `ce37677a6601008f` ‖ 32 zero bytes ‖ `0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881080000000404000000000604ffffffff`. "Nothing" (off) records: `0220f61eee3b…08000000 0404ffffffff 060400000000`. Seen-set sizes: 10 F nodes → 1,024 entries (41 KB); 1,000 → 8,000 (320 KB); 10,000 → 65,536 (2.6 MB).

**D11. Refuse:** D2's `coin_sig` presented in a listing by host key `other host`: the anchor statement names another key and the signature fails (A1). This is the "nobody can borrow a coin" rule.

**D12.** Five beacons of one host, sequences 1 to 5, different lobbies: the held set keeps sequences 2 to 5 (B10).

**D13. `overlay_init`**, store = 1, native kind 153, 77 bytes:

```
ce37677a6601 0099 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000 040101
store = 0 records, 37 bytes: 0220 || chain || 040100
```

**D14. `pool_request`**: Standard only (`profiles` = `0x02`), `channel_range` 50,000 to 200,000:

```
records, 55 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
00000301020510000000000000c3500000000000030d40
native, kind 145, 95 bytes: ce37677a6601 0091 00…00 (32) || records
onion payload field, type 106381, 61 bytes: fe00019f8d 37 || records
no filter (everything), 34 bytes: 0220 || chain
```

The tool checks that D7 matches, and that a Starter beacon and a 1,000,000-sat beacon of the same host do not.

**D15. `pool`** answering D14 with D7, the one match; no `next` record:

```
records, 204 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
000004a800a6 || D7 records (166 bytes)
native, kind 147, 244 bytes; onion payload field 210 bytes
```

One entry is 168 bytes: a 30,000-byte onion page holds 178 beacons, a 60,000-byte native page 356.

**D16. `listing_not_held`** for T1, native kind 155, 108 bytes:

```
ce37677a6601 009b 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
```

**D17. Two beacons, one sequence** (B8 b): D7 and a beacon of the same host for lobby `SHA256("lobby 2")`, also sequence 1, `beacon_id = 977b4bbe2e26405b0171a73fdcf6bb5991448534043df9bf4e06d248d5611d00`. Every node keeps **D7** (`7f25917d…`, the lower id) and drops the other, whatever the order of arrival.

**D18. Orphan pool** (8.4): 10 orphans from one link keep the last 8; 72 orphans spread over 9 links keep 64; an orphan 20 minutes old is gone. The tool runs the eviction rule and asserts these.

**D19. `host_list_request`** naming the test host only, native kind 137, 109 bytes:

```
ce37677a6601 0089 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
052102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156
```

Not yet vectors **(open, point 10)**: a channel anchor and a `host_list` entry, which need real BOLT 7 messages with ECDSA signatures.

## 21. Tests

Decoders are generated from the tables and fuzzed, as in `messages.md` 12.

**Encoding**
1. D2, D4, D5, D7 to D19 encode to exactly the bytes above; digests and signatures match.
2. Each record: non-minimal BigSize, types out of order or repeated, a fixed-width field one byte short or long, a length past the end: dropped.
3. A listing of 4,818 bytes; an index of 641 bytes, with 5 entries, a 48-byte entry, or a record 10; a beacon with an extra odd record, `profile` 4 or 0, or `channel_sat` 0; an `overlay_init` with `store` 2; a `pool_request` with smallest > largest: each dropped.

**Feature bit**
4. A host announces 449: an LND, CLN, Eclair and LDK node each keep connecting to it and routing through it, and relay its announcement (3.1). The same host announcing 448 instead: it is shunned.
5. No build ever sets 450 or 451, or appends TLV 118685 to `node_announcement`.

**Listing (hostile host or carrier)**
6. Listing signed by another key; `host_key` not equal to the outer record's; outer record with a bad shape, a mainnet chain on a signet build, or a bound broken: dropped (L2, L3).
7. D4x; start more than 6 blocks ahead; expired; past the outer deadline: dropped or not shown (L4).
8. Two listings with one `listing_id`: the shorter expiry wins everywhere (L6).
9. A host with 5 live listings: only the 4 earliest shown (L7, A4).
10. A listing whose outer record differs by one byte from the `terms_offer` received after `hello`: the member refuses the mismatched offer (`terms.md` 7 step 2).

**Queries**
11. Honest: index then listing, by onion and natively; the record bytes are identical in both.
12. An answer on another reply path or with another `path_id`: ignored (O2). An unasked `listing`: dropped (Q5). `unknown` from a store node: dropped (Q4).
13. `lobby_index` signed by another key; `as_of_height` 7 blocks off; entries not sorted or repeated: dropped (Q1).
14. Rate: a source sending 10 index requests in 10 s gets 1 answer; 100 sources at once: at most 50 answers a second in total (H2).
15. Unlisted and Circle lobbies never appear in any answer, beacon or scope-zero `hello` (H1, F1, B2).
16. Onion to an LND first hop without a channel: dropped; the asker falls back to native after the retry (O6, O7).

**Anchors**
17. Coin anchor unspent with 6 confirmations: accepted; with 5: dropped; spent after acceptance: dropped at the next 144-block check (A1, A2).
18. D11: dropped. One anchor under two live host keys: both dropped (A6).
19. Allowances of D2 at the edges; an anchor of 2,499 sat on signet: listing dropped (A3).
20. A Nostr listing without an anchor: dropped. A relay policy that accepts 5 listings for a 4-listing anchor: the wallet still shows 4 (A7).

**Beacon (honest)**
21. A host opens a lobby: its beacon reaches every relay in a 30-node test overlay within seconds, by immediate relay (RL1); each relay sends it to each link at most once (RL2).
22. Withdrawal D8 spreads and removes the beacon and the stored listing everywhere.
23. A host restarts: it re-sends its live beacons to each new link (RL6); duplicates stop at the first hop.

**Beacon (hostile)**
24. D9 arrives first, then D7 from another link: D9 closes its link (Reject); D7 is accepted (B5: seen only after verify).
25. A beacon whose host has no `node_announcement` yet: held as an orphan, not relayed; the announcement arrives 5 minutes later: the beacon is accepted and relayed (R-O4). After 20 minutes without it: gone.
26. One link sends 100 orphans: at most 8 kept from it; 9 links send 8 each: at most 64 in total, and no link loses orphans to a link holding fewer (R-O2, R-O3, D18).
27. D17 in both orders, at two nodes: both end holding D7 (B8 b).
28. A host sending 9 new sequence numbers within 144 blocks: the ninth is not relayed by any honest relay (B9).
29. A host with 5 live beacons: D12's eviction everywhere (B10).
30. Replay of an older sequence for the same lobby: ignored (B8 a). The same beacon from 8 links: relayed once (B4, RL2).
31. A link sending 100 beacons in one second: 20 accepted, then 1 a second (RL4); the link stays open.
32. A beacon with a 1,009-block lifetime: the link is closed for 24 hours (B3, 8.7). An expired beacon or one 7 blocks ahead: ignored, link kept (B6).
33. A peer that never set 449, or never sent `overlay_init`, sends beacons: ignored (B1, I3). An ordinary Lightning node connected to an F node never receives a beacon.
34. A filter of "nothing": the peer receives only the sender's own beacons. Filters sent 10 times a minute: one honoured. A filter is not followed by a backlog (10.2).

**Store nodes, fetch order, pool**
35. A store node holds a new beacon: it waits 0 to 60 s, asks its store peers, then the host, and stores the listing until expiry (S1 to S3).
36. An interested node asks a store peer that holds the listing: answered at once; the host receives no request. A store peer that does not hold it answers `listing_not_held` at once; the node waits 0 to 60 s and asks the host (G2 to G4).
37. A listing from a store peer whose profile or `channel_sat` differs from the beacon's, or signed by another key: dropped; the next source is tried (S2, G5).
38. A store node restarts: its listings and beacons are back, expired ones gone, hosts re-checked against the graph (S6, 8.6).
39. `overlay_init` sent twice with different flags: the second ignored (I2). A store node that answers no `listing_request`: de-preferred locally; nothing is sent about it (15).
40. Pool request D14 to a node holding D7, a Starter beacon and a large beacon: only D7 returned (D15). Paging with `after` at 1,000 hosts returns every live beacon exactly once.
41. A second pool request on one overlay connection, or within an hour from one peer: dropped (PL3).
42. A pool answer carrying one forged beacon: the link is closed; the other beacons in it are still checked and kept if valid.

**Light client**
43. A light client with two store nodes, one withholding a host's beacons: the client gets them from the other (12 step 5). A store node that forges a beacon: B5 fails.
44. A light client checks a new host with `host_list_request` naming it (D19): a host without bit 449 in its announcement is dropped.

**Bootstrapping**
45. Three F nodes, no beacons: a wallet finds the lobby by direct `lobby_index_request` to each (DQ2); a non-hosting F node answers an empty index (DQ1). Polling stops once beacons arrive (DQ4).

**Overlay peering (informative; tests of Gazpacho's own policy)**
46. Selection keeps the mix and diversity rules when candidates allow; with only hosts it fills (M4) and moves to non-hosts when they appear.
47. An attacker announces 200 F nodes in one /16: at most 2 links go to them (V2), and outbound links use one per group (V1).
48. Anchors are reconnected first after a restart (T3); one outbound link is rotated a day (T1); the scout runs hourly and replaces a link that withheld a beacon (T2).

**Privacy**
49. A query through the answerer as first hop is logged as "no privacy gain" in the test report; through another first hop with a fresh reply path each time: the answerer cannot link two queries by path.
50. The asker's native query uses a key never used for a seat.

## 22. Open points

1. **Final numbers** for the bit pair, the onion payload types and the Nostr kind: chosen and checked by section 2 on the day of first use beyond signet. Registration needs public proposals (a bLIP; a NIP), which only the owner can authorise. Nothing is to be posted.
2. **The beacon's filter fields are proposed** (ledger A4): `profile` and `channel_sat`. A third tiny field is possible: the target size (`u16`) or the deadline in Unix seconds. Each adds 4 to 10 bytes to every beacon. Owner to choose.
3. **Kind numbers.** 145 / 147 follow the research; 153 (`overlay_init`) and 155 (`listing_not_held`) are new. "Don't have" is its own kind rather than a record of `listing`, so a host's "no such lobby" and a store's "not here" never mix. Owner to confirm.
4. **`outer_sig` in the listing.** Left out (5.1); adding it (66 bytes) would let a reader run `terms.md` section 7 step 3 unchanged on the outer record alone.
5. **Channel-less inbound connections.** LND limits inbound peers without channels; whether that blocks overlay links to LND-based Gazpacho nodes is not checked.
6. **Coin anchors other than P2TR key path** (BIP 322 for P2WPKH and others): not in this draft.
7. **Proposed numbers to tune on signet:** 4 listings and 4 beacons per host; 8 new sequences per 144 blocks; 1,008-block lifetimes; orphans 8 / 64 / 20 min; 1 beacon a second, bursts of 20; queue 64; rebroadcast every 6 to 12 h; fetch delays 0 to 60 s; 30 s to the next source; 16 in flight; pool once per connection and per hour, once per 60 s by onion; page sizes 60,000 / 30,000; store limits of S7; H2 rates; direct polling once per node per hour, 32 nodes per hour (DQ2); all of section 13; the 1,000,000 / 10,000-sat units.
8. **Blinded contacts** for hosts not in gossip: format inside invitations and listings not specified.
9. **`messages.md` 6.1** still says scope-zero `hello` lists up to 16 lobbies and that "listing belongs to Nostr later". It must list at most 4 listed lobbies (H1) before native queries ship. Left to the messages editor (ledger B6).
10. **Missing vectors:** a channel anchor and a `host_list` entry (real BOLT 7 messages with ECDSA signatures).
11. **Hosts outside gossip** (taproot-only or unannounced channels) cannot originate beacons (B7) until taproot gossip (bolts#1059) merges. Until then they reach members by invitation, the built-in list, direct queries or Nostr. This is retirement condition N5.
12. **A host could censor rivals** only on links it holds. The mix rule bounds that, but early on most F nodes will be hosts (14). Measure on signet.
13. **Reject closes a link on one bad beacon** (8.7), where draft 1 waited for 10 in 10 minutes. Only view-independent checks are Reject, but a peer with a software bug loses its links for a day. Owner to confirm.
14. **Onion pool requests behind one LSP.** PL3 limits onion requests per incoming peer, so many light clients behind one LSP share one budget. Measure.
15. **Every F node answers `lobby_index_request`** (DQ1), phones included, with an empty signed index. Cheap, but it makes "is this a Gazpacho node that hosts?" askable by anyone who connects. Confirm.
16. **No incentive to run a store node.** Early store nodes will be run by Gazpacho and partners; N2 asks for at least 5 from at least 3 operators before Nostr can go.
17. **`LOBBY.md` and `terms.md`** still need the changes of section 19.
