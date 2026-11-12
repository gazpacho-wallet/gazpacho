# Discovery: finding hosts and their lobbies

Specification draft 3, 2026-11-12. Status: not reviewed. Draft 3 answers the independent review of draft 2 (`notes/review-discovery-d2.md`, cited as **RV** with its finding: RV 2). Draft 2 applied the owner's discovery decisions (`docs/research/ideas-ledger.md` section A, cited as **ledger**) and the peering research (`docs/research/peering-research.md`, cited as **PR**). Background: `docs/research/discovery-research.md` (**DR**). Items marked **(open)** are in section 22. Numbers marked **candidate** are reproducible random picks, not final (section 2). Fields and numbers marked **proposed** wait for the owner.

Conventions (integers, `point`, `sig`, `outpoint`, `TH`, "refuse", "ignore") are those of `messages.md` section 1, except that **discovery kinds are never refused**: every case `messages.md` would refuse is ignored (`messages.md` 4.1). TLV encoding is canonical as in `terms.md` section 2. Words: **host**, **member** as in `PROTOCOL.md`. **Listed** lobby: a lobby the host chooses to make public. Circle lobbies (profile 4) are never listed. **F node**: a node that sets the factory feature bit (section 3).

**What each section is.** Every section heading says **(normative)** or **(informative)**. Normative text is what two implementations need to work together. Informative text gives recommended defaults; peers need not agree on it. Tests in section 21 are tagged **[C]** (needed for the demo wallet, design C), **[D]** (design D) or **[Di]** (design D, Gazpacho's own informative policy).

## 0. Changes from draft 2 (informative)

Draft 1 to draft 2 is recorded in draft 2's own section 0 (commit `fcf1de4`).

| RV | Sev. | Finding, in brief | How draft 3 handles it | Where |
|---|---|---|---|---|
| 2 | H | Withdrawals fail L4; old listings replayed by anyone hide a host's new lobbies | A **withdrawal is its own signed record** (tag `gazpacho/withdrawal`), valid while not live, kept 1,014 blocks, suppressing every listing of that lobby; only the host can sign it, and it is final. A beacon withdrawal counts too. The per-host cap now keeps the **latest** start, and withdrawn listings do not count. Nostr carries withdrawal events; readers fetch them by `d` | 5.3, 5.2 (L7), 6.1, 9.2 (A5), 17 |
| 10 | M | A channel's other end can kill a host's channel-anchored listings through A6 | A6 applies to **coin anchors only**. A channel anchor gives each of its two nodes its own half; neither can affect the other | 9.2 |
| 14, C gaps | L | Builder gaps for design C | Section 14.1 fixes the demo wallet exactly: no graph; sources; which queries; chain server; Tor; coin anchors only; the bit; unregistered marking; Nostr operations (17.1). BIP 86 tweak stated and vector D2t added. Tests tagged by release | 14.1, 9.1, 17.1, 21 |
| 1 | H | One host bypasses the churn limit with a huge first sequence | `sequence` = height × 16 + counter, bounded by the tip (B6). B9 counts **every accepted new number** in any 144-block window, whatever the arrival order; over the limit is never held or relayed. D12 and new D20 run the rules in arrival order | 8.1, 8.3, 20 |
| 3 | H | Seen-set records view-dependent ignores; withdrawals not held or relayed | A beacon enters the seen-set **only when accepted**. Withdrawals are **held tombstones** until `open_height` + 1,008, relayed, and in `pool` answers. B8 compares with tombstones. Seen-set and tombstones persist. Vectors D21, D22 | 8.3, 8.6, 11.4 |
| 4 | H | Beacon path costs almost nothing per host | B7 gets a **price**, the same as Nostr's anchor rule: the host's own halves of channels at least 144 blocks old must total at least `unit` / 4, and back `min(4, max(1, floor(V / unit)))` live beacons. Queues drop by host weight, at most 4 per host per link. Sybil numbers restated | 8.2, 8.3 (B7, B10), 8.5 (RL3), 8.8 |
| 5 | H | Reject closes even a channel peer's connection; no upgrade path | Reject now means **stop discovery on that connection for 24 h**; no connection is ever closed for discovery. Only non-canonical encoding and a bad signature are Reject. Beacons may carry **unknown odd records** (records at most 256 bytes), relayed unchanged; kind 159 reserved for a future beacon version | 8.1, 8.7, 6.3; `messages.md` 4.1 |
| 6 | H | The light-client path cannot be built today | Section 12 says what works now (a **direct BOLT 8 connection to a store node, over Tor**) and what waits (onion queries without a graph). Light clients are **not overlay links** (`overlay_init` record `client`) and have their own budget. `host_list` moves into design D. Lookups counted correctly (3 Electrum, 4 Esplora). Censorship by one store operator stated | 10.1, 11.1 (S8), 12, 18 |
| 7 | M | Eclipse: Tor groups, attacker-controlled counts and flags, gameable scoring, no inbound eviction | Informative policy revised: Tor-only nodes are one group with at most 3 links; regime counts use only nodes at the full age floor and price; at most 2 links below the full floor; store claims tested; first deliveries counted only when confirmed by 2 other groups; anchors chosen by age and diversity; an inbound eviction rule. Limits stated honestly in 12 and 16 | 13 |
| 8 | M | Pool request: free keys, unbound cursor, rate inside answers, fresh nodes | Limits per **address group** as well as per peer; `next` carries a one-use **token** that the continuation must return; beacons in an asked-for `pool` answer are outside the per-link rate, bounded by the page; catch-up waits for gossip sync, and pool-answer orphans have their own bound | 11.4, 8.4 |
| 9 | M | Onion amplification; per-incoming-peer budgets | An onion **answer is never larger than its request**; an asker that wants large pages pads its request. Budgets: a global budget shared fairly among incoming peers (onion), and per address group (native) | 6.2 (O3), 6.4 (H2) |
| 11 | L | Coin-anchor capital can be recycled | "Unspent" is re-checked before showing when the cache is older than **6** blocks | 9.2 (A2) |
| 12 | M | Privacy rows missing | Rows added: the first hop is often the member's own host; the bit in `init`; direct polling; `host_list_request` with keys; Nostr; store fetch | 16 |
| 13 | L | Bandwidth leaves out scouts | Scouts read one page; table recomputed with scouts, rotation and the maximum churn rate | 13.8 |
| 14 | L | Consistency | Section 19 brought up to date; old open point 9 closed; paths to `docs/research/`; direction and scope rules reconciled in `messages.md` 4.1; the bit in the demo reconciled in `messages.md` 2 and `PROTOCOL.md` 8.3; `channel_sat` ≥ 546; L2 refuses profile 4; D5's `unknown` names the requested digest | 19, 5.2, 8.1, 20 |
| 15 | L | Statements stronger than the evidence | Fixed: BIP 37 (2012) versus `-blocksonly` (Core 0.12, 2016); "harmless" removed; "usually" for gossip completeness; full-RBF preferential peering was an unmerged pull request and Libre Relay a fork; one honest source suffices only if it is complete; store nodes do touch the host | 10.1, 8.6, 14, 13.3, 12, 1 |
| 16 | L | Sequences lost on restore | Fixed by the height-derived sequence | 8.1 |
| 17 | L | Normative and informative boundaries | Every section labelled; DQ2's numbers informative; the catch-up rules a builder needs moved into normative 11.4 (PL6); tests tagged | All |

Owner decisions recorded while draft 3 was written: the protocol identifier is decided (`messages.md` 10.3); it does not enter any discovery record.

## 1. The design in one table (informative)

1. Gossip says only **who is factory-capable**: one odd feature bit. No per-lobby data ever goes through BOLT 7 gossip.
2. Terms come only as a **signed listing**, asked for, never flooded. A **signed withdrawal** removes a lobby everywhere.
3. The **lobby beacon** is the one push: a signed note of about 166 bytes, "this host has a lobby open", with no terms, relayed at once among F nodes. A host pays for beacons with channel capital, as Nostr listings pay with anchors.
4. **Store nodes**, which opt in, fetch and serve listings, so interested nodes usually find a listing without asking the host. Store nodes themselves still ask the host once per lobby each.
5. **Collecting** other hosts' lobbies is off by default; **relaying** beacons is on by default (ledger A12).
6. **Nostr** is an optional annex, with conditions for retiring it.

| Layer | What | Carrier | Changes | Section |
|---|---|---|---|---|
| Capability | `factory_capable` on every Gazpacho build with discovery | Odd feature bit 449 in `init` and `node_announcement` | Rarely | 3 |
| Listing and withdrawal | One signed record per lobby, and one signed tombstone when it ends | Query answers; store nodes; Nostr. **Identical bytes on every carrier** | Once per lobby | 5 |
| Queries | `lobby_index_request`/`lobby_index`, `listing_request`/`listing` | Native messages; onion messages later | Per question | 6 |
| Host list | `host_list_request`/`host_list` | Native; onion | Rarely | 7 |
| Beacon | "Host H has lobby L open until height d", with profile and channel size | Native, over overlay links | Per lobby | 8 |
| Anchors | A channel or a coin backing a listing | Inside a listing | While unspent | 9 |
| Overlay links | `overlay_init` (store and client flags), `beacon_filter` | Native, BOLT 8 connections between F nodes | Per connection | 10 |
| Store and pool | Store nodes; fetch order; `listing_not_held`; `pool_request`/`pool` | Native; onion | Per beacon; per catch-up | 11 |
| Peering | Which F nodes to link to | Local policy (informative) | Daily | 13 |
| Live state, joining, signing | `terms_offer`, `lobby_status`, `join`, rounds | Direct BOLT 8 connection only | Often | `messages.md` 6, 7 |

**What protects a member is unchanged.** Nothing found through discovery is trusted. A member joins with `hello` whose `scope` is the listing's `outer_digest`; the `terms_offer` it gets is checked by `terms.md` section 7 in full, and the tree is checked at signing (`safety-rule.md` C8). Discovery can waste a query or hide a lobby; it cannot cost money (RV verdict).

## 2. Numbers: how each is chosen and checked (normative)

Every number here is a candidate printed by `tools/spec-vectors.py` (vector D0). None is final. A final number is chosen **on the day it is first used outside a private test**, by the procedure below, and the check and its date are written into `PROTOCOL.md` section 8.3 or 10.

| Item | Candidate | Range rule | Checks before it is final |
|---|---|---|---|
| `factory_capable` bit pair | **448/449** (advertise 449) | 256 to 511, from one pick `SHA256("gazpacho feature bits")` over 4-aligned blocks. Below 512 keeps the feature field at most 64 bytes (bit 449 gives 57) | (a) bLIP 2 feature-bit table as merged; (b) every open pull request in lightning/bolts and lightning/blips (bLIP-56's 270/271 among them); (c) known unregistered uses in LND, Core Lightning, Eclair, LDK; (d) the experimental "+100" copies of pending bits. Next candidates if taken: 452/453, 456/457 |
| Onion payload types | **106369 to 106385, odd** (nine) | Odd, one block of 64 above 65,600 | bLIP 2 onion-message table; BOLT 12's payload types; open pull requests; LDK, CLN, Eclair, LND handlers |
| Native kinds | **129 to 147 odd, 153, 155**; 149, 151, 157, 159 reserved | `PROTOCOL.md` 10.1 range 128 to 159 | None outside this project: kinds live inside type 52791 |
| Nostr kind | **31867** (listing and withdrawal) | Addressable, 30000 to 39999 | The NIPs repository kind table on the day (recalled uses listed in the tool, **not verified today**) |
| Tags | `gazpacho/listing`, `gazpacho/withdrawal`, `gazpacho/index`, `gazpacho/anchor`, `gazpacho/beacon` | `PROTOCOL.md` 8.2 | Registered there before use |
| **Reserved only** | Card TLV **118685**; Nostr kind **37329**; tag `gazpacho/card`; index record 10 | Never reused | None: never sent |

**Unregistered builds.** Until a number is registered (only through a public proposal, which only the owner can authorise), it is used **only on signet**, and a build that uses it says so: `gazpacho --version` prints the line `discovery numbers: unregistered candidates (signet only)`, and the interface's About page shows the same words. A build refuses to start discovery on any other chain.

### 2.1 Why 128 to 159

The research draft (DR B8) proposed native kinds 35 to 53, which lie in `PROTOCOL.md`'s session range. `PROTOCOL.md` reserved **128 to 159** for discovery, so this document uses that range.

## 3. The feature bit (normative)

| Name | Pair (candidate) | Bit sent | Contexts | Who sets it | Meaning |
|---|---|---|---|---|---|
| `factory_capable` | 448/449 | **449, odd** | `init`, `node_announcement` | Every Gazpacho build that includes discovery, member or host | Speaks the SuperScalar factory protocol natively on type 52791; takes part in discovery as this document says |

Rules:

1. A build that includes discovery sets 449 in `init`, from the demo wallet (design C) on. A build without discovery sets no bit (`messages.md` 2). A node with an announced channel also sets 449 in `node_announcement`.
2. **There is no hosting bit.** A **host** is a node that sends beacons (design D) or answers `lobby_index_request` with at least one entry (design C). Anyone may host (owner decision 4).
3. An F node SHOULD answer `lobby_index_request` over a direct connection, with an empty index if it hosts nothing (section 14; open point 7).
4. A host MUST answer section 6 queries for its own lobbies over a direct connection. In design D it also answers by onion message if it sets `option_onion_messages` (38/39).
5. Nothing that touches money depends on the bit. A wrong bit costs a wasted connection.
6. A node with no announced channel has no `node_announcement`. It sets the bit in `init` only, and its beacons are not accepted (B7). It reaches members by invitation, the built-in list, direct queries or Nostr.

### 3.1 Why the bit must be odd

Read from BOLT 7 on 2026-11-12: `node_announcement` feature bits "will be propagated normally", so ordinary nodes relay announcements with bits they do not know. For an unknown **even** bit, a receiver "SHOULD NOT connect to the node" and "MUST NOT route a payment through the node". So the bit is advertised odd (449); the even half (448) is never set (ledger A9).

## 4. The host card: withdrawn (normative)

Removed in draft 2 (ledger A2). **Reserved only, never sent:** `node_announcement` TLV type 118685, Nostr kind 37329, tag `gazpacho/card`, and record type 10 of the index record. A reader treats a record 10 in an index as an unknown even type (the index is dropped).

## 5. The listing and the withdrawal (normative)

### 5.1 Listing record

Exactly the outer terms record plus host key, start height, expiry, optional anchor and signature. A TLV stream, canonical. Unchanged from draft 1.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_key` | 33 | Equals the outer record's `host_key` (`terms.md` type 4) |
| 4 | `outer` | 1 to 4,096 | The outer terms record, byte for byte what `terms_offer` carries |
| 6 | `start_height` | `u32` | The height from which the listing is valid |
| 8 | `expiry_height` | `u32` | `start_height` ≤ `expiry_height` ≤ `start_height` + 1,008 |
| 10 | `anchor` | 1 to 600 | Optional. Section 9. Required on Nostr |
| 240 | `listing_sig` | 64 | BIP 340 by `host_key` over `listing_digest = TH("gazpacho/listing", every byte before record 240)` |

- **Size:** at most **4,817 bytes** (vector D4). Unknown odd records are skipped, covered by the signature and counted in the limit.
- **`listing_id`** is the `outer_digest`. It names the lobby; `listing_digest` names one signed version.
- **No `outer_sig`** (open point 5).
- **One listing, every carrier**: the same bytes in `listing` answers, through store nodes and on Nostr.
- **Live** while the reader's tip is below `expiry_height`, the reader's clock is before the outer `deadline`, and no withdrawal (5.3) for it is held.
- A host may re-sign a listing with an **earlier** `expiry_height`, never a later one (L6). To end a lobby it sends a withdrawal.

### 5.2 What a reader checks

In this order. Any failure: drop the listing, never show or forward it.

| Rule | Check |
|---|---|
| L1 | It decodes canonically within 4,817 bytes; records 2, 4, 6, 8 and 240 present |
| L2 | `outer` decodes under `terms.md` section 2 and passes `terms.md` section 7 steps 4 and 5. The outer `profile` is not 4 (Circle is never listed) |
| L3 | `host_key` equals the outer record's `host_key`; `listing_sig` verifies under it |
| L4 | `start_height` ≤ tip + 6; `start_height` ≤ `expiry_height` ≤ `start_height` + 1,008; live (5.1) |
| L5 | If `anchor` is present it passes section 9; if the carrier requires one (Nostr) it is present |
| L6 | Two valid listings with the same `host_key` and `listing_id` and different bytes: keep the smaller `expiry_height`; on a tie, the smaller `listing_digest` |
| L7 | **Per-host cap.** Withdrawn listings do not count. At most 4 live listings per `host_key` (A4); on Nostr, at most the anchor's allowance (A3). Over a cap, keep the **latest** `start_height`, ties by smaller `listing_id` (A5). A replay of old listings therefore cannot hide a host's newer lobbies (vector D23) |
| L8 | Local policy may drop more, never accept more (A7) |

Then the listing is shown and compared with the member's conditions by `terms.md` section 9; nothing in it is trusted.

### 5.3 Withdrawal record

A **withdrawal** is a signed tombstone: "lobby L of host H has ended". It is valid when the listing is no longer live, which is exactly when a reader needs it (RV 2).

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_key` | 33 | The host's key |
| 4 | `listing_id` | 32 | The lobby's `outer_digest` |
| 6 | `withdrawn_height` | `u32` | The host's tip when withdrawing |
| 240 | `withdrawal_sig` | 64 | BIP 340 by `host_key` over `withdrawal_digest = TH("gazpacho/withdrawal", every byte before record 240)` |

141 bytes (vector D4w). No other records are defined; unknown odd records are skipped and covered by the signature; at most 256 bytes.

| Rule | Text |
|---|---|
| W1 | Valid if it decodes canonically, `withdrawal_sig` verifies under `host_key`, and `withdrawn_height` ≤ tip + 6 |
| W2 | **Kept** until the reader's tip reaches `withdrawn_height` + 1,014. By then every listing the host signed for that lobby has expired anyway (any listing has `start_height` ≤ `withdrawn_height` + 6 and lasts at most 1,008 blocks) |
| W3 | **Suppresses** every listing with the same `host_key` and `listing_id`, whatever its bytes, author or carrier, in either order of arrival (vector D23) |
| W4 | **Final.** Nothing undoes a withdrawal: only the host can sign one, and not even the host can revoke it. A host that wants the lobby back opens a new lobby (a new salt gives a new `listing_id`) |
| W5 | A **beacon withdrawal** (8.1) for the same host and `outer_digest` counts as a withdrawal of the listing, with `withdrawn_height` = its `sequence` ÷ 16 |
| W6 | A withdrawal is not a lobby: it is never shown, only used to hide |
| W7 | When a lobby starts or is cancelled, the host MUST make a withdrawal, serve it in `listing` answers (6.1), publish it wherever it published the listing (17), and, in design D, send a beacon withdrawal |

## 6. Queries (normative)

Four messages between an asker and a host. **The record bytes are the same on both carriers.** Answers carry signed records, so the messages themselves are unsigned, as `terms_offer` is.

### 6.1 Records

**`lobby_index_request`**, asker → host: 2 `chain` (32, required); 3 `profiles` (`u8`, optional: bit (p − 1) for profile p, bit 0 Safety, bit 1 Standard, bit 2 Starter, bits 3 to 7 zero).

**`lobby_index`**, host → asker: one record, type 2 `index` (1 to 640 bytes), the signed **index record**:

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | Equals the request's |
| 4 | `host_key` | 33 | The host's node key |
| 6 | `as_of_height` | `u32` | The host's tip when answering |
| 8 | `entries` | 0 to 196 | 0 to 4 entries of 49 bytes: `outer_digest` (32), `deadline` (`u64`), `profile` (`u8`), `channel_sat` (`u64`). Distinct digests, increasing order. Values copied from the outer record. Withdrawn lobbies are never entries |
| 10 | — | — | **Reserved** (draft 1's card). Never sent |
| 240 | `index_sig` | 64 | BIP 340 by `host_key` over `TH("gazpacho/index", every byte before record 240)` |

**`listing_request`**, asker → host or store node: 2 `chain` (32); 4 `outer_digest` (32). Both required.

**`listing`**, host or store node → asker: exactly one of

| Type | Field | Size | Meaning |
|---|---|---|---|
| 2 | `listing` | 1 to 4,817 | The listing record (5.1) |
| 4 | `unknown` | 32 | The requested `outer_digest`. **From the host only:** "no such listed lobby" |
| 6 | `withdrawn` | 1 to 256 | The withdrawal record (5.3). From the host, or from a store node that holds it |

A store node that holds neither the listing nor its withdrawal answers `listing_not_held` (11.3).

### 6.2 Onion carrier (design D)

| Rule | Text |
|---|---|
| O1 | Each message is a BOLT 4 onion message whose final hop's `onionmsg_tlv` holds exactly one payload field. Types (candidates): `lobby_index_request` 106369, `lobby_index` 106371, `listing_request` 106373, `listing` 106375, `host_list_request` 106377, `host_list` 106379, `pool_request` 106381, `pool` 106383, `listing_not_held` 106385 |
| O2 | A request MUST carry `reply_path`. The asker accepts only an answer that arrives along that path with its own `path_id`. The answerer MUST answer along `reply_path` only |
| O3 | **No amplification.** An answer onion is **never larger than its request onion**. Requests are 1,366 or 32,834 bytes. An asker that wants an answer that does not fit 1,366 bytes (a large listing, a `pool` page of more than about 6 beacons) sends a 32,834-byte request, padded. An answer that would not fit the request's size is not sent; for `pool` the answerer sends a smaller page instead (RV 9) |
| O4 | The asker SHOULD use a first hop other than the node it asks, and a fresh reply path per request |
| O5 | To reach a node, route to its node key; this needs a route, which a node without a graph cannot build (12) |
| O6 | Onion messages are unreliable. No answer in 30 s: retry once through another first hop, then fall back to 6.3 |
| O7 | The first hop must accept onion messages from the asker. LND by default drops them from peers without a fully open channel (`relay-all` false); CLN, Eclair and LDK accept them by default |

### 6.3 Native carrier

The same records in an ordinary type-52791 envelope (`messages.md` 4), with **`scope` all zero**.

| Kind | Name | From → to | Design | Section |
|---|---|---|---|---|
| 129 | `lobby_index_request` | asker → host | C | 6 |
| 131 | `lobby_index` | host → asker | C | 6 |
| 133 | `listing_request` | asker → host or store node | C | 6, 11 |
| 135 | `listing` | host or store node → asker | C | 6, 11 |
| 137 | `host_list_request` | asker → trusted or store node | D | 7 |
| 139 | `host_list` | → asker | D | 7 |
| 141 | `lobby_beacon` | F node → F node, overlay link | D | 8 |
| 143 | `beacon_filter` | F node → F node, overlay link | D | 10.2 |
| 145 | `pool_request` | asker → F node | D | 11.4 |
| 147 | `pool` | F node → asker | D | 11.4 |
| 149 | `beacon_summary` | **Reserved**, no format | | 15 |
| 151 | Store-to-store sync | **Reserved**, no format | | 15 |
| 153 | `overlay_init` | first discovery message on an overlay or client link | D | 10.1 |
| 155 | `listing_not_held` | store node → asker | D | 11.3 |
| 157 | Bundled host proofs | **Reserved**, no format | | 15 |
| 159 | Beacon, next version | **Reserved**, no format: a future beacon format with new required fields, sent beside kind 141 during a migration | | 8.1 |
| 128 to 158 even | Not used. Discovery must be safe to send to anyone and safe to ignore | | | |

**Discovery is never worth a disconnect.** Every discovery kind is odd. A malformed discovery message, one with a nonzero `scope`, one with an unknown even record, or one sent in the wrong direction is **ignored**, never refused; `messages.md` 4.1 says so for kinds 128 to 159. Section 8.7 lists the only other step a receiver takes.

| Rule | Text |
|---|---|
| F1 | `hello` with scope zero stays as `messages.md` 6.1 specifies (at most 4 listed lobbies). A host MUST support both it and `lobby_index_request`. The demo wallet uses `lobby_index_request`, then `listing_request`, then `hello` with the chosen lobby's `scope` (14.1) |
| F2 | The asker SHOULD use a fresh BOLT 8 key per query session (not a seat key) and SHOULD connect over Tor where available. Without Tor the answerer learns the asker's address. The bit in `init` still says "Gazpacho" (16) |
| F3 | No answer in 30 s: give up on that node for 10 minutes |

### 6.4 Host rules (both carriers)

| Rule | Text |
|---|---|
| H1 | Answers list only the host's own **listed** lobbies in state Open, at most 4. Unlisted, Circle and withdrawn lobbies never appear as entries |
| H2 | **Budgets** (RV 9). Native: per source, at most 1 `lobby_index_request` and 4 `listing_request`s per 10 s, where the source is the **address group** of the connection (13.2 P1; one group for all Tor connections, with a budget 8 times larger); and at most 50 queries per second in total. Onion: a total budget of at most 50 queries per second, **shared fairly** among incoming peers (round-robin: no peer gets a second turn while another waits), with at most 10 per second from any one incoming peer. Beyond that, drop silently (BOLT 4 allows dropping) (ledger A7) |
| H3 | The host MUST NOT answer differently depending on who asks, beyond refusing. (Detectable by comparing with a store node, Nostr or another asker) |
| H4 | `lobby_index` and `listing` answers carry signed records, so they can be relayed or shown later without trusting the carrier |
| H5 | A host never sends `lobby_index` or `listing` unasked |
| H6 | A request whose `chain` is not the host's: ignored |

### 6.5 Asker rules

| Rule | Text |
|---|---|
| Q1 | `lobby_index`: decodes canonically within 640 bytes; `chain` equals the request's; `host_key` equals the node queried (native: the connection's BOLT 8 key; onion: the node routed to); `index_sig` verifies; `as_of_height` within 6 blocks of the asker's tip; entries as in 6.1. Otherwise drop |
| Q2 | Index entries are **hints**. The asker fetches a listing before showing anything as a lobby |
| Q3 | (Withdrawn in draft 2: the card rule) |
| Q4 | `listing`: exactly one of records 2, 4, 6. A listing passes 5.2, its `outer_digest` equals the one requested, and its `host_key` equals the host's (the host queried, or the beacon's `host_id` when it came from a store node). A withdrawal passes W1 and names the requested lobby and the host's key; the asker then holds it (5.3). `unknown` must name the requested digest and come from the host itself. Otherwise drop |
| Q5 | Answers not asked for, or after 30 s: drop |

## 7. Host list (normative; design D)

For a light client that needs to check hosts (12 step 4), from its own node, its current host, or a store node it uses.

**`host_list_request`**: 2 `chain` (32, required); 3 `skip` (`u16`, optional, entries to skip for paging); 5 `keys` (33 × 1 to 64, optional: answer only for these node keys; vector D19).

**`host_list`**: 2 `chain`; 4 `entries`, 0 to 64 entries, each: `u16` length and a `node_announcement` exactly as gossiped (2-byte type included) that sets bit 449; `u8` count c (1 to 4); then c times `u16` length and a `channel_announcement` exactly as gossiped in which that node is `node_id_1` or `node_id_2`. 5 `more` (`u8` 1, optional). At most 60,000 bytes natively, at most 30,000 bytes by onion message.

- **Hidden, never forged.** Every entry carries gossip's own signatures and chain anchors.
- The answering node includes enough channels to meet the beacon price (B7), largest first, at most 4.
- Without `keys`, it SHOULD list first the hosts of live beacons it holds.
- Asker checks per entry: the `node_announcement` signature; bit 449; each `channel_announcement`'s four signatures and that the node is one of its two nodes; each channel as an anchor (9.2 A1); then the price of B7 over the channels that passed. A failed entry is dropped, the rest kept.
- Rates: at most 1 request per 10 s per source, as H2's native budget.
- Never automatic: a wallet asks only a node its user named, or a store node it already uses (12).

## 8. The lobby beacon (normative; design D)

### 8.1 Record

`lobby_beacon` (kind 141):

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `host_id` | 33 | The host's node key |
| 4 | `outer_digest` | 32 | The lobby's identifier |
| 6 | `open_height` | `u32` | Height at which the lobby opened |
| 8 | `deadline_height` | `u32` | `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008. The beacon expires here |
| 10 | `sequence` | `u32` | **Height × 16 + counter**: the host's tip when it signs, times 16, plus a counter 0 to 15 for beacons signed at the same height. Strictly increasing per host. A host restored from its seed continues from its tip, so nothing is lost on restore (RV 16) |
| 12 | `profile` | `u8` | **Proposed.** The outer record's profile: 1, 2 or 3 |
| 14 | `channel_sat` | `u64` | **Proposed.** The outer record's `channel_sat` (`terms.md` type 30): at least 546 |
| 15 to 239, odd | Unknown odd records | | Allowed, skipped, covered by the signature and **relayed unchanged** (RV 5) |
| 240 | `beacon_sig` | 64 | BIP 340 by `host_id` over `beacon_id = TH("gazpacho/beacon", every byte before record 240)` |

- **Size:** records 166 bytes today (vector D7), 206 bytes as a Lightning message. Records at most **256 bytes**, odd records included.
- **Upgrades.** A new optional field is an odd record, which old relays relay. A new required field means a new beacon version under kind 159, sent beside kind 141 until old relays are gone.
- `beacon_id` is the deduplication key. It commits to every field except the signature.
- **Filter fields** (ledger A4) are copied from the outer record; a store node checks they match (S2).
- **Withdrawal:** a beacon with the same `outer_digest`, a higher `sequence`, and `deadline_height` = `open_height`. It is held as a **tombstone** until `open_height` + 1,008, relayed, served in `pool` answers, and withdraws the listing too (W5).

### 8.2 Roles

| Role | Who | What it does | Default |
|---|---|---|---|
| **Host** | Any F node that sends beacons and meets the price (B7) | Sends one beacon per newly opened **listed** lobby, and a withdrawal when it starts or is cancelled. Answers section 6 queries. Re-sends its live beacons (RL6) | When its user hosts |
| **Relay** | Every F node that holds a gossip graph | Accepts beacons (8.3), relays them at once (8.5), answers pool requests on overlay links | **On** (ledger A12) |
| **Store node** | A relay whose user turns storing on | Also fetches, keeps and serves listings, and serves light clients (11.1) | **Off** |
| **Interested node** | A node whose user browses or turns on "collect lobbies" | Fetches the listings it wants (11.2) | **Off** (ledger A12) |
| **Light client** | A node with no gossip graph | Asks 1 or 2 store nodes (12). Never relays | — |

- A host signs at most 8 new `sequence` numbers whose height part lies in any 144-block window (withdrawals count). Receivers enforce it (B9).
- Beacons travel only over **overlay links** (10). Ordinary Lightning nodes never see them.
- **The price is the channel graph** (ledger A8, RV 4). B7 needs the host's own announced channels, at least 144 blocks old, to carry at least `unit` / 4 of half-capacity: 250,000 sat on mainnet, 2,500 on signet. This is the price a coin anchor pays on Nostr (9.2 A3), so the beacon path is never cheaper than Nostr. No coin or channel proof travels with the beacon: each relay reads its own graph.

### 8.3 Acceptance rules

A node runs these on every beacon it receives, in this order, whether by relay or in a `pool` answer. The reference reader in `tools/spec-vectors.py` runs them in arrival order (vectors D12, D17, D20 to D22).

**The seen-set rule (RV 3).** A beacon enters the seen-set **only when it is accepted** (held, or held as a tombstone). Every ignore below depends on the receiver's tip, graph, memory or software version, so an ignored beacon is checked again if it comes back. A Reject never enters the seen-set either, because a bad copy has the same `beacon_id` as the good one.

| Rule | Check | On failure |
|---|---|---|
| B1 | It arrived on an overlay link after `overlay_init` (10), or in a `pool` answer this node asked for | Ignore |
| B2 | Records decode **canonically**; the beacon's records are at most 256 bytes | **Reject** |
| B3 | Records 2, 4, 6, 8, 10, 12, 14, 240 present; no unknown even record; `profile` is 1, 2 or 3; `channel_sat` ≥ 546; `open_height` ≤ `deadline_height` ≤ `open_height` + 1,008 | Ignore (a newer version may allow it) |
| B4 | `beacon_id` already in the seen-set | Ignore (duplicate) |
| B5 | `beacon_sig` verifies under `host_id` | **Reject** |
| B6 | **Heights.** `open_height` ≤ tip + 6. `sequence` ÷ 16 ≤ tip + 6 and ≥ `open_height`. A live beacon: `deadline_height` > tip. A withdrawal: `open_height` + 1,008 > tip | Ignore. A beacon "from the future" is checked again once this node's tip catches up (vector D22) |
| B7 | **Host in the graph, at a price.** `host_id` has a `node_announcement` that sets 449. Let V = the sum, over its announced channels at least **144 blocks** old, of half of each channel's capacity. The host's **beacon allowance** is 0 if V < `unit` / 4, else `min(4, max(1, floor(V / unit)))`, with `unit` 1,000,000 sat on mainnet and 10,000 on signet | Host unknown: hold as an **orphan** (8.4). Known, allowance 0: Ignore |
| B8 | **Sequence.** (a) A held beacon or tombstone with the same `host_id` and `outer_digest`: a tombstone is final (a live beacon after it is ignored); otherwise the newcomer's `sequence` must be higher, and it replaces the held one. (b) A held beacon or tombstone with the same `host_id` and the same `sequence`, different `beacon_id`: keep the **lower `beacon_id`** (vector D17) | Ignore the loser. If the newcomer is lower, it replaces the held one |
| B9 | **Churn** (RV 1). If `sequence` is not yet in this node's memory for the host, it is a **new number**. After counting it, no 144-block window of height parts (`sequence` ÷ 16) may hold more than **8** of the host's new numbers. Every accepted beacon counts, whatever the order it arrived in | Ignore. **Never held, never relayed** (PR B8, R2) |
| B10 | **Cap.** A live beacon (not a withdrawal): at most the host's allowance (B7) of live beacons. Over it, keep the highest `sequence`s; if the newcomer is the lowest, ignore it. Tombstones do not count | Evict the lowest, or Ignore the newcomer |

Then: hold the beacon (or tombstone), record its `sequence` in the host's memory, add `beacon_id` to the seen-set, and relay it (8.5).

### 8.4 Orphans

A beacon may arrive before its host's gossip.

| Rule | Text |
|---|---|
| R-O1 | A beacon that passes B1 to B6 and whose host is unknown (B7) is held as an **orphan**. Not seen, not relayed, not held against the sender |
| R-O2 | Relayed orphans: at most **8** per link, at most **64** in total, each for at most **20 minutes** (vector D18) |
| R-O3 | Over 8 on one link: evict that link's oldest. Over 64: evict the oldest orphan of the link holding the most |
| R-O4 | On each new `node_announcement` or `channel_announcement`, re-check orphans it names; one that now passes B7 continues at B8 |
| R-O5 | Two copies of one orphan (same `beacon_id`) are one orphan |
| R-O6 | **Pool-answer orphans** (RV 8): orphans from `pool` answers this node asked for are bounded separately, at most **256** in total, 20 minutes each, oldest first. A node SHOULD NOT send a catch-up `pool_request` before its gossip sync is done (PL6), so few of these arise |

### 8.5 Relay

| Rule | Text |
|---|---|
| RL1 | **Immediately** after accepting a beacon, a node sends it to every overlay link whose `beacon_filter` matches (10.2), except the link it came from and links known to have it (ledger A6). Never to light clients (they ask) |
| RL2 | **Known set.** Per link, a node remembers the `beacon_id`s sent to or received from it while they are held, and never sends a beacon to a link known to have it |
| RL3 | **Outgoing queue** per link: at most 64 beacons waiting, and at most 4 from one host. Beyond that, drop the waiting beacon whose host has the **lowest weight** (V × min(age of oldest channel, 1,008) / 1,008, as A7); ties, the oldest waiting. A burst from many cheap hosts cannot push out a heavier host's beacon (RV 4) |
| RL4 | **Per-link rate** for relayed beacons: at most **1 a second**, bursts of **20**. More are ignored. It does not apply to beacons inside a `pool` answer this node asked for, which are bounded by the page (11.4) |
| RL5 | **Own beacons.** A host sends each new beacon of its own to all its overlay links at once, whatever their filter |
| RL6 | **Rebroadcast.** A host SHOULD send its live beacons and tombstones to each new overlay link, and to all links at a random time every **6 to 12 hours** |
| RL7 | No announcement-then-fetch, no batching and no random delay on the beacon path. The random delays belong to fetching listings (11.2) |

### 8.6 Seen-set, held set, memory, persistence

- **Seen-set:** the `beacon_id`s accepted, each kept until its `deadline_height` (a tombstone: `open_height` + 1,008). Size at least `min(262,144, max(4,096, 64 × F))` entries, where F is the number of nodes in the graph that set 449: 40 bytes each, at most 10.5 MB (vector D10). When full, evict the oldest entry whose beacon is no longer held. A lost entry is not always harmless: B8 against the held set, the tombstones and the per-host memory must still drop the copy that comes back.
- **Held set:** live beacons (at most 4 per host, 166 bytes each) and tombstones (bounded by B9: at most 8 per 144 blocks per host).
- **Per host:** every accepted `sequence` and its height part, kept until 1,008 blocks after that host's last beacon's `deadline_height` (B8, B9).
- **Persistence.** A store node MUST, and other relays SHOULD, keep the held set with its tombstones, the seen-set and the per-host memory across restarts, as Bitcoin Core keeps its mempool (PR F7). On start it drops expired entries and re-checks every host against the graph (B7); a beacon whose host fails is dropped, not orphaned.

### 8.7 Misbehaving peers

Two classes, as gossipsub's Reject and Ignore (PR F15):

| Class | Cases | What the receiver does |
|---|---|---|
| **Reject** | B2 (non-canonical encoding, over 256 bytes) and B5 (bad signature), in a beacon or in a `pool` answer | **Stop discovery on that connection for 24 hours**: send `beacon_filter` "nothing", ignore every discovery kind from that peer, do not pick it as an overlay peer. **Never close the connection** for discovery: it may carry channels. A node may close a connection it opened only for the overlay and that carries no channel |
| **Ignore** | Everything else in 8.3 and 8.4, over the per-link rate (RL4), a discovery kind before `overlay_init` | Drop silently. Never held against the peer |

Reject is limited to checks that no version of this protocol relaxes: canonical TLV and BIP 340 signatures.

### 8.8 What the price buys (informative)

At mainnet's `unit`, one live beacon needs 250,000 sat of the host's half of channels at least 144 blocks old; 4 live beacons need 4,000,000 sat. The capital is locked but not spent.

| Sybil hosts | Capital locked (mainnet, 1 beacon each) | Held per relay | Beacons a day through each link (at the B9 maximum) | Store per store node |
|---|---|---|---|---|
| 100 | 0.25 BTC | 17 KB | about 800 | at most 0.5 MB |
| 1,000 | 2.5 BTC | 166 KB | about 8,000 | at most 4.8 MB |
| 10,000 | 25 BTC | 1.7 MB | about 80,000, at the per-link ceiling | at most 48 MB |

On signet the price is nominal (2,500 sat), which is fine for testing and nothing else. RL3 keeps a burst of cheap hosts from erasing a heavier host's beacon from a queue; RL6, scouts and catch-up recover anything dropped.

## 9. Anchors and caps (normative)

An anchor is a chain-backed proof that makes spam cost locked coins. It is required on Nostr only (9.3).

### 9.1 Encoding

The `anchor` value is a TLV stream with exactly one kind:

| Type | Field | Size | Kind |
|---|---|---|---|
| 2 | `channel_announcement` | 1 to 600 | Channel: a full BOLT 7 `channel_announcement` without its 2-byte type, in which `host_key` is `node_id_1` or `node_id_2` |
| 4 | `coin_outpoint` | 36 | Coin |
| 6 | `coin_valid_until` | `u32` | Coin: last height at which the statement holds |
| 8 | `coin_sig` | 64 | Coin: BIP 340 by the output key Q over `TH("gazpacho/anchor", chain ‖ host_key ‖ coin_outpoint ‖ u32 coin_valid_until)` |

A coin anchor has records 4, 6 and 8; a channel anchor record 2 alone. Coin anchors are accepted only on P2TR key-path outputs (script `5120 ‖ Q`). **Q is the output key, after the taproot tweak.** For a BIP 86 wallet coin with internal key P (even y), Q = P + t·G with t = `TH("TapTweak", x(P))`, and `coin_sig` is made with the tweaked secret (vector D2t). D2 uses a secret directly as Q, which is equally valid. Other script types (BIP 322) are open point 6.

### 9.2 Checks

| Rule | Check |
|---|---|
| A1 | Channel: four signatures; then through a chain server: `short_channel_id` → txid (Electrum `blockchain.transaction.id_from_pos`; Esplora `/block-height/:h` then `/block/:hash/txid/:i`); **fetch the transaction** (Electrum `blockchain.transaction.get`; Esplora `/tx/:txid/hex`) to read the output's script and value; the script is the P2WSH 2-of-2 of the two bitcoin keys; unspent (Electrum: the script's unspent list; Esplora `/tx/:txid/outspend/:vout`); at least 6 confirmations. That is 3 lookups on Electrum and 4 on Esplora. A full node may check its graph instead. **Value V = half the output's value, for the node named as the host only.** Coin: `coin_sig` verifies under the output's Q; unspent; at least 6 confirmations; `coin_valid_until` ≥ the backed listing's `expiry_height` and > tip. Value V = the output's value |
| A2 | A failed anchor drops the listing. "Unspent" is re-checked **before showing** a listing whose anchor was last checked more than **6 blocks** ago (RV 11). Other results may be cached for 144 blocks |
| A3 | **Allowance** per anchor: 0 if V < `unit` / 4; otherwise `min(4, max(1, floor(V / unit)))` live listings |
| A4 | At most **4 live listings per `host_key`**, on every path |
| A5 | Over A3 or A4: keep the **latest** `start_height`, ties by smaller `listing_id`; withdrawn listings do not count (L7) |
| A6 | **Coin anchors only:** one coin, one host. Two `host_key`s presenting the same coin while both listings are live: drop both. A coin statement names `host_key`, so a coin cannot be borrowed (D11). **A channel anchor is never dropped by A6:** each of the channel's two nodes uses only its own half, so the other end cannot affect it (RV 10) |
| A7 | **Relays and wallets may only tighten** A3 and A4: a budget, ranking by weight `V × min(confirmations, 1,008) / 1,008`, and when full a rolling minimum (drop the lowest weight; refuse below 1.1 × it; the minimum halves every 12 hours). They never accept beyond A3 or A4 |

### 9.3 Where anchors are required

| Path | Anchor | Why |
|---|---|---|
| Bit in gossip | No | Gossip is its own anchor |
| Beacons and `pool` answers | **No** | B7 prices the host from the receiver's own graph, at the same level as A3 |
| Listings from a store node | Optional | Signed by the host named in a beacon the asker accepted |
| Query to a known host | Optional | The asker chose the host; H1 caps the answer at 4 |
| Invitation, QR, built-in list | No | The user chose the host |
| **Nostr** | **Required** | Anyone can publish anything there for free |

## 10. Overlay links (normative; design D)

An **overlay link** is a BOLT 8 connection between two F nodes that both sent `overlay_init`, usually without a channel. It carries discovery messages and keep-alive, never lobby or round messages. A **client link** is a connection from a light client to a store node (`client` = 1); it carries only requests and answers. Which nodes to link to is local policy (13).

### 10.1 `overlay_init`: the store and client flags

`overlay_init` (kind 153) is the discovery handshake of a connection. It works like the relay flag of Bitcoin's `version` message (BIP 37, 2012), which `-blocksonly` nodes (Bitcoin Core 0.12, 2016) set to off (ledger A6; PR F13).

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | The node's chain |
| 4 | `store` | `u8` | 1: this node is a store node (11.1). 0: it is not |
| 5 | `client` | `u8` | Optional. 1: this is a light client; treat the connection as a client link, not an overlay link (vector D13c) |

| Rule | Text |
|---|---|
| I1 | Each side sends `overlay_init` once, as its first discovery message of kinds 141 to 159 on the connection |
| I2 | The flags cannot change on a connection. A second `overlay_init` is ignored. To change a flag, reconnect |
| I3 | `lobby_beacon`, `beacon_filter`, `pool_request` and `pool` received before the peer's `overlay_init` are ignored. The query kinds 129 to 139 and `listing_not_held` need no `overlay_init`: direct queries work on any connection (14) |
| I4 | A wrong `chain`, or a `store` or `client` value other than 0 or 1: ignore, and do not use the connection for discovery kinds 141 to 159 |
| I5 | A node that sends `store` = 1 MUST meet 11.1 for the whole connection |
| I6 | A client link: the client sends `store` = 0, `client` = 1, and no `beacon_filter`; the store node relays nothing to it and answers its requests (S8) |

### 10.2 `beacon_filter`: what flows on a link

Modelled on BOLT 7's `gossip_timestamp_filter`. Format unchanged from draft 1.

**`beacon_filter`** (kind 143): 2 `chain` (32); 4 `first_height` (`u32`); 6 `height_range` (`u32`), all required.

- A beacon matches if `first_height` ≤ `open_height` < `first_height` + `height_range` (computed without overflow).
- Before a peer's first filter, a node sends it **only its own** beacons. After it, the matching beacons as they are accepted (RL1).
- **No backlog.** Catch-up is by `pool_request` (11.4).
- A new filter replaces the previous one. (`0xFFFFFFFF`, 0) means "send me nothing" (vector D10). At most one filter per minute per peer.
- A relay sends (0, `0xFFFFFFFF`) after `overlay_init`. Relay links carry every valid beacon; interest filters belong to the pool request only (PR F4).
- **No node ever sends listings or lobby indexes about other hosts unasked.**

## 11. Store nodes, fetching a listing, and the pool request (normative; design D)

### 11.1 Store-node duties

A store node is a relay that sent `store` = 1. While the connection lasts it MUST:

| Duty | Rule |
|---|---|
| S1 Fetch | For every live beacon it holds (not orphans), fetch the listing by the fetch order (11.2), after an initial uniform random **0 to 60 s** delay |
| S2 Check | Accept a listing only if it passes 5.2, its `host_key` equals the beacon's `host_id`, its `listing_id` the beacon's `outer_digest`, and the outer record's profile and `channel_sat` equal the beacon's |
| S3 Keep | Keep the listing until its `expiry_height`, the outer `deadline`, or a withdrawal, whichever comes first; keep each withdrawal (5.3, W5) for as long as W2 says |
| S4 Serve | Answer every `listing_request` at once: the listing, else its withdrawal, else `listing_not_held` (11.3). Never wait to fetch first |
| S5 Pool | Answer `pool_request` on overlay and client links (11.4) |
| S6 Persist | Keep its store, tombstones and seen-set across restarts (8.6) |
| S7 Limits | Per overlay link, at most 16 `listing_request`s in flight and 20 per 10 s |
| S8 Clients | Serve client links outside the overlay's slot count, with their own budget: per client, at most 20 `listing_request`s per 10 s and the pool limits of PL3; at most 4 client links per address group. **Informative default:** up to 64 client links in total |

A store node MAY cap its store; when full it evicts the lowest-weight host's listings first (A7's weight), then the nearest deadline, and never evicts to make room for a host already at its allowance.

### 11.2 Fetching a listing: the fetch order

| Rule | Text |
|---|---|
| G1 | **One source at a time.** At most one fetch per beacon in progress |
| G2 | **Store peers first.** Ask a store peer this node is linked to; outbound links before inbound. At most 2 store peers per listing |
| G3 | A store peer answers at once. On `listing_not_held`, or 30 s without an answer, go to the next source |
| G4 | **The host last.** Wait a uniform random **0 to 60 s**, then ask the host with `listing_request` (natively, or by onion message where 6.2 works). The host's H2 budgets apply (ledger A5) |
| G5 | Check the listing as S2. A withdrawal answer ends the fetch: the lobby is over. A failed listing from a store peer: try the next source. From the host: give up on this beacon |
| G6 | At most 16 `listing_request`s in flight per peer |
| G7 | A host that does not answer: the beacon is kept until it expires; nothing is shown |

The host learns who asked only when no store peer had the listing. Store nodes start inside the same random window, so most of them ask the host once per lobby each; interested nodes usually find a store peer that holds it.

### 11.3 `listing_not_held`

`listing_not_held` (kind 155; onion type 106385), store node → asker: 2 `chain` (32); 4 `outer_digest` (32, the one requested). "I hold neither this listing nor its withdrawal." It says nothing about whether the lobby exists. Sent only as an answer. A host never sends it for its own lobbies. Vector D16.

### 11.4 The pool request

A node asks an F node for the live beacons and tombstones it holds (ledger A3). Uses: catch-up, a new overlay link, a scout, and light clients. The answering node can withhold beacons, but not forge them.

**`pool_request`** (kind 145; onion type 106381):

| Type | Field | Size | Required |
|---|---|---|---|
| 2 | `chain` | 32 | Yes |
| 3 | `profiles` | `u8` | No. Bitmap as in 6.1 |
| 5 | `channel_range` | 16 | No. `u64` smallest, `u64` largest `channel_sat`, smallest ≤ largest |
| 7 | `after` | 33 | No. Page cursor: only beacons whose `host_id` is greater than this key |
| 9 | `token` | 8 | With `after` only: the `token` of the page being continued (vector D15b) |

**`pool`** (kind 147; onion type 106383):

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | Equals the request's |
| 4 | `beacons` | 0 or more | Entries, each `u16` length then a beacon's records. Increasing `host_id`, then increasing `sequence`. All of one host's matching beacons and tombstones in the same page |
| 5 | `next` | 33 | Present when more remain: the last `host_id` in this page |
| 7 | `token` | 8 | With `next` only: a fresh one-use value, chosen by the answerer |

| Rule | Text |
|---|---|
| PL1 | The answer holds the answerer's held beacons that are live at its tip and match every filter field, **and its tombstones** (withdrawals, whatever the filter). Never orphans |
| PL2 | Page size: records at most **60,000 bytes** natively; by onion message, what fits the request's onion size (O3): about 1,100 bytes in a 1,366-byte onion (6 beacons), at most 30,000 bytes in a 32,834-byte one (178 beacons) |
| PL3 | **Rates** (RV 8). A request without `after` is a new request. New requests: over an overlay link, one per connection and at most one an hour per peer; and, across all connections, at most **4 an hour per address group** (one group for all Tor connections, with a budget 8 times larger). By onion message: within H2's onion budget, at most one new request per 60 s per incoming peer. **A continuation** (with `after` and `token`) does not count as new only if `after` and `token` equal the `next` and `token` this answerer sent within the last 60 s on that connection (natively) or for that reply path (onion), and each token is used once. Anything else is dropped silently |
| PL4 | Store nodes MUST answer on overlay and client links, and SHOULD answer by onion message within H2's onion budget. Other relays SHOULD answer over overlay links (Bitcoin Core gates BIP 35 `mempool` for bandwidth and fingerprinting reasons; these limits play that role) |
| PL5 | The asker runs 8.3 on every beacon in the answer, in order. RL4 does not apply (RL4); orphans go to R-O6. A light client checks hosts as 12 says |
| PL6 | **Catch-up.** A relay sends one `pool_request` with no filter to at least one store peer, if it has one, and to one other overlay link in a different address group, **after its initial gossip sync is done** (it has the graph from at least 3 peers and no new `node_announcement` for 10 minutes). A fresh node waits for that sync before its first catch-up |

Size: about 2 entries per host, 168 bytes each: about 34 KB at 100 hosts, 336 KB at 1,000 (several pages).

## 12. Light clients (normative; design D)

A light client has a chain server but no gossip graph.

**What works today.** A light client connects **directly** (BOLT 8, over Tor where possible) to 1 or 2 store nodes and uses the native carrier. That needs nothing from any Lightning implementation beyond BOLT 8.

**What waits.** Onion queries need a route to the store node, which a client without a graph cannot build. LDK's default router does not build multi-hop paths; CLN routes onion messages only through nodes with the onion bit; LND's graph-based sending is an open pull request (PR A3b; DR A8). The onion path works only when the store node is a direct peer of the client's first hop, or publishes a blinded path the client can reach; neither is specified (open point 9). In SuperScalar the client's channel peer is usually its current host, a rival of the lobbies it seeks, so the first hop learns that its member is browsing (16).

| Path | How | What the client checks |
|---|---|---|
| Invitation or QR | `<host_key, 66 hex>@<address>:<port>` (`messages.md` 2), optionally followed by `#<outer_digest, 64 hex>` | The handshake matches the key; then queries and `terms.md` 7 |
| Built-in list | Shipped per network: hosts and store nodes, each `node key`, address, optional label. The user can add, remove and edit entries; never changed remotely | Same |
| **Store nodes** | Steps below | Each beacon fully; each new host through `host_list` |
| Nostr | Section 17 | Listing (5.2), withdrawal (5.3), anchor (9) |
| Trusted full node | `host_list_request` to the user's own node (7) | Gossip signatures and channel anchors |

**Through store nodes:**

1. **Choose 2 store nodes run by different operators**, from the built-in list or an invitation. At least one should not be a host. A light client whose store nodes are all run by one operator **can be censored completely by that operator**: signatures stop forgery, not omission, and the union of sources is complete only if one source is complete.
2. **Connect directly**, over Tor where possible, send `overlay_init` with `store` = 0 and `client` = 1, then `pool_request` with the user's filter, following `next` and `token`.
3. **Check each beacon**: B2 to B6 and B8 to B10 against the chain server's tip.
4. **Check each new host** (B7) with `host_list_request` naming it (7, D19) to the same store node or another: the `node_announcement` with bit 449 and up to 4 `channel_announcement`s; signatures; then each channel through the chain server (3 lookups on Electrum, 4 on Esplora, A1); then the price. Cache for 144 blocks. A client that skips this trusts the store node for B7 and says so in its interface.
5. **Merge** answers from both sources.
6. **Fetch listings** from the same store node; the host only on `listing_not_held`.
7. **Then** query the chosen host for live state (`hello`) and join directly.

A light client never relays.

## 13. Overlay peering (informative)

Peers need not agree on this section. Its numbers are recommended defaults from the peering research (PR B1 to B9), revised for RV 7. Every number is **proposed** and to be tuned on signet. Bitcoin keeps the same kind of policy out of its BIPs, in code.

**The idea.** Choose overlay peers yourself, from the gossip graph, under slot and diversity rules, and keep them with local scoring. There is no random walk, no peer exchange and no topic registration. **The limits:** Lightning gives few address groups (most nodes are Tor-only, and onion addresses are free), the node counts and flags below can be inflated by an attacker, and "non-host" is self-declared. What defends best is not the mix but RL5 (hosts send their own beacons everywhere), E5 (no peer exchange), scouts drawn from the whole graph, and direct queries to known hosts (14).

### 13.1 Who may be a peer

| Rule | Text |
|---|---|
| E1 | **Eligible:** in the graph, sets 449, has a reachable address, and its oldest announced channel is at least **1,008 blocks** old (the full age floor) |
| E2 | While fewer than **16** nodes meet E1 **and** the price of B7, the floor drops to 144 blocks; while fewer than **8**, to 0. While the floor is relaxed, **at most 2** links go to nodes below the full floor |
| E3 | A **host**, for the mix rule, signs a live beacon this node holds or has seen in the last 1,008 blocks. Self-declared: an operator's own non-hosting relays count as "non-hosts" |
| E4 | The peer must send `overlay_init` within 30 s; a peer whose announcement has lost the bit is dropped |
| E5 | **Self-selection from the graph only.** No peer exchange. An optional built-in seed list until gossip is synced |

### 13.2 How to pick

| Rule | Text |
|---|---|
| P1 | **Address group:** IPv4 /16; IPv6 /32; the AS number when an AS map is loaded. **All nodes that announce only Tor (or other privacy-network) addresses form one group** |
| P2 | **Address group first:** choose a group uniformly at random among groups with an eligible node not yet linked, then a node uniformly in it. **At most 3** links go to the Tor-only group, unless fewer than 3 other groups are available |
| P3 | Prefer a node with which this node already has a channel, for at most 2 slots |
| P4 | Do not weight by channel capacity |

### 13.3 Slots

| Name | Value | From |
|---|---|---|
| Target links | **6** | gossipsub's default 6; Lighthouse 5 |
| Low / high | **4 / 8** | The owner's 4 to 8 |
| Outbound minimum | **3** | gossipsub `D_out` |
| Anchors kept across restarts | **2** outbound links, chosen by **age and distinct address groups**, not by score | Bitcoin `anchors.dat` |
| Scout | **1** short link every **60 min** (exponential delay) and on waking | Bitcoin's feeler and extra block-relay link |
| Overlay links are **in addition** to channel peers | — | As in Bitcoin's 2022 full-RBF preferential-peering pull request (#25600, unmerged) and the Libre Relay fork |

- **Inbound eviction.** At the high mark, a new inbound link may replace an existing inbound link. Protect: 2 links in distinct address groups, the 2 longest-lived links, and 1 link with the most counted first deliveries (13.6). Among the rest, evict the youngest link in the most-represented address group (Bitcoin's inbound eviction).
- Light clients use client links (10.1), outside these slots.

### 13.4 The mix rule

| Rule | Text |
|---|---|
| M1 | At least **half** the links go to F nodes that are not hosts (E3) |
| M2 | At most **2** links go to hosts |
| M3 | At least **1** outbound link goes to a **store node**. A store claim is tested: within an hour, ask it for a listing this node already holds; a node that answers `listing_not_held` twice for listings it should hold loses store preference locally |
| M4 | When too few non-hosts exist, fill with hosts in distinct groups, and scout every **20 min** |

### 13.5 Diversity

- **V1.** Outbound links: one per address group (with P2's Tor exception).
- **V2.** All links: at most **2** per address group, except the Tor-only group (P2).
- **V3.** At most 1 link to nodes known to share an operator. Advisory.

### 13.6 Local scoring

**Local only, never sent** (15). Per link, over a 7-day window.

| Term | Sign | Rule |
|---|---|---|
| First delivery | + | +1 for each valid beacon this link delivered first, **counted only if** the beacon's host has no channel with the link's node **and** the beacon later arrives on at least 2 other links in 2 other address groups. Capped at +20; decays 1% an hour |
| Missed delivery | − | −1 for each such confirmed beacon that this link, linked since before its `open_height`, never sent within 10 min. Counted only after 20 beacons in the window |
| Behaviour | − (squared) | Over RL4, reconnecting during a back-off, filter churn |
| Store peer | − | `listing_not_held` for listings it should hold (beacons more than 10 min old) |

A Reject (8.7) is handled there, not here. **K1.** Below zero: send "nothing" and drop the link. **K2.** Above the high mark: never break the outbound minimum, the mix or anchors; keep the 4 best scores; drop at random among the rest. **K3.** Protect the 2 anchors.

### 13.7 Rotation and scouts

| Rule | Text |
|---|---|
| T1 | **Daily rotation:** once every 24 h, at a random time, replace one outbound link that is not an anchor |
| T2 | **Hourly scout:** every 60 min (exponential) and on waking, open a short link to an eligible node drawn as in P2 from groups not already linked; send **one** `pool_request` with a random `after` (one page); close. Beacons the scout had that the overlay did not deliver count as missed (13.6). A scout that delivered a new beacon replaces the worst-scoring non-anchor outbound link |
| T3 | **Anchors:** on clean shutdown, save 2 outbound links by age and distinct groups; reconnect them first |

### 13.8 Bandwidth

Each beacon arrives once per link (6 links), 206 bytes; pool entries 168 bytes; a scout reads one native page, capped here at 64 entries (about 11 KB).

| Hosts | Beacons a day (typical 1.5 per host / B9 maximum 8) | Relay received per node a day (typical / maximum) | Scouts a day | Full catch-up (each restart, rotation, new link) |
|---|---|---|---|---|
| 10 | 15 / 80 | 19 KB / 99 KB | up to 82 KB (24 small pages) | about 3 KB |
| 100 | 150 / 800 | 185 KB / 989 KB | about 260 KB | about 34 KB |
| 1,000 | 1,500 / 8,000 | 1.9 MB / 9.9 MB | about 260 KB | about 336 KB |

A typical node at 1,000 hosts: about 1.9 MB of relay, 0.26 MB of scouts and 0.34 MB for a daily rotation, so about 2.5 MB a day. A store node also fetches one listing per beacon, at most 4,817 bytes, typically about 0.5 KB. Lightning gossip is about 103 MB of unique data a day (DR A1).

## 14. Bootstrapping and direct queries: design C (normative, with informative numbers)

Discovery works with few F nodes and with no overlay at all. It then **degrades to design C**: the bit plus direct queries (PR B9, C).

| Rule | Text |
|---|---|
| DQ1 | Every F node SHOULD answer `lobby_index_request` over a direct connection; one that hosts nothing answers an empty index. A host MUST answer (3, rule 4) |
| DQ2 | A wallet with no beacons for its interest sends `lobby_index_request` directly to the F nodes it knows: its built-in list, invitations, hosts named in Nostr listings, and, with a graph, the nodes in it that set 449. **Informative defaults:** at most once per node per hour, at most 32 nodes per hour |
| DQ3 | Index entries are hints (Q2): fetch listings with `listing_request` before showing a lobby |
| DQ4 | Once beacons arrive, stop polling hosts and use beacons, store nodes and the fetch order (11.2) |

| F nodes at the full floor and price (13.1) | Behaviour (informative) |
|---|---|
| Fewer than 8 | Link to all of them. Members mostly query hosts directly (DQ2) |
| 8 to 50 | Normal rules with E2's relaxed floor; M4 may apply |
| More than 50 | Full rules of section 13 |

The thresholds count only nodes at the full age floor and price, so fresh Sybils do not change the regime (RV 7). A node that has synced gossip from 3 to 5 peers **usually** sees every F node; announcements are rate-limited and take minutes to spread (DR A1).

### 14.1 The demo wallet, exactly (design C)

| Item | The demo wallet does |
|---|---|
| Graph | Holds **no** gossip graph. It is a light client for discovery |
| Bit | Sets 449 in `init` on every connection (3, rule 1; `messages.md` 2) |
| Sources of hosts | The built-in, editable host list; invitations and QR codes; Nostr listing events (17.1), which give the host key and, in the optional `addr` tag, an address |
| Queries | Over a **direct** BOLT 8 connection to each host: `lobby_index_request`, then `listing_request` for each entry, then `hello` with the chosen lobby's `scope` (F1). Native kinds 129 to 135 only; no onion messages |
| Withdrawals | Applies 5.3 to withdrawals from `listing` answers and from Nostr |
| Polling | DQ2's informative defaults, while the lobby browser is open |
| Chain server | The wallet's own configured chain view (`DESIGN.md` 10), for tips and coin-anchor checks |
| Tor | Used for queries and Nostr when the user has configured it; otherwise the interface says that hosts and relays see the wallet's address |
| Anchors | **Coin anchors only** (P2TR key path, BIP 86 tweak, D2t). Listings with channel anchors are shown only from a direct query to a host the user chose (no anchor needed there, 9.3); on Nostr they are dropped until channel-anchor vectors exist (open point 11) |
| Hosting | A demo host answers DQ1, publishes its listings and withdrawals on Nostr with a coin anchor, and runs no beacon or store machinery (ledger A6) |
| Unregistered numbers | Marked as section 2 says |
| Tests | Those tagged [C] in section 21 |

## 15. Reserved, and never on the wire (normative)

**Reserved:** a kind number and one sentence, no format (PR F2).

| Item | Number | What it would be | When |
|---|---|---|---|
| Have-summaries | Kind **149** `beacon_summary` | Per host: a short key prefix, the highest sequence held, a short prefix of that beacon's id (about 16 bytes a host) | Above about 500 hosts (PR B8, C2) |
| Store-to-store sync | Kind **151** | Store nodes bring each other's listings and withdrawals up to date | When store nodes are many (PR F16) |
| Sketch reconciliation | Through 149 or 151 | Erlay-style minisketch or Negentropy. Short ids must commit to content; decode cost bounded | Above about 10,000 hosts (PR F11) |
| Bundled host proofs | Kind **157** | A beacon sent with its host's `node_announcement` and channels | Only if orphans prove common (PR F10) |
| Beacon, next version | Kind **159** | A beacon with new required fields (8.1) | When needed |
| Store-node onion contact | No number yet | A blinded path for a store node, published in the built-in list, so light clients can reach it by onion message | When implementations route onion messages for light clients (12) |

**Never on the wire:** scoring of links and of store nodes. A node MAY de-prefer a store peer that answers `listing_not_held` for listings it should hold (13.6).

## 16. Privacy (informative)

| What | Who learns what | Advice |
|---|---|---|
| Onion query or pool request from a member | The **first hop**, usually the member's own factory host, learns that its member is querying, the sizes, and the next hop (often a rival host or a known store node). The destination learns that someone asked, not who | First hop other than the destination and, where possible, other than the member's own host (O4) |
| The bit in `init` | **Every peer**, including ordinary nodes and the member's LSP, learns "this is a Gazpacho build with discovery". A fresh BOLT 8 key per session does not hide it | Accepted cost; members use fresh keys so the bit links nothing beyond one connection |
| Bit in `node_announcement` | The whole network learns the node runs Gazpacho | Only nodes that choose to be announced |
| Direct polling (DQ2) | Up to 32 hosts an hour each learn the asker's address (without Tor) and that it is browsing; hosts can join these logs across hosts | Tor; fewer hosts |
| Native query | The answerer learns the interest, and the address without Tor | Fresh key; Tor (F2) |
| Pool filter | The answerer learns the asker's interest | Ask with no filter and filter locally |
| `host_list_request` with `keys` | The store node learns which hosts the light client considers new | Ask for a few extra keys, or for whole pages |
| Listing fetch | A store peer learns which lobbies interest the asker. The host learns nothing **unless** no store peer held the listing (G4) | The fetch order puts store peers first |
| Store flag | Overlay peers learn the node stores | — |
| Beacons | Relays learn which hosts open lobbies, with profile and channel size: public by design | No terms, no counts |
| Anchor checks | The chain server learns which outpoints interested the wallet | Tor or the wallet's own server |
| Coin anchor | Publishes one host coin and its value | Use a dedicated coin |
| Nostr | The relay learns the reader's address and that it subscribes to kind 31867 with label `gazpacho` | Tor; several relays |
| Censorship | A light client whose store nodes share one operator can be shown only what that operator wants (12 step 1) | Two operators |
| Answers | Never say who joined or how many | H3 |

## 17. Nostr annex (informative, optional)

Validity never depends on Nostr. The annex fixes a kind and tags so wallets interoperate.

**Listing event**, addressable, kind **31867** (candidate):

| Field | Value |
|---|---|
| `content` | Base64 (RFC 4648, with padding) of the listing record, **with an anchor** |
| `d` | `listing_id`, 64 lowercase hex |
| `expiration` (NIP-40) | Unix seconds: the smaller of the outer `deadline` and publish time + (`expiry_height` − tip) × 600. A publisher with no tip uses the outer `deadline` |
| Labels (NIP-32, namespace `gazpacho`) | `["L","gazpacho"]`, `["l","<network>","gazpacho"]` with `signet` or `mainnet`, `["l","<profile>","gazpacho"]` with `safety`, `standard` or `starter`, `["l","anchor-coin" or "anchor-channel","gazpacho"]` |
| `host` | `host_key`, 66 hex |
| `addr` | Optional: the host's address as `<host>:<port>`. Unsigned and untrusted: the connection checks the key |

**Withdrawal event**, the same kind and `d`: `content` = base64 of the withdrawal record (5.3); label `["l","withdrawn","gazpacho"]`; `expiration` = publish time + 1,014 × 600 s. No anchor is needed: only the host can sign it.

### 17.1 Operations

| Item | Rule |
|---|---|
| Relays | A built-in, user-editable list of at least 3 relays; the wallet reads from and publishes to all of them |
| Subscription | Kind 31867 with `#L` = `gazpacho` and `#l` = the network. For each listing shown, also subscribe by `#d` = its `listing_id`, so a withdrawal from **any** author is seen (addressable events are replaced per author, kind and `d`, so a host's withdrawal does not replace a copy someone else published) |
| Author | Any Nostr key may publish. A host SHOULD publish under a Nostr key derived from its wallet seed for that purpose, never its node key. Readers MUST verify the inner record and anchor, and MUST ignore the author for validity. The same listing from several authors is one listing (`listing_id`, then L6) |
| Withdrawals | W3: a valid withdrawal from any author suppresses every copy of the listing. Anyone may republish a withdrawal; that only helps |
| Publish and refresh | A host publishes a listing when the lobby opens and its withdrawal when it starts or is cancelled (W7), and republishes the listing every 24 h while live. A reader refreshes every 10 minutes while the lobby browser is open |
| Caps | A3 to A7 in full, latest start first |
| Registration | Kind and labels are not registered; a NIP is a public proposal for the owner to decide |

### 17.2 Why Nostr stays, for now

It lists hosts outside gossip, serves a fresh phone with no channel, fails independently of Lightning, carries whole listings, and keeps data while hosts are offline (PR D1).

### 17.3 Conditions for retiring the annex

From PR D3. **All** must hold for **six consecutive months**, measured by a monitor (a full overlay node plus a light-client probe):

| # | Condition | Threshold |
|---|---|---|
| N1 | Overlay size | At least 30 F nodes, from at least 10 operators, in at least 10 address groups |
| N2 | Store nodes | At least 5 answering pool and listing requests, from at least 3 operators, none over a third |
| N3 | Completeness | At least 99% of beacons seen by the full node reach the light-client probe within 10 min, over 30 days |
| N4 | Light-client path | At least 99% of light-client requests (direct over Tor today; onion when 12's onion path exists) answered within 30 s with retries |
| N5 | Hosts outside gossip | Taproot gossip deployed in at least 2 implementations, or under 5% of hosts listed only on Nostr |
| N6 | New users | A fresh install finds lobbies with Nostr off: built-in store nodes plus a direct (Tor) connection |
| N7 | Availability | At least 3 store nodes up at every sample over 90 days |

Keep Nostr as an optional fallback now; when design D ships, use the overlay first and Nostr second; when N1 to N7 hold, the annex becomes "off by default, out of the main text" (PR D4).

## 18. Release (informative)

| Release | Design | What ships | What does not |
|---|---|---|---|
| **Demo wallet** (signet, first) | **C** | Section 14.1 in full: bit 449; direct native queries 129 to 135; listings and withdrawals; Nostr with coin anchors | No beacons, overlay, store nodes, pool, host list or onion queries |
| **Next** (before mainnet) | **D** | Beacons (8), overlay and client links (10), store nodes and the fetch order (11), the pool request, **`host_list`** (7; light clients need it for B7), light clients over direct connections (12). Overlay peering (13). Collecting and storing offered, off by default. Channel anchors | Onion queries until 12's onion path exists |
| **Later** | | Onion queries and onion light clients. Final numbers registered (owner). Reserved items (15). Nostr retired when N1 to N7 hold. Taproot channel anchors | |

## 19. Changes in other documents (informative)

| Document | Change | State |
|---|---|---|
| `messages.md` 2 | The bit is set by builds with discovery | Done in draft 3 |
| `messages.md` 4 | `scope` all zero in discovery kinds | Done |
| `messages.md` 4.1 | Discovery kinds 128 to 159 are ignored, never refused, including the wrong direction and a nonzero `scope` | Done in draft 3 |
| `messages.md` 6.1 | Scope-zero `hello` lists at most 4 listed lobbies | Done (commit `a4fd3bc`) |
| `messages.md` open point 1 | Answered: one bit | Done |
| `terms.md` open point 7 | Answered: the listing carries the same bytes | Done (commit `a4fd3bc`) |
| `LOBBY.md` "What is public" | Beacons, store nodes, the pool request | Done (commit `a4fd3bc`); withdrawals to add |
| `PROTOCOL.md` 7, 8, 10 | Kinds, tags (`gazpacho/withdrawal`), the bit | Done in draft 3 |

## 20. Test vectors (normative)

Computed by `tools/spec-vectors.py` (`python -I tools/spec-vectors.py`; it takes a few minutes, because the signatures are pure Python). Test keys as `terms.md` section 11; the extra keys are `host coin`, `host coin internal` and `other host`. **Never use them for coins.** Auxiliary randomness 32 zero bytes. Every vector depends on T1's `outer_digest` `75e970b6…f0a424f2`, signet, tip 290,000, and on D0's candidates.

Changed in draft 3: D4w (now a withdrawal record), D5 (the `unknown` answer), D7, D8, D9, D15, D17 (height-derived sequence), D10 (seen-set sizes), D12 (now run in arrival order). New: D2t, D13c, D15b, D20 to D23. Unchanged: D0, D2, D4, D6, D11, D13, D14, D16, D18, D19. Withdrawn: D1, D3.

**The reference reader.** D12, D17 and D20 to D22 are produced by a small reader in the tool that runs B1 to B10 in arrival order with real signature checks; D23 by a reader that runs L1 to L8 and W1 to W3. They are the conformance oracle for RV findings 1 to 3.

**D0. Candidates:** bit 448/449 (features field 57 bytes); onion types 106369 to 106385 odd; native kinds 145, 147, 153, 155, reserved 149, 151, 157, 159; Nostr kind 31867. Reserved only: card TLV 118685, Nostr kind 37329.

**D2. Coin anchor.** Q = `7623edf9580bec93335131c7e0d085ba224d2c0a74566ba105654049d0b5b137` (secret `SHA256("gazpacho test key: host coin")` mod n, used directly as Q); outpoint txid `SHA256("gazpacho test coin txid")`, index 0; `coin_valid_until` 291,008.

```
anchor_digest = cd85b08e27342c96496fe3b24687dc9526589452467a6acd0bd4bee43d6138d0
anchor value, 110 bytes:
0424151f73e48f9bc78a94686e9aeb373dcba70e326588a4262b993cb40de4c7
11c1000000000604000470c00840dc45f44c60d5a3e849471f1f02d487ac13d1
1351876ee006a9c17741f0dd4442b69da472d6c32638fa51ab16679102e72788
4f0d961f21a8669695d95e5a555f
```

Allowances at the signet unit: 2,499 sat → 0; 2,500 → 1; 19,999 → 1; 20,000 → 2; 100,000 → 4.

**D2t. BIP 86 coin anchor**, same outpoint and statement. Internal secret `SHA256("gazpacho test key: host coin internal")` mod n:

```
internal key P  = 423c865efd3497f92d6cc83ce2a3b9bd29c5897209d16f5f7e845a6a8945c3e8
t = TH("TapTweak", x(P)) = 0836d29656ac7504c2e4513978e1a3927484a699b5a4b6deaa62bc4b75682380
output key Q = P + tG = b8bfc1f0f719dafc839d391db8204079bc39920bdb622a08c52b2afca3a224e2
coin_sig (tweaked secret) = f4da16fec68afb7745bc746e9f31c4cef70a26b6db9b59dcc0ae69167e52feaa21d6fb7cf5343f0ba4671e856be31a8bcbaed136bcfd2af69368a412172434a3
```

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

**D4w. Withdrawal** of T1 at height 290,010:

```
withdrawal_digest = efdc71259cbe1859882392cc0a8329a2f3012b05c2d94465e38335139a7feb98
withdrawal record, 141 bytes:
022102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473
349156042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb84314196
59f0a424f2060400046cdaf0405d1c793658586b9d9cf4e046fa7ebcf16652ff
ead9b4b1f6686ccdf26c067f663c6988f3cc01e2c036a633791760ebcb794379
1d345d6edcb4d620203a9f147e
listing answer "withdrawn": record 6 holding it, 143 bytes
```

D4x, **refuse**: expiry 291,009, validly signed, fails L4. Largest possible listing: 4,817 bytes.

**D5. Queries.**

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
lobby_index records, 194 bytes: 02c0 || index record (native 234 bytes)
listing_request records, 68 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659
f0a424f2
listing answer records, 456 bytes: 02fd01c4 || D4 (native 496 bytes; onion payload field 464 bytes)
listing answer "unknown" for that request, 34 bytes:
042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
```

**D6. Nostr content.** Listing event `d` = `75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2`, `content` = base64 of D4, beginning `AiECuN1zml0rBwn+xc6k6E63gRuQTM+HHHehp4seNHM0kVYE4QIg9h7uO2Oj` and ending `CAinXB0p4up0=` (604 characters).

**D7. Beacon** for T1, open 290,000, deadline 290,144, sequence 4,640,000 (= 290,000 × 16 + 0), profile 2, `channel_sat` 100,000:

```
beacon_id = 2a9deaae8e85326b58eba7d7ba7c91e98bc9ff389f6a5967eaed45bb139680f9
records, 166 bytes:
022102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473
349156042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb84314196
59f0a424f2060400046cd0080400046d600a040046cd000c01020e0800000000
000186a0f0402f68fd8ceed2aaf8556ed852dcdd5323476e04ef3a50814169b7
56c07dc7360093a6803b6206f923edcfb2846481747f7760182d4c8b5b5b9f43
464db67999af
native lobby_beacon, kind 141, 206 bytes: ce37 677a6601 008d 00…00 (32) || records
```

**D8. Beacon withdrawal** of D7 at height 290,010: sequence 4,640,160, deadline 290,000: `beacon_id = 53d2755e390dec9020da64329b8d3aecc8934fb38b5063a7f02104ffa0985101`, `beacon_sig = 0d10e6fc0995b7a5b4f622de60f83c54ec78f68e538c6d65bdccaf9711661fcf5eced1bb2fb3bfc9b804270b090e14c689be887bffdcfec585ce458f2b4051a3`.

**D9. Reject:** D7's records with a signature by `other host`: B5 fails. Not added to the seen-set, so the genuine D7 is accepted afterwards.

**D10. `beacon_filter`.** "Everything", native kind 143, 86 bytes: `ce37677a6601008f` ‖ 32 zero bytes ‖ `0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881080000000404000000000604ffffffff`. "Nothing" records: `0220f61eee3b…08000000 0404ffffffff 060400000000`. Seen-set sizes: 10 F nodes → 4,096 entries (164 KB); 1,000 → 64,000 (2.6 MB); 10,000 → 262,144 (10.5 MB).

**D11. Refuse:** D2's `coin_sig` in a listing by `other host`: the statement names another key and the signature fails (A1).

**D12. Cap, in arrival order:** one host with allowance 4, five beacons at heights 290,000 to 290,004 for five lobbies, arriving in that order at a node at tip 290,004: each is held; the fifth evicts the first.

**D13. `overlay_init`**, store = 1, native kind 153, 77 bytes:

```
ce37677a6601 0099 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000 040101
store = 0 records, 37 bytes: 0220 || chain || 040100
```

**D13c.** Light client (store = 0, client = 1), records, 40 bytes: `0220` ‖ chain ‖ `040100050101`.

**D14. `pool_request`**: Standard only (`profiles` = `0x02`), `channel_range` 50,000 to 200,000:

```
records, 55 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
00000301020510000000000000c3500000000000030d40
native, kind 145, 95 bytes; onion payload field, type 106381, 61 bytes: fe00019f8d 37 || records
no filter, 34 bytes: 0220 || chain
```

**D15. `pool`** answering D14 with D7:

```
records, 204 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
000004a800a6 || D7 records (166 bytes)
native, kind 147, 244 bytes; onion payload field 210 bytes
```

One entry is 168 bytes: a 60,000-byte native page holds 356, a 30,000-byte onion page 178, a 1,366-byte onion about 6.

**D15b. Continuation `pool_request`**, `after` = the test host key, `token` = `SHA256("gazpacho test pool token")[0:8]`, records, 79 bytes:

```
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000072102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e
34733491560908b2f48ee24ade1026
```

**D16. `listing_not_held`** for T1, native kind 155, 108 bytes:

```
ce37677a6601 009b 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
042075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
```

**D17. Two beacons, one sequence**, run in both orders: D7 and a beacon of the same host for lobby `SHA256("lobby 2")`, also sequence 4,640,000, `beacon_id = 3fb321be05932d7ec292f9b6d1634948a523570d84404f385c4661930d8173a7`. In either order the reader ends holding **D7** (the lower id) only.

**D18. Orphan pool:** 10 orphans from one link keep the last 8; 72 over 9 links keep 64; an orphan 20 minutes old is gone.

**D19. `host_list_request`** naming the test host, native kind 137, 109 bytes:

```
ce37677a6601 0089 00…00 (32)
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
052102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156
```

**D20. Churn (RV 1).** A beacon with `sequence` 2^32 − 1 is ignored at B6 (its height part is far ahead). Twelve new numbers for twelve lobbies, all in one 144-block window (heights 290,000 to 290,006, counters as needed), offered to a node at tip 290,006 in three orders: ascending; descending; and descending-then-ascending (the review's attack). Relayed: 8, 4 and 4. Never more than 8; in ascending order 8 are held and 4 ignored by B9.

**D21. Withdrawal before the original (RV 3).** D8 then D7: the tombstone is held (and served in `pool`), D7 is ignored. D7 then D8: the lobby is withdrawn. D7 offered again by a relay: ignored.

**D22. View-dependent ignores (RV 3, 4).** A node at tip 289,990 ignores D7 at B6 and does not mark it seen; at tip 290,000 the same D7 is accepted. A beacon whose host is not yet in the graph is an orphan, then accepted when the host appears. A host with 2,499 sat of half-capacity (signet), or whose channel is 143 blocks old, is below the price: ignored.

**D23. Listing reader (RV 2).** D4 and D4w in either order: nothing shown. A withdrawal of T1 signed by `other host`: ignored, D4 shown. A replay of four old listings of the test host (start 290,000) beside its new lobby (start 290,100), at tip 290,101: the new lobby is shown (the cap keeps the latest start). With the four old lobbies' withdrawals present: only the new lobby is shown.

Not yet vectors **(open, point 11)**: a channel anchor and a `host_list` entry (real BOLT 7 messages with ECDSA signatures).

## 21. Tests (normative)

Decoders are generated from the tables and fuzzed, as in `messages.md` 12.

**Encoding**
1. [C] D2, D2t, D4, D4w, D5 encode to exactly the bytes above; digests and signatures match. [D] Also D7 to D23.
2. [C] Each record: non-minimal BigSize, types out of order or repeated, a fixed-width field one byte short or long, a length past the end: dropped, and the connection kept.
3. [C] A listing of 4,818 bytes; an index of 641 bytes, with 5 entries, a 48-byte entry or a record 10; a withdrawal of 257 bytes: dropped. [D] A beacon of 257 bytes (Reject); a beacon with an unknown odd record of 20 bytes (accepted and relayed unchanged); with an unknown even record, `profile` 4 or `channel_sat` 545 (ignored, link kept); an `overlay_init` with `store` 2; a `pool_request` with smallest > largest: ignored.

**Feature bit**
4. [C] A host announces 449: LND, CLN, Eclair and LDK nodes keep connecting to it, route through it and relay its announcement. 448 instead: shunned.
5. [C] No build sets 450 or 451, or appends TLV 118685. A build without discovery sets no bit.

**Listing and withdrawal**
6. [C] Listing signed by another key; `host_key` not the outer record's; a bad outer record; outer profile 4: dropped (L2, L3).
7. [C] D4x; start more than 6 blocks ahead; expired; past the outer deadline: not shown (L4).
8. [C] Two listings with one `listing_id`: the shorter expiry wins (L6).
9. [C] D23 in full: D4 and D4w in either order show nothing; a withdrawal by another key is ignored; replayed old listings do not hide a new lobby; withdrawals remove the old ones.
10. [C] A withdrawal kept 1,014 blocks, then forgotten; a listing for that lobby arriving at block 1,013: still hidden.
11. [C] A Nostr withdrawal published by the host, and a copy of the listing republished by another author: the reader that subscribed by `#d` shows nothing (17.1).
12. [C] A host with 5 live listings: the 4 latest shown (L7, A4).
13. [C] A listing whose outer record differs by one byte from the `terms_offer` received after `hello`: refused (`terms.md` 7 step 2).

**Queries**
14. [C] Honest: index, listing, `hello` with the scope, natively. [D] By onion too; record bytes identical.
15. [C] An unasked `listing`: dropped. `unknown` naming another digest: dropped. [D] `unknown` from a store node: dropped.
16. [C] `lobby_index` signed by another key; `as_of_height` 7 blocks off; entries not sorted or repeated: dropped (Q1).
17. [C] Budgets: one address group sending 10 index requests in 10 s gets 1 answer; 100 fresh keys from one group the same; 100 groups at once: at most 50 answers a second in total (H2).
18. [C] Unlisted, Circle and withdrawn lobbies never appear in any answer or in scope-zero `hello` (H1).
19. [C] A discovery message with a nonzero `scope`, in the wrong direction, or malformed: ignored, the connection kept (`messages.md` 4.1).
20. [D] Onion: a 1,366-byte request never gets a larger answer; a padded 32,834-byte request gets a full page (O3). One incoming peer sending 100 requests a second cannot use more than its fair share of the onion budget (H2).
21. [D] Onion to an LND first hop without a channel: dropped; the asker falls back to native after the retry (O6, O7).

**Anchors**
22. [C] Coin anchor unspent with 6 confirmations: accepted; with 5: dropped; spent: dropped before the next display once the cache is 6 blocks old (A1, A2).
23. [C] D11: dropped. One coin under two live host keys: both dropped (A6). [D] A channel anchor used by both of its nodes: both kept, each with its half (A6).
24. [C] D2t accepted; the same signature under the untweaked internal key: dropped.
25. [C] A Nostr listing without an anchor: dropped. A relay that accepts 5 listings for a 4-listing anchor: the wallet shows 4 (A7).
26. [D] Channel anchor whose output is not the P2WSH 2-of-2 of the two bitcoin keys, or in which `host_key` is neither node: dropped.

**Beacon**
27. [D] A host opens a lobby: its beacon reaches every relay of a 30-node test overlay within seconds (RL1); each relay sends it to each link at most once (RL2).
28. [D] D21 in full: withdrawals held, relayed and served in `pool`; a relay resending a withdrawn beacon to a node that holds the tombstone: ignored; a node that missed the withdrawal gets it by `pool`.
29. [D] D22 in full; and a node that restarts keeps its tombstones and seen-set (8.6).
30. [D] D9 arrives first, then D7 from another link: discovery on D9's connection stops for 24 h, the connection stays open (it carries a channel in the test); D7 is accepted.
31. [D] Orphans: 100 from one link keep 8; 9 links keep 64 in total; an orphan whose host's announcement arrives 5 minutes later is accepted and relayed; pool-answer orphans keep up to 256 (R-O1 to R-O6, D18).
32. [D] D17 in both orders, at two nodes: both hold D7.
33. [D] D20 in full, and a host restored from its seed: its new beacons (height-derived) are accepted at once (8.1).
34. [D] A host with half-capacity 2,499 sat on signet, or channels 143 blocks old: its beacons are ignored. With 20,000 sat: 2 live beacons allowed (B7, B10).
35. [D] 100 cheap hosts release 4 beacons each at once: a heavier host's beacon waiting in the same queues is not dropped (RL3).
36. [D] A link sending 100 relayed beacons in one second: 20 accepted, then 1 a second (RL4). A `pool` page of 356 beacons that this node asked for: all checked.
37. [D] A peer that never sent `overlay_init` sends beacons: ignored. An ordinary Lightning node never receives a beacon.
38. [D] A filter of "nothing": only the sender's own beacons. Filters sent 10 times a minute: one honoured. No backlog after a filter.

**Store nodes, fetch order, pool**
39. [D] A store node fetches each listing after 0 to 60 s, from store peers first, then the host; keeps it until expiry or withdrawal (S1 to S3).
40. [D] An interested node asks a store peer that holds the listing: answered at once, the host receives nothing. A store peer holding the withdrawal answers with it. One holding neither answers `listing_not_held`; the node waits 0 to 60 s and asks the host (G2 to G5).
41. [D] A store peer's listing whose profile or `channel_sat` differs from the beacon's: dropped (S2).
42. [D] Pool: D14 returns only D7 and any tombstones; paging with `next` and `token` at 1,000 hosts returns every entry once; a continuation with a wrong or reused token, or after 60 s, counts as new and is dropped if over PL3.
43. [D] 100 fresh keys from one address group each ask for the whole pool: at most 4 answered an hour (PL3).
44. [D] A fresh node sends no catch-up before its gossip sync is done (PL6).
45. [D] A store node serves 64 light clients without using overlay slots; a ninth client from one address group gets no link (S8).

**Light client**
46. [D] A light client connects directly to two store nodes of different operators; one withholds a host's beacons: the client gets them from the other.
47. [D] A light client checks a new host with `host_list_request` naming it: a host without bit 449, or below the price, is dropped.

**Bootstrapping**
48. [C] Three hosts in the built-in list, no beacons: the demo wallet finds every listed lobby by direct `lobby_index_request` (DQ2); a non-hosting F node answers an empty index (DQ1). [D] Polling stops once beacons arrive (DQ4).

**Overlay peering**
49. [Di] Selection keeps the mix and diversity rules; with only hosts it fills (M4) and moves to non-hosts when they appear.
50. [Di] 200 F nodes in one IPv4 /16: at most 2 links go to them. 200 Tor-only F nodes: at most 3 links go to them while 3 other groups exist (P2).
51. [Di] 50 fresh F nodes added: the regime and the age floor do not change (E2, 14).
52. [Di] An attacker's link that delivers its own hosts' beacons first gains no first-delivery points (13.6). Anchors after restart are the oldest outbound links in distinct groups (T3).
53. [Di] At the high mark, a new inbound link evicts the youngest link of the most-represented group, never a protected one (13.3).

**Privacy**
54. [D] An onion query through the destination as first hop is logged as "no privacy gain".
55. [C] The asker's native query uses a key never used for a seat.

## 22. Open points (informative)

1. **Final numbers** for the bit pair, the onion payload types and the Nostr kind: chosen by section 2 on the day of first use beyond signet. Registration needs public proposals, which only the owner can authorise. Nothing is to be posted.
2. **The beacon's filter fields are proposed** (`profile`, `channel_sat`). A third tiny field is possible (target size, or the deadline in Unix seconds), now as an odd record that old relays relay.
3. **The beacon price** (B7): `unit` / 4 of the host's half-capacity, channels at least 144 blocks old, allowance as A3. Owner to confirm the level and the age (144 or 1,008). It excludes hosts with small or young channels from beacons; they still have direct queries and Nostr.
4. **A withdrawal is final, even for the host** (W4). The owner asked that it "cannot be undone by anyone but the host"; draft 3 is stricter, because a revocable withdrawal could be replayed in its revoked state. Owner to confirm.
5. **`outer_sig` in the listing.** Left out; adding it (66 bytes) would let a reader run `terms.md` 7 step 3 unchanged.
6. **Coin anchors other than P2TR key path** (BIP 322).
7. **Every F node answers `lobby_index_request`** (DQ1), phones included. Anyone who connects can ask whether a Gazpacho node hosts. Confirm.
8. **Kinds 153 and 155**, and 159 reserved for a beacon version. Owner to confirm.
9. **Onion path for light clients** (12, 15): a store-node blinded contact, and how the reply path's introduction node is chosen. Not specified until implementations route onion messages for clients without a graph.
10. **Numbers to tune on signet:** 4 listings and beacons per host; the price; 8 new sequences per 144 blocks; 1,008-block lifetimes; withdrawals kept 1,014 blocks; orphans 8 / 64 / 256 / 20 min; 1 beacon a second, bursts of 20; queue 64, 4 per host; rebroadcast 6 to 12 h; fetch delays 0 to 60 s; 30 s to the next source; 16 in flight; pool limits of PL3; page sizes; S7 and S8; H2 budgets; the anchor re-check at 6 blocks; DQ2's defaults; seen-set sizing; all of section 13.
11. **Missing vectors:** a channel anchor and a `host_list` entry. Until they exist, the demo wallet does not use channel anchors on Nostr (14.1).
12. **Hosts outside gossip** cannot send beacons until taproot gossip merges (N5).
13. **Light-client privacy and censorship:** the first hop is usually the member's own host (16); one store operator can censor a client completely (12). Two operators are recommended; whether the built-in list must contain two operators is the owner's choice.
14. **No incentive to run a store node.** N2 needs at least 5 from 3 operators before Nostr can go.
15. **The Tor-only group** (13.2) caps links to most of today's network at 3. Measure on signet and mainnet before tuning.
16. **Two honest nodes can disagree** about a misbehaving host's ninth beacon in a window (B9 keeps the first 8 each node accepted). Honest hosts never reach the limit; confirm that this is acceptable.
