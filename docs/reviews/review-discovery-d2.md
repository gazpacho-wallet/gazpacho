# Review: `spec/discovery.md` draft 2

Independent adversarial review, 2026-11-12. Reviewed at `origin/specs-slice1` = `a4fd3bc5`. Read on that branch: `spec/discovery.md`, `spec/PROTOCOL.md`, `spec/messages.md`, `spec/terms.md`, `tools/spec-vectors.py`, `docs/research/discovery-research.md` (DR), `docs/research/peering-research.md` (PR), `docs/research/ideas-ledger.md` section A. Primary sources fetched today: BOLT 4 (onion messages), bLIP 2, LND `docs/onion_message_rate_limiting.md`. Other primary sources were not re-fetched (see "What I could not check"). Nothing was posted anywhere.

## Verdict

**Needs rework** in three places before design D is built: the beacon replacement and seen-set rules (findings 1 to 3), the beacon path's Sybil price (4), and the light-client path (6). **Design C (the demo wallet) is ready after listed changes**: findings 2, 10 and 14, and the builder gaps in section "Can design C be built from this spec".

The basic idea holds up: signed pointers, signed listings with the same bytes on every path, and nothing trusted before `terms.md` 7 and C8. The money claim ("Discovery can waste a query; it cannot cost money", section 1) holds. Every finding below is about availability, spam, censorship, privacy or the ability to build the thing. None is about funds.

## Findings, ranked

Severity: **H** high (breaks a stated guarantee, or blocks building the design), **M** medium (an attack within reach, or a real ambiguity), **L** low (consistency or wording).

### 1. H. The churn limit B9 can be bypassed by one host, and the bypass is relayed everywhere

B9: "If `sequence` is higher than every sequence held or remembered for this host, it is a new number. At most **8** new numbers per host per **144** blocks." B10: "A fifth: keep the 4 with the highest `sequence`; if the newcomer is the lowest, drop it". B8(a) applies only to the same `outer_digest`.

Attack, with one host key that has one channel. First send a beacon with `sequence` = 2^32 − 1. That is one new number. Then send beacons with sequences 1, 2, 3, … for distinct random `outer_digest`s. None of them is "higher than every sequence held or remembered", so B9 never counts them. B8 does not apply because the digests differ. B10 keeps the four highest: {2^32 − 1, 1, 2, 3}, then 4 evicts 1, 5 evicts 2, and so on. Each newcomer is "held", so by "Then: hold the beacon and relay it" it is relayed to every link. Every honest relay sees the same order and does the same. The only limit left is RL4 (1 beacon a second per link). So one host can use the whole capacity of the overlay, which is about 86,400 beacons a day per link. Combined with RL3 ("at most 64 beacons waiting. Beyond that, drop the oldest waiting"), honest beacons are pushed out of every queue (finding 4).

The vector tool does not catch this. D12 is computed as `sorted(active)[-4:]` (tool lines 731 to 737). It never runs B9 or B10 in arrival order.

Fix: count **distinct sequence numbers accepted per host per window, whatever their order**. Alternatively, make B9 count every beacon that would be held or relayed. A beacon over the limit must not be relayed (PR B8 R2 says exactly "more are dropped and not relayed"). Add a vector that sends sequences in descending-then-ascending order.

### 2. H. Listing withdrawal cannot work, and old listings can hide a host's new lobbies (affects design C and Nostr)

Section 5.1: "**Withdrawal:** the same listing re-signed with `expiry_height` = `start_height`." L4 requires "live (5.1)", and 5.1 says "**Live** while the reader's tip is below `expiry_height`". For the "same listing" (same `start_height`, already reached), `expiry_height` = `start_height` ≤ tip. So **every withdrawal fails L4 and is dropped** before L6 ("keep the one with the smaller `expiry_height`") ever compares it. Test 22, the Nostr rule "L6 makes it win wherever both are seen" (17) and D4w all assume something the rules forbid.

Nostr makes it worse. 17: "**Any Nostr key may publish the event**". Addressable events are replaced per (author, kind, `d`). So a withdrawal published by the host never replaces a copy someone else republished. Readers drop the withdrawal (L4) and keep the copy.

Censorship follows from L7 / A5: "Over a cap, keep the earliest `start_height`". Anyone who archived a host's four listings can republish them after the host has started or cancelled those lobbies. Every reader then keeps the four old listings (still live for up to 1,008 blocks) and **drops the host's new lobbies**. This needs no key, no coin and no channel. The anchors of the old listings are the host's own, and stay valid until `coin_valid_until` or until spent. Design C ships Nostr (section 18), so this is a demo-wallet problem.

Fix: a withdrawal must be a **tombstone**. It is a signed listing for the same `listing_id` whose `expiry_height` ≤ tip. Readers accept it as valid-but-not-live, keep it until `start_height` + 1,008, and let it suppress every listing of that `listing_id` with a larger expiry. Also rethink A5's "earliest `start_height`" for the per-host cap: a tombstoned listing must not count, and "latest" is the better default against replay. Add a vector: D4 then D4w in both orders → nothing shown.

### 3. H. "Seen" includes view-dependent ignores; withdrawals are not held or relayed; early seen-set loss is not harmless

8.3: "Every beacon that passed B5, held or not, enters the seen-set". But B6 (ahead of this node's chain), B9 (churn) and B10 (cap) come **after** B5, and all three depend on the receiver's view. Bitcoin learned this lesson with BIP 339 and Core's reject filters: never cache a rejection whose reason can change. Here:

- A phone that wakes 7 blocks behind ignores fresh beacons at B6 and marks them seen. When it catches up, the copies that come back (RL6 rebroadcast, pool answers) are dropped at B4 until the beacon's deadline, up to 1,008 blocks.
- A beacon ignored by B9 at one node (because that node saw the host's earlier numbers) is accepted at a node that missed them. The two honest nodes then disagree until the deadline. RL6 cannot heal it, because B4 drops the rebroadcast.
- A withdrawal for a beacon not held is ignored (B6: "unless it is a withdrawal of a beacon held"), enters the seen-set and is not relayed. Withdrawals are not "live", so PL1 never puts them in a `pool` answer. So a node that receives the withdrawal before the original (or missed it while offline) later accepts the original from any relay's pool. A malicious relay that keeps withdrawn beacons can resurrect them at every node that catches up.
- 8.6: "Losing an entry early is harmless: a copy that comes back is checked again and dropped by B8." That is false after a withdrawal. B8(a) compares only with a **held** beacon, and a withdrawal "expires at once". The seen-set is also small: `max(1,024, 8 × F)` against up to 56 ids per host per 1,008 blocks. A host can fill it at 1 a second per link with B10-dropped beacons, which still "enter the seen-set" (finding 1).

Fix: put a beacon in the seen-set only after it is accepted, or after a view-independent failure. Keep withdrawals as held tombstones until `open_height` + 1,008, relay them, and include them in `pool` answers. Make B8(a) compare against tombstones and the per-host memory too. Persist the seen-set, or at least the tombstones, with the store (8.6).

### 4. H. The Sybil price of the beacon path is almost zero, and every bound is per host

B7 needs only "a `node_announcement` that sets 449, and … a node of at least one known `channel_announcement`". There is no minimum capacity and no age. A channel has two nodes, so **one channel makes two hosts**. A ring of N channels makes N hosts. At the owner's 0.1 sat/vB fee rate, an announced channel costs tens of sats in fees plus a small, recoverable output. Compare 9.2 A3: a channel anchor below `unit` / 4 (250,000 sat on mainnet) backs **zero** listings on Nostr. The spec therefore prices the beacon path, which reaches every relay, far below Nostr. Section 9.3 ("Gossip is the anchor") asserts this without counting it. PR B11 cites "an announced, funded channel at least a week old (E1)", but E1 governs **peering**, not beacon origin, and E2 relaxes it to 0.

Within the caps, 10,000 Sybil hosts (5,000 channels) make every relay hold 4 × 10,000 × 166 B = 6.6 MB, plus the per-host memory. They push about 80,000 beacons a day through every link, about 0.93 a second, which is the RL4 ceiling. Every store node would fetch and keep up to 4 × 10,000 × 4,817 B = 193 MB. Every light client's catch-up becomes about 6.7 MB, or 224 onion pages. Burst attack: 100 Sybil hosts × 4 beacons released at once give 400 beacons. That overflows every 64-entry queue (RL3, drop oldest) and erases any honest beacon in flight. Those beacons are recovered only by RL6 (6 to 12 h), by a scout (hourly) or by a new link. 13.8's table assumes "1.5 new beacons per host a day" from honest hosts only.

Fix: give B7 a price. For example: the host's channel(s) total at least `unit` / 4 and are at least 144 (or 1,008) blocks old. Or rank hosts by channel value × age with A7's rolling minimum, applied to **beacons, held set and store**, not only to Nostr listings. Count one channel for one host only (as A6 does for anchors). Make RL3 drop by host weight, not by age.

### 5. H. Reject closes the connection, even to a channel peer, and the beacon format has no upgrade path

8.7 Reject: "Close the overlay link. Do not link to that peer again for **24 hours**." 10: an overlay link *is* the BOLT 8 connection. 13.2 P3 prefers channel peers for 2 slots. Read literally, one bad beacon from a channel peer closes the connection that carries HTLCs and refuses it for a day. `messages.md` 1 and 4.2 already "refuse" (warning plus close) any malformed TLV in a type-52791 message, discovery kinds included. That contradicts section 6.3's "discovery is never worth a disconnect".

Version skew makes it worse. 8.1: "any extra record, odd included, makes the beacon invalid". B2 and B3 (`profile` 1 to 3, lifetime ≤ 1,008) are Reject. Open point 2 (a third filter field) and open point 7 (tune lifetimes) will both change these. The first upgraded host's beacons then make every old relay drop its links to upgraded relays. 8.7's justification, "checks that do not depend on the receiver's view", ignores the receiver's **software version**.

Fix: Reject means "stop using the connection for discovery (filter nothing, ignore discovery kinds) for 24 h". Never close a connection that carries a channel. Override `messages.md`'s refuse for kinds 128 to 159. Version the beacon by kind, for example a new odd kind for beacon v2, sent alongside v1 during migration. Alternatively, let unknown **odd** records be relayed but bounded by a fixed maximum size.

### 6. H. The light-client path (section 12) cannot be built as written

- **Onion routing without a graph.** A light client has no graph (12), but an onion message must name every unblinded hop. From the research itself: "LDK's default router builds no multi-hop path: if the target is not a peer it asks the app to connect directly" (PR A3b). "CLN routes onion messages only through nodes with the onion bit, else connects directly". LND "Graph-based sending is still an open pull request (#10651)" (DR A8). Section 12 step 2 ("by onion message through the client's own channel peer") works only if the store node is the LSP's direct peer, or publishes a blinded path that the client can reach. Neither is specified (open point 8 covers hosts only).
- **The LSP is the host.** In SuperScalar the member's channel peer is its factory's host. So the first hop of every onion query is the current host, a rival of the lobbies being sought (finding 12). O4's "first hop other than the node it asks" protects only against the destination, not against the first hop.
- **The reply path's introduction node** must be a peer the store node can reach. The spec does not say how it is chosen.
- **LND gate.** Verified today in LND's `docs/onion_message_rate_limiting.md`: messages from a peer without "at least one fully open channel" are dropped; `relay-all` defaults to false. BOLT 4 says nodes "SHOULD accept onion messages from peers without an established channel". O7 is accurate. N4 ("through an ordinary LSP") depends on LSP software that Gazpacho does not control.
- **B7 for light clients needs `host_list`**, which section 18 puts in **Later**. Design D ships pool requests to light clients without it, so a D light client "trusts the store node for B7" (12 step 4) by construction.
- **Store nodes cannot serve many light clients.** I6 makes a direct light client an overlay link. 13.3: "Inbound links count toward the high mark. At 8, accept a new inbound link only if it fills a missing mix requirement; otherwise … close." With the informative defaults, a store node serves about 8 light clients at once. Light clients must be excluded from the overlay slot count, with their own limits.
- Channel-anchor check (A1 and 12 step 4): `id_from_pos` and `outspend` alone do not give the output script or value. The client must also fetch the transaction. That makes 3 lookups on Electrum and 4 on Esplora, not "2 or 3".

### 7. M. Eclipse: the peering defences are weaker in Lightning than the text suggests

- **Address groups barely exist in Lightning.** PR A3: "8,905 Tor-only" of 12,878 mainnet nodes (2024). PR A1 records that Core's outbound netgroup rule exempts "Tor, I2P and CJDNS". Core's group for onion addresses, as far as I recall, is a few prefix bits, so at most about 16 groups. Onion addresses are free. So V1, V2 and P2's "Sybils packed into one range get one ticket per draw" give an attacker on Tor up to every Tor group at no cost. Test 47 (one /16) tests the easy case.
- **The regime thresholds are attacker-controlled.** E2 ("While fewer than 16 nodes meet E1, the age floor drops to 144 blocks; while fewer than 8, to 0") and section 14's "Fewer than 8 / 8 to 50 / more than 50" count nodes in the graph. Early on, adding 50 fresh Sybils turns the full mesh off. Their absence from E1 keeps the age floor relaxed, so the Sybils become eligible within a day.
- **"Non-host" is self-declared.** E3 classifies a node as a host only if it signs beacons. An operator's relays that never host count as the "neutral relays" of M1. M2 then limits only honest, self-interested hosts.
- **The store flag is self-declared and attracts slots.** M3 wants 1 or 2 outbound store nodes, "learned from `overlay_init`", and C3 / PL6 catch up from them. Claiming `store` = 1 wins those slots.
- **Scoring can be gamed** (PR A2: the gossipsub audit found scoring "can be gamed into a victim's peer list"). An attacker delivers its own Sybil hosts' beacons first and earns "First delivery" points. It then causes queue drops (findings 1, 4) and redelivers the dropped beacons through a scout or its own links, which charges honest links "Missed delivery". K2 keeps the 4 best scores, and T3 saves "the 2 best outbound links" as anchors. So the scoring tends to keep the attacker. Count first deliveries only for beacons whose host is not tied to the delivering link (for example, beacons that later arrive on at least 2 other links from different groups). Choose anchors by age and diversity, not by score.
- **No inbound eviction policy.** Eight well-behaved attacker inbound links fill the high mark. 13.3 lets a node refuse new inbound links but never evict. Bitcoin's `AttemptToEvictConnection` protects by netgroup, latency and recent useful relay.

What does defend: RL5 (hosts send their own beacons to every link), E5 (no peer exchange), hourly scouts that draw from the whole graph, and direct queries as the fallback. A member with one honest path and a direct query to a known host cannot be eclipsed for long. **A light client with 1 or 2 built-in store nodes run by one operator can be censored completely by that operator.** Say so in 12 and 16.

### 8. M. The pool request: rate keys, continuation and orphans

- PL3 limits "at most one an hour per peer". A peer is a BOLT 8 key, which is free. Each new key gets the full pool (336 KB at 1,000 hosts; much more under finding 4).
- "A request with `after` that follows the previous page within 60 s continues that request and does not count again". Nothing requires `after` to equal the `next` just sent. Re-sending any `after` within 60 s repeats pages for ever. Fix: `after` must equal the last `next` sent on that connection or reply path.
- **RL4 versus `pool` answers is undefined.** If RL4 (1 a second, bursts of 20) applies to beacons inside a `pool` answer, a 356-beacon page is mostly ignored and catch-up fails. If it does not, `pool` answers are an unthrottled path for signature checks and orphans.
- **Catch-up before gossip sync loses beacons.** PL6 sends `pool_request` on every new link. A fresh node with a partial graph orphans most of the answer, keeps 8 (R-O2), and cannot ask again for an hour. Delay PL6 until gossip is synced, or exempt pool answers from the 8-per-link bound with their own larger, short-lived bound.
- Precedent cut both ways. Core gates BIP 35 `mempool` behind a permission because of bandwidth and fingerprinting (PR F14). The spec makes it a MUST for store nodes, on both carriers.

### 9. M. Onion amplification and host query budgets

- O3 makes `listing` and `pool` answers 32,834-byte onions, against 1,366-byte requests: about 24× amplification. Anyone can build a reply path to any node keys, so the reply traffic runs through ordinary Lightning nodes chosen by the asker. That contradicts the impression that ordinary nodes carry nothing (tests 33, section 18 "changes nothing for anyone else" is true only for design C). A 452-byte listing fits in 1,366. Use 32,834 only when needed.
- H2: "The source is the incoming peer for onion messages". One attacker routing through the host's busiest neighbour uses up that neighbour's 1 index request per 10 s for everyone behind it, so all light clients of that LSP lose (open point 14 notes this). The global 50 a second is exhausted by cheap native connections with fresh keys. Prefer per-address-group budgets on the native carrier and fair queueing on the onion carrier.

### 10. M. A6 lets a channel counterparty kill a host's channel-anchored listings

A1: "Value V = half the output's value (half for each node)", so both nodes of a channel may use it. A6: "Two `host_key`s presenting the same anchor while both listings are live: drop both." The other end of the channel, for example an LSP or a rival host that opened a channel to the host, can publish one listing under its own key with the same channel anchor and so remove the host's channel-anchored Nostr listings. Fix: for channel anchors, count each node's half separately. A6 should apply only to coin anchors, which already bind `host_key` (D11).

### 11. L. Coin-anchor capital can be recycled

A2 caches "unspent" for 144 blocks. A host can anchor 4 listings, spend the coin to a new coin, wait 6 confirmations and anchor 4 more under another key. That is about 24 cycles a day at about 15 sats each at 0.1 sat/vB, so one coin backs about 96 live listings. Re-check unspent at display time when the cache is older than about 6 blocks, or tie the allowance to coins unspent for at least `coin_valid_until` − now.

### 12. M. Privacy: who learns what (question 6)

Section 16 misses these:

| Path | Who learns | Missing from 16 |
|---|---|---|
| Onion query or pool request from a member | The **first hop**, which in SuperScalar is the member's current host, learns that its member is querying, roughly what size (1,366 out, 32,834 back) and the next hop, often the rival host or a known store node | Yes |
| Every connection | 3 rule 1: "Every Gazpacho node sets 449 in `init`", including the fresh BOLT 8 keys of F2. Every peer, including ordinary nodes and the LSP, learns "Gazpacho wallet". F2's fresh key does not hide that | Partly (row "Bit in `init`") |
| DQ2 polling | Up to 32 nodes an hour each learn the asker's IP (no Tor in the demo is stated) and that it is browsing. Hosts can join the IPs across hosts | Yes |
| `host_list_request` with `keys` | The store node learns exactly which hosts the light client considers new | Yes |
| Nostr | The relay learns the IP and that the subscription is to kind 31867 with `L` = `gazpacho` | Partly |
| Store fetch | 11.2's claim that "the host never learns who asked" holds only when a store peer holds the listing. On `listing_not_held` the host is asked within 60 s | Fine as written; state it in 16 |
| DQ1 | Every F node, phones included, answers with a signed empty index, so anyone can ask "is this a Gazpacho node, and does it host?" (open point 15) | Covered as open |

### 13. L. The bandwidth estimate (13.8) leaves out the scouts

T2 runs a scout every 60 minutes, and PL6 / T2 send an unfiltered `pool_request` on each. At 1,000 hosts that is about 24 × 336 KB, roughly 8 MB a day per node, against the table's "about 1.9 MB". Daily rotation and restarts add more. The table also assumes 1.5 beacons per host a day, against a cap of 8 per 144 blocks, and against the unbounded rate of finding 1.

### 14. L. Consistency with the spec set

- Section 19 is stale. `messages.md` 6.1 already says "at most 4 (the same cap as a host's live listings…)". `terms.md` open point 7 is already "Closed". Discovery's section 19 still marks both "Not done", and open point 9 still says `messages.md` "still says … up to 16 lobbies".
- Paths. The document cites `notes/ideas-ledger.md`, `notes/peering-research.md` and `notes/discovery-research.md`. On this branch they are under `docs/research/`.
- Wrong direction. `messages.md` 4.1: "A kind sent in the wrong direction … is refused." Discovery 6.3: "ignored, not refused". `messages.md` 4.1 also refuses a discovery kind with a nonzero `scope`. One of the two documents must give way.
- Feature bit in the demo. `messages.md` 2 and `PROTOCOL.md` 8.3 say "None in slice 1". Discovery 18 says the demo wallet sets 449 "on every Gazpacho node". If the demo is slice 1, these conflict. If not, say which slice sets the bit.
- B2: "`channel_sat` ≥ 1". `terms.md` 3 has a lower bound of 546. Use the terms bound.
- No listing rule (L1 to L8) enforces "Circle lobbies are never listed" (conventions). Only B2 does, for beacons. Add `profile` ≠ 4 to L2.
- D5's `unknown` vector uses `sha256('no such lobby')` (tool line 207 of output). Q4 drops "`unknown` with another digest". As printed next to D5's `listing_request` for T1, the pair is not a valid exchange. Use the requested digest, or say the vector stands alone.

### 15. L. Statements stronger than the evidence

- 10.1 / ledger A6: the relay flag "which blocks-only nodes have used since 2012". The flag is BIP 37 (2012). `-blocksonly` dates from Core 0.12 (2016), and block-relay-only connections from 0.19.
- 8.6: "Losing an entry early is harmless." See finding 3.
- 8.7: the Reject checks "do not depend on the receiver's view". They depend on its version (finding 5).
- 14: "A node that has synced gossip from 3 to 5 peers sees every F node." This is PR B9's assumption, not a measured result. DR A1 records announcement rate limits and 200 s to reach 75% of nodes. Say "usually".
- 13.3: "Bitcoin's full-RBF and Libre Relay slots were added". The full-RBF preferential peering was an unmerged Core pull request (#25600, PR A1). Libre Relay is a fork.
- 12 step 1: "One honest source is enough, because the data is signed (BIP 157's reasoning)". That holds for the union only if the honest source is itself complete. Signatures stop forgery, not omission.
- Section 1, point 4: "so most askers never touch the host". It is true for interested nodes. For store nodes, all of them start S1 inside the same random 0 to 60 s window and mostly find their store peers empty (S4 never waits), so most of them ask the host anyway.

### 16. L. Sequence numbers do not survive a restore

8.1: "Per host, strictly increasing over all its beacons." A host restored from its seed has lost the counter. Its new beacons are ignored (B8 a, for re-announced lobbies) or evicted (B10) until its old beacons expire. Derive the sequence from the tip, for example `height × 16 + counter`, which also matches B9's window.

### 17. L. Normative and informative boundaries

- Section 14 is called normative but contains an "informative" table and **proposed** DQ2 numbers.
- Sections 16, 18, 19 and 21 are unlabelled.
- 13.6 repeats the normative Reject (8.7).
- 13.7 C3 and 13.4 M3 decide where catch-up and listings come from (G2, PL6), so a builder needs them, yet they are informative.
- The tests in section 21 are not tagged by release, so a design-C builder cannot tell which apply (for example, test 16 is onion, which is not in the demo).

## Questions asked, in brief

1. **Spam within the caps.** For one honest-rule host: 4 × 166 B held per relay, 8 beacons a day relayed, 4 × 4,817 B per store node. But B9 is bypassable (1) and each Sybil host costs half of a tiny channel (4). Malicious relays: replays of live beacons are deduplicated. Replays of withdrawn beacons succeed (3). Orphan filling is bounded at 8 per link and 64 in total and is fair (R-O3, D18 asserted). Filter abuse costs only the abuser. Pool amplification is unbounded per key (8). Onion amplification is about 24× through chosen paths (9).
2. **Eclipse.** RL5, scouts and direct queries protect a full node with one honest path. Diversity is weak on Tor. Thresholds and roles are self-declared. Scoring is gameable. A light client is censorable by its store operator (7).
3. **Identifiers.** `beacon_id` over everything but the signature, "seen after verify" and the lower-id tie are sound in themselves (D17 holds in any order *while both are held*). Sequence, churn, withdrawal and seen-set interact badly, and two honest nodes can disagree until a beacon's deadline (1, 3).
4. **A lying store node** can withhold (bounded by the fallback to the host and by scoring) and serve stale listings (no tombstone, 2). It cannot serve another host's listing (S2, Q4 bind `host_key` and the digest). `listing_not_held` is fine but unverifiable (a non-store node "MAY answer" it too). Store persistence does not include the seen-set or tombstones (3).
5. **Light clients.** Not implementable today as written (6).
6. **Privacy.** See finding 12.
7. **Lightning compatibility.** Bit 449 is odd and unlisted in bLIP 2 as fetched today (bLIP 2 rule: "bLIPs must use feature bits above that range" 0 to 255). A 57-byte feature field is fine. Onion payload types are odd, ≥ 64 ("Field numbers 64 and above are reserved for payloads for the final hop"), one per message (BOLT 4: more than one payload field, "MUST ignore"), and none are listed in bLIP 2. Type 52791 is odd, so ordinary peers ignore it. Ordinary nodes are burdened only as onion-message forwarders in design D (9).
8. **Consistency.** See findings 14, 15 and 17.
9. **Design C.** See the next section.

## Can design C (the demo wallet) be built from this spec alone?

Mostly yes: the bit, kinds 129 to 135, the listing, coin anchors, the Nostr event and vectors D2, D4 to D6. A builder would have to guess:

1. **Withdrawal and replacement on Nostr** (finding 2): as written, a withdrawn lobby cannot be removed and can block new ones.
2. **Which nodes to query, and from where.** DQ2's "the nodes in it that set 449" assumes a graph. Does the demo wallet hold one? Is it a light client? Which chain server does it use for the anchor checks? Is there Tor?
3. **Scope-zero `hello` (F1) versus `lobby_index_request`.** Both list lobbies on a direct connection. Which does the demo use, and must a host support both?
4. **Nostr operations:** default relays, the subscription filter (`kinds` 31867 with `#L` / `#l`), which key the host publishes under, how duplicates by several authors are shown, and publish and refresh timing. The `expiration` formula needs the publisher's tip; say what to do if it has none.
5. **Coin anchor key.** "BIP 340 by the output key Q" means the **tweaked** key for a BIP 86 wallet coin. D2 uses an untweaked secret as Q. State the tweak, and add a BIP 86 vector.
6. **Unregistered-build marking** (section 2: "builds that say it is unregistered"): where and how.
7. **Whether the demo sets 449 at all,** given `messages.md` 2 (finding 14).
8. **Which tests in section 21 apply** to the demo (finding 17).
9. **Channel anchors are "optional" in the demo,** but there are no channel-anchor vectors (open point 10).

## Vector check

Ran `python -I tools/spec-vectors.py` in a temporary detached worktree of `origin/specs-slice1` (`a4fd3bc5`). It exited 0, so every internal `assert` passed. I extracted every hex string of 16 or more characters from discovery.md section 20, joining multi-line code blocks: **44 strings, all 44 found verbatim in the tool's output.** By hand I also re-derived the stated sizes and lengths, and all match: D5 (34 / 192 / 194 / 234 / 68 / 456 with `02fd01c4` = 452 / 496 / 464), D7 (166 / 206), D10 (86, "nothing" 46), D13 (77 / 37), D14 (55 / 95 / 61), D15 (204, `04a800a6` = 168-byte entry with a 166-byte beacon; 244 / 210; 178 × 168 + 38 ≤ 30,000 and 356 × 168 + 38 ≤ 60,000), D16 (108), D19 (109), D6 (604 base64 characters for 452 bytes), D2 `coin_valid_until` `000470c0` = 291,008.

Limits of the tool. It **computes** D12 (`sorted(...)[-4:]`) and D17 (`min(...)`) instead of running B8 to B10 in arrival order, so finding 1 passes unnoticed. D4x and D4w are signed but no L-rule reader checks them, so finding 2 passes unnoticed. D9 and D11 check only that the signature fails. No vector exercises B6, B9, orphan re-check (R-O4), paging, or a tombstone. Channel-anchor and `host_list` vectors are missing (open point 10).

## What I could not check

- LND, CLN, Eclair and LDK source today: onion-message forwarding to non-peers, minimum channel sizes accepted into the graph, and inbound limits. I relied on DR / PR citations, plus LND's rate-limit doc, which I fetched.
- BOLT 7 and BOLT 9 were not re-fetched. 3.1's quotes ("will be propagated normally", "SHOULD NOT connect", "MUST NOT route a payment through the node") match my reading of BOLT 7. The bLIP-56 pull request was not read.
- Bitcoin Core `net.cpp`, `net_processing.cpp` and `txorphanage` were not re-read today. Core's onion-address grouping and the exemption of privacy networks from the outbound netgroup rule are taken from memory and PR A1.
- The gossipsub v1.1 spec and its evaluation paper were not read directly. I used PR A2's summary.
- The NIPs kind table (31867), and real Nostr relay handling of addressable events from many authors.
- Whether the demo wallet is "slice 1", and which Lightning implementation a SuperScalar host runs, which decides finding 6's LSP question.
- Live mainnet minimum fee and channel-size economics behind finding 4's cost estimate. It is an order-of-magnitude estimate, not measured.
