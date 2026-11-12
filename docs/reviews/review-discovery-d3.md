# Review: `spec/discovery.md` draft 3

Independent adversarial review, round 2, 2026-11-12. Reviewed at `origin/specs-slice1` = `0cbc1649`; the history was rewritten, and draft 2's `a4fd3bc` is now an ancestor. Read on that branch: `spec/discovery.md` draft 3, `spec/messages.md` (sections 2 and 4.1, open point 1), `spec/PROTOCOL.md`, `docs/DESIGN.md` 10 and `tools/spec-vectors.py` (the reference reader). Round 1 is `docs/reviews/review-discovery-d2.md`, cited as **R1-n**. Nothing was posted anywhere.

## Verdicts

- **Design C (the demo wallet, 14.1): ready after small changes.** The wire format, the records, the withdrawal and the operations are all specified, so a builder no longer has to guess any byte. Three changes remain:
  1. The Tor budget of H2 lets one free Tor client cut off every Tor asker of a host (N1).
  2. Section 17.1 should say to look up withdrawals by `#d` *before* first showing a listing, and how to tell listing content from withdrawal content (N12).
  3. `messages.md` open point 1 is stale (N14).
- **Design D: ready after listed changes; no rework needed.** All round-1 High findings are fixed or reduced to residuals. Six things still need text before D is built:
  1. Scouts are silently dropped by PL3 (N2).
  2. The catch-up trigger PL6 never fires on mainnet (N3).
  3. Every Tor client shares one budget per store node, so the recommended light-client path ("direct, over Tor") serves 4 Tor clients at a time (N1).
  4. Back-dated sequences give a burst of 56 relayed beacons per host, and tombstones are unbounded by B10 and unfiltered in `pool` answers (N4).
  5. First-delivery scoring can still be gamed (N5).
  6. A few peering details (N6).

## Status of round-1 findings

| R1 | Sev. | Status | Evidence |
|---|---|---|---|
| 1 Churn bypass | H | **Fixed**, with a residual (N4) | B9 now counts "every accepted new number … whatever the order". B6 bounds the sequence: `sequence ÷ 16 ≤ tip + 6`. The reference reader (tool lines 858 to 862) and D20 confirm it: 2^32 − 1 is ignored, and at most 8 are relayed in each of the three orders. Residual: sequences can be back-dated into older windows (N4) |
| 2 Withdrawal fails L4; replay hides new lobbies | H | **Fixed** | 5.3 is a separate signed record (W1 to W7), valid while not live, kept 1,014 blocks, and suppressing by (`host_key`, `listing_id`) in either order. L7 / A5 now keep the **latest** start. The D23 reader (`show_listings`) runs it: D4+D4w in either order shows nothing; a withdrawal by another key is ignored; the replay of four old listings does not hide the new one. 17.1 subscribes by `#d`, so a withdrawal from any author is seen. Small residuals: N10, N12 |
| 3 Seen-set records view-dependent ignores; withdrawals lost | H | **Fixed**, with a residual (N7) | 8.3: "A beacon enters the seen-set **only when it is accepted**". Tombstones are held until `open_height` + 1,008, relayed and served in `pool` (PL1). B8(a): "a tombstone is final". Seen-set and tombstones persist (8.6; S6 is a MUST for store nodes). D21 and D22 pass in the reader. Residual: a beacon ignored at B6 is never offered again (N7) |
| 4 Beacon path nearly free | H | **Fixed in substance**, with residuals (N4, N8) | B7: own halves of channels at least 144 blocks old total at least `unit` / 4; allowance as A3. RL3 drops by host weight, at most 4 per host. D22: 2,499 sat or 143 blocks gives "ignore:B7". Residuals: tombstones are outside B10 (N4); capacity can be rented (N8) |
| 5 Reject closes connections; no upgrade path | H | **Fixed** | 8.7: "**Never close the connection** for discovery". Reject is only non-canonical encoding / over 256 bytes, or a bad signature. B3's shape checks are now Ignore. Unknown odd records are "relayed unchanged". Kind 159 is reserved for a new beacon version. `messages.md` 4.1 line 121 overrides refuse for kinds 128 to 159, and line 125 overrides it for the wrong direction |
| 6 Light-client path unbuildable | H | **Partly** | Direct BOLT 8 to store nodes is specified (12, `client` flag, D13c, S8). `host_list` moves into D (18). The onion path is honestly deferred (open point 9). Lookups are counted correctly (A1). But the Tor-group budgets of S8 and PL3 cap how many Tor clients a store node can serve (N1) |
| 7 Eclipse | M | **Partly** | The Tor-only group with at most 3 links (P2), regime counts at the full floor and price (E2, 14), store claims tested (M3), anchors by age and groups (T3), inbound eviction (13.3) are all there. Still open: first-delivery scoring (N5), E1 without a price, and inbound eviction that targets Tor (N6) |
| 8 Pool request | M | **Partly** | The one-use token (PL3, D15b), per-group limits, RL4 exempting asked-for pages, and R-O6 are all there. But PL3 drops scouts (N2), and PL6's trigger never fires on mainnet (N3) |
| 9 Onion amplification; budgets | M | **Fixed** for size; new issue N1 | O3: "never larger than its request". H2 is fair round-robin on onion and per group on native. Residual hop-count amplification is low (N9) |
| 10 A6 and the channel counterparty | M | **Fixed** | A6 applies to coin anchors only. A1: "half the output's value, for the node named as the host only" |
| 11 Coin recycling | L | **Fixed** | A2: re-check before showing when the cache is older than 6 blocks |
| 12 Privacy rows | M | **Fixed** | Section 16 has all six rows asked for, plus censorship |
| 13 Bandwidth without scouts | L | **Partly** | Scouts are counted, but as "one native page, capped here at 64 entries". PL2 has no 64-entry cap, so a page is up to 356 entries. Tombstones are left out (N4, N13) |
| 14 Consistency | L | **Fixed**, with one leftover | Section 19, paths, `messages.md` 2 and 4.1, `channel_sat` ≥ 546, L2 profile 4 and D5's `unknown` (vector now names T1's digest) are all fixed. Leftover: `messages.md` open point 1 still says "set by every Gazpacho node … (draft 2)" (N14) |
| 15 Overstatements | L | **Fixed**, one new one | Every listed item is corrected. New overstatement: "Honest hosts never reach the limit" (open point 16) (N13) |
| 16 Sequences lost on restore | L | **Fixed**, with a residual (N11) | Height × 16 + counter |
| 17 Boundaries | L | **Fixed** | Every heading labelled; tests tagged [C], [D], [Di] |

## New findings, ranked

### N1. H for design D, M for design C. One Tor group means one free Tor client can starve every Tor user

Several rules key their budgets on the address group and treat all Tor connections as one group:

- H2 (hosts): "the source is the **address group** of the connection (…; one group for all Tor connections, with a budget 8 times larger)". So all Tor askers of a host together get 8 `lobby_index_request`s and 32 `listing_request`s per 10 s.
- PL3: "at most **4 an hour per address group** (one group for all Tor connections, with a budget 8 times larger)". So a store node answers 32 new pool requests an hour for every Tor client together.
- S8: "at most 4 client links per address group". There is no Tor exception, so a store node serves **4 Tor light clients at a time**.
- 7: `host_list`, "as H2's native budget".

A Tor client is free to run, and its key is free. An attacker sending one `lobby_index_request` every 1.25 s through Tor uses up a host's whole Tor budget. Every Tor-using demo wallet (14.1: "Tor | Used for queries and Nostr when the user has configured it") then gets no answer from that host. Against a store node, the attacker holds 4 Tor client links and makes 32 pool requests an hour, which locks out the light-client path that section 12 recommends ("Connect directly, over Tor where possible").

The intent is right (fresh keys must not multiply budgets), but the cure has to work inside the Tor group too. Options:

- Fair queueing per BOLT 8 key inside the Tor group (round-robin, as H2 already does for onion).
- Prefer keys seen before. Keys that have joined or asked earlier get a reserved share.
- A small proof of work for the Tor group.
- At minimum, give S8 the same Tor exception and multiplier as H2.

Add a [C] test: one Tor client at 10 requests a second does not stop a second Tor client from getting an index within 30 s.

### N2. M. PL3 drops scout requests, so T2 (the hourly scout) does nothing

T2: the scout sends "**one** `pool_request` with a random `after` (one page)". PL3: "A request without `after` is a new request … A continuation (with `after` and `token`) … Anything else is dropped silently." Field 9: "`token` … With `after` only". A request with a random `after` and no `token` is neither a new request nor a continuation, so it is dropped.

If a scout instead omits `after`, it always gets the first page, which holds the lowest `host_id`s. It never samples the rest of the pool. The scout is the main eclipse detector (13, "What defends best … scouts drawn from the whole graph"), so this matters. Fix: allow a new request with `after` and no `token`, counted as new. Add a [Di] test: a scout's random-`after` request is answered.

### N3. M. The catch-up trigger of PL6 never fires on mainnet

PL6: catch-up waits until "it has the graph from at least 3 peers and **no new `node_announcement` for 10 minutes**". DR A1 records that node announcements are about 30% of about 103 MB of gossip a day, and that 2.5% of nodes announce more than 144 times a day. On mainnet a 10-minute silence never happens, so a relay never sends its catch-up, and R-O6 never gets used. Use a condition that can come true: no new *F-node* announcement for 10 minutes, or a fixed delay after the initial sync (for example, a gossip-query round completed with every sync peer), with a 30-minute ceiling.

### N4. M. Back-dated sequences, and tombstones outside every cap

B6 lets `sequence ÷ 16` be anywhere in [`open_height`, tip + 6], and `open_height` may be up to 1,007 blocks old. B9 bounds each 144-block window, not the arrival rate. I ran the draft-3 reference reader (the tool's own `Reader` class, real signatures) on two cases:

- **One host, allowance 1, `open_height` = tip − 1,000, one sequence every 18 blocks: 56 offered, 56 held and relayed.** Each newcomer has the highest sequence, so B10 evicts the lowest and relays the newcomer. That is 7 times the "8 new numbers per 144 blocks" that 8.2 states, at once, after a week of quiet. After the burst the rate falls back to 8 per 144 blocks.
- **The same host, 56 withdrawals for random lobbies: 56 tombstones held.** B10 says "Tombstones do not count". A tombstone needs no prior beacon (D21: "D8 before D7: the tombstone is held").

What the tombstones cost:

1. They are held for up to 1,008 blocks. That is up to 56 per priced host, against the "at most 4 per host" of 8.6.
2. PL1 puts them in every `pool` answer "whatever the filter". At 1,000 priced hosts that is about 9.4 MB per full catch-up, against 13.8's 336 KB, and every filtered light client pays it.
3. PL1 requires "all of one host's matching beacons and tombstones in the same page", but a 1,366-byte onion page holds about 6 entries. A host with more than 6 entries can never be paged by small onions, and O3's "sends a smaller page instead" cannot be met.

Fixes:

- Count B9 by the **receiver's tip at acceptance** as well as by height part (8 per 144 blocks of arrival), except for asked-for `pool` pages.
- Require a tombstone to withdraw a beacon that was held or seen, or else count it against B10's allowance.
- Filter tombstones in `pool` like live beacons. Profile and `channel_sat` are in the record.

### N5. M. First-delivery scoring can still be gamed

13.6 counts a first delivery "only if the beacon's host has no channel with the link's node **and** the beacon later arrives on at least 2 other links in 2 other address groups". An attacker's relay R whose Sybil host H has its channels elsewhere passes the first test trivially. H sends to R first, so R delivers first. Honest relays then relay the beacon from 2 groups, which passes the second test. So R earns points for its operator's own beacons. Those points protect R:

- Inbound eviction protects "1 link with the most counted first deliveries".
- K2 keeps the 4 best scores.

Suggestions: cap the points per host (one beacon per host per window can earn at most one point); count a first delivery only for hosts whose beacons this node has also received first from another link at some time; and weigh points by the number of distinct hosts rather than beacons.

### N6. M. Peering details still favour cheap Sybils

- E1 (eligibility) has no price, only "oldest announced channel at least 1,008 blocks". The price applies to beacons and to E2's counts, not to who may be an overlay peer. Aged, tiny channels are cheap.
- P2 caps the Tor-only group at 3 links. On today's network (PR A3: 8,905 of 12,878 nodes Tor-only), half or more of a node's links therefore come from clearnet groups, where VPS addresses in many /16s are cheap.
- Inbound eviction removes "the youngest link in the most-represented address group". All inbound Tor connections share one group, so honest Tor inbound links are always first to go. Bitcoin Core does the opposite: it reserves eviction protection for inbound onion and I2P peers, as I recall; not re-read today.

Add the price to E1, or rank eligible nodes by weight. Protect a share of inbound Tor links.

### N7. L/M. A beacon ignored at B6 is never offered again

8.3 does not mark a B6-ignored beacon seen ("checked again if it comes back"), but nothing brings it back. RL2: a relay "never sends a beacon to a link known to have it", and it counts the link as having it once sent. So a node that was more than 6 blocks behind gets the beacon only from RL6 (6 to 12 h), a scout, or a catch-up. D22 ("accepts it when it catches up") assumes a second offer that the protocol does not make. Hold "future" beacons in a small pending pool (like R-O2: 8 per link, 64 in total), re-checked on each new block.

### N8. L/M. The price can be rented

B7 counts "half of each channel's capacity", whoever funded it. Inbound liquidity bought from an LSP or a liquidity market gives the host a half-capacity credit for a fee of a few percent. So "the beacon path is never cheaper than Nostr" (8.2) holds for locked capital, not for cost. Say so in 8.8. If the owner wants a capital price, count only the host's own *funding* contribution, which is visible on chain for single-funded channels. Separately, `host_list` carries "at most 4" channels. A host whose price needs more than 4 small channels is accepted by full nodes and rejected by light clients.

### N9. L. The onion carrier (Later)

- PL3's onion continuation is keyed "for that reply path", but O4 says "a fresh reply path per request". Onion paging needs one or the other.
- O3: an answer that does not fit "is not sent". The asker learns that only by a 30 s timeout. A one-byte "too large" record, which fits any request size, would let it retry at once.
- The asker still chooses the reply path's length, so total forwarded bytes can exceed the request's by the ratio of path lengths. That is small and bounded by BOLT 4's packet size.

### N10. L. Withdrawal edge cases

- W2's reason ("any listing has `start_height` ≤ `withdrawn_height` + 6") is true only for listings signed *before* the withdrawal.
- A host that reuses a `lobby_salt` within 1,014 blocks gets its new lobby silently hidden by its own old withdrawal. W4 says to use a new salt. Make it a MUST in `terms.md` (salts are random and never reused) and add a test.
- Nobody but the host can create or revoke a withdrawal, so a third party cannot use one to hide lobbies. I found no replay that hides a live lobby: a replayed old withdrawal only suppresses the same `listing_id`, and only until `withdrawn_height` + 1,014.

### N11. L. Restore at the same height

A host restored at the height of its last pre-restore beacon restarts the counter at 0 and can sign the same `sequence` again. B8(b) then keeps the lower `beacon_id`, so the new lobby's beacon loses half the time until the next block. Start the counter from a random value in 0 to 7, or wait one block after a restore before signing.

### N12. L. Nostr details for the demo

- 17.1 subscribes by `#d` "for each listing shown". It should be **before** a listing is first shown, or a withdrawn lobby flashes up.
- State how a reader tells a withdrawal event from a listing event. Both use the same kind and `d`, and the `content` is a different record. Say: by the `withdrawn` label, *and* by parsing record 4's length (32 bytes in a withdrawal, the outer record in a listing). Without the label, parsing decides.
- Say whether withdrawal events carry the `L` and network labels. As written, only the `#d` subscription finds them.
- The `addr` format `<host>:<port>` needs brackets for literal IPv6 and should name onion addresses.

### N13. L. Numbers and claims

- 13.8: the scouts' "capped here at 64 entries" is not a rule anywhere (PL2 allows 356), and tombstones are left out.
- Open point 16: "Honest hosts never reach the limit". A host running 4 lobbies that each start within a day signs 4 opens and 4 withdrawals, which is all 8. A fifth open in that window is ignored, at some nodes or all.

### N14. L. One stale sentence

`messages.md` open point 1 still reads "set by every Gazpacho node in `init` … (draft 2)". That conflicts with `messages.md` 2 and `discovery.md` 3 rule 1 ("A build that includes discovery").

### Mechanisms checked with no new finding

- **Reject that never closes.** 8.7 and `messages.md` 4.1 agree. The 256-byte Reject is safe because bigger beacons go under kind 159.
- **Per-half channel anchors.** A1 and A6 are consistent, and the counterparty attack is gone.
- **Pool tokens.** One-use, bound to the connection and 60 s. A replayed or guessed token is "anything else".
- **Answers never larger than requests.** O3 and PL2 agree on 6 entries in a 1,366-byte page, except the per-host page rule (N4).
- **Tip differences between honest nodes.** These cause only transient differences (B6 and W2 are tip-relative; ±6 tolerance), apart from N7.

## Can design C be built without guessing?

Yes for every byte on the wire. 14.1 fixes the sources, the queries in order (index, listing, then `hello` with the scope), withdrawals, polling, the chain view (`DESIGN.md` 10: Electrum-style servers by default, which can answer every coin-anchor check), Tor, coin anchors only with the BIP 86 tweak (D2t), the hosting duties and the unregistered marking (section 2: the exact `--version` line). The [C] tags give the test list.

What a builder still decides alone, without harm to interoperability: the built-in relay and host lists, the Nostr key derivation, and the polling UI. What it would still guess: the Nostr points of N12. The Tor budget of N1 is not a guess but a weakness to fix.

## Vector check

- **The tool runs clean.** `python -I tools/spec-vectors.py` in a temporary detached worktree of `0cbc1649` finished with exit 0 in about 2.5 minutes, so every internal assertion passed, including the arrival-order reader for D12, D17 and D20 to D23.
- **Every hex string matches.** I extracted every hex string of 16 or more characters from section 20, joining multi-line blocks. All 54 appear verbatim in the output.
- **Independent recomputation**, with my own BIP 340 and secp256k1 code (not the tool's):
  - **D2t**: P = `423c865e…`, t = `0836d296…`, Q = `b8bfc1f0…` match. `coin_sig` verifies under Q and **fails** under P (test 24's claim).
  - **D7**: 166 bytes; `beacon_id` `2a9deaae…`; signature valid; `sequence` record `0046cd00` = 4,640,000.
  - **D8**: `beacon_id` `53d2755e…`, rebuilt from its fields with sequence 4,640,160 and deadline 290,000; signature valid.
  - **D4w**: 141 bytes; `withdrawal_digest` `efdc7125…`; signature valid; height `00046cda` = 290,010.
  - **D15b**: token `b2f48ee24ade1026` = `SHA256("gazpacho test pool token")[0:8]`; 79 bytes.
  - **D13c**: 40 bytes.
- **Limits of the reference reader.** Its B3 checks only the lifetime (not `profile`, `channel_sat` or unknown even records). It does not model RL2 or second offers (N7), PL3 or paging (N2), RL3, or the tip-of-arrival rate (N4). My run of its `Reader` with back-dated sequences relayed 56 of 56 (N4).
- Channel-anchor and `host_list` vectors are still missing (open point 11), as stated.

## What I could not check

- Bitcoin Core's current inbound-eviction protection for onion peers (from memory).
- Real mainnet gossip timing for PL6. I used DR A1's figures.
- Market prices of inbound liquidity (N8 is qualitative).
- Lightning implementations' behaviour for client links without channels at scale.
- The NIPs kind table.
- The other `messages.md` sections beyond 2 and 4.1, and `LOBBY.md`.
