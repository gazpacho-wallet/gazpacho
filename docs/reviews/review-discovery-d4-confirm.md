# Confirmation review: `spec/discovery.md` draft 4

Round 3, 2026-11-12. This is a confirmation review, not a full review. Reviewed at `origin/specs-slice1` = `e833cae8`. Round 2 is `docs/reviews/review-discovery-d3.md`; its findings are cited N1 to N14. I read discovery.md draft 4 in full, the `lobby_salt` row of `terms.md`, and `messages.md` open point 1. I ran the vector tool, and I ran the tool's own reference reader on three attack cases. Nothing was posted anywhere.

## Verdicts

- **Design C (the demo wallet, 14.1): ready.** Every byte on the wire is specified. The Nostr gaps are closed (17, 17.1), the salt rule is in `terms.md`, and the Tor budget no longer lets one connection starve the others. One residual remains, and open point 17 states it honestly: an attacker with *many* Tor connections still shares the Tor total with honest askers. A new browsing user has no channel or seat to get priority with. That costs availability on signet only, so it does not block the demo. Do it before mainnet.
- **Design D: ready after the small changes listed under "New issues".** None of them needs rework: two are one-hop bounds, the scoring item is informative policy, and the rest are wording. The most useful are E1 (the pending pool can be filled with junk from unpriced keys) and E2 (beacons accepted from an asked-for pool page are relayed onward without the arrival cap). I reproduced both with the tool's own reader.

## N1 to N14

| N | Status | Evidence |
|---|---|---|
| 1 Tor budget | **Partly** | H2 now budgets each Tor connection (its BOLT 8 key) separately and serves them "in turn"; connections proving a resource go first. S8 and PL3 follow it. D27 passes: one attacker at 10 requests a second, and the honest wallet is answered at t = 5 s. **Residual:** many attacker connections still share the Tor total. With 8 index requests per 10 s and N attacker connections, an honest newcomer waits about N / 8 × 10 s, which is past the 30 s timeout once N > 24. Open point 17 says so. Also, S8's "a new client replaces the client idle longest" lets busy attacker connections push out idle honest light clients |
| 2 Scout dropped | **Fixed** | PL3: "A request **without `token`** is a new request, with or without `after`". New field `max_entries`. D15c is the scout's request; D26 answers it |
| 3 Catch-up trigger | **Fixed** | PL6 fires when the sync peers have finished, or after 10 minutes with no new announcement **of an F node**, and "at the latest 30 minutes" after start. Test 44 covers a network where announcements never stop |
| 4 Back-dating, tombstones | **Fixed for relays, two residuals** | B9(b) counts by arrival; tombstones have their own cap (allowance + 4); PL1 filters them; the cursor is (host, sequence). D24 passes: 8 relayed (draft 3: 56); tombstones held 5. Residuals: E2 and E3 below |
| 5 First-delivery farming | **Fixed**; it raises a new issue | 13.6 drops all positive credit. The penalty that remains can be steered (E4) |
| 6 Eligibility, Tor eviction | **Fixed** | E1 adds half-capacity of at least `unit` / 16. 13.3 protects "up to a quarter of the inbound links (at least 2) that are Tor-only, oldest first" |
| 7 No second offer | **Fixed**, residual E1 | R-P1 and R-P2 add a pending pool, re-offered at each block. D25 passes: held pending, not relayed, then accepted and relayed to the next node |
| 8 Rentable price | **Fixed** (stated) | 8.2 and 8.8 now say "locked capital, not cost"; open point 3. `host_list` carries up to 8 channels. Small inconsistency E6(b) |
| 9 Onion paging, silent too-large | **Fixed**, small inconsistency E6(a) | PL3 binds a continuation by its token alone, so pages may use fresh reply paths. `too_large` is added to `listing` (type 8) and `pool` (type 9) |
| 10 W2 reasoning, salt | **Fixed** | W2 is reasoned again (listings signed *before* the withdrawal; W4 forbids later ones). W4 makes no-reuse a MUST. `terms.md` row 6 now says "MUST draw a fresh salt … MUST NOT reuse one". Test 10a. Small inconsistency E6(c) |
| 11 Same-height restore | **Fixed**, edge E7 | 8.1: no beacon "until its tip is above the height at which it started" |
| 12 Nostr | **Fixed** | 17.1: query by `#d` "**before a listing is first shown**", waiting for end-of-stored-events or 5 s. 17 adds "Telling them apart" by parsing the content (labels are hints only), says withdrawal events carry every label, and fixes the `addr` format. Test 11 |
| 13 Numbers and claims | **Fixed** | `max_entries` 64 for scouts; 13.8 counts about 3.5 entries per host including tombstones; open point 16 now says the limit binds busy hosts |
| 14 Stale `messages.md` text | **Fixed** | `messages.md` 13, point 1: "set in `init` by every build that includes discovery … a build without discovery sets no bit" |

## New issues (the fixes against each other)

### E1. L/M. Junk from unpriced keys can fill the pending pool and push out an honest beacon

R-P1 holds a beacon pending once it passes **B1 to B5**: no graph, no price, and anything up to 144 blocks ahead. Eviction is "oldest evicted first" across all links. Unlike R-O3 for orphans, nothing protects a link that holds fewer.

I reproduced it with the draft-4 `Reader` (real signatures). A node at tip T holds one honest beacon pending, 10 blocks ahead, from link "good". Seventy beacons signed by 70 throwaway keys, each 100 blocks ahead, arrive from 9 other links. Result: 64 pending, and **the honest beacon is gone**.

A node that is actually synced also holds such junk for up to 6 hours. Fixes:

- Evict as R-O3 does (from the link holding the most).
- When the host is in the graph, check the price (B7) before holding a beacon pending.
- Consider "ahead by at most 144" → a smaller bound, for example 12, for nodes whose own sync shows they are not behind.

### E2. L/M. Beacons from an asked-for pool page are relayed onward without the arrival cap

B9(b) exempts "numbers from a `pool` page this node asked for", and 8.3 then says "hold … and relay it (8.5)". With the draft-4 `Reader`, one host with allowance 1 and 56 back-dated beacons delivered in an asked-for page gives: **56 accepted and 56 relayed**. With 56 tombstones: 56 relayed, 5 held.

Each neighbour then applies B9(b) and keeps 8, so the spread stops after one hop. But a malicious store or overlay peer can use any node that catches up from it to push 56 × 6 messages one hop further, and the catching-up node holds a different set from its neighbours. Fix: hold such beacons, but relay one only if it would also pass B9(b), or do not relay beacons that arrived in pool pages at all (peers do their own catch-up).

### E3. L. The tombstone cap can evict a tombstone that is still needed

B10 caps tombstones at the allowance + 4 and evicts the lowest sequence. Example: an honest host with allowance 1 that opens and withdraws one lobby a day has 6 tombstones by day 6. The oldest is evicted while its original beacon (deadline up to `open_height` + 1,008) may still be live at a node that missed the withdrawal. The original can then come back through that node's pool. Under W5, the same eviction also drops the *listing* withdrawal that a beacon withdrawal stands for. That contradicts W2 ("kept until … + 1,014") and S3.

8.6 still says tombstones are "bounded by B9: at most 8 per 144 blocks per host", which disagrees with B10.

Fix: apply the allowance + 4 cap only to tombstones that withdraw no beacon this node held or saw (the spam case D24 targets). Keep tombstones that replace a held beacon until `open_height` + 1,008, bounded by B9. Align 8.6.

### E4. M (informative policy). The penalty-only score can be used to drop honest links

13.6 Missed delivery: "−1 for each beacon that arrived on at least 2 other links in 2 other address groups, or from a scout, and that this link … never sent within 10 min. At most −1 per host per 144 blocks." Every link starts at +10, and K1 drops a link below zero.

An attacker holds 2 links to the victim in 2 cheap clearnet groups and runs about 11 priced hosts. It publishes those hosts' beacons **only** through its own relays (RL5 sends a host's beacons to *its* links, which are the attacker's). The victim's honest links never see them, so each honest link loses 1 point per host and falls below zero within one 144-block window. Removing the positive term (N5) made the scores unfarmable, but the remaining penalty can still be steered by whoever controls which beacons reach whom.

Mitigation: count a miss only when the beacon also reached this node through an anchor or through a link older than the penalised one. Or attribute misses only from scouts, since scout targets are random across groups. Or cap the total missed-delivery penalty per link per 144 blocks (for example at −2).

### E5. L. R-P3's second catch-up may be dropped by PL3

PL3 allows one new request "per connection and at most one an hour per peer". A phone that starts behind sends its PL6 catch-up after gossip sync, and then R-P3's catch-up "once its tip is within 6 blocks". If both go to the same peers within the hour, the second is dropped. Send R-P3's catch-up to a different peer, or wait for both conditions and send one catch-up.

### E6. L. Wording inconsistencies

(a) Q4 still reads "exactly one of records 2, 4, 6 … Otherwise drop". The new `too_large` (record 8 of `listing`, 6.1) is therefore dropped by a conforming asker.

(b) 12 step 4: "up to 4 `channel_announcement`s", but 7 now allows 1 to 8.

(c) Section 19 says `terms.md` 3 `lobby_salt` is "**Not done**". `terms.md` row 6 is done.

(d) Not wrong, but easy to get wrong: `token` is type 9 in `pool_request` and type 7 in `pool`, and `too_large` is type 9 in `pool` and type 8 in `listing`. The `pool` table lists 9 before 7. Encoders must sort the records anyway. Consider aligning the numbers, and listing the table rows in type order.

### E7. L. N11 edge case: a chain view that lags

The restore rule waits until the host's *own* tip passes its start height. A host restored on a device whose chain view lags the real tip by k blocks signs at heights it may already have used before the restore, so the "never repeats a sequence" claim depends on an honest, current chain view. Suggest also waiting until the tip is not behind the host's peers (as R-P3 measures), or adding a few blocks of margin.

## Vector check

- **The tool runs clean.** `python -I tools/spec-vectors.py` in a temporary detached worktree of `e833cae8` exited 0 after several minutes, so every assertion passed. That includes D15c and D24 to D27, D22 changed to pending, and the earlier arrival-order vectors.
- **Every hex string matches.** My extractor counts code-block fragments and joined blocks separately, so it finds 56 hex strings of 16 or more characters in section 20, not 45. **All 56 appear verbatim** in the output, so whatever set gives 45 matches too.
- **By hand:**
  - **D15b**: 83 bytes = chain record 34, plus `after` 2 + 37 (`0725`, host key, `0046cd00` = 4,640,000), plus `token` 2 + 8. The token `b2f48ee24ade1026` was independently recomputed in round 2.
  - **D15c**: 77 bytes = 34 + 39 (`after` with sequence `00000000`) + `0b020040` (`max_entries` 64).
- **D24 to D27** print what section 20 says:
  - D24: 8 relayed, 8 relayed, 5 tombstones held.
  - D25: pending, then accepted and relayed.
  - D26: scout answered, 12 entries paged once with hosts split across pages, bad tokens dropped, Starter beacon and tombstone filtered.
  - D27: answered at t = 5.0 s.
- **D27's limit.** Its model has one attacker connection, so it does not exercise the many-connection residual of N1.
- **Extra runs** with the same `Reader`: E1 (junk evicts the honest pending beacon) and E2 (56 relayed from an asked-for page).

## What I did not check

- The parts of draft 4 that did not change (this is a confirmation review), and documents other than those named.
- Lightning implementations' real behaviour for Tor client links and onion paging.
- Market rates for rented liquidity.
