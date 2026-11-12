# Review of `spec/exit.md` draft 1 and spec vectors section X

Reviewer: independent, adversarial; wrote none of the subject. Date 2026-11-12.
Subject: branch `specs-slice1` at `b797334` (`spec/exit.md`, `tools/spec-vectors.py` section X). Imported code read at `origin/main`, `core/superscalar/` (pin `e6573950`). Context read on the same branch: `spec/safety-rule.md`, `spec/terms.md`, `spec/storage-encryption.md` (the branch already carries **draft 2**), `spec/local-api.md` (the branch carries **draft 3**), `docs/MULTI-FACTORY.md`, `docs/DESIGN.md`, `docs/handoff/2026-11-12-tree-fees.md`, `notes/factory-paths.md`, `core/gazpacho/include/gazpacho/event.h`. Bitcoin Core policy read from `bitcoin/bitcoin` master (`src/policy/policy.h`, `src/policy/policy.cpp`, `src/validation.cpp`).

## Verdict

**Ready after listed changes.** The deadline arithmetic is right and I reproduced every number: H_leaf = E − 10·d is what the import builds, and `last_safe_confirm`, `leave_by`, the step deadlines, `host_force_by`, `unlock_by`, the payment and penalty rules and the T1 wind-down finding all check out. The keyless 65-byte anchor-only child is standard and relays on today's Bitcoin Core. Seven things must change before anything with a balance is built on this (Slice 3). Slice 1 and 1.5 owe nothing, so they can go ahead now on sections 4.1 to 4.4, 6.2 and the vectors.

1. **Tip estimate (F1).** The formula in 4.5 does not do what its text claims. If every server hides blocks, or none answers, or the person goes offline by choice, the estimate freezes and the exit never starts.
2. **Freeze (F2).** Section 5.3 step 1 fails payments back after `exit_started`. Failing a payment back means signing a new commitment and revoking the old one, which can revoke the very commitment the exit chose.
3. **Pinning (F3).** The anchor-only child can be pinned for about 234 sat even on a TRUC parent, by anyone, and in practice by the host. So "never a stall" for a member with no on-chain coins is not true against an adversary.
4. **Second-stage penalties (F4).** CH-5 asks for fully signed penalties on the host's second-stage HTLC transactions. Under the standard taproot and anchor HTLC shape those transactions' txids are not known in advance, so a locked watcher cannot hold such penalties.
5. **Spend classes (F5).** Every anchor spend, the member's own anchor-only child included, falls into class S8, "unexplained, stop payments".
6. **`unlock_by` (F6).** The deadline is honest only if the watcher has run since `leave_by_locked` and the tree steps confirmed on time.
7. **Contradictions.** The other specs disagree with this one in the places listed in section 4.

---

## 1. Findings, ranked

### F1. High. A dishonest or absent chain view can make the exit start late, without limit

Section 4.5: in doubt, `T = max(T₀, min(T_claim, T₀ + ⌈(now − t₀)/BLOCK_FAST_S⌉))`, where `T_claim` is the highest tip any server claims, or T₀ when none answers.

- The clock term only puts a **ceiling** on T. Nothing pushes T up. If every right-network server claims T₀ (all of them hide blocks, or an eclipse), or none answers (`unreachable`), or the person chose `offline_by_choice`, then T = T₀ for ever. The `deadline` trigger never fires, the at-risk notices never escalate, and `payments_stop_at` never arrives. The text's claim that "a server hiding blocks cannot make it start later than the clock bound allows" is false for this formula. The other claim, that griefing costs "at most half the remaining time", describes a clock **floor**, which the formula does not have.
- X5 never checks the case where blocks are hidden. All three of its rows have `T_claim ≥ T₀`.
- Open point 11 (offline by choice ends itself at `leave_by − A`) cannot work: while offline nothing is claimed, so T never reaches `leave_by − A`.
- **Trusted state.** While trusted (`agree`, `lagging`) there is no clock sanity check at all. A set of servers that agree on a stale tip, for example the defaults if one operator runs them, delays every date. `safety-rule.md` 11 already excludes "a false view of the chain for longer than the maximum safe absence", but the exit has no cheap detector, and needs one.
- **The other direction is wider than stated.** After a long absence (a laptop asleep for a week), the clock bound is about 2,000 blocks above T₀. One lying server can then claim any tip up to that bound and start the exit at once. Griefing is bounded by "at most half the remaining time" only in a steady state.
- **Fix.** Use two estimates.
  - The deadline estimate is `T_dl = max(T_view, T₀ + ⌊(now − t₀) / BLOCK_FAST_S⌋)` whenever the view is in doubt or stale. Stale means the view's tip has not moved while the clock says it should have, judged at a slow rate such as 1,800 s per block, after a grace period such as 30 minutes after waking or reconnecting so that catching up does not start a false exit.
  - Claims above the view count only if at least one other server agrees, or after headers are checked.
  - Give the watcher and the offline-by-choice timer the same rule.
  - Say plainly that a member eclipsed by all of its servers cannot broadcast either, so the floor buys warnings and a fallback broadcast route, not safety. Recommend one broadcast-only endpoint that is independent of the view servers.
  - Add a hiding case and a "none answers" case to X5.

### F2. High. Failing payments back after `exit_started` breaks the freeze and can revoke the chosen commitment

- 3.4 and X-I3 say that once `exit_started` is saved, "the channel never signs another update or releases another revocation", so the chosen commitment can never be revoked.
- 5.3 step 1 says: "Incoming payments not yet fulfilled are failed back if the host answers within one keep-alive". In BOLT 2, failing a payment back is `update_fail_htlc`, then `commitment_signed`, then `revoke_and_ack`. The member signs a new commitment and **revokes its current one**, which is the commitment `exit_started` recorded. An implementer who follows step 1 literally and later publishes the recorded commitment publishes a revoked state, and loses the channel balance to the host's penalty.
- **Fix.** Do not fail back after `exit_started`. Leave those payments to their expiry: they are the host's money, and on chain the host times them out.
  - If failing back is wanted, do it **before** `exit_started`, as a bounded pre-freeze phase. Choose the commitment only after that update settles or its time runs out, and choose at that point the highest-numbered commitment that is not revoked.
  - Also say what happens to actions saved before `exit_started` but not yet sent, for example a `revoke_and_ack` already journaled. Sending it is harmless, because it revokes an older commitment than the chosen one. X-I3 should say "no **new** signature or revocation decided after `exit_started`".

### F3. High for mainnet, Medium for 1.0.0 on signet. The anchor-only child can be pinned; "never a stall" is overstated

**What holds.** The child is standard and relays (section 2, Q2). Nobody can replace it in a way that lowers the parent's package rate, because a replacement must pay more absolute fee and improve the fee rate.

**Pre-emption.** The attack is to spend the anchor **first**, or to replace the member's child with one that pays a little more absolute fee but carries much more size.

- **Version-2 parent (today's trees, `tx_builder.c:77`).** The attacker attaches a child of up to 100 kvB (`MAX_STANDARD_TX_WEIGHT` 400,000), paying about 10,000 sat at 0.1 sat/vB. To replace it, the member's child must pay more than that in absolute fee (`PaysForRBF`, `validation.cpp` ReplacementChecks), so a member without coins cannot. The 101 kvB cluster limit (`DEFAULT_CLUSTER_SIZE_LIMIT_KVB`, `policy.h`) also leaves no room for another descendant. Before cluster mempool, the descendant limits did the same, although the CPFP carve-out might have let the next level in.
- **TRUC parent.** The attacker's child is capped at 1,000 vB, but the member's child pays a fixed 240 sat. A 1,000 vB attacker child paying F ≥ 234 sat cannot be replaced by it: 240 < F + ⌈0.1 · 65⌉. That cuts the leaf transaction's package rate from 1.11 to about (17 + 234)/(167 + 1000) = 0.22 sat/vB, for at most 234 sat, and the attacker pays it only if the package is mined. Sibling eviction does not help the member, because the eviction must still pay more.

**Who gains.** The host gains everything at H_leaf. So, while blocks clear above about 0.2 sat/vB, a member without coins can be stalled by the host through every tree step and the commitment.

**With coins** the member out-pays modestly: about 300 to 600 sat on a TRUC parent, up to about 10,000 sat per level on version 2. That is a cost, not a stall, and 6.4 rule 5 already says so.

**Requested changes.**

- Restate 0, 6.2 and 6.5 as "a member without coins confirms in calm conditions **unless someone pays to stop it**; that is a known gap".
- Add the pin to `safety-rule.md` 11 ("relay rules ... let someone obstruct it" covers it only loosely).
- Add 11.1 item 10 for TRUC parents too, and give the regtest pinning test an F = 234 case.

**Mitigations to weigh.**

- A larger tree anchor, which moves the threshold but does not remove it.
- For the commitment, a **keyed** anchor that only the member can spend. CH-2 already allows one with a pre-signed child.
- Make the commitment TRUC (F-related point in section 3, Q7).

### F4. High. CH-5's second-stage penalties cannot be fully pre-signed; pre-signed penalties have one fee

- **Second stage.** In anchor and simple-taproot channels, HTLC-timeout and HTLC-success are signed by the counterparty with `SIGHASH_SINGLE|ANYONECANPAY` and carry no fee of their own. The host adds its own inputs, so **their txids are unknown until the host publishes them**. A penalty spending their outputs cannot be signed in advance without a key, and a locked watcher has none. CH-5's "and for each second-stage transaction the host could publish from it" is therefore not achievable unless `channel.md` gives HTLC transactions a fixed fee and `SIGHASH_ALL`. That would itself strand members without coins, as CH-6 notes.
  - Consequence: while locked, a breach in which the host moves the payment outputs to the second stage within one block (the HTLC outputs carry a 1-block CSV) lets the host keep those payment amounts.
  - The loss is bounded by the sum of payment outputs in that revoked state. `storage-encryption.md` draft 2's invariant T rests on these pre-signed penalties, so the bound should be stated in 5.6 and in `safety-rule.md` 11.
- **One fee.** Each pre-signed penalty pays one fixed fee, so the locked watcher cannot bump it during a spike before c + W − B. Penalties all pay the member, so a **ladder of penalties** at several fee rates, all spending the same outputs, is safe under invariant T and costs only storage. Recommend it in CH-5, or give the penalty its own anchor.

### F5. Medium. Section 8's spend classes misfile normal events as S8 ("unexplained, stop payments")

- **Anchor spends.** Section 8 watches "every path step's anchor outpoint while its step is unconfirmed", but no class covers an anchor spend. Every keyless child lands in S8: the member's own anchor-only child, a sibling's, the host's, a stranger's. S8 says "should not exist: every other spend needs the member's signature", which is false for P2A. Each sibling's software would raise `at_risk` and stop payments whenever anyone bumps a shared level.
  - Add class S9, "anchor spent": record it. If its package does not meet the step deadline, it is the foreign child of 6.4 rule 5.
- **Commitment outputs.** After a commitment confirms, the host's spends of its payment outputs are unclassified. Those are the host's claim with the preimage, which the member must extract and record, and the host's timeout claim. The host's sweep of its own output is unclassified too.
- **The leaf channel's own cooperative close.** A `shutdown`/`closing_signed` close of the leaf channel once the leaf is on chain is either impossible in 1.0.0, in which case say so, or it needs a class.
- **Watching by script.** `event.h` today reports `GZ_CHAIN_SCRIPT_SPENT`, watched by **script**. Every P2A has the same script (`51024e73`, `channel.h:20`), and the leaf transaction's input and the channel output share one scriptPubKey (`factory.c:1312-1316`, `node->spending_spk`). Watching must be by **outpoint**, and 3.2 should say so explicitly, not only by reference to `signing-round.md` 12.1.

### F6. Medium. `unlock_by` is honest only in the good case

- `unlock_by = last_safe_confirm − A − M` (E − 42 for T1 at d = 2) assumes the watcher has run since `leave_by_locked` **and** every tree step confirmed by its `step_due`.
- **Tree steps late.** If the steps are late (no fee coins, a spike, the pin of F3), unlocking **earlier** is what helps, because the unlocked node can bump with wallet coins. The 5.6 table has no row for "tree step late while locked". Add one: `at_risk`, "Unlock now: leaving is behind and needs a higher fee".
- **Machine off.** If the machine was off rather than locked and comes up near `unlock_by`, the watcher still has n − 1 steps to publish. The strip must show `unlock_by` recomputed from `n_missing`, not the B5 constant.
- **Wording.** The row "Something to take out; T < `leave_by_locked`" should not suggest that unlocking at `unlock_by` is fine whatever happens. Recommended: "Unlock before block `leave_by`; by `unlock_by` at the very latest, if Gazpacho keeps running".
- **Never unlocking.** The draft is honest about it: a dishonest host takes the channel at H_leaf + 1. An H17 host forces the member out at `host_force_by`, at E − 36 once the path is out, and the balance then waits safely in the member's output on the host's commitment, with no competing claim. Payments whose secret was released are lost. Say this in one line in 5.6. Today it is only implied by "After block H_leaf the host can take this balance".
- **Contradictions in 5.6 itself.**
  - The table says "Can: compute the step dates and `unlock_by`" and "Cannot: change a date". Write "cannot change a stored date or constant".
  - The text says publishing "does not end the member's channel", but W3 then freezes it at unlock.

### F7. Medium. Siblings: funds are untouched, but the claims overreach and the other spec says the opposite

- **What is correct for 1.0.0 trees.** There are no relative timelocks (`node_nsequence`, `factory.c:129-140`: fixed kickoffs and pseudo-Spilman leaves `0xFFFFFFFE`, leaf kickoffs `0xFFFFFFFF`, lock time 0). A sibling's leaf transaction and channel output are untouched and its H_leaf is absolute. Its `n_missing` falls, so its `leave_by` moves later. The newly exposed outputs' timeouts, E − 5·(2j − 1), all lie after every H_leaf below them.
- **What overreaches: "S pays nothing".** Once the root kickoff is buried, the whole-factory cooperative close (E-a) and the rotation close (E-d) are gone. S can then extend only by paying across (E-b), which needs the host's liquidity and routing, or by its own on-chain exit. The commitment fee is the host's, but S's sweep fee and any bump are S's. So the honest statement is "loses no funds; may pay an on-chain sweep it would otherwise have avoided, and loses the cheap rotation". Say this in 7.1 and in the griefing paragraph that follows it.
- **The contradiction.** `storage-encryption.md` **draft 2** 8.7.5 says early publication makes every member under the subtree "pay exit fees and lose their off-chain places in the factory", and cites exit 7.1, which says the opposite.
- **Sibling duties to add to 7.1:**
  - classify anchor spends (F5);
  - switch the rotation planner to paying across, and recompute `move_by`, once the root kickoff is buried;
  - mark any in-flight rotation round on the old funding failed;
  - never re-publish shared levels already confirmed.

### F8. Medium. The host side lacks the payment-deadline rule; H15 row 2 has the commitments swapped

- **New rule H18.** A payment the host offers a member must be resolvable on chain by the host before the host's **upstream** deadline. If the member goes silent, the host must publish the member's whole path, its own commitment and the HTLC-timeout transaction. So the host's `cltv_expiry_delta` toward factory members, and its go-on-chain height for each such payment, must include (n + 1)·A + (B − 1) + M_host for that member's d. Standard deltas of 34 to 80 blocks can be shorter than a deep path at mainnet constants. Without the rule the honest host loses money and is pushed to cut corners.
- **H15 row 2.** "The host's output on a member's commitment ... no deadline unless the commitment is revoked (then the member's penalty competes ...)". On the **member's** commitment the host's output is `to_remote`, which carries no penalty path. If that commitment is revoked, it is the **host** that penalises. The row describes the host's `to_local` on the **host's own** commitment. Rewrite it as two rows.
- **H14, H16 and H17 are sound.** H17 does not contradict H1 to H13: H6 assumes a payout, and 1.0.0 has none. Two notes:
  - H17's "a member that is running always leaves first" holds only when the host's A and n are at least the member's. Say "normally".
  - H16 needs the funding transaction to **have** a host change output, or a P2A of its own. Require it.

### F9. Medium. Open point 1's T3 (wind-down 108) is too short once `move_by` is counted

- The finding itself is right: under T1, `leave_by` falls 14, 30 and 46 blocks before the lifetime ends, at d = 1, 2 and 3.
- The proposed fix covers only the lead. `MULTI-FACTORY.md` 4.1 has `move_by = start_leaving_by − route CLTV − claim time − margin`, and the route CLTV includes the destination's `min_final_cltv_expiry_delta`, which is 52 here (X4), plus the host's delta.
- At d = 3, with a 40-block host delta: `move_by` ≈ E − 82 − (40 + 52) − 6 − 14 = **E − 194**. With a 108-block wind-down, the move window opens at E − 108, **after** `move_by`. Rotation with a balance would still be untestable.
- T3 needs a wind-down of about 200 or more at d ≤ 3, or a shorter destination `min_final`. Recompute this with the real host delta before fixing T3.

### F10. Medium. The payment rules for a member without coins

- **Incoming.** On chain, a coinless member cannot claim an incoming payment through a zero-fee `SIGHASH_SINGLE|ANYONECANPAY` HTLC-success transaction. CH-6 notes this, but 4.4's acceptance rule assumes the claim is possible. Either refuse incoming payments that are not claimable without coins (beyond a small total), or count them as not protected and show that.
- **Outgoing.** Reclaiming an outgoing payment after h has the same problem.
- **Outgoing, "nothing competing".** That holds for the member's interest only. After h the host can still claim with the preimage until the member's timeout transaction confirms. The race is harmless to the member, but the wording should say so.

### F11. Low. The depth prose in 4.2 is wrong; the vectors are right

"d = 2 at 4 to 8 members ... d = 3 at 9 to 16" does not match the split rule. With `[4, 3]`:

- 5 to 7 members give some leaves at d = 1. X2 itself prints 5 members, member 5: d = 1.
- 9 to 15 members mix d = 2 and d = 3.
- 4 members uses `[3]`: binary, d = 2, not a width-4 level.

`notes/factory-paths.md` U-a ("D = 2 at 3 to 8 members") has the same error.

### F12. Low. Restore: 5.7 item 3 contradicts `DESIGN.md` 6

`DESIGN.md` 6 says "A restored backup never publishes its own channel state". 5.7 item 3 offers publication as the person's choice. Either change DESIGN or drop the option. The option is defensible; the contradiction is not.

### F13. Low. Ordering and save-before-send details

- **W3.** It says to broadcast the commitment "at once", but 5.3 sends a step only once its parent is confirmed. Say "as soon as the leaf transaction is confirmed".
- **The watcher.** Say whether it writes `watch.gzl` **before** each broadcast. If it does not, a crash loses the record, and W3's "if the watcher broadcast any tree step" cannot be decided. Better: decide W3 from the chain. If the member's own leaf kickoff or leaf transaction is confirmed and nothing has been moved, record `exit_started`.

### F14. Low. Encoding and wording

- **B5 constants are `u8`.** Mainnet M_spike (proposed 144) fits, but M_locked (n·A) or a two-day spike margin need `u16`.
- **The 6.6 example** "565, 623 or 614, and 786" lists four fees for three sizes. The 167 vB transaction has two fees, 17 and 26.
- **Checklist numbering** in section 13 runs 12, 15, 13, 14.
- **An invariant to add.** Refuse to put a leaf with `ps_chain_len > 0` in the bundle. "One version per funding output" is true only while leaves never advance, and an assertion should guard it.

### F15. Low. The constants

- B = 3, A = 6 and M_safe = 6 follow `safety-rule.md` 12.
- A's reasoning (one block, plus noticing, plus two climbs at `CLIMB` 2) adds up to about 6.
- M_spike = 6 on signet is a placeholder, and is marked [M].
- M = 14 is larger than safety-rule 12 value 6's margin of 6, which `safety-rule.md` C8 uses today, so the two specs disagree (section 4, item 2).
- **M_host.** It drops M_spike only because the host keeps a fee reserve (H7). That is reasonable, but the reserve itself is "no reserve" for members (decision 6). Fine as stated.

---

## 2. Answers to the review questions

### Q1. Deadline arithmetic

**Verified in the import (`factory.c`, pin `e6573950`):**

- `:1475` defines `TIMEOUT_STEP_BLOCKS 5`.
- `:1635-1644` sets `ko_cltv = E − (2·depth − 1)·5` and `st_cltv = E − 2·depth·5`; the root has `ko_cltv = 0`.
- Static kickoffs take `ko_cltv` (`:1683-1686`). A leaf is never static (`:1669`, `if (is_leaf) is_static = 0`).
- `add_node` builds the CLTV leaf into the node's own `spending_spk` when `node_cltv > 0` (`:185-214`). The parent's output to a node pays that `spending_spk`, so the timeout protects the output the node spends.
- The leaf kickoff's output 0 pays the state node's `spending_spk` (`:1749-1754`), and the pseudo-Spilman channel output copies `node->spending_spk` (`:1312-1316`). So the leaf transaction's input and the channel output both carry E − 10·d.
- The host's timeout spend is built with lock time = `cltv_timeout` and nSequence `0xFFFFFFFE` (`:4856-4861`). With Core's `CheckFinalTxAtTip`, which uses tip + 1, and `IsFinalTx` (lock time < block height), it is first mineable in block h + 1.
- Tree transactions have version 2 and lock time 0 (`tx_builder.c:77`, `:103-114`). nSequence comes from `node_nsequence` (`:129-140`): fixed kickoffs and pseudo-Spilman leaves `0xFFFFFFFE`, leaf kickoffs `0xFFFFFFFF`. There is no relative lock anywhere on the path.

So H_leaf = E − 10·d is correct, and n = d + 3 is the whole path. The leaf's spare-liquidity CSV of 144 blocks is not on the member's path.

**The formulas:**

- `last_safe_confirm = H_leaf − (B − 1)` is correct: block c has B confirmations at tip c + B − 1 = H_leaf.
- `leave_by` and `step_due` are consistent: `step_due(1) = leave_by + A` and `step_due(n) = last_safe − M`.
- The incoming-payment rule is right in shape. The `+1` is the second-stage claim; it covers the 1-block CSV on HTLC outputs inside A.
- The penalty rule `c + W − B` is right under BIP 68: the host's sweep is valid in block c + W.
- The tip estimate is wrong (F1).

### Q2. The anchor-only child

**Standard and relayable today. Verified:**

- **Size.** The non-witness size is exactly 65 bytes: version 4, one input of 1 + 36 + 1 + 4, one output of 1 + 8 + 1 + 5, lock time 4. `MIN_STANDARD_TX_NONWITNESS_SIZE{65}` (`policy.h`) is checked as `GetSerializeSize(TX_NO_WITNESS(tx)) < MIN_STANDARD_TX_NONWITNESS_SIZE` → `tx-size-small` (`validation.cpp`), so 65 passes. That has been the rule since Core 25.
- **P2A spend.** `IsWitnessStandard` rejects a P2A spend only if it **has** a witness ("witness stuffing", `policy.cpp`). An empty witness is standard from 28.0 (hand-off F9).
- **Dust.** By `GetDustThreshold` the P2A dust limit is (8 + 1 + 4 + 32 + 4 + 1 + 107/4 + 4) × 3000/1000 = 80 × 3 = **240 sat**, with `DUST_RELAY_TX_FEE{3000}`. A 240-sat anchor is therefore exactly at the threshold and **not** dust, because the test is `nValue < threshold`. This closes the hand-off's F10 by computation from source.
- **OP_RETURN output.** The zero-value output is unspendable, so its dust threshold is 0. It is standard null data.
- **Fee floor.** `DEFAULT_MIN_RELAY_TX_FEE{100}` and `DEFAULT_INCREMENTAL_RELAY_FEE{100}`. The child alone pays 3.69 sat/vB, and the parents pay 101 to 137 sat/kvB, so on 29.1 and later each step relays alone. On older nodes, or when the mempool floor rises, the parent needs 1p1c package relay, which is the chain-port requirement 6.8 states.
- **Replacement conditions.** 6.3's (a) to (c) are a sound conjunction across versions. On master `PaysForRBF` and `ImprovesFeerateDiagram` apply. I could not find `PaysMoreThanConflicts` on master, so rule (b) belongs to the versions before cluster mempool. Requiring all three is right for a mixed network.
- **Recomputed minimum first wallet child** on the 167 vB leaf transaction: rule (a) needs 256 sat, rule (b) 565, rule (c) 338. So 565, as the draft says.

**Pinning: yes, see F3.**

- On a version-2 parent anyone can pre-empt the anchor with a large child, and the cluster limit of 101 kvB blocks any other descendant.
- On a TRUC parent, a child of at most 1,000 vB paying 234 sat or more defeats the fixed-fee child. Sibling eviction (`validation.cpp`) does not let the member evict it without paying more.
- RBF never lets a third party **lower** the package rate below the member's child, so the anchor-only child cannot be "replaced to stall". It can only be pre-empted.

### Q3. The locked wallet

- **Publishing the tree path from any old bundle copy.** The tree transactions are fixed at creation, one per funding output in 1.0.0, never revoked, and fully signed. Publishing them takes no value. **But** it is not free in every sense:
  - it can spend set-aside fee coins up to their total;
  - it costs the victim and its siblings the cooperative and rotation close, and therefore possibly sweep fees (F7);
  - it reveals privacy.

  So "never costs money" should read "never moves value away; can cost fee coins and the cheaper ways out".
- **Penalties from any copy** are harmless, true, but see F4 for their limits.
- **`unlock_by`** is correct as the latest useful height in the good case. The headline is incomplete (F6).
- **Never unlocking:** a dishonest host takes the balance at H_leaf + 1. An honest H17 host forces the member out instead, and the balance stays claimable for ever. Payments whose secrets were released are lost.

### Q4. Siblings

Correct for funds, channel and H_leaf. Not quite correct for costs and options. The software duties are in F7.

### Q5. Crashes, reorganisations, restores, a host that stops halfway

- **Save points.** Every save in 3.4 precedes its action. Resuming from the start step works. Rebroadcasting the same bytes is harmless. `coin_reserved` prevents double use.
- **The hole is F2**: failing back after the freeze.
- **Concurrency.** `exit_started` must be written in the batch that freezes the channel and reads the latest commitment number. If the core is single-threaded that already holds, but say so.
- **Reorganisations.** They are handled by recomputing `n_missing`. A reorganisation deeper than B at H_leaf is accepted as a risk.
- **Restore.** No automatic commitment is published, which is good. It depends on the rollback guard of `storage-encryption.md` 6.3 catching a whole-disk or VM-snapshot restore. If that guard fails, X-I5 fails and a stale commitment is published. State the dependency in X-I5.
- **A host that stops halfway (H-a).** It is covered by the `deadline` trigger with the smaller n. `host_forcing` is only an earlier trigger, and it fires only once the leaf transaction is confirmed. That is fine, because the deadline still applies.

### Q6. The host's rules H14 to H17

Sound in substance. Fix H15 row 2 and add H18 (F8).

### Q7. The commitment shape, and the T1 finding

**The recommendation is right against the zero-fee #1228 shape with a zero-value anchor**: a member without coins could never confirm. Two additions:

- **Make the member's commitment TRUC (version 3).** It is broadcast only after the leaf transaction is confirmed (5.3), so it has no unconfirmed non-TRUC ancestor, and TRUC is allowed even under a version-2 tree. That caps a pinning child at 1,000 vB and enables sibling eviction (F3).
- **Prefer a member-keyed anchor**, with its child pre-signed at update time, which CH-2 already permits, over a P2A. The host then cannot pre-empt it.
- Either way the channel is no longer "Lightning's standard taproot channel format" (`DESIGN.md` 8). CH-3 already departs from it, so say so once.

**The T1 timing finding is correct** (recomputed below). The fix proposed in open point 1 is too small (F9).

---

## 3. Recomputed numbers

I recomputed these by hand and with my own small script, not by reusing `x_*`. I also ran section X (`python -I tools/spec-vectors.py`); its output matches every value below.

Signet constants: B = 3, A = 6, M = 14, M_host = 8. Heights relative to E.

| d | H_leaf | last_safe | `leave_by` | step deadlines | commitment due | `unlock_by` | `host_force_by` | before lifetime end (E − 36) |
|---|---|---|---|---|---|---|---|---|
| 1 | −10 | −12 | **−50** | −44, −38, −32, −26 | −26 | −32 | −44 | 14 |
| 2 | −20 | −22 | **−66** | −60, −54, −48, −42, −36 | −36 | **−42** | −60 | 30 |
| 3 | −30 | −32 | **−82** | −76, −70, −64, −58, −52, −46 | −46 | −52 | −76 | 46 |

- d = 2 with 5, 3 or 1 steps missing: `leave_by` is E − 66, E − 54, E − 42 (X3 prints 290114, 290126, 290138 at E = 290180). ✓
- The minimum incoming delta at d = 2 is (5 + 1)·6 + 2 + 14 = 52. ✓ Payment at h = 290100 goes on chain by 290048. ✓ Penalty example: confirm by 292133, send by 292113. ✓
- Sizes:
  - Tree transaction: ⌈(4·(64 + 43k) + 68)/4⌉ = 81 + 43k, giving 124, 167 and 253 vB. ✓
  - Wallet child: ⌈(4·135 + 69)/4⌉ = 153 vB. ✓
  - Anchor-only child: 65 bytes. ✓
- Package rates with the anchor-only child, in sat/vB: 257/189 = 1.36, 257/232 = 1.11, 266/232 = 1.15, 266/318 = 0.84. ✓
- Ladders: rung 1 pays 565, 623, 614 and 786 sat. ✓
- The mainnet example, lead = 40 + 5 + 84 + 152 = 281. ✓
- Not computed by the vectors:
  - the pin threshold on a TRUC parent, F ≥ 234 sat;
  - F9's `move_by` ≈ E − 194 at d = 3.

**The numbers check out.**

## 4. Contradictions with the other specifications

1. **`safety-rule.md` C5, first bullet.** "Deeper transactions expire earlier, by 5 blocks per tree transaction". **Section 12 value 2:** "less 5 blocks per tree transaction of depth". Exit 4.1: E − 5·(2j − 1) for a fixed kickoff and E − 10·d for the leaf. The safety rule's wording fits kickoff-and-state pairs only. With fixed levels each level is one transaction but still steps by 10. Value 2's "E less 5 blocks" for the root's outputs is right, because the depth-1 timeout is E − 5.
2. **`safety-rule.md` section 7 "Exit time", C8 and section 12 value 6** (allowance 6, margin 6). Exit 4.4 adds the H_leaf offset, B − 1 and a margin of 14, and changes the signing-time check. Exit 10.5 asks for these updates, which are not made yet.
3. **`safety-rule.md` H6** assumes a payout; exit adds H14 to H17. `safety-rule.md` 11 lacks the new exclusions: locked past `unlock_by`, no bundle, fees above the anchors, and the pin of F3.
4. **`docs/MULTI-FACTORY.md` 4.1.** `start_leaving_by` is "E less the member's exit time less margin" and "an exit time near 40 blocks". Exit 4.4 bases it on H_leaf = E − 10·d, with a lead of 50 to 82 blocks.
5. **`notes/factory-paths.md`:**
   - U-a: "end height less 5 per tree transaction of depth" and "bury D + 2 transactions". Exit has n = d + 3.
   - "D = 2 at 3 to 8 members". The split rule gives d = 1 leaves at 3 and at 5 to 7 members (F11).
   - H-a in 1.0.0: "simply wait and sweep after the leaf's timeout". Exit's H17 forbids exactly that.
6. **`spec/local-api.md` (the branch has draft 3; exit cites draft 2):**
   - (a) Draft 3 already has `watching.state = locked_watcher`. Exit 5.6 and 10.2 propose `watcher_locked` and say it "replaces `nobody_locked`", but `nobody_locked` is still needed for watcher off, key unavailable and bundle refused.
   - (b) Draft 3 4.7 says the locked watcher "Leaves alone by its dates: Yes", and its lock warning says it "will leave them alone by their dates". Exit 5.6 says it cannot finish an exit. Exit 10.2 describes 4.7 as "locked: leaves nothing alone", which is the draft-2 text and stale.
   - (c) `branch_partly_on_chain` is `at_risk` with "timed steps ... start counting" (exit: `important`, no timed steps).
   - (d) The provenance code is `end_less_exit_less_margin` (exit: `leaf_timeout_less_burial_exit_margin`).
   - (e) The lock is held only for signing (`held_for_signing`). Exit adds a hold for released payment secrets, which needs a new `lock.state` value.
   - (f) `next_action` is "the one date stored in the clear" (contradicts item 7c).
7. **`spec/storage-encryption.md` (the branch has draft 2):**
   - (a) 8.7.5: early publication makes siblings "pay exit fees and lose their off-chain places (`spec/exit.md` 7.1)". Exit 7.1 says the opposite.
   - (b) 8.7.6 moves B6 penalties into a separate append-only `watch.gzp` and says `watch.gzw` holds B1 to B5 and B7 to B9. Exit 5.6's bundle TLV still carries B6 as type 20 inside `watch.gzw`.
   - (c) 8.7.6 refuses clear copies of `next_action_height` and `unlock_by` (review F10). Exit 5.6 ("the bundle header's clear `next_action_height`") and 10.4 item 3 ask for them, and `local-api.md` d3 relies on a clear date.
   - (d) 8.7.1 uses `watcher_locked` (agreeing with exit, not with local-api).
8. **`docs/DESIGN.md`:**
   - 6: "A restored backup never publishes its own channel state" (exit 5.7 item 3 offers it as a choice).
   - 8: "standard taproot channel format" (CH-2's P2A and CH-3's tweaked funding output depart from it).
9. **`core/gazpacho/include/gazpacho/event.h`** watches by script (`GZ_CHAIN_SCRIPT_SPENT`). Exit's outpoint watching needs the new "outpoint spent" event (F5). Exit 3.2 says this only by reference.
10. **The tree-fees hand-off** (corrected in this commit) still asks for **TRUC tree transactions** (5 item 3). Exit computes and builds for version 2 today. The two are consistent in arithmetic: one level per block in both. But the anchor-only child's version must follow whatever SuperScalar ships, and section X should carry a TRUC tree vector once that exists.
11. **Inside `exit.md`:**
    - 5.3 step 1 against 3.4 and X-I3 (F2).
    - The 4.5 text against the 4.5 formula and X5 (F1).
    - The 4.2 depth text against X2 (F11).
    - W3 "at once" against 5.3's "confirmed parent" (F13).
    - The 5.6 "Can/Cannot" table and "does not end the channel" against W3 (F6).

## 5. What I could not check

- **A built tree.** I did not build a tree or read the scripts from one. My check of H_leaf is from the source only. The draft's 11.5 asks for the build-server test, which I did not run. No signet or regtest run of anything.
- **Bitcoin Core history.** I read Core master only, not the 28.x to 31.x tags. Not verified at those tags:
  - when `PaysMoreThanConflicts` (rule 6) was removed;
  - that the CPFP carve-out is gone with cluster mempool (I believe so, and my F3 reasoning for version-2 parents assumes it on 31 and later);
  - the exact 1p1c acceptance of non-TRUC parents below the floor before 31.0 (hand-off F12 and F14 are taken as given).
- **The `submitpackage` proposal.** Whether `MIN_STANDARD_TX_NONWITNESS_SIZE` and the P2A rules apply identically under `submitpackage` as in the single-transaction path (I believe yes).
- **The taproot channel format.** I did not check the simple-taproot-channel draft for the exact HTLC second-stage sighash flags and CSVs. F4 and F10 assume the anchor-style `SIGHASH_SINGLE|ANYONECANPAY`, zero-fee, 1-block-CSV shape. If `channel.md` chooses `SIGHASH_ALL` with fees, F4 changes and F10 gets worse.
- **Which signet servers accept packages** (S12), and what share of mainnet nodes run 29.1 or later.
- **Nonce storage.** Whether MuSig2 secret-nonce persistence for CH-1 (completing the member's signature weeks later, after restarts) can be done without reuse across a restore. That is `channel.md`'s, flagged only.
- **`journal.md` draft 3 numbering, and `signing-round.md` 12.1's exact event fields**, beyond what exit cites.
