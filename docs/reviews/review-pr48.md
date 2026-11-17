# Review of draft PR #48: exit draft 3 and the host-paid tree fee rate

Reviewed 2026-11-17. Branch `exit-spec-design2` at `a916629` (commits `4daa269` and `a916629`): `spec/exit.md` draft 3, and the 2026-11-16 changes to `spec/terms.md`, `spec/safety-rule.md` and `spec/signing-round.md`. Read against `notes/end-date-design.md` and `notes/exit-paths-audit.md`. The settled background (design 2, payouts from Slice 3, TRUC + P2A at the agreed rate, the host funding all tree fees) is taken as given. Numbers were recomputed by a script on the build server, kept in the review's folder there with its output.

## Verdict

**Accept after fixes.** The design-2 core is right and the paths are far more complete than draft 2's: the design-2 dates recompute exactly, the payout size of 124 vB holds under the stated assumptions, and most of the 5.9 numbers are correct. But two claims central to the draft do not hold as written (H1, H2), one reader rule is missing at creation (H3), and the P(r) reserve is defined in a way that is circular in `terms.md` and cannot be met together with `terms.md` 4.2's funding rule (M1, M2). One INTERIM table has two wrong dates (M3). None of these needs the design to change; all need text, and H2 needs a different placement rule.

## Findings

### High

**H1. "A member that does nothing is safe" is false against a host that publishes a revoked commitment, including after E.** H19 gives the host a commitment of its own, co-signed by the member, at every update. Today the host holds none, so this is a new exposure. Every revoked host commitment is a valid spend of the channel output, before and after E, and it competes with the channel payout from E + 1.
- Scenario: T1, d = 2. The member's wallet is switched off (not merely locked) from E − 500 to E + 2,000. Its channel started at commitment 0, where the member's balance was 0, and it later received 60,000 sat. At E + 1 the host broadcasts its revoked commitment 0 with a large anchor child, and it confirms before anyone publishes the channel payout. Nobody answers it within W, so the host sweeps its output after W. The member comes back and finds 0, not the 100,000 capacity or the 60,000 balance.
- These passages contradict O-1, which correctly says "A revoked commitment after E voids the channel payout, so it must still be answered after E":
  - section 0: "A member that does nothing is safe" and "What still needs a running wallet **before E**";
  - 1.3: "loses nothing whether the host is honest, gone or hostile";
  - 4.4: "never lost to the end date, whenever it comes back";
  - 5.8, last assumption row: "any time after E is enough for the balance";
  - X-4: "no output on its payout path has any other spend after E except transactions that pay it at least its balance";
  - 10.2's member wording: "at least <capacity> sats … with no help from the host";
  - the default "wait for E" under `host_silent` (6.1, U-3).
- Fix:
  - State the real property: the payouts make the end date safe, but a host commitment, revoked or not, can appear at any time. So something holding the penalty file (the wallet, the locked watcher, or a tower) MUST run at least once in every W blocks until the channel output is spent by a payout or by a current commitment.
  - Bound the time off by W, and make W a term or a CH-4 minimum that is long (W ≥ B + A + M + 1 = 24 on signet is the arithmetic floor; mainnet needs weeks).
  - Add "switched off longer than W" to 5.8's assumed table and to `safety-rule.md` 11.
  - Correct the member wording in 10.2 and the locked headline "paid … even while locked", which is true only while the watcher runs.
  - Answer checklist item 4: the revoked host commitment is the missing competing spend.

**H2. Under the placement rule and H6, the host can never get its spare liquidity back from a member it forces out; the member receives it at E.** The spare-liquidity output can be taken by the host only 144 blocks after the leaf transaction confirms. Its payout pays the leaf's member from E + 1. The draft defines `host_spare_by` (E − 172, −178, −184 at d = 1, 2, 3), but:
- the placement rule only needs E − E_wd ≥ 34, 40, 46;
- H6 forbids forcing before E_wd.

So at the minimum placement every forced member's leaf transaction confirms after E − 144, and the spare-liquidity payout wins.
- Scenario: T1, 16 members. One member stays silent through the wind-down. No friendly or rotation close exists without it (open point 12), so the other 15 pay across (E-2). They still hold payouts of their capacity in the old factory (open point 11), and the host must force all 16 out (H-1) after E_wd. Each of the 16 then also collects its leaf's spare liquidity at E: 100,000 sat less P(r) each, about 1.6 million sat. The one silent seat triggers that loss, and a member gains its own leaf's spare simply by going silent.
- This is the host's money rather than a member's. But it makes honest operation lose money, it rewards silence (it doubles the free-seat cost of open point 7), and it contradicts H-1 step 5 and H20's "SHOULD force that member out rather than lose it".
- Fix, either of:
  - place E so that E − E_wd ≥ (B − 1) + CSV_SPARE + (D + 2)·A + M_host (184 at D = 3 on signet), and let H6 start forcing at `host_spare_by` rather than E_wd;
  - or state as a decided trade-off that a forced member keeps the spare liquidity, and size the free-seat answer (open point 7) for it.

  Add a vector for it to X10.

**H3. No reader rule stops a member from consenting to funding before it holds its payouts.** 3.3 makes the host withhold the aggregated payout signatures until every host commitment 0 is co-signed. Nothing makes the member withhold its funding acknowledgement (`round_ack`, H1) until it holds and has verified every aggregated payout signature on its payout path.
- Scenario: the host collects every partial payout signature and the co-signed commitments, never sends the aggregates, and funds the tree. Members then hold a design-2 tree with no payouts. With #508's timeouts gone there is no host-alone path, so nothing is lost outright. But "a member that does nothing is paid at E" no longer holds: every member must leave alone and pay its own path fees. The locked watcher's bundle has nothing to publish.
- Fix: in 3.3, the reader MUST NOT send its funding acknowledgement until it holds every payout of its payout path fully signed and verified (and journaled, and in the bundle). It treats a missing payout message as C-4 (abort, no ack). Add a C-path test for it.

### Medium

**M1. P(r) is circular in `terms.md` 4.4.** It says "The member's capacity … is the channel output less P(r)", while C8 and 5.9 check "channel output ≥ capacity + P(r)". With that definition the check always passes. The promise the member can actually check is the term `channel_sat` (record 30 of the terms), and C8's channel row still checks only "at least `channel_sat`".
- Scenario: a host builds a T1 tree with every channel output exactly 100,000. A wallet that reads capacity as output − P(r) accepts it. The member's payout-backed capacity is then 99,747 at 0.1 sat/vB, or 98,520 at 10 sat/vB, below what its terms promised.
- Fix: state the check in terms of the promise: under design 2, channel output ≥ max(`channel_sat`, the member's own minimum) + P(r). Define capacity as output − P(r) only after that check.

**M2. The design-2 reserve cannot be met together with `terms.md` 4.2's funding rule.** 4.2 says the proposal's `funding_amount` MUST equal R(root), with R(leaf) = 2·`channel_sat` + 2·fee + 2·240. The confirmed builds give every leaf exactly 100,000 at 4 members.
- Once M1 is fixed, every T1 design-2 tree at 4 members fails C8's P(r) row. Raising the channels to 100,253 makes the funding differ from R(root), which 4.2 refuses.
- 5.9 also says the bottom-up builder of #46 receives "the member's capacity". It does not say whether the host passes `channel_sat` or `channel_sat` + P(r). That choice also changes what the tree payouts and the distribution transaction pay, since they pay "its capacity as carried in the proposal".
- Fix: give R(leaf) a design-2 form with + P(r) on the channel. Say which value the builder receives (`channel_sat` + P(r)). Say what the tree payouts' "capacity" means. Add an X-vector.

**M3. CH-14's balance cap has no enforcing side, and the party that would enforce it is the one with the opposite incentive.** The channel's Lightning funding is the whole output, capacity + P(r). With BOLT-style reserves (1% of 100,000 = 1,000 sat) and P(r) = 1,480 at 10 sat/vB, the member's balance can reach about 480 sat above its capacity. A host that then lets E pass pays the member only its capacity, and topic 1242 post 2 names exactly this incentive.
- CH-14 says "the member's balance never exceeds it" but names no writer or reader.
- Fix: the member's wallet MUST refuse an incoming HTLC, or a fee change, that would make its balance plus its pending incoming HTLCs exceed the output less P(r). The host MUST keep its own side at or above P(r) plus its commitment anchors (it then never offers such an HTLC).

**M4. The INTERIM `host_force_by` column of 4.5 is wrong at d = 1 and d = 3.** The formula last_safe_confirm − n_host·A − M_host, with the whole path missing, gives **E − 44, E − 60, E − 76**. The table says E − 54, E − 60, E − 66; the d = 1 and d = 3 values look computed with H_leaf fixed at E − 20.
- The wrong d = 1 value puts the host's forcing date before the member's own `leave_by` (E − 50), against draft 2's stated ordering ("6 blocks after `leave_by`").
- The column is marked [X3], so the vector, if it was run, disagrees with the text.
- Fix the two cells.

**M5. A higher host-chosen rate makes a free pin on the member's own exit.** With prepaid fees, anyone holding the tree (the host or any member) can broadcast the next pre-signed level as the one TRUC child of an unconfirmed step. 5.9 says "nothing here relies on it", but it occupies the slot the member's anchor-only child needs.
- To take the slot back, the 240-sat anchor-only child must pay more than the occupant's fee plus 7 sat (the incremental relay fee on 65 bytes). For a 167-vB occupant that fails once the rate is above about 1.4 sat/vB: 334 sat at 2 sat/vB, 1,670 at 10.
- Scenario: the host picks 2 sat/vB, the market is at 5 sat/vB, and a coinless member needs its path on chain for a payment claim (P-1). The host pushes level i + 1 behind level i at no cost to itself. The member can neither attach its child nor evict the occupant, so the claim's date passes. Under INTERIM rules (Slice 2) the same pin could run past H_leaf.
- 5.5's "the attacker must pay at least 234 sat" bound no longer holds: here the pin costs the attacker nothing.
- Fix: say so in 5.5 and 5.9. Weigh it in open point 19, since the recommended 1 sat/vB is still below the threshold (167 + 7 < 240) but 2 sat/vB is not. Add a regtest case.

**M6. After a restore, the payouts pay a key the restored wallet is not allowed to use.**
- The payouts pay the member's factory key (C2, open point 5).
- C-10, `safety-rule.md` C12 and the glossary say a restored wallet never derives an old key, except by the "recovery procedure", which is not specified (L1 of the cross-spec review).
- 6.7, X-5 and test S20 say "the wallet waits for E and the payouts pay it", but the restored wallet cannot spend those outputs, nor its output on a host's commitment.
- Fix: allow single-key spends of the member's own outputs (payout outputs, `to_remote`, swept outputs) with recovery-only keys, since they carry no MuSig nonce risk. Or name the recovery procedure as a dependency of X-5 and S20.

**M7. Two MUST rules on the tree fee contradict each other.**
- The C8 fee row (edited in `a916629`) and `terms.md` 4.2 require exactly ⌈rate × the largest signed size / 1000⌉ on every transaction: the pin `e6573950`'s one `fee_per_tx`.
- `exit.md` 5.9's reader requires "every tree transaction pays exactly that rate for its own signed size (unchanged)": #46's per-transaction rule.

At 0.1 sat/vB in T1 at 4 members the first gives 17 sat on the 124-vB leaf kickoff, the second 13. Say which rule applies under which import.

**M8. `safety-rule.md` still says 1.0.0 has no end-date payout, in text this PR edits around.** H17 reads "With no end-date payout (1.0.0)", and the header still pairs it with `exit.md` draft 2. At the same time the edited C8 row now carries the design-2 P(r) rule. `exit.md` 10.4 defers the alignment, but a C8 row and a host rule now state opposite things about 1.0.0. At least mark H17 and section 12 values 1 and 2 INTERIM in this PR, as 10.4 asks.

### Low

- **L1. The last column of 5.9's prepaid-fee table rounds on the path's total, not per transaction.** 4.2 and every other column round per transaction. Per transaction at 0.1 sat/vB it is **64, 64, 73, 90** for 3, 4, 8 and 16 members (the table says 63, 63, 72, 88). The other rates are exact.
- **L2. 124 vB holds only under stated conditions.** It needs a 64-byte signature (`SIGHASH_DEFAULT`), a key-path input, a P2TR member output and a single P2A. With a 65-byte signature the payout is 125 vB, and P(r) falls short by 1, 2, 5 and 10 sat at 1, 2, 5 and 10 sat/vB. The reader's "at least the capacity" check then refuses every proposal (it fails safe, but blocks Slice 3). If open point 5 lets a member name a payout address, that output must be no larger than 43 bytes. State these, or compute P(r) from the payout's actual built size.
- **L3. The spare-liquidity payout fails the reader check as written.** 5.9's reader says "every payout pays the member at least its capacity". The spare-liquidity payout pays spare − P(r), which is at least 330 sat but not the capacity. It passes in T1 only because spare equals channel. Exclude it by name.
- **L4. Wording and references.**
  - "Buried by E − (B − 1)" (H6, H-1 step 4) versus "confirmed at E − (B − 1), buried by tip E" (4.4): use one.
  - 3.3 cites "section 4.3's placement rule"; it is in 4.4.
  - 10.4 still says the channel payout "pays the output less its own fee and anchor (open point 4)", which is stale after 5.9 closed that point.
  - `docs/handoff/2026-11-12-tree-fees.md` still states term 32 as 1 (or 0) to 1,000,000.
- **L5. Two requirements are not testable as written.**
  - "Every server a party broadcasts to MUST run Bitcoin Core 28.0 or later": a wallet cannot verify an Electrum server's version. Restate as a reader rule on refusals, for example "treat a version-3 or P2A non-standard refusal as that server unusable for exits, and keep at least one known TRUC endpoint".
  - CH-14 has no writer or reader (M3).
  - `M_locked` is INTERIM with no named replacement.
  - The placement check "at the member's own constants" uses M_host, a host constant (open point 2).
- **L6. The term 32 floor of 100 breaks nothing found.**
  - No vector or spec uses a rate below 100. Record 30 on the current pin carries `fee_per_tx_sat`, which stays at least 13 sat.
  - Pre-launch terms with lower rates are simply refused.
  - It rules out a later zero-fee (ephemeral-anchor) tree design without a new term version; worth a sentence.
  - The rationale "Core's relay floor from 29.1" is right, but servers on 28.x and 29.0 still need a package at 0.1 sat/vB, as 5.9 says.

## Paths (section 7), item 1

All 35 are present (C-1 to C-10, E-1 to E-7, U-1 to U-3, H-1 to H-3, O-1 to O-3, P-1, X-1 to X-8).

Beyond H1 to H3 and M5, M6:
- **E-2 step 4 and E-4**: a member that paid across keeps a capacity payout in the old factory. Combined with H2 this is the main cost path for the host. It needs open point 11 before rotation is built, not "with M4".
- **X-4** must drop its "nothing is lost" sentence (H1).
- **6.4 step 2** tells a member to replace the host's *current* commitment in the mempool after E. That is allowed, and the member gains capacity minus balance less fees. But the fee budget is "a share of the expected recovered amount", and for this replacement that should be the gain over the balance, not the whole amount.
- **H-1** never says the host's commitment must confirm before E. It says "buried by E − (B − 1)" and is otherwise fine.
- **O-1** is correct and should be cited from sections 0, 4.4 and 5.8.
- No path covers **the host withholding the payout aggregates** (H3) or **a pin by the next pre-signed level** (M5).

## Recomputed numbers (signet constants: B 3, A 6, M 14, M_host 8)

| Quantity | d = 1 | d = 2 | d = 3 | Draft |
|---|---|---|---|---|
| `host_force_by`, design 2, whole path | E − 34 | E − 40 | E − 46 | Same |
| `host_stop_credit` | E − 40 | E − 46 | E − 52 | (not stated) |
| `host_spare_by` | E − 172 | E − 178 | E − 184 | (not stated; see H2) |
| Placement E − E_wd, D = d | 34 | 40 | 46 | 46 at D = 3, same |
| Placement with spare recovery | 172 | 178 | 184 | (absent; H2) |
| INTERIM H_leaf | E − 10 | E − 20 | E − 30 | Same |
| INTERIM `leave_by` | E − 50 | E − 66 | E − 82 | Same |
| INTERIM commitment due | E − 26 | E − 36 | E − 46 | Same |
| INTERIM `host_force_by`, whole path | **E − 44** | E − 60 | **E − 76** | E − 54, E − 60, E − 66 (M4) |
| INTERIM `unlock_commit` | E − 32 | E − 42 | E − 52 | E − 42 at d = 2, same |
| Payment allowance / `min_final_cltv` | 46 | 52 | 58 | 52 at d = 2, same |
| H18 delta | 40 | 46 | 52 | Same |

Fee and size figures:
- **Payout size.** The one-member payout is 496 WU = 124 vB with a 64-byte signature, and 125 vB with 65 bytes.
- **Distribution transaction.** 769 vB at 16 members, 9,971 vB at 230 and 10,014 vB at 231, so 230 is the TRUC limit.
- **P(r)** = 253, 364, 488, 860 and 1,480 sat at 0.1, 1, 2, 5 and 10 sat/vB (same as the draft). The spare-liquidity floor holds in T1 up to 801.8 sat/vB ("about 800": same).
- **Prepaid tree fees in total** (3, 4, 8 and 16 members), at 0.1 / 1 / 2 / 5 / 10 sat/vB, all as the draft:
  - 3 members: 124 / 1,207 / 2,414 / 6,035 / 12,070;
  - 4 members: 171 / 1,665 / 3,330 / 8,325 / 16,650;
  - 8 members: 334 / 3,249 / 6,498 / 16,245 / 32,490;
  - 16 members: 710 / 6,913 / 13,826 / 34,565 / 69,130.
- **Prepaid on the deepest path**, rounded per transaction, at 0.1 sat/vB: 64, 64, 73, 90 (L1); the other rates are as the draft.
- **Anchor-only child package rates.** 1.339 sat/vB over a one-member payout. Over a 167-vB step: 1.11, 1.75, 2.47, 4.63 and 8.23 sat/vB (same as the draft's rounding).
- **Pinning threshold.** 234 sat (same as the draft).
- **Next-level pin threshold** (M5): the anchor-only child can no longer evict a 167-vB pre-signed occupant above about 1.39 sat/vB.
- **Penalty.** `penalty_send_by` needs W > 23 blocks.
- **The 16-member distribution at 10 sat/vB** pays a 7,690-sat fee (same as the draft).

## Rate choice: can the host exploit it? (item 3)

There is no direct exploit:
- every fee is in the signed bytes and comes from the funding;
- a higher rate only raises what members receive at E (the distribution transaction pays "capacity plus an equal share of the rest");
- a rate whose P(r) breaks the spare floor is refused.

The one member-facing effect is M5, the free pin at rates above about 1.4 sat/vB. A second-order effect: since the member's ceiling is now only a sanity bound, the chain-cost joining fee (term 70) becomes the only place a host could pass a high rate back to members. Its ceiling must be set before term 70 is enabled.

## Open points missing from section 12

1. The watch interval, W and a tower for host commitments under H19, after E included (H1).
2. Placement against `host_spare_by`, or accepting the spare-liquidity transfer (H2).
3. The member withholding its funding acknowledgement until it holds the payouts (H3).
4. Which "capacity" the builder and the tree payouts use, and R(leaf) under design 2 (M1, M2).
5. Who enforces CH-14's cap (M3).
6. The free pin by the next pre-signed level at host-chosen rates (M5).
7. Spending payout outputs with recovery-only keys after a restore (M6).
8. Which fee rule (largest size or own size) is in force on which import (M7).
9. The payout's sighash and output-size assumptions behind P(r) (L2), to ask #508 together with open point 4's remainder.
10. Detecting servers that refuse version 3 or P2A (L5).
11. Mass forcing at E_wd in a 230-member factory: block space and H7's coin count when every member is forced in the same window. This is the host's risk, but it is the scenario H2 creates.
