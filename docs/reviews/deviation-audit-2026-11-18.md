# Deviation audit: Gazpacho against SuperScalar's design and code

Independent audit, 2026-11-18. Read-only. Nothing was posted, and nothing on the build server was touched.

**Sources read**
- Delving Bitcoin topics [1143](https://delvingbitcoin.org/t/1143) (posts 1, 13, 16, 26, 34), [1242](https://delvingbitcoin.org/t/1242) (post 1 and its sections "Inversion of Timeout Default" and "Old State Poisoning"; post 2) and [2705](https://delvingbitcoin.org/t/2705) (the implementation report).
- The import at `origin/main:core/superscalar/` (pin `50f7fa13`, `IMPORT.md`).
- Upstream pull requests through `gh`: [#508](https://github.com/8144225309/SuperScalar/pull/508), and the list #493 to #512.
- `spec/exit.md` draft 3, `spec/local-api.md` draft 5, `docs/ux/decisions.md`, `docs/PLAN.md`, `docs/DESIGN.md`, `docs/DECISIONS-WITHOUT-OWNER.md` (all on `origin/main`).
- The diffs and bodies of PRs #52, #53, #54 and #56.
- `notes/penalty-check.md`, `notes/k1-join-binding-check.md`, `notes/review-pr48.md`, `notes/review-pr52-a.md` and `notes/lobby-accountability-liveness.md`.

**What I did not check.** I ran no test and no regtest. I checked no number by computation, except where I say so. Each claim below rests on the cited text or code.

**Quotes.** Upstream text is paraphrased with post numbers and links, to keep quoting short. Code comments from the MIT-licensed import are cited by file and line.

**Classes.** A = same as upstream. B = left to the implementation. C = deliberate deviation with a sound written reason. D = deviation without enough justification, or against upstream's intent. E = not in upstream.

## Summary table

| # | Item | Class | Crypto sound? | Trustless both ways? | Plan drift | Verdict |
|---|---|---|---|---|---|---|
| 1 | Design 2 payouts on every shared output; take #508 | A (design 1143/26, 1242/1). #508 is an **unmerged, unreviewed draft** | Yes. Standard N-of-N MuSig2 pre-signed lock-time txs | Yes for the member at E. The host carries the risk by design | None: owner Q1 deferred it past Slice 1, and draft 3 does that | **Keep** the design. **Pause** code that depends on #508's exact shapes until #508 merges |
| 2a | Host-paid tree fee rate | A (the import already pays every tree fee from the funding at `tree_fee_rate`) | n/a | Yes | None | **Keep** |
| 2b | P(r) reserve on channel outputs | E (#508 lets the channel payout pay its own fee out of the member's capacity) | Arithmetic only. Depends on a 125-vB payout size, still owed by #508 | Improves the member's side | None | **Keep. Needs vectors** (open point 15 says they are owed) |
| 2c | Rate bound ⌊175,000/V_occ⌋ | E (refines upstream's claim that TRUC stops anchor pinning) | Rests on Core's sibling-eviction and incremental-fee rules (BIP 431, RBF rule 4); [R] only | Yes. It protects a coinless member | Open point 26, pending the owner | **Keep as a reader check. Needs a regtest test** (a free-pin eviction at r just under and just over the bound) |
| 2d | Term 32 floor raised to 100 sat/kvB | B (upstream allows 0 with an ephemeral anchor) | n/a | Yes | Matches the owner's 0.1 sat/vB rule | **Keep** |
| 3 | E placed `host_spare_by` after the wind-down (178/184/190); forcing starts there | C (upstream's #508 rule is EXPIRED + exit time + 6) | n/a | Yes, it only moves host capital | Decided "pending the owner"; **not in the decisions log** | **Simplify.** The 144-block S_spare it pads for exists only for the poison window, and 1.0.0 has no poison (detail 3) |
| 4 | Payout script named by the member in `ready`, from BIP 86 | E (#508 pays the factory key; upstream has no per-member payout script) | Yes. The script is bound by C1's rebuild and the member's own check | Yes | Pulls owner decision 6's 1.1.0 "fresh address per factory" into 1.0.0, which is justified by R3 | **Keep**, but it **blocks on an upstream API**. Do not patch the import |
| 5 | H19 (member co-signs the host's commitment), H6, H20 | A (1242/1: standard Poon-Dryja makes the LSP publish its latest commitment; #508 builds exactly this) | Yes. Standard LN-penalty | Yes, given watching (item 6) | None | **Keep** |
| 6 | Watch interval W − B − A − M | A (standard LN: watch within `to_self_delay`); the parameters are B | Yes | Yes, if the duty is met | Owner decision 16h puts towers after 1.2.0. 1.0.0 has only the device and its locked watcher | **Keep. Needs a regtest breach test** at the interval's edge |
| 7 | K1 (c): drop `bind_by_factory`; binding plus factory key in the first `ready` | B (upstream sends the factory key unsigned in HELLO) | Yes. BIP 327 needs no proof of possession; the contribution-key half carries all blame evidence | Yes | Restores owner decision 16d's AT_JOIN promise | **Keep.** This removes surface |
| 8a | Penalties pay the factory's `payout_script` | B (the wronged party picks the destination) | Yes | Yes | None | **Keep** |
| 8b | Independent penalty copy before any balance | E | Yes (a shachain record is ~2.3 KB) | Closes the stale-restore hole (T3) | **Conflicts** with DESIGN.md 8/9 (backup held by the host) and decision 16h (towers after 1.2.0) | **Needs an owner decision before code.** Sound, but a big product requirement |
| 8c | "Assume stale" restore with a uniform close request | E (BOLT 2 data-loss handling, adapted) | n/a | Protects nothing without the host's cooperation; it only avoids telling | Matches DESIGN.md "a restored backup never publishes" | **Keep.** Low cost |
| 8d | C12 exception for revocation-basepoint secrets | E (relaxes our own rule) | Yes, **if** the penalty is a single-signer BIP 340 signature and the exception can reach no MuSig2 key | Yes | Changes safety-rule C12 and R3 | **Needs proof and test**: a test that the exception cannot reach factory keys or any MuSig2 session |
| 8e | Penalty bumps by replacement only, no keyless anchor | D against **owner decision 16h item 6** ("P2A anchors on everything a tower might publish") | Yes | Yes | **Contradicts an owner decision** | **Ask the owner.** The audit leans to the penalty-check's view, but it is the owner's call |
| 9a | Reason 3 excused once per (scope, key) | E | n/a (liveness only) | Yes | None | **Keep** |
| 9b | Blamed seats skipped for one check | E | n/a | A host can already exclude anyone | None | **Keep** |
| 9c | 64-item tree cap | E (engine limit) | n/a | n/a | **Contradicts** the 32-seat lobby (~21-member tree limit): a full lobby is **cancelled** | **Fix now**: cap the target in the terms, or raise the cap |
| 9d | AT_JOIN gate bound to the values digest | E | Yes (constant-time digest compare) | n/a | Implements decision 16d C | **Keep** |
| 9e | READY carries the digest | E | n/a. Fixes a TOCTOU | n/a | None | **Keep** |
| 10 | Signing modes AT_JOIN / AUTO / WHEN_UNLOCKED | E | Honest about what it protects (not the seed) | Fund safety rests on C1/C8, not on gates | **Drift**: decision 16d asked for A, B and C. B is not built; WHEN_UNLOCKED was not asked for; C opens per ready, not "once at join" | **Simplify**: ship AT_JOIN and AUTO; drop WHEN_UNLOCKED until the owner asks; record B's absence as a decision |
| 11 | Key tree (purpose 254315617', host branch 2', BIP 86 coins) | B | Yes. All hardened. K2's host/member key collision is fixed by 2' | Yes | Owner Q5 "own branch": consistent, still awaiting a yes | **Keep.** Channel keys are still unplaced (they are needed by 8d) |
| 12 | `setup.gzp` marker, restore path, sealed counter | E (upstream has no encrypted journal) | Yes. The marker only covers a set-up whose words never signed | n/a | None | **Keep** |
| 13 | v2 funding at 0.1 sat/vB, spend-back, `must_spend`, UNWATCH | B | Yes. `must_spend` makes successive plans conflict | Yes. Members have nothing in it | 0.1 sat/vB is the owner's rule | **Keep.** Mainnet propagation at 0.1 sat/vB is a relay risk, not a safety one |
| 14 | TRUC trees, P2A, 0.1 sat/vB, package relay | A (#476) | Yes, with a known pin surface (2c) | Yes | None | **Keep** |
| 15 | Several lobbies, seat caps 32/48, standbys, unsigned accountability in Slice 1 | E (upstream has no lobby) | n/a (no funds in a lobby) | Liveness only | **K4 drift**: standbys, invitations and removal were pulled into Slice 1 by the coordinator against decision 10's 1.0.0 scope. Unsigned accountability is fine for Slice 1 only | **Pause standby and understudy work** until the owner confirms K4; fix 9c first |

## Detailed findings

### 1. Design 2 end-date payouts on every shared output, and taking #508

**Upstream design.** In [1143 post 26](https://delvingbitcoin.org/t/1143/26) ZmnSCPxj inverts the timeout default:
- Every node output gets an nLockTime transaction that pays the clients. The initial channels go to their clients, and the liquidity stock is split evenly among them.
- Near the lock time the LSP must force exits itself, and pay for them, or lose the subtree.

[1242 post 1](https://delvingbitcoin.org/t/1242) repeats this for hosted Poon-Dryja channels: Poon-Dryja makes the LSP publish its latest commitment. In the implementation report ([2705](https://delvingbitcoin.org/t/2705)), everyone co-signs a distribution transaction at expiry.

**Upstream code.** Pin `50f7fa13` still has design 1's host-only timeout leaves below the root, plus a distribution transaction on the funding output. [#508](https://github.com/8144225309/SuperScalar/pull/508) does the following:
- removes the timeout leaves;
- adds a payout on every shared output;
- adds the co-signed host commitment;
- adds a forced exit before T0.

#508 is **open, marked draft, created 2026-11-13, with zero reviews.**

**Ours.** `exit.md` draft 3 sections 0 and 3 to 4. Design 2 is required from Slice 3 and before real funds; INTERIM rules hold until then.

**Class: A.** It is the designer's own inversion, applied as the designer describes, to every node output.

**Soundness.** The payouts are N-of-N MuSig2 signatures over lock-time transactions, made in the creation round. That is the same assumption as the tree itself (MuSig2 under OMDL in the ROM, BIP 327).
- The member is trustless at E: every shared output on its path pays it at least its capacity.
- The host is not exposed beyond what the design intends: it loses capacity only if it is late.
- After E the host may race its *current* commitment against the channel payout. Either outcome pays the member at least its real balance, so this is not a theft path.

**Complexity.** One extra signed transaction per shared output. This is what feeds the 64-item cap (9c).

**Plan drift.** None. Owner Q1 deferred end-date payouts out of Slice 1 and asked that they be "built carefully from SuperScalar's work", and this does that.

**Verdict: keep the design. Pause building on #508's wire and shapes until it merges.** The following all assume #508's exact behaviour:
- `exit.md` 3.3 (FACTORY_PAYOUTS ordering);
- H19, CH-11 to CH-13;
- P(r)'s 125-vB size;
- the payout-per-output table, including open point 3 on the leaf kickoff's output.

A draft can still change. Gazpacho also needs a change #508 does not have: the per-member payout script (item 4). Until upstream accepts it, Gazpacho cannot sign #508's payouts without editing the import, which `IMPORT.md` forbids.

### 2. Host-paid tree fee rate, P(r), the rate bound, and term 32's floor

**Upstream.** Since #476 each tree transaction pays `tree_fee_rate` for its own size, from the funding.
- The default is 100 sat/kvB, and 0 is allowed with a zero-value (ephemeral) anchor (`factory.h:832-838`).
- The TRUC comment at `factory.h:41-47` claims the keyless anchor "cannot be used to pin the exit".

**Ours.** `exit.md` 5.1, 5.5 and 5.9, and `terms.md` term 32.

**2a. Host-paid rate: A.** The import already funds every pre-signed fee from the host's funding. Choosing a higher rate changes no member output. Sound. **Keep.**

**2b. P(r): E.** #508's channel payout pays the member the output less its fee and anchor. A member would then lose about 253 sat at 0.1 sat/vB, which grows with the rate. Ours puts P(r) above the capacity, paid by the host, and caps the member's balance at the capacity (CH-14).
- This is sound and consistent with 1242 post 2, where the client imposes the reserve on the LSP.
- The extra complexity is small: one more term in R(leaf).
- The 125-vB size assumption is [R]. Draft 3 lists the R(root) vectors as owed.
- **Keep. Needs vectors** before any code computes R(root) with it.

**2c. Rate bound: E.** This is our own analysis. With prepaid fees, anyone holding the tree can broadcast the next pre-signed level as the one TRUC child of an unconfirmed step, at no cost. That pins the member's anchor-only child, which must evict it by sibling eviction within 240 sat. This **corrects upstream's comment**: the keyless anchor *can* be pinned, by the tree itself.
- The bound follows from BIP 431's single-child rule and RBF's incremental-fee rule. I did not recompute 1,047; the formula is right in shape.
- At the 0.1 sat/vB default the bound never binds. It only refuses abusive rates.
- Low complexity.
- **Keep as a reader refusal. Needs a regtest test** of the eviction just under and just over the bound, on 28.x and 29.1 relay settings. **Tell upstream** that its comment overstates.

**2d. Floor of 100 sat/kvB: B.** It rules out upstream's rate-0 ephemeral-anchor mode. Draft 3 (L6) records that cost. It matches the owner's 0.1 sat/vB preference. **Keep.**

### 3. End-date placement of 178/184/190 blocks; forcing starts at `host_spare_by`

**Upstream.** #508 requires `--cltv-timeout >= EXPIRED + exit time + 6`. The spare-liquidity (L-stock) output has a CSV of `L_STOCK_CSV_DEFAULT_BLOCKS` = 144. The import's own comment at `factory.h:50-58` gives the rationale: the delay is long enough for clients or towers to broadcast the **pre-signed L-stock poison** before the LSP can spend alone. Topic 1242 pins no value. The CSV can be set per factory (`factory_set_l_stock_csv`).

**Ours.** `exit.md` 4.4 and H6 (from review-pr48 H2). E is placed so that a forced member's leaf transaction confirms S_spare + allowances before E + 1. That lets the host sweep the spare liquidity before its payout to the member becomes valid. The cost is about 144 more blocks of host capital per factory.

**Class: C.** The reason is written and sound: without it, being forced out pays a member the leaf's spare liquidity, which rewards going silent. Note that upstream's own design accepts that the liquidity stock goes to the clients when the LSP is late; our rule only gives the host time not to be late.

**The simpler upstream-aligned fix nobody weighed.** In 1.0.0 there are no leaf advances (owner decision on advanceless trees; `exit.md` 1.1 and O-3), so there is **no poison and no stale L-stock**. That is the penalty-check's own finding. The 144-block CSV therefore protects nothing in 1.0.0. It only delays the host's sweep.
- Setting the proposal's `l_stock_csv` to a few blocks (≥ B, say 6) shrinks the placement to about 46 to 60 blocks at D = 1 to 3.
- It keeps H2's property, that a forced member gets no spare liquidity.
- It returns most of the host's capital time.
- It changes no imported code: the CSV is already a parameter that every formula takes from the proposal.
- Raise it back to 144 or more when 1.1.0 adds sales and poison.

**Plan drift.** The decision is marked "pending the owner's confirmation". It is **not** recorded in `docs/DECISIONS-WITHOUT-OWNER.md`, and neither are 3.4 or open point 26. That is a process gap.

**Verdict: simplify.** Make S_spare a small 1.0.0 term, and keep the placement formula as it is, since it already uses S_spare. **Needs a check** that no other path reads the L-stock CSV as a safety window in a one-state K = 1 pseudo-Spilman leaf. I found none in the comments of the import, but I did not trace `factory.c`.

### 4. Payout scripts named by the member in `ready` (`exit.md` 3.4)

**Upstream.** The distribution and payout builders pay `P2TR(f->pubkeys[i])`, the factory key (`factory.c:5398-5420` per the penalty-check). #508 does the same. `factory_build_distribution_tx` takes caller outputs, but the per-output payouts do not. Upstream accepts a caller's channel script (`factory_set_leaf_channel_spk`), but no per-member payout script.

**Ours.**
- A 34-byte P2TR from the member's BIP 86 receive chain, a fresh index per factory.
- The index is journaled before it is sent, and burned on failure.
- The host carries it unchanged in the proposal, and the member refuses if it is altered.
- A restore finds the outputs by a gap-limit scan of 20 plus the open-factory limit.

**Class: E.** Its reason is sound: under R3 a restored wallet must never derive an old-epoch factory key, so payouts to that key would be unspendable after a restore. Owner decision 6 asked for "fresh address each time" in 1.1.0, so this pulls a planned feature into 1.0.0 for a good reason.

**Soundness.** The script is inside the signed proposal, and every member rebuilds the payouts from it (C1). A host cannot substitute a script without the owner of that script refusing. Other members cannot judge someone else's script and need not. There is no new signing surface.

**Risks.**
- **(i) It depends on an upstream API.** Until upstream takes a script per member, 3.4 cannot be met without forking the import.
- **(ii) Burned indexes can outrun the gap limit.** `keys.md` 5 proposes a warning past 28. Make that a refusal, not a warning: a lost scan is lost money until someone rescans wider.
- **(iii) The host learns one receive address of the member's own wallet per factory.** That is a privacy cost, not a safety one.

**Verdict: keep.** Make the gap-run limit a refusal. Get upstream's agreement before Slice 3 code.

### 5. H19 (the member co-signs the host's commitment), H6, H20

**Upstream.** 1242 post 1 says the forced exit relies on standard Poon-Dryja, with the LSP publishing its latest commitment. #508 adds `HOST_COMMITMENT_SIG`, refuses updates without the co-signature, and revokes the previous commitment only after it holds the next. The leaves are "a normal BOLT-2/3 Poon-Dryja channel" per the report ([2705](https://delvingbitcoin.org/t/2705)).

**Ours.** `exit.md` 9: H19, plus CH-11 to CH-13. H6 is the forcing schedule. H20 is a host accounting rule.

**Class: A.** Each side holding its own commitment, signed by the other, is ordinary Lightning. The import lacked it only because the host recovered channels by timeout. H6 and H20 are host policy with no signing surface. They are self-enforcing under design 2, because a late host loses capacity.

**Soundness.** It is the LN-penalty assumption: the cheater's revealed per-commitment secret lets the wronged party derive the revocation key. CH-12 is BOLT's usual rule: no preimage until the old state is revoked.

**Cost.** H19 creates the member's permanent watch duty (item 6) and the stale-restore exposure (8b). The penalty-check shows that any design letting the host settle unilaterally at the current balance has that exposure. Removing H19 would bring back the larger loss, where a silent member is paid the host's capacity.

**Verdict: keep.**

### 6. Watch interval W − B − A − M

**Upstream.** The design assumes watchtowers, for the LSP (1242 post 2). The report's tower holds finished pre-signed responses. A watch duty within the revocation delay is standard Lightning.

**Ours.**
- `exit.md` 4.3 and 4.4: W is the member's revocation window for host commitments (CH-4 and CH-15). It is 144 on signet and at least 2,016 proposed for mainnet.
- Something holding the penalty file runs at least once every W − B − A − M blocks, both before and after E.

**Class: A** in concept. The numbers are B.

**Soundness.** The formula is consistent with the rest of draft 3: penalty_send_by = c + W − B − A − M. The duty correctly continues past E, because a revoked host commitment stays a valid spend of the channel output.

**Plan tension.** Owner decision 16h schedules towers after 1.2.0, so in 1.0.0 only the device and its locked watcher satisfy the duty. The UI must say plainly, as 4.4 requires, that "doing nothing" means at least one run every ~20 hours on signet, or ~2 weeks on mainnet. A wallet should also publish the channel payout at E + 1 when the channel output is still unspent, which ends the duty. `exit.md` already says this.

**Verdict: keep. Needs a regtest breach test** at the interval's edge, once `channel.md` exists.

### 7. K1 option (c): drop `bind_by_factory`; binding plus factory key in the first `ready`

**Upstream.** HELLO sends the factory pubkey with no signature and no proof of possession (`client.c:3369-3381`). The posts say nothing on binding.

**Ours.** `notes/k1-join-binding-check.md`. The contribution-key signature over `TH("gazpacho/bind", scope ‖ F ‖ C)` stays and moves to `ready`. Duplicate keys are refused for the life of the lobby.

**Class: B.** It is still stricter than upstream.

**Soundness.** MuSig2 in the plain public-key model needs no proof of possession (BIP 327, [eprint 2020/1261](https://eprint.iacr.org/2020/1261)). Every blame in `signing-round.md` 9 rests on the contribution key. The factory key's half protected only its own owner, who checks for itself under C7.

**Effects.** It removes a BIP 340 statement made by a MuSig2 key, which was review 1's original worry. It restores AT_JOIN's "no seed at join". It saves 64 bytes per participant. The five added rules (duplicate history, epoch check, save-before-send, re-derive-and-compare, no factory key in Joined) are the right ones.

**Verdict: keep.** It reduces signing surface.

### 8. Penalties (`notes/penalty-check.md`)

**Upstream.**
- Channel penalties are single-signer, built by the wronged party, and pay `P2TR(local_payment_basepoint)` from a random secret (`channel.c:1153-1240`, `client.c:2818`).
- The only pre-signed penalty is the L-stock poison, which is not in 1.0.0.
- Upstream keeps per-commitment secrets flat, following 1143 post 34.
- Penalty transactions are v3 with an optional keyless P2A (`channel.c:1256-1290`).
- There is no second-stage HTLC transaction (`channel.h:573-585`).

I accept the penalty-check's reading of upstream. It cites lines I did not re-open.

**8a. Pay the factory's `payout_script`: B.** The destination is the member's free choice at signing, so nothing goes on the wire. Reusing one index costs privacy only on a breach. **Keep.**

**8b. An independent copy before any balance: E.**
- **What it protects.** It is sound and it closes T3: a host that holds the member's backup can return an old one, then publish a commitment revoked after it.
- **The shachain switch.** It is justified: ZmnSCPxj's flat-secret advice was for multi-signer endpoints, and a Gazpacho channel is two single signers. So it is a C-class deviation from upstream's code inside our own `channel.md`.
- **Conflicts with our plans.** It contradicts DESIGN.md 8 and 9 ("a member's backup is held by the host"). In practice it requires a tower or a user-chosen location before a member can receive, while decision 16h puts towers after 1.2.0. That is a product requirement on every user.
- **Simpler alternatives to put to the owner:**
  - (i) The independent copy is just a second file location on the device or in the user's export path, with no tower.
  - (ii) Accept T3 for small balances, under a stated cap, and require the copy only above it.
- **Verdict: needs an owner decision before `channel.md` hard-codes it.**

**8c. Assume stale: E.** Low cost. A uniform close request hides staleness only when the backup did not come from the host; when it did, the host knows anyway, and the note says so. It gives no protection without the record. **Keep**, with honest `at_risk` labelling.

**8d. C12 exception: E.**
- **Soundness.** It is sound under one condition: a penalty is a single-signer BIP 340 signature (the revocation key derived from our basepoint secret and the cheater's revealed secret). Signing twice with a BIP 340 key and proper nonce derivation (BIP 340's default, with aux randomness) is harmless. R3 exists to stop MuSig2 or tree double-signing, which a penalty cannot do.
- **The danger is scope creep.** The exception must be confined in code to one key family, with a test that it cannot yield a factory key or feed any MuSig2 session.
- **Channel keys.** They are not yet placed in the key tree (item 11). Upstream's random basepoints would make this impossible, so they must be derived (epoch-scoped, hardened) or journaled.
- **Verdict: needs proof and test.**

**8e. Replacement only, no keyless anchor: D, against an owner decision.** Decision 16h item 6 says "P2A anchors go on everything a tower might publish, even at 0.1 sat/vB". A penalty is the main thing a tower publishes.
- The penalty-check's argument is technically right: a keyless anchor on a time-critical transaction lets anyone take its child slot, and a pre-signed fee ladder needs no anchor, so a passive tower can broadcast rungs.
- But it overrules the owner silently.
- **Verdict: put it to the owner** with both sides. Do not write it into `channel.md` until then.

**Related drift (not in the brief).** The penalty-check's M3 recommends following upstream's single-stage HTLC outputs. Decision 16h item 3 says "HTLC second-stage txids are fixed when `channel.md` is written". Both lead to pre-signable penalties, but they are different designs; the owner should see that.

### 9. Signing blame rules (PR #52 and review-pr52-a)

**Upstream.** Upstream has no blame protocol. Its ceremonies wait asynchronously for clients ([2705](https://delvingbitcoin.org/t/2705)).

**Ours.** All E. None of it touches funds: a failed round signs nothing that spends, and the host has not funded. The rules are about liveness and griefing, and the host can always deny service anyway.

**Nonce safety.** RESTART_ANSWERS_ABORT never makes nonces twice for one round identifier. That is the property that matters cryptographically, and it holds.

- **9a. Reason 3 excused once per (scope, key).** It fixes an unbounded loop (review H1). **Keep.**
- **9b. Blamed seats skipped for one check.** Keyed by contribution key, so a member cannot clear its own blame, and cleared after one check, so a passing tip difference does not lock an honest member out. **Keep.**
- **9c. 64-item cap.**
  - **This is a real defect today.** A lobby of 32 seats has a tree of more than 64 items from about 22 members. The engine refuses `begin`, and `end_lobby(h, 3)` cancels the whole lobby at its first check (review M2).
  - **Fix before more lobby work.** Either cap a lobby's target in the terms at the tree's item limit, derived from the shape so it is not a magic 21, or raise `GZ_SIGN_MAX_ITEMS` with its memory cost. Design 2 adds payouts per shared output, so the item count per member rises further.
- **9d. Gate bound to the values digest.** This is real defence in depth. A hostile host's proposal under other values gets no factory key, even before C1 refuses it. The second case review M3 named (the gate closed mid-round) needs its node test. **Keep.**
- **9e. READY carries the digest.** It closes a time-of-check/time-of-use gap between screen and command (review M4). **Keep.**

**Complexity verdict.** Every rule is justified, but the stack is heavy for Slice 1. Do not add more blame rules until P4.4 runs a multi-process hostile-member test.

### 10. Signing modes and gates (local-api draft 5, 14.3)

**Upstream.** None. A client signs when asked.

**Ours.** `member_signing` is one of AT_JOIN (the default), AUTO or WHEN_UNLOCKED (1.0.0, answering 501 in Slice 1), with per-lobby and node-wide gates. Owner decision 16d asked for A, B and C, with C described as "unlock that lobby's keys once at join".

**Class: E.**

**Soundness.** The text is honest that no gate protects the seed while the wallet is unlocked. Fund safety rests on C1 and C8, which every mode runs. The gates are consent controls.

**Drift.**
- (i) B has no core counterpart. It is recorded as item 36, but **not as a decision against the owner**.
- (ii) WHEN_UNLOCKED was not asked for, and its API shapes are already fixed.
- (iii) C opens at each *ready*, and must be re-readied after a Retry. That is "per ready check", not "once at join". It may be the better design, but it is a change to the owner's words.
- (iv) The AUTO refusal loop (PR #52, flagged item 1) shows the mode stack interacting badly with blame.

**Verdict: simplify.** Ship AT_JOIN and AUTO. Remove WHEN_UNLOCKED's fixed shapes until the owner asks for it. Put B's absence and C's "per ready" meaning to the owner as explicit decisions.

### 11. Key tree (PR #53, `docs/notes/keys.md`)

**Upstream.** `hd_key` exists; the basepoints are random; the report does not specify wallet derivation.

**Ours.**
- Purpose 254315617' (SHA-256 prefix; not a registered BIP 43 purpose, and SLIP-0043 could not be checked).
- `net'`, then member 0', host key 1', host pairs 2', each under epoch'/i'.
- Coins on BIP 86 `m/86'/coin'/0'`.

**Class: B.**

**Soundness.**
- Everything is hardened. No Gazpacho key is a child of `m/86'`.
- The 31-bit random epoch gives about a 2^-31 chance per restore of colliding with an old epoch. That is acceptable, but note that a collision would mean MuSig2 key reuse across factories; nonce reuse would still be prevented by fresh nonces.
- K2 was a real bug, found by test: one seed as host and member collided keys. It is fixed by the 2' branch.

**Missing.** Channel keys (revocation, payment and delayed basepoints) have no branch yet, and items 8a and 8d need one.

**Verdict: keep.** Add the channel branch before `channel.md`.

### 12. Storage (PR #54): `setup.gzp`, restore path, sealed counter

**Upstream.** Not applicable: upstream persists to SQLite without this scheme.

**Ours.** The marker is written before the key file at set-up only, and removed after the first incarnation is durable. An interrupted set-up finishes as a new wallet, not a restore.

**Class: E.**

**Soundness.** It is safe because a set-up seed has signed nothing and has not been used elsewhere. A restore from the words removes any stale marker, so a reused seed always takes the restore path and a fresh epoch (R3).
- The sealed counter (`starts.gzs`) detects a rolled-back journal on the device.
- It does not help against a backup chosen by the host (8b); do not count it as T3's fix.

**Verdict: keep.**

### 13. Funding (PR #56)

**Upstream.** Funding is the LSP's own wallet's business. Gazpacho writes its own.

**Ours.** A v2 funding transaction at 0.1 sat/vB. `must_spend` makes the next plan reuse the previous attempt's input 0. The spend-back at the deadline replaces an unbroadcast or unconfirmed funding. UNWATCH frees chain-watch slots.

**Class: B.**

**Soundness.**
- `must_spend` guarantees that two fundings of one lobby conflict, so at most one factory exists (H11).
- The spend-back is H16's one exception, and members lose nothing: they hold no money in the factory before it is live.
- v2 rather than v3 is right. The root kickoff (v3) cannot have a v2 unconfirmed parent, but the tree is never sent before the funding is buried anyway.
- The funding can be bumped only by CPFP on its change output: an RBF would kill the signed tree. H16 states this.
- At 0.1 sat/vB on mainnet many nodes still relay at 1 sat/vB, so propagation is a liveness risk only.

**Verdict: keep.** The engine note `funding.md` is unreviewed; review it before wiring.

### 14. TRUC trees with P2A anchors at 0.1 sat/vB; package relay (PR #46)

**Upstream.** #476 makes every tree transaction v3, with one P2A each, at `tree_fee_rate`. Default 100 sat/kvB.

**Ours.** The same, from the re-import.

**Class: A.**

**Soundness.** BIP 431's single-child topology bounds pinning. The remaining free pin is covered in 2c. Exits take one block per level, which is in the deadlines.

**Verdict: keep.**

### 15. Lobby design

**Upstream.** None: the LSP chooses its clients.

**Ours.**
- Several lobbies per wallet (decision 16b).
- At most 32 seats per lobby and 48 connections per host (builder decision 12).
- Standby seats and understudies.
- Accountability unsigned in Slice 1, signed in 1.0.0 (decision 16c).

**Class: E.**

**Soundness.** No funds are at risk in a lobby; the costs are time and griefing. One stated residual: an outsider can occupy all 48 seats of a host (CONCERNS D13, parked).

**Drift.** `DECISIONS-WITHOUT-OWNER.md` K4 records that the coordinator brought invitations, removal and standby seats into Slice 1 against decision 10's 1.0.0 scope. Understudies were then moved to 1.0.0 by the owner (16e), not to Slice 1. This is the clearest case of scope added without the owner. Unsigned accountability is fine for signet Slice 1, as long as nothing is shaped so that signing receipts later means a message break.

**Verdict.** Keep several lobbies. **Pause standby and understudy machinery** until K4 is answered. Fix 9c's cap first, since standby seats push the seat count higher still.

## Overall answers

### Where have we drifted most from SuperScalar? Is each drift justified?

1. **The channel layer around penalties and restore (8b, 8d, 8e, the shachain switch).** This is the largest departure, and it sits in a specification that does not exist yet (`channel.md`).
   - Justified in substance: T3 is real and is caused by our own backup design, with the backup held by the host.
   - But it collides with two owner decisions (16h items 3 and 6) and with DESIGN.md's backup plan.
2. **The per-member payout script (4).** Justified by R3. It needs upstream's agreement; it is not a fork we should carry.
3. **The placement rule (3).** Justified as stated, but built on a 144-block CSV whose only purpose upstream is the poison window, which 1.0.0 does not have.
4. **Fee refinements (2b, 2c).** Small, justified, and they correct an upstream claim. They need vectors and one regtest test.

Everything else is upstream (1, 5, 14), standard Lightning (6), or left to the implementation (7, 11, 13).

### Our own inventions with no prior art, ranked by risk

1. **8d, the C12 exception.** It relaxes a key-safety rule. It is safe only if confined to single-signer penalties; one wrong branch could hand an old-epoch secret to MuSig2.
2. **8b, the independent penalty copy as a gate on receiving.** Sound, but a heavy product requirement that contradicts the plan and the tower schedule.
3. **4, payout scripts from the receive chain.** Funds can sit outside a restored wallet's scan if burned indexes outrun the gap.
4. **3, the placement rule.** Economic only; costs host capital.
5. **2c, the rate bound.** [R]-only analysis of Core relay policy. Easy to test.
6. **9 and 10, the blame and gate stack.** Liveness only, but large, and already showing feedback loops (AUTO refusal, 64-cap cancellation).
7. **15, lobby standbys and accountability.** Liveness only.
8. **12, the storage marker.** Narrow and well tested.

Lowest risk, and in fact reducing surface: **7 (K1)**.

### Is anything adding complexity that a simpler upstream-aligned approach would avoid?

- **Placement (3).** A short `l_stock_csv` in 1.0.0 gives the same guarantee with about 140 fewer blocks of host capital and no new formula.
- **Signing modes (10).** WHEN_UNLOCKED and its API shapes. Two modes are enough for Slice 1.
- **Standby seats in Slice 1 (15).** Not needed for the walking skeleton.
- **Penalty transport (8e).** Upstream's optional P2A versus our ladder-only approach. Pick one with the owner rather than carrying both.

### What should be reverted or paused before more code is built on it?

1. **Pause any code shaped by #508's wire and ordering** (FACTORY_PAYOUTS, HOST_COMMITMENT_SIG, the P(r) size) until #508 merges and upstream answers the payout-script request.
2. **Fix the 64-item cap against the 32-seat lobby (9c)** before more lobby or signing work. Today it cancels full lobbies.
3. **Pause the standby and understudy work** pending K4.
4. **Hold `channel.md`'s penalty rules (8b, 8d, 8e)** for an owner decision. Two of them contradict decisions 16h items 3 and 6, and 8b changes DESIGN.md's backup model.
5. **Drop WHEN_UNLOCKED's fixed API shapes**, and record mode B's absence as a decision against the owner.
6. **Record in `DECISIONS-WITHOUT-OWNER.md`** the decisions draft 3 took "pending the owner": the placement (3), the payout script (4), the rate bound (2c), and the penalty recommendations.

Nothing needs a hard revert: no merged code is cryptographically unsound. The risk is building more on undecided or upstream-draft ground.
