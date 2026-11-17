# Leaving a factory: exits, end-date payouts and watching

**Specification draft 3, 2026-11-16. This draft is not itself reviewed.** It will get a review round before anything is built from its new parts. Draft 2 (2026-11-12) is kept unchanged at `docs/specs-history/exit-d2.md`, draft 1 at `docs/specs-history/exit-d1.md`.

It specifies how a member's money leaves a 1.0.0 factory on every path, what the member's wallet and the host's software must do, by when, and who pays the fees. It rewrites draft 2 around the end-date design the owner has settled: **ZmnSCPxj's design 2** (Delving Bitcoin topic 1242, "SuperScalar: Laddered Timeout-Tree-Structured Decker-Wattenhofer Factories With Pseudo-Spilman Leaves", 2024-11-04), with its "inversion of timeout default". At the end date, pre-signed lock-time transactions on every shared output pay each member at least its full channel capacity, and pay the host nothing. The host gains nothing from the end date: before it, the host must move each member to another factory or push a silent member on chain at its own cost. A member that does nothing is paid.

Design 1 (topic 1143, first post, 2024-09-16: the host alone takes every output at the timeout, so members must leave first) is **not** Gazpacho's design. Draft 2 built its deadlines on design 1's host-only timeouts and said "1.0.0: no end-date payout". Both were wrong for 1.0.0; they were right only for the code we import today. This draft keeps those rules where they are still needed and marks each one **INTERIM**.

**INTERIM.** A rule marked INTERIM holds only while the imported SuperScalar code still carries host-only timeout leaves on tree and channel outputs (Gazpacho's pin `e6573950`, and `50f7fa13` of the re-import in draft pull request #46). Each INTERIM rule names what replaces it. An INTERIM rule MUST NOT be relied on with real funds. Section 1.2 says which slices run under which rules.

Companion documents: `safety-rule.md`, `signing-round.md`, `terms.md`, `messages.md`, `journal.md`, `storage-encryption.md`, `local-api.md`, `docs/MULTI-FACTORY.md`, `docs/THREAT-MODEL.md`, `docs/handoff/2026-11-12-tree-fees.md`, `docs/handoff/2026-11-11-end-date-payout.md`, `docs/handoff/2026-11-11-review-of-end-date-payout-draft.md`. The channel specification (`channel.md`) does not exist; section 10.1 lists what it must give this one. Section 10 lists every change this draft needs elsewhere; none of those documents is changed by this draft, except by the host-paid tree fee rate of 5.9 (2026-11-16), which changes `terms.md`, `safety-rule.md` and `signing-round.md` in the same commit.

**Marks.** **[C]** read in the imported code (file and line at the named pin); **[PR]** taken from a pull request's own text, not checked in code; **[S]** checked in a primary source (a design post, Bitcoin Core, a BIP); **[R]** reasoning, not checked by a source or a test; **[M]** a value to measure; **[X]** computed by `tools/spec-vectors.py` section X. A formula marked [R] has no vector yet (open point 15).

**Requirement words.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in BOLT 0 (RFC 2119). "The writer" is the party that builds, signs or sends something; "the reader" is the party that receives, checks or watches it. Each section ends with its **rationale**.

## Changes from draft 2

| Change | Where |
|---|---|
| The 1.0.0 end date follows design 2: a pre-signed payout on **every** shared output (funding, every output into a child tree transaction, every channel output, every spare-liquidity output), lock time E, paying members at least their capacity and the host nothing. Required from Slice 3 and before any real funds; taken from upstream draft #508 when it lands | 0, 1, 3, 4 |
| Deadlines are derived from design 2: the binding dates are the **host's** (`host_force_by`, the placement of E after the wind-down); a member's balance has no loss deadline at the end date | 4.1 to 4.4 |
| Draft 2's deadline system (H_leaf as a loss deadline, `leave_by` as the main trigger, `unlock_by` for the commitment, H15's timeout sweeps, H17, the host-wins race) kept and marked INTERIM, each with its replacement | 4.5, 6, 7, 9 |
| Fees stated as pre-signed at the agreed minimum tree rate (default 0.1 sat/vB) plus a keyless P2A anchor, the beneficiary paying the real fee by a TRUC one-parent-one-child package; no reserve; no rate in code. What is enforced and what is assumed is listed separately | 5 |
| Trees are TRUC (version 3) everywhere, as in the re-import of #46; the version-2 cases are gone | 4.2, 5 |
| Section 7 is now 35 paths, each with numbered steps: who acts, which transaction, lock time or deadline, who pays and how, what the member's wallet watches for, what happens if a step fails | 7 |
| The locked watcher holds the payouts (fully signed, never revoked), so under design 2 a locked or switched-off wallet is paid at E without an unlock | 6.6 |
| New host rules H19 (a commitment the member co-signed) and H20 (no end-date gain); H6 replaces H17 | 9 |
| Requirements written BOLT style, with writer and reader and a rationale per section; open points with owners | Throughout, 12 |
| 2026-11-16: **host-paid tree fee rate.** The host may choose a tree rate at or above 0.1 sat/vB and pays every pre-signed fee and anchor from the funding (the import already does this at any rate); under design 2 every channel output carries the channel payout's fee and anchor, P(r), above the capacity. Open point 4 closed; new open points 18 to 20. Not itself reviewed | 0, 3.1, 3.3, 5.1, 5.8, **5.9**, 7, 10.1, 12, 13 |
| 2026-11-17: **confirmation of the review of PR #48** (accept after fixes). N1: every payout pays a script the member names from its own BIP 86 receive chain, found after a restore by the normal gap-limit scan; the recovery keys are withdrawn and R3 stands (decision pending the owner, open point 5 closed). N2: the free-pin rate bound is floor(175,000 / V_occ) sat/kvB, 1,047 in T1, valid on Core 28.x and 29.0, and a member refuses a proposal above it. N3: a watcher that finds a revoked commitment runs until the penalty is buried. N4: `host_spare_by` counts the spare sweep's own allowance and uses the proposal's spare-liquidity delay: placement 178, 184, 190. N5: S18, X-2, the reader rule. Not itself reviewed | 3.3, 4.4, 5.5, 5.8, 5.9, 6.4, 6.7, 7, 10, 11, 12 |
| 2026-11-17: **review of PR #48** (`docs/reviews/review-pr48.md`, accept after fixes). H1: no member is safe while doing nothing; a watcher holding the penalty file runs at least once per watch interval, W long. H2: E placed `host_spare_by` after the wind-down (184 blocks at D = 3), forcing starts there; decision taken pending the owner. H3: no funding acknowledgement before the payouts are held. M1, M2: the reserve P(r) checked against `channel_sat`, and in R(leaf). M3: the member enforces the balance cap. M4: INTERIM `host_force_by` corrected. M5: the free pin by the next level, the rate bound. M6: payout keys after a restore. M7: one fee rule. L1 to L6. Open points 21 to 31. Not itself reviewed | 0, 1.3, 3.3, 4.4, 4.5, 5.5, 5.8, 5.9, 6.1, 6.6, 6.7, 7, 9, 10, 12, 13 |

Draft 2's long change tables (draft 1 findings F1 to F15, cross-specification review 1) are in `docs/specs-history/exit-d2.md`; every change they record is still in force unless this table says otherwise.

## Contents

0. The design in brief
1. Scope and which rules apply when
2. Terms
3. The transactions of a 1.0.0 factory
4. Deadlines
5. Fees at exit: what is enforced and what is assumed
6. The member's wallet: automatic actions
7. Every path: 35 paths, step by step
8. What is watched, and what a spend means
9. The host's side
10. Requirements on other specifications
11. Tests
12. Open points, with owners
13. Review checklist

---

## 0. The design in brief

- **At the end height E, members are paid; the host is not.** Every shared output of the tree has a pre-signed transaction with lock time E (the distribution transaction on the funding output; one payout on each other shared output). Each is signed by everyone in the creation round, pays every member under it at least its channel capacity on a key it controls, pays the host nothing, and carries a keyless pay-to-anchor (P2A) output. No shared output has a path the host can use alone at an absolute height [PR #508; S: topic 1242 post 1].
- **The host carries the end date.** Before E it moves each member to another factory (rotation), closes cooperatively, or forces a silent member out by publishing that member's path and **its own latest commitment, which the member co-signed** (H19). That pays the member its real balance. If the host is late, the member is paid its capacity at E and the host loses the difference and its spare liquidity under that member. This is the host's risk, not the member's.
- **The end date is safe for a member; doing nothing at all is not.** From E its wallet, or anything holding the payouts (a locked watcher, the host itself), publishes the payouts on its path. With one member per leaf and no sales, a member's balance never exceeds its capacity (the member's wallet enforces this, CH-14), so the payout covers it (the channel output carries the channel payout's own fee and anchor above the capacity, funded by the host: 5.9). But the host holds a commitment of its own for every channel (H19), and **every revoked host commitment stays a valid spend of the channel output, before and after E**. So something holding the member's penalty file (the wallet, its locked watcher, or a tower) MUST run at least once in every **watch interval** W − B − A − M blocks until the channel output is spent by a payout or by a current commitment (4.4, O-1). W, the member's revocation window for the host's commitments, is a long channel term (CH-4).
- **What needs a running wallet or watcher**, before and after E: answering a revoked host commitment (penalty; O-1), at least once per watch interval; and, before E, claiming an incoming payment whose secret was released before its expiry, and finishing what the host started. Only the first continues after E.
- **Fees.** Every tree transaction and payout is pre-signed at the agreed minimum tree fee rate (a term, default 0.1 sat/vB, never a constant in code) and carries a 240-sat P2A anchor. Whoever benefits from a transaction confirming pays the real fee at exit, by a child on that anchor (or, for a payout, on its own output), sent as a TRUC one-parent-one-child package (`submitpackage`) where a server refuses the parent alone. There is no fee reserve on the member's side. The rate is the host's choice, at or above 0.1 sat/vB, and the host pays every pre-signed fee and anchor from the funding, at any rate (5.9); at a rate at or above a server's relay floor a step is accepted alone, with no package.
- **Enforced versus assumed.** Who can spend what, and from when, is enforced by script and lock time. That a transaction **confirms in time** is assumed: it depends on fees, on pinning (bounded, not removed, by TRUC), on package relay being available (today only mempool.space offers a public package endpoint; Gazpacho runs its own signet node), and on the chain view. Section 5.8 lists both.
- **Today's import is half-way** (INTERIM). It has one payout from the funding output, which Slice 1 refuses, and design 1's host-only timeouts on every output below the root: a tree output at depth j times out at E − 5·(2j − 1), the leaf transaction's input and the channel output at **H_leaf = E − 10·d** [C]. Until the re-import of #508, a member with a balance must leave before H_leaf (draft 2's rules, section 4.5), and an honest host follows H17. Slices 1 and 1.5 owe nobody anything, so these rules cost nothing there.
- **The tree.** Advanceless (every interior level fixed), one member per pseudo-Spilman leaf (K = 1), TRUC transactions, P2A anchors, path-only exits: a member publishes only its own path, d + 3 transactions at depth d, one level per block.

## 1. Scope and which rules apply when

### 1.1 Scope

**In.** 1.0.0 as decided: advanceless trees (owner decision 9), one member per pseudo-Spilman leaf, no sales, no leaf advances, rotation as the only way to extend a life, the end-date payout on every shared output (owner decision of 2026-11-14 on the end date: design 2), the channel inside the leaf a taproot channel in Lightning's message flow with the departures `channel.md` must state (CH-2, CH-3, CH-11). Members only send and receive; they do not forward. Every path a 1.0.0 factory can take, from creation to the last sweep (section 7).

**Out.** Timed layers, leaf links, poison, sales, sub-factories (1.1.0): their rounds create new shared outputs, and each will need its own payouts signed in that round (#508 leaves them out for the same reason [PR]). The channel engine itself (section 10.1). Key handover: Gazpacho never hands over a key.

### 1.2 Which rules apply when

| Period | Import | End date | Member's protection at the end date | Rules |
|---|---|---|---|---|
| Slice 1, Slice 1.5 | `e6573950`, then `50f7fa13` (#46) | INTERIM: host-only timeouts; no payout signed (a member refuses one, `safety-rule.md` 12 value 1) | None needed: nobody is owed anything | INTERIM rules; the host recovers its signet coins by timeout (E-5) |
| Slice 2 (a payment on signet) | As above, unless #508 has landed | INTERIM | The member's own exit before H_leaf, and H17. The screen MUST say that the balance is not protected while the wallet is off | INTERIM rules |
| Slice 3 (leaving alone with a balance) and every later slice; any use with real funds | Re-import including #508 | **Design 2**: payout on every shared output | Payouts from E; the host's forced exit before E | Design-2 rules. A member MUST refuse a proposal that lacks the payouts |

The re-import that brings #508 changes every tree transaction id, adds payout signatures to the creation round and adds the member's co-signature of the host's commitment to every channel update (section 10). Upstream draft #508 (head `6e79b537`, 2026-11-14) was open, unreviewed and unmerged when this draft was written [PR]; this draft follows its text where it is specific and says so.

### 1.3 Rationale

The owner's Slice 1 decision was to leave the payout out of Slice 1, where nobody is owed anything, and to add it later and get it right. Draft 2 turned that into "no payout in 1.0.0", which the owner never decided. Design 2 is what the designer says "actual implementations" should use (topic 1242 post 1 [S]), it is the only option where the end date costs a member nothing whether the host is honest, gone or hostile (provided a watcher answers revoked host commitments within W, O-1), and our shape (one member per leaf, no sales) avoids the one weakness the designer names, a balance above the capacity (topic 1242 post 2 [S]).

## 2. Terms

| Term | Meaning |
|---|---|
| **E** | The end height, the import's `cltv_timeout` (`messages.md` 7.2 record 24). Under design 2 it is the lock time of every payout and of the distribution transaction: one date for the whole tree [PR #508] |
| **E_life** | The end of the factory's lifetime: the funding's confirmation height plus `lifetime_blocks` (`terms.md` record 26). The move window opens here |
| **E_wd** | The end of the wind-down: E_life plus `winddown_blocks` (record 28) |
| **d** | The depth of the member's leaf (root = 0). Read from the member's own held tree, never from the member count [X2]. D is `fixed_levels`, the deepest d |
| **Shared output** | An output that more than one key must sign for: the funding output, every tree output into a child tree transaction, every channel output (host and member), every spare-liquidity output. P2A anchors are not shared outputs |
| **Payout** | A pre-signed transaction spending one shared output, lock time E, paying the members under that output and never the host, with a P2A anchor last. On the funding output it is the **distribution transaction** |
| **Path** | The member's held exit transactions in order: the fixed kickoffs at depths 0 to d − 1, the leaf kickoff (depth d), the leaf transaction (depth d), then a commitment of the member's channel. n = d + 3 transactions |
| **Payout path** | The payouts of the shared outputs on the member's path, top to bottom, plus the payout of its leaf's spare-liquidity output |
| **Step** | One transaction of a path with its fee child and its state; states and kinds are `local-api.md` 16.3's list, with kind `payout` added (section 10.2) |
| **Missing** | Not confirmed in the trusted chain view |
| **Host's commitment** | The host's own commitment of the member's channel, **co-signed by the member** at channel open and at every update (H19, CH-11). It pays the member its full balance on an output only the member can spend |
| **Forced exit** | The host publishing a member's path and then its own latest commitment, at its own cost (H6) |
| **H_leaf** | INTERIM. The height in the host-only timeout leaf of the leaf transaction's input and of the channel output: E − 10·d [C] |
| **Tip estimate** | T_dl, the height the engines judge every deadline by (section 4.6) |
| **Anchor-only child** | The keyless 65-byte child of section 5.2 |
| **Bundle** | The watch-and-exit bundle `watch.gzw` (`storage-encryption.md` 8.7), records in section 6.6 |
| **Watcher** | The loop that runs from the bundle while the wallet is locked |
| **Beneficiary** | The party that gains if a transaction confirms. It pays that transaction's real fee |

## 3. The transactions of a 1.0.0 factory

### 3.1 Spend rules, design 2

Amounts below use T1 (channel 100,000 sat, tree rate 0.1 sat/vB). Every tree transaction is version 3 (TRUC, BIP 431) with lock time 0 and is valid as soon as its parent confirms [C at `50f7fa13`: `factory.h:48`, `src/factory.c:217-230`, `:748-783`]. Every payout is version 3 with lock time E, one key-path input, one output per member paying that member's **payout script** (3.4), no host output and one P2A anchor last, its fee at the agreed tree rate for its exact size [PR #508; the payout script is Gazpacho's requirement, open point 5].

| Output | Spent with all signers (key path) by | From E, also by | Anyone alone |
|---|---|---|---|
| Funding output 0 | The root kickoff; a friendly close (E-1); a rotation close (E-3) | **The distribution transaction**: each member its capacity plus an equal share of the rest, never less than its capacity [C at `50f7fa13`: `factory.h:1466-1480`]; at most 230 members [C at `50f7fa13`: `factory.h:858-864`] | — |
| A kickoff output into a child kickoff | The child kickoff | **Its payout** to the members under it, each at least its capacity [PR] | — |
| The leaf kickoff's output into the leaf transaction | The leaf transaction | Its payout, **if** #508 gives this output one (open point 3: #508 gives none to "a kickoff's output into its own state transaction" [PR]); otherwise a member publishes the leaf transaction first | — |
| Leaf output 0, the channel | Either side's commitment, both co-signed; a cooperative close of the channel | **Its payout** to the one member: the output's value less the payout's fee and anchor [PR], at least the capacity because the output carries the payout reserve P(r) above it (5.9) | — |
| Leaf output 1, spare liquidity | Everyone in the leaf (host and member) | **Its payout** to the leaf's member (K = 1) [PR], its fee and anchor from the host's stock (5.9) | The host, 144 blocks after the leaf transaction confirms (relative delay, unchanged) [C] |
| Every P2A anchor (240 sat) | — | — | Anyone, no key, empty witness |

So, under design 2, the host can take an output alone only through the spare liquidity's relative delay, and only after the leaf transaction is on chain. Everything else needs the member's co-signature or pays the member.

### 3.2 Spend rules, INTERIM (the current import)

| Output | Spent with all signers by | Host alone |
|---|---|---|
| Funding output 0 | Root kickoff; closes; the distribution transaction (refused in Slice 1) | Never (key path only, C1) |
| Output into a fixed kickoff at depth j ≥ 1 | That kickoff | From block E − 5·(2j − 1) + 1 [C at `50f7fa13`: `src/factory.c:1803`, `:2053-2070`] |
| Output into the leaf kickoff at depth d | The leaf kickoff | From block E − 5·(2d − 1) + 1 |
| Output into the leaf transaction | The leaf transaction | From block H_leaf + 1, H_leaf = E − 10·d |
| The channel output | Either commitment (today the host holds none of its own [PR #508]) | From block H_leaf + 1 (it copies the leaf transaction's script [C at `50f7fa13`: `src/factory.c:1630-1633`]) |
| Spare liquidity | Everyone | 144 blocks after the leaf transaction confirms |

A host timeout spend has lock time h and can first be mined in block h + 1. **Replaced by** 3.1 at the re-import of #508.

### 3.3 Requirements

The writer (the host, building a proposal):
- MUST, under design 2, include in the creation round the distribution transaction and a payout for every shared output of 3.1, each with lock time E, built from the proposal's own values, and MUST NOT include any host output in them.
- MUST, under design 2, fund every payout's fee and anchor as 5.9 requires: each channel output at least its member's capacity plus P(r), each spare-liquidity output at least P(r) + 330 sat.
- MUST NOT release the aggregated payout signatures before every member's channel is open with the host's commitment 0 co-signed (as #508's `FACTORY_PAYOUTS` [PR]); if any member does not co-sign, the opening MUST be aborted and no payout released.
- MUST send every member its aggregated payouts before asking for, or waiting on, its funding acknowledgement (the reader's rule below), and MUST NOT fund without every acknowledgement (H1).
- MUST NOT create a factory with E = 0, or while it cannot read the chain tip.

The reader (the member's wallet, at signing):
- MUST, under design 2, rebuild the distribution transaction and every payout on its payout path from the proposal and its own keys, and MUST refuse unless each verifies, has lock time exactly E, pays the member's own payout script (3.4, C2) at least its capacity (tree, distribution and channel: the channel output carries the payout reserve of 5.9; the spare-liquidity payout is excluded by name, it pays the spare output less P(r), at least 330 sat), and pays the host nothing.
- MUST refuse a proposal whose E is earlier than section 4.4's placement rule allows, computed with its own B and A and with M_safe + M_lag in place of the host's M_host (a host constant the member cannot know).
- MUST NOT send its funding acknowledgement (`round_ack`, H1) under design 2 until it holds every payout of its payout path and the distribution transaction **fully signed**, has verified each against the transactions it built, and has journaled them and written them to the bundle. A missing or invalid payout message is handled as C-4: no acknowledgement, the creation is abandoned on the member's side, and the host cannot fund without it.
- MUST, while INTERIM rules apply to its slice (1.2), refuse a proposal that carries a payout (`safety-rule.md` 12 value 1); from the design-2 slices on, MUST refuse one that lacks any payout on its payout path.
- MUST keep every payout on its payout path, fully signed, in its journal and in the bundle (6.6), and MUST NOT treat a payout as owed to the host.

### 3.4 The payout script (decision taken 2026-11-17, pending the owner's confirmation)

Every payout and the distribution transaction pay each member to a **payout script the member names**, taken from the member's own on-chain wallet's BIP 86 receive chain, m/86'/coin'/0'/0/i (coin 1 on signet and test networks, 0 on mainnet). A restored wallet finds those outputs by the wallet's normal gap-limit scan of that chain; no old factory key, epoch or lobby index is ever needed, and `safety-rule.md` R3 ("a restored node never derives a key it may have used before") stands unchanged.

The member (writer):
- MUST take, for each factory it joins, the next **unused** index i of its receive chain, record in the journal that i is given to that factory **before** sending it, and MUST NOT give that index to any other factory, invoice or address request, even if the creation fails (a failed creation burns the index).
- MUST send the script as the record `payout_script` of its contribution in the creation round (in its `ready`, beside its contribution key; `messages.md` gains the record): exactly 34 bytes, `51 20` followed by the 32-byte x-only output key of BIP 86 at index i (P2TR, key path only). Any other length or form is not allowed.
- SHOULD use the same script for its sweeps of that factory's other outputs (6.3 step 7).

The host (writer of the proposal) MUST carry each member's `payout_script` unchanged in the proposal (one per member, in member order) and MUST build the distribution transaction and every payout paying each member to it. The reader's C1 rebuild uses the scripts from the proposal; each member MUST refuse unless the script carried for itself equals the one it sent, and refuse any `payout_script` that is not 34 bytes of the form above.

**Finding them after a restore.** The payout indexes stay unused on chain until E, so a wallet with many open factories leaves a run of unused indexes. A restored wallet MUST scan its receive chain with a gap limit of 20 plus the most factories the wallet allows open at once (`MULTI-FACTORY.md`), and MUST keep that limit while any factory may still pay. The member's output on a host's commitment needs the same property from `channel.md` (CH-16).

**Rationale for 3.4.** A payout to the factory key (as #508 builds it) is spendable after a restore only by deriving a key of an earlier restore epoch, which R3 forbids and which a restored wallet cannot even find, since epochs are random (R2). An address from the wallet's own receive chain is found by the scan every wallet already does, and 34 bytes keeps P(r)'s size assumption (5.9). Upstream must accept a caller's payout script per member, as it already accepts a caller's channel script (`factory_set_leaf_channel_spk`); until it does, Gazpacho cannot sign #508's payouts as they are (open point 5).

**Rationale.** Design 2 puts the cost of the end date on the party that has coins and gains from service, the host (topic 1143 post 26 [S]: "we can instead have the signatories sign an `nLockTime`d transaction that sends the funds to the clients"). A member that checks every payout it needs at signing can later be paid without the host, with nothing to sign. Releasing payouts only after the host holds its first co-signed commitment means a member can never hold a payout for a channel the host cannot close; otherwise the host could be made to lose capacity it never had a chance to recover.

## 4. Deadlines

### 4.1 The end height and when a payout is valid

A payout with lock time E is final in block E + 1 and later (`IsFinalTx`: a height lock time is final when it is below the block's height) [S: Core]. A node accepts it into its mempool once the tip is E. So:

```
payout_first_block = E + 1          (broadcast from tip E)
```

There is one date for the whole tree [PR]. Section 4.5 keeps the INTERIM heights.

### 4.2 The path and its length

n = d + 3 transactions: d fixed kickoffs, the leaf kickoff, the leaf transaction, the commitment [X2]. In T1: at 3 members depths 1, 2, 2; at 4 all 2; at 5 to 7 a mix of 1 and 2; at 8 all 2; at 9 to 15 a mix of 2 and 3; at 16 all 3 [X2]. Signed sizes: a kickoff with k outputs and its anchor is 81 + 43·k vbytes (167 for two outputs, 253 for four, 124 for the leaf kickoff); each pays the terms' rate for its own size: 13, 17 and 26 sat at 0.1 sat/vB [X2]. A payout with one member output is 124 vbytes (496 weight units) with a 64-byte signature (`SIGHASH_DEFAULT`), a key-path input, one P2TR member output and one P2A, and 125 vbytes with a 65-byte signature; it pays 13 sat at 0.1 sat/vB [R; review recompute]; the distribution transaction is 81 + 43·m vbytes for m members [R], which stays under TRUC's 10,000-vbyte parent limit up to m = 230, the import's limit [R; C at `50f7fa13`: `factory.h:858-864`].

Under TRUC a transaction may have one unconfirmed parent and one unconfirmed child of at most 1,000 vbytes [S: BIP 431]. A level's fee child takes the parent's only child slot, so **each level must confirm before the next is sent: an exit takes at least one block per missing step**, plus burial of the last. Payouts on one path spend different outputs and can all be sent in the same block, each with its own child, once their parents are confirmed.

### 4.3 The constants

| Name | Signet | Meaning | Mainnet |
|---|---|---|---|
| **B** | 3 | Burial depth counted before a competing claim opens | Open (proposed 6) |
| **A** | 6 [M] | Confirmation allowance per transaction: one block, plus time to notice, rebroadcast and climb two fee steps. Measured by S2 | Open |
| **M_safe** | 6 | General margin: a restart, a slow save, a repeated broadcast | Open |
| **M_lag** | 2 [M] | Chain-view lag | 2 |
| **M_spike** | 6 [M] | Blocks a fee spike may outlast the allowance. Signet cannot produce one | Open (proposed 144) |
| **M** | 14 | M_safe + M_lag + M_spike (member side) | — |
| **M_host** | 8 | M_safe + M_lag (the host holds fee coins, H7) | Open |
| **W** | 144, minimum | The member's revocation window for the host's commitments (CH-4): a channel term with the member's own minimum in its conditions. Arithmetic floor B + A + M + 1 = 24 on signet; proposed 144 so that the watch interval is 121 blocks (about 20 hours) | Proposed at least 2,016 (two weeks); open point 21 |
| **Watch interval** | W − B − A − M | The longest time the wallet and every watcher holding its penalty file may all be off: 121 blocks with W = 144 on signet | W − B − A − M |
| S_spare | 144 | The spare liquidity's relative delay: a proposal parameter (the import's `l_stock_csv`, default 144 [C]); every formula uses the proposal's value | From the proposal |
| `PAY_STOP` | 6 (= A) | No new payment within this of the date that stops payments | = A |
| `BLOCK_FAST_S` | 300 s | Clock floor of the tip estimate (4.6) | 300 s |
| `GRACE_S` | 1,800 s | Wait for the view after a start or wake (4.6) | 1,800 s |
| `WARN_LEAD` | 36 | Heads-up before a date | Proposed 432 |
| `OPEN_MARGIN` | 36 | `open_app_by` lead | Proposed 144 |
| `HOST_SILENT_OFFER` | 1,008 | Host silence before the wallet offers leaving early (6.1) | 1,008, proposed |
| `HOST_SILENT_WD` | 36 | Host silence during the wind-down before the same offer | 36, proposed |
| `CLIMB` | 2 | Blocks between fee steps of one child | 1 near a deadline, else 2 |
| **M_locked** | 0 | INTERIM. Extra lead for the locked watcher (4.5). **Replaced by** nothing: under design 2 the watcher has no lead date for the balance, only the payment and penalty dates, which carry M | Proposed n·A |

Every value except S_spare (a proposal parameter) is **proposed, owner to confirm**. The values in force for a factory are copied into its `exit_plan` when it goes live and never loosened for that factory.

### 4.4 Design-2 formulas

All heights. n_host(m) is the number of transactions the host must still get confirmed to force member m out: m's missing tree steps plus the host's commitment (at most d + 3).

```
payout_first_block       = E + 1
host_last_safe(m)        = E − (B − 1)                            the host's commitment for m buried by tip E
host_spare_by(m)         = E − (B − 1) − S_spare − (n_tree(m) + 1)·A − M_host
                                                                    n_tree(m): m's missing tree steps (at most d + 2);
                                                                    S_spare: the proposal's spare-liquidity delay (the
                                                                    import's l_stock_csv, 144 by default); the + 1 is the
                                                                    spare sweep's own confirmation allowance. The host
                                                                    starts forcing m out here (H6)
host_force_by(m)         = E − (B − 1) − n_host(m)·A − M_host      the last start that still recovers the balance
                                                                    (the spare liquidity is then lost to m at E)
host_stop_credit(m)      = host_force_by(m) − PAY_STOP              no new payment toward m after it
placement (signing)      E − E_wd ≥ (B − 1) + S_spare + (D + 3)·A + M_host
                                                                    forcing can start at host_spare_by after the wind-down
move_by(m)               ≤ host_spare_by(m) − (route allowance)     a move must settle before the host starts forcing
```

With the signet constants and S_spare = 144, whole path missing [R; vectors owed, open point 15]. Started at `host_spare_by`, the leaf transaction is confirmed by E − 160 at d = 3, the spare sweep is valid from E − 16 and confirmed by E − 10, leaving (B − 1) + M_host = 10 blocks before the payout can be mined in block E + 1:

| d | `host_spare_by` (forcing starts) | `host_force_by` (last start) | `host_stop_credit` | Placement E − E_wd, D = d |
|---|---|---|---|---|
| 1 | E − 178 | E − 34 | E − 40 | 178 |
| 2 | E − 184 | E − 40 | E − 46 | 184 |
| 3 | E − 190 | E − 46 | E − 52 | 190 |

#508 states a shorter rule, "`--cltv-timeout >= EXPIRED + exit time + 6`" [PR], which leaves no room for the spare-liquidity delay.

**Decision (taken 2026-11-17 on the review's recommended option, pending the owner's confirmation): E is placed at least `host_spare_by` after the wind-down, and forcing starts at `host_spare_by`.** The host may then force every silent member out from E_wd and still have each leaf transaction confirmed S_spare blocks, plus one allowance for the sweep and the margins, before E + 1, so it sweeps the spare liquidity before the spare-liquidity payout is valid, and a forced member never receives its leaf's spare liquidity. **Rationale.** The alternative, letting E sit only the forced-exit time after the wind-down (46 blocks at D = 3), means every member the host forces out also collects its leaf's spare liquidity at E (in T1 100,000 sat less P(r) per leaf). One silent member that blocks the friendly close then forces the host to force out every member, and each of them gains its spare by going silent or being forced: the protocol would pay members for silence and double the free-seat cost (open point 7). The cost of the decision is a longer life for the host's capital: about 144 more blocks on signet (190 against 46 at D = 3), proportionally less at mainnet's longer wind-down.

**The member has no end-date deadline for its balance, but it has a watch interval.** After E every shared output still unspent on its path has a payout; the other transactions that can spend those outputs are the pre-signed tree transactions (which lead to further payouts below), the host's **current** co-signed commitment (which pays the member its balance) and **any revoked host commitment** (which pays the host what it had in that older state). A revoked one can appear at any time, before or after E, and only the penalty answers it (O-1). So the member's balance is not lost to the end date, but it is lost if nothing holding its penalty file runs within the watch interval after a revoked host commitment confirms [R]. What remains for the member is unchanged Lightning, plus that interval:

```
accept an incoming payment only if  h ≥ tip + (n + 1)·A + (B − 1) + M   and  tip < payments_stop_at
go_on_chain_by(h)       = h − (B − 1) − (n + 1)·A − M          once its secret is released and the host has not removed it
min_final_cltv_delta    ≥ (n + 1)·A + (B − 1) + M
penalty_send_by         = c + W − B − A − M                      for a revoked host commitment confirmed at height c
second_stage_unlock_by  = s + W − B − A − M                      for a host second-stage transaction confirmed at s
watch_interval          = W − B − A − M                          the wallet or a watcher holding the penalty file runs at least once per interval,
                                                                    until the channel output is spent by a payout or a current commitment;
                                                                    once it finds a revoked host commitment it keeps running,
                                                                    rebroadcasting and climbing the penalty ladder, until the penalty is buried
```

Under design 2 the member needs no stop date of its own: the acceptance rule above and the host's `host_stop_credit(m)` bound payments, and a channel output still unspent at E pays the member everything, payments in flight included. INTERIM: `payments_stop_at = leave_by − PAY_STOP`.

In T1 at d = 2 the payment allowance is 52 blocks [X4]. The `+ 1` is the claim on the commitment's payment output. These hold under both rule sets; draft 2's text on outgoing payments, coinless members (`UNPROTECTED_MAX`) and second-stage penalties is unchanged (`docs/specs-history/exit-d2.md` 4.4).

**Requirements.** The host MUST compute `host_spare_by(m)`, `host_force_by(m)` and `host_stop_credit(m)` for every member from its own constants and the member's held depth, and MUST NOT offer m a payment after `host_stop_credit(m)` unless m has been moved. The member's wallet MUST refuse a proposal that fails the placement rule at its own constants (3.3), MUST compute the payment and penalty dates above, MUST refuse a channel whose W is below its own minimum, and MUST tell the person the watch interval: the longest the wallet and every watcher may all be off. The wallet MUST NOT start an exit merely because E is near.

**Rationale.** Design 2 turns the end date into the host's deadline: "If the blockheight approaches the `nLockTime` of the tree, the LSP ***must*** initiate the unilateral exit itself, *and* pay for the confirmation of those nodes, or else it risks loss of all funds still locked in that part of the sub-tree" (topic 1143 post 26 [S]). The placement rule gives the host room to do that after the wind-down, including the spare liquidity's delay and the sweep's own allowance, so moving members in the wind-down and forcing the rest do not overlap and forcing costs the host only fees. The watch interval exists because H19 gives the host a commitment of its own: every revoked one is a valid spend for ever, and only a penalty answers it. The payment rules stay because a host's forced exit can put an unsettled payment on chain before E, and Lightning's own deadlines then apply.

### 4.5 INTERIM formulas (the current import)

**Replaced by** 4.4 at the re-import of #508. They are draft 2's, and they hold for the trees of `e6573950` and `50f7fa13`. **H_leaf = E − 10·d** (settled): a fixed kickoff at depth j times out at E − 5·(2j − 1), the leaf kickoff at E − 5·(2d − 1), the leaf transaction's input and the channel output at E − 10·d [C at `50f7fa13`: `src/factory.c:1803`, `:2053-2070`, `:1630-1633`]; it is the smallest timeout on the path.

```
H_leaf             = E − 10·d
last_safe_confirm  = H_leaf − (B − 1)
leave_by           = last_safe_confirm − n·A − M            n = steps still missing
step_due(i)        = last_safe_confirm − (n − i)·A − M
leave_by_locked    = leave_by − M_locked
unlock_commit      = last_safe_confirm − A − M               watcher running and no tree step late
                   = leave_by                                otherwise
unlock_by          = min(unlock_commit, go_on_chain_by(h), second_stage_unlock_by(s))
payments_stop_at   = leave_by − PAY_STOP
open_app_by        = min(leave_by, safe_absence_date) − OPEN_MARGIN
host_force_by      = last_safe_confirm − n_host·A − M_host  (H17)
```

T1 at the signet constants [X3]:

| d | H_leaf | `leave_by` | Commitment due | INTERIM `host_force_by`, whole path missing |
|---|---|---|---|---|
| 1 | E − 10 | E − 50 | E − 26 | E − 44 [R] |
| 2 | E − 20 | E − 66 | E − 36 | E − 60 |
| 3 | E − 30 | E − 82 | E − 46 | E − 76 [R] |

The INTERIM `host_force_by` falls M − M_host = 6 blocks after the member's `leave_by` at every depth (E − 44 against E − 50, E − 60 against E − 66, E − 76 against E − 82), so a running member leaves first; draft 3 as first published had E − 54 and E − 66 at d = 1 and 3, computed with H_leaf fixed at E − 20 (review of PR #48, M4). No host date falls before the member's `leave_by` [R]. T1's 36-block wind-down is shorter than these leads, so under INTERIM rules a member with a balance starts leaving before the move window opens. That is acceptable only because Slices 1 and 1.5 owe nothing (open point 1). Under design 2 the member's `leave_by` disappears and the wind-down needs only to fit moves before `host_force_by`.

**Requirements (INTERIM).** While its slice runs under INTERIM rules, the member's wallet MUST start leaving alone by `leave_by` for every channel with something to take out (6.1), MUST compute `unlock_by` for the locked page, and the host MUST follow H17. A member MUST be told, in its own words, that its balance is not protected while the wallet is off (`local-api.md`).

**Rationale.** In the current import the host can take a channel output alone from H_leaf + 1. Until that path is removed, the only protections are the member's own exit and an honest host's policy, so the dates that drive them must stay exact.

### 4.6 The tip estimate and the chain view

Unchanged from draft 2 4.5, under both rule sets. The engines judge every deadline by

```
T_dl = max( T_view,  T_a + ⌊ (now − t_a) / BLOCK_FAST_S ⌋ )
```

where T_view is the highest **counted** tip (agreed by a second right-network server, or with checked headers) and (T_a, t_a) is the highest counted tip with the earlier of when it was first seen and its header's timestamp. The estimate advances with the clock when no new block is counted, so hidden blocks, silent servers and a chosen offline period make actions start early, never late. A claim by one server without checked headers is not counted. For `GRACE_S` after a start, a wake or a reconnection, a trigger fired by the clock term alone waits for the view. Progress (a step `confirmed`, `buried`) is recorded only from the trusted view. The full case analysis (hiding servers, stale agreement, a lone liar after a long sleep, natural gaps) is draft 2's section 4.5 and vector X5.

Under design 2 the estimate matters less for the member: its only hard dates are payment and penalty dates. A clock-floor overshoot can at worst make it publish payouts a few blocks before E + 1, where they are refused as not final and simply rebroadcast.

**Requirements.** Both programs MUST judge every date of section 4 by T_dl, never by one server. A reader MUST NOT count a tip that one server claims without checked headers. A writer of a payout broadcast MUST rebroadcast every block until it confirms, whatever earlier refusals said.

**Rationale.** A deadline judged by a view the adversary controls is not a deadline. Erring early costs a few blocks of fees or a refused broadcast; erring late costs money.

## 5. Fees at exit: what is enforced and what is assumed

### 5.1 The principle

- Every tree transaction and every payout is **pre-signed at the agreed tree fee rate** for its own exact size: at least 0.1 sat/vB, chosen by the host and paid by the host from the funding (5.9). The rate is a term (`round_propose` record 30, sat/kvB; default 100, that is 0.1 sat/vB; a member refuses unless it equals the frozen terms' rate and is under its own ceiling) [PR #46]. **No fee rate is a constant in code.**
- Every such transaction carries a **keyless 240-sat P2A anchor** as its last output.
- **The beneficiary pays the real fee at exit**, by a child on the anchor (or, for a payout, a child spending its own output), sent as a TRUC one-parent-one-child package with `submitpackage` where a server refuses the parent alone.
- **No reserve.** A member holds no coins for fees (owner decision 6). The 240-sat anchor of each step is funded by the host at funding, inside R(root), and so is every pre-signed fee, at whatever rate the host chose (5.9).

Who benefits, and so pays:

| Transaction | Beneficiary, pays the fee |
|---|---|
| A member's path when it leaves alone | The member |
| A member's path and the host's commitment in a forced exit (H-1) | The host |
| Payouts and the distribution transaction | The members paid by them (each member bumps its own; one bump confirms the shared payout for everyone under it) |
| Friendly close, rotation close | The host (it recovers or redeploys its capital early; members could wait for E). Paid from the host's share |
| Penalty | The member, from the swept value |
| Spend-back of the funding (C-5) | The host |
| Host's sweeps (spare liquidity, its own outputs) | The host |

### 5.2 The anchor-only child

For every step with an anchor the program builds once, at plan time:

```
version   = 3 (the parent's; BIP 431 requires a TRUC parent's child to be TRUC)
input     = the parent's anchor outpoint, empty scriptSig, nSequence 0xFFFFFFFD, no witness
output    = 0 sat, script 6a 03 00 00 00 (OP_RETURN, three zero bytes)
lock time = 0
```

It is 65 bytes and pays its whole input, 240 sat, as fee: a package rate of about 0.84 to 1.34 sat/vB over T1's tree transactions [X6], about 1.34 sat/vB over a one-member payout [R]. The same bytes for every member, so siblings publishing a shared level or a shared payout send the same child. It needs no key and no coin, so a locked watcher can send it.

### 5.3 A wallet-funded child, and a child on the payout's own output

When a step needs more than the anchor-only rate, the exit engine builds a child spending the anchor and the member's own coins (153 vbytes with one P2TR coin [X7]) at `child_fee = ⌈ r · (V_p + V_child) / 1000 ⌉ − f_p`, where r is the estimate for the blocks left before the step's date. It replaces the child already there and MUST meet: (a) at least the replaced child's fee plus the incremental relay fee on its own size; (b) its own rate above the replaced child's; (c) the package rate above the replaced package's [S: Core; hand-off F1, F2, F14]. The first wallet child must pay at least 565 sat on T1's leaf transaction [X7].

**A payout can be bumped from its own output** (topic 1143 post 26 [S]: "they can trivially fee-bump this alternate timeout transaction"): a child spending the member's output of the payout, signed with the member's key, needs no other coin. It is the normal bump for a coinless member under design 2. It needs an unlocked wallet. Under TRUC it competes with any child already on the anchor, and must evict it by paying more (sibling eviction, BIP 431 [S]).

### 5.4 Re-bump rules

Unchanged from draft 2 6.4: rebroadcast every block; replace the child after `CLIMB` blocks unconfirmed when below the estimate or within A/2 of the step's date, at max(estimate, 1.25 × previous); within A/2 of the date `CLIMB` is 1; never above the fee budget (default 25% of the expected recovered amount, 90% once late; open point 8); never replace a pre-signed transaction; a foreign child on an anchor is left alone if it confirms the step in time, else out-paid, or shown as `exit_step_held_back`. Under design 2 a payout has no deadline for the member: its budget clause uses "late" only when a payment or penalty date depends on it, otherwise the wallet waits for cheap blocks.

### 5.5 Pinning

Anyone can spend a keyless anchor first. On a TRUC parent the attacker's child is at most 1,000 vB; paying F ≥ **234 sat** in it defeats the fixed 240-sat anchor-only child, since 240 < F + ⌈0.1 · 65⌉ [X8]; a member with a coin out-pays it for at least 250 sat. Sibling eviction does not help a member without a coin. **This is a stated, unprotected gap** (`safety-rule.md` 11): a member without a coin confirms in calm conditions unless someone pays to stop it.

What changes under design 2: **the host has nothing to gain from stalling a member at the end date**, since a stalled payout is still valid later and the host's own commitment pays the member its balance; pinning becomes griefing at the attacker's cost, not a way to take funds [R]. Before E, a stalled leave-alone exit matters only for payment claims. Under INTERIM rules the host gains everything at H_leaf and could stall a coinless member for about 234 sat a step (draft 2 6.5).

**The free pin by the next pre-signed level** (review of PR #48, M5). With fees prepaid, anyone holding the tree (the host or any member) can broadcast the next pre-signed level as the one TRUC child of an unconfirmed step. It costs the attacker nothing (its fee is already in the funding), and it takes the child slot the member's anchor-only child needs. TRUC sibling eviction lets a new child replace it only by paying at least the occupant's fee plus the incremental relay fee on its own size [S: BIP 431; Core]: 65 sat on 65 bytes at Bitcoin Core 28.x's and 29.0's 1 sat/vB incremental fee, 7 sat at 29.1's 0.1 sat/vB. Members must expect 28.x and 29.0 servers (5.9), so the 240-sat anchor-only child evicts an occupant of V_occ vbytes at rate r only while V_occ · r + 65 ≤ 240, that is r ≤ 175 / V_occ sat/vB: about **1.047 sat/vB** for a 167-vB occupant (T1's two-output kickoffs and leaf transactions), 1.411 sat/vB for the 124-vB leaf kickoff. On servers that are all 29.1 or later the bound would be 233 / V_occ (1.395 and 1.879 sat/vB). Above it the occupant's fee is 334 sat at 2 sat/vB and 1,670 at 10 sat/vB, and a coinless member can neither attach a child nor evict the occupant while the market is above r. Before E that can make a payment claim miss its date (P-1); under INTERIM rules it could run past H_leaf. The 234-sat bound above does **not** hold for this pin: it is free.

Mitigations for the free pin, in order: (1) the **tree-rate bound** of 5.9 (the rate at most ⌊175,000 / V_occ⌋ sat/kvB, rounded down, V_occ the largest tree transaction that can be a child of an unconfirmed tree transaction: 1,047 sat/kvB in T1), so the anchor-only child can always evict the next level; a member refuses a proposal above it (5.9; open point 26 asks the owner to confirm); (2) **TRUC sibling eviction with a spare coin**: a wallet child spending the anchor and one coin, paying at least the occupant's fee plus 153 sat (incremental relay on 153 vbytes at 1 sat/vB; 16 sat on 29.1) and a better package rate; (3) the wallet's **spare-coin guidance**: while a factory's rate is above the bound, the wallet asks the person to keep one confirmed coin of at least ⌈V_occ · r⌉ + 450 sat (the occupant's fee, the incremental fee and the child's own weight) and shows `exit_needs_fee_coin` until it does.

Mitigations: the member's commitment is TRUC with a **member-keyed anchor** whose child is pre-signed at update time (CH-2), so nobody else can attach a child to it; a payout can be bumped from its own output (5.3), which only the member can spend; the strip names a held-back step.

### 5.6 The pre-signed ladder (locked watcher only)

Rung 0 the anchor-only child, then 2, 5, 10, 20, 50, 100 and 200 sat/vB, each a child spending the step's anchor and that step's own set-aside fee coin, each replacing the rung below; no 1 sat/vB rung [X7]. Off by default (no reserve); offered when `exit_needs_fee_coin` shows (open point 9). Under design 2 the payouts get the same ladder if fee coins are set aside.

### 5.7 Never replace the funding

The funding's txid is fixed before the round (H1). Replacing it by fee kills the signed tree, payouts included. **H16**: the host bumps a stuck funding only by a child on its own change output (or a P2A of the funding), never by replacement, except the deliberate spend-back of C-5. The member never bumps the funding.

### 5.8 Enforced versus assumed

**Enforced** (by script, lock time and signatures, under design 2):

| What | By |
|---|---|
| No party alone spends the funding, a tree output or a channel output before E | Key-path-only outputs needing every signer [PR #508; C1] |
| No payout confirms before block E + 1 | Its lock time E [S: Core `IsFinalTx`] |
| A payout's amounts and recipients | Fixed at signing, checked by every member (3.3) |
| From E, every shared output still unspent can go to the members | The payouts, held by every member and by the host |
| The host's commitment pays the member its real balance | The member's co-signature on it (H19) |
| A revoked host commitment loses the channel to the member | The penalty, if the member answers within W (watching is assumed, below) |
| The host's spare liquidity is the host's only after 144 blocks of the leaf transaction | The relative delay |
| A fee child needs no key on an anchor | P2A [S: Core, from 28.0] |
| Every pre-signed fee and anchor is the host's; no member output pays one, and every payout pays its member at least its capacity | The amounts, fixed at signing and checked by every member (5.9; `safety-rule.md` C8) |

**Assumed** (not enforced; each is a risk the member or host carries):

| Assumption | Who bears it if it fails | Bound or mitigation |
|---|---|---|
| A transaction confirms in time: the host's forced exit before E | The host (the member is paid capacity instead) | H7 fee coins; `host_force_by` margins |
| A transaction confirms in time: a payment claim before h, a penalty before c + W | The member | The dates of 4.4; a coin in the wallet; the payment cap `UNPROTECTED_MAX` |
| A transaction confirms in time: INTERIM, the member's commitment before H_leaf | The member | `leave_by`; H17 (policy, not protection) |
| Fee spikes last no longer than M_spike | Whoever has a date | Anchors let the beneficiary pay; a coinless member is limited to the 240-sat child and, for a payout, a child on its own output |
| Pinning through a keyless anchor | The member without a coin | TRUC caps the attacker's child at 1,000 vB (about 234 sat to defeat the anchor-only child); member-keyed anchor on commitments; own-output bump on payouts |
| Package relay is available: a server accepts `submitpackage` (one parent, one child) for a parent below its floor | Every party | Today **only mempool.space offers a public package endpoint**; public Electrum servers offer none (`THREAT-MODEL.md` 2.4). Gazpacho runs its own signet node. The chain port needs `gz_chain_broadcast_package` (10.5). Bitcoin Core 29.1 or later relays 0.1 sat/vB alone [S: F1, F2], so in calm conditions a step needs no package; at a host-paid rate at or above a server's floor (1 sat/vB on Core 28.x and 29.0) neither does it there (5.9) |
| Miners do not censor; reorganisations are shallower than B | Every party | B; `safety-rule.md` 11 excludes both |
| The chain view is not a full eclipse | The member | 4.6's estimate; one broadcast-only route |
| The wallet, its locked watcher or a tower holding the penalty file runs at least once per watch interval (W − B − A − M blocks), before and after E, until the channel output is spent by a payout or a current commitment, and once it finds a revoked host commitment keeps running until the penalty is buried; and before each payment date | The member: a revoked host commitment not answered within W takes what the host held in that state, up to the whole channel (O-1) | W a long term (CH-4, open point 21); a tower holding only the penalty file (harmless in any copy, 6.6) |
| The wallet is never switched off, with no watcher or tower, for longer than the watch interval | The member | Stated to the person at joining and in the strip (10.2); `safety-rule.md` 11 |

**Rationale.** The owner's fee position (`docs/handoff/2026-11-12-tree-fees.md` 4.4, 4.5) and design 2 fit together: pre-signed transactions carry only the minimum, so nobody overpays in calm times, and the party that gains pays the rest when it needs it. Saying plainly which properties are enforced and which are assumed is what lets a member and a reviewer judge the remaining risk; draft 2's "never a stall" was stronger than its sources.

### 5.9 The host-paid tree fee rate

Added 2026-11-16 from the owner's proposal: the host may pre-pay a higher fee on the pre-signed transactions, from its own coins, so that a step can be sent alone, without a fee package. Checked against the re-import of draft pull request #46 (branch `reimport-superscalar`, upstream `50f7fa13`) on the build server. **Not itself reviewed.**

**What the import does today.** No output of a tree transaction pays that transaction's fee. With member capacities the builder sizes the tree bottom-up: a leaf's outputs are the member's capacity and the host's spare liquidity, and every node's input is its outputs plus its own fee (the rate for its exact size) plus its anchor [C at `50f7fa13`: `src/factory.c:586-594`, `:1928-1984`]. The funding output must be exactly the root's requirement, or the builder refuses [C: `src/factory.c:2427-2437`], and the funding is the host's own coins (`safety-rule.md` C11). So **every pre-signed tree fee and anchor is already the host's, at any rate**: a higher rate makes the funding larger and no member output smaller. The rate is one field, `tree_fee_rate`, which Gazpacho's engine sets from record 30 [C at `50f7fa13`: `factory.h:379-386`, `:833-837`; Gazpacho glue on #46: `core/tree/include/gazpacho/tree.h:211`, `core/tree/include/gazpacho/tree_import.h:14`]; a rate whose fee cannot be paid is refused by the builder [C: `src/factory.c:2389-2394`]. Choosing a higher rate needs **no change to the imported code** and no adaptation beyond the term's value. Under the pin `e6573950` (top-down, one `fee_per_tx` on every transaction) the result is the same through `terms.md` 4.2: the host funds R(root), which grows with the fee, and every channel stays at least `channel_sat`.

**Where a fee could fall on a member: the payouts.** A design-2 payout (#508, not imported yet) pays its own fee at the tree rate and a 240-sat anchor out of the one output it spends [PR]. On the funding output and on tree outputs that output already holds the host's spare liquidity and every fee and anchor of the subtree below, far more than the payout needs (in T1 at 10 sat/vB, the 16-member distribution transaction is 769 vbytes and pays 7,690 sat out of a surplus above the capacities of more than 1,600,000 sat) [R]. On the leaf kickoff's output into the leaf transaction it holds the leaf transaction's fee and anchor, more than a one-member payout's (167 against 124 vbytes) [R]. On the **channel output** it holds only the capacity, so without a rule the payout pays the member its capacity less the payout's fee and anchor: 253 sat at 0.1 sat/vB, 365 at 1, 490 at 2, 865 at 5 and 1,490 at 10 sat/vB (125 vbytes, 4.2). A higher host-chosen rate alone would make open point 4 worse. On the **spare-liquidity output** the fee comes from the host's stock, which must leave the member an output above dust.

The host's prepaid tree fees in T1 (sizes as measured on regtest with #46: 167 vbytes for a two-output kickoff, 124 for the leaf kickoff, 167 for the leaf transaction; 81 + 43·k for a kickoff with k outputs, so 253 for the four-output root; each fee rounded up per transaction) [R; vectors owed, open point 15]:

| Members | Tree transactions | Total vbytes | D | Deepest path, tree transactions | Prepaid by the host at 0.1 / 1 / 2 / 5 / 10 sat/vB | Of it, on the deepest path |
|---|---|---|---|---|---|---|
| 3 | 8 | 1,207 | 2 | 625 vB | 124 / 1,207 / 2,414 / 6,035 / 12,070 | 64 / 625 / 1,250 / 3,125 / 6,250 |
| 4 | 11 | 1,665 | 2 | 625 vB | 171 / 1,665 / 3,330 / 8,325 / 16,650 | 64 / 625 / 1,250 / 3,125 / 6,250 |
| 8 | 21 | 3,249 | 2 | 711 vB | 334 / 3,249 / 6,498 / 16,245 / 32,490 | 73 / 711 / 1,422 / 3,555 / 7,110 |
| 16 | 45 | 6,913 | 3 | 878 vB | 710 / 6,913 / 13,826 / 34,565 / 69,130 | 90 / 878 / 1,756 / 4,390 / 8,780 |

Every column rounds the fee up per transaction (the last column at 0.1 sat/vB was first published rounded on the path's total: 63, 63, 72, 88; review of PR #48, L1). The anchors (240 sat on each of those transactions) are on top and do not change with the rate.

**The payout reserve.** For a rate r in sat/kvB, `P(r) = ⌈r × 125 / 1000⌉ + 240` sat: the fee and anchor of a one-member payout, sized at 125 vbytes so that a 65-byte signature (any sighash other than `SIGHASH_DEFAULT`) still fits (124 vbytes with a 64-byte one; 4.2; the exact size is owed by #508). It also assumes a key-path input, one P2TR member output and one P2A: if open point 5 lets a member name its payout address, that output's script MUST be at most 34 bytes (P2TR or P2WSH; 43 bytes with its value and length). In T1: 253, 365, 490, 865 and 1,490 sat at 0.1, 1, 2, 5 and 10 sat/vB.

**The check, and what "capacity" means** (review of PR #48, M1, M2). The member's promise is the term `channel_sat` (record 30), and its own minimum. Under design 2 the reader checks **channel output ≥ max(`channel_sat`, its own minimum) + P(r)**; only after that check is the member's **capacity** defined as the channel output less P(r) (decision 5, CH-14). The host's builder receives `channel_sat` + P(r) as every member's capacity (the per-member capacity of #46's open point 1, or the leaf amount of `terms.md` 4.2 on the old pin), so the funding rule R(leaf) of `terms.md` 4.2 gains P(r) on the channel and on the spare liquidity (the import splits a leaf in two equal halves). The tree payouts and the distribution transaction pay each member "its capacity as carried in the proposal" [PR #508], which is then `channel_sat` + P(r); the reader checks that each pays it at least `channel_sat` + P(r). In T1 at 4 members and 0.1 sat/vB, R(root) becomes 804,835 sat against 802,811 without the reserve [R; X-vector owed, open point 24].

The writer (the host):
- MUST propose a tree fee rate (`terms.md` term 32, record 30) of at least 100 sat/kvB (0.1 sat/vB) and at most the term's ceiling; it MAY choose any value in between.
- MUST pay every pre-signed fee and anchor from the funding: the funding output equals the root's requirement at that rate, and no fee reduces any member output.
- MUST, under design 2, make every channel output at least max(`channel_sat`, the member's minimum) + P(r), and every spare-liquidity output at least P(r) + 330 sat, so that every channel and tree payout pays its member at least its capacity and no payout output is below the P2TR dust limit (330 sat).
- MUST keep, under design 2, its own side of every channel at or above P(r) plus its commitment anchors, so it never offers an HTLC that would take the member's balance above its capacity (CH-14).
- SHOULD keep the default rate of 0.1 sat/vB, and MUST NOT choose a rate above ⌊175,000 / V_occ⌋ sat/kvB, rounded down, where V_occ is the largest tree transaction that can be the child of an unconfirmed tree transaction (1,047 sat/kvB in T1; 920 at V_occ = 253, where 921 already fails), so that the anchor-only child can always evict a pre-signed next level on Bitcoin Core 28.x and 29.0 (5.5). Core 29.1's lower incremental fee would allow ⌊233,000 / V_occ⌋ (1,395 in T1); the bound does not use it while members may meet older servers. Decision pending the owner (open point 26).
- MUST keep the P2A anchor on every tree transaction and payout, and version 3.
- SHOULD choose a rate at or above the relay floor of the servers it and its members broadcast to: 0.1 sat/vB on Bitcoin Core 29.1 or later, 1 sat/vB on 28.x and 29.0.
- SHOULD weigh, before raising the rate, that a member leaving alone now spends the host's prepaid fees on its path (the last column above) instead of its own.

The reader (the member's wallet, at signing):
- MUST refuse unless the rate equals the frozen terms' rate (C8a) and is at least 100 sat/kvB; every tree transaction pays exactly ⌈rate × its own signed size / 1000⌉ (the one fee rule, matching the builder of #46 and later; on the pin `e6573950` only, before #46 merges, the builder pays one `fee_per_tx` = ⌈rate × the largest signed size / 1000⌉ on every transaction, INTERIM, `terms.md` 4.2); and, under design 2, every channel output is at least max(`channel_sat`, its own minimum) + P(r), every channel and tree payout and the distribution transaction pays the member at least its capacity (`channel_sat` + P(r) for the tree payouts and the distribution transaction), the spare-liquidity payout at least 330 sat, and no output is below 330 sat (`safety-rule.md` C8).
- MUST refuse a proposal whose rate is above ⌊175,000 / V_occ⌋ sat/kvB, with V_occ computed from the tree it built (`safety-rule.md` C8 fee row).
- SHOULD treat its own fee-rate ceiling as a sanity bound only, by default the term's ceiling (1,000 sat/vB): the rate costs the member nothing. A chain-cost joining fee (term 70, reserved) is where a higher rate would reach the member, and it has its own ceiling.
- MUST NOT rely on a step being accepted alone: when every server refuses it alone, it sends the package of 5.2 and 5.3 as before.

**Sent alone.** A version-3 transaction whose own rate meets a server's relay floor and its current mempool minimum is accepted alone. The regtest run of #46 (Bitcoin Core 29.1 binaries, T1 at 4 members, rate 0.1 sat/vB) showed both sides of that rule: with the node's floor at 1 sat/vB each of the 11 tree transactions was refused alone and accepted in a package with its anchor-only child; with the floor at 0.1 sat/vB each was accepted alone [M: `reimport/regtest-run1.log`, 2026-11-17]. It was not repeated at higher rates for this change: the regtest node was stopped, and this review did not start it. That a rate at or above the floor is accepted alone at any rate follows from the same rule [R]. When mempools are full the mempool minimum rises above any fixed rate, so the anchor stays the backstop; and being accepted is not confirming in time, so 5.8's assumptions are unchanged. A higher rate also raises the anchor-only child's package rate: over a 167-vbyte step about 1.1, 1.8, 2.5, 4.6 and 8.2 sat/vB at 0.1, 1, 2, 5 and 10 sat/vB [R].

**Servers that relay version 3 and P2A, whatever the fee.** Every tree transaction and payout is version 3. Releases before Bitcoin Core 28.0 do not relay version-3 transactions or spends of P2A outputs [S: BIP 431; Core 28.0 release notes]. A wallet cannot verify a server's version, so the rule is a reader rule on refusals: a party MUST treat a server that refuses a version-3 transaction or a P2A spend as non-standard (as opposed to a fee refusal) as unusable for exits and payouts, MUST stop sending exit steps to it, and MUST keep at least one endpoint known to accept TRUC and P2A (Gazpacho's own signet node, or a server that accepted a version-3 package before), raising `chain_no_truc_server` when none is left (open point 30). No rate changes this. Servers on Core 28.x and 29.0 still need a package at 0.1 sat/vB; a floor of 100 sat/kvB for term 32 also rules out a later zero-fee tree design with ephemeral anchors without a new term version (L6).

**TRUC limits and dust are unaffected.** Sizes do not depend on amounts. Tree transactions are 124 to 253 vbytes and the largest T1 payout 769, under the 10,000-vbyte limit; the children (65-vbyte anchor-only, 153-vbyte wallet) stay under 1,000. Output values (channels, spare liquidity, anchors) do not change with the rate; only inputs grow, so no output moves toward dust [R]. With prepaid fees a tree transaction can be sent as the one TRUC child of its unconfirmed parent, two levels at once [R]. Nothing here relies on it for progress, but an adversary can use it to pin the member's step for free (5.5): the rate bound above keeps the anchor-only child able to evict it.

**Abuse by the host.** (a) A rate so high that some node cannot pay its fee: not possible, because each node's fee is reserved in its parent's output by the builder and the funding must match; a host that under-funds is refused by the builder and by every member's rebuild (C1). The payout reserve and the dust rule catch the payouts: with T1's 100,000-sat spare liquidity they hold up to about 800 sat/vB, and a host asking more is refused. (b) A rate that makes a member's exit depend on the host: not possible; every fee is in the signed bytes, no output pays it, and no output becomes the host's alone. (c) A real trade-off, not an abuse: a member can push its own path on chain at the host's prepaid cost (up to 8,780 sat at 10 sat/vB in a 16-member tree), where today it pays its own children; and under design 2 any prepaid fee of an unpublished transaction goes to the members at E. Both are the host's cost of its choice.

**Not in 1.0.0.** A fee ladder (several pre-signed copies of each tree transaction at rising rates) is left for after 1.0.0; it multiplies signatures and stored transactions.

**Rationale.** The import already makes the host pay every tree fee from the funding, so letting the host choose a higher rate changes no member output and no check's shape, only the value checked. The one place a fee would fall on a member is the channel payout; funding its fee and anchor above the capacity, from the host, is what lets C8's "at least its capacity" hold on every payout, and closes open point 4. Prepaying at or above the servers' floor removes the dependence on package relay (5.8, open point 14) in calm conditions; it removes neither the anchor nor the need for Core 28.

## 6. The member's wallet: automatic actions

### 6.1 When it acts on its own

"Something to take out" means the latest commitment has an output for the member above dust, or an incoming payment it can claim. Watching runs in every case.

| Code | Trigger | Under design 2 | INTERIM |
|---|---|---|---|
| `payout` | T_dl ≥ E, and a shared output on the member's payout path is unspent (or spent only in a mempool) | **Publish the payouts (6.4), whatever the balance**, including a member owed nothing | Not used: no payouts are signed |
| `deadline` | T_dl ≥ `leave_by` (watcher: `leave_by_locked`) | Not used | Leave alone (6.3) |
| `payment_on_chain` | T_dl ≥ `go_on_chain_by(h)` for a released, unremoved incoming payment | Leave alone | Leave alone |
| `host_fault` | The channel ends by Lightning's rules (invalid signature, refused revocation, `error`) | Leave alone, unless T_dl is within the path's length of E, where waiting for the payouts costs less (6.3 step 0) | Leave alone |
| `round_unfinished` | A move or close round touching the channel stayed Unfinished past its deadline, or a co-signed close was withheld past it (C13) | Leave alone | Leave alone |
| `host_forcing` | The host published part of the member's path and its commitment did not follow within A blocks of the leaf transaction's confirmation | Nothing automatic: payouts at E cover what is left; leave alone only if a payment date needs it | Finish the path (6.3) |
| `host_silent` | No valid message from the host for `HOST_SILENT_OFFER` blocks (or `HOST_SILENT_WD` in the wind-down) | **Offer** leaving now at a fee, or waiting for E at no fee beyond anchors (open point 6). Waiting is safe only if the wallet or a watcher keeps running at least once per watch interval (O-1); the offer says so | Leave alone |
| `left_behind` | The group rotated without this member | Show it; wait for the host's forced exit or E | Leave alone by `leave_by` |
| `user` | The person asked (`local-api.md` 16.3) | Leave alone | Leave alone |

A breach is not a trigger: the watch engine answers it (section 8).

**Requirements.** The member's wallet MUST start the `payout` action at E without waiting for the host, the person, an unlock (when a bundle is armed), a fee estimate, a trusted view (broadcasts go to every right-network server) or any planner rule. It MUST NOT publish the root kickoff for the purpose of being paid while the funding output is unspent: the distribution transaction is that exit [PR #508]. It MUST NOT, under design 2, start leaving alone for the end date alone. While INTERIM rules apply, it MUST start leaving alone by `leave_by`.

**Rationale.** Under design 2 a member that leaves alone before E pays fees to get what the payouts give it for free, and spends the host's money on nothing. Leaving alone stays for the cases a payout does not cover: a payment that must be claimed on chain, a host that broke the channel, a round left half-done, and the person's wish. Publishing the payouts even when owed nothing is what makes the host's risk real; honest wallets that skip it would hand the host design 1 back.

### 6.2 What it never waits for

The host (no step needs it); the person (no confirmation, no fresh sign-in for automatic actions); a trusted chain view (only progress records wait for it); a fee estimate (with none, children are anchor-only); burial of intermediate steps (one confirmation of a parent is enough to send the next); the planner (1.1.0) or any rule (a rule's own dates are always earlier); a signing round touching the channel (the exit or payout and the round's transaction may conflict, and the watch engine accepts whichever confirms). Pause never stops, delays or alters an exit, a payout or the watcher.

### 6.3 Leaving alone (the member's own path)

For one channel, once a leave-alone trigger fires:

0. **Under design 2, if T_dl + n·A ≥ E** and no payment date requires a commitment on chain before E, the wallet SHOULD wait for E and publish payouts instead (cheaper, nothing at risk). Otherwise go on.
1. **Before the freeze (optional, bounded).** Only unlocked, host connected, trigger not `host_fault`, and no payment or INTERIM date due: fail back unfulfilled incoming payments in one update, waiting at most `PREFREEZE_S` (60 s, proposed).
2. **Freeze.** Save `exit_started`: the channel decides no new signature and no new revocation (X-I3). Unfulfilled incoming payments are left to resolve on chain.
3. **Choose the commitment**: the highest-numbered own commitment the member holds the host's signature for and has not revoked, counting journaled revocations (X-I5).
4. **For each missing step in order** (the first has a confirmed parent, or is the root kickoff on a confirmed funding): save `exit_step sent` (and `fee_child`, `coin_reserved`); broadcast the step, as a package with its child if every server refuses it alone; broadcast its anchor-only child or the current wallet child; every block until confirmed, rebroadcast both and apply 5.4; on confirmation by any server, go on; on trusted confirmation, save `exit_step confirmed`. A step whose input another expected transaction already spent is skipped.
5. **The commitment** is completed with the member's key and broadcast once the leaf transaction is confirmed (needs the wallet unlocked; CH-1). **Under design 2, if T_dl ≥ E before it is sent**, the wallet MUST NOT send it unless a payment claim needs it, and publishes the channel's payout instead; if it was already sent, it is kept: either outcome pays the member at least its balance.
6. **Commitment buried** (B confirmations, trusted): claim incoming payments whose secret the member holds, each before h; reclaim outgoing ones after expiry.
7. **Sweep** the member's delayed output after its delay and the claimed payment outputs after theirs, to the payout destination, at the cheapest rate that confirms within a day, fee from the swept value. No deadline.
8. Save `exit_ended`.

What a step's failure means: a step that does not confirm by its date (INTERIM `step_due`, or a payment date) raises `exit_step_late` and climbs fees within the budget; a step whose input is spent by an unexpected transaction is handed to section 8; a crash resumes from the records at the next start (3.5 of draft 2: the start step rebroadcasts every `sent` step and its child before anything else).

### 6.4 The payout procedure (design 2)

From T_dl ≥ E, for each factory in which the member's payout path has an unspent shared output:

1. **Funding output unspent**: broadcast the distribution transaction and its anchor-only child. Do not publish the root kickoff.
2. **Funding output spent by the root kickoff**: walk the path from the top. For each shared output on the payout path:
   - spent by a confirmed transaction of the path: go down to that transaction's output on the path;
   - unspent: broadcast **its payout** with its anchor-only child (or a child on the payout's own output, 5.3, when unlocked and the anchor-only rate does not confirm);
   - spent only in a mempool (for example the host's next tree transaction or its commitment, unconfirmed at E): broadcast the payout as a package whose child pays enough to replace that spend [PR #508], within a fee budget computed on the **gain** over what the competitor pays the member (for the host's current commitment, capacity less balance), not on the whole amount; if the competitor confirms first, go down (a tree transaction) or record the result (the host's commitment pays the balance, section 8 S4).
   - Where an output on the path has no payout (open point 3: possibly the leaf kickoff's output into the leaf transaction), publish the next path transaction (pre-signed, no lock time) and continue below it.
3. Also broadcast the payout of the leaf's spare-liquidity output if it is unspent.
4. Rebroadcast every block until each payout is confirmed and buried; then record the amounts from the confirmed transactions (`exit_ended`, `ended_how = paid_at_end_date`).
5. Sweep the member's payout outputs to its payout destination when unlocked, at no deadline (they pay the member's own payout script, 3.4).

The member checks every 10 seconds or every block, whichever it has, whatever the distribution transaction's state, so a payout goes out at E even if the distribution transaction was voided by a published root [PR #508 does the same].

**Requirements.** The writer (member's wallet or watcher) MUST broadcast only payouts it rebuilt and verified at signing, MUST rebroadcast every block until buried, and MUST NOT publish the root kickoff while the funding output is unspent. It SHOULD use one child per payout and SHOULD prefer the anchor-only child while no payment or penalty date depends on the payout. The reader (the host) MUST NOT treat a member's payout as a fault.

**Rationale.** The payouts are the design's enforcement: a member that publishes them at E proves the end date was the host's to manage. Walking from the top, and publishing only what is unspent, is the cheapest way to be paid; voiding the distribution transaction by publishing the root would cost the member and its siblings fees for nothing.

### 6.5 Pause and the planner

Pause stops payments, nothing else. The 1.1.0 planner may move funds out before any date; it never disables, postpones or re-times an exit or a payout (`MULTI-FACTORY.md` 4.6).

### 6.6 A locked wallet

**Two facts** from draft 2 (`docs/specs-history/exit-d2.md` 5.6) remain: the member never holds a final signature on its own commitment (it completes it at broadcast, which needs its key), and a completed own commitment must never enter any file outside the encrypted journal, because every commitment is later revoked and old copies of files survive outside the program's control. So **the bundle and the penalty file never hold a commitment of the member's own** (W2).

**What design 2 changes.** Payouts are signed once at creation, never revoked, never superseded in 1.0.0 (one tree version per funding output, X-I7), and from E they pay the member exactly what the design owes it. They satisfy invariant T of `storage-encryption.md` 8.7.2: no copy can move value away from its rightful owner, since from E the rightful owner of a shared output's value is the member set the payout names [R]. So:

- the bundle MUST hold, under design 2, the distribution transaction and every payout on the member's payout path, each with its anchor-only child;
- the watcher MUST publish them from E by 6.4, without an unlock;
- the balance of a member whose wallet stays locked (or is switched off and later started locked) is therefore paid at E, with no `unlock_by` for it. An unlock is still needed for: claiming an incoming payment whose secret was released (`go_on_chain_by(h)`), a host second-stage transaction after a breach (`second_stage_unlock_by`), sweeping the member's outputs (no deadline), and bumping from a payout's own output.

**INTERIM.** With no payouts, the watcher publishes the tree path and answers revoked host states, and the person must unlock by `unlock_by` for the commitment; after H_leaf a dishonest host takes the balance. Draft 2's section 5.6 is in force for those slices, unchanged: the unlock_by formula (4.5 here), the headline table, W1 to W5, the bundle and penalty-entry records, fee coins for a locked exit, and locking with payments in flight. Slice 1 builds no watcher (`nobody_locked`, reason `no_bundle`).

**Rules W1 to W5** (both rule sets): W1 the node and the watcher never run at once, and the watcher keeps running until the unlock has opened the key file; W2 no bundle or penalty file holds a commitment of the member's own or anything from which one could be completed; W3 at unlock the node merges `watch.gzl` as untrusted input and takes its decisions from the chain; W4 after a restore the bundle is rebuilt from the restored journal; W5 "maximum privacy" (no bundle) is refused while a factory has something to take out unless confirmed with the date it puts at risk (under design 2: the payment and penalty dates; E itself is not at risk, but nobody will publish the payouts while the wallet is locked without a bundle).

**Bundle records, design 2 additions** (the rest is draft 2 5.6): in a factory block's B4 path list, step kinds 4 `payout` (a payout on a shared output; field 12, the shared output it spends, 36 bytes) and 5 `distribution` (the distribution transaction); field 14 of B5 gains `E` (`u32`). A payout entry with a lock time other than the factory's E is refused at write and at read. `constants_version` becomes 3.

**Locked headlines, design 2.** First match wins; always no amounts.

| Case | Headline | Tier |
|---|---|---|
| The host closed the channel with its own commitment (S4) | "The host closed this channel. Your balance waits for you; unlock to collect it." | `important` |
| A released incoming payment is unsettled | "Unlock before block `unlock_by`, or a payment you received may be lost." | `at_risk` |
| A host second-stage transaction after a breach | "Unlock before block `unlock_by`. The host published an old state and moved payments out of it; answering that needs your passphrase." | `at_risk` |
| A revoked host state appeared and the penalty went out | "Locked. The host published an old state and Gazpacho answered it. Unlock to see." | `at_risk` until seen |
| T_dl ≥ E, payouts going out | "Locked. A factory has ended and Gazpacho is collecting what it owes you. Unlock any time to see it." | `important` |
| Something to take out, before E | "Locked. Gazpacho is still watching. If nothing else happens, your share of this factory is paid to you from block E (about …), as long as Gazpacho or your tower keeps running at least every <watch interval> blocks to answer old states." | — |
| No bundle ("maximum privacy") and something to take out | "Locked. Nothing is watched. Unlock after block E to be paid, and before any payment you received is due." | `at_risk` |
| Nothing to take out anywhere | "Locked. Gazpacho is still watching. Nothing needs you now." | — |

**Rationale.** Under design 2 the property the locked watcher could not give in draft 2, finishing an exit without the passphrase, comes from the payouts: they need no key and are never revoked, so they are safe to keep where a keyless program can use them. The commitment stays out of every file for the reason it always did.

### 6.7 After a restore

A restored wallet never publishes its own commitment automatically (`DESIGN.md` 6). Under design 2:
1. The payouts and the tree path are armed as usual: neither can be stale [R].
2. On reconnecting, the member asks the host to close with its own commitment (the host's commitment pays the member its balance, H19).
3. If the host does not, the wallet waits for E and is paid by the payouts, which pay its payout scripts (3.4): the restored wallet finds and spends them by its normal gap-limit scan. No "publish an old commitment" choice is offered unless a payment date needs one, and then only as the person's choice with the exact risk (*`restored_commitment_choice`*).
4. Factories the backup does not know are found only from a newer bundle on the device or from the host handing back the signed tree and payouts (`safety-rule.md` R7; open point 10).

**Keys after a restore.** No old factory key is ever derived (`safety-rule.md` R3, C12). The payouts pay scripts from the wallet's BIP 86 receive chain (3.4), found by the gap-limit scan; the member's output on a host's commitment and its sweeps follow CH-16 and 3.4. A factory whose payouts were never seen by the restored wallet (joined after the backup, with no newer bundle) still pays it at E: the scan finds the outputs once they confirm, and anyone holding the payouts (the host, a sibling's payout above) can publish them (R7, open point 10).

**INTERIM.** Without payouts, the choice of item 3 is offered at `host_force_by`, as draft 2 5.7.

**Rationale.** A restored wallet cannot know whether its latest commitment is current; publishing a revoked one loses everything to the host's penalty. Payouts remove the dilemma: they cannot be out of date.

## 7. Every path: 35 paths, step by step

Each path: **status** (S specified, G specified with gaps, N not yet specified), the rule set it runs under, then numbered steps. Every step says who acts, which transaction, its lock time or deadline, who pays the fee and how. **Watches** says what the member's wallet watches for (by outpoint and txid, section 8). **If a step fails** says what follows. Transactions are those of section 3; T1 numbers at the signet constants. "Pre-signed at the tree rate" means the host has already paid that rate and the anchor (5.9); "who pays" names who pays any fee beyond it.

### 7.1 Creation

**C-1. Creation refused or aborted before any signature.** S · both · Slice 1
1. The member rebuilds the tree (and, under design 2, every payout on its payout path) from the proposal and checks C1, C5, C8, C8a and 3.3. Deadline: the step timeout (60 s) inside the signing budget (10 min).
2. On a failed check, or a broken nonce step, the member sends `round_abort` with its reason. Nothing is signed. No transaction, no fee.
3. The host starts another attempt; the same funding outpoint may be reused, because no partial signature exists.
- Watches: nothing on chain.
- If a step fails: an `round_abort` that never arrives ends at the step timeout; the lobby returns to waiting.
- Ends with: nothing owed, nothing lost.

**C-2. Creation aborted after partial signatures.** S · both · Slice 1; test S9
1. Before sending partial signatures (tree and, under design 2, payouts), the member saves its exposure record (C7).
2. The round breaks. The member asks `round_status_request` at every reconnect.
3. After one signing budget on its own clock it marks the creation Abandoned.
4. The host's next attempt builds a **new funding transaction spending an input of the old one** (H11); the host pays its fee. Members refuse any other tree on the old outpoint (reason 11).
5. When anything spending an old funding input is buried, the old record is Dead.
- Watches: every input of the old funding transaction (outpoint spent), the old funding txid.
- If a step fails: if the host funds the old attempt anyway, it is C-6: live only if C11's re-check passes. Payouts in the exposure set pay the member and cannot hurt it.
- Ends with: nothing owed, nothing lost.

**C-3. Understudy and several attempts under one ready check.** G · both · 1.0.0; tests S23 to S25
1. The host's lobby replaces seats that did not answer, or that dropped mid-signing, with standby seats in join order, and checks each seat's minimum member count against the new set.
2. If enough remain and the budget allows, the host sends a new signed `start` naming attempt n + 1 under the same check.
3. If any partial signature of attempt n was released, the new attempt uses a new funding plan under H11 (host pays).
4. Everyone makes fresh nonces; every member rebuilds the new tree and payouts and re-checks C8.
5. A late outcome of attempt n changes nothing.
- Watches: as C-2 for any attempt in which it released partial signatures.
- If a step fails: fewer than the minimum remain, or the budget is spent: the lobby ends Failed (reason 3).
- Gaps: lives only in `docs/notes/composite-node.md` 9.6; `messages.md`, `journal.md` and `signing-round.md` do not yet carry the attempt number or standby seats (open point 13).

**C-4. The host never funds, a member withholds its acknowledgement, or the host withholds the payouts.** S · both · Slice 1; tests S5, S10, S35
1. Without every `round_ack` the host does not fund (H1); it starts again without that member on a new outpoint.
2. A member that acknowledged watches the funding txid and every funding input.
3. 36 blocks after its acknowledgement: Abandoned (`creation_abandoned`, still watched).
4. A funding input spent elsewhere and buried: Dead (`creation_dead`).
5. Design 2: the host collects the partial payout signatures and the co-signed commitments 0 but never sends the aggregated payouts. The member does not send its acknowledgement (3.3), so the host cannot fund (H1); the member treats it as step 1 (`round_abort`, reason "payouts missing") and the creation ends Abandoned, then Dead as above.
- Fee: none, or the host's own spend of its coins.
- If a step fails: a funding that appears later is C-6.

**C-5. The funding does not confirm; the host abandons it (spend-back).** G · both · test S21, S22
1. Before its deadline (the latest member deadline plus burial) the host may bump the funding only by a child on its own change output (H16); it pays.
2. At the deadline the lobby ends Failed and `cancel` goes to every seat.
3. The host broadcasts the **spend-back**: one funding input back to its own wallet at the smallest fee that replaces the funding and its child. The host pays.
4. When it is buried, every member's record ends Dead (C4(d)).
- Watches: funding txid and inputs.
- If a step fails: the funding is mined first: the factory is live for each member whose C11 re-check passes (S22).
- Gaps: H16 lacks the spend-back exception; no member wording for "the host gave up"; no vector for the spend-back's fee.

**C-6. The funding is buried after the member's deadline.** S · both · test S6
1. The member, still holding the whole signed tree and payouts, re-runs the time checks of C5 and C8 (and, under design 2, 4.4's placement rule) at that moment.
2. If they pass, the factory becomes live and its plan is armed; otherwise it stays Abandoned and watched.
- Fee: none.
- Watches: the funding txid to B and every funding input, as before.
- If a step fails: a check that fails leaves the creation Abandoned and watched; a funding input spent elsewhere later makes it Dead.

**C-7. The host replaces the funding by fee.** S · both · test S8 (negative)
1. The replacement has another txid; the signed tree and every payout can never be used.
2. The member reaches Dead when the replacement is buried: `creation_dead`, cause `funding_replaced`, "Nothing was owed."
- Fee: the host. Rules: H16, C4(d).
- Watches: every funding input; the replacement's txid to B.
- If a step fails: the original funding is mined after all: the tree is valid again and C-6 applies.

**C-8. The funding is reorganised out before burial.** S · both · later (own node)
1. Nothing was live. The member returns to awaiting funding.
2. The same txid confirming again keeps the tree and payouts valid; anything else spending a funding input is C-4 step 4.
- Fee: none. Watches: block disconnected events; the funding txid and inputs.
- If a step fails: the funding never returns: C-4 (Abandoned, then Dead).

**C-9. The funding is reorganised out after burial, or double-spent.** S (detection only; not defended) · both · later
1. Payments stop (not live, C11). Dates are kept; any exit step or payout is rebroadcast if the funding returns.
2. If a funding input is buried in another transaction, the tree and every payout are void: `ended_how = void_funding`, `funding_double_spent`, the amount lost recorded.
- Ends with: the member loses what it received in that factory. Listed in `safety-rule.md` 11.
- Fee: rebroadcasts only. Watches: block disconnected; every funding input.
- If a step fails: nothing defends it; the loss is recorded and shown.

**C-10. Restore during creation.** S · both · Slice 1; test S11
1. A restored wallet draws a new restore epoch and never derives an old key.
2. A replayed proposal naming the old key is refused (reason 12). The member loses its seat and joins again.
- Fee: none. Watches: any funding it acknowledged before the backup, if the backup records it (C-4).
- If a step fails: the old seat's funding confirms anyway: the member cannot sign with the old key, so it is X-5's case for a factory the backup does not know.

### 7.2 Normal ends

**E-1. The friendly close.** G · both · zero-balance version in 1.5 (S26, S27, if the owner agrees); with balances from Slice 2
1. The host proposes, before `host_force_by` of every member (design 2) or before the first H_leaf (INTERIM). Every member must be online.
2. Both sides pause each channel (C9); no payment in flight unless it stays claimable.
3. One tier: one transaction spending the funding output, paying each member its balance to a script its own software derived and the host the rest, **with a P2A anchor**, at no less than the tree fee rate. The host pays the fee from its share (5.1).
4. Each member records the exposure, then signs. The host combines and broadcasts; it bumps through the anchor if needed.
5. Until the close is buried, members refuse payments (C13).
- Watches: the funding output (class S6 when spent by the close); the close's txid to B.
- If a step fails: a silent member means no close; the host then moves or forces members one by one (E-2, H-1). A close the host withholds is `round_unfinished` for the member (6.1) and, if published later, X-6.
- Design 2 note: a member gives up nothing of value by co-signing a close that pays its balance, but it would be paid its capacity if it waited for E. Honest wallets MUST co-sign a close that passes the safety rule; the design relies on cooperation here ("assisted exit", topic 1143 posts 12 and 15 [S]).
- Gaps: no message encoding (purpose 4); no rule for one missing member (open point 12).

**E-2. Rotation by paying across.** G · both · later (M4)
1. From E_life the host offers the next factory.
2. The member joins, signs and waits for burial of the new factory (C11).
3. It pays its balance from the old channel to the new one through the host, before `move_by` (design 2: before the host's `host_spare_by` for it, less the route's allowance).
4. Design 2: the old factory still holds a payout of the member's capacity. The host recovers it only with every member's signature (E-1, E-3) or by forcing the member out (H-1, a zero-balance commitment) before E. This is the host's main cost path, so **open point 11** (a release the member can co-sign alone) MUST be settled before rotation is built, not with it.
5. INTERIM: the host recovers by its timeouts once nobody below is owed (E-5).
- Fee: the routing fee is the member's; the host's recovery is the host's.
- Watches: the new factory as usual; the old one until it ends.
- If a step fails: the payment does not arrive by `move_by`: the member stays (E-4).
- Gaps: `move_by` under design 2 depends on the host's constants, which the member cannot check (open point 2); successor lobbies are not designed.

**E-3. Rotation by closing into the new factory.** G · both · later (M4)
1. Tier 1: the whole new tree, its payouts (design 2) and opening channel states.
2. Tier 2: one transaction from the old funding output to the new one, signed by every signer of the old root, with a P2A anchor; the host pays (5.1).
3. The host broadcasts; members refuse payments in the old factory from signing (C13).
- If a step fails: any signer missing: fall back to E-2 for the members present.
- Gaps: opening channel states inside a round (`signing-round.md` 14.2); no anchor or fee rule in upstream's rotation drafts (#471) [PR].

**E-4. Left behind at rotation.** S · both · Slice 3 / M4
1. The move window passes; the old factory still holds a balance for the member. The wallet shows `left_behind`.
2. Design 2: the member waits, with its wallet or a watcher running at least once per watch interval (O-1). Either the host forces it out (H-1: the balance arrives on the host's commitment, the member sweeps it) or, from E, the member's wallet publishes the payouts (6.4). The host's cost is open point 11.
3. INTERIM: the automatic exit runs by `leave_by` (6.3); the member pays its path's fees.
- Watches: the path and the channel output; payouts from E.
- If a step fails: design 2 has no failing step for the balance; INTERIM, a late exit loses to the host's timeout from H_leaf + 1 (H-2).

**E-5. The host recovers an emptied factory.** S · both · Slice 1.5 (S1, S4) INTERIM
- **Design 2**: there is no timeout to recover by. The host recovers the funding only by a friendly close (E-1) or a rotation close (E-3) with every member's signature, or, member by member, by forcing out (H-1) and then sweeping its own outputs and the spare liquidity (CSV 144). Whatever is still unspent at E goes to the members.
- **INTERIM** (how Slice 1's host gets its signet coins back): 1. the host publishes the root kickoff from its held tree; 2. from block E − 5 + 1 it sweeps each root output alone through its timeout leaf, one transaction for several; 3. deeper outputs, if a branch was published, at their own heights. Never an output with an owed member below (H15). The host pays (H7).
- Watches (member): class S2 (INTERIM) on its path's outputs; nothing to do when owed nothing.
- If a step fails (INTERIM): a member below an output turns out to be owed something: the host MUST NOT sweep it (H15) and forces that member out instead (H-1).
- Replaced by: the design-2 bullet, at the re-import of #508.

**E-6. End-date payout, with the host.** S · design 2 · Slice 3; test S34
1. The host has moved or forced out everyone it could; for any member still in the factory at E it has lost capacity minus balance and the spare liquidity under that member (H20).
2. At tip E, the host MAY broadcast the distribution transaction (funding unspent) or the payouts it holds; it pays nothing for them and gains nothing.
3. Each member's wallet (or watcher) runs 6.4 from tip E: distribution transaction if the funding is unspent, else the payouts down its path, each with an anchor-only child; the host prepaid each payout's fee at the tree rate and its anchor (5.9); the member pays any further fee (5.3).
4. Payouts confirm from block E + 1; the wallet records `paid_at_end_date` with the amounts.
- Watches: every shared output on the payout path, the payouts' txids, their anchors (S9).
- If a step fails: a payout not confirming is rebroadcast and bumped; no one else can take the output alone, so the only cost is waiting. A competing mempool spend (the host's late tree transaction or commitment) is replaced by a package (6.4 step 2) or, if it confirms, followed (it pays the balance, or leads to further payouts).

**E-7. End-date payout, without the host.** S · design 2 · Slice 3; test S34
1. The host is gone (or hostile and silent). Nothing it can do changes any member's payout after signing.
2. Same as E-6 steps 3 and 4, with no host action. Shared payouts deduplicate: the same bytes for every member under the output, the same anchor-only child.
3. If the host published the root kickoff (voiding the distribution transaction) and left, members publish the payouts of the root's outputs and below [PR #508 test "kickoff"].
- Fee: the tree rate and the anchors, prepaid by the host (5.9); anything above them, the members, through anchors or their own payout outputs.
- If a step fails: as E-6. A member whose wallet never runs again is paid when anyone publishes its payouts (a sibling's payout above it pays it too).

### 7.3 Leaving alone

**U-1. One member leaves alone.** G · both · tree half in 1.5 (S2); with a balance in Slice 3
1. A trigger of 6.1 fires (design 2: a payment date, a host fault, an unfinished round, the person; INTERIM also `deadline`, `host_silent`, `left_behind`, `host_forcing`).
2. The member runs 6.3: freeze, choose the commitment, then for each missing step: the root kickoff (if not on chain), each fixed kickoff to depth d − 1, the leaf kickoff, the leaf transaction, one level per block, each pre-signed at the tree rate, which the host prepaid (5.9), sent alone or, where every server refuses it alone, with its anchor-only child (or a wallet child). The member pays every child.
3. The member completes its signature on its latest commitment and broadcasts it (unlocked). Design 2: not after E unless a payment needs it (6.3 step 5).
4. At B confirmations: claim incoming payments before h; later sweep its outputs. No deadline for the sweep.
- Deadlines: design 2: only payment dates; INTERIM: `leave_by`, `step_due(i)`, commitment buried by `last_safe_confirm`.
- Watches: every path output and anchor, the channel output, then the commitment's outputs.
- If a step fails: design 2: a step stuck past E is overtaken by the payouts of the outputs still unspent; INTERIM: from H_leaf + 1 the host can take the channel output alone (H-2), shown as `exit_missed`.
- Ends with: the member its balance less fees; the host its side and, 144 blocks after the leaf transaction, the spare liquidity (design 2: unless E comes first, then the member); neighbours untouched.
- Gaps: steps 3 and 4 wait for `channel.md` (CH-1 to CH-13); package broadcast is missing from the chain port.

**U-2. Several members leave.** S · both · tests S3, S4
1. A later member publishes only what is missing: shared levels are the same bytes with the same anchor-only child, so nothing conflicts.
2. Each level already confirmed shortens the next member's path (INTERIM: its `leave_by` moves A later per step).
- A neighbour who stays: funds, channel and dates untouched. Once the root kickoff is buried it can no longer take part in a friendly close or rotation close; it moves by paying across, waits for E (design 2), or leaves alone. Shown as `branch_partly_on_chain`, `important`, never `at_risk`.
- Watches: S1 on path outputs; S9 on shared anchors.

**U-3. Every member leaves (the host vanished after funding).** S · both · Slice 3; 128 and 512 members on regtest later
- **Design 2**: 1. each wallet shows `host_not_answering` and, after `HOST_SILENT_OFFER`, offers leaving now (6.1); 2. by default every member waits for E, its wallet or a watcher running at least once per watch interval (O-1); 3. from tip E each runs 6.4; the distribution transaction (or the root's payouts) pays everyone at once. Fees: one shared payout per output, its tree-rate fee and anchor prepaid by the host (5.9), bumped further by whichever member needs it first.
- **INTERIM**: each member leaves alone on `host_silent` (1,008 blocks) or `leave_by`. With the host gone nobody holds the timeout key; a host that returns can still sweep what is left after its timeouts.
- If a step fails: design 2, a member that waits and never comes back is still paid when any sibling publishes a payout above it.

### 7.4 The host's actions

**H-1. The host forces a silent member out.** G · both · Slice 3 (S18)
1. Trigger (host side): member m, still owed something or still covered by a payout, has not moved or left by `host_spare_by(m)` (design 2, H6; at the latest `host_force_by(m)`, losing the spare liquidity) or, INTERIM, by draft 2's date (H17).
2. The host publishes m's missing path steps, one level per block, paying each child from its own wallet (H7).
3. Once the leaf transaction is confirmed, the host publishes **its own latest commitment** of m's channel, co-signed by m (H19), with its child; the host pays.
4. Its commitment MUST be confirmed by block E − (B − 1), so that it has B confirmations at tip E, before any payout can be mined (block E + 1); then the channel's payout can no longer be used. m's balance sits in an output only m can spend, with no deadline.
5. After the leaf transaction has 144 confirmations the host sweeps the spare liquidity; started at `host_spare_by(m)` this is before E + 1, so the spare-liquidity payout never pays m (decision of 4.4). After W the host sweeps its own side.
- Member's wallet: watches the path outputs (S1), the channel output (S4: the host's current commitment), and the commitment's outputs; on S4 it claims released incoming payments before h and sweeps its output when unlocked; `ended_how = forced_by_host`.
- If a step fails: the host stops halfway or is late: design 2, the payouts of every unspent output pay m from E (the host's loss); INTERIM, m's trigger `host_forcing` finishes the path before H_leaf.
- Gaps: the host's commitment needs `channel.md` (CH-11); until then this path exists only as H17, a policy.

**H-2. The end-date race.** S · both
- **Design 2 (who wins at E)**: the competing spends of the channel output after E are the host's co-signed commitment (pays m its balance) and the channel payout (pays m its output less fee and anchor, at least its capacity: 5.9). Whichever confirms, m gets at least its balance. A **revoked** host commitment is a third competitor, before and after E: it pays the host its older share, and only m's penalty within W answers it (O-1). For tree outputs the competitors are the next pre-signed tree transaction and the payout; both lead to m being paid. Nobody can take m's balance [R].
  1. The host's current commitment confirmed by block E − (B − 1) (B confirmations at tip E): the host has won its own balance back.
  2. Otherwise, from block E + 1, whichever of the two the miners take. The host bumps its commitment's anchor; the member bumps its payout; the member is indifferent.
- **INTERIM (H_leaf)**: 1. the member wins if its commitment is confirmed by block H_leaf − (B − 1); 2. the host wins if the channel output (or an output above it at its own later height) is unspent at block H_leaf + 1: one host signature, lock time h; 3. published early, the host's spend is not final; 4. both in one mempool at H_leaf + 1: a miner's choice. The host's win takes m's balance (`host_timeout`, `exit_missed`, amount recorded); honest host software never does this to an owed member (H17). **Replaced by** the design-2 race at the re-import of #508.
- Watches: S2 (INTERIM), S4, S12.

**H-3. The host takes the spare liquidity.** S · both · 1.5 (part of S2)
1. 144 blocks after a leaf transaction confirms, the host alone spends output 1; it pays.
2. Design 2: if the leaf transaction was confirmed later than E − 144, the spare-liquidity payout is valid first (from E + 1) and pays the leaf's member; the host can still race it from 144 blocks after the leaf transaction.
- Member's wallet: records S3; nothing shown as a problem. Under design 2 it publishes the spare-liquidity payout at E if the output is unspent.

### 7.5 Old states

**O-1. The host publishes an old channel state.** G · both · Slice 3 (S17)
1. The watch engine sees the channel output spent by a revoked host commitment (S5), before or after E.
2. It broadcasts the penalty, pre-signed at revocation as a ladder of fee rates (CH-5), one rung every `CLIMB` blocks; the fee comes from the swept value. Deadline: `penalty_send_by` = c + W − B − A − M.
3. If the host moves a payment output to its second stage, the unlocked wallet signs a second penalty by `second_stage_unlock_by`.
- Locked: the watcher sends the pre-signed ladder from `watch.gzp`; it cannot answer a second stage (needs an unlock).
- If a step fails: the penalty not confirmed by c + W: the host sweeps its delayed output; the member loses the difference. A revoked commitment after E voids the channel payout, so it must still be answered after E. This is why the wallet, its watcher or a tower MUST run at least once per watch interval W − B − A − M (4.4) until the channel output is spent by a payout or a current commitment; a member off for longer, with nothing watching, can lose up to the whole channel.
- Ends with: the member takes the whole channel.
- Gaps: W, the penalty form and the second stage are `channel.md`'s.

**O-2. A member publishes an old state.** G · both · Slice 3
1. The honest wallet cannot (X-I5). A modified one can.
2. The host answers with its penalty by its own `penalty_send_by` (H14) and takes the channel; it pays from the swept value.
- Gap: H14 is proposed; the host's W is not yet a term.

**O-3. An old or second tree.** S · both · Slice 1
- Cannot exist in 1.0.0: one tree per funding output, ever (C7); no timed layers, no leaf advances (X-I7). So "the host publishes an old tree state" is not a path, and every payout stays valid for the life of the factory. This is what makes stale copies of the bundle harmless.
- Steps: none. Watches: the funding output; a second tree on it would be S8. Fee: none.
- If a step fails: a member asked to sign a second tree on a live funding output refuses it (C7).

### 7.6 Payments in flight

**P-1. Payments in flight when a channel goes on chain.** G · both · Slice 2 (acceptance), Slice 3 (on chain)
1. Before: an incoming payment is accepted only under 4.4's rule (52 blocks in T1 at d = 2); the host offers none after `host_stop_credit` (design 2); INTERIM, the member accepts none after `payments_stop_at`.
2. A channel goes on chain (the member's exit, the host's forced exit, a breach).
3. Incoming payments not yet fulfilled: left; the host takes them back after expiry (never owed).
4. Incoming payments whose secret the member released: claimed on chain before h; if the host has not removed one by `go_on_chain_by(h)`, that alone starts U-1. The member pays the claim's fee (CH-6).
5. Outgoing payments: reclaimed after expiry; no deadline for the member.
6. Design 2: if no commitment is on chain at E, the channel payout pays the member the whole output: payments in flight are resolved in the member's favour.
- Host side (H18): its expiry delta toward a member covers that member's whole path.
- If a step fails: a coinless member may not afford a claim; such payments are capped (`UNPROTECTED_MAX`, 1% of the channel, at most 10,000 sat) and shown as "not protected on chain".
- Gaps: the claim transactions are `channel.md`'s (CH-6).

### 7.7 Trouble on the way

**X-1. A reorganisation during an exit or a payout.** G · both · later (regtest)
1. A step or payout reorganised out counts as missing again; dates are recomputed; anything due is sent at once.
2. Steps and payouts are rebroadcast every block; burial of B is the only depth counted.
3. Design 2: a host's commitment reorganised out after E lets the payout compete again (H-2); the member is indifferent.
- Gaps: a reorganisation that removes a commitment after burial (INTERIM: lets the host's timeout in); a penalty reorganised out; B = 3 is a signet figure.

**X-2. Fees spike and pre-signed transactions are stuck; pinning.** G · both · test S12, regtest
1. With a coin: a wallet child on the step's anchor, replaced upward every `CLIMB` blocks within the budget.
2. Without a coin: the anchor-only child; under design 2, for a payout, a child on the payout's own output once unlocked (5.3). Shown early as `exit_needs_fee_coin`, when late as `exit_step_late`.
3. Pinning: a foreign child on an anchor (S9b) is out-paid if the member can, otherwise `exit_step_held_back` (5.5).
4. **The free pin by the next level** (5.5): someone broadcasts the next pre-signed level as the only child of an unconfirmed step. Within 5.9's bound (which a member enforces at signing) the anchor-only child evicts it; a member that joined above the bound (none should) needs a spare coin for a wallet child that evicts it (5.5), else `exit_step_held_back`.
- If a step fails: design 2, a stuck payout only waits; a stuck payment claim or penalty can lose that payment or the penalty's gain. INTERIM, a stuck path can lose the balance at H_leaf.
- Gaps: package broadcast in the chain port; public package endpoints (only mempool.space); M_spike unmeasured.

**X-3. The wallet is locked through a date.** S · both · Slice 3 (S15)
- **Design 2**: 1. the watcher holds the payouts (6.6); 2. from tip E it publishes them with anchor-only children; 3. the balance is paid without an unlock; 4. the person must unlock only for released payment claims, a breach's second stage, sweeps and own-output bumps.
- **INTERIM**: the watcher publishes the tree path by `leave_by_locked`; the person must unlock by `unlock_by` (E − 42 at d = 2 with the tree steps on time); after H_leaf a dishonest host takes the balance; an honest host closes with its commitment (H17) and the balance waits.
- Watches: as 6.6.

**X-4. The wallet is not running through a date.** S · both · Slice 3
- **Design 2**: the end date costs the member nothing: the host forces it out before E (the balance waits on the host's commitment) or, at E, anyone holding the payouts publishes them (the host may; a sibling's payout above pays the member too), and if nobody does the outputs stay unspent until the member publishes them. **But a switched-off wallet with no watcher or tower answers no revoked host commitment**: if the host publishes one (before or after E) and nobody penalises it within W, the host takes its share of that older state, up to the whole channel (O-1). So the wallet, or a watcher or tower holding the penalty file, MUST run at least once per watch interval until the channel output is spent by a payout or a current commitment. Off for longer than that is a stated loss case (5.8, `safety-rule.md` 11).
- **INTERIM**: nothing is published; an honest host forces the member out (H17); a dishonest host takes the balance from H_leaf + 1. `open_app_by` warns while the app runs.

**X-5. Restore from backup in the middle of a factory.** G · both · Slice 3 (S20)
1. New restore epoch; nothing signed with old keys.
2. The tree path and payouts are armed (never stale).
3. The commitment is never published automatically; the member asks the host to close with its own commitment.
4. Design 2: if the host does not, the wallet waits for E and the payouts pay it; it publishes them from its bundle or from the host's copy (R7), and finds and spends the outputs by its normal gap-limit scan, since they pay its payout scripts (3.4, 6.7). INTERIM: at `host_force_by` the person is offered the choice with the exact risk.
- Gaps: factories joined after the backup (R7; open point 10).

**X-6. A withheld close is published later.** S · both · later; test S28
1. A co-signed friendly close or rotation close the host kept back confirms later (class S6).
2. It is in the member's exposed set; payments were refused from signing (C13); it pays the member what it was owed. Recorded; nothing to sweep.
- Fee: the host, through the close's anchor. Watches: the funding output, the close's known txid (B9).
- Design 2: if it confirms after E, it competes with the distribution transaction; either pays the member at least its balance.
- If a step fails: a member that kept accepting payments after signing would be paid only the close's amount; C13 is what prevents it.

**X-7. A member owed nothing goes silent.** S · both · test S29
- **Design 2**: the member's payouts still pay it its capacity at E. The host must get its signature (E-1, E-3) or force it out before E (H-1), at its own cost: the free-seat problem (`safety-rule.md` 14 point 2; open point 7). The member's wallet, when it runs at or after E, publishes the payouts (6.1 `payout`).
- **INTERIM**: no automatic exit (publishing would end its place for nothing); the host recovers by timeout (E-5). Every Slice 1 member is in this case.
- Fee: design 2, the host's forced exit, or the member's anchor children at E. Watches: as any live factory.
- If a step fails: design 2, a host that neither forces nor closes loses the capacity; INTERIM, nothing is owed, nothing lost.

**X-8. A spend nobody can explain.** S · both · Slice 3
1. Any spend of a watched output that fits no class of section 8: `unexplained_spend`, `at_risk`.
2. Payments stop; the exit or payout goes on by whatever path remains.
- Fee: as the remaining path. Watches: everything, unchanged.
- If a step fails: the spend cannot be explained after review: the amount is recorded as lost and the factory ended (`ended_how` as `local-api.md` decides).

### 7.8 Vanishing, by stage

| Stage | The host vanishes | A member vanishes |
|---|---|---|
| Lobby, before the ready check | The lobby ends; nothing signed | Its seat is dropped; a standby takes it (C-3) |
| Signing, before partial signatures | C-1 | C-1 |
| Signing, after partial signatures | C-2 | C-2, C-3 |
| After every acknowledgement, before funding | C-4 | Nothing changes |
| Funding broadcast, not buried | C-4 or C-6 | Nothing changes |
| Live, owed nothing | Design 2: paid capacity at E (E-7); INTERIM: nothing to lose | Design 2: X-7 (host forces or pays at E); INTERIM: E-5 |
| Live, with a balance | Design 2: E-7; INTERIM: U-3 | Design 2: H-1 or E-6; INTERIM: U-1 (running), X-3 (locked), X-4 (off) |
| During a payment | P-1 | The host goes on chain under H18 |
| During a close or rotation round | `round_unfinished`; design 2 then waits for E unless a payment date needs an exit | The round fails; E-2 for the others, H-1 for it |
| Wind-down | Design 2: wait for E (offer at `HOST_SILENT_WD`); INTERIM: leave alone | E-4 |
| During a member's exit | No effect | — |
| During the host's forcing | Design 2: payouts from E for what is unspent; INTERIM: `host_forcing` | — |

**Rationale for section 7.** A path is only safe if every step names who acts, what they need (a key, a coin, the chain) and what happens when they do not. Draft 2 had one row per path; the audit of 2026-11-14 found the steps scattered over four documents and two paths unspecified (E-6, E-7). Each path above can be checked against the transactions of section 3 alone.

## 8. What is watched, and what a spend means

From the moment the factory is live (and, for creations, from the round), the watch engine watches **by outpoint and by txid, never by script** (every P2A has the same script, and a leaf transaction's input and the channel output share one): the funding txid to B and every funding input; every output on the member's path; every step's anchor while its step is unconfirmed; the leaf's channel and spare-liquidity outputs; under design 2 every payout's txid and anchor once sent; and, after a commitment confirms, each of its outputs. A spend is classified from the spender's bytes, fetched and checked:

| Class | The spend | Meaning | Response |
|---|---|---|---|
| S1 | A path output spent by the expected next path transaction | A sibling's or the host's publication | Mark the step confirmed |
| S2 | INTERIM. A path output or the channel output spent through the host's timeout leaf | The host's timeout sweep (H-2) | Record; loss if anything was owed below. **Cannot occur** under design 2: no such leaf exists |
| S3 | The spare-liquidity output spent by the host after its delay | The host's liquidity (H-3) | Record |
| S4 | The channel output spent by the host's current commitment | The host closed (H-1) | Claim released payments before h; sweep when unlocked. Locked: `host_closed` |
| S5 | The channel output spent by a revoked host commitment | Breach (O-1) | Penalty ladder; then watch its second stage (S10) |
| S6 | An output on or above the path spent by a transaction in the member's exposed set (a friendly close, a rotation close, a cooperative close of the leaf channel) | Owed under that transaction | Record; nothing to sweep |
| S7 | The channel output spent by the member's own commitment | Our exit | Continue 6.3 |
| S9 | An anchor spent: S9a by a child the member built (or a sibling's identical anchor-only child), S9b by anything else | A bump, or pre-emption | S9a nothing; S9b 5.4 rule for foreign children. Never stops payments |
| S10 | A payment output of a confirmed commitment spent (secret, timeout, second stage) | On-chain resolution of a payment | Extract and record any secret; answer a revoked commitment's second stage |
| S11 | A confirmed commitment's non-payment outputs swept | Ordinary sweeps | Record |
| **S12** | Design 2. A shared output on or above the member's payout path spent by its **payout** (lock time E, a known txid) | The end date paid the members under it, the member included | Record the member's output; sweep when unlocked; `paid_at_end_date` when nothing is left on the path |
| **S13** | Design 2. The funding output spent by the **distribution transaction** | The end date paid every member | As S12 |
| S8 | Anything else | Needs the member's signature: every remaining spend of a watched output | `at_risk` `unexplained_spend`; stop payments; continue by any remaining path |

A spend seen only in one server's mempool is acted on only for S5 (answer at once) and for a competitor of a payout at E (6.4 step 2); the rest is recorded once confirmed in the trusted view.

**Requirements.** The member's wallet MUST arm every watch above when a factory goes live and re-arm them at every start, MUST classify every spend before acting, and MUST NOT arm a watch by script. It MUST treat S12 and S13 as payment to itself, never as `at_risk`.

**Rationale.** Classifying by outpoint and known txids is what lets the wallet tell a sibling's harmless exit, the end-date payout and a real attack apart; under design 2 the set of spends that can hurt the member shrinks to S5 and S8.

## 9. The host's side

The host runs the same engines with the roles exchanged, plus these rules (for `safety-rule.md` section 10; proposed unless marked).

- **H6. A deadline for forcing out** (design 2; replaces H17). For every member m the host computes `host_spare_by(m)` and `host_force_by(m)` (4.4). From `host_spare_by(m)`, if m has not moved, left or co-signed a close, the host publishes m's path and then its own latest co-signed commitment, paying from its wallet, so that the leaf transaction has 144 confirmations and the commitment is confirmed by block E − (B − 1), before any payout can be mined. It MUST start no later than `host_force_by(m)`. It stops extending credit to m at `host_stop_credit(m)`. The host MUST NOT start forcing before E_wd unless m asked to leave or the channel failed; the placement rule of 4.4 makes `host_spare_by(m)` fall at or after E_wd.
- **H7. A fee reserve.** The host holds on-chain coins enough to add fees to every path it may have to publish, one coin per concurrent TRUC child.
- **H14. Answering old states.** The host watches every member's channel output and answers a revoked member commitment with its penalty by its own `penalty_send_by`; it signs second-stage penalties when they appear.
- **H15. The sweep schedule.** The host sweeps only what it may take alone: a leaf's spare liquidity 144 blocks after the leaf transaction confirms; its own outputs on commitments after their delays. INTERIM: also an unpublished tree output whose every member below is owed nothing, from its timeout height + 1, never one with an owed member below. Under design 2 there is no timeout sweep: the host recovers the funding by a close all members sign (E-1, E-3).
- **H16. Never replace the funding** (5.7), except the deliberate spend-back of C-5; the funding has a host change output or its own P2A for a child.
- **H17.** INTERIM, **replaced by H6**. With no end-date payout, the host's software never takes a member's balance through a timeout: it forces a silent owed member out with its own latest commitment by draft 2's `host_force_by` (4.5). This is the policy of honest host software, not a protection.
- **H18. Payment delta.** The host's expiry delta toward member m is at least (n + 1)·A + (B − 1) + M_host with n = d + 3 for m's depth (40, 46, 52 blocks at d = 1, 2, 3 with the signet constants [X4]).
- **H19. A commitment the member co-signed** (design 2; new). Every member co-signs the host's commitment at channel open and at every update; the host takes no update without that co-signature, keeps its latest co-signed commitment fully signed and durable, and revokes the previous one only after it holds the next, so the commitment it holds is never revoked [PR #508]. The commitment's anchor is paid from the funder's (the host's) balance [PR].
- **H20. No end-date gain** (design 2; new). The host's software MUST NOT count on anything a payout pays: from E every shared output still unspent is the members'. It MUST record, for every member still in a factory at `host_force_by`, the capacity it stands to lose, and SHOULD force that member out rather than lose it.

**Requirements.** The host MUST follow H6, H7, H14, H16, H18 and H19 under design 2, and H15 and H17 while INTERIM rules apply. A member cannot check these rules; its safety MUST NOT depend on them.

**Rationale.** Design 2 makes the honest host's duties self-enforcing: a host that does not force a silent member out loses that member's capacity, so H6 is in its own interest. H17 was the best available stand-in while the code still lets the host take a balance by timeout; it rests on honesty and is retired with that code.

## 10. Requirements on other specifications

### 10.1 `channel.md` (not written)

CH-1 to CH-10 of draft 2 (section 10.1 there) stand: the member completes its own commitment at any later time while unlocked and never writes a completed one outside the journal (CH-1); a TRUC member commitment with a member-keyed anchor whose child is pre-signed at update time, a 240-sat P2A the fallback (CH-2); the channel's funding output is the leaf's output 0 (CH-3; under design 2 key path only, no timeout leaf); the member's revocation window W for the host's commitments is a channel term (CH-4); penalties as a ladder of fee rates stored at each revocation (CH-5); second-stage claims and coinless members (CH-6); a fully signed first commitment before funding (CH-7); the engine stops at `exit_started` (CH-8); invoices' `min_final_cltv_expiry_delta` (CH-9); anchored families for secrets and commitments (CH-10). New:

| # | Requirement | Why |
|---|---|---|
| CH-11 | The member co-signs the host's commitment at channel open and in every update; an update without it is refused; the member revokes nothing and the host takes no revocation without it (H19) | The host's forced exit (H-1) |
| CH-12 | The member releases no payment secret while any host commitment below the current number is unrevoked [PR #508] | Otherwise the host could close with an older commitment that lacks the payment |
| CH-13 | The host's commitment 0 is co-signed before the payouts are released (3.3) | A member never holds a payout for a channel the host cannot close |
| CH-14 | Under design 2 the member's capacity is the channel output less the payout reserve P(r) (5.9), after the check of 5.9. **The member's wallet (reader) MUST refuse** an incoming HTLC, or a fee change, that would make its balance plus its pending incoming HTLCs exceed that capacity; **the host (writer) MUST** keep its own side at or above P(r) plus its commitment anchors, so it never offers such an HTLC. The reserve stays on the host's side and is never paid to the member over the channel | With BOLT-style reserves the balance could otherwise exceed the capacity by up to about 480 sat at 10 sat/vB in T1, and a host that let E pass would then pay less than the balance (topic 1242 post 2 [S]) |
| CH-15 | CH-4's W is long: at least the member's own minimum, which defaults to 144 on signet and at least 2,016 on mainnet (open point 21); the member's wallet refuses a channel below it | The watch interval (4.4, O-1) |
| CH-16 | The member's output on the host's commitment (`to_remote`) is built from a key of the member's BIP 86 receive chain (the payout script's key, or the next unused index, given at channel open), so that a restored wallet finds it by its gap-limit scan | 3.4; R3 |

### 10.2 `local-api.md`

New values: step kind `payout`; `ended_how = paid_at_end_date`; date kind `end_date_payout` (E + 1) shown in place of `start_leaving_by` under design 2; the design-2 locked headlines of 6.6; the `host_silent` offer (6.1) as a choice, not an attention code at `at_risk`. The member's wording, one line per factory: "This factory ends at block E (about <date>). Before then the host should move you to a new one. If nothing happens, from that date your wallet collects at least <capacity> sats for you, with no help from the host, as long as Gazpacho or your tower runs at least every <watch interval> blocks (about <time>) to answer old states, and you unlock within that time if it asks you to (a host's old state with payments moved out of it needs your passphrase)." The watch interval is also shown at joining and as a date in the strip (`watch_by`: the latest height by which the wallet or a watcher must next run). What it does not cover is stated too: fees above the anchors when a coin is missing; a payout lost by the wallet that the host will not resend. INTERIM: draft 2's values (`leave_by`, `unlock_by`, `exit_missed`) stay for slices under INTERIM rules, with the line "not protected while the wallet is off".

### 10.3 `signing-round.md` and `messages.md`

- The creation round carries payout nonces and partial signatures for the distribution transaction and every shared output's payout (item kind "payout"); the aggregated signatures are released only after every host commitment 0 is co-signed (3.3, CH-13), as a message of their own.
- `safety-rule.md` 12 value 1 and the Slice 1 profile ("refuse a proposal that carries a payout") become, from the design-2 slices, "refuse a proposal that lacks one".
- Purposes 4 (friendly close) and 5 (rotation): a P2A anchor on the close and its fee from the host's share (5.1).
- The understudy fields of C-3.
- The member's `payout_script` record (3.4): 34 bytes, sent in its `ready` beside its contribution key; the proposal carries one per member, in member order, and each member refuses a proposal whose script for itself differs from the one it sent.

### 10.4 `safety-rule.md`

- Section 6 and section 12: state the design-2 target; mark value 1 and value 2 (timeout recovery) INTERIM.
- C5: under design 2 no host-alone absolute-height path exists on any shared output; the spare liquidity is the members' at E, not simply the host's.
- C8 (done in this branch): the channel row checks channel output ≥ max(`channel_sat`, own minimum) + P(r) and the spare-liquidity row P(r) + 330; tree payouts and the distribution transaction pay at least `channel_sat` + P(r); the spare-liquidity payout is excluded from the capacity bound by name; one fee rule (5.9); 4.4's placement rule on the end-height row.
- Section 10: H6 as above; H17 INTERIM (done in this branch); H19, H20 new.
- Section 11: "a wallet left locked past `unlock_by`" and "the host takes a silent member's balance by timeout" INTERIM; "switched off longer than the watch interval" and "the free pin above the rate bound" added (done in this branch).
- C2: the member's own outputs include its payout scripts (3.4). C12 and R3 unchanged.
- Section 14 point 2 (free seats) now applies in full (open point 7).

### 10.5 `terms.md`, `journal.md`, `storage-encryption.md`, the chain port, the core contract

- `terms.md`: E's placement (4.4) for the design-2 slices: E = E_wd + (B − 1) + (D + 3)·A + M_host at least; per-factory limit of 230 members while a distribution transaction is signed; recompute T1-long (open point 1).
- `journal.md`: `exit_plan` gains E and the payout txids; record for payouts sent.
- `storage-encryption.md`: invariant T admits payouts (6.6); bundle step kinds 4 and 5.
- **Chain port**: `gz_chain_broadcast_package` (one parent, one child); per-server broadcast results; mempool spends of watched outpoints (6.4 step 2); one broadcast-only endpoint. The port must say which servers accept packages; today that is mempool.space among public servers and Gazpacho's own signet node.
- **Core contract** (`event.h`, `action.h`): the changes listed in draft 2 10.5 (time on every event; outpoint-spent and transaction-status events; block connected and disconnected; chain state; broadcast result; fee estimate; mempool floor; wallet coins; watch by outpoint and by txid; broadcast package).

**Rationale for section 10.** This draft changes only `exit.md`; every other document keeps its current text until its own pass, and this list is what that pass must do. Nothing here should be implemented from this list alone.

## 11. Tests

### 11.1 Simulator first

Every path of section 7 as a scenario, honest and adversarial, with independent accounting from the confirmed transactions alone (X-I6), under both rule sets where the path has both. In particular, under design 2:
1. E-6 and E-7 at every depth, with nothing published, with the root published (distribution transaction void), with each prefix of the path published, and with the host's next tree transaction or commitment in the mempool at E: every member paid at least its capacity (tree) or output less fee and anchor (channel).
2. H-1 completed before E (the member's balance on the host's commitment), stopped halfway (payouts at E cover the rest), and late (the host's commitment and the payout racing after E: the member gets at least its balance either way).
3. A payout broadcast at tip E − 1 is refused as not final; at tip E accepted.
4. A locked wallet through E: the watcher publishes the payouts; no unlock needed for the balance.
5. A member owed nothing publishes its payouts at E (X-7).
6. Every INTERIM test of draft 2 11.1 while its slices run.
7. Crash at every save point; chain-view cases of 4.6; pinning on a payout's anchor and the own-output bump.

### 11.2 Signet, Slice 1.5

The 27 tests S1 to S13 and S21 to S34 of the exit-path audit (2026-11-14), adopted as written: S1 to S13 (timeout recovery, one path, a second path, untouched branches swept, never funded, funded late, funding below the floor with a host child, funding replaced, abort after partial signatures, abort in the nonce step, restore and replay, a step bumped through its anchor with package submission, two servers disagreeing), S21 to S25 (spend-back, spend-back losing the race, understudy at the ready check, understudy mid-signing, attempts until the budget ends), S26 to S28 (friendly close of an empty factory, with one member silent, withheld then published; if the owner agrees), S29 (a member owed nothing stays away), S30 (locked Slice 1 wallet), S31 (the host's sweep cannot jump the queue), S32 (a stranger's child on an anchor), S33 (S1, S2, S3, S12 again on the TRUC trees of the re-import) and S34 (the end-date payout, after the re-import of #508). S1, S4 and S31 test INTERIM paths and are rerun as their design-2 counterparts after #508: S1 and S4 become "the host recovers by a friendly close or forced exits; whatever is unspent at E pays the members", S31 becomes "the host's commitment and the payout after E" (H-2).

### 11.3 Signet, Slice 3 (needs `channel.md` and #508)

| # | Test | Pass when |
|---|---|---|
| S14 | A member with a balance, every rule off, host stopped, app running | Paid at E by the payouts; amounts ≥ balance less fees |
| S15 | The same, the member's program restarted and left locked through E | The watcher publishes the payouts; no unlock needed |
| S16 | A member with no on-chain coin | Paid with anchor-only children; a payout bumped from its own output after unlock |
| S17 | Host breach while the member is locked, before and after E | The penalty confirms by `penalty_send_by` |
| S18 | H6: a silent member with a balance | The host starts forcing it out at `host_spare_by`, its commitment confirmed by E − (B − 1) and the leaf's spare liquidity swept before E + 1; the balance sits on the host's commitment; no channel or spare-liquidity payout confirms for that leaf |
| S19 | An incoming payment pending at `payments_stop_at` | Settled or failed back; none accepted after |
| S20 | Restore from an old backup | No automatic commitment; at E the payouts confirm to the member's payout scripts and the restored wallet finds and spends them by its gap-limit scan |
| S35 | The host withholds the aggregated payouts | No member acknowledges; no funding; every member Abandoned, then Dead (C-4 step 5) |
| S36 | A revoked host commitment published after E while the member's wallet is off and only its watcher (or tower) runs once per watch interval | The penalty confirms by `penalty_send_by`; without the watcher the loss is recorded (the stated case) |

### 11.4 Regtest (M5)

Every member paid at once at E with full mempools at 128 and 230 members (the distribution transaction's limit) and at 512 members with the root published; a reorganisation of depth B − 1 and B across the host's forced commitment near E; a fee spike lasting M_spike + 1 blocks; pinning on a payout's anchor at the 234-sat threshold and its own-output bump; the free pin by the next pre-signed level at tree rates 1, 1.047, 1.048, 1.395 and 2 sat/vB on Core 29.0 and 29.1 nodes, with and without a spare coin; forcing every member of a 230-member factory in one window after E_wd (block space and H7's coin count, open point 31); package submission against a node below and above 29.1.

### 11.5 Vectors

Section X of `tools/spec-vectors.py` (X1 to X9) is unchanged and still checks the INTERIM numbers. **Owed** (open point 15): X10, the design-2 dates of 4.4 (`host_spare_by`, `host_force_by`, `host_stop_credit`, the placement rule of 178, 184 and 190 with S_spare 144) for T1 and T1-long; X13, R(root) with the payout reserve (804,835 at 4 members, 0.1 sat/vB) and P(r) at 125 vbytes; X14, the free-pin bound ⌊175,000 / V_occ⌋ (and ⌊233,000 / V_occ⌋ on 29.1); X11, the payout's size, fee and the anchor-only package rate; X12, the distribution transaction's size at 3 to 230 members against the TRUC limit.

## 12. Open points, with owners

"Owner" is the project owner; "upstream" is SuperScalar's maintainer, asked by hand-off only, never in public.

| # | Point | Owner | Recommendation |
|---|---|---|---|
| 1 | Terms for the design-2 slices: E placed `host_spare_by` after the wind-down (4.4), and T1-long recomputed now that a member's `leave_by` is gone (draft 2's 252-block wind-down was sized for INTERIM `move_by`) | Owner; `terms.md` | Place E = E_wd + 190 at D ≤ 3 on signet (S_spare 144) (decision of 4.4, pending the owner); recompute T1-long with X10 |
| 2 | `move_by` under design 2 depends on the host's `host_force_by`, which the member cannot check | Owner; `MULTI-FACTORY.md` | Publish the host's A, B and M_host in the terms, so the member can compute it |
| 3 | Whether #508 gives the leaf kickoff's output into the leaf transaction a payout (it gives none to "a kickoff's output into its own state transaction") | Upstream (#508); this spec | Ask; 6.4 handles both |
| 4 | **Closed 2026-11-16 by 5.9**, owner to confirm. Was: the channel payout pays the output less its fee and anchor (253 sat in T1 at 0.1 sat/vB, 1,480 at 10), below a full balance. Now the host funds that fee and anchor as the reserve P(r) above the capacity, so every payout pays at least the capacity (C8) | Owner; `safety-rule.md`; upstream (#508) | Adopt 5.9; ask upstream (#508) only for the one-member payout's exact size, and to size the channel output as capacity plus P(r) when it builds payouts |
| 5 | **Closed 2026-11-17 by 3.4, pending the owner's confirmation.** Was: the payout's destination. Now: a 34-byte P2TR script from the member's BIP 86 receive chain, a fresh index per factory, named in the round | Owner; upstream (#508) | Ask upstream to accept a payout script per member, as for the channel script |
| 6 | `host_silent` under design 2: an offer, not an automatic exit | Owner | Adopt: an exit costs fees the payouts avoid |
| 7 | Free seats: a silent member owed nothing still costs the host a forced exit or its capacity at E | Owner; upstream | Land the proof-of-coin step with the payouts (`safety-rule.md` 14) |
| 8 | Fee budget: 25% of the recovered amount, 90% once late | Owner | Adopt |
| 9 | Fee coins set aside for a locked exit or payout | Owner | Off by default; offered on `exit_needs_fee_coin` |
| 10 | Factories joined after a backup: the host hands back the signed tree and payouts (R7) | `safety-rule.md`; upstream | Specify with the restore pass; ask whether upstream's recovery data includes payout signatures |
| 11 | A release the member can co-sign alone after paying across, so the host recovers without forcing | Owner; upstream | Design it with rotation (M4); until then the host forces or closes with everyone |
| 12 | A friendly close with one member missing: one funding output needs every signer, so no close of the rest exists | `signing-round.md`; owner | Specify the fallback: the others move by paying across (E-2), the missing member is forced out (H-1) or paid at E |
| 13 | Understudies in `messages.md`, `journal.md`, `signing-round.md` | `signing-round.md` | Bring in with the next pass |
| 14 | Package relay: only mempool.space offers a public package endpoint; our own signet node otherwise | Owner; chain port | Build `gz_chain_broadcast_package`; S12 records which servers accept packages |
| 15 | Vectors X10 to X12 for the design-2 formulas | This spec | Add with the review round's fixes |
| 16 | When #508 lands, and the commit to import; whether the 230-member limit stays | Upstream | Ask by hand-off; re-import once it merges |
| 17 | Mainnet constants (B, A, M_spike, `WARN_LEAD`, `OPEN_MARGIN`, M_host) | Owner | From signet and regtest measurements, before any mainnet build |
| 18 | The member's default fee-rate ceiling now that the host pays (5.9) | Owner; `safety-rule.md` C8 | The term's ceiling, 1,000 sat/vB, as a sanity bound; the member's real fee limit belongs on the chain-cost joining fee (term 70) |
| 19 | Which rate a host should choose, given that a member leaving alone spends the host's prepaid path fees and that rates above 175 / V_occ sat/vB make the free pin of 5.5 possible | Owner | 0.1 sat/vB by default; 1 sat/vB at most in T1 (below the 1.047 sat/vB bound); measure on regtest with the #46 helper before adopting |
| 20 | A fee ladder of pre-signed tree transactions | Owner | After 1.0.0 |
| 21 | The watch interval: W as a long channel term (CH-4, CH-15), its defaults, a tower for host commitments under H19, after E included (H1 of the review) | Owner; `channel.md` | W ≥ 144 on signet, ≥ 2,016 on mainnet; tower holding only the penalty file |
| 22 | Placement against `host_spare_by` (decided, pending the owner), or accepting that forced members keep the spare liquidity | Owner | Keep the decision of 4.4 |
| 23 | The member withholds its funding acknowledgement until it holds the payouts (3.3) | `signing-round.md`, `messages.md` | Add the payouts message before `round_ack` |
| 24 | Which capacity the builder and the tree payouts use (`channel_sat` + P(r)), and R(leaf) under design 2 (`terms.md` 4.2, 4.4) | `terms.md`; upstream (#508) | As 5.9; vector X13 |
| 25 | Who enforces CH-14's balance cap | `channel.md` | Both: the member refuses, the host keeps its side above P(r) |
| 26 | The free pin by the next pre-signed level at host-chosen rates | Owner | Adopt, as now written: the host MUST NOT and the member refuses above ⌊175,000 / V_occ⌋ sat/kvB (1,047 in T1, valid on Core 28.x and 29.0); SHOULD keep 0.1 sat/vB |
| 27 | **Withdrawn 2026-11-17**: recovery keys contradict R2 and R3; replaced by the payout script of 3.4 (open point 5) | — | — |
| 28 | Which fee rule is in force on which import: one `fee_per_tx` on `e6573950` (INTERIM), own size from #46 on | `terms.md`, `safety-rule.md` | As 5.9 |
| 29 | The payout's sighash and output-size assumptions behind P(r) (125 vbytes) | Upstream (#508) | Ask with open point 4's remainder |
| 30 | Detecting servers that refuse version 3 or P2A (5.9) | Chain port | `chain_no_truc_server`; keep one known TRUC endpoint |
| 31 | Mass forcing at E_wd in a 230-member factory: block space and H7's coin count when every member is forced in one window | Owner (host side) | Measure on regtest; host terms state how many it can force per block |

## 13. Review checklist

1. Section 3.1: does every shared output of a 1.0.0 tree have a payout with lock time E, and no host-alone absolute-height path, in the code being imported? Which outputs have none (open point 3)?
2. Section 4.1: is a payout with lock time E final in block E + 1 and accepted into a mempool at tip E?
3. Section 4.4: is `host_force_by` enough for the host to bury its commitment before E + 1? Is the placement rule enough for every member of a factory, forced in parallel?
4. Is it true that after E every spend of a shared output on a member's payout path pays the member at least its balance (the channel payout paying at least the capacity, 5.9), **except a revoked host commitment, which only a penalty within W answers** (O-1)? List every competing spend.
5. Can any INTERIM rule be mistaken for a design-2 rule, or be relied on with real funds?
6. Section 5.8: is any property listed as enforced actually assumed?
7. Section 6.6: can a payout in the bundle, in any old copy, move value away from its rightful owner?
8. Section 6.4: can a member ever void its own or a sibling's payout by what it publishes?
9. Section 7: does every one of the 35 paths name, for every step, who acts, which transaction, the lock time or deadline, who pays and how, what is watched, and what follows a failure?
10. Section 8: does it classify every possible spend? Is S8 truly impossible without the member's key?
11. Section 9: do H6, H19 and H20 contradict H1 to H18?
12. Is any safety claim here stated without a mark, or stronger than its source?

13. Section 4.4: does the placement of 190 blocks at D = 3 let the host sweep every forced member's spare liquidity before E + 1? Section 5.5: is ⌊175,000 / V_occ⌋ the right eviction bound on Core 28.x and 29.0? Section 3.4: can a payout script ever be reused across factories, or be missed by a restored wallet's scan?
