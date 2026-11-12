# Leaving alone and watching

Specification draft 1, 2026-11-12. Status: **not reviewed**. It specifies the exit, watch, schedule and lifecycle engines of `docs/DESIGN.md` section 5 for 1.0.0, as far as leaving a factory is concerned, and the host's matching duties. Its main input is the path study `notes/factory-paths.md` (the path table of its section 1, gaps 1 to 12 of its section 3.2, the Slice 1.5 plan of its section 4). Values marked **proposed** are this draft's; values marked **[M]** are to be measured on signet before they are relied on. Nothing here has been run. It already takes in the review of `storage-encryption.md` draft 1 (its findings F1, F2 and F4): the watch-and-exit bundle holds no commitment of the member's own, so a locked wallet publishes the tree path but needs an unlock for the last step (section 5.6).

Companion documents: `safety-rule.md` (draft 4), `signing-round.md` (draft 4), `terms.md` (draft 2), `journal.md` (draft 2), `storage-encryption.md` (draft 1, written at the same time; its section 8.7 defers the bundle's records, the fee ladder and the "lock with payments in flight" question to this document), `local-api.md` (draft 2), `docs/MULTI-FACTORY.md`, `docs/THREAT-MODEL.md`, `docs/handoff/2026-11-12-tree-fees.md`. The channel specification (`channel.md`) does not exist; section 10.1 lists what it must give this one.

Marks: **[C]** read in the imported code (file and line, pin `e6573950`); **[S]** checked in a primary source; **[R]** reasoning, not checked by a source or a test; **[M]** a value to measure; **[X]** computed by `tools/spec-vectors.py` section X.

## Contents

0. The design in brief
1. Scope
2. Terms
3. The engines and their contract
4. Deadlines
5. The automatic exit
6. Fees at exit
7. Every path 1.0.0 can reach
8. What is watched, and what a spend means
9. The host's side
10. Requirements on other specifications
11. Tests
12. Open points for the owner
13. Review checklist

---

## 0. The design in brief

- **One deadline per member and factory.** In a 1.0.0 tree every interior level is fixed and every leaf is a one-member pseudo-Spilman leaf (`safety-rule.md` C8). There are no relative timelocks in the tree. The only competing claim on a member's path is the host-only timeout of the member's leaf, at **H_leaf = E − 10·d**, where E is the end height and d the depth of the member's leaf [C, X1]. The member's commitment must be buried before the host's timeout spend can be mined.
- **Start leaving by** = H_leaf − (B − 1) − n·A − M, where n = d + 3 is the number of transactions on the path still missing (d fixed kickoffs, the leaf kickoff, the leaf transaction, the commitment), A the confirmation allowance per transaction (one level per block at least, under TRUC's one-parent-one-child rule), B the burial depth, and M the sum of the margins for safety, chain-view lag and fee spikes (section 4). For Slice 1's terms this falls 50, 66 and 82 blocks before E at depths 1, 2 and 3, which is **before T1's lifetime ends**: T1's 36-block wind-down is too short for an exit with a balance (section 4.6, open point 1).
- **The automatic exit** starts at that height, or earlier on stated triggers (section 5.1). It never waits for the host, for the person, for a trusted chain view, for a fee estimate or for the planner. Pause never stops it; no 1.1.0 rule can disable or postpone it.
- **It publishes only the member's own path**, one level per block, each level at its pre-signed fee with a keyless **anchor-only child** that spends the level's 240-sat pay-to-anchor output as its whole fee (65 bytes, needs no key and no coin; section 6.2, [X6]). With the member's own on-chain coins it bumps at market rate through the same anchor. Without coins it says so plainly and early, never as a stall.
- **A locked wallet does what needs no key, and says by when to unlock.** The watcher of `storage-encryption.md` 8.7 runs from a separately sealed **watch-and-exit bundle** of already-signed transactions; this document defines the bundle's records (section 5.6). The bundle **never holds a commitment of the member's own**: every commitment is later revoked, and an old copy of the bundle would let anyone publish a revoked state and lose the balance to the host's penalty. So a locked wallet publishes the tree path with its anchor-only children by the dates and answers the host's old states with pre-signed penalties; the last step, the member's commitment, needs the passphrase, and the strip names `unlock_by` (E − 42 for a T1 member at depth 2).
- **Watching** knows every outpoint on the member's path and its channel, and classifies every spend (section 8): a sibling's exit (continue as normal, fewer steps left), the host forcing the member out (finish the path), an old state (penalty), the host's timeout (loss, recorded), a co-signed close (owed elsewhere), a funding reorganisation.
- **The host** answers old states, sweeps its spare liquidity and timeouts on a schedule, never replaces the funding by fee, and, proposed for 1.0.0 without the end-date payout, never takes a silent member's balance through the timeout: it forces the member out with its own commitment by `host_force_by` instead (section 9, open point 2).

## 1. Scope

**In.** 1.0.0 as decided: advanceless trees (owner decision 9), one member per pseudo-Spilman leaf (K = 1), no sales, no leaf advances, rotation as the only way to extend a life, no end-date payout (`safety-rule.md` 12 value 1), the channel inside the leaf a standard taproot channel (`DESIGN.md` 8). Members only send and receive; they do not forward (study 1.6).

**Paths.** Every path of the study's table that 1.0.0 can reach: U-a (member leaves alone, every depth), U-a' (part of the path already on chain), U-b (siblings), U-c (everyone leaves), H-a (host forces a member out), H-b (host timeout sweep), H-c (spare liquidity), L-a, L-b, L-c, L-d (the leaf channel), C-e to C-h (creations never funded, funded late, reorganised), E-b and E-e (left behind at rotation), E-c (host recovery), M-a, M-c, V-b. Section 7.

**Out.** Timed layers, leaf links and poison (1.1.0); the end-date payout (not imported; when it lands every tree txid changes and section 4 gains a second competing claim, `safety-rule.md` C5); the cooperative close and the rotation close as rounds (`signing-round.md` 5; their effect on watching is covered in section 8); the channel engine itself (section 10.1).

## 2. Terms

| Term | Meaning |
|---|---|
| **E** | The tree's end height, the import's `cltv_timeout` (`messages.md` 7.2 record 24) |
| **d** | The depth of the member's leaf: the root is depth 0. Members of one factory can have different d (at 3 members, depths 1, 2, 2; [X2]). D, the deepest d, is `fixed_levels` |
| **Path** | The member's held exit transactions in order: the fixed kickoffs at depths 0 to d − 1, the leaf kickoff (depth d), the leaf transaction (the pseudo-Spilman leaf, depth d), then the member's latest commitment. n = d + 3 transactions |
| **Step** | One transaction of the path, with its children (fee) and its state: `pending`, `due`, `sent`, `confirmed`, `buried` (`local-api.md` 16.3) |
| **Missing** | A step not confirmed in the trusted chain view. `n_missing` counts them; steps confirmed by anyone (a sibling, the host) are not missing |
| **H_leaf** | The height in the timeout leaf of the leaf transaction's input and of the channel output: E − 10·d (section 4.1) |
| **Last safe confirmation** | H_leaf − (B − 1): the highest block in which the commitment may confirm and still have B confirmations at tip H_leaf, before block H_leaf + 1, the first in which the host's timeout spend can be mined |
| **`leave_by`** | Start leaving by (`local-api.md` date kind `start_leaving_by`). Section 4.4 |
| **Tip estimate** | The height the engines judge deadlines by: the trusted tip, or, while the chain view is in doubt, a bounded higher estimate (section 4.5) |
| **Anchor-only child** | The keyless 65-byte child of section 6.2 |
| **Bundle** | The watch-and-exit bundle `watch.gzw` (`storage-encryption.md` 8.7), records in section 5.6 here |
| **Watcher** | The small loop that runs from the bundle while the wallet is locked (`storage-encryption.md` 8.7.1) |
| **Exit started** | The moment the journal records `exit_started` for a channel. From then the channel signs nothing new (section 3.4) |

## 3. The engines and their contract

### 3.1 Four engines and one loop

All four are core engines: events in, actions out, no system calls (`DESIGN.md` 4). They share one journal and one runner.

| Engine | Job | Reads | Writes |
|---|---|---|---|
| **Schedule** | Computes every date of section 4 for every factory and channel, after every block, chain-state change, channel update and terms or conditions change. Raises triggers (section 5.1) | Factory records, the channel's latest state, chain events, the clock | `exit_plan` (dates), notices, the bundle's B5 dates |
| **Exit** | Runs one exit per channel: which step is due, building and replacing fee children, rebroadcasting, recording progress, ending | `exit_plan`, chain events, wallet coins, fee estimates | `exit_started`, `exit_step`, `fee_child`, `coin_reserved`, `exit_ended` |
| **Watch** | Knows every outpoint and txid that matters (section 8) and classifies every spend. Answers old states with penalties | Held and exposed sets (`safety-rule.md` 2), chain events | `spend_seen`, `response_sent`; requests to the exit engine |
| **Lifecycle** | The factory's state (`local-api.md` 16.1 `state`) and its transitions, including `awaiting_funding` → `live` (C11), `funding_reorganised`, `abandoned`, `dead`, `exiting`, `ended` with `ended_how` | All of the above | `factory_state`, `funding_status` (existing, `journal.md` 9) |
| **Watcher** (locked only) | Not an engine of the node: a loop over the bundle, the chain port and the broadcast port while the node is stopped (`storage-encryption.md` 8.7). Runs sections 4, 5.3 (tree steps only) and 6.2 from the bundle alone; never the commitment (5.6) | The bundle, the chain port, the clock | `watch.gzl` only |

The node and the watcher never run at once (section 5.6, rule W1).

### 3.2 Inputs

Events the engines need. Those marked **new** are not yet in `core/gazpacho/include/gazpacho/event.h` [C: `event.h:16-28`], which has only "script spent", "transaction confirmed" and "new tip"; `signing-round.md` 12.1 already requires the first two rows.

| Event | Fields | Source | New? |
|---|---|---|---|
| Transaction status | txid; `unknown`, `mempool`, or confirmed at height and block hash; checked confirmations (`gz_chain_confirm_tx`); whether the chain view was trusted | Chain port, on a "watch txid" action | Required by `signing-round.md` 12.1 |
| Outpoint spent | outpoint; spending txid and input; its status as above; the spender's raw bytes, fetched and hashed by the program (chain port note, "Spenders") | Chain port, on a "watch outpoint" action | Required by `signing-round.md` 12.1 |
| Block connected | height, block hash, previous hash | Chain port | New (today: "new tip" with a height only) |
| Block disconnected | height, old hash | Chain port | **New**. Needed for C-g, C-h and for steps reorganised out |
| Chain state | `connection.chain.state` (`local-api.md` 11.2) and, per server, the claimed tip and when it was seen | Chain port | **New** |
| Broadcast result | txid; per server: accepted, already known, refused with the server's reason text | Chain port | **New** (today a broadcast is fire-and-forget) |
| Fee estimate | target blocks → sat/kvB, as `gz_chain_choose_fee_rate` returns it; fixed 100 sat/kvB on test networks | Chain port | **New** |
| Mempool floor | the servers' minimum accepted fee rate, when they report it | Chain port | **New**, optional |
| Clock | wall time with every event (the runner already hands time to the core, `DESIGN.md` 4) | Runner | — |
| Wallet coins | the on-chain wallet's confirmed free coins | Wallet | **New** for the core (today the wallet is outside it) |
| Channel facts | latest own commitment number and bytes, payments in flight with expiries and whether their secrets are released | Channel engine | Internal |
| Host link | last valid message from the host (any kind, including `pong`) | Node | Internal |
| User | "leave alone now" (`local-api.md` 16.3), "speed up" (16.4), settings | Local API | — |

### 3.3 Outputs

| Action | When | New? |
|---|---|---|
| Save a batch | Before every action below that leaves the program (save before send, `DESIGN.md` 4) | — |
| Watch a txid to a depth; watch an outpoint | Section 8; armed at start and re-armed by the start step | Required (`signing-round.md` 12.1) |
| Broadcast a transaction | A step, a child, a penalty, a sweep. Sent to every server of the right network (chain port, section 5) | — |
| **Broadcast a package** | A parent the servers refuse alone, with its child (section 6.8) | **New**; needs `gz_chain_broadcast_package` |
| Set a timer | Re-check at a clock time (section 4.5) | — |
| Tell the user | A notice with a code of `local-api.md` 11.4 or one of section 10.2 | — |
| Ask the channel engine to stop | At `exit_started`: no new update, no revocation | Internal |
| Write the bundle | Implicit: the storage layer rewrites `watch.gzw` before confirming any batch that changes its contents (`storage-encryption.md` 8.7.4) | Storage duty |

### 3.4 What is saved before anything leaves

Record names only; numbers are assigned in `journal.md` draft 3. Every record carries the factory's local number and the channel.

| Record | Fields | In the batch that | Before |
|---|---|---|---|
| `exit_plan` | d; path txids in order and which output of each the next spends; anchor output index per step; H_leaf; the constants in force (B, A, M_safe, M_lag, M_spike, M_locked); the dates of section 4.4 | makes the factory live (C11), and again on every date change | The bundle's B4 and B5 are written from it |
| `exit_started` | reason (section 5.1 code); tip estimate and trusted tip; chain state; the commitment number chosen | decides to leave | **the first broadcast of the exit**, and the channel engine's stop. Once saved, the channel never signs another update or releases another revocation for that channel [R: so the commitment chosen can never become revoked] |
| `exit_step` | step index; txid; `sent` with height and time, or `confirmed` with height and block hash, or `buried`; the server results | records each state change | each (re)broadcast of a step is preceded by its `sent` record once; rebroadcasts of the same bytes need no new record |
| `coin_reserved` | wallet outpoints used by a child | builds a wallet-funded child | that child's broadcast. A reserved coin is never offered to any other spend until the child is dead or `exit_ended` |
| `fee_child` | parent txid; child bytes; package rate; fee; which child it replaces | builds or replaces a child | that child's broadcast |
| `spend_seen` | outpoint; spender txid; classification (section 8) | records a classification | any response |
| `response_sent` | trigger txid; response bytes; deadline | answers | the response's broadcast |
| `exit_ended` | `ended_how` (`local-api.md` 16.1); amounts recovered from the confirmed transactions | ends | — |
| `bundle_written` | bundle counter, as `storage-encryption.md` 8.7.4 rule 4 needs | rewrites the bundle | — |

A broadcast of a fully pre-signed transaction cannot cost the member money by being repeated, but recording it first is what lets the start step resume an exit in progress after a crash, and what makes `exit_started` irreversible.

### 3.5 The start step

After every start, before any message to the host, the node: re-arms every watch of section 8; recomputes every date from `exit_plan` and the chain; merges `watch.gzl` if the watcher ran (rule W3, section 5.6); for every channel with `exit_started` and no `exit_ended`, rebroadcasts every `sent` step and its current child, and resumes section 5.3; re-arms every pending response. A restart never resumes payments on a channel with `exit_started`.

### 3.6 Invariants (checked by the simulator after every step)

- **X-I1.** Every live factory in which the member has anything owed has an armed exit: an `exit_plan` whose `leave_by` the schedule engine recomputed at the current tip estimate, and a bundle (unless the person chose "maximum privacy", section 5.6) holding its path. This is `MULTI-FACTORY.md`'s invariant "every factory always has an armed exit that meets its `start_leaving_by`".
- **X-I2.** No action leaves before the batch that records it is confirmed.
- **X-I3.** After `exit_started`, the channel engine has produced no commitment signature and no revocation for that channel.
- **X-I4.** No bundle ever written holds a commitment of the member's own, or anything from which one could be completed (W2; byte search of every bundle version a run writes).
- **X-I5.** The node never broadcasts a commitment of its own other than the highest-numbered one it holds and has not revoked; after a restore, never one at all without the person's choice (section 5.7).
- **X-I6.** The simulator's independent accounting, from the confirmed transactions alone, finds the member's recovered amount equal to its owed amount less fees, on every honest path, at every crash point.

## 4. Deadlines

### 4.1 The timeouts in a 1.0.0 tree, exactly

From the import [C: `src/factory.c:1475` `TIMEOUT_STEP_BLOCKS 5`; `:1635-1644` ko and st heights; `:1669` a leaf is never a fixed node; `:1683-1686` fixed nodes; `:1749-1754` the leaf's kickoff and state pair; `:1314` the channel output copies the leaf node's spending script; `:185-214` a node's script has a timeout leaf exactly when its height is above 0]:

- A node's timeout protects the output **that the node spends**: its parent's output to it carries `<h> OP_CHECKLOCKTIMEVERIFY OP_DROP <host> OP_CHECKSIG` with the node's height h.
- A fixed kickoff at depth j ≥ 1 has h = E − 5·(2j − 1). The root kickoff (j = 0) has none; it spends the funding output, which is key-path only (C1).
- The leaf's kickoff at depth d has h = E − 5·(2d − 1); the leaf transaction (a state node) has h = E − 10·d; the leaf's channel output has the leaf transaction's script, hence the same h.
- Tree transactions have version 2 and lock time 0 [C: `tx_builder.c:77`, `:103-114`], with nSequence `0xFFFFFFFE` (fixed kickoffs and the pseudo-Spilman leaf) or `0xFFFFFFFF` (the leaf's kickoff) [C: `src/factory.c:129-140`]: each is valid as soon as its parent confirms.
- The host's timeout spend has lock time h [C: `src/factory.c:4856-4861`], so it can first be mined in block h + 1.

So on a member's path every timeout is at least E − 10·d, and the smallest is shared by the leaf transaction's input and the channel output:

```
H_leaf = E − 10·d
```

[X1] prints the table for d = 1, 2, 3. **Correction:** `safety-rule.md` C5 and section 12 value 2, the study (section 0 and U-a) and `MULTI-FACTORY.md` 4.1 say "less 5 blocks per tree transaction of depth" or "E less the exit time". With fixed levels each depth adds one kickoff but the step is still 10 per depth (the import's formula was written for kickoff and state pairs), and the leaf has two transactions. The deadline is E − 10·d, not E − 5·d and not E (section 10.5).

### 4.2 The path and its length

n = d + 3 transactions: d fixed kickoffs, the leaf's kickoff, the leaf transaction, the commitment [X2]. In T1: d = 1 or 2 at 3 members, d = 2 at 4 to 8 members (one interior level of width 4 above 4), d = 3 at 9 to 16. Sizes in T1: a kickoff with k outputs and its anchor is 81 + 43·k vbytes signed (167 for two outputs, 253 for four, 124 for the leaf's kickoff), and every tree transaction pays the same `fee_per_tx` (17 or 26 sat in T1, `terms.md` 4.2) [X2].

Under TRUC (BIP 431, one unconfirmed parent and one unconfirmed child [S: tree-fees hand-off F6, F12, F13]) each level must confirm before the next can be sent, because the level's fee child takes the parent's only descendant slot. The import's tree is version 2 today, where longer chains relay; section 5.3 still sends one level per confirmed parent, so the arithmetic below holds for both and matches the reference's recovery [S: SuperScalar `src/factory_recovery.c:246-257` at `490ed626`]. **So an exit takes at least one block per missing step**, plus burial of the last.

### 4.3 The constants

| Name | Signet value | Meaning, and why this value | Mainnet |
|---|---|---|---|
| `TIMEOUT_STEP` | 5 | The import's step [C]. Not a choice | 5 |
| **B** | 3 | Burial depth of the commitment (and of a penalty) before its competing claim opens. Same as the funding's (`safety-rule.md` 12 value 3): signet is mined by a fixed signer set and reorganisations deeper than a block or two are not expected | Open (proposed 6) |
| **A** | 6 [M] | Confirmation allowance per transaction: one block minimum, plus time to notice, rebroadcast and climb at most two fee steps. `safety-rule.md` 12 value 6 used 6 for C8. To measure in S2: blocks from first broadcast to confirmation at 0.1 sat/vB with the anchor-only child, median and maximum over every step of every run | Open: set from the fee climb of section 6.4 |
| **M_safe** | 6 | General margin, as `safety-rule.md` 12 value 6: a restart, a slow save, a broadcast repeated once | Open |
| **M_lag** | 2 [M] | Chain-view lag: the chain port tolerates one block between servers (`tip_slack` 1) and treats persistent lag as disagreement; one more block for the time to notice that | 2 |
| **M_spike** | 6 [M] | Fee spike: blocks a spike may outlast the allowance before the member's bump takes effect. Signet cannot produce a spike (study 4), so this is a placeholder sized like A; the regtest spike test sets it | Open (proposed 144: a day) |
| **M** | 14 | M_safe + M_lag + M_spike | — |
| **M_locked** | 0 | Extra lead for the locked watcher, which cannot pay market fees without set-aside fee coins (section 5.6). 0 on signet, where 0.1 sat/vB confirms | Open (proposed n·A) |
| **M_host** | 8 | The host's margin: M_safe + M_lag. The host holds a fee reserve (H7), so no spike margin. Makes `host_force_by` fall after the member's own `leave_by` | Open |
| `PAY_STOP` | 6 (= A) | No new payment once the tip estimate reaches `leave_by` − `PAY_STOP`, so payments in flight are mostly settled before the exit freezes the channel | = A |
| `BLOCK_FAST_S` | 300 s | While the view is in doubt, blocks are assumed to come at most twice as fast as the 600 s target (section 4.5). A burst faster than that for long is rare [R]; erring fast only makes the exit start earlier | 300 s |
| `WARN_LEAD` | 36 | Heads-up before `leave_by` ("leaving alone at block X unless moved") | Proposed 432 |
| `OPEN_MARGIN` | 36 | `open_app_by` lies this far before the earlier of `leave_by` and the safe-absence date | Proposed 144 |
| `HOST_SILENT_EXIT` | 1008 | Trigger T2 (section 5.1) | 1008, proposed |
| `HOST_SILENT_WD` | 36 | Trigger T3 | 36, proposed |
| `CLIMB` | 2 | Blocks between fee steps of one step's child (section 6.4) | 1 near the deadline, else 2 |

Every value except `TIMEOUT_STEP` is **proposed, owner to confirm**. The values in force for a factory are copied into its `exit_plan` when it goes live, and do not change for that factory unless the person tightens them (never loosens; a looser value would need the same check as signing).

### 4.4 The formulas

All heights. Each is computed for the member's own leaf, with n = `n_missing`, the steps not yet confirmed in the trusted view (initially d + 3).

```
H_leaf               = E − 10·d
last_safe_confirm    = H_leaf − (B − 1)
leave_by             = last_safe_confirm − n·A − M
step_due(i)          = last_safe_confirm − (n − i)·A − M          i = 1 … n, over the missing steps in order
leave_by_locked      = leave_by − M_locked                         (in the bundle, B5)
payments_stop_at     = leave_by − PAY_STOP
open_app_by          = min(leave_by, safe_absence_date) − OPEN_MARGIN
host_force_by        = last_safe_confirm − n_host·A − M_host       n_host: the host's missing steps (path, then its own commitment)
```

- `step_due(n)`, the commitment's, equals `last_safe_confirm − M`: a commitment confirmed by then has M blocks to spare.
- Part of the path on chain (U-a', U-b) shrinks n and moves `leave_by` later: a sibling's exit gives the member more time, never less [X3: d = 2 with 5, 3, 1 steps missing gives E − 66, E − 54, E − 42].
- A step reorganised out raises n again; the dates are recomputed and, if `leave_by` is now past, the exit is already due.

**Payments in flight.** For an incoming payment (an HTLC the host offers the member) with expiry h:

```
accept only if        h ≥ tip + (n + 1)·A + (B − 1) + M  and  tip < payments_stop_at
go_on_chain_by(h)     = h − (B − 1) − (n + 1)·A − M            (once its secret is released and the host has not removed it)
min_final_cltv_delta  ≥ (n + 1)·A + (B − 1) + M                 (in the member's invoices)
```

The `+ 1` is the claim on the commitment's HTLC output, which the host can take by its own timeout path from block h + 1. In T1 at d = 2 this is 52 blocks [X4], far under the 2,016 that senders commonly allow (`safety-rule.md` open point 6 is answered for 1.0.0's short exits). An outgoing payment (the member pays) sets no deadline for the member: on chain the host can take it only with the secret, which means the payment succeeded, and the member reclaims it after h with nothing competing [R]. It ties funds up until h plus the second-stage delay; the payment engine should keep outgoing expiries short. Payments in flight between two of the member's factories count as in flight on both sides (`safety-rule.md` 5) and are bounded by `move_by` (`MULTI-FACTORY.md` 4.1), which must be computed from this section's `leave_by`.

**Penalty.** For a revoked host commitment confirmed at height c, whose output to the host is delayed by the member's revocation window W (a channel term, `channel.md`):

```
penalty_last_confirm = c + W − B          (the host's sweep can be mined from block c + W)
penalty_send_by      = c + W − B − A − M
```

The watch engine sends at once on detection; the dates bound the safe absence (`safety-rule.md` 7) and drive the strip.

**Signing-time check.** `safety-rule.md` C8 "the end height leaves the exit time plus margin" becomes exact: the member refuses unless, at the member's own constants, `leave_by` (all n steps missing) is at least the funding deadline's height plus B plus one block of being live. A stricter, optional member condition is proposed in open point 1: `leave_by` not before the end of the lifetime.

### 4.5 The tip estimate and the chain view

The engines judge deadlines by a tip estimate T, never by a single server.

- **Trusted** (`agree`, `lagging`): T is the comparing backend's tip (the lowest agreeing tip, chain port section 5). M_lag covers the lag it allows.
- **In doubt** (`catching_up`, `one_source`, `disagree`, `unreachable`, `offline_by_choice`): T = max(T₀, min(T_claim, T₀ + ⌈(now − t₀) / BLOCK_FAST_S⌉)), where T₀ is the last trusted tip, t₀ the clock time it was first seen, and T_claim the highest tip any right-network server claims (or T₀ when none answers). [X5]
  - A server claiming a higher tip can only make the exit start earlier, and only within the clock bound; a server hiding blocks cannot make it start later than the clock bound allows.
  - The cost is griefing: one dishonest server that keeps the view in doubt makes the member leave early, by at most half the remaining time. The person is told (`chain_disagree` and the others are `at_risk`) and can change servers.
- **Progress** (a step `confirmed` or `buried`) is recorded only from the trusted view, checked against headers (`gz_chain_confirm_tx`). A step that only one server shows confirmed is still `sent`; the next level is nevertheless broadcast (section 5.2).

### 4.6 Slice 1's numbers, and the wind-down finding

T1: lifetime 144, wind-down 36, so E = tip + 180 (±6). With the signet constants [X3]:

| d | H_leaf | `leave_by` | Commitment due | Lead E − `leave_by` | Against the 36-block wind-down |
|---|---|---|---|---|---|
| 1 | E − 10 | E − 50 | E − 26 | 50 | starts 14 blocks before the lifetime ends |
| 2 | E − 20 | E − 66 | E − 36 | 66 | 30 blocks before |
| 3 | E − 30 | E − 82 | E − 46 | 82 | 46 blocks before |

So under T1 a member with a balance starts leaving alone **before the move window opens** (the end of the lifetime, `MULTI-FACTORY.md` 4.1): rotation with a balance cannot be tested under T1. In Slice 1 and 1.5 members are owed zero, so the automatic exit does not run (section 5.1, rule "nothing to take out") and T1 is fine for them. For Slice 3 and later, a wind-down of at least 82 blocks is needed at d ≤ 3, more with mainnet margins. Open point 1.

At the design's values (lifetime 4,320, wind-down 432) and, for example, d = 4, B = 6, A = 12, M = 6 + 2 + 144: lead = 40 + 5 + 7·12 + 152 = 281 blocks, inside the wind-down [R; the mainnet constants are open].

### 4.7 What the strip shows, from joining to the end

For a member with a balance in a live factory, in order. Codes are `local-api.md`'s; codes in *italics* are proposed in section 10.2.

| When (tip estimate) | `factory.state` | `doing.code` | Dates and attention |
|---|---|---|---|
| Live, before the move window | `live` | `idle_in_factory` | Dates: `open_app_by`, `move_window_opens`, `move_by`, `start_leaving_by` (provenance *`leaf_timeout_less_burial_exit_margin`*, section 10.2), `factory_ends` |
| No on-chain coin and the path would not confirm at the mempool floor with anchor-only children (section 6.5) | unchanged | unchanged | *`exit_needs_fee_coin`* (`important` while `leave_by` is more than `WARN_LEAD` away, `at_risk` after) |
| `leave_by` − `WARN_LEAD` | `winding_down` or `live` | unchanged | `date_near` (heads-up) for `start_leaving_by`: "Leaving alone at block X unless you move" |
| `payments_stop_at` | unchanged | unchanged | *`payments_stopped_for_exit`* (important); payments refused with a reason |
| Exit started (any trigger) | `exiting` | `leaving_alone` (priority 9) | `exit_progress` steps; one `leave_step_due` date per missing step; Activity records the trigger |
| A step not confirmed by its `step_due` | `exiting` | `leaving_alone` | *`exit_step_late`* (`at_risk`), with what would help: "add an on-chain coin", "keep the app running" |
| A bump needs more than the fee budget | `exiting` | `leaving_alone` | *`exit_fee_budget_reached`* (`act_now`, due the step's due) |
| Commitment buried | `exiting` | `leaving_alone` | Sweep waits the revocation window's own delay; no deadline |
| Own output swept | `ended`, `ended_how: left_alone` | next applicable | Activity: amounts from the confirmed transactions |
| H_leaf + 1 passed without the commitment buried, and the host swept | `ended`, `ended_how: host_timeout` | — | *`exit_missed`* (`at_risk` until seen), Activity with the amount lost |
| Locked | — | `wallet_locked` | Locked status: *`watching.state = watcher_locked`*, `next_action_height`, *`unlock_by`*, and the headline of section 5.6's table for each case |

## 5. The automatic exit

### 5.1 When it starts on its own

The exit starts at the first of these, for each channel in which the member has anything to take out. **"Something to take out"** means the latest commitment has an output for the member (its balance above the dust limit) or an incoming payment the member can claim. A member owed nothing (Slice 1 and 1.5, a member who has moved everything) gets no automatic exit: publishing the path would end its place for nothing. Watching continues in either case.

| Code | Trigger | Why |
|---|---|---|
| `deadline` | T ≥ `leave_by` (watcher: `leave_by_locked`) | The protection the design promises (`DESIGN.md` 7) |
| `host_silent` | No valid message from the host for `HOST_SILENT_EXIT` blocks (proposed 1,008, about a week) | A host gone that long will not rotate the member; leaving early, at calm fees, costs only the channel [R] |
| `host_silent_winding_down` | T ≥ `move_window_opens` and the host silent for `HOST_SILENT_WD` blocks (proposed 36) | In the wind-down the only alternative to leaving is a rotation that needs the host |
| `payment_on_chain` | T ≥ `go_on_chain_by(h)` for an incoming payment whose secret the member released and the host has not removed | Standard Lightning behaviour; the payment is owed (`safety-rule.md` 5) |
| `host_fault` | The channel engine reports a failure that ends the channel by Lightning's rules (an invalid signature, a refused revocation, an `error`) | As Lightning |
| `round_unfinished` | A move or close round touching the channel stayed Unfinished past its unfinished deadline (`safety-rule.md` 4.1 rule 5), or a co-signed close or rotation close was withheld past it (C13) | `safety-rule.md` 4.1 rule 5 and section 11 |
| `left_behind` | The group rotated without this member and nothing else applies | Same as `deadline`, shown differently (`doing.code = left_behind`) |
| `host_forcing` | The host published part of the member's path and its own commitment did not follow within A blocks of the leaf transaction's confirmation | The host started H-a and stopped; finish it before H_leaf |
| `user` | The person asked (`local-api.md` 16.3) | — |

When the watcher starts an exit while the wallet is locked, the reason is recorded as `deadline_while_locked` (rule W3). A breach (an old host commitment) is not a trigger: the channel ends on chain anyway, and the watch engine answers it (section 8).

### 5.2 What it never waits for

- **The host.** No step needs the host. Nothing in section 5.3 sends the host a message.
- **The person.** No confirmation, no fresh sign-in (the person's "leave alone" call needs one; the automatic exit does not), no unlock (section 5.6).
- **A trusted chain view.** Broadcasts go to every reachable server of the right network whatever the chain state; the next level is sent as soon as any such server reports its parent confirmed (a child of an unconfirmed parent is only refused or kept, never harmful). Only progress records wait for the trusted view.
- **A fee estimate.** With none, children are anchor-only.
- **Burial of intermediate steps.** One confirmation of the parent is enough to send the next level; only the commitment's burial is counted against the deadline.
- **The planner** (1.1.0) and any rule. A rule's own dates are always earlier than `leave_by` (`MULTI-FACTORY.md` 4.6).
- **A signing round.** An unresolved round touching the channel does not delay the exit; the exit's root kickoff and the round's transaction may conflict, and the watch engine accepts whichever confirms (section 8).

### 5.3 The procedure

For one channel, from `exit_started`:

1. **Freeze.** The channel engine stops (X-I3). Incoming payments not yet fulfilled are failed back if the host answers within one keep-alive; otherwise they are left to their expiry (they are not owed, `safety-rule.md` 5).
2. **Choose the commitment.** The highest-numbered own commitment the member holds the host's signature for and has not revoked (X-I5). Recorded in `exit_started`. The member completes its own signature when the commitment step is due (`safety-rule.md` 4.3; `channel.md`), which needs the wallet unlocked (5.6).
3. **For each missing step in order** (the first missing one has a confirmed parent, or is the root kickoff and the funding is confirmed):
   1. Save `exit_step sent` (and `fee_child`, `coin_reserved` if a wallet child is built).
   2. Broadcast the step. If every server refuses it for its fee, broadcast it as a package with its child (section 6.8).
   3. Broadcast its anchor-only child (section 6.2), or the current wallet-funded child (section 6.3).
   4. Every block until the step is confirmed: rebroadcast both to every server; apply section 6.4.
   5. On confirmation by any server, go to the next step; on trusted confirmation, save `exit_step confirmed`.
4. **Commitment buried** (B confirmations, trusted): save; the deadline is met. Claim incoming payments on chain whose secrets the member holds (each before `h`, section 4.4); outgoing ones are reclaimed after their expiry.
5. **Sweep** the member's own delayed output after its delay (no competing claim: the commitment is not revoked), and the claimed payment outputs after theirs, to the payout destination, at the cheapest rate that confirms within a day, paying the fee from the swept output itself. No deadline.
6. Save `exit_ended`.

A step whose output was already spent by the expected next transaction (a sibling, the host) is skipped (U-a'). A step whose input was spent by anything else is handed to section 8.

### 5.4 Pause

Pause never stops, delays or alters the exit, the watch engine or the watcher. Building a wallet-funded fee child signs with the on-chain wallet's key; that is part of leaving alone and allowed while paused (`local-api.md` 11.3: "leaving alone before an end date go[es] on"). Pause does stop payments, so `payments_stop_at` has no effect while paused.

### 5.5 The planner

1.1.0's planner may move funds out of a factory before `leave_by`; it never disables, postpones or re-times the exit (`MULTI-FACTORY.md` 4.6, MF10). A move that leaves the member owed nothing in a factory disarms that factory's automatic exit by the "nothing to take out" rule only after the move settles (the payment is in flight until then).

### 5.6 A locked wallet

**The problem.** After every restart the wallet is locked until the passphrase is typed (owner decisions 13 and 14; `local-api.md` 4.7). A locked node cannot read its journal. Without more, a power cut while the member is away would stop the exit that M-a depends on.

**Two facts fix what a locked program can do.**

1. Under the standard taproot channel format the member never holds a final signature on its own commitment: it holds the host's partial signature and nonce and completes its own at broadcast, which needs its key (`safety-rule.md` 4.3). So a keyless watcher cannot publish the member's commitment.
2. Pre-completing that signature while unlocked and storing it in the bundle would not be safe either. **Every** commitment the member holds becomes revoked at the next update, and copies of an older bundle survive outside the program's control (synchronised folders and their history, system backups, "previous versions", snapshots; `storage-encryption.md` 3.2 and 6.4). Anyone with such a copy and KB could publish a revoked commitment from their own machine, and the host's penalty would take the channel's balance (review of `storage-encryption.md` draft 1, findings F1 and F2). Rewriting the bundle before each revocation does not help against copies made earlier.

**Decision (proposed).** The bundle **never holds a commitment of the member's own**, completed or not. The locked watcher does everything that needs no key and no own commitment; the one step that does, the commitment, waits for the person to unlock, and the strip says by when. Concretely:

- the unlocked program keeps the **bundle** current with: the member's tree path (fully signed at creation, one version per funding output in 1.0.0, so no copy of it can ever be stale or revoked [R]); each step's anchor-only child; the penalties for the host's revoked commitments (CH-5; harmless in any copy, since each spends only a transaction the host would have to publish first); the dates; and, only if the person set fee coins aside, a ladder of pre-signed wallet children for the tree steps;
- the locked program runs only the **watcher** (`storage-encryption.md` 8.7), which reads the bundle with KB and runs sections 4.4, 4.5, 5.3 step 3 (tree steps only) and 6.2 from it;
- the commitment step is signed and broadcast **after unlock**, by the node, from the encrypted journal (a fresh signing step), within `unlock_by`.

Publishing the tree path while locked is worth doing even though it cannot finish the exit. It costs the member nothing (the tree's fees are pre-paid, the anchor-only children are keyless); it does not end the member's channel (payments can continue off chain with the leaf on chain); and it leaves a single step for the person, which makes `unlock_by` as late as it can be.

**`unlock_by`**, the last height at which an unlock still lets the node finish with every margin:

```
unlock_by = min( last_safe_confirm − A − M,                  the commitment's latest send height, every tree step done
                 go_on_chain_by(h) for each incoming payment whose secret is released )
```

In T1 at d = 2 that is E − 42 [X3: `leave_by` with one step missing]. The watcher publishes the tree steps by `leave_by_locked` exactly as an unlocked node would, so by `unlock_by` only the commitment remains. An unlock after `unlock_by` but before H_leaf still broadcasts the commitment at once, with less than the margin (best effort, shown as late).

**What a locked wallet can and cannot do.**

| Can | Cannot |
|---|---|
| Watch every outpoint and txid in the bundle, through the bundle's chain servers | Talk to the host or any peer; fail back, accept or settle a payment |
| Compute `leave_by_locked`, the step dates and `unlock_by`, with the tip estimate of 4.5 | Change a date, a constant or the bundle |
| Broadcast the member's tree path and each step's anchor-only child by those dates | **Broadcast the member's commitment** (it holds none), so it cannot by itself stop the host's timeout at H_leaf |
| Climb the pre-signed fee ladder of the tree steps, if fee coins were set aside | Sign anything (no new child, fee level, claim or sweep); pay fees from any other coin |
| Broadcast a pre-signed penalty when a revoked host commitment appears, and its second-stage penalties | Answer a revoked host commitment the bundle has no penalty for (none, if CH-5 holds) |
| Record a host's or sibling's publication of path steps (section 8 class S1) and recompute its dates | Claim an incoming payment, or sweep the member's own outputs after a host close (no deadline for the latter; waits for unlock) |
| Write what it saw and did in `watch.gzl`; answer `GET /api/v1/status` with the locked fields below | Anything else |

**What the strip says, in each case.** Always `wallet = locked`, `doing.code = wallet_locked`, and no amounts. The locked status carries the bundle header's clear `next_action_height` (`storage-encryption.md` 8.7.6) and *`unlock_by`*. While a bundle is armed, *`watching.state = watcher_locked`* replaces `local-api.md`'s `nobody_locked`. The headline, first match wins:

| Case | Headline | Tier |
|---|---|---|
| H_leaf passed while locked, with something to take out | "Unlock. A factory's deadline passed while Gazpacho was locked; it will check what happened." | `at_risk` |
| T > `unlock_by` | "Unlock at once. It may already be too late to leave a factory in time." | `at_risk` |
| An incoming payment's secret was released and the payment is not settled | "Unlock before block `unlock_by`, or a payment you received may be lost." | `at_risk` |
| Tree steps done, waiting for the unlock | "Unlock now. Only the last step of leaving a factory is left, and it needs your passphrase. After block H_leaf the host can take this balance." | `at_risk` |
| The watcher is publishing tree steps | "Locked and leaving a factory alone. The tree steps go out without you; the last step needs your passphrase. Unlock before block `unlock_by`." | `at_risk` |
| A revoked host state appeared and the penalty went out | "Locked. The host published an old state and Gazpacho answered it. Unlock to see." | `at_risk` until seen |
| "Maximum privacy" chosen (no bundle) and something to take out | "Locked. Nothing is watched. Unlock before block `leave_by`, or a factory balance is at risk." `watching.state = nobody_locked` | `at_risk` |
| Something to take out; T < `leave_by_locked` | "Locked. Gazpacho is still watching. Unlock before block `unlock_by` (about …): leaving a factory alone needs your passphrase for its last step." | `important` |
| Nothing to take out anywhere | "Locked. Gazpacho is still watching. Nothing needs you now." | — |

The locked page is served on loopback only and shows heights and estimated times, never amounts; the same headline is printed to the program's terminal.

**Locking with payments in flight** (`storage-encryption.md` 8.7.2's question). **A deliberate lock is allowed, but held** (as `local-api.md` 4.7 `lock_held`) while any incoming payment's secret has been released and the host has not removed the payment by an irrevocable update. Before holding, locking stops new payments and fails back incoming payments not yet fulfilled. Outgoing payments do not hold the lock: section 4.4 gives the member no deadline on them. An unplanned restart cannot be held; the most it can cost is the incoming payments whose secrets were released and not yet removed at that moment, if the person does not unlock before `unlock_by`. That window is the seconds between `update_fulfill_htlc` and the next commitment exchange [R]. A deliberate lock asked for when T ≥ `leave_by` − `WARN_LEAD` is allowed with a warning naming `unlock_by`.

**Rules W1 to W5** (in addition to `storage-encryption.md` 8.7.4's rules 1 to 5):

- **W1.** The node and the watcher never run at once. At lock: the node stops, the bundle is checked current, then the watcher starts. At unlock: the watcher stops and writes its last `watch.gzl` entry, then the node starts.
- **W2.** No bundle ever holds a commitment of the member's own, current or old, completed or not, nor any partial signature, nonce or secret from which one could be completed. So a stale or stolen bundle can at worst publish the member's tree path early (section 7.1) and spend set-aside fee coins on fees.
- **W3.** At unlock, before connecting to the host, the node merges `watch.gzl` in one batch. If the watcher broadcast any tree step of a channel that has something to take out, that batch records `exit_started` with reason `deadline_while_locked` and the channel is frozen; the node then completes, saves and broadcasts the commitment at once (section 5.3 step 2) before anything else. If the watcher only recorded others' publications, the node recomputes the dates and carries on.
- **W4.** After a restore marker the bundle is rebuilt from the restored journal as always (tree paths, dates, penalties; W2 already excludes commitments), its `made_after_restore_marker` flag is set, and section 5.7 governs the commitment.
- **W5.** Choosing "maximum privacy" (no bundle) is refused while any factory has something to take out, unless the person confirms with the date it puts at risk (proposed; open point 3).

**Bundle records** (the contents of `watch.gzw`, items B1 to B9 of `storage-encryption.md` 8.7.2). One BOLT 1 TLV stream (minimal BigSize, strictly increasing types; unknown even types refuse the bundle, unknown odd are skipped). A "list" is a sequence of entries, each `u32` length then a TLV stream. Integers are big-endian as in `messages.md` 1.

| Type | Item | Value |
|---|---|---|
| 2 | B1 header | TLV: 2 `chain` (32), 4 `bundle_id` (16), 6 `counter` (`u64`), 8 `journal_file_id` (16), 10 `sync_mark_offset` (`u64`), 12 `made_at_height` (`u32`), 14 `constants_version` (`u8`, 1 for section 4.3's set), 16 `made_after_restore_marker` (`u8`, 0 or 1) |
| 4 | B2 servers | List: 2 `operator` (UTF-8), 4 `base_url` (UTF-8); then in the stream 6 `quorum` (`u8`), 8 `tip_slack` (`u8`) |
| 6 | B8 fee coins | List: 2 `outpoint` (36), 4 `amount_sat` (`u64`), 6 `script` (34). Absent when none are set aside |
| 8 | B8 destination | The payout script, for display |
| 10 | B3 to B7, B9 factories | List of factory blocks, below |

A factory block:

| Type | Value |
|---|---|
| 2 | `local_no` (`u16`): the program's own number, never the lobby id or the host's key |
| 4 | Funding outpoint (36), 6 amount (`u64`), 8 script (34) |
| 10 | State (`u8`): 1 live, 2 awaiting funding (with 12), 3 abandoned and still watched, 4 exiting |
| 12 | Funding deadline (`u32`) and B for the funding (`u8`) |
| 14 | B5 dates: `d` (`u8`), `H_leaf`, `last_safe_confirm`, `leave_by`, `leave_by_locked`, `unlock_by` (each `u32`, `unlock_by` 0 when none), then the constants B, A, M_safe, M_lag, M_spike, M_locked (`u8` each) |
| 16 | B4 path: list of steps, each 2 `index` (`u8`), 4 `kind` (`u8`: 1 fixed kickoff, 2 leaf kickoff, 3 leaf transaction; there is no commitment step, W2), 6 `tx` (the fully signed bytes), 8 `anchor_vout` (`u8`, 255 when none), 10 `anchor_child` (the 65 bytes of 6.2, when 8 is not 255), 12 fee ladder (list of 2 `rung` (`u8`), 4 `package_rate_kvb` (`u32`), 6 `fee_coin_index` (`u8`), 8 `tx`) |
| 18 | The commitment's latest send height (`u32`), for the strip; never commitment bytes (W2) |
| 20 | B6 responses: list of 2 `trigger_txid` (32), 4 `tx` (fully signed penalty), 6 `send_by_delta` (`u32`, blocks after the trigger's confirmation, from 4.4) |
| 22 | B9 known txids: 32 × k, each a transaction in the member's exposed set that a host may publish (a co-signed close, a rotation close); followed by 24, k class bytes (1 cooperative close, 2 rotation close) |

Never in the bundle (`storage-encryption.md` 8.7.2, narrowed by W2): any key, revocation secret, secret nonce, payment secret, the words, an unsigned or partly signed transaction, **any commitment of the member's own** (current or old, completed or not) or the host's partial signatures on one, a lobby id, the host's key or address. Vectors for these records come with draft 2, once `channel.md` fixes the commitment's form.

**Fee coins for a locked exit.** Only for the tree steps; the commitment's child is built after unlock. Pre-signed wallet children conflict with each other if two levels spend one coin, and a child spending the previous level's change cannot be pre-signed without fixing which rung was used. So each step gets its **own** fee coin, made by one split transaction while unlocked, and each step's ladder spends only that coin. This is an on-chain cost, so it is **off by default** (decision 6: no reserve) and offered when the strip shows `exit_needs_fee_coin` (open point 7). Rungs are section 6.6's.

### 5.7 After a restore

A restored node (`wallet = restoring`, `safety-rule.md` section 9) never publishes its own commitment automatically (`DESIGN.md` 6). For each factory the backup knows:

1. The tree path is armed as usual: it has one version per funding output in 1.0.0, so publishing it is never a breach [R].
2. The commitment step is replaced by **ask the host**: on reconnecting, the channel's re-establishment proves the latest state (`option_data_loss_protect`, required by `channel.md`), and the member asks the host to close with its own commitment, whose output to the member needs no further action but a sweep.
3. If the host has not closed by `host_force_by`, the strip shows *`restored_commitment_choice`* (`at_risk`): "Your backup may be out of date. If you publish it and it is out of date, the host can take your whole balance in this channel. If you do nothing, the host can take it after block H_leaf." Publishing is the person's choice, with a fresh sign-in. It is never automatic (open point 4).
4. Factories the backup does not know (joined after it) are recovered only if the device's bundle is newer than the backup (it holds their tree paths and dates, never a commitment, W2; they are taken into a new `exit_plan` after the person confirms), or by the host handing the signed tree back (`safety-rule.md` R7 and section 11). Their channel state is then only what the host proves (item 2).

## 6. Fees at exit

### 6.1 The principle

The owner's position (`docs/handoff/2026-11-12-tree-fees.md` 4.4, 4.5): the pre-signed rate is a minimum, set in the terms (0.1 sat/vB in T1); whoever gains from a transaction confirming pays for it at exit time, through its anchor, at market rate; there is no reserve. A member leaving alone pays for its own path; members under a shared level it publishes pay nothing.

### 6.2 The anchor-only child

Every tree transaction carries a 240-sat pay-to-anchor output as its last output [C: `src/factory.c:498-507`; `channel.h:16`, `:20`]. Spending it needs no key and no witness [S: tree-fees hand-off F9]. So, for every step with an anchor, the program builds once, at plan time, the **anchor-only child**:

```
version   = the parent's (2 today; 3 for a TRUC parent, which BIP 431 requires)
input     = the parent's anchor outpoint, empty scriptSig, nSequence 0xFFFFFFFD, no witness
output    = 0 sat, script 6a 03 00 00 00 (OP_RETURN, three zero bytes)
lock time = 0
```

It is exactly 65 bytes, the smallest standard size without witness, and pays its whole input, 240 sat, as fee: a package rate of about 0.84 to 1.36 sat/vB over T1's tree transactions [X6]. It is the same bytes for every member, so siblings publishing a shared level produce the same child. The zero bytes carry no wallet fingerprint. It is broadcast with every step, always: it costs the member nothing (the anchor's value was set aside at funding), and it raises the step's rate about tenfold at 0.1 sat/vB.

### 6.3 A wallet-funded child

When a step needs more than the anchor-only rate (section 6.4), the exit engine builds a child spending the anchor and one or more of the member's own on-chain coins, paying change to the wallet. With one P2TR coin it is 153 vbytes [X7]. For a package rate r (sat/kvB) over a parent of V_p vbytes paying f_p:

```
child_fee = ⌈ r · (V_p + V_child) / 1000 ⌉ − f_p
```

The rate r is the estimate for `max(1, step_due − T − 1)` blocks, the cheapest rate that confirms before the step's deadline (hand-off 4.4: "not always urgent"). The child **replaces** the child already on the anchor (at first the anchor-only child), so it must meet all three of:

- (a) its fee is at least the replaced child's fee plus the incremental relay fee on its own size (BIP 125 rule 4; 0.1 sat/vB since Bitcoin Core 29.1 [S: hand-off F1, F2]);
- (b) its own fee rate is higher than the replaced child's (the rule of nodes before cluster mempool);
- (c) the parent's package rate is higher than with the replaced child (cluster mempool's comparison, 31.0 and later [S: hand-off F14]).

The fee is the larger of the formula above and the smallest fee meeting (a) to (c). Rule (b) matters: the anchor-only child pays 240 sat on 65 vB, 3.69 sat/vB of its own, so **the first wallet child must pay at least 565 sat** on T1's leaf transaction, a package of 1.82 sat/vB; a "1 sat/vB" child would be refused [X7]. A member wanting less than that leaves the anchor-only child in place [R: the exact replacement rules differ by node version; S12 checks them on signet].

### 6.4 Re-bump rules

For a step sent at height s with deadline u = `step_due(i)`:

1. Every block until confirmed, rebroadcast the step and its current child to every server (mempools forget; the chain port never repeats a broadcast on its own).
2. If the step is unconfirmed `CLIMB` blocks after its last fee change, and either its package rate is below the estimate for its remaining blocks, or T ≥ u − A/2: replace the child with one at max(estimate, 1.25 × previous package rate), with its fee raised as needed to meet 6.3's (a) to (c). Within A/2 of u, `CLIMB` is 1 and the target is the next block.
3. Never above the **fee budget**: the person's setting for this exit, default 25% of the expected recovered amount (proposed, open point 6), extended to 90% once T ≥ u (late: something recovered is better than nothing). Reaching it raises *`exit_fee_budget_reached`*.
4. Never replace a pre-signed transaction (impossible: its signatures commit to it); only children.
5. A foreign child seen spending the step's anchor (watch the anchor outpoint) is left alone if its package confirms the step in time; otherwise the replacement must out-pay it, and if that exceeds the budget the strip says the step is being held back by another party's transaction [R: possible on version-2 parents, where an anyone-can-spend anchor can carry a large low-rate child; TRUC caps that child at 1,000 vB, hand-off F6, F8; open point 10].
6. On signet the estimate is the fixed 0.1 sat/vB (chain port section 7), so rule 2 fires only on the deadline clause; S12 exercises it.

### 6.5 A member with no on-chain coins

It can still exit: every step at its pre-signed fee with its anchor-only child. Whether that confirms depends on the mempool's floor. The schedule engine checks, every block and at joining, whether every missing step's anchor-only package rate is at least the servers' reported floor (or 0.1 sat/vB on test networks), and if not raises *`exit_needs_fee_coin`* with the amount that would let the member bump every missing step at the floor's rate within the budget: "To leave this factory alone when fees are high, you need about X sat in your on-chain wallet." It is `important` while `leave_by` is more than `WARN_LEAD` away and `at_risk` after (the owner's "warn a member with no on-chain coins"). A step that cannot confirm is shown as *`exit_step_late`* with "needs an on-chain coin", never as a stall (hand-off 4.5).

### 6.6 The pre-signed ladder (locked watcher only)

Package rates of the rungs, in sat/vB: rung 0 the anchor-only child, then 2, 5, 10, 20, 50, 100, 200, each a child spending the step's anchor and that step's own fee coin, cut at the fee coin's value and the person's fee ceiling. Each rung's fee is the larger of its rate's fee and the smallest fee that replaces the rung below under 6.3's (a) to (c), so each replaces the last; there is no 1 sat/vB rung, because it could not replace rung 0 [X7: for T1's 124, 167 and 253 vB transactions the 2 sat/vB rung pays 565, 623 or 614, and 786 sat]. The watcher climbs one rung per `CLIMB` blocks while a step is unconfirmed past `step_due − A/2`.

### 6.7 Never replace the funding

The funding transaction's txid is fixed before the round (H1); every tree transaction commits to it. **Replacing the funding by fee (RBF) spends the same inputs in a different transaction, makes the old funding outpoint impossible and kills the signed tree** (study C-f). So:

- **H16 (proposed for `safety-rule.md`).** The host bumps a stuck funding transaction only by a child spending its own change output, never by replacement; it keeps that change output for that purpose until the funding is buried or dead.
- The member never bumps the funding. A funding replaced by the host reaches Dead by C4(d) when the replacement is buried; the strip shows `creation_dead` with *`params.cause = funding_replaced`*: "The host replaced its funding transaction. The tree you signed can never be used. Nothing was owed."

### 6.8 Relay facts this section relies on, and what is not known

- Bitcoin Core relays 0.1 sat/vB by default from 29.1 [S: F1, F2]; T1's tree pays about 0.1 to 0.137 sat/vB, so on such nodes each step relays alone and needs no package.
- P2A spending is standard from 28.0 [S: F9]; the P2A dust limit is 240 sat [not verified in a primary source: F10]. If it were higher, the anchor-only child would still be valid (spending dust is allowed) but the parent would be non-standard: S2 checks this by relay.
- A parent below a server's floor needs package submission. The chain port broadcasts single transactions (`POST /tx`) and public Electrum servers offered no package submission (`THREAT-MODEL.md` 2.4). **Requirement on the chain port: `gz_chain_broadcast_package`**, and S12 must establish which signet servers accept packages.
- Package relay is one parent and one child [S: F12]; so each level is its own package and must confirm before the next (F13). Section 4.2 builds this in.

## 7. Every path 1.0.0 can reach

Each row: how it is detected, what is done, the deadline, what is saved before acting, what is shown. "Section 8 class" refers to the table there.

| Path | Detection | Action | Deadline | Saved first | Shown |
|---|---|---|---|---|---|
| **U-a, d = 1, 2 or 3**: member leaves alone | A trigger of 5.1 | 5.3 | `leave_by`, `step_due(i)`; d from the held tree | `exit_started`, then per step `exit_step` | `exiting`, `leaving_alone`, steps |
| **U-a'**: part of the path already on chain | `outpoint spent` on a path output by the next path txid (class S1) | Mark the step confirmed by its txid; skip it | Recomputed with fewer missing steps (later) | `spend_seen`, `exit_step confirmed` | `branch_partly_on_chain` (`important`, not `at_risk`, in 1.0.0: no timed steps; the wording "timed steps start counting" does not apply, section 10.2) |
| **U-b**: a sibling's exit publishes shared levels | As U-a' | Nothing more: the member's channel stays open; whole-factory closes end (section 7.1) | Later | `spend_seen` | As U-a' |
| **U-c**: everyone leaves (host gone) | Each member's own triggers | Each as U-a; shared levels deduplicate (same bytes, same anchor-only child) | Each member's own | As U-a | As U-a; `host_not_answering` |
| **H-a**: host forces the member out | The host publishes path steps (class S1) and then its own commitment (class S4) | On S4: sweep the member's output on the host's commitment (the member's alone; in the standard taproot channel format after a one-block delay [R], to be fixed by `channel.md`), claim incoming payments before their h; no exit of its own is needed | Incoming payments' h; else none | `spend_seen` | `ended`, `ended_how: forced_by_host` |
| **H-a stopped halfway** | Path steps published, no host commitment within A blocks of the leaf transaction's confirmation | Trigger `host_forcing`: 5.3 from the first missing step | `leave_by` with n small | As U-a | As U-a |
| **H-b**: host timeout sweep of an output on the path | Class S2 | Nothing can be done for that output and everything under it | — (past) | `spend_seen` | *`exit_missed`* if the member was owed anything below; Activity with the amount |
| **H-c**: host takes the spare liquidity | Class S3 | Nothing (it is the host's) | — | — | Activity (record) |
| **L-a**: member force-closes its channel | Same as U-a: inside a factory a force close **is** the exit (study L-a) | 5.3 | As U-a | As U-a | As U-a |
| **L-b**: host force-closes with its current commitment | Class S4 | As H-a | As H-a | `spend_seen` | `ended`, `forced_by_host` |
| **L-c, host breach**: a revoked host commitment | Class S5 | Broadcast the penalty (and second-stage penalties as the host's second-stage transactions appear) | `penalty_send_by` | `spend_seen`, `response_sent` | `old_state_published`, `answering_old_state`, `answer`: `sent`, `confirmed`, `buried` |
| **L-c, member's own old state** | Cannot be produced by the node (X-I5) | — | — | — | — |
| **L-d**: restored member | `wallet = restoring` | 5.7 | `host_force_by` for the choice | `restored`, choices | *`restored_commitment_choice`* |
| **C-e, C-f**: never funded, or funded late | Funding txid and inputs watched (C11, C4(d)) | None: nothing is owed. If funded and buried late and C11's re-check passes, the factory becomes live and the exit is armed then; if it fails, it stays abandoned, still watched | Funding deadline | `funding_status` | `creation_abandoned` with `still_watched`; `creation_dead` |
| **C-g**: funding reorganised before burial | Block disconnected; funding back to unconfirmed | None (not live) | — | `funding_status` | `awaiting_funding` |
| **C-h**: funding reorganised after burial | Block disconnected under a live factory's funding | Stop payments (not live, C11); keep every date; rebroadcast any exit step when the funding is back | Unchanged | `funding_status reorganised_away` | `funding_reorganised` (`at_risk`) |
| **C-h, double-spent**: a funding input spent by another transaction, buried | Outpoint spent on a funding input | The tree is void; stop the exit; record the loss | — | `funding_status input_spent_elsewhere` | *`funding_double_spent`* (`at_risk` until seen); Activity with the amount lost (`safety-rule.md` 11: not defended) |
| **E-b, E-e**: the member missed rotation | Move window passed without a move; the old factory still holds a balance | `left_behind`, then as U-a by `leave_by` | `leave_by` | As U-a | `left_behind` |
| **E-c**: host recovers after everyone moved | Host side (section 9) | — | — | — | Host's view |
| **M-a**: member away with a balance | The member's own `deadline` trigger. Locked: the watcher publishes the tree path, and the balance is safe only if the person unlocks by `unlock_by` (5.6). Program not running at all: nothing | 5.3 | `leave_by` | As U-a | Before leaving: `open_app_by`; after: Activity |
| **M-c**: member with nothing owed is away | — | No exit (5.1) | — | — | — |
| **V-b**: host gone after funding | `host_silent` (5.1) or the deadline | 5.3 | `leave_by` | As U-a | `host_not_answering` |
| **Withheld close or rotation close** published later | Class S6 (a known txid of the exposed set) | Accept: the member is owed under it (`safety-rule.md` C13 already stopped payments) | — | `spend_seen` | Activity; the new factory's records for a rotation close |

### 7.1 What one member's exit does to its siblings

A member at depth d publishes d fixed kickoffs, which it shares with others (the root kickoff with every member, the kickoff at depth j with every member below it), and then its own leaf's kickoff and leaf transaction, which it shares with no one. For a sibling S whose path shares k of those kickoffs:

| Effect | In 1.0.0 | Source |
|---|---|---|
| S's funds | **Nothing is lost and S pays nothing.** S's leaf and channel sit below an output that is still unpublished; its channel keeps working off chain; no signature of S's is needed; the fees were pre-paid in the tree and the exiting member's children pay the rest | [R, from 4.1 and 6.2] |
| S's channel | **Stays open.** Publishing ancestors does not touch S's leaf transaction or channel output. (The storage-encryption review's "every sibling then pays exit fees and loses its channel" does not hold for 1.0.0 trees; it would for a tree with timed layers, where a published kickoff starts relative delays) | [R; `local-api.md`'s "timed steps start counting" likewise does not apply, 10.2] |
| S's deadline | **Later, never earlier.** S's `n_missing` falls by k, so its `leave_by` moves k·A later [X3]; H_leaf is absolute and unchanged | 4.4 |
| The host's reach | The newly confirmed kickoffs' other outputs are now on chain, each with the timeout leaf it always had (E − 5·(2j − 1) at depth j), all later than every H_leaf below them. Nothing can be taken from S earlier than before | [C: 4.1] |
| Factory-wide operations | **End once the root kickoff is buried.** The funding output is spent, so a cooperative close of the whole factory (E-a) and a rotation that closes the old funding into the new factory (E-d) can no longer happen. S rotates only by paying across (E-b). A co-signed but unpublished whole-factory close or rotation close in S's exposed set becomes Dead under C4(d) when the root kickoff is buried | `safety-rule.md` C4(d), 5 |
| Privacy | The published kickoffs show the shape and amounts of the tree above S | — |

**What S's software must do** (the node, or the watcher while locked): classify each spend as S1 (section 8) and save `spend_seen`; mark those steps confirmed in S's `exit_plan` and recompute every date; show `branch_partly_on_chain` as `important`, worded "A neighbour left the factory alone. Nothing is needed from you; you have more time, not less", never `at_risk`; once the root kickoff is buried, mark any whole-factory close or rotation close in its exposed set Dead, refuse any later round that spends the funding output (it no longer exists), and show that a move to the next factory will be by paying across; keep its own automatic exit armed exactly as before. The host's software sweeps or forces per remaining output from then on (section 9.2).

**An early publication by someone holding an old bundle and KB** (`storage-encryption.md` 8.7.5, griefing) is this case for every sibling, and for the victim it is U-a' with every tree step done: the victim's channel goes on working, its only remaining step is its commitment, and it loses nothing if it is running or unlocks by `unlock_by`; it does lose the factory-wide close and close-into-the-next-factory, as above.

## 8. What is watched, and what a spend means

From the moment the factory is live (and, for creations, from the round), the watch engine watches: the funding txid to B and every input outpoint of the funding transaction (existing, C4(d), C11); every output on the member's path (each path transaction's output that the next spends), every path step's anchor outpoint while its step is unconfirmed, the leaf's channel output, and after a commitment confirms, its outputs to the member and its payment outputs. A spend is classified from the spender's bytes, fetched and checked (chain port, "Spenders"):

| Class | The spend | Meaning | Response |
|---|---|---|---|
| S1 | A path output spent by the expected next path transaction | A sibling's or the host's publication | Mark the step confirmed (U-a', U-b) |
| S2 | A path output or the channel output spent through the host's timeout leaf (witness: one signature and the timeout script) | The host's timeout sweep (H-b) | Record; loss if anything was owed below |
| S3 | The leaf's spare-liquidity output spent | The host's liquidity (H-c) | Record |
| S4 | The channel output spent by the host's current commitment (its number, from the channel engine) | The host closed (L-b, H-a) | Sweep, claim payments |
| S5 | The channel output spent by a revoked host commitment | Breach (L-c) | Penalty |
| S6 | An output on or above the path spent by a transaction in the member's exposed set (B9) | A co-signed close or rotation close | Owed under that transaction |
| S7 | The channel output spent by the member's own commitment | Our exit (only the unlocked node can publish it, 5.6) | Continue 5.3 |
| S8 | Anything else | Should not exist: every other spend needs the member's signature | `at_risk` *`unexplained_spend`*; stop payments; keep exiting by other paths where any remain |

A spend seen only in one server's mempool is acted on only for S5 (answer at once: the penalty is harmless if the breach does not confirm) and recorded for the rest until confirmed in the trusted view.

## 9. The host's side

The host runs the same engines with the roles exchanged, plus these rules (proposed additions to `safety-rule.md` section 10).

### 9.1 Answering old states

**H14. The host watches every member's channel output and answers a member's revoked commitment** with the penalty, by `penalty_send_by` computed with the host's own constants and the member's delay (the host's W for that member). It keeps every penalty and second-stage penalty ready from the moment it learns each revocation secret. A host that is down longer than the shortest W of its members can lose to a breach; the host's terms should state its own W (`channel.md`). This closes `THREAT-MODEL.md` 2.2's "the host's duty to respond is not written as a rule".

### 9.2 The sweep schedule

**H15.** For each output the host may take alone:

| Output | From | When the host's software takes it |
|---|---|---|
| A leaf's spare liquidity | 144 blocks after the leaf transaction confirms (`or(all signers, host & CSV)`) [C: C5 table] | Any time after; batched; no deadline (no one else can take it alone) |
| The host's output on a member's commitment | Its delay | After it; no deadline unless the commitment is revoked (then the member's penalty competes and the host has nothing to win) |
| An unpublished tree output whose every member below is **owed nothing** or has already exited | Its timeout height h + 1 (section 4.1) | The highest such output, so one sweep covers the most: after a factory where everyone moved (E-c), the root kickoff, then each root output at E − 5 + 1 (`safety-rule.md` 12 value 2); one transaction may sweep several |
| An unpublished tree output with a member below who is owed something | — | **Never** (H17) |

Every host transaction is paid from the host's own wallet (H7), at the cheapest rate that confirms before the next competing claim, if any; none of a member's coins is ever touched (hand-off test 7).

### 9.3 Forcing a silent member out when there is no payout

`safety-rule.md` H6 assumes an end-date payout; 1.0.0 has none, so a silent member's balance would by default go to the host's timeout (M-a). **H17 (proposed, open point 2): the host's software never takes a member's balance through a timeout.** For each member still owed something who has not left or moved, the host starts, at `host_force_by` (section 4.4, with M_host), to publish that member's path and then **its own latest commitment** of the member's channel, paying from its wallet. The member's balance lands in its output on the host's commitment, which only the member can spend. The host stops extending credit to that member at `payments_stop_at` computed with the host's constants.

`host_force_by` falls after the member's own `leave_by` (by M − M_host = 6 blocks with the signet constants [X3]), so a member that is running always leaves first. The cost to the host is the path's fees and its commitment's; the gain is its own channel share and spare liquidity back before E, and never holding a balance it did not earn. This is a policy of honest host software, not a protection: a dishonest host can run other code, and the member's protection remains its own exit (`safety-rule.md` 11). It does make the honest outcome of M-a "the member keeps its balance".

### 9.4 Funding

H16 (section 6.7): never replace the funding; bump only by a child on the host's change. The host keeps the funding's inputs reserved, and does not spend them elsewhere unless it means to make the creation Dead (H11's retry on a new outpoint does exactly this, on purpose).

## 10. Requirements on other specifications

### 10.1 `channel.md` (not written)

| # | Requirement | Why |
|---|---|---|
| CH-1 | The member can complete its own signature on its latest commitment at any later time while unlocked, including after a restart (the nonce rules are `channel.md`'s, `safety-rule.md` 4.3), and a completed own commitment is never written outside the encrypted journal | The commitment step after unlock (5.6, W3); W2 |
| CH-2 | The member's commitment pays a fee fixed in advance (at least the factory's minimum rate, paid by the host as opener) and carries an anchor whose value alone funds a child: a 240-sat P2A, or the member's own keyed anchor with a child pre-signed at update time. A zero-fee commitment with a zero-value anchor (BOLTs #1228) **cannot be confirmed by a member with no on-chain coin** | 6.5; it contradicts the commitment shape asked of SuperScalar in the tree-fees hand-off 4.7 (open point 9) |
| CH-3 | The channel's funding output is the leaf's output 0: the 2-of-2 aggregate of the host's and the member's factory keys, tweaked by a tapscript with the host's timeout leaf [C: `src/factory.c:1310-1316`, `:185-214`]. Commitments spend it on the key path under that tweak | Not the BIP 86 output a standard taproot channel assumes |
| CH-4 | The member's revocation window W for the host's commitments is a channel term, with the member's minimum in its conditions; `penalty_send_by` uses it | 4.4; safe absence |
| CH-5 | At every revocation of a host commitment, the member builds and stores the fully signed penalty for it (and for each second-stage transaction the host could publish from it) | Bundle B6; the locked watcher |
| CH-6 | The member's payment claims (second stage) either carry their own fee or are counted as unavailable for a member without coins (`safety-rule.md` C3) | Zero-coin members; 6.5 |
| CH-7 | A fully signed first commitment exists for every member before the funding is broadcast (H9) | The reference fixed the same gap (SuperScalar #313, `tools/test_regtest_mass_exit.sh:10-12` at `490ed626`) |
| CH-8 | The channel engine stops at `exit_started` (X-I3) and re-establishes with data-loss protection (5.7) | Freeze; restore |
| CH-9 | Incoming expiries obey 4.4; invoices carry `min_final_cltv_expiry_delta` ≥ (n + 1)·A + (B − 1) + M | 4.4 |

### 10.2 `local-api.md`

New values (proposed): `watching.state = watcher_locked`; locked status fields `next_action_height`, `unlock_by`; attention codes `exit_needs_fee_coin`, `payments_stopped_for_exit`, `exit_step_late`, `exit_fee_budget_reached`, `exit_missed`, `funding_double_spent`, `restored_commitment_choice`, `unexplained_spend`; `creation_dead` `params.cause`; provenance code `leaf_timeout_less_burial_exit_margin` with inputs `end_height`, `leaf_depth`, `burial`, `steps_missing`, `allowance`, `margins`; `ended_how` gains `void_funding`. Changes: 4.7's "locked: leaves nothing alone" becomes the watcher's table (5.6); `branch_partly_on_chain` is `important` in 1.0.0 (no timed steps); the factory object's `exit.transactions` is d + 3 and `exit.blocks` the lead E − `leave_by`; offline-by-choice ends itself at `leave_by − A` (open point 11).

### 10.3 `journal.md`

The records of 3.4, numbered in draft 3; `exit_plan`, `exit_started`, `exit_step`, `coin_reserved`, `fee_child`, `spend_seen`, `response_sent` are never compacted while their factory is not `ended` or `dead`.

### 10.4 `storage-encryption.md` (being written beside this)

What it must say, from section 5.6 (this document does not edit it):

1. **B6 loses the member's own commitment.** No bundle holds a commitment of the member's own, current or old, completed or not, nor the host's partial signature on one (W2). The watcher therefore **cannot finish an exit**: it publishes the tree path and answers the host's old states; the commitment needs an unlock by `unlock_by`. 8.7.1's table, 8.7.2's B4 and B6, 8.7.4 rule 2 (now moot) and 8.7.5's threat rows change accordingly: an old bundle copy with KB can then publish only the member's tree path (griefing, section 7.1) and the pre-signed host penalties (harmless), and spend set-aside fee coins on fees; it can never publish a revoked state. This answers that review's F1, F2 and F4.
2. The record layout of 5.6 for `watch.gzw`'s contents (its 8.7.6 says "a TLV stream of `spec/exit.md`'s records"); B4 steps are the tree transactions only (kinds 1 to 3); B6 holds the host-state penalties only.
3. B5 adds `leave_by_locked`, `unlock_by`, `last_safe_confirm`, the commitment's latest send height and the constants; the clear `next_action_height` is min(`leave_by_locked`, `unlock_by`, the earliest tree-step deadline of an exit under way), and the clear header should also carry `unlock_by` so the locked page can show it before opening.
4. **B7, the fee steps** (its question): rung 0 is the pre-signed tree transaction at its own 0.1 sat/vB with the keyless **anchor-only child**, always present and needing no fee coin (package rates 0.84 to 1.36 sat/vB in T1, [X6]). Wallet rungs exist only with set-aside fee coins, **one coin per tree step**, at package rates 2, 5, 10, 20, 50, 100 and 200 sat/vB, each paying enough to replace the rung below under 6.3's three conditions; there is **no 1 sat/vB rung**, because it could not replace rung 0 [X7]. Steps starting at 0.1 sat/vB would be pointless: 0.1 is the parent's own pre-signed rate, and every wallet child must out-pay the anchor-only child's 3.69 sat/vB of its own. The griefing row "spend the fee coins on fees" is bounded by those coins.
5. **Payments in flight** (its question): a deliberate lock is allowed but held while an incoming payment's secret is released and unsettled; outgoing payments never hold it (5.6).
6. Rules W1 to W5: one runner at a time; `watch.gzl` merged before the host is contacted; if the watcher published tree steps, the node freezes the channel and broadcasts the commitment first thing after unlock.
7. The watcher needs the clock and the tip-estimate rule (4.5), not only the chain servers, and the locked page's headlines of 5.6.
8. Write cost: with commitments out of the bundle it changes at each host revocation (one new penalty) rather than at each own commitment; an append-only sealed part with its own counter would still avoid rewriting it whole; its choice.
9. The option "do not watch while locked" is refused while any factory has something to take out, unless the person confirms with the date it puts at risk (W5).

### 10.5 `safety-rule.md`, `terms.md`, `MULTI-FACTORY.md`, the chain port, the core contract

- `safety-rule.md`: C5 and section 12 value 2 state the timeouts as in 4.1 (E − 5·(2j − 1) for a fixed kickoff at depth j, E − 10·d for the leaf transaction and the channel); section 7's exit time for 1.0.0 is n·A with no relative delays; C8's "exit time plus margin" is 4.4's signing-time check; add H14 to H17; section 11 adds "a wallet that stays locked past `unlock_by` with a factory balance (the watcher cannot publish the member's commitment)", "a locked wallet whose bundle is turned off" and "a member without on-chain coins when fees exceed the anchors".
- `terms.md`: open point 1 (wind-down for Slice 3 terms).
- `MULTI-FACTORY.md` 4.1: `start_leaving_by` is "the leaf's timeout less burial less exit time less margins", 4.4 here.
- Chain port: `gz_chain_broadcast_package`; block-disconnected events; per-server broadcast results; the servers' mempool floor where reported.
- Core contract (`event.h`, `action.h`): the new events and actions of 3.2 and 3.3.

## 11. Tests

### 11.1 Simulator first

Every row of section 7 as a scenario, honest and adversarial, with the simulator's independent accounting (X-I6). In particular:

1. U-a at d = 1, 2, 3 at the last possible block: the commitment confirms in `step_due(n)` and is buried at H_leaf; the same one block later loses to the host's timeout (the arithmetic's edge, both sides).
2. U-a' and U-b with every subset of the path pre-published; U-c with every member at once.
3. H-a completed and stopped halfway; H-b on an owed member (loss recorded) and on an owed-nothing member (no loss); H17 on: the absent member is paid.
4. L-b, L-c (host breach at every commitment number, with and without payments in flight), L-d with a current and with a stale backup: no automatic publication; the choice offered at `host_force_by`.
5. C-e, C-f, C-g, C-h before and after burial, double-spent; funding replaced by the host (H16 broken): Dead with `funding_replaced`.
6. **Crash at every save point** of 3.4 and between every save and its action: after restart the exit resumes, no coin is double-reserved, no commitment other than the chosen one is ever broadcast, X-I3 holds.
7. **Chain view**: each `connection.chain.state` for a run of blocks at every phase; a server hiding the member's step; a server claiming a far-future tip (the exit starts no earlier than the clock bound); a server pretending to lag; disagreement through `leave_by` (the exit starts by the clock bound).
8. **Locked**: restart never unlocked: the watcher publishes the tree path by `leave_by_locked`, answers a breach with its penalty, shows each headline of 5.6 at its case, and the host's timeout takes the channel output after H_leaf (the expected loss, recorded at a later unlock); unlocked one block before `unlock_by`: the node freezes the channel (W3) and the commitment is buried by `last_safe_confirm`; an older bundle copied over the current one is refused; no bundle version written in any run contains a commitment of the member's (byte search).
9. **Pause** on through an exit: unchanged outcome. **Planner** rules (1.1.0) that try to delay: refused.
10. Fees: a fee spike while a path is half published, with and without wallet coins; the budget reached; a foreign child pinning a version-2 step.
11. Payments: an incoming payment at the acceptance boundary (4.4) accepted and claimed in time; one tick inside it refused; a released secret unremoved triggers `payment_on_chain` at exactly `go_on_chain_by(h)`.

### 11.2 Signet, Slice 1.5 (the study's S1 to S13)

S1 to S13 of `notes/factory-paths.md` 4.1 are adopted as written, with these additions:

- **S2** also records, for every step, the blocks from first broadcast to confirmation (measuring A) and that every step relays alone at 0.1 sat/vB with its anchor-only child; at D = 2 and D = 3 and, at 3 members, d = 1.
- **S3** checks that the second member's `leave_by` moved later by A per step already on chain.
- **S12** establishes which signet servers accept a package, and whether a parent refused alone confirms through a wallet-funded child.
- **S13** adds: the exit's tip estimate under disagreement follows 4.5.

### 11.3 Signet, Slice 3 (exit with a balance; needs `channel.md`)

| # | Test | Pass when |
|---|---|---|
| S14 | M-a: a member with a balance and every rule off; host stopped; app running | The exit starts at `leave_by`, every step by its deadline, the balance arrives less fees (terms with a wind-down ≥ 82, open point 1) |
| S15 | The same with the member's program restarted and left locked until `unlock_by` − 1 | The watcher publishes the tree path from the bundle; the locked page shows the 5.6 headlines in order; at unlock the channel is frozen, the commitment goes out at once and is buried by `last_safe_confirm` |
| S16 | A member with no on-chain coin | Exits with anchor-only children; `exit_needs_fee_coin` never shown at signet's floor |
| S17 | Host breach (a revoked commitment) while the member is locked | The pre-signed penalty confirms before `penalty_send_by` |
| S18 | H17: a silent member with a balance | The host forces it out by `host_force_by`; the member's output on the host's commitment holds its balance |
| S19 | An incoming payment pending at `payments_stop_at` | Settled or failed back; none accepted after |
| S20 | Restore from an old backup | No automatic commitment; the choice appears at `host_force_by` |

### 11.4 Regtest (M5)

The study's 4.2 list, plus: every member exits at once with full mempools at 128 and 512 members; the edge of 11.1 item 1 with exact blocks; a reorganisation of depth B − 1 and B across the commitment's confirmation; a fee spike lasting M_spike + 1 blocks (sets M_spike); pinning on version-2 steps.

### 11.5 Vectors

Section X of `tools/spec-vectors.py` (`python -I tools/spec-vectors.py`) prints and checks: X1 the timeout table; X2 the path shapes and sizes for T1, checked against the split rule; X3 `leave_by`, the step deadlines, `host_force_by` and the wind-down shortfall; X4 the payment and penalty rules; X5 the tip estimate; X6 the anchor-only child's bytes and txid, and package rates; X7 the wallet child's size, the three replacement conditions of 6.3 (a 1 sat/vB child does not replace the anchor-only child), and the ladder's fees, each rung replacing the last. A conforming implementation reproduces every number. A test against the import on the build server (the signed trees of `terms.md` 4.2) must confirm X1's heights from the built scripts.

## 12. Open points for the owner

| # | Point | Recommendation |
|---|---|---|
| 1 | **T1's wind-down (36) is shorter than the exit lead (50 to 82 blocks)**, so a member with a balance leaves before the lifetime ends and rotation with a balance cannot be tested under T1 | Keep T1 for Slice 1 and 1.5 (owed zero). Add terms T3 for Slice 3: lifetime 144, wind-down 108. Add an optional member condition "`leave_by` not before the lifetime's end", on by default |
| 2 | **H17**: honest host software never takes a balance through a timeout; it forces the member out with its own commitment by `host_force_by` | Adopt. It makes M-a safe against honest hosts at a small cost, until the end-date payout replaces it |
| 3 | The watch-and-exit bundle on by default, holding no own commitment, so a locked wallet publishes the tree path but needs an unlock by `unlock_by` for the last step; "maximum privacy" refused while a factory holds a balance unless confirmed with the date | Adopt (aligns `storage-encryption.md` open point 15). A machine that may stay locked for days should not hold a factory balance near its end; the join check can warn when `unlock_by` falls in a period the person marks as away (later) |
| 4 | A restored member never publishes its commitment automatically; at `host_force_by` it is offered as the person's choice, with the exact risk | Adopt: publishing a stale commitment and doing nothing can both lose the balance, but only the person can weigh how old the backup is |
| 5 | `HOST_SILENT_EXIT` 1,008 blocks; `HOST_SILENT_WD` 36 | Adopt as placeholders; revisit with mainnet constants |
| 6 | Fee budget: 25% of the recovered amount, 90% once a step is late | Adopt; shown in the leave-alone preview and Settings |
| 7 | Fee coins set aside for a locked exit (one split transaction, one coin per step) | Off by default (decision 6); offered when `exit_needs_fee_coin` shows |
| 8 | Locking is held while a released payment secret is unsettled | Adopt |
| 9 | **Commitment shape**: a zero-fee commitment strands a member without coins; the tree-fees hand-off (4.7) asked SuperScalar for exactly that shape | For members' commitments: a pre-set minimal fee paid by the host and a 240-sat P2A (CH-2). Tell the SuperScalar session before it acts on 4.7 |
| 10 | Version-2 trees can be pinned through the anyone-can-spend anchor | Keep asking for TRUC trees in the #476 follow-up; until then, rule 6.4.5 and the regtest pinning test |
| 11 | Offline by choice ends itself at `leave_by − A` | Adopt: it is protection, like pause not stopping the exit |
| 12 | Mainnet constants (B, A, M_spike, `WARN_LEAD`, `OPEN_MARGIN`) | Set from regtest and signet measurements before any mainnet build |
| 13 | Pipelining version-2 levels (send a level while its parent is unconfirmed) would shorten exits | Not in 1.0.0: it does not survive the move to TRUC and the arithmetic does not need it |

## 13. Review checklist

1. Section 4.1: do the heights match the import for fixed kickoffs, the leaf's kickoff, the leaf transaction and the channel output, read from `src/factory.c:1635-1644` and `:1314`, and from a built tree's scripts? Is "valid immediately once the parent confirms" true for every tree transaction (nSequence, lock time)?
2. Is `last_safe_confirm = H_leaf − (B − 1)` right given BIP 65 and `IsFinalTx` (a lock time of h is final in block h + 1)? Is `penalty_last_confirm = c + W − B` right for BIP 68?
3. Is n = d + 3 the whole path? Is any relative delay hidden on it?
4. Can any trigger of 5.1 be suppressed by the host, a chain server, pause, the planner or a lock? Can any be forced early by them, and at what cost to the member?
5. Can the node or the watcher ever broadcast a revoked own commitment (X-I3, X-I4, X-I5, W2, W4), including across a crash between any two saves, from an old bundle copy, and across a whole-disk restore?
6. Does every action in 3.4 leave only after its record is durable? Does the start step resume every exit and response?
7. Section 4.5: can a dishonest server delay the exit past `leave_by`? By how much can it bring it forward?
8. Is the anchor-only child standard (size, OP_RETURN, P2A spend with no witness, version matching the parent)? Are 6.3's replacement conditions (a) to (c) the ones current Bitcoin Core applies, before and after cluster mempool, so every wallet child and every rung replaces the one before?
9. Is every path of the study's table that 1.0.0 can reach in section 7, with detection, action, deadline, saved record and display?
10. Does section 8 classify every possible spend? Is S8 truly impossible without the member's key?
11. Do H14 to H17 contradict H1 to H13 or the member's rule?
12. Does anything in the bundle let a thief take coins (`storage-encryption.md` 8.7.5)? Does the bundle hold anything in its "never" list? Can any old copy of a bundle, with KB, do more than publish the member's tree path, the host-state penalties and the set-aside fee children?
15. Section 7.1: is it true that publishing a member's path changes no sibling's funds, channel or H_leaf, and only moves its `leave_by` later? Is every locked case of 5.6 given exactly one headline?
13. Are the T1 numbers in 4.6 those `tools/spec-vectors.py` prints?
14. Is any safety claim here stated without a mark, or stronger than its source?
