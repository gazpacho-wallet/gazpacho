# The funding engine (step P4.5, `core/funding`)

Draft 1, 2026-11-17. The engine of `docs/notes/composite-node.md` 9, 12.1 and 14, journal area 0x0003, written to contract v2 against the composite's engine interface on `main` (`core/node/engine.h`). It is built and tested alone. **It is not wired into `core/node` or `program/` yet**: that waits for P4.3, and the last section lists exactly what the wiring needs.

## 1. What it does

| Role | Step | Where |
|---|---|---|
| Host | The plan of each attempt through the wallet port; the same plan again when nothing was released; with a release (H11) a new plan spending input 0 of the previous one, which the engine checks | `gz_fund_host_plan` |
| Host | H1 before the lobby saves Funding: `gz_tree_h1` against the proposal's record 18 **and** the plan, every spent output a witness program; in AUTO also the wallet's signature, and the signed bytes without witnesses equal the plan | `gz_fund_host_h1` (appends nothing) |
| Host | After the lobby's save: AUTO saves `funding_signed` and a status, broadcasts, watches; CONFIRM saves "awaiting confirmation" and shows the attention item; H1 failed: the plan released, status Failed, a notice | `gz_fund_host_apply` |
| Host | CONFIRM: the person's command 0x0301 signs, checks, saves, broadcasts | handle, USER_COMMAND |
| Host | Burial: Live. An input spent elsewhere and buried: Dead (cancel reason 4) | tick |
| Host | Its funding deadline (its tip at the plan + 36; buried by it: Live; a burial after it: Abandoned, then funded late, with no spend-back): Abandoned (cancel reason 4), then the spend-back | tick |
| Host | Abandoned, then the funding buried first: funded late; the spend-back buried: Dead, nothing more reported | tick |
| Member | From its ack (the first `funding_status`): watches; C11 live, abandoned, late live (`gz_tree_c11`); C4(d) dead (`gz_tree_c4d_dead`) | `gz_fund_member_acked`, tick |
| Both | The slot end conditions: Live, Dead, abandoned, and the height after which no deadline of the scope can pass | `gz_fund_scope_state` |

Every chain-driven end goes out through the one `report` hook, called inside the step after the engine's own save and before its outward actions, so the composite brackets the lobby's and the signing engine's records with it (7.4, brackets Live and Dead or abandoned). The engine never calls another engine.

**One change per tick** (8.3): a NEW_TIP or a chain report records facts and arms the tick; each tick changes at most one factory, round-robin, and arms itself again (at `tick_ms`, 0) while anything is due.

**After a start** (review B of PR 56, H-1). The chain facts are memory only and come back through the watches set at start, but the first NEW_TIP can come before their reports (the program fires due timers before it takes the worker's events). So a factory restored at start takes no deadline decision (the host's abandon, its spend-back's level, the member's Abandoned) until the chain view has answered every one of its watches set at this start: `GZ_CHAIN_WATCH_SYNCED` (`event.h`; `action.h`, WATCHES; `docs/notes/chain-port.md`), sent after whatever the answer found. No count of tips stands in for it, since a block can come before the answers (review B's confirmation: a first version that ended the wait at the next block was shown unsafe). While the servers cannot be asked, no SYNCED comes and the engine waits: the safe side. Live and Dead, which come from reports, are not held back.

**At every tip** (integration review B12, PR #66). The same holds without a restart: a new tip comes before the reports it brings, so a tip that jumps past the deadline while the funding is buried would otherwise look like a funding not buried. The engine takes no deadline or abandon decision at tip T (the same decisions as above) until the chain view reports `GZ_CHAIN_TIP_SYNCED` for T: every watch it holds has had its answer for T, after what the answers found. A later NEW_TIP closes the gate again, until its own TIP_SYNCED. TIP_SYNCED names the tip block's hash, and one for a block replaced at the same height is not this tip's (review B's second confirmation, G-2).

**A watch never answered** (review B's second confirmation, G-1). One watch the chain view can never answer must not freeze every decision on the node: a host can make one on a member by putting into the funding an input spent deeper than the chain view follows (`max_link`). The chain view tells it once, `GZ_CHAIN_WATCH_FAILED`, and leaves it out of TIP_SYNCED, so the other factories decide as ever. For its own factory it is that watch's answer (after a start too), and what it would have told is unknowable, so the factory fails closed at once: a member's is Abandoned (its place in the table is freed); a host's is abandoned with no spend-back, and none is made at later blocks, since what the watch followed cannot be known. Live and Dead, which come from reports, still come first.

**A watch whose answer is put off** (review B's third confirmation). Only a confirmation deeper than the chain view follows fails a watch. An answer put off (a deep confirmation still being linked, an answer too large to fetch) is told pending after a few passes, `GZ_CHAIN_WATCH_PENDING`, and TIP_SYNCED stops waiting for it. The factory it belongs to alone waits: no deadline decision until that watch's WATCH_SYNCED (or WATCH_FAILED), while Live and Dead still come from reports. If the answer never comes, the factory fails closed `GZ_FUND_PENDING_GRACE` (144) blocks past its deadline or past the tip at which the watch went pending, whichever is later, as for a failed watch. Counted from the deadline alone, a node back after a long absence (its funding buried long ago, so linked anew) would fail a buried factory closed at once and cancel every seat (review of PR 72, P-1). A watch told pending before the first tip after a start takes its grace from that first tip (C-1).

## 2. The spend-back and its fee

At the host's deadline, if the funding is not buried, the host spends one input of the funding back to its own wallet (`gzt_funding_spend_back`): input 0, the wallet's largest coin, unless it cannot pay the fee and dust.

- **Level 0, the ordinary rate** (0.1 sat/vB): the funding was never signed (CONFIRM), or the chain servers never showed it (no report on input 0 named it). Nothing to replace.
- **Level 1, the smallest replacing fee**: the funding's fee (the whole evicted package: in Slice 1 the funding has no child; H16's fee child, when it exists, adds its fee here) plus the increment on the spend-back's own size (Core's rules 3 and 4), and above the funding's own rate (rule 6), with the increment of Bitcoin Core 29.1, 100 sat/kvB. `gz_fund_replace_fee`.
- **Level 2**: the same with 1,000 sat/kvB, the increment of Core 28.x and 29.0. Used only after a server refused level 1 (or level 0 refused, which goes to level 1). No further level. Once the funding or a spend of input 0 has a confirmation, no level is raised and nothing is sent again (review A, L10).

The engine checks what the wallet made: one input, the chosen outpoint, one output that does not pay the factory, the exact fee. Its size is measured from the signed bytes and the fee recomputed until they agree.

**H16's exception** is the only replacement of the funding (`safety-rule.md` H16, amended).

## 3. Records

Fields are TLV streams, every type even (journal.md open point 3, settled for this area here).

| Record | Fields |
|---|---|
| `funding_plan` 0x00030002 | 2 scope (32), 4 check (32), 6 attempt (u16), 8 mode (u8: 0 AUTO, 1 CONFIRM), 10 fee rate (u64, sat/kvB), 12 the unsigned transaction, 14 the spent outputs (per input: amount u64, script length u8, script), 16 the factory output's index (u32), 18 the tip when it was planned (u32, the deadline's basis; absent when no tip was known), 20 released (u8, 1: H11, a partial signature of its attempt was released and no plan spending its input 0 accepted yet; the plan is saved again with it) |
| `funding_signed` 0x00030004 | 2 scope, 4 txid (32), 6 the signed transaction |
| `funding_status` 0x00030006 | 2 scope, 4 txid, 6 state (u8: 1 acked, 2 awaiting confirmation, 3 broadcast, 4 live, 5 abandoned, 6 dead, 7 failed, 8 live late), 8 tip at the decision (u32), 10 deadline (u32: the host's abandon height; the member's ack tip + its funding deadline). The member's first write adds 12 the funding transaction, 14 vout, 16 amount, 18 script, 20 ack tip, 22 end height, 24 own depth (u8), 26 holds the whole tree (u8), 28 exit constants A, B, M, M_host (4 × u32), 30 funding deadline in blocks. A host's abandoned status adds 32 the spend-back, 34 its fee (u64), 36 its level (u8), 38 the input index (u32) |

- A status is saved at each decision, not at each confirmation. The chain facts are memory only; the watches report them again at start (node.h rule 4).
- **The member's first status is the anchored-batch write** of journal.md (it changes the watch bundle), saved in the member's outcome bracket with `round_completed`. It carries everything C11 and C4(d) need, so the engine reads **its own area only**: it does not parse the signing engine's records, which P4.3 is changing. composite-node.md 7.3 listed Round records as read by funding; this is the simpler choice, for the reviews to confirm.
- At load a record that does not decode, an unknown even field, a state step the engine never makes (journal.md's transitions, `legal_step`), or a type of the area it does not know is `GZ_ERR_CORRUPT`.

## 4. Limits

| Limit | Value | Why |
|---|---|---|
| Unsigned funding | 8,192 bytes, 197 inputs | `GZ_SIGN_MAX_FUNDING_TX`: the host's own proposal is never refused for its size (P4.3 item 13). The wallet's own cap is 64 inputs today |
| Factories followed | 16 | Host: an open plan per slot, and fundings in flight. Member: creations awaiting funding; past 16, the oldest Abandoned stops being followed; with none abandoned, the new one is followed to its deadline only and then reported Abandoned (never live: the safe side) |
| Ended factories remembered | 64 | `GZ_NODE_MAX_TOMBSTONES` |
| Inputs a member watches | the first 2 | See 5 |
| **Watch budget (T-P45-1)** | 48 = 16 × (1 + 2) | Host 2 per factory (txid, input 0, which also shows the spend-back); member 1 + 2. Counted as distinct keys: a watch two factories share (H11's input 0) counts once and is given back only when the last one ends |
| Timers | 1 | The tick, id 0x46540001 |
| Worst step | 12 actions, 2 × 21,393 + 16 KiB bytes | One save (the signed funding and its status), one broadcast, its watches, a notice, the tick |

## 5. Decisions for the reviews

1. **A member watches the funding's first two inputs, not every input** (signing-round.md 9 says every input). The host's spend-back and H11's reused input are input 0, so a member sees both. A hostile host that spends another input elsewhere leaves the creation Abandoned at its deadline instead of Dead; Abandoned blocks nothing (C10), and that funding can never be live. Watching up to 197 inputs per creation would not fit any registry.
2. **The host's funding deadline: pending the owner.** Draft 1 took the host's tip at the Funding outcome plus 36 plus B. Review A of PR 56 (M3) showed that this makes the host *later* than the members, whose deadline is their ack tip + 36: a burial between the two is Live for the host and late for every member, so the host's lobby is Active while its members may not co-operate. Changed in this PR to the host's tip **at the plan** plus 36, with no B, and a burial after it taken as funded late (Abandoned with no spend-back, then funded late), so the host is never later than a member whose chain view is not behind its own. A member whose view lags the host's still has an earlier deadline. The owner decides the rule (this one, or abandoning at the members' deadline minus B); the code follows this one until then. A plan handed out again for a new attempt (nothing released) takes that attempt's tip as its basis, saved again (review B of PR 56, M-1). When a burial by the deadline is no longer possible (tip + B - 1 past it) the host does not fund: H1 answers `GZ_FUND_H1_TOO_LATE` before the lobby saves Funding, so the lobby ends Failed with cancel reason 4 to every seat and the plan Failed, its coins back (review B's confirmation, N-1); in CONFIRM, once awaiting confirmation, the command answers 409 `too_late`.
3. **The spend-back's levels** (2): level 0 when the funding was never seen, as 14.3 says ("If the host's chain servers no longer see the funding"), with level 1 after a refusal; level 2 only after level 1 is refused. The incremental fee of the servers is not known in advance, so the lowest that works is found by refusal.
4. **The engine reads only its own area** (3).
5. **CONFIRM's "full H1" at the command** is the signature part: the signed bytes without witnesses equal the plan, which H1 already found equal to the proposal at the outcome.

## 6. Tests

- `tests/funding/test_funding.c`: fees and sizes; AUTO to Live with a restart; plans (reuse, H11, the wallet's failures, the factory output twice, a legacy spent output, the 8,192-byte cap at 197 and 198 inputs); H1's every refusal and the release; CONFIRM with a restart, every command result; the deadline in CONFIRM; the spend-back replacing a seen funding, its escalation and its end; never seen, then funded late; reorganisation; Dead by an input; one change per tick; restarts; the member's on-time, abandoned, late live, late refused (no whole tree), dead, not dead by its own funding; shared inputs; the table past 16; corrupt records.
- `tests/funding/test_funding_model.c`: random runs, host and member, with restarts; invariants I1 to I7 in its header.
- `tests/funding/fuzz_funding.c`: every decoder (three records, mutated seed journals, commands, chain events, the transaction walker).
- `tools/mutate-funding.py` over `tests/funding/funding_mutants.txt`.
- `tools/regtest-funding.py`: Bitcoin Core 29.1 regtest, its own data folder, RPC on 127.0.0.1, listen=0, stopped after. A: the funding at 0.1 sat/vB, version 2, is accepted alone and goes Live. B: left in the mempool past the deadline (empty blocks), the spend-back replaces it and is buried: Dead. C: a node with a 1 sat/vB increment refuses level 1, accepts level 2.

## 7. The wiring (after P4.3 merges)

Everything the composite and the program must add; nothing here is done yet.

**`core/gazpacho`**
- `node.h`: `gz_node_config_t` gains `gz_wallet_port_t wallet` (from `gazpacho/funding.h`, or moved to `ports.h`), host only; and the funding settings (`feerate`, `incremental`, `incremental_high`), defaults of `gz_fund_config_default`.
- Done in this PR: `GZ_NODE_MAX_WATCHES` is 112, with `GZ_NODE_FUNDING_WATCHES` (48) in the registry's static assertion; `funding.h` asserts its budget fits it.
- `command.h` or `node.h`: `GZ_CMD_FUNDING_CONFIRM` 0x0301 listed with its results.

**`core/node`**
- `internal.h`: an engine index `ENG_FUNDING` (the confirmation mask, `uint16_t`, still fits: 12 engines); a `gz_fund_t` in `gz_node_t`; `watches.c`'s `budget()` returns `GZ_FUND_MAX_WATCHES` for it, and the static assertion becomes `2 * TE_MAX_WATCHES + GZ_NODE_MAX_SLOTS * TS_MAX_WATCHES + GZ_FUND_MAX_WATCHES <= MAX_WATCHES` (T-P45-1); timers: funding 1, already counted in 7.1's 62.
- Done in this PR (coordinator's decision): **UNWATCH** (`action.h`). The engine appends it for a watch it no longer needs; the registry (`gz_watch_unnote`, `handoff.c`) clears the engine's bit and lets the UNWATCH out only when nobody asks any more; the program (`executor.c`, `pchain.c`) calls the worker's `gz_chainw_unwatch_tx` or `_outpoint`, which frees the place; the simulator traces it. A restart sets again only what the engines still need. Still to do with the wiring: a slot that closes (`gz_watch_forget`) frees its entries without an UNWATCH; the worker keeps them until the next start.
- `composite.c`: the ops `{ GZ_AREA_FUNDING, gz_fund_load, gz_fund_resume, gz_fund_handle, GZ_FUND_MAX_STEP_ACTIONS, GZ_FUND_MAX_STEP_BYTES, GZ_FUND_MAX_TIMERS }`, `reads` = {0x0003} only; the start's step 7 (after the lobbies) runs `gz_fund_resume`; `GZ_NODE_LIST_ACTIONS` and `_BYTES` add the engine's worst step (with the `report` hook's brackets).
- `route.c`: NEW_TIP, TX and OUTPOINT reports, BROADCAST_RESULT, USER_COMMAND 0x03xx and kind 81 to the funding engine (kind 81 is counted and dropped).
- `handoff.c`:
  - attempt bracket (host): `gz_fund_host_plan` first; `res.ok` 0 gives outcome Failed reason 3; the proposal's record 18 is `res.tx`, its outpoint `res.funding`. The `released` flag comes from the signing engine's outcome (P4.3 item 1).
  - Funding outcome (host): `gz_fund_host_h1` **before** the lobby's `round_result`; with a verdict other than 0 the lobby gets Failed reason 3; then `gz_fund_host_apply` in the same bracket, after the lobby's save.
  - lobby ended without Funding (Failed, Cancelled): `gz_fund_host_drop`.
  - member's outcome Complete: `gz_fund_member_acked`, with the funding transaction, outpoint, amount, script, ack tip, end height, own depth, "holds the whole tree", the member's exit constants and funding deadline, from the signing engine's outcome (P4.3: the outcome must carry them, or the adapter reads them from the round it holds).
  - the `report` hook: LIVE: signing `gz_sign_resolve` live (member), the lobby's Active, `slot_closed`; DEAD and ABANDONED: resolve dead or abandoned (member), the lobby's Failed reason 4 with `cancel` reason 4 to every seat (host), `slot_closed`; FUNDED_LATE: the "funded late" notice, the lobby stays Failed. Each in the funding engine's own step, so one bracket.
  - only the funding engine may BROADCAST: already enforced.
- `nodepart.c` / `lobbyslot.c`: a slot's Closing end uses `gz_fund_scope_state`: LIVE or DEAD ends it at once; otherwise at `until` + `GZ_NODE_CLOSING_GRACE_BLOCKS` on the tip (the members' unfinished deadline is the signing engine's). The index of ended lobbies is filled at that end (P4.2's).

**`program/`**
- The wallet port over `wallet/` (`gzt_funding_build` with `require_change`, `gzt_funding_unsigned`, `gzt_funding_prevout`, `gzt_funding_release`, `gzt_funding_spend_back`; the holds in memory), the key from the stand-in until P8. `sign_plan` and `spend_back` act only on a plan the wallet holds, found by its txid, never on bytes handed in (`docs/notes/signer.md`); `adopt(tx, script, amount)` holds a journal's plan again after a restart only if every input is one of the wallet's coins, output 0 is exactly `amount` to the factory's `script`, and the other output is the wallet's change. The factory's output is output 0 (the engine checks it). The engine never asks the spend-back for more than the top of its ladder (the funding's fee plus `incremental_high` on the spend-back's size; at 0.1 sat/vB, 127 sat on 111 vB), and checks it. signer.md's ceiling, the fee policy's ceiling times the spend-back's size (111 sat at 1 sat/vB), would refuse that level 2: the coordinator corrects signer.md; until then this note and `funding.h` are normative for the funding port. The spend-back's destination must come from the wallet's tracked change chain, saved before the spend-back is signed, so a restore from the phrase finds it (the regtest harness uses a fixed index). **The port offers only confirmed coins**, never a coin from a funding (or its change) not yet buried: a plan spending another lobby's unconfirmed change would be evicted with it, and the spend-back's fee would not cover both (review A of PR 56, M5); a test with the port when it is written. The master key is passed by pointer as in the rest of `wallet/tx`, to change with the `signer/` work. `tests/funding/regtest_harness.c` is a working example for one plan at a time.
- H11's reused input in the wallet: done in this PR (`gzt_funding_request.must_spend`): the coin is input 0 of the new plan (the engine checks input 0); the port passes `must_spend` through. Until a plan spending it is accepted, the released plan is kept in memory and in the journal (field 20), held again by the wallet, and never reused (review A, M1).
- `--host-funding auto|confirm` and `--funding-feerate` options; the local API's `settings` later (P6).
- `tests/program/program_funding` (composite-node.md P4.5, cases 1 to 11), against `ports/chain/tests/local_server.py` and on regtest.

**Specs** (changed in this step): `safety-rule.md` H12's scope and H16's exception; `messages.md` 6.10 cancel reason 4; `journal.md` 9's Funding fields, `funding_status` written by the funding engine only, the anchored-batch note.

## The host's funds check (`funds_short`)

Local-api 15.2 refuses a host's lobby open or start with `funds_short` when the wallet's confirmed spendable coins are below what is set aside for it (`gz_fund_set_aside_sat` of its terms, plus what other hosted lobbies hold set aside) **and** the most its funding can pay in fee (review of PR 77, L2: the fee is outside the set-aside). `gz_fund_funds_short(cfg, set_aside_sat, &need, &have)` answers it from the wallet port's optional `spendable` (the sum and count of confirmed coins no plan holds). The fee bound is the funding at the host's rate (`cfg.feerate`, the only rate a funding pays) for as many key-path inputs as the wallet has coins, at most 197, each with its largest witness, plus the factory's output and the change. -1 means the wallet cannot tell, and the caller refuses as for `no_wallet`. The caller is the API's host open (0x0108) and start (0x0109) on `composite-p6a` (PR 77): it passes the lobby's set-aside plus `set_aside_elsewhere_sat`, and reports `need` and `have` in the error's `params` and in `host_funds_short`. The program's wallet port (`program/wport.c`, on `integration-slice1`) fills `spendable` from the wallet's coin list.
