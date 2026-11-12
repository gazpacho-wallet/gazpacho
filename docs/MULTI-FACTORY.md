# Many factories, moving funds, and rolling forward

Design and plan for Gazpacho 1.1.0. Draft 1, 2026-11-12. Not reviewed.

**Why this exists.** The Slice 1 prototype tells a member: "You are already in a factory. You can look at lobbies, but the prototype handles one factory at a time, so joining is switched off until you have left it." The owner, 2026-11-12:

> "we need to fix this for v1.1.0 ... people will want to join a new factory and move funds between channels and setup all sorts of automation and other stuff to keep themselves moving their superscalar stacks around the ln network around close time instead of settling to the L1, so i need you to document that and plan some enhancements and features to help make that happen."

This document says what that means, what changes in each specification, what each feature depends on, and which end-to-end test proves it.

**How claims are marked.**

- **[V]** verified: read in a primary source named beside it (a design post, the reference code, a protocol document, or this repository's own specifications).
- **[I]** inference: our own reasoning or an estimate, not yet reviewed or tested.
- **[P]** proposed here: a design choice for the owner or a reviewer to accept.

Sources read for this draft: this repository's branch `specs-slice1` (`DESIGN.md`, `PLAN.md`, `SLICES.md`, `ux/decisions.md`, `AWAY.md`, `LOBBY.md`, `THREAT-MODEL.md`, `KNOWLEDGE-BASE.md`, the hand-off notes, `spec/safety-rule.md`, `spec/terms.md`, `spec/messages.md`, `spec/discovery.md`, `spec/journal.md`, `spec/local-api.md`, `spec/signing-round.md`, `spec/PROTOCOL.md`); ZmnSCPxj's SuperScalar posts on Delving Bitcoin, topics 1143 and 1242 (raw text), and the implementation report, topic 2705; the SuperScalar reference repository (GitHub `8144225309/SuperScalar`, main at `5f93110`): `include/superscalar/ladder.h`, `src/lsp_rotation.c`, `docs/rotation-ceremony.md`, `docs/trustless-offline-tolerant-rollover-plan.md`; and the prior-art pages listed in section 10.

Words: **host** (the SuperScalar LSP), **member** (its client), **hosting**, **providing liquidity**, **fees**. A member's **stack** is the set of factories it is in at once.

---

## 1. Goals and non-goals

### 1.1 Goals, in the owner's terms

1. **Join a new factory while already in one.** Any number up to a limit, with the same host or different hosts.
2. **Move funds between my channels**, inside one factory (1.1.0 brings several channels per factory, decision 5) and between factories, with one action and a preview of cost and time.
3. **Keep my stack moving around close time** without settling to the base chain: when a factory nears its end, its balance goes over Lightning into a factory that is still live or about to be.
4. **Automation:** standing rules set once ("two weeks before the end, join a lobby that fits and move my balance") that run unattended, inside the member's conditions, with a budget, a preview and a record.
5. **Safety unchanged:** every signature still passes the safe-to-sign rule; the member's own exit and its deadlines never depend on automation working.

### 1.2 Non-goals for 1.1.0

- Several hosts **inside one factory** (still not planned, `PLAN.md`).
- Members adding their own on-chain coins to a factory; swap-in and swap-out (GitHub issue 1). They stay later work; section 4.6 names where they would help.
- Atomic "old factory for new factory" swaps by key hand-over (the reference's PTLC key turnover, section 4.2). Studied here, deferred.
- Refresh in place. Never used: extending a factory always means rotation to a new funding output (decision 9; SuperScalar's finding of 2026-11-12) **[V: `handoff/2026-11-12-advanceless-default.md`]**.
- A custodial "balance" across factories. Each factory's money stays in that factory's channel; the stack view only adds numbers up.
- Mainnet. Signet first, as everywhere.

### 1.3 Why rolling forward over Lightning beats settling on chain

| | Leave alone (on chain) and rejoin | Move over Lightning |
|---|---|---|
| **Fees** | Every transaction on the member's path: in an advanceless tree, each interior kickoff, the leaf's kickoff and state, the channel's commitment, then a sweep of the member's delayed output, then later a new factory's share of funding. Base fees are built in from the host's side in 1.0.0 **[V: `DESIGN.md` 6; decision 6]**, but a fee spike needs anchor bumps paid with on-chain coins **[V: `safety-rule.md` C3]** | Routing fees only: the host's per-payment fee (`fee_base_msat`, `fee_proportional_millionths`, `terms.md` 3) plus any other nodes on the route. With one host, one hop, which the host may price at zero (section 3.4) |
| **Time** | Confirmations for every transaction on the path, then the channel's own delay before the member's output is spendable, which in 1.0.0 is the revocation window, "about two weeks" **[V: `safety-rule.md` 7; the figure is the design's, not measured]** | Seconds once the next factory is live. The wait is the next factory's funding burial (3 blocks on signet in Slice 1, **[V: `safety-rule.md` 12]**) |
| **Privacy** | Publishes the member's branch: tree shape, its position, amounts, timing; the sweep links the exit to the member's next coins **[I]** | Nothing on chain for the member. The hosts on the route see the payment (section 3.5) |
| **Block space** | One path per member; 512 members exiting together is a fee event of its own **[I]**. The reference staggers end dates so "exits across the fleet do not pile onto the same blocks" **[V: topic 2705 post 1]** | None |
| **Capital** | The member's funds are idle for the whole exit | Funds stay usable; only the moving amount is in flight for seconds |

The design posts expect exactly this. ZmnSCPxj: during the dying period clients "can join one of the 2 factories built on the 2 days of the dying period" and transfer funds to a new channel there; a cooperative exit can send funds "over Lightning" to "a new timeout tree with the same LSP, or to another LSP" **[V: topic 1143 post 1]**; "possibly to a new LSP if your current LSP allows it" **[V: topic 1143 post 3]**.

### 1.4 When settling on chain is still right, or forced

**The right answer** when:

- the member wants its coins out of Lightning (cold storage, spending on chain, leaving for good);
- no lobby fits its conditions before its deadline, and none will (section 4.5);
- the amount is large and chain fees are low, so routing fees across hosts cost more than an exit **[I]**;
- the member wants to break the link between its old and new positions, which a Lightning move cannot fully hide (section 3.5);
- in 1.1.0, the balance exceeds its coverage and the member holds no on-chain coin to defend it under a timed layer (decision 5; `safety-rule.md` 8) and cannot move it in time.

**Forced** when:

- the host is gone, or refuses to route out (section 7.2);
- the next factory never becomes live before the member's deadline;
- an old state is published, a neighbour's branch goes on chain, or the chain view is in doubt near a deadline;
- a payment in flight at the deadline cannot be resolved off chain.

Every forced case already has its answer in the 1.0.0 design: the member's software exits by itself before the deadline if nothing else has happened **[V: `DESIGN.md` 7]**. This document adds nothing that can delay that.

---

## 2. Many memberships

### 2.1 What is true already

- **Rotation needs two memberships at once.** For a move by paying across, the member is in the old factory and the new one at the same time, and the owed rule counts "the same total across both factories, less agreed fees; a payment in flight between them counts as in flight, not as arrived" **[V: `safety-rule.md` 5]**. The reference says the same: "the client temporarily has double its account limit while the old and new SuperScalars are still active", and it "must strictly enforce its own account limit while doing per-client maintenance" **[V: topic 1242, later posts]**. So the 1.0.0 core, which has rotation (M4), must already hold at least two factories per member. Slice 1's "one factory at a time" is a prototype limit, not a design one.
- **Keys are per lobby.** Each lobby gets fresh keys under (restore epoch, index) **[V: `safety-rule.md` 9, R2; `journal.md` `key_index`]**. Many memberships need no new key scheme.
- **Records are keyed by lobby.** Lobby, round and funding records carry the lobby identifier or the funding outpoint **[V: `journal.md` 9]**, and the local API's factory identifier is the lobby's fingerprint; "a move goes to a new lobby with a new fingerprint" **[V: `local-api.md`, identifiers]**.
- **One round per output** (C10) already allows rounds on different factories at the same time **[V: `safety-rule.md` C10]**.
- **The interface already carries `factory_id` on every attention item, and `factories_watched` in the status** **[V: `local-api.md`, status and attention]**.
- **The local API limits Slice 1 to one joined lobby and one hosted lobby**, editable, and says 1.0.0 allows several **[V: `local-api.md` open points; owner 2026-11-12]**.
- **The reference host runs a ladder of up to 8 factories** (`LADDER_MAX_FACTORIES 8`, "demo: 3-4 overlapping is sufficient", defaults 4,320 active and 432 dying blocks) **[V: `ladder.h`, identical in Gazpacho's import]**. It has no member-side support for several factories with several hosts **[V: topic 2705 reports none; I: not searched exhaustively in the client code]**.

### 2.2 What the wallet tracks per factory [P]

| Field | Where it comes from |
|---|---|
| Host key, alias, link state, last heard | Existing factory object |
| Balance, receivable, channel capacity; in 1.1.0 several channels and the covered amount | Channel engine; `channels`, `covered_sat` already reserved |
| **End date** (`factory_ends`), **move window opens**, **move by**, **start leaving by**, **open app by** | Schedule engine; all five already in the factory's `dates` |
| **Forcing deadline** of the host (H6): the payout's lock time less the full exit time less a margin | Computed from the tree, shown so the member knows when the host must act **[V: `safety-rule.md` H6]** |
| **Exit cost and time now**: amount, fee estimate, blocks, transactions, what it needs | Existing `exit` object |
| **Move cost now**: same host, other host, estimates and the fee each would take | New (section 3) |
| **Host health** | New, local only: link uptime, rounds completed or stalled (local history, `LOBBY.md`), success of recent payments out through this host, whether a successor lobby was offered in time, fee changes |
| **Successor**: the host's next lobby offered to this factory's members, and its fit | New (section 6) |
| **Rule state**: which standing rule applies, its next action and date | New (section 5) |
| **Payout destination** (1.1.0: a derived address per factory, decision 6) | Existing reserved `wallet/payout` |

### 2.3 Limits [P]

| Limit | Default | Hard limit | Why |
|---|---|---|---|
| Factories at once (member) | 8 | 32 | 8 matches the reference ladder; each costs watching, journal space (about 0.5 MB per member per factory, `journal.md` 7) and one more exit to fund in the worst case |
| Lobbies joined and not started | 3 | 8 | Each holds a seat others could use, and a signing window the app must be open for |
| Factories with one host | 4 | 8 | Concentration (section 7.6) |
| End dates in one 144-block window | 2 | — | Too many simultaneous deadlines (section 7.4) |
| Creation rounds signing at once | 1 | 2 | Signing secrets live only in memory; one at a time keeps restarts cheap (`LOBBY.md`). Two only for a member whose rule moves between hosts on the same day |

Every limit is a member condition, editable within the hard limit, with the tightening rule already decided for Slice 1: tightening leaves a lobby that no longer fits; loosening affects only future joins (owner, 2026-11-12).

### 2.4 The interface: the stack [P]

- **Home shows one strip per factory**, most urgent first: ordered by the earliest date that needs the member (`start_leaving_by`, then `move_by`, then `open_app_by`), with anything `at_risk` above all.
- Each strip: host name (marked unverified unless proven), balance, receivable, a bar from start to end with today's position and the move window shaded, the next date in words ("move by Thursday"), host health as one word (`good`, `slow`, `not answering`), and the rule that will act ("will move to Tomato Garden 13 on 3 Dec").
- **"My money"** adds every factory, with on-chain coins and set-aside amounts separate, as today. In 1.1.0 the covered total sits beside it.
- **A timeline** (one row per factory, end dates on a shared axis) shows laddering and clashes at a glance.
- **"Move funds"** is one action on the stack: from, to, amount; the preview gives each path's fee, time and what it reveals, and the cheapest is chosen by default.
- **Joining while in a factory** is ordinary: the lobby list shows "you are in 2 factories; joining this makes 3", the limits that would apply, and how the new end date sits on the timeline.
- The Slice 1 sentence quoted at the top is replaced by that line.

### 2.5 Changes to the specifications

**Safety rule (`spec/safety-rule.md`).** The rule stays per request: "after this signature, can I still leave alone, in time, with what I am owed". What changes:

1. **Owed across factories.** The "rotation by paying across" row becomes general: **a move between any two of the member's factories** keeps the total, less agreed fees, with the payment in flight counted as in flight on both sides until it settles. A circular route through other nodes counts the same way **[P]**.
2. **New global check G1, the deadline load.** Before joining, refuse a factory whose `start_leaving_by` falls within the clash window of more other factories than the member's limit allows, unless the member's fee funds cover every exit in that window at the member's stress fee rate **[P]**. This is the one check that looks at the whole stack.
3. **New global check G2, the safe absence.** The maximum safe absence shown is the minimum over every factory, and a join that would lower it below the member's own floor is refused **[P]**.
4. **New global check G3, coverage (1.1.0).** No move, manual or automatic, may take a channel's balance above its covered amount unless the member holds the on-chain coin decision 5 requires **[P]**.
5. **C13 for moves.** A move is two payments to the safety module: an outgoing one in the source factory and an incoming one in the destination. Each is checked in its own factory. The incoming one needs the destination live (C11) and its deadline room (section 7 of the rule).

**Journal (`spec/journal.md`).** Records are already keyed per lobby. Add: a **stack record** (the member's factory list and limits, saved before a join); **rule records** (each standing rule, its version and the person's confirmation, saved before the rule first acts); **move records** (a move's plan, the two payment hashes, its state; saved before the outgoing payment is offered, so a restart resumes or settles it). Journal size grows linearly with factories; compaction (open in `journal.md`) becomes necessary before a member runs a long ladder **[I]**.

**Local API (`spec/local-api.md`).** Lift `already_in_lobby` to the stack limits (error becomes `stack_limit` with the limit named). Add `GET /api/v1/stack` (the strips, ordered, with the timeline), `POST /api/v1/moves/preview` and `POST /api/v1/moves`, `GET /api/v1/moves/{id}`, and `GET`/`PUT /api/v1/rules`. `status.doing` keeps its single value with its stated priority; a second simultaneous activity shows in the stack, never hidden. Attention items already carry `factory_id`; add `move_failed`, `deadline_clash`, `host_cap_reached`, `rule_paused`, `rule_budget_used`.

**Lobby engine (`docs/LOBBY.md`).** State per lobby, as now, plus:

- **Conditions are global with per-host and per-rule overrides.** A standing rule may narrow conditions (a lower fee ceiling for automatic joins), never widen them **[P]**.
- **Concurrency.** Several gathering lobbies at once; signing windows of different hosts may overlap; the app keeps every signing round's secrets in memory only and runs them on separate state machines. If two starts collide and the member allows one signing at a time, it signs the one whose rule is more urgent and un-readies the other with a stated reason **[P]**.
- **Personal block lists and local history apply across hosts**, as now.
- **One identity per lobby by default**, as now. Several memberships with one host do not reuse a name or a key.

---

## 3. Moving funds between factories and channels

### 3.1 The paths

| Path | How | Release |
|---|---|---|
| **A. Between my channels in one factory** | 1.1.0 gives a member several channels in one factory, each made by a sale (decision 5). A payment from one to the other through the host: one hop, both channels with the same host | 1.1.0, with sales |
| **B. Between my factories with one host** | A payment out of factory F1's channel to the host, and from the host into factory F2's channel. The host's own node forwards it between two of its channels. One hop | 1.1.0 (paying across for rotation is 1.0.0, M4) |
| **C. Between my factories with two hosts** | A payment out of F1 (host A), across the network, into F2 (host B). A circular payment to oneself | 1.1.0 |
| **D. Same host, closing into the next factory** | A signing round spending the old funding output into the new one, carrying balances as opening balances. Needs every signer of the old root; if some do not rotate, it falls back to paying across **[V: `signing-round.md` 5; `safety-rule.md` 5]** | Later (section 8) |
| **E. Through the chain** | Leave alone, then join and be paid in again; or a swap | Always available; swaps later |

### 3.2 What liquidity each needs

Members start at zero and are paid in over Lightning; the host funds everything **[V: `DESIGN.md` 7]**. So:

- **The destination channel must have room to receive.** A new channel's receivable is its capacity less any balance: `channel_sat` or more for a new member (`terms.md` 3). A move of b needs receivable ≥ b plus fees. A member moving more than one channel's room must split across channels, factories, or buy room (1.1.0 sales).
- **Path B:** the host needs b on its side of F2's channel, which it has by construction, and nothing on the public network **[I]**.
- **Path C:** host A needs b of outbound liquidity from its routing node towards the network; host B needs b of inbound from the network and b on its side of F2's channel. Intermediate nodes need b along the route. At close time, every member of host A's ending factory may be moving out at once, so host A's outbound drains exactly when it is most needed (section 7.1) **[I]**.
- **The host's capital during a move.** Paying across means the host funds F2 before F1's capital comes back: F1's capital returns only when F1 closes. ZmnSCPxj: the LSP "funds the new mechanism from the mechanism that expires today", and a longer dying period means "the more extra funds the LSP has to dedicate to the construction" **[V: topic 1242]**. Transitioning a large client needs the LSP to "put up funds that is at least the account balance" of that client **[V: topic 1242]**.

### 3.3 Cost

- Path A and B: the host's per-payment fee, which its terms fix and the member checked at join (`fee_base_msat`, `fee_proportional_millionths`). A host may set a different, lower fee for moves between its own factories (section 3.4).
- Path C: host A's fee, the route's fees, host B's fee. Circular rebalancing tools on ordinary Lightning nodes cap this with an absolute limit, a parts-per-million limit, and a check against expected value **[V: rebalance-lnd README]**; Gazpacho uses the member's `max_move_fee_sat` condition (already reserved in the conditions object **[V: `local-api.md` conditions]**) plus a ppm ceiling.
- Path E: every transaction on the exit path, a sweep, the time of the revocation window, and the next factory's join fee. The preview shows E beside B and C so the member sees why the Lightning path was chosen.

### 3.4 A cheap or free "move between my factories" with one host [P]

A host gains from keeping members: a member who moves with it keeps paying fees, and its capital in the old factory is freed sooner. So the terms may carry:

- **`internal_fee_ppm` and `internal_fee_base_msat`** (new even adjustable types, ranges): the fee for a payment between two channels of the same member with this host, in any of the host's factories. Zero is allowed and expected.
- **`move_fee_sat`** (new even adjustable type, range; the fee reserved for "recurring, at each move" in decision 2): a flat fee charged once per move into this lobby's factory, taken from the first payment received there, like the joining fee. Replaces the joining fee for a member arriving from the host's own ending factory, if the host chooses.
- **`successor_of`** (new even fixed type, optional): the outer digests of the host's factories whose members this lobby is meant for. A member whose factory is listed may treat the lobby as its rotation lobby (section 6).

How the member's app checks it: an internal payment is recognised because both channels are the member's own, with the same host key; the host's fee on it must be within the frozen `internal_fee` values of **both** factories' terms. A host that charges more is refused at the payment, as any fee above the signed terms is (decision 2: "a host cannot take any charge the member has not signed").

### 3.5 Failure modes

| Failure | What the member sees | What the app does |
|---|---|---|
| No route, or route fee above the limit | "Could not move: no route under 500 sats" | Retries with smaller parts (multi-part payments), later, or another destination; never raises the limit by itself |
| Destination has too little room | Preview refuses with both numbers | Splits across channels or factories, or waits for a successor with larger channels |
| Destination not live yet (funding not buried) | "Waiting for the new factory to confirm" | Waits; C11 forbids receiving before |
| Payment stuck in flight | "Pending; returns by …" with the date | Counted as in flight on both sides; resolves on chain if needed before the source's deadline |
| Host A refuses to forward out | Health becomes `refusing` | Tries path B with host A (if it offers a successor), else the fallback (section 4.5) |
| Host B accepts the payment but does not settle into F2 | The member is the final recipient and holds the secret only after its own channel commits the HTLC; standard Lightning rules apply | Nothing is lost: the payment fails back to F1 **[I: holds if the destination invoice is created by the member's own app in F2, as it is]** |
| A crash in the middle | On restart the move record names both payment hashes | Resumes, or waits for the HTLC to resolve; never pays twice (request ids, journal) |

### 3.6 Privacy

- **Path A and B** reveal nothing the host does not already see: it sees every payment of its members **[V: `THREAT-MODEL.md` 2.1, accepted]**. It learns the member holds both factories, which it knows anyway.
- **Path C** shows host A a payment leaving towards some destination, and host B an arrival for its member; with route blinding in the member's own invoice, host A does not learn which of host B's members it is **[I]**. Hosts that collude, or one operator running both, can link the two by amount and timing. **Close time makes timing correlation easy**: everyone moves in the same window **[I]**.
- Mitigations **[P]**: move in several parts over hours, not one payment at the deadline; start early in the window at a random time; round amounts are avoided; derived payout addresses per factory (decision 6) so on-chain fallbacks do not link; fresh identity per lobby (already the default). A later Tor carrier hides the network address (reserved in the local API).
- The spread rule ("at least N hosts", section 5) trades privacy one way for another: more hosts each see less, but more parties see something. The preview says so.

---

## 4. Rolling forward at close time

### 4.1 The dates

Per factory, all already in the schedule engine's vocabulary **[V: `local-api.md`, factory dates]**:

| Date | Meaning |
|---|---|
| `factory_ends` | The tree's end height E: start + `lifetime_blocks` + `winddown_blocks` (`terms.md` 3; design: about 4,320 + 432 **[V: topic 1143 post 1, `ladder.h`]**) |
| `move_window_opens` | The end of the lifetime, the start of wind-down: from here the host offers the next factory |
| `move_by` | The last moment a move can still start and settle off chain (below) |
| `start_leaving_by` | E less the member's exit time less margin (`safety-rule.md` C5, section 7) |
| Host forcing deadline (H6) | The payout's lock time less the full exit time less a margin: after it, a host that has not forced a silent member's path loses to the payout **[V: `safety-rule.md` H6; `handoff/2026-11-11-review-of-end-date-payout-draft.md`]** |

**Advanceless trees make these close together.** With every level fixed, each level adds only a confirmation allowance, "the forcing deadline is just before the end date" **[V: `handoff/2026-11-12-advanceless-default.md`]**, and a member's exit time is the confirmation allowance per transaction on its path plus margin, with no 432-block waits per timed level **[V: same; KNOWLEDGE-BASE 4]**. At Slice 1's allowance of 6 blocks per transaction plus 6 of margin **[V: `safety-rule.md` 12]**, a path of five or six transactions gives an exit time near 40 blocks **[I]**. From 1.1.0, a factory with a timed level adds about 432 blocks per timed level on the path **[V: KNOWLEDGE-BASE 4]**.

**`move_by` for a Lightning move.** An outgoing payment from the source factory is safe only if, should it get stuck, the member can still reclaim it on chain before the source's competing claims. So:

```
move_by = start_leaving_by − (route's total CLTV delta) − (time to claim an HTLC on chain) − margin
```

For path B, one hop with the host's delta. For path C, several hops; at common per-hop deltas of tens of blocks, a few hops cost one to two days **[I: per-hop defaults vary by node software; to measure on signet]**. So cross-host moves must start days before `start_leaving_by`, not hours.

**The destination's own rule.** Receiving into the destination needs the payment's deadline later than now + the destination's exit time + claim time + margin **[V: `safety-rule.md` 7, "Accepting a payment"]**. A destination near its own end cannot receive; the planner never picks one whose `move_by` would come before the source's balance could be useful there.

### 4.2 (a) Same host: rotation into its next factory

What the reference does **[V: `src/lsp_rotation.c`, `ladder.h`]**: phase A, "PTLC key turnover": each cooperating client releases, through an adaptor signature bound to the dying factory's txid, the new factory's nonce and the rotation epoch, the scalar of its key in the dying factory; phase B, a cooperative close of the dying factory when every client's key is extracted and every client is online, or else "partial retirement" (the old factory "expires naturally, distribution TX protects participants"); phase C, creating the new factory; phase D, reinitialising channels. Retries back off exponentially, three by default. The rollover plan records that the stateless creation path left the distribution transaction unsigned, so partial rotation's protection for absent clients was "unsound as shipped" until fixed **[V: `docs/trustless-offline-tolerant-rollover-plan.md`, G1]**. The design posts expect clients to come online "on the specific times that the LSP is constructing the new factory", try "on the next day" if they miss it, and exit if they miss the last day **[V: topic 1242, quoted in `docs/rotation-ceremony.md`]**.

Gazpacho's 1.0.0 plan (M4) is **paying across**, with closing-into as an optimisation reserved as round purpose 5 **[V: `messages.md` 10.5; `PROTOCOL.md` 8.1]**. The flow, for a member whose rule says "move with this host if the next factory fits":

1. **Before the window.** The host opens a successor lobby (section 6) and offers it to F1's members over the existing connection. The member's app fetches its terms and runs the fit check against the member's conditions, whole range by default.
2. **Join.** If it fits and the rule allows, the app joins and readies. Joining is consent; the app signs at the start without asking, within conditions **[V: `local-api.md`, "Joining is consent"]**.
3. **Signing and funding.** The successor's creation round runs; the host funds last; the member waits for burial (C11). F2 is now live with balance zero and receivable `channel_sat` or more.
4. **Pay across.** The app makes an invoice in F2 for the amount (balance less fees, within F2's receivable), and pays it from F1 through the host (path B). Owed is the same total less fees, in flight while it settles.
5. **Repeat** in parts if the balance exceeds F2's room, or move the rest elsewhere.
6. **F1 ends.** With a zero balance in F1 the member owes nothing and is owed nothing there; a later cooperative close or the host's own path and payout handle the rest. A zero-balance member needs no on-chain action (decision 6).

### 4.3 (b) Another host's factory, over Lightning

Same as (a), with path C instead of B, and with discovery instead of a successor offer: the app looks for lobbies whose terms fit and whose host passes the member's rules (caps, spread, avoided hosts, health). It must start earlier, because the route's CLTV delta is larger and the destination must be live first. The rule's lead time therefore defaults to the whole wind-down plus a week before it (section 5.2).

### 4.4 (c) Laddering

The host's ladder is the design's: daily factories, about 30 days active and 3 dying, so about 33 at once **[V: topic 1143 post 1]**; staggered so exits do not pile up **[V: topic 2705]**. The member's ladder is new **[P]**:

- **Hold two or three factories with end dates at least a week apart**, ideally with two hosts. There is then always a live factory to receive into, and a move never has to wait for a new lobby to fill and fund.
- When one nears its end, move its balance into the one that ends latest, if it has room; open a new membership only to keep the ladder's length.
- **Cost:** each extra membership costs a joining fee (if any), a seat, and watching. With members starting at zero, holding an empty membership costs no capital **[I]**.
- The timeline view (2.4) shows the ladder and its gaps; a rule "keep at least 2 factories, ends at least 7 days apart" maintains it.

### 4.5 (d) When nothing is available

If no destination is live in time, the member falls back, in order:

1. **Keep the balance in a factory that is still live** (another rung of the ladder), even if it is not the preferred host.
2. **Stay in F1 to the end.** In 1.0.0 a member's balance can never exceed its channel capacity (decision 5). Once the end-date payout lands (SuperScalar round 2, not yet in Gazpacho's import **[V: `handoff/README.md`]**), doing nothing means either the host forces the member's path by its forcing deadline, paying it its balance, or the payout pays it its full channel capacity, which the posts give as "equal to the total channel capacity of that client", "without any funds going to the LSP" **[V: topic 1143 post 26; topic 1242]**. Either way the member gets at least its balance, to its payout destination (one wallet in 1.0.0, derived addresses in 1.1.0). **Until the payout lands, Gazpacho's member must exit before `start_leaving_by`**, because every tree node still has a host-only timeout **[V: KNOWLEDGE-BASE 4]**.
3. **Leave alone before `start_leaving_by`**, automatically, if (2) is not safe: the payout has not landed, or the balance exceeds coverage (1.1.0), or the chain view or fees put the payout at risk.

The fallback is armed from the day the member joins, by the schedule engine, independently of every rule.

### 4.6 What must never depend on automation

- **The member's own exit path and its deadline.** The automatic exit before `start_leaving_by` is part of the 1.0.0 core and runs whatever the rules say, including when every rule is paused or broken.
- **Watching** and answering an old state.
- **The safe-to-sign check.** A rule only proposes; the safety module decides, as for any request.
- **The deadline arithmetic.** A rule's own deadline (`give up by`) is computed by the schedule engine and is always earlier than `start_leaving_by`; a rule cannot set it later.
- **Pause** stops rules, never protection: pause already stops joining and readying but keeps watching, moves already agreed and leaving alone **[V: `local-api.md`, pause]**. A move already under way (payment in flight) finishes or fails back; a move not yet started does not start.

Where splicing, JIT channels, receiving-room sales and swaps (1.1.0 and later) would help: buying room in the destination before a large move (sales, 1.1.0); a channel opened on demand by host B when F2 is not ready (JIT, 1.1.0); a swap-out to chain when no factory is available and the member wants coins on chain cheaply (later, issue 1).

---

## 5. Automation: standing rules

### 5.1 The shape

A new core engine, **the planner**, beside the schedule engine. Events in, actions out, like every engine **[V: `DESIGN.md` 4]**. On each block and each relevant event it reads the stack, the rules and the lobbies known, and proposes actions: join, ready, move, leave a lobby, tell the person. Each proposal goes through the same paths as a person's request: the fit check, the safe-to-sign rule, the stack limits. The planner holds no keys and has no path the person's own requests do not have **[P]**.

Prior art for unattended rules with limits: Phoenix waits and retries a swap-in when the fee would exceed the user's maximum, or rejects the payment **[V: ACINQ, "Phoenix splicing update"]**; Ark clients renew expiring outputs automatically in the background, Second's VTXOs from rounds lasting 28 days **[V: second.tech docs, lifetime; docs.arkadeos.com, batch expiry]**; Wasabi's automatic coinjoin is off by default and, when on, has a maximum mining fee (default 50 sat/vB) and a stop threshold (default 0.005 BTC) **[V: docs.wasabiwallet.io]**; JoinMarket's tumbler takes counterparty counts and fee caps and warns it can take "hours or days" **[V: JoinMarket tumbler guide]**. Ark's renewal is the closest analogue to rolling forward: the output is moved into a new batch with a new expiry before the old one can be swept **[V: second.tech]**. Two differences: under the inversion of the timeout default the expiry favours members, not the operator, once the payout lands; and Gazpacho never refreshes in place.

### 5.2 The rules [P]

| Rule | Parameters | Default |
|---|---|---|
| **Roll forward** | Lead time before `move_by`; preferred host (same, any, list); amount (all, all but X); give-up time | On, "same host if it fits", lead time = from `move_window_opens`; ask before moving to another host |
| **Keep at most X per host** | Sats, or share of total | Off; suggested 50% when two or more hosts are in use |
| **Spread across at least N hosts** | N; applies only when total > a floor | Off |
| **Rebalance when a channel is below Y** | Y receivable or Y balance; source order | Off |
| **Ladder** | Minimum factories; minimum spacing of end dates | Off; suggested 2, 7 days |
| **Settle to chain only if no lobby by deadline minus Z** | Z | Z = 2 days before `start_leaving_by` for same-host plans, 4 days for other hosts **[I: to set from signet measurements]** |
| **Budget** | Fees per 30 days; per move; per join | Per move = `max_move_fee_sat`; per 30 days 0.5% of the total moved; joins count the joining fee |

Rules compose in a fixed order: protection first (never configurable), then roll forward, then caps and spread, then rebalance, then ladder. A conflict is resolved by the earlier rule and recorded.

### 5.3 How rules are bounded by the member's conditions

- A rule can only **narrow** conditions: an automatic join must be **Fits** against the whole range; **Fits only now** is never joined automatically, whatever the member's `compare_with` setting for manual joins **[P]**.
- Every fee a rule causes is inside the frozen terms of the factories it touches and inside the rule's budget. When the budget is used, the rule stops and says so (`budget_used` already exists for automatic joining **[V: `local-api.md`]**).
- Stack limits (2.3) bind rules as they bind the person.
- A rule may not choose an avoided host, a lobby with a blocked person, or a host whose health is `refusing` or `not answering`.

### 5.4 Unattended signing

Joining is consent, and signing at the start then happens without asking **[V: `local-api.md`]**. A rule-made join is consent **only because the person confirmed the rule** with its preview: the confirmation names the rule, its bounds and its budget, and is saved in the journal before the rule first acts **[P]**. Moves are payments; the person's confirmation of the rule covers payments inside its bounds. Anything outside them asks.

The app must be running to sign: a phone or a closed laptop misses the signing window (open question Q7 in `OPEN-QUESTIONS.md`). Rules therefore schedule moves early enough that one missed day still leaves a retry, as the design expects ("try on the next day") **[V: topic 1242]**. A companion device the member owns, signing within the member's conditions, is the later answer (`AWAY.md`); no watcher ever holds keys.

### 5.5 What the interface shows

**Before:** each rule as a sentence ("Two weeks before a factory ends, join a lobby that fits, with Tomato Garden if it offers one, and move my balance; at most 2,000 sats in fees a month"), its next action and date on the strip it will act on, a dry run ("in the next 30 days this rule would: join 1 lobby, move 182,400 sats, cost about 180 sats"), and a pause switch per rule.

**After:** an Activity entry for every action with the rule's name and version, the conditions it checked, the fees taken against the budget, and "undo" where undo means something (leave a lobby not yet started).

### 5.6 What is logged

In the journal: the rule and its confirmation; each proposal the planner made, whether it was carried out or refused and why; each move record. In Activity: every action with its rule. Nothing about rules is sent to any host: a host sees joins and payments, never the rule behind them **[P]**.

---

## 6. The host side

### 6.1 What hosts need to offer

1. **Successor lobbies that open before old factories close.** A lobby per ending factory (or per day of the ladder), open from at least a week before `move_window_opens` to the end of wind-down, so members can be live in the new factory before they need to move. The reference already retries rotation with back-off **[V: `lsp_rotation.c`]**.
2. **Standing invitations for existing members.** Over the existing connection, never listed: "factory F1's members have a seat in lobby L2 until date D". Seats held for them count as standbys until they ready. An invitation reveals nothing new to the member or to others **[P]**.
3. **Liquidity for the overlap.** The host funds F2 before F1's capital returns (3.2). Its funds limits (`max_per_factory_sat`, `max_total_sat`, already in host setup **[V: `local-api.md`]**) must cover two ladders' worth at the overlap; the host's earnings page shows the overlap cost.
4. **Prices for moves.** `internal_fee_*` and `move_fee_sat` (3.4); zero is the competitive default **[I]**.
5. **Outbound liquidity at close time** for members who leave to other hosts, or an honest statement that the host routes out at a stated maximum per day. A host that cannot route out loses members to the fallback, at its own cost under the payout **[I]**.
6. **Closing the old factory.** When every member has moved, the host closes F1 cooperatively or, for members who did not answer, forces their paths by H6 or lets the payout run. Members with zero balance cost nothing to leave behind.

### 6.2 How discovery helps

- **Beacons announce successor lobbies** as any other lobby; the listing is the outer terms record, so `successor_of` (3.4) travels in it and every reader checks it **[V: `discovery.md` 5]**.
- **The churn limit** is 8 new beacon numbers per 144 blocks, 4 opens and 4 withdrawals a day **[V: `discovery.md` open point 16]**. A daily ladder with one successor lobby a day fits; a host opening more must use invitations for the rest.
- **The member's app watches its own hosts' listings** and, for path C, the pool of other hosts, within the query rate limits (once per host per hour unless the person asks **[V: `local-api.md`, discovery]**).
- A listing never says who joined **[V: `discovery.md`]**; nothing here changes that. A `successor_of` field says which factories a lobby succeeds, which is the host's own public history (funding is on chain anyway).

### 6.3 Host interface

The host's ladder page (already 1.0.0, `GET /api/v1/host/factories` **[V]**) gains: per ending factory, members moved, moving, not answered, balance still inside; the successor lobby's fill; the overlap capital; outbound liquidity left for moves out today.

---

## 7. Safety and threat analysis

Additions to `THREAT-MODEL.md`. None removes a protection the 1.0.0 model has.

### 7.1 Liquidity griefing

| Attack | Effect | Answer |
|---|---|---|
| Someone drains host A's outbound liquidity just before close time (large payments out and back, or HTLCs held to their expiry) | Members cannot move out over path C | Start moves early (rules default to the start of the window); prefer path B with host A's successor; split into parts; fallback to payout or exit. Not fully defended **[I]** |
| Someone fills host B's successor with seats and never readies | F2 does not start or starts small; members cannot move in | Already answered by standby seats, host removal and seat costs (decision 10, `LOBBY.md`); the member's rule tries another destination |
| A member holds an incoming HTLC in F2 to the last moment | Host B's liquidity tied up | Host's ordinary limits (H10, HTLC caps) |
| Many members hold empty memberships to keep options | Host's seats and watching used | Joining fees, seat costs (later), host limits on members with zero balance at a successor lobby **[P]** |

### 7.2 A host that refuses to route out at close time

A host that wants to keep members can fail payments out while offering its own successor. **Defence:** the member's rule never needs host A's cooperation for the member's safety, only for its preference: if host A refuses, the member stays to the payout (which costs host A, under the inversion: "the LSP always has something to lose at the timeout" **[V: topic 1242]**), or exits. Host health records refusals, and the member's later rules avoid that host. Refusal is not provable to others (silence is not provable, `LOBBY.md`), so there is no public mark **[V: `THREAT-MODEL.md` 2.1, refusal of service accepted]**.

### 7.3 Fee spikes

- Lightning moves are not affected by chain fees, except that the destination's funding must confirm. A host pays its own funding fees.
- The fallback is: on-chain exits under spikes need anchor bumps paid with the member's own coins, and 1.0.0 recommends none (decision 6). **So under a spike the roll-forward path matters more, not less**; rules should move earlier when the stress fee rate is high **[P]**.
- G1 (2.5) refuses stacks whose exits all fall in one window unless the member's fee coins cover them.

### 7.4 Too many simultaneous deadlines

A member in eight factories that all end within a day, with every host gone, needs eight exits in that day. **Answer:** the clash limit (2.3), G1, the ladder rule's spacing, and the timeline view. Host-side, the reference's stagger has the same aim **[V: topic 2705]**.

### 7.5 Automation bugs

| Risk | Answer |
|---|---|
| A rule moves funds to the wrong place | Moves only between the member's own factories, to invoices made by its own app; a move to anything else is not a rule action **[P]** |
| A rule loops (moving back and forth) | A move is never proposed into a factory the same rule moved out of in the last 144 blocks; per-30-day budget; a cap of moves per day |
| A rule joins too many lobbies | Stack limits; joined-not-started limit |
| A rule misses its deadline | The fallback exit is independent and earlier than any rule could push it (4.6) |
| A rule spends above its budget through retries | Budget counts attempts' fees, including failed parts |
| The planner's view of the chain is wrong | Rules stop when the chain view is in doubt (`chain_view = in_doubt`), as joining does now |

Testing: the simulator runs the planner with seeded random rules, crashes at every save, and checks two new invariants after every step: **the member's total across factories never falls by more than the fees it agreed**, and **every factory always has an armed exit that meets its `start_leaving_by`** **[P]**.

### 7.6 Correlation and privacy across factories

- One host with several of the member's factories sees them all: it does anyway for payments. Fresh identities per lobby hide nothing from a host that sees the same network address; Tor (later) hides that **[I]**.
- Two hosts that collude link a member by move amount and timing (3.6).
- On chain: derived payout addresses per factory (1.1.0) keep fallbacks unlinked; one wallet (1.0.0) links them **[V: decision 6; `handoff/2026-11-12-to-superscalar.md`, privacy cost]**.
- Concentration: a member with all its funds in one host's factories depends on one host; the per-host cap and spread rules exist for that, and the preview says what they cost in privacy.

### 7.7 Coverage (1.1.0)

With sales, a balance can exceed coverage; a member above coverage under a timed layer has under a day of safe absence and needs an on-chain coin **[V: `safety-rule.md` 7, 8; decision 5]**. Moving resets coverage in the destination (decision 5). G3 (2.5) keeps moves from creating that state; the roll-forward rule treats "above coverage" as a reason to move early.

---

## 8. Features by release

Each feature names the specifications it changes, what it depends on, and the end-to-end test that proves it. The owner requires an end-to-end test for every new or skipped feature. "E2E" means the real programs on signet (or regtest where the chain must be controlled), driven through the interface or the local API, as in the slice walkthroughs.

### 8.1 Prerequisite in 1.0.0 (already planned work, made explicit)

| # | Feature | Spec changes | Depends on | E2E test |
|---|---|---|---|---|
| P1 | **Two concurrent factories per member in the core**, needed by rotation | `journal.md` stack record; `local-api.md` lift the Slice 1 limit to 2 for moves; `safety-rule.md` owed row generalised (2.5 item 1) | M4 rotation | One member, one host: F1 live, joins successor F2, both live, restart the member mid-way, both factories intact and correctly shown |
| P2 | **Pay across with the same host** (path B) | `move.md` (reserved, kinds 448 to 511) | Slice 2 payments; M4 | F1 balance 100,000 moves to F2 through the host; totals equal less the host's fee; kill the member during the payment, restart, no loss and no double payment |
| P3 | **Fallback exit armed per factory** | Schedule engine; `exit.md` | M3 | Member in F1 with every rule off and the host stopped: the app exits alone before `start_leaving_by` and gets its balance |

### 8.2 1.1.0

| # | Feature | Spec changes | Depends on | E2E test |
|---|---|---|---|---|
| F1 | **The stack**: many factories, same or different hosts, with limits | `local-api.md` `GET /stack`, `stack_limit`; `journal.md` stack record; `LOBBY.md` concurrency; `safety-rule.md` G1, G2 | P1 | One member joins 3 factories with 2 hosts on signet; the stack shows them most urgent first; a 4th join past the member's limit of 3 is refused with `stack_limit`; restart loses nothing |
| F2 | **Move funds** (paths A, B, C) with preview | `move.md`; `local-api.md` moves; `safety-rule.md` C13 for moves | P2; for path A, sales and several channels per factory (decision 5); for C, the host's Lightning node adapter (`HOST-NODES.md`) | Path B and path C each move 50,000 sats; path C between two hosts linked through a third node; preview fees within 10% of actual; a move above the destination's room is refused with both numbers |
| F3 | **Successor lobbies and standing invitations** (host side) | `terms.md` `successor_of`; `messages.md` an invitation message in the session family (35 to 63, reserved for invitations **[V: `PROTOCOL.md` 8.1]**); `discovery.md` notes on churn | Invitations (1.0.0, not yet designed) | Host with F1 opens L2 `successor_of` F1 a week before F1's window; F1's members receive the invitation; a non-member does not; members join and are live in F2 before F1's `move_window_opens` |
| F4 | **Move fees in the terms** | `terms.md` new even types `internal_fee_base_msat`, `internal_fee_ppm`, `move_fee_sat`; `local-api.md` fit rows | F2 | A host charging an internal fee above its frozen value is refused by the member's app, and a host charging zero is accepted; the member's records show the frozen values |
| F5 | **Roll forward rule**, same host and other hosts, with the settle-to-chain deadline | Planner engine (new spec, `planner.md`); `local-api.md` rules; `journal.md` rule and move records | F1 to F4 | On signet with short factory lives: member in F1 with "roll forward"; host offers L2; the member moves without any person acting; then host stopped before L3 opens: the member's rule tries another host, finds none, and the app settles by its deadline |
| F6 | **Caps and spread** (at most X per host, at least N hosts) | Planner; `safety-rule.md` none (rules only) | F5 | Member with 2 hosts and a 50% cap receives a payment that would break the cap; the rule moves the excess to the other host within its budget |
| F7 | **Rebalance below Y** | Planner | F2 | A channel whose receivable falls below Y is topped up from another factory; the budget stops the rule after its limit |
| F8 | **Member ladder** | Planner; timeline in the interface | F1, F5 | Member with ladder rule "2 factories, 7 days apart" joins and holds them; a third join that would clash is refused by G1 |
| F9 | **Coverage-aware moves** | `safety-rule.md` G3 | Shared leaves and sales (1.1.0) | A move that would take a channel above coverage is refused, and is allowed once the member holds the required on-chain coin |
| F10 | **Room before a move**: buy receiving room, or a channel on demand, in the destination | `sale.md`; JIT design | Sales and JIT (both 1.1.0) | A balance larger than F2's room is moved after the app buys room within its fee limit; the bought room appears as a new channel (decision 5) |
| F11 | **Derived payout addresses per factory** for fallbacks | Already planned (decision 6); `payout.md` | End-date payout (SuperScalar round 2) | Two factories' fallback payouts go to two different addresses of the same wallet |
| F12 | **Planner invariants in the simulator** | `TESTING.md` | F5 | Seeded random rules over 10,000 steps with crashes at every save: total never falls by more than agreed fees; every factory always has an armed exit |

### 8.3 Later

| # | Feature | Depends on | E2E test |
|---|---|---|---|
| L1 | **Closing into the next factory** (path D, round purpose 5) | Every signer of the old root online; the end-date payout; review of the reference's PTLC key turnover | All members rotate: F1's funding is spent into F2 in one transaction; with one member silent, the round falls back to paying across and the silent member is protected by its exit or the payout |
| L2 | **Atomic old-for-new by key turnover** (the reference's phase A) | Its own safety analysis: the released key must be worthless to the member once F2 holds its balance **[I]** | Turnover with the host killed between the member's release and F2's funding: the member loses nothing |
| L3 | **Swap-out to chain** as a cheaper fallback than an exit | Issue 1 | No lobby available: the member swaps its balance to an on-chain address through a submarine swap within its fee limit |
| L4 | **Companion device** signing moves within conditions while the phone sleeps | `AWAY.md`; Q7 | Phone app closed through a whole move window; the companion completes the move |
| L5 | **Tor** for host connections | Transport | Two hosts cannot link the member's memberships by network address |
| L6 | **Outside or cold wallet** as fallback destination | Decision 6 (later) | Fallback payout lands on a hardware wallet's proven address |
| L7 | **Notifications** for rule actions and failures (Nostr, email, push) | `AWAY.md` | A rule failure reaches the person through the chosen channel within an hour |

---

## 9. Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| MF1 | **When does "many factories" ship?** The owner says 1.1.0; the local API says 1.0.0 allows several, and rotation in 1.0.0 needs two at once | Core support for any number in 1.0.0, tested at 2 and 3, because rotation needs it anyway (P1). The interface for many, cross-host moves and rules in 1.1.0 |
| MF2 | **Default for rolling forward** | "Same host, by itself if it fits" on, as the conditions' `move_to_next` already defaults; moving to another host asks first until the person turns it on |
| MF3 | **Default limits** (8 factories, 3 lobbies, 4 per host, 2 ends per 144 blocks) | Accept as starting values, settle from signet runs |
| MF4 | **May a rule-made join count as consent?** | Yes, only when the person confirmed the rule with its preview, only for lobbies that fit the whole range, and only within the rule's budget |
| MF5 | **Move fees in the terms** (`internal_fee_*`, `move_fee_sat`, `successor_of`) | Add them as even types in `terms.md` draft 3; a host can set zero |
| MF6 | **Lead times** (`give up by` 2 days before `start_leaving_by` for same host, 4 for others) | Accept as placeholders; measure route CLTV deltas and funding times on signet before fixing |
| MF7 | **Closing into the next factory (path D)** in M4 or later | Later: paying across first, since one silent member blocks closing-into and the payout's shape is not final |
| MF8 | **The reference's PTLC key turnover** | Study it as L2, with its own safety analysis, before Gazpacho signs any adaptor that releases a factory key |
| MF9 | **Standing invitations: listed or private?** | Private, over the existing connection only; never in a listing |
| MF10 | **Should the fallback exit ever be switchable off?** | No. It is protection, like watching, and pause does not stop it |
| MF11 | **Spread rule versus privacy** | Off by default; the preview states that more hosts see part of the member's activity |
| MF12 | **G1 (deadline load) as a hard refusal or a warning** | Hard refusal above the member's limit, since the cost of a clash falls exactly when hosts fail |
| MF13 | **Seats for members with zero balance in successor lobbies** | Free for a host's own members moving with it (they bring a balance); hosts may cap empty memberships later, under decision 10's per-lobby choice |
| MF14 | **Phones** (Q7): rules on a phone that sleeps | Rules schedule moves early with a retry day; a companion device (L4) is the real answer; until then the interface says a phone must be opened in the window |

---

## 10. Sources

**This repository**, branch `specs-slice1`: as listed at the top. Owner decisions 1 to 14 (`ux/decisions.md`).

**Design posts** (reading only; nothing posted):
- ZmnSCPxj, "SuperScalar", Delving Bitcoin topic 1143 (raw text), posts 1, 3, 9 and 26 (inversion of timeout default).
- ZmnSCPxj, SuperScalar with pseudo-Spilman leaves, Delving Bitcoin topic 1242 (raw text), including the later posts on maintenance, limited coverage and the double account limit.
- Implementation report, Delving Bitcoin topic 2705, post 1.

**Reference implementation**, GitHub `8144225309/SuperScalar`, main at `5f93110`: `include/superscalar/ladder.h` (identical to Gazpacho's import), `src/lsp_rotation.c` (phases A to D, partial rotation, retry back-off), `docs/rotation-ceremony.md`, `docs/trustless-offline-tolerant-rollover-plan.md`.

**Prior art:**
- ACINQ, "Phoenix splicing update": acinq.co/blog/phoenix-splicing-update (one channel per user, splice-in and splice-out, fees, the maximum-fee rule). The Phoenix FAQ could not be read.
- Lightning Loop fees: docs.lightning.engineering, Loop fees page (Loop Out prepayment and example costs).
- Boltz: its documentation could not be reached; nothing from it is relied on here.
- rebalance-lnd: github.com/C-Otto/rebalance-lnd (circular rebalancing, fee limits). LND `SendPaymentV2` `allow_self_payment`: lightning.engineering API docs.
- LSPS1 (bLIP-51) and LSPS2 (bLIP-52): github.com/lightning/blips (`channel_expiry_blocks` lease; `opening_fee_params` with `min_fee_msat`, `proportional`, `valid_until`, `promise`). LSPS2's signed, time-limited fee quote is a model for a host's move price.
- Ark: docs.arkadeos.com, batch expiry (automatic renewal by default; sweep after expiry); second.tech/docs, lifetime and intro (28-day VTXOs from rounds, background and delegated refresh, emergency exit before expiry, boarding and offboarding).
- Wasabi Wallet documentation: docs.wasabiwallet.io (automatic coinjoin off by default, maximum mining fee, stop threshold, non-private coin isolation).
- JoinMarket tumbler guide: github.com/JoinMarket-Org/joinmarket-clientserver, `docs/tumblerguide.md`.
