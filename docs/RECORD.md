# Gazpacho design record

The dated history of the design: drafts, findings, reviews and the owner's decisions, in the order they happened. Earlier sections are kept as written and are superseded wherever a later section differs. The design currently in force is `DESIGN.md`.

Draft 1, 2026-11-11. Illustrated version: `design.html`. This file is the short record of the decisions; items marked **(proposed)** await the owner's yes.

## 1. Relationship to the SuperScalar repo

- Gazpacho is its own codebase.
- It **imports** SuperScalar's primitives as a pinned snapshot under `core/superscalar/`: tree builder, MuSig2 sessions, timelock counter, ladder, transaction and script builders, adaptor signatures, key handling. About 11,000 lines. **(proposed: vendored snapshot, not a live dependency)**
- Changes to imported files go to the SuperScalar repo first, then we update the snapshot. No private forks of the primitives, except a clearly listed patch queue when we cannot wait.
- Everything above the primitives is **written new**, using SuperScalar's host and member code as the reference for behaviour.
- A differential test builds the same factory in both and requires identical transaction IDs.

## 2. Layers

| Layer | Contents | Source |
|---|---|---|
| L5 Apps | `gazpacho` command line, host service, web screens | new |
| L4 Ports | storage, chain, network, clock, randomness, host's Lightning link | new |
| L3 Node | sessions, journal, timers, on-chain wallet, host terms, member and host roles | new |
| L2 Engines | signing round, channel, payment, exit, watch | new |
| L1 Factory model | tree, timelocks, leaves, exits, ladder | imported |
| L0 Primitives | secp256k1-zkp, hashing, transactions, scripts, MuSig2 | imported |

L0–L3 are the core library: portable C with no system calls.

## 3. Core contract

One entry point: an **event** goes in, a list of **actions** comes out. The core never blocks and never calls the outside world.

- Events: message received, timer fired, chain event, user command, storage confirmed.
- Actions: save records (one atomic batch), send message, broadcast transaction, watch script, set timer, tell the user.
- **Save before send:** the shell runs an action list in order and does not send anything until the batch before it is safely stored. This is enforced once, in the shell runner, for every engine.

## 4. Engines

- **Signing round engine.** One state machine for every group signature: propose, nonces, partial signatures, done. SuperScalar has about 40 message types across seven separate families for this (create, close, leaf advance, path, state advance, sub-factory, reallocation). Here it is one engine, given "what is being signed" and an acceptance rule.
- **Acceptance rule (member side).** Before contributing to any signature a member computes, from its own data only: "after this, can I still exit alone with at least what I am owed?" If not, it refuses. This single rule replaces per-ceremony checks.
- **Channel engine.** One update routine: save new state, send signature, receive and verify revocation, save, release own secret. Handles reconnect and updates that arrive mid-update by queueing, never dropping.
- **Payment engine.** Invoices, incoming and outgoing payments, deadlines derived from the tree's exit time.
- **Exit engine.** Plans a unilateral exit: which transactions, in what order, when each becomes valid, and how fees are bumped from the on-chain wallet.
- **Watch engine.** Lists what must be watched and what to do when each thing appears on chain.

## 5. Decisions on behaviour

- Sign before fund: the host signs its funding transaction only after the whole tree and every member's exit are signed. Built in from the first version.
- One funder per factory (the host). Members start at zero; pay in over Lightning or swap in.
- Pseudo-Spilman leaves, one member per leaf. Payments never change the tree; only liquidity changes do.
- Payment deadlines are computed from the factory's exit time plus a margin. Payments with less headroom are refused.
- Members exit automatically before the factory's expiry if the host has not rotated them.
- Host terms are a published record; the member's limits are checked before any signing.

## 6. Message format **(proposed, revised 2026-11-11)**

Do not invent a format. Speak Lightning's own wire language, so a Gazpacho connection is an ordinary Lightning peer connection that also carries factory messages.

- **Connection:** the BOLT 8 encrypted transport (Noise XK, the responder's key known in advance, which is exactly a pinned host key). Over TCP, and over WebSocket binary frames for browsers.
- **Framing:** the BOLT 1 message: 2-byte type, payload, optional trailing fields. Maximum 65,535 bytes.
- **Session:** the standard `init` (feature bits, chain), `ping`/`pong`, `error` and `warning`.
- **Extending without breaking:** no version numbers. Feature bits say what each side supports; every message ends in a typed-field (TLV) stream; unknown odd fields and messages are ignored, unknown even ones are refused ("it's ok to be odd").
- **Factory messages:** one odd message type in the custom range (32768 and above), carrying an envelope in the style of bLIP-56: protocol name, factory identifier, sub-message kind, then typed fields. About 15 sub-message kinds.
- **Channel messages:** the standard BOLT 2 set (`update_add_htlc`, `commitment_signed`, `revoke_and_ack`, `channel_reestablish`, `stfu`), with the taproot-channel fields for signing nonces. Reconnect follows `channel_reestablish`, which is the most-reviewed part of Lightning.
- **Large data:** group-signing data for hundreds of members exceeds one message. Send it as a sequence of small messages with an explicit "complete" marker, as Lightning's interactive transaction building does.
- **Member backup at the host:** the standard peer storage messages (`peer_storage`, `peer_storage_retrieval`).
- **Host terms and service requests:** binary typed fields in the first release; an LSPS-style (bLIP-50) interface can be added later for wallets that already speak it.
- **How it is written:** message tables in `spec/`, in the same table form the BOLTs use. Encoders and decoders are generated from the tables, not written by hand. Every message has test vectors, and every decoder is fuzzed.
- The specification is offered to the SuperScalar repo as the shared format, and written so it could be submitted as a bLIP.

## 7. Storage

- An append-only journal of typed records plus periodic snapshots.
- Encrypted at rest.
- The same journal, encrypted, is the off-device backup. The host also holds an opaque copy for the member.

## 8. Chain port

- Subscribe to a script; get a transaction's confirmation with proof; broadcast; fee estimate; chain tip.
- Block headers are checked for proof of work, and confirmations are checked against headers, so a server cannot invent a confirmation. It can only hide one, which asking several servers addresses.
- Backends: Electrum protocol, HTTP block explorer, Bitcoin node.

## 9. Testing

1. **Vectors and differential tests:** official cryptographic vectors; identical transaction IDs to SuperScalar.
2. **Engine unit tests.**
3. **Simulator:** host, N members, a simulated chain and a simulated network in one process, driven by a seed. It drops, delays and reorders messages, crashes any party at every save point, and plays scripted cheating peers. Invariants are checked after every step. This is the main safety net and is only possible because the core does no I/O.
4. **Regtest end to end:** the real programs against a real Bitcoin node and Electrum server. Scenarios: join, pay, receive, swap in, liquidity change, rotation, cooperative close, forced exit, host disappears, host publishes an old state, member publishes an old state, restart in the middle of each ceremony.
5. **Signet and testnet:** the public host with scripted users running nightly.
6. **Always:** sanitizers, fuzzing of every message parser, and for each safety rule a run with the rule removed that must fail.

### Invariants checked everywhere

- Money is conserved across every state change.
- Every member can exit alone with at least what they are owed, at every step.
- No party signs two different states with the same number.
- Nothing is sent before it is saved.
- No party's software broadcasts a state it has revoked.
- Every payment deadline is later than the time needed to exit.
- The host's funding is never signed before every exit is signed.

## 10. Milestones

| | Outcome | Rough size |
|---|---|---|
| M0 | Trial run of SuperScalar on regtest; primitives imported; differential test | 1 week |
| M1 | Simulator skeleton; signing round engine; a factory is created in the simulator | 2 weeks |
| M2 | Channel and payment engines; invariants on | 2–3 weeks |
| M3 | Exit and watch engines; crash and cheating schedules pass | 2 weeks |
| M4 | Ports: SQLite, encrypted TCP, Bitcoin node and Electrum; regtest end to end | 2 weeks |
| M5 | Command line, host service, host's Lightning link, public signet host, release | 2 weeks |
| M6 | Web version | 3–4 weeks |

## 11. Not designed yet

- The message specification itself, field by field.
- State tables for each engine.
- The journal's record types.
- The timelock and deadline schedule in numbers, for the chosen tree shape.
- Full timeout inversion at every tree output: it is a change to the imported tree builder, so it is a request to the SuperScalar repo, or a listed local patch.
- Waking members who are offline at rotation.
- The self-contained host's ordinary Lightning channels.

## 12. Why this is not simple

- The channel update routine must be exactly right under crashes and reconnects.
- Channel state cannot be rebuilt from a recovery phrase.
- Members must be reachable at rotation and must watch the chain.
- A forced exit needs on-chain funds for fees at the moment it is needed.
- Deadlines, timelocks and factory lifetime must be mutually consistent for every tree shape.
- A browser is a fragile place to keep channel state.
- Public chain servers can hide transactions.
- The imported tree code still has open design issues being fixed upstream.

## 13. Review 1 (2026-11-11)

Findings from a critical read of draft 1. Decisions pending in `design-review-1.html`.

Corrected in this document's intent (text above to be revised once the decisions are in):

- The "identical transaction IDs" test is vacuous for unchanged imported code. Replace with recorded reference results from SuperScalar runs, used to catch drift when the import is updated.
- Header proof-of-work checking does not apply to signet (blocks are signed). On signet compare several servers; do the full check on testnet and mainnet.
- Add a **lifecycle manager** (waiting room, creation, rotation, close) and the **swap-in flow** to the engine list.
- Signing secrets are never stored. "Save before send" does not apply to them; an interrupted signing round is abandoned and restarted.
- A restored backup never publishes its own channel state. It asks the host to prove the latest state and waits for the host to close.
- The member's safety rule needs a precise definition (timelocks, in-flight payments, fees) and its own tests before any engine relies on it.
- The browser can only reach hosts that offer a secure (certificate-backed) WebSocket.
- Estimate revised: 13–15 weeks to a first release if the channel uses Lightning's standard taproot format.

Open, awaiting the owner:

1. Tree for the first version: fixed tree with one member per leaf, or with a movable-liquidity layer.
2. Who pays exit fees for a member with no on-chain coins.
3. Protection while a member's app is closed: long response time, a watching service, or both.
4. Channel on-chain format: Lightning's standard taproot channels, or the old code's own.
5. How a factory fills and starts.
6. Which regular Lightning node a host links to first (must be able to hold a payment open).
7. Swap-in in the first release or the next.
8. Which hosts the web version can reach.
9. Schedule versus scope.

## 14. Decisions from review 1 (owner's answers, 2026-11-11)

1. **Tree:** the first release ships the full layered tree. Build order is fixed tree first, then the layers; the core is designed for the full tree from the start.
2. **Exit fees:** a member with no balance has nothing to exit. For members with a balance, the base fee is built into the tree and commitment transactions and comes from the host's side (the host is the funder). The app recommends a small on-chain reserve for busy periods. At wind-down a member either pays their balance into the next factory over Lightning or co-signs a close that funds the next factory directly; either avoids an on-chain exit.
3. **Away protection:** a long response window (about two weeks) in the first release. The watch engine is built so it can also run as a separate process: a service we offer, or one a user runs at home.
4. **Channel format:** Lightning's standard taproot channel format, exactly. The old format is documented and retired.
5. **Factory formation:** a lobby, like a game server. The host opens a lobby with rules; members join and mark themselves ready; the host starts when the start rule is met. Lobby listings and host proofs live on Nostr. Design note to be written (see below).
6. **Host's Lightning node:** one small adapter interface; both LND and Core Lightning supported. LND is implemented first as the reference.
7. **Swap-in:** not in the first release. Tracked as an issue together with swap-out.
8. **Web screens:** a local interface. The `gazpacho` program serves its screens on the local machine only, and the browser is just the display. Keys and channel state stay in the C program. A wallet that runs wholly inside a browser page is not planned for now.
9. **Schedule:** quality first; no deadline.

Consequences for earlier sections:

- §2: the web screens talk to the local program; the core is not compiled for the browser in the first releases.
- §8 and review finding 9: the browser no longer connects to hosts or chain servers, so certificates and browser storage are not concerns.
- §10: milestone M6 becomes "local web interface".

### Lobby: first sketch (to be developed)

- A host publishes a lobby: terms, minimum and maximum members, start rule, closing time. The listing and the host's proof of funds or channels are on Nostr; everything else is direct.
- A member's app checks the terms against the member's limits before showing "join".
- Joining is a direct connection to the host. The member appears in the lobby and can mark themselves ready.
- Changing the rules: the host proposes new terms; each member accepts or leaves. There is no binding vote, because nothing binds anyone until they sign, and every member signs for themselves.
- Start rule: minimum reached, and either all present are ready, or the host starts, or the closing time arrives.
- At start, members who do not answer are dropped and the signing round restarts without them.
- Open: a small refundable deposit to deter people who join and never sign; how much of the lobby state is public.

### Host's Lightning node: the adapter interface

Four operations are enough:

1. Pay an invoice, with a spending limit and a deadline; report the payment secret on success.
2. Create an invoice for a payment hash whose secret the node does not know, and hold the incoming payment open.
3. Settle a held payment once the member has revealed the secret.
4. Cancel a held payment.

LND offers all four natively. Core Lightning offers 1 natively and needs a plugin for 2–4.

## 15. Decisions and direction from the second discussion (2026-11-11)

- **Reminders.** A schedule engine in the core computes every date by which the user must act (open the app to stay protected, sign a rotation, leave before expiry). The screens show countdowns; reminders are built on it.
- **Old channel format is archived, not deleted.** Documented under `spec/archive/`, code reachable at a pinned SuperScalar version, and the channel engine keeps the on-chain format behind one interface so a different format can be plugged in later.
- **Lobby requirements (owner):**
  - Members set automatic join conditions (minimum members, minimum channel size, fee ceilings and so on). Once set they are locked in: a rule change can never carry a member into a factory that violates them.
  - The host fixes the rules it cares about and leaves others open within ranges; members vote on the open ones.
  - Members can vote to remove a participant; the software honours a proven majority.
  - Several defences together: reputation, a deposit, vote-to-remove, others as research shows.
  - Rule profiles, such as a safety profile that disables optional features.
  - Research commissioned; results in `LOBBY-research.md`, design note to follow.
- **Host's Lightning node.** The most widely used node first, then the others, aiming at every major implementation and at working across the whole Lightning network.
- **Local web interface** confirmed: a web front end over the C program.
- **Illustrated pages are versioned.** Earlier versions are kept under `docs/history/` and each page has a version switch (`docs/versions.js`).

### Bringing a member's own coins into a live factory (analysis, not yet reviewed)

Three ways exist; none is in the first release.

| Way | Who signs | New capital for the factory? | Main risk |
|---|---|---|---|
| Swap-in (issue 1) | Member and host, outside the tree | No: uses liquidity the host already has on that member's side | Funds are locked until a timeout if the other side stalls |
| Add the coins to the member's leaf | Only that leaf's signers | Yes | The member's coins must first be locked on chain under joint control, or the member could spend them elsewhere and void the new leaf state |
| Add coins at creation | Everyone | Yes | Any contributor can abort the funding for all |

The second row is this project's own reasoning, not taken from a published design, and needs a proper review before it is relied on.

## 16. M0 findings: what the reference code does today (2026-11-11)

From a trial run of SuperScalar (main plus its start-up crash fix) on regtest with four members and the default leaf type.

**What works**

- Factory creation, four payments and a cooperative close ran correctly; final balances matched to the satoshi. Creation took about 2 seconds, each payment about 2 seconds.
- A host-side forced close published and confirmed all 14 tree transactions.

**What does not**

- A member exiting alone, with the host gone, got all 14 tree transactions confirmed but could not publish its channel transaction: the fee built into it is below the relay minimum (154 against 167). So in the reference code today a member cannot complete an exit without the host. Gazpacho's channel engine replaces this code; the finding is passed to the SuperScalar repo.
- The default factory size is too small to make a payment (channel reserve exceeds the balance).

**Foundations: separable**

- 16 of the 20 candidate files build and run alone, needing only the signature library and a general cryptography library: tree, group signing, timelock counter, ladder, transaction and script builders, adaptor signatures, key derivation, recovery phrases, address and invoice encoding, fee helpers.
- 4 files are tied to the old database or channel code and are not imported as they are: keyfile, invoice, sweeper, on-chain wallet source. Gazpacho writes its own.
- A standalone program built from the 16 files reproduces exactly the 14 tree transaction IDs of the real run. Reference values for 4 and 8 members are in `tests/reference/`.

**Changes the imported files need before they fit the core's rules**

- Randomness is read directly from the operating system in several places, including for every signing nonce. The core must be handed randomness by the program around it.
- Diagnostic printing, one environment-variable hook and one test-only global variable in the tree builder.
- Member positions in the tree follow connection order, not key order, and the transaction IDs depend on it. Gazpacho must fix the order by an explicit rule.

**Message counts observed**

- Creation: 2 round trips for the signing, 2 more to set up the channel.
- A payment: 8 messages for the payer, 11 for the payee, all driven by the host.
- Cooperative close: 5 messages, 2 round trips.

## 17. Third discussion (2026-11-11)

- **Voting and vote-to-remove are off** for now (owner). The lobby uses host removal, personal block lists and locally kept history. See `LOBBY.md`.
- **No threshold key for the factory.** A key that a majority can use without the minority would let that majority spend a member's money. The factory stays "everyone signs". Threshold keys are fine where one party splits its own key.
- **Removing someone from a live factory** can only mean they agree to leave or their branch is published; either way they keep their money. Anything needing every signature can be stopped by one member, so the design limits how often everyone is needed rather than voting.
- **Identity and joining requirements** (control of coins, signing history, a chosen identity) will develop over time and must remain options a host sets. New joining rules usually need balances, coins or other state to decide what is safe to sign, so adding one is normally a reviewed change to the safe-to-sign module itself, which is kept small, with defined inputs and its own tests (owner's correction).
- **Coordination as its own library.** The lobby, the signing round engine and the proof-of-fault scheme are written without dependence on the factory code so they can be split out.
- **Host nodes** are listed with difficulty in `HOST-NODES.md`. LND first.
- **A member adding coins to their own leaf** (later feature): other members never sign anything involving it, and nothing above that leaf changes, so their exits and balances are unaffected. The added coins sit in a separate on-chain output under joint control of that member and the host, so a cooperative close or rotation must spend that output in the same transaction that pays the member. It is an extension beyond the published SuperScalar design, and needs review. See `OPEN-QUESTIONS.md` item 18.
- Documents reorganised: `PLAN.md` rewritten; `LOBBY.md`, `HOST-NODES.md`, `OPEN-QUESTIONS.md` and `handoff/` added.

## 18. M0b: foundations imported (2026-11-11)

- `core/superscalar/` holds 38 files copied unchanged from SuperScalar at commit `3de6120` (17 source files, 20 headers, the licence). `IMPORT.md` lists each with its SHA-256. `tools/update-import.sh` refreshes the copy and fails if the reference test stops passing.
- The reference test (`tests/test_reference_tree.c`) builds 4- and 8-member trees and compares every transaction ID with recorded values, including the 14 IDs from a real regtest run. It passes in a normal build and under the address and undefined-behaviour sanitizers, with no compiler warnings.
- Only the signature library and a general cryptography library are linked.

Found during the import, for the core's design:

- **Member order can depend on the C library.** The tree builder sorts members with a comparison that returns "equal" for everyone by default, and the C sort is not required to keep equal items in order. Gazpacho must put the keys in an agreed order (host first) and select the builder's "sequential" placement before building, so the tree never depends on the sort.
- **Partial signatures are not checked individually.** A function to verify one member's partial signature exists but nothing calls it; only the final combined signature is checked. Gazpacho's signing engine must verify every partial signature as it arrives, which is also what makes it possible to name who broke a round.
- Randomness, the clock, one environment variable, 37 diagnostic prints and one test global are reached directly from the imported files (exact lines are in the hand-off note).

## 19. Decisions from questions round 2 (2026-11-11)

**Lobby**

- **Timing.** One mechanism with timers the host sets. Gathering is long: a lobby can stay open for hours or days and members can join at any time and leave their app to act for them. Signing itself is short and happens at the scheduled start. Reason: the secrets used in a signing round are never stored, so every member's app must stay running from the first signing step to the second, and anyone dropping out forces a restart for all. A short signing window keeps that cheap; a long gathering window gives the convenience. A host may lengthen the signing timers if it accepts more restarts.
- **Audience.** Newcomers with no funds are the main audience. Each host sets the share of seats they may take.
- **Visibility and admission are two separate settings.** A lobby is listed on Nostr or unlisted; and open to anyone or by invitation. Invitations are links, shown as QR codes. An unlisted, invitation-only lobby gives privacy in practice.
- **Deposits:** not in the first release. Planned as the next step after it (issue 3).
- **Names, chat and rule-change requests** are each a setting the host can switch off. With all three off, members see only a head-count.
- **Optional self-identification.** A member may attach an identity to their seat. Standard kinds are proven by signing the lobby's challenge with that identity's key (a Nostr key, a Lightning node key). A free-text field is allowed and always shown as unverified.
- **Identity** is new for each lobby by default; a member may choose to bring a lasting one.
- **What is on Nostr.** A listing carries the terms the host has fixed and the acceptable range for the others, size limits, start time and an expiry. It changes rarely. Live details, such as how full a lobby is, are asked of the host directly.
- **Track records.** A host may publish the factories it has funded. Whether members can likewise prove past participation by signing with keys or coins from earlier factories is to be investigated (it links a member's factories together, so it must be opt-in).
- **Profiles:** all four ship: Safety, Standard, Starter, Circle.

**Product**

- **Chain servers:** well-known public servers at first; one of our own is added around launch.
- **Reminders:** countdowns in the app first; then Nostr messages, email, and phone notifications with the mobile app. Ways to act while the member is away are collected in `AWAY.md`.
- **The repository goes public now** (owner's decision), with `SECURITY.md` and `CONTRIBUTING.md` added first.

**How we work**

- **New rules and features follow a proposal process** modelled on BIPs and bLIPs: request in a set format, open discussion, ACK or NACK on record, then a separate decision on whether it ships. A proposal can be approved and not shipped, with the reason stated, so other factory software can adopt it. See `sips/`.
- **Review:** independent AI review of every engine as it is built, by several different models; and before real funds, outside human reviewers, including people who try to break it. The owner arranges outside reviewers.
- **Hand-off notes** are local documents; the owner pastes a short message pointing the other session to them.

## 20. Lobby start rule and SIPs (2026-11-11)

- **Start rule (owner):** a target, a minimum and a deadline. Reaching the target starts the lobby at once; at the deadline it starts if the minimum is met and is cancelled otherwise. Soup wallet's design had the same rule (`min_clients_to_start`, a force-start deadline, immediate start when full) and re-opened on a shortfall; here carry-over to the next lobby is an option and cancelling is the default. Coinjoin coordinators use the same pattern. Detail and the fit with SuperScalar are in `LOBBY.md`.
- **Signing timing default:** long gathering, short signing, software signs automatically within the member's conditions. A long signing window is a host option. Soup treated signing as slow (up to 24 hours per response); that remains possible but is not the default, because signing secrets are not stored and one dropout restarts the round.
- **Proposals are SIPs:** SuperScalar Improvement Proposals, in `sips/`, with categories Rule, Protocol, Process and Informational, a rule-request template and a worked example.
- **Review** is arranged by the owner. This session brings the software to release candidates.

## 21. Public repository, specifications, testing plan (2026-11-11)

- The repository is public (owner's decision), with private vulnerability reporting enabled.
- Drafted: `spec/safety-rule.md` (nine member-side checks C1 to C9, three host-side rules, definitions of owed, exit value and exit time) and `spec/signing-round.md` (six messages, states, nonce rules, proof of fault, never left half-finished). Both are draft 1 and unreviewed; each ends with its open points.
- Checked against BIP 327 directly: a secret nonce must never sign twice; partial signature verification exists for identifying a disruptive signer and requires untampered contributions; a dishonest combiner could otherwise blame an honest signer; the standard does not cover convincing a third party. Our signed-contribution scheme extends it and needs expert review.
- `TESTING.md` sets out the testing plan: seven levels, the simulator, nine invariants, regtest scenarios, and the bar for a release candidate.
- Illustrated design page is at version 3.

## 22. Design consolidated; design page version 4 (2026-11-11)

- This file was `DESIGN.md` and is now the dated record. `DESIGN.md` is a consolidated statement of the design in force.
- The illustrated page keeps its layout and gains sections that open for full detail, filled from the Markdown documents by `tools/build-design-page.py`. Its source also embeds the main documents and the source list, not displayed, for readers working from the file alone. Run the script after editing any source document.
