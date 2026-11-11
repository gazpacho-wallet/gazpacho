# Gazpacho design

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
