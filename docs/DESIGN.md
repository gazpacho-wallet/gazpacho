# Gazpacho design

The current design, consolidated. 2026-11-11; owner decisions of 11 and 12 Nov added 2026-11-12.

How it got here, with dates, findings and superseded ideas, is in `RECORD.md`. Where the two differ, this file is the one in force. The illustrated version is `design.html`.

## 1. What Gazpacho is

One program that lets a person join a SuperScalar channel factory as a **member** or run one as a **host**. It carries its own small Lightning node for factory channels and an ordinary on-chain wallet, and reads the chain through Electrum-style servers or the user's own node. It needs no modified node software. First releases are signet-only; the code for mainnet exists and is switched off.

## 2. Where the code comes from

- **Imported unchanged** from SuperScalar, pinned to a known version under `core/superscalar/`: tree building, group signing, timelock counter, ladder, transaction and script building, adaptor signatures, key derivation, recovery phrases, address and invoice encoding, fee helpers. 38 files. A manifest records each file's checksum, and a script refreshes the copy.
- **Written new:** everything above that. SuperScalar's host and member code is the reference for behaviour, not a source of code.
- **Not edited here:** a change to an imported file is requested from the SuperScalar repo. If it cannot wait it goes in a short, listed patch queue.
- **Reference results** recorded from real SuperScalar runs catch any drift when the import is updated.

## 3. Layers

| Layer | Contents | Source |
|---|---|---|
| L5 Programs | `gazpacho` command line, host service, local web interface | new |
| L4 Ports | storage, chain view, network, clock, randomness, host's Lightning node | new |
| L3 Node | sessions, journal, timers, on-chain wallet, host terms, member and host roles | new |
| L2 Engines | signing round, channel, payment, exit, watch, lifecycle, schedule | new |
| L1 Factory model | tree, timelocks, leaves, exits, ladder | imported |
| L0 Primitives | signatures, hashing, transactions, scripts, group signing | imported |

L0 to L3 are the **core**: portable C with no system calls. Everything is C except the screens of the local web interface.

The lobby, the signing round engine and the proof-of-fault scheme are written without dependence on the factory code so they can be split out as a coordination library.

## 4. The core contract

An **event** goes in and a list of **actions** comes out. The core never waits and never touches the outside world.

- Events: a message arrived, a timer fired, something happened on chain, the user asked for something, storage confirmed a save.
- Actions: save records as one atomic batch, send a message, broadcast a transaction, watch a script, set a timer, tell the user.
- **Save before send.** The program around the core carries out actions in order and sends nothing until the save before it is safely stored. Enforced in one place for every engine.
- **Storage is a journal.** Saves go to storage at once, in the order they were made, and become durable in that order. A send, broadcast or notification waits until every save made before it is durable. Confirmations arrive in order; one out of order is an error.
- **A save's identity is never reused.** Each is numbered by the runner with the program's start count and a sequence. A late confirmation from before a restart is ignored and can never release anything.
- **A refused step is fatal for that node.** If the runner cannot accept a step, the node's memory is ahead of what was saved, so the program stops the node and rebuilds it from storage. A storage failure does the same.
- **A node has a start step** that returns actions, so after a restart it can re-arm timers, watch again and resend what was saved but never sent.
- **A timer that times out a message comes after that message** in the list of actions, so a slow save cannot make a deadline pass before the request has left.
- Randomness and time are handed to the core, so a whole factory can be simulated repeatably.

## 5. Engines

| Engine | Job | Specification |
|---|---|---|
| Signing round | Every group signature: propose, nonces, partial signatures, combine. One engine for creation, leaf changes, layer updates, rotation and close | `spec/signing-round.md` |
| Channel | One update routine: save, sign, verify the other side's cancellation of the old state, save, release our own. Updates arriving mid-update are queued | To write |
| Payment | Invoices; incoming and outgoing payments; deadlines derived from exit time | To write |
| Exit | Plans leaving alone: which transactions, in what order, when each is valid, how fees are paid | To write |
| Watch | Knows every output that matters and the response if it is spent. Can run as a separate process | To write |
| Lifecycle | Lobby, creation, liquidity changes, rotation, close | `docs/LOBBY.md` for the lobby; rest to write |
| Schedule | Computes every date by which the user must act | To write |

## 6. Safety

The full definition is `spec/safety-rule.md`. In brief:

- **One rule before every signature:** sign only if, afterwards, the member can still leave alone, in time, with at least what they are owed, whatever everyone else does.
- A member's software signs only transactions it rebuilt itself, recognises its outputs by its own keys, and never helps create an output without already holding its signed exit from it.
- **The factory key always needs everyone's signature.** No threshold key.
- **Sign before fund:** the host signs funding only after the whole tree is signed and verified.
- **Every partial signature is verified** as it arrives.
- **Signing secrets are never stored.** An interrupted round is abandoned.
- **A restored backup never publishes** its own channel state. It asks the host to prove the latest and waits for the host to close.
- **Exit fees** are built in from the host's side, with pay-to-anchor outputs so anyone can raise a fee. No on-chain reserve is required or recommended in 1.0.0 (owner decision 6); in 1.1.0 a member above its coverage keeps a small on-chain coin (decision 5).
- **Away protection:** about two weeks to respond to an old state in 1.0.0, the channel's revocation window (the design's figure, not measured; `spec/safety-rule.md` sections 7 and 8). In 1.1.0 a member above its coverage may have under a day.
- A new safety or joining rule is normally a reviewed change to the safe-to-sign module, proposed through a SIP.

## 7. The factory

- The full layered SuperScalar tree in the first release; the fixed tree is built first.
- Pseudo-Spilman leaves, one member per leaf. Payments never change the tree; liquidity changes do.
- One funder per factory: the host. Members start at zero and are paid in over Lightning.
- The tree's shape for each size is fixed by the host's terms; members are placed in an agreed order, host first.
- Shape rules, from the scale check: a level is at most 15 wide; a wide level is used only where every subtree under it has more members than the width; two-way trees are not used at size (27 days to exit at 512 members); upper levels are fixed where possible, since each timed level adds 3 days to an exit. Small factories (4, 8, 32) have their own shapes.
- Payment deadlines are computed from the factory's exit time plus a margin; payments with less headroom are refused.
- A member's software exits automatically before expiry if nothing else has happened.
- At wind-down a member pays their balance into the next factory over Lightning, or co-signs a close that funds the next factory directly.
- Target size 512 members; routine tests at smaller sizes.
- Not in the first release: JIT channels, swap-in and swap-out, members adding their own coins, several hosts per factory.
- **Shared leaves come with sales in 1.1.0** (agreed with SuperScalar, 11 Nov). 1.0.0 has one member per leaf (K = 1). In 1.1.0 shared leaves (K > 1) arrive with sales of receiving room under the design's "limited coverage": each member's coverage is fixed when the factory is built and shown beside the balance. Each sale spends only the host's spare liquidity and makes a **new channel** for the buyer; existing channels never move, so a member can hold several channels in one factory (`ux/decisions.md` 5).

## 8. Messages and channel format

- A Gazpacho connection is an ordinary Lightning peer connection that also carries factory messages.
- Lightning's encrypted transport with the host's key pinned; over TCP, and over WebSocket where needed.
- Lightning's message shape, session start and feature flags. No version numbers: unknown odd fields are skipped, unknown even ones refused.
- Lightning's standard channel messages and its standard taproot channel format for the channel inside a leaf. The old SuperScalar channel format is archived and can be reinstated behind the channel engine's format interface.
- Factory messages travel inside one custom message type, with an envelope naming the protocol, the factory and the message kind.
- Large signing data is split across messages with a completion marker.
- A member's backup is held by the host using Lightning's peer-storage messages.
- Encoders and decoders are generated from tables in `spec/`, with test vectors and fuzzing.
- The message specification is `spec/messages.md`. **Our own odd envelope (type 52791) is the specification**; bLIP-56 is carried by an adapter, and signatures are always over our native bytes (owner's choice, 2026-11-12). It is offered to the SuperScalar repo as the shared format.
- **A layered standard** (`spec/PROTOCOL.md`): transport, envelope, group coordination (a separate library), SuperScalar operations, channels and discovery are separate layers, each with its formats, state machines, acceptance rules and test vectors (owner, 2026-11-12).

## 9. Storage and backup

- An append-only journal of typed records with periodic snapshots, encrypted at rest.
- The encrypted journal is also the backup: one copy with the host, one the user can export.
- A restored copy is never used to publish a channel state.

## 10. Chain view

- Three choices: public Electrum-style servers (default), the user's own server, the user's own Bitcoin node.
- Gazpacho checks block headers and checks confirmations against them, so a server cannot invent a confirmation. On signet, where blocks are signed, it compares several servers.
- A server can hide a transaction, so Gazpacho asks more than one. Hosts should use their own node.
- Default list: well-known public servers; one of ours is added around launch.

## 11. Forming a factory

Full detail in `docs/LOBBY.md`.

- A lobby, like a game server. **Start rule:** a target, a minimum and a deadline. Reaching the target starts at once; at the deadline it starts if the minimum is met, and otherwise quits or carries members over.
- Gathering is long; signing is short and automatic within each member's conditions.
- A member's conditions are locked in, and are checked against the real tree at signing.
- Listed or unlisted; open or by invitation (QR codes). A listing is one signed record, the same bytes on every path (`spec/discovery.md` draft 2): asked of the host over Lightning; announced by a small signed beacon relayed among factory-capable nodes and served by opt-in store nodes; and, optionally, on Nostr. One odd feature bit marks a factory-capable node; a host is whoever sends beacons. The signet demo ships the bit, direct queries and Nostr; beacons and store nodes come next.
- No voting. The host removes people; each member has a personal block list; history is kept locally.
- Host switches for names, chat and rule-change requests. Optional self-identification. Identity is new per lobby by default.
- Four rule profiles: Safety, Standard, Starter, Circle.
- Listings carry fixed terms, ranges, size and start time. Live details come from the host.
- **Terms** (owner decision 1, `spec/terms.md`): a lobby's outer rules are fixed when it opens; adjustable terms move only inside signed ranges; values freeze at the ready check; the outer rules' digest is the rules fingerprint and the lobby's identity. Changing an outer rule makes a new lobby.

## 12. The host

- Runs Gazpacho continuously, with its own Bitcoin node recommended.
- Links its factory to the rest of Lightning through a regular node, by an adapter with four operations: pay an invoice; create an invoice whose secret the node does not know and hold the payment; settle it; cancel it. LND first, then Core Lightning, then others. See `docs/HOST-NODES.md`.
- Later the built-in node holds ordinary channels itself and no separate node is needed.
- Publishes signed, versioned terms. May publish its funded factories as a track record.
- **Fees in 1.0.0** (proposed after the owner's direction, decision 2; owner to confirm): a per-payment fee (a base amount plus a proportion), and an optional joining fee taken from the first payment received. The fee for extra receiving room comes in 1.1.0. A host cannot take any charge the member has not signed.

## 13. The user's side

- **No role question** (owner decision 4): everyone can be member and host. The app never asks "member or host?"; hosting is always visible, with a calm starting page until the person hosts something.
- **Where coins go** (owner decision 6): 1.0.0 pays out to one wallet; 1.1.0 adds derived addresses of the same wallet per factory; an outside or cold wallet comes later. A destination is fixed before the factory forms, because pre-signed transactions fix it, and an outside address is proven before use. The tree builder must accept a destination per member (a request to SuperScalar, `handoff/2026-11-12-to-superscalar.md`, E2).
- **Screens:** a local web interface served by the C program on the local machine only, with a start-up token and refusal of requests from other sites. Keys and channel state never enter the browser.
- **Reminders:** countdowns in the app first. Other channels and ways to act while away are in `docs/AWAY.md`.

## 14. Changing the rules

SuperScalar Improvement Proposals, `docs/sips/`. Request in a set format, open discussion, ACK or NACK on record, then separate decisions on approval and on shipping.

## 15. Testing

`docs/TESTING.md`: seven levels, a simulator that injects network faults, crashes and cheating, nine invariants checked after every step, and two tests for every safety rule.

## 16. Milestones

| | Outcome | State |
|---|---|---|
| M0 | Reference code run end to end | Done |
| M0b | Foundations imported with a test and automated checks | Done |
| M1 | Core skeleton, simulator and signing round engine; a fixed-tree factory in the simulator | In progress |
| Slice 1 | Form a factory on signet, shown in the local web interface | After M1 |
| M2 | Channel and payment engines | |
| Slice 2 | A payment on signet | After M2 |
| M3 | Exit, watch and schedule engines | |
| Slice 3 | A member leaves alone on signet | After M3 |
| M4 | The full layered tree and rotation | |
| M5 | Hardening of the outer pieces; Electrum backend; a node of our own for controlled-chain tests | |
| M6 | First release candidate on signet | |

Slices are defined in `docs/SLICES.md`.

## 17. Not designed yet

See `docs/OPEN-QUESTIONS.md` and the open points at the end of each specification.
