# Gazpacho wallet: plan

Updated 2026-11-12. This is the short plan. The reasoning and detail live in the documents listed at the end.

## Mission

Get SuperScalar into people's hands. Gazpacho is a professional proof-of-concept wallet and the flagship way into SuperScalar: one program that lets anyone join a channel factory or host one, with no Bitcoin node, no separate Lightning node and no modified node software required.

## What it is

- **Member and host in one program.** "Host" is what the SuperScalar design calls the LSP; "member" is its client.
- **Self-contained.** Its own small Lightning node for the factory channel, an ordinary on-chain wallet, and a chain view through public Electrum-style servers or the user's own node.
- **C throughout**, with a local web interface as the screens.
- **Signet first.** Mainnet code paths exist but are switched off in releases until the bar for real funds is met.
- **Quality first, no deadline.**

## Decisions in force

| Area | Decision |
|---|---|
| Source | SuperScalar's low-level files imported unchanged as a pinned copy; everything above them written new |
| Structure | A core library with no outside access (events in, actions out), ports for storage, chain and network, thin programs on top |
| Tree | 1.0.0 trees are advanceless: every interior level fixed, no timed levels (owner decision 9, 2026-11-12). Timed levels and layer updates arrive with 1.1.0 and liquidity sales. Extending a factory always means rotation. Pseudo-Spilman leaves, one member per leaf. JIT channels off |
| Funding | One funder per factory, the host, who signs funding only after the whole tree is signed. Members start at zero. Funding is automatic and on by default: once H1 passes, the host broadcasts without asking; consent is at opening the lobby and at the start. Before real money it becomes a setting that still defaults to automatic (owner decision 16a, 2026-11-13) |
| Lobbies per wallet | Several at once from Slice 1; every lobby record carries a lobby field (owner decision 16b) |
| Member signing | Modes selectable by members and hosts: A automatic; B passphrase when the lobby fills; C keys unlocked once at join for that factory only, then wiped (the default, owner confirmed); D watchtower services, after 1.2.0, variants D1 to D4, where third-party keyed D4 is custody and never a default. "Not unlocked" counts as not answering the ready check (owner decision 16d) |
| Host accountability | 1.0.0: signed seat receipts, the signer-choice rule in the outer terms, signed removals with a reason, signed lobby-wide counts without identities (owner decision 16c) |
| Privacy | Slice 1: a generic user agent, an explicit chain proxy, no addresses in logs. 1.0.0: one Tor setting (`socks5h` only, no silent clearnet fallback), onion-service hosts, the chain server over Tor or your own node, block-based chain lookups. Later: built-in Tor and a compact block filter client (owner decision 16g) |
| Messages | Lightning's own wire language; factory messages inside one custom odd message type (52791), which is the specification; bLIP-56 through an adapter |
| Channel | Lightning's standard taproot channel format; the old format archived and recoverable |
| Safety | One member-side rule before every signature; save before send; signing secrets never stored; a restored backup never publishes |
| Forming a factory | A lobby: long gathering, short signing at a scheduled start; listed or unlisted, open or by invitation; member conditions locked in; no voting; host removal and personal block lists; four rule profiles |
| Changing the rules later | A public proposal process modelled on BIPs and bLIPs |
| Host's link to Lightning | An adapter to a regular node: LND first, then Core Lightning, then others. Later the built-in node does it alone |
| Away protection | About two weeks to open the app; the watch engine can also run as a separate process |
| Reminders | The core knows every date by which the user must act |
| Finding hosts | Discovery over Lightning first: one feature bit, direct queries, signed beacons and opt-in store nodes; Nostr as an optional annex, where listings need a coin or channel anchor (`spec/discovery.md`). Live state, joining and signing stay direct. Slice 1 uses none of it: the member is given the host's address |
| Seats | Free in 1.0.0, protected by invitation-only lobbies, host removal before the start, standby seats and the signing time budget. Next a proof of control of a coin or channel for public lobbies, with a share of newcomer seats that need none. Later the host chooses per lobby in its terms (owner decision 10) |
| Protocol id | `factory_protocol_id` = SHA-256 of `SuperScalar/1`, shared with the SuperScalar projects (owner decision 8) |
| Not in the first release | Swap-in and swap-out, a watching service, members adding their own coins, several hosts per factory |
| Old projects | Soup wallet is mothballed and kept for reference. The SuperScalar repo is maintained by another session |

## Milestones

| | Outcome | State |
|---|---|---|
| M0 | Reference code run end to end; foundations shown to separate; reference values recorded | Done |
| M0b | Foundations imported into this repo with a build and a reference test | Done |
| M1 | Core skeleton and simulator (merged 11 Nov; a follow-up, pull request 9, hardens restart and adds faults the engines need); signing round engine; a fixed-tree factory created in the simulator with funding signed last | In progress. The signing round engine is built on the build server but not yet in a pull request (`SLICE1-WORK.md`) |
| **Slice 1** | **Form a factory on signet:** lobby, signing, funding last, shown in the local web interface | After M1 |
| M2 | Channel engine on the standard taproot format; payment engine; invariants on | |
| **Slice 2** | **A payment** between two members through the host, on signet | After M2 |
| M3 | Exit, watch and schedule engines; crash and cheating runs pass | |
| **Slice 3** | **Leaving alone:** a member exits on signet with the host stopped | After M3 |
| M4 | Rotation into the next factory (1.0.0 trees are advanceless: fixed levels only). Timed levels and layer updates are 1.1.0 work, with liquidity sales | |
| M5 | Hardening of storage, transport and chain view; Electrum backend; a node of our own for controlled-chain tests | |
| M6 | First release candidate on signet: lobby listings, host service, LND adapter, full local web interface, our public host | |

Slices are defined in `SLICES.md`. Each pulls a thin, real version of the outer pieces forward so there is something to run early; the simulator stays the main safety net.

## After the release candidate

More node adapters and a browser of hosts; swap-in and swap-out; a watching service; the self-contained host.

**Towards a Lightning standard** (owner, 2026-11-12). The long-term aim is factories as a core part of Lightning. The path, as dual funding and splicing went: our own odd message type now (`spec/messages.md`); bLIP-56's even type through the adapter; a feature bit of our own; then a BOLT (`spec/PROTOCOL.md`).

## Steps towards real funds

1. Remaining design fixes, including the SuperScalar requests marked "before real funds".
2. **Legal advice before anyone hosts on mainnet.** Whether running a host, or publishing host software, brings duties under money-transmission or similar law in the places it is used. Prosecutors in the Samourai case treated developers of non-custodial software as money transmitters. Gazpacho does not give legal advice; this step is advice from a lawyer, for the project and for hosts (`OPEN-QUESTIONS.md`).
3. An outside audit.
4. A capped beta.

## Releases

| Release | In it |
|---|---|
| 1.0.0 | The milestones above. One member per leaf. Fees (proposed, owner to confirm): per payment, and an optional joining fee from the first payment received. Payout to one wallet. No on-chain reserve. Host accountability: signed seat receipts, the signer-choice rule in the terms, signed removals, signed counts. Member signing modes A to C. One Tor setting, onion-service hosts, the chain server over Tor or your own node, block-based chain lookups (owner decision 16) |
| 1.1.0 | Buying receiving room, splicing and channels opened on demand: built and documented with this goal, the interface kept hidden until then. Shared leaves (K > 1) with sales under "limited coverage", each sale a new channel, so several channels per member. Derived payout addresses per factory. **Many factories at once** (same or different hosts) shown as a stack, moving funds between channels and factories over Lightning, successor lobbies and standing invitations from hosts, move fees in the terms, and standing rules that roll a member's funds forward before a factory closes instead of settling on chain (`MULTI-FACTORY.md`, unreviewed). Understudies: standby seats that answered the ready check are swapped in automatically, at the ready check or mid-signing with fresh nonces (owner decision 16e) |
| Later | Payout to an outside or cold wallet. Closing into the next factory; the reference's key-hand-over rotation; swap-out as a fallback; a companion device for unattended moves. Built-in Tor (for example Arti), a BIP 157/158 compact block filter light client, automatic onion creation and DNS-name hosts (owner decision 16g). Accountability proofs published to Nostr from fresh keys after a lobby ends. After 1.2.0: mode D, watchtower services, as the fourth way to take part (research pending) |

## Work list

Items decided by the owner that are not yet tied to a milestone (`ux/decisions.md`).

| Item | Source |
|---|---|
| A "speed up a stuck transaction" action, using the pay-to-anchor outputs. Document the alternatives (fee tiers signed in advance, paying the fee from the member's own output, a paid helper) and prepare A/B samples for testers later | Decision 6, on-chain reserve |
| The dedication: About > Dedication, Credits, Licences; one line on the last first-run screen; one line under `gazpacho --version` | Decision 7 (proposed, owner to confirm) |
| The interface starts from layout concept H, with the critique's fixes and the owner's answers still to apply | Interface critique, 2026-11-12 |
| Core holds several factories per member from 1.0.0 (rotation needs two at once); lift Slice 1's one-lobby limit to the stack limits; generalise the safety rule's owed row to any move between the member's factories | `MULTI-FACTORY.md` 2, P1; owner 2026-11-12 |
| Write `move.md` (paying across, same host and other hosts) and `planner.md` (standing rules, budgets, logging); add safety checks G1 to G3; journal stack, rule and move records; local API stack, moves and rules calls | `MULTI-FACTORY.md` 2.5, 3, 5 |
| Terms draft 3: `internal_fee_base_msat`, `internal_fee_ppm`, `move_fee_sat` (even, ranges) and `successor_of` (even, fixed); an invitation message for standing invitations | `MULTI-FACTORY.md` 3.4, 6 |
| A UI/UX review pass after 1.0.0, to add the signing modes and the other settings gracefully | Decision 16f |
| Lift the one-lobby limit in `spec/local-api.md` (open point 9, `already_in_lobby`, `already_hosting`) and `MULTI-FACTORY.md`: several lobbies at once from Slice 1 | Decision 16b |
| Measure on signet: route timelock totals for moves across hosts, funding burial times, and the lead times for "move by" and "give up by" | `MULTI-FACTORY.md` 4.1, MF6 |

## How work proceeds

1. **Specification**, written before code.
2. **Review of the specification** by an agent that did not write it.
3. **Build**, against `ENGINEERING-CHECKLIST.md`, including the builder's own mutation testing.
4. **Pull request**, kept small; automated checks must pass.
5. **Review of the code** by an agent that did not write it, which tries to break it.
6. **Fixes**, then a second review of what changed.
7. **Merge**, then the knowledge base and handbook are updated.

Work that does not depend on the server (specifications, research, reviews of text) runs alongside work that does (building and testing), so the critical path is never waiting for a document.

## How work is checked

- Every safety rule has a test, and a run with the rule removed that must fail.
- A simulator runs whole factories in one process with dropped messages, crashes at every save point and scripted cheating, checking the invariants after every step.
- The real programs run on regtest, then signet and testnet.
- Each engine gets an independent review before it is built on.

## Documents

| File | What it holds |
|---|---|
| `KNOWLEDGE-BASE.md` | Start here: glossary, facts, decisions in force, how sure we are of each claim |
| `DESIGN.md` | The design currently in force |
| `RECORD.md` | The dated record of findings, reviews and decisions |
| `design.html`, `gazpacho-overview.html` | Illustrated versions, with earlier versions under `history/` |
| `LOBBY.md`, `LOBBY-research.md` | The lobby design and the research behind it |
| `HOST-NODES.md` | Lightning nodes a host can link to, and how hard each is |
| `CHAIN-SERVERS.md` | Public chain servers found to answer, and how they are used |
| `TESTING.md` | What runs today, and the testing plan with the milestone of each item |
| `../spec/` | Specifications: the protocol map (`PROTOCOL.md`), the safe-to-sign rule, the signing round, messages, host terms, the journal, discovery; the transport is on branch `transport` |
| `SLICES.md` | The vertical slices: what each shows, needs, and when it is done |
| `SLICE1-WORK.md` | Slice 1's work table (piece, spec, branch, state) and merge order |
| `OPEN-QUESTIONS.md` | What is still undecided |
| `sips/` | How rules and features are proposed and decided |
| `AWAY.md` | Meeting a member's duties while they are away |
| `ASSESSMENT.md` | What existed at the start and what has to be built |
| `handoff/` | Notes sent to the SuperScalar repo session; `handoff/README.md` is the ledger of every request and its state |
| `reviews/` | Independent reviews; `reviews/README.md` is the ledger of every review round |
| `THREAT-MODEL.md` | Who can attack what, and which rule answers each attack |
