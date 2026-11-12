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
| Tree | The full layered SuperScalar tree in the first release; fixed tree built first. Pseudo-Spilman leaves. JIT channels off |
| Funding | One funder per factory, the host, who signs funding only after the whole tree is signed. Members start at zero |
| Messages | Lightning's own wire language; factory messages inside one custom odd message type (52791), which is the specification; bLIP-56 through an adapter |
| Channel | Lightning's standard taproot channel format; the old format archived and recoverable |
| Safety | One member-side rule before every signature; save before send; signing secrets never stored; a restored backup never publishes |
| Forming a factory | A lobby: long gathering, short signing at a scheduled start; listed or unlisted, open or by invitation; member conditions locked in; no voting; host removal and personal block lists; four rule profiles |
| Changing the rules later | A public proposal process modelled on BIPs and bLIPs |
| Host's link to Lightning | An adapter to a regular node: LND first, then Core Lightning, then others. Later the built-in node does it alone |
| Away protection | About two weeks to open the app; the watch engine can also run as a separate process |
| Reminders | The core knows every date by which the user must act |
| Finding hosts | Listings and host proofs on Nostr; everything else direct |
| Not in the first release | Swap-in and swap-out, a watching service, members adding their own coins, several hosts per factory |
| Old projects | Soup wallet is mothballed and kept for reference. The SuperScalar repo is maintained by another session |

## Milestones

| | Outcome | State |
|---|---|---|
| M0 | Reference code run end to end; foundations shown to separate; reference values recorded | Done |
| M0b | Foundations imported into this repo with a build and a reference test | Done |
| M1 | Core skeleton and simulator (merged 11 Nov; a follow-up hardens restart and adds faults the engines need); signing round engine; a fixed-tree factory created in the simulator with funding signed last | In progress |
| **Slice 1** | **Form a factory on signet:** lobby, signing, funding last, shown in the local web interface | After M1 |
| M2 | Channel engine on the standard taproot format; payment engine; invariants on | |
| **Slice 2** | **A payment** between two members through the host, on signet | After M2 |
| M3 | Exit, watch and schedule engines; crash and cheating runs pass | |
| **Slice 3** | **Leaving alone:** a member exits on signet with the host stopped | After M3 |
| M4 | The full layered tree; rotation into the next factory | |
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
| 1.0.0 | The milestones above. One member per leaf. Fees (proposed, owner to confirm): per payment, and an optional joining fee from the first payment received. Payout to one wallet. No on-chain reserve |
| 1.1.0 | Buying receiving room, splicing and channels opened on demand: built and documented with this goal, the interface kept hidden until then. Shared leaves (K > 1) with sales under "limited coverage", each sale a new channel, so several channels per member. Derived payout addresses per factory |
| Later | Payout to an outside or cold wallet |

## Work list

Items decided by the owner that are not yet tied to a milestone (`ux/decisions.md`).

| Item | Source |
|---|---|
| A "speed up a stuck transaction" action, using the pay-to-anchor outputs. Document the alternatives (fee tiers signed in advance, paying the fee from the member's own output, a paid helper) and prepare A/B samples for testers later | Decision 6, on-chain reserve |
| The dedication: About > Dedication, Credits, Licences; one line on the last first-run screen; one line under `gazpacho --version` | Decision 7 (proposed, owner to confirm) |
| The interface starts from layout concept H, with the critique's fixes and the owner's answers still to apply | Interface critique, 2026-11-12 |

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
| `TESTING.md` | The testing plan |
| `../spec/` | Specifications: the safe-to-sign rule, the signing round |
| `SLICES.md` | The vertical slices: what each shows, needs, and when it is done |
| `OPEN-QUESTIONS.md` | What is still undecided |
| `sips/` | How rules and features are proposed and decided |
| `AWAY.md` | Meeting a member's duties while they are away |
| `ASSESSMENT.md` | What existed at the start and what has to be built |
| `handoff/` | Notes sent to the SuperScalar repo session |
