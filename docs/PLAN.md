# Gazpacho wallet: plan

Updated 2026-11-11. This is the short plan. The reasoning and detail live in the documents listed at the end.

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
| Messages | Lightning's own wire language; factory messages inside one custom message type |
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
| M1 | Simulator skeleton; signing round engine; a fixed-tree factory created in the simulator with funding signed last | Next |
| M2 | Channel engine on the standard taproot format; payment engine; invariants on | |
| M3 | Exit, watch and schedule engines; crash and cheating runs pass | |
| M4 | The full layered tree; rotation into the next factory | |
| M5 | Storage, Lightning transport, Bitcoin node and Electrum; regtest end to end | |
| M6 | First release on signet: lobby, command line, host service, LND adapter, local web interface, our public host | |

After that: more node adapters and a browser of hosts; swap-in and swap-out; a watching service; the self-contained host; then the work for real funds (remaining design fixes, an outside audit, a capped beta).

## How work is checked

- Every safety rule has a test, and a run with the rule removed that must fail.
- A simulator runs whole factories in one process with dropped messages, crashes at every save point and scripted cheating, checking the invariants after every step.
- The real programs run on regtest, then signet and testnet.
- Each engine gets an independent review before it is built on.

## Documents

| File | What it holds |
|---|---|
| `KNOWLEDGE-BASE.md` | Start here: glossary, facts, decisions in force, how sure we are of each claim |
| `DESIGN.md` | The design and the record of decisions and findings |
| `design.html`, `gazpacho-overview.html` | Illustrated versions, with earlier versions under `history/` |
| `LOBBY.md`, `LOBBY-research.md` | The lobby design and the research behind it |
| `HOST-NODES.md` | Lightning nodes a host can link to, and how hard each is |
| `OPEN-QUESTIONS.md` | What is still undecided |
| `proposals/` | How rules and features are proposed and decided |
| `AWAY.md` | Meeting a member's duties while they are away |
| `ASSESSMENT.md` | What existed at the start and what has to be built |
| `handoff/` | Notes sent to the SuperScalar repo session |
