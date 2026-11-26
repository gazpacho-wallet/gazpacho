# Vertical slices

Decided 2026-11-11. A slice is one complete path through every layer that a person can run and watch, on a public test network. Slices are built as soon as the engines they need have passed their simulator tests, instead of waiting until every engine exists.

Network: **signet first**, through public chain servers (`CHAIN-SERVERS.md`). A second independent testnet4 server has been found (`CHAIN-SERVERS.md`), so testnet4 can be added; no slice is scheduled on it yet.

## Rules for every slice

1. A slice uses only engines that have passed their simulator tests and been reviewed.
2. Nothing in a slice skips the safe-to-sign check.
3. The slice programs refuse to start on mainnet.
4. The outer pieces (storage, connection, chain view, screens) may be thin, but they are the real ones, written to be hardened later, not demo code to throw away.
5. Each slice has a written walkthrough that a newcomer can follow, and an automated run of the same steps.

## Slice 1: form a factory

Who is building each piece, on which branch, and the merge order: `SLICE1-WORK.md`.

**What you see:** a host opens a lobby; members join; when the start rule is met their software signs; the host funds last; the funding transaction confirms on signet; the screen shows the lobby, the tree and the confirmation.

| Needs | From |
|---|---|
| Core skeleton and simulator | M1, first piece (merged; follow-up in pull request 9) |
| Signing round engine and the creation checks of the safe-to-sign rule | M1, second piece |
| Lobby with target, minimum and deadline | Lifecycle engine, first cut |
| Chain view over the HTTP explorer interface, comparing two servers | Chain port (started alongside M1) |
| On-chain wallet able to fund one output and report its confirmation | Wallet, first cut |
| A connection between programs | Transport, first cut |
| A file-based journal | Storage, first cut |
| `gazpacho` program that can host and join (no modes: everyone can do both, owner decision 2026-11-11), and the local web interface on the chosen layout | Programs, first cut |
| Signet coins for the host | A faucet, or the owner |

**Not in slice 1:** payments, liquidity changes, rotation, exits, the host's Lightning node, Nostr listings (the member is given the host's address directly), invitations, profiles beyond Standard.

**Through the interface** (owner decision 11, 2026-11-12, `ux/decisions.md`): Slice 1 ships with the local web interface in place, and every Slice 1 action is done through it: creating or restoring a wallet, the backup check of the 24 words, conditions, finding and joining a lobby, hosting a lobby, the signing moment and refusals, and the live factory. The command line is for start-up and diagnostics. The calls are in `spec/local-api.md`, section 2.1.

**Done when:** one host and at least three members on separate processes form a factory on signet from a clean start, twice in a row, by following the walkthrough **in the interface**; the automated run does the same through the same local API; and a member whose conditions are not met is seen to refuse, on the screen.

## Right after Slice 1: the idle lock (owner, 2026-11-26)

The owner: "right after, get it on the roadmap for the next slice". It goes in the slice that follows Slice 1, which is Slice 1.5 if the plan in PR #99 is adopted, and Slice 2 otherwise.

**What you see:** a setting, "Lock after N minutes without use". When the time passes with no request from the person, the wallet locks itself. That lock is the one the person can choose by hand (#54): keys are wiped from memory, the sign-in page comes back, and the locked wallet does what a locked wallet does (`spec/local-api.md` 4.7).

**Still to specify** (in `spec/local-api.md` and `spec/storage-encryption.md`, before it is built): the default N, and whether "never" is offered; what counts as use (a request from the interface counts; the engines' own background work does not); what happens if the time runs out during a signing round whose partial signatures are out. Since #81, leaving is refused then, so the lock should probably wait for the round to end. The specification pass decides.

**Done when:** a wallet left alone for N minutes is locked, with its key material wiped, as the lock's own test shows for the manual lock; a request just before the limit resets the timer; and the setting survives a restart.

### Key exposure, next steps (owner, 2026-11-26)

The idle lock shortens how long keys sit in memory. These follow it, in order:

1. **Keys for one lobby only, before Slice 2.** An unlock opens the keys of the lobby that needs them, not the whole wallet's.
2. **A separate signer, before 1.0.0.** Signing keys live in their own process, and the program never holds them. The signer boundary check (`tools/check-signer-boundary.sh`) already keeps secret-key symbols inside `signer/`.

## Slice 2: a payment

**What you see:** one member pays another through the host, and both balances change on the screen.

Needs the channel engine on Lightning's standard taproot format and the payment engine (M2).

**Done when:** payments in both directions succeed, a payment with too little time before its deadline is refused, and killing either program in the middle of a payment loses nothing after restart.

## Slice 3: leaving alone

**What you see:** the host is stopped; a member's program publishes its own path and ends with coins only it controls, on signet.

Needs the exit, watch and schedule engines (M3).

**Done when:** the exit completes with the host gone, the amount equals what the member was owed, and the screen showed the dates correctly beforehand.

## Later slices

Rotation into the next factory (M4); paying and being paid across the wider Lightning network through the host's node; finding hosts through discovery (`spec/discovery.md`). Liquidity changes and timed levels are 1.1.0 (owner decision 9).

**Many factories and rolling forward** (1.1.0, `MULTI-FACTORY.md`): one member in three factories with two hosts moves its balance from an ending factory into a live one over Lightning, by a standing rule and without anyone acting, and the app settles to chain by its own deadline when no lobby is available.

## A stuck funding (owner, 2026-11-26)

The funding's txid is fixed before anything is signed, because the whole tree is signed against it. A replacement by fee therefore kills the factory (H16), so a funding that waits can only be helped by a child transaction (CPFP). The funding stays version 2.

| Piece | What it does |
|---|---|
| Coin selection | Prefers a plan that leaves a change output, adding a small coin if needed |
| Speed-up output | When no change is possible, the funding preview says so plainly and offers a 240-sat P2A output that anyone can bump from. **A host setting only**, "Speed-up output on fundings": **Auto** (the default: on when the chosen rate is near the relay floor, 0.1 to 1 sat/vB, off otherwise), **Always** or **Never**. It is not in the lobby terms and is not sent to members, and members cannot object to it: how the host funds is the host's business |
| "Speed up" (host) | On a funding that is waiting, a button with a preview of the child: what it spends (the change or the speed-up output), its fee and the package rate. It never replaces the funding |
| Status (host and members) | "Funding not confirmed: waited N blocks; the lobby ends in M blocks if it doesn't confirm", where M counts to the funding deadline (the tip at the acknowledgement plus 36). Amber once the wait is longer than normal; red when M is small (for example 6 or fewer) |
| Status (members) | "The host's funding is waiting; you are released automatically in M blocks." No button. For later: members could bump through a keyless anchor |
| Version 3 | Reconsidered before mainnet. It would only add zero-fee fundings, which are not needed |

**Members' safety is unaffected by the funding's shape.** Their checks read only the funding output the tree spends, plus the inputs they watch (`spec/safety-rule.md` C1). An extra change or anchor output never changes their verdict. The countdown is shown to them because it is about their seat.

**Host-side code to change before this is built.** Today two host-side checks would refuse a funding with a P2A output, or one with no change:
- the funding engine's plan check, which requires exactly two outputs, the factory's and a P2TR change at output 1 (`core/funding/funding.c`, `plan_ok`);
- the signer's adopt check, which requires every other output to be change (`docs/notes/signer.md`, `gz_sg_fund_adopt` step 3).

The wallet's funding builder can already require change (`require_change`). It has no speed-up output yet.

Tested in the Slice 1.5 plan's S7 (PR #99), on regtest at 0.1 and 1 sat/vB floors.

## Chain sources (owner, 2026-11-26)

The owner: "we need all the options covered". Today's comparison of two Esplora operators stays. These are added in this order:

| # | Source | When | Trust | Privacy |
|---|---|---|---|---|
| — | **Two Esplora operators, compared** (today) | Slice 1 | Either server can hide or delay something. Headers are checked, and only what both operators agree on counts (`THREAT-MODEL.md` 2.4) | Each operator sees every script and txid asked about, and the address the query came from unless it goes over Tor |
| 1 | **Electrum-protocol servers** (Fulcrum, ElectrumX, electrs) | M5 | The same as Esplora: a server can hide or withhold, and headers can be checked. Two operators are compared, or the person runs their own server on their own node | A public server sees every script hash subscribed and the address the query came from. A server of one's own on one's own node shows nothing to anyone |
| 2 | **The person's own Bitcoin node over RPC**, pruned nodes included | M5 | The node validates everything itself, so there is nothing to trust beyond it | Nothing about the wallet leaves the machine; broadcasts go out through the node's peers. **Pruned:** blocks below the prune height are gone, so a restore that must find history older than that needs another source (the node can still list current coins, but not their history) |
| 3 | **Compact block filters** (BIP 157/158) as the **default private light mode** | Before mainnet | The wallet fetches filters from several peers and compares their filter headers, so a peer that lies is caught when the others disagree. Blocks are checked against their headers and proof of work | Peers learn which blocks the wallet downloads, not which scripts it watches, and no server sees its addresses. Cost: the filters since the wallet's birthday, plus every block that matches. There is no mempool view, so the two-Esplora comparison stays for unconfirmed spends and package broadcast |

**The single-server scan gap.** The host wallet's scan asks one server, and believes it when that server answers "never used" and also hides the coins (`THREAT-MODEL.md` 2.4, the "Reuse" row, added on `integration-slice1` by #97). Each source above closes it differently:
- Electrum-protocol servers close it when the scan goes through the comparing backend over two operators, which is the same fix the Esplora path needs before mainnet.
- One's own node closes it completely.
- Compact filters close it because the wallet matches every block's filter itself.

This decision moves compact block filters from "later" (owner decision 16g) to "before mainnet".

## Where slices run

On the project's build server at first, with the screen viewed through a secure tunnel. Running natively on Windows is tracked separately and follows slice 1.

## What slices do not replace

The simulator remains the main safety net. A slice on signet shows the path works once, slowly, with honest parties. Dropped messages, crashes at every save point and cheating are tested in the simulator, and the controlled-chain scenarios wait for a node of our own.
