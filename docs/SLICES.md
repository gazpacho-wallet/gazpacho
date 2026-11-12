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

## Where slices run

On the project's build server at first, with the screen viewed through a secure tunnel. Running natively on Windows is tracked separately and follows slice 1.

## What slices do not replace

The simulator remains the main safety net. A slice on signet shows the path works once, slowly, with honest parties. Dropped messages, crashes at every save point and cheating are tested in the simulator, and the controlled-chain scenarios wait for a node of our own.
