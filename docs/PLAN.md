# Gazpacho wallet: plan

Draft of 2026-11-11. Items marked **(assumed)** are my recommendation and still need the owner's yes.

## Mission

Get SuperScalar into people's hands. Anyone can run Gazpacho and take part in a channel factory, with no patched Core Lightning, no plugin, and no wait for bLIP-56.

## Decisions so far

- One app, two roles: every install can **join** a factory or **host** one.
- Every install has an ordinary on-chain bitcoin wallet outside Lightning. Hosts fund factories from it; everyone uses it to pay exit fees and receive exit funds.
- First release is signet-only. The mainnet code paths exist from the start but are switched off in release builds.
- Tests run on regtest, signet and testnet as we go.
- A public signet host runs on the VPS (reuse what is there, or start a new one).
- First screen after the command line: web.
- Leaves are pseudo-Spilman only. JIT channels are off in v1. Target 512 clients per factory, tested at 128 or 256.
- Many factories with different advertised terms. Soup wallet is mothballed and kept for reference only: we reuse its ideas (policy schema, validator, rendezvous list) but do not target compatibility with it.
- **Both roles run self-contained:** host and member each need only Gazpacho (with its built-in Lightning node) plus a chain server (public Electrum or HTTP servers, the user's own server, or their own Bitcoin node). No Bitcoin node or separate Lightning node is required for either role.
- **Watching is live and built in:** while Gazpacho runs it watches every factory and channel output through the chain server and responds to old states itself.
- Wording: hosting, providing liquidity, fees. Never "staking".
- The SuperScalar repo is fixed by another session. Gazpacho consumes it and sends hand-off requests for anything it needs.

## Assumed, awaiting confirmation

- **Chain view, three choices in settings (the Sparrow model):**
  1. Public servers (Electrum protocol on desktop, Esplora HTTP on web). Default; nothing to install.
  2. The user's own Electrum server.
  3. The user's own Bitcoin node.
  Keys never leave the app in any of the three. With public servers, Gazpacho asks more than one and compares answers, because a hidden transaction can cost funds in a factory.
- **How a self-contained host reaches the rest of Lightning (assumed):** the built-in node gains the ability to hold a few ordinary Lightning channels to well-connected outside nodes, speaking the standard channel protocol. It does not become a routing node: no gossip, and route-finding is delegated to the outside node where possible.
  - Until that exists, a host links to a regular Lightning node through an adapter (Core Lightning first). The adapter stays afterwards as an option for hosts who already run a node.
  - A host with no outside link is a test setup only.
- **Built-in Lightning stays small:** factory channels for everyone; a few ordinary channels for hosts. No gossip and no forwarding for strangers.
- **Design rule:** the core's logic does not depend on the wire format, so the standard Lightning message format can be added without a rewrite.
- **Shared format with the SuperScalar repo:** the message format, scope and division of responsibilities may be revised in the repo, in Gazpacho, or both, toward one proper shared format (bLIP-56-style where that fits, not necessarily bLIP-56 itself). Both projects then implement it. Until it is agreed, nothing in Gazpacho may hard-code today's repo format outside one translation layer.
- **One funder per factory in v1: the host.** Members start at zero, as in the design and the current code, and bring money in by:
  - a Lightning payment from any other wallet (works today);
  - a swap-in: the member sends on-chain bitcoin from Gazpacho's own wallet to the host and receives the same amount in their factory channel, tied to one payment secret so neither side can cheat. Needs building.
- **Jointly funded factories (several hosts, or members adding coins at creation) are a later release.** They wait for sign-before-fund in the repo and need a new interactive funding protocol with abort handling. Host-side code that calls a Lightning node must require a release with the 2026 dual-funding and splicing security fixes (Core Lightning v26.06.10 or later).
- **Nostr:** not in the first release. Host discovery through the rendezvous list arrives in the second.

## Architecture

1. **Core library** (portable C, no networking, storage or chain access of its own):
   - factory tree and group signing;
   - ceremonies: create, join, liquidity change, rotation, close, exit, for both roles;
   - a one-peer channel (client side) and its counterpart (host side);
   - policy check: refuse to sign terms outside the user's limits;
   - on-chain wallet logic.
2. **Three slots each shell fills:** storage, connection to the host, chain view.
3. **Shells:** command line, then web. Host role also runs as a server process.
4. **Host side:** the host process, plus a stock Lightning node for the outside network, plus a watchtower.

## Phases

| Phase | Outcome | Rough size |
|---|---|---|
| 1. Base | Hand-off list to the repo session; cut-down build of the repo; chain view through public servers and through the user's own Bitcoin node | 1–2 weeks |
| 2. Core | Core library with both roles; host accepts WebSocket; policy check in place | 2–3 weeks |
| 3. Signet release | Command-line Gazpacho: create wallet, join, receive, pay, force-exit; public signet host with faucet; downloads and walkthrough | 1–2 weeks |
| 4. Web | Web shell on signet; encrypted off-device backup of channel state | 2–4 weeks |
| 5. Hosting for everyone | Hosting from the app with the adapter link; always-on process; factory browser with terms | 3–4 weeks |
| 5b. Self-contained host | Built-in node holds ordinary channels to outside nodes, so a host needs no separate Lightning node | open, large |
| 6. Real money | One channel-update routine; sign-before-fund; full timeout inversion; payment deadlines from the tree; audit; capped mainnet beta | open |

Sizes are guesses. Phases 1–3 are the most certain.

## Tests at every phase

- Unit tests with a "fix removed, test fails" check for each safety rule.
- Regtest end-to-end for every ceremony, both roles.
- Signet and testnet runs against the public host before each release.
- A mainnet-configured build is compiled and unit-tested in CI, and refuses to start.

## Main risks

1. **The channel code.** The repo's channel handling is the least reliable part, and Gazpacho depends on it. Signet can ship before the rebuild; mainnet cannot.
2. **Being online.** Members must sign at rotation and watch for old states. Web and phone users are usually offline. Needs wake-ups and a watchtower (phase 5).
3. **State backup.** Channel state cannot be rebuilt from a seed phrase. Loss of browser storage must not mean loss of funds.
4. **Web trust.** A served page can be changed by whoever serves it. Web is for signet; real funds need an installed app.
5. **Dependence on the repo session.** Our schedule follows their merges.
6. **Small hosts.** A host that disappears forces on-chain exits. Proof tiers and visible track records limit this.

## Open questions

0. The shared format: who drafts it, and when. Proposed: this session drafts a short scoping note after the phase 1 spike and sends it to the repo session as a hand-off.

1. Confirm one host per factory for v1.
2. Which public servers does Gazpacho ship with, and do we run our own as one of them?
