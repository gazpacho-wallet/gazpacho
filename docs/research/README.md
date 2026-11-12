# Research and reviews

The evidence behind Gazpacho's decisions. Each document says what was verified against a source and what was recalled. Reviews are independent: written by someone who did not write what they review. Server addresses and local paths have been removed.

## Research (`docs/research/`)

| Document | What it covers |
|---|---|
| `discovery-research.md` | How people should find factories and join them: Lightning gossip, onion messages, LSPS, liquidity ads, Nostr, Soup's design, spam and privacy |
| `peering-research.md` | The overlay's peering technique, from Bitcoin Core, Ethereum gossipsub, BitTorrent and Nostr; Bitcoin mempool patterns; what is normative and what is reserved; when Nostr could be retired |
| `discovery-comparison.html` | Six discovery designs compared side by side, with the chosen one |
| `envelope-comparison.html` | Gazpacho's own message envelope against bLIP-56's |
| `superscalar-changes-explainer.html` | The SuperScalar repository's planned changes, checked against the original design |
| `channel-groundwork.md` | Channels inside a factory: the standard taproot channel format, moving a channel, deadlines, decisions needed |
| `ideas-ledger.md` | Every idea and decision from the owner discussions of 11 and 12 November 2026, and where each was recorded |
| `ux/` | Interface research (wallets; node dashboards and markets; lobbies and consent), the gap check against SuperScalar's materials, and the brief the layout concepts were built from |

## Reviews (`docs/reviews/`)

| Document | What was reviewed |
|---|---|
| `spec-review-1.md` to `spec-review-3.md`, `spec-review-3-confirm.md` | The safe-to-sign rule, the signing round, and the Slice 1 message, terms and journal specifications |
| `review-pr7-chain.md` | The chain view (pull request 7) |
| `review-pr9-core-followup.md` | The core frame follow-up (pull request 9) |
| `review-pr10-transport.md` | The transport (pull request 10) |
| `review-wallet-tx.md` | Wallet transactions (pull request 11) |
| `ux-critique.md` | The eight interface layout concepts |
