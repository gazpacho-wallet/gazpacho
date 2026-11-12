# Finding factories and negotiating a seat: research

Research note, 2026-11-12. Read-only research; nothing was posted anywhere.

The question, from the project owner: how should people find SuperScalar factories and negotiate joining one, in the way that best follows Lightning's established patterns? Is asking each host for its lobbies optimal, or should Lightning carry a maintained list of lobbies? Is shipping without a discovery path a mistake, and can one be added later?

The owner later sharpened it (messages relayed by the coordinator, same day):

1. Should the protocol specification include Nostr lobby discovery, or is Lightning's own communication (gossip, direct custom messages, onion messages) the proper and safe home for lobby records?
2. Is there any problem carrying lobby records over Lightning's channels of communication, or is gossip simply not built for this?
3. Two separate answers: what the **specification** should define, and what the **demo wallet** (first release) should do.
4. Evaluate a "sub-gossip" network of factory-capable nodes that relay lobby announcements only among themselves.
5. How to carry Soup's three proof tiers without a trusted coordinator, so each wallet (including a light client with a chain server but no graph) checks them itself, and how they bound spam.

Part B answers these directly. The short answers are in B1.

## How to read this file

- Every claim carries a source link and a mark.
  - **[V]** VERIFIED: the source was read in this session (by me or by a research helper working this session).
  - **[R]** RECALLED: from memory, not re-read this session. Treat as a lead, not a fact.
- Part A is evidence, numbered as the owner's seven questions. Part B is the synthesis and recommendation.
- Short quotes are kept under 15 words.

---

# Part A. Evidence

Abbreviations for the specification files (all read as raw files on 2026-11-12):
B1 = [BOLT 1](https://raw.githubusercontent.com/lightning/bolts/master/01-messaging.md), B4 = [BOLT 4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md), B7 = [BOLT 7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md), B9 = [BOLT 9](https://raw.githubusercontent.com/lightning/bolts/master/09-features.md), B12 = [BOLT 12](https://raw.githubusercontent.com/lightning/bolts/master/12-offer-encoding.md), bLIP-NN = `https://raw.githubusercontent.com/lightning/blips/master/blip-00NN.md`.

## A1. Lightning gossip (BOLT 7)

### What `node_announcement` can carry

| Point | Mark |
|---|---|
| Fields: signature, features, `u32` timestamp, node id, colour, 32-byte alias, addresses (IPv4, IPv6, Tor v3, at most one DNS name) | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| **No TLV stream is defined on master.** B7 only says fields beyond `addresses` "may also be added in the future"; the signature covers appended fields | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| A receiver MAY decline to queue messages longer than the minimum expected length, so extended announcements may legally not be relayed | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| LDK refuses to relay a `node_announcement` with more than 1,024 bytes of unknown extra data (`MAX_EXCESS_BYTES_FOR_RELAY`) | [V] [LDK gossip.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/routing/gossip.rs) |
| Any message is at most 65,535 bytes | [V] [B1](https://raw.githubusercontent.com/lightning/bolts/master/01-messaging.md) |
| **Unknown even feature bit in a `node_announcement`:** a node "SHOULD NOT connect to the node" and must not route through it. So a "hosts factories" bit in `node_announcement` must be **odd**, or it cuts the host off from the network | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |

### Who receives it, how often, how long it lives

| Point | Mark |
|---|---|
| A `node_announcement` from a node not tied to a known channel is ignored. So only nodes with at least one **announced, funded channel** are in gossip at all. This is the anti-spam anchor | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Channels must point at a P2WSH output (`channel_announcement` checks). Taproot channels cannot be announced on master | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| A new announcement needs a strictly greater timestamp. B7 sets **no** numeric limit on how often; it says flush outgoing gossip every 60 s ("a natural rate limit") and discourages regular re-announcing | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Pruning: a channel whose latest update in both directions is older than two weeks MAY be pruned; a node left without channels MAY be purged | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Peers must send `gossip_timestamp_filter` before receiving others' gossip; `query_short_channel_ids` can ask for node announcements | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Core Lightning generates its own gossip at most every 300 s (`GOSSIP_MIN_INTERVAL`), flushes every 60 s, prunes at 14 days, and delays its first `node_announcement` 60 s for the liquidity-ad plugin | [V] [CLN gossip_constants.h](https://raw.githubusercontent.com/ElementsProject/lightning/master/common/gossip_constants.h) |
| LND: 10 channel updates per minute burst per channel direction; byte-rate token buckets; a ban score with 48 h bans for stale or excessive gossip | [V] [sample-lnd.conf](https://raw.githubusercontent.com/lightningnetwork/lnd/master/sample-lnd.conf) |
| Eclair: broadcast every 60 s; at most 5 sync queries per second | [V] [Eclair reference.conf](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/resources/reference.conf) |

### Size and load today

| Point | Mark |
|---|---|
| About 6,200 announced nodes and 27,000 live channels; 113,000 to 149,000 new `node_announcement`s per day; average 427 bytes; 123 to 157 KiB/s of inbound gossip with duplicates (window to 2026-09-29) | [V] [gossip-observer](https://gossip-observer.jharveyb.xyz/) (read through a summarising fetch) |
| One-day sample, November 2025: 103 MB of unique gossip per day; node announcements 30% of messages; 2.5% of nodes announced more than 144 times a day; 200 s to reach 75% of nodes | [V] [Delving 2105](https://delvingbitcoin.org/raw/2105) |

### Light clients

| Point | Mark |
|---|---|
| LDK Rapid Gossip Sync, "aimed primarily at mobile", sends compressed, unsigned data the client must trust. Its node records carry features and addresses only: **TLV extensions are dropped**. Default snapshot every 3 hours | [V] [RGS lib.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning-rapid-gossip-sync/src/lib.rs), [processing.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning-rapid-gossip-sync/src/processing.rs), [RGS server README](https://raw.githubusercontent.com/lightningdevkit/rapid-gossip-sync-server/main/README.md) |
| Phoenix uses trampoline and does not sync the graph; Breez/Greenlight-style clients rely on a server | [R] [Phoenix](https://github.com/ACINQ/phoenix), [bolts#829](https://github.com/lightning/bolts/pull/829) |

### Proposals that change gossip

| Proposal | What it changes | Status | Mark |
|---|---|---|---|
| Taproot gossip, "1.75" (bolts#1059) | New `channel_announcement_2`, `node_announcement_2`, all TLV with BIP 340 signatures; **block heights instead of times**; "at most one announcement and update per block", backdating up to 2,016 blocks. Still needs a known channel; channels still anchored to a UTXO | Open; Rusty Russell implemented parts in May 2026; taken over by Lightning Labs in August 2026; LND has merged storage pieces | [V] [bolts#1059](https://github.com/lightning/bolts/pull/1059), [Delving 1202](https://delvingbitcoin.org/raw/1202), [Delving 1198](https://delvingbitcoin.org/raw/1198) |
| Set reconciliation (minisketch) | Sketches of channels, updates and node announcements every 60 s instead of flooding; Rusty: node announcements "only change when you change IP address or something" | A draft extension BOLT (jharveyb), revised after May 2026; no merged implementation found. gmaxwell warns decoding cost grows faster than linearly | [V] [Delving 2105](https://delvingbitcoin.org/raw/2105) |
| UTXO-less gossip | ZmnSCPxj recalls a discussion of proving a share of n-of-n funds and gossiping up to a multiple of it | Idea only | [V] [Delving 1252 #3](https://delvingbitcoin.org/t/pluggable-channel-factories/1252/3) |

None of these makes gossip a place for frequently changing application data. Taproot gossip makes updates *rarer* (one per block at most).

## A2. Services advertised in gossip: liquidity ads

| Point | Mark |
|---|---|
| The original `option_will_fund` (bolts#878) put lease rates in `node_announcement`. It was **closed** in October 2024, superseded by #1153 | [V] [bolts#878](https://github.com/lightning/bolts/pull/878) |
| Review there: Rusty Russell, "As these msgs are gossiped all over the network, bytes matter." niftynei wanted the announcement "as small as possible" | [V] [bolts#878](https://github.com/lightning/bolts/pull/878) |
| Stale offers in CLN's version: the buyer states the rates it expects; if the seller's reply differs, the open fails and the buyer is told the new rates | [V] [bolts#878](https://github.com/lightning/bolts/pull/878) |
| t-bast (2023): rates in `node_announcement` and `init` are "default rates", with no promise they are what is offered at request time | [V] [bolts#878](https://github.com/lightning/bolts/pull/878) |
| "Extensible liquidity ads" (bolts#1153, t-bast) puts `will_fund_rates` in an `init` TLV **and** a `node_announcement` TLV (both type 5), at most 10 rates. The seller must reject a request naming a rate it does not offer, may decline to fund, and signs what it agrees to | [V] [bolts#1153](https://github.com/lightning/bolts/pull/1153) |
| In that review t-bast agreed rates should also be obtainable **out of band**, not only from gossip; niftynei saw this leading to "other markets/billboards" | [V] [bolts#1153](https://github.com/lightning/bolts/pull/1153) |
| Status: #1153 is **open**, still on 2026 meeting agendas, about five years after #878 began | [V] [bolts#1153](https://github.com/lightning/bolts/pull/1153), [bolts#1354](https://github.com/lightning/bolts/issues/1354) |
| Implementations: CLN ships the old #878 format as `node_announcement` TLV type 1; Eclair has an early prototype, disabled by default, using TLV 1339; no `will_fund` code found in LND or LDK | [V] [CLN peer_wire.csv](https://raw.githubusercontent.com/ElementsProject/lightning/master/wire/peer_wire.csv), [Eclair RoutingTlv.scala](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/scala/fr/acinq/eclair/wire/protocol/RoutingTlv.scala), [Eclair v0.11.0 notes](https://raw.githubusercontent.com/ACINQ/eclair/master/docs/release-notes/eclair-v0.11.0.md) |
| Other gossip-advertised services use a **feature bit only**: `option_supports_lsps` (729), `dns_resolver` (258/259, context N), `hosted_channels` (256/257) | [V] [bLIP-2](https://raw.githubusercontent.com/lightning/blips/master/blip-0002.md) |
| No proposal was found to put a BOLT 12 offer or other service pointer in `node_announcement` | [V] searches of lightning/bolts and lightning/blips (not exhaustive) |
| No explicit "gossip is for routing only" quote was found from Matt Corallo or roasbeef in the threads read | [V] [bolts#1059](https://github.com/lightning/bolts/pull/1059) and the threads above |

**The lesson.** The one market that tried gossip has spent five years unmerged, and even its authors treat the gossiped numbers as non-binding defaults confirmed at request time. A capability bit in gossip is normal; the offer itself is negotiated directly.

## A3. Discovery and negotiation outside gossip

### LSPS (bLIP-50, -51, -52, -55)

| Point | Mark |
|---|---|
| LSPS0: all messages are one odd custom type, 37913, carrying JSON-RPC; client speaks first, LSP must not push; no rate limits specified; clients time out "on the scale of minutes" | [V] [bLIP-50](https://raw.githubusercontent.com/lightning/blips/master/blip-0050.md) |
| **Onion messages were considered and rejected**: a client must connect to the LSP anyway to manage channels | [V] [bLIP-50](https://raw.githubusercontent.com/lightning/blips/master/blip-0050.md) |
| **Discovery**: LSPs MAY set feature 729 in `init` and `node_announcement`; clients MUST NOT. The rationale: clients can find LSPs by downloading gossip. Nothing else is specified | [V] [bLIP-50](https://raw.githubusercontent.com/lightning/blips/master/blip-0050.md) |
| No LSP directory bLIP exists | [V] [lightning/blips](https://github.com/lightning/blips) search |
| LSPS1: `get_info` returns slow-changing limits; the LSP "SHOULD NOT change" them more than once per day; `create_order` outside them fails with "Option mismatch"; each payment option has its own expiry | [V] [bLIP-51](https://raw.githubusercontent.com/lightning/blips/master/blip-0051.md) |
| LSPS2: a menu of fee offers, each with `valid_until` (at least 10 minutes ahead) and a `promise` (a MAC or signature over the offer), so the LSP stays stateless and is bound to what it offered | [V] [bLIP-52](https://raw.githubusercontent.com/lightning/blips/master/blip-0052.md) |
| LSPS5: webhooks registered by the client; the LSP pushes over HTTPS to wake a phone | [V] [bLIP-55](https://raw.githubusercontent.com/lightning/blips/master/blip-0055.md) |

### How wallets find an LSP in practice

| Wallet or library | How | Mark |
|---|---|---|
| LDK Node | `add_liquidity_source(node_id, address, ...)`: configured by node id and address | [V] [builder.rs](https://raw.githubusercontent.com/lightningdevkit/ldk-node/main/src/builder.rs) |
| Zeus | Hard-coded defaults the user can edit | [V] [SettingsStore.ts](https://raw.githubusercontent.com/ZeusLN/zeus/master/stores/SettingsStore.ts) |
| Breez SDK | Fetches an LSP list from Breez's own server | [V] [breez_services.rs](https://raw.githubusercontent.com/breez/breez-sdk-ldk/main/libs/sdk-core/src/breez_services.rs) |
| Phoenix | Hard-codes ACINQ's node | [R] [Phoenix](https://github.com/ACINQ/phoenix) |

No light-client wallet found uses gossip to find its LSP.

### BOLT 12 offers and onion messages

| Point | Mark |
|---|---|
| Onion messages (type 513, feature 38/39) are in the BOLTs (merged July 2023). A node MAY rate-limit by dropping; no number is given. Payload should be 1,366 or 32,834 bytes | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md), [bolts#759](https://github.com/lightning/bolts/pull/759) |
| New bit 66/67 `option_onion_messages_only_channels`: such a node refuses onion messages from peers without a channel | [V] [B9](https://raw.githubusercontent.com/lightning/bolts/master/09-features.md) |
| Replies travel only along a `reply_path` (blinded), so the asker need not reveal itself | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) |
| Offers (merged September 2024) carry `offer_paths` (blinded paths), `offer_issuer_id`, `offer_absolute_expiry`, and an experimental TLV range 1,000,000,000 and up. Fields are mirrored into the request so the issuer can be stateless | [V] [B12](https://raw.githubusercontent.com/lightning/bolts/master/12-offer-encoding.md), [bolts#798](https://github.com/lightning/bolts/pull/798) |
| Non-payment onion-message use exists: bLIP-32 DNSSEC queries (payload types 65536, 65538, 65550) | [V] [bLIP-32](https://raw.githubusercontent.com/lightning/blips/master/blip-0032.md) |
| No specified use of an offer as a general query endpoint was found; it would be an extension | [V] [B12](https://raw.githubusercontent.com/lightning/bolts/master/12-offer-encoding.md) (absence) |

**What this means for lobbies.** A host could publish a long-lived contact (blinded paths) and answer "list your lobbies" over onion messages, so a member browses without connecting or revealing its address. The member still connects directly to join and sign. This is a privacy improvement for browsing, not a broadcast mechanism.

### From proposal to BOLT: dual funding and splicing

| Point | Mark |
|---|---|
| Dual funding (bolts#851): opened March 2021, merged February 2024 after CLN-Eclair cross-tests | [V] [bolts#851](https://github.com/lightning/bolts/pull/851) |
| Quiescence (bolts#869): merged June 2024 | [V] [bolts#869](https://github.com/lightning/bolts/pull/869) |
| Splicing (bolts#1160, replacing #863): opened May 2024, merged March 2026 after Eclair, CLN and LDK cross-tests; "this specification is now final" | [V] [bolts#1160](https://github.com/lightning/bolts/pull/1160) |
| While unmerged, experiments use the proposed bit plus 100 (CLN used 162 for splicing; Eclair 154/155 for Phoenix); final bit 62/63 | [V] [BOLTs CONTRIBUTING.md](https://raw.githubusercontent.com/lightning/bolts/master/CONTRIBUTING.md), [CLN v24.08 features.h](https://raw.githubusercontent.com/ElementsProject/lightning/v24.08/common/features.h), [Eclair Features.scala](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/scala/fr/acinq/eclair/Features.scala) |
| The "two interoperating implementations" rule is a meeting convention, not written in CONTRIBUTING.md | [R] [lightning/bolts](https://github.com/lightning/bolts) PR threads |
| bLIP-2: feature bits 0 to 255 belong to BOLTs; bLIPs use higher bits; message types 0 to 32,767 belong to BOLTs; bLIP TLVs on BOLT messages use types above 65,536 | [V] [bLIP-2](https://raw.githubusercontent.com/lightning/blips/master/blip-0002.md) |
| BOLT 1: unknown odd message ignored; unknown even message closes the connection; custom types should be picked at random | [V] [B1](https://raw.githubusercontent.com/lightning/bolts/master/01-messaging.md) |
| BOLT 9: bits come in pairs, odd optional, even compulsory | [V] [B9](https://raw.githubusercontent.com/lightning/bolts/master/09-features.md) |

### Other Lightning and Bitcoin precedents

| System | How discovery works | Freshness and spam | Mark |
|---|---|---|---|
| PeerSwap | Odd custom messages (42069 to 42085). Polls every connected peer on start and every 10 minutes; no feature bit, no broadcast | Peer state dropped after 30 minutes of silence | [V] [peer-protocol.md](https://raw.githubusercontent.com/ElementsProject/peerswap/master/docs/peer-protocol.md), [peersync.go](https://raw.githubusercontent.com/ElementsProject/peerswap/master/peersync/peersync.go) |
| Lightning Pool | One hard-coded auctioneer (`pool.lightning.finance:12010`); sealed bids; clears per block or batch | Central | [V] [Pool README](https://raw.githubusercontent.com/lightninglabs/pool/master/README.md), [config.go](https://raw.githubusercontent.com/lightninglabs/pool/master/config.go) |
| Amboss Magma | Central marketplace with an API and an LSPS1 REST API; hold invoices | Central ranking by history and uptime | [V] [Magma docs](https://docs.amboss.tech/magma) (summarised fetch) |
| JoinMarket | 2 or 3 hard-coded **directory nodes** (Tor onions) pass peer lists. Order book is pulled: a taker broadcasts `!orderbook`, makers answer privately; offers are withdrawn with `!cancel` | Fidelity bonds: value grows faster than linearly with coins and lock time; takers pick makers weighted by bond, with 12.5% of picks ignoring bonds | [V] [onion-message-channels.md](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/onion-message-channels.md), [protocol.py](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/src/jmdaemon/protocol.py), [fidelity-bonds.md](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md) |
| Wasabi / Ginger | Coordinators announce on Nostr (kind 15750, replaceable) every 15 minutes; users can also paste a connection string | Clients should ignore events older than 15 minutes (NIP draft) or 4 hours (Wasabi PR). The Wasabi PR admits it has no real Sybil resistance; fidelity bonds for coordinators are only proposed | [V] [CoordinatorAnnouncer.cs](https://github.com/WalletWasabi/WalletWasabi/blob/master/WalletWasabi/Discoverability/CoordinatorAnnouncer.cs), [nips#384](https://github.com/nostr-protocol/nips/pull/384), [Wasabi#14506](https://github.com/WalletWasabi/WalletWasabi/pull/14506), [discussion #14503](https://github.com/orgs/WalletWasabi/discussions/14503) |
| JoinStr | Pools announced on Nostr (kind 2022) with an expiry time; everything else in encrypted DMs | Expired or wrongly signed announcements ignored; optional ring proofs of owning a coin | [V] [JoinStr protocol](https://docs.joinstr.xyz/protocol/) |
| Ark (arkd) | Client is given a server URL; `GetInfo` returns keys, limits, a fee table, the **next scheduled session** and a `digest` of the parameters | Schedule and fees advertised ahead; digest detects changes | [V] [service.proto](https://github.com/arkade-os/arkd/blob/master/api-spec/protobuf/ark/v1/service.proto), [types.proto](https://github.com/arkade-os/arkd/blob/master/api-spec/protobuf/ark/v1/types.proto) |
| Ark (Second) | Fixed published server URLs; rounds every hour | None needed | [V] [connection details](https://second.tech/docs/connection-details.md), [intro](https://second.tech/docs/learn/intro.md) |
| Spark | Operators and service provider hard-coded in the SDK | None | [V] [wallet-config.ts](https://github.com/buildonspark/spark/blob/main/sdks/js/packages/spark-sdk/src/services/wallet-config.ts) |
| DLC oracles | An announcement is signed by the oracle key, so it can be fetched from any untrusted source; distribution is not specified. Nostr NIP drafts carry the same TLV in base64 | Self-verifying; carrier does not matter | [V] [Oracle.md](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md), [nips#2394](https://github.com/nostr-protocol/nips/pull/2394) |

### Nostr patterns

| NIP or project | Relevant point | Mark |
|---|---|---|
| NIP-01 | Addressable events (kinds 30000 to 39999) keep only the latest per author, kind and `d` tag | [V] [01.md](https://github.com/nostr-protocol/nips/blob/master/01.md) |
| NIP-40 | `expiration` tag: relays and clients SHOULD drop expired events; not a guarantee | [V] [40.md](https://github.com/nostr-protocol/nips/blob/master/40.md) |
| NIP-13 | Proof of work on event ids; can be outsourced | [V] [13.md](https://github.com/nostr-protocol/nips/blob/master/13.md) |
| NIP-42 | Relay authentication, enabling paid or restricted relays | [V] [42.md](https://github.com/nostr-protocol/nips/blob/master/42.md) |
| NIP-47 | Wallet Connect: info event kind 13194; requests and replies ephemeral and encrypted; relays come from a URI shared out of band, so no public discovery | [V] [47.md](https://github.com/nostr-protocol/nips/blob/master/47.md) |
| NIP-69 | Peer-to-peer orders, kind 38383, used by Mostro, lnp2pBot, RoboSats and Peach: a shared format let several platforms interoperate. Two expiries: a status expiry and a NIP-40 relay expiry | [V] [69.md](https://github.com/nostr-protocol/nips/blob/master/69.md) |
| NIP-15, NIP-99, NIP-89 | Marketplace stalls and products; classified listings; app handlers recommended by people you follow. None handles spam beyond author choice | [V] [15.md](https://github.com/nostr-protocol/nips/blob/master/15.md), [99.md](https://github.com/nostr-protocol/nips/blob/master/99.md), [89.md](https://github.com/nostr-protocol/nips/blob/master/89.md) |
| LSP or liquidity NIPs | None merged. A liquidity "advert" kind (nips#2127) was closed in November 2025. `publsp` publishes LSP offers adapted from bLIP-51 as kind 39735, orders by encrypted DM | [V] [nips#2127](https://github.com/nostr-protocol/nips/pull/2127), [publsp](https://github.com/smallworlnd/publsp) |
| Mostro health events | Heartbeat every 30 to 3,600 s; expiry is exactly 3 times the interval; readers treat a missing or old heartbeat as unknown | [V] [Mostro health event](https://mostro.network/protocol/health_event.html) |
| Bonds against fake takers | Mostro and RoboSats use hold-invoice bonds slashed on timeouts or cheating | [V] [Mostro bonds](https://mostro.network/protocol/pay_bond_invoice.html); RoboSats [R] [learn.robosats.com](https://learn.robosats.com) |
| Measured spam studies | None found for NIP-69, NIP-99 or kind 15750 | [V] search (absence) |

## A4. The owner's earlier work: soup-rendezvous and the SuperScalar CLN plugin

### What was built

| Piece | What it does | Mark |
|---|---|---|
| `soup-rendezvous` | A Nostr "seed list" of verified hosts. A coordinator checks a host's proof and publishes a **vouch** (kind 38101, addressable, d-tag = host's Nostr key) holding only a Lightning node id, optional addresses, a tier label and an expiry. Kind 38099 is the coordinator's own identity post; kind 4 encrypted DMs carry proof requests | [V] [README](https://github.com/8144225309/soup-rendezvous/blob/main/README.md), [kinds.rs](https://github.com/8144225309/soup-rendezvous/blob/main/src/kinds.rs) |
| Explicit design rule | "Nostr is pure discovery": factory parameters, slots, joining and signing all happen host-to-wallet over Lightning | [V] [kinds.rs](https://github.com/8144225309/soup-rendezvous/blob/main/src/kinds.rs) |
| Removed on purpose | A factory advertisement kind (38100) was removed. Slot-fill status, join requests and software version fingerprints are "never added to Nostr" (the last because scraping helps attackers find vulnerable versions) | [V] [WALLET_INTEGRATION.md §12](https://github.com/8144225309/soup-rendezvous/blob/main/WALLET_INTEGRATION.md) |
| Spam tiers | Tier 1 proof-of-channel (the host signs a challenge with its node key; the check needs the node to be in BOLT 7 gossip, which is chain-anchored). Tier 2 proof-of-UTXO (signs with a bitcoin address holding an unspent output; the node id is the host's unverified word). Tier 3 proof-of-peer (a Noise handshake only; off by default on mainnet) | [V] [README](https://github.com/8144225309/soup-rendezvous/blob/main/README.md) |
| Caps and rates | At most 10 live vouches per node key (channel tier), 10 per address (UTXO tier), 3 per peer key. 80 chain-anchored and 20 peer requests per hour globally; 5 per hour and 1 per minute per sender | [V] [README](https://github.com/8144225309/soup-rendezvous/blob/main/README.md) |
| Freshness | Every vouch has a NIP-40 expiry: 14 days on mainnet, 30 on test networks. The host re-applies to stay listed ("use it or lose it"). Revocation republishes the same d-tag with `status: revoked` | [V] [README](https://github.com/8144225309/soup-rendezvous/blob/main/README.md), [WALLET_INTEGRATION.md §6](https://github.com/8144225309/soup-rendezvous/blob/main/WALLET_INTEGRATION.md) |
| Wallet side | Wallets hard-code coordinator keys, allow custom ones, take the union of several coordinators' lists, filter by tier at the relay (`#l` tag), and dedupe by node id. A channel-tier vouch should be checked against the wallet's own gossip, if it has any | [V] [WALLET_INTEGRATION.md §1, §8](https://github.com/8144225309/soup-rendezvous/blob/main/WALLET_INTEGRATION.md) |
| Live | Three coordinators (signet, testnet4, mainnet) are listed as live | [V] [README](https://github.com/8144225309/soup-rendezvous/blob/main/README.md) |
| Per-host browse | `superscalar-cln` defines `FACTORY_INFO_REQUEST` / `FACTORY_INFO_RESPONSE` (submessages 0x0140 / 0x0141): "third-party can ask: what factories do you run?" Read-only, no funds. The RPC `factory-browse-host` takes a node id and an optional `since_block` | [V] [ceremony.h](https://github.com/8144225309/superscalar-cln/blob/main/ceremony.h), [SUPERSCALAR_RPC_SPEC.md](https://github.com/8144225309/superscalar-cln/blob/main/SUPERSCALAR_RPC_SPEC.md) |
| Joining | `JOIN_REQUEST` / `JOIN_RESPONSE` (accepted, queued, rejected, already queued, already member) / `JOIN_CANCEL` (0x0142 to 0x0144). Requests are attributed by the BOLT 8 sender key, so they cannot be spoofed | [V] [ceremony.h](https://github.com/8144225309/superscalar-cln/blob/main/ceremony.h) |
| Host-side limits | At most 16 pending browse requests; 30 s timeout; per-peer limit of 10 requests per minute; per-peer concurrency cap; "soft ban" error codes | [V] [superscalar.c](https://github.com/8144225309/superscalar-cln/blob/main/superscalar.c) |
| Policy binding | The wallet caches the policy the host advertised in the info response, keyed by (host, factory instance), and refuses to sign a later proposal that breaks it | [V] [superscalar.c](https://github.com/8144225309/superscalar-cln/blob/main/superscalar.c) |
| Carrier | All factory traffic rides one **odd** custom type, 33001, carrying bLIP-56's envelope, instead of bLIP-56's even 32800. Stated reason: CLN dispatches only odd custom types to plugins, and the feature bit already gives must-understand. Feature bits 270/271 are set in `init` | [V] [superscalar-cln README](https://github.com/8144225309/superscalar-cln/blob/main/README.md) |
| Report | The implementation report on Delving names soup-rendezvous as the discovery path: "the factory protocol itself never touches Nostr" | [V] [Delving 2705](https://delvingbitcoin.org/t/superscalar-an-implementation-report/2705) |

### What worked, and what it teaches

1. **The split held up.** A small, rarely-changing, spam-filtered pointer on a public medium, then everything else over a direct, authenticated Lightning connection. That is the same split LSPS uses (A3) and JoinMarket's directory nodes use (A3). Gazpacho's plan keeps it.
2. **The chain anchor is the anti-spam.** Tier 1 reuses exactly what Lightning gossip uses to bound itself: a node exists in gossip only if it has a funded, announced channel.
3. **Expiry instead of cleanup.** Nothing had to be deleted; listings that are not refreshed vanish.
4. **What it did not do:** list lobbies. A wallet learned *hosts*, then asked each host. Gazpacho's plan adds lobby listings on Nostr, which reverses the earlier decision (already noted in `docs/LOBBY-research.md` A1 and B8).
5. **One gap:** the vouch says "this host exists" but not "this host runs factories now". The per-host browse fills that, at the cost of one connection per host.

## A5. What SuperScalar's own discussion says about finding a factory

| Point | Mark |
|---|---|
| The LSP runs a **ladder** of factories with overlapping lives. Example: 7-day active plus 2-day dying period, 9 factories. Suggested for deployment: 30 days active plus 3 dying, so **33 factories at once**, ideally one 1-input, 1-output transaction per day | [V] [Delving 1143 #1](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) |
| A member moves at the end of a factory's life: exit, assisted exit, or "move to a new factory (with LSP cooperation, possibly to a new LSP...)" | [V] [Delving 1143 #3](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143/3) |
| **Factories are built daily, and the LSP invites the member.** Joining the newest factory is how the monthly fee is paid; "the LSP can invite the client to join the newest SuperScalar"; misses get more chances on later days | [V] [Delving 1242 #2](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242/2) |
| **Onboarding: pick an LSP once.** "The app may present an interface to select one among multiple LSPs." A standard account opens "within 48 hours": the LSP schedules the new client into the next daily factory and wakes the app | [V] [Delving 1242 #2](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242/2) |
| Waking the app: the LSP can expose **LSPS5** (webhooks) so a wallet's push service wakes the phone at scheduled times | [V] [Delving 1242 #2](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242/2) |
| How a client finds an LSP's factory is **not discussed** in either topic beyond "select one among multiple LSPs". No gossip, Nostr or listing mechanism is proposed | [V] both topics read in full: [1143](https://delvingbitcoin.org/raw/1143) (34 posts), [1242](https://delvingbitcoin.org/raw/1242) (3 posts) |
| The implementation report says ladder cadence and how many factories run in parallel "are still being tuned" | [V] [Delving 2705](https://delvingbitcoin.org/t/superscalar-an-implementation-report/2705) |
| ZmnSCPxj's reply to the report: the next step is "getting people who actually run LSPs" to ship it | [V] [Delving 2705 #2](https://delvingbitcoin.org/t/superscalar-an-implementation-report/2705/2) |

**bLIP-56 (lightning/blips#56).**

| Point | Mark |
|---|---|
| Open since 2024-12-02, one author (ZmnSCPxj), files `blip-0002.md` and `blip-0056.md` | [V] [PR #56](https://github.com/lightning/blips/pull/56) |
| It covers: a feature bit (270/271, `pluggable_channel_factories`), an `open_channel` TLV 65600 (`channel_in_factory`), one message type 32800 with 16-bit submessages, `supported_factory_protocols` (sent right after `init`), `factory_piggyback` (opaque payload for the plugin), and factory state changes reusing splicing's quiescence and batched `commitment_signed` | [V] [PR #56 diff](https://github.com/lightning/blips/pull/56/files) |
| It does **not** cover factory creation, lobbies or discovery. The piggyback payload format is "outside the scope"; how the plugin talks to the node is "not specified" | [V] [PR #56 diff](https://github.com/lightning/blips/pull/56/files) |
| Small inconsistency: the glossary says the bit is advertised "in `node_announcement` and `init`", but its row in the bLIP-2 table gives context **I** only (the `init` message) | [V] [PR #56 diff](https://github.com/lightning/blips/pull/56/files) |
| Gossip for channels inside factories is deliberately out of scope. ZmnSCPxj: Lightning uses the UTXO set "to limit the size of the gossiped public network", so a gossip change (prove a share of n-of-n funds, gossip up to some multiple) must come first | [V] [Delving 1252 #3](https://delvingbitcoin.org/t/pluggable-channel-factories/1252/3) |
| René Pickhardt expects routing nodes to need factories too, which would need gossip extensions | [V] [Delving 1252 #2](https://delvingbitcoin.org/t/pluggable-channel-factories/1252/2) |
| t-bast (Eclair): wait for a reference implementation before merging; bLIPs nobody implements belong on Delving. tnull (LDK) pointed out bLIP-1 allows Draft merges; t-bast: early merges are for when more than one implementation is in progress | [V] [PR #56 comments](https://github.com/lightning/blips/pull/56) |
| The owner (2026-04-14) told the PR a team is building on bLIP-56, with a CLN fork and plugin | [V] [PR #56 comments](https://github.com/lightning/blips/pull/56) |

**What follows for discovery.** In ZmnSCPxj's own model, discovery is mostly a *first-time* problem. After onboarding the member does not browse: the LSP invites it into the next daily factory and wakes it. Browsing matters for (a) a new user choosing a host, (b) a member who wants to change host at the end of a factory's life, and (c) Gazpacho's open lobbies, which are more market-like than ZmnSCPxj's single-LSP account model.

## A6. Gossip's subscription rule, and load control elsewhere

| Point | Mark |
|---|---|
| "A node which wants any gossip messages has to send" `gossip_timestamp_filter`; otherwise it receives none. A new filter replaces the old one | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| A node "MUST not send gossip it did not generate itself, until it receives `gossip_timestamp_filter`", and "MUST NOT relay any gossip messages it did not generate itself, unless explicitly requested" | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| A node sends gossip it generated itself "regardless of `timestamp`", ignoring filters | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| To turn gossip off from a peer, set `first_timestamp` to 0xFFFFFFFF and `timestamp_range` to 0; the rationale suggests doing so after the first few peers | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| **Correction to the owner's recollection:** the rule no longer depends on negotiating `gossip_queries`. That bit has been "slightly repurposed": not offering it now means "not worth querying". The no-relay-until-filtered rule applies to every peer | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Bitcoin Core: when the mempool is full it evicts the lowest-fee-rate chunk and raises its minimum fee rate to that rate **plus** the incremental relay fee | [V] [txmempool.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/txmempool.cpp) |
| That rolling minimum decays with a 12-hour half-life, faster (6 h or 3 h) when the mempool is under half or a quarter full | [V] [txmempool.h](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/txmempool.h), [txmempool.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/txmempool.cpp) |
| Lightning implementations limit gossip locally, not by spec numbers: CLN 300 s between its own messages; LND burst 10 per minute per channel direction plus ban scores; LDK drops oversized extras. Taproot gossip would fix "one per block" in the spec | [V] sources in A1 |
| LND limits inbound connections with `num-restricted-slots=100` (default shown in the sample config) | [V] [sample-lnd.conf](https://raw.githubusercontent.com/lightningnetwork/lnd/master/sample-lnd.conf) |
| That the restricted slots are for peers **without channels** | [R] [LND release notes](https://github.com/lightningnetwork/lnd/tree/master/docs/release-notes) |
| Core Lightning dispatches only **odd** custom message types to plugins | [V] [superscalar-cln README](https://github.com/8144225309/superscalar-cln/blob/main/README.md) (the owner's own finding) |

## A7. Light clients can check chain anchors without a graph

| Point | Mark |
|---|---|
| Electrum protocol `blockchain.transaction.id_from_pos(height, tx_pos, merkle)` turns a block height and position (exactly what a `short_channel_id` encodes) into a txid, optionally with a Merkle proof | [V] [Electrum protocol methods](https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html) |
| `blockchain.transaction.get` returns the raw transaction; a `listunspent` method on a script returns its unspent outputs | [V] [Electrum protocol methods](https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html) |
| Esplora: `/block-height/:height`, `/block/:hash/txid/:index`, `/tx/:txid/hex`, and `/tx/:txid/outspend/:vout` (spent or not) | [V] [Esplora API.md](https://github.com/Blockstream/esplora/blob/master/API.md) |
| Soup's proof-of-channel used CLN `checkmessage`, which recovers the key and accepts only if it is in the local gossip graph; proof-of-UTXO used `verifymessage` plus `gettxout`; proof-of-peer a Noise handshake only. All three needed the coordinator's node | [V] [PROOF_OF_CHANNEL.md](https://github.com/8144225309/soup-rendezvous/blob/main/PROOF_OF_CHANNEL.md), [PROOF_OF_UTXO.md](https://github.com/8144225309/soup-rendezvous/blob/main/PROOF_OF_UTXO.md), [PROOF_OF_PEER.md](https://github.com/8144225309/soup-rendezvous/blob/main/PROOF_OF_PEER.md) |
| Soup's UTXO floor on mainnet: 100,000 sat recommended; 0 on signet | [V] [PROOF_OF_UTXO.md](https://github.com/8144225309/soup-rendezvous/blob/main/PROOF_OF_UTXO.md) |
| Soup's own estimate: a peer-tier Sybil costs about a $5/month server, and IPv6 makes addresses nearly free | [V] [PROOF_OF_PEER.md](https://github.com/8144225309/soup-rendezvous/blob/main/PROOF_OF_PEER.md) |

So a `channel_announcement` is a **self-verifying proof**. It holds both node keys, both bitcoin keys, four signatures and the short channel id. A wallet with only a chain server can find the funding output, check its script is the 2-of-2 of those bitcoin keys, read its value, and check it is unspent. The coordinator is not needed.

## A8. Onion messages as a query path: the details

The owner's leading design sends "list lobbies" and "get lobby terms" as onion messages with a blinded reply path. These are the facts it rests on.

| Point | Mark |
|---|---|
| **There is no BOLT 69.** The BOLTs are numbered 00 to 12 (no 06), plus `bolt-simple-taproot.md`. Onion messages are in **BOLT 4** ("Onion Messages" section); BOLT 12 uses them for offers. "69" is probably NIP-69 (Nostr peer-to-peer orders, A3) or the open bLIP pull request #69 (`client_info` for LSPS) | [V] [lightning/bolts file list](https://github.com/lightning/bolts), [bLIP PR search](https://github.com/lightning/blips/pulls) |
| BOLT 4 introduces onion messages as a way to "query for invoices" over existing connections, and calls them **unreliable**: no storage to forward and no errors returned | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) |
| Message type 513 `onion_message`; feature bits **38/39** `option_onion_messages` ("Can forward onion messages", contexts I and N). Bits 66/67 `option_onion_messages_only_channels` (refuses peers without a channel) | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md), [B9](https://raw.githubusercontent.com/lightning/bolts/master/09-features.md) |
| "For consistency, all onion messages use Route Blinding." A request carries a `reply_path` (a blinded path); the reply MUST go along it. A reply that does not use the exact path must be ignored, to stop probing | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) |
| **Size:** `len` is a `u16`, so the packet is bounded by the 65,535-byte message limit. Writers SHOULD use 1,366 (looks like a payment onion) or 32,834 bytes; larger sizes "should be used sparingly as it reduces the anonymity set" | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md), [B1](https://raw.githubusercontent.com/lightning/bolts/master/01-messaging.md) |
| **Rate limits:** a reader "MAY rate-limit messages by dropping them". It SHOULD accept messages from peers without a channel, unless it advertises bit 66/67 | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) |
| **Custom payloads:** fields 64 and above in the final hop's `onionmsg_tlv` are payloads. A message with more than one payload field MUST be ignored. A final node ignores a message with unknown even types. Intermediate nodes ignore messages carrying anything but `encrypted_recipient_data` | [V] [B4](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) |
| bLIP-2 keeps a table of onion-message payload types for bLIPs. The only entries are bLIP-32's DNSSEC types 65536, 65538 and 65550. So bLIP payloads sit at **65,536 and above** | [V] [bLIP-2](https://raw.githubusercontent.com/lightning/blips/master/blip-0002.md) |
| **LDK:** a `CustomOnionMessageHandler` trait reads custom payload types, handles them, and returns a reply sent along the `Responder` (the reply path) | [V] [LDK messenger.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/onion_message/messenger.rs) |
| **Core Lightning:** the `onion_message_recv` hook gives plugins unsolicited onion messages, including `unknown_fields` and the `reply_blindedpath`. `injectonionmessage` lets a plugin send one | [V] [onion_message_recv.json](https://github.com/ElementsProject/lightning/blob/master/doc/schemas/hook/onion_message_recv.json), [injectonionmessage.json](https://github.com/ElementsProject/lightning/blob/master/doc/schemas/injectonionmessage.json) |
| **Eclair:** API `sendonionmessage` takes a node or blinded route, `expectsReply`, and custom content. Its parser ignores unknown onion-message TLVs ("onion messages can be spammy") | [V] [Message.scala](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-node/src/main/scala/fr/acinq/eclair/api/handlers/Message.scala), [OnionMessageTlv.scala](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/scala/fr/acinq/eclair/wire/protocol/OnionMessageTlv.scala) |
| How Eclair delivers received custom onion messages to the application (an event stream) | [R] [Eclair API docs](https://acinq.github.io/eclair/) |
| **LND (master):** `SendOnionMessage` takes a prebuilt onion; `SubscribeOnionMessages` returns `custom_records` and the reply path. Graph-based sending is still an open pull request (#10651). BOLT 12 handlers merged in November 2026 behind a protocol flag | [V] [lightning.proto](https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/lightning.proto), [LND PR search](https://github.com/lightningnetwork/lnd/pulls?q=onion+message) |
| Which LND release first ships this | Not verified |
| **LND drops onion messages from peers without a fully open channel by default** (a "channel-presence gate"; `relay-all` is false by default). Then a per-peer bucket of 512 kbit/s and a global one of 5,120 kbit/s | [V] [LND onion_message_rate_limiting.md](https://raw.githubusercontent.com/lightningnetwork/lnd/master/docs/onion_message_rate_limiting.md) |

**What this means.**

- **Request size.** A query fits a 1,366-byte onion. A reply holding one listing fits a 32,834-byte onion.
- **The first hop.** A member sending a query needs a peer to inject it.
  - A member with a channel (to its current host or any LSP) uses that peer.
  - A brand-new user with no channel can connect to a node that accepts peers without a channel. CLN, Eclair and LDK do by default, as the spec says they SHOULD; LND does not.
  - If the first hop is the queried host itself, onion routing hides nothing. So the privacy gain needs a different first hop.
- **Anonymity.** The host learns that someone asked, but not who. Its reply goes back along a blinded path that it cannot trace.

## A9. A static "host card" in `node_announcement`

| Point | Mark |
|---|---|
| `node_announcement` has no TLV stream in the BOLTs. Liquidity ads proposes adding one (#1153, type 5); CLN (type 1) and Eclair (type 1339) already append one | [V] A1, A2 |
| bLIP-2: TLVs a bLIP adds to BOLT messages use types **above 65,536** | [V] [bLIP-2](https://raw.githubusercontent.com/lightning/blips/master/blip-0002.md) |
| LDK relays at most 1,024 bytes of unknown extra data; LDK's Rapid Gossip Sync drops it entirely | [V] A1 |
| A receiver may decline to queue announcements longer than the minimum | [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| Whether CLN and Eclair relay unknown `node_announcement` TLVs they do not parse | [R] [CLN gossipd](https://github.com/ElementsProject/lightning/tree/master/gossipd) (not checked) |
| Precedent for change rate: LSPS1's `get_info` values "SHOULD NOT change" more than once a day | [V] [bLIP-51](https://raw.githubusercontent.com/lightning/blips/master/blip-0051.md) |
| Any `node_announcement` change is a network-wide flood. CLN emits at most one per 300 s; taproot gossip would allow one per block | [V] A1 |

---

# Part B. Synthesis

## B0. The design this part follows

The owner's leading design, which the evidence supports:

1. **Gossip says only who hosts factories.**
   - An odd feature bit in `node_announcement`.
   - Optionally a small, static **host card** TLV.
   - **No per-lobby or per-factory event ever goes through gossip.**
   - The card is subject to `node_announcement`'s own rate limits and pruning.
2. **Details are asked of the host.**
   - "List lobbies" and "get lobby terms" go as **onion messages with a blinded reply path**, as BOLT 12 does for invoice requests. The host learns that someone asked, not who or from where.
   - A query over a direct encrypted connection is the fallback.
3. **Joining and signing use a direct connection,** as specified in `spec/messages.md`.
4. **Collecting other hosts' lobbies is off by default.** A lobby relay network ("sub-gossip") is a reserved option, not part of the design.
5. **Nostr** serves light clients that have no gossip. It carries host cards and lobby listings. This is where chain anchors and per-anchor caps matter most.

## B1. Short answers

| Question | Answer |
|---|---|
| Should the specification include Nostr lobby discovery? | **Yes, as an optional binding (an annex), not as the core.** The core is Lightning: bit, card, onion and direct queries, a self-verifying listing record. The Nostr annex says which event kind and tags carry the same record, so wallets interoperate (NIP-69's shared format let four platforms do so). Validity never depends on Nostr |
| Is Lightning's own communication the proper and safe home? | **Yes, for everything except broadcasting lobbies.** The bit and a static card fit gossip, as LSPS's bit 729 and liquidity ads do. Queries fit onion messages: this is what they were made for ("to query for invoices", BOLT 4). Negotiation fits direct messages, as in LSPS and PeerSwap |
| Any problem carrying lobby records over Lightning? | Direct and onion messages: none, within sizes (1,366 / 32,834-byte onions; 65,535-byte messages) and rate limits. Gossip: not built for it. It reaches the wrong audience, has no room, sets a slow pace, and light clients cannot see it (B3) |
| Sub-gossip among factory nodes? | Workable but not needed now. It brings weak relay incentives and channel-less peering, and it is roughly as much work as the whole lobby system. Keep the record format and reserve the messages; do not build it (B4) |
| Proofs without a coordinator? | Channel and coin anchors can be checked by any wallet through a chain server. Needed on Nostr; on Lightning paths the host's own gossip presence or connection already says enough. Peer-only proofs do not bound spam (B5) |
| "Don't send me announcements"? | Copy `gossip_timestamp_filter`: nothing about other hosts is sent unless asked. Off by default. Since lobbies are not relayed, this matters only for the reserved relay option (B6) |
| How many lobbies per host? | At most **4 listed** lobbies open per host key. On Nostr, also **one listing per 1,000,000 sat of anchor** (minimum anchor 250,000 sat), with relays and wallets free to tighten under load (B7) |
| Per-host querying optimal? | Yes, for terms and live state, and with onion messages it reveals little. To *find hosts*, light clients need a list (Nostr, invitations, a built-in list, or a trusted full node), as every LSP wallet today does |
| Shipping without discovery a mistake? | Not if the bit, the card, the listing record and the query messages are in the first specification. Carriers can then be added later |
| Even message types? | Right for must-understand messages after negotiation; wrong for discovery (B11) |

## B2. The layers

| Layer | What | Where | Changes | Spec |
|---|---|---|---|---|
| 0. Capability | "Hosts factory lobbies" | Odd feature bit, `init` and `node_announcement` | Rarely | Core |
| 1. Host card | Protocol id, channel size range, usual lobby time and cadence, profiles | `node_announcement` TLV (optional); the same bytes in onion and direct answers and on Nostr | At most once a day | Core, optional to publish |
| 2. Lobby index | Which listed lobbies are open: `outer_digest`, deadline, profile, size range | Onion-message answer; direct fallback; Nostr | Per lobby | Core |
| 3. Listing | One signed record per lobby: the outer terms, contact, optional anchor, expiry | Onion-message answer; direct fallback; Nostr (anchor required there) | Once per lobby | Core |
| 4. Live state | Current values, fill, seats | Direct connection only | Often | Core (`messages.md`) |
| 5. Negotiation | `join`, `ready`, rounds | Direct connection only | Per step | Core (`messages.md`) |
| 6. Host lists for light clients | Hosts to try | Nostr, invitations, built-in list, a trusted full node's answer from its graph | Rarely | Nostr annex; one optional query |
| Reserved | Lobby relay among factory nodes | Not built | | Messages reserved |

**The listing is the outer terms record**, which never changes during a lobby (`spec/terms.md` section 1), plus a signature. Everything that moves stays on the direct connection. This is the pattern liquidity ads reached (gossip holds non-binding defaults, binding terms come at request time) and LSPS2 uses (offers carry an expiry and a promise).

## B3. Why gossip carries only the bit and the card

1. **No room for lobbies.** No TLV stream on master. LDK drops more than 1,024 extra bytes. A Slice 1 outer record alone is 225 bytes.
2. **Wrong audience.** All 6,000-plus routing nodes receive every byte. Rusty Russell made this point about liquidity ads: bytes matter because they are gossiped "all over the network".
3. **Wrong pace.** There are 113,000 to 149,000 node announcements a day already. Taproot gossip would allow one per block. A daily lobby would mean a network-wide flood each day for every host.
4. **Light clients cannot see it.** They do not sync gossip, and Rapid Gossip Sync strips TLVs.
5. **The bit and a small static card are fine.** They follow precedent (bits 729, 258/259, 256/257; liquidity-ad rates). A card of about 60 bytes is well under LDK's limit. It changes at most daily, like LSPS1's `get_info`.
6. **Honest limit of the card.** It is a TLV the BOLTs do not define yet. Whether every implementation relays unknown `node_announcement` TLVs is not verified (A9). So the card is a convenience for full nodes. The same card bytes must also be obtainable by query and from Nostr.

## B4. The sub-gossip idea, evaluated

**The idea.** Nodes with the factory bit peer with each other and relay lobby listings and start times among themselves only.

| Aspect | Assessment |
|---|---|
| Peering | Hosts find each other by the bit and hold connections **without channels**. LND drops onion messages from channel-less peers by default [V] and limits inbound connections [V]. A mesh must expect refusals |
| Sync and dedup | Copy gossip: no relaying until a filter is received (B6). Deduplicate by `outer_digest`, exact because listings are immutable |
| Flood control | 60-second flush, per-host and per-anchor allowances (B7), expiry by block height |
| Set reconciliation | Not needed. 1,000 hosts × 4 listings × about 800 bytes is about 3.2 MB a day, against about 103 MB of unique gossip a day |
| Light clients | Could ask any factory node; listings are self-verifying, so a relay can omit but not forge |
| Incentive | Weak. A host gains nothing by relaying a competitor and may silently drop it. Routing nodes relay gossip because they need the whole graph to route; hosts do not need each other's lobbies |
| Implementer acceptance | Not needed if it stays an application overlay (BOLTs never forward custom messages). A BOLT version would be hard to pass |
| Work | About as large as the lobby subsystem: store, eviction, channel-less peering, filters, restart tests |
| Verdict | **Reserved.** The owner's design (query the host; Nostr for light clients) gets the same reach for much less. The only case for building it: if Nostr becomes unusable *and* no trusted full node is available to light clients. Reserve message kinds now so it can be added without a format change |

## B5. Proofs without a coordinator, and where they matter

**Where anchors matter.**

| Path | Spam risk | Anchor needed? |
|---|---|---|
| Gossip bit and card | Bounded already: a node is in gossip only with an announced, funded channel | No (gossip is the anchor) |
| Onion or direct query to a known host | The asker chose the host; the host lists only its own lobbies | No; the per-host cap still applies |
| Host found by invitation or QR | The member chose to trust the link | No |
| **Nostr** | Anyone can publish anything, for free | **Yes** |
| Reserved relay | Anyone can push | Yes |

**Self-verifying anchors** (replacing Soup's coordinator):

| Soup tier | Self-verifying version | Wallet check | Keep? |
|---|---|---|---|
| Proof-of-channel | The listing carries the host's `channel_announcement` (about 430 bytes); the host is node 1 or node 2 | Four signatures. Then, through a chain server: `short_channel_id` → txid (Electrum `id_from_pos`, or Esplora `/block-height` then `/block/:hash/txid/:index`); the output is the P2WSH 2-of-2 of the two bitcoin keys; read its value; check it is unspent (`/tx/:txid/outspend/:vout`). Full nodes may check their graph instead | **Keep**, main anchor |
| Proof-of-UTXO | The listing carries an outpoint, `valid_until_height`, and a signature by the coin's key over `TH("gazpacho/anchor", chain ‖ host_key ‖ outpoint ‖ valid_until_height)`: BIP 340 for key-path P2TR, BIP 322 otherwise | Signature; output exists, unspent, at least 6 confirmations, script matches the key | **Keep**, for hosts with only taproot or unannounced channels. Publishes one host coin |
| Proof-of-peer | Nothing that bounds spam | | **Drop** for public listings. Invitations replace it |

**From Soup, keep:**

- tier labels (cheap relay-side filtering on Nostr);
- caps per anchor;
- expiry;
- domain-separated signatures;
- "a bad listing costs a wasted query";
- merging several sources.

**Change:**

- each wallet verifies, instead of a coordinator;
- one signature scheme (BIP 340 over tagged hashes);
- the coin signature names `host_key`, so nobody can borrow a coin;
- the listing carries the outer terms, so a wallet can filter before querying;
- the anchor value is visible, since it is on chain anyway;
- lifetimes follow the lobby (hours), not 14 days.

**Light-client cost.** Two or three chain-server requests per anchor, done only for listings the wallet shows. Results are cached for 144 blocks. Each check tells the chain server which outpoint interested the wallet: use Tor or the wallet's own server.

**Limit.** `channel_announcement` covers P2WSH channels only until taproot gossip merges (A1).

## B6. "Don't send me factory announcements"

The Lightning rule, verified (A6):

- A node "MUST not send gossip it did not generate itself, until it receives `gossip_timestamp_filter`".
- It sends its own gossip regardless.
- A new filter replaces the old.
- A filter that matches nothing turns relayed gossip off.
- Correction: this no longer depends on negotiating `gossip_queries`; that bit was repurposed.

The analogue for factories:

- **Gossip itself needs nothing new.** The bit and card ride in the host's own `node_announcement` and follow gossip's filter.
- **No node sends lobby information about other hosts, ever, in the core design.** A host sends information about its own lobbies only when asked (`lobby_index_request`, `listing_request`, `hello`).
- **Stockpiling is off by default.** A wallet or node collects other hosts' lobbies only when its user turns that on. On Nostr that means subscribing; with the reserved relay it would mean sending a `listing_filter`.
- **Reserved `listing_filter`.** It works like `gossip_timestamp_filter`: nothing is relayed before it, it replaces the previous one, and a filter matching nothing (0xFFFFFFFF, 0) means off.

## B7. How many lobbies per host

**Need.** A ladder host starts about one factory a day and lobbies overlap a day or two. With two public profiles (Standard, Starter), that is up to four open listed lobbies. Circle lobbies are unlisted and do not count. The owner's "3" is close; 4 fits the ladder.

| Option | For | Against |
|---|---|---|
| Fixed maximum per host key | Simple; bounds every answer | On Nostr, keys are free: a spammer makes more keys |
| Allowance per anchor, by value | Spam cost scales with locked coins; linear, so splitting coins gains nothing | Shuts out the smallest hosts at the floor |
| Weight by age | Discourages coins moved in only to list | Splices reset age |
| Tighten under load | Adapts without a protocol change; Bitcoin's mempool raises its minimum fee when full | Different readers see different sets |

**Recommendation.**

- *Fixed by the protocol, all paths:*
  - at most 4 listed lobbies open per host key;
  - an answer never lists more.
- *Fixed by the protocol, Nostr (and the reserved relay):*
  - every listing carries an anchor;
  - an anchor of value V backs at most `min(4, floor(V / unit))` open listings;
  - an anchor must be at least `unit / 4`;
  - `unit` is 1,000,000 sat on mainnet and 10,000 on signet.
- *Local, may only tighten:*
  - a wallet or relay keeps a budget and ranks by weight `V × min(confirmations, 1008) / 1008`;
  - when full, it drops the lowest weight and refuses anything below that weight times 1.1;
  - this minimum halves every 12 hours, as Bitcoin Core's rolling minimum fee does.

## B8. Draft rule set for the specification

Draft text. Numbers are proposals (**owner to confirm**). Kinds use `spec/messages.md`'s envelope: odd kinds are optional, unknown odd kinds are ignored.

### D1. Capability bit

1. A host that offers factory lobbies SHOULD set the feature bit `factory_host` in `init` and `node_announcement`, **odd only**, a bit above 255 chosen at random and registered in bLIP-2 (number **(open)**). An unknown even bit in `node_announcement` makes other nodes refuse to connect (BOLT 7).
2. Members MUST NOT set it. (LSPS bit 729 has the same rule.)
3. A node that sets it MUST answer D4 queries by onion message if it sets `option_onion_messages`, and over a direct connection in all cases.

### D2. Host card

A TLV stream, canonical as `terms.md` section 2, at most 256 bytes.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `protocol_id` | 32 | The factory protocol (bLIP-56 style id) |
| 4 | `channel_range` | 16 | Smallest and largest `channel_sat` the host usually offers (`u64`, `u64`) |
| 6 | `schedule` | 4 | Usual lobby start, minutes after 00:00 UTC (`u16`), and cadence in hours (`u16`); 0xFFFF = irregular |
| 8 | `profiles` | 1 | Bitmap of profiles the host lists (bit 0 Safety, 1 Standard, 2 Starter) |
| 9 | `name` | 1 to 32 | Optional, display only |

- In `node_announcement` it travels as one odd TLV type above 65,536 **(open)**, signed by the announcement's own signature.
- The card is **static and advisory**. The host SHOULD NOT change it more than once in 24 hours, the LSPS1 rule. Any change is a new `node_announcement`, so it is subject to that message's rate limits and pruning.
- A reader MUST NOT treat the card as terms. Terms come only from a listing or `terms_offer`.
- The same bytes are returned in `lobby_index` (D4) and may be published on Nostr (D8), signed there by `host_key`.

### D3. Listing record

A TLV stream, canonical, at most 8,192 bytes.

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `chain` | 32 | |
| 4 | `host_key` | 33 | Equals the outer record's `host_key` |
| 6 | `outer` | 1 to 4,096 | The outer terms record |
| 8 | `outer_sig` | 64 | `terms.md` section 6 |
| 10 | `listed_height` | `u32` | At most 6 blocks ahead of the reader's tip |
| 12 | `expiry_height` | `u32` | At most 1,008 blocks after `listed_height`. The listing is also dead after the outer `deadline` |
| 14 | `anchor` | 1 to 600 | D6. Required on Nostr and the reserved relay; optional in D4 answers |
| 15 | `addresses` | BOLT 7 address list | Optional; for hosts not in gossip |
| 17 | `blinded_contact` | blinded path | Optional; for hosts not in gossip that accept onion queries |
| 240 | `listing_sig` | 64 | BIP 340 by `host_key` over `TH("gazpacho/listing", every byte before 240)` |

`listing_id` is the `outer_digest`. A withdrawal is the same listing re-signed with `expiry_height` equal to `listed_height`.

### D4. Queries: onion message first, direct connection as fallback

Two requests, two answers. They are the same records on both carriers.

| Name | From → to | Records | Answer |
|---|---|---|---|
| `lobby_index_request` | asker → host | `chain` (32); optional `profiles` (1) | `lobby_index` |
| `lobby_index` | host → asker | `chain`; `host_card` (D2); `entries`: 0 to 4 × (`outer_digest` 32, `deadline` `u64`, `profile` `u8`, `channel_sat` `u64`); `as_of_height` `u32`; `index_sig` (BIP 340 by `host_key`, record 240) | |
| `listing_request` | asker → host | `chain`; `outer_digest` (32) | `listing` |
| `listing` | host → asker | One listing record (D3), or `unknown` | |

**Over onion messages:**

- O1. Each message is an onion message whose final-hop `onionmsg_tlv` holds exactly one payload field, of a type **(open)** registered in bLIP-2's onion-message table (65,536 and up). Proposed: four odd types, one per message.
- O2. A request MUST carry `reply_path`. The asker MUST put a `path_id` in its own blinded path and accept only replies that use it (BOLT 4).
- O3. Requests SHOULD be 1,366-byte onions. `lobby_index` fits 1,366 bytes. `listing` uses 32,834 bytes.
- O4. The asker SHOULD use a first hop other than the host, and a fresh reply path per request. Sent through the host itself, the query hides nothing.
- O5. For a host in gossip, the asker routes to `host_key`. For one not in gossip, it uses the listing's or invitation's `blinded_contact`.
- O6. Onion messages are unreliable. An asker that gets no answer within 30 s MAY retry once by another first hop, then fall back to the direct query.

**Over a direct connection (fallback):**

- F1. The same four messages are kinds 43, 45, 47 and 49 of the native carrier (type 52791), with the same records. `hello` with scope zero stays as specified and returns `terms_offer` for each listed lobby.
- F2. The asker SHOULD use a fresh BOLT 8 key per query session, not its seat key. It SHOULD connect over Tor where available. Without Tor the host learns the asker's address.

**Host-side limits, both carriers:**

- H1. Each answer lists only the host's own listed lobbies, at most 4. Unlisted lobbies never appear.
- H2. A host answers at most 1 `lobby_index_request` and 4 `listing_request`s per 10 s per source. By onion message the source is the incoming peer; directly it is the connection. It also answers at most 50 queries per second in total. Beyond that it drops silently (BOLT 4 allows dropping).
- H3. The host MUST NOT answer differently depending on who asks, beyond refusing. (A member can detect a host that does, by comparing with Nostr.)
- H4. Answers are signed (`index_sig`, `listing_sig`), so they can be relayed or shown later without trusting the carrier.

### D5. Live state and joining stay direct

- Current values, fill level, seats and every negotiation and round message travel only over a direct BOLT 8 connection, as in `messages.md` sections 6 and 7.
- `lobby_index` and listings never say who joined, or how many.
- The `outer_digest` in a listing equals the `scope` the member uses in `hello` and `join`. So the lobby browsed is provably the lobby joined.

### D6. Anchors (required on Nostr and the reserved relay)

| Type | Anchor | Contents | Check |
|---|---|---|---|
| 2 | Channel | A full BOLT 7 `channel_announcement`; `host_key` is node 1 or node 2 | Signatures; output found through the chain; P2WSH 2-of-2 of the bitcoin keys; unspent; at least 6 confirmations. Value counts half for each node |
| 4 | Coin | `outpoint` (36), `valid_until_height` (`u32`), signature by the coin's key over `TH("gazpacho/anchor", chain ‖ host_key ‖ outpoint ‖ valid_until_height)` | Signature; output exists, unspent, at least 6 confirmations, script matches the key |

- A1. A listing whose anchor fails is dropped and never relayed or shown.
- A2. Re-check "unspent" before showing a listing whose anchor was last checked more than 144 blocks ago.
- A3. Allowance: `min(4, floor(V / unit))` open listings per anchor. Minimum anchor `unit / 4`. `unit` is 1,000,000 sat on mainnet and 10,000 on signet.
- A4. At most 4 open listings per `host_key`, on any path.
- A5. Over an allowance, keep the earliest `listed_height` (ties: lowest `listing_id`) and drop the rest.
- A6. One anchor, one host. If two `host_key`s present the same anchor while both listings are open, drop both.
- A7. Local policy may only tighten A3 and A4: a budget, priority by weight, and a rolling minimum (B7).

### D7. Host lists for light clients

A light client without gossip finds hosts by any of these:

- invitations and QR codes (`host_key@address`, or a blinded contact);
- a built-in list the user can edit;
- Nostr (D8);
- **optionally, a trusted full node** (its own node, or its current host) answering `host_list_request`. That node answers from its own graph with up to 64 entries. Each entry is a `node_announcement` that carries `factory_host`, together with one of that node's `channel_announcement`s. Every entry is therefore signed and chain-anchored, and the answering node can omit entries but not forge them. Kinds 51 and 53 natively; onion payload types **(open)**.

### D8. Nostr binding (informative annex)

- **Listing event.** Addressable, kind **(open)** in 30000 to 39999.
  - `d` = `listing_id` hex.
  - NIP-40 `expiration` at `expiry_height` or `deadline`, whichever is sooner.
  - Content = base64 of the listing record, **with anchor**.
  - Tags `chain`, `profile`, `anchor` (`channel` or `coin`) for relay-side filtering.
- **Host card event.** Replaceable, kind **(open)**.
  - Content = base64 of the host card plus a `host_key` signature over `TH("gazpacho/card", card)` plus an anchor.
- **Validity.** Any Nostr key may publish either event. Readers MUST verify the inner records and anchors and MUST ignore the Nostr author for validity.
- **Withdrawal.** A withdrawal replaces the listing event.

### D9. Reserved

- Kinds 35 to 41 (`listing_query`, `listing`, `listing_end`, `listing_filter`) are reserved for a lobby relay among factory nodes. They are not specified now.
- If specified later, they follow B6:
  - nothing is relayed before a filter;
  - filters replace each other;
  - D6 applies in full;
  - relays may only tighten (B7).

## B9. What the demo wallet does (first release, signet)

| Item | Demo wallet | Why |
|---|---|---|
| Join by link or QR | Yes | Already specified |
| Built-in, editable host list | Yes | How every LSP wallet works today (A3) |
| Feature bit and host card on the demo host | Yes, both set | Cheap; exercises D1 and D2. The wallet does not depend on them |
| Direct queries (D4 fallback, F1, F2) | **Yes, primary in this release** | Smallest new code: kinds in the existing carrier, fresh key per session, Tor optional |
| Onion-message queries (D4, O1 to O6) | **Next step, before mainnet** | Needs Sphinx onion construction, route blinding and reply-path handling in the core. That is real new code, unless the host runs inside a node that has it (LDK, CLN, Eclair). Specified now so it slots in unchanged |
| Nostr listings and host cards | Yes, read and publish, with coin anchors (signet unit 10,000 sat) | The light-client path; tests D6 and D8 end to end |
| Channel anchors | Optional | Signet demo hosts may have no public channel |
| Trusted full node `host_list_request` | No | Later |
| Stockpiling other hosts' lobbies | No (off) | B6 |
| Reserved relay | No | B4 |

## B10. Protocol map additions

| Element | Value | Signed by | Expiry or rate |
|---|---|---|---|
| Feature bit `factory_host` | Odd, above 255, contexts I and N, **(open)** | `node_announcement` | Gossip's |
| Host card TLV | Odd, above 65,536, **(open)**; D2 | `node_announcement`, or `host_key` elsewhere | At most one change per 24 h |
| Listing record | D3 | `host_key` | `expiry_height`, `deadline` |
| Anchors | D6 types 2 and 4 | Channel signatures; coin key | While unspent |
| `lobby_index_request`, `lobby_index`, `listing_request`, `listing` | Onion payload types **(open)**; native kinds 43, 45, 47, 49 | Answers signed by `host_key` | H2 |
| `host_list_request`, `host_list` | Native kinds 51, 53; onion types **(open)** | Entries carry gossip signatures | Optional |
| Reserved relay | Native kinds 35 to 41 | | |
| Tags | `gazpacho/listing`, `gazpacho/anchor`, `gazpacho/card`, `gazpacho/index` | | |
| Nostr kinds | Two, **(open)**; avoid 38099 and 38101 (Soup) and 38383 to 38389 (NIP-69, Mostro) | | NIP-40 |

**One record, every path.** The listing bytes are the same in a `listing` onion reply, a direct reply, a Nostr event, and a reserved relay. The outer record inside is byte-for-byte what `terms_offer` carries. One verifier serves all carriers.

**Changes to existing drafts this implies:**

- `messages.md` open point 1 is answered: a feature bit is needed, for discovery.
- `messages.md` section 6.1's "at most 16" can drop to 4 for listed lobbies.
- `LOBBY.md` "What is public" gains the onion query, the host card and anchors.

## B11. The even-type question

- **What even means.** BOLT 1: an unknown even message closes the connection. BOLT 9: an even bit is compulsory. In `node_announcement`, an unknown even bit makes other nodes refuse to connect.
- **When even is right.** For messages both sides must understand after negotiating a feature: channel updates inside a factory, or bLIP-56's factory change flow. Splicing works this way.
- **When it is wrong.** For discovery and queries, which must be safe to send to anyone and safe to ignore. Every Lightning discovery precedent is odd: LSPS 37913 and bit 729, PeerSwap, bLIP-32. CLN also gives only odd custom types to plugins, the reason the owner's plugin used 33001 (A4). Inside the odd outer type, Gazpacho's even `kind`s already give must-understand semantics where needed.
- **The path to "core".** It runs as dual funding and splicing did:
  1. a proposal;
  2. experimental bits (+100);
  3. two or three implementations interoperating (three years for dual funding; two more for splicing);
  4. then a BOLT.
  
  The near step:
  - bLIP-56 with a reference implementation, t-bast's condition for merging (A5);
  - Gazpacho can supply that implementation;
  - a BOLT follows only when a second team ships.
- **Discovery stays optional even then.** LSPS discovery never became mandatory. If anything becomes compulsory, it is the channel-in-factory messages.

## B12. Risks and open questions

| Item | Note |
|---|---|
| Bit, TLV, onion-payload and Nostr numbers | Choose at random, check bLIP-2 and the NIPs repository, register when proposing |
| Host card relay | Not verified that every implementation relays unknown `node_announcement` TLVs. Keep the card also in `lobby_index` and on Nostr |
| Onion first hop | LND gates channel-less peers by default; a new user with no channel must use a CLN, Eclair or LDK node as first hop, or fall back to direct |
| Onion anonymity | Lost if the first hop is the host. Large (32,834-byte) replies have a smaller anonymity set (BOLT 4) |
| bLIP-56 bit 271 context | Table says I only, glossary says N too. A separate host-only bit is still needed, as LSPS separates LSPs from clients |
| Coin anchor privacy | Publishes a host coin; use a dedicated one |
| Channel anchors and taproot channels | P2WSH only until taproot gossip |
| Fake lobbies | Bounded in number on Nostr by D6; on Lightning paths by the 4-per-host cap. Local history de-ranks hosts whose lobbies never start |
| Host overload | H2 limits; onion messages may be dropped at will |
| What a member reveals | Onion query: that someone asked. Direct query: interest, and the address without Tor. Nostr read: nothing to the host; the relay sees the subscription |
| Proposed numbers | 4 per host, 1,000,000 / 250,000 sat, 1,008-block expiry, H2 rates: tune on signet |

## B13. What needs proposing publicly, and what Gazpacho can do alone

- **Gazpacho alone, now:**
  - the bit and card on its own hosts (unregistered numbers);
  - the listing record and queries in its own carrier;
  - onion payload types in the bLIP range;
  - anchors;
  - the Nostr binding;
  - the demo wallet behaviour.

  All of it is odd and ignorable by others.
- **Needs a public proposal later** (drafts stay local until the owner decides, per the standing rule):
  - registering the bit, the card TLV, the onion payload types and the custom message type in bLIP-2, through a bLIP;
  - a NIP for the two Nostr kinds;
  - feedback on bLIP-56 (the even 32800 versus plugins, and the bit's context).
- **Not to propose:** lobbies in BOLT 7 gossip.

## B14. What could not be read

- lightning-dev mailing-list archives (bot check; not bypassed);
- the "Magical Minisketch" PDF;
- jharveyb's draft minisketch BOLT;
- the LND release that first ships onion messages, and LND's exact rule for channel-less connections;
- whether CLN and Eclair relay unknown `node_announcement` TLVs;
- how Eclair delivers received custom onion messages;
- the Lightning Pool whitepaper;
- Amboss's API reference;
- the Greenlight SDK repository;
- RoboSats' learn pages;
- Mostro's spam pages.

The gossip-observer and Magma figures came through a summarising fetch.
