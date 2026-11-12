# Preferential peering for the beacon overlay, and whether Nostr can go: research

Research note, 2026-11-12. Read-only research; nothing was posted anywhere.

The owner's questions:

1. What is the best technique for the preferential peering and the overlay in Gazpacho's discovery design (layer 3, the lobby beacon)?
2. Could this design one day let Gazpacho drop Nostr?

Background that this note does not repeat is in `notes/discovery-research.md`, cited below as **DR** with its section (for example DR A8). The explainer for the owner is `notes/discovery-comparison.html`.

## How to read this file

- Every claim carries a source link and a mark.
  - **[V]** VERIFIED: the source was read in this session, by me or by a research helper working this session.
  - **[R]** RECALLED: from memory or a search summary, not read this session. Treat it as a lead.
- Line numbers in code links are from `master` as fetched on 2026-11-12. They will drift.
- Short quotes stay under 15 words.
- Part A is evidence. Part B is the design. Part C compares the six discovery designs. Part D is the Nostr verdict. Part F (added on the owner's request) checks Bitcoin's relay and mempool patterns and says what `discovery.md` should fix now. Part E lists what could not be read.

## The design being refined

From the brief, and from `tools/spec-vectors.py` in the specs worktree (vectors D7 to D12; `spec/discovery.md` itself is not written yet):

| Layer | What | Fixed so far |
|---|---|---|
| 1 | Odd feature bit(s) in `node_announcement`. The brief had two (F factory-capable, H hosting); the ledger now has **one**, F (A1) | Ordinary nodes relay them: BOLT 7 says odd bits "will be propagated normally" [V] [B7](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md) |
| 2 | Onion-message queries to a host for its signed lobby listings | DR B8 D4 |
| 3 | Lobby beacon | Records: host key (33), lobby digest (32), open height, deadline height, sequence (`u32` each), BIP 340 signature over `TH("gazpacho/beacon", …)`. **153 bytes** of records, 193 on the wire with the native header. Native kinds 141 (`lobby_beacon`) and 143 (`beacon_filter`). Withdrawal = next sequence with deadline = open height. A host keeps at most 4 live beacons; a fifth evicts the lowest sequence. Seen-set of `min(65,536, max(1,024, 8 × hosts))` entries | [V] `tools/spec-vectors.py` lines 553, 690-726 (worktree `wt-specs`) |
| 4 | Optional Nostr annex for light clients | DR B8 D8 |

Beacons are accepted only from nodes in the gossip graph with the bit, capped per host, expire at the deadline, are relayed by default among F nodes, and are stored only by nodes that opt in.

**Update from the ideas ledger (`notes/ideas-ledger.md` A1, A3, A6), applied throughout this note:**

- **One** public factory bit F, not two. A *host* is whoever sends beacons. In this note "host" means an F node with a live beacon in the receiver's store.
- A per-connection **lobby store** flag in the factory handshake, like the relay flag in Bitcoin's `version` message (BIP 37 `fRelay`, used by blocks-only nodes).
- Every F node relays beacons **immediately**.
- **Store nodes** fetch the listing for every beacon they hear (after a random delay), keep it until expiry, and serve peers.
- Others ask a store peer first ("don't have" answered immediately), then the host after a random delay.
- A **pool request** gives catch-up and the light-client path.
- No per-beacon "have" flag.

The two-bit wording in the brief is kept only where it explains the original question.

---

# Part A. Evidence

## A1. Bitcoin Core: preferring peers with a service bit

### Segwit: NODE_WITNESS

| Claim | Source | Mark |
|---|---|---|
| In v0.13.1, `nRelevantServices` gained `NODE_WITNESS` as soon as a segwit deployment was defined, not at activation | [v0.13.1 init.cpp l.1443-1452](https://raw.githubusercontent.com/bitcoin/bitcoin/v0.13.1/src/init.cpp) | [V] |
| v0.13.1 skipped addresses lacking the relevant bits, unless 40 or more tries had failed and fewer than half of the 8 outbound slots were up. So only the first 4 slots could fall back | [v0.13.1 net.cpp l.1716-1718](https://raw.githubusercontent.com/bitcoin/bitcoin/v0.13.1/src/net.cpp) | [V] |
| A peer whose `version` lacked the expected bits was disconnected ("does not offer the expected services") | [v0.13.1 main.cpp l.4979-4985](https://raw.githubusercontent.com/bitcoin/bitcoin/v0.13.1/src/main.cpp) | [V] |
| DNS seeding was skipped only when 2 or more peers had the relevant bits; otherwise seeds were asked for those bits | [v0.13.1 net.cpp l.1503-1535](https://raw.githubusercontent.com/bitcoin/bitcoin/v0.13.1/src/net.cpp) | [V] |
| PR 8949 (gmaxwell, merged October 2016) allowed fallback to other peers only "until half the outbound connections are up" | [PR 8949](https://github.com/bitcoin/bitcoin/pull/8949) | [V] |
| Issue 9072 objected to "preferential peering" toward witness peers before activation; closed | [issue 9072](https://github.com/bitcoin/bitcoin/issues/9072) | [V] |
| PR 9082 ("…non-Witness peers are still connected to") was closed unmerged. gmaxwell's objection: a sudden topology change at activation risks a partition. sipa: the goal was to "never connect to anything but segwit nodes" | [PR 9082](https://github.com/bitcoin/bitcoin/pull/9082) | [V] |
| PR 11456 (October 2017) removed `nRelevantServices`: outbound non-feeler connections now always require NETWORK and WITNESS; feelers need only NETWORK | [PR 11456](https://github.com/bitcoin/bitcoin/pull/11456) | [V] |
| Today `GetDesirableServiceFlags()` returns `NODE_NETWORK_LIMITED \| NODE_WITNESS` near the tip (within 144 blocks), else `NODE_NETWORK \| NODE_WITNESS`. `HasAllDesirableServiceFlags(s)` is `!(desirable & ~s)` | [net_processing.cpp l.1856-1871](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| On `version`, a peer is disconnected if the connection type expects services and the peer lacks the desirable flags. Types that expect them: full-relay, block-relay, addr-fetch, private-broadcast. Not: inbound, manual, feeler | [net_processing.cpp l.3865](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp), [net.h l.852-863](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.h) | [V] |
| Address selection is not biased by service bits today. The connection loop calls `Select()` up to 100 times and skips candidates without the flags | [net.cpp l.2882-2955](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| `protocol.h` reserves bits 24 to 31 for temporary experiments, and warns service bits are "just unauthenticated advertisements" | [protocol.h l.343-349](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/protocol.h) | [V] |

### Outbound slots, anchors, feelers, diversity today

| Claim | Source | Mark |
|---|---|---|
| `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8`, `MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2`, `MAX_FEELER_CONNECTIONS = 1`, `MAX_ADDNODE_CONNECTIONS = 8` (separate budget), `DEFAULT_MAX_PEER_CONNECTIONS = 200` | [net.h l.70-82](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.h) | [V] |
| `FEELER_INTERVAL = 2min`; `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min`; drawn as exponential delays | [net.h l.62-64](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.h) | [V] |
| Connection priority each loop: anchor, full-relay to 8, block-relay to 2, extra full-relay on stale tip, extra block-relay on timer, feeler, network-specific extra | [net.cpp l.2795-2862](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| Stale tip: no tip update for 3 block intervals, checked every 10 min (`STALE_CHECK_INTERVAL`), then one extra outbound peer is tried | [net_processing.cpp l.112, 1429-1436](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| Every 45 s, the extra full-relay peer that least recently announced a block is dropped; up to 4 are protected | [net_processing.cpp l.108-116, 5607-5660](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| Anchors: `anchors.dat`, `MAX_BLOCK_RELAY_ONLY_ANCHORS = 2`; block-relay-only peers saved on clean shutdown and reconnected first | [net.cpp l.60-63](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| Each outbound IPv4/IPv6 connection (not feelers) must be in a distinct netgroup. Tor, I2P and CJDNS are exempt | [net.cpp l.2743-2780, 2930](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| A netgroup is /16 for IPv4 and /32 for most IPv6, or the AS number when an ASMap is loaded | [netgroup.cpp l.28-75](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/netgroup.cpp) | [V] |
| Inbound eviction protects, in order: 4 by netgroup, 8 by lowest ping, 4 by recent novel transactions, up to 8 block-relay peers with novel blocks, 4 by recent novel blocks, then half the rest by uptime; up to 25% reserved for rare networks. The victim is the youngest in the most-connected netgroup | [eviction.cpp l.97-231](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/eviction.cpp) | [V] |
| Address manager: 1,024 new buckets, 256 tried, 64 entries each. The new bucket depends on the *source's* group: one source group reaches at most 64 buckets | [addrman_impl.h l.26-33](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/addrman_impl.h), [addrman.cpp l.28-41](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/addrman.cpp) | [V] |
| Test-before-evict: a feeler probes the incumbent of a tried slot; it stays if it connected within 4 h | [addrman.h l.40-44](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/addrman.h) | [V] |
| PR 27213 (2023) opens one extra outbound to any reachable network with no connection yet, on a 5-minute timer, and protects the only peer on each network from eviction | [PR 27213](https://github.com/bitcoin/bitcoin/pull/27213), [net.cpp l.2594-2610](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| Transaction announcements are trickled on Poisson timers: 5 s average to inbound, 2 s to outbound | [net_processing.cpp l.173-177](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |

### Full-RBF: a minority overlay inside Bitcoin

| Claim | Source | Mark |
|---|---|---|
| PR 25600 was by ariard (not Peter Todd). It added `NODE_FULL_RBF = (1 << 26)` and `MAX_FULLRBF_RELAY_CONNECTIONS = 4` extra outbound slots, active with `-mempoolfullrbf` | [PR 25600](https://github.com/bitcoin/bitcoin/pull/25600) | [V] |
| The 4 slots were on top of the normal ones; candidates without bit 26 were skipped; a peer lacking it at `version` was disconnected | [PR 25600 diff](https://github.com/bitcoin/bitcoin/pull/25600/files) | [V] |
| Peter Todd's test: his nodes did not "reliably connect to more than one full-rbf node"; raising the slot's priority fixed it | [PR 25600](https://github.com/bitcoin/bitcoin/pull/25600) | [V] |
| Objections: privacy, and a NACK that it "increases opportunity for attackers". Others preferred turning full-RBF on by default | [PR 25600](https://github.com/bitcoin/bitcoin/pull/25600) | [V] |
| mzumsande simulated that with about 10% of nodes supporting full-RBF, a supporting path exists over 90% of the time even without preferential peering | [PR 25600 review](https://github.com/bitcoin/bitcoin/pull/25600) | [V] |
| Closed unmerged on 2022-11-08 ("high-level conceptual and procedural issues") | [PR 25600](https://github.com/bitcoin/bitcoin/pull/25600) | [V] |
| Core later made full-RBF the default | [Bitcoin Core release notes](https://github.com/bitcoin/bitcoin/tree/master/doc/release-notes) | [R] |
| Peter Todd's branches `full-rbf-v24.0` to `v27.0` carry the same 4 extra slots | [full-rbf-v24.0 net.h l.67-68](https://raw.githubusercontent.com/petertodd/bitcoin/full-rbf-v24.0/src/net.h) | [V] |
| His older `replace-by-fee-v0.12` used 8 normal plus 8 RBF outbound slots (16 total) | [replace-by-fee-v0.12 net.cpp l.62-80](https://raw.githubusercontent.com/petertodd/bitcoin/replace-by-fee-v0.12/src/net.cpp) | [V] |
| Bitcoin Knots advertises bit 26 when full-RBF is on (0.21 to 28.x) but no outbound preference for it was found (three files grepped) | [Knots 25.x init.cpp l.1616-1618](https://raw.githubusercontent.com/bitcoinknots/bitcoin/25.x-knots/src/init.cpp) | [V] |

### Address formats and seeds

| Claim | Source | Mark |
|---|---|---|
| BIP 155 `addrv2`: network id plus variable address up to 512 bytes (IPv4 4, IPv6 16, Tor v3 32, I2P 32, CJDNS 16); services become CompactSize; negotiated with `sendaddrv2` | [BIP 155](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0155.mediawiki) | [V] |
| BIP 159: bit 10 means at least the last 288 blocks are served; nodes out of initial sync "should consider connecting some" pruned peers | [BIP 159](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0159.mediawiki) | [V] |
| Core asks seeds for `x9.<seed>` (NETWORK and WITNESS), at most 32 addresses per seed | [net.cpp l.2411-2443](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.cpp) | [V] |
| `bitcoin-seeder` reads `x<hex>.` as a flag mask and answers only whitelisted masks, returning nodes with `(services & flags) == flags`. A new bit needs each seed operator to whitelist it | [bitcoin-seeder main.cpp l.280-294](https://raw.githubusercontent.com/sipa/bitcoin-seeder/master/main.cpp) | [V] |
| Lightning's DNS seeds (BOLT 10) support only conditions `r` (realm), `a` (address types), `l` (node id) and `n` (count): **no feature-bit filter** | [BOLT 10](https://raw.githubusercontent.com/lightning/bolts/master/10-dns-bootstrap.md) | [V] |

**Lessons from Bitcoin.**

1. Preferred slots work when they are *added* to normal ones and *high in priority*. Four low-priority slots found only one full-RBF peer.
2. Check the bit when the peer answers, not only in the advertisement. Bitcoin disconnects at `version`.
3. Make preference cover enough slots, with a fallback after many tries, so a sparse population still connects.
4. Gmaxwell's warning applies: a sudden switch in topology risks partition. Gazpacho's overlay is new, so it grows gradually by construction.

## A2. Ethereum consensus layer and gossipsub

### ENR records and finding peers on a subnet

| Claim | Source | Mark |
|---|---|---|
| An ENR is `[signature, seq, k, v, …]`; the signature covers the rest; keys sorted and unique | [enr.md](https://raw.githubusercontent.com/ethereum/devp2p/master/enr.md) | [V] |
| Maximum 300 bytes, because records "are relayed frequently"; EIP-778 is Final with the same limit | [enr.md](https://raw.githubusercontent.com/ethereum/devp2p/master/enr.md), [EIP-778](https://raw.githubusercontent.com/ethereum/EIPs/master/EIPS/eip-778.md) | [V] |
| `seq` is a 64-bit number nodes increase on every change, then republish | [enr.md](https://raw.githubusercontent.com/ethereum/devp2p/master/enr.md) | [V] |
| Unknown keys are accepted without implementation consensus | [enr.md](https://raw.githubusercontent.com/ethereum/devp2p/master/enr.md) | [V] |
| ENR `attnets` is a 64-bit bitvector of attestation subnets; Altair adds `syncnets` | [phase0 p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/p2p-interface.md), [altair p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/altair/p2p-interface.md) | [V] |
| With too few peers on a subnet, a node searches discovery for peers with the subnet's bit set, then confirms with the `GetMetaData` call | [phase0 validator.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/validator.md) | [V] |
| The spec calls ENR-based subnet discovery a stopgap: "ENRs should ultimately not be used for this purpose" | [phase0 p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/p2p-interface.md) | [V] |
| discv5 topic advertisement was described for years without deployment; a full "TopDisc" spec was merged only in June 2026 (devp2p PR 270) | [discv5-theory.md](https://raw.githubusercontent.com/ethereum/devp2p/master/discv5/discv5-theory.md) | [V] |
| No consensus client runs discv5 topic advertisement in production | none read | [R] |
| Lighthouse finds subnet peers by a random walk with a filter on ENR fields (`find_node_predicate`); at most 4 concurrent subnet queries | [Lighthouse discovery/mod.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/discovery/mod.rs), [subnet_predicate.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/discovery/subnet_predicate.rs) | [V] |
| Deterministic long-lived subnets: each node joins `SUBNETS_PER_NODE = 2` subnets derived from its node id, rotating every 256 epochs, staggered per node | [phase0 p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/p2p-interface.md) | [V] |
| Why (PR 3312, 2023): there was "no way to enforce" honest subscriptions; deriving them from the node id makes them checkable. Grinding node ids to capture a subnet was judged "not a new vector" | [consensus-specs PR 3312](https://github.com/ethereum/consensus-specs/pull/3312) | [V] |
| PeerDAS: ENR `cgc` (custody group count); groups derive from the node id, so "a node knows exactly what a peer should" serve, and may downscore it | [fulu das-core.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/fulu/das-core.md), [fulu p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/fulu/p2p-interface.md) | [V] |

### Peer managers

| Claim | Source | Mark |
|---|---|---|
| Lighthouse targets 200 peers; 30% outbound target, discovery restarts below 20% outbound | [Lighthouse peer_manager/mod.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/peer_manager/mod.rs) | [V] |
| Lighthouse prunes in order: negative score; peers on no long-lived subnet; peers on the densest subnet (never below 2 per needed subnet); then at random | [Lighthouse peer_manager/mod.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/peer_manager/mod.rs) | [V] |

### gossipsub

| Claim | Source | Mark |
|---|---|---|
| v1.0 defaults: `D = 6`, `D_low = 4`, `D_high = 12`, heartbeat 1 s, `mcache_len = 5`, `mcache_gossip = 3`, `seen_ttl = 2 min` | [gossipsub-v1.0.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.0.md) | [V] |
| Each heartbeat: graft up to `D` below `D_low`; prune to `D` at random above `D_high` | [gossipsub-v1.0.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.0.md) | [V] |
| IHAVE lists recent message ids to non-mesh peers, who ask with IWANT | [gossipsub-v1.0.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.0.md) | [V] |
| gossipsub assumes "ambient peer discovery" and specifies none | [gossipsub-v1.0.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.0.md) | [V] |
| v1.1 `D_out`: below `D_low` and at most `D/2`. A node keeps at least `D_out` outbound mesh peers; at `D_high` it accepts grafts only from outbound peers, so an inbound attack "can never fully take over" | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Flood publishing: a node sends its *own* messages to all peers above a score threshold, "to counter eclipse attacks" | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Adaptive gossip to `GossipFactor = 0.25` of eligible peers | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Peer exchange: a PRUNE may carry signed peer records; both sides back off (1 minute recommended) | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| PX is accepted only above `AcceptPXThreshold`, ideally reachable only by bootstrappers | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| `D_score`: when pruning keep the best-scoring 4 or 5 (for D = 6), the rest random, subject to `D_out` | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Opportunistic grafting: about once a minute, if the median mesh score is low, graft 2 peers above the median | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Score terms: P1 time in mesh, P2 first deliveries, P3 mesh delivery deficit (squared), P3b sticky failure, P4 invalid messages (squared), P5 application, P6 IP colocation (squared), P7 behaviour penalty (squared). Local only, never shared | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Validators return Accept, Reject (penalised) or Ignore (not penalised) | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| Bootstrapping without discovery: bootstrappers run with `D = 0` and PX on | [gossipsub-v1.1.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.1.md) | [V] |
| v1.2 `IDONTWANT` targets large messages and "may have negative effect on small messages" | [gossipsub-v1.2.md](https://raw.githubusercontent.com/libp2p/specs/master/pubsub/gossipsub/gossipsub-v1.2.md) | [V] |
| Ethereum's values: `D = 8`, `D_low = 6`, `D_high = 12`, `D_lazy = 6`, heartbeat 0.7 s, `mcache_len = 6`; scoring parameters still "under investigation" in the spec | [phase0 p2p-interface.md](https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/p2p-interface.md) | [V] |
| Lighthouse defaults: mesh 5 (low 3, high 10), outbound minimum 2, flood publishing off; thresholds gossip −4000, publish −8000, graylist −16000, accept PX 100; at most 8 nodes per IP before the colocation penalty | [Lighthouse config.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/config.rs), [gossipsub_scoring_parameters.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/lighthouse_network/src/service/gossipsub_scoring_parameters.rs) | [V] |
| rust-libp2p defaults: mesh 6, low 5, high 12, outbound minimum 2, PX off, back-off 60 s | [rust-libp2p config.rs](https://raw.githubusercontent.com/libp2p/rust-libp2p/master/protocols/gossipsub/src/config.rs) | [V] |

### The gossipsub v1.1 security evaluation

| Claim | Source | Mark |
|---|---|---|
| Vyzovitis, Napora, McCormick, Dias, Psaras, July 2020; over 5,000 VM nodes | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Attacks defined: Sybil, eclipse, censorship, cold boot, flash, covert flash; results shown for eclipse, cold boot and covert flash | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Setup: 1,000 honest nodes against 4,000 Sybils, Sybils opening 100 connections each against honest nodes' 20 | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Warm-network eclipse: latency unchanged from baseline; Sybils held only 2 to 4 mesh slots; plain gossipsub lost about 10% of messages | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Cold boot: 100% delivery, mesh recovered "within 90 heartbeats" | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Mapping: `D_out` against Sybil, flash and eclipse; opportunistic grafting against a poisoned mesh; flood publishing against eclipse; back-off against GRAFT spam | [arXiv 2007.02754](https://arxiv.org/abs/2007.02754) | [V] |
| Least Authority audited v1.1; the blog post is dated 2020-07-07; the audit PDF on IPFS could not be fetched | [IPFS blog](https://blog.ipfs.tech/gossipsubv1.1-eval-report-and-security-audit/) | [V] (blog only) |
| The audit found scoring creates centralisation pressure and can be gamed into a victim's peer list | leastauthority.com (search snippet only) | [R] |

### discv5 eclipse defences

| Claim | Source | Mark |
|---|---|---|
| k = 16 buckets; disjoint-path lookups recommended; unverified nodes never relayed | [discv5-theory.md](https://raw.githubusercontent.com/ethereum/devp2p/master/discv5/discv5-theory.md) | [V] |
| About 2 nodes per /24 per bucket and 10 per /24 per table; do not admit incoming contacts "unless the table is well-stocked from outbound queries"; favour long-lived nodes | [discv5-rationale.md](https://raw.githubusercontent.com/ethereum/devp2p/master/discv5/discv5-rationale.md) | [V] |
| sigp/discv5 enforces 10 per /24 per table and 2 per bucket | [filter.rs](https://raw.githubusercontent.com/sigp/discv5/master/src/kbucket/filter.rs) | [V] |
| The rationale notes that Sybils are serious for small topics | [discv5-rationale.md](https://raw.githubusercontent.com/ethereum/devp2p/master/discv5/discv5-rationale.md) | [V] |

**Lessons from Ethereum.**

1. **Ethereum lacks what Lightning has.** discv5 has no Sybil cost and no complete member list, so it needs random walks, IP limits, scoring and peer exchange. Lightning gossip gives every node the full list of F nodes, each anchored by a funded channel. Gazpacho can pick peers *from the list* and skip peer exchange.
2. **`D_out` is the single most effective rule** against inbound Sybil floods, by the paper's own account.
3. **Flood publishing by the source** makes eclipse of a source pointless: a host sends its own beacon to every overlay link.
4. **Lazy gossip (IHAVE/IWANT) and IDONTWANT** exist for high-rate, large-message topics. Beacons are rare and small.
5. **Self-declared roles can be made checkable.** Ethereum moved to deterministic subnets for this reason. For Gazpacho, host status is checkable: a node that sends beacons must answer `lobby_index` and `listing_request` for them (DR B8 D1). Store nodes can be checked by asking for a listing the asker already holds.

## A3. Other overlays, reconciliation and Lightning precedent

### Lightning: peers without channels, gossip sync, onion messages

| Claim | Source | Mark |
|---|---|---|
| LDK rejects new inbound connections once 2,500 peers have no funded channel (`MAX_NO_CHANNEL_PEERS`); 50 peers with only unfunded channels | [LDK channelmanager.rs l.3476-3493](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/ln/channelmanager.rs) | [V] |
| Eclair: `max-no-channels = 64` incoming connections from peers without channels | [Eclair reference.conf l.451](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/resources/reference.conf) | [V] |
| LND: `num-restricted-slots=100` caps incoming connections; outbound is not restricted | [sample-lnd.conf l.586-591](https://raw.githubusercontent.com/lightningnetwork/lnd/master/sample-lnd.conf) | [V] |
| That LND's restricted slots apply to peers without channels | DR A6 | [R] |
| LDK requests a full gossip sync from only the first 5 peers (`FULL_SYNCS_TO_REQUEST = 5`), then receives new gossip from all | [LDK gossip.rs l.369-372, 795](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/routing/gossip.rs) | [V] |
| LND: `numgraphsyncpeers=3` active gossip syncers; `historicalsyncinterval=1h`; pinned syncers do not count and are not rotated | [sample-lnd.conf l.449, 566, 1984-2002](https://raw.githubusercontent.com/lightningnetwork/lnd/master/sample-lnd.conf) | [V] |
| Eclair onion messages: at most 10 per peer per second; reply timeout 15 s; up to 3 attempts; at least 6 hops before itself in reply paths it builds; transient connections opened to relay are closed after 30 s idle | [Eclair reference.conf l.681-692](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/resources/reference.conf) | [V] |
| BOLT 4: a node SHOULD accept onion messages from peers without a channel and MAY rate-limit by dropping | [B4 l.1803-1804](https://raw.githubusercontent.com/lightning/bolts/master/04-onion-routing.md) | [V] |
| BOLT 7: a node relays others' gossip only after the peer sends `gossip_timestamp_filter` | DR A6 | [V] |

(Further Lightning, BitTorrent, IPFS and Erlay claims: section A3b below.)

### Light clients, set reconciliation, Nostr

| Claim | Source | Mark |
|---|---|---|
| BIP 157: a client SHOULD connect to multiple outbound peers per filter type; the protocol guarantees correctness "with at least one honest peer" | [BIP 157](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0157.mediawiki) | [V] |
| BIP 157's motivation: BIP 37 Bloom filters gave "zero privacy" and a DoS vector; downloading from any source improves privacy | [BIP 157](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0157.mediawiki) | [V] |
| NIP-77 (draft): Negentropy range-based set reconciliation for client-relay and relay-relay sync | [NIP-77](https://raw.githubusercontent.com/nostr-protocol/nips/master/77.md) | [V] |
| NIP-65: users list 2 to 4 read and write relays; clients fetch an author's events from their write relays | [NIP-65](https://raw.githubusercontent.com/nostr-protocol/nips/master/65.md) | [V] |
| Measured Nostr (Oct to Dec 2023): 911 relays seen, 712 with data; the largest relay held 73% of posts; average replication 34.6 relays per post | [Wei and Tyson, arXiv 2402.05709](https://arxiv.org/html/2402.05709v2) | [V] |
| Same study: about 50% of relays up over 99% of the time; about 20% down over 40%; 132 dead relays | [arXiv 2402.05709](https://arxiv.org/html/2402.05709v2) | [V] |
| Same study: 95% of free relays estimated unable to cover costs from donations; 98.2% of download traffic redundant | [arXiv 2402.05709](https://arxiv.org/html/2402.05709v2) | [V] |
| Random k-out graphs on n nodes are k-connected with high probability for k ≥ 2 (Fenner and Frieze) | [arXiv 1405.2129](https://arxiv.org/abs/1405.2129) (search summary of its citation; abstract read, does not state it) | [R] |
| Mainnet Lightning (June 2024 snapshot): 12,878 nodes, 8,905 Tor-only | [mempool.space API](https://mempool.space/api/v1/lightning/statistics/latest) | [V] (old snapshot) |
| Signet Lightning (March 2025 snapshot): 75 nodes, 864 channels | [mempool.space signet API](https://mempool.space/signet/api/v1/lightning/statistics/latest) | [V] (old snapshot) |

## A3b. Further overlay precedents

### BitTorrent and IPFS

| Claim | Source | Mark |
|---|---|---|
| Mainline DHT: buckets of K = 8; a node is "good" if it answered within 15 min | [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) | [V] |
| `announce_peer` needs a token from `get_peers`, tied to the asker's IP (SHA1 of IP and a secret rotated every 5 min), to stop "signing up other hosts" | [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) | [V] |
| Peer exchange: at most 1 message a minute; at most 50 added and 50 dropped contacts per message; a peer is listed only once connected | [BEP 11](https://www.bittorrent.org/beps/bep_0011.html) | [V] |
| BEP 42 ties the first 21 bits of a node id to its IP, because otherwise about 8 IPs near a target id suffice to attack it | [BEP 42](https://www.bittorrent.org/beps/bep_0042.html) | [V] |
| Sybil attacks on Mainline DHT were measured around 2012 (Wang and Kangasharju) | not fetched | [R] |
| IPFS Amino DHT: k = 20, alpha = 10; provider records valid 48 h, republished every 22 h | [amino/defaults.go](https://raw.githubusercontent.com/libp2p/go-libp2p-kad-dht/master/amino/defaults.go) | [V] |
| IPFS diversity filter: at most 3 peers per IP group per routing table and 2 per bucket; IPv4 groups by /16, IPv6 by AS number (else /32) | [amino/defaults.go](https://raw.githubusercontent.com/libp2p/go-libp2p-kad-dht/master/amino/defaults.go), [peerdiversity/filter.go](https://raw.githubusercontent.com/libp2p/go-libp2p-kbucket/master/peerdiversity/filter.go) | [V] |
| IPFS nodes could be eclipsed "with moderate effort" (CVE-2020-10937); a 2025 Sybil attack still denies content in about 80% of lookups | [arXiv 2011.00874](https://arxiv.org/abs/2011.00874), [arXiv 2505.01139](https://arxiv.org/abs/2505.01139) | [V] |

### Erlay, minisketch, Dandelion

| Claim | Source | Mark |
|---|---|---|
| BIP 330 (Draft): `sendtxrcncl` before `verack`; short ids by salted SipHash; PinSketch over GF(2^32); one extension, then fall back to sending everything | [BIP 330](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0330.mediawiki) | [V] |
| Erlay floods to at most 8 outbound links and never to inbound links, against timing attacks; reconciles with one peer every second | [Erlay paper](https://arxiv.org/pdf/1905.10518) | [V] |
| In Core, minisketch and the BIP 330 signalling are merged, but Erlay is a debug-only option; several implementation PRs closed unmerged. A 2026 draft (#35591) adds 4 reconciliation-only links on top of the 8 | [net_processing.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp), [PR 35591](https://github.com/bitcoin/bitcoin/pull/35591) | [V] |
| minisketch always decodes when the difference is at most the capacity; decoding is quadratic | [minisketch README](https://raw.githubusercontent.com/sipa/minisketch/master/README.md) | [V] |
| BIP 156 (Dandelion) is Closed; Core PR 13947 closed in 2019: supporting RBF and CPFP "while not opening DOS vectors" was "non-trivial" | [BIP 156](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0156.mediawiki), [PR 13947](https://github.com/bitcoin/bitcoin/pull/13947) | [V] |

### More Lightning

| Claim | Source | Mark |
|---|---|---|
| LND rotates one active gossip syncer every 20 min (`DefaultSyncerRotationInterval`), picks syncers at random, and has active, passive and pinned syncers | [sync_manager.go](https://raw.githubusercontent.com/lightningnetwork/lnd/master/discovery/sync_manager.go), [syncer.go](https://raw.githubusercontent.com/lightningnetwork/lnd/master/discovery/syncer.go) | [V] |
| LND gossip limits: 1,000 KiB/s overall, 50 KiB/s per peer | [sync_manager.go](https://raw.githubusercontent.com/lightningnetwork/lnd/master/discovery/sync_manager.go) | [V] |
| LND's graph bootstrapper samples peers from the graph at random, not by feature bit | [bootstrapper.go](https://raw.githubusercontent.com/lightningnetwork/lnd/master/discovery/bootstrapper.go) | [V] |
| CLN keeps 10 gossip slots (`SEEKER_GOSSIPERS`), fills empty ones at random, and ejects the worst gossiper about every 30 min | [seeker.c](https://raw.githubusercontent.com/ElementsProject/lightning/master/gossipd/seeker.c) | [V] |
| Eclair syncs gossip from 5 peers, chosen by largest channel capacity with us | [Eclair reference.conf](https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/src/main/resources/reference.conf) | [V] |
| LDK picks blinded-path introduction nodes from connected peers with onion messages, non-Tor first, then most channels; at most 3 paths | [LDK messenger.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/onion_message/messenger.rs) | [V] |
| LDK's default router builds no multi-hop path: if the target is not a peer it asks the app to connect directly (`Event::ConnectionNeeded`) | [LDK messenger.rs](https://raw.githubusercontent.com/lightningdevkit/rust-lightning/main/lightning/src/onion_message/messenger.rs) | [V] |
| CLN routes onion messages only through nodes with the onion bit, else connects directly | [establish_onion_path.c](https://raw.githubusercontent.com/ElementsProject/lightning/master/plugins/establish_onion_path.c) | [V] |
| Trampoline (bits 56/57, bolts PR 836) is still open; Electrum hard-codes three trampolines | [bolts PR 836](https://github.com/lightning/bolts/pull/836), [electrum trampoline.py](https://raw.githubusercontent.com/spesmilo/electrum/master/electrum/trampoline.py) | [V] |
| bLIP-32 resolvers set bit 258/259 in `node_announcement`; payers find them "searching the lightning gossip network" and query by onion message: the closest Lightning precedent for "find by bit, ask by onion" | [bLIP-32](https://raw.githubusercontent.com/lightning/blips/master/blip-0032.md) | [V] |
| Libre Relay (Peter Todd's Core fork): `NODE_LIBRE_RELAY = (1 << 29)` and 4 extra outbound slots that accept only flagged addresses, on top of 8 + 2 | [libre-relay-v31.2 net.h](https://raw.githubusercontent.com/petertodd/bitcoin/libre-relay-v31.2/src/net.h), [net.cpp](https://raw.githubusercontent.com/petertodd/bitcoin/libre-relay-v31.2/src/net.cpp) | [V] |
| Gossip reconciliation (Delving 2105): gmaxwell says flooding "takes the bulk of the load off the sketch"; the draft has creators flood their own messages | [Delving 2105](https://delvingbitcoin.org/raw/2105), [jharveyb draft](https://raw.githubusercontent.com/jharveyb/bolts/dd9f97a87518d62b82460b2b6e4e274663ec126a/bolt-gossip-minisketch.md) | [V] |
| Equivocation: ids that do not commit to content let an attacker keep stable partitions holding different versions | [Delving 2105 #25](https://delvingbitcoin.org/raw/2105) | [V] |
| May 2026 summit feedback: peers must not be able to force heavy CPU work; about 100 ms worst-case decode on a Raspberry Pi 5 | [Delving 2105 #24](https://delvingbitcoin.org/raw/2105) | [V] |

---

# Part B. The design: preferential peering for the beacon overlay

## B0. The idea in one paragraph

**Choose your overlay peers yourself, from the Lightning gossip graph, under Bitcoin-style slot and diversity rules, and keep them with gossipsub-style scoring.** Lightning already gives every full node what discv5 and gossipsub lack: a complete list of factory-capable nodes in which each entry cost a funded, announced channel. So there is no need for random walks, peer exchange or topic registration, which are where those systems' Sybil problems live. The overlay is small and slow: a few 153-byte beacons per host per day. So beacons are pushed whole, and the heavy machinery (lazy gossip, sketches) is unnecessary until there are thousands of hosts.

## B1. Who may be a peer

- **E1.** A node is *eligible* if it is in the local gossip graph, carries the F bit, has an address this node can reach, and its oldest announced channel is at least **1,008 blocks** old.
- **E2.** While fewer than **16** nodes meet E1, the age floor drops to **144 blocks**. While fewer than 8 meet it, it drops to 0.
- **E3.** A node is a *host*, for the mix rule, if it is the signer of at least one live beacon this node holds or has seen in the last 1,008 blocks. There is no separate hosting bit (ledger A1).
- **E4.** Eligibility is checked again when the link opens. The peer must complete the factory handshake, with its lobby store flag, within 30 s, as Bitcoin checks bits at `version` (A1). A peer whose current announcement has lost F is dropped.
- **E5.** Never take candidates from peers. No peer exchange. Gossip is the only source, plus an optional built-in seed list used only until gossip is synced.

## B2. How to pick

- **P1.** Group eligible nodes by *address group*: IPv4 /16; IPv6 /32; the AS number when an AS map is loaded (Bitcoin's `netgroup.cpp`, A1); Tor v3 by Bitcoin Core's grouping of onion addresses. A node with several addresses takes the group of the one used.
- **P2.** To pick an outbound peer: choose a group uniformly at random among groups with an eligible node not yet linked; then a node uniformly in it. Sybils packed into one range get one ticket per draw, as Bitcoin's address buckets give one source group at most 64 of 1,024 buckets.
- **P3.** Prefer a node with which this node already has a channel, for at most 2 slots. That connection exists anyway and the peer has funds at stake with this node.
- **P4.** Do not weight by channel capacity. Capacity weighting makes large hosts the centre of the overlay. The age floor and channel requirement already price an identity.

## B3. Slots

| Name | Value | From |
|---|---|---|
| `D` target links | **6** | gossipsub v1.0 default 6; Lighthouse 5 |
| `D_lo` / `D_hi` | **4 / 8** | Owner's 4 to 8; gossipsub 4 / 12 |
| `D_out` minimum opened by this node | **3** | gossipsub: `D_out` < `D_lo` and ≤ `D/2` |
| Anchors kept across restarts | **2** outbound links | Bitcoin `MAX_BLOCK_RELAY_ONLY_ANCHORS = 2` |
| Scout | **1** short link, every **60 min** (exponential delay) and on waking | Bitcoin feeler (2 min) and extra block-relay link (5 min), scaled to beacon rate |
| Overlay links are **in addition** to channel peers | — | PR 25600 and Peter Todd's forks added slots, not replaced them |

- **S1.** Inbound links count toward `D_hi`. At `D_hi`, accept a new inbound link only if it fills a missing mix requirement; otherwise answer with `beacon_filter` "nothing" and close (gossipsub accepts only outbound grafts when full).
- **S2.** The overlay never needs more than 8 channel-less connections per node, well under LDK's 2,500, Eclair's 64 and LND's 100 limits (A3).

## B4. The mix rule

Applied to the set of overlay links, with `D` = 6:

- **M1.** At least **half** are non-hosting F nodes (F without H).
- **M2.** At most **2** are hosts.
- **M3.** At least **1** outbound link (2 when available) is to a *store* node, learned from the lobby store flag in the factory handshake, not from a gossip bit.
- **M4.** When fewer non-hosting candidates exist than M1 needs, fill with hosts, but each host link must be in a distinct address group, and scouts run every **20 min** instead of 60. The mix rule is a target that degrades, not a hard stop (B9).

Why: beacons originate at hosts, and a host has a motive to drop a rival's beacon. Neutral relays dilute that motive. Two host links per node are enough for propagation, because each host flood-publishes its own beacons to all of its own links (gossipsub's flood publishing, A2).

## B5. Diversity

- **V1.** Outbound links: one per address group (Bitcoin, A1).
- **V2.** All links: at most **2** per address group (discv5's 2 per /24 per bucket, A2).
- **V3.** At most 1 link to nodes that share an operator, when an operator is known (a built-in list, or identical `alias`/address patterns). Advisory only.

## B6. Scoring and eviction

Local, never shared (gossipsub, A2). Computed per link over a sliding window of 7 days.

| Term | Sign | Rule |
|---|---|---|
| First delivery | + | +1 for each valid beacon this link delivered first; capped at +20; decays 1% per hour |
| Missed delivery | − | −1 for each beacon a scout or another link delivered that this link (a storing or relaying peer since before the beacon's open height) never sent within 10 min. Counted only after 20 beacons in the window, to avoid noise |
| Invalid | − (squared) | Bad signature, deadline past, open height over 6 blocks ahead, or beyond 1,008 blocks of life. A bad signature drops the link at once with a **24 h** back-off |
| Over cap | − | A 5th live beacon for a host is not penalised once (relays may lag), but repeated ones are |
| Behaviour | − (squared) | Rate breaches (R2), reconnecting during back-off, filter churn |

- **K1.** Below zero: drop the link (send `beacon_filter` "nothing").
- **K2.** When over `D_hi`: never break `D_out`, the mix rule or anchors; keep the **4** best scores (`D_score`); drop at random among the rest.
- **K3.** Protect, as Bitcoin's inbound eviction does: the 2 anchors, and the link with the most first deliveries.

## B7. Rotation and scouts

- **T1.** Once every **24 h**, at a random time, replace one outbound link that is not an anchor and not protected (K3). This matches the daily lobby rhythm (DR A5) and slowly heals a quiet eclipse without inviting a fast one.
- **T2.** Scout: every **60 min** (exponential) and on waking from sleep or a restart, open a short link to an eligible node drawn as in P2, from groups not already linked. Run catch-up (B8) with it, then close.
  - Beacons the scout has that the overlay did not deliver count against the links that should have had them (B6).
  - If the scout delivered at least one new beacon, it replaces the worst-scoring non-anchor outbound link.
- **T3.** Anchors: on clean shutdown, save the 2 best outbound links; reconnect them first (Bitcoin `anchors.dat`).

## B8. Relay and catch-up

### Live relay: eager push

- **L1.** A host sends each new beacon to **all** its overlay links (flood publishing).
- **L2.** A node that accepts a beacon forwards it **immediately** (ledger A6) to every overlay link except the one it came from and any link already known to have it. No batching is needed at this volume.
- **L3.** Deduplicate by `beacon_id` with the seen-set already sized in `spec-vectors.py`, plus a per-link "known" set (Bitcoin's `m_tx_inventory_known_filter`, Part F).
- **L3b.** A beacon whose host is not (yet) in the receiver's graph, or lacks F there, is not penalised: it is held as an orphan (Part F, rule F6).
- **L4.** No IHAVE/IWANT on the live path. At 1,000 hosts, sending 32-byte ids instead of 193-byte beacons would save about 1.4 MB a day per node and cost a round trip per beacon. gossipsub's lazy gossip is built for busy topics; v1.2 itself says IDONTWANT may hurt small messages (A2).
- **L5.** Origin privacy needs no Poisson trickle: the host signs the beacon publicly. The random delay belongs to *fetching listings* (ledger A5), where it spreads load on the host.

### Catch-up after being offline

- **C1.** Stage 1 (now): the **pool request** (ledger A3): the peer sends every live beacon it holds that matches the request's filter, as `gossip_timestamp_filter` and Bitcoin's `mempool` message do (DR A6, Part F). Once per connection and at most once an hour. Size: about 2 live beacons per host × 193 bytes; at 100 hosts about 40 KB.
- **C2.** Stage 2 (above about **500** hosts; **reserved**, Part F): a `beacon_summary` lists, for each host, the first 8 bytes of its key, the highest sequence number held, and the first 4 bytes of that beacon's id: 16 bytes per host. The 4 id bytes catch equivocation (two beacons with one sequence number), the Delving 2105 lesson. The peer replies with only newer or different beacons. Exact, because each host numbers its beacons; no sketches. At 1,000 hosts: 16 KB.
- **C3.** Catch up from **2** peers in different address groups, at least one storing.
- **C4.** Sketch reconciliation (Erlay's minisketch) or range reconciliation (Negentropy, NIP-77) only above about **10,000** hosts, when even a 12-byte-per-host summary passes 100 KB. Neither is needed for the foreseeable future.

### Rate limits

- **R1.** At most **4** live beacons per host (already fixed).
- **R2.** At most **8** new sequence numbers per host per **144** blocks; more are dropped and not relayed. This bounds "withdraw and re-issue" churn within the cap.
- **R3.** Per link: at most **1** beacon a second, bursts of **20**, plus one catch-up answer per filter or summary per **10 min**.

### Bandwidth

Assuming 1.5 new beacons per host a day, 6 links, 193 bytes on the wire:

| Hosts | Beacons a day | Received per node a day | Full catch-up | Summary catch-up |
|---|---|---|---|---|
| 10 | about 15 | about 17 KB | about 4 KB | — |
| 100 | about 150 | about 174 KB | about 40 KB | about 1.6 KB |
| 1,000 | about 1,500 | about 1.7 MB | about 390 KB | about 16 KB |

Store nodes also fetch one listing per beacon: at most 8,192 bytes each (DR B8 D3), typically about 1 KB. At 1,000 hosts that is about 1.5 MB a day, and a store of about 2,000 live listings, at most 16 MB.

For comparison, Lightning gossip is about 103 MB of unique data a day (DR A1).

## B9. Bootstrapping when factory nodes are few

| F nodes in gossip | Behaviour |
|---|---|
| Fewer than 8 | Link to all (a full mesh). Members mostly query each host directly (layer 2). The overlay costs nothing and exercises the code |
| 8 to 50 | Normal rules with the relaxed age floor (E2). M4 may apply. Scouts every 20 min while M4 applies |
| More than 50 | Full rules |

- Partitions heal by themselves: scouts and rotations draw from the whole gossip graph, not from overlay neighbours, so separate clusters keep meeting. A random graph in which each node opens 3 or more links to random others is connected with high probability (k-out graph results, A3, [R]).
- Gossip completeness is the real dependency. A node that has synced gossip from 3 to 5 peers (LND, LDK practice, A3) sees all F nodes. Before that, it uses the built-in seed list.
- Lightning DNS seeds cannot filter by feature bit (BOLT 10, A1). A seed extension (a feature condition) would need each seed operator to adopt it, as Bitcoin's `x` masks need whitelisting. Not needed: gossip is enough.
- **Early honest caveat.** At first almost every F node will be a host, run by Gazpacho or its early partners. The overlay then adds little over querying each host. That is fine; it exists so discovery keeps working when there are hundreds of hosts.

## B10. Light clients

A light client has no gossip graph, only a chain server.

1. **Choose sources.** 2 or more storing F nodes: from the built-in list, the current host, or an invitation. At least one should not be a host. (BIP 157: several sources; one honest is enough when data is verifiable.)
2. **Send the pool request** (ledger A3), by onion message or over a direct connection: an onion payload pair `pool_request` / `pool` (types **open**, bLIP range above 65,536; native kinds proposed). The request carries the filter fields (ledger A4) and a page cursor by host key, and later may carry the Stage 2 summary (C2). The client can then ask the same store node for listings it wants. The client sends through its own channel peer with a fresh blinded reply path (DR A8). The storing node learns that someone asked, not who.
3. **Verify each beacon:** signature; open and deadline heights against the chain server's tip; at most 4 live per host.
4. **Verify each new host,** using `host_list_request` (DR B8 D7) to the same node or another: the host's `node_announcement` with the F bit, and one of its `channel_announcement`s. Check the signatures, then the channel's output through the chain server (2 or 3 lookups, DR A7). Cache for 144 blocks.
5. **Merge** answers from all sources. A source can omit beacons but cannot forge them.
6. **Then** query the chosen host for the listing and terms (layer 2), and join directly.

Sizes: at 100 hosts the answer fits one 32,834-byte onion reply; at 1,000 hosts about ten, so the request pages by host key. Onion messages are unreliable: retry once by another first hop after 30 s (Eclair uses 15 s and 3 attempts, A3).

A brand-new client with no channel can connect directly (over Tor where possible) to a storing node that accepts peers without channels (CLN, Eclair, LDK do; LND gates onion messages from channel-less peers by default, DR A8), and send the same request over the native carrier.

## B11. Attacks and defences

| Attack | Defence in this design | Residual risk | Precedent |
|---|---|---|---|
| Sybil F nodes flood the overlay | Each identity needs an announced, funded channel at least a week old (E1). Group-first picking (P2). `D_out = 3` links chosen by this node. No peer exchange (E5). Inbound capped at `D_hi` with mix rules (S1) | A rich attacker with many channels across many ASes. Cost scales with channels × time × address groups | Bitcoin address buckets; gossipsub `D_out`; Lightning's own channel rule |
| Eclipse of a member (sees one host's lobbies only) | At most 2 hosts (M2); half neutral (M1); anchors (T3); daily rotation (T1); hourly scouts with set comparison (T2); hosts flood-publish their own beacons (L1) | A node whose gossip view is itself eclipsed. Mitigated by syncing gossip from several peers | Bitcoin anchors and feelers; gossipsub flood publishing and `D_out` |
| Beacon withholding by a relay or host | Missed-delivery score (B6); scouts; catch-up from 2 groups (C3); the host also answers layer-2 queries directly | A withholding peer that also controls the scout's target. Unlikely with random group picks | gossipsub P3; Bitcoin extra block-relay link |
| Beacon spam within caps | 4 live per host (R1); 8 new numbers per 144 blocks (R2); per-link rate (R3); only F nodes in gossip may originate | A host with many node identities. Each needs a channel. Local de-ranking of hosts whose lobbies never start (DR B12) | LND ban score; CLN 300 s spacing; gossip's channel rule |
| Partition, few F nodes | Full mesh below 8 (B9); scouts from the whole graph; fallback to layer-2 queries | None material | gossipsub bootstrappers; Bitcoin DNS seeds |
| Host tells different askers different lobbies | Beacons are public and numbered; a lobby that is in the index but not in beacons, or the reverse, is visible | None material | ENR `seq` |
| Privacy: who wants lobbies | Overlay members already show F. Browsing beacons touches no host. Light clients ask by onion message with blinded reply paths. A direct query without Tor reveals the address | A storing node sees how often someone asks; a host sees the final `listing_request` | BOLT 4 reply paths; BIP 157 vs BIP 37 |
| A storing node lies about storing | A client or peer can test it with a beacon it already holds; a node that claims to store but misses known beacons is scored down | — | PeerDAS custody checks |

## B12. Messages this adds or reuses

| Element | Status |
|---|---|
| `lobby_beacon`, native kind 141 | Fixed in the vectors |
| `beacon_filter`, native kind 143 | Fixed in the vectors; "nothing" turns relay off on a link (B6 of DR) |
| Lobby store flag | A record in the factory handshake (ledger A6); sent once, before any beacon |
| `pool_request` / `pool` | Normative now (ledger A3); onion payload types open; native kinds 145 / 147 proposed |
| `beacon_summary` | **Reserved**: native kind 149, no format yet (Part F) |
| Store-to-store sync | **Reserved**: native kind 151, no format yet (Part F) |
| `host_list_request` / `host_list` | Already in DR B8 D7 (native 137 / 139 in the vectors) |

---

# Part C. Six discovery designs compared

Ratings are judgements from the evidence above and in DR. The explainer shows the same table with colours.

| Criterion | A. Soup coordinator + Nostr | B. Nostr listings only | C. Bit + queries | D. Bit + queries + beacon overlay | E. Naive sub-gossip, no caps | F. Lobbies in ordinary gossip |
|---|---|---|---|---|---|---|
| Spam resistance | Good: coordinator checks and rate-limits | Mixed: anchors per coin; only wallets can check | Good: a host lists only itself, 4 at most | Good: F bit in gossip, 4 per host, churn limit | Poor: no caps | Mixed: gossip limits, but everyone pays |
| Censorship resistance | Poor: coordinator can refuse | Mixed: many relays; a few hold most data | Good: the host answers for itself | Good: many paths, mix rule, scouts; host queries still work | Mixed: no eclipse defence | Good: the whole network |
| Privacy of the browser | Good | Good | Mixed: each host sees a query (not who) | Good: browsing touches no host | Good | Good |
| Light clients | Good: any relay over a websocket | Good, plus chain lookups | Poor without a helper | Mixed: onion queries to 2+ storing nodes; fully verified | Mixed: unverified | Poor: Rapid Gossip Sync drops TLVs |
| Bandwidth | Low | Low to mixed (redundant downloads) | Grows with hosts × users | Low: about 1.7 MB a day per node at 1,000 hosts | Unbounded | High, on 6,000 nodes |
| Implementation work | Exists | Small | Small to medium (onion messages) | Medium to large | Medium | Very large, needs every implementation |
| Lightning-native | No | No | Yes | Yes | Yes | In form only; against gossip's norms |
| Outside dependence | Nostr and coordinator | Nostr | None | None (Nostr optional) | None | None |
| Bootstrapping | Easy | Easy | Easy | Degrades to C | As D | Unreachable without BOLT change |
| Hosts not in gossip | Yes (coin tier) | Yes (coin anchor) | By invitation | By invitation | Depends | No |
| **Verdict** | Retire the coordinator | Keep as annex | Core; ship first | **Target design** | Do not build | Do not propose |

**Why D over C.** C works for a handful of hosts. It does not tell anyone that a new lobby exists: each user must poll each host, and each host sees every poll. D adds one cheap push so users learn of lobbies without polling and without the host seeing who browses. It also makes a host's lobby set public and numbered, which C cannot.

**Why D over E.** E is D without caps, without the "host in gossip with the bit" rule and without peering rules. Every defence in B11 is missing.

**Why not F.** Gossip reaches 6,000 nodes that do not care, has no TLV room, and is invisible to light clients (DR B3). Liquidity ads spent five years trying (DR A2).

---

# Part D. Could Gazpacho drop Nostr?

## D1. What Nostr does that the overlay cannot

1. **Hosts outside gossip.** A host with only taproot or unannounced channels has no `node_announcement`, so it cannot originate beacons. Nostr with a coin anchor lists it (DR B5). Taproot gossip is still an open proposal (DR A1).
2. **Zero-state users.** A fresh phone with no channel can read Nostr over a websocket. The overlay needs a Lightning connection first, and LND drops onion messages from channel-less peers by default (DR A8).
3. **Independent failure.** If onion messages are rate-limited network-wide or the overlay is attacked, Nostr still works; and the reverse.
4. **Full listings.** Nostr can carry a whole listing; beacons are deliberately 153-byte pointers.
5. **Third-party storage.** Relays keep data while hosts and members are offline. The overlay stores only what opting-in nodes keep.

## D2. What the overlay does better

1. No outside operators. Measured Nostr: the largest relay held 73% of posts; about 20% of relays were down more than 40% of the time; most free relays cannot cover costs (A3).
2. The Sybil cost is a funded channel that every node checks, not a free key.
3. No coordinator, and nothing about Gazpacho users reaches a non-Lightning service.

## D3. Conditions under which the annex can be retired

All must hold for **six consecutive months**, measured by a monitor (a full overlay node plus a light-client probe):

| # | Condition | Threshold |
|---|---|---|
| N1 | Overlay size | ≥ 30 F nodes in gossip, from ≥ 10 operators, in ≥ 10 address groups |
| N2 | Store nodes | ≥ 5 answering pool and listing requests, from ≥ 3 operators, none over a third |
| N3 | Completeness | ≥ 99% of beacons seen by the full node reach the light-client probe within 10 min, over 30 days |
| N4 | Light-client path | ≥ 99% of onion queries from a phone through an ordinary LSP answered within 30 s with retries |
| N5 | Hosts outside gossip | Taproot gossip deployed in ≥ 2 implementations, or < 5% of hosts listed only on Nostr |
| N6 | New users | A fresh install finds lobbies with Nostr off: built-in storing nodes plus a direct (Tor) connection |
| N7 | Availability | ≥ 3 storing nodes up at every sample over 90 days |

## D4. Recommendation

**Keep Nostr, as an optional fallback, now. Plan to retire it later against D3.**

- Now: the Nostr annex stays in the specification as informative, optional, and off-able. The demo wallet reads it (DR B9).
- When layer 3 ships: the wallet uses the overlay first and Nostr second.
- Retire when D3 holds for six months: "off by default, out of the main text". Wallets may still read it.
- Do not expect that before taproot gossip ships, because N5 depends on it.
- Retiring needs no format change: the signed records are the same on every path (DR B10).

---

# Part F. Bitcoin relay patterns, and what `discovery.md` should fix now

Extra scope from the owner (relayed by the coordinator): which Bitcoin transaction-relay and mempool patterns apply, and what is normative now versus reserved.

## F0. Sources read for this part

| Claim | Source | Mark |
|---|---|---|
| Transaction download: at most 100 requests in flight per peer before a 2 s extra delay; at most 5,000 announcements tracked per peer; non-preferred (inbound) peers delayed 2 s; after 60 s without an answer, ask the next announcer (`GETDATA_TX_INTERVAL`) | [txdownloadman.h l.25-38](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/txdownloadman.h) | [V] |
| Per-peer announcement queue `m_tx_inventory_to_send` and a rolling "known by this peer" filter of 50,000 entries | [net_processing.cpp l.308-313](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| Announcements trickle on Poisson timers: 5 s average to inbound (one shared timer), 2 s to outbound ("less privacy concern"); an inventory token bucket bounds the rate | [net_processing.cpp l.170-185](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| `inv` is capped at 50,000 entries (`MAX_INV_SZ`) | [net_processing.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp), [BIP 35](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0035.mediawiki) | [V] |
| BIP 133 `feefilter`: the receiver asks peers not to announce transactions below a fee rate; answers to `mempool` are also filtered; Core re-sends it about every 10 min | [BIP 133](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0133.mediawiki), [net_processing.cpp l.189-191](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| BIP 35 `mempool`: the peer answers with an `inv` of its whole pool. Core answers only if it offers `NODE_BLOOM` or the peer has permission, and otherwise disconnects | [BIP 35](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0035.mediawiki), [net_processing.cpp l.5186-5197](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| BIP 37 `fRelay` in `version`: if false, no transactions are announced until a filter is set; it prevents being "flooded" right after the handshake | [BIP 37](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0037.mediawiki) | [V] |
| Mempool: 300 MB default (5 MB for blocks-only); expiry 336 h (two weeks); when full, evict lowest fee rate and raise the minimum, decaying with a 12 h half-life | [mempool_options.h l.19-23](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/kernel/mempool_options.h), DR A6 | [V] |
| `-persistmempool` defaults to true; `mempool.dat` is reloaded at start, and expired entries are counted and dropped on load | [mempool_persist_args.h](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/mempool_persist_args.h), [mempool_persist.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/mempool_persist.cpp) | [V] |
| Orphanage: limited per peer (404,000 weight reserved each) and globally; when over, evict the oldest from the most demanding peer; "no peer can trigger the eviction of another peer's orphans" | [txorphanage.h](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/txorphanage.h) | [V] |
| The old fixed orphan limit (100) and 20-minute expiry | Core 0.x `net_processing.cpp` | [R] |
| Wallet rebroadcast: next resend at a random time 12 to 36 h ahead; the code says rebroadcasting "only damages privacy" when it cannot help | [wallet.cpp l.1901-1920](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/wallet/wallet.cpp) | [V] |
| Private broadcast (new in Core): a node's own transaction is sent over 3 short-lived connections, re-tried if not seen back within 1 min | [private_broadcast.h](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/private_broadcast.h) | [V] |
| BIP 339 `wtxidrelay`: sent before `verack` (after it, MUST be ignored or treated as invalid). Motivation: txids do not commit to witnesses, so caching a rejected txid let a third party block relay by malleating | [BIP 339](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0339.mediawiki) | [V] |
| BIP 331 package relay (Draft): negotiated by `sendpackages` in the handshake; `ancpkginfo` and `getpkgtxns` fetch a transaction's missing ancestors | [BIP 331](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0331.mediawiki) | [V] |
| Misbehaviour: `Misbehaving()` now simply sets "should discourage"; there is no score. The peer is then disconnected and discouraged | [net_processing.cpp l.2015-2026, 5368-5371](https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp) | [V] |
| Erlay, minisketch, Dandelion | A3b above | [V] |
| NIP-77 Negentropy, range-based reconciliation for client-relay and relay-relay sync | [NIP-77](https://raw.githubusercontent.com/nostr-protocol/nips/master/77.md) | [V] |

## F1. Pattern by pattern

| # | Bitcoin pattern | Verdict | Rule it adds to `discovery.md` |
|---|---|---|---|
| F1 | `inv` / `getdata`: announce, then fetch | **Applies, one level up.** The beacon *is* the announcement; the listing is the fetched object. Beacons themselves are pushed whole (153 bytes, smaller than a useful `inv` round trip) | A node fetches a listing from **one source at a time**: a store peer first, outbound before inbound; next source after an immediate "don't have" or **30 s** without answer; the host last, after a uniform random **0 to 60 s** delay. At most **16** listing requests in flight per peer |
| F2 | Per-peer inventory queue and "known" filter | **Applies** | Keep per link a set of beacon ids sent to or received from it; never send a beacon to a link that has it. Outgoing queue per link bounded (drop oldest beyond 64) |
| F3 | Poisson trickling, inbound 5 s vs outbound 2 s | **Does not apply to beacons** (origin is public and signed). **Applies to listing fetches** as plain jitter (ledger A5) | Relay beacons immediately. Store nodes fetch a new beacon's listing after a uniform random **0 to 60 s** delay, so a host is not hit by every store node at once |
| F4 | `feefilter` (BIP 133) | **Does not apply to relay links**: every F node relays every valid beacon, or the overlay splits by interest. **Applies to pool requests** | `pool_request` carries the filter fields (ledger A4: channel-size range, profile). Relay links carry everything; `beacon_filter` stays on/off only |
| F5 | Mempool size limit and eviction | **Applies, lightly.** The store is already bounded by hosts × 4 | A store node MAY cap its store. When full, evict first the listings of the host with the most stored listings, then the nearest deadline. Never evict to make room for a host that already has 4 |
| F6 | Orphan handling | **Applies.** A beacon may arrive before the host's `node_announcement` (gossip takes 200 to 500 s to reach most nodes, A3b) | Hold an otherwise valid beacon whose host is not in the graph, or lacks F there, as an **orphan**: at most **8 per link** and **64** in total, for at most **20 min**. Re-check when a new `node_announcement` arrives. Do not relay an orphan. Do not penalise the sender. Evict the oldest from the link holding most |
| F7 | Mempool persistence | **Applies to store nodes** | A store node SHOULD save live beacons and listings on shutdown and reload them on start, dropping expired ones and re-checking the host against the graph |
| F8 | Originator rebroadcast | **Applies, cheaply** (host privacy is not at stake) | A host SHOULD re-send its live beacons to each new overlay link, and to all links at a random time every **6 to 12 h**. Duplicates stop at the first hop |
| F9 | wtxid relay: choose the right identifier | **Applies; most important lesson** | `beacon_id` = `TH("gazpacho/beacon", records before the signature)` (as in the vectors). A node marks a `beacon_id` as seen **only after the signature verifies**; an invalid copy never blocks the valid one. Replacement: for one host and lobby digest, the higher sequence wins. Withdrawal: higher sequence with deadline = open height. **Equivocation** (two valid beacons, one host, one sequence, different ids): keep the lower `beacon_id`, so every node converges |
| F10 | Package relay (BIP 331) | **Does not apply now.** The "parent" of a beacon is the host's gossip, which arrives by Lightning gossip anyway; light clients get it with `host_list` | None. Revisit only if orphans (F6) prove common |
| F11 | Erlay (BIP 330), minisketch | **Reserve** | Covered by the reserved `beacon_summary` (C2). Sketches only above about 10,000 hosts. If ever used: short ids must commit to content (Delving 2105 equivocation), and decode cost must be bounded |
| F12 | Dandelion (BIP 156) | **Does not apply.** It hides who *originated* a transaction; a beacon is signed by its host on purpose. Asker privacy is handled by onion messages. Core dropped Dandelion over DoS concerns | None. Note Core's newer *private broadcast* (short-lived connections) as the model for a light client without an onion path: query over a short-lived Tor connection |
| F13 | Handshake flags (`fRelay`, `wtxidrelay`, `sendtxrcncl`) | **Applies** | The lobby store flag is sent once in the factory handshake, before any beacon, and cannot change on that connection; a change means reconnecting |
| F14 | `mempool` message (BIP 35) | **Applies: it is the pool request** | Core gates `mempool` because it is costly and aids fingerprinting. So: answer a pool request **once per connection** and **at most once an hour** per peer (ledger A3), filtered, paged, at most 32,834 bytes per onion reply |
| F15 | Misbehaviour handling | **Applies** | Two classes, like gossipsub's Reject and Ignore. *Reject* (bad signature, malformed records, lifetime over 1,008 blocks, 5th live beacon after a warning): drop the link, 24 h back-off. *Ignore* (orphan, already expired, duplicate, over the per-host churn limit R2): drop silently, no penalty |
| F16 | Nostr NIP-77 Negentropy | **Reserve** for store-to-store sync and very large light-client syncs. It works on any ordered set and is in use between Nostr relays | Reserve the store-to-store kind. If specified later, prefer per-host version vectors (C2); use range reconciliation only beyond about 10,000 hosts |
| F17 | Bitcoin's 2 block-relay-only links and Erlay's reconciliation-only links | **Applies, as the scout** (B7) | Already in B7 |

## F2. Answer to question 1: what is normative now

**Normative now** (MUST or SHOULD in `discovery.md`), because two implementations cannot interoperate without them:

1. The beacon record, `beacon_id`, signature, caps, lifetime, sequence rules, replacement, withdrawal, and the equivocation tie-break (F9).
2. Acceptance: host in the graph with the F bit; orphan handling bounds (F6); the Reject and Ignore classes (F15).
3. Immediate relay to every factory link except the sender and links that already have it (F2).
4. The lobby store flag in the handshake (F13), and a store node's duties: fetch every beacon's listing after a random delay (F3), keep it until expiry, answer `listing_request` with the listing or an immediate "don't have", and answer pool requests.
5. The fetch order: store peer first, then the host after a random delay (F1).
6. The pool request and reply: filter fields, paging, once per connection and once an hour (F4, F14).
7. Per-host churn limit R2, and host rebroadcast as a SHOULD (F8).

**Recommended policy** (an informative section, "SHOULD" at most, numbers as defaults): the peering rules of Part B (eligibility, group-first picking, `D` = 6, `D_out` = 3, mix, diversity, anchors, rotation, scouts), store size and eviction (F5), persistence (F7). Bitcoin keeps all of this out of the BIPs, in code; peers do not need to agree on it.

**Reserved only** (a kind number and one sentence, no format):

- periodic have-summaries between peers (`beacon_summary`, C2, F11);
- store-to-store synchronisation (F16);
- package-style bundling of host proofs with beacons (F10).

**Not on the wire at all:** scoring of store nodes and of links. It is local, as in gossipsub ("never shared") and Bitcoin. The specification should say only that a node MAY de-prefer a store peer that answers "don't have" for listings it should hold.

---

# Part E. What could not be read

- The Protocol Labs gossipsub evaluation report and the Least Authority audit PDF (IPFS gateways failed).
- Prysm's peer manager code.
- Whether any client implements discv5 TopDisc (merged June 2026).
- Which PR introduced v0.13.1's "40 tries, half the slots" rule (probably the segwit merge).
- That Core made full-RBF the default (recalled).
- Live Lightning node counts: the mempool.space snapshots are from 2024 and 2025.
- A primary source for the k-out connectivity result.
- PeerSwap's polling code; the BitTorrent DHT Sybil measurement paper; Erlay's timing code in Core (unmerged).
- A helper reported that Bitcoin Knots `29.x-knots` prefers peers with a new `NODE_BLAKE2B` bit on every outbound slot. It is unexpected and was not re-checked, so it is left out of the evidence.
