# Ideas ledger, 2026-11-12

Every idea or decision from the owner conversation of 2026-11-11 and 12 that must reach the documents. Each row: the idea, its source, the document it belongs in, and its state. "Owner" means the owner said or chose it; "proposed" means it waits for the owner; "found" means a review or research found it.

## A. Discovery (spec/discovery.md, spec/PROTOCOL.md). HOLD until the peering research lands (docs/research/peering-research.md)

| # | Idea | Source | State |
|---|---|---|---|
| A1 | One factory feature bit, not two. A host is whoever sends beacons | Owner | Owner leaning; apply |
| A2 | Drop the host card (not standard; node_announcement has no TLV stream; liquidity ads unmerged after ~5 years). Reserve its number only | Owner question, research | Apply |
| A3 | Pool request: a node asks a factory-capable peer for its active beacons (on connect, after being offline), filtered, once per connection or per hour; beacons are signed so a peer can withhold but not forge; bounded by hosts × 4 × ~150 bytes. Precedent: Lightning gossip queries, Bitcoin mempool request, gossipsub IHAVE/IWANT. Also the light-client path | Owner | Apply |
| A4 | Two or three tiny filter fields in the beacon (channel-size range, profile) so most nodes never ask | Proposed | Apply, mark proposed |
| A5 | Random delay (jitter) before fetching a listing after hearing a beacon. Precedent: BOLT 7 gossip batching, Bitcoin's randomised transaction trickling | Owner question | Apply |
| A6 | Ask peers for a listing before the host. Final form (owner, 2026-11-12): NO per-beacon "have" flag (beacons are relayed before anyone could have fetched the listing, so it would almost always be "no"). Instead a per-connection **lobby store** flag in the factory handshake (precedent: Bitcoin's version-message relay flag, used by blocks-only nodes since 2012). Store nodes fetch the listing for every beacon they hear (after a random delay), keep it until expiry (bounded by the beacon caps) and serve peers; a store peer answers a listing request with the signed listing or an immediate "don't have". Other nodes relay beacons and, when interested, ask a store peer first, then the host after a random delay. Light clients connect to one or two store nodes and use the pool request (A3). Every listing is checked against the host's signature. Reserve room for, but do not specify, periodic have-summaries, store-node scoring and store-to-store sync. The demo wallet needs no store machinery (known hosts plus Nostr) | Owner | Apply |
| A7 | Hosts rate-limit and silently drop excess queries | Research | Already in; keep |
| A8 | Beacon over Lightning needs no extra proof (anchored by the gossip graph); coin or channel proofs only on Nostr | Owner | Check the spec says this |
| A9 | Feature bits must be odd: BOLT 7 says a node with an unknown even bit is not connected to and not routed through | Found (BOLT 7 quote) | Already in; keep |
| A10 | Overlay peer mix, diversity, refresh | Owner | Already in; tune from peering research |
| A11 | Nostr: keep as optional annex now; conditions to retire it later come from the peering research | Owner question | Apply from research |
| A12 | Collecting other hosts' lobbies is off by default; relaying beacons is on by default among factory-capable nodes | Owner | Already in; keep |

## B. Wire format and standard (spec/messages.md, spec/PROTOCOL.md, docs/KNOWLEDGE-BASE.md)

| # | Idea | Source | State |
|---|---|---|---|
| B1 | Option 3: our own odd envelope (type 52791) is the specification; bLIP-56 is an adapter; signatures always over our native bytes | Owner chose after comparison | In messages.md; add to KNOWLEDGE-BASE decisions |
| B2 | Long-term aim: factories as a core part of Lightning; path is our odd type now, bLIP-56 even type via adapter, our own bit, then a BOLT (as dual funding and splicing went) | Owner | In PROTOCOL.md; add to KNOWLEDGE-BASE and PLAN "after the release candidate" |
| B3 | Layered standard (transport, envelope, group coordination as a separate library, SuperScalar operations, channels, discovery) with formats, state machines, acceptance rules and vectors for each | Owner | In PROTOCOL.md; add to DESIGN.md summary |
| B4 | Keep the 4-byte tag for Slice 1; sign the 32-byte protocol id only together with renaming the tags, once the shared name is agreed | Review 3 | In messages.md |
| B5 | bLIP-56 amendments to propose later (odd type, taproot nonces, no "forget a channel" without evidence): owner permission needed to post | Found | Add to OPEN-QUESTIONS |
| B6 | Messages.md still needs: zero scope for discovery kinds 128–159; scope-zero hello listing only listed lobbies | Discovery spec writer | Apply |

## C. Signing and safety (spec/signing-round.md, spec/safety-rule.md)

| # | Idea | Source | State |
|---|---|---|---|
| C1 | The host's round random value must mix in the incarnation and a counter: a host restored from an old backup with repeating randomness re-created a round identifier its members had signed | Found by the engine builder | Add to signing-round S4 |
| C2 | session_id32 = tagged hash of (secret port bytes, incarnation, in-memory counter) | Engine builder decision | Add to signing-round section 8 as the rule |
| C3 | In 1.0.0 nothing updates a timed layer, so timed layers cannot cause a loss, only a longer exit (draft 3 reasoning, unchecked against the design posts) | Found | Already in SR 8; add to OPEN-QUESTIONS for the owner's timed-levels decision, with "verify by simulator test and against the posts" |
| C4 | No on-chain reserve recommended in 1.0.0 conflicts with C3 (fee coins to win a race at a timed level); resolved if 1.0.0 has no timed-layer updates | Found | OPEN-QUESTIONS |

## D. Product and owner decisions (docs/ux/decisions.md, docs/DESIGN.md, docs/PLAN.md, docs/OPEN-QUESTIONS.md)

| # | Idea | Source | State |
|---|---|---|---|
| D1 | No role question; everyone can host; hosting always visible | Owner | In decisions.md; add to DESIGN.md |
| D2 | Terms: fixed outer rules, signed ranges, freeze at the ready check, rules fingerprint | Owner | In terms.md and decisions.md; add to DESIGN.md |
| D3 | Fees for 1.0.0: per payment (base + proportion), optional joining fee from the first payment received | Owner | In decisions.md; add to DESIGN.md |
| D4 | Receiving room, splicing, on-demand channels are 1.1.0; build and document with the goal, UI hidden | Owner | In decisions.md; add to PLAN.md release table |
| D5 | Shared leaves (K > 1) with sales in 1.1.0 under "limited coverage"; each sale makes a new channel; several channels per member | Agreed with SuperScalar | In decisions.md; add to DESIGN.md and PLAN.md |
| D6 | Payout destinations: one wallet (1.0.0), derived per-factory addresses (1.1.0), outside or cold wallet (later); must be fixed before the factory forms; proven before use | Owner | In decisions.md; add to DESIGN.md and the SuperScalar requests |
| D7 | Hosting on phones: always a tab, with "header until you host" as a setting; compare later with testers, never tracking | Owner | In decisions.md |
| D8 | No on-chain reserve in 1.0.0; pay-to-anchor; a "speed up a stuck transaction" action; document the alternatives (fee tiers, own-output CPFP, paid helper); A/B samples later | Owner | In decisions.md; add the action to PLAN.md work list |
| D9 | Dedication: About > Dedication, Credits, Licences; one line on first run; in `gazpacho --version` | Owner | In decisions.md; add to PLAN.md work list |
| D10 | Interface direction: concept H as the base, with the critique's fixes and the owner's answers still to apply | Critique | Add to PLAN.md |
| D11 | Legal advice before anyone hosts on mainnet (the Samourai case treated non-custodial developers as money transmitters) | Raised by me | Add to PLAN.md "towards real funds" and OPEN-QUESTIONS |
| D12 | Seat cost: the free-seat liveness weakness (one peer can exhaust seat creations) | Found | OPEN-QUESTIONS, linked to the seat-cost question |
| D13 | A phone needs the app open during the signing window to move factories; companion device as the clean answer | Owner question | OPEN-QUESTIONS (mobile research item) |

## E. Requests to SuperScalar (new hand-off note docs/handoff/2026-11-12-to-superscalar.md)

| # | Request | Source |
|---|---|---|
| E1 | Caller-supplied channel output script (standard taproot channel funding output) | Earlier, accepted "if small" |
| E2 | Payout destination per member (for cold wallets, D6) | Owner |
| E3 | Bound the layer-counter write inside init (overflow at 257+ members) | Review 2/3 |
| E4 | Honour the host's hash at node index 512 and above (caps factories at ~128 members today) | Review 2/3 |
| E5 | A setter for member placement | Review 2 |
| E6 | Free a live signing session before re-initialising it (leak) | Review 2 |
| E7 | Split coins between branches by member count, not equally (today a member under a smaller subtree gets a bigger channel) | Spec editor build |
| E8 | Agree the shared protocol name and id (SHA256("SuperScalar/1")), a shared tag prefix replacing "gazpacho/", and whether the reference adopts this message format | Protocol map |
| E9 | Single-input sale (new channel per sale) and the four shared-leaf prerequisites: include in one round so we re-import once | Their study |

## F. Engineering (docs/ENGINEERING-CHECKLIST.md, docs/KNOWLEDGE-BASE.md practical facts)

| # | Idea | Source | State |
|---|---|---|---|
| F1 | "A save made early in a start holds back every later send; start records last" | Core builder | Sent to core builder; check it landed |
| F2 | "Invariants check the property itself, not a proxy" | Core review | Same |
| F3 | Mutation runners must kill children on timeout (hung mutants loaded the server for hours) | Found | Add to checklist |
| F4 | Build server SSH limit: one connection per 60 s per agent; long jobs detached | Found | Add to KNOWLEDGE-BASE practical facts |
| F5 | A new protection always gets a cross-check against an independent implementation where one can be written (the Python BOLT 8 peer, the independent sighash, the independent parser all paid off) | Reviews | Add to checklist |
