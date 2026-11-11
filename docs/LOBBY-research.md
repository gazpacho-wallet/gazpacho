# Lobby: research and design note

Research note, 2026-11-11. Status: proposal for the owner's decision. Nothing here is decided.

The **lobby** is the waiting room where a host and members gather before they jointly sign a new factory. This note reports what earlier work and comparable systems did, recommends a design, and lists what is uncertain.

The note has three clearly separated parts:

- **Part A** is what was found in sources, with links.
- **Part B** is the recommended design. It answers the ten questions in order.
- **Part C** is what is uncertain or unverified, and the questions that need the owner.

Terms used throughout:

| Term | Meaning |
|---|---|
| Host | The party that funds the factory. The design literature calls it the LSP. |
| Member | A party that gets a channel in the factory. The literature calls it a client. |
| Terms record | The structured record a host publishes: tree shape, sizes, lifetime, fees, limits. |
| Limits | The member's own conditions, held in the member's wallet. |
| Seat | One member's place in a lobby, identified by a public key the member chose for this lobby. |
| Roster | The list of seats that will be in the tree. |
| Signing attempt | One run of the group signing: propose the tree, collect nonces, collect partial signatures, combine. |
| Partial signature | One signer's contribution to a MuSig2 group signature. It is not a valid signature by itself. |
| Sybil | One person operating many identities that look like separate people. |

---

## Summary

1. **Before signing completes nobody has money at risk.** Every defence in the lobby is therefore a defence against wasted time, not against theft. The defences should be light in proportion.
2. **The only real guarantee for a member is the check their own wallet makes on the actual tree at signing time.** Everything said in the lobby is a convenience that lets the wallet leave early. This is sound and is the centre of the design.
3. **Votes cannot bind anyone,** because every participant signs for themselves and the host chooses who is in the tree. A "vote" can only be a structured way for members to state preferences so that the host can pick a value most members will accept. Vote-kick has the same limit, and in a lobby where identities are free it can be captured by one person with many identities.
4. **Every comparable system that successfully bans misbehaving participants bans a scarce resource** (a coin, a paid fee, a locked bond), never an identity. Gazpacho members arrive with no funds, so there is no scarce resource unless the design adds one. This is the hardest problem in the note.
5. **Only one kind of misbehaviour is provable to outsiders: a bad partial signature,** and only if every signing message is signed with the sender's seat key. A participant who simply does not answer can never be proven guilty, because the host could have dropped the message.
6. **Recommended first version:** listing on Nostr, direct join, versioned terms with automatic leave, a scheduled start with a ready check, signed signing messages, drop-and-restart up to three attempts, host kick plus a personal block list, local-only reputation, no deposit. Add a short held Lightning deposit at the ready check second.

---

# Part A. What the sources say

## A1. Prior work by the same owner

Repositories read: [`8144225309/superscalar-wallet`](https://github.com/8144225309/superscalar-wallet) (`docs/PROTOCOL_V1.md`, `docs/FACTORY_POLICY_V1.md`, `docs/PROTOCOL_NOTES.md`, `docs/CLIENT_JOIN_DEMO.md`) and [`8144225309/soup-rendezvous`](https://github.com/8144225309/soup-rendezvous) (`README.md`, `WALLET_INTEGRATION.md`, the three `PROOF_OF_*.md` files). Both were read at their current head on 2026-11-11.

### What was designed or built for joining

| Piece | Where | State |
|---|---|---|
| Host listing on Nostr: a coordinator verifies a host's proof and publishes a "vouch" (kind 38101, replaceable, with a NIP-40 expiry) | soup-rendezvous | Built. Three reference coordinators are described as live. |
| Three proof tiers: channel (host's Lightning node has an announced channel), UTXO (host controls an unspent output, 100,000 sat suggested on mainnet), peer (host's node merely answers a connection; off on mainnet) | soup-rendezvous | Built. |
| Caps and rate limits: at most 10 live vouches per Lightning node or per Bitcoin address, 3 per peer-tier node; 80 chain-anchored and 20 peer requests per hour; 5 per hour per sender | soup-rendezvous `README.md` | Built. |
| Browse a host's factories over the direct connection (`FACTORY_INFO_REQUEST` and response) | `PROTOCOL_NOTES.md` phase 2 | Recorded as done and tested on signet. |
| Join request and response, cancel, host-side queue, `factory-kick-joiner` | `PROTOCOL_NOTES.md` phase 3 | Designed in detail. `PROTOCOL_V1.md` (May 2026) says "the join button does nothing". `CLIENT_JOIN_DEMO.md` (later) walks through a working join on regtest. The documents disagree, and the code was not inspected, so the true state is unverified. |
| Start rule: start at once when all seats are filled; otherwise at a deadline if a minimum is met; otherwise push the deadline back (`min_clients_to_start` default 4, deadline default 36 blocks, about six hours) | `FACTORY_POLICY_V1.md` §4.7.7–4.7.8 | Specified. |
| Presence check before signing: host sends a heartbeat, members acknowledge within 30 seconds, those who do not are dropped | `PROTOCOL_NOTES.md` §3.1 step 5, §4.5–4.6 | Specified; listed as phase 4, "not started". |
| The terms record: about 60 fields in 13 groups, sent as a compact difference from defaults | `FACTORY_POLICY_V1.md` | Specified at length. |
| A three-level classification of every field by how strongly it is enforced (see below) | `FACTORY_POLICY_V1.md` §4.0.1 | Specified. This is the most reusable idea in the prior work. |
| Member-side validator functions that check a proposal against the terms before signing | `FACTORY_POLICY_V1.md` §7.1 | Declared, mostly not implemented (see below). |

The three enforcement levels, in the prior document's own terms:

| Level | Meaning | What stops a violation |
|---|---|---|
| Hard | The value is part of the signed transactions (lifetime, tree shape, channel size). | A violating transaction has no valid signature. |
| Member-enforceable | The host could try to violate it, but the member's software checks every proposal and refuses. | The member's refusal to sign. |
| Soft | An advertised promise about host behaviour with nothing behind it. | Reputation, and members walking away. |

### What was left unfinished

- **The member-side checks mostly do not exist.** `FACTORY_POLICY_V1.md` §10.5.17 audits its own claims and concludes that the member checks only tree shape; for payment limits, channel size, the host's reserve and several others the member "signs blind" because the values are not even in the proposal message. Its own words: the security model is "aspirational". Gazpacho's design already makes the member-side acceptance rule a first-class part of the core, which closes this gap, but only if the proposal message carries everything the rule needs.
- **No authorisation for joining.** "Any peer can ask" (`PROTOCOL_NOTES.md` §9). Whether a joiner must prove anything or pay a deposit is listed as an open question in both protocol documents.
- **No handling of members who stall,** beyond dropping those who miss the 30-second heartbeat. No restart count, no give-up rule.
- **No reputation.** Deferred as "needs real traffic data". Host reputation is "wallet-local for now".
- **No voting, no rule changes after joining, no profiles.** The terms record has no notion of versions inside one lobby.
- **No join fee.** A one-time fee was prototyped and removed "because it has no lib infrastructure".
- **Privacy pass not done.** Join records keep member node identifiers and amounts; marked to be reviewed before mainnet.

### Three points where the prior work conflicts with the current requirements

1. **Listings on Nostr were deliberately removed.** `soup-rendezvous/WALLET_INTEGRATION.md` §12 lists factory advertisements under "deliberately out of scope and never added to Nostr" and records that an advertisement kind (38100) was removed. The stated reasons are that a wallet should inspect everything directly, and that public listings leak the host's business. `PROTOCOL_V1.md` separately proposes a per-factory announcement (kind 38102) as a cheap way to show something in the user interface. Owner requirement 7 puts listings on Nostr, which reverses the first position. Part B8 proposes how to do that without losing the benefit.
2. **The host proofs do not prove the host can fund the lobby.** They prove that the host controls one channel or one output. The verified balance is deliberately stripped from the published vouch. They are a spam filter on host identities, not a proof of funds.
3. **The earlier design treats signing as slow and asynchronous** (each signer has up to 24 hours to answer, `confirm_timeout_sec`). The Gazpacho brief treats it as everyone online at the same moment. These are different products. See the first open question in Part C.

The older documents also describe the member's requested amount with wording the project now avoids. In Gazpacho the member's number is a "requested channel size", and the host is "hosting" or "providing liquidity".

## A2. ZmnSCPxj's SuperScalar posts

Sources: [first post, September 2024](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143); [revised design and "SuperScalar UX notes", November 2024](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242); [Optech summary](https://bitcoinops.org/en/newsletters/2024/11/01/#timeout-tree-channel-factories). Read only; nothing was posted. Quotes were read through a summarising tool and should be re-checked against the posts before being cited elsewhere.

| Topic | What is said |
|---|---|
| Gathering | The host "simply schedules the new client to join the next" factory. There is no lobby concept: the host assigns, the member waits for the slot. |
| Schedule (the ladder) | A new factory every day. Suggested lifetime: 30 days active plus 3 days dying, so the host runs 33 factories at once. |
| Being online | Without new Bitcoin opcodes, members must come online at the specific time the host builds the factory. Phones are woken by the operating system's notifications. The host can group members by time zone. |
| No-shows | If a member is too slow, the host restarts the opening without that member. No timeout or restart count is given. |
| Who pays | The host pays tree fees by default and recovers them through a periodic fee. |
| Incentive to be online | A small payment or a small amount of free inbound liquidity for members who show up when asked. |
| Abuse | The host should "be picky about its clients". A minimum deposit is suggested "to prevent trivial DoS attacks where a botnet just spams the LSP", with an optional initial fee. |
| Fake members | In the reverse direction, members may have to assume that an unfunded fellow member is the host's own puppet. |
| Size | No recommended member count; examples use 8 and 16. A [third-party implementation report](https://delvingbitcoin.org/t/superscalar-an-implementation-report/2705) (July 2026, read via a mirror) mentions up to 127 members and says fee reserves for a member with no coins "remain an open design question". |

Two consequences for the lobby. First, the original design has no market in which members choose among lobbies; the game-server lobby is the owner's addition and has no precedent in the SuperScalar posts. Second, the author of the design already expected a deposit and a daily fixed time.

## A3. Coinjoin coordination

Coinjoin is the closest precedent: many strangers must all sign one transaction, and one non-signer spoils the round.

**Wasabi (WabiSabi).** Sources: [user documentation](https://docs.wasabiwallet.io/using-wasabi/CoinJoin.html), [coordinator defaults](https://raw.githubusercontent.com/WalletWasabi/WalletWasabi/master/WalletWasabi/WabiSabi/Coordinator/WabiSabiConfig.cs), [ban logic](https://raw.githubusercontent.com/WalletWasabi/WalletWasabi/master/WalletWasabi/WabiSabi/Coordinator/DoSPrevention/Prison.cs).

| Item | Value |
|---|---|
| Phases | Input registration, connection confirmation, output registration, signing, broadcast |
| Start rule | Start when the maximum number of inputs is reached, or when the registration timer ends and the minimum is met |
| Timers | Registration 1 hour; confirmation, output registration and signing 1 minute each |
| Size | Maximum 100 inputs, minimum 50 |
| Blame round | If some inputs do not sign, those that did sign rerun the round without them, with a 3-minute registration and a lower minimum (40). This repeats until too few remain. |
| What is banned | The coin (the specific unspent output), not a person. Smaller coins are banned longer. Repeat offences multiply the ban by 1.3. Coins descended from a banned coin inherit half the ban. |

Why it works: each disruption attempt ties up a real coin, and a fresh coin costs an on-chain transaction. Criticism: [Peter Todd on the bitcoin-dev list, June 2022](https://mirror.b10c.me/lists/bitcoindev/Yrj9N7k8osWsxhY4@petertodd.org/1-a.txt) pointed out that the only answer to a dropout is punishment in later rounds, and that an attacker with many coins can still disrupt. No published measurement of the cost of disruption was found.

**JoinMarket fidelity bonds.** Sources: [design](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af), [documentation](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md). A fidelity bond is a coin locked until a future date so that an identity is costly to create. Nobody can seize it; the cost is the time value of the locked money. Bond value grows faster than linearly with the amount (exponent 1.3), which rewards one large bond over many small ones. Counterparties are picked at random weighted by bond value, and 12.5% of picks ignore bonds so that newcomers are not shut out. Limits: the bond is public and links to the owner's coins; a long-term holder gets a bond almost for free; the unbonded picks are cheap to fake.

**Whirlpool.** Sources: archived [server repository](https://raw.githubusercontent.com/Samourai-Wallet/whirlpool-server/develop/README.md) and [theory document](https://raw.githubusercontent.com/Samourai-Wallet/Whirlpool/whirlpool/THEORY.md). Five participants per mix. Each participant pays the coordinator's fee once, in advance, in a preparatory transaction; that fee is the Sybil cost. Phases of about one minute. The theory document rejects both IP bans and fidelity bonds and bans misbehaving coins instead. Production ban values could not be verified.

## A4. Ark and similar round protocols

Sources: [arkd settings](https://raw.githubusercontent.com/arkade-os/arkd/master/docs/settings.md), [arkd offence list](https://raw.githubusercontent.com/arkade-os/arkd/master/internal/core/domain/conviction.go), [Second: rounds](https://second.tech/docs/learn/rounds), [Second: hArk](https://second.tech/blog/hark-explained/), [Delving post on Ark with new opcodes](https://delvingbitcoin.org/t/evolving-the-ark-protocol-using-ctv-and-csfs/1602).

- Ark has the same structure as a factory creation: the operator and all round participants sign a tree with MuSig2.
- Rounds are on a fixed timer (Second: hourly; arkd: a session of 30 seconds, schedulable). Wallets must be online in the window.
- arkd records named offences: nonce not submitted, signature not submitted, invalid signature. Three offences bring a five-minute ban. The ban again attaches to a resource (the participant's existing balance in the system), not an identity.
- The direction of development is to remove steps that need everyone at once. Second's hArk moved one all-must-sign step out of the round because "one user's failure" stalled everyone. Delegated signers can sign the tree on behalf of offline phones.

## A5. Finding the culprit in a failed group signature

Sources: [BIP-327 (MuSig2)](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki), [RFC 9591 (FROST)](https://datatracker.ietf.org/doc/html/rfc9591), [ROAST](https://eprint.iacr.org/2022/550), [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg).

- BIP-327 lets whoever collects the partial signatures check each one individually and identify exactly one signer who sent a bad one. It calls this **identifiable aborts**. It holds only if messages were not tampered with (authenticated connections), the nonces were combined honestly, and every partial signature was checked.
- BIP-327 warns that a dishonest collector "can always make signing abort and wrongly hold honest signers accountable".
- BIP-327 also notes that partial signatures can be forged by anyone. A bad partial signature shown to an outsider therefore proves nothing unless its author also signed it with an identity key.
- A signer who does not answer is not covered at all. Nothing in MuSig2 or FROST makes silence attributable.
- A nonce must never be used for two signing runs, or the signer's key leaks. Every restart needs fresh nonces.
- ROAST makes threshold signing robust by opening new sessions with whoever responds. It relies on spare signers. In an all-must-sign scheme there are none: removing a signer changes the key, which for a factory means a new tree. Only the pattern "identify, remove, rebuild" carries over.
- ChillDKG is the closest example of signed transcripts. It states plainly that there is "in general, no way to verify an accusation by some party that another party is to blame".

## A6. Lightning: griefing, jamming and held payments

- **Dual-funded channels** ([BOLT 2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md)): a peer can stall the joint construction and keep the other side's coins reserved. The specification's advice is not to treat reserved coins as locked and to reuse them across sessions. This applies directly to a host's reserved funding.
- **Liquidity advertisements** ([proposal](https://github.com/lightning/bolts/pull/1153)): the seller "should keep the channel open for at least a month, but there is no way to guarantee that"; the buyer's remedy is to stop using that seller. An enforced lock was [dropped because it could be used to pin the seller's funds](https://bitcoinops.org/en/newsletters/2023/12/13/#discussion-about-griefing-liquidity-ads).
- **Channel jamming** ([overview](https://bitcoinops.org/en/topics/channel-jamming-attacks/), [Unjamming Lightning](https://bitcoinops.org/en/newsletters/2022/11/16/#paper-about-channel-jamming-attacks)): the researched answer is two parts used together, a small unconditional fee and locally kept reputation. After several years, the reputation part exists in logging-only form ([LND, October 2026](https://bitcoinops.org/en/newsletters/2026/10/23/#lnd-10919)) and upfront fees are deployed nowhere. The lesson is that purely local reputation is what proved shippable.
- **Held payments** ([overview](https://bitcoinops.org/en/topics/hold-invoices/)): the receiver accepts a payment but delays completing it, then either completes or cancels. While it is held, every routing node on the path has liquidity and one payment slot locked without compensation. If it is held close to its expiry, channels along the path are force-closed. Consumer wallets refuse long holds: [Phoenix rejected RoboSats bonds](https://github.com/RoboSats/robosats/issues/44) once the hold window grew to two days.
- **RoboSats bonds** ([documentation](https://learn.robosats.org/docs/bonds/)): a held payment of about 3% of the trade to the coordinator, cancelled on success and completed on forfeiture. Whoever created the payment secret can complete the payment at any time, so the bond is fully trusted to the coordinator.
- **Proving coin ownership as an entry ticket:** [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) defines a signed proof of funds. [aut-ct](https://github.com/AdamISZ/aut-ct) proves ownership of some coin without revealing which, one token per coin per context; its author calls it experimental and unsafe.

## A7. Game lobbies

- **Ready checks.** [League of Legends](https://support.riotgames.com/en-us/league-of-legends/gameplay/queue-dodging) escalates penalties for leaving at the ready stage: 6 minutes, 30 minutes, 12 hours, with the level decaying after a clean day. The penalty is a delay before the next attempt, attached to an account that is costly to replace.
- **Vote-kick.** [World of Warcraft's group finder](https://warcraft.wiki.gg/wiki/Vote_Kick): majority vote; the initiator must give a reason; no kick in the first 15 minutes or during a fight; at most two kicks per group; players who initiate kicks often are blocked from initiating for two hours.
- **Known abuse:** a group of friends that forms the majority kicks the lone stranger. Counter-Strike 2 reportedly made a solo player matched with a party of four immune to kicks (secondary source only).

The safeguards are thresholds, cooldowns, limits per group and immunity for the outnumbered. All of them assume that an account is costly to replace. None of them survives free identities.

## A8. Nostr

Source: [NIP index](https://github.com/nostr-protocol/nips/blob/master/README.md).

| Need | Mechanism | Caveat |
|---|---|---|
| A listing that can be updated in place | Addressable events (NIP-01, kinds 30000–39999, keyed by a `d` tag) | |
| Listings that disappear when stale | [NIP-40](https://github.com/nostr-protocol/nips/blob/master/40.md) expiry | Relays "MAY persist them indefinitely"; explicitly not a security feature. Wallets must check the expiry themselves. |
| Private messages | NIP-17 with NIP-44 encryption and NIP-59 wrapping | The prior work still uses the older kind 4. |
| Labels and reports | NIP-32 (kind 1985), NIP-56 (kind 1984) | Anyone can publish them about anyone. |
| Third-party scores | [NIP-85](https://github.com/nostr-protocol/nips/blob/master/85.md) trusted assertions (kind 30382) | Draft. You trust the provider you name. |
| Proof of work on an event | NIP-13 | A cost in electricity, weak against a determined attacker. |
| Reviews or ratings | No merged standard | |

How others handle reputation on Nostr:

- [Mostro](https://mostro.network/protocol/user_rating.html): the coordinator signs a rating event per user. Reputation is per coordinator and not portable.
- [RoboSats](https://learn.robosats.org/docs/robots/): no ratings; a fresh identity per trade; bonds do the work.
- [Joinstr](https://docs.joinstr.xyz/protocol/): a pool is announced as a public event with size, peer count and timeout; joiners message the creator from a fresh key; optional aut-ct proof for Sybil resistance.
- [publsp](https://github.com/smallworlnd/publsp): liquidity offers as addressable events, orders by private message, no reputation.

Web-of-trust scores (rank by who follows whom, for example [Vertex](https://vertexlab.io/docs/algos/)) are weak in three ways: keys are free, follows can be farmed, and a new user has an empty graph. Scores personalised to the viewer resist manipulation better than global ones but are not immune.

## A9. The pattern across all sources

1. **Bans work only on scarce things.** Wasabi bans coins, Ark bans existing balances, Whirlpool charges in advance, JoinMarket prices identities with locked coins, RoboSats holds a bond, games rely on accounts with history. No system was found that successfully polices free identities.
2. **Short signing windows and an automatic rerun without the non-signers** is the standard liveness pattern (Wasabi, Whirlpool, Ark, and the SuperScalar notes).
3. **Penalties escalate with repetition and decay with time.**
4. **Reputation that shipped is local.** Shared reputation is either per coordinator or absent.
5. **Nobody proves blame for silence.** Systems exclude locally and move on.

---

# Part B. Recommendations

## B0. Three facts that shape everything

**Fact 1. Nothing binds until a participant signs.** The host decides which seats are in the tree. Each member decides whether to sign. No message, vote or promise in the lobby changes either of those.

**Fact 2. Identities are free.** A seat key, a Lightning node key and a Nostr key each cost nothing to create. Any rule that counts identities can be captured by one person.

**Fact 3. The damage a griefer can do is bounded and small.** Members have no funds in play. The host's funding is only reserved, not spent, until the tree is signed, and reserved funds can be released at once. The loss is everyone's time and the host's opportunity.

The owner's requirements are assessed against these facts:

| # | Requirement | Assessment |
|---|---|---|
| 1 | Game-server lobby, starts only when conditions are met | Sound. See B1. |
| 2 | Member conditions locked in; nobody carried into a factory that violates them | Sound, and strong, for conditions the wallet can check in the tree. Weaker than it sounds for promises about the host's future behaviour and for "at least N members". See B2. |
| 3 | Members vote on open rules | Sound only as preference gathering. It cannot be binding. See B3. |
| 4 | Vote-kick honoured by everyone's software | Weaker than it sounds. Unsafe against one person with many seats unless seats cost something. See B4. |
| 5 | Layered defences | Sound. The layers must be chosen for members with no funds. See B5 and B6. |
| 6 | Rule profiles | Sound. See B9. |
| 7 | Listings and proofs on Nostr | Sound, with a caution: it reverses an earlier deliberate choice, and the existing proofs do not prove funds. See B8. |
| 8 | Wording | Followed in this note. |

## B1. Lobby state machine (question 1)

### Lobby states

| State | Meaning | Who moves it on | Leaves by |
|---|---|---|---|
| Draft | The host has written terms but not published | Host publishes | to Open |
| Open | Listed. Members join, accept terms, wait. The host may issue a new version of the terms. | Start rule (automatic), or host cancels, or closing time | to Ready check, or Cancelled |
| Ready check | Terms and roster are frozen. Each seated member must confirm within a short window. | Timer | to Signing, or back to Open, or Cancelled |
| Signing (attempt 1, 2, 3) | The group signing runs | Success, failure or timer | to Funding, or next attempt, or back to Open, or Cancelled |
| Funding | The tree is fully signed. The host signs and broadcasts the funding transaction. | Chain confirmation or deadline | to Active, or Failed |
| Active | The factory exists. The lobby is finished. | | end |
| Cancelled | The host cancelled, or the closing time passed without a start | | end |
| Failed | Signed but never funded | | end |

### A member's seat states

Requested, then Seated (the host admitted the member), then Accepted (the member's wallet accepted the current terms version), then Confirmed (answered the ready check), then Signed, then Member. A seat can end at any point as Left (member's choice), Removed (host's choice, or automatic after a fault) or Declined (the wallet refused new terms).

### Start rule

The host publishes the start rule as part of the lobby rules. Recommended form:

- A **scheduled start time**, published when the lobby opens. A fixed time is the best tool for getting phones online together and matches the daily schedule in the SuperScalar design.
- A **minimum** and a **maximum** number of members.
- A **closing time** after which the lobby is cancelled if it has not started.
- Optional **start when full**: if every seat is Accepted before the scheduled time, give two minutes' notice and start.

At the scheduled time: if the number of Accepted seats is at least the minimum, go to Ready check. If not, move the start to the next scheduled slot (the host states the slot spacing in advance) or cancel at the closing time. The lobby never starts below the minimum.

The host can always cancel. Nothing can prevent that, because the host can simply refuse to sign. The host cannot start early in any way that matters, because each member's wallet checks the tree (B2).

### Timers (proposed defaults, to be tuned on signet)

| Timer | Default | Basis |
|---|---|---|
| Ready check window | 60 seconds | Wasabi's one-minute phases; prior work's 30-second heartbeat |
| Nonce window, per attempt | 30 seconds | Software answers without user action |
| Partial signature window, per attempt | 30 seconds | Same |
| Attempts | At most 3 | See below |
| Whole signing budget | 10 minutes | Keeps a short deposit hold workable (B5) |
| Funding broadcast deadline | 6 blocks after signing | Host states it in the terms |
| Listing refresh and expiry | Republish every 10 minutes, expire after 30 | Stale listings vanish |

### What happens in each attempt

1. **Propose.** The host sends each confirmed member the roster, the tree, the funding transaction (unsigned) and the attempt number.
2. **Member check.** Each wallet runs the full check in B2. A wallet that refuses says so with a reason code and leaves.
3. **Nonces.** Each member sends fresh nonces, signed with their seat key.
4. **Nonce set.** The host sends everyone the full set of signed nonces.
5. **Partial signatures.** Each member sends partial signatures, signed with their seat key together with a hash of the nonce set they used.
6. **Verify and combine.** The host checks each partial signature as it arrives and combines them.
7. **Complete.** The host sends the finished signatures. Each wallet verifies every signature on its own exit path before it treats the factory as real.

### No-shows and restarts

- A member who misses a window, or whose partial signature fails verification, is removed.
- All members who missed the same window are removed together, not one per attempt.
- The next attempt includes only members who behaved in the previous one, plus standby seats (below). No new joiners. This is Wasabi's blame round.
- Before each new attempt every wallet re-runs its check, because the tree and the member count have changed.
- If the remaining members fall below the minimum, the lobby returns to Open with the next scheduled start. It does not start short.
- After three failed attempts or ten minutes, the lobby returns to Open (or is cancelled at closing time). Members who caused failures are not readmitted to that lobby.
- Every attempt uses fresh nonces and a new session identifier. Nonces are never stored.

**Standby seats.** The host may admit a few more members than the maximum. Extra members pass the same ready check and wait. When a member is removed, a standby member takes the place in the next attempt, so one failure does not shrink the factory. This is the "backfill" idea from game matchmaking.

**Limit.** An attacker holding k seats can respond with all but one each time and burn k attempts. The attempt cap, the limit on unproven seats (B5) and standby seats bound this; nothing removes it.

### What a member's wallet checks at each step

| Step | Check |
|---|---|
| Reading the listing | The listing is signed by the host's key, not expired, and the host has a vouch from a coordinator the user accepts. The public terms pass the member's limits. If not, the lobby is not offered. |
| Joining | The wallet fetches the terms directly from the host and compares their hash to the listing. A mismatch is a host fault (provable: two signed records). The terms pass the member's limits. |
| Terms change | The new version is signed and numbered. The wallet re-evaluates the limits. Pass: accept automatically if the user allowed that, otherwise ask. Fail: decline and leave. |
| Ready check | The frozen terms hash equals the version the wallet accepted. The roster size meets the member's own minimum. Any deposit is within the member's own cap. |
| Propose | The full check in B2, on the actual tree. |
| Nonce set | The member's own nonce is in the set unchanged. Every nonce carries a valid seat signature. |
| Complete | Every signature on the member's exit path verifies. The funding transaction's inputs exist and are unspent, as far as the chain source can tell. |
| Funding | The funding transaction confirms by the deadline. If not, the wallet records the failure and tells the user. |

## B2. Member-locked conditions (question 2)

### Where the guarantee comes from

The guarantee is one sentence: **the member's wallet signs nothing until the tree in front of it passes every condition the member has set, computed by the wallet from the proposal itself.** This is already the member-side acceptance rule in `DESIGN.md` §4. It does not depend on the lobby, the host, other members or any vote.

The lobby adds convenience only. Checking the published terms lets the wallet avoid lobbies that will fail the check, and leave early when a rule change makes failure certain.

"Locked in" should therefore mean three concrete things:

1. The member's conditions are stored in the member's wallet and bound to the seat when the member joins.
2. Nothing the host or other members send can loosen them. Only the user can, by an explicit action in their own wallet.
3. At every later step (terms change, ready check, each signing attempt) the wallet re-evaluates them and leaves on failure.

With this, "nobody is carried into a factory that violates their conditions" holds for honest wallet software regardless of what the host or the other members do.

### Which conditions can really be locked

Not every condition is equally checkable. Reusing the prior work's classification:

| Kind of condition | Examples | How it is enforced | Strength |
|---|---|---|---|
| Visible in the signed tree | Channel size, factory lifetime, exit delays, tree shape, depth of the member's exit path, number of leaves | The wallet computes it from the proposal | Full |
| Enforced by the wallet later | Fee per liquidity purchase, payment size limits, how often the host may ask for re-signing | The wallet refuses each later request that exceeds the limit | Full, as long as the wallet keeps checking |
| A promise about host behaviour | "The host will offer a place in the next factory", "the host will stay online", forwarding fees charged outside the factory | Nothing | None. The wallet can only record the signed promise. |

The wallet's settings screen should show which kind each condition is, so that a user does not believe a promise is a guarantee. The host should sign its terms record with its host key, so that a broken promise can at least be shown to others later.

### Two conditions that are weaker than they sound

**"At least 10 members."** The wallet can verify that the tree has at least 10 member leaves. It cannot verify that they are 10 different people. The host, or anyone, can fill seats with puppets, as ZmnSCPxj also notes. The condition should be described to users as "at least 10 seats". It is also worth asking what the member wants from it: a larger tree means a deeper and more expensive exit path for each member, so a larger count is not simply better for the member.

**"Fees below some level."** A fee the member pays is enforceable, because the wallet refuses to pay more. A fee the host deducts on some future service the member has not yet asked for is a promise.

### Should the host see a member's conditions?

Recommendation: no, by default. The host learns only "accepted" or "declined, reason code". If the host saw every member's maximum fee it could price exactly at each member's limit. The one deliberate exception is the preference ballot in B3, which a member may choose to fill in.

## B3. Voting on open rules (question 3)

### What voting can and cannot mean

A vote in a lobby cannot be binding in either direction.

- It cannot bind a member, because the member's wallet will not sign a tree that fails the member's conditions (B2).
- It cannot bind the host, because the host builds the tree and can decline to.
- It cannot be made fair by counting, because one person can hold many seats.

What remains is useful but modest: **a structured way for members to tell the host what they would accept, so the host can pick the value that keeps the most members.** The note recommends calling this "preferences" in the user interface and reserving "vote" for the informal description.

### Recommended design

1. **The host marks each rule as fixed or open.** An open rule has a range the host will tolerate.
2. **Most choices should be per member, not shared.** Channel size, inbound liquidity and which optional features a member uses can be chosen by each member within the host's range, with no vote at all. Only rules that are truly shared need preferences: start time, factory lifetime, tree shape, minimum and maximum size, and the profile.
3. **Each member's wallet sends a ballot** for each open shared rule: the range the member would accept, and optionally the value the member prefers. The acceptable range is taken from the member's limits, and the member chooses whether to disclose it.
4. **The host's software chooses** the value inside its own range that the largest number of seated members accept. Ties are broken by the median of the preferred values. The median is used rather than the average because a minority cannot drag a median by stating extreme values.
5. **The result is issued as a new terms version.** Every wallet re-evaluates as in B2. Members whose conditions it fails leave. Nobody is forced.
6. **Ballots are signed with seat keys** and the host shows the set of ballots to members on request, so that members can check the host followed its stated rule.

### Weighting

Recommended: one ballot per seat, counted only for seats that have passed whatever admission cost the lobby uses (B5). No weighting by size of channel or by reputation in the first version.

The honest position on weighting: because identities are free, any weighting scheme is only as good as the cost of a seat. Where seats are free, the count means little, and the host should treat the result as advice. The host is entitled to weigh ballots however it likes, since it decides anyway; what the design can require is that the host states its rule in advance and can be seen to follow it.

### Limits

- A person with many seats can move the result, within the host's range. The effect on an honest member is that the outcome falls outside their conditions and their wallet leaves. They lose time, not money.
- The host can ignore the ballots. A member who dislikes that leaves.
- The audit in step 6 proves the host counted the ballots it showed. It cannot prove the seats were real people.

## B4. Vote-kick (question 4)

### Can it be made safe against many fake seats?

Not by counting seats. If seats are free, one person can hold the majority and can both kick honest members and protect a griefer. The safeguards used by games (thresholds, cooldowns, immunity for the outnumbered) all assume an account is costly to replace. A vote-kick is exactly as Sybil-resistant as the cost of a seat, and no more.

There is a second, less obvious problem. **Members have little to base a kick on.** For privacy, a seat key should be new for each lobby, so members cannot recognise each other from earlier lobbies. There is no chat. The only behaviour visible in a lobby is whether a seat signed correctly, and that is already handled automatically. "A known problem or low reputation" can only be judged if members show each other a lasting identity, which costs every member their privacy.

### What "the software honours the vote" can mean

| Mechanism | Works against a dishonest host? | Works against modified member software? |
|---|---|---|
| The host's software removes a seat when shown a valid kick certificate | No. The host can ignore it or cancel. | Not relevant |
| Each member's software refuses to sign any tree that contains a seat named in a valid kick certificate | Yes. A tree containing that seat cannot be completed while honest software is in it. | No. Modified software can ignore certificates, but one honest member's refusal is enough to block the tree. |

A **kick certificate** is a set of signed ballots from seated members that meets the lobby's published threshold. The second row is the real mechanism and it does satisfy the owner's wording: once a certificate exists, the software of every member, including those who voted against, will not sign with the kicked seat. Because every member must sign, this is effective.

The same property is the danger. A certificate obtained by fake seats makes every honest wallet refuse to sign with an honest member.

### Recommended design

Use four tools, in this order of importance.

1. **Automatic removal for proven faults.** A seat that misses a window or sends a bad partial signature is removed without any vote (B1). This covers the only misbehaviour that can actually be observed in a lobby.
2. **Host kick.** The host may remove any seat before signing, with a reason code shown to the removed member. The host has the evidence (connection history, deposit, its own records) and bears the cost of failed rounds. Prior work already planned `factory-kick-joiner`.
3. **Personal block list.** Each member's wallet holds a list of keys it will never sign with, and a list of hosts it will not join. If a blocked key is in the roster, the wallet says so and leaves. This needs no vote and cannot be abused against anyone else. It is the individual form of vote-kick.
4. **Kick certificate, optional and later.** Only in lobbies where seats cost something (a deposit, a proof of coin ownership, or an invitation), with these safeguards:
   - Threshold of two thirds of eligible seats, and at least five ballots.
   - Only seats that have met the lobby's admission cost may vote.
   - A reason code is required.
   - Each seat may start one kick per lobby.
   - No kicks once the ready check has begun; from then on only automatic removal applies.
   - The effect is limited to this lobby. It is never published and never becomes a ban elsewhere.
   - The kicked member is shown the certificate.

### Stated limits

- In an open lobby with free seats, vote-kick should be switched off. The profile decides (B9).
- A kicked person can return under a new key unless seats cost something.
- A host that disagrees with a kick can cancel the lobby and open another.
- Vote-kick is most meaningful in invitation-only lobbies among people who know each other, where identities are real and the problem of fake seats does not arise.

## B5. Deposits (question 5)

A deposit here has one job: to make a seat cost something, so that stalling is not free. It protects time, not money, and should be small.

| Option | How it works | Cost to an honest member | Can a dishonest host abuse it? | Member with no funds |
|---|---|---|---|---|
| **Held Lightning payment** | The member pays the host a payment that the host holds without completing. The host cancels it after the member signs, or completes it if the member stalls. | Routing fee is zero if cancelled. The amount is locked for the hold time. Routing nodes carry the lock unpaid. | Yes. The host created the secret and can complete the payment at any time. The amount is trusted to the host. | Cannot pay |
| **Non-refundable join fee** | An ordinary small Lightning payment, credited against the member's later fees in the factory | The fee, if the lobby never completes and the host does not refund | Yes. A host can collect fees and never start. | Cannot pay |
| **On-chain bond, time-locked** (JoinMarket style) | The member proves ownership of a coin locked until a future date | On-chain fees and the time value of the coin. Reveals a coin to the host. | No. Nobody can seize it. It is only a proof of cost. | Cannot provide |
| **Proof of an ordinary coin** (Wasabi style) | The member signs a challenge with the key of an unspent coin. The host bans that coin after a fault. | None beyond revealing the coin to the host | No | Cannot provide |
| **Invitation** | An existing member or the host issues a single-use code | None | No | Works |
| **Proof of work** | The member's device computes for some seconds | Battery and time | No | Works, but weak against an attacker with hardware |
| **Earned standing** | The member presents receipts for factories completed earlier (B6) | None | No | Works only from the second factory on |

### Points that matter

**A held payment cannot be made trustless.** There are two ways to build it. If the host knows the secret, the host can take the deposit whenever it likes. If only the member knows the secret, the host can never take it, so it punishes nobody. RoboSats uses the first form and trusts its coordinator. The first form is acceptable only because the amount is small and the host has far more to lose (its vouch, its record, its business).

**A held payment must be short.** Holding a payment for the hours or days a lobby is open would lock routing nodes' funds, would be refused by consumer wallets, and risks channel closures near expiry. The deposit should therefore be taken at the ready check and released within minutes: when the member's valid partial signature arrives, or when the attempt ends through no fault of the member. The ten-minute signing budget in B1 is chosen for this. Taking the deposit at the ready check also makes the ready check mean something.

**The wallet caps the deposit.** The member's limits include a maximum deposit amount and a maximum hold time. A lobby that asks for more is not offered.

**A wrongful forfeit for stalling cannot be disproved.** A host can claim a member stalled and keep the deposit. Silence is not provable either way (B7). The member's remedy is to record it locally and avoid that host.

**Members with no funds cannot pay any monetary deposit.** This is the main audience for a factory wallet. A lobby that requires a deposit from everyone excludes them. The recommended answer is a **mixed lobby**:

- Seats are either **backed** (deposit, coin proof, invitation or earned standing) or **unbacked**.
- The host's rules cap the share of unbacked seats, for example one quarter. JoinMarket does the same with its 12.5% unbonded allowance.
- Unbacked seats are the first to be replaced by standby seats after a failure.
- The host accepts the remaining risk as a cost of acquiring new users, as ZmnSCPxj's notes expect the host to be "picky".

**Recommendation.** First version: no monetary deposit; invitations, the unbacked-seat cap, per-connection rate limits and the attempt cap. Second step: a held Lightning payment at the ready check for backed seats, using the hold operations the host's Lightning adapter already needs (`DESIGN.md` §14). Later: proof of coin ownership, and a privacy-preserving version if aut-ct matures.

## B6. Reputation (question 6)

### The governing fact

With free identities, **a bad record is useless**, because the owner discards the identity. Only two things work: a **good record that took time to earn**, and **cost**. Reputation for members should therefore be positive only. Reputation for hosts can be both, because a host's identity is anchored by its vouch and its capital and is costly to replace.

### What can be measured

| Event | Who observes it | Provable to outsiders? |
|---|---|---|
| Member answered the ready check and signed correctly | Host | Yes, if the host issues a signed receipt |
| Member sent an invalid partial signature | Host | Yes, with signed signing messages (B7) |
| Member did not answer in time | Host | No. The host could have dropped the message. |
| Host showed different terms or different nonce sets to different members | Members who compare | Yes: two conflicting messages signed by the host |
| Host's listing did not match the terms it served | Member | Yes: two signed records |
| Host completed signing and then did not fund | Members | Partly. If the host sent the signed "complete" message, that message plus the absence of the funding transaction on chain is evidence. A host that claims a member stalled leaves no evidence. |
| Host funded a factory of a stated size | Anyone, if the host publishes the funding output | Yes for existence and amount. Not for the number of real members. |
| Host cancelled a lobby | Members | No more than their word |

### Where it is stored and who writes it

| Layer | Content | Written by | Version |
|---|---|---|---|
| **Local, in each wallet** | The member's own history with each host: lobbies joined, completed, cancelled, failed to fund, deposits kept | The wallet | First |
| **Local, at each host** | The host's history with seat keys, coins and deposits; its own ban list | The host | First |
| **Receipts held by the member** | A host-signed statement "this key completed signing in a factory of mine in month M" | The host, given to the member | Later |
| **Public evidence on Nostr** | Self-verifying fault proofs only (the "Yes" rows above) | Anyone holding the proof | Later |
| **Public host record on Nostr** | Funding outputs the host chooses to publish, checkable on chain | The host | Later, optional |

### Stopping fake praise and fake blame

- **No free-form ratings.** Stars and comments from arbitrary keys are trivially faked in both directions and no Nostr standard exists for them.
- **Fake blame** is prevented by accepting only evidence that verifies by itself. A statement "member X stalled" or "host Y is a scammer" carries no weight in the software.
- **Fake praise for members** is limited by treating a receipt as worth only as much as the host that issued it. A host decides which other hosts' receipts it accepts. A dishonest host can issue receipts to its own puppets, but an accepting host can ignore unknown issuers.
- **Fake praise for hosts** is limited by counting only factories that exist on chain, which cost real capital to create.
- **Web-of-trust scores** may be shown to the user as a hint, never used by the software to make a decision, because of the weaknesses in A8.

### Privacy cost

- Any lasting member identity lets a host link a person across factories. Receipts are therefore held by the member and shown only when the member chooses, and seat keys are new for each lobby by default.
- Member reputation should never be published. A public record of which keys joined which host's factories is a map of the host's customers.
- A host that publishes its funding outputs to build a record lets chain observers follow its factories. That is the host's choice.
- Published fault proofs reveal an unsigned tree and the seat keys in it. Since the tree was never funded, the loss is small.

## B7. Identifying the culprit (question 7)

### What is achievable

| Fault | Identifiable by the host? | Provable to members and outsiders? |
|---|---|---|
| Invalid partial signature from a member | Yes, by checking each one (BIP-327) | Yes, with the measures below |
| Member silent | Yes | No, never |
| Host sends inconsistent data | Members can detect by comparing | Yes, two signed messages |
| Host silent or never funds | Members see it | Weakly (B6) |

### Measures to build in from the first version

These are cheap now, while the message formats are still being written, and expensive to add later.

1. **Every signing message is signed with the sender's seat key** and names the lobby, the terms hash, the roster hash and the attempt number. BIP-327 notes that nonces and partial signatures can otherwise be fabricated by an accuser.
2. **A member signs its partial signature together with a hash of the complete nonce set it was given.** Without this, a host could send one member a different nonce set, receive a partial signature that is correct for that set, and present it as invalid against the real set. With it, a fault proof must show a nonce set whose hash the accused signed, in which every nonce is signed by its owner.
3. **The host signs every message it sends,** so that inconsistency is provable.
4. **A fault proof** is then a bundle: the roster and keys, the transaction being signed, the signed nonces, and the accused member's signed partial signature. Anyone can recompute the check and see that it fails.
5. **Silence is handled locally and never published.** The software removes the silent seat and restarts. It never issues a public accusation of stalling, because none could be verified. This is also the protection against fake blame.
6. **Members verify the final signatures themselves** and do not rely on the host's statement that signing succeeded.
7. **Fresh nonces for every attempt,** never stored, as BIP-327 requires and as `DESIGN.md` §13 already states.

### Limit

BIP-327 is explicit that a dishonest collector can always make a round fail. The measures above stop the host from framing a member with a forged or mismatched partial signature. They cannot stop a host from pretending a member was silent. The design accepts this: the host is the party with most to lose from failed rounds, and members judge hosts by their own experience.

## B8. Public on Nostr versus private (question 8)

### Recommended split

| Information | Where | Reason |
|---|---|---|
| Host identity and the coordinator's vouch | Public (exists today) | Discovery and spam filtering |
| Lobby listing: lobby identifier, hash of the terms record, a short summary (profile, channel size range, lifetime, main fees), minimum and maximum members, scheduled start, closing time, admission requirements, status | Public, addressable event with a short expiry | Requirement 7; lets a wallet filter before connecting |
| How full the lobby is | Public but coarse: "open", "minimum reached", "full" | An exact count reveals the host's business in real time and cannot be verified anyway |
| The full terms record | Fetched directly from the host; hash in the listing | The direct copy is what the wallet checks; the hash catches a mismatch |
| Roster and seat keys | Private, host and seated members only | Member privacy |
| Join requests, a member's limits, ballots, deposits | Private, host and that member | A member's limits are commercially sensitive |
| Signing messages and the tree | Private, host and members | |
| Fault proofs | Private unless the holder chooses to publish | |
| The funding output of a finished factory | Not linked to the listing | Linking lets observers trace the factory on chain |

### Trade-offs to be aware of

- **A listing is a claim, not a fact.** Everything in it is the host's unverified word until the wallet fetches the terms directly and later checks the tree. The wallet must treat the listing as a hint for filtering only.
- **This reverses the earlier decision** that no factory state goes on Nostr (A1). The earlier concerns were leaking the host's business and making attackers' scanning easier. The coarse fill level, the short expiry and keeping the full terms off the relay address most of that. Software version details should stay out of listings, as the earlier work advised.
- **Expiry is not enforced by relays.** Wallets must check it themselves.
- **The existing vouch does not prove funds.** If the owner wants "proof of funds", the practical version is this: at the proposal step the host shows members the unsigned funding transaction, and each wallet checks that its inputs exist, are unspent and are large enough. This reveals the host's coins to members a few minutes before they would become public anyway. A public proof of funds on Nostr would expose the host's coins to everyone and is not recommended.
- **Members' network addresses are visible to the host** on a direct connection. Prior work recommended Tor by default for members; that recommendation still stands.
- **Kind number.** Prior work proposed 38102 for a per-factory announcement. Whether that number is free of collisions was not checked.

## B9. Rule profiles (question 9)

A profile is a named preset over the terms record and the lobby rules. It is a label for humans. What the wallet enforces is still each field. The wallet ships its own definition of every profile and verifies that a lobby claiming a profile actually matches it, so the name cannot be claimed falsely. Profiles carry a version number.

The optional features named below are those found in the prior terms record (`allow_jit_fallback`, `allow_splice`, forwarding policy, automatic rotation, auto-accept). Which of them Gazpacho will actually have is for the main design to settle.

| | **Safety** | **Standard** | **Starter** | **Circle** |
|---|---|---|---|---|
| For whom | Users who want the smallest attack surface | Most users | New users with no funds | People who know each other |
| Just-in-time channels | Off | On | On | Host's choice |
| Liquidity changes during the factory's life | Only at rotation | On request | On request | On request |
| Splicing and other optional channel features | Off | Host's choice | Off | Host's choice |
| Host may route its own payments through member channels | Off | On | On | Host's choice |
| Tree | Fixed, shallow (cheap exit), smaller maximum | Layered | Layered | Small |
| Exit margins and payment deadlines | Longest | Default | Default | Default |
| Payment size limits | Low | Default | Low | Default |
| Wallet accepts terms changes automatically | Never; always asks | Within limits | Within limits | Within limits |
| Admission | Backed seats only | Mixed, unbacked seats capped | Mostly unbacked; invitation or proof of work | Invitation list only |
| Deposit | Yes, once available | For backed seats | None | None |
| Vote-kick certificate | Off | Off | Off | On |
| Preference ballots | Off (all rules fixed) | On | On | On |
| Listed publicly | Yes | Yes | Yes | No, or listed without details |
| Fees | Higher (less flexibility for the host) | Default | Higher (host carries more risk) | By agreement |

Other profiles worth considering later: a **Merchant** profile (large inbound liquidity, high payment limits, just-in-time channels on, backed seats only) and a **Long-term** profile (longest lifetime, fewest occasions when the member must be online).

## B10. First version, later additions (question 10)

### Build first

1. Lobby listing on Nostr (addressable, expiring), next to the existing vouch.
2. Direct join; terms fetched from the host and compared to the listing hash.
3. Versioned, host-signed terms. The wallet accepts or leaves automatically according to the member's limits.
4. Scheduled start, minimum, maximum, closing time, optional start when full.
5. Ready check with a 60-second window.
6. Signing with seat-signed messages and the nonce-set hash (B7). This is first-version work because it shapes the message formats.
7. Automatic removal and restart, at most three attempts, standby seats.
8. Host kick with reason code. Personal block list in the wallet.
9. Admission without money: invitations, a cap on unbacked seats, rate limits per connection.
10. Local-only history in the wallet and at the host.
11. Two profiles: Safety and Standard.
12. Funding deadline, and the wallet's check of the funding inputs.

All of this can be exercised in the simulator, including scripted stallers and bad signers.

### Add second

- Held Lightning deposit at the ready check, with the wallet's caps.
- Preference ballots for open shared rules.
- Starter and Circle profiles.

### Add later, if measurement shows a need

- Host-signed completion receipts as portable standing.
- Publishable fault proofs.
- Kick certificates (Circle profile first).
- Proof of coin ownership as a seat backing; a privacy-preserving form.
- Pre-shared nonces to make restarts faster.
- Delegated signing for offline phones, as Ark is exploring. This changes the trust model and needs its own note.

---

# Part C. Uncertain, unverified, and for the owner

## C1. Not verified

| Item | Status |
|---|---|
| Whether the join flow in the older wallet actually works | Two of its documents disagree. The code was not read. |
| ZmnSCPxj quotations | Read through a summarising tool; wording to be re-checked. Posts after about number 22 in the first thread were not read. |
| History of failed Wasabi rounds, and any measured cost of disrupting them | No primary source found. |
| Whirlpool production ban values | Only development configuration found. |
| Whether Ark's server reruns a failed round automatically without the offender | Not confirmed. |
| ROAST paper body and WabiSabi paper body | Not fetched; abstract and blog only. |
| Counter-Strike 2 and Dota 2 ready-check and kick rules | Secondary sources or memory only. |
| LND's default maximum hold length for a payment | From memory (about two weeks of blocks). |
| Whether Nostr kind 38102 is unused by others | Not checked. |
| All timer values in B1 | Proposals. They need testing with real phones on signet. |
| The claim in B7 that signing the nonce-set hash prevents framing | The author's reasoning from BIP-327. BIP-327 does not describe transferable blame. It should be reviewed by someone with MuSig2 expertise before it is relied on. |
| The median rule in B3 | Standard result for preferences with a single peak; not checked against the specific rules that would be open. |

## C2. Open questions for the owner

1. **Synchronous or asynchronous signing?** A fixed start time with everyone online for minutes (this note's assumption, and the game-lobby picture), or a long window in which each member answers when their phone wakes (the older design's 24 hours)? The second is kinder to phones but keeps the host's funds reserved for a day and makes a short held deposit impossible.
2. **Are members with no funds the main audience for the first release?** If yes, a monetary deposit cannot be the main defence, and the host must accept some risk from unbacked seats. What share of unbacked seats is acceptable?
3. **Is a deposit that the host could keep acceptable,** given that it is small and capped by the member's wallet? No trustless version of a held deposit exists.
4. **Lasting or per-lobby member identity?** Per-lobby keys protect privacy but give members nothing to judge each other by, and make portable standing opt-in.
5. **Should members see the roster before signing?** They must see the seat keys at signing. Showing them earlier is needed for any member-initiated kick.
6. **Is vote-kick worth building,** given that automatic removal, host kick and a personal block list cover the cases that can be observed, and that it is unsafe where seats are free? This note recommends limiting it to the Circle profile.
7. **Is "preferences" an acceptable form of voting,** given that a binding vote is not possible?
8. **Listings on Nostr:** confirm the reversal of the earlier "nothing about factories on Nostr" decision, and choose exact or coarse fill levels.
9. **Proof of funds:** is showing the unsigned funding transaction to seated members at signing enough, or is something public wanted despite the privacy cost to the host?
10. **Numbers:** maximum members per lobby, restart cap, signing budget, whether a restart may proceed with a lower minimum that the host publishes in advance.
11. **Should a host be able to publish its funded factories** as a public record, accepting that this lets observers follow them on chain?
12. **Incentive to show up:** should the host give something small (for example a fee credit) to members who complete the ready check and sign, as ZmnSCPxj suggests?
