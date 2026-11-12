# Gazpacho knowledge base

The single place to start. It gathers what has been learned and decided, says how sure we are of each thing, and points to the document that holds the detail. Updated 2026-11-12. Update it whenever a decision is made or a fact is checked.

## 1. Where everything is

| Need | Document |
|---|---|
| The short plan and milestones | `PLAN.md` |
| The design currently in force | `DESIGN.md` |
| The dated record of findings, reviews and decisions | `RECORD.md` |
| What every piece of work must satisfy before review | `ENGINEERING-CHECKLIST.md` |
| What runs today, and the testing plan | `TESTING.md` |
| The vertical slices | `SLICES.md`; Slice 1's work table and merge order in `SLICE1-WORK.md` |
| Specifications: protocol map, safe-to-sign rule, signing round, messages, host terms, journal, discovery (transport on branch `transport`) | `../spec/`, starting at `PROTOCOL.md` |
| Threat model | `THREAT-MODEL.md` |
| Reviews, and the ledger of every review round | `reviews/README.md` |
| What is still undecided | `OPEN-QUESTIONS.md` |
| How a factory forms | `LOBBY.md`, with research in `LOBBY-research.md` |
| Lightning nodes a host can link to | `HOST-NODES.md` |
| Public chain servers found to answer, and how they are used | `CHAIN-SERVERS.md` |
| What existed at the start | `ASSESSMENT.md` |
| Notes for the SuperScalar repo session, and the ledger of every request | `handoff/`, `handoff/README.md` |
| Illustrated pages (versioned) | `design.html`, `gazpacho-overview.html`, older versions in `history/` |
| Everything in one file | `handbook.html`: a list of contents when closed, the full text of every document when opened. Rebuild with `tools/build-handbook.py` after editing any document |
| Questionnaires put to the owner | `design-review-1.html`, `questions-2.html`, `questions-4-release.html` (answered: decisions 9 and 10), `questions-5-decisions.html` (decisions made for the owner, awaiting answers). Questions 3 is on branch `ux-concepts` |
| Owner decisions 1 to 10 | `ux/decisions.md` |
| Imported code and its manifest | `../core/superscalar/IMPORT.md` |
| How rules and features are proposed and decided (SIPs) | `sips/`, with a rule-request template and a worked example |
| Meeting a member's duties while they are away | `AWAY.md` |
| Deferred features | GitHub issues 1 (swap-in and swap-out), 2 (watching service), 3 (lobby deposit), 4 (reminders and acting while away) |

## 2. Words we use

| Word | Meaning |
|---|---|
| Factory | One on-chain output shared by a host and many members, from which each member gets a Lightning channel |
| Host | The party that funds a factory, co-signs everything in it and links it to the rest of Lightning. The SuperScalar papers call this the LSP |
| Member | Someone with a channel in a factory. The papers call this the client |
| Tree | The pre-signed transactions that divide the shared output down to each member's channel |
| Leaf | The last transaction on a member's branch, holding their channel and some of the host's spare liquidity |
| Layer | A level of the tree whose state can be replaced, using shrinking timelocks (Decker-Wattenhofer). Each adds about three days to an exit at mainnet settings |
| Pseudo-Spilman leaf | A leaf whose states are chained, each spending the last, so it needs no timelock |
| Host's spare liquidity (L-stock) | Funds on a leaf that the host can sell to a member as receiving capacity |
| Exit | Leaving a factory. Cooperative: everyone signs one transaction. Alone (unilateral): the member publishes their branch |
| Rotation | Moving members from a factory near its end into a new one |
| Ladder | Running many factories with staggered end dates, a new one starting each day |
| Signing round | One group signature: propose, exchange nonces, exchange partial signatures, combine |
| Lobby | The waiting room where members gather before a factory is created |
| Terms | The rules a host publishes for a factory |
| Safety rule | The member-side check before every signature: "after this, can I still leave alone with at least what I am owed?" |
| Core | Gazpacho's library that decides everything and touches nothing outside itself |
| Port | A replaceable connection from the core to the outside: storage, chain view, network |
| Engine | One of the core's decision-makers: signing round, channel, payment, exit, watch, lifecycle, schedule |
| Held payment | An incoming Lightning payment a node accepts but does not settle until told to |
| SIP | SuperScalar Improvement Proposal: the written request, discussion and decision record for a rule or feature. Categories: Rule, Protocol, Process, Informational |
| Target, minimum, deadline | A lobby's start rule: start at once at the target; at the deadline start if the minimum is met, otherwise cancel |
| Never say | "Staking". Say hosting, providing liquidity, fees |

## 3. How SuperScalar is meant to work

From ZmnSCPxj's posts on Delving Bitcoin (topics 1143 and 1242) as read in earlier research. Not re-read today.

- One host and many members share one on-chain output that needs everyone's signature.
- The host funds everything. Members start at zero and are paid in over Lightning.
- A tree of pre-signed transactions gives each member an exit that needs nobody's help.
- Upper layers can be re-signed to move the host's spare liquidity between members. Leaves near the bottom need only a few members online to change.
- When a factory expires, members are meant to receive everything and the host nothing ("inversion of the timeout default"), which makes keeping the service running the host's financial duty.
- Factories last about 30 days plus about 3 days of winding down. A new one starts daily. Members move to a new factory by paying across over Lightning.
- A payment's final deadline must be at least the tree's total exit delay plus a margin.
- Arity 2 is suggested near the leaves, wider higher up, and fixed (stateless) near the root.
- Pseudo-Spilman leaves were designed for several members per leaf sharing the host's liquidity. The reference code builds that shape too (corrected 2026-11-11): `factory_set_ps_subfactory_arity(K)` gives K members per sub-factory sharing the spare liquidity and K sub-factories per leaf (K² members), and `factory_subfactory_chain_advance_unsigned` sells liquidity by extending the chain, with a penalty for a stale chain. Both are in Gazpacho's import (`core/superscalar/src/factory.c:1059`, `:2971`). The default is K = 1, and the SuperScalar programs switch sales and advances off for now (#478, #481). Known divergence (corrected again 2026-11-11 by the SuperScalar shared-leaf study, and confirmed in our copy at `factory.c` around line 3007): every sale, the first included, spends all K+1 outputs of the previous step and grows the buyer's existing channel, so every channel on that sub-factory moves. The designer's shape, planned by SuperScalar for 1.1.0, is one input (the spare liquidity) and two outputs: a new channel for the buyer and the remaining stock. Channels then never move, and a member can hold several channels. Also found by the study, all to fix before shared leaves: the stale-chain penalty probably fires on honest exits; the exit-time check ignores K; the member-to-leaf mapping is wrong for K = 3 at 64 to 512 members; no second-spend guard on the shared stock; a host "funding reorged" message resets sale state without the member checking the chain. The orchestration around it (`lsp_subfactory_chain_advance`) is program code Gazpacho does not import.

## 4. What the reference code does today

Tested or read; see `RECORD.md` sections 16 and 18 and the hand-off note.

| Fact | How we know |
|---|---|
| Creation, payments and cooperative close work for 4 members on regtest | Run on 2026-11-11 |
| It has run 127 members on signet | The project's own published record; not re-run by us |
| A member cannot complete an exit alone on main: the channel transaction's fee is below the relay minimum. The SuperScalar session reports that its draft pull request 476 fixes this (the exit relays as a package with a fee-paying child) | Run on 2026-11-11; fix reported by the other session, not re-run by us |
| Factories above 16 members in the reference code use several users per leaf on an older leaf type. One-member pseudo-Spilman leaves under wide upper levels have not been shown to work at 64, 127 or 512 members | Reported by the SuperScalar session on 2026-11-11 from its own runs |
| The size figures in the shared headers (256 signers, 256 leaves, 512 tree transactions) are only defaults at the current import: the tree grows past them. One member per pseudo-Spilman leaf under wide upper levels builds, signs and verifies at 64, 127, 255, 512 and 1000 members, in one process with all keys | Built and run by us on 2026-11-11; under independent review |
| Exit delay is 432 blocks (3 days) per timed level on a member's path; the leaf adds none. At 512 members: 3,888 blocks with two-way levels, 1,296 with two 16-way levels, 432 with those two levels fixed | Same run |
| Limits that remain in the shared code: a level is at most 16 wide (15 if the node keeps its fee anchor); at most 8 levels; at most 8 timed layers; a pre-made nonce pool of 256 | Same run |
| The shared code silently turns a small subtree under a wide level into one multi-member leaf, so small factories need different shapes from large ones | Same run |
| The host funds before the tree is signed | Read in the code by the earlier session |
| Only the funding output pays members at expiry; every tree node still has a host-only timeout branch | Read in the code by the earlier session |
| Payment deadlines are fixed at 80, 40 and 18 blocks, far shorter than an exit | Read in the code by the earlier session |
| About 100 message types, in a private format | Read on 2026-11-11 |
| 16 low-level files build and run alone and reproduce real transaction IDs | Built and tested on 2026-11-11 |
| Member order in the tree can depend on the C library's sort | Read on 2026-11-11 |
| Individual partial signatures are never verified | Read on 2026-11-11 |
| Randomness is read directly from the operating system, including for signing nonces | Read on 2026-11-11 |
| The earlier session found and fixed several ways for a host to take members' funds (close paying only the host, liquidity change emptying a balance, and others) | That session's work; fixes are being merged there |

## 5. Decisions in force

Newest first within each area. The date is when the owner decided.

### Product
- Gazpacho is both host and member software, self-contained, C, signet first, quality before dates. (11 Nov)
- Soup wallet is mothballed, kept for reference. The SuperScalar repo is maintained by another session. (11 Nov)
- Home is `github.com/gazpacho-wallet/gazpacho`, MIT, public since 11 Nov 2026.
- The screens are a local web interface served by the C program. No wallet-in-a-web-page. (11 Nov)
- No role question; everyone can host; hosting always visible. Fees in 1.0.0 (proposed, owner to confirm): per payment, plus an optional joining fee from the first payment received. Payout to one wallet in 1.0.0, derived per-factory addresses in 1.1.0, outside wallet later. Receiving room, splicing, on-demand channels and shared leaves with sales are 1.1.0. Detail in `ux/decisions.md`, summary in `DESIGN.md` and `PLAN.md`. (11 Nov)
- Interface: layout concept H is the base, with the critique's fixes and the owner's answers still to apply. (12 Nov)

### Construction
- **1.0.0 trees are advanceless** (owner, 2026-11-12, questions 4): every interior level fixed, no timed (Decker-Wattenhofer) levels; timed levels and layer updates arrive with 1.1.0 and liquidity sales. This replaces the earlier "full layered tree in the first release". 1.0.0 seats are free (protected by invitation-only lobbies, host removal and standbys), then a proof of a coin or channel, then a per-lobby choice of options. Pseudo-Spilman leaves, one member per leaf. JIT channels off. Target 512 members, tested at 128 or 256.
- One funder per factory: the host, who signs funding only after the whole tree is signed. Members start at zero.
- The factory key always needs everyone's signature. No threshold key.
- Lightning's standard taproot channel format for the channel; the old format archived and recoverable.
- Our own odd envelope (type 52791) is the message specification; bLIP-56 is an adapter; signatures are always over our native bytes (owner chose "option 3" after a comparison, 12 Nov; `spec/messages.md`). The 4-byte tag stays for Slice 1; the 32-byte protocol id is signed only together with renaming the tags, once the shared name is agreed with SuperScalar.
- The standard is layered: transport, envelope, group coordination (a separate library), SuperScalar operations, channels, discovery, each with formats, state machines, acceptance rules and vectors (12 Nov; `spec/PROTOCOL.md`).
- Long-term aim: factories as a core part of Lightning. Path: our odd type now, bLIP-56's even type via the adapter, our own feature bit, then a BOLT, as dual funding and splicing went (12 Nov; `PLAN.md`).
- Lightning's own wire language; factory messages inside one custom message type.
- Members adding their own coins, several hosts per factory, swap-in and swap-out: after the first release.

### Safety
- One member-side rule before every signature. Save before send. Signing secrets never stored. A restored backup never publishes its own state.
- Exit fees are built in from the host's side, and tree transactions carry pay-to-anchor outputs so anyone can raise a fee. No on-chain reserve is required or recommended in 1.0.0; only a member who chooses to leave alone pays fees (owner decision 6, 11 Nov). In 1.1.0 a member holding more than its coverage keeps a small on-chain coin (decision 5).
- About two weeks to respond to an old state in 1.0.0: the channel's revocation window, set by the terms; the design's figure, not measured (`spec/safety-rule.md` section 7). It holds below a timed layer only if the channel engine keeps every old anchor current; in 1.1.0 a member above its coverage may have under a day. The watch engine can also run as a separate process.
- New joining or safety rules are normally changes to the safe-to-sign code itself, which is kept as one small, tested module.

### Forming a factory
- A lobby like a game server, with member conditions that are locked in. Gathering is long; signing is short at a scheduled start; the host sets both timers.
- Newcomers with no funds are the main audience; each host sets their share of seats.
- A lobby is listed or unlisted, and open or by invitation (QR invitations).
- Names, chat and rule-change requests can each be switched off by the host. A member may attach a proven or free-text identity; identity is new per lobby by default.
- Listings carry fixed terms, ranges, size and start time; live details come from the host. Hosts may publish a track record.
- All four rule profiles ship: Safety, Standard, Starter, Circle. Deposits come in the release after the first.
- No voting and no vote-to-remove. The host removes people; each member has a personal block list; history is kept locally.
- Discovery over Lightning first, Nostr as an optional annex (12 Nov; `spec/discovery.md` draft 2): one odd feature bit, no host card; a host is whoever sends lobby beacons; beacons relayed among factory-capable nodes; opt-in store nodes serve listings; a pool request for catch-up and light clients. Proofs (anchors) are needed only on Nostr. The demo ships the bit, direct queries and Nostr; beacons and store nodes next. Live state, joining and signing stay direct.
- The lobby and signing coordination are written so they can become their own library.

### Hosts
- A host links to a regular Lightning node through an adapter: LND first, then Core Lightning, then others. Later the built-in node holds ordinary channels itself.

- Work proceeds in vertical slices on signet as soon as the engines they need are tested: form a factory, then a payment, then leaving alone. (11 Nov)

### Working method
- The owner handles outside review. This session's job is to bring the software to release candidates fit for review.
- New rules and features go through SIPs (SuperScalar Improvement Proposals), modelled on BIPs and bLIPs. Approval and shipping are separate; the record of ACKs and NACKs is kept.
- Review: several different AI models on every engine as it is built; outside human reviewers and red-teamers before real funds.
- Hand-off notes are local documents the owner points the other session to.
- Chain servers: well-known public ones first (checked list in `CHAIN-SERVERS.md`); our own around launch. No Bitcoin node of our own for now.
- Reminders: in-app countdowns first; Nostr, email and phone notifications later.
- Imported SuperScalar files are never edited here. Changes are requested from the SuperScalar repo.
- Every safety rule has a test and a run with the rule removed that must fail.
- Illustrated pages keep earlier versions behind a version switch.
- Claims are checked against primary sources where money depends on them, and marked when they are not.

## 6. How sure we are

### Checked today against a primary source or by running it
- Lightning's message format, type ranges, typed fields and the odd/even rule (the messaging specification).
- Peer-storage messages exist in the specification.
- Core Lightning's dual-funding code received security fixes in four releases from August to November 2026 (its release notes).
- LND has hold, settle and cancel for invoices built in (its interface definition).
- Everything in section 4 marked as run, built or read on 2026-11-11.

### From secondary sources only
- Lightning's taproot channel format was merged into the specification in 2026 and ships in LND and Eclair.
- LND is about 90% of public nodes; Core Lightning about 5%.
- Core Lightning holds payments through a community plugin.
- A WebSocket carrier for Lightning connections is not standardised.

### Our own reasoning, not yet reviewed
- The scheme for proving who broke a signing round.
- That a member adding coins to their own leaf leaves other members unaffected.
- That swap-in is safe under three conditions (confirmations first, on-chain timeout after the channel deadline, refund after timeout). The technique is long established; our statement of it was not re-checked against sources.
- Estimates of size and effort.

### Not yet known
- Whether Eclair, LDK-based nodes and Nostr Wallet Connect can hold payments open in a way we can use.
- The timelock and deadline numbers for 1.0.0's advanceless trees, and later for 1.1.0's timed levels.
- How members who are offline at rotation are reached.

## 7. Risks we are carrying

0. **The chosen leaf design is proven only for building and one-process signing.** One member per pseudo-Spilman leaf works at up to 1000 members in that test. Still untested at size: signing by separate parties, state changes, a member building its own copy, and anything on a chain. The SuperScalar session is running the whole-program test.
1. The channel update routine must be exactly right through crashes and reconnects.
2. Channel state cannot be rebuilt from a recovery phrase.
3. Members must be reachable at rotation and must watch the chain.
4. Deadlines, timelocks and factory lifetime must agree for every tree shape.
5. Public chain servers can hide a transaction.
6. The imported tree code still has open design issues upstream.
7. Gathering many people to sign at once, with people who join and never sign.
8. Privacy: a host sees all of its members' payments.

## 8. Practical facts

- Builds and tests run on Gazpacho's own build server, in one folder. The server used earlier is left to the SuperScalar session.
- The project runs no Bitcoin node of its own for now. It uses public chain servers, on signet (`CHAIN-SERVERS.md`).
- Commits are authored as `8144225309 <8144225309@users.noreply.github.com>`.
- Automated checks run on GitHub for every push: a normal build and one with memory-error checkers.
- The owner's machine is sometimes short of memory; long-running local helpers may be stopped. Pages open from disk without them.
- Test transactions use a fee rate of 0.1 satoshi per virtual byte to preserve test coins (owner's instruction, 11 Nov). Anchor outputs for adding fees later are an accepted option. If a transaction at that rate does not spread, find out why before paying more.
- Nothing is posted publicly, and nothing public is started, without the owner's say.
- The build server allows each agent one SSH connection per 60 seconds. Long jobs (mutation runs, scale checks) are started detached and their results read later, not held open over a connection. (Found 12 Nov)
