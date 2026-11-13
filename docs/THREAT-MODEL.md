# Threat model

Draft 1, 2026-11-11. Built from section 8 of `docs/reviews/spec-review-2.md`, edited to match `spec/safety-rule.md` and `spec/signing-round.md` draft 3. Not reviewed.

**Changes after cross-spec review 1** (`docs/reviews/review-cross-spec-1.md`, its section 1.2): the rule names now run to H18; 2.2 cites H14 for the host's duty to answer old states; 2.4 cites the exit's clock floor (`spec/exit.md` 4.5); section 3 gains the exclusions `safety-rule.md` 11 added with `spec/exit.md` draft 2 (a wallet left locked past `unlock_by`, no watch bundle, pinning of keyless anchors, the second-stage breach while locked, a penalty file cut while locked). 2.7 had been updated with `spec/storage-encryption.md` draft 3.

**What this is.** For each party that could harm a Gazpacho user: what it can do, which rule is meant to stop it, and what is not defended. It describes what the specifications say. It does not say the defences work. That needs the tests in `safety-rule.md` section 13 and `signing-round.md` section 16, none of which exist yet.

**Scope.** A member and a host running Gazpacho as the specifications and `DESIGN.md` describe, in 1.0.0: one member per leaf, no sales of receiving room, signet. Notes marked **1.1.0** say what changes when sales and shared leaves arrive.

Rule names: C1 to C13, C8a and H1 to H13 are in `safety-rule.md`, and H14 to H18 in `spec/exit.md` section 9 (listed in `safety-rule.md` section 10); R1 to R7 are its restore rules (section 9); S1 to S5 are the contribution rules of `signing-round.md` section 3. "SR" is `safety-rule.md`, "RD" is `signing-round.md`.

## 1. What is being protected

| Asset | Whose | Why it matters |
|---|---|---|
| Channel balance, and payments in flight | Member | The money. It must be claimable alone, in time |
| Factory key, contribution key, channel keys, wallet seed | Member, host | Theft of these is theft of the money or of the right to sign |
| Secret nonces | Every signer | Using one twice reveals the factory key |
| Held set and exposed set | Member | Losing the record of what was signed is as bad as losing the transactions |
| Round records: identifiers, sent bytes, received nonce sets | Every signer | Protect against being framed; needed as evidence |
| Restore epoch and guard record | Member | Stop a restored node from signing again with an old key; detect a stale backup |
| Funding capital and spare liquidity | Host | The host funds everything |
| The host's long-term key and reputation | Host | It signs terms, proposals and results; proof against it is the valuable kind |
| Payment preimages | Member | Releasing one before the payment is irrevocably committed loses the payment |
| Being able to act in time: online, a true view of the chain, fees | Member | The deadlines of C5 and the response windows of C4 |
| Privacy: membership, balances, network addresses, links between a person's lobbies | Member | The host sees much by design; others should not |

## 2. Who can attack, and what stops them

### 2.1 The host

The host coordinates, co-signs everything, funds, relays every message and keeps members' backups.

**It can:** choose the participants, their order, the parameters within its terms, and the timing; withhold, delay, reorder or alter any message it relays; pick its nonce after seeing all others; run several rounds; hold seats of its own; withhold results; publish any transaction in a member's exposed set; refuse service; return any backup version it holds; see every payment.

| Attack | Stopped by | Not stopped, or gap |
|---|---|---|
| Publish a transaction the member signed but does not hold | The exposed set; C3 and C4 draw from it | — |
| Get two trees signed on one funding output | C7 (one tree per output, record before the first partial signature); C11; the journal's mandatory sync mark so the record cannot be silently lost | Not yet tested: the tests are listed in the specs but not written |
| The same, after returning an old backup | R2 to R5: a restored node uses only new keys, and joins a creation only on a funding output that commits to one | Not yet tested (RD test 4b) |
| Make the member sign an output before it holds its exit from it | C6, tiers | How this works for channel commitments is not specified yet (SR 4.3) |
| A stale channel state on an old anchor | SR 4.1 rules 1 to 3; H4 | The channel engine is not specified yet |
| An old layer state against an absent member | SR 4.1 rule 3; SR section 8 classifies the old state as harmless when its capacity covers the balance, which in 1.0.0 is always | The classification is reasoning from the code, not yet checked against the design posts or by test. **1.1.0:** a member above its coverage must win a one-step race |
| A host-only timeout before the member can leave | C5, from the scripts | — |
| An unknown spending path or a bad parameter | C1, C2, C5, C8 with the full parameter list (RD 4.1) | A defect in the parameter list itself |
| A funding script that is not the participants' aggregate | C1 | — |
| A distribution transaction that pays the member less than it is owed | C4; C8's bound (lock time at least the end height, share at least capacity) | Whether Slice 1 signs one is undecided |
| Credit on an unconfirmed factory, then the funding spent elsewhere | C11; H3 | — |
| Values moved after the ready check | C8a; the freeze (`terms.md` section 8) | — |
| Overlapping rounds | C10; H8 | — |
| A withheld cooperative close, published later | C7; C13 | The member must exit (SR section 11) |
| A withheld round result | SR 4.1 rule 5; RD section 10: the member stays paused, asks again, then exits | The only remedy is an exit at the member's cost |
| Learn the member's key through nonce reuse | RD section 8; S1 and S2; S5 after a restore | A copy of a running program (accepted) |
| Frame an honest member | Signed nonces over (round, tier, item); unique item numbers; S1, S2, S5 | Not yet tested |
| Escape blame for a round it broke | The fault table, when it equivocates under its own key | A host with a seat of its own (accepted, RD section 9) |
| Claim that a member was silent | Recorded as the host's claim only | Unprovable either way (accepted) |
| Choose who is in a factory by delaying messages | — | Denial of service (accepted) |
| Refuse service | Leaving | Accepted |
| See payments, membership and network addresses | — | Accepted. The member's IP address also undoes the fresh per-lobby keys towards this host: the host (and any host it shares logs with) links a person's lobbies, and who only browsed or refused terms, by address. Section 1 lists those links as an asset; without Tor they are not protected from the host. 1.0.0 plan in 2.8 |

### 2.2 A member, seen from the host's side

**It can:** join for free under a fresh identity; answer late or not at all; send malformed or invalid data; leave alone at any time; route small payments to itself through the host; withhold its partial signature or its acknowledgement.

| Attack | Stopped by | Not stopped, or gap |
|---|---|---|
| Spoil a round anonymously | H2; the time budget; removal from the next attempt | Silence cannot be proven; it costs an attempt, and after a partial-signature step a new funding outpoint (H11) |
| Withhold its acknowledgement | H1: the host does not fund | Costs an attempt, as silence does |
| A free seat that stays silent, then collects at the end date | H6, H9; owner open point 2 (a deposit) | No cost per seat in 1.0.0 |
| Make the host pay unbounded fees | H6, H7 | Fee levels are set by the market |
| Make the host's commitment unrelayable with many small payments | H10 | The channel engine is not specified yet |
| An old channel state against the host | Channel revocation; H4; **H14**: the host watches every member's channel output and answers a revoked member commitment by `penalty_send_by`, signing second-stage penalties as they appear (`spec/exit.md` 9.1) | The channel engine is not specified yet. A host down longer than the shortest revocation window of its members can lose to a breach |
| An old layer state | The newer state wins within one step if the host watches | For channel states the duty is H14 (`spec/exit.md` 9.1); for 1.1.0's timed layers it is not written yet |
| Leave on day one to disturb the others | — | Accepted; it costs the host fees |

### 2.3 Other members of the same factory

They can work together and with the host. The host together with all other members is exactly the adversary of SR section 2, so every row of 2.1 applies.

Without the host they cannot sign for a third member, because every output needs every signer below it (MuSig2's unforgeability, BIP 327). They cannot frame a third member, because each contribution is signed by its author [reasoning]. They learn the keys of shared nodes, hence who else is in their branch.

Draft 2 would have shown them each other's channel states in a layer update. Draft 3 marks layer updates not specified and states the requirement that no member learns another's channel state through a round (RD 14.3).

### 2.4 Chain servers

Public Electrum-style or explorer servers, or the user's own.

**They can:** hide a transaction; delay a broadcast; refuse a package; report false fee rates; report a stale tip. They cannot invent a confirmation if headers are checked (`DESIGN.md` section 10).

| Attack | Stopped by | Not stopped, or gap |
|---|---|---|
| A fake confirmation of the funding | Header checks; two servers compared (Slice 1's chain port) | The burial depth is not yet chosen |
| Hiding the kickoff or an old state | Several sources; the maximum safe absence shown to the user (SR section 7) | Beyond the safe absence (accepted). **1.1.0:** under a day for a member above coverage under a timed layer |
| Hiding new blocks, a stale tip, or going silent, so the exit starts late | The exit's tip estimate has a **clock floor**: it advances at an assumed two blocks per ten minutes whenever no new block is seen, so hidden blocks, silent servers or offline-by-choice make the exit start early, never late; a claim counts only if a second server reaches it or its headers were checked, so one lying server cannot start an exit either (`spec/exit.md` 4.5) | A full eclipse also stops the member's broadcasts; one broadcast-only route independent of the view's servers is recommended, not guaranteed (`spec/exit.md` 4.5, open point 15) |
| Hiding or delaying the member's own broadcast | Several servers | Package submission was not available on the public Electrum servers found (`docs/research/channel-groundwork.md`, 1.9) |
| False fee rates, so the member underpays | — | Not addressed |
| **Observe**: link every member's IP address, and the host's, to one factory | Slice 1: the User-Agent is a common browser string, not a Gazpacho name; no proxy is taken from the environment, and an optional `socks5h://` proxy (Tor) can be set (`ports/chain`, `gz-chain --proxy`); a member must not ask about the funding txid before it can have been broadcast (`docs/notes/chain-port.md` section 9) | Each member polls the same funding txid and tree outputs from its own address, and every query goes to every configured operator, so each operator can group a factory's members and host by address, add each member's wallet scripts, and see the host as the first broadcaster. Not defended without Tor or the user's own server. 1.0.0 plan in 2.8 |

### 2.5 Nostr relays

Listings and host proofs only; not in Slice 1.

They can withhold listings, serve an older signed version of a host's terms, and see who asks. They cannot forge a host's signature. An old terms version leads at worst to a `ready` that names digests the host does not accept, so the round does not start (owner decision 1). Censorship and metadata are not defended.

### 2.6 Network observers between member and host

They can see that a device talks to a host and when rounds happen, and drop, delay, replay and reorder packets. They cannot read or forge anything inside the encrypted connection (`DESIGN.md` section 8).

A replayed round message is answered from saved bytes or refused by the saved identifier (RD sections 3 and 4). Delaying chosen members pushes them out of an attempt (accepted). Membership and timing are visible (not defended).

### 2.7 A stolen or copied device

| Case | Stopped by | Not stopped |
|---|---|---|
| Stolen, locked (or a copy of the data folder taken) | Encryption at rest from Slice 1 on (owner decision 13; `spec/storage-encryption.md`): every file sealed under a storage key that only the wallet passphrase unwraps, through Argon2id at 256 MiB (storage 3, 4). The 24 words need the passphrase typed for them (storage 9) | File sizes, times and counts (storage 3.2); a weak passphrase, guessed offline at the cost of one Argon2id per guess (storage 3.3); in 1.0.0, a thief who also has the person's operating-system key store reads the watch bundle (factories, amounts, dates) and can grief by publishing the member's tree path early, but cannot publish a revoked state or move value from its owner (storage 8.7.5, invariant T) |
| An older copy of the data folder put back (a sync service's history, a system restore, a snapshot) | The mark file and the guard catch a journal cut back or rolled back past an anchored batch (storage 6); the key store's counters catch an older watch bundle, penalty file or attempts file (storage 8.7.3); a journal found behind is never started as current, only as a restore under a new epoch | The whole folder rolled back together, or together with the key store: not detected locally (storage 6.4); the restore rules then decide (`safety-rule.md` 9) |
| Stolen unlocked, or keys extracted | — | The thief can co-sign with the host and pay the balance out. The safe-to-sign rule trusts its own keys |
| A copied disk restored elsewhere and run | "A restored backup never publishes" (`DESIGN.md` section 6); C12; R2 to R5 | Two devices running one key at the same time |
| A copy of a running program (a machine snapshot, a fork) holding a secret nonce | — | Accepted |
| An old backup returned by the host | C12; R2 to R6 | The member loses sight of factories joined after the backup, and may not be able to re-derive their keys without the guard record or a later export (R7) |

### 2.8 Network addresses: the Tor trap and the 1.0.0 plan

**The Tor trap.** The transport caps connections at 4 per address (IPv4, or IPv6 by /64; `transport.md` L9). Over Tor, all members of a clearnet host arrive from a few exit addresses, and at an onion-service host every connection arrives from `127.0.0.1`. So the cap that guards against floods refuses the fifth Tor member. Before Tor ships, an onion listener must be counted per connection, not per address (as `discovery.md` H2 already does for queries).

**The 1.0.0 plan.**

- **Tor for members.** A SOCKS5h dialer for member-to-host connections, a fresh Tor stream per `CONNECT` (matching the fresh BOLT 8 key), on by default when a Tor proxy is found, with no silent fall-back to the open network.
- **Onion hosts.** Invites and the transport accept `<key>@<name>.onion:<port>`; the host keeps listening on `127.0.0.1` behind a `HiddenServicePort`, with the per-connection count above.
- **The chain over Tor.** One proxy setting for host, chain and discovery traffic, isolated per chain operator; the user's own server as a first-class choice.
- **Whole blocks for lookups.** Watch factory outputs by fetching each new block's transaction ids (and the raw block when one may match) and matching locally, so an operator learns only that a wallet follows blocks, not which txids it cares about.

## 3. Not defended, in one list

- Refusal of service.
- A host with a seat of its own escaping blame.
- Silence and lateness, which cannot be proven.
- A false view of the chain, or fees out of reach, for longer than the maximum safe absence.
- Loss of the held set or the exposed set.
- Two devices running one key.
- Copies of a running program.
- A whole data folder put back from an older copy, together with the key store (storage 6.4).
- Offline guessing of a weak wallet passphrase from a stolen or copied file (storage 3.3).
- Theft of unlocked keys.
- Relay rules that obstruct pre-signed transactions.
- Bugs in the imported tree builder.
- A reorganisation of the funding after it was buried, or (1.1.0) of a leaf link.
- The host's view of all payments and of members' network addresses, which also links a person's lobbies with that host despite fresh per-lobby keys (until Tor, 2.8).
- Chain-server operators linking all members of one factory, and the host, by network address (until Tor, the user's own server, or block-based watching, 2.8).
- Withheld results and withheld closes, which force the member to exit at its own cost.
- Factories joined after an old backup, whose keys may be lost without the guard record (R7).
- For 1.1.0 members above their coverage: losing a one-step race in a timed layer.
- For every member below a timed layer: a channel engine that fails to keep an old anchor current.
- A wallet left locked past `unlock_by` with a factory balance: the locked watcher publishes the tree path but not the member's commitment, and after H_leaf a dishonest host takes the balance (`safety-rule.md` 11; `spec/exit.md` 5.6).
- A locked wallet with no watch-and-exit bundle ("maximum privacy", no OS key store, or Slice 1): nothing is published while locked.
- Pinning of a keyless anchor: anyone can spend a tree step's pay-to-anchor output first with a large low-rate child (about 234 sat on a TRUC tree, about 10,000 sat on a version-2 tree), and a member without on-chain coins cannot replace it (`spec/exit.md` 6.5).
- A breach while locked, for the payment outputs: penalties against the host's second-stage payment transactions cannot be pre-signed, so a member that stays locked past `second_stage_unlock_by` loses those outputs (`spec/exit.md` 4.4).
- A penalty file cut or rolled back while locked: detected and reported (`penalty_file_short`), but a host that publishes one of the newest revoked states while the person stays locked past its revocation window takes that channel's balance; not detected if the OS key store is rolled back too (`storage-encryption.md` 8.7.5).

## 4. What is not yet known

- Whether SR section 8's reasoning, that keeping old anchors current removes the loss from an old layer state in 1.0.0, matches the design posts. A named simulator test checks it (SR section 13).
- Whether the restore rules survive an independent review.
- The burial depth, the funding and unfinished deadlines, and the confirmation allowance per transaction.
- Whether the libsecp256k1 session functions, given an unset structure, fail an argument check (and so abort) in the pinned build. Expected, not tested.
