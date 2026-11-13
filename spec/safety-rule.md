# The safe-to-sign rule

Specification draft 4, 2026-11-12. Status: draft 3 brought in line with the four companion specifications after a third, joint review (`docs/reviews/spec-review-3.md`, findings F1 to F28), which judged draft 3 "ready after listed changes" and found that no finding needs a different cryptographic design. Draft 4 has not itself been reviewed. Nothing here has been reviewed outside this project. Values marked **proposed, owner to confirm** are Slice 1 choices the owner has not objected to and has not yet confirmed.

This document defines the check a member's software runs before it contributes to any signature, the matching rules for the host, and what the rule cannot protect against. The code that implements it is one module, the only place where "is this safe to sign?" is decided.

Companion documents: `signing-round.md` (draft 4), `messages.md` (draft 2), `terms.md` (draft 2) and `journal.md` (draft 3), all brought in line with this draft; `exit.md` (draft 2), `storage-encryption.md` (draft 3) and `local-api.md` (draft 4), which the alignment section below uses; `THREAT-MODEL.md` (`docs/`).

## Changes after cross-spec review 1

Alignment fixes from `docs/reviews/review-cross-spec-1.md`, made in one pass with `exit.md`, `storage-encryption.md`, `local-api.md` and `journal.md`. No new draft number: no check changes.

| Item | Change | Where |
|---|---|---|
| D1, review 1.1 | New exclusion: **a penalty file cut while locked**, past the revocation window (`storage-encryption.md` 8.7.5) | Section 11 |
| Locked-member gap | Section 11's "left locked past `unlock_by`" says what an honest host's H17 close leaves: the balance waits, with no deadline | Section 11 |
| Stale references | The companion line names the current drafts and the exit, storage and local API specifications; C12 and R4 say that `exit.md` 5.7 now specifies the 1.0.0 part of the recovery procedure | Header, C12, R4 |

Marks used where it matters: **[C]** read in the imported code (file and line); **[S]** checked in a primary source; **[R]** reasoning, not yet checked by a source or a test.

## Alignment with `exit.md` draft 2 (2026-11-12)

Draft 4 is brought in line with `spec/exit.md` draft 2 and its review (`docs/reviews/review-exit-d1.md`, section 4 items 1 to 3, finding F15). The checks keep their shape, but C8's end-height test becomes stricter: it is judged against the leaf's timeout, not the end height, with `exit.md`'s margins. The timeouts, the exit time and its margins now say exactly what the import builds and what the exit engine computes; a Slice 1 build that coded draft 4's numbers must change them.

| Point | Change | Where |
|---|---|---|
| Timeout heights | A fixed kickoff at depth j spends an output timing out at E − 5·(2j − 1); the leaf transaction and the channel output at **H_leaf = E − 10·d**, the binding one. Draft 4's "5 blocks per tree transaction" fitted kickoff-and-state pairs only | C5, section 12 value 2 |
| Exit time and margins | 1.0.0's exit time is n·A plus burial (B − 1), with n = d + 3 and no relative delays, judged against H_leaf; the margin is `exit.md`'s M (M_safe + M_lag + M_spike, 14 on signet), not 6 | Section 7, C8, section 12 value 6 |
| Host rules | H14 to H18 of `exit.md` section 9 listed; H6 noted as payout-only | Section 10 |
| Exclusions | Locked past `unlock_by`; no bundle; fees above the anchors and the pinning of keyless anchors; second-stage payments after a breach while locked; an eclipse | Section 11 |

## Changes after review 3

| Finding | How it was handled | Where |
|---|---|---|
| F1 one-member pseudo-Spilman leaves | New explicit C8 row: every leaf is a pseudo-Spilman leaf with exactly one member; shape and fixed levels follow `terms.md` section 4 | C8 |
| F3 restore specified three ways | One scheme, here, copied by the others: a 31-bit epoch, 0 at installation, drawn **without** the secret tag at the first start after a restore; no "fresh start" confirmation; R4's recognition step dropped, protection rests on C7's fresh-key rule; reason 12 has one meaning (the proposal lacks the member's current key for this lobby); the guard is a real record whose storage duty is stated in `journal.md` section 8 | Section 2, C7, C12, section 9 |
| F4 leaf amount, funding amount | C8 rows tie the funding amount and the fee per transaction to the terms (`terms.md` 4.2); every channel at least `channel_sat` | C8 |
| F6 C10 against H11; creation states | A creation round touches only its funding outpoint and its tree; an unresolved attempt of the same lobby does not block the next one; one name per state: **Abandoned** (a deadline passed), **Dead** (a funding input spent elsewhere and buried); Dead records are no longer consulted, never removed; late funding re-runs the time checks | Section 2, C4(d), C10, C11 |
| F7 the C7 record | It holds the funding outpoint, the funding transaction and the tree digest of `messages.md` 7.12; "the same tree" means the same tree digest | C7 |
| F8 chain actions | C11 and C4(d) need "watch this txid" and "watch this outpoint"; stated as requirements on the core contract in `signing-round.md` section 12.1 | C4(d), C11 |
| F15 secret tag | R2 draws the epoch with the ordinary (untagged) request; the tag itself is a core-contract requirement (`signing-round.md` 12.1) | Section 9 |
| F16 stale backup | Section 11 now says a stale backup also lacks the held set of later factories, which is a loss of funds in 1.0.0, not only a denial of service | Section 11 |
| F18 512 limit | One wording: a node with index 512 or more that carries a spare-liquidity hash; Slice 1 carries no hashes | C8 |
| F23 layer delay overflow | Noted under C8 for timed layers | C8 |
| F24 anchors | Tree anchors are always on in 1.0.0 (owner decision 6) | C8 |
| F19 stale text | Companion line and open point 10 updated | Header, section 14 |
| L6 other documents | `KNOWLEDGE-BASE.md` and `DESIGN.md` corrected; open point 9 closed | Section 14 |
| Slice 1 decisions | No distribution transaction; the host recovers its coins through a short life and its timeouts; burial 3 blocks; funding deadline 36 blocks; unfinished deadline one signing budget (all **proposed, owner to confirm**) | Section 12 |

## Changes from draft 2

| Finding | What changed | Where |
|---|---|---|
| N1 restore reopens two trees and the restart frame | Restore epochs: keys are never derived again after a restore; old keys become recovery-only; a creation round is joined only for a funding output that commits to a fresh key; a restore guard record detects stale backups | C7, C12, section 9 |
| N2 leaf change is not the decided operation | Draft 2's leaf-change order and owed row withdrawn; requirement for the 1.1.0 sale stated; K = 1 in C8 | Section 4.2, section 5, C8 |
| N3 timed-layer race overstated | Restated from the code, marked as reasoning; old states classified by capacity; race fee needed only when the balance exceeds old capacity; open point 1 restated | Sections 7, 8, 14 |
| N4 no acknowledgement, no reconnect request | H1 triggered by `round_ack`; `round_status_request`; results kept by the host | H1, H12; `signing-round.md` section 4 |
| N5 parameters not listed | C8 lists every setting that changes the tree's bytes; the full table is in `signing-round.md` section 4.1; funding script checked | C1, C8 |
| N6 retries against one tree per output | The exposure record is written before the first partial signature, not at nonce time; a retry after any release uses a new funding outpoint | C7, H11 |
| N7 state contradictions | Handled in `signing-round.md` sections 3 and 7 | — |
| N8 nonce function | Handled in `signing-round.md` section 8 | — |
| N9 channel states in tiers | Marked not specified in draft 3; requirement stated | Section 4.3 |
| N10 layer-update identifiers | Handled in `signing-round.md` section 14 | — |
| N11 frozen terms | New check C8a; values do not move between attempts | C8a |
| N12 C5 refuses real trees; distribution transaction | Anchors recognised and valued at zero; every exposed pre-signed transaction with a lock time is a competing claim; C8 bounds the distribution transaction | C5, C8, section 6 item 7 |
| N13 import hazards | Handled in `signing-round.md` section 12; the 512-node limit enters C8 | C8 |
| N14 pause against "keep both current" | An Unfinished member stays paused and exits after a stated time; withheld results listed as a limit | Section 4.1 rule 5, section 11 |
| N15 fault table | Handled in `signing-round.md` section 9 | — |
| N16 unfunded creation | The funding transaction is known before signing; records end when a funding input is spent elsewhere; abandonment deadline | C4(d), C7, section 2 |
| N17 contribution key | Handled in `signing-round.md` section 2 | — |
| N18 nonces at the ready check | Handled in `signing-round.md` section 11 | — |
| N19 payout review items | H10 caps HTLCs; C3 notes transactions without anchors; partial rotation falls back to paying across | H10, C3, section 5 |
| N20 TESTING invariant 3 | Invariant rewritten to match C7 and section 4.1 rule 1 | `docs/TESTING.md` |
| L1 recovery close undefined | Marked not specified; Slice 1 signs nothing with old keys | C12, section 9 |
| L2 withheld close | Listed as a limit | Section 11 |
| L3 funding malleation | H1: segwit inputs only, txid fixed before the round | H1 |
| L4 timeout order | Settled from the import; former open point 4 closed | C5 |
| L5 delay functions | Confirmed and kept | Section 7 |
| L6 other documents | Recorded as an editorial open point | Section 14 |
| L7 leaf-link reorganisation | Listed as a limit | Section 11 |
| L8 deterministic last-signer nonce | Open point in `signing-round.md` | — |

Review 1's residuals as review 2 lists them: F1 and F7 (restore) by N1; F2 by N2, N3, N9, N14; F3 by N3; F4 by N7 and N9; F5 by N1, N7, N11; F6 by N8; F7 (retries) by N6; F10 by N15 and N17; F11 by N5, N12, N13; F14 by N13; F15 by L7.

## 1. The rule in one sentence

A member's software signs only if, once the signature exists, the member can still leave alone, in time, with at least what they are owed, whatever the host and every other member do.

## 2. Terms

| Term | Meaning |
|---|---|
| **Held set** | Every fully signed transaction the member holds, plus the secrets and signed penalty transactions it holds for cancelling old states |
| **Exposed set** | Every transaction for which the member has ever released a partial signature or a channel signature, whether or not it ever saw the result. The record is written durably before the signature is sent (C7) |
| **Adversary** | The host together with all other members. It may publish any transaction in the member's exposed set, in any consistent combination, at any time. The member may publish only from its held set |
| **Request** | A proposal to create new signatures |
| **Live anchor** | An output that the member's channel could end up funded by: the channel output of any leaf transaction that could still reach the chain |
| **Owed** | What the member is entitled to, from the member's own records. Section 5 |
| **Exit value** | What the member can bring under its sole control from its held set, against the adversary's best choice from the exposed set. Section 6 |
| **Exit time** | Blocks needed to complete an exit. Section 7 |
| **Maximum safe absence** | The longest the member's software can be away, or blind to the chain, without being able to lose funds. Section 7 |
| **Buried** | Confirmed to the depth set in the member's own conditions |
| **Funding transaction** | The host's unsigned transaction that creates a factory's funding output. The member receives it before it contributes (`signing-round.md` section 4.1), so the funding outpoint is its txid and an output index |
| **Restore** | Loading the node's state from a backup instead of from the live journal on the device. Section 9 |
| **Restore epoch** | A 31-bit number under which every new key is derived: 0 for the original installation, a fresh random non-zero value at each restore. Section 9 |
| **Recovery-only key** | A key derived under an earlier restore epoch. The node never derives one again for signing; only the recovery procedure may (C12) |
| **Tree digest** | `TH("gazpacho/tree", …)` over the funding outpoint and amount, the participants and every item of a creation round, without the host's random value (`messages.md` section 7.12). Two trees are the same if and only if their tree digests are equal |
| **Abandoned creation** | A creation round whose factory was not funded and buried by the member's funding deadline, or that stayed Unfinished past the unfinished deadline. Its records are kept, but it no longer blocks the member (C10). It can still become live (C11) |
| **Dead creation** | A creation round one of whose funding inputs was spent by another transaction that is buried, so its funding output can never exist (C4(d)). Its records are no longer consulted for any decision; they are never removed from the journal |

## 3. The checks

A request is safe to sign only if all of these hold. Each is evaluated on data the member's software built or stored itself.

**C1. Rebuilt, not received.** The member's software constructs every transaction in the request itself, from its own stored state, the host's terms and the proposal's parameters, and signs only digests it computed. Every setting that changes the transactions' bytes is set explicitly, never left to a default of the imported code (`signing-round.md` section 4.1). Every item is signed in one fixed way: a 64-byte signature, the default hash type, no annex, and a stated mode (key path with a stated tweak, or script path with a stated leaf). No item uses a hash type that lets inputs be added. A participant list containing the same key twice is refused. **The funding output's script is checked:** it must be the BIP 86 key of the MuSig2 aggregate of the participant keys in order, read from the output of the funding transaction that the outpoint names. The imported `factory_set_funding` takes the script on trust [C: `src/factory.c:1214-1228`].

**C2. Own outputs are recognised by own keys.** The member's software identifies its outputs by deriving the scripts from its own keys, never from labels, indexes or positions in the request. This includes any output of the distribution transaction, which the import pays to the member's factory key [C: `factory.h:1258-1261`].

**C3. Value.** The exit value after the request is at least the amount owed after the request. The adversary draws from the exposed set; the member draws from the held set, and may rely only on responses it can make within its maximum safe absence and with fee funds it actually has. In 1.0.0 a member is not expected to hold on-chain coins (owner decision 6, `docs/ux/decisions.md`), so a response that needs a fee beyond what is built into the transaction counts as unavailable unless the member has the coins. Two import facts bear on this: the leaf chain transactions after the first carry no anchor output [C: `src/factory.c:2776-2779`], so they confirm only at their built-in fee; and the distribution transaction gets no anchor when the fee estimator reports below 1 sat/vB [C: `src/fee.c:90-97`, `src/factory.c:4532-4539`].

**C4. Every exposed transaction is accounted for.** For every transaction in the exposed set after the request, the module names which of these applies, and refuses if none does:
- **(a) Harmless:** if it is published, the member still reaches at least what it is owed from its held set.
- **(b) Revoked:** the member holds a secret or a signed transaction that lets it take the funds if this appears, within a stated window W.
- **(c) Outraced:** the member must get a specific transaction buried within R blocks of a specific on-chain event, and has the means to. The module states R.
- **(d) Dead:** an input it spends has been spent by a different transaction that is buried. For a creation round this includes any input of the funding transaction: once one is spent by another buried transaction, the funding output can never exist. Seeing this needs a watch on each input outpoint of the funding transaction, whose scripts the member does not know (`signing-round.md` section 12.1). A dead record stays in the journal and is no longer consulted.

**C5. Time, from the scripts.** For every output on the member's exit path, the module lists every way that output can be spent, from the script of the transaction it built. The recognised ways are:

| Way | Where the import builds it |
|---|---|
| Everyone on the node signs: key path, or a script path under the untweaked aggregate key | Every tree output; the penalty leaf [C: `src/factory.c:97-118`, `musig.h:186-195`] |
| Host alone after an absolute height | The timeout leaf of each node and of the channel output [C: `src/factory.c:199-214`, `:541-548`] |
| Host alone after a relative delay | The spare-liquidity output (default 144 blocks) [C: `factory.h:50`, `:429-432`] |
| Member alone | The member's own outputs |
| Behind a hash, with the signatures the script names | The hash-gated penalty path of the spare-liquidity output [C: `factory.h:379-387`] |
| **Anyone, for the anchor value only** | The keyless pay-to-anchor output on tree transactions and on the distribution transaction, 240 satoshis [C: `src/factory.c:498-507`, appended at `:1325`, `:1742`, `:1768`, `:1876`; `:4451-4458`; `channel.h:16`] |

A way it does not recognise fails the check. The anchor way is valued at zero: spending it takes no value from the member.

The exit must be complete, with a margin, before the earliest **competing claim** on any output on the path or above it. A competing claim is any moment from which someone else can take or replace that output:

- each host-only timeout on the path. In the import every tree transaction below the root kickoff spends an output that carries one, and the root kickoff has none [C: `src/factory.c:1475`, `:1632-1644`]. A fixed kickoff (and a leaf's kickoff) at depth j ≥ 1 spends an output timing out at E − 5·(2j − 1); a leaf transaction at depth d spends one timing out at E − 10·d, and the leaf's channel output copies that script, so it carries the same height [C: `src/factory.c:1312-1316`, `:1635-1644`, `:1749-1754`]. Deeper outputs expire **earlier**, by 10 blocks per level of depth (the import's step of 5 was written for kickoff-and-state pairs; with fixed levels each level is one transaction but still steps by 10). So the binding one is the leaf's, **H_leaf = E − 10·d**, where d is the depth of the member's leaf (`spec/exit.md` 4.1, vectors X1). An end height of 0 builds no timeouts at all [C: `src/factory.c:185`, `:541`, `:1636-1644`];
- the lock time of **every pre-signed transaction in the exposed set** that spends an output on the path or above it, whenever the member's balance exceeds what that transaction pays the member. Today that is the **distribution transaction**, which already exists in the import: a key-path spend of the funding output, locked to a chosen height, co-signed by every participant at creation [C: `factory.h:471-486`, `:1237-1256`; `src/factory.c:4430-4624`]. Once its lock time passes, anyone holding it can publish it and void the whole tree, unless the root kickoff is already buried, in which case it is dead under C4(d).

Former open point 4 (which way the timeouts are staggered) is settled by the first bullet.

**C6. Children before parents.** A round is divided into ordered tiers (`signing-round.md` section 5). The member releases its partial signatures for a tier only after it holds and has verified the final signatures of the tier below. So the member never helps create an output without already holding its own signed exit from it. Creation may use one tier, because of C11. For tree transactions, "holds" means holds the fully signed transaction. What "holds" means for a channel commitment is not specified yet (section 4.3).

**C7. Exposure is recorded before it happens.**
- **When.** The exposure record for a transaction is written durably **before the member's first partial signature or channel signature for it is sent**, in the same atomic write as the bytes to be sent. It is not written at nonce time: a public nonce exposes nothing. So a failure in the nonce step leaves no record, and a retry may use the same funding outpoint.
- **Two spends of one output.** Two different transactions that spend the same output may both be signed only if C3 to C5 hold with both in the exposed set. Two cooperative closes that pay the member the same amount pass.
- **One tree per funding output, ever.** The record for a creation round (`journal.md` record `exposure`) holds the funding outpoint, the funding transaction and the **tree digest** (section 2; `messages.md` section 7.12). The member refuses a round on an outpoint it holds a record for unless the round's tree digest equals the recorded one (`round_abort` reason 11). So a retry after any partial signature was released must use a new funding outpoint (H11). The host builds a new funding transaction for it, unbroadcast, which costs nothing. The funding transaction is kept in the record because C4(d) needs its inputs for as long as the record lasts, and compaction never drops it.
- **Fresh funding output.** The member contributes to a creation round only if the funding output's script (C1) is the aggregate over a participant list that contains, exactly once, **the member's current key for this lobby**: the factory key (and contribution key) it derived under its current restore epoch and bound to this lobby at `join`. Otherwise it refuses with `round_abort` reason 12. This needs no recognition of old keys: the member compares the list with the one key it holds for the lobby now. A tree the member signed with any other key spends an output that commits to that other key, so it cannot spend this one [R]. This is what makes C7 survive a restore (section 9).
- **Leaving the record.** A record leaves the exposed set only by C4(d).

**C8. Parameters inside the member's own limits.** Every setting that affects who can spend an output, or when, or how much it holds, is inside a range set by the member's own conditions. Matching the host's published terms is necessary and proves nothing about safety. The settings, each with its source and encoding in `signing-round.md` section 4.1:

| Setting | Member's limit, or rule |
|---|---|
| End height (every host-only timeout derives from it) | Not past; not 0; the member's `leave_by` with every step of its path missing, H_leaf − (B − 1) − n·A − M (`spec/exit.md` 4.4, with H_leaf = E − 10·d and n = d + 3), is at least the funding deadline plus B plus one block of being live (C5, section 7) |
| Spare-liquidity delay | Inside its conditions |
| Step and number of states of each timed layer | Inside its conditions. All levels are fixed in Slice 1 |
| Shape | The level arity is the terms' shape entry for the member count, interior widths then the leaf kind 3 (`terms.md` section 4.1); inside its conditions |
| **Leaf kind** | **Every leaf of the built tree is a pseudo-Spilman leaf with exactly one member** (the import's `is_ps_leaf`, two signers: the host and that member), and the member's own factory key is on exactly one leaf. A non-pseudo-Spilman one-member leaf and a multi-member leaf are both refused (reason 9): sections 6 and 7 analyse no other kind, and a non-pseudo-Spilman leaf under fixed levels would read a layer the import never set [C: `src/factory.c:148`, `:1651-1652`] (review 3, F1, F17) |
| Number of fixed levels | Exactly D, the depth of the deepest leaf (`terms.md` section 4.2), so every interior node is fixed. All levels are fixed in 1.0.0 |
| Members per sub-factory, K | **1** in 1.0.0 (owner decision 5). K = 1 alone does not give one member per leaf; the leaf kind row does |
| Member count | Inside its conditions (its own minimum, at least) |
| Fee per tree transaction | Exactly the terms' rule, ⌈fee rate × largest signed size / 1000⌉ (`terms.md` section 4.2); at most the member's ceiling |
| Tree anchors | On, always, in 1.0.0 (owner decision 6: pay-to-anchor outputs so anyone can raise a fee) |
| Split of the leaf between channel and spare liquidity | Fixed at half each by the import [C: `src/factory.c:1299-1323`]; checked by rebuilding |
| Channel amount | **Every** leaf's channel output at least the terms' `channel_sat` (a host that pays one member less than its terms promise is refused by all); the member's own channel at least its own minimum |
| Placement | Sequential only |
| Hash path on spare-liquidity outputs, and one hash per node | Each hash used for one state only; the same hash for two states is refused. A tree in which any node with index 512 or more carries such a hash is refused, because the import's member copy ignores it there [C: `src/factory.c:393`]. Slice 1 carries no hashes (no penalties in Slice 1, `signing-round.md` section 15) |
| Distribution transaction, if signed | Lock time no earlier than the end height; the member's share at least its channel capacity; outputs and lock time are proposal parameters. Not signed in Slice 1 (**proposed, owner to confirm**, section 12) |
| Funding amount and script | The amount equals the terms' funding rule, R(root) of `terms.md` section 4.2, and the funding transaction's output; script as C1 |

When timed layers arrive, C8 must also bound step × (states − 1) to at most 65,535 per layer, because the import's delay is a `uint16_t` [C: `src/dw_state.c:9-12`] (review 3, F23).

A timeout that is already past, or closer than the exit time plus margin, is refused. Concretely for 1.0.0: the check of the end-height row above, at the member's own constants (`spec/exit.md` 4.3).

**C8a. The frozen terms.** Every proposal parameter that the terms fix equals the frozen current value, and the proposal's terms digests (outer and current) equal the ones named in the member's own `ready` (owner decision 1; `terms.md` section 8). Attempts within one round's time budget reuse the same frozen values.

**C9. Nothing in flight is stranded, and the channel is quiet.** A request that touches a channel's anchor is refused unless the channel has been paused by agreement of both sides, and stays paused until the request is resolved. A request that closes or replaces a channel is refused while a payment is in flight on it, unless the resulting sets still let the member claim or reclaim that payment.

**C10. One open round per output.** The member takes part in at most one unresolved round touching any given output it has an interest in. A second proposal touching such an output is refused (reason 6). What a round touches: a **creation round touches only its own funding outpoint and the outputs of its own tree**, not the inputs of its funding transaction. An attempt of the same lobby that is Unfinished, Complete or Awaiting funding does not block that lobby's next attempt, which H11 puts on a new outpoint spending an input of the old funding transaction; at most one of the two can ever be funded, and C7 keeps both records. An Abandoned or Dead creation no longer counts as unresolved. (Review 3, F6: without this rule every retry after a partial-signature failure would be refused.)

**C11. A factory is live only when its funding is buried.** The member treats a factory as live, and accepts any payment in it, only when the exact funding output of its held tree, with the exact amount and script, is buried. The funding is the host's own coins and can be spent elsewhere until then. If the funding is not buried by the member's funding deadline, the creation is abandoned. Funding buried later makes an abandoned creation live only if the member still holds the whole signed tree **and** C5's and C8's time checks pass again at that moment, since the margin was judged at signing; otherwise it stays abandoned. Watching for this needs a "watch this txid to a depth" action (`signing-round.md` section 12.1).

**C12. After a restore, sign nothing with old keys.** A restored node signs only with keys of its current restore epoch, and contributes to a request only through C7's fresh-key rule: its own entry must be its current key for that lobby. It never derives a key of an earlier epoch in order to sign, so it cannot sign with one, whatever the request names, and whether or not the backup knew of the factory or round. This is how C12 is implemented; no step tries to recognise an old key in a request (review 3, F3: a restored node does not know the epochs and indexes used after the backup, so it could not). The recovery procedure (a recovery close or exit after the host proves the latest state, `DESIGN.md` sections 6 and 9) belongs with the exit engine (Slice 3), and it alone may ever derive old keys. Its 1.0.0 part is now `exit.md` 5.7: the restored member asks the host to close with its own commitment, never publishes its own automatically, and at `host_force_by` is offered the choice; recovering the keys of factories joined after the backup (R7) is not yet specified. Section 9 gives the rules.

**C13. A payment is a signature.** Accepting or making a payment signs new channel states, so it runs this module like any other request. A member with an unbroadcast cooperative close in its exposed set therefore refuses further payments on that channel.

If any check fails, the member's software sends nothing for that request, tells the host it refused, and keeps its sets unchanged.

## 4. Tree changes and the channel

A channel is funded by an output of a leaf transaction. When the tree under a channel changes, that output changes. In 1.0.0 trees are advanceless (owner decision 9, 2026-11-12: fixed levels only), so it happens only through rotation, which creates a new factory and a new funding output. From 1.1.0, **a state update in a timed layer** also changes it: it rebuilds every transaction below it, so every channel below gains a new anchor. Leaf changes are 1.1.0 work (section 4.2).

### 4.1 Rules for the channel engine

These are requirements on the channel engine, which is not specified yet (section 4.3).

1. **Commitments are kept in step on every live anchor.** Every channel update is signed for every live anchor with the same number and the same revocation secret. One revocation covers all anchors.
2. **An anchor that can no longer reach the chain is retired.** Its commitments are dropped from the update.
3. **An anchor under an old state of a timed layer cannot be retired.** That state can reach the chain if it wins the race (section 8). Its commitments are kept current for the factory's whole life. Section 8 explains why this rule carries the safety of a member below a timed layer.
4. **Pause.** No payment update on a channel while a round that touches its anchor is between "partial signatures sent" and "resolved".
5. **Unfinished rounds.** A member that has sent partial signatures and lacks the result stays paused on every affected channel. It asks for the result on every reconnect (`round_status_request`). If the round is not resolved within the unfinished deadline set in its conditions, it exits; a creation round, which has nothing to exit, becomes Abandoned instead (section 2). It never behaves as if only the old state exists. (Draft 2 also said "keeps both anchors current"; while paused nothing changes, so there was nothing to keep current. Review 2, N14.)

### 4.2 Not specified yet: the leaf change (to be specified with 1.1.0 sales)

Draft 2's rule 6 (the order of a leaf change), its owed row for "a liquidity change on the member's leaf", and its tier "Leaf change" in the signing round described an operation that 1.0.0 does not have and 1.1.0 will not use. They are withdrawn. Nobody should build from them.

What is known, for whoever specifies it:

- The imported K = 1 leaf advance spends output 0 of the previous chain transaction, has one output, adds no liquidity, and makes the channel smaller by the fee [C: `src/factory.c:2769-2782`]. Draft 2's open point 3 is settled for K = 1: no value moves from the spare liquidity.
- Owner decision 5: in 1.1.0 "every sale spends only the spare liquidity and creates a new channel for the buyer; existing channels stay where they are". So in 1.1.0 a sale is a transaction spending the shared spare-liquidity output into a new channel plus the remaining stock, and a member can hold several channels in one factory.
- Requirements the specification must meet: the second-spend guard on the shared stock; the stale-chain penalty must not fire on honest exits (`KNOWLEDGE-BASE.md` section 3); the owed and exit-value rules for a member with several channels; the coverage figure and the on-chain coin a member above coverage needs (decision 5); and, if any channel ever moves, rules 1 to 5 above.

### 4.3 Not specified yet: channel commitments inside rounds (to be specified with the channel engine, before Slice 2)

Draft 2 put channel states inside round tiers. That conflicts with the standard taproot channel format, where a party never holds a final signature on its own commitment: it holds the peer's partial signature and signing nonce, and completes its own partial signature at broadcast with a verification nonce that must be reproducible weeks later (`docs/research/channel-groundwork.md`, Part 1.1, "Nonces"). The round engine's nonce rules forbid exactly that (`signing-round.md` section 8).

The requirement, for the channel engine's specification:

- Channel commitments are signed by the channel engine under the channel format's own nonce rules, not the round's.
- The round engine releases a tier that creates a new channel output only after the channel engine reports "commitment stored for the new outpoint".
- For C6, "holds" a commitment means: holds the peer's verified partial signature and nonce, and can complete its own.
- One place is chosen for the first channel exchange: inside the creation round, or the standard opening messages after `round_complete` and before funding. H9 is written for the second.

## 5. What the member is owed

Always from the member's own records, never from the request. Stated after the channel reserve and the fees the member has agreed to.

| Operation | Owed after the request |
|---|---|
| Creating a factory | Zero. Nothing is owed until funding is buried |
| A payment received | The previous balance plus the amount, once the member can claim it |
| A payment sent | The previous balance less the amount and fee; if it fails, the amount is owed back |
| A payment in flight, incoming | Counted only if the member knows the secret and the deadline leaves room (section 7) |
| A payment in flight, outgoing | Owed back if it fails or times out; counted as owed back in the exit value |
| A sale of receiving room (1.1.0) | Not specified yet (section 4.2) |
| A change to a layer above the leaf | Unchanged |
| Rotation by paying across | The same total across both factories, less agreed fees; a payment in flight between them counts as in flight, not as arrived |
| Rotation by closing into the new factory | The same balance, carried as the opening balance in the new tree. Needs every signer of the old root. If some members do not rotate, it falls back to paying across |
| A cooperative close | The balance, paid to a script the member's software derived |
| Another member's leaf | Unchanged, and the member is not a signer |
| After a restore | Unknown to the member until the host proves the latest state; see C12 and section 9 |

## 6. Exit value

1. Find the member's exit path in the held set. For a leaf with a chain it is the whole chain of leaf transactions, not only the newest, and each link carries a fee.
2. Add up the final outputs only the member controls.
3. Subtract fees. Value that can be reached only with on-chain coins the member does not have counts as zero.
4. Payments in flight: each needs a further transaction with its own fee, and one too small to claim on chain counts as zero. Count an incoming one only if claimable in time.
5. For each transaction in the exposed set, take the adversary's best choice, then the member's best response within its maximum safe absence and fee means. Use the lowest result.
6. A penalty the member could collect from the host's liquidity is a deterrent. It is not counted in exit value.
7. **Pre-signed payouts** are members of both sets. The distribution transaction exists in the import today (C5); later end-date payouts will add more. From its lock time any party holding one can publish it, and it pays the member a fixed share. If that share is below the member's balance, the member must have exited first; C5 enforces this. In 1.0.0 a member's balance never exceeds its channel capacity (decision 5), so C8's bound, share at least capacity, makes the distribution transaction harmless for the member.

## 7. Exit time and maximum safe absence

**Exit time.** Sum, from the transactions themselves, every relative timelock on the path plus a confirmation allowance per transaction set by the member's conditions. **In 1.0.0** the path has no relative timelock [C: `src/factory.c:129-140`, `tx_builder.c:77`, `:103-114`], so the exit time is n·A for the n = d + 3 transactions still missing (d fixed kickoffs, the leaf's kickoff, the leaf transaction, the commitment), plus B − 1 blocks of burial, and it is judged against the leaf's timeout H_leaf = E − 10·d, with the margin M = M_safe + M_lag + M_spike of `spec/exit.md` 4.3 (14 blocks on signet). The resulting date is `spec/exit.md` 4.4's `leave_by`, the date `docs/MULTI-FACTORY.md` 4.1 calls `start_leaving_by`. Where a timed layer has more than one live state, use the **slowest** live state (the oldest), since the adversary chooses which state is published (section 8). The imported delay functions are not used: `factory_early_warning_time` sums step × (states − 1) per layer, then subtracts one layer whenever any leaf is pseudo-Spilman, although such leaves have no layer of their own, and it has no confirmation allowance [C: `src/factory.c:4900-4927`]. An output on the path is safe once the member's transaction spending it is buried. The exit is complete, for C5, when the member's channel transaction is buried and every payment in flight has met its own deadline. The member's own delayed output is outside C5: nobody else has a claim on it.

**Accepting a payment.** Only if its deadline is later than now plus exit time plus the time to claim it on chain, plus margin. The schedule must also state the largest exit time at which ordinary senders can still pay the member, since senders limit total timelock.

**Maximum safe absence.** The smallest of all W and R values named under C4 on the member's path, less a margin, and never later than the moment the member must start leaving to meet C5. The schedule engine shows it to the user.

- With fixed levels and one-member pseudo-Spilman leaves it is the channel's revocation window, which the terms set (the design's figure is about two weeks; not measured).
- With a timed layer above the member (none in 1.0.0, owner decision 9; from 1.1.0), it is the same as long as no balance exceeds its capacity, provided section 4.1 rule 3 holds, because every old state is then C4(a) (section 8) [R].
- A member whose balance exceeds its capacity under some live old state (possible only with sales, 1.1.0) has R = one step of that layer, about a day at a 144-block step.

## 8. Timed layers

**Owner decision 9 (2026-11-12): 1.0.0 trees have no timed layers.** This section applies from 1.1.0; its "In 1.0.0" paragraph is kept as the reasoning behind that decision.

**This section is reasoning from the imported code. It has not been checked against the design posts (ZmnSCPxj, Delving topics 1143 and 1242) or by a simulator test.** It replaces draft 2's statement that losing the race is "loss, not delay" for every member, which review 2 (N3) showed to be overstated once rule 3 is applied.

**What the code does.**
- A timed layer orders its states by relative timelock: the delay of state i is step × (states − 1 − i), so the newest state has no delay and can confirm one step before the next older one [C: `src/dw_state.c:9-12`]. Nothing else stops an older state. 144 blocks per step is a setting used so far, not a constant in the code.
- A layer advance moves the state counter, rewrites the spare-liquidity output scripts, and rebuilds every transaction from the same outputs; no output amount changes [C: `src/factory.c:2437-2448` calling `update_l_stock_outputs` at `:431-490`, which rewrites only the spare-liquidity script at `:486`, and `build_all_unsigned_txs` at `:586-620`, which recomputes only the sequence number at `:604`]. So, without sales, a channel's capacity is the same under every state of a layer.

**What an older state that wins costs the member,** when rule 3 holds and the channel on the old anchor carries the current balance:

- max(0, balance − the channel's capacity in that state), plus
- the longer delay of the older state, at most step × (states − 1) for that layer, plus
- the fees of the path it ends up on.

**How C4 classifies an old layer state.** As (a), harmless, when its capacity covers the balance. Otherwise as (c), outraced, with R = one step of that layer.

**In 1.0.0** (no sales), the capacity under an old state equals the capacity under the new one, and a balance never exceeds capacity. So every old layer state is (a). Consequences:

- The race does not set the maximum safe absence (section 7).
- Draft 2's requirement that the member fund the race fee from its own coins is not needed. That removes the collision with owner decision 6 (no on-chain reserve in 1.0.0).
- The exit time must use the slowest live state (section 7).
- **Rule 3 becomes safety-critical.** If the channel engine fails to keep a commitment current on an old anchor and that state wins, the loss is the balance change since the commitment was last updated there. The watch engine must watch every old anchor.
- The cost of rule 3 is one more commitment signature per live anchor on every channel update. The live anchors on a path are one per layer epoch signed so far, bounded by the product of the states per layer on the path [C: `src/dw_state.c:41-43`].
- No 1.0.0 operation that updates a timed layer is yet specified. In the design, layer updates move the host's spare liquidity between members (`KNOWLEDGE-BASE.md` section 3), which is sales work. If 1.0.0 has no such operation, no old layer state ever exists in 1.0.0 and the race does not arise; a timed layer then only lengthens the exit [R].

**In 1.1.0** (sales), a member's balance can exceed its capacity under an older state. For that member the old state is (c), and draft 2's analysis applies: being away, being shown a false chain, or being unable to pay the fee for one step can each cost it the difference. The member then needs the race fee from its own coins (C3), the watch engine and the chain view are safety-critical within hours, and its maximum safe absence is under a day. This matches decision 5's "a member holding more than its coverage keeps a small on-chain coin".

**What stays true in every case.** The host's spare liquidity in an old state is a deterrent only: the member can take it if the host publishes that state, and it is not counted in exit value. An older state that wins delays the exit.

## 9. Restore

The host keeps a copy of each member's backup and chooses which version to return; the user may also keep an export of their own (`DESIGN.md` sections 8 and 9). A backup may be older than rounds the member took part in. Draft 2's C12 protected only factories that existed at the backup's date. These rules replace it.

**R1. Every load from a backup is a restore.** The node knows it is restoring; nothing it reads tells it how old the backup is.

**R2. A new restore epoch at every restore.** The original installation uses epoch 0, written in a `key_epoch` record at the journal's first start. At the first start after a restore, before any key is derived and before any message is sent, the node draws 8 bytes from the randomness port with the **ordinary, untagged** request and takes as the epoch 31 bits of a bijective mix of those bytes with its incarnation (the SplitMix64 finaliser of the bytes XOR the incarnation times an odd constant; the placeholder in `core/gazpacho/node.c` shows it), retrying while it is 0, and saves it at once in a `key_epoch` record, so later backups carry it (`journal.md` section 8). The epoch is not a secret: it is stored and backed up, so it must not be drawn with the secret tag, whose bytes are never journaled (`signing-round.md` section 8; review 3, F3). Every per-lobby key, factory key and contribution key alike, is derived under (epoch, index); 31 bits fit a hardened BIP 32 index. The incarnation never repeats and a restore cannot rewind it (`runner.h`), so a port that repeats its draws after a restore (a machine restored from a snapshot) does not repeat the epoch (PR 9 review round 4, N3). Two restores drawing the same epoch is the only way a key could repeat; for n restores the chance is about n² in 2^32, under one in forty million for ten restores [R].

**R3. Old keys are recovery-only.** Every key derived under an earlier epoch is recovery-only. The key index is never restored backwards into use: a restored node never derives a key it may have used before. A member restored while in an open lobby loses its seat there and must join again with a new key. There is no separate "fresh start" confirmation: the new epoch is enough, and the app simply tells the user that it was restored and which seats were lost.

**R4. Nothing is signed with a recovery-only key** except the recovery procedure (C12; its 1.0.0 part is `exit.md` 5.7). R4 is a consequence of C7's fresh-key rule and needs no step of its own: a replayed proposal names the member's old key, the member's current key for that lobby is absent from it (or the member has no current key for that lobby at all), and the member refuses with `round_abort` reason 12 (`messages.md` section 7.9). It signs no nonce for it. This closes the restart frame of review 2, N1, step 4a.

**R5. A creation round needs a fresh funding output** (C7, "Fresh funding output"). This closes the second tree on an old outpoint, review 2, N1, step 4b: every tree signed before the restore commits to an old key, so it cannot spend an output whose script commits to the new one [R].

**R6. A restore guard record detects stale backups.** A small record holding a write counter, the epochs used, the highest key index allocated under each, and the count of rounds ever started (format in `journal.md` section 8.3). The core puts a `guard` record, with the complete new contents, **in the same save batch** as each `key_index` record (before a key is used) and each `round_started` record (before a round's first contribution). The storage program stores the batch in the journal **and** replaces the guard file, which lives on the device outside the journal in a place a restore never overwrites, and confirms the batch only when both are synced (`journal.md` section 8.3). So the existing runner rule (nothing outward before the save is confirmed) orders the guard before the key's first use and before the first nonce; no new action or port is needed. The guard is also in every export the user holds; it is never only in the host's copy. On a restore, if a guard is found whose counter is ahead of the backup's newest `guard` record, the backup is known to be stale and the app tells the user. If no guard is found, the backup is treated as possibly stale. **The guard only detects; R2 to R5 are what protect.**

**R7. Recovering keys.** The keys of factories joined after the backup can be found again only if the guard, or a later export, holds their epoch. Without one, those keys cannot be re-derived from the seed, and funds in those factories depend on the recovery procedure the host must support. That is listed in section 11.

## 10. The host's side

The host's software runs the same module with the roles exchanged, plus:

**H1. Funding last.** The host signs funding only after every tree transaction is fully signed and verified, and it holds a valid `round_ack` from every chosen member (`signing-round.md` section 4). It signs exactly the funding transaction it sent in the proposal. That transaction spends only segwit inputs, so its txid cannot change between the round and the broadcast.

**H2. Every partial signature is verified** as it arrives, against its sender's key and nonce.

**H3. No credit before it is covered.** The host does not act on an operation for a member until the transactions protecting the host in the new state are fully signed. It gives no channel credit before funding is buried.

**H4. The host always holds its own signed channel state** for every channel on every live anchor, kept current through every update.

**H5. Secrets after, not before.** The host does not reveal an old state's liquidity secret, or revoke its own old channel state, until it holds the new state fully signed.

**H6. A deadline for forcing out.** For every member, the host knows the date by which it must start publishing that member's path so that it resolves by real balances before any pre-signed payout becomes valid: the payout's lock time, less the full exit time, less a margin. It stops extending credit to a non-cooperating member before that date. H6 applies only once an end-date payout exists; 1.0.0 has none, and H17 below takes its place.

**H7. A fee reserve.** The host holds on-chain coins sufficient to add fees to every path it may have to publish.

**H8. Rounds one at a time per subtree.**

**H9. A member who never completes the first channel exchange** is treated as absent from the start: its seat gets no credit and is forced out under H6.

**H10. A cap on HTLCs.** The host refuses an HTLC that would take its commitment beyond the relay size limit for its transaction version. Otherwise a member can fill the commitment with small HTLCs, go silent, and leave the host with a commitment it cannot relay (review 2, N19, from the SuperScalar payout review).

**H11. A new funding outpoint after any release.** An attempt that follows one in which any partial signature was released uses a new funding transaction. The new one spends at least one input of the previous one, so that once it is buried the previous outpoint can never exist and every member's records for it end under C4(d).

**H12. Results are kept and answered.** The host keeps, for each member and round, the bytes of every `round_tier_result` and `round_complete` it sent, until the factory's funding output is spent or the creation is dead under C4(d). It answers `round_status_request` with them.

**H13. A restored host never resumes a round.** A host loaded from a backup starts new attempts only, with new random values; it never contributes again to a round identifier found in its records.

**H14 to H18** are specified in `spec/exit.md` section 9 (proposed, owner to confirm), and listed here so that this section names every host rule:

- **H14.** The host watches every member's channel output and answers a member's revoked commitment with the penalty by `penalty_send_by`, at its own constants.
- **H15.** The host's sweeps of outputs it may take alone follow a schedule; it never sweeps an unpublished tree output with an owed member below it.
- **H16.** The host never replaces the funding transaction by fee; it bumps it only by a child on its own change output (or a P2A of the funding's own), which the funding must therefore have.
- **H17.** With no end-date payout (1.0.0), the host's software never takes a member's balance through a timeout: it forces a silent owed member out with its own latest commitment by `host_force_by`.
- **H18.** The host's expiry delta toward a factory member, and its go-on-chain height for each payment it offers that member, cover that member's whole path, its own commitment and its HTLC-timeout transaction: (n + 1)·A + (B − 1) + M_host with n = d + 3.

## 11. What this rule does not protect against

- **Being ignored.** A host can refuse service. The remedy is to leave.
- **A withheld or lost round result.** The member stays paused on the affected channels and must exit after its unfinished deadline, at its own cost in fees and time (section 4.1 rule 5).
- **A withheld cooperative close.** It stays in the exposed set, so by C13 the member refuses further payments on that channel and must exit. This is a cheap lever for a host.
- **Losing a race in a timed layer,** for a member whose balance exceeds its capacity in an older state (1.1.0), through absence, fees or a hidden transaction. And, for every member below a timed layer, a channel engine that fails to keep an old anchor current (section 8).
- **A false view of the chain** for longer than the maximum safe absence. The exit's tip estimate never freezes (`spec/exit.md` 4.5: it advances with the clock), so a hidden chain makes the exit start early, not late; but a member whose every server is hostile (an eclipse) cannot broadcast through them either. A broadcast-only route independent of the view's servers is recommended, not guaranteed.
- **Fees far above what the member can fund**, including fees above what the tree's anchors pay when the member holds no on-chain coin (`spec/exit.md` 6.5).
- **Pinning of a keyless anchor.** Anyone, the host in particular, can spend a tree transaction's pay-to-anchor output first with a large low-rate child: for about 10,000 sat on a version-2 tree and about 234 sat on a TRUC tree. A member without on-chain coins then cannot replace it, and its step can be held back while blocks clear above about 0.2 sat/vB. A member without coins confirms in calm conditions unless someone pays to stop it (`spec/exit.md` 6.5).
- **A wallet left locked past `unlock_by`** with a factory balance: the locked watcher publishes the tree path but cannot publish the member's own commitment (`spec/exit.md` 5.6). After H_leaf a dishonest host takes the balance. An honest host closes with its own commitment by `host_force_by` (H17), and the balance then waits in the member's output, with no deadline, until the unlock.
- **A penalty file cut while locked** (or replaced by an older copy) by anyone who can write the data folder, which needs no key: the locked watcher detects it, reports it (`penalty_file_short`, `at_risk`) and keeps answering with the penalties it still holds, but a host that publishes one of the newest revoked states while the person stays locked past that state's revocation window takes that channel's balance (`storage-encryption.md` 8.7.4 rule 7, 8.7.5). Not detected at all if the OS key store is rolled back with it.
- **A locked wallet with no watch-and-exit bundle** ("maximum privacy", no OS key store, or Slice 1): nothing is published while locked.
- **A breach while locked, for the payment outputs.** Penalties against the host's second-stage payment transactions cannot be pre-signed; a member that stays locked for the revocation window after such a transaction confirms loses those payment outputs, at most the sum of the payment outputs of the revoked state (`spec/exit.md` 4.4).
- **Loss of the held set or the exposed set.** Losing the record of what was signed is as serious as losing the transactions.
- **A host that returns an old backup.** Section 9 stops it from getting a second tree or a second nonce. It does not stop the member losing sight of factories joined after the backup, whose keys it may not be able to re-derive (R7). Nor does the backup hold the **held set** of those factories, the signed tree the member needs to leave alone: in 1.0.0 that is a loss of funds unless the host or another member hands the signed tree back, not only a denial of service (review 3, F16). Not relevant in Slice 1, where nothing is owed.
- **The same key running on two devices.**
- **A copy of a running program** (a snapshot or a fork) that repeats a one-time signing secret.
- **Funding that is reorganised away** after it was buried to the member's chosen depth.
- **A chain reorganisation that changes which leaf link confirmed** (1.1.0, if leaf chains are used).
- **Relay rules** that keep a pre-signed transaction from spreading, or let someone obstruct it (pinning, above, is the known case).
- **A fixed pre-signed payout that is smaller than the member's balance,** if the member did not exit first.
- **Bugs in the imported tree builder** that make two honest parties build different trees.
- **Someone tying up the member's receiving capacity.**
- **Privacy.** The host sees its members' payments, membership and network addresses.

## 12. Slice 1 profile

Slice 1 (`docs/SLICES.md`): one host and at least three members, on separate processes on signet, form a factory; the host funds last; the funding confirms; a member whose conditions are not met refuses. No payments, liquidity changes, rotation, exits, Lightning node or Nostr. This follows review 2, section 5.

| Part | In Slice 1 | How |
|---|---|---|
| Section 2 terms, held and exposed sets | Yes | The exposed-set store is real and durable from the start, although nothing is owed |
| C1 | Yes | Including duplicate keys, explicit settings and the funding-script check |
| C2 | Yes | The member's leaf; the distribution output only if the distribution transaction is signed |
| C3, C4 | Degenerate | Owed is zero, so both pass. The code still records which branch applies to each exposed transaction, and C4(d) is used to end records |
| C5 | Reduced | Enumerate every script, anchors included. The real test is C8's "timeout past or too close", using the summed timelocks |
| C6 | One tier | — |
| C7 | Yes | Record before the first partial signature; one tree per outpoint; fresh funding output |
| C8, C8a | Yes | The "member whose conditions are not met refuses" test. Every row of the table; K = 1; every leaf a one-member pseudo-Spilman leaf; all levels fixed (D); anchors on; no hashes |
| C9, C13 | No | No channels or payments |
| C10 | Yes | One open round per output; a creation touches only its funding outpoint and tree; abandonment and death release it |
| C11 | Yes | Exact output, amount and script buried, through the chain port comparing two servers; funding deadline; time checks again on late funding |
| C12, section 9 | Yes | Restore epochs, the fresh-key rule, the guard record and guard file. The recovery procedure is not needed: a restored Slice 1 node never derives an old key |
| Sections 4, 6, 8 | No | — |
| Section 7 | Exit-time sum only | For C8's "closer than exit time plus margin" |
| H1, H2, H8, H11, H12, H13 | Yes | H1 triggered by `round_ack` |
| H3 to H7, H9, H10 | No | No credit and no channels |
| Section 13 tests | For C1, C2, C5, C7, C8, C8a, C10, C11, C12, H1, H2, H8, H11, H12 | Including "two trees on one funding output", with and without a restore |

**Slice 1 values** (each **proposed, owner to confirm**; the owner has not objected to any):

1. **No distribution transaction in Slice 1.** The creation round signs tree transactions only. A Slice 1 member refuses a proposal that carries one (`messages.md` record 44). So nothing pre-signed can overtake the host's timeout recovery (point 2), and C2 and C5 have no payout to cover.
2. **The host recovers its signet coins through a short factory life and the existing host timeout.** The terms give a short life (T1: 144 blocks plus 36 of wind-down, about a day and a half on signet), so the end height is near. Every tree output carries the host-only timeout leaf [C: `src/factory.c:1632-1644`, `:199-214`]: an output feeding a kickoff at depth j times out at E − 5·(2j − 1), and a leaf transaction's input and channel output at E − 10·d (C5); the root kickoff, which spends the funding output on its key path, has none. The root's own outputs feed depth 1, so they time out at E − 5. After a factory, the host publishes the root kickoff from its held tree and, once the end height less 5 blocks has passed, sweeps each of the root's outputs alone through its timeout leaf: for up to 4 members that is the root plus one sweep of two outputs, a few hundred vbytes at 0.1 sat/vB. Members, owed zero, lose nothing. No cooperative close is added to Slice 1. An end height of 0 is still not an option: the import then builds no timeouts (C5).
3. **Burial depth: 3 blocks on signet** for C11, as seen by both chain servers of the chain view (`docs/CHAIN-SERVERS.md`). Signet is mined by a fixed signer set, so a reorganisation deeper than a block or two is not expected, and 3 keeps a Slice 1 run to about half an hour after broadcast.
4. **Funding deadline: 36 blocks** after the block that was the member's chain tip when it sent `round_ack`. The host broadcasts as soon as it holds every ack; at 0.1 sat/vB, on signet, the funding may wait several blocks, and 36 (about six hours) leaves room for that and for a host restart and rebroadcast, while staying far inside T1's life: funding buried at the deadline still leaves over 100 blocks before the leaves' timeouts, so the C11 re-check passes.
5. **Unfinished deadline: one signing budget** (the terms' `signing_budget_ms`, 10 minutes in T1) on the member's own clock, counted from when the member sent its partial signatures. Within the budget the host may legitimately still be collecting, combining or resending results (`round_status_request`); past it the host's own terms say the round is over. A creation round still Unfinished then becomes **Abandoned** (there is nothing to exit, since nothing is owed until funding is buried); its records stay, and it becomes Dead if a funding input is spent elsewhere.
6. Confirmation allowance per transaction for the exit-time sum (section 7, open point 7): A = 6 blocks, with burial B = 3 and the margin M = 14 blocks of `spec/exit.md` 4.3 (M_safe 6, M_lag 2, M_spike 6), judged against H_leaf = E − 10·d. For Slice 1's C8 check this gives `leave_by` at E − 50, E − 66 and E − 82 at depths 1, 2 and 3, which T1 passes with room to spare (vectors X3). Draft 4 said a margin of 6 against the end height; both were too loose.

## 13. How it is tested

For every check C1 to C13, C8a and H1 to H13:

1. A simulator scenario where the other side sends a request that violates the check. The software must refuse and its sets must be unchanged.
2. The same scenario with the check switched off. The simulator's independent accounting, which replays what each party could actually publish, must then show a loss, or for a liveness rule the failure it exists to prevent.
3. Honest scenarios for each operation, which must still succeed.

Named attack scenarios that must each be a test:

- two trees on one funding output;
- **the same after a restore from a backup older than the first tree** (review 2, N1): a replayed proposal and a second tree on the same outpoint are both refused (reason 12), and no second nonce is signed for the old identifier;
- the same with the backup's journal damaged instead: a flipped bit in a confirmed `exposure` entry stops the start (`journal.md` section 5), rather than being cut away;
- a tree whose shape gives a multi-member leaf, or a one-member leaf that is not pseudo-Spilman: refused by every member (C8 leaf kind);
- a host that pays one member's channel below `channel_sat`, or proposes a funding amount or fee other than the terms' rule: refused;
- a retry after a partial-signature failure, on a new outpoint spending an input of the old funding transaction: accepted, not refused by C10;
- funding buried after the funding deadline: live only if the time checks pass again;
- a funding script that is not the aggregate of the participants;
- a retry after a failure in the partial-signature step: refused on the old outpoint, accepted on a new one; a retry after a failure in the nonce step: accepted on the same outpoint;
- a proposal whose values differ from the frozen terms;
- a tree with anchors (accepted) and a tree with an unrecognised spending path (refused);
- a distribution transaction whose lock time is before the end height, or whose share for the member is below its capacity;
- a withheld cooperative close published later;
- a stale channel state on an old anchor;
- an old layer state against an absent member, with rule 3 kept (no loss in 1.0.0) and with rule 3 broken (loss): the test that checks section 8's reasoning;
- two overlapping rounds on one subtree;
- a timeout in the past; a reused penalty hash; a node hash at index 512 or more;
- a host that never funds: the record ends when a funding input is spent elsewhere;
- a silent member at the end date; a member exiting on the first day.

The simulator's accounting computes exit value independently of this module, from the transactions alone.

## 14. Open points

**For the owner**

1. Closed by owner decision 9 (2026-11-12, `docs/ux/decisions.md`): no timed layers in 1.0.0; they arrive with 1.1.0 and liquidity sales. Still to do: a simulator test that no 1.0.0 operation advances a layer. The reasoning that led there, kept for 1.1.0: **Timed layers and absence** (restated after review 2, N3). If section 8's reasoning holds, in 1.0.0 an old layer state never costs a member its balance, provided the channel engine keeps every old anchor current. Then the trade-off is not draft 2's "watched within a day, or a much longer step, or no timed layers". It is:
   - timed layers cost a longer worst-case exit (up to step × (states − 1) per timed layer), one more commitment signature per live anchor on every channel update, and a watch engine that watches every old anchor;
   - fixed levels only cost nothing of that, and keep one anchor per channel, which makes the channel engine simpler;
   - no 1.0.0 operation that updates a timed layer is specified yet; without one, a timed layer only lengthens the exit.

   Before deciding: check the reasoning against ZmnSCPxj's text and the named simulator test. For 1.1.0 members above their coverage, draft 2's options return.
2. **Free seats and the end-date payout.** Owner decision 10 (2026-11-12): seats are free in 1.0.0, then a proof of a coin or channel, then a per-lobby choice. The concern below stands for the proof step, which should land with the end-date payout. Once members are paid their channel's capacity at the end date, a seat that costs nothing and stays silent takes the host's capital unless the host forces it out on chain, at the host's expense. A deposit or another cost per seat becomes a precondition for that payout, not an extra.
3. **The Slice 1 decisions** in section 12.

**To settle by reading or measuring**

4. ZmnSCPxj's own text on channel states across a tree change, and on the penalty for a one-member leaf. Both reviews worked from summaries.
5. Relay rules for the pre-signed transactions, and whether they can be obstructed.
6. Whether senders' limit on total timelock leaves room for a payment to a member whose exit takes six to nine days.
7. The confirmation allowance per transaction, which is the largest unknown in exit time.
8. Whether the restore guard can live somewhere a lost phone does not take with it, beyond the user's own export.
9. Closed: `THREAT-MODEL.md` now says the journal is not encrypted in Slice 1 and lists the missing tests for two trees on one output (review 3, F16).

Closed since draft 3: former open point 9 (`KNOWLEDGE-BASE.md` section 5 and `DESIGN.md` section 6 corrected after review 3, L6) and former open point 10 (`messages.md`, `terms.md` and `journal.md` draft 2 follow this draft). The Slice 1 decisions of section 12 are now proposed values.

Closed since draft 2: former open point 3 (how value moves into a one-member leaf: it does not, section 4.2) and former open point 4 (timeout order: C5).
