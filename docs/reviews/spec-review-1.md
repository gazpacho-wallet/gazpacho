# Review 1 of the safe-to-sign rule and the signing round

2026-11-11. Adversarial review of `spec/safety-rule.md` (draft 1) and `spec/signing-round.md` (draft 1), read against `docs/KNOWLEDGE-BASE.md`, `docs/DESIGN.md`, `docs/LOBBY.md`, `docs/TESTING.md`, the two hand-off notes, `docs/notes/tree-scale-check.md` (from branch `m1a-core-skeleton`), and the imported `factory.h`, `musig.h`, `musig.c` and parts of `factory.c`. Nothing was built or run.

Every statement below carries one of three marks:

- **[S]** verified today in a primary source that I fetched (link given in section 7);
- **[C]** read today in the imported code or the project documents (file and line given);
- **[R]** my own reasoning, not confirmed by a source or a test.

Where I rely on memory of a source I did not fetch, I say so.

## 1. Verdicts

**`spec/signing-round.md`: sound with changes.** The MuSig2 usage is essentially correct and the statements about BIP 327 are accurate with three inaccuracies (section 7). The protocol around it has real gaps: the round identifier is under-defined, a restart can make an honest party look like a cheat, the message flow contradicts check C6 of the other document, section 8's argument is wrong for timed layers, and three attempts will not converge at 512 members. None of these needs a different cryptographic design. All of them need text before code.

**`spec/safety-rule.md`: needs rework.** The one-sentence rule is the right goal. The checks do not yet deliver it. The rule reasons about the transactions the member *holds*, while the adversary can publish every transaction the member ever *contributed a partial signature to*. It says nothing about what happens to the channel's own commitment transactions when the tree under the channel changes. It treats old states in timed layers as "cancellable" when they can only be outraced within about one day at the imported settings. And the definitions of owed, exit value and exit time are loose enough that two implementers would write different code. The host's rules H1 to H4 do not protect a host against free, silent or hostile members once the end-date payout lands.

The four changes I consider necessary before any code is written are listed in section 2 as F1 to F4.

## 2. Findings, most serious first

### Critical

#### F1. The rule looks at what the member holds; the adversary uses what the member has signed

Concerns: safety-rule sections 2, 3 (C3, C4, C7), 4 (creation); signing-round sections 2, 5, 8.

**Scenario: two trees on one funding output.** [R]

1. The host opens creation attempt 1 with participant list L and funding outpoint O. Every member rebuilds tree T1, the checks pass (owed is zero at creation, so C3 and C4 pass for *any* tree), and every member sends partial signatures for all its items.
2. The host now holds a complete T1. It sends no `round_complete`. Members move to Unfinished for attempt 1.
3. The host opens attempt 2 with the same list L and the same outpoint O but different parameters allowed by its terms (amounts, timeouts, shape, liquidity hashes). The funding output script depends only on the aggregate key of L [C: `factory.c:100-118`, the output key is the aggregate of the keys plus a tweak], so T1 and T2 spend the same output. Members rebuild T2, the checks pass again, they sign, and this time the host completes.
4. The host funds O. Members hold T2 and treat the factory as live. They receive payments over Lightning in channels anchored in T2.
5. The host publishes the root of T1. T2 is now void. Members do not hold T1's lower transactions or any commitment transaction under T1. Their balances sit in outputs that need the host's signature, and the host takes them at the timeout branches that exist in the imported tree today [C: `factory.c:199-208`, `:529-548`].

**Why the text allows it.** "Held set" is "every fully signed transaction the member holds". Transactions from an Unfinished or aborted round are not in it, so C4 ("every transaction in the resulting set that the adversary could publish") never sees T1. C7 could stop step 3, but C7 is keyed on "position and state number in the same factory", and "factory" is not defined. If the factory identifier is the lobby or a host-chosen name, C7 does block step 3 but also blocks every honest retry after a failure in the partial-signature step (see F7). If it is anything attempt-specific, C7 does not bind the two attempts at all.

The same hole appears later in a factory's life:

- **A cooperative close that the host does not broadcast.** The member signs a close paying its current balance. The host holds the complete close and keeps it. The member goes on receiving payments. Weeks later the host broadcasts the old close, which pays the old, smaller balance. Nothing in C1 to C9 makes the member stop using a channel after contributing to a close. [R]
- **A host that answers a signed round with `round_abort`.** The member state table has no entry for `round_abort` arriving in state Signed. If an implementer maps it to Aborted, the member forgets transactions the host can complete. [C: signing-round section 5]

**Proposed change.**

1. Add a third set to section 2: the **exposed set**, every transaction for which the member has ever released a partial signature (or a commitment signature), recorded durably *before* the signature is sent. The C7 record becomes this set. Transactions leave it only when an input they spend is spent by a different transaction that is buried on chain.
2. Restate the adversary: it may publish any transaction in the member's exposed set, in any consistent combination. The member may publish only from its held set.
3. C3, C4 and C5 are evaluated with the adversary drawing from the exposed set and the member drawing from the held set.
4. Add a creation rule: **one tree per funding outpoint, ever.** Before releasing any partial signature at creation, the member records the funding outpoint and the digest of the tree, and refuses any different tree for that outpoint.
5. Add an activation rule: the member treats a factory as live only when the exact funding outpoint of its held tree, with the exact amount and script, is confirmed to a depth set by its conditions. The funding inputs are the host's own coins and the host can double-spend an unconfirmed funding transaction at will. [R]
6. State that accepting or making a payment is a "contribution to a signature" and runs the same module. With the exposed set in place, a member holding an unbroadcast close will correctly refuse an incoming payment.
7. In the member state table: once in Signed, no message moves the member to Aborted. Only `round_complete` or on-chain evidence resolves it.

#### F2. Nothing says what happens to the channel's commitment transactions when the tree under the channel changes

Concerns: safety-rule C4, C6, C9, section 4 rows "liquidity change" and "change to a layer above the leaf", open points 2 and 5; signing-round section 8; `DESIGN.md` section 5 (channel engine).

**Fact.** In the imported code a pseudo-Spilman leaf change builds a new transaction that spends output 0 of the previous leaf transaction, which is the channel output [C: `factory.c:623-648`, `:2764-2781`]. So the channel's funding outpoint moves on every leaf change. A state update in a timed layer rebuilds every transaction below it with new transaction IDs, so every channel below that layer also moves. The commitment transactions the two sides hold are anchored to the *old* outpoint. The old outpoint remains spendable by them for as long as the old leaf transaction can reach the chain, which for a pseudo-Spilman chain is always (every earlier link must confirm before a later one).

**Scenario A: stale commitment on the old outpoint.** [R]

1. Member M has a balance of 10 on leaf state k. Both sides hold commitment transactions anchored at leaf transaction k.
2. A liquidity change creates leaf transaction k+1. New commitments are signed on its output. Nothing in either specification says the commitments on k are revoked.
3. M receives 50 more. Only the commitments on k+1 are updated.
4. The host publishes the leaf chain up to k and then its own commitment anchored at k, which pays M 10. It is not a revoked state, so M has no penalty. M loses 50.

**Scenario B: revoked without replacement.** [R] Suppose instead the implementer revokes the commitments on k at step 2. The host publishes the chain up to k and stops. If M can still publish leaf transaction k+1, M is fine. But for a timed-layer update the equivalent is the host getting an *old layer state* confirmed (see F3). Under the old state the channel output has no valid commitment on either side. It sits in a two-party output until the host's timeout branch [C: `factory.c:529-548`] and the host takes all of it.

**Scenario C: the Unfinished member.** Section 8 says a member without `round_complete` "behaves as if only the previous state exists". For a timed layer that is unsafe. The host holds the new state transaction, whose relative timelock is shorter, so the host can make the new state win whenever it likes. A payment M accepts on the old anchor only is lost if the host then publishes the new state. [R]

**Why the text allows it.** C4 says the member "holds what is needed to cancel" a publishable transaction but does not say what that is for a channel whose anchor moved. C6 requires an exit from each *new* output but says nothing about the *old* ones. The interaction is listed nowhere, including the open points.

ZmnSCPxj's post on pseudo-Spilman leaves describes the intended handling as a hand-over modelled on splicing: both ends sign for the old and the new funding outpoints on each commitment update until the new factory state is valid and the old one invalid, and the superseded state is made unattractive by revoked commitments plus a "poisoning" transaction on the host's liquidity. [S, as summarised from topic 1242; I did not read the full text word for word.]

**Proposed change.** Write a section "Tree changes and the channel" before the channel engine is designed. It must fix, at least:

1. **Anchors.** A channel has a set of live anchors (outpoints it could end up funded by). A tree change adds an anchor. Every commitment update is signed for every live anchor with the same commitment number and the same revocation secret, so one revocation covers all anchors.
2. **Retirement.** An anchor is retired only when it can no longer reach the chain, or when both sides have revoked the last commitment on it *and* the member holds a transaction that spends the anchor's parent output to a newer anchor and can always get it confirmed first. For a pseudo-Spilman chain that condition can be met (the member can publish link k+1 as soon as link k confirms). For an old state in a timed layer it cannot be met by cryptography, only by winning a race (F3). The specification must say which choice is made for timed layers: keep old anchors current for the factory's whole life, or accept the race.
3. **Quiescence.** No payment update on a channel while a round that touches its anchor is between "partial signatures sent" and "resolved". The channel engine needs a pause like Lightning's `stfu`.
4. **Unfinished.** A member that has sent partial signatures and lacks the result treats *both* outcomes as live: it keeps both anchors current, or it stops using the channel and exits. "Behaves as if only the previous state exists" is removed.
5. **Order inside a leaf change** (see section 4 of this review).

#### F3. Old states in timed layers are not cancelled, only outraced, and the window is about one day

Concerns: safety-rule C4, section 6, section 8, open point 2; `DESIGN.md` section 6 ("Away protection: about two weeks"); `KNOWLEDGE-BASE.md` section 5.

**Facts.** A timed layer orders states by relative timelock: 432, 288, 144, then 0 blocks, with a step of 144 blocks at the settings used in the scale check [C: tree-scale-check "144 blocks per step, 4 states per layer"; S: topic 1143 gives the same example]. Once the kickoff transaction above a layer confirms, the newest state can confirm one step (144 blocks) before the next-older one. Nothing else stops the older one. ZmnSCPxj's design adds a deterrent: the host's liquidity outputs in an old state can be taken or burned by members who hold a secret released when the state was replaced [S: topic 1143; C: `factory.h:198-212`, `:536-560`]. He states that this protects members only up to the poisoned amount [S: topic 1242, as summarised].

**Scenario.** [R]

1. A layer above M's leaf has been updated once. M holds the new state; the old state is in M's exposed set.
2. M's app is closed for 30 hours. The knowledge base promises "about two weeks to respond to an old state".
3. The host publishes the kickoff, waits for the old state's timelock, and publishes the old state. Alternatively the host only needs M's chain view to hide the kickoff for a day; the default chain view is public Electrum-style servers [C: `DESIGN.md` section 10].
4. Under the old state M's channel is on an old anchor. By F2 it either carries a stale balance or no usable commitment. M can take the host's old liquidity on its leaf with the revealed secret. That amount has no relation to M's balance.

**A second way to lose the race.** M is online, but the newest state transaction carries only its built-in fee. The scale check used 200 satoshis per transaction; test policy is 0.1 sat/vB [C: tree-scale-check inputs; `KNOWLEDGE-BASE.md` section 8]. Members start with no on-chain coins, so M cannot use the anchor output to raise the fee. If the going fee rate is above the built-in rate for 144 blocks, M's transaction does not confirm, and the host, which has coins, attaches a fee-paying child to the old state the moment it matures. Section 8 lists "fees far above what was built in" as a risk of *delay*. In a timed layer it is a risk of *loss*, and the adversary profits from it. [R]

**Why the text allows it.** C4's second branch ("the member holds what is needed to cancel it in time") reads as if cancellation were a thing the member holds. For a timed layer it is an obligation: be online, see the chain correctly, and get a transaction confirmed within one step minus confirmation time. Section 6 counts "the response window for a cancelled channel state" only for the channel. The two-week figure is the channel's delay and has been applied to the whole product.

**Proposed change.**

1. Split C4's second branch in two: (a) *revoked*: the member holds a secret or signature that lets it take the funds if the transaction appears, within a window W it can state; (b) *outraced*: the member must confirm a specific transaction within R blocks of a specific on-chain event. For each transaction in the exposed set the module must name which branch applies and the value of W or R.
2. Define the member's **maximum safe absence** as the minimum over all such W and R on its path, less a margin. The schedule engine shows that number. With the imported settings it is under one day for any member below a timed layer. Either the step is made much longer (which multiplies exit time: three steps per layer), or timed layers are not offered to members who have no always-on watcher, or the two-week promise is withdrawn for layered factories.
3. State plainly in section 8 that the liquidity penalty is a deterrent and is not counted in exit value, or define exactly when it may be counted.
4. Make C3 for a timed layer require that the member's exit fee for the *race* transaction is fundable at a stated fee rate from resources the member actually has.
5. Record that with timed layers the watch engine and the chain view are safety-critical within hours, and that hiding one transaction for a day is enough for theft.

#### F4. Check C6 and the round's message flow contradict each other

Concerns: safety-rule C6; signing-round sections 3, 4, 8, open point 2.

C6 says the member "does not help complete a signature on a transaction that creates an output unless it already holds its own fully signed exit from that output". The round sends *all* of a member's partial signatures in one `round_partial_sigs` message (step 5) and delivers all results in one `round_complete` (step 7). At the moment the member releases its partial signature on a parent it holds no fully signed child. So either every round violates C6, or C6 is read loosely and section 8's claim ("the member's exit from any new output is signed before the transaction that creates it") is not true of the protocol as written. [C]

At creation this does not matter, because nothing is at stake until the factory is funded and confirmed. In later rounds it does: with all partial signatures in hand the host alone holds the new parent and may withhold the children.

**Proposed change.** Give a round ordered **tiers**. Section 4 of this review recommends the order. The engine releases a member's partial signatures for tier n+1 only after the member holds and has verified the final signatures of tier n. Creation may use a single tier because of the activation rule in F1.

### High

#### F5. A restart can make an honest member or host look like a provable cheat; the round identifier is under-defined

Concerns: signing-round sections 2, 6, 7.

**Scenario.** [R]

1. The host sends `round_propose` with attempt number 1. Member A computes `round_id`, generates nonces N1, signs "round_id, N1" and sends it.
2. A's program restarts. Section 6 says "the round is over for that member". A keeps no record of it, because nothing in the specification says the round identifier is saved.
3. The host (or a network replay of the host's message inside a new session) sends the same `round_propose` again. A computes the same `round_id`, generates N2, signs and sends.
4. The host now holds two different nonces for the same round and item, both signed by A. Section 7's table treats exactly that pattern as proof of fault when the host does it. A is framed. The same happens to an honest host that restarts and reuses an attempt number.

**Other gaps in the identifier.** The formula lists "factory identifier" and "digest of every item" without defining either. For the identifier to bind what it must, it needs: a protocol name and version; the chain (genesis hash); the host's long-term key; the digest of the host's signed terms; the funding outpoint and amount; the ordered participant keys; and for every item its index, the outpoint spent, the BIP 341 signature hash, the signing mode (key path with which tweak, or script path with which leaf), and the ordered signer keys of that item. The BIP 341 signature hash already commits to all spent amounts and scripts, all outputs, lock time, sequences, the hash type and the presence of an annex [S: BIP 341, signature message], so "amounts" and "shape" are covered once every item's hash is included and the member has built every item itself. The signer set per item is *not* covered by the signature hash and must be added. The attempt number is chosen by the host and can repeat.

**Proposed change.**

1. Define `round_id` as a tagged hash over the list above.
2. Add a fresh random value from the host and one from each member to the round (the member's goes in `round_nonces`), or require each party to save the round identifier durably before sending its first contribution and to refuse that identifier for ever after. The second is simpler and fits "save before send". A party that has a saved record of a round but no nonces answers only with `round_abort`.
3. `round_propose` and `round_complete` are signed by the host. Without a host signature on the proposal a member's `round_abort` can carry no evidence, and a third party cannot recompute the round identifier.
4. Equivocation counts as proof only for two signed contributions under the same `round_id` *including the party's own random value*.

#### F6. Randomness handed to the core, a journal that replays, and nonces that "are never stored" do not fit together yet

Concerns: signing-round section 6, section 10; `DESIGN.md` section 4.

BIP 327 requires that the nonce be drawn from fresh uniform randomness and says it "must not be derived deterministically from the session parameters because otherwise active adversaries can trick the victim into reusing a nonce" [S]. The design hands randomness to the core as an input so a factory can be simulated from a seed, stores an append-only journal, and rebuilds a node from storage after a failure [C: `DESIGN.md` section 4].

**Scenario.** [R] If the randomness delivered to the core is ever recorded (as a journalled event, in a snapshot, or as the state of a seeded generator) and the node is rebuilt by replay, the core regenerates the same secret nonce. The host then supplies a different set of other nonces. The member signs twice with one secret nonce and its key can be computed from the two partial signatures [S: BIP 327, "possible to extract the secret signing key"]. A virtual-machine snapshot or a forked process produces the same result without any journal.

**A related inaccuracy.** Section 6 says the nonce is generated "together with the member's key, the aggregate key and the message when known". The imported `musig_generate_nonce` passes the secret key, the public key and the key-aggregation cache, and passes NULL for the message and for the extra input [C: `musig.c:463-480`]. Its signature has no parameter for either. So the message-dependent safeguard BIP 327 recommends is not available through the function section 10 names.

**Proposed change.**

1. Add to section 6: randomness used for nonces comes from the operating system at the moment of use, is never written anywhere, and is never produced by a generator whose state is saved or restorable. The seeded source exists only in simulator builds and cannot be linked into a release build.
2. Add to the storage requirements: rebuilding a node from the journal never re-creates a secret nonce; any round found in progress is abandoned (and, by F5, its identifier is refused).
3. Ask the SuperScalar repository (the hand-off already asks for a randomness callback) for a nonce function that also takes the message and an extra input, and pass the round identifier and item index as the extra input. BIP 327 calls this a last resort, not a defence [S].
4. Correct the sentence in section 6 to say what the imported function does today.

#### F7. C7 is too weak and too strict at once

Concerns: safety-rule C7, open point 6.

- **Too weak:** it is keyed on undefined terms and does not survive a restore from a stale backup (the record is gone, the host proposes a different transaction for the same place, the member signs). The host stores the member's backup [C: `DESIGN.md` section 8] and so chooses which version a restoring member gets. [R]
- **Too strict:** it refuses honest repeats. The imported cooperative close sets the lock time to the current block height [C: `factory.h:1087-1106`]. A close retried one block later is a different transaction for the same position, so C7 refuses it for ever. A leaf change retried with a different amount after a lost message is refused for ever. If "factory" means the lobby, every creation retry after a failure in the partial-signature step is refused. [R]

**Proposed change.** Replace C7 with the exposed-set rule of F1. Two different transactions spending the same outpoint may both be signed if and only if C3 to C5 hold with *both* in the exposed set. Two cooperative closes that pay the member the same amount pass. Two leaf changes that both keep the balance pass. Two creation trees on one funding outpoint fail by the explicit rule in F1. Add: after a restore, the module refuses every request in a factory that existed before the restore, except a close or exit that the specification defines for that case. On open point 6: a record may be discarded only when an input of the recorded transaction has been spent by another transaction that is buried.

#### F8. The host's rules do not cover free, silent or hostile members

Concerns: safety-rule section 7 (H1 to H4), open point 3; `LOBBY.md` ("Nobody has money at risk in a lobby").

The agreed second round of tree changes pays, at the end date, each member "their full initial channel capacity" and gives the host's spare liquidity "to the members under that node" [C: `RECORD.md` line 391]. Members join at no cost and identities are free [C: `LOBBY.md`].

**Scenario: the silent member.** [R]

1. An attacker fills k seats with fresh identities, signs creation honestly, and never connects again.
2. Each seat's channel holds only the host's money. At the end date the payout gives all of it, plus the leaf's spare liquidity, to the seat.
3. To avoid that, the host must put each silent seat's whole path on chain, get its own commitment transaction confirmed (this is what H4 is for), and do so early enough for every timed layer on the path to run out. At 512 members with the shapes in the scale check that is 6 to 9 days of timelocks plus confirmations per path [C: tree-scale-check, 864 and 1,296 blocks]. The host pays every fee.
4. The attacker's cost is zero. The host's cost is on-chain fees for k paths every factory, and loss of the capital in any seat it fails to evict in time, for example in a fee spike.

**Scenario: exit as vandalism.** [R] A free member exits alone on day one. That publishes the root and the upper levels of the tree. Every transaction's fee is built in "from the host's side". Timed layers on the published path now have to be resolved on chain by someone, and liquidity can no longer be moved at those levels for the rest of the factory's life.

**Scenario: stalling.** A member who sends nonces and never sends partial signatures costs one attempt. With three attempts, three identities acting in turn cancel a 512-member creation (see section 5 of this review).

**What is missing.** A deadline rule (the host starts forcing out a non-cooperating member no later than the end date minus the full exit time minus a margin, and stops giving that member credit before that). A fee-reserve rule (the host holds on-chain coins sufficient to fee-bump every path it may have to publish). A rule that the host gives no channel credit before funding is buried. A rule that the host does not release an old-state secret, or revoke its own old commitment, before it holds the new state fully signed (the mirror of F2). A rule for a member who never completes the first commitment exchange. And an economic defence against free seats: the deposit that `LOBBY.md` places "in the release after the first" is, on this analysis, a precondition for the end-date payout, not an extra.

#### F9. Rounds that overlap are checked one at a time

Concerns: signing-round sections 1, 5; safety-rule section 3.

The host may run rounds in parallel. MuSig2 itself is secure under concurrent sessions [S: MuSig2 paper abstract]. The safe-to-sign check is not: it evaluates each request against "the held set as it would be if the request completed", one request at a time.

**Scenario.** [R] Round A updates a layer and re-signs M's subtree with M's leaf at chain position k. Round B, in parallel, is a liquidity change taking M's leaf from k to k+1 under the *old* layer state. Each passes alone. After both, the new layer state contains no k+1. If M paid for the liquidity, the host publishes the new layer state and keeps both the payment and the liquidity.

The imported code also keeps a single signing session per tree node [C: `factory.h:173-175`], so two rounds on one node cannot be run on one `factory_t` at all.

**Proposed change.** A member takes part in at most one unresolved round per outpoint it has an interest in. A second proposal that touches an outpoint of an unresolved round is refused. The host serialises rounds per subtree. With the exposed set of F1 this follows from the rule; it should still be stated as a protocol rule so the engine refuses early.

#### F10. The proof-of-fault scheme: what it does and does not prove

Concerns: signing-round section 7, open points 1 and 3; `LOBBY.md` ("A wrong partial signature can be proven to anyone").

I could not make the host frame an honest member for a *bad partial signature* as long as (a) every nonce is signed by its owner under a properly bound round identifier and (b) the member's partial-signature message names the nonce set. The member's partial signature verifies against the set it named; a third party can check that. The weaknesses are elsewhere.

1. **The restart frame** (F5).
2. **The named digest has no defined opening.** A dishonest member can sign a partial-signature message naming a digest D' of a set that never existed and claim the host sent it. The host cannot prove what it sent. Rule needed: whoever names a digest must be able to open it to a set of nonces each validly signed under that round identifier. If the member cannot, the member is at fault. If it can, some signer signed two nonces for one item and that signer is at fault. The digest function (order, encoding) must be specified. [R]
3. **A host with one seat of its own is never caught.** The host gives member A a set containing nonce N' from its own seat C, and everyone else a set containing N. A's signature fails against the common set. A opens its set, C is shown to have equivocated, and the blame lands on a free identity. The table's row "the host gave different members different nonces" only catches a host careless enough to equivocate under its own key. [R]
4. **"Silence" is not the only unprovable fault.** Also unprovable to a third party: the host not sending `round_all_nonces` or `round_complete`; the host sending wrong final signatures (unless `round_complete` is signed); a proposal that fails a member's checks (unless `round_propose` is signed); a contribution that is malformed or carries a bad signature (the transport authenticates it to the host only); anything that arrived late; and a member whose software built different transactions and so signed a different round identifier, which is a disagreement, not a provable fault, unless the third party rebuilds the tree from the signed proposal. A host can also *assert* silence about any member and exclude it; member apps that keep "who stalled" histories [C: `LOBBY.md`] must record that as the host's claim.
5. **What a third party must be given and do.** The host-signed proposal (or the full preimage of the round identifier); for the item in question the ordered signer keys, the tweak or script leaf, and the signature hash; every signer's signed nonce for the item; the accused's signed partial-signature message. It must check the signatures, check that the digest opens to that set, recompute key aggregation and the session values, and run BIP 327's `PartialSigVerify`. That is a real program, not a glance.
6. **What it reveals.** The full list of participant keys of the item, hence the membership of the factory or branch, and hashes that identify the tree. Publishing evidence has a privacy cost that should be stated.
7. **What it is worth.** Member identities are new per lobby by default [C: `LOBBY.md`]. Proving that a throwaway key misbehaved is of use only inside that lobby. Proof against the host's long-term key is the valuable half, and item 3 shows the host can avoid it.
8. **A valid partial signature does not prove participation.** BIP 327 states that partial signatures "are not signatures" and can be forged by an adversary that controls another signer and chooses nonces [S]. Only the signed contribution proves authorship. Evidence must never rest on a partial signature alone.
9. **The contribution key.** In the imported code a member's factory key is also used directly as the key of single-signer outputs: the liquidity penalty and the distribution transaction pay to an output "keyed on that signer's xonly pubkey" [C: `factory.h:536-541`, `:1258-1261`]. So the same key would sign protocol messages, take part in MuSig2, and later sign an ordinary taproot spend. BIP 340 advises separating contexts by partitioning the message space and notes the safest course is not to reuse a key across schemes [S: BIP 340, "Domain Separation" and the nonce-generation remarks]. BIP 327 is silent on using an individual key for other signatures [S]. I know of no attack on BIP 340 signatures and MuSig2 partial signatures under one key when the BIP 340 messages are tagged hashes that cannot equal a taproot signature hash, but I know of no proof either. [R] Recommendation: sign contributions with a *separate* key (the Lightning node key that already authenticates the connection, or a key derived for the purpose), bound to the factory key once, in the lobby, by one statement signed with the factory key over a tagged hash. Every contribution message is a tagged hash with a Gazpacho-specific tag. This also answers open point 3.

#### F11. "Rebuilt, not received" still depends on numbers the host supplies

Concerns: safety-rule C1, C2, C5, C8.

The member rebuilds the transactions, but from parameters. Several parameters decide who else can spend an output: each node's absolute timeout [C: `factory.h:163-166`], the delay on the host's liquidity output [C: `factory.h:429-432`], the hash committed in each liquidity output, which the host sends because the member cannot derive it [C: `factory.h:389-398`], the fee per transaction, whether anchors are used, the number of fixed levels, the step and the number of states per layer.

**Scenarios.** [R] A timeout already in the past gives the host an immediate sole spend of that output. A liquidity hash for which the host later reveals no preimage leaves the old state unpunishable. The same hash used for two states means revealing one secret exposes the current state (a loss for the host, and a sign of a broken host). For node indexes of 512 and above the imported builder ignores the supplied hash [C: hand-off note, section 9 item 6], so member and host build different leaves in any tree over about 130 members.

C8 says the parameters must "match the host's signed terms". The terms are the host's; matching them proves nothing about safety.

**Proposed change.** C5 is computed from the *scripts of the rebuilt transactions*: the module enumerates every spending path of every output on the member's path and classifies each (all sign; host after height H; host after delay D; member alone; hash-locked). An unrecognised path fails the check. C8 becomes: every parameter is inside the range set by the member's own conditions. Add: a superseded state counts as covered only after the member has checked the revealed secret against the hash in the output *it built*, and holds the fully signed penalty transaction for it.

### Medium

#### F12. The definitions of owed, exit value and exit time

Concerns: safety-rule sections 4, 5, 6. Each item is a place where two implementers would differ. [R unless marked]

**Owed.**
- Not stated whether owed is before or after the channel reserve, the commitment fee and anchor amounts.
- "Liquidity change: the same channel balance as before." In the imported code each leaf change deducts the transaction fee from the channel output [C: `factory.c:2773-2777`]. Someone's balance falls. The row must say whose, and that a fee the member agreed to is allowed.
- "Rotation: the same total … at every step" leaves no room for routing or service fees and treats a payment in flight between the two factories as if it were settled.
- "Payments in flight the member can claim": an outgoing payment in flight is neither owed nor not owed; it is conditionally owed back. The table needs both directions.
- Owed comes "from the member's own records". After a restore those records may be old. The rule needs a statement for that case (F7).

**Exit value.**
- Step 1, "the newest fully signed transaction at each position", is wrong for a pseudo-Spilman leaf, where the exit is the *whole chain* of leaf transactions, each with a fee, and grows with every liquidity change. It is also wrong for a timed layer, where the adversary chooses whether the race is run.
- Step 3 subtracts "any fee the member must add". A member with no coins cannot add any. Value that can only be reached with coins the member does not have should count as zero.
- Payments in flight need second-stage transactions with their own fees; small ones are not claimable on chain at all. Neither is mentioned.
- The end-date payouts are new members of the held and exposed sets. At the payout's lock time *any* party under that node can publish it. A member whose balance exceeds its fixed payout share then receives less than it is owed. So C5's bound does not go away when the host's timeout branches go; it moves to the earliest payout lock time on the path. Open point 3 should say this.
- Step 5 takes "the lowest result … after the member's best available response". The response must be limited to what the member can do within its stated maximum absence and fee means (F3).

**Exit time.**
- "Counted from now" is in blocks and must be compared with absolute heights; the confirmation allowance per transaction is undefined and is the largest unknown in the sum.
- When is an exit complete? Section 6 adds "the response window for a cancelled channel state". If the channel's own delay (about two weeks) must finish before the bound in C5, then with 6 to 9 days of layer timelocks a member would have to start leaving a 30-day factory in its first week. The competing claims in the imported tree are on the tree outputs and the channel output [C: `factory.c:199-208`, `:529-548`], not on the member's delayed output of its own commitment transaction. Proposed definition: an output on the path is safe once it is spent by the member's transaction and that transaction is buried; the exit is complete for C5 when the commitment transaction is buried and every in-flight payment's own deadline is met. The member's delayed output is outside C5.
- The imported delay functions under-report on deep trees [C: hand-off note section 9 item 3]. The specification should say the module sums timelocks from the transactions, as the scale check did.
- The rule for accepting a payment ("deadline later than exit time plus margin") collides with the limit on total payment timelock that senders apply. The imported header cites a 2,016-block ceiling [C: `factory.h:848-850`; I did not check the Lightning specification for it today]. An exit time of 1,296 blocks leaves little room; the specification should state the largest exit time at which a member can still be paid by ordinary senders.

#### F13. Scale

See section 5. In short: three attempts do not converge at 512 members, the root item's nonce set with signatures does not fit one Lightning message, and each member downloads on the order of 100 to 150 KB per attempt.

#### F14. Hazards in the imported functions the round engine will call

- `musig_session_set_pubnonce` increments a counter on every call and does not check whether that signer's slot was already set [C: `musig.c:307-321`]. Setting one slot twice and another never satisfies the "all nonces collected" test with an unset nonce in the array. The engine must track slots itself and must treat duplicated `round_nonces` as an error before calling in.
- Library argument errors in libsecp256k1 call an abort handler by default (from memory, not checked today). A malformed nonce or signature from the network must be parsed and rejected before it reaches a session function.
- The engine, not the imported code, must reject duplicate participant keys. BIP 327 allows duplicates and leaves the choice to the application [S]. Here a duplicate would mean two seats with one key, which breaks blame and payout accounting.
- The engine must fix the signing mode: 64-byte signatures, default hash type, no annex. BIP 341 commits to the hash type and to the presence of an annex in the signature message, so a signature made this way cannot be reused with an annex or another type [S]. The imported code also contains an `ANYONECANPAY|ALL` signature-hash routine [C: `tapscript.c:663-679`]; no round item may use it.
- The penalty transaction is signed on a script path under the *untweaked* aggregate key [C: `musig.h:186-195`]. Section 1's definition of an item needs a signing-mode field, and the round identifier must include it (F5).

#### F15. Additions to section 8, "what this rule does not protect against"

Missing from the list: losing a race in a timed layer (absence, fees, or a hidden transaction), which is loss and not delay; a host that returns an old backup; funding that is unconfirmed or reorganised away; transaction pinning and relay policy on the pre-signed transactions (the imported builder writes version 2 transactions with a keyless anchor [C: `tx_builder.c:77`; I did not determine which nodes use which version]); the same key or seed used on two devices; a chain reorganisation that changes which leaf link confirmed; the fixed end-date payout paying less than a member's balance; denial of service that locks a member's *incoming* capacity; the secret-nonce exposure of F6 (snapshots, forks); bugs in the imported builder that make two honest parties build different trees; and the host learning members' network addresses and membership (already half-covered by "privacy").

### Low

- Signing-round section 4 step 5 says the member "confirms its own nonces are included unchanged". It should also say the member rejects a second `round_all_nonces` for the same round, and that a re-sent `round_partial_sigs` after a reconnect is the *saved bytes*, never a new signature. The saved record therefore has to include the partial signatures.
- `round_complete` carries "the final signatures for every transaction on the member's exit path". It must also carry the payouts, the penalty templates and anything else the member's exposed-set analysis relies on. Section 11a says so for payouts only.
- Section 9: a member's deadline runs on its own clock. A network attacker who delays messages can push chosen members out of an attempt. That is denial of service only, but it lets an attacker choose who is in a factory.
- TESTING invariant 3 ("no party signs two different states with the same number") should be restated to match F7.

## 3. Each operation: what the member holds, what the adversary can publish

All [R], on the assumption that F1 to F4 are adopted. "Adversary" is the host with every other member.

| Operation | Member holds before | Exposed after | Worst the adversary can publish | Member exits whole and in time? |
|---|---|---|---|---|
| **Creation** | Nothing | One tree on one funding outpoint; initial commitments | Never fund; fund a different output; double-spend funding | Yes, trivially: owed is zero. Needs the one-tree rule and the activation rule (F1). The host must not be able to give credit before funding is buried |
| **Payment** | Tree, commitment n on every live anchor | Commitment n+1 on every live anchor; n revoked | Tree path plus any commitment the host holds | Yes if commitments are kept in step on every live anchor (F2) and the deadline rule uses the F12 exit time. Fee for second-stage claims is open |
| **Leaf liquidity change** | Leaf chain to k, commitments at k | Link k+1, commitments at k+1, payout and penalty for the new outputs | Chain to k then a commitment at k; chain to k+1 with nothing below | Yes only with the order in section 4 and a defined retirement of anchor k. Each change lengthens the exit and costs a fee from the channel output |
| **Layer state update** | Old state and its subtree | New state and its whole subtree, for every member under the node | Either state, forever. The old one wins if the member is absent, cannot pay, or cannot see the chain for one step | **Not guaranteed.** Depends on the race (F3). Old anchors must stay current or the loss is total |
| **Rotation by paying across** | Balance in the old factory; complete, funded, buried new factory with enough incoming capacity | A payment in flight from self to self through the host | Stall the payment until near its deadline; publish either tree | Yes if the member knows the secret, both deadlines clear both exit times, and the old factory has that much life left. Fees must be allowed in "owed" |
| **Rotation by closing into the new one** | Old tree | A close that spends the old funding output into the new funding output; a complete new tree under it whose first commitments carry the members' balances | Publish the old tree instead of the close; hold the close and publish it later | Only if the new tree and its commitments are fully held before any partial signature on the close, the channel is frozen from that moment until one of the two is buried, and all signers of the old root take part. "Members start at zero" does not hold for this tree |
| **Cooperative close** | Tree and commitments | The close | Hold the close and publish it after the balance has changed | Yes if the channel is frozen from the first partial signature on the close until the funding output is spent (F1) and nothing is in flight (C9) |
| **Another member's leaf** | Unchanged | Nothing, if the member is not a signer | — | Yes. If the change is a layer update the member *is* a signer and the row above applies |

**Host-favouring timeout branches today.** Every tree output and the channel output carry a host-only branch after an absolute height [C]. The member must have spent each such output on its path, with a buried transaction, before that height. With staggered per-node heights the binding one is the earliest on the path. C5 says this in general terms; F12 gives the precise completion point.

**Who can be made to pay fees.** The host, by any member, at any time, for that member's whole path (F8). The member, in a timed-layer race it cannot fund (F3). The member, for second-stage payment claims (F12). The channel output, for every leaf change [C].

## 4. Section 8 and its open point: who releases what, and when

Fair exchange between the host and members is not possible; someone completes first. The design goal is that *whoever completes first gains nothing by withholding*. [R throughout]

**Creation.** Nothing is at stake before funding is buried. Order: members' partial signatures, host verifies each, host combines, host sends `round_complete`, host funds. The host should fund only after every member has acknowledged `round_complete`, because a member without the tree will not accept payments and its seat is dead capital. Passing all partial signatures to all members (open point 2) adds about 16 KB per 513-signer item per member and removes the host's ability to hold the result alone. It is cheap and I recommend it for creation. It does not stop the host from simply not funding.

**Leaf change (host and one member).** Recommended tiers:

1. Channel paused.
2. Tier 1: commitments on the new channel output for both sides, at the current balance; the payout that spends the new shared outputs; the penalty transaction that spends the *old* liquidity output (usable only with the old state's secret). Results delivered to the member and verified.
3. Tier 2: the new leaf transaction. Either party may complete it. If the host completes and withholds, the member still has state k and everything on it; if the host publishes k+1 the member holds its exit from it.
4. When the member holds the new leaf transaction: the member revokes its last commitment on anchor k. When the host holds it: the host reveals the old liquidity secret and revokes its own last commitment on k. The member checks the secret against the hash in the output it built.
5. Channel resumed on k+1.

What each side holds if the other stops: after step 2, both hold only harmless additions. After step 3 with the host silent, the member treats both k and k+1 as live and keeps both current or exits. The host must never perform step 4 before it holds the new leaf transaction, or it has given away the penalty on a state that is still current.

I could not determine from the imported code how a liquidity purchase moves value from the liquidity output into the channel. The link builder for one-member leaves spends only the channel output and produces a single output [C: `factory.c:2764-2781`]. If the real operation also spends the liquidity output, the host's delayed sole-spend path on that output [C: `factory.h:39-50`, 144 blocks] becomes a second race the member must win, and belongs in F3's list.

**Layer update (host and every member under the node).** Tiers run from the leaves upward: commitments on every new channel output; then payouts and penalties; then leaves; then each level up; last the new state transaction. Until the last tier nothing new can reach the chain. For the last tier the host should send its own partial signature and every member's partial signatures to all signers, so every member can complete the state transaction. If only the host can complete it, a host that withholds leaves every member under the node in Unfinished with two live anchors and no end to that condition, because the withheld state always beats the old one. Old-state secrets are released only after the host holds the new state transaction.

**Section 8's sentence** "a host that withholds `round_complete` gains nothing: publishing the new state pays the member correctly, and the member can still use the old one" should be replaced. It is true for a leaf change with the tiers above. For a layer update the member cannot rely on the old state, and "pays the member correctly" holds only while the member keeps the new anchor current.

## 5. Scale at 512 members

Figures from the scale check [C] and arithmetic [R]. Shape `15,15,ps` with two fixed levels: 1,614 transactions, 513 signers at the root, 8 transactions on the longest exit.

- **Items per member.** About 8 tree transactions, the funding-output distribution transaction, and under the planned change about one payout per shared output on the path: roughly 17 to 20 items. The member uploads that many 66-byte nonces and 32-byte partial signatures: a few kilobytes.
- **Items for the host.** Every transaction and every payout: more than 3,000 nonces and partial signatures of its own, and on the order of 10,000 partial-signature verifications and as many contribution-signature checks. About a second or two of processor time (estimate).
- **Message size.** One 513-signer item is 513 × 66 = 33,858 bytes of nonces. With a 64-byte signature per nonce it is 66,690 bytes, which is larger than one Lightning message (65,535 bytes, from memory of the messaging specification, not fetched today). "One message per item" in section 3 does not work for root-level items; an item must be splittable. At 1,024 members it does not fit even without signatures.
- **Per-signer signatures.** Section 3 says each nonce comes "with that signer's signature", but section 7 says a member signs once over all its nonces. To check that one signature a receiver would need *all* of the signer's nonces, including those for items it does not share. Specify one signature per (round, item, nonce), or a Merkle root over the member's nonces signed once with a path per item.
- **Download.** Two 513-signer items cost each member about 133 KB with signatures. The host sends on the order of 70 MB per attempt.
- **Time for the root item.** One process signs the whole tree in 0.6 seconds [C]. The real time is two network round trips to the slowest of 512 devices, bounded by the timers: up to 60 seconds per attempt.
- **Convergence.** If each member independently fails to finish an attempt with probability p, an attempt succeeds with probability (1−p)^512: 60% at p = 0.1%, 8% at 0.5%, 0.6% at 1%. Removing the failed members does not help if failures are independent. Three attempts will almost never produce a 512-member factory from phones on ordinary networks. The limit should be a time budget, not a count, with a live ready check seconds before each attempt. Generating nonces at the ready check (open point 5) leaves one critical exchange in place of two; BIP 327 permits it and warns that stored nonces need more care and lose the message safeguard [S], which the imported function does not use anyway (F6).
- **Does it degrade safely?** At creation, yes: failure means no factory and no funds at risk. For later rounds with many signers, failure after the partial-signature step leaves members in Unfinished, which is safe only with the changes in F1 and F2.
- **A lighter variant to consider.** BIP 327 lets a signer sign with only the aggregate nonce [S]. Members could receive the aggregate nonce, a Merkle root over all signed nonces signed by the host, and a proof that their own nonce is included, and name the root and aggregate in their partial-signature message. That is a few hundred bytes per item. Blame then rests on the host opening the tree. This is my suggestion and needs the same expert review as section 7.

## 6. Contradictions between the documents, the code and the design posts

1. **"About two weeks to respond to an old state"** (`DESIGN.md` 6, knowledge base 5) against a 144-block step in timed layers (F3).
2. **Signing-round section 8 and safety-rule C6** against the single-message flow of sections 3 and 4 (F4).
3. **Signing-round section 6** says the message goes into nonce generation; the imported function does not accept one (F6).
4. **"Members start at zero"** (knowledge base, `DESIGN.md` 7) against rotation by closing into a new factory, where the new tree must open with balances.
5. **"Nobody has money at risk in a lobby"** (`LOBBY.md`) is true of the lobby, but the host's cost from free seats arrives after funding (F8).
6. **Safety-rule section 4, "liquidity may move toward the member, never away from the member's balance"** against the imported leaf link, which lowers the channel output by the fee each time [C].
7. **Knowledge base section 3** says pseudo-Spilman leaves "were designed for several members per leaf". Topic 1242 describes leaves of k² clients in k factories [S, as summarised]. The one-member leaf is the reference code's and Gazpacho's choice; ZmnSCPxj's safety argument for the poisoning transaction (any client can pay for it out of its own output) should be re-checked for a leaf with one member.
8. **Knowledge base section 3, "members are meant to receive everything and the host nothing"** at expiry. Topic 1143 as fetched describes the host recovering funds at the timeout and a burn transaction for liquidity; the inversion is from the later post [S, as summarised]. The knowledge base should cite which post.
9. **`DESIGN.md` 6, "Exit fees are built in from the host's side"** against a race or a second-stage claim that needs a fee the built-in amount does not cover (F3, F12).
10. **TESTING's threat list** ("the threat list") refers to a list that does not exist; section 9 below drafts one.

## 7. Claims checked against primary sources

| Claim in the specifications | Result | Source |
|---|---|---|
| A secret nonce must never sign twice; doing so can reveal the key | Correct | BIP 327, General Signing Flow [S] |
| Nonce generation takes fresh randomness plus the key, aggregate key and message when known | Correct as a description of BIP 327 (these are optional, recommended inputs; the public key is mandatory). **Not what the imported function does** | BIP 327, Nonce Generation [S]; `musig.c:463-480` [C] |
| Nonces may be generated early, with care, losing a safeguard | Correct | BIP 327, Nonce Generation [S] |
| A partial signature is produced only after the complete nonce set is received | Stricter than BIP 327, which needs only the aggregate nonce to sign; individual nonces are needed for partial-signature verification. Not wrong | BIP 327 [S] |
| BIP 327 lets honest parties identify a bad partial signature "provided contributions cannot be tampered with" | **Incomplete.** BIP 327 gives three conditions: untampered contributions, honest nonce aggregation, and verification of every partial signature | BIP 327, Identifying Disruptive Signers [S] |
| The combiner could otherwise blame an honest signer | Correct | BIP 327, Further Remarks [S] |
| BIP 327 says nothing about convincing a third party | Correct as far as I could find | BIP 327 [S] |
| Participants in an agreed order, host first; no sort | Permitted. Key aggregation depends on order and does not sort by default | BIP 327, Public Key Aggregation [S]; `musig.c:17-36` [C] |
| (Not stated in the specification) Duplicate keys | BIP 327 allows them and lets the application reject them. The specification should reject them | BIP 327 [S] |
| (Not stated) Each nonce is two points | Handled by the library; the 66-byte size in `musig.h` matches | BIP 327 [S]; `musig.h:46` [C] |
| (Not stated) Taproot tweak | The imported code applies an x-only tweak, as BIP 327 requires for taproot; and signs untweaked for the script-path penalty | BIP 327, Tweaking [S]; `musig.c:347-372`, `:374-406` [C] |
| (Not stated) Is it harmful that the host picks its nonce after seeing all others? | No, for unforgeability. BIP 327 itself describes a signer that waits for all other nonces, and a deterministic variant for a single last signer. MuSig2 is secure under concurrent sessions; earlier two-round schemes were not | BIP 327, Nonce Generation and Modifications to Nonce Generation [S]; MuSig2 paper abstract [S]; search summary of the Drijvers et al. attack (secondary) |
| (Not stated) Rogue keys | MuSig2 key aggregation needs no proof of possession. I verified only that BIP 327 does not require one; the security claim is from the MuSig2 paper, whose abstract does not mention it | BIP 327 [S]; from memory otherwise |
| (Not stated) Hash type and annex | The taproot signature message commits to the hash type, all input amounts and scripts, and whether an annex is present; a 64-byte signature implies the default type | BIP 341 [S] |
| Section 10: the imported code never verifies partial signatures | Consistent with the hand-off note; `musig_verify_partial_sig` exists | `musig.c:423-436` [C] |

Links:

- BIP 327: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
- BIP 340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- BIP 341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- MuSig2 paper: https://eprint.iacr.org/2020/1261
- SuperScalar, topic 1143: https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143
- SuperScalar with pseudo-Spilman leaves, topic 1242: https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242
- Blockstream on MuSig2 and the earlier attacks (secondary): https://blog.blockstream.com/musig2-simple-two-round-schnorr-multisignatures/
- Coinjoin coordinators and non-signers (secondary, informal): https://lontivero.github.io/Wiki/html/wasabi/wasabito_dos_protection.html

The two Delving topics were read through an automated summariser, not word for word, and the second was read in two parts. Statements marked "[S, as summarised]" should be re-read in the original before they are relied on.

## 8. Requirements on parts not yet designed

**Channel engine**
- Commitments are signed for every live anchor at one commitment number with one revocation secret (F2).
- A pause that both sides acknowledge, entered before any round touching the channel's anchor and left only when the round is resolved.
- H4 as a two-sided invariant: neither side's latest commitment may lag on any live anchor.
- The first commitments are part of the creation round's first tier.
- Payment acceptance and every commitment signature go through the safe-to-sign module.
- The taproot channel format uses MuSig2 itself; its nonces fall under signing-round section 6 and F6.

**Storage**
- The exposed set is written and durable before any partial or commitment signature is sent.
- Round identifiers for which a contribution was sent are durable and are never accepted again (F5).
- Sent partial signatures are stored so a resend is byte-identical.
- No secret nonce, and no randomness from which one could be regenerated, is ever written; replay never recreates one (F6).
- Evidence (signed proposals, signed nonce sets, own signed messages) is kept for as long as a dispute could matter.

**Backup and restore**
- A restored node signs nothing in an existing factory except a defined close or exit.
- The specification states that the host, as keeper of the backup, can return an old one, and what the member can and cannot detect.
- The exposed set is part of the backup; losing it is as serious as losing the held set.

**Watch engine**
- For every transaction in the exposed set: the on-chain event that makes it dangerous, the response, and the deadline in blocks (W or R of F3).
- Response to an old layer state within one step, including fee means.
- Monitoring of the funding outpoint's depth and of reorganisations that change which leaf link is confirmed.
- More than one independent chain source for any event with a deadline under a day.

**Exit engine and schedule engine**
- Exit time by the F12 definition, summed from the transactions.
- The date by which the member must start an exit: the earliest competing claim on its path (today the host's timeouts; later the earliest payout lock time, if the member's balance exceeds its share) minus exit time minus margin.
- The member's maximum safe absence, shown to the user.
- For the host: the date by which each non-cooperating member must be forced out, and the fee reserve that requires.

**Lifecycle engine**
- One tree per funding outpoint; activation only on buried funding.
- Serialisation of rounds per subtree.
- A time budget for attempts instead of a count.

## 9. Draft threat model

For each attacker: what it controls, what it must never achieve, the rule that defends, and gaps. Rule names refer to the current drafts; "F" refers to a change proposed above. **No rule** marks a case nothing covers today.

### 9.1 Malicious host (coordinator, co-signer of everything, funder, relay of all messages, keeper of backups)

Controls: participant list and order; proposals and their timing; which messages are relayed, altered or withheld; parallel rounds; its own nonces after seeing all others; funding; its Lightning node; possibly some member seats.

| Must never | Defence | Status |
|---|---|---|
| Take a member's balance by publishing a transaction the member signed but does not hold | C4 over the held set | **No rule** until F1 |
| Get two trees signed on one funding output | C7 | **Ambiguous**; F1 |
| Publish a stale channel state on an old anchor | — | **No rule**; F2 |
| Win with an old layer state | C4 second branch | **Not achieved** for an absent, unfunded or eclipsed member; F3 |
| Hold a parent transaction while withholding the child | C6 | Contradicted by the message flow; F4 |
| Take funds at a timeout before the member can leave | C5 | Covered in principle; needs F11 and F12 |
| Insert a spending path the member does not know | C1, C2 | Partly; F11 |
| Learn a member's key through nonce reuse | Signing-round section 6 | Covered in the protocol; **no rule** for replay, snapshots, restore; F6 |
| Make an honest member provably "at fault" | Section 7 | **Fails** on restart; F5. Otherwise holds |
| Avoid blame for a round it broke | Section 7 | **Not achieved** when the host holds a seat; F10 |
| Use a held, unbroadcast close or rotation later | — | **No rule**; F1 |
| Profit from two overlapping rounds | — | **No rule**; F9 |
| Return an old backup and get a second signature for a state | — | **No rule**; F7 |
| Give credit on an unconfirmed factory and then double-spend the funding | — | **No rule**; F1 |
| Refuse service | Not defended, by design (section 8) | Accepted |

### 9.2 Malicious member

Controls: its key, its seat, when it answers, what it publishes from its held set.

| Must never | Defence | Status |
|---|---|---|
| Take the host's funds with an old channel state | Channel revocation; H4 | Standard, engine not yet designed |
| Take the host's funds by silence until the end date | — | **No rule**; F8 |
| Make the host pay unbounded fees | — | **No rule**; F8 |
| Spoil a round without being named | H2, section 7 | Covered for bad partial signatures; silence is unprovable |
| Make the host look at fault | Section 7 | Holds, except the restart frame applied to the host (F5) and the unopened digest (F10) |
| Break creation for everyone at no cost | Attempts, removal | **Weak**: three identities suffice; F13, F8 |
| Publish an old layer state | The race; penalty does not apply to members | The host and other members must respond within one step; **no rule** names the host's duty |
| Harm another member's balance | Every shared output needs every signer below it | Covered by construction; a member's unilateral exit does shorten others' options (F8) |

### 9.3 Several colluding members (without the host)

| Must never | Defence | Status |
|---|---|---|
| Frame a third member | All contributions pass through an honest host and are signed by their authors | Holds [R] |
| Sign for a third member | Aggregate key needs every signer | Holds [S: BIP 327, unforgeability with all but one signer corrupt] |
| Take the host's liquidity | Penalty secrets are released only for superseded states; H3 | Needs the ordering rule in F8 |
| At the end date, publish a payout that underpays a member with a large balance | C5, restated | Needs F12 |

### 9.4 Host colluding with all other members

This is the adversary of the safe-to-sign rule. Every row of 9.1 applies with the addition that all other signatures are available to it. The one-sentence rule is the requirement; F1 to F4 are the gaps.

### 9.5 Network attacker (can drop, delay, replay and reorder; cannot read or forge inside the encrypted transport)

| Must never | Defence | Status |
|---|---|---|
| Forge or alter a contribution | Transport authentication; signed contributions | Covered |
| Cause a nonce to be used twice by replay | Nonce erased on use; round identifier | Covered for signing; the *nonce message* replay after restart is F5 |
| Choose who gets into a factory by delaying some members | — | Denial of service only; **no rule** |
| Keep a member from the chain or the host for one step of a timed layer | Chain port; several servers | **Insufficient** given F3 |

### 9.6 Chain-view attacker (controls the member's servers)

Must never cause loss by hiding a transaction for less than the member's stated safe absence. Defence: header checks and asking several servers [C: `DESIGN.md` 10]. Status: the safety rule lists this as out of scope; with timed layers the tolerance is under a day and should be stated as a number.

### 9.7 Crash at any instruction, restore, duplicate device

| Must never | Defence | Status |
|---|---|---|
| Send a signature whose record is not saved | Save before send | Covered by design; the *content* of the record is F1, F7 |
| Sign twice with one nonce | Memory-only nonces | Covered; F6 for replay and snapshots |
| Forget an exposure | — | **No rule** for restore; F7 |
| Publish a revoked state after restore | "A restored backup never publishes" | Covered by decision; not yet in the specification |
| Run two devices on one key | — | **No rule** |

## 10. What I could not determine

1. How a liquidity purchase on a one-member pseudo-Spilman leaf moves value from the host's liquidity output to the channel in the imported code. The link builder I read spends only the channel output. The answer decides whether there is a second race (section 4).
2. Whether the imported tree's per-node timeouts are staggered so that deeper nodes expire earlier or later, and by how much. C5's bound depends on it.
3. The exact text of ZmnSCPxj's treatment of channel commitments across a leaf change and of the poisoning transaction for a one-member leaf. I had a summary, not the text.
4. Whether signing BIP 340 messages and MuSig2 partial signatures with one key has a proof of security or a known attack. BIP 327 is silent. I recommend separate keys for that reason.
5. Relay policy for the pre-signed transactions (version, anchors, package relay) and therefore how exposed they are to pinning. Not in scope of what I read.
6. Whether Lightning senders' limit on total timelock in fact leaves room for an incoming payment whose final deadline exceeds a 6-to-9-day exit. The imported header cites 2,016 blocks; I did not check the specification.
7. Real per-attempt failure rates for members on phones. The convergence figures in section 5 are arithmetic on an assumed rate.
8. The Decker-Wattenhofer paper itself was not fetched; the description of decrementing timelocks is from topic 1143 and the imported code.
9. The coinjoin literature on coordinator denial of service was not read in a primary source. The one page found is an informal developer note; it supports only the general point that coordinators ban the coin that failed to sign, which presupposes that a seat costs a coin.
10. Whether libsecp256k1's argument-error handler aborts the process in the build Gazpacho uses (F14).
