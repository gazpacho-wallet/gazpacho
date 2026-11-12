# The safe-to-sign rule

Specification draft 2, 2026-11-11. Status: reworked after an adversarial review of draft 1, which judged the goal right and the checks insufficient. Draft 2 has not itself been reviewed. Nothing here has been reviewed outside this project.

This document defines the check a member's software runs before it contributes to any signature, the matching rules for the host, and what the rule cannot protect against. The code that implements it is one module, the only place where "is this safe to sign?" is decided.

## What changed from draft 1

- The rule now reasons about what the member has **signed**, not only what it holds. Draft 1 let a host collect signatures for one tree, withhold the result, run creation again for a second tree on the same funding output, and later publish the first.
- A section on **what happens to the channel when the tree under it changes**. Draft 1 said nothing, which allowed a stale balance to be published on an old funding output.
- **Timed layers are described honestly.** An old state in a timed layer is not cancelled; it is outraced, and the time to respond is one step of that layer, about a day at current settings.
- Signatures are released in **tiers**, children before parents. Draft 1 required this and then described a protocol that did not do it.
- The time bound is computed from the **scripts of the transactions the member built**, not from numbers the host supplied.
- More rules for the host, including against members who join for free and then go silent.

## 1. The rule in one sentence

A member's software signs only if, once the signature exists, the member can still leave alone, in time, with at least what they are owed, whatever the host and every other member do.

## 2. Terms

| Term | Meaning |
|---|---|
| **Held set** | Every fully signed transaction the member holds, plus the secrets and signed penalty transactions it holds for cancelling old states |
| **Exposed set** | Every transaction for which the member has ever released a partial signature or a channel signature, whether or not it ever saw the result. Recorded durably before the signature is sent |
| **Adversary** | The host together with all other members. It may publish any transaction in the member's exposed set, in any consistent combination, at any time. The member may publish only from its held set |
| **Request** | A proposal to create new signatures |
| **Live anchor** | An output that the member's channel could end up funded by: the channel output of any leaf transaction that could still reach the chain |
| **Owed** | What the member is entitled to, from the member's own records. Section 5 |
| **Exit value** | What the member can bring under its sole control from its held set, against the adversary's best choice from the exposed set. Section 6 |
| **Exit time** | Blocks needed to complete an exit. Section 7 |
| **Maximum safe absence** | The longest the member's software can be away, or blind to the chain, without being able to lose funds. Section 7 |
| **Buried** | Confirmed to the depth set in the member's own conditions |

## 3. The checks

A request is safe to sign only if all of these hold. Each is evaluated on data the member's software built or stored itself.

**C1. Rebuilt, not received.** The member's software constructs every transaction in the request itself, from its own stored state and the proposal's parameters, and signs only digests it computed. Every item is signed in one fixed way: a 64-byte signature, the default hash type, no annex, and a stated mode (key path with a stated tweak, or script path with a stated leaf). No item uses a hash type that lets inputs be added. A participant list containing the same key twice is refused.

**C2. Own outputs are recognised by own keys.** The member's software identifies its outputs by deriving the scripts from its own keys, never from labels, indexes or positions in the request.

**C3. Value.** The exit value after the request is at least the amount owed after the request. The adversary draws from the exposed set; the member draws from the held set, and may rely only on responses it can make within its maximum safe absence and with fee funds it actually has.

**C4. Every exposed transaction is accounted for.** For every transaction in the exposed set after the request, the module names which of these applies, and refuses if none does:
- **(a) Harmless:** if it is published, the member still reaches at least what it is owed from its held set.
- **(b) Revoked:** the member holds a secret or a signed transaction that lets it take the funds if this appears, within a stated window W.
- **(c) Outraced:** the member must get a specific transaction buried within R blocks of a specific on-chain event, and has the means to. The module states R.
- **(d) Dead:** an input it spends has been spent by a different transaction that is buried.

**C5. Time, from the scripts.** For every output on the member's exit path, the module lists every way that output can be spent, from the script of the transaction it built: everyone signs; host alone after a height; host alone after a delay; member alone; behind a hash. A way it does not recognise fails the check. The exit must be complete, with a margin, before the earliest moment at which anyone else gains a sole or competing claim on any output on the path. Today that is each node's host-only timeout. After the planned end-date payouts it is the earliest payout lock time on the path, whenever the member's balance exceeds its fixed share of that payout.

**C6. Children before parents.** A round is divided into ordered tiers (see the signing round). The member releases its partial signatures for a tier only after it holds and has verified the final signatures of the tier below. So the member never helps create an output without already holding its own signed exit from it. Creation may use one tier, because of C11.

**C7. Exposure is recorded before it happens.** Before any partial signature or channel signature is sent, the transaction it is for is added to the exposed set and that record is durable. Two different transactions that spend the same output may both be signed only if C3 to C5 hold with both in the exposed set. Two cooperative closes that pay the member the same amount pass; two liquidity changes that both keep the member's balance pass. **One tree per funding output, ever:** at creation the member records the funding output and a digest of the tree before signing, and refuses any different tree for that output. A record leaves the exposed set only by C4(d).

**C8. Parameters inside the member's own limits.** Every parameter that affects who can spend an output, or when, is inside a range set by the member's own conditions: each timeout, each delay, the step and number of states of each timed layer, the number of fixed levels, fees, whether anchors are present, the member count. Matching the host's published terms is necessary and proves nothing about safety. A timeout that is already past, or closer than the exit time plus margin, is refused. A hash the host supplies for a penalty is accepted for one state only; the same hash for two states is refused.

**C9. Nothing in flight is stranded, and the channel is quiet.** A request that touches a channel's anchor is refused unless the channel has been paused by agreement of both sides, and stays paused until the request is resolved. A request that closes or replaces a channel is refused while a payment is in flight on it, unless the resulting sets still let the member claim or reclaim that payment.

**C10. One open round per output.** The member takes part in at most one unresolved round touching any given output it has an interest in. A second proposal touching such an output is refused.

**C11. A factory is live only when its funding is buried.** The member treats a factory as live, and accepts any payment in it, only when the exact funding output of its held tree, with the exact amount and script, is buried. The funding is the host's own coins and can be spent elsewhere until then.

**C12. After a restore, sign nothing old.** Software restored from a backup refuses every request in a factory that existed before the restore, except the defined recovery close or exit. The host keeps the member's backup and can return an old one; the member cannot always tell.

**C13. A payment is a signature.** Accepting or making a payment signs new channel states, so it runs this module like any other request. A member with an unbroadcast cooperative close in its exposed set therefore refuses further payments on that channel.

If any check fails, the member's software sends nothing for that request, tells the host it refused, and keeps its sets unchanged.

## 4. Tree changes and the channel

A channel is funded by an output of a leaf transaction. When the tree under a channel changes, that output changes.

- **A liquidity change on a leaf** adds a leaf transaction that spends the previous one's channel output. The channel gains a new anchor.
- **A state update in a timed layer** rebuilds every transaction below it. Every channel below gains a new anchor.

Rules:

1. **Commitments are kept in step on every live anchor.** Every channel update is signed for every live anchor with the same number and the same revocation secret. One revocation covers all anchors.
2. **A leaf anchor is retired** when both sides have revoked the last commitment on it and the member holds the next leaf transaction, which it can publish as soon as the previous one confirms. After retirement a commitment on the old anchor is a revoked state and is punishable in the usual way.
3. **An anchor under an old state of a timed layer cannot be retired.** That state can always reach the chain if it wins the race (section 8). Either its commitments are kept current for the factory's whole life, or the member accepts that losing the race loses the channel. This specification requires them to be kept current.
4. **Pause.** No payment update on a channel while a round that touches its anchor is between "partial signatures sent" and "resolved".
5. **Unfinished rounds.** A member that has sent partial signatures and lacks the result treats both outcomes as live: it keeps both anchors current, or it stops using the channel and exits. It never behaves as if only the old state exists.
6. **Order within a leaf change:** pause; first tier: channel states on the new output for both sides at the current balance, the payout for each new shared output, and the penalty for the old liquidity output; second tier: the new leaf transaction; then the member revokes on the old anchor, and the host reveals the old liquidity secret and revokes on the old anchor only once it holds the new leaf transaction; resume.

## 5. What the member is owed

Always from the member's own records, never from the request. Stated after the channel reserve and the fees the member has agreed to.

| Operation | Owed after the request |
|---|---|
| Creating a factory | Zero. Nothing is owed until funding is buried |
| A payment received | The previous balance plus the amount, once the member can claim it |
| A payment sent | The previous balance less the amount and fee; if it fails, the amount is owed back |
| A payment in flight, incoming | Counted only if the member knows the secret and the deadline leaves room (section 7) |
| A payment in flight, outgoing | Owed back if it fails or times out; counted as owed back in the exit value |
| A liquidity change on the member's leaf | The same balance, less only a fee the member agreed to in its conditions |
| A change to a layer above the leaf | Unchanged |
| Rotation by paying across | The same total across both factories, less agreed fees; a payment in flight between them counts as in flight, not as arrived |
| Rotation by closing into the new factory | The same balance, carried as the opening balance in the new tree |
| A cooperative close | The balance, paid to a script the member's software derived |
| Another member's leaf | Unchanged, and the member is not a signer |
| After a restore | Unknown to the member until the host proves the latest state; see C12 |

## 6. Exit value

1. Find the member's exit path in the held set. For a leaf it is the whole chain of leaf transactions, not only the newest, and each link carries a fee.
2. Add up the final outputs only the member controls.
3. Subtract fees. Value that can be reached only with on-chain coins the member does not have counts as zero.
4. Payments in flight: each needs a further transaction with its own fee, and one too small to claim on chain counts as zero. Count an incoming one only if claimable in time.
5. For each transaction in the exposed set, take the adversary's best choice, then the member's best response within its maximum safe absence and fee means. Use the lowest result.
6. A penalty the member could collect from the host's liquidity is a deterrent. It is not counted in exit value.
7. An end-date payout is a member of both sets. From its lock time any party under that node can publish it, and it pays the member a fixed share. If that share is below the member's balance, the member must have exited first; C5 enforces this.

## 7. Exit time and maximum safe absence

**Exit time.** Sum, from the transactions themselves, every relative timelock on the path plus a confirmation allowance per transaction set by the member's conditions. The imported delay functions are not used; they under-report on deep trees. An output on the path is safe once the member's transaction spending it is buried. The exit is complete, for C5, when the member's channel transaction is buried and every payment in flight has met its own deadline. The member's own delayed output is outside C5: nobody else has a claim on it.

**Accepting a payment.** Only if its deadline is later than now plus exit time plus the time to claim it on chain, plus margin. The schedule must also state the largest exit time at which ordinary senders can still pay the member, since senders limit total timelock.

**Maximum safe absence.** The smallest of all W and R values named under C4 on the member's path, less a margin. The schedule engine shows it to the user. With pseudo-Spilman leaves under fixed levels it is the channel's revocation window, which the terms can make about two weeks. With a timed layer above the member it is one step of that layer.

## 8. Timed layers

A timed layer orders its states by relative timelock: newer states can confirm sooner. Nothing else stops an older state. Once the transaction above the layer is on chain, the newest state can confirm one step before the next older one. At the settings used so far a step is 144 blocks, about a day.

So for a member below a timed layer:

- If the host, or any member under that node, starts publishing, the member's software must see it and get the newest state buried within one step. An older state that wins leaves the member's channel on an old anchor.
- Being away for a day, being shown a false view of the chain for a day, or being unable to pay enough fee for a day, can each lose the race. This is loss, not delay.
- The host loses its spare liquidity on that leaf to the member if it does this. That is a deterrent, sized by the liquidity and unrelated to the member's balance.

Consequences this specification imposes:

- C3 requires that the member can fund the fee for the race at a rate stated in its conditions, from coins it has.
- The watch engine and the chain view are safety-critical within hours for such a member, and need more than one independent source.
- The member's maximum safe absence is under a day. Any statement that a member has about two weeks applies only to factories with no timed layer above that member.

Whether the first release offers timed layers to members without an always-on watcher is an owner decision; see the open points.

## 9. The host's side

The host's software runs the same module with the roles exchanged, plus:

**H1. Funding last.** The host signs funding only after every tree transaction is fully signed and verified, and every member has acknowledged holding the result.

**H2. Every partial signature is verified** as it arrives, against its sender's key and nonce.

**H3. No credit before it is covered.** The host does not act on an operation for a member until the transactions protecting the host in the new state are fully signed. It gives no channel credit before funding is buried.

**H4. The host always holds its own signed channel state** for every channel on every live anchor, kept current through every update.

**H5. Secrets after, not before.** The host does not reveal an old state's liquidity secret, or revoke its own old channel state, until it holds the new state fully signed.

**H6. A deadline for forcing out.** For every member, the host knows the date by which it must start publishing that member's path so that it resolves by real balances before the end-date payouts become valid: the end date, less the full exit time, less a margin. It stops extending credit to a non-cooperating member before that date.

**H7. A fee reserve.** The host holds on-chain coins sufficient to add fees to every path it may have to publish.

**H8. Rounds one at a time per subtree.**

**H9. A member who never completes the first channel exchange** is treated as absent from the start: its seat gets no credit and is forced out under H6.

## 10. What this rule does not protect against

- **Being ignored.** A host can refuse service. The remedy is to leave.
- **Losing a race in a timed layer,** through absence, fees or a hidden transaction.
- **A false view of the chain** for longer than the maximum safe absence.
- **Fees far above what the member can fund.**
- **Loss of the held set or the exposed set.** Losing the record of what was signed is as serious as losing the transactions.
- **A host that returns an old backup.**
- **The same key running on two devices.**
- **A copy of a running program** (a snapshot or a fork) that repeats a one-time signing secret.
- **Funding that is reorganised away** after it was buried to the member's chosen depth.
- **Relay rules** that keep a pre-signed transaction from spreading, or let someone obstruct it.
- **A fixed end-date payout that is smaller than the member's balance,** if the member did not exit first.
- **Bugs in the imported tree builder** that make two honest parties build different trees.
- **Someone tying up the member's receiving capacity.**
- **Privacy.** The host sees its members' payments, membership and network addresses.

## 11. How it is tested

For every check C1 to C13 and H1 to H9:

1. A simulator scenario where the other side sends a request that violates the check. The software must refuse and its sets must be unchanged.
2. The same scenario with the check switched off. The simulator's independent accounting, which replays what each party could actually publish, must then show a loss.
3. Honest scenarios for each operation, which must still succeed.

Named attack scenarios that must each be a test: two trees on one funding output; a withheld cooperative close published later; a stale channel state on an old leaf anchor; an old layer state against an absent member, a member without fee funds, and a member shown a false chain; two overlapping rounds on one subtree; a restore from an old backup followed by a second signing request; a timeout in the past; a reused penalty hash; a silent member at the end date; a member exiting on the first day.

The simulator's accounting computes exit value independently of this module, from the transactions alone.

## 12. Open points

**For the owner**

1. **Timed layers and absence.** With a timed layer above them, members must be watched within a day. Options: offer timed layers only to members with an always-on watcher; lengthen the step (three steps per layer, so a week-long step means three weeks of exit per layer); or ship the first release with fixed levels and pseudo-Spilman leaves only, where about two weeks holds.
2. **Free seats and the end-date payout.** Once members are paid their channel's capacity at the end date, a seat that costs nothing and stays silent takes the host's capital unless the host forces it out on chain, at the host's expense. A deposit or another cost per seat becomes a precondition for that payout, not an extra.

**To settle by reading or measuring**

3. How the imported code moves value from the host's liquidity output into a one-member leaf's channel, and whether that adds a second race.
4. Whether the imported tree's per-node timeouts make deeper nodes expire earlier or later, and by how much.
5. ZmnSCPxj's own text on channel states across a leaf change and on the penalty for a one-member leaf. The review worked from a summary.
6. Relay rules for the pre-signed transactions, and whether they can be obstructed.
7. Whether senders' limit on total timelock leaves room for a payment to a member whose exit takes six to nine days.
8. The confirmation allowance per transaction, which is the largest unknown in exit time.
