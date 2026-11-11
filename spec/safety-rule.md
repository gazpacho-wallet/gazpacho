# The safe-to-sign rule

Specification draft 1, 2026-11-11. Status: for review. Nothing here has been reviewed by anyone outside this project.

This document defines the check a member's software runs before it contributes to any signature, and the matching check on the host's side. The code that implements it is one module, the only place where "is this safe to sign?" is decided.

## 1. The rule in one sentence

A member's software signs only if, once the signature exists, the member can still leave alone, in time, with at least what they are owed, whatever the host and every other member do.

## 2. Terms

| Term | Meaning |
|---|---|
| **Held set** | Every fully signed transaction the member holds, plus the secrets it has been given for cancelling old states |
| **Request** | A proposal to create new signatures: for new transactions, or for transactions that replace existing ones |
| **Resulting set** | The held set as it would be if the request completed |
| **Exit path** | The chain of transactions from the factory's funding output down to outputs only the member controls |
| **Owed** | The amount the member is entitled to, taken from the member's own records. Defined in section 4 |
| **Exit value** | What the member can bring under their sole control by publishing transactions from a set, defined in section 5 |
| **Exit time** | The number of blocks needed to complete an exit from a set, defined in section 6 |
| **Adversary** | The host together with all other members. They may publish any transaction they hold a valid signature for, including old ones, at any time |

## 3. The checks

A request is safe to sign only if all of these hold. Each is checked against data the member's software built or stored itself.

**C1. Rebuilt, not received.** The member's software constructs every transaction in the request itself, from the host's signed terms, the agreed ordered list of participant keys, and the member's own stored state. It signs only digests it computed. It never signs a transaction or digest supplied by another party.

**C2. Own outputs are recognised by own keys.** The member's software identifies which outputs are the member's by deriving the scripts from its own keys. Labels, indexes or positions stated in the request are not trusted.

**C3. Value.** The exit value of the resulting set is at least the amount owed after the request (section 4).

**C4. Every state the adversary could publish is covered.** For every transaction in the resulting set that the adversary could publish, including ones the request is meant to replace, one of these is true:
- publishing it leaves the member able to reach at least the owed amount; or
- the member holds what is needed to cancel it in time and still reach the owed amount.

**C5. Time.** The exit time of the resulting set, plus a margin, ends before the earliest moment at which anyone else gains a competing claim on any output on the member's exit path. Today the imported tree gives the host such a claim at each node's timeout, so that timeout bounds the exit.

**C6. Children before parents.** The member does not help complete a signature on a transaction that creates an output unless it already holds its own fully signed exit from that output. For example, a new channel commitment on a new leaf output is fully signed and in the member's hands before the member signs the leaf transaction that creates that output.

**C7. One state per number.** The member never contributes to two different transactions for the same position and state number in the same factory. Before sending a partial signature it stores a record of what it signed for that position and number, and refuses anything different later.

**C8. Terms.** The parameters used to build the transactions match the host's signed terms, and the terms and the actual member count satisfy the member's own conditions.

**C9. Nothing in flight is stranded.** A request that closes or replaces a channel is refused while a payment is in flight on it, unless the resulting set still lets the member claim or reclaim that payment.

If any check fails, the member's software sends nothing for that request, tells the host it refused, and keeps its held set unchanged.

## 4. What the member is owed

Always from the member's own records, never from the request.

| Operation | Owed after the request |
|---|---|
| Creating a factory | Zero. Members start with nothing |
| A payment in the channel | The balance after the payment the member itself authorised or received, plus payments in flight the member can claim |
| A liquidity change on the member's leaf | The same channel balance as before. Liquidity may move toward the member, never away from the member's balance |
| A change to a layer above the leaf | Unchanged |
| Rotation into a new factory | The same total, across the old and new factories together, at every step |
| A cooperative close | The channel balance, paid to a script the member's software derived |
| Another member's leaf or branch | Unchanged; and normally the member is not a signer at all |

## 5. Exit value

The exit value of a set is computed by the member's software as follows.

1. Find the member's exit path in the set: the newest fully signed transaction at each position from the funding output down, ending in outputs whose scripts the member alone can satisfy.
2. Add up those final outputs.
3. Subtract any fee the member must add that is not already built into the transactions.
4. For payments in flight, count only those the member can certainly claim: it knows the secret and the deadline leaves enough time (section 6).
5. Apply C4: if the adversary can publish a different transaction at some position, take the lowest result over every such choice, after the member's best available response.

The answer is the least the member can end up with. It must be at least the owed amount.

## 6. Exit time

1. Sum the waiting periods on the exit path: each relative timelock, plus a confirmation allowance for each transaction.
2. Add the response window for a cancelled channel state, if the member's own channel transaction is delayed by one.
3. The result, counted from now, must end before the bound in C5, with a margin set by the terms.

A payment may be accepted only if its deadline is later than the exit time plus a margin, so that the member could still claim it on chain.

## 7. The host's side

The host's software runs the same module with the roles exchanged, plus three rules of its own.

**H1. Funding last.** The host does not sign the transaction that funds a factory until every tree transaction is fully signed and verified.

**H2. Every partial signature is verified** as it arrives, against its sender's key and nonce.

**H3. No credit before it is covered.** The host does not treat an operation as complete, and does not act on it for a member (forward a payment, release a secret), until the transactions that protect the host in the new state are fully signed.

## 8. What this rule does not protect against

- **Being ignored.** A host can refuse service. The remedy is to leave.
- **A false view of the chain.** The rule assumes the member's view of the chain is correct. That is the chain port's job.
- **Fees far above what was built in**, if the member has no on-chain coins to add.
- **Loss of the held set.** Backups are a separate mechanism.
- **Privacy.** The host sees its members' payments.

## 9. How it is tested

For every check C1 to C9 and H1 to H3:

1. A scenario in the simulator where the other side sends a request that violates the check. The software must refuse and its held set must be unchanged.
2. The same scenario with the check switched off. The simulator's independent accounting, which replays what each party could actually publish on its pretend chain, must then show a loss. If it does not, either the check is unnecessary or the test is too weak.
3. Honest scenarios for each operation, which must still succeed.

The simulator's accounting computes exit value independently of this module, from the transactions alone, so a mistake in the module is not hidden by the same mistake in the test.

## 10. Open points

1. **Fees.** How much of the exit's fee is built in at each level, and how the member's possible top-up is counted in step 3 of section 5.
2. **Old states in the layered tree.** C4 for the shrinking-timelock layers depends on the cancellation mechanism for the host's spare liquidity. That analysis has to be written out per layer.
3. **Timeouts that favour the host.** C5 is stricter than it would be if every tree output paid members at expiry. If the imported tree changes, the bound changes.
4. **Rotation.** "The same total across both factories at every step" needs a step-by-step statement for each rotation method.
5. **Payments in flight** during a liquidity change on the same leaf.
6. Whether C7's record can ever be safely discarded.
