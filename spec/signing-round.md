# The signing round

Specification draft 2, 2026-11-11. Status: reworked after an adversarial review of draft 1, which judged it sound with changes. Draft 2 has not itself been reviewed. The parts on proving fault are this project's own design and have had no outside review.

A signing round produces group signatures for a set of transactions. One engine runs every round in Gazpacho: creating a factory, changing a leaf, updating a layer, rotating, closing. It follows the MuSig2 standard (BIP 327) and uses the imported signing code.

## What changed from draft 1

- The round identifier is fully defined and is **saved before a party's first contribution, and refused for ever after**. Draft 1 let a restart make an honest party sign two nonces under one identifier, which looks exactly like cheating.
- Contributions are signed with a **separate key**, not the key that takes part in the group signature.
- Signatures are released in **ordered tiers**, children before parents.
- The host signs its proposal and its result.
- The rules for one-time secrets now cover replayed journals, restored backups and copied processes.
- An honest account of what the fault proof can and cannot show.
- Attempts are limited by a **time budget**, not a count, and large signing data is split.

## 1. Parties and scope

- The **coordinator** is the host. It is also a signer in every transaction.
- **Members** are the other signers. Each talks only to the host.
- A round covers one or more **items**. An item is one transaction input to be signed. It has: an index; the output it spends; the signature digest; the ordered keys of its signers; and its **signing mode** (key path with a stated tweak, or script path with a stated leaf). A member signs only the items on its own path.
- Items are grouped into ordered **tiers** (section 5).
- The engine does not decide whether signing is safe. It asks the safe-to-sign module (`safety-rule.md`) and obeys it.
- Every item is signed with a 64-byte signature, the default hash type and no annex.

## 2. Keys

- The **factory key** is the member's key in the group signature. It signs nothing but group-signature items.
- The **contribution key** signs the member's round messages. It is a different key: the key that authenticates the member's connection, or one derived for the purpose. In the lobby the member binds it once, with one statement signed by the factory key.
- The **host's long-term key** signs proposals and results.
- Every signed protocol message is a tagged hash with a tag specific to this protocol, so it can never equal the digest of a transaction.
- A participant list with the same key twice is refused.

## 3. What identifies a round

```
round_id = tagged_hash(
    protocol name and version,
    chain (genesis hash),
    host's long-term key,
    digest of the host's signed terms,
    funding output and amount,
    ordered participant factory keys,
    purpose, tier structure,
    for every item: index, output spent, signature digest, signing mode, ordered signer keys,
    host's fresh random value for this round )
```

- The signature digest already commits to every spent amount and script, every output, lock time and sequence. The signer set and signing mode of an item are not in it, so they are listed separately.
- **Each party saves the round identifier durably before sending its first contribution, and never contributes to that identifier again.** A party that finds a saved identifier for which it holds no nonces answers only with `round_abort`. This is what makes a restart safe.
- A new attempt has a new host random value and so a new identifier.

## 4. Messages

Carried as factory messages inside the Lightning connection.

| Message | From → to | Carries | Signed by |
|---|---|---|---|
| `round_propose` | Host → member | Purpose, the parameters from which the member rebuilds the transactions, the ordered participant list, tiers, deadlines, the host's random value | Host's long-term key |
| `round_nonces` | Member → host | For each of the member's items in this tier, a public nonce, each signed over (round, item, nonce) | Member's contribution key |
| `round_all_nonces` | Host → member | For each of the member's items: every signer's public nonce with its signature | Carried signatures |
| `round_partial_sigs` | Member → host | The member's partial signature for each item in the tier; for each item, a digest of the exact nonce set the member used | Member's contribution key |
| `round_tier_result` | Host → member | The final signatures of a tier, and for the last tier every signer's partial signatures | Host's long-term key |
| `round_complete` | Host → member | Everything the member's safety analysis relies on: final signatures for its exit path, the payouts, the penalty transactions | Host's long-term key |
| `round_abort` | Either way | A reason, and evidence where fault can be shown | Sender |

- Parameters are sent, not transactions. A member builds the transactions itself.
- One item's nonce set for a 513-signer root is larger than one Lightning message once signatures are included. Every item's data is therefore splittable across messages, with a marker that the set is complete.
- A second `round_all_nonces` for the same round is rejected.
- A message re-sent after a reconnect is the **saved bytes**, never a new signature. So the saved record includes what was sent.
- The digest of a nonce set is a tagged hash over the nonces in signer order, each in its standard 66-byte form.

## 5. Tiers

A tier is a set of items that may be completed together. The engine releases a member's partial signatures for a tier only after the member holds and has verified the final signatures of the tier before it.

| Round | Tiers, in order |
|---|---|
| **Creation** | One tier: the whole tree, the first channel states and the payouts. Nothing is at stake until funding is buried, and the host funds last |
| **Leaf change** | 1. Channel states on the new output for both sides, the payouts for new shared outputs, the penalty for the old liquidity output. 2. The new leaf transaction |
| **Layer update** | From the leaves upward: channel states on every new channel output; payouts and penalties; leaf transactions; each level up; last, the new state transaction |
| **Cooperative close** | One tier, with the channel paused from the first partial signature until the funding output is spent |
| **Rotation by closing into a new factory** | 1. The whole new tree with its opening channel states. 2. The transaction that spends the old funding output into the new one |

For the last tier of a layer update the host sends its own partial signature and every member's to all signers, so any member can complete the state transaction. A host that could hold it alone would leave every member under that node with two live outcomes and no end to that condition.

## 6. Steps within a tier

1. **Propose** (once per round). The host sends `round_propose`.
2. **Check.** Each member verifies the host's signature, rebuilds the transactions, computes the round identifier, runs the safe-to-sign checks, and saves the round identifier. On failure it sends `round_abort` and stops.
3. **Nonces.** Each member generates a fresh secret nonce per item and sends the public parts.
4. **Distribute.** When the host has every signer's nonces for the tier, it sends `round_all_nonces`.
5. **Verify and sign.** Each member checks every nonce's signature, confirms its own nonces are present and unchanged, runs the safe-to-sign checks again, records the exposure (`safety-rule.md`, C7), then sends `round_partial_sigs`.
6. **Verify.** The host verifies each partial signature as it arrives.
7. **Result.** The host combines, verifies each final signature, and sends `round_tier_result`.
8. **Accept.** Each member verifies the final signatures. The next tier begins, or `round_complete` ends the round.

## 7. States

**Member**

| State | Leaves on |
|---|---|
| Idle | `round_propose` → Checking |
| Checking | Checks pass → Nonces sent. Checks fail → Aborted |
| Nonces sent | `round_all_nonces` valid → Signed. Deadline, invalid data or `round_abort` → Aborted |
| Signed | Tier result valid → next tier or Complete. Deadline → Unfinished |
| Complete | |
| Aborted | Secret nonces erased; the round identifier stays refused |
| Unfinished | See section 10 |

**Once a member has sent partial signatures, no message moves it to Aborted.** The host holds signatures it can complete. Only a valid result or evidence on chain resolves the round.

**Host:** collecting nonces → collecting partial signatures → tier result → next tier or complete; or failed, with a list of who did not answer or sent something invalid.

A party takes part in at most one unresolved round touching any given output. The host runs rounds one at a time per subtree.

## 8. One-time secrets

BIP 327 says a secret nonce must never be used to sign twice, since two signatures can reveal the signer's key, and that nonces must not be derived deterministically from the session's parameters.

- The randomness for a secret nonce comes from the operating system at the moment of use. It is never written anywhere and never produced by a generator whose state is saved or can be restored.
- The core is handed its randomness so that a factory can be simulated from a seed. The seeded source exists only in simulator builds and cannot be linked into a release build.
- A secret nonce lives in memory only, and is erased as soon as it has signed or the round ends for any reason.
- Rebuilding a node from its journal never recreates a secret nonce. Any round found in progress is abandoned and its identifier refused.
- A partial signature is produced only after the complete nonce set for that item has been received and checked. This is stricter than the standard, which needs only the combined nonce; the individual nonces are needed to verify partial signatures.
- The imported `musig_generate_nonce` uses fresh randomness, the secret key, the public key and the key aggregation data. It takes no message and no extra input, so the standard's optional safeguard of binding the nonce to the message is not available through it today. A function that takes both has been requested from the SuperScalar repository; when it exists, the round identifier and item index are passed as the extra input.
- A copy of a running program, such as a machine snapshot, can repeat a secret nonce. Nothing in software prevents this; it is listed among the limits.

## 9. Who broke the round

BIP 327 lets honest parties identify a signer who sent a bad partial signature under three conditions: contributions are not tampered with, the nonces are combined honestly, and every partial signature is verified. It warns that whoever combines could otherwise blame an honest signer, and it does not address convincing a third party. The scheme here is our extension.

**What can be shown, and to whom**

| Fault | Evidence | Convinces a third party? |
|---|---|---|
| A member sent a bad partial signature | The host-signed proposal; the item's signer keys and signing mode; every signer's signed nonce for the item; the member's signed partial-signature message. The verifier recomputes the session and runs the standard check | Yes |
| The host altered someone's nonce | It lacks the owner's signature and is rejected at step 5 | Not needed |
| A party signed two different nonces for one round and item | Both signed nonces | Yes, against that party's contribution key |
| A member names a nonce set that never existed | The member cannot open its digest to a set of validly signed nonces | Yes |
| The host says a good partial signature is bad | Verification against the set the member named succeeds | Yes, the claim is disproved |
| The host sent wrong final signatures, or a proposal that fails the checks | The host's signature on the result or proposal | Yes |
| Someone did not answer, answered late, or sent something malformed | Nothing that a third party can check | No |
| Two parties built different transactions and so signed different identifiers | A disagreement, shown only by rebuilding the tree from the signed proposal | Only with that work |

**Limits, stated plainly**

- **A host that also holds a member seat can break a round and put the blame on that seat.** It gives one member a different nonce from its own seat; the evidence then points at a throwaway identity. The scheme catches a host only when it equivocates under its own key.
- **A host can assert that any member was silent** and leave it out. Apps that keep a history of who stalled record that as the host's claim, not as fact.
- **A valid partial signature does not prove who made it.** The standard says partial signatures are not signatures. Evidence always rests on the signed contribution.
- **Member identities are new per lobby by default,** so proof against a member matters only inside that lobby. Proof against the host's long-term key is the valuable kind.
- **Publishing evidence reveals** the participant keys of the item, hence who is in that factory or branch.
- Checking evidence is a program, not something read by eye.

**After a fault:** the faulty or silent signers are removed together and the host starts a new attempt with a new round identifier.

## 10. Never left half-finished

Someone always completes first. The aim is that whoever does gains nothing by withholding.

- **Creation.** The host funds only after every member has acknowledged the result (`safety-rule.md`, H1). A member treats the factory as live only when the funding is buried (C11).
- **Leaf change.** After the first tier, both sides hold only harmless additions. If the host completes the leaf transaction and withholds it, the member still holds the old state and everything on it, and if the host publishes the new one the member already holds its exit from it.
- **Layer update.** Nothing new can reach the chain until the last tier, and every signer can complete that tier.
- **Unfinished.** A member that has sent partial signatures and lacks the result treats both outcomes as live: it keeps its channel current on both, or stops using the channel and exits. It asks again on reconnect. It never assumes the old state is the only one.

## 11. Time, attempts and size

- **A time budget, not a count.** With many signers, a fixed number of attempts does not converge: if each of 512 members fails an attempt one time in a hundred, about one attempt in 170 succeeds. The host sets a total time for the round; attempts repeat within it, each preceded by a ready check a few seconds earlier, each without those who failed the last.
- **Fewer critical moments.** Nonces may be generated at the ready check, leaving one exchange that everyone must complete in place of two. BIP 327 allows this with care. It is an option for the host's terms, off until reviewed.
- **Deadlines run on each party's own clock.** Someone who can delay messages can push chosen members out of an attempt. That costs them a seat, not money.
- **Size at 512 members** (shape 15, 15, pseudo-Spilman leaves): a member signs roughly 17 to 20 items and uploads a few kilobytes; it downloads on the order of 130 kilobytes per attempt; the host sends on the order of 70 megabytes per attempt and makes about ten thousand verifications. These are estimates.
- **A lighter variant, for later review:** members receive only the combined nonce, a root over all signed nonces signed by the host, and proof that their own nonce is included.

## 12. Guards around the imported code

The engine must do these itself, because the imported functions do not:

| Hazard in the imported code | The engine's guard |
|---|---|
| Setting a signer's nonce twice counts twice, so "all collected" can be true with a slot empty | Track slots; a repeated `round_nonces` is an error before any call |
| Bad input to the signature library can stop the whole program | Parse and reject every nonce and signature from the network before it reaches a session function |
| Duplicate participant keys are accepted | Refuse them |
| A routine exists for a hash type that lets inputs be added | No item may use it |
| The penalty is signed on a script path under the untweaked group key | The signing mode is part of the item and of the round identifier |
| Partial signatures are never verified | `musig_verify_partial_sig` on each as it arrives |
| Member order can depend on the C library's sort | Sequential placement, set before the tree is built |
| The timelock counter is overwritten from 257 members until the shape is set | Set the shape immediately after initialising |

## 13. Use of the imported code

| Step | Function in `core/superscalar` |
|---|---|
| Build the tree | `factory_init_from_pubkeys`, then at once `factory_set_arity` or `factory_set_level_arity`, sequential placement, `factory_set_funding`, `factory_build_tree` |
| Start signing for an item | `factory_session_init_node` |
| Generate a nonce | `musig_generate_nonce` |
| Record a signer's nonce | `factory_session_set_nonce`, then `factory_session_finalize_node` |
| Produce a partial signature | `musig_create_partial_sig` |
| Verify a partial signature | `musig_verify_partial_sig` |
| Record and combine | `factory_session_set_partial_sig`, `factory_session_complete_node` |
| Verify the result | A standard signature check on each signed transaction, from its bytes |

The imported code keeps one signing session per tree node, so two rounds on one node cannot share one tree object. Section 7's rule of one round per subtree matches that.

## 14. How it is tested

1. Honest rounds of every purpose, at several sizes, with every tier order.
2. Each message dropped, delayed, duplicated and reordered, at each step.
3. A crash and restart of each party at each step, including a replayed proposal after the restart. No secret nonce may survive; no party may contribute twice to one identifier.
4. A restore from an old backup, with randomness that repeats: a signing secret must not repeat.
5. Each fault in section 9: the right party is named, the evidence verifies, and an honest party cannot be framed, including by the restart and by the unopened digest.
6. A host that withholds each result in turn: the member loses nothing.
7. Two overlapping rounds on one subtree: the second is refused.
8. Removal of each rule in turn, each of which must make a specific test fail.
9. Fuzzing of every message decoder, and of the evidence checker.

## 15. Open points

1. **Expert review** of sections 2, 3, 8 and 9 by someone who knows MuSig2.
2. Whether signing protocol messages and group-signature items with related keys is provably safe. Separate keys are used because no proof was found.
3. The exact encoding of every message. It belongs in the message specification, which does not exist yet.
4. Whether the host with a seat of its own can be denied its escape from blame, for example by requiring seats to be backed by something scarce.
5. Whether nonces at the ready check, and the lighter variant in section 11, are worth their risks.
6. The size and timing figures are estimates and need measuring.
