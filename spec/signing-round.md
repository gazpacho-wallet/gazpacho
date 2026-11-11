# The signing round

Specification draft 1, 2026-11-11. Status: for review. The part on proving fault (section 7) is this project's own design and has had no outside review.

A signing round produces group signatures for a set of transactions. One engine runs every round in Gazpacho: creating a factory, changing a leaf, updating a layer, rotating, closing. It follows the MuSig2 standard (BIP 327) and uses the imported signing code.

## 1. Parties and scope

- The **coordinator** is the host. It is also a signer in every transaction.
- **Members** are the other signers. Each talks only to the host.
- A round covers one or more **items**. Each item is one transaction input to be signed, with its own set of signers. A member signs only the items on its own path.
- The round engine does not decide whether signing is safe. It asks the safe-to-sign module (`safety-rule.md`) and obeys it.

## 2. What identifies a round

```
round_id = hash( protocol name, factory identifier, purpose, attempt number,
                 ordered list of participant keys, digest of every item )
```

Anything that changes any of these is a different round, with fresh nonces. Participants are ordered by an agreed rule, host first, so every party computes the same identifier and builds the same transactions.

## 3. Messages

Six kinds, carried as factory messages inside the Lightning connection.

| Message | From → to | Carries |
|---|---|---|
| `round_propose` | Host → member | Purpose, attempt number, the parameters from which the member rebuilds the transactions, the ordered participant list, the deadlines for each step |
| `round_nonces` | Member → host | The member's public nonce for each of its items, and the member's signature over the round identifier and those nonces |
| `round_all_nonces` | Host → member | For each of the member's items: every signer's public nonce with that signer's signature |
| `round_partial_sigs` | Member → host | The member's partial signature for each of its items, and the member's signature over the round identifier, a digest of the nonce set it used, and those partial signatures |
| `round_complete` | Host → member | The final signatures for every transaction on the member's exit path |
| `round_abort` | Either way | A reason, and evidence where fault can be shown |

Parameters are sent, not transactions. A member builds the transactions itself.

Nonce sets for large factories are sent as a sequence of messages, one per item, ending with a marker that the set is complete.

## 4. Steps

1. **Propose.** The host sends `round_propose` to every signer.
2. **Check.** Each member rebuilds the transactions, computes the round identifier, and runs the safe-to-sign checks. If they fail it sends `round_abort` and stops.
3. **Nonces.** Each member generates a fresh secret nonce per item and sends the public parts in `round_nonces`.
4. **Distribute.** When the host has every signer's nonces, it sends `round_all_nonces`.
5. **Verify and sign.** Each member checks every nonce's signature, confirms its own nonces are included unchanged, runs the safe-to-sign checks again, stores its record of what it is about to sign (see `safety-rule.md`, check C7), then sends `round_partial_sigs`.
6. **Verify.** The host verifies each partial signature as it arrives.
7. **Complete.** When all are in and valid, the host combines them, verifies each final signature, and sends `round_complete`.
8. **Accept.** Each member verifies the final signatures. Only then does it add the new transactions to what it holds.

## 5. States

**Member**

| State | Leaves on |
|---|---|
| Idle | `round_propose` → Checking |
| Checking | Checks pass → Nonces sent. Checks fail → Aborted |
| Nonces sent | `round_all_nonces` valid → Signed. Deadline or invalid → Aborted |
| Signed | `round_complete` valid → Complete. Deadline → Unfinished |
| Complete | |
| Aborted | Secret nonces erased |
| Unfinished | The member has signed but does not hold the result. See section 8 |

**Host**: Collecting nonces → Collecting partial signatures → Complete, or Failed with a list of who did not answer or sent something invalid.

## 6. Rules for secret nonces

From BIP 327, which says a secret nonce must never be used to sign twice, since that can reveal the signer's key.

- A secret nonce is generated from fresh randomness supplied to the core, together with the member's key, the aggregate key and the message when known.
- It lives in memory only. It is never written to storage and never included in a backup.
- It is erased as soon as it has been used to sign, or the round ends for any reason.
- If the program restarts during a round, the round is over for that member. It will take part in the next attempt with new nonces.
- A partial signature is produced only after the complete nonce set for that item has been received and checked.

## 7. Who broke the round

BIP 327 lets honest parties identify a signer who sent a bad partial signature, provided contributions cannot be tampered with in transit. It warns that whoever combines the nonces could otherwise blame an honest signer, and it says nothing about convincing a third party. The scheme below is our extension to cover both.

**Every contribution is signed by its author**, with the same key that takes part in the group signature:

- a member's `round_nonces` is signed over the round identifier and the nonces;
- a member's `round_partial_sigs` is signed over the round identifier, a digest of the full nonce set the member used, and the partial signatures.

**What this proves:**

| Fault | Evidence | Convinces a third party? |
|---|---|---|
| A member sent a bad partial signature | Its signed nonces, its signed partial signature naming the nonce set, and that nonce set (each nonce signed by its owner). Anyone can run the standard verification and see it fail | Yes |
| The host changed someone's nonce before passing it on | The changed nonce does not carry its owner's signature, so members reject it in step 5 | Not needed; it is caught at once |
| The host gave different members different nonces of its own | Two nonces for the same round and item, both signed by the host | Yes |
| The host claims a member's partial signature is bad when it is not | The member's signed message names the nonce set it used; verification against that set succeeds | Yes, the claim is disproved |
| Someone did not answer | Nothing | No. Silence can only be observed, not proved |

**After a fault:** the faulty or silent signers are removed together and the host starts a new attempt, with a new round identifier, for those who remain. The host's terms say how many attempts are made and what happens if too few members remain.

## 8. Never left half-finished

The danger in any round is that the host ends up holding complete signatures while a member does not.

- **A member treats a round as finished only when it holds valid final signatures for its whole exit path.** Until then it behaves as if only the previous state exists: it accepts no payment and releases no secret that depends on the new one.
- **Creation:** members have nothing at stake, and the host signs funding last.
- **Later rounds:** the safe-to-sign checks require that the new state is at least as good for the member as the old one, and that the member's exit from any new output is signed before the transaction that creates it. So a host that withholds `round_complete` gains nothing: publishing the new state pays the member correctly, and the member can still use the old one.
- A member in the Unfinished state asks again on reconnect. If the host never answers, the member exits using what it holds.

## 9. Timers

Set by the host's terms and visible to members before they join. Starting values, to be tuned on signet:

| Step | Default |
|---|---|
| Ready check before the first attempt | 60 seconds |
| Nonces, per attempt | 30 seconds |
| Partial signatures, per attempt | 30 seconds |
| Attempts | 3 |

A host may set longer signing timers. Members' software must then stay running throughout, because of section 6.

## 10. Use of the imported code

| Step | Function in `core/superscalar` |
|---|---|
| Build the tree | `factory_init_from_pubkeys`, `factory_set_arity`, `factory_set_funding`, `factory_build_tree`, with sequential placement selected so member order never depends on a sort |
| Start signing for an item | `factory_session_init_node` |
| Generate a nonce | `musig_generate_nonce` |
| Record a signer's nonce | `factory_session_set_nonce`, then `factory_session_finalize_node` |
| Produce a partial signature | `musig_create_partial_sig` |
| Verify a partial signature | `musig_verify_partial_sig`. The imported code never calls this itself; the round engine must |
| Record and combine | `factory_session_set_partial_sig`, `factory_session_complete_node` |
| Verify the result | A standard signature check on each signed transaction |

The imported nonce generator reads randomness from the operating system directly. Until that is changed upstream, the engine cannot be simulated repeatably through that function; the hand-off note asks for a way to supply randomness.

## 11. How it is tested

1. Honest rounds of every purpose, at several sizes.
2. Each message dropped, delayed, duplicated and reordered, at each step.
3. A crash and restart of each party at each step. No secret nonce may survive a restart, and no party may sign twice.
4. Each fault in section 7, checking that the right party is named and the evidence verifies, and that an honest party cannot be framed.
5. A host that withholds `round_complete`: the member must lose nothing.
6. Removal of each rule in turn (nonce signature check, partial signature verification, the C7 record), each of which must make a specific test fail.
7. Fuzzing of every message decoder.

## 12. Open points

1. **Review of section 7** by someone expert in MuSig2.
2. **Whether the host should send its own partial signatures first**, and pass every member's partial signatures to the others, so that members can complete transactions themselves and the host is never the only one holding the result.
3. **Which key signs contributions.** The factory key is the natural choice. Whether signing other messages with it is acceptable needs checking.
4. **Size.** How nonce sets are split for the largest factories, and the largest round we support.
5. **Generating nonces early**, at the ready check, to save a step. BIP 327 permits it with care; it conflicts with nothing above but removes one of the standard's safeguards.
