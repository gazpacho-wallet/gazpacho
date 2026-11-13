# The signing round

Specification draft 4, 2026-11-12. Status: draft 3 corrected after a third, joint review of the five Slice 1 specifications (`docs/reviews/spec-review-3.md`), which judged draft 3 "ready after listed changes" and found that no finding needs a different cryptographic design. Draft 4 has not itself been reviewed. The parts on proving fault are this project's own design and have had no outside review. Values marked **proposed, owner to confirm** are Slice 1 choices the owner has not objected to and has not yet confirmed.

A signing round produces group signatures for a set of transactions. One engine runs every round in Gazpacho: creating a factory, updating a layer, rotating, closing. It follows the MuSig2 standard (BIP 327) and uses the imported signing code, with the exceptions in section 13.

Companion documents: `safety-rule.md` (draft 4), `messages.md`, `terms.md` and `journal.md` (draft 2, brought in line with this draft).

Marks used where it matters: **[C]** read in the imported code (file and line); **[S]** checked in a primary source (the secp256k1-zkp headers at the pinned commit were read for this draft; statements about BIP 327 rely on the passages review 2 fetched and quoted); **[R]** reasoning, not yet checked by a source or a test.

## Changes after review 3

| Finding | How it was handled | Where |
|---|---|---|
| F1 shape against the import | The level arity is the terms' interior widths followed by the leaf kind 3; the engine checks after building that every leaf is a one-member pseudo-Spilman leaf; test 12 checks the leaf kinds. Confirmed by building on the build server (`terms.md` section 4.2) | Sections 4.1, 13, 16 |
| F3 restore | S5 rests on the fresh-key rule; reason 12 means "the proposal lacks my current key for this lobby"; the epoch is drawn untagged, so nothing secret is journaled | Section 3 S5; section 8 |
| F4 leaf amount, F17 fixed levels | Leaf and funding amounts, fee per transaction and `fixed_levels` = D are functions of the terms (`terms.md` section 4.2) | Section 4.1 |
| F5 placement | Fixed by this specification at the import's value 0; not a proposal field; `messages.md` has no placement record | Section 4.1 |
| F6 creation states | Unfinished creation becomes Abandoned at the unfinished deadline; one name each for Abandoned and Dead; Dead records are no longer consulted, never removed; late funding re-runs the time checks | Section 7 |
| F7 C7 record | The tree digest is defined (`messages.md` 7.12); S1 saves the tier and item indices | Section 3 |
| F8 chain actions, F15 secret tag | Requirements on the core contract: watch a txid, watch an outpoint, a secret-tagged randomness request | Section 12.1 |
| F9 lost `start` | `start` is signed, saved and resent; a valid proposal for a check the member answered and was chosen in stands on its own | Section 6 step 1; `messages.md` 6.9 |
| F10 same identifier, other bytes | Every case is keyed on the round identifier (rule S6); contribution keys are now inside the identifier | Section 3 |
| F12 key before the lobby | A fresh index per new connection, bound to the lobby at `join` | Section 2 |
| F14 `round_abort` items | Slice 1 aborts whole rounds only; the tier and items are optional odd records | Section 4 |
| F18 hash order | Noted against the upstream fix | Section 12 |
| F24 anchors | Always on in 1.0.0 | Section 4.1 |
| F26 resend after reconnect | The member resends its saved `round_partial_sigs` after `hello` | Section 6, step 5 |
| F27 funding script length | Checked to be 34 bytes before `factory_set_funding` | Section 12 |
| G15, G17 | The nonce function uses the tweaked key-aggregation cache; the member waits one step timeout for the result | Sections 6, 8 |
| F19 stale text | Companion line; `messages.md` is no longer provisional; open point 3 closed | Header, section 17 |
| Slice 1 values | No distribution transaction; short life and host timeout; burial 3; deadlines (all **proposed, owner to confirm**, `safety-rule.md` section 12) | Section 15 |

## Changes from draft 2

| Finding | What changed | Where |
|---|---|---|
| N1 restore and the restart frame | A restored party never contributes with a key from before the restore; a replayed proposal naming one is refused | Section 3 rule S5; `safety-rule.md` section 9 |
| N4 no acknowledgement, no reconnect request | `round_ack` and `round_status_request` added; the host keeps results; creation has a step 9 | Sections 4, 6, 10 |
| N5 parameters never listed | New section 4.1, every setting that changes the tree's bytes, with source and C8 range; build sequence in section 13 | Sections 4.1, 13 |
| N6 retries against one tree per output | A retry after any released partial signature uses a new funding outpoint; the exposure record is written before the first partial signature | Section 11; `safety-rule.md` C7, H11 |
| N7 four contradictions | Rules per (round, tier, item); item indices unique in the round; tier inside the signed nonce; Aborted only before any partial signature; restart answer per item | Sections 1, 3, 4, 7 |
| N8 nonce function | `musig_generate_nonce` no longer named; the engine calls `secp256k1_musig_nonce_gen` directly with randomness from the port, tagged secret, and the message and an extra input | Sections 8, 13 |
| N9 channel states in tiers | Not specified in draft 3; requirement stated | Section 14.2 |
| N10 layer-update identifier | Not specified in draft 3; requirement stated | Section 14.3 |
| N2 leaf change | Draft 2's "Leaf change" tier withdrawn | Section 14.1 |
| N11 frozen terms | Both terms digests in the identifier; values frozen across attempts | Sections 3, 11 |
| N13 import hazards | Guard table extended; the overflow guard corrected; all session kinds mapped | Sections 12, 13 |
| N14 Unfinished | Stays paused, asks on reconnect, exits after a deadline; option of the host signing first in two-party tiers recorded | Sections 7, 10, 17 |
| N15 fault table | Two rows weakened; evidence includes the identifier's preimage; unsigned nonce sets stated | Section 9 |
| N16 unfunded creation | Funding transaction in the proposal; records end when a funding input is spent elsewhere; Abandoned state | Sections 4, 7 |
| N17 contribution key | Per lobby, two-way binding, duplicates refused, factory-key sentence corrected | Section 2 |
| N18 nonces at the ready check | Stated as incompatible with the identifier rules as written | Section 11 |
| N19 rotation | Partial rotation falls back to paying across | Section 5 |
| L8 deterministic last-signer nonce | Recorded, not adopted | Section 17 |

Review 1's residuals that this document carries: F4 (state table per tier) by N7; F5 (tier wording, indices, digests, restore) by N1, N7, N11; F6 (randomness) by N8; F10 (evidence, key) by N15, N17; F14 (hazards) by N13.

## 1. Parties and scope

- The **coordinator** is the host. It is also a signer in every transaction.
- **Members** are the other signers. Each talks only to the host.
- A round covers one or more **items**. An item is one transaction input to be signed. It has: an index, **unique within the round across all tiers** (0, 1, 2 … in tier order); its kind (tree node, distribution, penalty, or one input of a multi-input node; section 13); the output it spends; the signature digest; the ordered keys of its signers; and its **signing mode** (key path with a stated tweak, or script path with a stated leaf). A member signs only the items on its own path. Because the round identifier is unique, (round identifier, index) names an item uniquely everywhere.
- Items are grouped into ordered **tiers** (section 5).
- The engine does not decide whether signing is safe. It asks the safe-to-sign module (`safety-rule.md`) and obeys it.
- Every item is signed with a 64-byte signature, the default hash type and no annex.

## 2. Keys

- The **factory key** is the member's key in the group signature, one per lobby, derived under the current restore epoch (`safety-rule.md` section 9). It signs group-signature items and **one binding statement**, each with its own tag or digest. The import also pays two kinds of output to it: the distribution transaction's outputs [C: `factory.h:1258-1261`] and the penalty transaction's outputs [C: `factory.h:536-541`]. So it will later sign ordinary single-signer spends of those. Draft 2's "signs nothing but group-signature items" was wrong for the import. A payout destination other than the factory key is to be requested from SuperScalar; it fits owner decision 6 ("a destination per member").
- The **contribution key** signs the member's round messages. It is derived **per lobby**, under the restore epoch, and is never the member's long-lived node key. In `messages.md` it is the member's per-lobby BOLT 8 key. Published evidence (section 9) therefore links nothing beyond the lobby.
- **Which key before the lobby is known** (review 3, F12). The member opens a connection with a BOLT 8 key before it may know the lobby (a `hello` with scope zero lists lobbies). Rule: for every new connection that is not for a lobby it already has a seat in, the member allocates a **fresh key index** (saved in `key_index`, with the guard of `safety-rule.md` R6, before the handshake), and uses that key as BOLT 8 key; if it joins a lobby on that connection, that key becomes the lobby's contribution key and its factory key is derived at the next index, both bound to the lobby in the saved `join`. A connection for a lobby with a seat reuses the seat's key. An index allocated and never used for a join is simply skipped; nothing ever reuses it.
- **Binding, both ways.** In the lobby the factory key signs `TH("gazpacho/bind", lobby || factory key || contribution key)`, and the contribution key signs the same hash. Both signatures travel to every signer in `round_propose`, so anyone can check that each key vouches for the other. The host refuses two seats with one factory key or one contribution key.
- The **host's long-term key** signs terms, proposals and results, and serves as the host's contribution key for its own nonces.
- Every signed protocol message is a tagged hash with a tag specific to this protocol, so it can never equal the digest of a transaction.
- A participant list with any key twice is refused.

## 3. What identifies a round

```
round_id = tagged_hash(
    protocol name and version,
    chain (genesis hash),
    host's long-term key,
    outer terms digest, frozen current-values digest,
    funding output and amount,
    ordered participant factory keys and contribution keys,
    purpose, tier structure,
    for every item: index, output spent, signature digest, signing mode, ordered signer keys,
    host's fresh random value for this attempt )
```

- The signature digest already commits to every spent amount and script, every output, lock time and sequence. So every proposal parameter of section 4.1 is bound through the digests. The signer set and signing mode of an item are not in the digest, so they are listed separately.
- The current-values digest already includes the outer digest (`terms.md` section 6). Both are listed, as owner decision 1 describes; the cost is 32 bytes.
- A member computes the identifier from transactions it built itself. A member whose tree differs from another signer's computes a different identifier, so the other signers' nonce signatures fail against it at step 5, before any partial signature. This property is kept on purpose.
- The **contribution keys** are inside (draft 4; review 3, F10): every nonce signature is checked under them and section 9's evidence rests on them, so a round identifier now names the keys its nonces are signed with. 33 bytes per participant.
- The **tree digest** is the same hash without the protocol, host key, terms digests, contribution keys, purpose, tier structure and host random value: it names the transactions alone (`messages.md` section 7.12). C7's record holds it, and "the same tree" means the same tree digest (`safety-rule.md` C7).

**Rules on contributions.** These replace draft 2's single sentence, which read literally forbade every tier after the first (review 2, N7a and b).

- **S1. Save before the first nonce of a tier.** Before a party sends its nonces for a tier, it saves durably: the round identifier, the proposal's bytes, and the tier and item indices it is about to send nonces for (`journal.md` records `round_started` and `round_proposal`).
- **S2. One nonce and one partial signature per (round, item), ever.** A party never sends two different nonces, or two different partial signatures, for one (round identifier, item index). After a restart, an item whose nonce was sent before the restart can never be signed, because its secret nonce is gone. For such an item the party answers only `round_abort`. It never generates a new nonce for it.
- **S3. Resend saved bytes.** A message re-sent after a reconnect is the saved bytes, never a new signature. Public nonces are not resent after a restart (S2).
- **S4. A new attempt has a new host random value** and so a new identifier. *(Added after the signing engine build, 2026-11-12.)* The host's random value is not fresh randomness alone: it is a tagged hash of the randomness port's bytes, the node's **incarnation** (the runner's count of starts, saved before the node does anything else) and a **counter** that the host increments for every attempt it proposes in that incarnation. The engine builder found that a host restored from an old backup whose randomness repeated re-created a round identifier its members had already signed under. With the incarnation and the counter mixed in, two attempts never share a host random value even when the random source repeats.
- **S5. No contribution with a recovery-only key.** A party contributes only to a round whose participant list contains, exactly once, its **current** key for that lobby (`safety-rule.md` C7, "Fresh funding output"); otherwise it answers `round_abort` reason 12. A restored party never derives a key from before the restore, so a replayed proposal, which names the old key, always fails this check; no step tries to recognise the old key (`safety-rule.md` section 9, R4). This is what stops a host from replaying a proposal to a restored member to collect a second signed nonce under an old identifier (review 2, N1).
- **S6. One proposal per identifier.** Every case is keyed on the round identifier, never on the proposal's bytes. A proposal whose identifier the party has saved is the saved proposal, whatever its other fields say (check identifier, attempt, terms version, deadlines, bindings): the party answers as the saved round's state requires (`messages.md` 7.2) and generates nothing new. If its bytes differ from the saved ones and it is validly signed, it is kept as evidence that the host signed two proposals under one identifier (review 3, F10).

## 4. Messages

Carried as factory messages inside the Lightning connection. The encoding is in `messages.md` draft 2, section 7, which follows this draft.

| Message | From → to | Carries | Signed by |
|---|---|---|---|
| `round_propose` | Host → member | Purpose; the parameters of section 4.1; the **unsigned funding transaction**; the ordered participant list with both binding signatures per participant; tiers; deadlines; the host's random value | Host's long-term key |
| `round_nonces` | Member → host | For each of the member's items in this tier: its index, a public nonce, and a signature over (round identifier, tier, index, nonce) | Each entry by the member's contribution key |
| `round_all_nonces` | Host → member | For each of the member's items: every signer's public nonce with its signature | Carried signatures only |
| `round_partial_sigs` | Member → host | The tier; for each item, its index, the member's partial signature, and a digest of the exact nonce set the member used | Member's contribution key |
| `round_tier_result` | Host → member | The final signatures of a tier | Host's long-term key |
| `round_complete` | Host → member | Everything the member's safety analysis relies on that the tier results did not carry. For a tree-only creation round, nothing beyond closing the round | Host's long-term key |
| **`round_ack`** | Member → host | The round identifier and a digest of what the member now holds (its signed items). Sent after the member has verified and stored every tier result and `round_complete` | Member's contribution key |
| **`round_status_request`** | Member → host | The round identifier. Sent on every reconnect while the round is Unfinished, or Complete and not yet live | Unsigned |
| `round_abort` | Either way | A reason; the tier and items it concerns, if not the whole round (optional; Slice 1 aborts whole rounds only); evidence where fault can be shown | Sender |

- Parameters are sent, not transactions, except the funding transaction. A member builds the tree itself. The funding transaction is sent because the member cannot build it (it spends the host's coins) and must know its txid and inputs: the txid fixes the funding outpoint before anyone signs, and the inputs let the member see when the funding can never exist (`safety-rule.md` C4(d)).
- The nonce signature covers `TH("gazpacho/nonce", round_id || tier || index || public nonce)`. With indices unique in the round, two different signed nonces under one (round, index) are always equivocation, never an honest second tier (review 2, N7d).
- `round_ack` is the host's trigger to fund (`safety-rule.md` H1). Being signed, it lets the host show that each member held its signed path before the funding was signed.
- `round_status_request` is answered with the saved bytes of every `round_tier_result` sent to that member for the round, then `round_complete` if it was sent; or with `round_abort` and its reason if the round failed. The host keeps these bytes until the funding output is spent or the creation is dead (`safety-rule.md` H12).
- One item's nonce set for a 513-signer root is larger than one Lightning message once signatures are included. Every item's data is therefore splittable across messages (`messages.md` section 5).
- A second `round_all_nonces` for the same round and tier with different bytes is rejected and kept as evidence.
- The digest of a nonce set is a tagged hash over the nonces in signer order, each in its standard 66-byte form.

### 4.1 Proposal parameters

For two parties to build byte-identical trees, every input to the imported builder must match. The member rebuilds from four sources: the host's **outer terms**, the **frozen current values** (`terms.md`), the values **derived from the terms** by `terms.md` section 4.2, and the **proposal fields**. Constants of the import are listed so that nobody mistakes them for parameters. Anything not in this table that changes a transaction's bytes is a defect in this table. A proposal field whose value is fixed or derived here must equal that value, or the member refuses (reason 9).

| Setting | Import | Source | C8 rule (`safety-rule.md`) |
|---|---|---|---|
| Participant factory keys, in tree order, host first | Argument of `factory_init_from_pubkeys` [C: `src/factory.c:853-860`] | Proposal (`participants`) | Distinct; own key present once, current epoch, this lobby only |
| Layer step and states per layer | Arguments of `factory_init_from_pubkeys` [C: `src/factory.c:853-860`] | Proposal | Inside conditions. While every level is fixed they change no byte (build server, 2026-11-12: (144, 4) and (1, 2) give the same txids), so Slice 1 fixes them at **144 and 4** to keep one encoding per tree |
| Shape: arity per level | `factory_set_level_arity` [C: `src/factory.c:1164-1176`] with the list `interior ‖ leaf_kind` from the terms' shape entry for the member count (`terms.md` section 4.1), never empty (section 12). **The last entry is the leaf type**; 3 = pseudo-Spilman | Outer terms | As the terms give; inside conditions. After building, **every leaf is a pseudo-Spilman leaf with exactly one member** (`is_ps_leaf`, two signers), the member's own key on exactly one (`safety-rule.md` C8) |
| Fixed levels near the root | `factory_set_static_near_root` [C: `src/factory.c:1189`] | Proposal (`fixed_levels`), which must equal D (`terms.md` section 4.2) | All interior levels in 1.0.0 |
| Members per sub-factory, K | `factory_set_ps_subfactory_arity` [C: `src/factory.c:1059`] | Proposal | 1 in 1.0.0 |
| Placement | Field `placement_mode`; no setter; the default sorts [C: `src/factory.c:831`, `:889`, `:1961-1974`] | **Fixed by this specification; not a proposal field** (`messages.md` has no placement record) | Sequential (`PLACEMENT_SEQUENTIAL`, value 0, `factory.h:60`), written by the engine |
| End height (`cltv_timeout`) | Field, no setter [C: `factory.h:358-359`]; used for every node timeout and the channel timeout leaf [C: `src/factory.c:1632-1644`, `:541-548`] | Proposal (`end_height`), checked against tip + lifetime + wind-down from the outer terms | Not past; leaves exit time plus margin; not 0 |
| Tree anchors | Field `use_tree_anchor` [C: `factory.h:434-440`; `src/factory.c:498-507`] | Proposal (`tree_anchors`), which must be 1 | **Always on in 1.0.0** (owner decision 6, pay-to-anchor outputs; review 3, F24). Hence interior widths of at most 15 (`terms.md` 4.1) |
| Fee per tree transaction | Field `fee_per_tx` (default 200) [C: `src/factory.c:861`]; overridden by a fee estimator if one is set [C: `:1900-1903`] | Derived from the terms: ⌈`tree_feerate` × largest signed size / 1000⌉ (`terms.md` section 4.2); the proposal's `fee_per_tx_sat` must equal it | At most the member's ceiling. The engine sets no estimator, so no estimator state enters the bytes |
| Spare-liquidity delay | `factory_set_l_stock_csv` [C: `src/factory.c:1054`; default `factory.h:50`] | Proposal | Inside conditions |
| Hash path on spare-liquidity outputs, and the hash per node | Fields `use_hashlock_poison` and the member's mirror via `factory_set_node_l_stock_hash` [C: `factory.h:387-398`; `src/factory.c:387-415`] | Proposal (`lstock_hashes`) | One hash per state; no node with index 512 or more carries a hash (section 12). **Slice 1: no hashes, `use_hashlock_poison` written as 0** (no penalties in Slice 1, section 15) |
| Funding txid, output index, amount and script | `factory_set_funding`, taken on trust, and silently ignoring a script longer than its buffer [C: `src/factory.c:1214-1228`] | Proposal: outpoint, amount, script, and the funding transaction itself | Txid equals the funding transaction's; amount equals its output and the terms' funding rule R(root) (`terms.md` section 4.2); script equals its output, is exactly 34 bytes, and is the aggregate (C1) |
| Split of each leaf between channel and spare liquidity | Fixed at half each [C: `src/factory.c:1299-1323`] | Import constant | Checked by rebuilding |
| Channel amount per member | Follows from the funding amount, the fee, the anchors and the shape: equal shares per child, remainder to the last [C: `src/factory.c:1694-1720`, `:1759-1761`] | Outer terms (`channel_sat`) through `terms.md` section 4.2 | Every leaf's channel output at least `channel_sat`; the member's own at least its own minimum |
| Distribution transaction outputs and lock time, if signed | Arguments of `factory_build_distribution_tx_unsigned` [C: `src/factory.c:4516-4568`]; its anchor depends on the fee estimator [C: `:4532-4539`; `src/fee.c:90-97`] | Proposal (`distribution`) | Lock time at least the end height; member's share at least its capacity. With no estimator set, the anchor is present. **Not in Slice 1** (**proposed, owner to confirm**) |
| Transaction version, lock time and sequence of tree transactions | Fixed by the builder, sequence from the layer state [C: `src/factory.c:124-149`, `:604`] | Import constant | Rebuilt |

`messages.md` section 7.2 encodes these fields.

## 5. Tiers

A tier is a set of items that may be completed together. The engine releases a member's partial signatures for a tier only after the member holds and has verified the final signatures of the tier before it.

| Round | Tiers, in order |
|---|---|
| **Creation** | One tier: the tree transactions, and the distribution transaction if the owner decides it is signed. Nothing is at stake until funding is buried, and the host funds last. Whether the first channel states belong here is not specified yet (section 14.2). Slice 1 signs no distribution transaction (**proposed, owner to confirm**) |
| **Cooperative close** | One tier, with the channel paused from the first partial signature until the funding output is spent |
| **Rotation by closing into a new factory** | 1. The whole new tree with its opening channel states. 2. The transaction that spends the old funding output into the new one. Needs every signer of the old root; if some members do not rotate, rotation falls back to paying across. The opening channel states fall under section 14.2 |
| **Leaf change** | Withdrawn (section 14.1) |
| **Layer update** | Not specified yet (sections 14.2 and 14.3). Draft 2's requirement stands for whoever specifies it: tiers run from the leaves upward, and for the last tier the host sends its own partial signature and every member's to all signers, so any member can complete the state transaction |

## 6. Steps within a tier

1. **Propose** (once per attempt). The host has sent each chosen member a signed `start` (`messages.md` 6.9), which both sides save and the host resends after a reconnect; it then sends `round_propose`. A member accepts a validly signed proposal whose check identifier is one it answered, unless it holds a saved `start` for that check that did not choose it (role 2). It does not need the `start` itself: the signed proposal carries everything, so a `start` lost across a reconnect costs nothing (review 3, F9).
2. **Check.** Each member verifies the host's signature and every binding, rebuilds the transactions, computes the round identifier, runs the safe-to-sign checks, and saves (rule S1). On failure it sends `round_abort` and stops.
3. **Nonces.** Each member generates a fresh secret nonce per item (section 8) and sends the public parts.
4. **Distribute.** When the host has every signer's nonces for the tier, it sends `round_all_nonces`.
5. **Verify and sign.** Each member checks every nonce's signature, confirms its own nonces are present and unchanged, runs the safe-to-sign checks again, then saves in one atomic write the exposure record (`safety-rule.md` C7) and the `round_partial_sigs` bytes, and only then sends them. After a reconnect while the result is missing, the member resends these saved bytes after `hello`, before `round_status_request` (rule S3; review 3, F26), so a host still collecting partial signatures gets them.
6. **Verify.** The host verifies each partial signature as it arrives.
7. **Result.** The host combines, verifies each final signature from the transaction's bytes, saves the result, and sends `round_tier_result`.
8. **Accept.** Each member verifies the final signatures and saves them. The next tier begins, or `round_complete` ends the round. A member waits for the result at most the terms' step timeout after sending its partial signatures; then it is Unfinished (section 7).
9. **Acknowledge (creation).** Each member verifies and stores `round_complete`, then sends `round_ack`. The host funds only when it holds every chosen member's ack (`safety-rule.md` H1). Each member then watches the funding txid to the burial depth and every input outpoint of the funding transaction (section 12.1), until its funding deadline.

## 7. States

State is kept **per round and per tier**. One tier's failure after an earlier tier released partial signatures does not erase what that earlier tier exposed.

**Member**

| State | Meaning | Leaves on |
|---|---|---|
| Idle | — | `round_propose` → Checking |
| Checking | Verifying and rebuilding | Checks pass and saved (S1) → Nonces sent (tier t). Checks fail → Aborted |
| Nonces sent (tier t) | Holds secret nonces for tier t | Valid `round_all_nonces` → Signed (tier t). Deadline, invalid data, `round_abort`, or restart → **Aborted if no partial signature was ever sent in this round; otherwise Unfinished** |
| Signed (tier t) | Partial signatures for tier t sent; exposure recorded | Valid tier result → Nonces sent (tier t+1), or Complete after the last tier. Step timeout, invalid result, `round_abort` → Unfinished |
| Complete | Holds every tier result and `round_complete` | Ack sent → Awaiting funding |
| Awaiting funding (creation) | Ack sent | Funding buried → Live. Funding deadline → Abandoned. A funding input spent elsewhere and buried → Dead |
| Live | The factory is live (C11) | — |
| Aborted | No partial signature was ever sent | Secret nonces erased; the identifier and items stay refused |
| Unfinished | Partial signatures sent, result missing | Valid result (from `round_status_request` or a resend) → the state it completes. Unfinished deadline → for a creation round, **Abandoned** (there is nothing to exit); for other purposes, exit (section 10). A funding input spent elsewhere and buried → Dead |
| Abandoned (creation) | Funded too late or not at all, or the result never came | Records kept; no longer blocks the member (C10). Funding buried later → Live, only if the member holds the whole signed tree and the C5 and C8 time checks pass again at that moment. A funding input spent elsewhere and buried → Dead |
| Dead | The round's outputs can never exist (C4(d)) | Records **kept but no longer consulted**: they block nothing and count for nothing. Nothing is removed from the journal (`journal.md` record `round_ended`, outcome dead) |

**Names.** "Abandoned" always means a deadline passed (funding or unfinished); "Dead" always means a funding input was spent by another buried transaction. No other document uses either word for the other case (review 3, F6).

**Aborted is reachable only while the member has sent no partial signature in the round.** After that, every failure leads to Unfinished, with the exposure recorded, because the host may hold signatures it can complete. A `round_abort` from the host to a member in Signed or Unfinished is recorded and changes nothing.

**A restart.** Secret nonces are gone. For every item whose nonce was sent and whose partial signature was not, the member sends `round_abort` for those items when asked again (S2). The round becomes Aborted if no partial signature was ever sent, else Unfinished. Saved partial-signature bytes are resent when asked.

**Host:** collecting nonces → collecting partial signatures → tier result → next tier → complete → collecting acks → funded; or failed, with a list of who did not answer or sent something invalid. A host that restarts mid-attempt starts a new attempt (`safety-rule.md` H13), on a new funding outpoint if any partial signature had been released (H11).

A party takes part in at most one unresolved round touching any given output. The host runs rounds one at a time per subtree.

## 8. One-time secrets

BIP 327 says a secret nonce must never be used to sign twice, since two signatures can reveal the signer's key, and that nonces must not be derived deterministically from the session's parameters [S].

**How a secret nonce is made.** The engine has its own nonce function. It calls `secp256k1_musig_nonce_gen` of the pinned secp256k1-zkp directly [S: `include/secp256k1_musig.h` at commit `6152622`] with:

| Argument | Value |
|---|---|
| `session_id32` | `TH("gazpacho/session-id", secret port bytes ‖ incarnation ‖ counter)`: 32 bytes from the core's **randomness port**, with the request tagged **secret** (a contract change, section 12.1), hashed with the node's incarnation and an in-memory counter (rule below; added after the signing engine build) |
| `seckey` | The secret factory key |
| `pubkey` | The factory key |
| `msg32` | The item's signature digest, which the member computed itself |
| `keyagg_cache` | The item's key-aggregation cache **with the item's tweak applied**: exactly the cache later passed to the partial-signing call. For a script-path item (the penalty, not in Slice 1) that is the untweaked cache. Either would satisfy the library; one is chosen so that two builds are comparable (review 3, G15) |
| `extra_input32` | `TH("gazpacho/nonce-extra", round_id || tier || index)`: the round identifier and item, hashed to the 32 bytes the function takes |

The library documents the message, the cache and the extra input as optional inputs that increase misuse resistance [S]. BIP 327 calls such inputs a defence in depth, to be "viewed as a last resort" [S]. They are used as that, not as the protection. The protection is the fresh `session_id32`. Because `session_id32` is fresh randomness, the nonce is not derived deterministically from the session's parameters.

**Rules.**

- **The randomness port, tagged secret.** In release builds a secret request reads the operating system's random source at the moment of the call. The bytes go only to the caller. They are never journaled, logged, put in an event, or produced by a generator whose state is saved or can be restored. Randomness that **is** saved (the restore epoch, `safety-rule.md` R2; the host's random values, check identifiers and lobby salts, which travel in messages) uses the ordinary, untagged request.
- **How `session_id32` is formed** *(added after the signing engine build, 2026-11-12; the engine builder's decision, now the rule)*. `session_id32 = TH("gazpacho/session-id", s ‖ incarnation ‖ counter)`, where `s` is 32 bytes from a secret-tagged request, `incarnation` is the node's saved count of starts (8 bytes, big-endian), and `counter` is an 8-byte big-endian count kept in memory only, starting at zero in each incarnation and incremented for every `session_id32` made. Neither the result nor `s` is saved. The incarnation and counter add no secrecy; they make sure that a repeating random source (a restored backup, a copied machine, a seeded simulator) still never gives two nonce calls the same `session_id32` within or across incarnations. The fresh secret bytes remain the protection.
- **Seeded only in the simulator.** The core is handed its randomness so that a factory can be simulated from a seed (`DESIGN.md` section 4). The seeded source exists only in simulator builds and cannot be linked into a release build.
- **Not used from the import:** `musig_generate_nonce` and the import's nonce pool. Both read `/dev/urandom` themselves, so they cannot take the port's randomness and fail where there is no such file, including a native Windows build; and `musig_generate_nonce` passes no message and no extra input [C: `src/musig.c:9-15`, `:171-209`, `:463-480`]. No imported file needs editing for this: the import itself calls `secp256k1_musig_nonce_gen` with a message [C: `src/musig.c:75-77`] and with an extra input [C: `:198-201`].
- **Memory only.** A secret nonce lives in memory only, and is erased as soon as it has signed or the round ends for any reason. The library itself zeroes a secret nonce when it signs and aborts if handed an all-zero one [S: `secp256k1_musig_partial_sign`, same header].
- **No recreation.** Rebuilding a node from its journal never recreates a secret nonce. Any item found with a nonce sent and no partial signature can never be signed: the member answers it only with `round_abort` (rule S2, section 7).
- **The complete set first.** A partial signature is produced only after the complete nonce set for that item has been received and checked. This is stricter than the standard, which needs only the combined nonce; the individual nonces are needed to verify partial signatures.
- **Copies of a running program,** such as a machine snapshot, can repeat a secret nonce. Nothing in software prevents this; it is listed among the limits.

## 9. Who broke the round

BIP 327 lets honest parties identify a signer who sent a bad partial signature under three conditions: contributions are not tampered with, the nonces are combined honestly, and every partial signature is verified. It warns that whoever combines could otherwise blame an honest signer, and it does not address convincing a third party [S]. The scheme here is our extension.

**What can be shown, and to whom**

| Fault | Evidence | Convinces a third party? |
|---|---|---|
| A member sent a bad partial signature | The host-signed proposal and the **round identifier's preimage**, from which the verifier gets the item's signature digest, tweak or leaf, and signer keys; every signer's signed nonce for the item; the member's signed partial-signature message. The verifier recomputes the session and runs the standard check | Yes |
| The host altered someone's nonce | It lacks the owner's signature and is rejected at step 5 | Not needed |
| A party signed two different nonces for one (round, item) | Both signed nonces. Never honest under rules S1 and S2 | Yes, against that party's contribution key |
| A member names a nonce set that never existed | An unopened digest. That the member *cannot* open it is shown only by a challenge with a deadline that goes unanswered | **No.** It is the host's claim, unless the member answers the challenge |
| The host says a good partial signature is bad | Verification against the set the member named succeeds | Yes, the claim is disproved |
| The host sent wrong final signatures | The host's signature on the result | Yes |
| The host's proposal fails a check anyone can evaluate: a duplicate key, a malformed value, a timeout already past at a stated height, a funding script that is not the aggregate | The host's signature on the proposal | Yes |
| The host's proposal fails a member's private limits (C8) | — | **No.** A third party cannot see the member's conditions; such a refusal is the member's choice, not the host's fault |
| The host sent a malformed or inconsistent nonce set | `round_all_nonces` is not signed as a whole | No. The member can only refuse |
| Someone did not answer, answered late, or sent something malformed | Nothing that a third party can check | No |
| Two parties built different transactions and so signed different identifiers | A disagreement, shown only by rebuilding the tree from the signed proposal | Only with that work |

**Limits, stated plainly**

- **A host that also holds a member seat can break a round and put the blame on that seat.** It gives one member a different nonce from its own seat; the evidence then points at a throwaway identity. The scheme catches a host only when it equivocates under its own key.
- **A host can assert that any member was silent** and leave it out. Apps that keep a history of who stalled record that as the host's claim, not as fact.
- **A valid partial signature does not prove who made it.** The standard says partial signatures are not signatures. Evidence always rests on the signed contribution.
- **Member identities are new per lobby by default,** so proof against a member matters only inside that lobby. Proof against the host's long-term key is the valuable kind.
- **Publishing evidence reveals** the participant keys of the item, hence who is in that factory or branch.
- Checking evidence is a program, not something read by eye.

**After a fault:** the faulty or silent signers are removed together and the host starts a new attempt with a new round identifier, on a new funding outpoint if any partial signature had been released (section 11).

## 10. Never left half-finished

Someone always completes first. The aim is that whoever does gains nothing by withholding.

- **Creation.** The host funds only after every chosen member has sent `round_ack` (`safety-rule.md` H1). A member treats the factory as live only when the funding is buried (C11). A member that withholds its ack costs the attempt, like a silent member: the host must start again without it, on a new funding outpoint. A host that never funds costs the member nothing: the creation becomes Abandoned at the funding deadline, and Dead once a funding input is spent elsewhere.
- **Cooperative close and rotation.** One tier spends the funding output; the channel stays paused until that output is spent or the round is resolved.
- **Layer update.** Not specified yet (section 14). The requirement that every signer can complete the last tier stands.
- **Unfinished.** A member that has sent partial signatures and lacks the result stays paused on every affected channel. It sends `round_status_request` on every reconnect. If the round is not resolved within the unfinished deadline set in its conditions, it exits; an Unfinished creation round becomes Abandoned instead, since nothing is owed before funding is buried. It never assumes the old state is the only one. A host that withholds a result, or that lost its own secret nonce and so can never complete, leaves the member no remedy but that exit (`safety-rule.md` section 11).

## 11. Time, attempts and size

- **A time budget, not a count.** With many signers, a fixed number of attempts does not converge: if each of 512 members fails an attempt one time in a hundred, about one attempt in 170 succeeds. The host sets a total time for the round (the terms' signing budget); attempts repeat within it, each preceded by a ready check a few seconds earlier, each without those who failed the last.
- **Frozen values across attempts.** Every attempt within one round's time budget uses the same frozen terms (owner decision 1; `safety-rule.md` C8a). Only the participant set, the funding outpoint and the host's random value may change between attempts.
- **A new funding outpoint after any release.** An attempt that follows one in which any partial signature was released uses a new funding transaction, which spends at least one input of the previous one (`safety-rule.md` H11). Members refuse a different tree on an outpoint they hold an exposure record for (C7), and they are right to: the members who dropped out are part of the adversary, so the earlier tree may be complete in the host's hands. An attempt that failed in the nonce step may reuse the outpoint: no exposure record exists yet.
- **Nonces at the ready check** would leave one exchange that everyone must complete in place of two. As written it is **incompatible with this specification**: at the ready check there is no proposal, hence no round identifier and no item digests, so the nonces cannot be bound to a round, rule S1 has nothing to save, and the library's misuse-resistance inputs are unavailable. BIP 327 allows early nonces with more care and says they are not compatible with the defence-in-depth inputs [S]. It would need its own pre-round identifier fixed by the ready check, with its own refusal record. It stays off.
- **Deadlines run on each party's own clock.** Someone who can delay messages can push chosen members out of an attempt. That costs them a seat, not money.
- **Size at 512 members** (shape 15, 15, pseudo-Spilman leaves): a member signs roughly 17 to 20 items and uploads a few kilobytes; it downloads on the order of 130 kilobytes per attempt; the host sends on the order of 70 megabytes per attempt and makes about ten thousand verifications. These are estimates. Until the import's defects in section 12 are fixed, a factory is limited to about 128 members.
- **A lighter variant, for later review:** members receive only the combined nonce, a root over all signed nonces signed by the host, and proof that their own nonce is included.

## 12. Guards around the imported code

The engine must do these itself, because the imported functions do not:

| Hazard in the imported code | The engine's guard |
|---|---|
| Setting a signer's nonce twice counts twice, so "all collected" can be true with a slot empty [C: `src/musig.c:307-321`] | Track slots; a repeated `round_nonces` is an error before any call |
| **Setting a partial signature twice counts twice as well**, in the node and the distribution sessions [C: `src/factory.c:2066-2076`, `:4606-4612`] | Same slot tracking for partial signatures |
| Bad input to the signature library can stop the whole program. A failed argument check calls the library's illegal callback, whose default "writes the message to stderr and calls abort" [S: `include/secp256k1.h` at the pinned commit]. Whether an unset session structure fails such a check is expected, not tested | Parse and reject every nonce and signature from the network before it reaches a session function; never pass an unset slot |
| Duplicate participant keys are accepted [C: `src/musig.c:17-36`] | Refuse them |
| A routine exists for a hash type that lets inputs be added [C: `src/tapscript.c:663-680`] | No item may use it |
| The penalty is signed on a script path under the untweaked group key [C: `musig.h:186-195`; `src/musig.c:374-406`] | The signing mode is part of the item and of the round identifier |
| Partial signatures are never verified [C: `src/factory.c:2066-2076`, `:3139-3158`] | `musig_verify_partial_sig` on each as it arrives |
| `factory_session_complete_node` does not verify the final signature [C: `src/factory.c:3139-3158`] | A standard signature check on each signed transaction, from its bytes (section 13, last row) |
| Placement has no setter; the default sorts by time zone over profiles that are all zero, so the order is whatever the C library's sort does [C: `src/factory.c:831`, `:889`, `:1970-1973`] | Write `placement_mode = PLACEMENT_SEQUENTIAL` after initialising and before building |
| **The layer counter is written out of bounds inside initialisation** from 257 members: `factory_init_from_pubkeys` computes the layer count for a two-way tree and `dw_counter_init` writes `layers[i]` for every i with no bound, into an array of 8 [C: `src/factory.c:880-884`; `src/dw_state.c:36-46`; `dw_state.h:38-41`]. Draft 2's guard ("set the shape immediately after initialising") only overwrites the damage afterwards | No factory of more than 256 members until SuperScalar bounds the write (to be requested). It is undefined behaviour, which the build with undefined-behaviour checks may report. The next row's limit is lower in any case |
| The member's copy ignores the host's spare-liquidity hash for a node index of 512 or more: the check uses the compile-time `FACTORY_MAX_NODES`, not the grown array [C: `src/factory.c:391-397`]. The member then builds a different script from the host's, so the trees diverge. Reported in review 1 (F11); still in the import | Refuse a tree in which a node that carries a hash has index 512 or more (`safety-rule.md` C8). With one member per leaf that is about 128 members [R, from the node bound at `src/factory.c:1917`]. The cap applies only when the optional hashlock penalty is on (SuperScalar's reply, 2026-11-12); a tree with no hashes is not limited by this row. Being fixed upstream in their pull request 486 |
| Re-initialising a node session does not free a live large session first [C: `src/factory.c:3109-3116`; contrast `:2036`] | A fresh tree object per attempt. Each attempt has a new funding outpoint or participant set anyway, hence new transactions |
| `factory_set_level_arity` with an empty list reads `arities[-1]` [C: `src/factory.c:1176`] | Never call it with an empty list |
| A fee estimator, if set, overrides the fee per transaction and decides whether the distribution transaction has an anchor [C: `src/factory.c:1900-1903`; `src/fee.c:90-97`] | Set no estimator; set the fee per transaction from the proposal |
| The level-arity list's last entry silently sets the leaf type, and a node at most as wide as its level becomes one multi-member leaf [C: `src/factory.c:1175-1176`, `:948-955`] (review 3, F1) | Write `interior ‖ 3` only; after `factory_build_tree`, check every leaf's `is_ps_leaf` and signer count, and refuse otherwise |
| `factory_set_funding` returns nothing and silently ignores a script longer than its 34-byte buffer [C: `src/factory.c:1219-1222`] | Check the script is exactly 34 bytes before the call (review 3, F27) |
| `factory_set_node_l_stock_hash` drops an index at or above the **current** `max_nodes` [C: `src/factory.c:411`], and `factory_build_tree` grows the arrays and zeroes the new tail only later [C: `:1919-1936`]. So even after the upstream fix of the 512 check, mirror hashes for high indexes set in section 13's order would be lost | Slice 1 sets no hashes. When the 512 fix lands, set the mirror hashes after the arrays have grown, or ask SuperScalar to grow them first (review 3, F18) |

### 12.1 Requirements on the core contract

Not code changes made by this specification: requirements that `core/gazpacho/include/gazpacho/ports.h`, `action.h` and `event.h` must meet before the signing engine and the creation checks are written. The first four are met by the core contract for Slice 1 (pull request 21, `core-contract-slice1`); the fifth is a duty of the program, not of the core. The last four come from the program skeleton's findings and are met by contract v2 (`docs/notes/contract-v2.md`), in the pull requests named.

| Requirement | Why | Where it is met |
|---|---|---|
| **A secret tag on the randomness port**: a request marked secret, whose bytes are never journaled, logged or put in an event, and come from a seeded source only in simulator builds (section 8) | `session_id32`, and nothing else in Slice 1 | `GZ_RANDOM_SECRET` and `GZ_RANDOM_ORDINARY` (`ports.h`); the simulator refuses secret draws shorter than 16 bytes and checks that no 8 contiguous secret bytes leave in an action (`sim.h`, "secrets never leave") (review 3, F15) |
| **Watch a txid**: report the confirmations of a given transaction, up to a requested depth, and its disappearance in a reorganisation | C11: the member watches the funding txid to the burial depth | `GZ_ACTION_WATCH_TX` (`action.h`), answered by `GZ_CHAIN_TX_CONFIRMED` and `GZ_CHAIN_TX_UNCONFIRMED` (`event.h`); txids in the byte order the chain hashes them (review 3, F8) |
| **Watch an outpoint**: report when a given outpoint is spent, with the spending txid and its confirmations | C4(d) and Dead: the member watches each input of the funding transaction, whose scripts it does not know (the funding transaction is sent without its previous outputs) | `GZ_ACTION_WATCH_OUTPOINT`, answered by `GZ_CHAIN_OUTPOINT_SPENT`, 0 confirmations meaning not final (`action.h`). The Esplora-style chain view can answer both (`docs/CHAIN-SERVERS.md`) |
| **A restore marker at start**: the program tells the node, before any other event, that this start follows a restore; the node answers with its first save batch (`key_epoch`, `restored`, `guard`) through the runner, as sequence 1 of the new incarnation | `safety-rule.md` R2; `journal.md` section 8 (review 3, F22: no batch is ever written outside the runner) | `restored` in `gz_storage_reader_t` (`ports.h`, the restore marker); the restore epoch is mixed with the incarnation (R2) |
| **The guard's storage duty**: a batch holding a `guard` record is confirmed only after the guard file is replaced and synced as well (`journal.md` section 8.3) | `safety-rule.md` R6 | A duty of the program around the runner, like the journal's; nothing in the runner changes |
| **The key before the handshake**: a connection with a fresh key index is made only after the batch holding that `key_index` (and its `guard`) is confirmed (section 2) | Section 2, review 3 F12: no key is shown to anyone before its index is saved | `GZ_ACTION_CONNECT`, outward, so the runner holds it behind the save (`docs/notes/contract-v2.md` section 3; pull request P4) |
| **Messages carry kind and scope**: a round message is sent and received as (`kind`, `scope`, `records`), so the engine never builds or parses the envelope header | `messages.md` sections 4 and 5: the signature covers kind and scope; the transport splits and reassembles | `SEND` and `GZ_EVENT_MESSAGE_RECEIVED` (contract v2 section 7; P4) |
| **A peer named by its keys**: resends after a restart are addressed to the link (our key, its key), which a restart does not change | Rule S3 and `messages.md` 6: the member resends `round_partial_sigs` after reconnecting | `gz_link_t` (contract v2 section 2; P4); resends at `GZ_EVENT_PEER_CONNECTED` (node rule 6) |
| **An incarnation that a restore of the journal alone cannot rewind**: the restore epoch and nonce inputs mix in the incarnation. A snapshot of the whole data folder or machine rolls it back too and is not defended (storage 6.4); there only the epoch's random draw protects | Section 8; `safety-rule.md` R2 | The start counter `starts.gzs` (contract v2 section 8): a stand-in in P3, sealed in P9; a duty of storage |

## 13. Use of the imported code

| Step | Function in `core/superscalar` |
|---|---|
| Build the tree | `factory_init_from_pubkeys` [C: `src/factory.c:853`], then at once, in one fixed order on every party: `factory_set_level_arity` [`:1164`] with `interior ‖ 3` (never `factory_set_arity` in 1.0.0), `factory_set_static_near_root` [`:1189`] with D, `factory_set_ps_subfactory_arity` [`:1059`] with 1, `factory_set_l_stock_csv` [`:1054`]; write the fields `placement_mode` (0), `use_tree_anchor` (1), `use_hashlock_poison` (0 in Slice 1), `fee_per_tx`, `cltv_timeout`; set the member's mirror hashes with `factory_set_node_l_stock_hash` [`:409`] (none in Slice 1); check the funding script is 34 bytes; `factory_set_funding` [`:1214`]; `factory_build_tree` [`:1882`], which recomputes the layer counter from scratch [`:1940-1944`]; then check every leaf (section 12). This order was run on the build server on 2026-11-12 for T1 at 3, 4, 5, 8 and 16 members (`terms.md` section 4.2) |
| Build the distribution transaction, if signed | `factory_build_distribution_tx_unsigned` [`:4516`] |
| Start signing an item | Tree node: `factory_session_init_node` [`:3109`]. Distribution: `factory_session_init_dist` [`:4577`]. Penalty (script path): `factory_session_init_node_poison` [`factory.h:942`]. One input of a multi-input node (K > 1, not in 1.0.0): `factory_session_init_node_input` [`factory.h:893`] |
| Generate a nonce | **The engine's own function** calling `secp256k1_musig_nonce_gen` (section 8). Not `musig_generate_nonce` |
| Record a signer's nonce | `factory_session_set_nonce` [`:2043`], or the `_dist`, `_poison`, `_input` variant; then the matching `finalize` |
| Produce a partial signature | `musig_create_partial_sig` [`src/musig.c:408`] |
| Verify a partial signature | `musig_verify_partial_sig` [`src/musig.c:423`] |
| Record and combine | `factory_session_set_partial_sig` [`:2066`], `factory_session_complete_node` [`:3139`], or the matching variant |
| Verify the result | A standard signature check on each signed transaction, from its bytes |

The imported code keeps one signing session per tree node **for each kind of signature**: each node has a main session and a second, independent penalty session, and the factory has one distribution session [C: `factory.h:173-175`, `:186-196`, `:482-484`]. So two rounds of one kind on one node cannot share one tree object. Section 7's rule of one round per subtree matches that.

## 14. Not specified yet

These sections replace draft 2 text that review 2 found wrong or incomplete. Nobody should build from the old text.

### 14.1 The leaf change (to be specified with 1.1.0 sales)

Draft 2's tier "Leaf change" (channel states on the new output, then the new leaf transaction) is withdrawn. It described the imported K = 1 leaf advance, which only moves the channel and makes it smaller by the fee [C: `src/factory.c:2769-2782`]. Owner decision 5 instead has every 1.1.0 sale spend only the spare liquidity into a new channel and the remaining stock, with existing channels never moving. The tiers for that operation, and its own hazards (the second-spend guard on the shared stock; the stale-chain penalty firing on honest exits), are to be specified with sales. `safety-rule.md` section 4.2 lists the requirements.

### 14.2 Channel commitments inside rounds (to be specified with the channel engine, before Slice 2)

Draft 2 put "the first channel states" in the creation tier and "channel states on the new output" in later tiers, and section 8 applied the round's nonce rules to everything the engine signs. That conflicts with the standard taproot channel format, which the project has chosen: the holder of a commitment completes its own signature at broadcast with a verification nonce that must be reproducible weeks later, and the format recommends deriving it from a per-channel shachain (`docs/research/channel-groundwork.md`, Part 1.1). The requirement: channel commitments are signed by the channel engine under the channel format's own nonce rules, outside sections 3 and 8; the round engine releases a tier that creates a channel output only after the channel engine reports the commitment stored for it; "holds" a commitment means holds the peer's verified partial signature and can complete its own; and one place is chosen for the first channel exchange, the creation round or the standard opening messages after `round_complete` and before funding.

### 14.3 The layer-update identifier (to be specified with layer updates)

Draft 2's identifier hashes every item's signature digest. In a layer update the first tier would hold every member's new channel states, so member A would need the digests of member B's commitments. A cannot compute them (it lacks B's per-commitment points, HTLCs and balance), and if the host supplied them every member would learn every other member's balance. The requirement: tree items, which everyone can rebuild, are bound into the identifier directly; each member's private items are bound by a per-member digest that only that member and the host check, or are kept out of the round altogether (14.2). No member learns another member's channel state through a round.

## 15. Slice 1 profile

Slice 1 (`docs/SLICES.md`) runs one purpose, **creation**, in a **"creation, tree only"** profile, as review 2, section 5, recommends.

| Part | In Slice 1 |
|---|---|
| Sections 1 to 3 | Yes. Item kinds: tree nodes, and the distribution transaction only if the owner decides it is signed |
| Section 4 messages | `round_propose` (with the funding transaction and section 4.1's parameters), `round_nonces`, `round_all_nonces`, `round_partial_sigs`, `round_tier_result`, `round_complete`, `round_ack`, `round_status_request`, `round_abort` without evidence and without tier or items (whole rounds only). `messages.md` adds an unsigned `factory_funded` hint the member never relies on |
| Section 5 | Creation only, one tier, tree transactions only. No channel states, no payouts other than the distribution transaction if decided, no penalties |
| Sections 6 and 7 | Yes, steps 1 to 9. Member states: Idle, Checking, Nonces sent, Signed, Complete, Awaiting funding, Live, Aborted, Unfinished, Abandoned, Dead. With one tier, "per tier" and "per round" coincide; the encoding still carries the tier |
| Section 8 | Yes, in full, including the randomness port's secret tag and the seeded source in simulator builds only |
| Section 9 | Only as far as naming who failed, to remove them. Evidence is not encoded in Slice 1 |
| Section 10 | Creation and Unfinished |
| Section 11 | Time budget, frozen values, new funding outpoint after a release. Nonces at the ready check: off |
| Sections 12 and 13 | Yes, including section 12.1's contract requirements. Factory size limited to about 128 members by section 12 when the hashlock penalty is on; Slice 1 sets no hashes and needs four participants |
| Section 16 tests | 1 to 5, 4b, 7, 9 to 15 for creation |

**Slice 1 values** (each **proposed, owner to confirm**; the reasons are in `safety-rule.md` section 12):

1. **No distribution transaction**: the creation round signs tree transactions only.
2. **The host recovers its signet coins through a short factory life and the existing host timeout**: it publishes the root kickoff and sweeps the root's outputs through their timeout leaves after the end height less 5 blocks. No close round in Slice 1.
3. **Burial depth 3 blocks** on signet, on both chain servers.
4. **Funding deadline 36 blocks** after the member's ack; **unfinished deadline one signing budget** after its partial signatures.

## 16. How it is tested

1. Honest rounds of every specified purpose, at several sizes.
2. Each message dropped, delayed, duplicated and reordered, at each step.
3. A crash and restart of each party at each step, including a replayed proposal after the restart. No secret nonce may survive; no party may send two different nonces or partial signatures for one (round, item).
4. A restore from an old backup, with randomness that repeats: a signing secret must not repeat.
   - **4b.** A restore from a backup older than an unfinished creation round, then a replayed proposal and a second tree on the same outpoint: both refused, and the member signs no second nonce under the old identifier (review 2, N1).
5. Each fault in section 9: the right party is named, the evidence verifies, and an honest party cannot be framed, including by the restart, by the unopened digest, and by a second tier with the same item numbers.
6. A host that withholds each result in turn: the member loses nothing, stays paused, asks on reconnect, and exits after its deadline.
7. Two overlapping rounds on one subtree: the second is refused.
8. Removal of each rule in turn, each of which must make a specific test fail.
9. Fuzzing of every message decoder, and of the evidence checker.
10. A failure in the partial-signature step followed by a retry: on the old funding outpoint it is refused; on a new one it succeeds. A failure in the nonce step followed by a retry on the same outpoint succeeds.
11. A member that does not ack: the host does not fund; a new attempt without that member succeeds.
12. Two parties build the tree from the same proposal with every row of section 4.1 varied in turn: the transactions are byte-identical when the inputs agree and differ when one row differs. For the terms of `terms.md` T1 at every member count from 3 to 16, the built tree has exactly the leaves of `terms.md` section 4.2: each a pseudo-Spilman leaf with one member, every interior node fixed, every channel at least `channel_sat`; and the shape {4: width 4} of draft 1 is refused. Rows that change no byte (layer step and states under fixed levels; fixed levels above D) are fixed by this specification, so the test checks they are refused when they differ.
13. A second proposal with a saved round identifier but other bytes (another check identifier, attempt, deadline or binding): treated as the saved proposal; no second nonce; kept as evidence (S6).
14. A member that reconnects while the host still collects partial signatures resends them after `hello`, and the round completes (F26). A member that lost `start` across a reconnect still takes part on the signed proposal (F9).
15. A restored member receives a replayed proposal and a second tree on its old outpoint: reason 12 for both, nothing signed, no old key derived.

## 17. Open points

1. **Expert review** of sections 2, 3, 8 and 9 by someone who knows MuSig2.
2. Whether signing protocol messages, group-signature items and later single-signer spends with related keys is provably safe. Separate per-lobby contribution keys are used because no proof was found; the factory key still signs single-signer spends of outputs the import pays to it (section 2). Request to SuperScalar: payout destinations other than the factory key.
3. Closed: `messages.md` draft 2 encodes every message of this draft, including the tier and items of `round_abort`, reason 12 as "the proposal lacks my current key for this lobby", and section 4.1's table.
4. Whether the host with a seat of its own can be denied its escape from blame, for example by requiring seats to be backed by something scarce.
5. Whether nonces at the ready check (with a pre-round identifier) and the lighter variant in section 11 are worth their risks.
6. The size and timing figures are estimates and need measuring.
7. **Who signs first in two-party tiers** (review 2, N14). The host could send its own partial signature with `round_all_nonces`, so that the member always completes first and the host, which is online, carries the Unfinished state instead. BIP 327 does not forbid it. An owner decision for the channel and close rounds.
8. **A deterministic nonce for the host as the last signer** (review 2, L8). BIP 327 allows a deterministic nonce for a signer that sends its nonce after receiving all others (as quoted in review 2; not re-read here). It would let the host survive a crash mid-attempt without a new attempt. Not adopted: it conflicts with this document's simpler rule that no secret nonce is ever reproducible, and the host's crash costs only an attempt.
9. **Requests to SuperScalar:** bound the layer-counter write in initialisation; honour the mirror hash for every node index, and grow the hash arrays before they are set; a setter for placement; free a live session on re-initialisation; a payout destination per member; split a node's coins between children by subtree size (`terms.md` open point 6); make `factory_set_funding` report a script it ignores.
10. **The protocol identifier.** The round identifier's first field stays the 4-byte tag in Slice 1, a fixed alias of the protocol identifier (`messages.md` 4.3). Signing the 32-byte identifier instead happens together with renaming the tags, once the protocol name is agreed with SuperScalar (review 3, F28).
