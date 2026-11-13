# The host terms record

Specification draft 2, 2026-11-12. Status: draft 1 reworked after the third review (`docs/reviews/spec-review-3.md`), which found section 4 unable to express the tree Slice 1 needs. Draft 2 has not itself been reviewed. It specifies owner decision 1 of 2026-11-11 (`docs/ux/decisions.md`): a lobby's outer rules are fixed when it opens; adjustable values move only inside signed ranges and freeze at the ready check; the outer rules have a fingerprint that is the lobby's identity; the current values have a version and their own digest that includes the outer one; a member's ready names both. Items marked **(open)** are listed at the end. Values marked **proposed, owner to confirm** are Slice 1 choices the owner has not objected to and has not yet confirmed.

Conventions (integers, `point`, `sig`, `TH`) are those of `messages.md` section 1.

## Changes after review 3

| Finding | How it was handled | Where |
|---|---|---|
| F1 shape table against `factory_set_level_arity` | The shape entry now carries the interior widths and a separate leaf kind, which must be 3 (one-member pseudo-Spilman leaf, K = 1); the import's last arity entry is the leaf kind. The split rule is stated, so a reader can check every entry statically; an entry that would make a multi-member or non-pseudo-Spilman leaf is refused on receipt. Confirmed by building the corrected T1 shapes with the import on the build server | Section 4 |
| F1 vectors | T1 uses the shapes {up to 4: leaf kind 3} and {up to 16: width 4, leaf kind 3}; T1 to T6 regenerated | Section 11 |
| F4 leaf amount against channel size | Term 30 renamed `channel_sat` (the smallest channel output on any leaf); the funding amount and the fee per transaction are now functions of the terms, the member count and the shape | Sections 3, 4.2 |
| F11 keep-alive against step timeout | `step_timeout_ms` now starts at 60,000 ms, twice the keep-alive | Section 3 |
| F13 member-side writes | A current version is saved only when the member readies for it | Section 7 |
| F16 "T1 is the slice 1 example" | True again: T1 builds the Slice 1 tree for 3 to 16 members | Sections 2, 11 |
| F17 fixed levels | The number to write is D, the depth of the deepest leaf, from the split rule | Section 4.2 |
| F19 stale "(provisional)" text | Section 10.4 states draft 3's decision; former open point 8 closed (draft 3 keeps those values in the proposal) | Sections 10, 13 |
| F24, F25 anchors and 16-wide levels | Tree anchors are always on in 1.0.0 (owner decision 6), so an interior width is at most 15 | Section 4.1 |
| F28 protocol id | No change here: the terms records carry no protocol field; the tags carry the domain | Section 6 |
| Slice 1 values | Short factory life in T1 (144 blocks plus 36 of wind-down), so the host recovers its signet coins by its timeouts (**proposed, owner to confirm**) | Section 11 |

## 1. What the record is

A host's terms for one lobby are two signed records.

| Record | Holds | Changes | Digest | Signed by |
|---|---|---|---|---|
| **Outer rules** | The profile, every fixed term, and for each adjustable term its allowed range | Never. Different outer rules are a different lobby | `outer_digest`: the lobby identifier | Host's long-term key |
| **Current values** | A version number, the outer digest, and one value for each adjustable term | Only to a higher version, only inside the ranges, only until the freeze | `current_digest` | Host's long-term key |

The host's long-term key is its BOLT 8 key, the key the member pinned when it connected (`messages.md` section 2).

Both records travel in `terms_offer`. Each signature is over its own record's digest, so either record can be shown to a third party without the message around it.

## 2. Encoding rules

Both records are BOLT 1 TLV streams with these extra rules. Together they make the encoding **canonical**: one set of terms has exactly one valid byte string, so equal terms always have equal digests.

1. BOLT 1's rules: BigSize type and length, minimally encoded; types strictly increasing; a length past the end is invalid.
2. **Fixed widths.** Every value has the exact size in its table. No truncated integers (`tu64` and the like are not used), because they give a second way to write a value unless every reader checks for leading zeros.
3. **Even types must be understood.** A record with an unknown even type makes the whole record invalid. **Every term that can cost the member money or affect what it signs has an even type.** An app that does not understand such a term must refuse the lobby rather than ignore the term.
4. **Odd types are for display only** (a host name, a description). An app may skip them. They are still inside the digest and the signature.
5. **Type numbers say what kind of term a record is.**

| Types | Kind | In the outer record | In the current record |
|---|---|---|---|
| 1 to 63 | Fixed terms, and display text | The value | Never (2 and 4 have their own meaning there) |
| 64 to 127 | Adjustable terms | The range: `u64` minimum then `u64` maximum, 16 bytes | The value: `u64`, 8 bytes |
| 128 and up | Reserved | Invalid in draft 2 | Invalid |

So an app that meets an unknown even type in 64 to 127 knows it is an adjustable term it cannot judge, and refuses.

6. A reader checks every bound in sections 3 and 4 and refuses a record that breaks one. Bounds are the widest values the software accepts at all; a member's own conditions are narrower.
7. Limits: an outer record is at most 4,096 bytes; a current record at most 1,024 bytes. The Slice 1 example (vector T1) is 225 bytes and its current record 70 bytes. The limits leave room for a long shape table and display text, keep both records inside one `terms_offer`, and bound what a reader must hold.

## 3. The outer rules

Required unless marked. "Slice 1" says which values a Slice 1 app accepts; others are refused by Slice 1 apps.

| Type | Term | Size | Bounds | Slice 1 | Why it is here |
|---|---|---|---|---|---|
| 2 | `chain` | 32 | | The genesis hash of the host's network, internal order: signet `f61eee3b…08000000` or testnet4 `43f08bda…00000000` | A record for one network can never be used on another. Mainnet is refused (`SLICES.md` rule 3). The member refuses a chain other than its own (`messages.md` section 2, contract v2 item 15) |
| 3 | `host_alias` | 1 to 32 | UTF-8 | Optional | Display only |
| 4 | `host_key` | 33 | Valid point | Must equal the pinned BOLT 8 key | Binds the terms to the key the member connected to |
| 5 | `description` | 1 to 280 | UTF-8 | Optional | Display only |
| 6 | `lobby_salt` | 16 | Random | Required | Two lobbies with the same rules get different identifiers. 128 bits make a collision among one host's lobbies negligible. A host MUST draw a fresh salt for every lobby and MUST NOT reuse one: a withdrawal is final and hides every listing with that identifier, so a reused salt would silently hide the new lobby (`discovery.md` W4) |
| 8 | `profile` | `u8` | 1 Safety, 2 Standard, 3 Starter, 4 Circle | 2 only | `LOBBY.md`: four profiles; Slice 1 has Standard only |
| 10 | `target` | `u16` | 3 to 1,000 | | Start at once at this many members (host not counted). 3: Slice 1 needs at least three members. 1,000: the largest tree built and signed so far (`KNOWLEDGE-BASE.md` section 4) |
| 12 | `minimum` | `u16` | 3 to `target` | | Start at the deadline only with at least this many |
| 14 | `deadline` | `u64` | Unix seconds | | When the start rule is applied if the target was not reached |
| 16 | `on_shortfall` | `u8` | 0 cancel, 1 carry over | 0 only | `LOBBY.md`: cancelling is the default |
| 18 | `ready_window_ms` | `u32` | 1,000 to 600,000 | | How long members have to answer a ready check. At least 1 s to cross a network; at most 10 minutes, beyond which "present now" means little. It may be below the keep-alive: a member whose connection drops during a ready check only misses that check |
| 20 | `signing_budget_ms` | `u32` | `step_timeout_ms` to 86,400,000 | | Total time for all attempts (`signing-round.md` section 11: a time budget, not a count). At most a day |
| 22 | `step_timeout_ms` | `u32` | 60,000 to 600,000 | | The longest a party waits for one round message. At least twice the 30 s keep-alive of `messages.md` section 2, so a dead connection is noticed, and the member can reconnect, within one step |
| 24 | `shape_table` | 4 to 1,000 | Section 4 | | Every member's app builds the same tree for the same number of members (`LOBBY.md`) |
| 26 | `lifetime_blocks` | `u32` | 1 to 52,560 | | How long the factory is active. 52,560 blocks is about a year, far above the 30 days the design expects (4,320 blocks) |
| 28 | `winddown_blocks` | `u32` | 1 to 52,560 | | The winding-down period after the lifetime (design: about 3 days, 432 blocks) |
| 30 | `channel_sat` | `u64` | 546 to 2,100,000,000,000,000 | | **The smallest channel a member gets**: every member's leaf pays at least this to its channel output (section 4.2). The leaf holds the same again as spare liquidity, plus fees. 546 is the import's dust limit [C: `channel.h:14`]; the maximum is the supply in satoshis. Draft 1 called this `leaf_amount_sat` and gave it two meanings (review 3, F4) |
| 32 | `tree_feerate` | `u32` | 1 to 1,000,000 satoshis per 1,000 vbytes | | Fee rate of the tree transactions (section 4.2). Thousandths of a satoshi per vbyte are needed: the owner's test rate is 0.1 sat/vB, which is 100 here. The ceiling, 1,000 sat/vB, is far above any fee seen |
| 34 | `switches` | `u8` | Bit 0 names, bit 1 chat, bit 2 rule-change requests; other bits 0 | 0 | `LOBBY.md`: three host switches. A set unknown bit is refused, since this is an even record |
| 64 | `joining_fee_sat` | 16 | Range, `min` ≤ `max` ≤ 2,100,000,000,000,000 | | A flat joining fee, taken from the first payment the member receives (decision 2). Not collected in Slice 1 |
| 66 | `fee_base_msat` | 16 | Range, `max` ≤ 4,294,967,295 | | The per-payment base fee. The ceiling is BOLT 7's `fee_base_msat` width (`u32`) |
| 68 | `fee_proportional_millionths` | 16 | Range, `max` ≤ 4,294,967,295 | | The per-payment proportional fee, in BOLT 7's unit and width |

Reserved even types, not valid in draft 2: 70 a joining fee as a share of the chain cost with a ceiling (decision 2, proposed for 1.0.0, **(open)**); 72 the fee for extra receiving room (1.1.0, decision 3); 36 the share of seats for members who bring nothing; 38 invitation-only. An app that sees one refuses the lobby, which is the right default for a term it cannot judge.

Not in the record: anything about channels (revocation window, reserve, dust limit), timed layers, end-date payouts and deposits. They arrive with the slices that use them, as new even types. The tree settings that are the same for every attempt (spare-liquidity delay, layer step and states) stay proposal fields, as `signing-round.md` draft 4 section 4.1 decides; a member judges them at signing (C8).

## 4. The shape table

The tree's shape depends on the number of members. The host fixes it per size in the outer rules, so the shape is never chosen after members are known.

### 4.1 Encoding, and what the import makes of it

Value: one or more entries, each

| Field | Size | Bounds |
|---|---|---|
| `max_members` | `u16` | 3 to 1,000; strictly increasing from entry to entry |
| `n_interior` | `u8` | 0 to 6 |
| `interior` | `u8` × `n_interior` | 4 to 15 each: the width of each interior level, from the root down |
| `leaf_kind` | `u8` | **3 only** in 1.0.0: a one-member pseudo-Spilman leaf |

For n members the first entry with `max_members` ≥ n applies. The last entry's `max_members` must be at least `target`.

**What the imported builder does with it.** The engine calls `factory_set_level_arity` with the list `interior ‖ leaf_kind` (length `n_interior` + 1) [C: `src/factory.c:1164-1176`]. The import reads that list in a way draft 1 did not say:

- The **last entry is also the leaf type**: `leaf_arity` is set to it [C: `src/factory.c:1175-1176`]. The leaf types are 1, 2 and **3 = `FACTORY_ARITY_PS`**, pseudo-Spilman [C: `factory.h:52-56`].
- A depth beyond the list uses the last entry [C: `src/factory.c:927-932`]. So below the interior levels, every depth uses 3, and the real tree is usually deeper than `n_interior` + 1.
- At a depth whose entry is 3, a node with one member is a pseudo-Spilman leaf (K = 1), and a node with more is split **in two** [C: `src/factory.c:948-955`, `:971-975`].
- At a depth whose entry is a width a ≥ 4, a node with **at most a members is itself one leaf**, with several members (`setup_nway_leaf_outputs`) or, for one member, the non-pseudo-Spilman `setup_single_leaf_outputs` [C: `src/factory.c:948-955`, `:1774-1808`]. That is what made draft 1's T1 unusable (review 3, F1). A node with more than a members is split into a children (below).
- Widths 1, 2 and 3 have special meanings at interior depths (1 and 2 are other leaf types, 2 splits by a different rule, 3 splits in two) [C: `src/factory.c:948-955`, `:971-986`]; draft 2 allows none of them as an interior width. Binary splitting is what the leaf kind 3 already does below the interior levels.
- At most 8 entries are read [C: `factory.h:415`, `src/factory.c:1172`], so `n_interior` is at most 7; draft 2 allows 6, leaving one entry spare.
- Interior widths stop at 15 because tree anchors are always on in 1.0.0 (`signing-round.md` section 4.1, owner decision 6) and the import silently leaves out the anchor of a node with 16 outputs [C: `src/factory.c:501`; `factory.h:21`].

### 4.2 The tree an entry builds

Every reader must be able to compute, from the terms alone, the tree's leaves, its depth, the fee per transaction and the funding amount. These rules are the import's behaviour written out; RD test 12 and section 12 test 17 check them against the import.

**The split rule.** Let `levels` = `interior ‖ leaf_kind`, and let the entry for depth d be `levels[d]`, or the last entry if d is past the end. A node at depth d (the root is depth 0) with m members, in member order:

- entry 3: if m = 1 the node is a leaf; otherwise its children hold ⌊m/2⌋ and m − ⌊m/2⌋ members, in that order;
- entry a ≥ 4: m must be greater than a (otherwise the shape is invalid for this n, section 4.3); the node has up to a children, made in order: with r members still unplaced and j children made so far, the next child takes ⌈r / (a − j)⌉ members, until none are left [C: `src/factory.c:994-1010`].

**D**, the number of fixed levels: the depth of the deepest leaf. The proposal's `fixed_levels` must equal D (`messages.md` 7.2), and the engine passes D to `factory_set_static_near_root`, so every interior node is a fixed (kickoff-only) node and every leaf is a kickoff and state pair [C: `src/factory.c:1659-1669`]. A smaller value builds a different tree; a larger one builds the same bytes (build server, 2026-11-12); only D is accepted, so that one tree has one encoding.

**The fee per tree transaction.** The import pays one fee, `fee_per_tx`, on every tree transaction [C: `src/factory.c:1694-1696`, `:1759-1761`, `:1299-1300`]. It is

```
fee_per_tx_sat = ⌈ tree_feerate × V / 1000 ⌉
```

where V is the largest virtual size (BIP 141) of any tree transaction in its signed form: ⌈(4 × unsigned bytes + 2 + 66) / 4⌉ vbytes, the 2 for the segwit marker and flag and the 66 for a witness of one 64-byte signature. Sizes do not depend on amounts, so V can be read from a tree built with any fee. The proposal must carry exactly this value.

**The funding amount.** With every interior node fixed, the import gives a node's coins less `fee_per_tx` and the anchor (240 satoshis, `ANCHOR_OUTPUT_AMOUNT` [C: `channel.h:16`]) to its children in equal shares, the remainder to the last child, and splits a leaf's coins, less two fees and two anchors (its kickoff and its state transaction), into a channel and an equal spare-liquidity output [C: `src/factory.c:1694-1720`, `:1759-1761`, `:1299-1323`]. So define, for a node, its requirement R:

```
R(leaf)                 = 2 × channel_sat + 2 × fee_per_tx + 2 × 240
R(node with k children) = k × max R(child) + fee_per_tx + 240
funding_amount          = R(root)
```

The proposal's `funding_amount` must equal R(root). With it every leaf's channel output is at least `channel_sat`, and the leaf with the largest requirement gets exactly `channel_sat`. Leaves under smaller subtrees get more, because the import splits equally between children, not by their sizes: with 3 members, member 1's channel is about twice `channel_sat` (build server, below). Requesting a split by subtree size is listed for SuperScalar **(open)**.

**Confirmed by building**, 2026-11-12, on the build server with the imported code at pin `e6573950…` (`factory.c` SHA-256 `f1928bb0…`), using `signing-round.md` section 13's order and section 4.1's Slice 1 settings and T1's values (`channel_sat` 100,000, fee rate 100):

| Members | Level arity | fee_per_tx | funding_amount | Leaves | Channels |
|---|---|---|---|---|---|
| 3 | [3] | 17 (V = 167) | 802,827 | 3, each pseudo-Spilman with 1 member | 200,385; 100,000; 100,000 |
| 4 | [3] | 17 (V = 167) | 802,827 | 4, each pseudo-Spilman with 1 member | 100,000 each |
| 5 | [4, 3] | 26 (V = 253) | 1,605,586 | 5, each pseudo-Spilman with 1 member | 100,000 (2); 200,399 (3) |
| 8 | [4, 3] | 26 | 1,605,586 | 8, each pseudo-Spilman with 1 member | 100,000 each |
| 16 | [4, 3] | 26 | 3,211,970 | 16, each pseudo-Spilman with 1 member | 100,000 each |

In every row every interior node was fixed, and the layer step and states (144 and 4, or 1 and 2) left every txid unchanged. Draft 1's T1 shape (level arity [4]) at 3 and 4 members, and review 3's suggestion [4, 3] at 3 members, each built **one N-way leaf holding every member**. `tools/spec-vectors.py` applies the same rules and reproduces the funding amounts.

### 4.3 What a reader checks

On receipt of the outer record (section 7, step 5), for every entry and every n from the previous entry's `max_members` + 1 (or 3, for the first entry) to its own `max_members`: the split rule never meets a node at an interior depth with m ≤ a. So every leaf comes from the leaf kind, with one member. A shape that fails for any n in its range is refused before the member joins. That is at most 1,000 small simulations per record.

The member's app still builds the real tree at signing and checks every leaf (`safety-rule.md` C8): this section lets it refuse a bad lobby early; C8 is what protects.

## 5. The current values

| Type | Field | Size | Rule |
|---|---|---|---|
| 2 | `outer_digest` | 32 | The digest of the outer record these values belong to |
| 4 | `version` | `u32` | 1 for the first; each later version strictly greater. Gaps are allowed |
| 64 to 127 | one value per adjustable term | `u64` | Exactly the adjustable types present in the outer record, no more, no fewer; each inside its range, ends included |

`u32` versions: a host that changes a value every second would need 136 years to run out.

## 6. Digests and signatures

```
outer_digest   = TH("gazpacho/terms/outer",   outer record bytes)
current_digest = TH("gazpacho/terms/current", current record bytes)
outer_sig      = BIP 340 signature by host_key over outer_digest
current_sig    = BIP 340 signature by host_key over current_digest
```

- The current record contains `outer_digest`, so `current_digest` commits to the outer rules too. One 32-byte value names everything a member agreed to.
- The tags differ, so an outer digest can never be passed off as a current digest, a message hash (`gazpacho/msg`) or a round identifier.
- The digests are signed directly. They are already tagged hashes specific to this protocol (`signing-round.md` section 2).
- `outer_digest` is the lobby identifier: the `scope` of every lobby and round message (`messages.md` section 4).
- The records bind the chain but no protocol version: the tags carry the domain. If the tags are renamed for a shared format (`messages.md` 4.3), these digests change with them.

## 7. What a member's app checks on receipt

In this order; any failure refuses the offer and saves nothing.

1. Both records decode under section 2, inside their size limits.
2. `TH("gazpacho/terms/outer", outer)` equals the message's `scope`.
3. `host_key` equals the pinned BOLT 8 key; both signatures verify under it.
4. `chain` is the member's own network (signet or testnet4).
5. Every bound in sections 3 and 4, including the shape check of section 4.3.
6. The current record's `outer_digest` equals the computed outer digest; it has exactly the outer record's adjustable types; each value is inside its range.
7. Its `version` is higher than any accepted for this lobby, or equal with identical bytes (a duplicate). Equal with different bytes is the host signing two values under one version: keep both as evidence and leave.
8. The lobby is not frozen (section 8), or the record is the frozen one.

Then it compares the records with the member's conditions (section 9). It **saves** the outer record before its first `join`, and a current version only before a `ready` that names it (`journal.md` record `terms_received`). Versions it only displays are kept in memory, so a host that signs a new version every second costs the member no writes (review 3, F13). Evidence of a fault is saved once, before `leave`.

## 8. Freezing

- The **ready check** freezes the current values. The first `ready_check` of a lobby (`messages.md` section 6.8) names a version and its digest. From then on that version is the lobby's only current values, for every later ready check and every signing attempt. Decision 1: "After it nothing moves."
- The host saves the freeze before it sends the first `ready_check`, so a restarted host cannot sign different values for the same lobby.
- A host-signed current record with a different version after the freeze, or a ready check naming other values, is proof that the host broke its terms. The member's app leaves and keeps the evidence.
- A lobby that returns to Open after a ready check without a start stays frozen. Members who join later see only the frozen values.

## 9. Comparing a member's conditions

A member's conditions are its own limits: the highest fees it accepts, the smallest channel, the profiles it accepts, the shortest and longest lifetime, the smallest number of members, and so on. They are stored on the member's device and never sent, except `min_members` as an optional hint (`messages.md` section 6.4).

**Fixed terms** are compared with their one value. For `channel_sat` that is the guaranteed minimum; the member's real channel can be larger (section 4.2) and is checked at signing.

**Adjustable terms** are compared, by default, with the **whole range**: the value the member likes least. For a fee, that is the range's maximum. This is decision 1's default: a member whose limits cover the whole range can never be caught out by a late change.

Each lobby is shown in one of three classes:

| Class | When | What the app does |
|---|---|---|
| **Fits** | Every fixed term fits, and every range fits as a whole | May ready automatically. No change the host can make inside the outer rules takes the member out |
| **Fits only now** | Every fixed term fits; a range does not fit as a whole, but its current value does | Listed with the lobbies that do not fit, one tap showing the numbers (decision 6, answer A). Readies only if the member chose the looser option ("ready while the current value fits"), and then sends `unready` as soon as a new version moves outside its limits |
| **Does not fit** | A fixed term, or a current value, is outside the member's limits | Never readies |

At the freeze, a "fits only now" lobby whose frozen values fit becomes, in effect, "fits": the values can no longer move.

**At signing** the member's app checks the real tree it built from the outer rules, the frozen values and the proposal's parameters against its conditions and the safe-to-sign rule (`safety-rule.md` C8). Fees taken later (joining fee, per-payment fees) are checked at the moment they are taken against the frozen values. Nothing said in the lobby replaces those checks (`LOBBY.md`, "What protects a member", point 2).

## 10. How the digests enter the signing round

1. A member's `ready` names `outer_digest` (also its `scope`), `current_version` and `current_digest`, and is signed by its contribution key.
2. The `ready_check` names the version and `current_digest` it freezes, signed by the host.
3. `round_propose` names the frozen `terms_version` and `terms_digest`. A member refuses a proposal whose digest is not its frozen one.
4. The round identifier (`signing-round.md` section 3, encoded in `messages.md` section 7.1) lists both the outer digest and the frozen current digest. `signing-round.md` draft 3 settles this: the current digest already includes the outer one, and both are listed as owner decision 1 describes, at a cost of 32 bytes. Every nonce and partial signature a member makes is therefore tied to exactly the terms it readied for. A host that ran the round under other terms would produce a different identifier, and the member would see the mismatch before contributing.
5. The proposal's parameters must equal the frozen values, and the values section 4.2 derives from the terms, wherever the terms define them; the frozen digest must equal the one in the member's own `ready` (check C8a). Attempts within one signing budget reuse the frozen values; nothing moves between attempts.

## 11. Test vectors

Computed by `tools/spec-vectors.py`, which uses its own BIP 340 code checked against BIP 340's first official vector. Auxiliary randomness is 32 zero bytes for every signature, so the vectors repeat. **Every vector below changed after review 3**, because T1's shape and lifetime changed and everything else here depends on T1's digest.

**Test keys. Never use them for coins.** Each secret key is `SHA256("gazpacho test key: <label>")` taken modulo the curve order:

| Label | Public key (33 bytes) |
|---|---|
| `host` | `02b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156` |
| `member 1 factory` | `0223a26c411e719d542783e3bb05fa00a467fb73227d495ab89734fef0ecec3974` |
| `member 1 contribution` | `024322bd904fa9770421b0b48f08e961d473f3ee9a36a5bc85fa3cac30fa2e15ae` |

**T1. Outer rules, the Slice 1 example.** Signet; the test host key; `lobby_salt = SHA256("gazpacho test lobby salt")[0:16]` = `c31b4b333d598e176bb883203548a5e6`; Standard; target 8; minimum 3; deadline 1,794,441,600 (2026-11-12 00:00 UTC); cancel on shortfall; ready window 30 s; signing budget 10 minutes; step timeout 60 s; shapes {up to 4 members: no interior level, leaf kind 3} and {up to 16: one interior level of width 4, leaf kind 3} (bytes `0004 00 03` and `0010 01 04 03`); lifetime 144 blocks and wind-down 36 (a short Slice 1 life, **proposed, owner to confirm**, `safety-rule.md` section 12); `channel_sat` 100,000; tree fee rate 100 (0.1 sat/vB); switches 0; joining fee 0 to 2,000 sat; fee base 0 to 1,000 msat; fee proportional 100 to 2,500 millionths.

```
outer record, 225 bytes:
0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800
0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e
34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02
00030e08000000006af501801001001204000075301404000927c016040000ea
6018090004000300100104031a04000000901c04000000241e08000000000001
86a02004000000642201004010000000000000000000000000000007d0421000
0000000000000000000000000003e84410000000000000006400000000000009
c4
outer_digest = 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2
outer_sig    = 0bb885ba5dbf0f21fda26a90c68d6736f71619b72583d8691581319efafdfeb5
               db7c87c85def6708994c5b78dc93be56fd9dd9f670147f353d74787d922bf54d
```

**T2. Current values, version 1:** joining fee 500, base 1,000, proportional 1,000.

```
current record, 70 bytes:
022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4
24f2040400000001400800000000000001f4420800000000000003e844080000
0000000003e8
current_digest = d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942
current_sig    = a739c225be7e2842c2e7925c12b8e824751ba1d019e31c9f16342cf78f02633f
                 f00d0ef1ff618b18456f472818758017a0e682b211d553d00edf3e2d1b1c140d
```

**T3. Current values, version 2:** joining fee 1,500, others unchanged.

```
current record, 70 bytes:
022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4
24f2040400000002400800000000000005dc420800000000000003e844080000
0000000003e8
current_digest = ba3bccb892b8b65321956753d973bfba1bbdcbf2e5c68e28052683a713b2b7be
current_sig    = 7a692794d41ad38a845e6533b2499b197a3d63d86f196d274a14d4aa33478bf3
                 f563f2503def1c0b1bf53e096cd2e7be0f45f10c30066f5a6be5d98ff53fff5b
```

**T4. Must be refused:** T1 with record 10's length written `fd 00 02` instead of `02` (not minimal). The bytes differ from offset 91. A reader that hashed it anyway would get a different identifier (`adb3a733…eb352a4d`), which is why non-minimal encodings must be refused, not tolerated.

**T5. Must be refused:** version 3 with joining fee 2,001, outside 0 to 2,000:

```
022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4
24f2040400000003400800000000000007d1420800000000000003e844080000
0000000003e8
```

**T6. Comparison.** A member with limits joining fee ≤ 1,000, base ≤ 1,000, proportional ≤ 2,500, against T1 and T2: joining fee "fits only now" (range up to 2,000; current 500); base fits the whole range; proportional fits the whole range. So the lobby is "fits only now". After T3 (joining fee 1,500), it does not fit, and a member on the looser option sends `unready`.

**T7. The tree T1 builds** (section 4.2, the generator's split and funding rules, and the build server): for 3 and 4 members, level arity [3], D = 2; for 5 to 8, [4, 3], D = 2; for 9 to 16, [4, 3], D = 3 (corrected after the confirmation review); every leaf a one-member pseudo-Spilman leaf. With fee 17, the funding amount is 802,827 satoshis for 3 or 4 members. Draft 1's shape entry `0004 01 04` (level arity [4]) is refused by section 4.3 at n = 3.

## 12. Tests

**Encoding**
1. T1 to T3 encode to exactly the bytes above; digests and signatures match.
2. T4 and T5 are refused. So are: a record with types out of order or repeated; each fixed-width value one byte short or long; a truncated last record; an outer record of 4,097 bytes; a current record of 1,025 bytes.
3. An unknown even type in 1 to 63, in 64 to 127 and from 128: refused. An unknown odd type in 1 to 63: skipped, but a change to it changes the digest and fails the signature.
4. A current record missing one adjustable type, or carrying one that the outer record lacks: refused.
5. Every bound in sections 3 and 4 at its edge (accepted) and one past it (refused), including `min` > `max`, `minimum` > `target`, a shape table not increasing, a last shape entry below `target`, `n_interior` 7, an interior width of 3 or 16, a leaf kind other than 3, a step timeout of 59,999 ms, a `channel_sat` of 545, a set unknown switch bit.
6. A fuzzed decoder for both records.

**Shape (section 4)**
17. For T1 and for every n from 3 to 16, the split rule gives n one-member leaves and the depth D stated in T7; the imported builder, given `interior ‖ 3` and `fixed_levels` = D, builds exactly those leaves, each a pseudo-Spilman leaf with one member, every interior node fixed (`signing-round.md` test 12).
18. An entry whose split puts m ≤ a members at an interior depth for some n in its range (for example draft 1's {4: width 4}): refused on receipt, before joining.
19. `fee_per_tx` and `funding_amount` computed by section 4.2 for T1 at 3, 4, 5, 8 and 16 members equal the build-server table; every channel output is at least `channel_sat`; with `funding_amount` − 1 at 4 members some channel output is below it.

**Signatures and identity**
7. A record signed by another key; a valid record whose `host_key` is not the pinned key; a signature over the wrong digest (the outer digest under the current tag and the other way round): refused.
8. Two lobbies with equal rules and different salts have different identifiers.
9. A mainnet chain hash: refused by a Slice 1 app.

**Versions and freezing (hostile host)**
10. Version 2 then version 1: version 1 ignored. Two different records both numbered 2: the member leaves with both as evidence, and a separate checker confirms the evidence.
11. A new version after the first ready check: the member leaves with evidence. A ready check naming a version other than the latest accepted: not answered with those values.
12. The host restarts between saving the freeze and sending the ready check, and after sending it: it never signs another current record for that lobby.
13. A `round_propose` whose `terms_digest` is not the frozen digest: refused before the member saves anything.
20. A host that signs a new current version every second for an hour: the member's journal grows only when it readies.

**Comparison**
14. T6 gives the classes stated. A member on the default option never readies for a "fits only now" lobby; on the looser option it readies and is unreadied by T3.
15. A lobby that fits by its terms but whose real tree breaks a member condition at signing (for example a funding amount one satoshi short, so one channel is below the member's minimum): the member refuses at signing. This is Slice 1's "a member whose conditions are not met is seen to refuse".
16. Rule removed: with the range comparison replaced by a current-value comparison, test 14's default-option member must be seen to ready and then be caught by a version change. That test must fail.

## 13. Open points

1. **Which terms may be ranges.** Draft 2 has exactly three: joining fee, per-payment base fee, per-payment proportional fee. Channel size (`channel_sat`) and lifetime are fixed. Should the channel size be a range too?
2. **The chain-cost joining fee** (type 70): its formula and ceiling (decision 2).
3. **Freeze for ever after the first ready check**, including when the lobby returns to Open. Decision 1 says "after it nothing moves"; this draft reads that strictly. The alternative is unfreezing when a check fails before the deadline.
4. **Timed layers and channel terms** in the record, when those slices come. Timed layers will need a new even leaf or level description, and C8's bound on step × (states − 1) (review 3, F23).
5. **Whether `host_key` should be a separate signing key** bound to the BOLT 8 key, rather than the BOLT 8 key itself (`messages.md` open point 9).
6. **Unequal channels.** The import splits a node's coins equally between its children, so members under smaller subtrees get larger channels (section 4.2). We asked SuperScalar to split by subtree size (request 7, `docs/handoff/README.md`). **Pending change:** their reply (2026-11-12) confirms the bug but chooses a **per-member capacity carried in the proposal** instead of equal channels, and Gazpacho agreed. Section 4.2 and `messages.md` 7.2 must then carry a capacity per member, each member checking its own. Not written yet; to do when their change lands.
7. Closed: a listing carries exactly the outer record, the same bytes on every carrier (Lightning query, store node, Nostr); see `discovery.md`.
8. **Slice 1 lifetime**: 144 blocks plus 36 of wind-down in T1, so the host recovers its signet coins within about a day and a half (`safety-rule.md` section 12) — **proposed, owner to confirm**.

Closed in draft 2: draft 1's open point 6 (shape validity is now a static check, section 4.3) and open point 8 (lobby-constant tree parameters stay in the proposal, as `signing-round.md` draft 4 section 4.1 decides).
