# Review 3 of the five Slice 1 specifications

2026-11-12. Adversarial review of `spec/safety-rule.md` (draft 3, "SR"), `spec/signing-round.md` (draft 3, "RD"), `spec/messages.md` (draft 1, "MS"), `spec/terms.md` (draft 1, "TR") and `spec/journal.md` (draft 1, "JN"), read as one system for Slice 1. I wrote none of them. Read against `docs/reviews/spec-review-2.md` (N1 to N20, L1 to L8), `docs/SLICES.md`, `docs/THREAT-MODEL.md`, `docs/ux/decisions.md`, `docs/KNOWLEDGE-BASE.md`, `core/gazpacho/include/gazpacho/{runner,ports,action,event,types,node}.h`, the imported code `core/superscalar/` at pin `e65739500bbb…`, the secp256k1-zkp header at pin `6152622`, BOLT 1, BIP 327 and BIP 340.

Marks: **[C]** read today in code or a document (file:line); **[S]** checked today in a primary source I fetched; **[V]** recomputed today; **[R]** my reasoning, not confirmed by a test. Line numbers refer to the files as they stand today.

Nothing was built. The vector generator was run (`python -I tools/spec-vectors.py`) and every vector was also recomputed with an independent BIP 340 implementation of my own (section 6).

---

## 1. Verdicts

| Spec | Verdict | Why, in one line |
|---|---|---|
| `safety-rule.md` draft 3 | **Ready after listed changes** | The checks are right in substance and review 2 is answered; the restore rules contradict RD and JN in four places (F3), C10 can block every H11 retry (F6), and C8 lacks an explicit "one-member pseudo-Spilman leaf" check (F1) |
| `signing-round.md` draft 3 | **Ready after listed changes** | The cryptographic design, contribution rules and nonce function are sound and verified against the library header; section 4.1 maps the shape, placement, fixed levels and leaf amount wrongly onto the import (F1, F4, F5, F17), and the creation state table has gaps (F6) |
| `messages.md` draft 1 | **Ready after listed changes** | The encoding is careful and its vectors are correct; it has not been brought in line with draft 3 (reason 12, `round_abort` items, placement, "abandoned" against Dead, stale "(prov.)" text), and it has two flow gaps that a builder must guess at (F9, F12) |
| `terms.md` draft 1 | **Ready after listed changes, section 4 to redo** | The canonical encoding, digests, freeze and comparison are good and the vectors verify; but the shape table cannot express the tree Slice 1 needs, and its own example T1 builds multi-member leaves that every member refuses (F1). `leaf_amount_sat` contradicts the import (F4). Fixing T1 changes every downstream vector |
| `journal.md` draft 1 | **Ready after listed changes, sections 5 and 8 to redo** | File format, writing, syncing and limits are solid and the vectors verify; but the torn-tail rule silently cuts confirmed records in every Slice 1-sized journal (F2), and section 8 implements review 2's restore proposal, not draft 3's (F3) |

None of the five is ready to build Slice 1 from as it stands. No finding needs a different cryptographic design.

**Can the signing engine start now?** Partly. The engine's core can start today in the simulator: the nonce function of RD section 8 (the header claims check out, section 6), the per-(round, item) state machine and rules S1 to S4, the slot tracking and the other guards of RD section 12, partial-signature verification, combining, and checking the final signature from the transaction bytes. It can be tested on trees built directly with fixed test parameters. **Creation from terms plus proposal should wait** for F1, F4, F5 and F17 (otherwise RD test 12, "byte-identical trees", cannot pass with the example terms), for F7 (what the C7 record holds) and for F3 (how keys are derived), because that work would otherwise be rewritten.

---

## 2. Findings, most serious first

No finding lets an honest member lose money in Slice 1 as written, because a member is owed nothing until funding is buried. F2 and F3 come closest: they reopen the two-tree attack and the framing attack that draft 3 set out to close.

### High

#### F1. The shape table cannot express one-member pseudo-Spilman leaves, and its example T1 builds multi-member leaves that every member refuses

Concerns: TR section 4 (lines 74–88), T1 (line 176); RD 4.1 row "Shape" (line 113); SR C8 (lines 122–123); the import.

The import does not read the level-arity list as "fan-out per level" alone. The **last entry is also the leaf type**:

- `factory_set_level_arity` sets `f->leaf_arity = (factory_arity_t)arities[n - 1]` [C: `src/factory.c:1175-1176`]. The leaf types are 1 (one member, 2-of-2), 2 (two members per leaf) and **3 = `FACTORY_ARITY_PS`**, pseudo-Spilman [C: `factory.h:52-56`].
- `subtree_is_leaf`: for arity a ≥ 2 other than 3, a subtree of up to a members **is one leaf** [C: `src/factory.c:948-955`]. A leaf with several members gets `setup_nway_leaf_outputs`, and a leaf with one member at an arity other than 3 gets the non-PS `setup_single_leaf_outputs` [C: `src/factory.c:1774-1808`]. Only arity 3 gives `setup_ps_leaf_outputs`, and arity 3 splits **in two**, not three ways [C: `src/factory.c:963-968`].
- Depths beyond the list use the last entry [C: `src/factory.c:927-932`], so the real tree can be deeper than TR's `levels`.

T1's shapes are "up to 4 members: one level of 4" and "up to 16: levels 4, 4" (TR line 176; bytes `18 09 0004 01 04 0010 02 04 04` in the outer record [V]). For 3 or 4 members, depth 0 has arity 4 and 3 ≤ 4, so **the whole factory is one 3- or 4-member N-way leaf**, with `leaf_arity` set to 4, which is not a valid enum value. For 5 to 16 members you get four-member N-way leaves. TR section 4 says the member then refuses at signing (line 88), so with the example terms Slice 1 can never form. KNOWLEDGE-BASE line 84 records the same habit of the import.

Also: K = 1 (`factory_set_ps_subfactory_arity`) does not ensure one member per leaf. It only matters for PS leaves. SR C8 lists K = 1 and the shape but no check that **every leaf is a PS leaf with exactly one member**, and TR's "one member per leaf" (line 88) would accept a non-PS single leaf, which SR's analysis (no anchor on chain links, C3; no leaf layer, section 7) does not cover.

**Change.**
- TR section 4: state the import's meaning. Either carry the leaf type as its own field, written as the last arity entry, or require the last entry to be 3 and give the binary split below it. Bounds: interior arity 2 to 16 (15 with tree anchors, F27), leaf entry exactly 3 in 1.0.0.
- Redo T1 with a shape that builds PS leaves for 3 to 16 members (for example `{16: [4, 3]}`), and regenerate T1 to T6, M1, M3 and every digest that depends on the outer digest.
- SR C8 and RD 4.1: add "every leaf is a pseudo-Spilman leaf with exactly one member, the member's own key".
- Add to RD test 12 a check that the T1 shape builds the expected leaf kinds.

#### F2. The journal's torn-tail rule silently cuts confirmed records in any journal under 24 MiB, which is every Slice 1 journal

Concerns: JN section 5 step 4 (lines 109–114), section 4 (line 96), open point 7 (line 282).

The rule: if the bytes after the last valid entry are at most 16 MiB plus one largest entry (24 MiB), they are "a torn tail ... no batch in them was ever confirmed", and they are cut (JN line 111). That holds only if the only way an entry can become invalid is a write that never finished. A bit flip, a bad sector or a bad copy in an entry that was synced and confirmed long ago is classified the same way, provided it lies within 24 MiB of the end of the file. JN line 137 puts a Slice 1 member journal at a few tens of kilobytes, so **any** damage anywhere in it is a "torn tail". The node then cuts every later entry and starts as though nothing happened.

What it loses can be `round_started` (the refusal of a round identifier) or `exposure` (the C7 record). JN line 143 says these two sets are what stop a second contribution and a second tree. With them gone, a host that replays the proposal gets fresh signed nonces under the old identifier (framing, RD S2), and a second tree on an outpoint whose first tree it may hold complete (the review 1 F1 attack). Both are what draft 3's restore rules exist to stop. The reader cannot know where the last sync was. The 16 MiB bound is a promise the writer makes, and nothing on disk records it.

SR section 11 lists "loss of the held set or the exposed set" as not defended. Silently starting without them is worse than refusing to start, and the threat model lists no gap for two trees (THREAT-MODEL line 38). [R]

**Change.** Make JN open point 7 mandatory. After each successful sync, write a small "synced through offset X" mark, or keep that offset in a second small file. On start, any invalid entry before the last mark is **corruption**: refuse to start and tell the user. Only bytes after the last mark may be cut. Add a test: a flipped bit in a confirmed `exposure` entry of a 40 KB journal must stop the start, not cut it.

#### F3. The restore scheme is specified three different ways, and one rule contradicts another

Concerns: SR section 9 R2 to R6 (lines 258–270), C12 (line 143); RD S5 (line 79), section 8 (line 201), open point 3 (line 357); MS section 2 (line 24), 7.2 (line 466), reason 12 (line 601), test 52 (line 850); JN section 8 (lines 141–152), records `key_epoch`, `restored`, `fresh_start` (lines 162–165). Slice 1 includes all of this (SR line 339).

| Point | SR draft 3 | JN / MS |
|---|---|---|
| Epoch | Random **31-bit**, never 0; **the original installation uses epoch 0** (SR:260) | **32 random bytes**, drawn "at every restore **and at creation**" (JN:147) |
| How the epoch is drawn | From the randomness port **tagged secret**, and "saved in the journal at once" (SR:260) | RD:201: secret-tagged bytes "are never journaled". **SR R2 breaks RD section 8 as written.** The epoch is not secret; it should be drawn untagged |
| After a restore | R3: the seat in an open lobby is lost; join again with a new key. No user confirmation step | `restored` record, then **no creation round until the user confirms** (`fresh_start`); every `round_propose` is answered with reason 12 until then (JN:148, MS:466) |
| Reason 12 | "The proposal names a recovery-only key" (SR:264, RD:357) | "Restored from a backup; no creation until the user confirms a fresh start" (MS:601) |
| Stale-backup guard (R6) | A record **outside the journal**, updated durably before each key allocation and each round's first contribution, kept where a restore never overwrites it | Not in JN. The runner contract has one storage stream (`runner.h:21-25`); no action, port or record can sequence a write to a second store before a send |

Two further problems with what SR claims:

- **R4's detection cannot be implemented in general.** A restored node can recognise "its old key" only by deriving it, and it does not know the epochs or indexes used after the backup. That is R7's point. What actually protects is C7's "fresh funding output" rule (own **current-epoch** key present exactly once), which refuses a replayed proposal anyway, under reason 1 or 9 rather than 12. Say that R4 is a consequence of C7 and needs no recognition step. [R]
- The protection itself is sound as far as I can reason. A tree signed before the restore spends an output whose script commits to the old aggregate key, and C1 with C7 make the member contribute only to an output whose script commits to its new key. A host that builds a new funding transaction on the same inputs gets a new outpoint, and only one of the two can confirm. [R]

**Change.** Pick SR's version and rewrite JN section 8 and the MS reason-12 rows to match: one epoch format (a 31-bit hardened derivation index fits BIP 32), epoch 0 at installation, drawn **without** the secret tag, `fresh_start` either removed or added to SR. Define the guard record's format, its location and how the core orders it (a new action, or a second journal behind the same runner rule), or move R6 out of the Slice 1 profile.

### Medium

#### F4. `leaf_amount_sat` means two different things, and the funding amount cannot be derived from the terms

TR line 63: "The host's coins placed on each member's leaf: **the member's future channel size**." The import splits the leaf in half, channel and spare liquidity [C: `src/factory.c:1299-1323`], and RD 4.1 says so (line 123). So either the channel is half of `leaf_amount_sat` or the leaf is twice it. RD 4.1 (line 124) says the leaf amount "follows from the funding amount and the shape", with `leaf_amount_sat` as its source. The import computes each node's amounts top-down from the funding amount, less `fee_per_tx` and the anchor per transaction, with remainders given to the last child [C: `src/factory.c:1700-1720`]. So leaves are never exactly equal and never exactly `leaf_amount_sat`. No document gives the rule that ties `funding_amount` (MS record 14) to the terms, so a member cannot tell whether the host funded the amount the terms promised. **Change:** define `funding_amount` as a function of `leaf_amount_sat`, n, the shape, `fee_per_tx` and the anchors, or define the C8 check as "each leaf's channel output ≥ X" with X stated precisely. Rename the term to say whether it is the leaf or the channel.

#### F5. Placement is encoded two ways

RD 4.1 (line 116): placement is "Fixed by this specification ... value 0, written by the engine", not a proposal field. MS 7.2 record 26 (line 438) is a required `placement` field whose value must be **1**, and MS line 656 repeats "`placement` = 1". The import's `PLACEMENT_SEQUENTIAL` is 0 and 1 is `PLACEMENT_INWARD` [C: `factory.h:60-61`]. A builder who copies the wire value into the field gets the balance sort. **Change:** drop record 26, or state that wire value 1 means the import's 0.

#### F6. C10 against H11, and the creation states after a released partial signature

- H11 requires each retry's funding transaction to spend an input of the previous one (SR line 296). C10 (SR line 139) forbids a second unresolved round "touching any given output it has an interest in". A member that released partial signatures in attempt 1 is Unfinished, and through C4(d) its records depend on attempt 1's funding inputs. If an implementer counts those inputs as "touched", **every retry after a partial-signature failure is refused with reason 6**, the outcome review 2 N6 warned of. **Change:** say that a creation round touches only its funding outpoint and the tree, and that an Unfinished creation attempt of the same lobby does not block that lobby's next attempt.
- The Unfinished state "exits" after the unfinished deadline (RD 10, line 247), but a creation round has nothing to exit. Say that a creation round that is Unfinished becomes Abandoned at the funding deadline and Dead under C4(d).
- MS 7.9 (line 608), MS test 35 (line 829) and JN open point 6 (line 281) call "a funding input spent elsewhere and buried" **abandoned**. RD (lines 167, 171–172) calls that **Dead** and keeps "Abandoned" for the funding deadline. JN `round_ended` (line 191) has no "dead" outcome. RD says Dead records are "discarded"; JN says `round_started` is "never removed" (lines 185, 278). Use one set of names and say that Dead means "no longer consulted", not "removed".
- Late funding: "Abandoned → Live if funding buried later" (RD line 171) should re-run the C5 and C8 time checks at that moment, since the margin was judged at signing. Low in Slice 1. [R]

#### F7. What the C7 record holds is not defined in a way the journal stores

SR C7 (line 111): the record holds "the funding outpoint, the funding transaction and **a digest of the tree**", and the member refuses "any different tree". No document defines the tree digest, or what makes two trees "the same". It cannot be the round identifier, which changes with `host_random`. JN `exposure` (line 187) holds the round, tier, funding outpoint and per-item index, spent outpoint and digest, but **not** the funding transaction or a tree digest. The funding transaction is only in `round_proposal`, which "may be dropped by a later compaction" (line 186), yet C4(d) needs its inputs to end the record. RD S1 also saves "the tier and item indices"; JN `round_started` does not. **Change:** define `tree_digest` (for example a tagged hash of the item list as in MS 7.1 without `host_random`), put it and the funding transaction (or its input outpoints) in `exposure`, and say that the compaction rule keeps both.

#### F8. The chain actions cannot express what C11 and C4(d) ask for

`GZ_ACTION_WATCH` watches "an output paying this script" [C: `action.h:37`, `:62`]. Events report script spends, transaction confirmations and tips [C: `event.h:24-28`]. The member must (a) watch the funding txid until buried, which needs a "watch this txid" action (`TX_CONFIRMED` exists as an event, but no action asks for it), and (b) see when any **input** of `funding_tx` is spent elsewhere. `funding_tx` is sent without witnesses and without the previous outputs (MS line 434), so the member does not know those inputs' scripts and cannot watch them by script. **Change:** add watch-by-outpoint and watch-txid actions to the core contract (the Esplora-style chain view can answer both). Without this, C4(d), Dead and N16's resolution cannot be built.

#### F9. Losing `start` across a reconnect leaves the member ignoring the proposal

`start` is unsigned, is not saved by the member (no JN record) and is never resent: after a reconnect the host sends `terms_offer` and `lobby_status` only (MS line 174). The member ignores a `round_propose` "before `start` for its `check_id`" (MS lines 467, 641). A reconnect or member restart between `start` and `round_propose` therefore costs the attempt. That is liveness, not money, but a builder must guess whether `lobby_status` seat state 3 ("Chosen to sign") counts as `start`. **Change:** either let a valid signed `round_propose` whose `check_id` the member answered stand on its own (the proposal is signed and carries everything), or resend `start` after `hello` while signing.

#### F10. A proposal with a known round identifier but different bytes is unhandled

Fields outside the round identifier include `check_id`, `attempt`, `terms_version`, `nonces_due_ms`, `sigs_due_ms`, and every participant's contribution key and two bindings (MS 7.1 against 7.2). The MS 7.2 case table is keyed on "same bytes" (line 461). A member in Nonces sent that receives a second, validly signed proposal with the same `round_id` and different bytes falls through the table. An implementer who reads "new bytes" as "new proposal" generates a second nonce for (round, item): the equivocation evidence of RD section 9, though no key leak, because `session_id32` is fresh. RD S2 forbids it in general, so this is a missing row, not a design flaw. **Change:** key every case on `round_id` and say that any second proposal for a saved `round_id` is treated as a duplicate, and kept as evidence if it differs. Consider putting the contribution keys inside the identifier: the evidence of RD section 9 relies on them and they cost 33 bytes each.

#### F11. Keep-alive and step timeout contradict each other

MS line 27: 30 s "is well below the shortest step timeout a host may set (section 3 of `terms.md`)". TR line 59: `step_timeout_ms` from **1,000** ms, "Above the 30 s keep-alive". Both claim the other is larger. **Change:** raise TR's minimum to above 30,000 ms (and the ready window, line 57, if it should also exceed it), or shorten the keep-alive.

#### F12. Which BOLT 8 key the member uses before it knows the lobby

The contribution key is "a fresh BOLT 8 static key for each lobby" and names the seat (MS lines 24, 172). But the first `hello` may carry scope zero to list lobbies (MS line 213), and the member learns the lobby identifier only from the answer. So the member must choose a key before it knows the lobby: allocate an index per connection attempt, or reconnect with a new key before `join`. R6 updates the guard before every key allocation, so this choice also matters there. **Change:** state it. The simplest rule: allocate a fresh index per new connection, and bind it to the lobby at `join`.

#### F13. Unbounded writes a peer can force

- At the host: `join` creates a seat "saved before it answers" (MS line 257). `leave` then `join` again "creates the seat again" (line 304), and `ready` and `unready` save seat changes (JN `seat` holds "the seat's latest signed `ready` bytes"). None is rate-limited, and seat keys are free. One member can loop join/leave or ready/unready until the host's journal reaches its soft limit (768 MiB), at which point the host stops opening lobbies (JN line 134), or its hard limit, where it stops. **Change:** a per-connection and per-seat limit on state changes, and do not save a seat change that returns to a state already saved.
- At the member: every new `current` version before the freeze is saved (`terms_received`, JN line 176), and versions are free for the host. Bound how many versions are kept, for example the frozen one, the latest accepted and evidence.
- `hello` with scope zero answers with up to 16 `terms_offer` of up to about 5 KB each: an amplification of about 80 KB per small message per connection per second. Accepted for Slice 1, but worth a global limit.

#### F14. `round_abort` has no tier or item fields

RD section 4 (line 95): "a reason; the tier and items it concerns, if not the whole round". RD S2 (line 76) answers per item with `round_abort`. RD open point 3 lists "the optional tier and items in `round_abort`". MS 7.9 (lines 578–584) has `round_id`, `reason`, `evidence`, `detail`, `sig` only. That is harmless with one tier, where an abort covers the whole round, but it is a mismatch. **Change:** add odd records `tier` (u8) and `items` (u32 list), or state that Slice 1 aborts whole rounds only.

#### F15. The randomness port has no "secret" tag

RD section 8 and SR R2 depend on "the randomness port, with the request tagged secret". `gz_random_port_t` is `fill(ctx, out, len)` with no tag [C: `ports.h:19-25`]. **Change:** add the tag to `ports.h` (or a second function) before the engine is written. Then R2 must use the untagged form (F3).

#### F16. Stated more strongly than supported

- THREAT-MODEL line 38: two trees on one output, gap "—". F2, and the tests do not exist yet.
- THREAT-MODEL line 112: "The journal is encrypted at rest". JN line 25: "Not encrypted in slice 1".
- SR section 11 (line 311): a host returning an old backup causes loss of sight of later factories "nor the denial of service". A stale backup also lacks the **held set** of those factories. That is a loss of funds in 1.0.0 unless the host or other members supply the signed tree, so it is not only denial of service. Not relevant in Slice 1, where nothing is owed.
- TR line 39 calls T1 "the slice 1 example". By F1, T1 cannot form a Slice 1 factory.
- JN line 111: "no batch in them was ever confirmed". By F2, this is not known.
- MS line 443 says fixed levels have "no timelocks". Static nodes carry the host-only CLTV timeout and set nSequence to enable it [C: `src/factory.c:129-136`, `:1632-1644`]; they lack only the relative (layer) timelock.

### Low

- **F17. What `fixed_levels` counts.** The import's `static_threshold_depth` counts tree depths, a leaf can never be static [C: `src/factory.c:1659-1667`], and `dw_n_layers_for` always returns at least one layer [C: `:710-718`]. "Every level of the shape" (MS line 443) does not say which number to write, and the real depth can exceed the shape's `levels` (F1). Give the number as a formula. Also, a non-PS leaf whose layer index is −1 would read `layers[-1]` in `node_nsequence` [C: `:1652-1653`, `:146`]. That is one more reason for F1's PS-only check.
- **F18. Three wordings of the 512 limit.** SR C8 (line 129) and RD (line 275): refuse a hashed node at index 512 or more. MS line 442: refuse a tree with more than 512 nodes. MS allows 4,096 hash entries. Also, `factory_set_node_l_stock_hash` drops indexes at or above the **current** `max_nodes` [C: `src/factory.c:411`], and RD section 13 calls it before `factory_build_tree` grows the arrays and zeroes the new tail [C: `:1919-1936`]. So even after the upstream fix at line 393, that order would lose the high hashes. Note it in RD section 12 for when the fix lands.
- **F19. Stale text in MS and TR.** MS 4.3 (line 123) still discusses draft 2's factory-key contradiction. MS 7.2 (line 421) still says the parameter list is provisional "until draft 3 publishes its table". MS open point 4 (line 857) says RD section 5 puts channel states in the creation tier. TR 10.4 (line 161) and open point 8 (line 264) wait for draft 3, which has decided. JN open point 5 likewise. SR line 7 and RD line 7 describe MS and TR as provisional.
- **F20. Signer selection wording.** "Cut to the target ..., then reduced until every chosen seat's `min_members` is met" (MS line 355). Removing seats cannot raise a count. Say: repeatedly drop every seat whose `min_members` exceeds the current count.
- **F21. JN minimum entry length.** 17 (JN line 47) allows an empty payload, which is invalid for both kinds: an incarnation entry needs 8 bytes and a batch entry 4. Use 21, then check per kind.
- **F22. The first batch after a restore.** "The program writes `key_epoch` and `restored` as the first batch of the restored journal's first new incarnation, before the node starts" (JN line 152). Sequences are issued by the runner from 1 (`runner.h:27-36`), so a batch written outside the runner collides with the runner's sequence 1 (JN order rule 4). Say who issues that batch.
- **F23. Layer delay overflow.** `dw_delay_for_state` returns `uint16_t` step × (states − 1 − i) [C: `src/dw_state.c:9-12`]. When timed layers arrive, C8 must bound step × (states − 1) ≤ 65,535. Not Slice 1.
- **F24. Owner decision 6 says "Use pay-to-anchor outputs"** (`decisions.md` line 65). RD 4.1 makes tree anchors a host choice "inside conditions" (line 118). Either fix them on, or record that the member's conditions should require them.
- **F25. A 16-wide level with anchors.** TR allows arity 16, and the import silently omits the anchor on a node with no output slot left [C: `src/factory.c:501`; KNOWLEDGE-BASE line 83]. Both sides build the same bytes, but "anchors on" is then not true of every transaction (C3, C5).
- **F26. Saved partial signatures after a reconnect.** If the member reconnects while the host is still collecting partial signatures, nothing triggers the resend. The host does not resend `round_all_nonces` and has no tier result yet to answer `round_status_request` with. The attempt then fails at `sigs_due_ms` and moves to a new outpoint. Let the member resend its saved `round_partial_sigs` after `hello` (S3 allows it).
- **F27. `factory_set_funding` returns void and silently ignores a script longer than its buffer** [C: `src/factory.c:1219-1222`]. Add to RD section 12: check that the script is exactly 34 bytes before the call.

### F28. The coordinator's question: sign the 32-byte `factory_protocol_id` instead of the 4-byte tag

Proposal: in MS 4.3's `msg_hash` and in MS 7.1's round-identifier preimage, replace `protocol` (`67 7a 66 01`) with `factory_protocol_id = SHA256("SuperScalar/1")` (32 bytes).

**Is it a strict improvement? No. It is neutral for security, a modest gain for interoperability, and it adds a dependency.**

- **Security: no change.** The 4 bytes are not a security parameter. They are input to a 256-bit tagged hash whose tag (`gazpacho/msg`, `gazpacho/round_id`) already separates domains. A short field in a preimage gives a forger no collision or substitution to exploit. What matters is that each protocol version has exactly one encoding, and MS 10.2 already makes tag and id one-to-one. MS 10.2 (line 695) also already has **both carriers sign the native form**, so native and adapter already bind exactly the same identity: the adapter rebuilds the 4-byte tag from TLV 0 before checking anything. [R]
- **Interoperability: a real but partial gain.** If the payload format becomes the shared "SuperScalar/1", signing the bLIP-56 identity rather than a Gazpacho-branded `gzf` tag lets a second implementation compute the same hashes without knowing our tag. But the tagged-hash **tag strings** are still `gazpacho/…` (msg, round_id, nonce, nonceset, held, bind, part, terms/outer, terms/current, nonce-extra). A shared format would need those renamed too. Otherwise the change only half reaches its goal.
- **Cost and risk.** The string "SuperScalar/1" is still **(open)**, not agreed with the SuperScalar session (MS 10.3, open point 18). Putting it into every signature now means that if the name changes, every signed vector and every saved signed record has to change. The preimage would also no longer be a prefix of the wire bytes (the wire keeps the 4-byte tag), so implementers must substitute the id rather than hash the received bytes. That is small, but it is one more place to get wrong. Cost in bytes: 28 more bytes hashed per message, which is negligible.

**What else would change.**
- MS 4.3 (`msg_hash`); MS 7.1 (first field 4 → 32 bytes); MS 10.2 (the "signatures do not change" paragraph, rewritten as "both carriers sign over the id"); vectors **M1** (`msg_hash` and its signature) and **M3** (same new signature); `tools/spec-vectors.py`.
- Through the round identifier: every nonce signature (`gazpacho/nonce` covers `round_id`) and `nonce-extra`. No vectors exist for these yet (MS line 417).
- **Unchanged:** TR's digests and T1 to T6 (the terms records contain no protocol field, and TR's tags separate them); the binding (`gazpacho/bind` covers scope and keys only); `transfer_id` and M2; `nonceset`; `held`; every JN record and J1 to J4 (JN stores native envelope bytes, which keep the tag).
- Side note: the terms records then bind the chain but no protocol version at all. That is acceptable, because the tags carry the domain, but worth stating in TR section 6.

**Recommendation.** Do not change it for Slice 1. Decide it together with the shared-format question: when "SuperScalar/1" (or another name) is agreed with SuperScalar, rename the tag strings to the agreed namespace and switch signed preimages to the 32-byte id in the same change, with new vectors. Until then, state in MS 4.3 that the 4-byte tag is a fixed alias of the protocol id and is not a security parameter.

---

## 3. Cross-spec consistency table

✓ agrees; ✗ disagrees (finding); — not mentioned.

| Item | SR d3 | RD d3 | MS d1 | TR d1 | JN d1 | Status |
|---|---|---|---|---|---|---|
| Round identifier | Uses it | Defined abstractly, section 3: both terms digests, items, mode, signers, `host_random` | Defined concretely in 7.1, tag `gazpacho/round_id`; signers by position | 10.4 still calls it "digest of the host's signed terms", "(provisional)" | Stored in `round_started` | ✓ defined once (MS 7.1), used the same way; TR text stale (F19). Contribution keys not inside (F10) |
| Both terms digests in the identifier, C8a | ✓ C8a | ✓ | ✓ (marked prov.) | ✓ (marked prov.) | — | ✓; "(prov.)" can be dropped |
| Nonce signature `TH(nonce, round_id‖tier‖index‖nonce)` | — | ✓ line 98 | ✓ line 480 | — | — | ✓ |
| `nonce-extra` tag | — | ✓ line 195 | Not in MS's list of tags | — | — | Missing from MS (low) |
| `nonceset`, `held` digests | — | Described, tag unnamed | ✓ named | — | — | ✓ |
| Binding `TH(bind, lobby‖factory‖contribution)` | — | ✓ | ✓ | — | — | ✓; vector verified |
| `round_ack`, `round_status_request` | ✓ | ✓ | ✓ kinds 76, 80 (prov.) | — | ✓ records | ✓; "(prov.)" can be dropped |
| `round_abort` tier and items | — | Has them | Lacks them | — | — | ✗ F14 |
| Reason 12 | Recovery-only key | Recovery-only key | No creation before `fresh_start` | — | `fresh_start` | ✗ F3 |
| Reason 11 (another tree on the outpoint) | ✓ | — | ✓ | — | ✓ test 21 | ✓ |
| Restore epoch | 31-bit, ≠ 0, install = 0, secret tag, journaled | Secret bytes never journaled | "journal's key epoch" | — | 32 bytes, also at creation | ✗ F3, F15 |
| Guard record R6 | Required, outside the journal | — | — | — | Absent | ✗ F3 |
| C7 record contents | Outpoint, funding transaction, tree digest | Exposure + partial-signature bytes in one write | One batch (7.4) | — | `exposure`: no funding transaction, no tree digest | ✗ F7 |
| Record before the first partial signature, same atomic write | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| Placement | Sequential | Not a field; value 0 | Field 26 = 1 | — | — | ✗ F5 |
| Shape / arity | Terms' table | `factory_set_level_arity` from the table | Not carried | 2–16 per level | — | ✗ F1 (against the import) |
| Leaf amount | Channel ≥ minimum | Leaf half/half; from `leaf_amount_sat` | — | = channel size | — | ✗ F4 |
| Fixed levels | All in Slice 1 | `factory_set_static_near_root` | "without timelocks" | Levels all fixed | — | ✗ wording, F16/F17 |
| 512-node limit | Hashed node index ≥ 512 | Same | > 512 nodes | — | — | ✗ wording, F18 |
| Member states Abandoned / Dead | ✓ | Abandoned = deadline; Dead = input spent | "abandoned" for input spent | — | No "dead" outcome; records never removed | ✗ F6 |
| Results kept by the host | Until funding spent or dead (H12) | Same | Until funding spent | — | Until funding spent | ✓ (small difference) |
| Funding transaction in the proposal | ✓ | ✓ | ✓ record 18 | — | `funding_plan` (host) | ✓ |
| Keep-alive vs step timeout | — | — | 30 s < step | step ≥ 1 s "above 30 s" | — | ✗ F11 |
| Ready window = `answer_within_ms` | — | — | ✓ | ✓ | — | ✓ |
| Freeze at the first ready check | ✓ C8a | ✓ | ✓ | ✓ | ✓ `freeze` | ✓ |
| Lobby identifier = outer digest = scope | — | — | ✓ | ✓ | ✓ | ✓ |
| Record type 240 = signature, last | — | — | ✓ | — | — | ✓ |
| Journal record types even, area/kind split | — | — | Odd/even rule | — | ✓ | ✓ |
| Factory key signs items + one binding | — | ✓ section 2 | ✓ 4.3 (old discussion stale) | — | — | ✓; F19 |

**MS "(prov.)" items against draft 3:** `round_ack` ✓; `round_status_request` ✓; two-way binding ✓; tier in the nonce signature ✓; one nonce and partial signature per (round, item) ✓; per-tier state, Aborted only before any partial signature ✓; new outpoint after a release ✓; both digests ✓; reason 11 ✓; **reason 12 ✗**; **parameter table: placement ✗, `round_abort` items ✗**, and otherwise as RD 4.1. **JN "(prov.)" items:** `exposure` before partial signatures ✓; **key epoch, `restored`, `fresh_start` ✗**.

---

## 4. Slice 1 walk-through

One host H, members M1 to M3, separate processes, signet. "Save → send" means one action list [save batch, send] through the runner: the send leaves only after the batch is confirmed after a sync. Gaps where a builder must guess are numbered **G**.

| # | Step | Journal (before the outward action) | Crash or restart at this point | Gaps |
|---|---|---|---|---|
| 0 | Start | JN section 5: lock, header check, scan, cut tail, new incarnation entry synced, read records, `gz_node_start` | A crash during the tail cut or the incarnation write is safe (JN line 118) | **G1** the torn-tail rule cuts confirmed records (F2). **G2** restore: which epoch format, guard, `fresh_start` (F3) |
| 1 | Connect (BOLT 8 XK to the pinned host key), `init` with signet only | Member: `key_index` before the key is used | Reconnects with the same derived key | **G3** which key before the lobby is known (F12); key derivation path open (MS open point 3) |
| 2 | `hello` | — | Idempotent | — |
| 3 | `terms_offer` → check TR section 7, classify (section 9) | Host: `lobby_opened` / `terms_version` before sending. Member: `terms_received` before `join` | Host restart: same records; a duplicate is ignored | **G4** T1's shape builds multi-member leaves (F1); `leaf_amount_sat` meaning (F4) |
| 4 | `join` (factory key, two bindings) | Member: `joined`, `key_index` (and the R6 guard: no mechanism). Host: `seat` before `lobby_status` | Idempotent by key | **G5** guard write ordering (F3); unbounded seat writes (F13) |
| 5 | `lobby_status` | — | Newest wins | — |
| 6 | `ready` (both digests, signed) | Member: `ready_sent`. Host: `seat` | Resent byte for byte | — |
| 7 | `ready_check` (freezes) | Host: `freeze` before the first one. Member: `freeze` before answering `ready` with `check_id` | Same `check_id`: the same saved `ready` | — |
| 8 | `start` (unsigned) | **Nothing saved** | Lost across a reconnect: the member ignores the proposal | **G6** F9 |
| 9 | `round_propose` → member: verify the signature and bindings; rebuild from outer terms + frozen values + fields; compute `round_id`; C1–C12; save | Host: `funding_plan`, then `round_started` + `round_proposal` before sending. Member: `round_started` + `round_proposal` before `round_nonces` | Member restart before the save: nothing, fresh start. After the save: the identifier is refused, reason 3 | **G7** shape → `level_arity`, leaf kind check (F1); **G8** `fixed_levels` number (F17); **G9** placement value (F5); **G10** fee rule (MS "exact rule provisional"); **G11** funding amount rule (F4); **G12** tree digest for C7 (F7); **G13** C10 and funding inputs (F6); **G14** same `round_id`, other bytes (F10) |
| 10 | Nonce generation, `round_nonces` | Secret nonce in memory only; covered by step 9's batch | Restart: nonce lost, reason 3 on the next proposal (S2) | **G15** no secret tag on the port (F15); RD 8 does not say whether the tweaked or untweaked key-aggregation cache is used (either is allowed by the header; pick one) |
| 11 | `round_all_nonces` → member verifies every `nonce_sig`, its own nonces, re-runs the checks | **`exposure` + `round_partial_sigs` bytes in one batch** before sending | Restart after the save: resend the saved bytes, Unfinished | **G16** no trigger to resend after a reconnect mid-collection (F26) |
| 12 | `round_partial_sigs` → host verifies each one (H2), combines, verifies finals from bytes | Host: `round_signed` (+ per-member `round_tier_result` bytes) before sending | Host restart: a new attempt, new outpoint (H11, H13) | **G17** no member deadline for the result (only `nonces_due_ms`, `sigs_due_ms`); the step timeout is presumably meant |
| 13 | `round_tier_result` → member verifies the finals against its own transactions | (member saves together with the next step) | — | — |
| 14 | `round_complete` | Member: `round_signed` + `round_completed` (with the ack bytes) before `round_ack` | Duplicate: resend the ack | — |
| 15 | `round_ack` → host checks `held_digest` | Host: `ack_received` before signing the funding | — | — |
| 16 | Funding: the host signs exactly `funding_tx` | Host: `funding_signed` before broadcast; rebroadcast after a restart | — | **G18** burial depth, funding deadline, unfinished deadline: owner values (SR section 12) |
| 17 | `factory_funded` (hint); the member watches the exact output to burial (C11) through two servers | Both: `funding_status` | — | **G19** no watch-txid or watch-outpoint action; input scripts unknown (F8) |
| 18 | Live / Abandoned / Dead | `round_ended` | — | **G20** state names (F6) |

Failure paths: a member silent in step 10 → host `round_abort` reason 4 → new ready check and attempt on the **same** outpoint ✓. A bad partial signature in step 12 → new attempt on a **new** outpoint spending an input of the old one ✓ (needs G13 settled). A missing ack → no funding, new attempt without that member ✓. A member whose conditions fail at step 9 → `round_abort` reason 1 or 9, nothing saved ✓. That is Slice 1's "seen to refuse", and with T1 as written **every** member refuses (F1).

Also needed and not in these five: the owner's Slice 1 decisions (distribution transaction or not; how the host recovers its signet coins; burial depth; deadlines), the key derivation path, and the TLV field numbers inside each journal record (JN open point 3, an internal choice).

---

## 5. Status of review 2's findings

| | Status | Residual |
|---|---|---|
| N1 restore | **Resolved in SR, contradicted by JN and MS** | F3 (epoch format, secret tag, reason 12, `fresh_start`, guard record); R4 detection not implementable as stated |
| N2 leaf change | Resolved | — |
| N3 timed-layer race | Resolved (restated, marked reasoning) | Still unchecked against the design posts, as SR says |
| N4 ack, status request | Resolved | Encoded in MS; F26 resend gap |
| N5 parameters | **Partly resolved** | RD 4.1 exists; shape semantics (F1), leaf amount (F4), placement (F5) and fixed levels (F17) are wrong or ambiguous |
| N6 retries | Resolved | C10 interplay (F6); record contents (F7) |
| N7 state contradictions | Resolved | `round_abort` items missing in MS (F14) |
| N8 nonce function | Resolved, header verified [S] | Port has no secret tag (F15) |
| N9 channel states | Resolved as a deferral | — |
| N10 layer-update identifier | Resolved as a deferral | — |
| N11 frozen terms | Resolved | TR/MS "(prov.)" text stale (F19) |
| N12 C5 anchors, distribution | Resolved | F25 (anchor omitted at 16-wide) |
| N13 import hazards | Resolved | New: level-arity leaf type (F1), F18, F23, F27 |
| N14 Unfinished | Resolved | Creation case undefined (F6) |
| N15 fault table | Resolved | — |
| N16 unfunded creation | Resolved in the specs | Cannot be built with today's chain actions (F8); naming (F6) |
| N17 contribution key | Resolved | First-connection key (F12) |
| N18 nonces at ready check | Resolved | — |
| N19 payout review | Resolved | — |
| N20 TESTING invariant 3 | Resolved (`docs/TESTING.md:41`) | — |
| L1 recovery close | Resolved (marked not specified) | — |
| L2 withheld close | Resolved | — |
| L3 funding malleation | Resolved | The member cannot see that inputs are segwit; this is the host's own risk, which is acceptable |
| L4 timeout order | Resolved, verified [C: `src/factory.c:1475`, `:1632-1644`] | — |
| L5 delay functions | Resolved, verified [C: `:4900-4927`] | — |
| L6 other documents | **Not resolved** (recorded as SR open point 9) | `KNOWLEDGE-BASE.md:115-116`, `DESIGN.md:70-71` unchanged |
| L7 leaf-link reorganisation | Resolved | — |
| L8 deterministic last-signer nonce | Resolved (recorded, not adopted) | — |

---

## 6. What was checked

**Code citations.** Every file:line cited by SR and RD was opened. All point at what they claim, including: `factory_set_funding` on trust `:1214-1228`; anchors `:498-507`, `:1325`, `:1742`, `:1768`, `:1876`, `:4451-4458`, `:4532-4539`; `fee.c:90-97` (no estimator → anchor); timeouts `:185`, `:541-548`, `:1475`, `:1632-1644`; PS leaf `:1299-1326`; mirror-hash bug `:391-397`; init `:853-900` (overflow `:880-884`, placement default `:889`, fee 200 `:861`); setters `:903`, `:1054`, `:1059`, `:1164`, `:1189`, `:409`; `:1900-1903`, `:1917`, `:1940-1944`; sessions `:2036`, `:2043`, `:2066-2076`, `:3109-3158`, `:4577`, `:4606-4612`; `:2437-2448`, `:2769-2782`, `:4900-4927`; `dw_state.c:9-12`, `:36-46`; `dw_state.h:38-45`; `musig.c:9-15`, `:17-36` (no sorting, so order matters), `:75-77`, `:171-209`, `:307-321`, `:374-406`, `:408-421`, `:423`, `:463-480`; `tapscript.c:663`; `factory.h:50`, `:60`, `:173-196`, `:358-359`, `:379-398`, `:429-440`, `:471-486`, `:536-541`, `:893`, `:942`, `:1237-1261`; `musig.h:186-195`; `channel.h:16`. The root kickoff key is BIP 86 (`taproot_tweak_pubkey` with no merkle root uses `TapTweak(P)`, `:61-96`), which supports C1's funding-script check. What the citations miss is F1 (the meaning of the last arity entry).

**secp256k1-zkp at `6152622`** [S, header fetched]: `secp256k1_musig_nonce_gen(ctx, secnonce, pubnonce, const session_id32, seckey, const pubkey*, msg32, keyagg_cache, extra_input32)`. `session_id32` must be unique and should be uniformly random; message, cache and extra input are optional inputs that "increase misuse-resistance". `partial_sign` overwrites the secret nonce with zeros and aborts on an all-zero one. RD section 8 matches. The call does not modify `session_id32`.

**BOLT 1** [S]: custom types 32768–65535; unknown odd ignored, unknown even close; too short close; TLV minimal BigSize, strictly increasing, unknown even fail, odd skip, overlong fail; maximum 65,535 bytes; `networks` mismatch MAY close; `warning` does not require closing (MS's "refuse = warn and close" is Gazpacho's own stricter choice, which is allowed); a missing `pong` MAY close. MS section 2 matches. Arithmetic checked: header 38; records ≤ 65,495; part overhead 56; M2 sizes 65,096 / 11,896; count ≤ 17 at 1 MiB; `round_nonces` ≤ 34,304; adapter 65,491 / 65,457.

**Vectors** [V]: the generator's output equals every vector printed in TR, MS and JN. Independently recomputed: the three test public keys from their labels; T1 (225 bytes) outer digest and signature; T2 digest and signature; binding and both binding signatures; M1 `msg_hash` and signature over `protocol‖kind‖scope‖records before 240`; type 52791; `SHA256("SuperScalar/1")`; J1 check; J2 and J3 checksums; M2 `transfer_id`. All match.

## 7. What I could not check

1. Nothing was built. F1 is from reading `factory.c`, not from running a four-participant build. The first thing to do is build T1's shape for 3 members and see the leaf kind.
2. Whether "all levels fixed" with PS leaves builds and signs in the import at Slice 1 sizes (F17).
3. BIP 327 passages beyond what review 2 quoted; BOLT 8 was not re-fetched (the 65,535 limit was confirmed in BOLT 1).
4. bLIP-56 (MS section 10; not used in Slice 1): its numbers and rules were not re-read.
5. Whether libsecp256k1 aborts on an unset session structure (still "expected, not tested").
6. `docs/LOBBY.md`, `DESIGN.md`, `CHAIN-SERVERS.md`, `RECORD.md` beyond the lines cited in the specs.
7. Whether signet relays tree transactions at 0.1 sat/vB with the chosen servers.
8. SR section 8's reasoning against ZmnSCPxj's text, as SR itself says.
