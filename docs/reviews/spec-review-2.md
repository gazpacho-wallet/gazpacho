# Review 2 of the safe-to-sign rule and the signing round

2026-11-11. Adversarial review of `spec/safety-rule.md` (draft 2) and `spec/signing-round.md` (draft 2). Read against `docs/reviews/spec-review-1.md` (F1 to F15), `docs/KNOWLEDGE-BASE.md`, `docs/DESIGN.md`, `docs/ux/decisions.md`, `docs/SLICES.md`, `docs/research/channel-groundwork.md`, the SuperScalar end-date payout review (a local folder; Gazpacho's summary is `docs/handoff/2026-11-11-review-of-end-date-payout-draft.md`), the imported code under `core/superscalar/` (`src/factory.c`, `src/musig.c`, `src/dw_state.c`, their headers, and one routine in `src/tapscript.c`), and BIP 327 as fetched today. I did not write either specification. Nothing was built or run.

Marks, as in review 1:

- **[S]** checked today in a primary source that I fetched (BIP 327; link in section 7);
- **[C]** read today in the imported code or the project's documents (file and line given);
- **[R]** my own reasoning, not confirmed by a source or a test.

Line numbers for the specifications refer to the drafts as they stand today: `safety-rule.md` is "SR", `signing-round.md` is "RD".

---

## 1. Verdicts

**`spec/safety-rule.md`: ready after listed changes.** Draft 2 answers review 1 in substance. The exposed set, the one-tree rule, the activation rule, the split of C4, the honest account of timed layers and the host rules are all there and mostly right. What stops it being ready: a restore from an old backup reopens the two-tree attack for any factory created after that backup (N1); the leaf-change model it spends section 4 on is not the one the owner decided to ship (N2); its own rule that old-state anchors are kept current undercuts its statement that losing a timed-layer race is "loss, not delay", which is the premise of open point 1 (N3); and C5 and C8 as written either refuse every real tree or leave out parameters that change the tree (N5, N12). For Slice 1 only a small part is needed, and that part is close (section 5). Section 4 needs real rework before liquidity sales (1.1.0).

**`spec/signing-round.md`: ready after listed changes.** The round identifier, save-before-first-contribution, separate contribution keys, host-signed proposal and result, tiers and the honest fault table fix review 1's findings. Nothing needs a different cryptographic design. But the state rules contradict each other in four places, one of which can make an honest member sign two nonces for one (round, item) (N7). The host's rule H1 needs an acknowledgement message that does not exist (N4). The time-budget retries collide with "one tree per funding output" unless the funding outpoint changes per attempt, and nobody says it must (N6). The function it names for nonce generation reads the operating system's randomness itself and cannot be fed the core's randomness (N8). Putting channel states into round tiers conflicts with how the standard taproot channel format handles its own nonces and signatures (N9). For Slice 1, changes N4 to N8 are blocking. N9 and N10 block later slices only.

---

## 2. Findings, most serious first

No finding is critical in the sense of "an honest member loses money without any unusual circumstance". The first one comes closest.

### High

#### N1. A restore from an old backup reopens the two-tree attack and the restart frame for any round begun after that backup

Concerns: SR C12 (line 65), C7 (line 55), section 10 (lines 170–171); RD section 3 (line 50), section 8 (line 125), test 4 (line 210).

C12 refuses "every request in a factory that existed before the restore". The round-identifier refusal list (RD line 50) and the one-tree record (C7) are in the journal. The host keeps the member's backup and chooses which copy to return (SR line 65 says so; `DESIGN.md` sections 8 and 9 [C]).

**Scenario** [R]:

1. The member's backup held by the host is dated D.
2. After D the host runs creation for factory F on funding outpoint O. The member records O and tree T1, saves round identifier R1, sends nonces and partial signatures. The host withholds the result.
3. The member's phone is lost. The member restores from the host's copy dated D. That copy holds no record of R1, O or T1. F did not exist at D, so C12 does not apply.
4. The host now (a) replays R1's proposal: the member computes the same R1, finds no saved record, and sends fresh signed nonces. The host now holds two signed nonces from the member for R1, which section 9 treats as proof of fault. The member is framed. Or (b) proposes T2 on the same O: the member has no record, so C7 passes. This is the F1 attack again: T2 is completed and funded, the member is paid in T2, the host publishes T1's root.

There is a second path to the same place without a replay. Identity is new per lobby by default (`KNOWLEDGE-BASE.md` section 5 [C]). If the per-lobby key comes from a derivation index stored in the journal, a restored member derives again the key it used after D, so a "new" lobby can use the same aggregate key, hence the same funding script, as a factory signed before the restore.

**Change.**
- A restored node refuses creation rounds with every host it ever dealt with until its records show nothing in flight. It cannot prove that, so the simple rule is: after a restore, the per-lobby key derivation jumps forward by a fresh random offset, the contribution key is replaced, and the node refuses any round whose funding outpoint it cannot show was created after the restore. Or, more simply, it signs no creation round until the user confirms a fresh start.
- C12 should cover "any factory or round the node may have taken part in since the backup", not "a factory that existed before the restore".
- Add test 4b to RD section 14: restore from a backup older than an unfinished creation round, then a replayed proposal and a second tree on the same outpoint. Both must be refused.

#### N2. The leaf change in section 4 is not the operation the owner decided to ship

Concerns: SR section 4 (lines 75, 85), section 5 rows "liquidity change" (line 98), C7 (line 55, "two liquidity changes"); RD section 5 "Leaf change" (line 80), section 10 (line 163); `docs/ux/decisions.md` decisions 3 and 5.

- SR line 75: "A liquidity change on a leaf adds a leaf transaction that spends the previous one's channel output. The channel gains a new anchor."
- Owner decision 3: buying receiving room is 1.1.0, not 1.0.0. Owner decision 5: in 1.1.0 "Every sale spends only the spare liquidity and creates a **new channel** for the buyer; existing channels stay where they are." [C: `docs/ux/decisions.md` lines 48, 69]
- The imported K = 1 leaf advance spends output 0 of the previous chain transaction, has one output and adds no liquidity: it only moves the channel and makes it smaller by the fee [C: `src/factory.c:2769-2782`]. Open point 3 (SR line 202) is therefore settled for K = 1: no value moves from the spare liquidity.

So section 4's ordered leaf change and the RD tier "Leaf change" specify an operation that 1.0.0 does not have and 1.1.0 will not use. The operation 1.1.0 will use is not specified: a transaction spending the shared spare-liquidity output into a new channel plus the remaining stock. It has its own hazards: the second-spend guard on the shared stock and the stale-chain penalty firing on honest exits [C: `KNOWLEDGE-BASE.md` section 3], and a member holding several channels.

The channel-moving rules (rules 1 and 2, the pause, unfinished rounds) are still needed for layer updates and rotation. Only the leaf-change specifics are wrong.

**Change.** Mark section 4 rule 6 and the RD "Leaf change" tier as "superseded by owner decision 5; to rewrite with the 1.1.0 sale shape". Keep rules 1 to 5 for layer updates. Add to C8 a parameter K (members per sub-factory), range {1} in 1.0.0.

#### N3. With old-state anchors kept current, losing a timed-layer race is not loss of the balance, so section 8 overstates and open point 1 rests on that overstatement

Concerns: SR section 4 rule 3 (line 82), section 8 (lines 128–138), section 7 (line 122), open point 1 (line 197); RD section 10.

SR line 82 requires that commitments on anchors under old timed-layer states are "kept current for the factory's whole life". SR lines 130–131 then say an older state that wins "leaves the member's channel on an old anchor ... This is loss, not delay."

If rule 3 is obeyed, the channel on the old anchor carries the current balance, so the member can still close at its current balance there. What it loses is only:

- any part of its balance above its channel capacity in that old state, and
- whatever the newer state changed for it, such as liquidity bought in the newer state.

In the imported code a layer advance rebuilds the spare-liquidity scripts and the timelocks but does not change any channel output's amount [C: `src/factory.c:431-490` (`update_l_stock_outputs` rewrites only the L-stock script), `:586-620` (rebuild keeps output amounts); `src/factory.c:2786-2797`]. So in 1.0.0, with no sales, the channel capacity under an old layer state equals the capacity under the new one. With rule 3 in force, an old layer state is C4(a), harmless, for the member's balance. It is not C4(c). [R]

Consequences:

- The statement "maximum safe absence is under a day" for every member below a timed layer (SR lines 122 and 138) is true only for a member whose balance exceeds its capacity in some old state still able to reach the chain. That is a 1.1.0 situation.
- The race-fee requirement (SR line 136) collides with owner decision 6: no on-chain reserve required or recommended in 1.0.0 [C: `docs/ux/decisions.md` line 65]. A member without coins can never meet it, so as written every coinless member refuses every layer update. Under the reasoning above, the requirement is not needed in 1.0.0.
- Owner open point 1 asks for an always-on watcher, a longer step, or no timed layers. All three answer a risk that rule 3 has mostly removed for 1.0.0. The owner should see the corrected trade-off: rule 3 costs one more commitment signature per live anchor on every payment, which is at most the number of states per layer, against a race that otherwise loses the channel.

What remains true with rule 3: the old state's spare-liquidity penalty is a deterrent only; an old state that wins delays the exit by its longer timelock; and the member must watch old anchors.

**Change.** Rewrite section 8 as: "With rule 3, an older state that wins costs the member max(0, balance − capacity in that state), plus delay. C4 classifies each old state as (a) when its capacity covers the balance, else as (c) with R = one step." Recompute maximum safe absence from that. Restate open point 1. Have the review this hands to the owner state that this is my reasoning, not yet checked against ZmnSCPxj's text.

#### N4. H1 needs an acknowledgement that the round does not have; "asks again on reconnect" has no message

Concerns: SR H1 (line 146); RD section 4 (lines 57–65), section 7 (line 107), section 10 (lines 162, 165).

H1: the host funds only after "every member has acknowledged holding the result". RD's message table has no acknowledgement after `round_complete`. RD line 165 says an Unfinished member "asks again on reconnect", but no message asks, and nothing says the host must keep results available to answer. [C]

Without an acknowledgement H1 cannot be implemented, and Slice 1's "the host funds last" step has no trigger.

**Change.** Add `round_ack`, sent by a member after it has stored and verified `round_complete` and signed with its contribution key, so that it can serve as evidence that the member holds the tree. Add `round_status_request`, from member to host, answered by the saved `round_tier_result` or `round_complete` bytes. Add to the host's storage rules that results are kept until the factory's funding output is spent. The member also needs a deadline after which an unacknowledged creation is given up (see N16).

#### N5. The parameters a member rebuilds from are never listed, and the build sequence in RD section 13 leaves out settings that change the tree's bytes

Concerns: RD section 4 (line 59, "the parameters from which the member rebuilds"), section 13 (line 194), section 15 point 3; SR C8 (line 57).

For two parties to build byte-identical trees, every input to `factory_build_tree` must match. From the import, these change the transactions but are neither in RD section 13 nor named as proposal parameters [C]:

| Setting | Where in the import | How it is set |
|---|---|---|
| Absolute end height `cltv_timeout`, from which every host-only timeout is derived | `src/factory.c:1632-1644`; `factory.h:358-359` | Field written directly. No setter |
| Placement mode. The default is `PLACEMENT_TIMEZONE_CLUSTER`, which sorts | `src/factory.c:831`, `:889`, `:1970-1973` | Field written directly. No setter exists for "sequential placement" (RD line 194) |
| Tree anchors on or off | `src/factory.c:498-507`; `factory.h:434-440` | Field `use_tree_anchor` |
| Fee per transaction, or a fee estimator that overrides it | `src/factory.c:788`, `:861`, `:1900-1903` | Field, or `f->fee` |
| Spare-liquidity delay | `factory_set_l_stock_csv`, `src/factory.c:1054` | Setter |
| Per-node spare-liquidity hashes (the client mirror) | `factory_set_node_l_stock_hash`, `src/factory.c:409-415`; used at `:391-397` | Setter. Silently ignored for node index ≥ 512 (N13) |
| Fixed levels | `factory_set_static_near_root`, `src/factory.c:1189` | Setter |
| Members per sub-factory, K | `factory_set_ps_subfactory_arity`, `src/factory.c:1059` | Setter |
| Step and states per layer | arguments of `factory_init_from_pubkeys`, `src/factory.c:853-860` | Argument |
| Funding txid, vout, amount and script, all supplied by the caller and never checked against the aggregate key | `factory_set_funding`, `src/factory.c:1214-1228` | Setter |
| Distribution (funding-level payout) outputs and lock time | `factory_build_distribution_tx_unsigned`, `src/factory.c:4516-4568` | Arguments |

C8's list (SR line 57) misses several that decide who can spend what and when: the end height, the spare-liquidity delay, K, the split between channel and spare liquidity on the leaf (fixed at half each at `src/factory.c:1299-1323`), and the distribution outputs and lock time.

**Change.** Add to RD a table "Proposal parameters", one row per setting above with its encoding and the C8 range that applies. Add the missing rows to C8. Require the member to check that the funding script is the BIP 86 key of the aggregate of the participant keys in order, because the import takes it on trust. Slice 1 cannot be built without this table.

#### N6. Retries under the time budget collide with "one tree per funding output, ever"

Concerns: SR C7 (line 55); RD section 11 (line 169), section 9 last line (line 156).

RD repeats attempts "each without those who failed the last" and gives each attempt a new identifier. A new participant set is a new tree. C7 refuses "any different tree for that output". So once any partial signature has been released in attempt 1, attempt 2 on the same funding outpoint is refused by every remaining member, for ever. C7 is right to refuse: the adversary includes the members who dropped out, so attempt 1's tree may be complete in the host's hands (F1).

Neither specification says that each attempt after partial signatures have been released must use a new funding outpoint, which means the host signs a fresh funding transaction (not broadcast, so it costs nothing). Neither says whether the C7 record is made at nonce time or at partial-signature time. If it is made at nonce time, even a failure in the nonce step forces a new outpoint. [R]

As written, either retries at 512 members never succeed after the first partial signatures, or an implementer relaxes C7 and reopens F1.

**Change.** In C7: "the record is made, durably, before the member's first partial signature for that outpoint". In RD section 11: "an attempt that follows one in which any partial signature was released uses a new funding outpoint". Add a test with a failure in the partial-signature step followed by a retry.

#### N7. Four contradictions in the round's state rules, one of which frames an honest member

Concerns: RD section 3 (line 50), section 4 (lines 60, 70), section 6 steps 1 and 3, section 7 (lines 106, 112).

a. **"Never contributes to that identifier again"** (line 50) against tiers. A multi-tier round has one identifier, and the member contributes nonces and partial signatures in every tier. Read literally, tier 2 is forbidden.

b. **"A party that finds a saved identifier for which it holds no nonces answers only with `round_abort`"** (line 50). After signing, a member never holds nonces, because they are erased (line 124). So a member in Signed must answer everything with `round_abort`, including the host's request to resend partial signatures, which line 70 says must be resent as saved bytes. The rule is meant for "a nonce request for an item whose nonce I already sent".

c. **Nonces sent + `round_abort` → Aborted** (line 106) against **"once a member has sent partial signatures, no message moves it to Aborted"** (line 112). In tier 2 or later the member is in "Nonces sent" having already released tier 1's partial signatures. The table sends it to Aborted, which erases its view of what tier 1 exposed.

d. **Item indices are not said to be unique across tiers**, and a nonce is signed over (round, item, nonce) only (line 60). If an implementation numbers items per tier, the member signs two different nonces for (R, 3), one in tier 1 and one in tier 2. That is exactly the evidence section 9 accepts as proof of equivocation. An honest member is framed by its own protocol. [R]

**Change.** State the rule per (round, tier, item): "a party never sends two different nonces, or two partial signatures, for one (round, item)", with item indices unique within a round and the tier inside the signed nonce message. Track member state per tier. Aborted is reachable only if no partial signature was ever sent in the round; otherwise the round is Unfinished with the exposure recorded. Replace (b) with "for an item whose nonce was sent before a restart, the party answers only `round_abort` for that item; saved messages are resent byte for byte".

#### N8. The named nonce function reads the operating system itself and cannot take the core's randomness; the message safeguard is available today without it

Concerns: RD section 8 (lines 122–123, 127), section 13 (line 196); `DESIGN.md` section 3 (L0–L3 have "no system calls") and section 4 ("Randomness and time are handed to the core").

- `musig_generate_nonce` draws its session identifier from a private `fill_random`, which opens `/dev/urandom` [C: `src/musig.c:9-15`, `:463-480`]. It takes no randomness argument. So the core cannot be "handed its randomness" for nonces, the simulator cannot be seeded through it, the "seeded source only in simulator builds" rule (line 123) has nothing to attach to, and the function fails outright on a system with no `/dev/urandom`, which includes the native Windows build tracked after Slice 1 (`docs/SLICES.md`).
- RD line 127 says binding the nonce to the message and an extra input "is not available through it today" and has been requested from SuperScalar. That is true of `musig_generate_nonce`. But the engine can call `secp256k1_musig_nonce_gen` from the pinned library directly, passing a session identifier from the randomness port, the message and an extra input. The import itself does exactly this elsewhere [C: `src/musig.c:75-77` passes `msg32`; `:198-201` passes `extra_input`]. No imported file needs editing.

**Change.** Section 13: "Generate a nonce: the engine's own function, which calls `secp256k1_musig_nonce_gen` with 32 bytes from the randomness port, the secret key, the public key, the key-aggregation cache, the item's signature digest and the extra input (round identifier ‖ item index)". In release builds the randomness port reads the OS at the moment of use. State that `musig_generate_nonce` and the import's nonce pool are not used. BIP 327 calls the optional inputs "a last resort" [S]; keep that wording.

#### N9. Channel states inside round tiers conflict with the standard taproot channel format

Concerns: RD section 5 (creation, leaf change, layer update), section 8; SR C6 (line 53), C7; `docs/research/channel-groundwork.md` 1.1, Part 3 §4 and §7, Part 4 decisions 5 and 9.

The tiers put "the first channel states" (creation) and "channel states on the new output for both sides" (leaf change, layer update) inside the round. C6 requires that the member "holds and has verified the final signatures of the tier below".

In the standard taproot channel format, which is the decided format (`KNOWLEDGE-BASE.md` section 5), a party never holds a final signature on its own commitment before it broadcasts it. It holds the peer's partial signature and signing nonce, and produces its own partial signature at broadcast with its *verification* nonce. That nonce must be reproducible weeks later, so the groundwork recommends deriving it from the channel seed, commitment number and funding txid [C: `docs/research/channel-groundwork.md` lines 75–77 and 693]. RD section 8 forbids exactly that for anything the round engine signs ("never produced by a generator whose state is saved or can be restored"; "rebuilding ... never recreates a secret nonce"). The groundwork also recommends opening with the standard opening messages rather than inside the creation round (its decision 9), and H9 (SR line 162) speaks of a separate "first channel exchange".

**Change.** Say that channel commitments are signed by the channel engine under the channel format's own nonce rules, outside the round's nonce rules. Say that the round engine waits for the channel engine's "commitment stored for the new outpoint" before releasing the tier that creates that outpoint. Define "holds" for a commitment as "holds the peer's verified partial signature and can complete its own". Choose one place for the first channel exchange: the creation round, or the standard opening messages after `round_complete` and before funding.

#### N10. In a layer update the round identifier would require every member to rebuild every other member's channel states

Concerns: RD section 3 (line 45), section 5 "Layer update" (line 81), section 11 (line 172).

The identifier hashes "for every item: index, output spent, signature digest ...". A layer update's first tier is "channel states on every new channel output". So member A would compute the digests of member B's commitment transactions. A cannot: it lacks B's per-commitment points, HTLCs and balance. If the host supplied them, every member under the node would learn every other member's balance, a privacy cost no document states. Section 11 already has members download only their own items' data. [R]

**Change.** Bind the tree items, which everyone can rebuild, into the identifier directly. Bind each member's private items (its channel states) by a per-member digest that only that member and the host check, or keep channel states out of the round altogether (N9).

### Medium

#### N11. Owner decision 1 (frozen terms, two digests) is not bound as decided

Concerns: RD section 3 (line 41); SR C8; `docs/ux/decisions.md` decision 1 (lines 9–12).

The owner decided on two digests: the outer rules, and the current values (with a version number and including the outer digest), frozen at the ready check. A member's limits are compared with the whole range by default. RD's identifier has one "digest of the host's signed terms". Neither specification:

- says which digest is meant. It should be the current-values digest, which commits to the outer one;
- requires the member to check that the proposal's parameters equal the frozen current values named in its own ready message;
- says whether values may move between attempts under the time budget, where each attempt has its own ready check (RD line 169). The decision says nothing moves after the freeze.

**Change.** Identifier: outer digest and current-values digest, both. Add a check C8a: "every proposal parameter equals the frozen current value, and the current-values digest equals the one in my ready message". Add: "attempts within one round's time budget reuse the frozen values".

#### N12. C5 as written refuses every production tree and misses today's competing spender on the funding output

Concerns: SR C5 (line 51), section 6 item 7.

- C5 lists the recognised ways to spend an output (everyone signs; host after a height; host after a delay; member alone; behind a hash) and says "A way it does not recognise fails the check". Every tree transaction with anchors on carries a keyless pay-to-anchor output that anyone can spend [C: `src/factory.c:498-507`, appended at `:1742`, `:1768`, `:1876`, `:1325`]. So does the distribution transaction [C: `src/factory.c:4451-4458`]. C5 refuses them.
- C5 says the payout lock time is the binding moment "after the planned end-date payouts". A funding-level payout already exists in the import: the distribution transaction, a pre-signed key-path spend of the funding output locked to a chosen height, co-signed by every participant in the creation ceremony [C: `factory.h:471-486`, `:1240-1256`; `src/factory.c:4430-4624`]. Once its lock passes, anyone can publish it and kill the root kickoff.
- The import's distribution outputs are chosen by the caller. The "balanced" variant pays each member its channel balance, which is zero at creation [C: `factory.h:1268-1279`]. A member would sign it at creation (owed zero, so C4(a) holds), and then C4 would correctly refuse every later payment once exit time reaches its lock. That fails safe, but it makes the factory useless.

**Change.** Add "anyone, for the anchor value only" to C5's recognised ways, valued at zero. Say that C5's competing claims include every exposed pre-signed transaction with a lock time, from C4. Add to C8 a bound on the distribution transaction: lock time no earlier than the end date, and the member's share at least its channel capacity.

#### N13. Hazards in the imported code that RD section 12 does not list, and a guard that does not work

Concerns: RD sections 12 and 13. Each item [C]:

1. **Partial signatures double-count too.** `factory_session_set_partial_sig` and `factory_session_set_partial_sig_dist` increment a counter with no slot tracking [`src/factory.c:2066-2076`, `:4606-4612`], exactly like nonces. A repeated `round_partial_sigs` can make `complete` aggregate over an unset slot. In libsecp256k1 an unset structure fails its argument check, which aborts the process by default. That last point is from memory, not checked today. Same guard as for nonces.
2. **The timelock-counter overflow happens inside initialisation.** `factory_init_from_pubkeys` computes the layer count for a two-way tree and calls `dw_counter_init`, which writes `layers[i]` for every `i < n_layers` with no bound [`src/factory.c:880-884`; `src/dw_state.c:36-46`]. The array holds 8 [`dw_state.h:38-41`]. At 257 or more members `n_layers` is 9 and `layers[8]` overwrites the counter's own `n_layers`, `total_states` and `current_epoch`. RD's guard "set the shape immediately after initialising" (line 188) only overwrites the damage afterwards; it cannot prevent the out-of-bounds write. Ask SuperScalar to bound it. It is undefined behaviour, which a bounds sanitiser in CI may report.
3. **The member's copy ignores the host's spare-liquidity hash for node index ≥ 512.** The check uses the compile-time `FACTORY_MAX_NODES` (512), not the grown array [`src/factory.c:393`]. The member then builds a one-leaf spare-liquidity script while the host builds two, so the trees diverge in any tree with more than 512 nodes (about 128 members and up). Review 1 F11 reported this; it is still in the import.
4. **Re-initialising a node session leaks.** `factory_session_init_node` does not free a live large session first [`src/factory.c:3109-3116`]. `factory_sessions_init` does [`:2036`]. Each retry on one tree object leaks per node with more than 8 signers.
5. **`factory_set_level_arity` with `n = 0`** reads `arities[-1]` [`src/factory.c:1176`]. The engine must never call it with an empty list.
6. **Placement has no setter.** The default, set inside init, is the timezone sort over profiles that are all zero [`src/factory.c:831`, `:889`, `:869`, `:1970-1973`]. The comparator returns 0 for every pair, so the order is whatever the C library's `qsort` does. The engine must write `placement_mode = PLACEMENT_SEQUENTIAL` itself; RD should say so.
7. **Section 13 maps only the plain node session.** The tiers also need the distribution session (`factory_session_*_dist`, `factory.h:1251-1256`), the penalty session on a script path (`factory_session_*_poison`, `factory.h:942-950`), and for K > 1 the per-input sessions (`factory_session_*_input`, `factory.h:893-901`). Each node also holds a second, independent penalty session [`factory.h:186-196`], so the RD line 203 statement "one signing session per tree node" is true per kind of signature, not per node.
8. **`factory_session_complete_node` does not verify the final signature** [`src/factory.c:3139-3158`]. RD section 13's last row already requires a standard check. It is correct; this is noted only so nobody drops that check.

#### N14. Pausing and "keeping both anchors current" contradict each other, and a withholding host can freeze a member out of every future round

Concerns: SR section 4 rules 4 and 5 (lines 83–84), C9, C10 (line 61); RD sections 7 and 10 (line 165).

Rule 4 forbids payment updates while a round touching the anchor is unresolved. Rule 5, and RD line 165, say an Unfinished member "keeps both anchors current". But while the round is unresolved nothing may change, so there is nothing to keep current. The real options are to wait, paused, with no end, or to exit.

Combined with C10 (one unresolved round per output) and RD line 112 (only a valid result or evidence on chain resolves the round): a host that withholds a result, or one that crashed and lost its own secret nonce, so that the round can never be completed, leaves the member paused and unable to take part in any later round on those outputs. That includes rotation by closing into a new factory, which touches the funding output. The member's only remedy is a unilateral exit with its fees and timelocks. That is reasonable, but it is not stated, and SR section 10 lists only "being ignored". [R]

**Change.** Delete "keeps both anchors current" from SR rule 5 and RD line 165. Say: "an Unfinished member stays paused; if the round is not completed within a stated time, it exits". Add "a withheld or lost round result" to SR section 10. Note the option, in two-party tiers, of the host sending its own partial signature with `round_all_nonces`, so that the member always completes first and the host, which is online, carries the Unfinished state instead. That is a design choice for the owner, and BIP 327 does not forbid it.

#### N15. Parts of the fault table and evidence are stated more strongly than they hold

Concerns: RD section 9 (lines 138, 141, 143), section 4 (line 61).

- "A member names a nonce set that never existed → the member cannot open its digest → Yes." That a party *cannot* open a digest is shown only by challenging it and getting no answer. A third party holding static evidence sees an unopened digest, not proof that it never existed. This needs an interactive challenge with a deadline, which is a claim against the member, not proof.
- "A proposal that fails the checks → host's signature on the proposal → Yes." That holds only for checks anyone can evaluate (duplicate keys, malformed values, a timeout already past at a stated height). It does not hold for a member's own private limits under C8, which a third party cannot see. Such a refusal is the member's choice, not the host's fault.
- The evidence for "a member sent a bad partial signature" (line 138) must include the round identifier's preimage, so that the verifier gets the item's signature digest and tweak, or leaf, for the session. Otherwise it must rebuild the tree. The table lists keys and mode but not the digest or the preimage.
- `round_all_nonces` is "signed by carried signatures" only (line 61). A member that receives a malformed set cannot show the host sent it. That is consistent with "the host can assert silence", but should be said.

#### N16. A factory that is never funded leaves records that can never be discarded

Concerns: SR C4(d) (line 49), C7 ("a record leaves the exposed set only by C4(d)"), C10.

If the host never funds, the funding outpoint never exists. C4(d) needs "an input it spends has been spent by a different transaction that is buried". The member is given the outpoint, not the host's funding transaction, so it cannot see the funding inputs being spent elsewhere. The records and the C10 lock stay for ever. Harmless for money, but storage grows and the state is undefined.

**Change.** Have the host send the unsigned funding transaction in `round_complete` (the member already needs its txid). The member then discards the records when any funding input is spent by another buried transaction. Add a member-side timeout after which an unfunded creation is marked abandoned, with the records kept but no longer blocking.

#### N17. The contribution key: a contradiction, a code fact, and a privacy cost

Concerns: RD section 2 (lines 28–29), open point 2; owner decision "identity is new per lobby by default" (`KNOWLEDGE-BASE.md` section 5).

- RD line 28: the factory key "signs nothing but group-signature items". Line 29: the contribution key is bound "with one statement signed by the factory key". Those two cannot both hold.
- The import pays the distribution transaction to P2TR of each participant's factory key [C: `factory.h:1258-1261`] and the spare-liquidity penalty to P2TR of each member's factory key [C: `factory.h:536-541`]. So the factory key will later sign ordinary single-signer spends. Separation by key is not what the import does.
- If the contribution key is "the key that authenticates the member's connection" (the Lightning node key), the binding statement links every per-lobby factory key to one long-lived node key. Any evidence published under section 9 then shows that link to third parties. That defeats "identity new per lobby".
- Two seats could bind the same contribution key. The host should refuse duplicates, and the binding should be two-way (the contribution key also signs the factory key) so that no seat can claim another party's key.

**Change.** Derive a contribution key per lobby. Bind both ways. Refuse duplicates. Correct line 28 to "signs only group-signature items and the one binding statement, with distinct tags". Ask SuperScalar for payout destinations that are not the factory key; this fits owner decision 6, "a destination per member".

#### N18. "Nonces at the ready check" cannot coexist with the round identifier

Concerns: RD section 11 (line 170), section 3 (line 50), section 4 (line 60).

A nonce is signed over (round, item, nonce), and the identifier is saved before the first contribution. At the ready check there is no proposal, hence no identifier and no item digests. Nonces made then cannot be bound to a round, and the restart protection has nothing to key on. BIP 327 allows early nonces "with care" and says they are "not compatible with the defense-in-depth mechanism" [S]. The option needs its own identifier, for example a pre-round identifier fixed by the ready check, with its own refusal record. As written it is incompatible. It is off by default, which is right.

#### N19. Findings of the SuperScalar payout review that these specifications should carry

Concerns: SR section 9; `SuperScalar-SPEC-end-date-payout-REVIEW.md` 3.3a, 3.6, 4.2.

- **HTLC count against the version-3 size limit** (that review's 3.3a). A member can make the host's commitment unrelayable by filling it with small HTLCs and then going silent; under payouts it is then paid full capacity. No H rule caps non-dust HTLCs per commitment. Add H10: "the host refuses an HTLC that would take its commitment beyond the relay size limit".
- **Commitments on superseded outpoints** (3.6). SR section 4 rules 1 to 3 answer it, provided N3's correction is made and rule 2's retired anchor is known to be settled by the penalty. The imported chain transactions after the first carry no anchor [C: `src/factory.c:2777-2779`, one output and no `factory_append_tree_anchor` call], so "the member can publish it as soon as the previous one confirms" (SR line 81) depends on the built-in fee. Say so under C3.
- **Rotation order** (4.2). SR's "rotation by closing into the new factory" orders the new tree before the close, and the close itself creates the new funding output, so the double window that review describes does not arise. Good. Partial rotation (some members not rotating) is not covered by "closing into", which needs every signer of the old root. Say that it falls back to paying across.

#### N20. TESTING invariant 3 contradicts SR section 4 rule 1 and C7

`docs/TESTING.md:41`: "No party signs two different states with the same number." SR rule 1 requires exactly that, the same number on every live anchor, and C7 allows two closes. Review 1 flagged this as a Low item; it has not been changed. A test written to the invariant will fail the specification. [C]

### Low

- **L1.** SR C12 refers to "the defined recovery close or exit". No document defines a recovery close.
- **L2.** A withheld cooperative close puts a close permanently in the exposed set, so by C13 the member refuses all further payments on that channel and must exit. This is a cheap lever for a host. Add it to SR section 10.
- **L3.** H1 should also require that the host's funding transaction spends only segwit inputs and that its txid is fixed before the round. Otherwise the tree can be invalidated by malleation. That is the host's own risk, plus wasted rounds for members.
- **L4.** SR open point 4 can be settled from the import: deeper nodes expire *earlier*, by 5 blocks per tree transaction (`TIMEOUT_STEP_BLOCKS 5`), and the root kickoff has no timeout [C: `src/factory.c:1475`, `:1636-1644`]. The binding host timeout on a path is the leaf state's, which also guards the channel output [C: `:1314-1316` uses the leaf's own script].
- **L5.** SR section 7 says the imported delay functions under-report. Confirmed: `factory_early_warning_time` sums `step × (states − 1)` per layer, then subtracts one whole layer whenever any leaf is pseudo-Spilman, although pseudo-Spilman leaves have no layer of their own [C: `src/factory.c:4900-4927`]. It also has no confirmation allowance.
- **L6.** Documents still say "about two weeks" without qualification (`KNOWLEDGE-BASE.md` section 5; `DESIGN.md` section 6) and "a small on-chain reserve is recommended" (`DESIGN.md` section 6), against owner decision 6. These are not the specifications, but they are what newcomers read.
- **L7.** SR section 10 omits "a chain reorganisation that changes which leaf link confirmed", from review 1 F15.
- **L8.** RD section 8 could mention that BIP 327 allows a deterministic nonce for a unique last signer, which the host is [S]. That would let the host avoid storing secret nonces across a crash. Optional.

### What draft 2 gets right (so that it is kept)

- Each member signs its nonces over a round identifier it computed itself from its own rebuilt transactions. A member whose tree differs from another's is therefore caught at step 5, before any partial signature, because the other signers' nonce signatures fail against its identifier. [R] That is a good property and should be stated as one.
- Children-before-parents tiers, and "every signer can complete the last tier of a layer update", close review 1's F4 and the SuperScalar review's phase-B concern (3.3b) for later rounds. H1 covers creation.
- The fault table's "Limits, stated plainly" are accurate, including the host with a seat of its own and the warning that a valid partial signature proves nothing.
- The arithmetic checks: 0.99^512 ≈ 0.0058, about one attempt in 172 (RD says about one in 170). 513 × (66 + 64) = 66,690 bytes, more than one 65,535-byte message.

---

## 3. Status of review 1's findings

Three statuses: **Resolved**; **Resolved, with a residual** (the text answers the finding, and a gap or contradiction remains, listed here); **Partly resolved** (part of the finding is still open). None is unresolved.

| | Finding | Status | Residual or gap |
|---|---|---|---|
| F1 | Rule looks at held, adversary uses signed | Resolved, with a residual | Exposed set, adversary, one-tree rule, activation rule and C13 are all in. A restore from an old backup reopens two trees on one outpoint for factories created after the backup (N1) |
| F2 | Commitments when the tree changes | Partly resolved | Section 4 exists and rules 1–3 are right. The leaf-change model contradicts owner decision 5 (N2); rule 4 contradicts rule 5 (N14); channel-format nonces are not reconciled (N9); rule 3 undercuts section 8 (N3) |
| F3 | Timed layers outraced, not cancelled | Resolved, with a residual | Split of C4, maximum safe absence, deterrent not counted and race fee are all in. Overstated given rule 3, and the race fee collides with owner decision 6 (N3) |
| F4 | C6 against the message flow | Resolved, with a residual | Tiers added. "Final signatures" undefined for channel states (N9); the state table is not per tier (N7c) |
| F5 | Restart frame; identifier under-defined | Resolved, with a residual | Identifier defined and saved before first contribution; proposal and result signed. Tier wording (N7a, b), item indices across tiers (N7d), one terms digest instead of two (N11), framing after restore (N1) |
| F6 | Randomness, journal, stored nonces | Partly resolved | Rules written. The named function reads `/dev/urandom` itself and cannot take the core's randomness; the message binding is available today through the library (N8) |
| F7 | C7 too weak and too strict | Partly resolved | Weak side fixed by the exposed set and C12, except restore (N1). Strict side: creation retries still blocked unless the outpoint changes, which is unstated (N6) |
| F8 | Free, silent or hostile members | Resolved | H3, H5, H6, H7 and H9 added; deposit raised as owner point 2. The HTLC-count gap is new and comes from the SuperScalar review (N19) |
| F9 | Overlapping rounds | Resolved | C10, H8, RD section 7. Liveness cost of a permanent Unfinished round in N14 |
| F10 | What proof of fault shows | Resolved, with a residual | Table and limits written; digest opening and separate key added. Two rows overstated and evidence incomplete (N15); contribution key contradiction and privacy (N17) |
| F11 | Host-supplied numbers | Resolved, with a residual | C5 from scripts, C8 member ranges, hash used once. C5 refuses anchors (N12); C8 list incomplete (N5); hash ignored at node ≥ 512 still in the import (N13.3) |
| F12 | Definitions of owed, exit value, exit time | Resolved | Every bullet addressed; the confirmation allowance stays an open number, honestly marked |
| F13 | Scale | Resolved | Time budget, splittable data, signature per (round, item, nonce), sizes, lighter variant |
| F14 | Imported hazards | Resolved, with a residual | All five listed hazards guarded. New ones: partial-signature double count, overflow inside init, unmapped session kinds (N13) |
| F15 | Missing limits | Resolved, with a residual | All but one added; reorganisation of a leaf link omitted (L7) |

**Counts: Resolved 4 (F8, F9, F12, F13); Resolved, with a residual 8 (F1, F3, F4, F5, F10, F11, F14, F15); Partly resolved 3 (F2, F6, F7); Unresolved 0.**

Review 1's Low items: a second `round_all_nonces` rejected (RD line 69), resend of saved bytes (line 70), `round_complete` carrying payouts and penalties (line 64), deadlines on own clock (line 171): all done. TESTING invariant 3: not done (N20).

---

## 4. Claims checked

### 4.1 Against the imported code

| Claim | Where made | Result | Evidence |
|---|---|---|---|
| `musig_generate_nonce` uses fresh randomness, the secret key, the public key and key-aggregation data, and takes no message or extra input | RD line 127 | **Correct.** The randomness is read inside, from `/dev/urandom` (N8) | `src/musig.c:463-480`, `:9-15` |
| Setting a signer's nonce twice counts twice | RD line 181 | Correct. The same holds for partial signatures (N13.1) | `src/musig.c:307-321`; `src/factory.c:2066-2076`, `:4606-4612` |
| Bad input to the library can stop the program | RD line 182 | Parse functions return 0 [C: `src/musig.c:246-268`]. Abort on an invalid structure passed to a session function is libsecp256k1 behaviour, not checked today | — |
| Duplicate participant keys are accepted | RD line 183 | Correct: passed straight to aggregation | `src/musig.c:17-36` |
| A routine exists for a hash type that lets inputs be added | RD line 184 | Correct (`ANYONECANPAY|ALL`, key path) | `src/tapscript.c:663-680` |
| The penalty is signed on a script path under the untweaked group key | RD line 185 | Correct | `musig.h:186-195`; `src/musig.c:374-406` |
| Partial signatures are never verified | RD line 186 | Correct for the session helpers; the verifier exists | `src/factory.c:2066-2076`, `:3139-3158`; `src/musig.c:423-436` |
| Member order can depend on the C library's sort | RD line 187 | Correct: default is the timezone sort over zero profiles. No setter for sequential placement (N13.6) | `src/factory.c:831`, `:889`, `:1970-1973` |
| The timelock counter is overwritten from 257 members until the shape is set | RD line 188 | **Correct about the threshold; the guard is insufficient.** The write is out of bounds inside init (N13.2) | `src/factory.c:880-884`; `src/dw_state.c:36-46`; `dw_state.h:38-41`; `:1492-1499` |
| One signing session per tree node | RD line 203 | Correct for the main signature. Each node also has a penalty session; the factory has a distribution session | `factory.h:173-175`, `:186-196`, `:482-484` |
| Functions in RD section 13 exist | RD lines 194–200 | Correct: `factory_init_from_pubkeys` `src/factory.c:853`, `factory_set_arity` `:903`, `factory_set_level_arity` `:1164`, `factory_set_funding` `:1214`, `factory_build_tree` `:1882`, `factory_session_init_node` `:3109`, `factory_session_set_nonce` `:2043`, `factory_session_finalize_node` `:3118`, `factory_session_set_partial_sig` `:2066`, `factory_session_complete_node` `:3139`, `musig_create_partial_sig` `src/musig.c:408`, `musig_verify_partial_sig` `:423`. Section 13 omits the distribution, penalty and per-input variants (N13.7) | as listed |
| Today the competing claim is each node's host-only timeout | SR line 51 | Correct for tree outputs and the channel output. Incomplete: the distribution transaction on the funding output already exists (N12) | `src/factory.c:199-214`, `:1314-1316`, `:4430-4624` |
| A liquidity change adds a leaf transaction spending the previous one's channel output | SR line 75 | Correct for the import at K = 1; adds no liquidity. Not the shape decided for 1.1.0 (N2) | `src/factory.c:2769-2782` |
| A step is 144 blocks at the settings used so far; the newest state confirms one step before the next older | SR line 126 | The formula is correct (`step × (states − 1 − index)`). 144 is a setting, not in the code | `src/dw_state.c:9-12` |
| The imported delay functions under-report on deep trees | SR line 118 | Correct (L5) | `src/factory.c:4900-4927` |
| The funding script depends only on the aggregate key (review 1, used by C7) | SR C7 | The import takes the funding script from the caller and never checks it; the root kickoff has no timeout, so the expected script is the BIP 86 key of the ordered aggregate. The engine must check it (N5) | `src/factory.c:1214-1228`, `:1636-1638`, `:97-118` |

### 4.2 Against BIP 327

| Claim | Where made | Result |
|---|---|---|
| A secret nonce must never sign twice; two signatures can reveal the key | RD line 120 | Correct: "must not be executed twice with the same secnonce ... possible to extract the secret signing key from the two partial signatures" [S] |
| Nonces must not be derived deterministically from the session parameters | RD line 120 | Correct, and the reason given in the BIP is that active adversaries can trick the victim into reusing a nonce [S]. BIP 327 does allow a deterministic nonce for a unique last signer (L8) |
| Binding the nonce to the message is an optional safeguard; the extra input can carry the round identifier | RD line 127 | Correct in substance. The BIP calls the optional inputs a defence-in-depth mechanism to be "viewed as a last resort" and gives a session identifier as an example of extra input [S] |
| Signing needs only the combined nonce; individual nonces are needed to verify partial signatures | RD line 126 | Correct [S] |
| Three conditions for identifying a disruptive signer | RD line 132 | Correct and complete: untampered contributions, honest nonce aggregation, and every partial signature verified with PartialSigVerify [S] |
| Whoever combines could otherwise blame an honest signer | RD line 132 | Correct: a malicious aggregator can "wrongly hold honest signers accountable" [S] |
| The BIP does not address convincing a third party | RD line 132 | Correct as far as I could find [S] |
| Partial signatures are not signatures | RD line 151 | Correct, verbatim [S] |
| Nonces may be generated early with care | RD line 170 | Correct: such applications "must therefore be even more careful not to reuse them", and the method is incompatible with the defence-in-depth inputs [S]. Incompatible with RD's identifier rules (N18) |
| Duplicate keys may be refused | SR C1, RD line 32 | Permitted: "applications may reject duplicate individual public keys" [S] |

---

## 5. Slice 1: what it needs from these specifications

Slice 1 (`docs/SLICES.md`): one host and at least three members, on separate processes on signet, form a factory; the host funds last; the funding confirms; a member whose conditions are not met refuses. No payments, liquidity changes, rotation, exits, the host's Lightning node or Nostr.

**From `safety-rule.md`:**

| Part | Needed | Note |
|---|---|---|
| Section 2 terms, held set, exposed set | Yes | The exposed-set store must be real and durable from the start, even though nothing is owed |
| C1 rebuilt, not received | Yes | Including the duplicate-key refusal and the funding-script check (N5) |
| C2 own outputs by own keys | Yes | Identify the member's leaf and the distribution output, if the distribution transaction is signed |
| C3, C4 | Degenerate | Owed is zero, so both pass. Implement the record of which branch applies, so the code is not rewritten in Slice 2 |
| C5 | Yes, reduced | Enumerate scripts, including anchors (N12). The real test is C8's "timeout already past or too close" |
| C6 | Single tier | — |
| C7 | Yes | One tree per funding output, recorded before the first partial signature (N6) |
| C8 | Yes | This is the "a member whose conditions are not met refuses" test. Needs the full parameter list (N5) and the frozen-terms check (N11) |
| C9, C13 | No | No channels or payments |
| C10 | Yes | One open round per output |
| C11 | Yes | Buried funding, exact amount and script, through the chain port comparing two servers |
| C12 | Yes | With N1's change, because the journal will be restored in tests |
| Sections 4, 6, 7, 8 | No | Except the exit-time sum if C8's "closer than exit time" is enforced; it may use the summed timelocks only |
| H1, H2, H8 | Yes | H1 needs `round_ack` (N4) |
| H3–H7, H9 | No | No credit and no channels |
| Section 11 tests | For C1, C2, C7, C8, C10, C11, C12, H1, H2, H8 | Including the attack "two trees on one funding output" |

**From `signing-round.md`:** sections 1 to 4 (with N4's messages and N5's parameter table); section 5, creation only, *without* channel states (N9: Slice 1 has no channel engine, so define a "creation, tree only" profile); sections 6 and 7 (with N7's fixes); section 8 (with N8's nonce function); section 9 only as far as naming who failed, to remove them; section 10, creation only; section 11 time budget (simple form, with N6's new outpoint per attempt); sections 12 and 13 (with N13); tests 1–5, 7 and 9 of section 14 for creation.

**Not yet decided, and needed for Slice 1:**

1. Whether the creation round signs the distribution transaction. If it does, its outputs and lock time are proposal parameters with C8 bounds (N12).
2. **How the host gets its signet coins back.** Slice 1 has no close and no exit. With the import's host-only timeouts the host must publish the whole tree, at fees, after the end height. If the distribution transaction pays members their capacity, the host loses that at its lock time. Given the owner's wish to preserve test coins (0.1 sat/vB), either include a one-tier cooperative close round in Slice 1, or set a short end height and accept publishing the tree, or do not sign the distribution transaction in Slice 1.
3. The encoding of the proposal and the messages (RD open point 3). Slice 1 can use a provisional encoding if it is written down as such.
4. The member's depth for "buried" and the chain view's comparison rule (`docs/CHAIN-SERVERS.md`), which C11 depends on.
5. The lobby's ready check and frozen values (owner decision 1), because C8's test runs against them.

---

## 6. Requirements on parts not yet designed, added by this review

- **Channel engine:** signs its own commitments under the taproot format's nonce rules; tells the round engine "commitment on the new outpoint stored" (N9). Takes part in a pause that ends only by round completion or exit (N14). Caps HTLCs by the commitment's relay size (N19).
- **Storage:** round state per (round, tier) (N7); the received signed nonce sets, kept for evidence; the funding transaction for creation (N16); the key-derivation offset after restore (N1).
- **Lifecycle engine:** a new funding outpoint per attempt after partial signatures (N6); terms frozen across attempts (N11); abandonment of unfunded creations (N16).
- **Randomness port:** the only source for nonce session identifiers; operating system at the moment of use in release builds (N8).

---

## 7. Sources

- BIP 327: <https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki>, fetched 2026-11-11 through an automated reader that returned quoted passages. I relied on those quotes, not on a word-for-word reading of the whole page.
- Imported code at pinned commit `e65739500bbbbb53bc142ad68add40509238264c` (`core/superscalar/IMPORT.md`).

---

## 8. Threat model (draft)

Scope: a member and a host running Gazpacho as these specifications and `DESIGN.md` describe them, in 1.0.0 (one member per leaf, no sales, signet). "Defended by" names the rule; "Not defended" is what the specifications and design accept or have not addressed. This draft is what the specifications support. It is not a statement that the defences work, which needs the tests in SR section 11 and RD section 14.

### 8.1 Assets

| Asset | Owner | Why it matters |
|---|---|---|
| Channel balance, and payments in flight | Member | The money. Must be claimable alone, in time |
| Factory key, contribution key, channel keys, wallet seed | Member, host | Theft of these is theft of the money or of the right to sign |
| Secret nonces | Every signer | Reuse reveals the factory key |
| Held set and exposed set | Member | Losing the exposed set is as bad as losing the transactions (SR section 10) |
| Round records (identifiers, sent bytes, received nonce sets) | Every signer | Protect against framing; needed for evidence |
| Funding capital and spare liquidity | Host | The host funds everything |
| Host's long-term key and reputation | Host | Signs terms, proposals and results; the target of valuable fault proofs |
| Payment preimages | Member | Release before the payment is irrevocably committed loses the payment |
| Ability to act in time (online, a true chain view, fees) | Member | Deadlines under C5 and the response windows under C4 |
| Privacy: membership, balances, network addresses, links between per-lobby identities | Member | The host sees much by design; others should not |

### 8.2 Parties, what each can do, what defends, what does not

#### Host (coordinator, co-signer of everything, funder, relay of all messages, keeper of members' backups)

Can: choose the participants and their order, the parameters within its terms, and the timing; withhold, delay, reorder or alter any relayed message; pick its nonce after seeing all others; run several rounds; hold seats of its own; withhold results; publish any transaction in a member's exposed set; refuse service; return any backup version it holds; see every payment.

| Attack | Defended by | Not defended / gap |
|---|---|---|
| Publish a transaction the member signed but does not hold | Exposed set; C3 and C4 drawn from it (SR section 2) | — |
| Two trees on one funding output | C7; C11 | After a restore from an old backup (N1) |
| Make the member sign an output before it holds its exit from it | C6 tiers | Channel states in tiers undefined (N9) |
| Stale channel state on an old anchor | SR section 4 rules 1–3; H4 | — |
| Old layer state against an absent member | Rule 3 (old anchors current); C4(c) | Correct classification depends on N3 |
| Host-only timeout before the member can leave | C5 | C5 refuses anchors as written (N12) |
| Insert an unknown spending path, or a bad parameter | C1, C2, C5, C8 | C8 list incomplete (N5) |
| Distribution transaction that pays the member less than owed | C4 | No C8 bound, so the factory may be useless (N12) |
| Credit given on an unconfirmed factory, then the funding double-spent | C11; H3 | — |
| Overlapping rounds | C10; H8 | — |
| Withheld cooperative close, published later | C7; C13 | The member must then exit (L2) |
| Withheld round result | RD line 112; SR section 4 rule 5 | Freezes the member out of further rounds; only remedy is exit (N14) |
| Learn the member's key through nonce reuse | RD section 8; save-before-first-contribution | Replay after a restore from an old backup (N1); copies of a running program (accepted, SR section 10) |
| Frame an honest member | Signed nonces; saved identifiers; named nonce-set digest | Restore (N1); item indices across tiers (N7d) |
| Escape blame for a round it broke | Fault table when it equivocates under its own key | A host with a seat of its own (accepted, RD section 9) |
| Assert that a member was silent | Recorded as the host's claim only | Unprovable either way (accepted) |
| Return an old backup | C12 | Only for factories that existed at the backup's date (N1) |
| Choose who is in a factory by delaying messages | — | Denial of service; accepted (RD line 171) |
| Refuse service | Leaving | Accepted |
| Observe payments, membership, network addresses | — | Accepted (SR section 10) |

#### A member (from the host's side)

Can: join free under a fresh identity; answer late or not at all; send malformed or invalid data; exit alone at any time; route small HTLCs to itself through the host; withhold its partial signature.

| Attack | Defended by | Not defended / gap |
|---|---|---|
| Spoil a round anonymously | H2; time budget; removal | Silence is unprovable; costs an attempt only |
| Free seat that stays silent, then collects at the end date | H6, H9; owner point 2 (deposit) | No cost per seat in 1.0.0 |
| Make the host pay unbounded fees | H6, H7 | Fee size set by market conditions |
| Make the host's commitment unrelayable with many HTLCs | — | Not defended (N19) |
| Old channel state against the host | Channel revocation; H4 | Channel engine not yet specified |
| Old layer state | The newer state wins within one step if the host watches | The host's duty to respond is not named |
| Exit on day one to disturb others | — | Accepted; costs the host fees |

#### Other members of the same factory

Can collude with each other and with the host. The host colluding with all other members is exactly the adversary of SR section 2, so every host row above applies. Without the host they cannot sign for a third member, because every output needs every signer below it (BIP 327 unforgeability [S]), and they cannot frame a third member, because contributions are signed by their authors [R]. Under the per-identifier rules they learn the item keys of shared nodes, hence who else is in their branch. In a layer update as written they would learn each other's channel states (N10).

#### Chain servers (public Electrum-style or HTTP explorer servers; the user's own server)

Can: hide a transaction; delay a broadcast; refuse package submission; report false fee rates; report stale tips. They cannot invent a confirmation if headers are checked (`DESIGN.md` section 10).

| Attack | Defended by | Not defended / gap |
|---|---|---|
| Fake confirmation of the funding | Header checks; two servers compared (`DESIGN.md` 10; Slice 1 chain port) | — |
| Hide a kickoff or an old state | Several sources; maximum safe absence shown to the user (SR section 7) | Beyond the safe absence: accepted (SR section 10) |
| Hide or delay the member's own broadcast | Several servers | Package submission not available on the public Electrum servers found (`docs/research/channel-groundwork.md` 1.9) |
| False fee rates, so the member underpays | — | Not addressed |

#### Nostr relays (listings and host proofs only; not in Slice 1)

Can: withhold listings; serve an older signed version of a host's terms; observe who queries. They cannot forge a host's signature. An old terms version leads at worst to a ready message that names digests the host does not accept, so the round does not start (owner decision 1). Censorship and metadata are not defended.

#### Network observers (between member and host)

Can: see that a device talks to a host and when rounds happen; drop, delay, replay and reorder packets. They cannot read or forge inside the encrypted transport (`DESIGN.md` section 8). A replay of a round message is answered from saved bytes or refused by the saved identifier (RD sections 3 and 4). Delaying chosen members pushes them out of an attempt (accepted). Membership and timing are visible (not defended).

#### A stolen or copied device

| Case | Defended by | Not defended |
|---|---|---|
| Stolen, locked | Journal encrypted at rest (`DESIGN.md` 9) | Strength of the device lock and the passphrase is outside these specifications |
| Stolen, unlocked, or keys extracted | — | The thief can co-sign with the host and pay out the balance. Not defended by the safe-to-sign rule, which trusts its own keys |
| Copied disk restored elsewhere and run | "A restored backup never publishes" (`DESIGN.md` 6); C12 | Two devices on one key (SR section 10); the restore gaps of N1 |
| Copy of a running program (VM snapshot, fork) holding a secret nonce | — | Accepted (SR section 10; RD line 128) |
| Old backup returned by the host | C12 | N1 |

### 8.3 Not defended, in one list

Refusal of service; a host that holds a seat of its own escaping blame; silence and lateness (unprovable); a false chain view, or fees out of reach, for longer than the maximum safe absence; loss of the held or exposed set; two devices on one key; copies of a running program; theft of unlocked keys; relay-policy obstruction of pre-signed transactions; bugs in the imported builder; reorganisation of the funding after it was buried, or of a leaf link; a host's view of all payments and of members' network addresses; withheld results and closes leading to forced exits (N14, L2); HTLC flooding of the host's commitment (N19); the restore gaps (N1) until fixed.

---

## 9. What I could not check

1. Whether libsecp256k1-zkp at the pinned commit aborts the process on an invalid structure passed to a session function (N13.1, RD line 182). This is from memory.
2. The Lightning message size limit of 65,535 bytes. Taken from review 1; not fetched today.
3. Whether keeping old-anchor commitments current really removes the loss for an old layer state (N3) against ZmnSCPxj's own text. It is my reasoning from the import, where a layer advance leaves channel amounts unchanged.
4. The SuperScalar programs that drive the imported functions (not imported), so how the reference actually orders the distribution and penalty sessions in a ceremony.
5. `docs/LOBBY.md` and `docs/TESTING.md` beyond the lines cited; the hand-off notes; the standard taproot channel document itself (I relied on `docs/research/channel-groundwork.md` for it).
6. Nothing was built or run. In particular I did not build a four-participant tree to see which settings change its bytes; the table in N5 comes from reading the code.
