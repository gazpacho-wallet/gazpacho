# Review 3, confirmation of fixes

2026-11-12. Confirms whether `notes/spec-review-3.md` (F1 to F28, G1 to G20, section 3 table) is answered by the revised specs on branch `specs-slice1` (commit `4ad3b68`): `spec/safety-rule.md` and `spec/signing-round.md` draft 4 ("SR", "RD"), `spec/messages.md`, `spec/terms.md`, `spec/journal.md` draft 2 ("MS", "TR", "JN"), `tools/spec-vectors.py`, `docs/THREAT-MODEL.md`. Read with `git show`; the branch was not checked out in the main folder. This is not a fresh review: it checks each finding and looks for inconsistencies the fixes introduced.

## 1. Summary

- **Findings: 26 fixed, 2 partly, 0 not.** The two partial ones (F8, F15) are fixed in the specs, which now state them as requirements on the core contract (RD 12.1); `ports.h`, `action.h` and `event.h` on the branch are unchanged, as RD itself says ("Today they do not").
- **Vectors:** `python -I tools/spec-vectors.py` (temporary worktree in the scratch area, removed afterwards) ran cleanly. Every hex vector in TR (T1 to T5, digests, signatures, test keys, salt), MS (M0 to M3, binding, both binding signatures, `msg_hash`, protocol id, type 52791) and JN (J1, J2, J3, J5, J6's second mark) matches its output byte for byte, checked by script. J4 and J6 offsets (122, 164, 167, 204) recomputed by hand: correct. TR 4.2's funding amounts recomputed from the R formula for 3, 4, 5, 8 and 16 members: correct.
- **New inconsistencies:** five, all low (section 4). The one a builder could trip on is TR T7's D for 9 to 15 members.
- **Can the signing engine build creation trees from these specs? Yes.** Shape → level arity `interior ‖ 3`, D, K, placement, anchors, fee per transaction, funding amount, the setter order and the leaf check are all specified, consistent across SR/RD/TR/MS, and reported as built on the build server for T1 at 3, 4, 5, 8 and 16 members (TR 4.2; not re-run by me). Before the **full round** can be built, the core contract must gain the secret-tagged randomness request, watch-txid, watch-outpoint and the restore marker (RD 12.1).

## 2. Findings

| # | Status | Where fixed | Note |
|---|---|---|---|
| F1 shape / leaf kind | **Fixed** | TR 4.1 (`leaf_kind` = 3, interior widths 4–15, ≤ 6 interior), 4.2 (split rule), 4.3 (static check on receipt); SR C8 "Leaf kind" row; RD 4.1 shape row, 12 (new hazard row), 13 (order, leaf check), test 12; T1 redone (`0004 00 03`, `0010 01 04 03`), T1–T6, M1, M3 regenerated | The generator also refuses review 3's own suggestion `[4,3]` at 3 members, correctly |
| F2 torn tail | **Fixed** | JN 3.3 (self-locating sync mark), 4 (confirm only after mark synced), 5 step 4 (mark after damage = corruption, refuse), J5/J6, tests 7–10, 25–27; SR 13 named test | Residual edge (two flips: damage in the last confirmed group *and* in its mark) would be cut as a torn tail; acceptable, worth one sentence |
| F3 restore three ways | **Fixed** | SR 2, C7 "Fresh funding output", C12, 9 R2–R6; RD S5, 8; MS 2, 7.2 reason-12 row, 7.9 code 12, test 52; JN 8.2, 8.3, record table (`fresh_start` withdrawn, `0x00040008` unused) | One scheme: 31-bit, 0 at install, untagged, no fresh-start; R4 rests on C7; guard = record + file with a storage duty |
| F4 leaf amount | **Fixed** | TR 3 type 30 renamed `channel_sat`; TR 4.2 R(leaf)/R(node)/`funding_amount` = R(root); SR C8 rows; RD 4.1; MS 7.2 records 14, 30 | Unequal channels stated, upstream request open |
| F5 placement | **Fixed** | RD 4.1 (value 0, not a field); MS 7.2 (record 26 removed, refused as unknown even), test 37 | |
| F6 C10 / states / names | **Fixed** | SR 2 (Abandoned, Dead), C10 (touches only funding outpoint and tree), C11 (late funding re-check); RD 7 (Unfinished → Abandoned, names paragraph); MS 7.9, test 35; JN `round_ended` outcome dead | |
| F7 C7 record | **Fixed** | MS 7.12 `tree_digest`; SR C7; RD 3 (S1 saves tier and items); JN `exposure` (funding tx, tree digest), `round_started`, OP 2 compaction rule | Tree-digest vector still open (no items until the engine runs) |
| F8 chain actions | **Partly** | RD 12.1 (watch txid, watch outpoint) referenced by SR C4(d), C11 | Requirement only; `action.h` unchanged on the branch |
| F9 lost `start` | **Fixed** | MS 6.9 (`start` signed, saved, resent; proposal stands alone), 6 reconnect rule; RD 6 step 1; JN `start_sent`, `start_received`; tests MS 54, RD 14 | |
| F10 same id, other bytes | **Fixed** | RD S6; MS 7.1 (contribution keys inside), 7.2 table keyed on `round_id`, test 53; JN `host_fault` | |
| F11 keep-alive | **Fixed** | TR 3 type 22 min 60,000 ms; MS 2 | Ready window may stay below keep-alive, stated (TR type 18) |
| F12 key before lobby | **Fixed** | RD 2; MS 2 | Derivation path still open (MS OP 3) |
| F13 forced writes | **Fixed** | MS 6 "Limits on state changes", 6.1 global scope-zero limit; TR 7; JN `seat`, `terms_received`; tests MS 56, TR 20 | Limits are first guesses (MS OP 11); see 4.5 |
| F14 `round_abort` items | **Fixed** | MS 7.9 records 9, 11 (odd); RD 4, 15 | |
| F15 secret tag | **Partly** | RD 8, 12.1; SR R2 / JN 8.2 draw the epoch untagged | `gz_random_port_t` still `fill(ctx,out,len)` on the branch |
| F16 overstatements | **Fixed** | THREAT-MODEL line 38 ("Not yet tested") and 112 ("not encrypted in Slice 1"); SR 11; TR 2/11 (T1 valid again); JN 5; MS 7.2 record 36 (keeps host-only absolute timeout) | SR OP 9 now stale, see 4.1 |
| F17 `fixed_levels` | **Fixed** | TR 4.2 (D = depth of deepest leaf); MS record 36; RD 4.1 | T7 misstates D, see 4.2 |
| F18 512 wording / hash order | **Fixed** | SR C8; MS record 34, test 39; RD 12 last row | |
| F19 stale text | **Fixed** | MS 4.3, 7.2, OPs 4/5/13/15 closed; TR 10.4, OP 8 → closed; JN OP 5 closed; SR/RD headers | New stale bits, see 4.1 |
| F20 signer selection | **Fixed** | MS 6.9 | |
| F21 entry length | **Fixed** | JN 3 (≥ 21; 25 for kinds 1, 3) | |
| F22 first batch after restore | **Fixed** | JN 8.2; RD 12.1 restore marker | Marker mechanism itself "not yet defined" (gap S1-1) |
| F23 delay overflow | **Fixed** (noted) | SR C8 note; TR OP 4 | Not Slice 1 |
| F24 anchors | **Fixed** | SR C8; RD 4.1; MS record 28 = 1 | |
| F25 16-wide + anchors | **Fixed** | TR 4.1 (interior ≤ 15) | |
| F26 resend partial sigs | **Fixed** | RD 6 step 5; MS 6, 7.10, test 55 | |
| F27 funding script length | **Fixed** | RD 12, 13; RD 4.1 funding row | |
| F28 protocol id | **Fixed** (as recommended) | MS 4.3 (fixed alias, not a security parameter), OP 18; RD OP 10; TR 6 | |

G-items: G1 F2 ✓; G2 F3 ✓; G3 F12 ✓ (path open); G4 F1/F4 ✓; G5 guard ordering via same batch ✓, seat writes ✓; G6 ✓; G7–G9 ✓; G10 fee rule now exact (TR 4.2) ✓; G11 ✓; G12 ✓ (no vector); G13 ✓; G14 ✓; G15 tweaked cache chosen (RD 8) ✓, tag a contract item; G16 ✓; G17 step timeout (RD 6 step 8) ✓; G18 proposed values (SR 12) ✓ pending owner; G19 contract item; G20 ✓.

## 3. Cross-spec consistency table, re-run

✓ agrees across every spec that mentions it.

| Item | SR d4 | RD d4 | MS d2 | TR d2 | JN d2 | Status |
|---|---|---|---|---|---|---|
| Round identifier | Uses | Abstract, now with contribution keys | 7.1 concrete, contribution keys after factory keys | 10.4 settled | `round_started` | ✓ |
| Tree digest | Term, C7 | 3 | 7.12, tag `gazpacho/tree` | — | `exposure` | ✓ (SR omits "chain" from its prose list; MS is normative) |
| Tags | — | nonce, nonce-extra, bind | Full table incl. `nonce-extra`, `tree` | terms/outer, terms/current | — | ✓ (review 3's missing `nonce-extra` fixed) |
| Reasons 1–12 | 6, 9, 11, 12 | 9, 12 | 7.9 table | — | 3, 12 in tests | ✓; 12 = "lacks my current key for this lobby" everywhere |
| `round_abort` tier/items | — | Optional, Slice 1 whole rounds | Odd 9, 11 | — | — | ✓ |
| Restore epoch | 31-bit, 0 install, untagged | Untagged, secret bytes never journaled | 31-bit | — | `key_epoch` u32 < 2^31 | ✓ |
| Guard | R6 record + file | 12.1 storage duty | "saved with the guard" | — | 8.3 format, `guard` 0x0004000a | ✓ |
| C7 record | Outpoint, funding tx, tree digest | Exposure + partial sigs, one write | 7.4 one batch | — | `exposure` | ✓ |
| Placement | Sequential | Value 0, not a field | No record 26 | — | — | ✓ |
| Shape / leaf kind | C8 row | 4.1, 12, 13 | Not carried | 4.1–4.3 | — | ✓ |
| Funding amount / fee | C8 R(root), fee rule | 4.1 | Records 14, 30 | 4.2 | — | ✓ (vectors recomputed) |
| Fixed levels | D | D | Record 36 = D | 4.2 D | — | ✓ (T7 wording, 4.2 below) |
| 512 limit | Hashed node ≥ 512 | Same | Same | — | — | ✓ |
| Anchors | On | On | Record 28 = 1 | ≤ 15 wide | — | ✓ |
| Layer step/states | Inside conditions | Slice 1: 144/4 | Records 40/42 = 144/4 | "stay proposal fields" | — | ✓ |
| States Abandoned/Dead | ✓ | ✓ | ✓ | — | outcomes abandoned, dead | ✓ (JN also has "failed", a host outcome RD names only in prose) |
| Results kept (H12) | Until spent or dead | Same | 7.6 same | — | same | ✓ |
| Keep-alive vs step | — | — | 30 s < 60 s | ≥ 60,000 | — | ✓ |
| `start` | — | Signed, saved | 6.9 signed, `sig` 240 | — | `start_sent`/`start_received` | ✓ |
| Kinds | — | — | 2, 16–34, 64–80, 81 | — | — | ✓ |
| Record 240 last, journal types even | — | — | ✓ | — | ✓ | ✓ |
| Journal record kinds named elsewhere | `key_epoch`, `key_index`, `guard`, `exposure`, `round_started` | `round_started`, `round_proposal`, `key_epoch`, `restored`, `guard` | `round_started`, `start_sent`, `start_received` | `terms_received` | All defined in section 9 | ✓ |

## 4. New inconsistencies introduced by the fixes

1. **Stale text.** SR open point 9 still says THREAT-MODEL claims encryption at rest and lists no gap for two trees; the branch's THREAT-MODEL (lines 38, 112) no longer does. TR section 3 (line 88) still cites "`signing-round.md` draft 3 section 4.1". JN test 1 says "J1 to J4"; J5 and J6 also exist. Specs cite `docs/ux/decisions.md`, which is not on `specs-slice1` (it is on `ux-concepts`); fine after merge, worth knowing.
2. **TR T7's D is wrong for 9 to 15 members.** T7: "for 5 to 16, [4, 3], D = 2 (D = 3 at 16)". By the split rule any root child with 3 or 4 members splits twice, so D = 3 for every n from 9 to 16 (e.g. n = 9: children 3,2,2,2). The generator prints only 3, 4, 5, 8, 16, so it does not catch this. TR test 17 says "the depth D stated in T7", so a builder following T7 would fail RD test 12. Fix: "D = 2 for 3 to 8, D = 3 for 9 to 16", and print every n in the generator.
3. **Reason for a second tree on the old outpoint after a restore.** SR 13, RD test 15, MS test 52, JN test 23 all expect reason 12 for both the replay and the second tree. JN 8.2(2) says the second tree is refused by C1's script check. Both are true for different host choices (old key named: reason 12; new key named: funding script no longer matches, reason 1 or 9). Tests should say which variant they build, or accept either.
4. **R6's "outside the journal" vs export.** R6 and JN 8.3 put the guard file outside the backup set, and say the export carries a copy; how an export carries it is left to the backup specification (JN OP 4). Consistent, but the stale-backup check depends on it.
5. **Lobby-wide seat cap is a new griefing lever.** MS 6: "per lobby, at most 4 × `target` seats ever created, one creation per second". Seats cost nothing, so one peer can exhaust 32 creations for T1 in about half a minute, after which no one can join or rejoin. Liveness only; a per-connection or per-address cap, or counting only seats that reached Ready, would avoid it.

## 5. Slice 1 walk, remaining gaps

Re-walked review 3 section 4's steps 0 to 18 against the new text. Every G1–G20 point is now answered in the specs. What a builder must still guess or wait for:

- **S1-1 Core contract.** Secret-tagged randomness, watch-txid, watch-outpoint, and the restore marker (RD 12.1) are requirements with no defined API. The restore marker is explicitly "not yet defined" (a user command or a flag to `gz_node_start`).
- **S1-2 Key derivation path** (MS OP 3): inputs fixed (seed, 31-bit epoch, index), path not.
- **S1-3 TLV field numbers inside journal records** (JN OP 3): internal, but needed before any record is written.
- **S1-4 No round-identifier or tree-digest vectors** (MS 7.1, 7.12): they come only once the engine builds items, so the first implementation is its own reference.
- **S1-5 Member default conditions** for Slice 1 are not listed: fee ceiling, `lstock_delay` range, own minimum channel, minimum members. SR C8 says "inside its conditions"; the test of "a member whose conditions are not met refuses" needs one stated default set.
- **S1-6 T7's D** (4.2 above).
- **S1-7 Host's own binding** (MS OP 8, "Confirm").
- **S1-8 Owner values** still "proposed" (section 6).

None of these blocks building trees; S1-1 blocks the full round and C11/C4(d).

## 6. Marked "proposed, owner to confirm"

- SR 12 / RD 15: (1) no distribution transaction in Slice 1 (MS record 44 refused, MS OP 14); (2) host recovers signet coins through a short life and its timeout leaves, no close round; (3) burial depth 3 blocks; (4) funding deadline 36 blocks after the member's ack; (5) unfinished deadline one signing budget; (6) confirmation allowance 6 blocks per transaction plus a 6-block margin (under the "each proposed" heading).
- SR C8 / RD 4.1 / RD 5: distribution transaction not signed in Slice 1.
- TR T1 and TR OP 8: lifetime 144 blocks plus 36 of wind-down.
- MS changes table / 7.2: layer step 144 and states 4 fixed in Slice 1.
- JN OP 6 repeats the deadlines.

Not marked proposed but still open: MS rate limits (OP 11), signers in joining order (OP 10), protocol id string (OP 18).
