# Review ledger

Every independent review of a pull request or a specification, one row per piece of work and one line per round. Started 2026-11-12 after the gap review found reviews archived on the wrong branch or not at all.

Every reviewer is an agent that did not write the work. No review has been posted on GitHub itself; the files here are the record.

**Rule**, from `PLAN.md` ("How work proceeds": fixes, then a second review of what changed, then merge) and `SLICE1-WORK.md` (nothing merges with CI red or missing): no merge while a high or medium finding is open, while the second review of the fixes is missing, or while CI is red or missing. As of 2026-11-12, pull requests 7, 9, 10 and 11 do not meet it.

Update this file in the same commit as each new review. Copy each pull request's review onto that pull request's branch as well, so the review travels with the code.

## Pull requests

| PR | Work | Round | File | Commit reviewed | Date | Verdict | Findings and their status |
|---|---|---|---|---|---|---|---|
| 5 | Core and simulator skeletons (merged) | 1 | Not archived | — | 2026-11-11 | Merge after fixes | Summarised in `RECORD.md` section 28 |
| | | 2 | Not archived | — | 2026-11-11 | Merged after a third round of fixes | `RECORD.md` section 32. Follow-up items went to PR 9 |
| 6 | Wallet keys (merged) | 1 | Not archived | — | 2026-11-11 | Merged | Summarised in `docs/notes/wallet-keys.md`. No second review recorded |
| 7 | Chain view (Esplora backend, comparing layer, `gz-chain`) | 1 | `review-pr7-chain.md` | `8d4baac` | 2026-11-11 | Merge after fixes | Findings 1 to 5 before merge; 6 to 9 need a comment and a test. 26 fix commits since; **status unknown until round 2** |
| | | 2 | — | — | — | Running (`SLICE1-WORK.md`) | — |
| 8 | Screens prototype (draft) | — | None | — | — | Not reviewed | `web/API.md` not reviewed from the core's side |
| 9 | Core follow-up (`m1a-followup`) | 1 | `review-pr9-core-followup.md` | `b3d9312` | 2026-11-12 | Merge after fixes | **F1, F2, F3 high, open**: a reply recorded as sent but never sent; a start that can never complete; the secret invariant judges the wrong thing. F5's two untested memory guards open. Fixes in progress |
| 10 | Transport (BOLT 8, BOLT 1) | 1 | `review-pr10-transport.md` | `5d850c2` | 2026-11-12 | Merge after fixes | F1 to F10. The only CI run, on this commit, failed in the sanitizer build |
| | | 2 | `review-pr10-transport-r2.md` | `872202f` | 2026-11-12 | **Unfinished**: no verdict, new findings or mutation counts written. `SLICE1-WORK.md` lists the second review as running | F1, F3, F4, F5, F6, F9, F10 fixed; F2 fixed as a decision (the blocking accept stays, choice open); F7 fixed in the tool (the port still cannot report failure); F8 fixed in documentation. No CI run on the fix commit |
| 11 | Wallet transactions library (`wallet-tx-lib`) | 1 | `review-wallet-tx.md` | `f3a5c79` (library), `8ed8ce4` (tool tree) | 2026-11-12 | Merge after fixes | **M1, M2, M3 medium, open**: the release gate trusts a caller-writable txid; two parser rules no test pins; a factory funding may pay any witness program. **The reviewer's own mutation results were never read** (server access ended) |
| 12 | Wallet transactions tool (stacked on 11) | — | Read within the review of 11 | `8ed8ce4` | 2026-11-12 | Not reviewed on its own | — |
| 13 | Slice 1 specifications (`specs-slice1`) | — | See "Specifications" below | — | — | — | — |
| 14 | Interface concepts (draft) | 1 | `ux-critique.md` | — | 2026-11-12 | Critique of seven concepts | The critique's fixes and the owner's answers still to apply to concept H |

## Specifications

| Specification | Round | File | Draft reviewed | Date | Verdict | Findings and their status |
|---|---|---|---|---|---|---|
| `safety-rule.md` | 1 | `spec-review-1.md` | 1 | 2026-11-11 | Needs rework | F1 to F15; answered in draft 2 |
| | 2 | `spec-review-2.md` | 2 | 2026-11-11 | Ready after listed changes | N1 to N20, L1 to L8; answered in draft 3 |
| | 3 | `spec-review-3.md` (joint, five specs) | 3 | 2026-11-12 | Ready after listed changes | F1 to F28, G1 to G20; answered in draft 4 |
| | 3, confirmation | `spec-review-3-confirm.md` | 4 | 2026-11-12 | 26 fixed, 2 partly (F8, F15: now requirements on the core contract), 0 not | Five new low inconsistencies; the T7 depth, stale text and seat-cap note were fixed in two later commits. **Draft 4 itself has not been reviewed** |
| `signing-round.md` | 1 | `spec-review-1.md` | 1 | 2026-11-11 | Sound with changes | As above |
| | 2 | `spec-review-2.md` | 2 | 2026-11-11 | Ready after listed changes | As above |
| | 3 | `spec-review-3.md` | 3 | 2026-11-12 | Ready after listed changes | As above |
| | 3, confirmation | `spec-review-3-confirm.md` | 4 | 2026-11-12 | As above | Rules S4 and section 8 were added after the signing engine build; **draft 4 not reviewed** |
| `messages.md` | 3 | `spec-review-3.md` | 1 | 2026-11-12 | Ready after listed changes | Answered in draft 2 |
| | 3, confirmation | `spec-review-3-confirm.md` | 2 | 2026-11-12 | Fixes confirmed | **Draft 2 not reviewed** |
| `terms.md` | 3 | `spec-review-3.md` | 1 | 2026-11-12 | Ready after listed changes, section 4 to redo | Answered in draft 2 |
| | 3, confirmation | `spec-review-3-confirm.md` | 2 | 2026-11-12 | Fixes confirmed | T7 depth corrected afterwards. **Draft 2 not reviewed** |
| `journal.md` | 3 | `spec-review-3.md` | 1 | 2026-11-12 | Ready after listed changes, sections 5 and 8 to redo | Answered in draft 2 |
| | 3, confirmation | `spec-review-3-confirm.md` | 2 | 2026-11-12 | Fixes confirmed | **Draft 2 not reviewed** |
| `discovery.md` | 1 | `review-discovery-d2.md` | 2 | 2026-11-12 | Needs rework for design D; design C (the demo wallet) ready after listed changes | Answered in draft 3 |
| | 2 | `review-discovery-d3.md` | 3 | 2026-11-12 | Design C ready after small changes; design D ready after listed changes, no rework | N1 to N14; answered in draft 4 |
| | 3, confirmation | `review-discovery-d4-confirm.md` | 4 | 2026-11-12 | Design C ready; design D ready after small changes | N1 partly fixed (a residual Tor-sharing limit, stated in open point 17); the others fixed, some with small residuals; new items E1 to E7 applied in draft 4.1. **Draft 4.1 not reviewed** |
| `local-api.md` | 1 | `review-local-api-d1.md` | 1 (`8447ea3`) | 2026-11-12 | Ready after listed changes | F1 to F3 high (session cookie readable by every loopback port; the phrase check as an oracle; "cancelled" reported as "nothing was signed" after partial signatures), F4 high for 1.0.0 (host-node file read), F5 to F16 medium, F17 to F24 low; 14 Slice 1 gaps. Answered in draft 2 ("Changes from draft 1"; draft 1 kept at `../specs-history/local-api-d1.md`). Copied unchanged except one loopback address range, written out in words under the no-IP rule |
| | 2 | `review-local-api-d2.md` | 2 (`7aedcf4`) | 2026-11-12 | Ready after listed changes | Round-1 findings: all fixed, F11 and F12 partly. New: N1 high (the sign-in layer rested on a storage specification that did not exist), N2 high for 1.0.0 (a locked wallet stopped watching, and every restart locks it), N3 medium-high (the first-run token on the browser launcher's command line), N4 to N9 medium, N10 to N16 low; nine Slice 1 gaps; views on defaults D2 to D16. Answered in draft 3 ("Changes from draft 2"; draft 2 kept at `../specs-history/local-api-d2.md`), together with `storage-encryption.md` draft 1's requirements. Copied unchanged: it contains no address written with a prefix length. **Draft 3 not reviewed**; its locked-wallet section follows storage 8.7, which that specification's own review says needs rework |
| `storage-encryption.md` | 1 | `review-storage-encryption-d1.md` | 1 (`b626a9e`) | 2026-11-12 | Ready after listed changes; section 8.7 (the watch bundle) needs rework | F1 to F4 high (old bundle copies hold commitments that later become revoked; no completed own commitment exists in the taproot channel format; rollback anchors miss commitment, revocation and `round_signed` batches; a restored backup could rebuild a bundle that publishes stale state), F5 to F12 medium, F13 to F25 low; all answered in draft 2 (its "Changes from draft 1"). Draft 1 kept at `docs/specs-history/storage-encryption-d1.md`. **Draft 2 not reviewed** |
| Cross-specification: `exit.md`, `storage-encryption.md`, `local-api.md`, `safety-rule.md` (with `journal.md`, `THREAT-MODEL.md`, `MULTI-FACTORY.md`) | 1 | `review-cross-spec-1.md` | exit 2, storage 3, local API 4, safety rule 4, journal 3 (`47e831e`) | 2026-11-12 | Consistent after the listed fixes | D1 to D4 medium (the short penalty file, the unlock order, when the bundle is rewritten, Slice 1's lock echo), D5 to D16 low, stale references, threat-model gaps, and a missing headline for a member the host closed out while locked. All applied as alignment fixes, without new draft numbers ("Changes after cross-spec review 1" in each changed document). **The fixes have not had a second review** |
| `PROTOCOL.md` | — | None | 1 | — | Not reviewed | — |
| `transport.md` (branch `transport`) | — | Read in full by the round-2 review of PR 10 | 2 | 2026-11-12 | The reviewer says it may count as the specification review, with two conditions, for the owner to confirm (`OPEN-QUESTIONS.md` A12) | Written before the code but reviewed only after it |
| `docs/notes/chain-port.md` (branch `chain-esplora`) | — | Only within the review of PR 7 | — | 2026-11-11 | Did not exist in the branch at review time | — |
| `docs/notes/wallet-tx.md` (branch `wallet-tx-lib`) | — | Only within the review of PR 11 | — | 2026-11-12 | Written by the builder, not reviewed on its own | — |
| `THREAT-MODEL.md` | — | None | 1 | — | Not reviewed | Built from section 8 of `spec-review-2.md` |
| `web/API.md` (branch `ui-prototype`) | — | None | — | — | Not reviewed | Contradicts owner decision 4 (`roles`, `host_node_missing`) |

## Reviews of SuperScalar's work

| Subject | File | Date | Verdict |
|---|---|---|---|
| SuperScalar's end-date payout draft | `../handoff/2026-11-11-review-of-end-date-payout-draft.md` | 2026-11-11 | Direction right; four additions to decide on purpose. Their reviewed draft has not arrived |

## Not in the repository

- The reviews of PRs 5 and 6 (only their summaries above).
- The SuperScalar session's "decisions v3" questions and Gazpacho's answers (`RECORD.md` section 23).
- Reviewer scratch files and logs on the build server, cited by path in some reviews.
