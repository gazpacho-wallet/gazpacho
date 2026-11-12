# SuperScalar request ledger

Every request Gazpacho has made to the SuperScalar repository, its state from their replies, and what Gazpacho must check when it lands. Started 2026-11-12. The notes themselves are in this folder; this file is the index and the status.

Gazpacho imports SuperScalar's low-level files unchanged (`core/superscalar/IMPORT.md`) and waits for their changes rather than patching its own copy. When a change lands, the general check is always: re-import, regenerate the reference values (`tests/reference/`), re-run the scale check, run the case the request names, and update the specifications that cite the old behaviour. The rows below add what is specific.

States: **sent** (no answer yet), **accepted** (they will do it), **in progress** (named in a pull request or round), **landed** (merged upstream), **re-imported**, **verified** (our check passed), **refused**, **superseded**.

## The notes

| Date | Note | What it is |
|---|---|---|
| 2026-11-11 | `2026-11-11-to-superscalar.md` | First findings from running and importing the reference code, and from the scale check. Called "11-n" below |
| 2026-11-11 | `2026-11-11-end-date-payout.md` | Asks that the end-date payout land with the other tree-transaction changes |
| 2026-11-11 | `2026-11-11-review-of-end-date-payout-draft.md` | Gazpacho's review of their draft specification of the end-date payout |
| 2026-11-12 | `2026-11-12-to-superscalar.md` | Ten requests, E1 to E10, with their reply and our corrections |
| 2026-11-12 | `2026-11-12-advanceless-default.md` | Proposes the advanceless tree as their default; with their reply |
| 2026-11-11 | Not in the repository | The "decisions v3" exchange (`RECORD.md` sections 23 and 24) |

## Their rounds

| Round | Contents | State | Gazpacho's check when it lands |
|---|---|---|---|
| Round 1 | Tree fees (their pull request 476), which also repairs a member's failed lone exit, plus four tree-builder fixes. By our reading these are the four our end-date note grouped with it: participant order, the layer-counter overwrite at 257 members and above, the exit-delay functions that under-report on deep trees, the anchor dropped on a 16-output node. They have not confirmed the list in writing | In progress. Expected "within about a week" of 2026-11-11; they will announce it with the list of changed files | Re-import with `bolt11.c`; new reference values; scale check at every size; confirm a lone exit completes (Slice 3); check the changed-file list against our 38 imported files |
| Their #486 | Requests E3, E4, E5, E6 and E10 of 12 November | In progress | As each request below says. Take it with round 1 in one re-import (`SLICE1-WORK.md`) |
| Round 2 | The end-date payout at every level, with a short specification first | Draft specification received and reviewed by Gazpacho (2026-11-11); reviewed version not yet received | Review the reviewed specification; then re-import, new reference values, and loosen our exit rule to match. Check whether the points of our review were decided on purpose |

## Requests

| # | Request | Note | Their answer | State | When it lands, Gazpacho must |
|---|---|---|---|---|---|
| 11-1 | Bug: a member cannot complete a lone exit (`min relay fee not met, 154 < 167`) | 11 Nov, 1 | Their draft 476 fixes it (`RECORD.md` 23) | In progress (round 1) | Confirm a lone exit reaches a spendable output with the host gone |
| 11-2 | Let the caller supply randomness (signing nonces and other direct reads) | 11 Nov, 2 | No specific answer recorded | Sent | Remove Gazpacho's wrapper; check the simulator repeats a run from a seed with no wrapper |
| 11-3 | No direct output or environment access in the tree builder (`fprintf`, `getenv`, a test-only global) | 11 Nov, 3 | No specific answer recorded | Sent | Re-run the core isolation check on the imported files |
| 11-4, 11-5 | A defined participant order; the order today depends on the C library's sort | 11 Nov, 4 and 5 | Confirmed (`RECORD.md` 23). The fix is in round 1; a placement setter is in #486 (E5); **the default stays timezone grouping** | In progress | Confirm two builds on different systems give identical trees. Find out what placement value 0 selects, and whether timezone grouping needs members' timezones (a privacy cost) |
| 11-6 | Partial signatures are never verified one by one | 11 Nov, 6 | Confirmed | Not needed: Gazpacho's signing engine verifies each one itself | Nothing |
| 11-7 | Raise the 256-member size limit toward 512 | 11 Nov, 7 | Largely answered by the scale check (the limits are defaults); the remaining defects became E3 and E4 | Superseded by E3, E4 | — |
| 11-8a | Remove the older leaf types, not the timed layers above the leaves, "since Gazpacho's first release ships the full layered tree" | 11 Nov, 8 | They keep the older leaf types until one-member pseudo-Spilman leaves are proven at size (`RECORD.md` 23, 24) | **Superseded** by the advanceless proposal (owner decision 9): Gazpacho 1.0.0 uses no timed layers | — |
| 11-8b | Tag the last commit before any removal; say when a merge touches imported files or changes tree transactions | 11 Nov, 8 | Agreed (`RECORD.md` 23, 24, 30) | Accepted | Note the tag in `IMPORT.md` when it exists |
| 11-9.1 | Out-of-bounds read in `node_nsequence` with a non-pseudo-Spilman leaf in fixed levels | 11 Nov, 9 | Not answered on its own | Sent | Gazpacho never builds that shape (C8); re-run the reproduction |
| 11-9.3 | Exit-delay functions under-report on deep trees | 11 Nov, 9 | In round 1, by our reading | In progress | Compare with our own sum from the transactions (Gazpacho does not use these functions) |
| 11-9.4 | Anchor silently dropped on a node with 16 outputs | 11 Nov, 9 | In round 1, by our reading | In progress | Re-run the reproduction; Gazpacho's widths stay at 15 |
| 11-9.5 | `subtree_is_leaf` silently changes the leaf type | 11 Nov, 9 | Not answered on its own | Sent | Gazpacho's leaf check after building stays in any case |
| P1 | Land the end-date payout together with the other tree-transaction changes | End-date note | Accepted as round 2, separate from round 1, with a specification first (`RECORD.md` 30) | In progress | As round 2 above |
| P2 | Our review of their payout draft: no payout on kickoff outputs or a relative lock; slack against the 6-block assumption; members gain when the host fails; the funding payout above about 230 members; one-member leaves for full protection | Review note | Not yet answered in writing | Sent | Read their reviewed specification against points 1 to 8 of our review |
| E1 | A caller-supplied channel output script | 12 Nov, 1 | Accepted only as an **opt-in** builder option: removing the host-only branch strands host funds until their programs have two-sided commitments (their P627) | Accepted (revised) | Opt in from Gazpacho's channel engine (Slice 2); check the leaf's chain extension is built for the same script |
| E2 | A payout destination per member | 12 Nov, 2 | Accepted for 1.1.0; bound in the proposal; per-type dust limits; the anchor stays | Accepted (1.1.0) | Check standard-script limits are enforced by every signer; size and fee computed from the actual scripts |
| E3 | Bound the layer-counter write in initialisation (257 members and above) | 12 Nov, 3 | Fixed or being fixed in #486 | In progress (#486) | Run 257 and 513 members under the sanitizers; lift Gazpacho's 256-member refusal only then |
| E4 | Honour the host's hash at node index 512 and above | 12 Nov, 4 | Being fixed in #486. **The ~128-member cap applies only when the optional hashlock penalty is on** | In progress (#486) | Lift the refusal of hashes at index 512 or more; check member and host build the same tree with hashes at those indexes |
| E5 | A setter for member placement | 12 Nov, 5 | In #486; the default stays timezone grouping | In progress (#486) | Use the setter instead of writing the field; see 11-4 |
| E6 | Free a live signing session before re-initialising it | 12 Nov, 6 | In #486 | In progress (#486) | Run the leak checker on a re-initialised session |
| E7 | Split coins between branches by member count | 12 Nov, 7 | Bug confirmed. They will carry **a per-member capacity in the proposal** instead of forcing equal channels | Accepted (changed) | Write the per-member capacity into `spec/terms.md` 4.2 and `spec/messages.md` 7.2, each member checking its own (pending, see below) |
| E8 | Agree the shared protocol name, id and tag prefix; ask whether they adopt Gazpacho's message format | 12 Nov, 8 | Base the id on bLIP-56; new tags only for new hashes; adopting the format is later, the owner's call | Partly agreed. The owner then decided the id: SHA-256 of `SuperScalar/1` (decision 8), to be recorded in superscalar-docs and adopted by superscalar-cln and the reference | Confirm the same id in their code; one change for the id and any tag rename, then regenerate every vector |
| E9 | Single-input sale and the four shared-leaf prerequisites, in one round | 12 Nov, 9 | Agreed for 1.1.0 | Accepted (1.1.0) | Re-import once; re-check coverage rules (`ux/decisions.md` 5) |
| E10 | `factory_set_funding` should refuse a script it ignores | 12 Nov, 10 | Our description was inverted: the builder uses the given script verbatim and never checks it against the factory key. A library refusal is being added in #486 | In progress (#486) | Gazpacho's check C1 stays; add a test that the library refuses a mismatched script |
| A1 | Make the advanceless tree their default while tree advances are off | Advanceless note | Agreed in principle. Before making it the default they will build, sign and exit an all-static tree at 4, 64 and 512 members on regtest, check every path that assumes a state layer, and refuse refresh-in-place without state layers. Their further finding: under the end-date payout, refresh-in-place can never extend a factory, so extending always means rotation | Accepted, in progress (no pull request named yet) | Read their regtest results at 4, 64 and 512; confirm refresh-in-place is refused; keep the advanceless shape available as an option when advances return |

## Changes their replies imply for Gazpacho's own documents

| Change | Source | State |
|---|---|---|
| The ~128-member cap applies only when the hashlock penalty is on | Reply to E4 | **Done** 2026-11-12: `spec/signing-round.md` section 12 and section 15 table, `spec/messages.md` open point 16 |
| A per-member capacity in the proposal, each member checking its own | Reply to E7 | **Pending**: recorded as `spec/terms.md` open point 6 and `spec/messages.md` open point 20; the format change is written when their change lands |
| The channel script is opt-in, not the default | Reply to E1 | Recorded in the request note; to apply in `spec/channel.md` when written |
| Extending a factory always means rotation; refresh-in-place is never used | Reply to A1 | **Done**: owner decision 9, `DESIGN.md` section 7, `PLAN.md` |
| Placement default stays timezone grouping | Reply to E5 | Open question for Gazpacho (privacy); Gazpacho keeps sequential placement (decision 8) |

## Not to plan around

From their replies: their Core Lightning plugin for holding payments, and their whole-program scale test at 64, 127 and 255 members, are far off. A Gazpacho-written plugin is acceptable if Gazpacho reaches the Core Lightning adapter first. They are not building a second signing engine and will assess adopting Gazpacho's once it is reviewed (`RECORD.md` 30).

## Not yet done

- No watch on the upstream repository: nobody is notified when round 1 or #486 merges.
- No CI step recomputes the imported files' hashes against `IMPORT.md`.
- `spec/terms.md` 4.2's build-server table is pinned to the current import and will go stale at the re-import.
