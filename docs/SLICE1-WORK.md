# Slice 1: work table and merge order

Created 2026-11-12 after the gap review found that the Slice 1 pieces existed on separate branches, had never been built together, and that three pieces had no owner. Slice 1 is done when one host and at least three members, each a separate process, form a factory on signet twice in a row from a clean start, and a member whose conditions are not met is seen to refuse (`SLICES.md`).

## Work table

| Piece | Spec | Branch / PR | State | Next | Blocks |
|---|---|---|---|---|---|
| Core frame and simulator | runner contract in `core/gazpacho/` | `m1a-followup`, PR 9 | Review round 1 fixes in progress | Second review; merge | Everything below |
| Core contract additions (secret tag, watch txid, watch outpoint, restore marker) | `signing-round.md` 12.1, `safety-rule.md` 9, `journal.md` 8 | `m1a-followup` (same builder) | Assigned | Build after the PR 9 fixes | Signing engine, journal, lobby |
| Signing engine core | `signing-round.md`, `safety-rule.md` (draft 4) | `signing-core` on the build server | Built, 1,394 checks; fault runs finishing | Commit; draft PR; review | Creation rounds |
| Creation trees from terms | `terms.md`, `signing-round.md` 4.1 and 13 | after `signing-core` | Not started | Build on the merged signing core | Slice 1 |
| Storage journal | `journal.md` (draft 2) | new: `journal` | **Starting now** | Build; review | The program |
| Lobby engine | `messages.md`, `terms.md` (draft 2) | new: `lobby` | **Starting now** | Build; review | The program |
| Transport | `transport.md` (draft 2) | `transport`, PR 10 | Second review running | Merge | The program |
| Chain view | `chain-port.md` note | `chain-esplora`, PR 7 | Second review running | Merge | The program |
| Wallet transactions | `wallet-tx.md` note | `wallet-tx-lib`, `wallet-tx`, PRs 11, 12 | Review fixes in progress | Second review; merge | Funding |
| Local API (program to interface) | not written | — | **Spec starting now** | Write; review | The program, the interface |
| `gazpacho` program (executor wiring core to ports, host and member in one) | needs the local API spec | — | Not started | After the API spec, journal and lobby | Slice 1 |
| Interface (concept H wired to the API) | `docs/ux/`, the API spec | PR 14 (draft) | Concept chosen; fixes owed | Fix H; wire after the program | Slice 1 walkthrough |
| A real signet funding broadcast | — | wallet tool | Approved by the owner | After the wallet-tx second review | Confidence in the broadcast path |

## Merge order

1. PR 13 (specifications) once the discovery confirmation and the documentation pass land.
2. CI hardening (draft PR), then branch protection on `main` with the checks required.
3. PR 9 (core frame follow-up and contract additions). Everything else rebases on it.
4. PRs 10 (transport), 7 (chain view), 11 and 12 (wallet transactions), each rebased on `main` after 9, in any order.
5. The signing engine core, then creation trees from terms.
6. The journal and the lobby engine.
7. The local API spec, then the program.
8. An integration branch `slice1` that builds everything together in CI, followed by the signet runs and the walkthrough.

## Rules for this phase

- Every piece is built against a reviewed spec and reviewed independently before merge; nothing merges with CI red or missing.
- Branches on the build server that predate the history rewrite are replayed onto the rewritten history before pushing; no IP address or local path is ever committed (CI checks this once hardened).
- SuperScalar re-imports (their round 1 and #486) are taken in one step after PR 9 merges, with the reference values regenerated.
