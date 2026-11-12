# Slice 1: the live board

The state of every Slice 1 piece, with evidence. Rewritten 2026-11-12 (truth pass) from `gh pr list --state all`, `git log` on `main`, the branches on GitHub and the build server's folders. **Update it in the same pull request as every merge**, and whenever a piece changes state.

Slice 1 is done when one host and at least three members, each a separate process on the build server, form a factory on signet twice in a row from a clean start, through the interface, and a member whose conditions are not met is seen to refuse (`SLICES.md`; owner decision 11). The walkthrough is recorded and archived.

Review counts follow the plan's rule: two independent reviews for anything touching keys, signatures, transactions, storage encryption or the safety rule; one for other code; fixes are reviewed again before merge, and the review is recorded in `reviews/README.md` in the same pull request. No merge with an open high or medium finding, or with CI red or missing (11 required checks on `main`).

## Merged into `main`

| PR | Work | Merged (2026-11-12, UTC) | Reviews | Notes |
|---|---|---|---|---|
| 5 | Core and simulator skeletons; scale check of the tree shape | 00:52 | 2 rounds, not archived | Summaries in `RECORD.md` sections 28 and 32 |
| 6 | Wallet keys (BIP 39, BIP 32, BIP 86) | 05:55 | 1, not archived | Summary in `docs/notes/wallet-keys.md` |
| 16 | CI hardening: 11 jobs, pinned actions, read-only token | 09:37 | None recorded | Protection on `main` requires all 11 jobs |
| 17 | Fuzz runner: absolute build path | 10:53 | None recorded | Fixes the cause found in the review of PR 11 |
| 10 | Transport: BOLT 8, BOLT 1 framing, `gz-net` | 11:08 | 2 rounds; the follow-up commits after round 2 not reviewed | `reviews/README.md` |
| 18 | Valgrind runner honours `WILL_FAIL` | 12:29 | None recorded | |
| 11 | Wallet transactions library | 12:45 | 2 rounds; the round-2 fix commit not reviewed | `reviews/README.md` |
| 12 | `gz-wallet-tx` tool | 13:09 | Read within the reviews of 11 | |
| 13 | Slice 1 specifications, protocol map, threat model | 13:56 | See `reviews/README.md`, specifications | Every current draft that code is built from is unreviewed (S13) |
| 7 | Chain view: Esplora backend, comparing layer, `gz-chain` | 15:17 | 3 rounds; round 3 by reading the code only | `reviews/README.md` |
| 20 | `net_conn` timing checks robust under valgrind and load | 17:28 | None recorded | |
| 19 | `gz-wallet-tx` fixes from the first signet broadcast | 18:07 | None recorded | `docs/notes/wallet-tx.md` section 10 |

`main` is at `67678bb` (PR 19). The one supervised signet funding broadcast has happened (it led to PR 19).

## Open pull requests

| PR | Branch | State today | Piece |
|---|---|---|---|
| 9 | `m1a-followup` | Open, not draft. **Conflicts with `main`, so CI does not run.** Head on GitHub `82a06e2`; the build server holds newer commits (S1) | S1 |
| 21 | `core-contract-slice1` | Draft, stacked on 9. CI at `f5d8a9d`: 6 of 11 pass; the handbook and the three clang jobs fail, one gcc build had not finished | S1 |
| 15 | `signing-core` | Draft, stacked on 9, **stale**: head `8e8b738`, CI red. The engine's newer state is only on the build server | S2 |
| 8 | `ui-prototype` | Draft. Screens on fake data with a proposed local API (`web/API.md`), which predates `spec/local-api.md` and contradicts owner decision 4 | S10 |
| 14 | `ux-concepts` | Draft. Options map, eight layout concepts, comparison, owner decisions; concept H chosen | S10 |

## Built, but only on the build server

Not on GitHub in any form. Each needs to be replayed onto GitHub's history (the history was rewritten) and pushed from the server.

| Work | Branch on the server | Last commit | State |
|---|---|---|---|
| Journal | `journal` | `2c9a491` | Built in draft 2's clear format, with crash, fault, fuzz and mutation tests, on history from before the rewrite. The encryption of draft 3 is not built; a note beside the branch lists what it will change |
| Lobby engine | `lobby` | `761de83` | Built with mutation runs; its decisions are in `docs/notes/lobby.md` on that branch (listed in `DECISIONS-WITHOUT-OWNER.md`) |
| Signing engine | `signing-core` | `1c4497d`, with uncommitted changes | Newer than PR 15; `decoders.h` uncommitted; 61 survivors of `sign_tx.c` to re-run |
| Core follow-up | `m1a-followup` | `e85dd1f` | `main` merged in and a test for K6 added; the first gate run passed; a second run was going; not pushed |

## Slice 1 pieces (plan section 4)

| # | Piece | State | Branch / PR | Depends on | Next step | Reviews required |
|---|---|---|---|---|---|---|
| S1 | Core gate: the follow-up and the contract additions (secret tag, watch txid, watch outpoint, restore marker) | Follow-up: PR 9, review round 1 archived (`review-pr9-core-followup.md`, three high findings); commit titles name a second and third review that are not archived. Newer commits only on the server. Contract additions: PR 21, draft, red | `m1a-followup` (PR 9), `core-contract-slice1` (PR 21) | Phase 0 | Push the server's `m1a-followup`, so PR 9 no longer conflicts; merge it into PR 21 and make PR 21 green; archive or redo the reviews | 2 |
| S2 | Signing engine to draft 4 | Built to an earlier draft, on the server only; PR 15 is stale | `signing-core` (PR 15) | S1 | Commit `decoders.h`, re-run the 61 survivors, push a fresh branch; then draft 4 (`messages.md` encoding, journal records, the C7 exposure record, restore epochs, libFuzzer harness, BIP 327 vectors) | 2 and a cryptography reviewer |
| S3 | Trees from terms; creation checks C1 to C11 and H1 | Not started on GitHub; the build server holds a clean clone of `main` for it | — | Interfaces only | Build against `terms.md` section 4, `signing-round.md` 4.1 and 13, `safety-rule.md`; add vectors to `tools/spec-vectors.py` | 2 |
| S4 | Lobby engine | Built on the server only | `lobby` (server) | S1 | Replay and push; open a PR; amend `messages.md` 6.3 for standby joins; register the lobby record type in `journal.md` 9.1 | 2 |
| S5 | Journal, then its encryption layer | Journal built on the server only; encryption layer not started | `journal` (server) | S1; S6 for the encryption | Replay and push the journal; then the encryption layer to `journal.md` draft 3 | 2, and a cryptography reviewer for the encryption |
| S6 | Storage encryption code, Slice 1 subset (key file, Argon2id helper, sealed entries, mark file, guard, attempts; no watcher) | Not started. libsodium is not in the build | — | The owner's yes on the cryptography choices (plan section 8, question 1) | Pin libsodium by hash; build to `storage-encryption.md` draft 3; confirm its section E vectors against libsodium | 2 and a cryptography reviewer |
| S7 | Transport for lobbies: the `messages.md` envelope (type 52791, 38-byte header, splitting), peer ids, `init`, ping and pong, failure reporting | Not started (a folder on the build server, empty). **This is the Slice 1 blocker nobody owned:** the transport closes a connection idle for 30 s, while a lobby gathers for hours | — | Nothing | Build to `transport.md` and `messages.md` section 2 | 2 |
| S8 | Chain watch loop: `WATCH_TX` and `WATCH_OUTPOINT` to events, reorganisations, the far-behind server rule | Not started | — | S1 | Build to `docs/notes/chain-port.md`; take up round 3's follow-up of PR 7 (a server far behind counts as no reply) | 1 |
| S9 | Local API server framework: parser, sessions, passphrase sign-in through S6, event stream, status, every Slice 1 call against a fake backend | Not started | — | S6's interface (a stub first) | Choose the HTTP parser; build to `local-api.md` draft 4 (unreviewed, S13) | 2, with browser security in scope |
| S10 | Interface: redo `slice1-screens.md` for API draft 4; wire concept H to a draft-4 mock, then to S9; Playwright checks in CI | Concepts and a prototype exist on drafts only; `slice1-screens.md` is keyed to API draft 1 | PRs 14, 8 | The API specification | Redo the screens list; move `web/` into the repository | 1 and a UX critique |
| S11 | The `gazpacho` program: executor loop, ports wiring, one lock per data folder, refusal of mainnet | Not started. No executor exists: only `sim/` drives the runner | — | S1 to S10 | A reviewed design note `docs/notes/program.md` first | 2 |
| S12 | SuperScalar re-import (their #494, #487, #488, #486 and later), reference values regenerated, tree shapes checked against their advanceless default | Not started. The import (pinned `e657395`) predates all of these | — | S1 | `tools/update-import.sh`, then the checks listed in `handoff/README.md` | 1 |
| S13 | Independent reviews of the drafts code is built from: signing-round 4, safety-rule 4, messages 2, terms 2, journal 3, storage-encryption 3, local API 4, exit 2 | Not started as a stream. Each is marked unreviewed in `reviews/README.md` | — | Nothing | One review per draft, archived in `docs/reviews/`, fixes applied | — |

Also owed for Slice 1, outside the table: the owner's answer on the key path (W2, `OPEN-QUESTIONS.md`), the member's starting limits written into `terms.md` (W1, decided), and the Slice 1.5 list of deferred features with the test each one owes (owner, questions 6).

## Order of work

From the plan (waves; at most four builders and two light agents at a time, one heavy job on the build server at a time):

1. **Wave A, now:** S1 to completion; S3, S7 and S9 in parallel (none depends on S1); S13 and this truth pass as light agents.
2. **Wave B:** S2, S4 and S5 as S1 lands; S6 as soon as the owner answers; S10.
3. **Wave C:** S8, S12, then S11.
4. **Integration:** a `slice1` branch that builds everything in CI; the signet runs (twice, from a clean start) and the recorded walkthrough.

## Rules for this phase

- Every piece is built against a reviewed specification and reviewed independently before merge; nothing merges with CI red or missing.
- Builds, tests, mutation runs and clones happen on the build server or in GitHub Actions, never on a personal computer.
- Work on the build server that predates the history rewrite is replayed onto the rewritten history before pushing; no IP address or local path is ever committed (CI checks this).
