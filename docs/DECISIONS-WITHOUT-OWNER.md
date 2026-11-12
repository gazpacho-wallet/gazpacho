# Decisions made without the owner

Every choice the coordinator or a builder made on the owner's behalf that the owner should be able to overrule. Started 2026-11-12 (truth pass). The owner's own decisions are in `ux/decisions.md`; questions still waiting for an answer are in `OPEN-QUESTIONS.md`.

**To overrule one,** say which and what instead. The document named in the "Where" column is then changed, with the owner's answer recorded in `ux/decisions.md`, and any code that follows it is changed in its own pull request. Nothing here is settled by being written down.

**Keep it current.** A builder or reviewer who decides something a specification left open adds a row here in the same pull request. A row leaves this file when the owner confirms or overrules it; it moves to "Answered" at the end.

## 1. Made by the coordinator

| # | Decision | Where it is written | What it affects | What overruling would change |
|---|---|---|---|---|
| K1 | **Chain lag limits: 3 blocks and 30 minutes.** Two chain servers that disagree count as "one is lagging" only while the disputed item lies above the lower server's tip, the tips are at most 3 blocks apart on one chain, and the lag has lasted at most 30 minutes; beyond either limit it is a disagreement, and the answer is refused | `docs/notes/chain-port.md` section 12 item 2; `GZ_MULTI_LAG_MAX_BLOCKS` and `GZ_MULTI_LAG_MAX_MS` in `ports/chain/include/gazpacho/chain_multi.h` | Every confirmation and coin lookup the wallet makes. Set after round 2 of the review of PR 7, which asked for some bound and named none. Round 3 notes the 3-block limit is the one that binds, and that with three operators one stalled honest server then blocks deep confirmations | Other numbers; or the follow-up round 3 proposed (a server far behind counts as no reply) |
| K2 | **Slice 1 builds no locked watcher.** In Slice 1 a locked wallet watches nothing; no watch-and-exit bundle is written | `spec/local-api.md` 24.1 D17 and the `no_bundle` reason ("every Slice 1 build"); `spec/storage-encryption.md` E-D13 ("Not built in Slice 1") | Slice 1 members hold no balance, so nothing is at risk on signet; the watcher arrives in 1.0.0. Answers item R11 of the local API's draft-3 review | Build the watcher in Slice 1, which adds the bundle, the penalty file and the OS key store to Slice 1's work |
| K3 | **A damaged penalty file keeps the watcher running.** A short, damaged or unrecognised penalty file is used for what it holds; the watcher goes on, showing `watcher_locked` with reason `penalty_file_short` (`at_risk`). Only a refused bundle stops it (`nobody_locked`) | `spec/exit.md` and `spec/storage-encryption.md`, "Changes after cross-spec review 1", item D1 | 1.0.0 (no watcher in Slice 1). The alternative stops all watching because some answers are missing | Stop the watcher when the penalty file is damaged |
| K4 | **Invitation-only lobbies, seat removal and standby seats are built in Slice 1.** Owner decision 10 names them for 1.0.0; the coordinator brought them into Slice 1 | `docs/notes/lobby.md` decisions 1, 6 and 7, on the lobby branch (build server only) | The lobby engine's states and `messages.md` 6.3 (standby joins are accepted during a ready check and during signing, which 6.3 does not yet allow) | Leave them for 1.0.0; Slice 1's lobby becomes simpler |
| K5 | **The dedication keeps "people".** `DEDICATION.md` dedicates Gazpacho "to the people who paid for our freedom to hold our own keys" | `DEDICATION.md` line 3 | The wording in the repository and, later, in the wallet's About page. **Inconsistent today:** `ux/decisions.md` decision 7 quotes the first-run line as "dedicated to the developers who paid …" | Use "developers" in `DEDICATION.md`, or "people" in decision 7's first-run line |
| K6 | **Leaving alone always goes ahead, even with a move unfinished.** A move or close round left Unfinished past its unfinished deadline is itself a trigger to leave alone; an unfinished move never holds the exit back | `spec/exit.md` section 5.1, trigger `round_unfinished`; `spec/safety-rule.md` 4.1 rule 5 | Slice 3 and 1.0.0 (Slice 1 members are owed nothing, so the automatic exit does not run) | Wait for the move to finish or fail first, at the risk of missing `leave_by` |
| K7 | **Journal record type numbers assigned** for the exit and watch records (areas 0x0007 and 0x0008) and for the local API's saved state (new area 0x000d, all even) | `spec/journal.md` "Changes after cross-spec review 1" and section 9.1 | Closes Slice 1 input W3 for the type numbers; the field numbers inside each record are still open. Area 0x000d is still to be added to `spec/PROTOCOL.md` 10.4 | Other numbers, before any journal is written with them |
| K8 | **The name "T1-long"** for the longer test terms (lifetime 144 blocks, wind-down 252), not "T3", which is a vector name in `terms.md` | `spec/exit.md` section 12, open point 1 | Slice 3 tests of rotation with a balance | Another name |

## 2. Made by the lobby engine's builder

Written in `docs/notes/lobby.md` section 2 on the `lobby` branch, which exists only on the build server today (`SLICE1-WORK.md`). The note says itself that nothing in it overrides a specification. In short:

1. Standby seats accept joins during a ready check and during signing (changes `messages.md` 6.3; K4).
2. Signing and verifying go through a port; the engine holds no key and has its own SHA-256.
3. Inputs are whole Lightning messages; "refuse" is a BOLT 1 `warning` followed by a close notice.
4. The hand-off to the signing engine: `begin` and `cancel`, with the outcome reported back.
5. A join refused as invalid gets seat state 7 with reason 5 (a reused code); one refused because the lobby is closed, full or limited gets no reason, and the member retries every 1.5 s, at most 30 times per connection.
6. Invitation-only means the lobby is never named in answers to scope-zero `hello` (K4).
7. A host may remove a seat while Open and during a ready check, never after signing begins; a removed key cannot join again (K4).
8. A ready check is not resumed after a host restart.
9. The start rule counts seats Ready for the latest values and connected now.
10. `lobby_status` goes to a seat only when it changes, at most once a second.
11. A member resends its saved `join` and `ready` when the host has lost them, at most three times per connection.
12. Slice 1 sizes: at most 32 seats and 48 connections per host; saved `ready`, `start` and `ready_check` at most 256 bytes.
13. Any error from an engine call stops the node, which is rebuilt from storage.
14. The 4 × target creation limit counts every seat ever created, rejoins included, across restarts.
15. A user's unready is kept until the user sets conditions again.
16. A member that left is told nothing more and does not rejoin that lobby.

## 3. Made by other builders, in tables of their own

Each table is the list to read; this section says where they are and which entries matter most.

| Source | What it holds | The entries the owner is most likely to want to see |
|---|---|---|
| `docs/notes/chain-port.md` section 12 (13 decisions) | The chain view's rules where the documents were silent | No majority vote (one well-formed contradiction blocks); the lowest tip is the agreed tip; operators taken from host names unless named; fees fixed at 0.1 sat/vB on test networks, and on mainnet the lowest estimate with a factor-3 disagreement rule and a caller's ceiling; at most 144 headers followed; plain http only for this machine's own names |
| `docs/notes/wallet-tx.md` section 5 (12 decisions) | The wallet transaction library | Funding at output 0 and change at 1, always (which reveals the change); no anti-fee-sniping lock time; largest-first coin selection, not privacy-minded; signing at release only; a rate of 0 refused |
| `spec/transport.md`, "Decisions where BOLT 8, BOLT 1 and our documents are silent" (12) | The transport | Confirmed by both reviews of PR 10, and the owner counted that review (questions 6, Q9). Still open by design: how the host stops one silent peer from stalling it (a step-wise handshake, or capped threads or processes) |
| `spec/storage-encryption.md` section 1 (E-D1 to E-D13) | The encryption of every file | The cryptography choices (Argon2id at 256 MiB and 3 passes, 1 GiB and 4 for exports; XChaCha20-Poly1305; libsodium; a passphrase of at least 15 characters with six generated words offered; the export carries the 24 words only if chosen). **They await the owner's yes, and stream S6 waits for it** |
| `spec/local-api.md` 24.1 (D2 to D20) | Defaults Slice 1 builds against, "for the owner's yes" | Idle sign-out 15 minutes (D3); `join` and `ready` need no fresh sign-in (D4); the passphrase in every payment request (D5); the words check limits (D8); the words shown until Done with a 10-minute ceiling and no copy (D9); password managers may fill the passphrase (D14); passphrase attempt delays (D15); lock refused while hosting an Open lobby (D20). D1 is answered (owner decision 12) |
| `spec/exit.md` section 12 (16 open points with recommendations) | Leaving alone and watching | H17 (honest host software forces a member out by `host_force_by` rather than taking a balance by timeout); a restored member never publishes its commitment automatically; fee budget 25% of the recovered amount, 90% once a step is late; `UNPROTECTED_MAX` 1% of the channel and 10,000 sat; one broadcast-only endpoint. All recommended "adopt"; none confirmed by the owner |
| The "Changes" tables at the top of `spec/safety-rule.md`, `signing-round.md`, `messages.md`, `terms.md`, `journal.md`, `local-api.md`, `storage-encryption.md`, `exit.md`, `discovery.md` | How each review finding was answered | Mostly corrections. Choices of policy among them: Slice 1 aborts whole rounds only (`signing-round.md`, F14); the member's placement in the tree fixed at the import's value 0 and never sent (`signing-round.md` 4.1, F5); a deterministic last-signer nonce recorded but not adopted (`signing-round.md` 17); a step timeout of at least 60 s, twice the keep-alive (`terms.md` 3, F11); limits on seat changes per seat and per connection (`messages.md` 6, F13); a sync mark after every successful sync, and an invalid entry before it treated as corruption that refuses the start (`journal.md`, F2) |

## 4. Answered by the owner (kept for the record)

- The Slice 1 values marked "proposed, owner to confirm" in the safety rule, the signing round, the terms and the messages (open items A1 to A8): accepted in questions 6 (Q1 and Q2, answer A).
- The member's starting limits (W1): the small-lobby values, questions 6, Q3.
- Counting the transport's code review as its specification review (A12): questions 6, Q9.
- The defaults of questions 6, Q7 (ports 39735 and 39736, one optional tunnel port, sign-in with the wallet passphrase) and Q8 (one lobby at a time in Slice 1, limits editable).

See `OPEN-QUESTIONS.md` for the full answers and what each still leaves open.
