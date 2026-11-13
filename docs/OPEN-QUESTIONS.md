# Open questions

Kept current. Rewritten 2026-11-12 after the gap review; the owner's answers to questions 6 recorded the same day (section 0). Choices made on the owner's behalf, which the owner may overrule, are listed in `DECISIONS-WITHOUT-OWNER.md`.

What was removed, because it is answered:

- The threat model, the host terms record and the message specification now exist (`THREAT-MODEL.md`, `spec/terms.md`, `spec/messages.md`). The two first specifications have had three reviews and a confirmation (`reviews/README.md`).
- Timed levels in 1.0.0 (old O1): none. 1.0.0 trees are advanceless (owner decision 9, `ux/decisions.md`).
- The on-chain reserve against timed levels (old O2): not needed, since there are no timed levels in 1.0.0.
- Seat cost (old O5): free in 1.0.0, then a proof, then per-lobby options (owner decision 10).
- The precise safety rule and the signing round specification (old 5 and 6): `spec/safety-rule.md` and `spec/signing-round.md`.
- Raising the 256-member limit (old 5c): SuperScalar accepted it; it is tracked in `handoff/README.md`.

Numbering is new. A document citing an old number ("item 18", "O1") means the list as it stood before this date.

## 0. Questions 6: the owner's answers (2026-11-12)

`questions-6-blocking.html` asked only what blocked the first factory: nine questions, each with a recommendation. The owner's answers, with the owner's notes in short and what each leaves to do:

| Q | Question | Answer | Decided? | What it still leaves |
|---|---|---|---|---|
| 1 | Keep the end-date payout and the friendly close out of Slice 1 (A1, A2) | **A**: leave both out | **Yes** | The owner's notes: add them later and get them right, learning from SuperScalar's work; test every deferred feature end to end in a **Slice 1.5**; research every path a factory can take (cooperative, unilateral, timeout, payout, host vanishes, member vanishes, and more) and what SuperScalar's tooling tracks, before proceeding. The Slice 1.5 list is not written yet |
| 2 | The timing numbers for the test factory (A3 to A8) | **A**: accept the proposed set | **Yes**, for Slice 1 | Mainnet numbers get their own decision |
| 3 | A member's starting limits (W1) | **A**: the small-lobby values | **Yes** | Not yet written into `spec/terms.md` |
| 4 | Which fees a host may charge in 1.0.0 (A9) | **A**: a per-payment fee plus an optional flat joining fee | **Yes**, as the direction | The owner wants every option researched: from a payment to the host up to the host taking all the channel fees it sets, possibly limited by the rule sets; a default where the host takes all channel fees or splits a share with the member whose coins were used; SuperScalar's modes and splits; what our rules can enforce, and how; Soup. The fee-models research is not written yet |
| 5 | The key path for each factory (W2) | No answer; the owner leans to **A** (a branch of its own in the standard key tree) and asked why it is an issue | **No** | Explained in chat; work proceeds with A unless the owner objects. Still needs the owner's yes after the review of the written recipe |
| 6 | Files unencrypted on test networks | **B**: encrypt from the start | **Yes** | Owner decision 13; `spec/storage-encryption.md`. The cryptography choices themselves still await the owner (`DECISIONS-WITHOUT-OWNER.md`) |
| 7 | How the wallet's screens are opened | **A**, plus one optional extra port for a tunnel | **Yes** | The owner's note: sign-in should be like any professional wallet, such as Sparrow; so sign-in became the wallet passphrase (owner decision 14). Ports 39735 and 39736 |
| 8 | One lobby at a time; changing limits while waiting | **A**: one at a time in Slice 1, limits stay editable | **Yes**; the lobby limit was replaced on 2026-11-13 by several lobbies at once (section 0a) | The owner's note: any skipped feature must be tested later, so do not skip too much. A ledger of deferred features, each with its later test, is owed (with Slice 1.5) |
| 9 | Count the transport's code review as its specification review (A12) | **A** | **Yes** | The owner's note: re-review the transport specification fully once the program is built, possibly as a separate review then |

## 0a. The owner's decisions of 13 November (2026-11-13)

Recorded in full as decision 16 in `ux/decisions.md`. In short:

- Host funding is automatic and on by default once H1 passes. Before real money it becomes a setting that still defaults to automatic.
- Several lobbies at once per wallet from Slice 1. This replaces Q8's answer above. Every lobby record carries a lobby field; the composite node design is PR 37.
- Host accountability in 1.0.0: signed seat receipts, the signer-choice rule in the outer terms, signed removals with a reason, signed lobby-wide counts without identities. Proofs on Nostr later, from fresh keys, after the lobby ends.
- Member signing modes A to D. Understudies in 1.1.0. A UI/UX review pass after 1.0.0. A privacy roadmap from Slice 1 to later releases.

Still for the owner to confirm:

- **Mode C as the default** signing mode.
- **The proposed timing defaults:** a 60 s ready window, 60 s per step, a 10-minute signing budget.

Still to research: mode D (watchtower services).

## 1. Awaiting the owner's yes

Values that a specification or design document marks **proposed, owner to confirm**. Builders may use them; none is settled until the owner says yes. The questionnaire `questions-5-decisions.html` covers most of them: open it, pick Keep, Change or Discuss for each item, and paste the answers back.

| # | Proposed value | Where it is marked | State |
|---|---|---|---|
| A1 | Slice 1 signs no end-date distribution transaction; a member refuses a proposal that carries one | `spec/safety-rule.md` section 12 (1) and the table in section 3; `spec/signing-round.md` sections 4.1, 5 and 15 (1); `spec/messages.md` record 44 and open point 14 | **Decided** (questions 6, Q1, A). The documents still say "proposed" |
| A2 | The host gets its signet coins back through a short factory life and its own timeouts; no cooperative close round in Slice 1 | `spec/safety-rule.md` section 12 (2); `spec/signing-round.md` section 15 (2); `spec/PROTOCOL.md` section 5 ("owner decision open") | **Decided** (questions 6, Q1, A) |
| A3 | Example factory life in T1: 144 blocks plus 36 of wind-down | `spec/terms.md` section 11 (T1) and open point 8 | **Decided** for Slice 1 (questions 6, Q2, A) |
| A4 | Burial depth 3 blocks on signet, seen by both chain servers | `spec/safety-rule.md` section 12 (3); `spec/signing-round.md` section 15 (3) | **Decided** for Slice 1 (Q2) |
| A5 | Funding deadline 36 blocks after the member's `round_ack` | `spec/safety-rule.md` section 12 (4); `spec/signing-round.md` section 15 (4); `spec/journal.md` open point 6 | **Decided** for Slice 1 (Q2) |
| A6 | Unfinished deadline: one signing budget after the member's partial signatures | `spec/safety-rule.md` section 12 (5); `spec/signing-round.md` section 15 (4); `spec/journal.md` open point 6 | **Decided** for Slice 1 (Q2) |
| A7 | Confirmation allowance 6 blocks per transaction plus a 6-block margin, for Slice 1's exit-time check | `spec/safety-rule.md` section 12 (6) | **Decided** for Slice 1 (Q2) |
| A8 | Layer step 144 blocks and 4 states fixed in every Slice 1 proposal | `spec/messages.md` "Changes" table and section 7.2 | **Decided** for Slice 1 (Q2) |
| A9 | Fees in 1.0.0: a per-payment fee (base plus proportion) and an optional joining fee taken from the first payment received | `DESIGN.md` section 12; `PLAN.md` "Releases"; `KNOWLEDGE-BASE.md` section 5; `ux/decisions.md` 2 | **Decided as the direction** (questions 6, Q4, A); the owner asked for research on every fee model (section 0) |
| A10 | The dedication in the wallet: About > Dedication, Credits, Licences; one first-run line; one line under `gazpacho --version` | `ux/decisions.md` 7; `PLAN.md` "Work list" | Open. Answer directly. Note the wording differs between `DEDICATION.md` ("people") and decision 7 ("developers") (`DECISIONS-WITHOUT-OWNER.md` K5) |
| A11 | Discovery: the beacon price (`unit` / 4, channels 144 blocks old); a withdrawal is final even for the host; Nostr kinds 153 and 155, with 159 reserved | `spec/discovery.md` open points 3, 4 and 8 | Open (in questions 5: price and withdrawal yes; the kinds no) |
| A12 | The transport specification's draft 2 counts as reviewed (the round-2 code review read it in full), its decisions 1 to 12 are confirmed, and the review-after-code is recorded as an exception to checklist item 1 | `spec/transport.md`; `reviews/review-pr10-transport-r2.md` | **Decided** (questions 6, Q9, A). The owner asks for a full re-review once the program is built |

A1 to A8 are decided, but the specifications still mark them "proposed, owner to confirm"; that wording is to be changed at their next revision.

## 2. Slice 1 inputs not yet written

Slice 1 cannot be finished without these. Each needs a short text, then the owner's yes.

| # | What is missing | Why Slice 1 needs it | Where it belongs |
|---|---|---|---|
| W1 | **The member's default conditions** for Slice 1. **Decided** (questions 6, Q3, A), the small-lobby values: fewest members 3; smallest channel 50,000 sat; joining fee at most 2,000 sat; payment fee at most 1,000 msat plus 2,500 per million; factory life at most 8,640 blocks; leaving alone at most 1,008 blocks; these become the Everyday preset, every number visible and editable. **Not yet written** where it belongs | `SLICES.md` "done when": a member whose conditions are not met is seen to refuse. Without defaults there is nothing to refuse against (confirmation review, S1-5) | `spec/terms.md` section 9, or a short wallet specification |
| W2 | **The key derivation path** per lobby, for the contribution key and the factory key. Its inputs are settled: seed, restore epoch (31 bits, a hardened index) and key index. **Not decided:** the owner gave no answer in questions 6 (Q5), leaning to a branch of its own in the standard key tree; work proceeds on that unless the owner objects | Every member derives these keys; two builds must agree | The wallet specification (`spec/messages.md` open point 3) |
| W3 | **The field numbers inside each journal record type**. The record **type** numbers of the local API's saved state (`spec/local-api.md` 7.5) and of the exit records are now assigned (`spec/journal.md` 9.1, after cross-spec review 1), so W3 is closed for those type numbers; the field numbers remain | The journal cannot be written without them | `spec/journal.md` open point 3, fixed with the engine's code tables |

Also missing, but not a decision: test vectors for the round identifier and the tree digest. The first implementation will be its own reference unless they are written first (confirmation review, S1-4).

## 3. Other questions for the owner

| # | Question | Blocks |
|---|---|---|
| Q1 | ~~Does Slice 1's "done when" need the screens?~~ **Answered by owner decision 11** (2026-11-12): yes, every Slice 1 action goes through the interface; there is no slice 1b. The local API is specified (`spec/local-api.md`, draft 4); its server is not built | — |
| Q2 | **Which release is the demo wallet?** `spec/discovery.md` section 18 says the signet demo ships Nostr listings with anchors; Slice 1 has no listings at all | Discovery work order |
| Q3 | **Platforms for 1.0.0:** Linux only, or Windows and macOS too, and when phones. The owner's machine runs Windows; nothing builds there today | CI, the outer pieces |
| Q4 | **A release for each of these,** none of which has one: backups, export and restore; host concurrency (the transport's blocking accept, choice between a step-wise handshake and capped threads or processes); package relay for exits | 1.0.0 scope |
| Q5 | **Legal advice before anyone hosts on mainnet** (money-transmission and similar law, for the project and for hosts). Prosecutors in the Samourai case treated developers of non-custodial software as money transmitters. The dedication names people convicted or charged in such cases; that belongs on the same list. Gazpacho gives no legal advice (`PLAN.md`, steps towards real funds) | Mainnet hosting |
| Q6 | **Proposing bLIP-56 amendments** (an odd message type, taproot nonces, no "forget a channel" without evidence). Nothing is posted without the owner's permission | The standard path only |
| Q7 | **Phones and the signing window.** A phone must have the app open during the signing window to move into a new factory. Is a companion device (an always-on machine the member owns, signing within the member's conditions) the answer, and when? | Rotation on phones |
| Q8 | **Numbers for the lobby:** largest lobby, default gathering time, signing timers. Recommended: settle from signet testing. (Slice 1's one-lobby-at-a-time rule is decided, questions 6, Q8; encryption at rest is decided, from the start, owner decision 13) | Release defaults |
| Q9 | **Who besides the owner can approve a SIP,** and who the maintainers are | The SIP process |
| Q10 | **Is the security catalogue from the earlier SuperScalar work copied into this repository** as reference, or left where it is? | Nothing |

## 4. For this project to settle (research or build)

- **Lightning's standard taproot channel on an off-chain funding output that moves.** The decision rests on secondary sources. Groundwork from the specification: `research/channel-groundwork.md`. `spec/channel.md` is not written.
- **Package relay through public chain servers.** A forced exit needs a parent and child accepted together. Package submission was not available on the public Electrum servers found (`research/channel-groundwork.md` 1.9). Without it, Slice 3 needs a node of our own, against the owner's "no node for now".
- **The transport against the message specification.** `spec/messages.md` section 2 requires `init`, a ping every 15 s of silence and a close at 30 s without a pong. The transport (on `main` since PR 10) has none of these and cuts any connection idle for 30 s. A lobby gathers for hours. Stream S7 (`SLICE1-WORK.md`), not started.
- **The core contract** lacked four things every Slice 1 specification requires: a secret-tagged randomness request, watch a txid to a depth, watch an outpoint, a restore marker (`spec/signing-round.md` 12.1). Built in PR 21 (a draft stacked on PR 9, CI red), not merged.
- **The message codec generator.** `DESIGN.md` section 8 plans encoders generated from tables; none exists. Build it before the lobby and round codecs, or drop the plan.
- **Builds beyond Linux.** CI has gcc and clang (with ASan, UBSan and MemorySanitizer) on Linux only; no Windows, no macOS (`TESTING.md`).
- **Long runs.** No nightly job; long runs happen only when someone starts them (`TESTING.md`).
- **The table of tree shapes by size** for 1.0.0, where every level is fixed: depth and exit time for each size up to 512.
- **The timelock and deadline numbers** for advanceless trees, and the channel's revocation delay, which now sets safe absence (to be fixed in the channel specification).
- **The proof-of-fault scheme** in `spec/signing-round.md` is our own design and needs an expert review.
- **MuSig2 test vectors** (BIP 327) are not run anywhere yet; the signing engine needs them.
- **Holding payments open** on Eclair, LDK-based nodes and Nostr Wallet Connect.
- **A host proof of funds** sized to the lobby it advertises.
- **Whether members can prove past participation,** and at what cost to privacy.
- **Acting while the member is away:** pre-signed responses, unattended signing, hardware devices (`AWAY.md`).
- **Adding a member's own coins to their leaf** in a live factory: needs a proper review.
- **Waking members who are offline** when a factory rotates.
- **The default chain-server list for release.** Signet and testnet4 each have two operators now (`CHAIN-SERVERS.md`); the operators' terms have not been read.

## 5. Waiting on the SuperScalar repository

Work Gazpacho deliberately does not do itself: it waits, re-imports when the change lands, and checks the result. Every request, its state and the check to run when it lands are in **`handoff/README.md`**.

In short, as of 2026-11-12: SuperScalar has merged the advanceless default (our request, their #494), members claiming the end-date payout without the host (#487), rotation off by default (#488, because it hands members' secret keys to the host), eight tree-builder fixes (#486) and others. Still open there: tree fees (#476), the HTLC success-path claim (#474) and the rotation-safety stack (#470 to #473). **Gazpacho's import (pinned `e657395`) predates all of it**, so no check has started; the re-import is stream S12 (`SLICE1-WORK.md`). `handoff/README.md` has not yet been updated for these merges.
