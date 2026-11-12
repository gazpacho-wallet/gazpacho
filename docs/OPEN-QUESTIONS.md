# Open questions

Kept current. Rewritten 2026-11-12 after the gap review.

What was removed, because it is answered:

- The threat model, the host terms record and the message specification now exist (`THREAT-MODEL.md`, `spec/terms.md`, `spec/messages.md`). The two first specifications have had three reviews and a confirmation (`reviews/README.md`).
- Timed levels in 1.0.0 (old O1): none. 1.0.0 trees are advanceless (owner decision 9, `ux/decisions.md`).
- The on-chain reserve against timed levels (old O2): not needed, since there are no timed levels in 1.0.0.
- Seat cost (old O5): free in 1.0.0, then a proof, then per-lobby options (owner decision 10).
- The precise safety rule and the signing round specification (old 5 and 6): `spec/safety-rule.md` and `spec/signing-round.md`.
- Raising the 256-member limit (old 5c): SuperScalar accepted it; it is tracked in `handoff/README.md`.

Numbering is new. A document citing an old number ("item 18", "O1") means the list as it stood before this date.

## 1. Awaiting the owner's yes

Values that a specification or design document marks **proposed, owner to confirm**. Builders may use them; none is settled until the owner says yes. The questionnaire `questions-5-decisions.html` covers most of them: open it, pick Keep, Change or Discuss for each item, and paste the answers back.

| # | Proposed value | Where it is marked | In questions 5 |
|---|---|---|---|
| A1 | Slice 1 signs no end-date distribution transaction; a member refuses a proposal that carries one | `spec/safety-rule.md` section 12 (1) and the table in section 3; `spec/signing-round.md` sections 4.1, 5 and 15 (1); `spec/messages.md` record 44 and open point 14 | Yes |
| A2 | The host gets its signet coins back through a short factory life and its own timeouts; no cooperative close round in Slice 1 | `spec/safety-rule.md` section 12 (2); `spec/signing-round.md` section 15 (2); `spec/PROTOCOL.md` section 5 ("owner decision open") | Yes |
| A3 | Example factory life in T1: 144 blocks plus 36 of wind-down | `spec/terms.md` section 11 (T1) and open point 8 | Yes |
| A4 | Burial depth 3 blocks on signet, seen by both chain servers | `spec/safety-rule.md` section 12 (3); `spec/signing-round.md` section 15 (3) | Yes |
| A5 | Funding deadline 36 blocks after the member's `round_ack` | `spec/safety-rule.md` section 12 (4); `spec/signing-round.md` section 15 (4); `spec/journal.md` open point 6 | Yes |
| A6 | Unfinished deadline: one signing budget after the member's partial signatures | `spec/safety-rule.md` section 12 (5); `spec/signing-round.md` section 15 (4); `spec/journal.md` open point 6 | Yes |
| A7 | Confirmation allowance 6 blocks per transaction plus a 6-block margin, for Slice 1's exit-time check | `spec/safety-rule.md` section 12 (6) | Yes |
| A8 | Layer step 144 blocks and 4 states fixed in every Slice 1 proposal | `spec/messages.md` "Changes" table and section 7.2 | Yes |
| A9 | Fees in 1.0.0: a per-payment fee (base plus proportion) and an optional joining fee taken from the first payment received | `DESIGN.md` section 12; `PLAN.md` "Releases"; `KNOWLEDGE-BASE.md` section 5; `ux/decisions.md` 2 | No (it is in decision 2, which questions 5 leaves out). Answer directly |
| A10 | The dedication in the wallet: About > Dedication, Credits, Licences; one first-run line; one line under `gazpacho --version` | `ux/decisions.md` 7; `PLAN.md` "Work list" | No. Answer directly |
| A11 | Discovery: the beacon price (`unit` / 4, channels 144 blocks old); a withdrawal is final even for the host; Nostr kinds 153 and 155, with 159 reserved | `spec/discovery.md` open points 3, 4 and 8 | Price and withdrawal yes; the kinds no |
| A12 | The transport specification's draft 2 counts as reviewed (the round-2 code review read it in full), its decisions 1 to 12 are confirmed, and the review-after-code is recorded as an exception to checklist item 1 | `spec/transport.md` on branch `transport`; `reviews/review-pr10-transport-r2.md` | No. Answer directly |

The safety rule's own list (section 12) says the owner has not objected to any of A1 to A7.

## 2. Slice 1 inputs not yet written

Slice 1 cannot be finished without these. Each needs a short text, then the owner's yes.

| # | What is missing | Why Slice 1 needs it | Where it belongs |
|---|---|---|---|
| W1 | **The member's default conditions** for Slice 1: the limits a member signs within when the user has set none | `SLICES.md` "done when": a member whose conditions are not met is seen to refuse. Without defaults there is nothing to refuse against (confirmation review, S1-5) | `spec/terms.md` section 9, or a short wallet specification |
| W2 | **The key derivation path** per lobby, for the contribution key and the factory key. Its inputs are settled: seed, restore epoch (31 bits, a hardened index) and key index | Every member derives these keys; two builds must agree | The wallet specification (`spec/messages.md` open point 3) |
| W3 | **The field numbers inside each journal record type**. The record **type** numbers of the local API's saved state (`spec/local-api.md` 7.5) and of the exit records are now assigned (`spec/journal.md` 9.1, after cross-spec review 1), so W3 is closed for those type numbers; the field numbers remain | The journal cannot be written without them | `spec/journal.md` open point 3, fixed with the engine's code tables |

Also missing, but not a decision: test vectors for the round identifier and the tree digest. The first implementation will be its own reference unless they are written first (confirmation review, S1-4).

## 3. Other questions for the owner

| # | Question | Blocks |
|---|---|---|
| Q1 | **Does Slice 1's "done when" need the screens?** `SLICES.md` puts the local web interface in Slice 1's needs. The local API is not specified and no server exists. If not, the screens become a slice 1b | Slice 1's scope |
| Q2 | **Which release is the demo wallet?** `spec/discovery.md` section 18 says the signet demo ships Nostr listings with anchors; Slice 1 has no listings at all | Discovery work order |
| Q3 | **Platforms for 1.0.0:** Linux only, or Windows and macOS too, and when phones. The owner's machine runs Windows; nothing builds there today | CI, the outer pieces |
| Q4 | **A release for each of these,** none of which has one: backups, export and restore; encryption at rest; host concurrency (the transport's blocking accept, choice between a step-wise handshake and capped threads or processes); package relay for exits | 1.0.0 scope |
| Q5 | **Legal advice before anyone hosts on mainnet** (money-transmission and similar law, for the project and for hosts). Prosecutors in the Samourai case treated developers of non-custodial software as money transmitters. The dedication names people convicted or charged in such cases; that belongs on the same list. Gazpacho gives no legal advice (`PLAN.md`, steps towards real funds) | Mainnet hosting |
| Q6 | **Proposing bLIP-56 amendments** (an odd message type, taproot nonces, no "forget a channel" without evidence). Nothing is posted without the owner's permission | The standard path only |
| Q7 | **Phones and the signing window.** A phone must have the app open during the signing window to move into a new factory. Is a companion device (an always-on machine the member owns, signing within the member's conditions) the answer, and when? | Rotation on phones |
| Q8 | **Numbers for the lobby:** largest lobby, default gathering time, signing timers. Recommended: settle from signet testing | Release defaults |
| Q9 | **Who besides the owner can approve a SIP,** and who the maintainers are | The SIP process |
| Q10 | **Is the security catalogue from the earlier SuperScalar work copied into this repository** as reference, or left where it is? | Nothing |

## 4. For this project to settle (research or build)

- **Lightning's standard taproot channel on an off-chain funding output that moves.** The decision rests on secondary sources. Groundwork from the specification: `research/channel-groundwork.md`. `spec/channel.md` is not written.
- **Package relay through public chain servers.** A forced exit needs a parent and child accepted together. Package submission was not available on the public Electrum servers found (`research/channel-groundwork.md` 1.9). Without it, Slice 3 needs a node of our own, against the owner's "no node for now".
- **The transport against the message specification.** `spec/messages.md` section 2 requires `init`, a ping every 15 s of silence and a close at 30 s without a pong. The transport (branch `transport`) has none of these and cuts any connection idle for 30 s. A lobby gathers for hours.
- **The core contract** lacks four things every Slice 1 specification requires: a secret-tagged randomness request, watch a txid to a depth, watch an outpoint, a restore marker (`spec/signing-round.md` 12.1). Assigned (`SLICE1-WORK.md`).
- **The message codec generator.** `DESIGN.md` section 8 plans encoders generated from tables; none exists. Build it before the lobby and round codecs, or drop the plan.
- **Builds beyond Linux with one compiler.** No clang, no Windows, no macOS in the automated checks (`TESTING.md`).
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

In short, as of 2026-11-12: round 1 (tree fees, their pull request 476, plus four tree-builder fixes) and their pull request 486 (requests 3 to 6 and 10 of 12 November) are in progress; round 2 (the end-date payout) has a draft specification that Gazpacho reviewed; the advanceless default is agreed in principle. Nothing has landed in Gazpacho's import yet, so no check has started.
