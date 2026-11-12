# Open questions

Kept current. Last updated 2026-11-12, after the ideas ledger of that day.

## For the owner

1. **Numbers for the lobby:** largest lobby, default gathering time, signing timers, number of signing attempts. Recommended: settle from signet testing.
2. **Who besides the owner can approve a SIP.**
3. **Review of the two drafted specifications** (`spec/`): the open points at the end of each, and an expert look at the proof-of-fault scheme.
4. **Is the full security catalogue from the earlier SuperScalar work copied into this repo** as reference, or left where it is?

5c. **Raising the 256-member limit** in the shared files toward the 512 target: confirm it is work for the SuperScalar repository now. (Requested as E3 and E4 in `handoff/2026-11-12-to-superscalar.md`.)

Added 2026-11-12. "Blocks" says what cannot finish until the question is answered.

| # | Question for the owner | Blocks |
|---|---|---|
| O1 | **Timed levels in 1.0.0.** The safety rule's reasoning (`spec/safety-rule.md` section 8 and open point 1, from draft 3) is that nothing in 1.0.0 updates a timed layer, so a timed layer can cause no loss, only a longer exit. That reasoning has not been checked against the design posts. Decide how many timed levels 1.0.0 uses; before relying on the reasoning, verify it by a simulator test and against the posts | The shape table (5d); payment deadlines; 1.0.0 |
| O2 | **On-chain reserve against timed levels.** "No on-chain reserve in 1.0.0" (decision 6) conflicts with O1 if a member could ever need fee coins to win a race at a timed level. The conflict goes away if 1.0.0 makes no timed-layer updates. Confirm that 1.0.0 makes none, or revisit the reserve | 1.0.0 |
| O3 | **Legal advice before anyone hosts on mainnet.** Whether to take a lawyer's advice, for the project and for hosts, on money-transmission and similar law before mainnet hosting is switched on. Prosecutors in the Samourai case treated developers of non-custodial software as money transmitters. Gazpacho does not give legal advice and makes no claim either way (`PLAN.md`, steps towards real funds) | Mainnet hosting; not signet work |
| O4 | **Proposing bLIP-56 amendments** (an odd message type, taproot nonces, no "forget a channel" without evidence). Needs the owner's permission before anything is posted | Nothing in Slice 1; the standard path (`PLAN.md`) |
| O5 | **Seat cost.** Seats are free, so one peer can exhaust the host's seat creations and stall a lobby (a liveness weakness, `spec/messages.md` limits). Decide whether a seat costs something (a small payment, a proof, a deposit) and when | Public listed lobbies beyond Slice 1; links to the lobby deposit (issue 3) |
| O6 | **Phones and the signing window.** A phone must have the app open during the signing window to move into a new factory. Is a companion device (an always-on machine the member owns that signs within the member's conditions) the answer, and when? To research with mobile | Rotation on phones; mobile release |

## For this session to settle (research or build)

Found in the plan review of 2026-11-11:

- **Can Lightning's standard taproot channel format be used when the channel's funding output is off chain and moves?** The decision to use it rests on secondary sources. Groundwork from the specification itself is under way (`notes/channel-groundwork.md`, local).
- **Can a whole exit path be confirmed through public chain servers?** A forced exit publishes a chain of pre-signed transactions with small built-in fees and a fee-paying child. That needs the server to accept a parent and child together. Not yet checked for the public servers we use. Without it, slice 3 needs our own node.
- **A threat model** does not exist as a document. One is being drafted with the specification review.
- **The host's terms record** (what Soup called the policy) has no specification, and the lobby and the signing round both need it.
- **The message specification** has to exist before the signing engine sends anything.
- **Builds other than Linux with one compiler.** The goal is that anyone can run it, and the owner's machine runs Windows. A second compiler and a Windows build should be in the automated checks before the outer pieces grow.
- **Long test runs happen only when an agent chooses to run them.** A nightly run on the build server, with results kept, is not set up.
- **How many timed levels each factory size uses** (each costs three days of exit time): needs the owner.


5d. **The table of tree shapes by size** that a host's terms may use, given the shape rules in `DESIGN.md` section 7, and how many timed levels the first release uses at each size (each costs 3 days of exit delay and 3 days of payment deadline).

5. The precise definition of the member's safety rule.
6. The signing round specification: messages, states, timers, and the proof of who broke a round. The proof scheme is our own reasoning and needs expert review.
7. The timelock and deadline numbers for the full layered tree.
8. Lightning's taproot channel format: confirm status and details against the specification itself.
9. Holding payments open on Eclair, LDK-based nodes and Nostr Wallet Connect.
10. A host proof of funds sized to the lobby it advertises.
11. Whether members can prove past participation, and at what cost to privacy.
12. Acting while the member is away: pre-signed responses, unattended signing, hardware devices. See `AWAY.md`.
13. Adding a member's own coins to their leaf in a live factory: needs a proper review.
14. Waking members who are offline when a factory rotates.
15. The default chain-server list for release: candidates are checked in `CHAIN-SERVERS.md`; a second independent testnet4 operator is still needed, and the operators' terms have not been read.

## Waiting on the SuperScalar repo

Work Gazpacho deliberately does not do itself. It waits, re-imports when the change lands, checks the result, and notes here when that check starts and what it found.

| Waiting for | Why we wait instead of doing it | Needed by | Our check when it lands |
|---|---|---|---|
| **Round 1** (expected within about a week of 2026-11-11): tree fees (their pull request 476) plus the four tree-builder fixes | Changes the tree's transactions in the shared files; they will announce it | Slice 3 (a member leaving alone) | Re-import; new reference values; scale check; confirm a lone exit completes |
| **Round 2**: payout to members at every level on the end date. They will write the transaction shape as a short specification first | Shared files; changes every transaction ID a second time | Before real funds; the specification is wanted early so the signing engine can target it | Review the specification when it arrives; then re-import, new reference values, loosen our exit rule to match |
| A defined order for participants | Shared files | M1 works around it; wanted before release | Confirm two builds on different systems give identical trees |
| Timelock-counter overwrite at 257 members and above | Shared files | Before any run above 256 members outside the simulator | Confirm with the reviewer's reproduction |
| Exit-delay functions under-reporting on deep trees | Shared files | Before payment deadlines are computed from them | Compare with our own sum from the transactions |
| Caller-supplied randomness | Shared files | Repeatable signing in the simulator; M1 wraps around it meanwhile | Remove our wrapper |
| The nine requests of 12 Nov (`handoff/2026-11-12-to-superscalar.md`): channel script, payout destination, layer-counter bound, hashes at index 512+, placement setter, session leak, split by member count, shared name, single-input sale with shared-leaf prerequisites | Shared files; one note so they can plan rounds | Each request is marked Slice 1, 1.0.0 or 1.1.0; none blocks Slice 1 | As each request says |
| Verifying each partial signature inside the tree code | Shared files | Not blocking: our signing engine verifies them itself | None needed |
| A Core Lightning plugin for holding payments | Their bridge rework. **They say this is far off; do not plan around it.** LND comes first for us anyway; if we reach the Core Lightning adapter before they do, we write the plugin | Core Lightning adapter | Review and reuse if theirs exists by then |
| Their whole-program scale test at 64, 127 and 255 | **Far off on their side; do not plan around it.** Size is covered by our one-process scale check now and by our own simulator and slices later | Not blocking | Compare if it arrives |

Nothing has landed yet, so no check has started.

## Notes sent to the SuperScalar repo session

- `handoff/2026-11-11-to-superscalar.md`: findings from running and importing the reference code, and from the scale check.
- `handoff/2026-11-11-end-date-payout.md`: why the end-date payout should land with the other tree-transaction changes, and what needs deciding in it.
- `handoff/2026-11-12-to-superscalar.md`: nine requests (E1 to E9), each marked with what it blocks.
- A shared message specification will follow.
