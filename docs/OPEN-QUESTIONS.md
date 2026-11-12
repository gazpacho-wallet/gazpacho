# Open questions

Kept current. Last updated 2026-11-11, after questions round 2.

## For the owner

1. **Numbers for the lobby:** largest lobby, default gathering time, signing timers, number of signing attempts. Recommended: settle from signet testing.
2. **Who besides the owner can approve a SIP.**
3. **Review of the two drafted specifications** (`spec/`): the open points at the end of each, and an expert look at the proof-of-fault scheme.
4. **Is the full security catalogue from the earlier SuperScalar work copied into this repo** as reference, or left where it is?

5c. **Raising the 256-member limit** in the shared files toward the 512 target: confirm it is work for the SuperScalar repository now.

## For this session to settle (research or build)

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
| Tree fees (their pull request 476) | Changes the tree's transactions in the shared files | Slice 3 (a member leaving alone) | Re-import; new reference values; scale check; confirm a lone exit completes |
| Payout to members at every level on the end date | Shared files; changes every transaction ID | Before real funds; shape wanted early | Re-import; new reference values; review the division rule and lock times; loosen our exit rule to match |
| A defined order for participants | Shared files | M1 works around it; wanted before release | Confirm two builds on different systems give identical trees |
| Timelock-counter overwrite at 257 members and above | Shared files | Before any run above 256 members outside the simulator | Confirm with the reviewer's reproduction |
| Exit-delay functions under-reporting on deep trees | Shared files | Before payment deadlines are computed from them | Compare with our own sum from the transactions |
| Caller-supplied randomness | Shared files | Repeatable signing in the simulator; M1 wraps around it meanwhile | Remove our wrapper |
| Verifying each partial signature inside the tree code | Shared files | Not blocking: our signing engine verifies them itself | None needed |
| A Core Lightning plugin for holding payments | Their bridge rework | Core Lightning adapter, after LND | Review and reuse |
| Their whole-program scale test at 64, 127 and 255 | Their programs | Confidence in the leaf design at size | Compare with our one-process results |

Nothing has landed yet, so no check has started.

## Notes sent to the SuperScalar repo session

- `handoff/2026-11-11-to-superscalar.md`: findings from running and importing the reference code, and from the scale check.
- `handoff/2026-11-11-end-date-payout.md`: why the end-date payout should land with the other tree-transaction changes, and what needs deciding in it.
- A shared message specification will follow.
