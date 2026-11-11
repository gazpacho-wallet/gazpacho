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

## For the SuperScalar repo session

See `handoff/2026-11-11-to-superscalar.md`. Later: paying members at every tree output on expiry; a shared message specification.
