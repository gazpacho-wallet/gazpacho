# Open questions

Kept current. Last updated 2026-11-11, after questions round 2.

## For the owner

1. **Numbers for the lobby:** largest lobby, default gathering time, signing timers, number of signing attempts. Recommended: settle from signet testing.
2. **Who besides the owner can approve a SIP.**
3. **Review of the two drafted specifications** (`spec/`): the open points at the end of each, and an expert look at the proof-of-fault scheme.
4. **Is the full security catalogue from the earlier SuperScalar work copied into this repo** as reference, or left where it is?

5a. **Should the SuperScalar repository still rebuild its own channel code,** now that Gazpacho is building the channel on Lightning's standard format? Suggested: no; it keeps its current channel code with the safety fixes under way and concentrates on the shared low-level files and the construction fixes.
5b. **Light-client mode in the reference programs:** remove or disable it (suggested, since Gazpacho covers running without a Bitcoin node), or still fix it there?
5c. **Raising the 256-member limit** in the shared files toward the 512 target: confirm it is work for the SuperScalar repository now.

## For this session to settle (research or build)

5d. **Does one member per pseudo-Spilman leaf work at 64, 127, 255 and 512 members,** and how long is the exit? The SuperScalar session has offered to run it at 64 and 127. Gazpacho tests tree building and signing at those sizes at the start of M1. Until then the leaf decision is provisional.

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
15. Which well-known public chain servers go in the default list.

## For the SuperScalar repo session

See `handoff/2026-11-11-to-superscalar.md`. Later: paying members at every tree output on expiry; a shared message specification.
