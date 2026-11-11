# Open questions

Kept current. Each has a recommendation where there is one. Last updated 2026-11-11.

## For the owner

### Lobby

1. **Is signing live at a fixed time, or spread over a long window?**
   Recommended: live at a scheduled time. It is simpler and matches the game-lobby picture. A long window suits people in different time zones but leaves the host's capital waiting.
2. **Are people with no funds the main first audience?** If so, what share of seats in a public lobby may go to members who bring nothing scarce?
   Recommended: yes for signet; the host sets the share.
3. **Is a small deposit acceptable, knowing the host could keep it?**
   Recommended: not in the first version. Revisit with real experience of trolls.
4. **Do members see who else is in the lobby before signing?**
   Recommended: yes, as temporary per-lobby names. Personal block lists need it.
5. **Is a member's identity lasting, or new for each lobby?**
   Recommended: new for each lobby by default; a member may choose to bring a lasting identity.
6. **Are lobby listings public on Nostr, with terms, size and start time?** The earlier host list kept factory details off Nostr on purpose.
   Recommended: yes for terms, size limits and start time; never the list of who joined.
7. **May a host publish the factories it has funded as a track record?**
   Recommended: yes. They are visible on chain anyway.
8. **Numbers:** largest lobby, how many signing attempts, how long each signing step may take.
   Recommended: decide from signet testing.

### Product

9. **Which public chain servers ship in the default list, and do we run our own as one of them?**
   Recommended: a short list of well-known servers plus one of ours.
10. **Who drafts the shared message specification, and when is it offered to the SuperScalar repo?**
    Recommended: this session, after the signing engine exists in the simulator.
11. **Does the first release need chat in the lobby?**
    Recommended: no.

## For this session to settle (research or build)

12. The precise definition of the member's safety rule: what "I can leave with at least what I am owed" means with timelocks, payments in flight and fees.
13. The timelock and deadline schedule in numbers for the full layered tree.
14. The proof-of-fault scheme for signing rounds. The proposal (sign each partial signature together with a hash of the nonces used) is our own reasoning from the signing standard and needs expert review.
15. A host proof of funds sized to the lobby it advertises.
16. Hold, settle and cancel on Eclair, LDK-based nodes and Nostr Wallet Connect: not yet verified.
17. Lightning's taproot channel format: confirm its status and details against the specification itself, not secondary sources.
18. Adding a member's own coins to their leaf in a live factory: our reasoning says it is safe for other members because they never sign anything involving it, but it needs a proper review.
19. Waking members who are offline when a factory rotates.

## For the SuperScalar repo session

See `handoff/2026-11-11-to-superscalar.md`: the exit failure, caller-supplied randomness, no direct output in the tree builder, a defined participant order. Later: paying members at every tree output on expiry.
