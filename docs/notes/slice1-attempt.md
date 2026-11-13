# Slice 1 attempt (throwaway branch, never merged)

This is the first end-to-end Slice 1 run, made on 2026-11-13 on the throwaway branch `slice1-attempt`. The owner approved skipping reviews on this branch only. Nothing here merges to main. The findings below feed the real pull requests.

## What the branch holds

`main` (8a6e422) with these branches merged:

- `program-skeleton` (PR 27);
- `transport-lobby` (PR 23);
- `lobby` (919ad7a);
- the signing engine: PR 15 plus the build server's three newer commits, replayed as 2ef9ce7, 93de720 and 33f2ac6.

On top of that, `program/s1/` builds `gazpacho-slice1`. Each party runs as its own process. The program drives:

- **The lobby engine,** over PR 23's `peers.h`. The host opens a lobby with T1-style test terms: target 3, minimum 3, `channel_sat` 100,000, tree fee rate 100 (0.1 sat/vB), lifetime 144 blocks and wind-down 36. Members join with the host's address and the lobby identifier. Then come the ready check, the freeze and the start.
- **The signing engine,** with its limits raised. The items of each round are the transactions of the tree built from the terms (`core/tree`). A member runs `gz_tree_import_member_check` inside the engine's builder before it signs, and `gz_tree_may_ack` before its ack.
- **Host funding from test wallet 1,** through the wallet library:
  1. `gzt_funding_build` before signing. This is the dry run, and every output is checked against the funding script.
  2. `gzt_funding_release` once every member has acked.
  3. An independent `gz-wallet-tx decode` of the signed bytes.
  4. One broadcast to both signet operators, after a gate file is created by hand.
- **The chain view** (comparing backend: mempool.space and blockstream.info). It follows the funding until it is buried (3 confirmations). Each member then runs its C11 check (`gz_tree_c11`) on the output read from the chain.

Run scripts on the build server: `/root/gz/attempt/runloop.sh` (loopback, fake chain) and `/root/gz/attempt/runsignet.sh`.

## Results

**A factory formed on signet.** The host and 3 members ran as separate processes, and a fourth member refused the terms.

| What | Value |
|---|---|
| Funding | `f1e6995cee60a98bd47385b65902dd53cd7c736a06c2d9ac749ab95048092ea1:0`, 802,827 sat to the aggregate key of the host and 3 members; change 10,177,141 sat to wallet 1 at change index 1; fee 16 sat for 154 vB (0.1 sat/vB) |
| Confirmed | signet block 330619. At tip 330621, mempool.space and blockstream.info both reported state confirmed, height 330619, 3 confirmations. The host set the lobby to Active, and all three members' C11 said *live* |
| End height | 330796 (tip 330616 + 144 + 36). The host's coins come back through the timeout leaves after 330791 |
| Tree, 8 transactions, all signed and verified by every party | 0 `e270a9b9cf30b1e29bb3fb321105c80cc10b89b3e64d027b066fc717fdf46f09` (root, 4 signers) · 1 `023790b03092253b2b154ae50f1613ae58d359c8316e1e47b8b62965c3b04ecd` · 2 `700299a3e7d4d6d9106b22ce37678b5f10e9fe87e95b709614e781a7addb9aed` · 3 `6d94dfaecda15f7ad7e76b062adbe67e636d60d302467cd6ad7bcd197c044124` (3 signers) · 4 `c7d696eb8912ef9fb87712d7fa65ba6957cdac07fed0e2577041ec35ec862ef6` · 5 `4a57928d17b253dff73b905aa11f6c453734ca72f2a011d14f2f5a4cf2bccccc` · 6 `04f528dbef6b81a7e3eae234a2e8a6e50c5db9b21ff44a9ca1cbb7f35224652a` · 7 `5dc913b587a90a811c1285c3aef506d94fbc016c15070f6454c4c0d2baf4a44c` (the rest have 2 signers). They are not broadcast; they are the exit path |
| Refusal | The fourth member wanted at least 200,000 sat per channel. It got class 3 (`GZ_FIT_NO`) on term 30 (`channel_sat`), did not join, and stayed connected. The lobby went on with the other three |
| Timeline (UTC) | 04:59:22 lobby open · 04:59:28 three seats · 04:59:58 start (the full 30 s ready window) · 04:59:58.1 to 04:59:58.3 proposal, nonces, partial signatures, results and every ack (about 200 ms) · 05:04:30 broadcast (gate opened after the decode check) · 05:14:03 buried, Active, C11 live |

The loopback run with a fake chain (`runloop.sh`) gave the same result: the same flow, an 8-transaction tree and the same refusal. The fake chain has no real funding, so nothing was broadcast. Every piece worked the first time it ran once it compiled. No round failed and no message was lost.

## Mismatches between the pieces, and the fix each real PR needs

Ordered by consequence. "Glue" means what this branch did instead. No glue workaround should be copied into a real PR.

1. **The program skeleton cannot host the engines** (PR 27, core contract v2 P4).
   - `gz_node` is the placeholder ping node. There is no node that holds the lobby and signing engines and routes events to them.
   - Neither engine is a `gz_node`. The lobby takes `gz_lobby_input_t`, and signing takes `gz_event_t` plus its own start.
   - The skeleton's network adapter is the blocking `conn.h`, not `peers.h`.
   - Glue: its own loop over `peers.h`, synchronous saves (append and fsync, in list order, so saves still come before sends) and no restart path. The executor, the runner, the journal stand-in and the journal (PR 29) are all unused.
   - Fix: a composite node (lobby, then signing, then funding) behind `gz_node_handle`/`gz_node_start` once P4 lands. The skeleton's network adapter moves to `peers.h`.
2. **Two terms libraries for the same records** (lobby and `core/tree`). Both define `gz_terms_outer_t`, `gz_terms_current_t` and `gz_terms_range_t`, with different layouts. Both export `gz_terms_outer_digest`, `gz_terms_current_digest` and `gz_terms_classify`.
   - The two headers cannot be included together, and the program cannot link both.
   - Glue: renamed the lobby's to `gz_lterms_*`. On the signet run both decoders accepted the same records and gave the same digests (checked at every hand-off).
   - Fix: the lobby uses `core/tree`'s `terms.h` (receipt, version rule and classify are already there), and its own copy goes.
3. **`gz_tx_parse` exists twice with different signatures:** `signing.h` (`gz_tx_t`) and `tree.h` (`gz_tx_info_t`). This is a link-time collision. Glue: the signing engine's copy is renamed `gz_stx_parse`. Fix: the signing engine uses the tree's transaction code, or gets its own prefix.
4. **The lobby's outcome macros collide with signing's enum.** `lobby.h` `#define`s `GZ_ROUND_ACTIVE` and `GZ_ROUND_FAILED`, which `signing.h` declares as enum members. A file cannot include both, and the lobby-to-signing glue is exactly such a file. Glue: three translation units. Fix: `GZ_LOBBY_ROUND_*`.
5. **The signing engine's wire format is its own** ("GS", provisional), not `messages.md` 7. The transport checks the record tables of kinds 64 to 81, so the engine's messages cannot travel as `round_*` kinds.
   - Glue: each message is carried as record 1 of test kind 32767 (`gazpacho_net_testkinds`), scope zero.
   - Fix (PR 15): encode `round_propose` and the rest as `messages.md` 7.
6. **No encoding of `round_propose` (messages.md 7.2) into `gz_tree_proposal_t`.** The engine's parameters are opaque and the builder has to decode them. Glue: its own encoding of the proposal fields, 1,067 bytes for 4 participants. Fix: a `round_propose` codec shared by the host's builder and the member's check.
7. **The signing engine's limits.**
   - `GZ_SIGN_MAX_PARAMS` was 64, raised to 4,096. A proposal needs about 290 bytes (the funding transaction included) plus 194 per participant: 1,067 at 4 participants, about 3.6 KB at 17.
   - `GZ_SIGN_MAX_TX` was 512, raised to 720, to match the tree's `GZ_TREE_MAX_TX`.
   - `GZ_SIGN_MAX_PARTICIPANTS` and `GZ_SIGN_MAX_SIGNERS` are still 16, because `have_nonce`, `have_psig` and `acked` are `uint16_t` bitmasks. T1 at 16 members needs 17 participants (the masks must become `uint32_t`) and 45 items (the current 64 is enough).
   - Fix: PR 15.
8. **Contribution keys.** Signing uses 32-byte x-only keys; the lobby and `messages.md` use 33-byte points. Glue: dropped the prefix byte. Fix: the engine takes the 33-byte key (the round id and the bindings hash the 33 bytes).
9. **No hook for `gz_tree_may_ack`.** The engine acks by itself in `member_complete`.
   - Glue: `cfg.may_ack`, called before the ack is built.
   - The ack tip must also be journaled with the ack (`funding_status`), and the engine's `M_COMPLETE` record has no field for it.
   - Fix: PR 15, with `journal.md`.
10. **The lobby's hand-off lacks what the member's check needs.** `gz_tree_member_check` re-runs the receipt and needs the host's two signatures and the pinned key, but `gz_lobby_handoff_t` has neither signature. Glue: read them from the member struct's own fields. Fix: add `outer_sig`, `current_sig` and the pinned key to the hand-off.
11. **Peer identity in signing.** The engine wants a distinct `peer` for every participant, and requires participant 0's peer to equal the connection the proposal came on.
    - A member knows only the host's link. The host's own entry is never addressed.
    - Glue: invented ids for other members and a sentinel for the host.
    - Fix: members address only the host (participant 0); other entries need no peer. This goes with contract v2's links.
12. **Message shapes between engines and the transport.**
    - The lobby emits whole Lightning messages; `peers.h` delivers kind, scope and records. Glue: `gz_env_write` to rebuild the message, and `gz_peers_send_raw` to send.
    - The lobby's refusals (BOLT 1 warnings) also come out as SEND.
    - Fix: P4's SEND/MESSAGE with kind, scope and records, in both engines.
13. **Seats and closes are notices.** The program must map `GZ_NOTE_SEATED` to `gz_peers_set_seated_key`, and `GZ_NOTE_CLOSE` (an 8-byte peer id) to a refusal. This worked. Fix: P4's SET_SEATED and DISCONNECT actions.
14. **PR 15 sits on a main from before PRs 9, 21 and 28.**
    - Its core, simulator and isolation changes conflict in 15 files, and it still uses `GZ_RANDOM_OTHER`.
    - Glue: main's files kept, `GZ_RANDOM_ORDINARY` used, only the engine built (its tests are not registered here).
    - Fix: rebase PR 15 on main.
15. **The skeleton broke when merged with the transport.** `program/net.c` passes the core's `gz_random_port_t`, where `conn.h` now takes `gz_net_random_t`. Glue: an adapter. Fix: PR 27, when it moves to `peers.h`.
16. **The wallet library hides the unsigned funding.** `round_propose` record 18 needs the unsigned funding transaction, but `gzt_funding` has it only in the private `priv_tx`. Glue: read the field. Fix: `gzt_funding_unsigned()`.
17. **The host's H1 check was not run.** `gz_tree_h1` needs the script of every coin the funding spends, which the wallet library keeps private. The glue gated the broadcast on every ack and every tree signature verified, plus a manual decode. Fix: H1 takes the `gzt_funding`, or the wallet exposes the spent scripts.
18. **Change indexes are the caller's to track.** The host was told change index 1 (from `FUNDS.md`). Fix: wallet state, with a record of used change indexes.
19. **There is no burial watch or C11 input from the chain.** The `WATCH_*` actions have no watch loop. Glue: polled the transaction status every 30 s, read the output with `gz_chain_raw_tx`, and computed `buried_at` as height + B − 1. Fix: S8's watch loop, feeding `gz_tree_c11` with chain facts.
20. **Chain calls block the loop** (program.md mismatch 5, confirmed). The coin scan took about 9 s before the lobby opened, and each status poll took 0.2 to 1 s. Nothing timed out at these sizes.
21. **Simultaneous honest joins are refused for a limit.** Two of the three members got seat state 7 at once and only took a seat 1.5 to 3.5 s later, on the engine's retry. Fix (lobby): let the seat-creation limit pass a burst the size of the target.
22. **The ready check always waits the whole window.** Every seat answered within milliseconds, but the start came exactly 30 s (the ready window) after the check opened. Fix (lobby): start once every seat has answered.
23. **Nothing reports the signing outcome.** The program must poll `gz_sign_latest()` to learn that every ack is in, and must call `gz_lobby_host_round_result` itself. Fix: an outcome action or notice from the engine.
24. **The funding is large compared with the channels.** R(root) for 3 members at `channel_sat` 100,000 is 802,827 sat, about 2.7 times the channels. Test coin budgets should plan for it.

## Not done here

These were not done:

- restart and crash paths;
- the journal (PR 29);
- the encrypted storage;
- the screens;
- the retry after a failed round (`cfg.retry` is NULL);
- the host's H1;
- the sweep back of the host's coins (due after block 330791; see `FUNDS.md`).
