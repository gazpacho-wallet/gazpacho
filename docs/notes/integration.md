# Integration: Slice 1 end to end (P4.6)

Draft 2, 2026-11-18. Branch `integration-slice1`, a draft pull request (#66) that is **never merged**. It merges the
open pull requests of Slice 1 onto `main`, in this order: #51 (`p5-p6-api`), #52 (`composite-p4-3`), #54
(`s5-s6-program`), #53 (`keys-p8`), #56 (`funding-p45`), #55 (`composite-p6a`). Then it wires them together so
that one host and three members, each a separate `gazpacho` process, form a factory on the local test chain
(Bitcoin Core regtest): from a clean start to a buried funding and a Live factory. This is step P4.6 of
`docs/notes/composite-node.md` 15. The audit that started it found that the funding engine (#56) is never called
and that the composite (#52) proposes a stand-in funding (its finding M1).

How the branch is kept:
- each owner keeps fixing their own pull request, and the new heads are merged in again as they land;
- fixes made here are small and self-contained, each listed in section 3 with the pull request that should fold
  it in;
- nothing here weakens a check, and no test is loosened or removed. A test that the merged tree breaks is listed
  in section 4 with its owner, not changed.

## 1. Merges and their conflicts

Base: `main` at `4aab237` (#64). Heads merged: #51 `cd98aed`, #52 `91aa062`, #54 `7752258`, #53 `f53d1e6`, #56
`bf739c0`, #55 `e3b7268`.

| Merge | Conflicts | Resolution |
|---|---|---|
| #51 | none | |
| #52 | `program/CMakeLists.txt`: both edited the library's link line and added a test after `program_lobby` | Union. The link line names `gazpacho_api` (#51) and `gazpacho_tree_import` (#52) and keeps #51's unlock sources. `program_p6a_views` (#51) and `program_signing` (#52) are both registered |
| #54 | `program/CMakeLists.txt` (sources, link line, tests), `program/executor.c` (after the start), `program/main.c` (statics, functions) | Sources: #51 adds `view.c` and `api.c`; #54 replaces `journal_standin.c` with `store_journal.c` and `store_unlock.c` (the stand-in moves to the test build only). Link line: the union. Tests: #51's and #52's kept, #54's test passphrase file after them. `executor.c`: #51's `gzp_api_node_started` kept, #54's rename of `gzp_standin_poisoned` to `gzp_store_poisoned` taken. `main.c`: #51's `api` and `on_illegal` and #54's `wallet` and `append_batch` all kept |
| #53 | `program/CMakeLists.txt` (sources, tests), `program/executor.c` (`port_secret`), `program/main.c` (statics, the key opening, its call), `tests/program/refusals.py` | Sources: `keys.c` added to the union; `keys_standin.c` in the test build only. Tests: all four sides kept (an `endif()` restored between two blocks). `port_secret`: #53's (under AT_JOIN, from the scoped table only: audit M2). `main.c`: **the key port's seed is the unlocked storage's** (`gzp_keys_seed_from_unlock` over #54's `gzp_wallet_unlock_api`), not `wallet-seed.standin`, which #54 removed: this is #53's own merge blocker 1. #54's stand-in transport key gives way to #53's `transport_key` (the host key, `keys.md` 4); #53's `keys_open` replaces #54's `wallet_open` and makes the same first-address check, and more. `refusals.py`: #53's check that no `transport.key` is written is kept; the key file made world-readable is #54's `keys.gzk` |
| #56 | none | |
| #55 | `CMakeLists.txt`, `core/gazpacho/include/gazpacho/ports.h`, `core/node/CMakeLists.txt`, `core/node/internal.h`, `tests/node/mutants.txt` | All unions: #56's `node_watch_release` and #55's `fuzz_api`; #52's `host_secret` and #55's `epoch_ok` in the key port, with both comments; `signslot.c`, `view.c` and `api.c` in both source lists; #52's signing block and #55's view and API block; both sets of mutants |

## 2. The wiring list: every stand-in still used between components

| # | Stand-in or gap | Where | The real fix | Owner | State here |
|---|---|---|---|---|---|
| W1 | **The stand-in funding**: `sg_test_funding` made a funding transaction with one made-up input (a hash of scope, check and attempt), never broadcast; a new attempt spent another made-up input (audit L3) | `core/node/signslot.c`, `sg_begin` | The host's attempt asks the funding engine for its plan first and proposes its unsigned bytes and outpoint, with `released` from the previous attempt's signing outcome (H11) | #56 (its `funding.md` 7); #52 gives the outcome's fields | **Done** (section 3, F3). The stand-in remains only for a test-build host node with no wallet port (unit tests) |
| W2 | **No funding engine in the node**: no `ENG_FUNDING`; NEW_TIP, TX and OUTPOINT reports, BROADCAST_RESULT and command 0x0301 reached no funding engine; H1 never ran; no member called `gz_fund_member_acked`; the `report` hook reached no lobby | `core/node` | As `funding.md` 7 lists | #56 | **Done** (F3), except W13 and W16 |
| W3 | **No wallet port in the program** | `program/` | A port over `wallet/tx`: the host's confirmed BIP 86 coins from the chain port, the master key from the unlocked seed | #56, with #53's keys | **Done** (F3: `program/wport.c`), with the stand-ins of W15 |
| W4 | **Key routing under AT_JOIN** (audit M2, D3): #53's `port_secret` answers only from the scoped table, and nothing fills it: no call of `gzp_keys_scope_open` anywhere. An AT_JOIN member can neither ready with the passphrase nor sign | `program/executor.c` (#53), the READY route of `ports/api` (#51) | The READY-with-passphrase path calls `gzp_keys_scope_open` once the passphrase is checked, before the node gets its ready command; the node's gate then requires the scoped secret (audit M4) | #53 (the call), #51 (the route) | Open. `program_slice1` uses AUTO members |
| W5 | **`host_secret`**: #52's port gave the key at (epoch 0, index 0); #53 sets no `host_secret` | `program/executor.c` | Over `gzp_keys_host` | #53 | **Done** (F1) |
| W6 | **The unlock call between #51 and #54**: #51's API server unlocks through `unlock_standin.c` (test build) or `unlock_none.c` (release: `not_built`); #54's `store_unlock.c` implements `unlock.h` over the sealed storage, but #54's program waits for the unlock *before* the loop in which #51's API server runs. So the merged release program never unlocks; only `gazpacho-test --test-passphrase-file` does | `program/main.c`, `program/api.c`, `program/store_unlock.c` | The API server runs while locked (before storage opens), with `gzp_wallet_unlock_api(wallet)` as its unlock table; `unlock_standin.c` and `unlock_none.c` go | #54 (after #51, as its body plans), #51 for the locked phase of its server | Open |
| W7 | **The key port's seed**: #53 read `wallet-seed.standin` | `program/main.c` | `gzp_keys_seed_from_unlock` over #54's table | #53 (its merge blocker 1) | **Done** at the #53 merge |
| W8 | **Chain watches feeding burial**: the chain worker's reports reached the test engines and the lobby slots only; `composite.c` dropped `GZ_CHAIN_BROADCAST_RESULT` | `core/node/composite.c` | Routed to the funding engine | #56 | **Done** (F3) |
| W9 | **No regtest in the program**: `--network` took signet or testnet4; the chain port had no regtest network; the transport accepts only the signet and testnet4 chain hashes | `program/`, `ports/chain`, `ports/net` | Regtest as a test network | P4.6 | **Done** (F2), in the test build only for the program option and the transport. On regtest the lobby's terms still name signet: Slice 1's terms policy (`core/lobby/fit.c`, `core/tree/terms.c`) is unchanged |
| W10 | **No Esplora on regtest**: the chain port speaks Esplora only | test tool | `tools/esplora-regtest.py` | P4.6 | **Done** (F2) |
| W11 | **Two commands set the member-signing mode, with opposite timing** (audit L4): #52's `GZ_CMD_SIGNING_SET` and #55's `GZ_CMD_API_SET_SIGNING` | `core/node/lobbyslot.c`, `core/node/api.c` | One command, which `PUT /settings/signing` uses | #52 and #55 to agree | Open |
| W12 | **The API does not reach the node's API engine**: #51 answers every lobby call with `not_yet core-view`; #55's API engine exists but #51's server does not forward to it | `program/api.c` (#51), `core/node/api.c` (#55) | The server forwards lobby calls to the node's API engine and reads its views | #51, after #55 | Open |
| W13 | **No lobby result for cancel reason 4**: the lobby's round results are Funding, Active, Retry and Failed (reason 3); the funding engine's Dead and abandoned ends need Failed with cancel reason 4 to every seat (`messages.md` 6.10). Here a Dead or abandoned report resolves the member's round and tells the lobby nothing | `core/lobby` `lobby_handoff.h` | A Failed result that names its reason | #56 (it added reason 4), in the lobby | Open |
| W14 | **`epoch_ok` is not set**: #55 added the key port's `epoch_ok` for P8 to set ("P8 sets it"); #53 does not, so a restore's new epoch is drawn without the check | `program/executor.c` | #53's port answers `epoch_ok` (the epoch's hardened child is valid) | #53 | Open |
| W15 | **The wallet port's stand-ins** (`program/wport.h`): coins are read once, at the start (a coin received later is seen at the next start); `adopt` holds again only a plan this run made, so after a process restart a journal's plan is refused and never signed; in the test build with no chain, one invented coin, so that the tests without a chain still reach Funding through the real engine (nothing is broadcast without a chain) | `program/wport.c` | Coins followed by the chain worker; `adopt` rebuilt from the journal's plan (a `wallet/tx` function that holds a funding from its bytes) | #56, with `wallet/` | Open |
| W16 | **No slot end from the funding engine**: `gz_fund_scope_state` is not yet asked when a slot's Closing ends, and `gz_fund_host_drop` is not called when a lobby ends without Funding | `core/node/lobbyslot.c`, `nodepart.c` | As `funding.md` 7 lists | #56 | Open |

## 3. Fixes made on this branch, for the owners to fold in

| Fix | What | Test that fails without it | Owner |
|---|---|---|---|
| F1 | `port_host_secret` is `gzp_keys_host`, not `gzp_net_key(net, 0, 0)`: with #53's key function behind the transport, (0, 0) is a member-path lobby key, derived only under the current epoch and never the key the terms name, so the host could sign no proposal | `program_signing` and `program_slice1` | #53 (its merge blocker 2) |
| F2 | Regtest as a test network (chain port; program and transport in the test build), and `tools/esplora-regtest.py` | `program_slice1` | P4.6 |
| F3 | The funding engine in the composite (`core/node/fundslot.c`, `ENG_FUNDING`) and the host's wallet port (`program/wport.c`), wired as `funding.md` 7 lists | `program_slice1` (no funding was ever broadcast before) | #56 |
| F4 | `scoped_only` (AT_JOIN's key routing) only on a member: a host derives its own pairs for every round it proposes (B6) | `program_slice1`; CI's `program_signing` | #53 |
| F5 | `sg_ftx` holds `GZ_SIGN_MAX_FUNDING_TX` bytes (B7) | `program_slice1` (`sign-begin-refused-funding` before) | #52 |
| F6 | The sealed journal's table of known record types holds `journal.md` 9's area 0x000d, Slice 1 rows (B9) | `program_lobby` (every restart refused before; with F6 on the build server only case 7, AT_JOIN with the passphrase, still fails: B2) | #54 |

## 4. Cross-PR bugs found

| # | Bug | Seen how | Owner |
|---|---|---|---|
| B1 | #53's `tests/program/derived_keys.py` writes `wallet-seed.standin` and reads `journal.standin`; on the merged tree the seed is the sealed storage's and the journal is sealed (#54), so the test cannot set its seed or read its journal | Reading; CI on this branch | #53, once #54 is on `main` (restore from the test words through `unlock.h`, dump with `--test-dump-journal`) |
| B2 | Under AT_JOIN (the default) no member can ready with the passphrase or sign once #53 is merged (W4) | Reading, audit M2; `program_signing`'s AT_JOIN member on this branch | #53 and #51 |
| B3 | The merged release program cannot unlock (W6) | Reading | #54 and #51 |
| B4 | The host's round secret was the lobby key at (0, 0) after #53 (F1) | Reading; fixed here | #53 |
| B5 | `epoch_ok` left unset (W14) | Reading | #53 |
| B6 | #53 sets `scoped_only` from `--member-signing`, whose default is AT_JOIN, on the host as well: the host's `port_secret` then answers only from the (empty) scoped table, so the host cannot make its own factory key for any round it proposes. Seen as CI's `program_signing` failure on this branch (no proposal is ever answered) | CI, reading; fixed here (F4) | #53 |
| B7 | #52's composite holds the proposal's funding transaction in `sg_ftx[128]`, room for its stand-in only: a real funding (154 bytes with one input, up to 8,192) does not fit, so every real plan was refused (`sign-begin-refused-funding`). The 8,192-byte limits of #52 and #56 agree; this buffer did not | `program_slice1` on the build server; fixed here (F5) | #52 |
| B8 | CI on this branch: `web_p6a_fixme` fails by design once #55's `core/node/view.c` is in: #51 must switch `tests/web/multiprocess.spec.mjs` on | CI | #51 |
| B9 | Every restart of a folder that opened a lobby is refused: `cannot start storage: journal: unknown_record`. #54's sealed journal keeps a table of known record types (`gz_journal_type_known`) with none of `journal.md` 9's area 0x000d (Local API), and #55 writes `local_ids` (0x000d000e) in a slot's first batch. CI's `program_lobby` cases 2 to 7 ("the host starts again on the same folder", "the member restarts"); `program_two_process` and `program_journal_kill` write no such record and restart fine | CI; reproduced on the build server (the restarted host's log); fixed here (F6) | #54 |
| B10 | `program_keys_ct` (valgrind constant-time check of the key derivation) fails in the gcc build: an untriaged secret-dependent branch in `gzw_bip32_master` through libcrypto. It fails on #53's own CI too, so it is #53's, not the merge's | CI | #53 |
| B11 | Two threads on one chain client: the chain worker (P7) runs in its own thread on the program's `gz_chain`, and a synchronous lookup from the loop's thread on the same client (`--check-chain`'s `gzp_chain_show_outputs`, and this branch's first wallet scan) races it: the first wallet scan here crashed the host with a heap corruption. The wallet scan now uses a client of its own (`program/wport.c`); `--check-chain` keeps the race, short-lived since it exits at once | `program_slice1` on the build server | main (P7, `program/pchain.c`) |
| B12 | A tip that jumps past the funding deadline in one report (here: regtest blocks every second against the default 60 s tip poll; in life: a host or member asleep for six hours) makes the funding engine judge the factory abandoned on the tip alone, before the watch reports that it was buried on time arrive: the host then broadcast a spend-back (refused, its input spent) and took the factory as funded late; the members went abandoned, then live late. #56's review B resync gate covers a start only | `program_slice1` on the build server (first runs) | #56 |

## 5. The multi-process regtest test

`tests/program/slice1.py`, CTest `program_slice1` (skipped, exit 77, without `GZ_BITCOIN_BIN`, the folder holding
`bitcoind` and `bitcoin-cli`). It starts its own regtest node (its own data folder under the test's work folder, RPC
on 127.0.0.1 at a free port, `-listen=0`, stopped at the end) and `tools/esplora-regtest.py` over it.

1. One host and three AUTO members from clean folders: the host's coin is a real regtest coin paid to its first
   receive address, found by its wallet port at its start. The round is signed; the funding engine plans the funding
   from that coin, H1 passes, the funding is broadcast at 0.1 sat/vB, confirms and is buried (3 blocks); the host
   and every member go Active, each member by its own chain view (C11).
2. The same with a fourth member whose conditions the terms do not meet (its highest tree fee rate, 1 sat/kvB, is
   below the terms' 100): it refuses, is never seated, signs nothing and follows no funding; the host and the three
   others go Live.

Not yet in it, from `composite-node.md` P4.6: a host with two lobbies, a member in both, every process restarted once with nothing lost, and `program_slice1_signet` (opt in, `GZ_LIVE_TESTS`, the test coins). Results on the build server (Core 29.1): section 6.

## 6. Results on the build server

Bitcoin Core 29.1 regtest, its own data folder, `-listen=0`, RPC on loopback; every process `gazpacho-test` from the
branch's tree with F1 to F6 and the wiring, its chain worker polling the tip every 250 ms.

| Run | What happened |
|---|---|
| First runs | The real plan was refused (`sign-begin-refused-funding`): B7, then F5. The host could make no factory key: B6, then F4. The first wallet scan crashed the host (heap corruption): B11, then the scan's own client |
| With the default 60 s tip poll and a block a second | Funding broadcast at 0.1 sat/vB (16 sat, 154 vB), confirmed and buried; every member judged it Live (C11), but the host's tip jumped past its funding deadline before the burial was reported: abandoned, a spend-back refused, funded late (B12) |
| `program_slice1` as committed | **PASS**, both cases, 0 failed checks: in each, the real coin found, the round signed with the three members, the plan from that coin, H1 passed, the funding broadcast (16 sat for 154 vB), buried, Live on time on the host and by each member's own chain view (C11), Active everywhere, no node-error. In case 2 the refusing member was never seated, signed nothing and followed no funding |
