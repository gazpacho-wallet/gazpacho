# Integration: Slice 1 end to end (P4.6)

Draft 1, 2026-11-18. Branch `integration-slice1`, a draft pull request that is **never merged**. It merges the open
pull requests of Slice 1 onto `main`, in this order: #51 (`p5-p6-api`), #52 (`composite-p4-3`), #54
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

The tree at the #56 merge builds both programs (`gazpacho`, `gazpacho-test`) on the build server with no
warning-as-error.

## 2. The wiring list: every stand-in still used between components

| # | Stand-in or gap | Where | The real fix | Owner |
|---|---|---|---|---|
| W1 | **The stand-in funding**: `sg_test_funding` makes a funding transaction with one made-up input (a hash of scope, check and attempt) that is never broadcast; a new attempt spends another made-up input (audit L3) | `core/node/signslot.c`, `sg_begin` | The host's attempt bracket calls `gz_fund_host_plan` first and proposes its unsigned bytes and outpoint, with `released` from the previous attempt's signing outcome (H11) | #56 (its `funding.md` 7 lists the hand-off); #52 gives the outcome's fields |
| W2 | **No funding engine in the node**: no `ENG_FUNDING`, no `gz_fund_t`; NEW_TIP, TX and OUTPOINT reports, BROADCAST_RESULT and command 0x0301 reach no funding engine; H1 is never run; a member never calls `gz_fund_member_acked`; the `report` hook (Live, Dead, abandoned) reaches no lobby, so no lobby is ever Active | `core/node/composite.c`, `route.c`, `handoff.c`, `internal.h`, `watches.c` | As `funding.md` 7 lists | #56 |
| W3 | **No wallet port in the program**: `gz_wallet_port_t` has no implementation outside `tests/funding`; the program does not know its own coins | `program/` | A port over `wallet/tx` (`gzt_funding_*`), its coins from the chain port (`gz_chain_script_outputs` of the BIP 86 receive and change scripts, confirmed only, review A of #56 M5), the master key from the unlocked seed | #56, with #53's keys |
| W4 | **Key routing under AT_JOIN** (audit M2, D3): #53's `port_secret` answers only from the scoped table, and nothing fills it: no call of `gzp_keys_scope_open` anywhere. An AT_JOIN member can neither ready with the passphrase nor sign | `program/executor.c` (#53), the READY route of `ports/api` (#51) | The READY-with-passphrase path calls `gzp_keys_scope_open` once the passphrase is checked, before the node gets its ready command; the node's gate then requires the scoped secret (audit M4) | #53 (the call), #51 (the route) |
| W5 | **`host_secret`**: #52's port gave the transport key at (epoch 0, index 0); #53 sets no `host_secret` | `program/executor.c` | Over `gzp_keys_host`. **Done on this branch** (F1, section 3) | #53 |
| W6 | **The unlock call between #51 and #54**: #51's API server unlocks through `unlock_standin.c` (test build) or `unlock_none.c` (release: `not_built`); #54's `store_unlock.c` implements `unlock.h` over the sealed storage, but #54's program waits for the unlock *before* the loop in which #51's API server runs. So the merged release program never unlocks; only `gazpacho-test --test-passphrase-file` does | `program/main.c`, `program/api.c`, `program/store_unlock.c` | The API server runs while locked (before storage opens), with `gzp_wallet_unlock_api(wallet)` as its unlock table; `unlock_standin.c` and `unlock_none.c` go | #54 (after #51, as its body plans), #51 for the locked phase of its server |
| W7 | **The key port's seed**: #53 read `wallet-seed.standin` | `program/main.c` | `gzp_keys_seed_from_unlock` over #54's table. **Done at the #53 merge** (section 1) | #53 (its merge blocker 1) |
| W8 | **Chain watches feeding burial**: the chain worker's reports reach the test engines and the lobby slots only; `composite.c` drops `GZ_CHAIN_BROADCAST_RESULT` "until P4.5" | `core/node/composite.c` `on_chain` | Routed to the funding engine (W2) | #56 |
| W9 | **No regtest in the program**: `--network` takes signet or testnet4; the chain port has no regtest network (genesis, proof-of-work limit); the transport accepts only the signet and testnet4 chain hashes (`ports/net/peers.c`); Slice 1's terms policy requires the signet chain (`core/tree/terms.c`, a static policy in `core/lobby/fit.c`) | `program/options.c`, `program/main.c`, `ports/chain`, `ports/net`, `core/tree`, `core/lobby` | Regtest as a test network everywhere a network is named, and the terms checked against the node's own chain (signet nodes still demand signet) | P4.6 (this branch), then the owners of each module |
| W10 | **No Esplora on regtest**: the chain port speaks Esplora only | test tool | `tools/esplora-regtest.py`, an Esplora look-alike over Core's RPC, tests only | P4.6 (this branch) |
| W11 | **Two commands set the member-signing mode, with opposite timing** (audit L4): #52's `GZ_CMD_SIGNING_SET` (at once, unsaved, closes every gate) and #55's `GZ_CMD_API_SET_SIGNING` (saved, applied at the next start) | `core/node/lobbyslot.c`, `core/node/api.c` | One command, which `PUT /settings/signing` uses | #52 and #55 to agree |
| W12 | **The API does not reach the node's API engine**: #51 answers every lobby call with `not_yet core-view`; #55's view objects and API engine exist but #51's server does not forward to them | `program/api.c` (#51), `core/node/api.c` (#55) | The server forwards lobby calls to the node's API engine and reads its views | #51, after #55 |
| W13 | **No lobby result for cancel reason 4**: the lobby's round results are Funding, Active, Retry and Failed (reason 3); the funding engine's Dead and abandoned ends need Failed with cancel reason 4 to every seat (`messages.md` 6.10) | `core/lobby/include/gazpacho/lobby_handoff.h` | A Failed result that names its reason | #56 (it added reason 4), in the lobby |

## 3. Fixes made on this branch, for the owners to fold in

| Fix | What | Test that fails without it | Owner |
|---|---|---|---|
| F1 | `port_host_secret` is `gzp_keys_host`, not `gzp_net_key(net, 0, 0)`: with #53's key function behind the transport, (0, 0) is a member-path lobby key, derived only under the current epoch and never the key the terms name, so the host could sign no proposal | `program_signing` on this branch | #53 (its merge blocker 2) |

## 4. Cross-PR bugs found

| # | Bug | Seen how | Owner |
|---|---|---|---|
| B1 | #53's `tests/program/derived_keys.py` writes `wallet-seed.standin` and reads `journal.standin`; on the merged tree the seed is the sealed storage's and the journal is sealed (#54), so the test cannot set its seed or read its journal | Reading; CI on this branch will show it | #53, once #54 is on `main` (restore from the test words through `unlock.h`, dump with `--test-dump-journal`) |
| B2 | Under AT_JOIN (the default) no member can ready with the passphrase or sign once #53 is merged (W4) | Reading, audit M2; `program_signing`'s AT_JOIN member on this branch | #53 and #51 |
| B3 | The merged release program cannot unlock (W6) | Reading | #54 and #51 |

## 5. The multi-process regtest test

To come: `tests/program/slice1.py`, CTest `program_slice1` (opt in, needs Bitcoin Core): one host and three members
from a clean start to a buried funding and a Live factory; then the same with one member refusing on its
conditions, which must refuse and not be funded.
