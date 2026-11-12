# Testing

How Gazpacho is shown to work. Two parts, kept apart on purpose:

- **Part 1, what runs today:** only what exists, and where it runs.
- **Part 2, planned:** the full plan, each item with the milestone that adds it.

Rewritten 2026-11-12 after the gap review, which found that the plan read as if it already ran. Update Part 1 whenever a test is merged, and move an item from Part 2 to Part 1 only when it runs.

## Principles

These hold for both parts.

1. **Every safety rule has two tests:** one showing the rule stops the attack, and one with the rule removed that must show a loss. The second proves the first can catch the bug it exists for.
2. **The checker is independent of the code it checks.** Money is counted from the transactions themselves, not by the module under test.
3. **Failures can be replayed.** Anything random is driven by a recorded seed.
4. **Nothing is "done" on a claim.** A milestone is finished when its tests pass in the automated checks.

# Part 1: what runs today

As of 2026-11-12, on `main` at `67678bb` (after PR 19). Nothing here touches a real network, except where it says so.

## On GitHub, on every pull request and every push to `main`

The workflow is `.github/workflows/ci.yml`: 11 jobs on Ubuntu 24.04, every one required before a merge into `main` (branch protection, since 2026-11-12). `notes/ci.md` says what each guards and how to run it locally. In short:

- gcc 13, two builds: Release, and AddressSanitizer with UndefinedBehaviorSanitizer (`GZ_SANITIZE=ON`). Each runs `ctest`, then the scale check. The Release build also runs the wallet break-checks.
- clang 18, two builds: plain, and ASan with UBSan.
- clang MemorySanitizer, with secp256k1-zkp and OpenSSL built for it.
- valgrind on every compiled test of a build without sanitizers.
- libFuzzer: each fuzz target for 60 seconds (`fuzz_noise`, `fuzz_tlv`, `fuzz_tx_parse`).
- The imported SuperScalar files are byte for byte what `IMPORT.md` records.
- No tracked file names a real address or a local user path.
- `tools/spec-vectors.py` runs and its own self-checks pass. It does not compare its output with the specifications' text.
- The committed handbook matches its Markdown.

The tests that `ctest` runs:

| Test | What it checks |
|---|---|
| `reference_tree` | The imported tree code reproduces the 14 transaction IDs recorded from a real SuperScalar run |
| `action`, `runner`, `node` | The core's action list, the save-before-send runner and the placeholder node |
| `core_isolation`, `core_isolation_refuses_sneaky_object` | The compiled core reaches no system call it should not, and the check catches an object that tries |
| `rng`, `sim` | The simulator's seeded generator and harness |
| `sim_known_trace` | One fixed seed gives the trace digest written in the test |
| `sim_seeds` | 1,000 seeds of 400 steps with every fault at a moderate rate |
| `sim_profile_1` to `sim_profile_9` | 100 seeds of 300 steps under each of nine extreme fault profiles |
| `wallet_vectors`, `wallet_keys`, `wallet_rare` | Wallet keys against the BIP 32, BIP 39 and BIP 86 test vectors, and rare cases |
| `wallet_tool`, `wallet_tool_faults` | The `gz-wallet-keys` tool, including injected faults |
| `wallet_keys_no_io`, `wallet_no_io_rejects_*` | The wallet library does no input or output, and the check refuses objects that would |
| `wallet_break_checks` (Release build only, label `slow`) | Each protection is damaged in turn in a scratch copy and a test must fail |
| `wallet_tx_vectors`, `wallet_tx`, `wallet_tx_faults` | Wallet transactions (PR 11): the BIP 341 signature-message vectors, serialising and the strict parser, fees and sizes, coin selection, the funding held until release, and injected faults |
| `wallet_tx_fuzz`, `wallet_tx_fuzz_refuses_flags` | The parser fuzz loop with its plain driver, and the driver's refusal of a libFuzzer flag as a round count |
| `wallet_tx_no_io`, `wallet_tx_header_cxx` | The library does no input or output; its header compiles as strict C++11 |
| `wallet_tx_tool`, `wallet_tx_tool_chain` | The `gz-wallet-tx` tool (PRs 12 and 19); with the chain port, against a fake Esplora server on the loopback address only |
| `chain_json`, `chain_headers`, `chain_esplora`, `chain_multi`, `chain_confirm`, `chain_model`, `chain_fuzz` | The chain view (PR 7): the strict JSON reader, header and Merkle-proof checks, the Esplora backend on recorded answers, the comparing layer, confirmations along linked headers (fabricated signet blocks), a model of the comparing rules, a parser fuzz loop |
| `chain_local_servers`, `chain_tool_usage`, `chain_tool_refuses_mainnet_broadcast` | The libcurl transport against local hostile servers (bad certificates, redirects, slow and huge answers), and the `gz-chain` tool's usage, exit codes and mainnet refusal. `chain_live`, against the real signet servers, is opt-in and not run in CI |
| `net_*` (including `net_fuzz_noise`, `net_fuzz_tlv` and `net_gz_net`) | The transport (PR 10): BOLT 8 and BOLT 1 vectors, connection tests (timeouts, phases, the member check), the wipe test, the frame and TLV fuzz loops, the `gz-net` tool. `net_interop_py`, against an independent Python BOLT 8 peer, is opt-in (`-DGZ_INTEROP_PY=ON`) and not run in CI |
| `tree_shapes 64 8,ps 0` and `tree_shapes defects` (a workflow step, not `ctest`) | One small scale-check case, and reproductions of two defects in the imported code. These reproductions will start failing when SuperScalar fixes the defects; that is intended, and the step is then changed |

**The simulator checks four invariants** after every step (`sim/sim.h`): nothing is sent before it is saved; storage keeps what it stored; a confirmation from before a crash releases nothing; the same seed gives the same run. It runs a placeholder node and a test node. **No factory can be simulated yet**, because no engine is merged.

**A gate.** Branch protection on `main` requires all 11 jobs on a branch up to date with `main`, for administrators too. A pull request with merge conflicts gets no run at all (PR 9 today), so it cannot merge until it is rebased.

## On unmerged branches

These run in CI only on their own pull requests, and are not on `main`:

| Branch, pull request | Tests | CI today |
|---|---|---|
| `m1a-followup`, 9 | The core follow-up's tests: runner latches, stepped start, restore from backup, simulator faults | No run: the pull request conflicts with `main` |
| `core-contract-slice1`, 21 (stacked on 9) | The contract additions: watch kinds, the restore marker, the simulator invariant "secrets never leave" | Red: the handbook and the three clang jobs fail |
| `signing-core`, 15 (old draft, stacked on 9) | The signing engine as it stood when the draft was opened | Red |

Built and tested only on the build server, not on GitHub: the journal (`journal`), the lobby engine (`lobby`), the signing engine's newer state, and the core follow-up's newer commits (`SLICE1-WORK.md`).

## On the build server, by hand

Run by a builder or reviewer when they choose; results are kept in review notes, not in the repository.

- **Mutation testing**, with a different script per component (`wallet/tests/break-checks.sh`, `tools/mutate-net.py` on `transport`, and others). Survivor lists are in the review notes listed in `reviews/README.md`.
- **The full scale check** (`tree_shapes`) at sizes up to 1,000 members (`docs/notes/tree-scale-check.md`).
- **Long fuzz runs** (millions of inputs per decoder), valgrind, `gcc -fanalyzer`.
- **Comparing `python -I tools/spec-vectors.py` with the specifications.** CI runs the script and its self-checks, but nothing compares its output with the hex printed in the specifications; that was done by hand in the confirmation review.

## Not run anywhere today

- No engine tests: no engine is merged.
- No regtest: the project runs no Bitcoin node (owner's decision, `RECORD.md` section 25).
- **No automated broadcast.** One signet funding transaction was broadcast by hand with `gz-wallet-tx` on 2026-11-12; PR 19 fixed the four problems it showed (`docs/notes/wallet-tx.md`, section 10). Nothing broadcasts in CI.
- No MuSig2 (BIP 327) vectors.
- No kept fuzz corpus, no long fuzz runs in CI (60 seconds per target), no coverage report.
- No Windows or macOS build.
- No nightly job and no long soak runs.
- No interoperability test with a real Lightning node.
- No reproducible build.

# Part 2: planned

Each item names the milestone that adds it (`PLAN.md`). Where a milestone is not decided, it says so.

## Levels

| Level | What runs | What it proves | When it runs | Added by |
|---|---|---|---|---|
| 1. Reference values | The imported tree code against recorded transaction IDs | The foundations behave exactly as upstream | Every push | **Runs today** |
| 2. Standard vectors | Official vectors for signatures, group signing (BIP 327), key derivation, recovery phrases, invoices, and Lightning's message and transaction vectors | We agree with the standards byte for byte | Every push | Partly today: wallet keys (BIP 32, 39, 86), BOLT 8 and BOLT 1 (transport), BIP 341 (wallet transactions). BIP 327 with the signing engine (M1); invoices and channel vectors with M2 |
| 3. Engine tests | One engine at a time, fed events, checked on the actions it returns | Each engine's rules | Every push | Signing round: M1. Lobby and journal: Slice 1. Channel and payment: M2. Exit, watch, schedule: M3 |
| 4. Simulator | A host, many members, a pretend chain and network in one process | The whole system under failure and attack | Short runs every push (today); long runs nightly | Factories in the simulator: M1. Payments: M2. Crash and cheating runs that must pass: M3. Nightly job: not scheduled; wanted before Slice 1 is called done |
| 5. Regtest | The real programs with a real Bitcoin node and Electrum server | The ports and programs, end to end | Core set every push; all scenarios nightly | M5 ("a node of our own for controlled-chain tests") |
| 6. Signet and testnet | Our public host with scripted users | It works on a real network over days | Nightly | Slice runs by hand from Slice 1; nightly with M6 |
| 7. Release candidate | Everything above, at full size and length, plus a clean install by hand | Fit to hand to outside reviewers | Before each release candidate | M6 |

## The simulator, as planned

The main safety net. It is possible because the core does no input or output.

- **Schedules:** a seeded generator picks operations for every party: join, pay, receive, rotate, close, exit (M1 to M4). Liquidity changes and layer updates come with 1.1.0 (owner decision 9).
- **Network faults:** each message may be dropped, delayed, duplicated or reordered. *Runs today for the placeholder node.*
- **Crashes:** each party may be stopped at every point where it saves or sends, and restarted from what it saved. *Runs today for the placeholder node.*
- **Cheating:** scripted dishonest hosts and members try each attack in the threat list (`THREAT-MODEL.md`): paying a close to themselves, shrinking a balance, publishing an old state, sending a bad partial signature, withholding a result, altering a nonce. M1 for the signing round; M2 and M3 for the rest.
- **After every step,** the invariants below are checked.
- **On failure,** the seed and schedule are saved so the case becomes a permanent test.

## Invariants, as planned

To be checked after every simulator step and at the end of every regtest scenario. Numbers 4 and part of 5 run today (Part 1); the rest need the engines named.

| # | Invariant | Added by |
|---|---|---|
| 1 | Money is conserved across every state change | M1 (creation), M2 (payments) |
| 2 | Every member can leave alone with at least what they are owed | M3 |
| 3 | A party signs two different transactions that spend the same output only where the safe-to-sign rule allows it (`spec/safety-rule.md` C7): never two trees on one funding output; two cooperative closes only if each pays it at least what it is owed; one channel state number only for the same state on each of a channel's live anchors, with one revocation secret (section 4.1 rule 1). It never sends two different nonces or partial signatures for one round and item | M1 (rounds), M2 (channel states) |
| 4 | Nothing is sent before it is saved | **Runs today** |
| 5 | No secret nonce survives a restart or is used twice | M1 (the restart half runs today as "a confirmation from before a crash releases nothing") |
| 6 | No party's software publishes a state it has cancelled | M2 |
| 7 | Every payment deadline is later than the time needed to exit | M2 and M3 |
| 8 | The host's funding is never signed before every exit is signed | M1 |
| 9 | An honest party is never named as the cause of a failed signing round | M1 |

## Regtest scenarios, as planned (M5)

Each runs through a Bitcoin node and again through an Electrum server. Until a node exists these behaviours are tested in the simulator only.

- Lobby fills to target; lobby starts at the deadline; lobby misses its minimum.
- Join, receive, pay inside the factory, pay out through the host's Lightning node, receive from outside.
- Rotation into a new factory; cooperative close. (Liquidity change and layer update: 1.1.0.)
- A member exits alone with the host gone, through to spendable coins.
- The host publishes an old state; a member publishes an old state.
- Restart of each program in the middle of each operation.
- A member away for the whole response window.
- Restore from backup, then recover without publishing.

## Signet, as planned

- **One supervised funding broadcast** with `gz-wallet-tx` and `gz-chain`: done 2026-11-12. What it found is in `docs/notes/wallet-tx.md` section 10, fixed in PR 19.
- Slice 1, 2 and 3 runs by their walkthroughs (`SLICES.md`).

## Sizes

Routine runs use 4, 8 and 32 members. Nightly runs use 128 and 256. Release candidates run the target of 512. (Today: the simulator runs a placeholder; the one-process scale check runs up to 1,000 by hand.)

## Tooling, as planned

| Item | Added by |
|---|---|
| Fuzzing of every message decoder with a kept corpus and coverage guidance (clang and libFuzzer) | libFuzzer for 60 s per target in CI since PR 16 (the transport and wallet-transaction parsers). Not scheduled: a kept corpus, long runs, the chain parser in libFuzzer form |
| A second compiler (clang) and MemorySanitizer | In CI since PR 16 |
| valgrind in CI on `main` | In CI since PR 16 |
| A thread-error checker for anything concurrent | When the host serves more than one connection at once (a choice still open, `OPEN-QUESTIONS.md` Q4) |
| Coverage reports | Not scheduled |
| A nightly job for long runs | Not scheduled; wanted before Slice 1 is called done |
| One mutation runner and a committed survivors file per component | Not scheduled |
| A CI check that the imported files match `core/superscalar/IMPORT.md` | In CI since PR 16 |
| A CI check that the handbook is current | In CI since PR 16 |
| A CI check that the specifications' hex equals what `tools/spec-vectors.py` prints | Not scheduled. The CI job runs the script and its self-checks only |
| Windows and macOS builds | Depends on the platform decision (`OPEN-QUESTIONS.md` Q3) |
| Reproducible builds, pinned toolchain | Before mainnet |
| Compiler warnings are errors | Always for new code (`-Wall -Wextra -Werror`, `CMakeLists.txt`); the chain port's stricter set is the option `GZ_WERROR`, on in the gcc CI builds, so a newer compiler's new warning does not stop a local build |

## Before a release candidate (M6)

- Every invariant has passing tests at all three of simulator, regtest and signet.
- Every safety rule has its rule-removed test.
- The long simulator run and the fuzzers have run clean for a day.
- Nightly scenarios have been green for seven nights.
- Each engine has had an independent review, and its findings are closed or recorded as accepted.
- The documents state what is unreviewed.

Outside review then begins; the owner arranges it.
