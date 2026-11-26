# Slice 1.5: every path a tree can take, tested end to end

**Plan, draft 2, 2026-11-26. Not reviewed.** Design and planning only: nothing in it is built yet. Implementation starts after Slice 1 closes (section 4 says what can start earlier).

**Draft 2** takes in the owner's answers of 2026-11-26 to section 7:
- Q1 A: the milestone capital is moved only when the set is ready, at 0.1 sat/vB after checking mempool rates.
- Q3 A: the regtest suite becomes a required check after seven consecutive green runs; R1 and R2 stay on the roadmap.
- Q4 A: P5 is the recover call with a preview the host confirms, plus the automatic recovery of H15.

Q2 is still open. The coordinator's proposed middle path is written into 2.7 and section 7.

Slice 1.5 runs every path a factory can take *without* the channel engine, with the Slice 1 programs: the 13 signet tests S1 to S13 that `spec/exit.md` 11.2 adopted from the exit-path audit of 2026-11-14, plus the controlled-chain tests that used to wait for "a node of our own". Members are owed nothing in every test (no channels yet), so the INTERIM spend rules of `spec/exit.md` 3.2 and 4.5 apply throughout.

**Owner direction (2026-11-25): regtest is the routine test bed; signet is the public proof at milestones.** Every S test runs first, and repeatedly, on Bitcoin Core regtest, where blocks are instant and the test controls reorganisations, mempools and fees. A short signet set (S1, S2, S5, S12 and one full factory life) runs at each major milestone. The line "no regtest, the project runs no Bitcoin node" in `docs/TESTING.md` Part 1, and in the path study it came from, is out of date: `tools/regtest-tree.py`, `tests/regtest/tree_regtest.c` and the integration branch's `program_slice1` and `program_sweep` already run on regtest (section 1.2).

Sources read: `spec/exit.md` (draft 3), `spec/safety-rule.md`, `spec/signing-round.md`, `spec/terms.md`, `spec/journal.md`, `spec/local-api.md` 16.3, `docs/SLICES.md`, `docs/TESTING.md`, `docs/notes/program.md` on `main` at `c45af72`; `docs/notes/integration.md` (draft 13), `program/options.c`, `program/sweep.h`, `tests/program/release_build.py` and `tools/esplora-regtest.py` on `integration-slice1` at `8bb508a`; the test options in the diffs of open pull requests #53, #54, #55, #93, #95, #97; #57's text (deep checks on GitHub's runners). The imported tree builder is read at the pin in `core/superscalar/IMPORT.md` (`50f7fa13`).

Marks, as in the specifications: **[C]** read in code (file and line on the named branch); **[S]** a primary public source; **[M]** measured (a run named); **[R]** reasoning or estimate, not checked.

## Contents

0. Answers to the open questions
1. Common ground: the two test beds, the coin-total check, the parties
2. The tests, one by one (S1 to S13, then R1 to R8)
3. New pieces to build, in order, one pull request each
4. What can start before Slice 1 is done
5. Tonight: run 1's recovery as the first S1
6. Order, parallelism, the signet milestone set and the roadmap
7. Questions for the owner
8. What this plan did not check

---

## 0. Answers to the open questions

**0.1 Do our tree transactions use version 3 with a P2A anchor?** Yes, on `main` since the re-import of #46 (merged 2026-11-17; pin `50f7fa13`). `FACTORY_TREE_TX_VERSION` is `3u` [C: `core/superscalar/include/superscalar/factory.h:47`]. A keyless P2A output is appended last to every tree transaction when `use_tree_anchor` is set [C: `factory.h:466-472`, `src/factory.c:575-631`], and Gazpacho's glue always sets it [C: `core/tree/import/tree_import.c:113`]. The anchor is 240 sat at any non-zero tree rate; it is 0 (ephemeral dust) only at rate 0 [C: `factory.h:839-842`], which `spec/terms.md` forbids (at least 100 sat/kvB). The regtest run of #46 confirmed both on Bitcoin Core 29.1 [M: `tools/regtest-tree.py`, `spec/exit.md` 5.9 "Sent alone"]. Run 1 on signet (2026-11-25) was built on this pin: its root kickoff is 167 vbytes, the size of a version-3 two-output kickoff with its anchor [M: `integration.md` 9]. **The funding is not TRUC:** it is a version-2 wallet transaction with sequence `0xfffffffe` [C: `wallet/tx/src/funding.c:180`, `:192`]; only the spend-back signals replacement (`0xfffffffd`, `:372`). This matters for S7 and S8.

**0.2 Do `spec/terms.md`'s bounds allow a short end height, or do we need a test-build "short life" setting?** The terms allow it: `lifetime_blocks` and `winddown_blocks` are each 1 to 52,560 [`terms.md` 3, types 26 and 28]. The binding floor is the member's own safety check, not the terms: at its acknowledgement a member requires `leave_by` (every step of its path missing) to be at least its funding deadline plus B plus one block (`safety-rule.md` C8 row "End height"; [C: `core/tree/exit.c:60-63`]). With the signet constants (A 6, B 3, M 14, funding deadline 36) that is E ≥ tip at the ack + 16·d + 74: **90, 106 and 122 blocks** at depths 1, 2 and 3 [R, matching `program_ack_depth`'s bound in `integration.md` 5]. A test-build setting below that would have to weaken a safety check, which the integration rules forbid. **Under the owner's direction it is not needed at all:** on regtest, T1's 180-block life is mined in seconds, and the one signet full life uses T1 unchanged. The only "short life" left is S6's second run, which needs an end height that fails the late-funding re-check; that is a real term value (lifetime + wind-down 112 at depth 2), not a test setting (2.6). **Recommendation: drop the short-life setting.**

**0.3 How does S12 probe package submission harmlessly?** In four steps, cheapest first, each against both servers separately (section 2.12): (1) a malformed body to `POST /txs/package` (Esplora's documented endpoint [S: Blockstream esplora `API.md`]): a 400 with a parse error means the endpoint exists, a 404 means it does not; nothing can be broadcast. (2) A zero-fee version-3 parent that spends one host test coin back to the host's own address, with a 240-sat P2A, sent **alone**: it must be refused for its fee, which costs nothing. (3) The same parent with its 65-byte anchor-only child as a package: if accepted, the only effect is the host's own coin moving to the host's own address and 240 sat of fee. (4) A real tree step sent as a package, inside S2. On regtest the same four steps run against the shim with `submitpackage` behind it (3.2), with node floors set to 1 and 0.1 sat/vB, so the result is known before any signet coin moves.

**0.4 Parallel factories.** Yes. On regtest every test is minutes, so parallelism matters only for CI time (shards, 1.3). On signet, the milestone set runs as parallel factories from separate host folders, one per fault switch (section 6.2), which cuts the signet milestone from about four days run one after another to about 31 hours.

---

## 1. Common ground

### 1.1 What "pass" means

Per `docs/SLICES.md` rule 5 and `docs/TESTING.md` principle 2, a test passes only if:
1. its **written walkthrough** (steps a newcomer follows, through the interface where the step is a person's action) passes;
2. its **automated run** (the same steps through the same local API, from a test script) passes, **twice in a row** from clean folders;
3. the **coin totals** computed by the independent ledger check (1.4) from confirmed transactions alone balance to the satoshi, and agree with what each program says it recovered.

On regtest, (1) to (3) run on every nightly. On signet, at a milestone, the walkthrough and one automated run each count as a run, so a milestone signet pass is two runs, of which one may be the walkthrough.

### 1.2 Test bed 1: regtest (routine)

What exists, and what each S test reuses:

| Piece | Where | State |
|---|---|---|
| `tools/regtest-tree.py` + `tests/regtest/tree_regtest.c` | `main` | A T1 tree level by level on a node it starts: version 3, P2A, `submitpackage`, refusal alone at a 1 sat/vB floor and acceptance at 0.1, the host timeout spend non-final until H_leaf [C: header of `regtest-tree.py`] |
| `tools/esplora-regtest.py` | `integration-slice1` | An Esplora look-alike over the node's RPC, loopback only, refuses any chain but regtest. **The package endpoint answers 404** [C: its docstring] |
| `tests/program/slice1.py` (`program_slice1`) | `integration-slice1` | One host and three members, separate `gazpacho-test` processes, a real funding at 0.1 sat/vB, buried, Live by each chain view; skipped (77) without `GZ_BITCOIN_BIN` [C: `integration.md` 5] |
| `tests/program/sweep.py` (`program_sweep`) | `integration-slice1` | The host's timeout sweep: refused before its height by the tool and by the node, owed outputs refused, every satoshi accounted [M: `integration.md` 6, 9] |
| Core download, verified | open #57, `deep-checks.yml` | Core 29.1 from bitcoincore.org, `SHA256SUMS` signed by at least 3 pinned guix.sigs builder keys, the tarball hash pinned [PR #57] |

What regtest adds over signet: instant blocks (`generatetoaddress`), reorganisations (`invalidateblock`, `reconsiderblock`), the relay floor per node (`-minrelaytxfee`), fee pressure (filling the mempool with the test's own transactions, `prioritisetransaction`), exact heights, two nodes for two "operators", and hundreds of runs. What it cannot show: the public servers' real policy and versions, real propagation, real block times. That is what the signet set is for.

**Two operators on regtest.** The chain port compares servers by operator (`--chain-operator`; all loopback names count as one operator unless named [C: `program.md` 2]). Each regtest test runs **two nodes**, peered, each with its own shim, named as two operators. That gives S13 natively (stop the peering, or hide a transaction in one shim) and lets S12 compare a 1 sat/vB node with a 0.1 sat/vB one.

### 1.3 How regtest runs in CI

- **Where:** GitHub Actions, standard runners, through #57's `deep-checks.yml` once it merges: a new suite `regtest-paths` beside its existing `regtest` suite.
- **Core:** downloaded, never built: an **exact pinned version**, its `SHA256SUMS` checked against at least 3 pinned builder signatures and its tarball against the pinned hash, as #57 already does for 29.1.0. Two versions: **29.1.0** (floor 0.1 sat/vB) for every test, and **29.0** (floor 1 sat/vB, incremental relay 1 sat/vB) for S7, S12 and R8, which depend on the floor. (Core 30.0 moved the same defaults to 0.1 sat/vB [S: Bitcoin Core 30.0 release notes]; add it when a third pin is worth its time.)
- **When:** nightly on `main` (with #57's other suites) and **on every push to `integration-slice1`**, because the programs that run S1 to S13 live there until Slice 1 merges. On pull requests that touch `core/tree`, the exit engine, the sweep, `ports/chain` or `tests/program`, a smoke set (S1, S2 at depth 2, S5) on demand (`workflow_dispatch`).
- **Shape:** one job per test group, `max-parallel` as #57 sets it (the 20 runners are shared with CI). Each job uploads the nodes' logs, the programs' logs and the ledger check's JSON as artifacts.
- **Required after seven consecutive green runs** (owner, 2026-11-26, Q3 A). Once Slice 1.5's pieces are on `main`, the suite becomes a required check there after **seven green runs in a row**. Since regtest runs accelerated, the seven may be dispatched back to back (`workflow_dispatch`); they need not be seven nights. A red run starts the count again.
- **Reorganisations stay on the roadmap explicitly.** R1 (the funding reorganised out before burial) and R2 (after burial, with a double spend) are in the suite from its first version. They are not dropped to make the seven runs pass (6.4).
- **Gates:** `permissions: contents: read`, no secrets, actions pinned by full SHA, as #57. Regtest nodes listen on loopback only with `-listen=0`.

### 1.4 The independent coin-total check

A new tool, `tools/chain-ledger.py` (standard library only, `python -I`), **not** linked to any Gazpacho code. Given a funding txid, the host's and members' destination scripts and one or more Esplora base URLs, it:
1. fetches the funding and every transaction that spends any output reachable from it (`/tx/T/outspend/N` recursively), from **each** server, and refuses if the servers disagree on any confirmed spend;
2. decodes each transaction itself (its own small parser), checks version 3 and a 240-sat P2A last on every tree transaction, and recomputes every fee as inputs minus outputs;
3. prints, and checks: **funding amount = Σ paid to the host + Σ paid to members + Σ fees + Σ value still unspent** (anchors left on chain counted by name), to the satoshi; every output spent at most once; every tree transaction's txid in the set the host printed at signing (`sweep-tree` lines) and **no other** tree transaction on chain;
4. per test, the extra assertions named in section 2.

It reads only confirmed transactions (B confirmations), so it is the same tool on regtest (against the shims) and on signet (against both public operators). It never broadcasts.

### 1.5 Parties and terms

- **Parties:** the `gazpacho-test` program, one process per party, one data folder each, as `program_slice1`. "Host + 3" means one host and three members.
- **Terms:** T1 (`spec/terms.md` vector T1) with `channel_sat` 10,000 (integration F14: a factory then fits one 0.001 coin: 82,811 sat at 3 members [M: run 1]), tree rate 100 sat/kvB (0.1 sat/vB), lifetime 144, wind-down 36, so **E = tip at the begin + 180** (`terms.md` 4.5, INTERIM). Depth: 3 to 8 members give D = 2 (3 members: depths 1, 2, 2), 9 to 16 give D = 3 [`exit.md` 4.2].
- **The spare-liquidity delay** (proposal record 32, `lstock_delay`, inside the member's conditions [C: `core/tree/checks.c:382-387`]) stays at its default 144 on regtest (mining 144 blocks is instant). On signet, a factory that must see the host's spare sweep (H-3) uses 144 too, and that sweep lands after E (2.2).
- **INTERIM heights** used below, from `exit.md` 3.2 and `safety-rule.md` 12 value 2: a root output (into depth 1) times out at E − 5, an output into depth j at E − 5·(2j − 1), the leaf transaction's input and the channel output at H_leaf = E − 10·d. A spend with lock time L is accepted into a mempool from tip L and mined from block L + 1.

### 1.6 Signet constants for costs and times

- About 6 blocks an hour (10 minutes a block); burial B = 3 is about 30 minutes [M: run 1, buried about 30 minutes after broadcast].
- Fees at 0.1 sat/vB: funding 16 sat (154 vB) [M: run 1]; tree transactions pre-paid by the host inside the funding: 17 sat for a two-output kickoff or leaf transaction (167 vB), 13 for a leaf kickoff (124 vB), 26 for a four-output kickoff (253 vB) [`exit.md` 4.2]; a host sweep of two root outputs 26 sat [M: `program_sweep` and run 1's print]; every tree transaction carries a 240-sat anchor that is either spent whole as fee by a 65-byte anchor-only child or left on chain (below dust alone) [`exit.md` 5.2; `integration.md` 9].
- Regtest coins cost nothing; regtest time is the programs' polling (250 ms in the tests) and the test's own pacing.

---

## 2. The tests

Each test: the path (`exit.md` 7), the steps (the walkthrough, which the automated run repeats through the local API), the program commands and test switches it needs (**exists** with where, or **new** with the piece of section 3 that adds it), the ledger assertions, then regtest time, and signet cost and time where it is in the signet set or can run there.

New pieces are named by their section-3 numbers: **P1** ledger, **P2** package broadcast, **P3** exit engine (tree half), **P4** member "publish my path", **P5** host sweep command, **P6a to P6g** fault switches, **P7** shim and harness additions.

### 2.1 S1: the host recovers a factory by its timeouts (E-5, H-2 INTERIM)

Host + 3 (repeat at host + 4 and host + 9, so one run has a four-output root).

Steps:
1. The host opens a lobby on T1; three members join and ready; the round is signed; the host funds; the funding is buried; every party is Live.
2. All members stop (they are owed nothing; X-7: a stopped member is the normal case).
3. Any time after burial, the host publishes the root kickoff from its held tree (**P5**: `POST /api/v1/factories/{id}/recover`, the first action of its plan). Check: the root kickoff's txid equals the held tree's.
4. At tip E − 6 the host's spend of a root output is offered to both servers and **refused as not final** (the command refuses it itself; `--test-sweep-force` builds it anyway to show the server refusing).
5. At tip E − 5 the host's command broadcasts the sweep of every root output (one transaction); it is mined from block E − 4. (At depth 3 with a four-output root, the same.)
6. When the sweep is buried the host shows the factory ended, `ended_how = host_timeout_recovered` (a new value for `local-api.md`; section 7 Q4).
7. The members, started again, show the factory ended, each spend classed S1 (root kickoff) and S2 (INTERIM host timeout), owed nothing, nothing lost.

Commands and switches: the host's recover command (**P5**, new; today the test tool `--test-sweep HEIGHT`, `--test-sweep-force`, `--test-sweep-to`, `--test-owed N` [C: `program/options.c`, `integration-slice1`] exists and only prints). The broadcast itself: today by hand from the printed hex; with P5, the program's chain port.

Ledger: funding amount = root kickoff fee + its anchor (left unspent) + sweep fee + the host's recovered amount. Run 1's numbers: 82,811 = 17 + 240 + 26 + 82,528 [M: `program_sweep` pattern; run 1's print]. No other tree transaction on chain; each root output spent once, by the host's spend, with lock time E − 5.

Regtest: about 2 minutes (mine 180 blocks). Repeat with E − 6 broadcasts at both nodes.
Signet (milestone set): cost ≈ **299 sat** (funding 16 + 17 + 240 + 26); capital 82,811 sat locked for the life; **about 30 hours** from the begin (E = begin + 180; sweep mined at E − 4, buried 3 later).

### 2.2 S2: a member publishes its own path, the host stopped (U-1 tree half, H-3)

Two shapes: host + 4 (every leaf at depth 2: four tree steps on the path) and host + 9 (depth 3: five steps).

Steps:
1. As S1 step 1. Then the host stops.
2. Member m1 asks to leave alone (**P4**: `POST /api/v1/factories/{id}/leave-alone/preview`, then `leave-alone`, `local-api.md` 16.3). Its plan shows each step's kind and state (`tree`, `leaf_kickoff`, `leaf`; `pending`, `waiting`, `due`, `sent`, `confirmed`, `buried`). No `channel` step exists in Slice 1.5.
3. The wallet sends the root kickoff, waits one confirmation, then each fixed kickoff, the leaf kickoff and the leaf transaction, **one level per block** (TRUC: one unconfirmed parent, one child [`exit.md` 4.2]). Each step goes alone if every server accepts it at its own rate, otherwise as a package with its 65-byte anchor-only child (**P2**).
4. Record, per step, the blocks from broadcast to confirmation: this is the measurement of A (`exit.md` 4.3: A = 6 is [M], "measured by S2").
5. The host starts again. Its watch classes the published path as a member's exit (S1). The host's recover command (**P5**) then sweeps what it may alone, each at its own height: the root's other output (E − 5), the depth-1 kickoff's other output into a sibling's leaf kickoff (E − 15 at depth 2), m1's channel output (H_leaf = E − 20, the member owed nothing), and m1's spare liquidity 144 blocks after m1's leaf transaction confirmed (H-3).
6. m1 shows `ended`, `left_alone`, owed nothing; the other members show `branch_partly_on_chain`, `important`, never `at_risk` (U-2).

Commands and switches: **P4** (new), **P5** (new, deeper outputs and the spare CSV), **P2** (new). No fault switch: stopping the host is a process stop.

Ledger: only m1's path among tree transactions; each step version 3 with its anchor; per step either the anchor-only child spent the anchor (240 sat of fee) or the anchor is left unspent; funding = Σ pre-paid fees on the path + Σ anchors burned or left + Σ host sweep fees + Σ host recovered. Every output on chain ends with exactly one spend except anchors left by name.

Regtest: about 3 minutes per shape. Signet (milestone set, both shapes): cost ≈ **1,100 sat at depth 2** (funding 16, path fees 64, four anchors 960, three or four host sweeps about 60) and ≈ **1,450 sat at depth 3** [R]; capital 82,811 sat at host + 4, and up to about 332,000 sat at host + 9 if the 16-member shape is funded as 16 leaves (the program prints the funding it needs before any coin moves [M: run 1's first attempt]; check with `tools/spec-vectors.py` before funding). Time: the member's part **about 1 hour** (four or five blocks plus burial); the host's last sweeps at E − 4 (about **30 hours** from the begin), and the spare sweep 144 blocks after m1's leaf transaction confirmed, about **25 hours** from the begin, so inside the same window.

### 2.3 S3: a second member exits after the first (U-1 on a partly published path, U-2)

Host + 4, the same factory as S2 at depth 2: m2 is m1's sibling under the same depth-1 kickoff.

Steps: after S2 step 3, m2 asks to leave alone. Its plan shows the root kickoff and the shared kickoff `confirmed` already, and only its own leaf kickoff and leaf transaction `due`. INTERIM display: its `leave_by` moves A later per step already confirmed (`exit.md` 7.3 U-2).

Commands: **P4**. Ledger: no tree transaction broadcast twice to the chain (each txid confirmed once); m2's two steps only; the shared ones are S2's.

Regtest: under a minute, after S2. Signet: not in the milestone set; if run, +2 anchors (480 sat) and about 40 minutes.

### 2.4 S4: one path published, the host sweeps the untouched branches (E-5 with U-2, H-2 INTERIM)

Host + 4, the same factory as S2 and S3. The root's other branch (m3, m4) is untouched.

Steps: after S2 and S3, the host's recover command sweeps the root output into the untouched branch at E − 5, and, on the published branch, the channel outputs of m1 and m2 at H_leaf and their spare liquidity after 144 blocks. A run with `--test-owed 3` (exists, on the test tool; P5 keeps the check as the H15 refusal) shows the host refusing the untouched branch's output when a member below it is owed.

Ledger: **every output of every confirmed transaction of the factory ends with exactly one spend**, anchors left on chain listed by name; nothing else unspent; totals balance.

Regtest: included in S2's run. Signet: not in the milestone set except as part of the full life (6.3).

### 2.5 S5: the host never funds (C-4)

Host + 3.

Steps:
1. Lobby, round, every member's `round_ack`.
2. The host does not broadcast the funding (**P6a** `--test-never-fund`).
3. Each member: `creation_abandoned` (still watched) 36 blocks after the tip at its ack.
4. The host spends one input of the planned funding to itself (`--test-spend-coin TXID:VOUT:AMOUNT:SCRIPT` **exists** on `integration-slice1` [C: `program/sweep.h`], prints the transaction; P6a adds its broadcast in the test build). When that spend is buried, each member shows `creation_dead`; records kept; nothing signed again on that outpoint.

Ledger: no funding transaction exists on chain; the input's spend pays the host; fee only.

Regtest: about a minute. Signet (milestone set): cost ≈ **12 sat** (one input, one output); **about 7 hours** (36 blocks, then the spend and its burial).

### 2.6 S6: the funding is buried after the member's deadline (C-6)

Host + 3, two runs.

Steps:
1. Lobby, round, acks. The host holds the funding back (**P6b** `--test-fund-after-blocks N`) for 40 blocks, past every member's 36-block deadline: members show `creation_abandoned`.
2. The host broadcasts; it is buried.
3. **Run A** (T1, E = begin + 180): at burial each member re-runs C5 and C8's time checks (C11); `leave_by` at depth 2 is E − 66 = begin + 114, at least burial + B + 1: **Live**.
4. **Run B** (terms with lifetime 72 and wind-down 40, so E = begin + 112, which passes the check at the ack with a few blocks to spare (0.2)), and the funding held for 45 blocks: at burial `leave_by` = begin + 46 is below burial + B + 1: the creation **stays Abandoned**, still watched.
5. Both factories are then recovered by the host as S1.

Ledger: as S1 for each factory; for run B, additionally, no member's record says Live.

Regtest: about 2 minutes each. Signet: not in the milestone set (about 8 hours to the verdict, then the factory's life to recover).

### 2.7 S7: the funding does not get relayed alone, then a child on the host's change (C-4, H16)

Host + 3. **Changed from the audit's wording** (0.1): the funding is version 2, and Bitcoin Core relays a non-TRUC parent in a package only if it meets the minimum relay feerate on its own [C: the import's comment at `factory.h:41-46`]. So "funding below the relay floor, rescued by a child" cannot happen for our funding on any node; the test has two halves.

Steps:
1. **Negative half (harmless):** the host builds the funding at a rate below the node's floor (**P6c** `--test-funding-rate SATKVB`, test build only, may go below the term's floor) and sends it alone and then as a package with a child on its change. Both are refused; the test records the server's reason. Nothing confirms; the members wait and, after 36 blocks, show Abandoned; then S5's step 4.
2. **Positive half:** the funding at the floor (0.1 sat/vB on 29.1, 1 sat/vB on a 29.0 node) and a child on the host's change at a higher rate (**P6c** `--test-funding-child SATKVB`), sent as one package through **P2**. The same funding txid confirms; members go Live at burial.

Ledger: positive half: the funding's txid is the one every member signed for; the child spends only the change.

Regtest: on 29.1 and 29.0 nodes, a minute each. Signet: not in the milestone set; S12 decides whether it is worth one run there.

**Open with the owner (Q2).** The funding cannot be replaced by fee: the tree is pre-signed against its txid, so a replacement kills it (C-7, H16). A stuck funding can only be bumped by a child.

**The coordinator's proposed middle path, pending the owner's decision:** keep the funding at version 2, but always give it an output the host can bump from. That is the host's change when there is change, or a non-dust 240-sat P2A output when change would be dust. S7's positive half then also covers the P2A case: a funding with no change, bumped by a child on its P2A.

If adopted, it changes:
- the wallet's funding builder (`wallet/tx/src/funding.c`);
- H16's wording (`spec/safety-rule.md`, `spec/exit.md` 5.7);
- the funding's size and fee vectors.

### 2.8 S8: the host replaces the funding by fee (C-7, negative)

Host + 3.

Steps: lobby, round, acks, funding broadcast. Within seconds, the host broadcasts a replacement that spends one funding input back to itself at a higher fee (**P6d** `--test-replace-funding SATKVB`, built on the existing spend-back builder [C: `wallet/tx/src/funding.c:355-372`; `core/funding/funding.c:1173`]). The replacement confirms. Every member shows `creation_dead`, cause `funding_replaced`, "Nothing was owed." Nothing is signed on the replacement's txid.

Ledger: the funding txid never confirms; the replacement pays the host; its fee is at least the funding's plus the incremental relay fee.

Regtest: exact, since the test mines only after the replacement. Signet: not in the set; there the original can be mined first (a race against the next block), which voids the run but loses nothing.

### 2.9 S9: abort after partial signatures, then retry (C-2, H11)

Host + 4.

Steps:
1. The host collects every partial signature and then aborts before `round_complete` (**P6e** `--test-abort-after-partials`). Each member, which saved its exposure record before sending (C7), shows the round Unfinished, then Abandoned after one signing budget (10 minutes on its own clock).
2. The host starts attempt 2: its funding engine plans a **new funding that spends an input of the old one** (H11, exists in `core/funding/funding.c:524-606` [C]). Each member refuses any tree on the old outpoint (reason 11) and signs the new one.
3. The new funding is buried: the factory is Live; each member's old record becomes Dead (an old input spent and buried).

Ledger: one funding on chain; it spends an input of the old plan; the old outpoint never exists.

Regtest: about 12 minutes (the signing budget is wall-clock time; the test may run with a shorter `signing_budget_ms` in its terms, a real term). Signet: not in the set.

### 2.10 S10: abort in the nonce step; a member withholds its ack (C-1, C-4)

Host + 4, two parts.

Steps:
1. m1 drops `round_all_nonces` (kind 68) with `--test-drop-kind 68` (**exists** [C: `program/options.c`]). Its nonce step times out (60 s); the round aborts; m1 starts again without the switch; the host's next attempt uses **the same funding outpoint** (no partial signature existed) and succeeds.
2. In a second lobby, m1 signs but never sends `round_ack` (**P6f** `--test-withhold-ack`). The host does not fund (H1); it starts again without m1, on a new outpoint.

Ledger: part 1, the funding spends the outpoint planned in attempt 1; part 2, no funding for the round m1 did not ack.

Regtest: about 3 minutes. Signet: not in the set.

### 2.11 S11: restore from a backup taken before a round, then a replay (C-10)

Host + 3.

Steps:
1. m1's folder is copied (the backup) before the lobby's ready check.
2. The factory forms normally.
3. m1 is restored from the copy (`--test-restore-from FILE` exists on `integration-slice1`; `--test-start-as-restore` in #54 [C: diffs]). It draws a new restore epoch.
4. The host sends m1 the old round's proposal again (**P6g** `--test-replay-propose`, unless `--test-commands`' `raw-kind` can carry a whole message; check). m1 refuses with reason 12; the guard reports a stale backup; no old key is derived.

Ledger: as S1 for the factory (recovered later); nothing from m1's restored wallet on chain.

Regtest: about 2 minutes. Signet: not in the set.

### 2.12 S12: a tree step bumped through its anchor; package submission (X-2; `THREAT-MODEL.md` 2.4)

Host + 3. **Runs before any exit is relied on.**

Steps:
1. **Endpoint probe, per server:** `POST /txs/package` with a malformed body (P2's probe mode in `gz-chain`). 400 means present, 404 absent. Nothing broadcast.
2. **Alone, refused:** a zero-fee version-3 parent, one host test coin to the host's own address plus a 240-sat P2A, sent alone. Expected refusal for its fee. Cost nothing.
3. **As a package:** the same parent with its anchor-only child. Accepted or refused, per server, recorded with the reason. If accepted, it confirms: the host's coin moves to itself, 240 sat of fee.
4. **A real step:** in an S2 factory, the root kickoff sent as a package with its anchor-only child although it would be accepted alone at a 0.1 sat/vB floor, to show the exit engine's package path end to end.
5. **Report:** per server, does it accept TRUC, P2A spends, a sub-floor TRUC parent in a package; and the program's check (`exit.md` 11.2 blocker items 2 and 3): a server that refuses a version-3 step as non-standard is not used for exits, and `chain_no_truc_server` shows when none is left.

Regtest (first, decides the design): two nodes, floors 1 and 0.1 sat/vB, on 29.0 and 29.1, behind shims with the package endpoint enabled (**P7**); the 404 case with it disabled.
Signet (milestone set): cost ≈ **240 sat** (step 3, once; the second server then sees it already in its mempool) plus step 4's part of S2; **under an hour**.

### 2.13 S13: two chain servers disagree, or one hides the funding (C11, `exit.md` 4.6)

Host + 3.

Steps:
1. One of the member's two servers hides the funding (the shim's hide option, **P7**: `/tx/T/status` unconfirmed, `/tx/T/hex` 404, its outspends empty). No member goes Live on the other server's word.
2. The hiding server also freezes its tip: the tip estimate T_dl still advances with the clock (one block per `BLOCK_FAST_S`, 300 s), so dates move early, never late.
3. The hiding stops: members go Live at burial as seen by both.

Ledger: as S1.

Regtest only (two nodes, two shims): about 15 minutes (the clock term needs real time). On signet the public servers cannot be made to lie; a filtering proxy in front of one would test the same code as regtest.

### 2.14 The regtest-only tests, now in the main plan

Each needs control a public network does not give. INTERIM rules apply; the design-2 rows of `exit.md` 11.4 wait for the re-import of #508.

| # | Test | Path | Pass when | Needs |
|---|---|---|---|---|
| R1 | Funding reorganised out before burial (`invalidateblock` at depth 1 and 2), then the same txid mined again | C-8 | Members return to awaiting funding, then Live on the same tree | P7 reorg helper |
| R2 | Funding reorganised out after burial (depth 4) and a funding input double-spent in the new branch | C-9 | Payments stop (none here), `void_funding`, `funding_double_spent`; the loss (zero here) recorded | P7, P6d's spend-back builder for the double spend |
| R3 | A step of a member's exit reorganised out mid-path | X-1 | The step counts as missing again, is rebroadcast; dates recomputed | P3, P4, P7 |
| R4 | Fee pressure while a path is half published: the test fills both mempools above the anchor-only package rate | X-2 | The step waits; `exit_step_late` when its INTERIM `step_due` passes; with a wallet coin (later) it would climb. Records how long a coinless step waits | P3, P7 mempool filler |
| R5 | The last-block edges: the member's path finishes in block H_leaf − (B − 1), and in another run one block late; the host's spend at tip H_leaf − 1 (refused) and H_leaf (accepted) | H-2 INTERIM (audit's S31) | The host can first win at exactly vector X1's height | P3, P5 |
| R6 | Every member exits at once at 128 and 512 members, mempools full | U-3 | Every path confirms, no conflict between siblings' identical shared steps and children; ledger balances | `tree_regtest`-style driver: the core in one process, not 512 programs (section 3, P8). Needs terms with deeper shapes than T1's 16 members |
| R7 | A stranger's child on a published step's anchor; the free pin by the next pre-signed level | X-2, `exit.md` 5.5 | The foreign child is classed S9b, never `at_risk`; at 0.1 sat/vB the anchor-only child evicts the next level on 29.0 and 29.1 | P3, P7 |
| R8 | Package floors: S12 steps 2 and 3 on nodes at 1 and 0.1 sat/vB, on 29.0 and 29.1 | — | The table of what each version accepts, against `exit.md` 5.9's claims | P2, P7 |

### 2.15 Summary

| Test | Fault switches (exists / new) | Program commands | Regtest | Signet milestone | Signet cost | Signet time |
|---|---|---|---|---|---|---|
| S1 | `--test-sweep-force` (exists) | P5 recover | 2 min | **Yes** | ≈ 299 sat | ≈ 30 h |
| S2 | none | P4 leave-alone, P5, P2 | 3 min per shape | **Yes, depths 2 and 3** | ≈ 1,100 + 1,450 sat | 1 h member, ≈ 30 h host |
| S3 | none | P4 | < 1 min | In the full life | ≈ 480 sat | 40 min |
| S4 | `--test-owed` (exists, kept by P5) | P5 | in S2 | In the full life | in S2 | in S2 |
| S5 | P6a `--test-never-fund`; `--test-spend-coin` (exists) | — | 1 min | **Yes** | ≈ 12 sat | ≈ 7 h |
| S6 | P6b `--test-fund-after-blocks` | P5 | 2 × 2 min | No | — | — |
| S7 | P6c `--test-funding-rate`, `--test-funding-child` | P2 | 2 × 1 min | No (unless S12 says so) | — | — |
| S8 | P6d `--test-replace-funding` | — | 1 min | No | — | — |
| S9 | P6e `--test-abort-after-partials` | — | 12 min | No | — | — |
| S10 | `--test-drop-kind 68` (exists); P6f `--test-withhold-ack` | — | 3 min | No | — | — |
| S11 | `--test-restore-from` (exists), `--test-start-as-restore` (#54); P6g `--test-replay-propose` | — | 2 min | No | — | — |
| S12 | none | P2 probe, P4 | 2 min per node pair | **Yes** | ≈ 240 sat | < 1 h |
| S13 | none (shim hide, P7) | — | 15 min | No | — | — |
| R1 to R8 | P7 helpers | P3 to P5 | minutes each; R6 longer [M owed] | No | — | — |

One signet milestone pass (two runs of S1, S2 at both depths, S5, S12, and the full life of 6.3) costs about **7,500 sat** in fees [R], and needs about 0.9 million sat of capital in flight at once if run in parallel (section 6.2).

---

## 3. New pieces to build, in order

Each is one pull request, test first (the failing test is the first commit). "Spec" lists the sections it implements. Every new `--test-*` option is compiled into `gazpacho-test` only, follows `program.md`'s rule (the release build refuses `--test-*` without knowing their names, B4), and is **added to `TEST_STRINGS` in `tests/program/release_build.py`** so `program_release_build` fails if its name reaches the release binary.

**Already owed: `TEST_STRINGS` lists only four option names** (`--test-pings`, `--test-timer-ms`, `--test-start-delay-ms`, `--test-node-error-at`) [C: `tests/program/release_build.py:29-30`, `integration-slice1`]. The existing `--test-sweep`, `--test-sweep-force`, `--test-sweep-to`, `--test-owed` and `--test-spend-coin` are not in it. P0 below adds them.

### P0. `TEST_STRINGS` catches up (integration branch, then each owner's PR)
- Adds every `--test-*` name `program/options.c` knows today, generated from its usage block so the list cannot fall behind again (a check that each name in the test build's usage text is in `TEST_STRINGS`).
- Tests first: `program_release_build` fails on a test binary built with one name removed from the list.
- Depends on: nothing. Base: `integration-slice1` (the sweep and spend-coin options live there), folded into their owners' PRs.

### P1. The independent coin-total check, `tools/chain-ledger.py` (main)
- Spec: `docs/TESTING.md` principle 2; `exit.md` 11.1 "independent accounting" (X-I6).
- Tests first: recorded Esplora answers of `program_sweep`'s regtest factory and of run 1 on signet (both public chain data), which must balance; the same with one satoshi altered, an extra unknown spend, and two servers disagreeing, which must fail.
- Depends on: nothing. Its own transaction parser; no Gazpacho code.

### P2. Package broadcast in the chain port, `gz_chain_broadcast_package` (main)
- Spec: `exit.md` 10.5 (chain port), 5.1, 5.8 (package relay), 11.2 release blocker item 1; open point 14; `THREAT-MODEL.md` 2.4.
- What: `POST /txs/package` (Esplora [S: `API.md`]) with one parent and one child; per-server results (accepted, refused with reason, endpoint absent); `gz-chain package` and `gz-chain package --probe` (the malformed-body probe of 0.3).
- Tests first: against local hostile servers, as `chain_local_servers` does: endpoint 404, 400 on malformed input, parent refused and child accepted, both accepted, slow and huge answers; mainnet refused as for `POST /tx`.
- Depends on: nothing (`ports/chain` is on main).

### P3. The exit engine, tree half (main, core)
- Spec: `exit.md` 2 (path, step), 4.2 (one level per block), 4.5 (INTERIM dates, for display), 5.2 (anchor-only child), 5.4 (rebroadcast every block; no wallet child in 1.5), 6.2, 6.3 steps 0, 2, 4 and 8 (no channel, so no commitment, no claims), 7.3 U-1 and U-2, 8 (watch by outpoint and txid; classes S1, S2, S3, S7 not reachable, S8, S9); `journal.md` 9.1 records `exit_plan`, `exit_started`, `exit_step`, `exit_ended` (type numbers already assigned, D13), brought forward from Slice 3; `local-api.md` 16.3's step kinds and states.
- What: a core engine (no input or output) that, from the held signed tree and the chain view, plans the member's path, builds each step's anchor-only child, saves before it sends, skips a step already confirmed, and classifies every spend of a watched output.
- Tests first, in the simulator: U-1 at depths 1, 2, 3; U-2 with every prefix of the path already confirmed; a sibling's identical anchor-only child (S9a); a foreign child (S9b); a step's input spent by an unknown transaction (S8, `unexplained_spend`); a crash at every save point and a restart that rebroadcasts every `sent` step first; a reorganisation that removes a confirmed step.
- Depends on: the core contract's outpoint and txid watches and broadcast results (on main with the funding engine, #56).

### P4. The member's "publish my path" command (integration, then main with Slice 1's program)
- Spec: `local-api.md` 16.3 (`leave-alone/preview`, `leave-alone`, `GET leave-alone`, kind A confirmation); `exit.md` 6.1 trigger `user`, 6.3; 11.2 release blocker items 2 and 3 (check that each configured server accepts a version-3 step, alone or as a package; the strip's `chain_no_truc_server`); `exit.md` 10.2 attention codes used (`exit_step_late`, `exit_step_held_back`).
- What: the program wires P3 into the composite node, its broadcasts and packages to P2, its progress to a view, and the interface's leave-alone screen (concept H). In Slice 1.5 the answer's amount is 0 and the steps are tree steps only.
- Tests first: `tests/program/leave_alone.py` on regtest (S2, S3 shapes), and the API test for 16.3's errors (`host_factory`, `already_exiting`, `preview_expired`, `confirm_mismatch`, `chain_in_doubt`).
- Depends on: P2, P3; **#54** (the sealed journal, where the member's held tree and the exit records live); **#55** (view objects for `exit_progress`); **#53** only for the kind-A confirmation's real unlock (the anchor-only children need no key); the integration branch's wiring.

### P5. The host's recovery: a recover call with a preview, and the automatic sweep by timeout (integration)

**Definition (owner, 2026-11-26, Q4 A).** Two ways in, one engine:
1. **A local-API recover call with a preview, which the host confirms.**
   - `POST /api/v1/factories/{id}/recover/preview` answers with everything that would be broadcast: each transaction (its txid, which outputs it spends, the height from which it is valid, its size), the amounts in and out, each fee and the rate it pays, the total coming back, and the destination (the host wallet's next receive address).
   - `POST /api/v1/factories/{id}/recover` with the `preview_id` and `"confirm": "recover"` broadcasts exactly what was previewed.
   - `GET` shows progress, with `local-api.md` 16.3's step states.
   - Errors: `preview_expired`, `nothing_to_recover`, `not_yet` (with the first valid height), `member_owed` (H15), `payout_tree` (design 2), `chain_in_doubt`.
2. **The host doing it automatically after each timeout, while no member below the output is owed** (H15, INTERIM). When an output's timeout height is reached, the host's engine builds the same transactions the preview would show, broadcasts them without asking, and records each in the journal and in the factory's history.

Both pay the tree rate, 0.1 sat/vB (the owner's preference), and bump through a child only when a step has not confirmed by its date.

- **Spec:** `exit.md` 3.2, 7.2 E-5 (INTERIM), 7.4 H-2 and H-3, 9 H7 and H15; `safety-rule.md` 12 value 2; `local-api.md`, new: the recover calls above and `ended_how = host_timeout_recovered`.
- **What it recovers.** The engine is the host's side of the exit engine, in the core. It covers every output of the factory whose parent is confirmed and whose host-only timeout has passed, and the spare liquidity of every confirmed leaf after its delay. It refuses an output with an owed member below it (H15).
- **What the program does.** It builds each transaction, signs it with the host's per-lobby factory key, broadcasts it through the chain port (P2 where a package is needed) and journals it.
- **It refuses a tree that carries payouts** (design 2, after #508: there is no timeout to recover by, `exit.md` E-5).
- **Tests first:**
  - `program_sweep`'s checks move to the command: refused at tip L − 1, accepted at tip L, owed outputs refused, every satoshi accounted for with P1.
  - The preview matches what is broadcast, byte for byte; a stale preview is refused.
  - The automatic path fires at each timeout height, and never for an owed output.
  - New heights: deeper outputs on a published branch at E − 15 and H_leaf, and the spare liquidity at 143 and 144 blocks.
  - A design-2 tree is refused.
- **Depends on:**
  - **#54** (the sealed journal);
  - **#53** (the real host factory key; the test tool finds it today by searching epochs and indices);
  - **the integration branch hosting from its own wallet** (the wallet port: destination and fee coins);
  - P2, for packages;
  - **#55** (the preview and progress views).

### P6. The fault switches, one pull request each (integration)

Every one: test build only; in `TEST_STRINGS`; a program test that shows the switch does what it says, and the release build refusing it.

| PR | Switch | Role | Test | What it does | Depends on |
|---|---|---|---|---|---|
| P6a | `--test-never-fund` | host | S5 | Holds every ack and never broadcasts the funding; with `--test-spend-coin`, broadcasts the spend of a planned input (today print only) | wallet port (integration) |
| P6b | `--test-fund-after-blocks N` | host | S6 | Broadcasts the funding N blocks after the last ack | wallet port |
| P6c | `--test-funding-rate SATKVB`, `--test-funding-child SATKVB` | host | S7 | Funds at the given rate (test build may go below the term's floor); adds a child on the change, sent as a package | wallet port, P2 |
| P6d | `--test-replace-funding SATKVB` | host | S8, R2 | Right after the funding, a replacement spending one funding input back to the host (the spend-back builder) | wallet port |
| P6e | `--test-abort-after-partials` | host | S9 | Sends `round_abort` after collecting every partial signature, before `round_complete` | **K1, #95 and #98** (the round's first steps change) |
| P6f | `--test-withhold-ack` | member | S10 | Signs, never sends `round_ack` | K1 (#95, #98) |
| P6g | `--test-replay-propose` | host | S11 | Resends a journaled `round_propose` to a member that reconnects | K1 (#95, #98), #54 |

S13 needs no program switch: the hiding is in the test's shim (P7), so the program under test is the one shipped.

### P7. Harness additions (integration, test side only)
- `tools/esplora-regtest.py`: `POST /txs/package` through `submitpackage`, with an option to answer 404 instead (as today); a hide option for one txid and a frozen tip (S13); per-shim operator name.
- A regtest helper module for the tests: two peered nodes with chosen floors and versions, `invalidateblock` and `reconsiderblock`, a mempool filler paying a chosen rate (R4), `generatetoaddress`.
- `tests/program/slice15.py`: S1 to S13 as cases, P1 run after each; and `tests/program/slice15_signet.py`, opt in as `slice1_signet.py` (`GZ_LIVE_TESTS`), for the milestone set.
- The `regtest-paths` suite in `deep-checks.yml` (1.3), with a second pinned Core (29.0).
- Depends on: #57 for the workflow.

### P8. The mass-exit driver for R6 (main)
- `tests/regtest/` gains a driver that builds a 128- and a 512-member tree with the core in one process (as `tree_regtest.c` does for T1), signs it with test keys, and publishes every member's path at once against one node with a full mempool; P1 checks the totals.
- Needs terms whose shapes reach 512 members (`terms.md` shape table; `tree_shapes` already builds to 1,000 [`TESTING.md` Part 1]).
- Depends on: P1, P3.

---

## 4. What can start before Slice 1 is done

**Now, against `main`** (none of it waits for a Slice 1 pull request):
- P1 (ledger), P2 (package broadcast), P3 (exit engine, tree half, in the simulator), P8's driver.
- P7's shim and helper changes, written against the integration branch's copy of the shim but touching no program code.
- The walkthroughs of S1 to S13 as documents (they describe the interface steps, which Slice 1 fixes, so they are drafts until it closes).
- Specification passes the plan needs: `local-api.md` gains the host's recover call and `ended_how = host_timeout_recovered`; `journal.md` moves the exit records from Slice 3 to Slice 1.5; `exit.md` 11.2's S7 is reworded per 2.7; `TESTING.md` Part 1's "no regtest" line is corrected.
- The S12 endpoint probe (0.3 step 1) with P2's `gz-chain package --probe`, which broadcasts nothing.

**Now, against `integration-slice1`:**
- P0 (`TEST_STRINGS`).
- P6a to P6d (funding faults): they touch the funding call in the program and the wallet port, both on the integration branch; each owner folds them in.
- Regtest runs of S1 (with the test tool), S5 (with a hand-held stop instead of P6a), and the existing `program_sweep`, as dry runs of the harness.

**Must wait:**
- P4 waits for #54 (sealed journal) and #55 (views); its kind-A confirmation for #53.
- P5 waits for #54, #53 and the integration branch's wallet port reaching `main`.
- P6e to P6g wait for the K1 work (#95, #98): the round's first messages are changing; switches written now would be redone.
- **No S test counts as passed until Slice 1 is done:** the tests must run on the programs Slice 1 ships. Runs before then are rehearsals.

---

## 5. Tonight: run 1's recovery as the first S1

Signet run 1's factory (funding `26a86fc0…`, 82,811 sat, three members, root outputs with lock time 332,548 [M: `integration.md` 8, 9]) is being recovered tonight with the test tool from block 332,548. That is S1's path. To count it as **the first of S1's two signet runs**:

1. **Walkthrough:** write down each step as it is done (who, which command, the printed txids, the tip at each step), in the walkthrough's form of 2.1. It is a test-tool run, not P5's command, so it counts as the walkthrough half; the automated half needs P5.
2. **The negative check:** offer one root-output spend at **tip 332,547** to both servers and record the "non-final" refusal (`--test-sweep-force` builds it). At tip 332,548 it must be accepted, and it can be mined from block 332,549. If the spend is only ever sent at 332,548, the run lacks S1's "refused one block early" check, and the second run must carry it.
3. **Coin totals, from the chain alone:** after burial, with P1 if it exists, else by hand from both operators' confirmed transactions, show that **100,000 = 16 (funding fee) + 17,173 (change) + 17 (root kickoff fee) + 240 (root anchor, left on chain) + 26 (sweep fee) + 82,528 (to the host)**, to the satoshi [R: the printed plan; to be checked against the chain]; that the root kickoff's txid is the held tree's (`dbf7f36e…`); that no other tree transaction is on chain; and that each root output is spent once, by the host's spend.
4. **The members:** if their folders still exist, start each once and record what it shows for the factory (expected: ended, owed nothing). If not, say so in the record; it is then not a full S1 run for the member side.
5. **A second run:** a fresh factory, run by P5 through the local API when P5 exists (the automated half), with the step 2 check. A candidate sample is the 2026-11-13 attempt factory (0.00802827, past its end height, `integration.md` 8), if the tool can read its folder; it would be a second walkthrough, not the automated run.

---

## 6. Order, parallelism and the signet milestone set

### 6.1 Order

1. **S12 on regtest first** (P2, P7), then its signet probe: it decides whether exits on our servers need packages, and it must pass before any exit is relied on (`exit.md` 11.2 release blocker).
2. **S1, S2 and S5** on regtest (P3, P4, P5, P6a): the core of the slice.
3. S3, S4 (same factory as S2), S6 to S11, S13 on regtest as their switches land.
4. R1 to R8 on regtest.
5. The signet milestone set (6.3).

### 6.2 Parallelism

- **Regtest:** each test starts its own nodes in its own folder, so tests run side by side in CI shards without sharing a chain. The full S1 to S13 set is about 45 minutes of runner time [R]; R6 at 512 members is not measured yet.
- **Signet:** one host folder per fault switch, because a switch applies to the whole process; several factories per host folder where no switch is used (a host already runs two lobbies at once [M: `program_slice1` case 3]). Members are separate processes on the build server.

Signet milestone set, run in parallel from one start:

| Host folder | Factories | Capital in flight | Done by |
|---|---|---|---|
| H1 (no switch) | S1 twice (host + 3), the full life (host + 4: S2 at depth 2, S3, S4) | ≈ 250,000 sat | ≈ 31 h |
| H2 (no switch) | S2 at depth 3 (host + 9) | up to ≈ 332,000 sat | ≈ 31 h |
| H3 (`--test-never-fund`) | S5 twice | the planned coin only, never committed | ≈ 7 h |
| H4 | S12 probe and package step | one small coin | < 1 h |

**Capital (owner, 2026-11-26, Q1 A).** It is moved from the test wallets only when the set is ready to run, at 0.1 sat/vB, after checking the signet mempool's rates at the time. If 0.1 sat/vB would not confirm within a few blocks then, the move waits.

About 0.6 to 0.9 million sat in flight for the first round of runs, about 7,500 sat spent over both rounds [R]; the second runs follow the first in the same folders. The program host wallet holds about 99,700 sat after tonight's recovery; the rest has to come from the test wallets in the funds record, which needs the owner's go-ahead.

### 6.3 The signet milestone set

At each major milestone (Slice 1.5 done; after the re-import of #508, when S1, S2, S3 and S12 rerun as their design-2 counterparts, `exit.md` 11.2 and S33):
- **S1** (two runs), **S2** (depths 2 and 3), **S5**, **S12**;
- **one full life:** one host + 4 factory on T1 from lobby to the last sweep, no fault: funding, m1's exit (S2), m2's exit (S3), the host's sweeps of everything else at its heights (S4), the spare liquidity after 144 blocks; the ledger shows every output spent once.

Its record, with every txid, is the public proof the audit proposed (a page of signet txids, one per path).

---

### 6.4 On the roadmap (owner, 2026-11-26)

- **P5, the host's recovery** (definition in section 3): the recover call with its preview and confirmation, and the automatic sweep by timeout while no member is owed. It is built after P2 and before the signet milestone set, which uses it for S1 and the full life.
- **Reorganisation handling, R1 and R2.** Both stay in the regtest suite from its first version, and in its required set.
- **The regtest suite as a required check on `main`**, after seven consecutive green runs (1.3).

## 7. Questions for the owner

**Answered 2026-11-26:**
- **Q1, A.** The milestone capital is moved only when the set is ready, at 0.1 sat/vB, after checking mempool rates at the time (6.2).
- **Q3, A.** The suite becomes required after seven consecutive green runs, which may be dispatched back to back. R1 and R2 stay on the roadmap (1.3, 6.4).
- **Q4, A.** P5 is the local-API recover call with a preview of the transactions, amounts, fees and destination, which the host confirms, plus the automatic recovery after each timeout while no member is owed (H15). It is on the roadmap (P5, 6.4).

**Still open:**

**Q2. S7 and the funding's bump.** Our funding is version 2 and cannot be replaced by fee, because the tree is signed against its txid. So it can only be bumped by a child, and a version-2 parent below the floor cannot be rescued that way.
- A: test the two halves of 2.7 as they stand.
- B: make the funding TRUC with its own anchor, which changes H16 and the wallet's funding builder.
- **Proposed by the coordinator, pending the owner:** keep the funding at version 2, but always give it a bumpable output: the host's change, or a non-dust 240-sat P2A when change would be dust (2.7).

## 8. What this plan did not check

- Nothing was built or run for it. Every regtest time is an estimate [R]; the signet times come from run 1's 16-minute confirmation and 30-minute burial.
- Whether either public signet operator accepts `POST /txs/package`: that is S12's job. The research note's mention of a mempool.space package path was not checked against its own documentation.
- The funding needed at host + 9 (whether the 16-member shape pads leaves): check with `tools/spec-vectors.py` or the program's own message before funding.
- Whether `--test-commands`' `raw-kind` can carry a whole message (for S11 without P6g).
- Whether the funding engine's H11 path reuses exactly one old input (S9 asserts it; read only in outline here).
- The 29.0 behaviour that S7, S12 and R8 depend on, beyond what `tools/regtest-tree.py`'s header records for a 1 sat/vB floor on 29.1.
