# Continuous integration

What `.github/workflows/ci.yml` runs, what each job guards, and how to run the same check on your own machine. Written 2026-11-12 with the CI hardening branch (PR 16); brought up to date the same day, after the transport, chain view and wallet transactions merged.

CI runs in two tiers (below): the fast tier on every pull request push, and the heavy tier as well in the merge queue, on every push to `main`, nightly, by hand, and on pull requests labelled `full-ci`. All jobs run in parallel on GitHub's `ubuntu-24.04` runners. Every job has a time limit, so that a real slowdown shows. The wallet break-checks run in a workflow of their own (`wallet-break-checks.yml`, below). Tests on demand, for agents and builders, run in `agent-run.yml` (below), not on a server.

## Tiers

Nothing that guards `main` is dropped: every required check still runs, for real, on the merge queue's merge commit before anything reaches `main`. What changed is when the slowest jobs run on a pull request.

- **Fast tier, every run:** `build (OFF)` and `build (ON)` with their shards and the shard-list check, `clang (plain)`, `clang (ASan+UBSan)`, `specification vectors`, `handbook up to date`, `imported SuperScalar files unchanged`, `no addresses or local paths`, `signer boundary`, `interface in a browser`, and the wallet break-checks (their own workflow, unchanged).
- **Heavy tier:** `clang MemorySanitizer`, the three `valgrind` shards and the job `valgrind`, `libFuzzer, 60 s per target`, `constant time (Debug build)`, the six node mutant shards and the job `node mutants`, `signer mutants (run)` and the job `signer mutants`. Each has the same job-level `if:`; it is true when any of these holds:
  - the event is `merge_group` (the merge queue);
  - a push (the `push` trigger is `main` only);
  - `schedule`: nightly at 02:23 UTC;
  - `workflow_dispatch` with `tier` = `full` (the default; `fast` runs the fast tier only);
  - a pull request carrying the label `full-ci`;
  - a pull request into `integration-slice1` or `composite-p6a`, which have no merge queue (review of #96, M-4).

**Why the required checks still work.** GitHub reports a job skipped by its own `if:` as a pass, and such a job does not block a merge even when its check is required ("Status checks" and "Troubleshooting required status checks" in GitHub's documentation). So on an ordinary pull request `clang MemorySanitizer`, `valgrind` and `libFuzzer, 60 s per target` show as skipped and passing, and the merge queue then runs them for real on the merge commit: a failure there takes the pull request out of the queue. Branch protection and the ruleset are unchanged, and no required job was renamed. The required `valgrind` keeps `always()` in its `if:` beside the tier condition: in the heavy tier it runs, and fails, when a shard failed or was cancelled; outside it, it is skipped with its shards. (A skipped matrix job shows as one check with its name unexpanded, such as `valgrind (shard ${{ matrix.shard }} of 3)`; none of those is required.) A dependent job that is skipped because a job it needs failed would also read as passing, which is why the required aggregators (`build (OFF)`, `build (ON)`, `valgrind`) use `always()` and test the results themselves.

**The labels, when added (`ci-label.yml`).** `full-ci` runs `ci.yml` again (as a called workflow), heavy tier included, with the label in the event. Its checks are named `label / <job>`, so they neither satisfy nor hide the required checks of the pull request's own run, and they cancel nothing of that run; each label has its own concurrency group, so a second label's run never cancels the first. While `full-ci` stays on, every later push runs the heavy tier in the pull request's own run, under the required names. `signer-boundary-growth` re-runs the job `signer boundary` of the pull request's own CI run (the newest `ci.yml` run of its head commit that GitHub lists for that pull request's number), after that run has finished, unless the job already passed; the job reads the label through the API, so the required check itself changes with the label. A fork's pull request gets a read-only token there, so a maintainer re-runs the job by hand. Any other label starts nothing but skipped jobs. The coordinator's rule for a branch other than `main`: wait for the heavy tier (automatic on a pull request into `integration-slice1` or `composite-p6a`), and list every red job's failing tests, as before.

**Aggregators.** `valgrind`, `node mutants` and `signer mutants` each `need` their jobs and have `always()` beside the tier condition: in the heavy tier they run, and fail, when any of their jobs failed or was cancelled; outside it they are skipped with them. `constant time (Debug build)` is one job with one fixed name. Only `valgrind` is required today; whether `node mutants`, `signer mutants` and `constant time (Debug build)` become required is the owner's decision (review of #96, M-1), made in the repository settings, not here.

**Branches without a merge queue run the pull request's own workflow files.** A `pull_request` run uses the workflows of the pull request's merge commit, so a pull request can change the checks that judge it: edit `ci.yml`, the build action or `ci-label.yml`, and its own run runs the edited version. Into `main` the merge queue runs the queue's merge commit, but that commit holds the same edited files, so review of every change under `.github/` is what guards it there too. Into `integration-slice1` and `composite-p6a`, which have no queue, the pull request's own run is the only gate. So a change under `.github/` needs a reviewer who checks the workflows themselves, whatever the base. (A `CODEOWNERS` entry for `.github/` would make GitHub ask for that review; that is the owner's decision.)

**`signer boundary` in each case.** On a pull request (labelled `full-ci` or not) it compares the allow list with the merge base and reads `signer-boundary-growth` through the API when the job runs (so a re-run sees a label added since); if that lookup fails, it fails closed: the list may not grow. In the queue it compares with the queue's `base_sha` and reads the label through the API, failing closed. On a push, the nightly run or a dispatch it runs `--no-growth` without a base, as a push to `main` always did.

**Nightly.** A schedule runs on the default branch only. The nightly run of `ci.yml` is itself the full run of `main`; `nightly.yml`, at the same time, starts `ci.yml` with `tier=full` by `workflow_dispatch` on `integration-slice1` and `composite-p6a` (its job has `actions: write`, nothing else), each with that branch's own `ci.yml`. A branch whose `ci.yml` has no `workflow_dispatch` yet (it has not merged `main` since the tiers came) gets a warning there and no run. To add a branch, add it to that job's list.

**By hand:** `gh workflow run ci.yml -R gazpacho-wallet/gazpacho -r <branch> -f tier=full` (or `tier=fast`).

## Agent runs (`.github/workflows/agent-run.yml`)

Tests on demand on GitHub's runners, for agents and builders, instead of a server: no SSH, no waits, up to 20 jobs at once. Started only by `workflow_dispatch`, so only by someone who can write to the repository; never a required check. Inputs:

- `ref`: a branch of this repository, or a full commit SHA reachable from one. The plan fetches this repository's branches only (no pull request refs, no tags, no lazy fetching) and refuses anything else, so a fork's commit is never built here;
- `suite`: `focused` (one build, `ctest -R <regex>`), `full` (the fast tier: both gcc builds unsharded with the ThreadSanitizer steps and the scale check, both clang builds, the browser job, the script checks, the wallet break-checks), `heavy` (the heavy tier, sharded as in CI), `mutants` (the named mutants only) or `playwright` (the browser job);
- `regex`: the `ctest -R` pattern (required for `focused`; it narrows `full` and `heavy`, and is a spec-file filter for `playwright`); `exclude`: `ctest -E`;
- `mutants`: names from `tests/node/mutants.txt` or `signer/tests/mutants.txt`, space-separated; each is looked up and run by its own runner, and an unknown name fails the plan;
- `sanitizer` (`focused` only): `none` (the gcc build), `asan` (gcc with ASan+UBSan) or `msan` (clang MemorySanitizer);
- `build_type`: a choice, `default` (the build's own) or a `CMAKE_BUILD_TYPE`.

Every build goes through the action `.github/actions/gz-build`, the same one `ci.yml` uses, taken from the branch the workflow runs from (`-r`, normally `main`), so an agent's build is CI's build applied to `ref`. The valgrind shards use `tools/ci-valgrind.py` (CI's list of shorter cases) from `ref` when it has one. Each job writes a step summary with the passed and failed test names and the tail of each failure's output (`tools/ci-summary.py`, from ctest's and Playwright's JUnit output, or from the valgrind and mutant runners' result lines), and keeps its log, JUnit files, `build/Testing` and the program tests' logs as the artifact `agent-run-<job>` for 7 days. Token: `contents: read`. It restores main's caches and never saves any. One run at a time per `ref` and `suite`: a newer one waits for the running one.

    gh workflow run agent-run.yml -R gazpacho-wallet/gazpacho -r main -f ref=<sha> -f suite=focused -f regex='^program_'
    gh run list -R gazpacho-wallet/gazpacho --workflow agent-run.yml -L 1
    gh run view <id> -R gazpacho-wallet/gazpacho --log-failed
    gh run download <id> -R gazpacho-wallet/gazpacho -n agent-run-focused

Agents iterate on `focused` runs and do one `full` run before asking for review; push work in progress to a branch (`wip/<name>`) to test it.

## Caches

Caches only save time; none changes what is tested.

- **ccache.** Every C job of `ci.yml` (not the mutant runners, which build their own trees) builds with `-DCMAKE_C_COMPILER_LAUNCHER=ccache`, except in the merge queue. The cache is kept with `actions/cache`, keyed by the runner image, the compiler, the build type, the sanitizer and the build configuration, plus the run; a job restores the newest entry of its key. ccache hashes the compiler, every flag and every preprocessed input of a compilation, and failed compilations are never cached. Entries are saved only by a push to `main` and by the nightly run (one job per configuration: shard 1 of the gcc builds, shard 0 of valgrind); pull requests, dispatched runs and agent runs restore but never save.
- **Two pinned tarballs.** libsodium and utf8proc, the release tarballs `ports/storage/crypto/CMakeLists.txt` pins by SHA-256, are cached under a key made of those hashes: two regular files, never extracted by the action, with no git metadata. On every use the action checks that the folder holds exactly those two files, each with its pinned SHA-256, and only then passes `-DGZ_DEPS_DIR`; CMake checks each SHA-256 again before extracting. secp256k1-zkp is not cached: CMake fetches it at its pinned commit, as before (review of #96, M-3). If anything does not match, or a fetch fails, CMake fetches the tarballs itself.
- **OpenSSL for MSan**, as before: built from its hash-checked source and cached under its version, except in the merge queue, which builds it every time.
- **The merge queue uses no cache at all.** It neither restores nor saves ccache, the tarballs or OpenSSL, and builds without the ccache launcher: the result that gates `main` depends on no cache entry (review of #96, M-2). Neither do pull requests into `integration-slice1` or `composite-p6a`, which have no queue: their own run is their gate.
- **Who can write a cache main reads.** A pull request's run, from a fork or not, can only write its own scope (`refs/pull/N/merge`), which `main` and the queue never read, and with these rules it saves nothing at all. `main`'s scope is written only by pushes to `main` and the nightly run, which build reviewed code. An agent run executes under the scope of the branch it is dispatched from, so `agent-run.yml` builds only this repository's branches, never a fork's commit, and never saves; even so, the queue reads no cache, so nothing in any cache can change the result of a required check in the queue.

## Rules for the workflow file

- **Read-only token.** `permissions: contents: read` at the top. No job needs to write to the repository; a job that ever does must ask for exactly that permission itself, in that job.
- **Actions pinned by commit.** Every third-party action is named by its full 40-character commit SHA with the release in a comment, for example `actions/checkout@3d3c42e5... # v7.0.1`. A tag can be moved by whoever controls the action's repository; a commit cannot. To update, look up the new tag's commit with `gh api repos/<owner>/<action>/git/ref/tags/<tag>` (if `object.type` is `tag`, follow `object.url` to the commit) and change the SHA and the comment together.
- **No stored credentials.** Every checkout uses `persist-credentials: false`, so the token is not left in `.git/config` for later steps.
- **Downloads are pinned by hash.** The OpenSSL source for the MSan job is checked against its SHA-256; the handbook's Markdown renderer is installed with `pip --require-hashes` from `tools/handbook-requirements.txt`.
- **Tests run in parallel.** The gcc, clang and MSan jobs run `ctest -j "$(nproc)"` (4 on GitHub's runners), so they stay inside their limits on a slow runner without raising them. A test that cannot share the machine says so in CMake: the program tests that pick their port with `free_port()` (bind port 0, close, listen on that number later) hold the lock `gzp_free_port` and run one after another (with `program_two_process`, whose later hosts listen again on the number its first host was given); `program_chain_watch` is `RUN_SERIAL` (its wait for the worker's BUSY answer flaked under load); and the wallet break-checks are `RUN_SERIAL` (they build and test with `-j4` themselves). `valgrind_signing` (the build without sanitizers) is `RUN_SERIAL` too: alone it takes about 450 s of its 600 s limit, and beside three other tests it ran out. PR 51's `program_api` and `program_api_limits` pick ports with their own `free_port()` and must join `gzp_free_port` when PR 51 merges. Every other test makes its own folder (`mkdtemp`, or a folder of its own in the build directory) and listens on port 0 with the socket the kernel gave it. A new test that uses a fixed port, a shared folder or the whole machine must get a `RESOURCE_LOCK` or `RUN_SERIAL` too.
- **Program logs on failure.** When a test fails in the gcc, clang or MSan job, the logs that the program tests' processes write under `build/program` (`*.log`, one per process) are kept as the artifact `program-logs-<job>` for 7 days: `gh run download <run-id> -p 'program-logs-*'`.
- **The merge queue.** Every workflow that gives a required check also runs on `merge_group`, so the queue gets its results on the merge commit it builds. A step that reads a pull request's context uses the queue's own there: the wallet break-checks compare with `github.event.merge_group.base_sha` instead of the pull request's base. A queue run is never cancelled by a newer push.
- **Stale runs are cancelled.** A new push to a pull request cancels that pull request's run in progress; a label never does (each label's run has a group of its own). Runs on `main` are never cancelled. The event is part of the concurrency group, so a nightly or dispatched run never waits behind a push's run of the same branch.
- **Builds through one action.** Every C job installs, configures and builds through `.github/actions/gz-build`; `configs.sh` there holds each build's packages and options. A change there changes what CI checks and is reviewed as such.

## The jobs

### build (OFF) and build (ON): gcc, the original job

Sharded so that each runner stays well inside the 30-minute limit: `build (OFF)` runs as three shards (`build (OFF, shard 1)`, `shard 2`, `shard serial`) and `build (ON)` as two. `tools/ctest-shard.py` makes each shard's `ctest -R` list: the tests by name, round robin, with the tests joined by a fixture kept in one shard (ctest adds a fixture's setup test to any run that needs it, so a split fixture ran `program_lobby` twice), and `valgrind_signing` alone in the shard `serial` (it is `RUN_SERIAL`, about 7.5 minutes). Each shard prints and uploads the list it runs, and the job `build shards cover every test once` fails if the union of a build's lists has a test twice or misses one of `ctest -N -LE slow`. The ThreadSanitizer steps and the scale check run in shard 1. The jobs named `build (OFF)` and `build (ON)`, the required checks, pass only if every shard of theirs passed and that check did.

Guards: the whole tree builds with gcc 13 and every CTest test passes, once without sanitizers and once with AddressSanitizer and UndefinedBehaviorSanitizer (`-DGZ_SANITIZE=ON`), except the wallet break-checks (label `slow`, `-LE slow`). The build without sanitizers runs the core and simulator tests a second time under valgrind. Both builds also run the transport's interop test (`-DGZ_INTEROP_PY=ON`, with Ubuntu's `python3-cryptography`): `gz-net` against the independent Python peer in `tests/net/interop/`, over BOLT 8 and over BOLT 1's `init`, ping and pong with factory messages, in both roles. Then the scale check: one small tree and the two upstream defect reproductions.

The lobby connections' keep-alive runs here as `net_keepalive`: two processes hold one connection for 4 seconds with a ping every 100 ms. The same test at the real values (a ping every 15 s, a 30 s pong timeout, six minutes) is registered only with `-DGZ_LONG_TESTS=ON` and is not run in CI.

### interface in a browser

Guards: the local web interface (`web/`, stream S10) works in a real browser against `gz-api-fake`, the API server with the fake backend and the interface compiled in. Playwright drives Chromium through every Slice 1 flow (`tests/web/`: first run and the 24 words, sign-in and lock, conditions, lobbies, the signing moment and its refusals, hosting, the factory, node busy, the chain view in doubt, the event stream dropping), checks that no page makes a request to any host but the local API and that the words leave the page, and then runs the API server's own browser checks (`tests/api/browser/`), which no job ran before. The job builds only the `gz-api-fake` target. Playwright is installed with `npm ci` from `tests/web/package-lock.json`, which pins every package by hash; the Chromium build is the one that Playwright version names (downloaded by Playwright, not pinned by a hash of ours). The static rules for the interface's files run in every build as the CTest test `web_static_check`.

End to end: the job builds `gazpacho-test` too and sets `GZ_PROGRAM`, so `tests/web/multiprocess.spec.mjs` drives real program processes, a host and its members, through their own interfaces to the ready check, with a refusal seen by the host. In CI the spec may not be skipped for want of the program (it throws without `GZ_PROGRAM`). On `main` it is still marked `fixme` until P6a (the core's lobby view objects) merges; on `composite-p6a` it runs, with three members. The job is not required.

Locally: `tests/web/README.md`. Run it on a server or in CI, never on a workstation holding a wallet.

### wallet break-checks (`.github/workflows/wallet-break-checks.yml`)

Guards: `wallet/tests/break-checks.sh` damages one wallet protection at a time (about 110 faults) and requires a wallet test to fail. For each fault it rebuilds only the wallet's directory (`make -C build/wallet`, which builds the wallet tools as well) and runs only the wallet's tests (`ctest -R '^wallet_'`, less `wallet_tx_tool_chain`, which waits on the chain port's retry pauses and runs once in the baseline): nothing else in the tree links the wallet, so no other test could notice a wallet fault. A run takes a few minutes, under a 30-minute limit.

When: on every push to `main`, nightly at 03:17 UTC, by hand (`workflow_dispatch`), and on every pull request. On a pull request the job always runs and always reports, but does the work only if the request changes `wallet/`, `tools/gz-wallet-*`, the root `CMakeLists.txt` or this workflow; otherwise it passes at once. That is what lets it be a required check without making every other request wait. Whether it is required is set in branch protection, not here.

Locally:

    cmake -B build -DCMAKE_BUILD_TYPE=Release -DGZ_SANITIZE=OFF -DGZ_INTEROP_PY=ON   # or ON
    cmake --build build -j
    ctest --test-dir build --output-on-failure --timeout 600
    ./build/tree_shapes 64 8,ps 0 && ./build/tree_shapes defects

### imported SuperScalar files unchanged

Guards: `core/superscalar/` stays byte for byte what `core/superscalar/IMPORT.md` records. `tools/check-import.sh` recomputes the SHA-256 of every file in the table and fails if one differs or is missing, or if a file is present that the table does not list. Imported files are never edited (CONTRIBUTING.md, checklist item 19); before this job nothing noticed an edit. A deliberate re-import goes through `tools/update-import.sh`, which rewrites the table, so the two always change together.

Locally: `sh tools/check-import.sh`

### no addresses or local paths

Guards: no tracked file names a real machine or someone's computer. `tools/check-no-addresses.py` reads every file `git ls-files` lists, except `core/superscalar/` and binary files, and fails on:

- an IPv4 address other than `127.0.0.1`, the unspecified address, and the three documentation ranges of RFC 5737;
- a Windows user path (a drive letter followed by the Users folder) or the Windows per-user application data folder.

Version numbers with four parts are not addresses: a match that is part of a longer dotted run, touches letters, or follows "v", "version", "release", "since" and similar words is skipped. A line that must hold an address on purpose, such as a test input the code is meant to refuse, carries the marker `address-check: allow` in a comment; use a documentation address instead wherever one will do. A file that is not an address and is not covered by these rules goes in the script's `ALLOWED` set with a reason.

Locally: `python -I tools/check-no-addresses.py` (or name files, relative to the repository root).

### specification vectors

Guards: `tools/spec-vectors.py` runs to the end and its own self-checks pass (the BIP 340 test vector, the split and funding rules, and its other asserts). The job runs `python3 -I tools/spec-vectors.py` and fails on a non-zero exit.

**What it does not guard:** the script reads no specification. It prints the vectors; it does not compare them with the hex printed in the specifications. A vector edited by hand in a specification, or a change to the script whose output was never pasted back, passes this job. That comparison is still done by hand, in review. A check that compares the two is not scheduled (`TESTING.md`, Part 2).

The script has been on `main` since PR 13 (the Slice 1 specifications). On a branch without it the job prints a notice and passes. The script uses the standard library only; its elliptic-curve arithmetic is pure Python, so it takes about five minutes (`specs-slice1`, checked by hand on 2026-11-12: exit 0).

Locally: `python -I tools/spec-vectors.py`

### handbook up to date

Guards: `docs/handbook.html` is never stale. The job installs the pinned Markdown renderer, runs `tools/build-handbook.py` and then `git diff --exit-code docs/handbook.html`. The two lines that carry the build date (the "Built on" sentence and the `"built"` field) are ignored with `git diff -I`, so a page built yesterday from the same Markdown still passes. Any other difference fails: someone changed a chapter's Markdown, or the chapter list, without rebuilding the page.

Locally:

    python -m pip install --require-hashes -r tools/handbook-requirements.txt
    python tools/build-handbook.py
    git diff docs/handbook.html

### clang (plain) and clang (ASan+UBSan)

Guards: a second compiler. clang 18 builds the tree with the same `-Wall -Wextra -Werror` on new code, then runs the tests, once without sanitizers and once with AddressSanitizer and UndefinedBehaviorSanitizer. clang's warnings and its sanitizer instrumentation differ from gcc's, and the known-trace digest is checked on a second compiler. The wallet break-checks are left out (`-DGZW_BREAK_CHECKS=OFF`, `-LE slow`); they run in the gcc build.

Locally (Linux, clang 18 and its runtime libraries installed):

    CC=clang-18 cmake -B build-clang -DCMAKE_BUILD_TYPE=Release -DGZ_SANITIZE=ON -DGZW_BREAK_CHECKS=OFF
    cmake --build build-clang -j
    ctest --test-dir build-clang --output-on-failure -LE slow

### clang MemorySanitizer

Heavy tier. Guards: reads of uninitialised memory, which neither ASan nor valgrind reports precisely (checklist item 23). MSan needs every library the tests call to be built with it, or it reports the bytes that library returns as uninitialised. So:

- secp256k1-zkp is built from source by our CMake anyway; the job passes the MSan flags through `CMAKE_C_FLAGS`, which reach it, and turns off its x86-64 assembly (`-DSECP256K1_ASM=OFF`), whose writes MSan cannot see.
- OpenSSL is built from the 3.0.22 release source (libcrypto only, static, `enable-msan no-asm`), checked against its SHA-256, and cached between runs (`actions/cache`), so only the first run after a change of version pays the few minutes it takes.
- The C library is handled by MSan's own interceptors. Not all of it: the fortified `__*_chk` forms are not intercepted, so libsodium is built without `_FORTIFY_SOURCE` here (see "libsodium and utf8proc in every job" below).

All tests run except the slow wallet break-checks, including the symbol checks (core isolation, wallet no-I/O), which already know the sanitizers' own symbols.

Locally (Linux, clang 18):

    curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-3.0.22/openssl-3.0.22.tar.gz
    echo "67ebca7e50d17383028045486653492195b83db95f8558709701bb47b5c1ef81  openssl-3.0.22.tar.gz" | sha256sum -c
    tar xzf openssl-3.0.22.tar.gz && cd openssl-3.0.22
    ./Configure linux-x86_64-clang enable-msan no-asm no-shared no-tests no-module \
      --prefix="$HOME/openssl-msan" --libdir=lib CC=clang-18 \
      CFLAGS="-fsanitize-memory-track-origins -fno-omit-frame-pointer -g -O1"
    make -j"$(nproc)" build_libs && make install_dev && cd -
    CC=clang-18 cmake -B build-msan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGZW_BREAK_CHECKS=OFF \
      -DCMAKE_C_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=memory" -DSECP256K1_ASM=OFF \
      -DOPENSSL_ROOT_DIR="$HOME/openssl-msan" -DOPENSSL_USE_STATIC_LIBS=TRUE
    cmake --build build-msan -j
    ctest --test-dir build-msan --output-on-failure -LE slow

### valgrind

Guards: memory errors and definite leaks in the compiled tests, on a build with no sanitizer (so it sees the code as shipped, at `-O2`). `tools/valgrind-tests.py` asks CTest for the registered tests and runs each one whose command is a program built in the build directory under `valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --track-origins=yes`, with the same arguments. Tests run through `sh` or Python are listed and skipped: valgrind would check the shell, not our code. Tests run one per processor in parallel. The job runs as three shards side by side (`valgrind (shard I of 3)`, `--shard I/3`: by name order, every third test), each under the same 35-minute limit, so every test still runs under memcheck exactly once; the job named `valgrind`, the required check, passes only if all three shards passed. The constant-time step runs in shard 0. The 1,000-seed simulator run took eight minutes under valgrind, so this job runs it with 200 seeds of the same length (`--args "sim_seeds=200 400 1 0"`); every other build runs all 1,000. Before this job, valgrind ran only in `m1a-followup`'s copy of the workflow.

Heavy tier. The list of shorter cases is in `tools/ci-valgrind.py`, which `agent-run.yml` uses too; with `--include` or `--exclude` it passes only the `--args` of the tests selected.

Locally (Linux, valgrind installed):

    cmake -B build-vg -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGZW_BREAK_CHECKS=OFF
    cmake --build build-vg -j
    python -I tools/ci-valgrind.py build-vg [--include REGEX] [--exclude REGEX] [--shard I/N]

The storage layer's E2r test (Argon2id at 256 MiB, `storage_vector_e2r`) is excluded here: it is E2's code at more memory and takes minutes under memcheck. A second step runs `storage_ctime`, the constant-time check: `sc_test_ctime` marks the passphrase key, MSK, the seed and the words' entropy undefined and runs every storage operation that holds them under memcheck, so a branch or index on a secret is an error (libsecp256k1's method). Its CTest command is `ports/storage/crypto/tests/ctime-check.py`, so `valgrind-tests.py` lists it as skipped; the step runs it, and fails if it was not registered (valgrind, its headers or Python missing). The checker runs memcheck with no suppression file and its errors written as XML, and allows exactly one source line: libsodium 1.0.22's `if (ret != 0)` after the constant-time tag comparison (`aead_xchacha20poly1305.c` line 111, reached from `sc_unseal`), whose outcome is public. Any other error, or that branch at another line, fails. A suppression file could name only the function, which after a libsodium upgrade would hide any new secret-dependent branch in it (review A, L5); a libsodium upgrade has to re-check the line. libsodium is built with `-g` in every job for this.

### libsodium and utf8proc in every job

The storage layer (`ports/storage/crypto`, from PR S6) links libsodium 1.0.22 and utf8proc 2.12.0. CMake downloads both while building and checks each against the SHA-256 pinned in `ports/storage/crypto/CMakeLists.txt`; nothing is taken from the distribution, so every job builds the same code with no extra install step. libsodium is configured with the job's compiler and `CMAKE_C_FLAGS` (so the MSan and fuzz jobs instrument it) and `--disable-asm`. `GZ_SANITIZE` adds its flags with `add_compile_options`, which does not reach libsodium's own build, so with `GZ_SANITIZE=ON` the same `-fsanitize=address,undefined -fno-sanitize-recover=undefined` go to libsodium's `CFLAGS` and `LDFLAGS` as well: the gcc and clang ASan+UBSan jobs instrument libsodium too (review A, L4; before, they checked our code only, against an uninstrumented `libsodium.a`). utf8proc is built by our CMake (`FetchContent`), so every option reaches it; it is fetched as its release asset `utf8proc-2.12.0.tar.gz`, not GitHub's generated tag archive, whose bytes GitHub has changed before. Under MSan two more things change, through `CPPFLAGS`. Fortification is off (`-D_FORTIFY_SOURCE=0`): on glibc libsodium's configure otherwise adds `-D_FORTIFY_SOURCE=3`, clang then compiles each `memcpy` whose destination size is known only at run time as a call to glibc's `__memcpy_chk`, and MSan does not intercept that function, so the bytes it writes stay "uninitialised" in MSan's view; that is why Argon2's output (written by `store64_le` in `argon2_finalize`) and every key and tag derived from it were reported. And the SIMD paths are left out (their `HAVE_*INTRIN_H` definitions undefined), so the code checked is the reference code whatever the runner's CPU. Every other job builds libsodium as its configure sets it, SIMD paths and fortification included. `-DGZ_DEPS_DIR=<folder>` uses local copies of the same tarballs instead of downloading. `tools/verify-libsodium.sh` repeats the minisign check of the tarball against libsodium's published key before a version change; `docs/notes/storage-crypto.md` records it.

### Chain worker under ThreadSanitizer

A step of the `build (OFF)` job, not a job of its own. Guards: the chain worker thread and the loop share two queues, a watch mirror and a generation counter under one mutex (`ports/chain/chainw.c`); a data race or a lock-order problem there shows only under a race detector. `tools/chain-tsan.sh` compiles the chain library and `ports/chain/tests/test_chainw.c` with `-fsanitize=thread` in a scratch directory and runs the test, in which loop calls, server changes, resets and shutdown race for 40 rounds. ThreadSanitizer does not mix with the other sanitizers, hence its own small build. The step first lowers `vm.mmap_rnd_bits` to 28, because the default of the runner kernel leaves ThreadSanitizer too little room to map its shadow memory.

A second step, `tools/pchain-tsan.sh`, builds the program's chain adapter (`program/pchain.c`) with the chain port and its libcurl transport under ThreadSanitizer and runs `tests/program/test_pchain_threads.c` against a local Esplora stub (`tests/program/pchain_threads.py`): the loop asks for a script's outputs, as `--check-chain` does, again and again while the chain worker polls the tip. Guards: no chain client is used by two threads (docs/notes/integration.md B11, where a shared client corrupted the heap). The stub also checks that the worker's polls and the lookups interleaved, so a run that never overlapped does not pass.

### libFuzzer, 60 s per target

Heavy tier. Guards: every parser of outside input keeps being fuzzed (checklist item 20), with coverage guidance, ASan and UBSan. The job looks for `LLVMFuzzerTestOneInput` in the C sources. If there is none (a branch from before PR 10), it prints a notice and passes. Otherwise it builds the tree with clang, `-fsanitize=fuzzer-no-link,address,undefined` and `-DGZ_LIBFUZZER=ON`, and `tools/run-fuzz.sh` runs every executable named `fuzz_*` for 60 seconds. It fails on any crash, leak, sanitizer report or 10-second input, and libFuzzer prints the failing input in the log. If the sources define fuzz targets but no `fuzz_*` executable was built, it fails, so a target cannot drop out of the job by being renamed.

The targets on `main` today: `fuzz_noise` and `fuzz_tlv` (the transport's BOLT 8 and TLV decoders, since PR 10) and `fuzz_tx_parse` (the wallet's transaction parser, since PR 11). The storage layer adds `fuzz_sc_keyfile`, `fuzz_sc_frame` (journal entries and header), `fuzz_sc_mark` (mark and guard files) and `fuzz_sc_export` (exports, their bodies and the attempts file). The chain view's fuzz test (`chain_fuzz`, `ports/chain/tests/test_fuzz.c`) has only a plain driver: it runs as a CTest test in every build, but not in this job.

How a branch adds a fuzz target. The targets on `main` are built both ways: with a plain driver as a CTest test normally, and in the libFuzzer form when `GZ_LIBFUZZER` is ON (declared once, at the top of `CMakeLists.txt`). A new target does the same:

1. Name the executable `fuzz_<name>` and define `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` in its source. Keep `main` in a separate driver file.
2. In CMake, when `GZ_LIBFUZZER` is ON, build the target without the driver and link it with `-fsanitize=fuzzer`, and do not register the plain-driver CTest test:

       if(GZ_LIBFUZZER)
         add_executable(fuzz_tlv tests/net/fuzz_tlv.c)
         target_link_options(fuzz_tlv PRIVATE -fsanitize=fuzzer)
       else()
         add_executable(fuzz_tlv tests/net/fuzz_tlv.c tests/net/fuzz_main.c)
         add_test(NAME net_fuzz_tlv COMMAND fuzz_tlv 200000)
       endif()
       target_link_libraries(fuzz_tlv PRIVATE gazpacho_net)

3. Optionally commit a starting corpus as `fuzz/corpus/<name>/` (one small file per interesting input). The job fuzzes a scratch copy and never writes to the repository.
4. When the job finds something, add the input to the corpus or to a unit test with the fix.

Each target costs 60 seconds of the job; past about twelve targets, lower the time per target in the workflow or split the job.

Locally (Linux, clang 18):

    CC=clang-18 cmake -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGZW_BREAK_CHECKS=OFF -DGZ_LIBFUZZER=ON \
      -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
    cmake --build build-fuzz -j
    sh tools/run-fuzz.sh build-fuzz 60

### constant time (Debug build)

Not required; heavy tier. The constant-time tests (`signing_ctime` and `signer_ctime`; `program_keys_ct` is added to the list when the program's key layer, #53, merges) run under memcheck in a Debug build, with no optimisation. Every other job optimises, and optimisation can turn a branch on a secret into straight-line code, so a Release run can pass where the code is not constant time: unoptimised, `a && b` on two secret-dependent results is a branch. The job first checks that each expected test is registered exactly once (`ctest -N -R "^name$"`), so a test that silently stopped being registered fails it. Locally: `cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug`, build, then `ctest --test-dir build-debug -R '^(signing_ctime|signer_ctime|program_keys_ct)$'`.

### node mutants (shards 0 to 5)

Not required; heavy tier; the job `node mutants` passes only if all six shards did. `tools/mutate-node.py --shard I/6` runs every sixth mutant of `tests/node/mutants.txt`, so the six shards together run each mutant exactly once. For each mutant it changes one file, rebuilds the node's tests and runs them. A shard fails if any of its mutants survives without a `# equivalent` or `# untested` line giving the reason, or does not apply or compile. Locally: `python3 -I tools/mutate-node.py . WORK [-j N] [--shard I/N] [NAME...]`.

### signer boundary and signer mutants

Neither job is yet a required check; making them required is the owner's call in the repository settings. Steps S1 and the S4 skeleton of `docs/notes/signer.md` (sections 7 and 9).

`tools/check-signer-boundary.sh` lists every signing or secret-key symbol of `tools/signer-only-symbols.txt` used outside `signer/`:
- in every file git tracks with one of the endings `.c`, `.h`, `.inc`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.S` and `.s` (build output is never tracked, so no folder is left out by name; a tracked `build-*/` folder is scanned);
- with backslash-newlines spliced first, as the preprocessor does, then comments and strings blanked (a digit separator such as `1'000` is not a quote);
- with `signer/` and `core/superscalar/` (imported, allowed by name) left out.

It counts the uses per file and compares them with `tools/signer-boundary-allowed.txt`, which may only shrink. CI runs it with `--no-growth`, so a new use or a stale line fails. On a pull request it also runs `--base-allow` against the merge base's copy of the list, so a change cannot add a use together with its own allow-list line. Step S4 empties the list and switches the check to `--fail`.

Some findings are **hard**: they fail in every mode, and no allow list can hold them. They all name the fixed-aux test build of the signer (decision K20) outside `signer/`:
- `GZ_SG_VECTORS`, `gz_sgv_*` or the marker `gz_sg_vectors_build_never_ship` in code;
- token pasting onto a `gz_sg` name;
- an `#include` of a `signer/*.c` or `*.inc` file;
- a computed `#include` (a macro, not a literal);
- in a tracked `CMakeLists.txt`, `*.cmake`, `*.yml`, `*.yaml`, `*.sh`, `*.json` or `Dockerfile` (a release recipe or preset included), `GZ_SG_VECTORS` (as a substring, so `-DGZ_SG_VECTORS` counts), `gazpacho_signer_vectors`, or any `signer/*.c` path.

`signer/vectors_guard.cmake` adds two more guards:
- at configure time, it refuses any target other than `test_signer_vectors` that links that build;
- the CTest `signer_never_ship` runs `nm` on every program the build makes (test and fuzz programs excepted) and requires the marker to be absent.

**The label `signer-boundary-growth`** lets a pull request grow the allow list or drop a line of the symbol list (`--base-symbols` compares `tools/signer-only-symbols.txt` with the merge base's: a symbol deleted in the same change as a new use of it is growth). Only a maintainer who reviews the signer boundary may set it, never the pull request's author, and the review must say why the new use cannot go through `signer/`. GitHub does not enforce this rule; review does.

**In the merge queue** (`merge_group`), the allow list is compared with the queue's `base_sha`. The label is read through the API from the pull request named in the queue's head ref (`gh-readonly-queue/<branch>/pr-<number>-<sha>`), because the queue event carries no labels; the job has `pull-requests: read` for that. If the ref does not parse or the lookup fails, the queue fails closed: the list may not grow. A pull request that must grow the list and cannot pass the queue merges outside it, after a maintainer of the signer boundary has reviewed it.

`tools/check-tags.py` fails on a `gazpacho/` string in code that `spec/PROTOCOL.md` 8.2 does not register. It runs with `--report` while main still has unregistered strings.

The job fails on:
- the tools' own tests (`tests/tools/test_check_signer_boundary.py`, `tests/tools/test_check_tags.py`);
- `tools/signer-vectors.py --check`, the signer's vectors recomputed in pure Python.

`signer mutants (run)` (heavy tier; the job `signer mutants` passes only if it did) runs `tools/mutate-signer.py` over `signer/tests/mutants.txt`: one mutant per check of the signer and of the two tools. A test must kill each one, or a line `# equivalent NAME: why` must triage it.

The signer's constant-time test, `signer_ctime`, runs in the first valgrind shard, with `storage_ctime` and `signing_ctime`.

Locally: `sh tools/check-signer-boundary.sh`, `python3 -I tools/check-tags.py`.

## What the second compiler changed in the symbol checks

The first clang runs failed two existing tests on `main`, not because the code changed but because the checks only knew gcc's output:

- `wallet_keys_no_io` (`wallet/tests/check_no_io.py`): clang emits `bcmp` for a `memcmp` whose result is only compared with zero, and `memchr` for a byte-search loop. Both are now on the allow-list beside `memcmp` and `strchr`. Under clang's ASan it also saw `__start_asan_globals` and `__stop_asan_globals` (weak references to ASan's section bounds), `___asan_globals_registered`, and `switch.table.<function>` lookup tables shown as data; these are accepted by prefix, each with its reason in the file.
- `core_isolation` (`tools/check-core-isolation.sh`): the same ASan names, and under MSan the `__msan_*` runtime calls, its weak `__msan_track_origins` and its thread-local shadows reached through `%fs`. Since round 4 of PR 9's review these are accepted only from an exact list of the instrumentation's entry points (numbered families such as `__asan_report_load<N>` written as such), not by prefix: a call to any other runtime function, such as `__sanitizer_print_stack_trace`, is refused in every build, and so is ordinary state under a checker's name.

The negative tests of both checks (the sneaky object, the five bad libraries) still fail as they must in every build.

## What CI does not do

- **It does not require a review.** Since 2026-11-12, branch protection on `main` requires all 11 jobs above to pass on a branch that is up to date with `main`, applies to administrators too, and refuses force pushes and deletions. It does not require an approving GitHub review: reviews are kept as files in `docs/reviews/`, and their rule is checked by people, not by GitHub.
- **A pull request with merge conflicts gets no run.** GitHub runs `pull_request` workflows on the merge of the branch into its base; while the pull request conflicts there is no merge to test, and no run starts, however many commits are pushed. Rebase on `main` to get a result.
- **Pushes to other branches do not run CI** on their own (the `push` trigger is `main` only); a branch is tested through its pull request, by `agent-run.yml`, or nightly (`integration-slice1` and `composite-p6a`).
- **No Windows or macOS build**, no 32-bit build, no regtest node, no reproducible-build check, no mutation testing (the storage layer's runner, `tools/mutate-storage.py`, runs on the build server; its results are in `docs/notes/storage-crypto.md`).
