# Continuous integration

What `.github/workflows/ci.yml` runs, what each job guards, and how to run the same check on your own machine. Written 2026-11-12 with the CI hardening branch (PR 16); brought up to date the same day, after the transport, chain view and wallet transactions merged.

CI runs on every pull request and on every push to `main`. All jobs run in parallel on GitHub's `ubuntu-24.04` runners; the longest is the gcc build without sanitizers (the wallet break-checks), about 12 to 20 minutes. Everything else finishes in a few minutes.

## Rules for the workflow file

- **Read-only token.** `permissions: contents: read` at the top. No job needs to write to the repository; a job that ever does must ask for exactly that permission itself, in that job.
- **Actions pinned by commit.** Every third-party action is named by its full 40-character commit SHA with the release in a comment, for example `actions/checkout@3d3c42e5... # v7.0.1`. A tag can be moved by whoever controls the action's repository; a commit cannot. To update, look up the new tag's commit with `gh api repos/<owner>/<action>/git/ref/tags/<tag>` (if `object.type` is `tag`, follow `object.url` to the commit) and change the SHA and the comment together.
- **No stored credentials.** Every checkout uses `persist-credentials: false`, so the token is not left in `.git/config` for later steps.
- **Downloads are pinned by hash.** The OpenSSL source for the MSan job is checked against its SHA-256; the handbook's Markdown renderer is installed with `pip --require-hashes` from `tools/handbook-requirements.txt`.
- **Stale runs are cancelled.** A new push to a pull request cancels that pull request's run in progress. Runs on `main` are never cancelled.

## The jobs

### build (OFF) and build (ON): gcc, the original job

Guards: the whole tree builds with gcc 13 and every CTest test passes, once without sanitizers and once with AddressSanitizer and UndefinedBehaviorSanitizer (`-DGZ_SANITIZE=ON`). The build without sanitizers also runs the wallet break-checks (label `slow`), which damage one protection at a time and require a test to fail. Then the scale check: one small tree and the two upstream defect reproductions.

Locally:

    cmake -B build -DCMAKE_BUILD_TYPE=Release -DGZ_SANITIZE=OFF   # or ON
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

Guards: reads of uninitialised memory, which neither ASan nor valgrind reports precisely (checklist item 23). MSan needs every library the tests call to be built with it, or it reports the bytes that library returns as uninitialised. So:

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

Guards: memory errors and definite leaks in the compiled tests, on a build with no sanitizer (so it sees the code as shipped, at `-O2`). `tools/valgrind-tests.py` asks CTest for the registered tests and runs each one whose command is a program built in the build directory under `valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --track-origins=yes`, with the same arguments. Tests run through `sh` or Python are listed and skipped: valgrind would check the shell, not our code. Tests run one per processor in parallel. The 1,000-seed simulator run took eight minutes under valgrind, so this job runs it with 200 seeds of the same length (`--args "sim_seeds=200 400 1 0"`); every other build runs all 1,000. Before this job, valgrind ran only in `m1a-followup`'s copy of the workflow.

Locally (Linux, valgrind installed):

    cmake -B build-vg -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGZW_BREAK_CHECKS=OFF
    cmake --build build-vg -j
    python -I tools/valgrind-tests.py build-vg --args "sim_seeds=200 400 1 0" [-j N] [-v] [--include REGEX] [--exclude REGEX]

The storage layer's E2r test (Argon2id at 256 MiB, `storage_vector_e2r`) is excluded here: it is E2's code at more memory and takes minutes under memcheck. A second step runs `storage_ctime`, the constant-time check: `sc_test_ctime` marks the passphrase key, MSK, the seed and the words' entropy undefined and runs every storage operation that holds them under memcheck, so a branch or index on a secret is an error (libsecp256k1's method). Its CTest command is valgrind itself, so `valgrind-tests.py` lists it as skipped; the step runs it, and fails if it was not registered (valgrind or its headers missing). Its one suppression (`ports/storage/crypto/tests/ctime.supp`) is libsodium's branch on whether a tag verified, whose outcome is public.

### libsodium and utf8proc in every job

The storage layer (`ports/storage/crypto`, from PR S6) links libsodium 1.0.22 and utf8proc 2.12.0. CMake downloads both while building and checks each against the SHA-256 pinned in `ports/storage/crypto/CMakeLists.txt`; nothing is taken from the distribution, so every job builds the same code with no extra install step. libsodium is configured with the job's compiler and `CMAKE_C_FLAGS` (so the MSan and fuzz jobs instrument it) and `--disable-asm`. Under MSan two more things change, through `CPPFLAGS`. Fortification is off (`-D_FORTIFY_SOURCE=0`): on glibc libsodium's configure otherwise adds `-D_FORTIFY_SOURCE=3`, clang then compiles each `memcpy` whose destination size is known only at run time as a call to glibc's `__memcpy_chk`, and MSan does not intercept that function, so the bytes it writes stay "uninitialised" in MSan's view; that is why Argon2's output (written by `store64_le` in `argon2_finalize`) and every key and tag derived from it were reported. And the SIMD paths are left out (their `HAVE_*INTRIN_H` definitions undefined), so the code checked is the reference code whatever the runner's CPU. Every other job builds libsodium as its configure sets it, SIMD paths and fortification included. `-DGZ_DEPS_DIR=<folder>` uses local copies of the same tarballs instead of downloading. `tools/verify-libsodium.sh` repeats the minisign check of the tarball against libsodium's published key before a version change; `docs/notes/storage-crypto.md` records it.

### libFuzzer, 60 s per target

Guards: every parser of outside input keeps being fuzzed (checklist item 20), with coverage guidance, ASan and UBSan. The job looks for `LLVMFuzzerTestOneInput` in the C sources. If there is none (a branch from before PR 10), it prints a notice and passes. Otherwise it builds the tree with clang, `-fsanitize=fuzzer-no-link,address,undefined` and `-DGZ_LIBFUZZER=ON`, and `tools/run-fuzz.sh` runs every executable named `fuzz_*` for 60 seconds. It fails on any crash, leak, sanitizer report or 10-second input, and libFuzzer prints the failing input in the log. If the sources define fuzz targets but no `fuzz_*` executable was built, it fails, so a target cannot drop out of the job by being renamed.

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

## What the second compiler changed in the symbol checks

The first clang runs failed two existing tests on `main`, not because the code changed but because the checks only knew gcc's output:

- `wallet_keys_no_io` (`wallet/tests/check_no_io.py`): clang emits `bcmp` for a `memcmp` whose result is only compared with zero, and `memchr` for a byte-search loop. Both are now on the allow-list beside `memcmp` and `strchr`. Under clang's ASan it also saw `__start_asan_globals` and `__stop_asan_globals` (weak references to ASan's section bounds), `___asan_globals_registered`, and `switch.table.<function>` lookup tables shown as data; these are accepted by prefix, each with its reason in the file.
- `core_isolation` (`tools/check-core-isolation.sh`): the same ASan names, and under MSan the `__msan_*` runtime calls and its weak `__msan_track_origins`. Accepted by exact name or the sanitizer prefix, as `__asan_*` already was.

The negative tests of both checks (the sneaky object, the five bad libraries) still fail as they must in every build.

## What CI does not do

- **It does not require a review.** Since 2026-11-12, branch protection on `main` requires all 11 jobs above to pass on a branch that is up to date with `main`, applies to administrators too, and refuses force pushes and deletions. It does not require an approving GitHub review: reviews are kept as files in `docs/reviews/`, and their rule is checked by people, not by GitHub.
- **A pull request with merge conflicts gets no run.** GitHub runs `pull_request` workflows on the merge of the branch into its base; while the pull request conflicts there is no merge to test, and no run starts, however many commits are pushed. Rebase on `main` to get a result.
- **Pushes to other branches do not run CI** on their own (the `push` trigger is `main` only); a branch is tested through its pull request.
- **No Windows or macOS build**, no 32-bit build, no regtest node, no reproducible-build check, no mutation testing (the storage layer's runner, `tools/mutate-storage.py`, runs on the build server; its results are in `docs/notes/storage-crypto.md`).
