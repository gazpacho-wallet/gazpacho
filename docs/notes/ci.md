# Continuous integration

What `.github/workflows/ci.yml` runs, what each job guards, and how to run the same check on your own machine. Written 2026-11-12 with the CI hardening branch.

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

Guards: the test vectors printed in the specifications are still what `tools/spec-vectors.py` computes, and the script's own self-checks (the BIP 340 test vector, the split and funding rules) pass. The job runs `python3 -I tools/spec-vectors.py` and fails on a non-zero exit. On a branch without the script (today, `main`) it prints a notice and passes. The script uses the standard library only.

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
- The C library is handled by MSan's own interceptors.

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

Guards: memory errors and definite leaks in the compiled tests, on a build with no sanitizer (so it sees the code as shipped, at `-O2`). `tools/valgrind-tests.py` asks CTest for the registered tests and runs each one whose command is a program built in the build directory under `valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --track-origins=yes`, with the same arguments. Tests run through `sh` or Python are listed and skipped: valgrind would check the shell, not our code. Tests run one per processor in parallel; the 1,000-seed simulator run is the longest, about five minutes under valgrind. Before this job, valgrind ran only in `m1a-followup`'s copy of the workflow.

Locally (Linux, valgrind installed):

    cmake -B build-vg -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGZW_BREAK_CHECKS=OFF
    cmake --build build-vg -j
    python -I tools/valgrind-tests.py build-vg [-j N] [-v] [--include REGEX] [--exclude REGEX]

### libFuzzer, 60 s per target

Guards: every parser of outside input keeps being fuzzed (checklist item 20), with coverage guidance, ASan and UBSan. The job looks for `LLVMFuzzerTestOneInput` in the C sources. If there is none (today, `main`), it prints a notice and passes. Otherwise it builds the tree with clang, `-fsanitize=fuzzer-no-link,address,undefined` and `-DGZ_LIBFUZZER=ON`, and `tools/run-fuzz.sh` runs every executable named `fuzz_*` for 60 seconds. It fails on any crash, leak, sanitizer report or 10-second input, and libFuzzer prints the failing input in the log. If the sources define fuzz targets but no `fuzz_*` executable was built, it fails, so a target cannot drop out of the job by being renamed.

How a branch adds its fuzz targets. Branches today (`transport`, `wallet-tx`, `wallet-tx-lib`) build each target with a plain driver and run it as a CTest test; keep that, and add the libFuzzer form:

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

## What CI does not do

- **It is not yet a gate.** Nothing makes these checks required before a merge; that is a repository setting (branch protection on `main` with the jobs above as required checks).
- **A pull request with merge conflicts gets no run.** GitHub runs `pull_request` workflows on the merge of the branch into its base; while the pull request conflicts there is no merge to test, and no run starts, however many commits are pushed. Rebase on `main` to get a result.
- **Pushes to other branches do not run CI** on their own (the `push` trigger is `main` only); a branch is tested through its pull request.
- **No Windows or macOS build**, no 32-bit build, no regtest node, no reproducible-build check, no mutation testing.
