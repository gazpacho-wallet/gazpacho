# Reference comparison and choices

Reviewed 2026-11-13 against the exact revisions below; corrected after
independent review on 2026-11-14. This compares selected
public source files, not the projects' overall security, current production
deployments or the results of their CI runs. Bitcoin Core is C++; secp256k1,
libsodium and curl are C references, and Core Lightning is the Lightning
implementation reference. Size and age make an overall ranking misleading.

## What to borrow

| Reference | Observed practice | Gazpacho choice |
|---|---|---|
| Bitcoin Core | Guix build environment; separate non-codesigned attestations; multiple builders sign matching checksum manifests; compiled-binary checks | Adopt exact artifact identity, required independent reproduction, multi-signer detached signatures and ELF verification. Guix is a long-term target; do not claim equivalent assurance now |
| libsecp256k1 | Release PR sanity checks include distcheck, installation through CMake/Autotools and ABI checks; CI includes Valgrind/constant-time and sanitizer configurations | Test the actual extracted/installed package and clean source build. Preserve Gazpacho's existing diagnostics. Library ABI tooling becomes relevant if Gazpacho distributes a supported library ABI |
| Core Lightning | RC checklist compares local and draft checksums and appends builder signatures; separated builds; nightly build in the reproducible environment checks a clean version/tree, not equality of two builds | Separate build, verify, sign and publish; require matching independent builds and a pre-publication signer quorum. Do not count the nightly job as a two-build comparison |
| libsodium | Authenticated distribution tarballs; signature verification instructions; production compiler guidance; CI includes multiple build modes and CIFuzz | Verify dependency origin/digest and follow upstream crypto build constraints. Diagnostic flags are not a production optimization policy |
| curl | Signed source releases and reviewed notes; distribution CI rebuilds/tests/installs generated archives; grouped monthly dependency updates | Test the source tarball outside Git, include correct notices, and keep update volume bounded. Do not inherit its release calendar or every platform job |
| SuperScalar | Defined manager/RC process, signed tags, recommended offline GPG checksum signing; multi-platform artifacts; broad development CI | Reuse the vocabulary, human signing boundary and checklist. Improve input locking and draft-before-publication handling in Gazpacho's design |

## SuperScalar and Gazpacho, specifically

SuperScalar at `9482de06a6ff56c3989dc9620516ce089d0ac99a` has a substantive
development pipeline: Linux/macOS and ARM64 jobs, ASan/UBSan, ThreadSanitizer,
Cppcheck, coverage, regtest integration, multi-process regtest cases and
five-minute-per-target fuzz runs with corpus handling. Merely defining a job
does not establish a clean run or complete coverage; this is a source inventory.

Gazpacho at `ae023f3818b2c5ebb9ca82d0d0a49c23c205ca8c` already has GCC and
Clang builds, ASan/UBSan, MSan with instrumented OpenSSL, Valgrind, a scoped
storage constant-time check, 60-second-per-target fuzzing, wallet mutation
checks and core/import isolation checks. Its current main workflows do not
define equivalent dedicated Cppcheck, TSan, coverage or regtest jobs. This
release work does not silently add those to the 12 required merge checks.

The inspected SuperScalar release workflow is useful working scaffolding,
but it is not a reproducibility proof:

- Its event is `release: published` (or manual dispatch), although parts of
  the release guide describe draft uploads before publication. Gazpacho's
  proposed state machine verifies and stages first, then publishes explicitly.
- Its release jobs use mutable runner labels and package-repository inputs;
  Actions are referenced by version tags there. A pinned base image alone
  would still not lock packages fetched inside it.
- It packages compiled binaries and generates checksums, with detached GPG
  signing assigned to the release manager. The inspected release workflow
  does not compare two clean builds or run its CI test matrix itself.
- Uploads use replacement behavior. Gazpacho's proposal fails on conflicting
  existing bytes and creates a new candidate instead of changing an existing
  candidate's meaning.

The CMake pin for SuperScalar's secp256k1-zkp is the same commit used by
Gazpacho; its inspected cJSON input uses a version tag. Gazpacho's libsodium
and utf8proc inputs already have archive hashes, while its production OpenSSL,
libcurl and toolchain closure still need locking. This is not grounds to claim
that either whole project is safer than the other.

## Selected combination

The proposal is **Gazpacho's existing C checks + a locked Linux build closure +
distribution tests + reproducible unsigned outputs + required independent
builder signatures + a separately controlled publication step**. A clean
same-provider rebuild finds nondeterminism; it does not satisfy the independent
builder requirement for the first official M6 publication.

ELF checks inspect the generated application, not a wish list of compiler
flags. Add PIE, non-executable stack, RELRO/binding, stack protection, FORTIFY,
separate code/data segments, applicable CET and ABI
checks in RE4, with applicability and dependency-specific review. In particular,
libsodium warns about LTO and sanitizer/custom production compiler flags.
Do not globally alter crypto flags or Gazpacho's freestanding core contract.

Static analysis, thread checking, coverage reports and longer corpus-based
fuzzing are sensible separately reviewed quality candidates. Select them from
measured gaps: thread checking for actual concurrent adapters, coverage to
find unexercised branches rather than meet a percentage target, and longer
fuzzing in a bounded scheduled job. Keep them out of this release-specification
PR so the core team's merge queue is not expanded accidentally.

## Current work versus proposed work

| Capability | Observed Gazpacho baseline | After accepted release work packages |
|---|---|---|
| Existing C memory/fault checks | Present, with scoped workloads and exclusions | Preserved; release profile additionally tested |
| Complete release input lock | Partial dependency pins; system build inputs mutable | Recorded and verified release closure |
| Byte-identical artifact comparison | No release comparison in inspected main workflows | Required two-build comparison, with an explicit assurance limit |
| Source/package install test | Development and executable tests; no complete release distribution pipeline observed | Clean source archive and extracted package verified |
| Release authentication | No complete workflow observed | Trusted tag plus manager/independent-builder signatures on matching sums; verified final downloads |
| Publication boundary | No complete release workflow observed | Checked candidate, separate signer/uploader, draft then explicit publication |
| Supply-chain certification | None established by this review | None claimed without separate evidence/assessment |

Core Lightning and Bitcoin Core allow multiple builders' signatures over the
same checksum bytes. This is stronger than draft 2's single-manager signature.
Draft 3 adopts that quorum and distinguishes additive signatures in a draft
from immutable published assets: late attestations use a separate store.

The right-hand column is a specification target, **not functionality delivered
by this PR**. The current pin/CI baseline must be rechecked when engines merge.

## Primary sources

Commit links make this comparison reproducible even if the reference branches
change. All text above is a summary; no code or release scripts were copied.

- Bitcoin Core [release process](https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/doc/release-process.md), [Guix build/attestation guide](https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/contrib/guix/README.md), [binary hardening](https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/contrib/guix/security-check.py), [symbol/runtime checks](https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/contrib/guix/symbol-check.py).
- libsecp256k1 [release process](https://github.com/bitcoin-core/secp256k1/blob/2e1e6c60e970b8c27adfd6e5f0e6d23a91bc70f6/doc/release-process.md) and [CI](https://github.com/bitcoin-core/secp256k1/blob/2e1e6c60e970b8c27adfd6e5f0e6d23a91bc70f6/.github/workflows/ci.yml).
- Core Lightning [checklist](https://github.com/ElementsProject/lightning/blob/fce8f5375669eaa373db3d0713f8986420f304bd/doc/contribute-to-core-lightning/release-checklist.md), [release builds](https://github.com/ElementsProject/lightning/blob/fce8f5375669eaa373db3d0713f8986420f304bd/.github/workflows/release-build.yml), [nightly environment build](https://github.com/ElementsProject/lightning/blob/fce8f5375669eaa373db3d0713f8986420f304bd/.github/workflows/repro.yml).
- libsodium [installation, compiler guidance and signatures](https://doc.libsodium.org/installation), [CI](https://github.com/jedisct1/libsodium/blob/c000d33005c607c55bb4eb0c1002ee079f774110/.github/workflows/ci.yml), [CIFuzz](https://github.com/jedisct1/libsodium/blob/c000d33005c607c55bb4eb0c1002ee079f774110/.github/workflows/cifuzz.yml).
- curl [release procedure](https://github.com/curl/curl/blob/4f2b5fba5212a32c4e4a889492cc153e1220e619/docs/RELEASE-PROCEDURE.md), [distribution checks](https://github.com/curl/curl/blob/4f2b5fba5212a32c4e4a889492cc153e1220e619/.github/workflows/distcheck.yml), [update grouping](https://github.com/curl/curl/blob/4f2b5fba5212a32c4e4a889492cc153e1220e619/.github/dependabot.yml).
- SuperScalar [release process](https://github.com/8144225309/SuperScalar/blob/9482de06a6ff56c3989dc9620516ce089d0ac99a/docs/release-process.md), [release workflow](https://github.com/8144225309/SuperScalar/blob/9482de06a6ff56c3989dc9620516ce089d0ac99a/.github/workflows/release.yml), [development CI](https://github.com/8144225309/SuperScalar/blob/9482de06a6ff56c3989dc9620516ce089d0ac99a/.github/workflows/ci.yml), [dependency definitions](https://github.com/8144225309/SuperScalar/blob/9482de06a6ff56c3989dc9620516ce089d0ac99a/CMakeLists.txt).
- Reproducible Builds [definition](https://reproducible-builds.org/docs/definition/) and [source timestamp convention](https://reproducible-builds.org/specs/source-date-epoch/).
- GitHub [required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) and [Dependabot scope](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories).
- SLSA [build requirements and signing isolation](https://slsa.dev/spec/v1.2/build-requirements).
- GitHub [immutable release asset/tag restrictions](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases); additions belong in the draft before publication.
- [REUSE 3.3](https://reuse.software/spec-3.3/) for unchanged-file annotations and [SPDX](https://spdx.github.io/spdx-spec/v2.3.1/) for the SBOM.
- GnuPG [automated/batch verification](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html) and [signature commands](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html).
