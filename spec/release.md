# Release artifacts and verification

Draft 2, 2026-11-13. **Independent review pending; implementation has not begun.**
Scope: experimental test-network distributions. This does not authorize a
mainnet build, change the wallet's safety rules or satisfy its slice tests.
The [handoff](../docs/release/README.md) defines ownership and implementation PRs.

## 1. Identity and inputs

An official candidate names one full Git commit and one signed annotated
version tag. Resolve and verify both once; build that commit, not a moving
branch. Reject an untrusted signer, a changed tag, an invalid version or a
dirty source tree. Before an official release, the owner must define the
trusted fingerprint and approve the version; neither is invented by a builder.
A rehearsal uses an explicit commit and is labelled unofficial.

Proposed tag grammar: `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rcN`,
where components are decimal integers without leading zeros and N is positive.
Limit the complete tag to 64 ASCII characters. Reject other characters rather
than interpreting a tag, filename or manifest value as shell syntax. VERSION
in artifact names is this validated tag. The resolved commit must be on an
owner-approved source branch, initially main; a trusted signature on an
otherwise unapproved commit is insufficient.

Record the source archive digest, dependency digests, build recipe digest,
compiler/linker/CMake versions, target and CPU baseline, configuration flags,
and package closure in the reproducible manifest. Put builder identity,
CI run URLs and other run-specific provenance in separate evidence, outside
the reproducible manifest and archives. Record only allowlisted facts: no full
environment, credentials, personal paths or wallet data. Normalize paths in
published compiler metadata.

The [inventory](../docs/release/dependencies.md) is an observed baseline,
not a completed lockfile. RE3 must enumerate all actual release inputs,
including transitive build/runtime libraries, and verify their acquisition.
An OCI image digest alone does not fix packages installed later from mutable
repositories. Use a retained package snapshot/closure with exact versions and
digests, or an equivalent fully specified source-built dependency closure.

Separate acquisition from build: acquire authenticated, digest-verified inputs
first, then build without network access. Recheck cached inputs. Record source
locations and preserve the inputs needed to rebuild; an unavailable old input
is a failed reproducibility check, not permission to fetch a newer version.

## 2. Production build profile

The first profile is Linux x86_64. Pin a reviewed compiler/toolchain and a
minimum supported runtime. Record the dynamic-loader and shared-library
requirements; do not label a dynamically linked package self-contained.
Avoid host-specific CPU tuning. Missing required HTTPS support fails the
release build; the development build's optional-libcurl fallback is unsuitable.

Keep production and diagnostic profiles distinct. ASan, UBSan, MSan,
Valgrind and fuzzing continue in their existing jobs; they do not become
flags in a downloadable wallet binary. No test kinds, test hooks, fake API
backend, seeded random source, test executable or test wallet is packaged.
Use the existing release-build tests rather than a second weaker check.

Audit the resulting ELF for the architecture, expected dependency set, PIE,
non-executable stack, RELRO/immediate binding, stack protection and symbol
version compatibility. Document applicability and review any exception.
Apply hardening flags per target only after compatibility and crypto tests;
do not blanket-enable LTO, sanitizers or new optimization flags on crypto
dependencies. Libsodium's upstream production-build guidance is part of that
review. This specification does not modify its present diagnostic builds.

## 3. Outputs

The proposed deliverables are:

| Artifact | Contents |
|---|---|
| `gazpacho-VERSION-linux-x86_64.tar.gz` | Allowlisted production executables, verification instructions, test-network status, release notes and required licence notices |
| `gazpacho-VERSION-source.tar.gz` | Exact project source including imported files and generated files required for a non-Git build; dependency acquisition/lock information |
| `release-manifest.json` | Version, commit, recipe/input identities, runtime requirements and artifact names/digests; no secrets or machine-local paths |
| `SHA256SUMS` | Sorted SHA-256 entries for both archives and `release-manifest.json` |
| `SHA256SUMS.asc` | Release-manager detached GnuPG signature over the exact checksum file |

The source archive need not contain every third-party tarball, but the retained
input closure must be available separately, with source and licence obligations
fulfilled. Its acquisition must be tested. A clean source-archive build must
not depend on the project's `.git` directory, an existing checkout or
unrecorded generated files. VCS tools may still be installed in the builder;
the test is independence from project repository metadata.

Use an explicit file allowlist. Reject unsafe archive names, absolute members,
parent traversal, symlinks/hardlinks, duplicate members, missing required files
and unexpected executables. The versioned manifest schema selects an exact
field allowlist and types; reject duplicate keys, unknown fields, invalid
digests and names outside the expected ASCII artifact-name set. RE3 must settle
the machine-readable schema and concrete size limits before parser code starts.
Bound manifest, archive and decompressed sizes. A digest does not make a
hostile archive safe to extract.

Avoid a circular manifest: `release-manifest.json` describes the archives;
`SHA256SUMS` covers the archives and manifest. Neither file hashes itself.
Require the exact expected file set and names, not merely a successful check
of the subset mentioned in a checksum file. Use standard SHA-256 and GnuPG
implementations, not a new signing or hashing scheme.

## 4. Reproducibility

Given the same source, declared environment and instructions, two isolated
clean builds must produce identical unsigned archives and executables.
Vary checkout/build directory names, timezone and wall-clock start; fix locale,
CPU baseline and other declared inputs. Use a source-derived
`SOURCE_DATE_EPOCH`, deterministic ordering, ownership, permissions, gzip
headers and archive timestamps. Remap debug/source paths where needed.

Compare the actual bytes/digests. On mismatch, keep bounded diagnostic reports
and refuse candidate promotion. Demonstrate that the comparison catches a
deliberately changed output. Same-runner rebuilds find nondeterminism; they do
not prove an uncompromised compiler or independent builder agreement.

Signatures, CI URLs, logs and attestations are evidence attached to a build,
not outputs required to be byte-identical. The stable input/recipe fields in
the manifest must agree between builders; run-specific evidence is separate.
RE4 first checks executable bytes. RE5 adds deterministic source/binary
packaging and extends the comparison to those archives, avoiding a dependency
on a packager that has not yet been built.

## 5. Candidate, signing and publication

The state machine is **source approved -> built -> verified -> signed ->
uploaded as draft -> final download verified -> published by release manager**.
Only the release manager advances the final state. No build triggered by an
untrusted PR has signing secrets, write-capable release credentials or access
to the signer's workspace. Never run repository-controlled build scripts in
the trusted signing stage. Build jobs use read-only repository permissions;
grant draft-upload rights only to the separate uploader.

Verify all 12 existing required checks and wallet acceptance evidence for the
exact candidate revision before signing. Require every expected check from
the approved workflow/App identity with an explicit successful result; missing,
cancelled, failed or unrelated same-named checks are insufficient. The release
policy and check list come from an independently reviewed policy revision,
not candidate-controlled data that could waive requirements. Record that
policy/workflow revision and the resolved commit in the verification evidence.
An old PR result for a different merge commit does not satisfy this check.
Test the release profile itself;
passing a sanitizer build of a different configuration is insufficient. Do not
rebuild after verification and then sign the new, untested bytes.

The release manager verifies the tag, expected commit, independent reviewer
evidence, manifest and complete artifact set before signing. Publish the
trusted fingerprint through a channel independent of the downloaded files;
a public key shipped next to an artifact does not establish trust by itself.
Match the full approved signer fingerprint, not a short key ID or display name,
and apply the owner's documented validity/rotation/revocation policy.
Document key expiry, replacement, revocation and a compromised-key response
before official signing is enabled. A temporary-key rehearsal is not an
official release signature.

Use immutable names. An identical retry may complete missing uploads after
checking existing bytes. Different bytes under an existing name fail; issue
a new candidate instead of overwriting. A partially uploaded or unsigned
draft remains unpublished. After interruption, re-read and verify the draft's
complete file set before continuing. Verify the final downloads, not only the
local staging directory. Store staging files atomically and never resume
from an unchecked cached success flag.

An RC-to-final version/source change is a new candidate and repeats the
applicable checks. A signature authenticates bytes, not wallet correctness.
No release candidate becomes mainnet-enabled through this process.

## 6. Required tests before implementation is accepted

Each new protection has a negative or rule-removal test with explicit outcomes.
Use independent standard digest/signature tools to cross-check generated data.
Tests run on GitHub Actions or the contributor's own server.

| Test | Required outcome |
|---|---|
| R1: clean recipe and source archive | Acquire verified inputs, disable build network, build from archive without the project's `.git` directory, test installed/extracted executable on a clean supported runtime |
| R2: altered or missing dependency/cache entry | Fail before compiling, with no fallback to a moving upstream version |
| R3: repeat under varied paths/timezone/start time | Executables match in RE4; archives also match in RE5; run-specific evidence does not change reproducible outputs; one-byte changed output is detected |
| R4: package boundary | Missing file, unexpected test binary, unsafe path/link, duplicate member and oversized input each fail before unsafe extraction |
| R5: manifest/checksum cross-check | Changed archive/manifest, truncated checksum, missing/extra artifact and duplicate filename each fail |
| R6: signing rehearsal | Standard GnuPG verifies a temporary trusted signature; wrong key, invalid signature, changed sums and untrusted valid signature fail |
| R7: tag and provenance binding | Tag moved to another commit, unapproved source branch, wrong architecture, mismatched recipe/source and invalid/oversized version each fail |
| R8: privilege separation | PR job cannot sign or publish; publisher does not execute untrusted candidate code; missing/wrong-revision or untrusted same-named checks cannot authorize signing; failure in verification prevents upload/promotion |
| R9: interrupted/repeated upload | Partial draft stays unpublished; identical retry succeeds; conflicting existing bytes fail without overwrite |
| R10: executable properties | Release/test separation, mainnet refusal before data creation, HTTPS support, expected linkage and applicable hardening are checked on the packaged binary |
| R11: verification from a fresh consumer | Download complete staged set, authenticate expected signer, check exact file set and digests, then safely unpack and smoke-test |
| R12: licence and attribution | Missing required redistributed notice fails; imported-source integrity check remains green |

## 7. What this does not establish

This draft is not a release implementation, certification, security audit or
proof of constant-time behavior. It leaves the exact toolchain lock, runtime
floor, official version, signer identity, support policy and any future
architecture to explicit review. Those values must be resolved before their
implementation PR can claim the corresponding requirement is complete.
