# Release artifacts and verification

Draft 3, 2026-11-14. Independent review of draft 2: **accept after changes**.
This revision addresses that review and awaits confirmation. Implementation
has not begun. See the [response](../docs/release/review-response.md).
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
in artifact names is this validated tag. The resolved commit must be on main;
a trusted signature on an
otherwise unapproved commit is insufficient.

Reserve the version and record both the annotated tag object ID and peeled
commit ID at approval. Recheck both before signing and publication. Never
move/recreate a release tag or reuse a version after public exposure, even if
the release is withdrawn. Abandoned official candidate identities are retired.
Tag rules blocking updates/deletion of `v*` and immutable releases must be
enabled and verified before the first official `v*` tag. These are owner
settings, not effects a PR can apply. No settings change is made by this spec.

Record the source archive digest, dependency digests, build recipe digest,
compiler/linker/CMake versions, target and CPU baseline, configuration flags,
and package closure in the reproducible manifest. Put builder identity,
CI run URLs and other run-specific provenance in separate evidence, outside
the reproducible manifest and archives. Record only allowlisted facts: no full
environment, credentials, personal paths or wallet data. Normalize paths in
published compiler metadata.

The [inventory](../docs/release/dependencies.md) is an observed baseline,
not a completed lockfile. RE3a must enumerate all actual release inputs,
including transitive build/runtime libraries, and verify their acquisition.
An OCI image digest alone does not fix packages installed later from mutable
repositories. The initial method is an OCI image pinned by digest, with
compiler/build packages from one dated Debian/Ubuntu snapshot. RE3b locks the
image, snapshot metadata/trust roots and package versions/digests. OpenSSL and
libcurl, including the chosen TLS backend and transitive libraries, are built
from hash-pinned source and linked statically; glibc remains dynamic. Static
linking requires a prompt rebuild/release procedure for advisories. Specify
CA trust-store and OpenSSL provider/configuration-loading policy; ambient
settings must not add unrecorded runtime dependencies. Guix is the longer-term
bootstrappability target, not a claim about this initial method.

Separate acquisition from build: acquire authenticated, digest-verified inputs
first, then build without network access. Recheck cached inputs. Record source
locations and preserve the inputs needed to rebuild; an unavailable old input
is a failed reproducibility check, not permission to fetch a newer version.
For secp256k1-zkp, retain the approved commit/tree identities and actual archive
bytes with SHA-256 and an archive recipe. Do not assume `git archive` output
is stable across tool versions. Acquisition changes do not authorize upgrades.

## 2. Production build profile

The first profile is Linux x86_64. Pin a reviewed compiler/toolchain and a
minimum supported runtime. Record the dynamic-loader and shared-library
requirements; do not label a dynamically linked package self-contained.
Avoid host-specific CPU tuning. Missing required HTTPS support fails the
release build; the development build's optional-libcurl fallback is unsuitable.

RE3c supplies an explicit production CMake profile and `install()` allowlist.
Require a selected Release configuration, reject empty/unsupported settings,
normalize paths and enumerate secp modules and Valgrind options explicitly.
Preserve ECDH for Noise, MuSig for signing/adaptor operations, Schnorr,
extrakeys and recovery where the imported invoice code needs it. Determine
the final module closure with SuperScalar and under crypto review; the ECDSA
adaptor module is distinct from MuSig adaptor operations. Set
`SECP256K1_VALGRIND=OFF` in production and choose diagnostic settings explicitly.
Record/assert libsodium's effective optimization/flags against upstream
guidance; no silent `-O0`, LTO or diagnostic flag leakage.

The reviewer observed embedded BPPP paths and `GLIBC_2.38` in one Release
build. These are properties of that build, not a claim that all builds require
glibc 2.38. RE3b fixes a reviewed numeric symbol ceiling and oldest runtime
image; RE3c prevents newer symbol imports, and RE4/RE5 check that oldest
runtime. The runtime floor is unresolved until the profile is approved.

Keep production and diagnostic profiles distinct. ASan, UBSan, MSan,
Valgrind and fuzzing continue in their existing jobs; they do not become
flags in a downloadable wallet binary. No test kinds, test hooks, fake API
backend, seeded random source, test executable or test wallet is packaged.
Use the existing release-build tests rather than a second weaker check.

Audit the resulting ELF for the architecture, expected dependency set, PIE,
non-executable stack, RELRO/immediate binding, stack protection, FORTIFY,
separate code/data segments, applicable CET properties and symbol
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
| `gazpacho-VERSION.spdx.json` | SPDX 2.3-series SBOM derived from verified inputs and actual linked/packaged components, with source and licence relationships |
| `SHA256SUMS` | Sorted SHA-256 entries for archives, SBOM and `release-manifest.json` |
| `SHA256SUMS.asc` | Detached OpenPGP signatures from the approved release manager and at least one independent reproducing builder over the same checksum bytes |

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
digests and names outside the expected ASCII artifact-name set. RE3a must settle
the machine-readable schema and concrete size limits before parser code starts.
Bound manifest, archive and decompressed sizes. A digest does not make a
hostile archive safe to extract.

Avoid a circular manifest: `release-manifest.json` describes archives and SBOM;
`SHA256SUMS` covers those and the manifest. The SBOM describes inputs/components,
not a checksum of itself or its enclosing manifest. Neither manifest hashes
itself. Fix SBOM timestamps/tool metadata deterministically; run identity is
separate evidence. Reconcile SBOM entries with both the lock and linked output.
Require the exact expected file set and names, not merely a successful check
of the subset mentioned in a checksum file. Use standard SHA-256 and GnuPG
implementations, not a new signing or hashing scheme.

RE2 uses SPDX headers for project-owned files and REUSE annotations/sidecars
for imported, vendored, generated or uncommentable files, with licence texts
in `LICENSES/`. Keep original bytes/attribution intact; do not infer ownership
or apply the project's MIT licence to unrelated files. Account for current
headers first. `reuse lint` and the package-notice check are acceptance evidence.

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
It also has terminal **abandoned** and **withdrawn** states. Verification or
content failures abandon the candidate; a transient transport interruption
may retry only the same already-approved identity/bytes. A published release
is withdrawn through the advisory process below, never silently repaired.
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

### 5.1 Signers, custody and verification

RE-K must name the release manager and at least one independent builder, their
full primary/subkey fingerprints, roles and separate control of build/signing
systems. Require the manager plus one independently reproduced matching build
before the first official publication. Two subkeys of one primary key, or two
keys controlled by the same person, do not count as independent approvals.
Each signer verifies/recomputes the complete artifact set against the same
`SHA256SUMS`; the independent builder also reproduces unsigned outputs.
Keep per-builder signed records in an owner-designated attestation store.

The owner must approve custody, backups, expiry/renewal, revocation-certificate
custodians, lost-key handling and emergency recovery before signing work starts.
An offline certification primary with a hardware signing subkey and two-year
expiry is a recommendation for that ceremony, not permission to buy hardware,
generate keys or invent named signers. A compromised old key's cross-signature
alone cannot authenticate its replacement. RE-S expands the existing
`SECURITY.md`; RE-K supplies the actual approved identities and key policy.

The release manager verifies the tag, expected commit, independent reviewer
evidence, manifest and complete artifact set before signing. Publish the
trusted fingerprint through a channel independent of the downloaded files;
a public key shipped next to an artifact does not establish trust by itself.
Match the full approved signer fingerprint, not a short key ID or display name,
and apply the owner's documented validity/rotation/revocation policy.
Document key expiry, replacement, revocation and a compromised-key response
before official signing is enabled. A temporary-key rehearsal is not an
official release signature.

Use isolated GnuPG configuration/keyrings and machine-readable `--status-fd`
output. Always pass both the detached signature file and the explicit
`SHA256SUMS` data file. `GOODSIG` or exit status alone is not authorization;
associate `VALIDSIG` with the full approved primary/subkey fingerprints and
evaluate every signature's validity/revocation/expiry under the approved policy.
Reject malformed or invalid submitted signature blocks and test mixed bundles.
Count distinct approved principals, not packets, display names or short IDs.

### 5.2 Retries, concurrency and immutability

Use immutable names. An identical retry may complete missing uploads after
checking existing bytes. Different bytes under an existing name fail; issue
a new candidate instead of overwriting. **The draft signature bundle is the
exception:** OpenPGP signatures carry time metadata, so another valid signature
over the same checksum bytes need not be byte-identical. Add only verified
signatures, preserve accepted approvals, and count a repeated signer's retry
once. Reject signatures over other checksum data. Freeze the bundle after the
required quorum and final verification. Publication makes all assets immutable;
later attestations go in the separate store, not into the published `.asc`.

Only one uploader may hold the version/tag-scoped lock across read, validate,
append and upload. Use non-cancelling concurrency plus a cross-invocation lease
or equivalent single-writer mechanism; if locks/remote state cannot be verified,
fail closed. An interrupted holder must revalidate remote bytes and the approval
state before resuming. Signers may produce signatures separately, but do not
race to replace the shared draft bundle. A partially uploaded or unsigned
draft remains unpublished. After interruption, re-read and verify the draft's
complete file set before continuing. Verify the final downloads, not only the
local staging directory. Store staging files atomically and never resume
from an unchecked cached success flag.

Before publication, recheck the tag object/commit IDs, key status, signer quorum,
owner protections and downloaded complete artifact set. Revocation/compromise
during staging abandons the candidate; it cannot publish using stale approval.

### 5.3 Withdrawal and monitoring

On a bad release or key compromise, stop promotion and use the preapproved
emergency procedure: issue a signed withdrawal/advisory binding version, commit
and artifact digests; update release notes/title and recommended/latest status;
coordinate a GitHub Security Advisory and a changelog entry. Keep immutable
payloads and retired versions as evidence; a corrected build uses a new version.
Verifiers apply current authenticated withdrawal/key-status records and refuse
withdrawn candidates. Offline verification states its status-record freshness
limit instead of claiming knowledge of later withdrawals. Emergency recovery
must not require a signature from a known-compromised key.

RE7's scheduled pin/advisory report is required, with an owner, retained evidence
and a release freshness gate. An unavailable upstream/advisory source is reported
as incomplete, not clean. Static-library advisories need a rebuilt candidate.
Dependabot Actions updates are bounded and reviewed; arbitrary CMake pins have
their own monitoring and update procedure. Enabling automation does not waive
the existing required reviews or 12 checks.

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
| R3: repeat under varied environment | Vary paths/depth, user, umask, timezone and start time; executables match in RE4 and archives in RE5; run evidence does not change reproducible outputs; one-byte changes are detected |
| R4: package boundary | Missing file, unexpected test binary, unsafe path/link, duplicate member and oversized input each fail before unsafe extraction |
| R5: manifest/checksum cross-check | Changed archive/manifest, truncated checksum, missing/extra artifact and duplicate filename each fail |
| R6: signing rehearsal | Isolated GnuPG checks the explicit data file and full fingerprints; wrong/untrusted, expired/revoked, malformed/mixed signatures and omitted data fail; one principal cannot satisfy two roles |
| R7: tag and provenance binding | Tag moved to another commit, unapproved source branch, wrong architecture, mismatched recipe/source and invalid/oversized version each fail |
| R8: privilege separation | PR job cannot sign or publish; publisher does not execute untrusted candidate code; missing/wrong-revision or untrusted same-named checks cannot authorize signing; failure in verification prevents upload/promotion |
| R9: interrupted/repeated upload | Partial draft stays unpublished; identical payload retry succeeds; timestamp-different valid re-signing and a second independent signer succeed once each; conflicting bytes, checksum/signature mismatch and concurrent upload races fail |
| R10: executable properties | Release/test separation, mainnet refusal before data creation, HTTPS support, expected linkage and applicable hardening are checked on the packaged binary |
| R11: verification from a fresh consumer | Download complete staged set, authenticate expected signer, check exact file set and digests, then safely unpack and smoke-test |
| R12: licence and attribution | Missing required redistributed notice fails; imported-source integrity check remains green |
| R13: protected identity | Changed/deleted tag object or peeled commit, reused/abandoned version, missing protections and stale signer status block publication |
| R14: SBOM | Validate SPDX JSON and reconcile source/linked/packaged components with the lock; missing/extra component, altered digest and nondeterministic metadata fail |
| R15: runtime floor | Run the extracted executable on the oldest supported image; check explicit glibc symbol ceiling and reject newer imports |
| R16: workflow boundary | Lint triggers, permissions, action pins and trusted workflow bindings; use harmless fixture credentials to show a PR job cannot reach signer privileges, never a real-secret probe |
| R17: withdrawal | Abandoned/withdrawn candidate, compromised-key recovery and stale status evidence are exercised without deleting or mutating published payloads |
| R18: monitoring | An outdated pin/advisory report, missing owner or incomplete source fails the candidate freshness gate; no automatic dependency upgrade |

## 7. What this does not establish

This draft is not a release implementation, certification, security audit or
proof of constant-time behavior. It leaves the exact toolchain lock, runtime
floor, official version, signer identity, support policy and any future
architecture to explicit review. Those values must be resolved before their
implementation PR can claim the corresponding requirement is complete.
