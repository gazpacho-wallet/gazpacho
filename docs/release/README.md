# Release engineering handoff

Draft 3 for review confirmation, 2026-11-14. This workstream prepares verifiable
distributions; it does not declare the wallet ready to release. No release
automation is implemented by this planning PR.

Start with the [release specification](../../spec/release.md), the
[dependency inventory](dependencies.md), and the [reference comparison](benchmark.md).
The author's [second review](self-review.md) records corrections; it is not
the independent specification approval required before implementation.
The independent review accepted draft 2 after changes; the
[response](review-response.md) maps those changes and remaining decisions.
The wallet's acceptance criteria remain in [SLICES.md](../SLICES.md) and
[PLAN.md](../PLAN.md). Release engineering is not another prerequisite for
calling an internal Slice 1 experiment complete; distributing an official
candidate does require the applicable release checks.
RE2-RE7, RE-S and RE-K are tied to M6, the first signet release candidate.
Monitoring, signing quorum and distribution evidence must be complete before
an official M6 candidate is published. Internal slice work can proceed beside
this workstream; its own acceptance criteria remain unchanged.

## Boundaries

- Use a separate branch per PR and GitHub Actions or the contributor's own
  build server. Do not use the shared, SSH-rate-limited build server.
- Every PR still needs all 12 existing required checks green on the applicable
  revision, an up-to-date branch, and the required independent reviews.
- Keep machine addresses, personal paths, secrets and raw environment dumps
  out of commits and review reports. Record repository-relative paths and
  allowlisted, sanitized build facts instead.
- Own `docs/release/`, `spec/release.md`, `tools/release/`, dedicated release
  workflows and dependency-update configuration. Agree shared CMake edits
  with the engine coordinator before making them.
- Do not edit imported sources, change dependency versions, compiler behavior,
  wallet engines or the existing merge gates as part of a packaging PR.
  A necessary change to these is a separately scoped and reviewed PR.
- A builder supplies evidence; a different reviewer confirms it. The release
  manager owns signing identities, tags and public publication.

## Proposed PRs

The identifiers below are work packages, not GitHub issue or PR numbers.
Each implementation starts only after its relevant specification is reviewed,
as required by engineering-checklist item 1.

| ID | Title and scope | Depends on | Acceptance evidence |
|---|---|---|---|
| RE1 | Specify releases, inventory dependencies and benchmark reference projects (this PR) | None | Independent review of requirements, inventory and source links; existing CI green. No runtime or workflow change |
| RE2 | Package notices, SPDX headers and REUSE annotations | RE1 review | Inventory existing headers; correct per-file ownership/licences; `LICENSES/` and `REUSE.toml`/sidecars for unchanged imports/vendor/generated files; lint and missing-notice rejection |
| RE3a | Define input schema and verified acquisition | RE1 review | Exact identities/digests and bounded schema; retained secp archive from the same commit/tree; verified offline dependency folder; damaged/unlisted/cache inputs rejected |
| RE3b | Lock the Linux build environment | RE3a | Digest-pinned image, dated package snapshot and package closure; source-pinned static OpenSSL/curl and TLS closure; dynamic glibc ceiling, CA policy and offline build |
| RE3c | Add the production CMake profile | RE3a, RE3b; engine coordination and crypto review | Explicit modules/Valgrind settings, path maps, reviewed libsodium optimization/flags, required curl, selected Release configuration, hardening and `install()` allowlist |
| RE4 | Verify executable reproducibility and binary properties | RE3c | Vary paths/depth, user, umask, timezone and start time; identical executable bytes; deliberate differences detected; ELF hardening and glibc ceiling checked |
| RE5 | Package and test experimental Linux distributions | RE2, RE3c, RE4 | Deterministic archives and SPDX SBOM; clean source build and extracted executable on oldest runtime; exact contents/dependency checks and negative tests |
| RE-S | Expand the existing security policy | RE1 review | Supported versions, severity/response targets agreed with maintainers, private reporting/advisories, upstream embargo coordination, withdrawal and compromised-key response; no invented guarantees or signer names |
| RE-K | Define signing policy and conduct owner-led key ceremony | RE-S; named owner decisions | Manager and independent builder identities, quorum, custody/recovery/revocation, settings evidence and attestation store; no hardware purchase or key generation without owner decisions |
| RE6 | Rehearse multi-signer draft releases | RE5, completed RE-K | Explicit-data/full-fingerprint verification, distinct-principal quorum, signature retries, upload lock, tag rechecks, immutable publication and withdrawal tests; no public release needed for acceptance |
| RE7 | Monitor dependencies and bound update automation | RE3a input inventory; RE1 review for Actions configuration | Required retained scheduled pin/advisory report and release freshness gate; grouped low-volume Actions updates, SHA/permissions lint; incomplete sources cannot report clean |

RE2 and RE-S can proceed beside RE3a. RE3b/RE3c are distinct reviews; compiler
and crypto-module changes are not housekeeping. Actions monitoring can start
before the full C dependency inventory is finished, but the required report
must cover the final closure before M6. Signing/publication work stays on hold
until RE-K's owner decisions are resolved. Keep one review-ready PR per builder
in the coordinator's queue.

## CI placement

These are proposed additional jobs. The existing 12 checks are not renamed,
filtered away or made optional by this workstream.

| Event | Additional work |
|---|---|
| Ordinary PR | Fast release metadata checks. Run focused script/package tests when the relevant inputs change |
| Release recipe, dependency, compiler or packaging PR | Clean build plus the applicable reproducibility, package and negative tests before merge |
| Scheduled main build | One bounded Linux release rehearsal and required pin/advisory report, initially weekly; retain freshness/status evidence. Manual trigger supports investigations |
| Official candidate | All existing checks for the exact source revision, full release recipe, two-build comparison, archive/source-install checks and required wallet acceptance evidence |
| Signing/publishing | Separate trusted stage after candidate verification; verify the downloaded final assets again before publication |

New jobs use their own names, timeouts, concurrency group and dependency cache.
Cancel superseded PR runs; do not cancel an in-progress signing operation.
Verify cached bytes, and never share writable caches or artifacts from
untrusted PR runs with a privileged publication stage. Measure runner minutes
and queue time before expanding the schedule. Do not use a conditional job's
successful skip as evidence that an applicable release test passed.

## Proposed decisions for review

1. Linux x86_64 is the first release-engineering target, not a promise of the
   complete product's platform support. Other architectures follow separately.
2. Use OpenPGP detached signatures for `SHA256SUMS` and signed annotated Git
   tags. Require the manager and at least one independent reproducing builder;
   the owner names people, roles, fingerprints and custody in RE-K.
3. Release signing stays outside PR jobs. Offline release-manager signing is
   the initial design; any hosted signer requires its own reviewed trust model.
4. Start with a digest-pinned image and dated package snapshot, static
   source-pinned crypto/network libraries and dynamic glibc with a ceiling.
   Guix is the long-term target; this method is not bootstrappable assurance.
5. Source/packaging changes get release-specific checks before merge. Wallet
   acceptance, expert cryptographic review and the mainnet gates remain the
   owning team's responsibility.

The coordinator recommends these engineering defaults. The owner still must
name the signers, approve custody/revocation arrangements and authorize `v*`
tag protection/immutable releases. The settings are administrator actions,
not changes this PR makes. No production signer or token is assumed to exist.

## Review and completion

The release process needs an independent supply-chain/build review; crypto
dependency flags need the existing cryptography review rules as well. A second
builder reproducing an artifact is useful independent evidence, but two jobs
on one provider do not establish independent organizational control.

RE1 is complete when this specification has been independently reviewed and
CI is green and the independent reviewer confirms the changes. The workstream
is complete only after RE2-RE7, RE-S and RE-K have passing
evidence and an independently checked candidate rehearsal. Track actual job
durations and findings in their PRs; do not convert this list into an assumed
calendar deadline or claim a SLSA level from a document.
