# Release engineering handoff

Draft for independent review, 2026-11-13. This workstream prepares verifiable
distributions; it does not declare the wallet ready to release. No release
automation is implemented by this planning PR.

Start with the [release specification](../../spec/release.md), the
[dependency inventory](dependencies.md), and the [reference comparison](benchmark.md).
The author's [second review](self-review.md) records corrections; it is not
the independent specification approval required before implementation.
The wallet's acceptance criteria remain in [SLICES.md](../SLICES.md) and
[PLAN.md](../PLAN.md). Release engineering is not another prerequisite for
calling an internal Slice 1 experiment complete; distributing an official
candidate does require the applicable release checks.

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
| RE2 | Package licence notices and add scoped SPDX metadata | RE1 review | Every redistributed dependency mapped to its actual licence files; existing attribution preserved; import check passes; missing notice rejected |
| RE3 | Lock one Linux release recipe and its input closure | RE1 review | Exact source/toolchain/package identities and digests; verified downloads and cache entries; clean offline build after acquisition; altered or unlisted input rejected |
| RE4 | Verify executable reproducibility and binary properties | RE3 | Two isolated clean builds with changed source paths, timezone and wall-clock start produce identical executables; a deliberate difference is detected; hardening and ABI evidence recorded |
| RE5 | Package and test experimental Linux distributions | RE2, RE3, RE4 | Extend reproduction to source/binary archives; clean-room source build, extracted-binary smoke test, exact contents and dependency checks; bad archive, missing file, test binary and wrong digest rejected |
| RE6 | Rehearse signed draft releases and candidate verification | RE5 | Temporary-key signing rehearsal, trusted-identity verification and tamper tests; restart-safe draft upload; release-manager checklist; no production key or public release needed for the PR |
| RE7 | Add bounded dependency-update automation | RE1 review | Supported manifests identified; low-volume grouped Actions updates; exact pins retained; custom CMake pins covered by a separate review procedure. Optional follow-up |

RE2 can proceed beside RE3. RE4 and RE5 can be developed together on a stack,
but remain separate reviews. RE7 is not a blocker for Slice 1 or the first
candidate. Keep one review-ready PR per builder in the coordinator's queue.

## CI placement

These are proposed additional jobs. The existing 12 checks are not renamed,
filtered away or made optional by this workstream.

| Event | Additional work |
|---|---|
| Ordinary PR | Fast release metadata checks. Run focused script/package tests when the relevant inputs change |
| Release recipe, dependency, compiler or packaging PR | Clean build plus the applicable reproducibility, package and negative tests before merge |
| Scheduled main build | One bounded Linux release rehearsal, initially weekly; report reproducibility drift. A manual trigger supports investigations |
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
2. Use standard GnuPG detached signatures for `SHA256SUMS` and signed annotated
   Git tags, following the Bitcoin/Lightning references. The owner designates
   the trusted fingerprint and recovery/revocation process before official use.
3. Release signing stays outside PR jobs. Offline release-manager signing is
   the initial design; any hosted signer requires its own reviewed trust model.
4. Start with a locked Linux toolchain/package closure rather than adopting
   Guix or another replacement build system. This is weaker than Bitcoin
   Core's bootstrappable toolchain and must be described that way.
5. Source/packaging changes get release-specific checks before merge. Wallet
   acceptance, expert cryptographic review and the mainnet gates remain the
   owning team's responsibility.

## Review and completion

The release process needs an independent supply-chain/build review; crypto
dependency flags need the existing cryptography review rules as well. A second
builder reproducing an artifact is useful independent evidence, but two jobs
on one provider do not establish independent organizational control.

RE1 is complete when this specification has been independently reviewed and
CI is green. The workstream is complete only after RE2-RE6 have passing
evidence and an independently checked candidate rehearsal. Track actual job
durations and findings in their PRs; do not convert this list into an assumed
calendar deadline or claim a SLSA level from a document.
