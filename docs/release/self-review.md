# Author's second review

2026-11-13, reviewing the original specification at
`e857f10aaf4cb339ed6b3614140890ea3ff1ef05`. This is an author review,
**not independent approval**, and it does not make release automation exist.

| Finding | Correction in draft 2 |
|---|---|
| SR1: RE4 asked for reproducible archives before RE5 supplied packaging | RE4 compares executable bytes first; RE5 adds archive generation and archive comparison |
| SR2: input/recipe metadata and run-specific builder evidence were not separated clearly enough | Keep run URLs and builder identity outside the reproducible manifest/archives; compare stable inputs and outputs |
| SR3: tag/check binding needed a more explicit authorization rule | Define tag grammar and size; require an approved source branch, exact commit, approved workflow/App identity and reviewed release policy; reject unrelated same-named checks |
| SR4: a source build "without Git" could be read as forbidding the tool rather than repository metadata | Test the project archive without its `.git` directory; VCS tools may still be installed |
| SR5: "unknown critical fields" left the manifest parser's acceptance boundary vague | Require a versioned exact field/type allowlist; RE3 must settle schema and size limits before parser implementation |

## Evidence inspected

- Five recorded dependency identifiers/hashes were compared to the checked-in
  source definitions: SuperScalar import, secp256k1-zkp, libsodium, utf8proc and
  the diagnostic OpenSSL build. All five matched.
- Seven repository-relative links in the original documents were resolved;
  all existed. The follow-up adds this report's link.
- Benchmark source files were retrieved from the six recorded repository
  revisions. Claims describe inspected files, not unobserved CI outcomes or
  a blanket security ranking.
- The PR changes documentation only. Whitespace validation passed on the
  original commit; final-revision GitHub checks must be inspected separately.

## Still required

Follow-up, 2026-11-14: independent review of draft 2 returned accept after
changes. The [response](review-response.md) maps corrections in draft 3;
confirmation of those corrections is pending. CI success cannot substitute
for that review.
The toolchain closure, concrete manifest schema/limits, runtime floor, signer
identity, version and support policy remain explicitly unresolved inputs for
their owning implementation PRs. Reproducibility, package and signing tests
R1-R12 were specified in draft 2; draft 3 also adds R13-R18. None has been
implemented or executed by this planning PR.
