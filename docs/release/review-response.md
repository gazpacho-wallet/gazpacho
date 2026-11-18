# Independent review response

Response dated 2026-11-14 to the independent review of 2026-11-13. That
build/supply-chain review of PR 40 at
`6e302d4a6d4de9e43baee1ac5341d5ab51650066` returned **accept after changes**.
Draft 3 addresses its nine required-change groups below. Confirmation of this
revision remains pending; this response is not a substituted approval.
The raw review remains with the coordinator; no private paths or build-server
details are copied here.

| Review group | Draft 3 response |
|---|---|
| 1: Core Lightning nightly claim | Benchmark now says a scheduled build/clean-version check in the reproducible environment, not a two-build comparison |
| 2: independent signers | Manager plus an independent reproducing builder required before the first official M6 publication; count distinct approved principals; RE-K must name them |
| 3: signature retries | Verify the same checksum data and trusted fingerprints; allow timestamp-different valid signatures in the draft; freeze the bundle before immutable publication |
| 4: lifecycle gaps | Retired versions, abandoned/withdrawn states, signed withdrawal/advisory process, version-scoped single-writer lock, tag-object/commit rechecks and owner protection gates |
| 5: concrete environment | Digest-pinned OCI image, dated package snapshot with full closure, source-pinned static OpenSSL/curl/TLS dependencies, dynamic glibc ceiling and CA/provider policy; Guix long-term target |
| 6: build findings | RE3a acquisition, RE3b environment and RE3c production CMake profile; explicit module/Valgrind settings, optimization checks, prefix maps, installation and runtime compatibility |
| 7: missing verification scope | SPDX SBOM, REUSE annotations, ELF FORTIFY/separate-code/CET checks, GnuPG status/fingerprint handling, R13-R18 including oldest-runtime and monitoring cases |
| 8: work-package size and ownership | Split RE3; add RE-S security policy and RE-K owner-led signing policy/ceremony; require dependency reporting; hold signing/publication work for the owner decisions |
| 9: security policy and plan | Explicitly expand the existing SECURITY.md in RE-S; tie the work to M6 in PLAN.md and its handbook rendering |

## Verification and qualifications

Source inspection confirmed secp's module defaults, AUTO Valgrind detection,
Release assertion/optimization handling and libsodium's CMake flag override.
Noise explicitly calls ECDH and uses OpenSSL HMAC/ChaCha20-Poly1305, not only
SHA-256. Preserve these dependencies; a name containing "adaptor" is not enough
to decide whether a module can be disabled.

The reviewer's binary results (matching `gz-chain`, different wallet binaries,
BPPP path, ELF properties and GLIBC_2.38) are reviewer evidence, not a second
build performed by this contributor. They need reproducible Actions/independent
builder probes in the profile package. GLIBC_2.38 describes the tested binary,
not an intrinsic requirement of every possible source build.

The empty-build-type risk needs a qualified statement: pinned secp's
single-config CMake chooses RelWithDebInfo when unspecified. An empty effective
flag set could still suppress libsodium's defaults; test the configuration and
effective command, rather than assert that omission always yields `-O0`.

GitHub documentation confirms published immutable assets cannot be appended
or replaced. Collect the initial signature quorum in the draft; store later
attestations separately. Withdrawal updates authenticated advisory/status
information and release notes, not the locked payload. Do not silently extend
the byte-immutability exception beyond pre-publication signatures.

Read-only repository checks confirmed private vulnerability reporting enabled,
immutable releases disabled, no rulesets, and 12 required checks. Required PR
approvals are not enforced by branch protection, so the team's review process
remains an additional gate. No repository setting, signer, key or token was
created or changed by this revision.

## Open owner decisions

- Name the release manager and independent signer(s), roles and full fingerprints.
- Approve custody, expiry/renewal, backups and revocation-certificate custodians.
  Hardware signing subkeys are a proposal; no purchase or key generation is implied.
- Authorize `v*` tag protection and immutable releases before official tags.

The runtime floor, exact package/image lock and manifest limits are technical
values the relevant reviewed work packages must settle before implementation
can claim completeness. SECURITY.md response targets must match maintainers'
actual capacity; the report does not invent service guarantees.
