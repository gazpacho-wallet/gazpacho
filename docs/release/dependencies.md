# Release input inventory

Updated through Gazpacho `5c68e50b75ecda04ebabf80eb55e63fd48d3be7a`,
2026-11-14. This is an inventory for review, **not a release lockfile**.
Reconcile it with the actual release link map and input closure in RE3a-RE3c.
Branches may add inputs before merge; snapshot them again for each candidate.

## Project and fetched runtime code

| Input | Observed identity / verification | Source of truth | Remaining release work |
|---|---|---|---|
| Imported SuperScalar files | Commit `e65739500bbbbb53bc142ad68add40509238264c`; per-file SHA-256 inventory and unchanged-import CI | `core/superscalar/IMPORT.md`, `tools/check-import.sh` | Re-import is the core team's S12, not a dependency upgrade hidden in release work; verify included source/notices at the candidate |
| secp256k1-zkp | Git commit `6152622613fdf1c5af6f31f74c427c4e9ee120ce` | Root `CMakeLists.txt` | Record verified source-object/archive identity and availability, enabled modules and compiler flags; run imported pin consistency check |
| libsodium | 1.0.22; SHA-256 `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`; upstream minisign verification helper | `ports/storage/crypto/CMakeLists.txt`, `tools/verify-libsodium.sh` | Record verified distribution tarball, selected production flags and actual redistributed licence files; do not copy sanitizer/LTO settings into production |
| utf8proc | 2.12.0 release asset; SHA-256 `a393fbef160835fb315bc3e91ba8d86f7a73a7cec9e6198b6c60b848b498bfeb` | `ports/storage/crypto/CMakeLists.txt` | Preserve release-asset bytes, Unicode-related notices and actual dependency closure |
| OpenSSL libcrypto | System discovery via `find_package(OpenSSL REQUIRED)` | Root, wallet and chain CMake files | Production package/source identity, ABI/runtime floor and transitive dependencies are not locked |
| libcurl / HTTPS dependencies | Optional system discovery in the developer build | `ports/chain/CMakeLists.txt` | Required in release profile; lock TLS backend, transitive dependencies, CA trust handling and runtime requirements |
| llhttp | Vendored v9.4.3; commit `0e815792b167a9bd8ace259b95b7da953776c288`; archive SHA-256 `1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39`; per-file hashes | `ports/api/third_party/llhttp/IMPORT.md`, `SHA256SUMS`, `tools/check-llhttp.sh` | Now on main through PR 26; preserve exact vendored bytes/notices and per-file hashes. Retain acquired bytes rather than rely on regenerated GitHub tag archives |
| C library and dynamic loader | Supplied by the build/runtime system | Release link map, not yet generated | Define minimum runtime and verify symbol versions; record both build and runtime requirements |

The original inventory preceded PR 26; its merge is included above. Resnapshot
the closure as engines land. The production design calls for OpenSSL/curl from
pinned source and static linkage, plus a documented dynamic-glibc ceiling and
CA policy. Record rebuild responsibility for advisories in statically linked
components. OpenSSL is used for HMAC and ChaCha20-Poly1305 in the transport,
as well as hashing; removing it is not a release-engineering change.

## Findings to resolve in RE3a-RE4

The independent review reports two builds on a separate server: `gz-chain`
matched byte-for-byte; `gazpacho` and `gz-wallet-keys` differed, with an embedded
BPPP module path. It also reports distro-default hardening and a glibc 2.38
symbol requirement in the tested `gazpacho`. These binary results have not
been independently repeated by the release contributor; preserve that evidence
boundary. Reproduce them on Actions or an independently controlled builder.

Source inspection confirms the pinned secp module defaults include unused
experimental modules and `SECP256K1_VALGRIND=AUTO` probes the host. Noise needs
ECDH, and MuSig adaptor operations are not the optional ECDSA adaptor module.
Map imports/call sites before disabling modules and obtain crypto review.
RE3a adds retained, SHA-256-verified secp source archive acquisition without
upgrading the approved commit; RE3c supplies the explicit production options.

libsodium receives parent CMake flags plus `-g`. A genuinely empty effective
build-type flag set risks unoptimized code when that override suppresses its
own defaults. However, pinned secp's single-config CMake sets an unspecified
build type to RelWithDebInfo: do not state that omitting the top-level option
always produces `-O0`. Test single/multi-config generators, empty/unknown types
and the effective compiler command. Production requires an explicit reviewed
Release profile and optimization checks. Diagnostic builds remain separate.

The production profile must also introduce installation rules, prefix maps,
explicit application hardening and checked oldest-runtime compatibility.
Compiler/default changes affect crypto behavior and need the owning reviews.

## Build, documentation and test inputs

| Input | Observed state | Remaining work |
|---|---|---|
| GCC, Clang, CMake, binutils, Make and system development packages | Existing CI installs from Ubuntu package repositories; runner label alone is not an immutable build closure | Lock the dedicated release environment and all acquired packages; leave the development matrix separate |
| GitHub Actions | Existing checkout/cache actions pinned to full commits | Keep pins and explicit minimum permissions for new release actions; inventory action/runtime inputs |
| Markdown renderer | `markdown==3.10.3` and two distribution hashes | `tools/handbook-requirements.txt`; verify whether generation is needed for a candidate or committed HTML is packaged |
| OpenSSL for MemorySanitizer | 3.0.22 tarball SHA-256 `67ebca7e50d17383028045486653492195b83db95f8558709701bb47b5c1ef81` | Diagnostic-only build in CI, not the production dependency pin |
| Valgrind, Python, Python cryptography and sanitizer runtimes | System packages in CI | Record test environment when reporting evidence; production package contents use an explicit allowlist |
| Official wallet vector sources | bitcoin/bips `b34d9f751791d4feb22feff4f2ed00bcac83961b`; python-mnemonic `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`; wallet-tx fetch also verifies file hashes | Keep regeneration inputs distinct from runtime dependencies; record checked-in generated vectors and licence obligations |
| Future signing/package tooling | Not selected or implemented by this PR | Pin tooling in its implementation PR; use standard GnuPG/SHA-256; keep private keys outside PR execution |

## Candidate lock and licence inventory

RE3a must produce an input manifest with each input's role, exact version or
commit, source location, digest, verification method, redistribution status,
licence-file references and source availability. Capture transitive entries,
not just the rows above. RE3b locks the actual environment and RE5 derives an
SPDX SBOM reconciled against the linked/packaged output. REUSE annotations cover
unchanged imports/vendor/generated files without inserting headers into them.
Unknown licence metadata stays unresolved; do not
assign the project's MIT licence to another author's files.

Generated evidence lists sanitized compiler/package identities, target,
configuration, source commit and recipe digest. It must not capture the full
process environment or the builder's directory tree. Source paths use a
documented normalization scheme and are exercised in the reproducibility test.

Pinning fixes which bytes are used; it does not prove those bytes safe or
maintained. Monitor advisories, authenticate upstream releases where possible,
review updates and regenerate the lock deliberately. Dependabot covers only
its supported manifests; custom CMake pins need the required retained
scheduled pin/advisory report and a candidate freshness gate.
