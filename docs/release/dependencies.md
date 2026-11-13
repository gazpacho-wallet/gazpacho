# Release input inventory

Observed on Gazpacho `ae023f3818b2c5ebb9ca82d0d0a49c23c205ca8c`,
2026-11-13. This is an inventory for review, **not a release lockfile**.
Reconcile it with the actual release link map and input closure in RE3.
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
| C library and dynamic loader | Supplied by the build/runtime system | Release link map, not yet generated | Define minimum runtime and verify symbol versions; record both build and runtime requirements |

The API branch (PR 26) adds a vendored llhttp parser. At this snapshot it is
not on main. Include its branch-local version, checksums, notices and parser
configuration once that code becomes part of the candidate. Do not fabricate
a pin from the PR title or treat this inventory as frozen while engines land.

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

RE3 must produce an input manifest with each input's role, exact version or
commit, source location, digest, verification method, redistribution status,
licence-file references and source availability. Capture transitive entries,
not just the rows above. Unknown licence metadata stays unresolved; do not
assign the project's MIT licence to another author's files.

Generated evidence lists sanitized compiler/package identities, target,
configuration, source commit and recipe digest. It must not capture the full
process environment or the builder's directory tree. Source paths use a
documented normalization scheme and are exercised in the reproducibility test.

Pinning fixes which bytes are used; it does not prove those bytes safe or
maintained. Monitor advisories, authenticate upstream releases where possible,
review updates and regenerate the lock deliberately. Dependabot covers only
its supported manifests; custom CMake pins need a named maintenance procedure.
