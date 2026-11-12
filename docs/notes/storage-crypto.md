# Storage encryption: the Slice 1 code

What `ports/storage/crypto/` builds from `spec/storage-encryption.md` draft 3, what it relies on, how it is tested, and the choices made where the specification is silent. Written 2026-11-12 with the first pull request of stream S6.

## What is built

| Spec | Code | Notes |
|---|---|---|
| 4.2 parameter rule, floor and ceiling | `gz_sc_params_check` (`sc_core.c`) | Checked before every derivation, for the key file, every export slot, and again inside the helper. Defaults: key file 256 MiB / 3, export 1 GiB / 4 |
| 4.4 subkeys, 5.2 seal with hedged nonces | `sc_derive`, `sc_keys`, `sc_seal`, `sc_unseal` | libsodium's HKDF-SHA256, HMAC-SHA256 and XChaCha20-Poly1305; every sealing key has its nonce key |
| 4.5 to 4.7 key file, commitment, change, upgrade | `sc_keyfile.c`; `gz_sc_rewrap` | The commitment is compared in constant time before the wrap is opened |
| 8.3, 8.4 Argon2id in a helper process | `sc_kdf.c` | `gz_sc_kdf_helper` starts `program --gz-kdf-helper` with a socket on its standard input; `gz_sc_helper_main` is the hidden mode |
| 5.3 to 5.5 the journal's seal and open interface | `gz_sc_header_seal/_clear/_open/_recover`, `gz_sc_frame_seal/_open` (`sc_journal.c`) | The journal (not on GitHub yet) owns the file, scan and torn-tail search and calls these per entry |
| 10.2 mark file, 10.1 guard file | `gz_sc_mark_*`, `gz_sc_guard_*` | |
| 6.3 start rule, steps 0 to 2 and 4 | `gz_sc_start_rule`, `gz_sc_check_start`, step 0 in `gz_sc_unlock` | The journal passes a view (highest incarnation, its sync marks, newest guard counter) |
| 7 crash safety | `sc_files.c` | Every operating-system call through a table (`gz_sc_os_t`) |
| 7.4 creation order | `gz_sc_setup` | Key file, guard, mark file, journal header |
| 9.2, 9.3 words, recovery from the words | `gz_sc_words`, `gz_sc_recover_keyfile` | |
| 11 exports, profiles 1 and 2 | `sc_export.c` | The words are in profile 1 only, and only when chosen |
| 12.2 socket token folder | `gz_sc_token_dir`, `gz_sc_token_dir_make` | Linux and macOS paths |
| 12.3 attempts file, mode 1 | `gz_sc_attempts_*` | With `local-api.md` D15's delays |
| 4.1, 14 passphrase rules and the generated six words | `sc_pass.c`, `sc_wordlist.c` | NFC by utf8proc |

Not built (1.0.0, or another stream's): the watcher, KB, the OS key store and store record, the bundle, the penalty file and the watcher's log (their vectors E12, E13p and E14's keyed mode are reproduced from the same primitives in the tests); rekey (4.8); the log file (12.1); Windows (the code is POSIX and errors at compile time elsewhere); the journal itself; the local API's canonical JSON (E15's digest is checked from the canonical bytes).

## Memory

Every storage-layer secret (the passphrase and its NFC copy, PK, MSK, every subkey and HKDF intermediate, the seed copy, the words' entropy) is in `sodium_malloc` memory and freed with `sodium_free`, which wipes it. Long-lived keys (the vault's MSK and seed, key pairs) are `sodium_mprotect_noaccess` between uses. The helper locks its pages with `mlockall(MCL_CURRENT | MCL_FUTURE)` only when `RLIMIT_MEMLOCK` (raised to its hard limit) covers the derivation plus 64 MiB: with `MCL_FUTURE` and a smaller limit, Argon2's allocation would fail, and 8.3 says a refused lock must not stop the derivation. It reports whether it locked (`mem_locked`), for 14's "memory not locked". The storage layer is single-threaded: the `mprotect` toggles are not safe across threads.

## Dependencies and how they were checked

- **libsodium 1.0.22**, release tarball `libsodium-1.0.22.tar.gz`, SHA-256 `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`. Its minisign signature (`.minisig`, prehashed Ed25519) was verified on the build server on 2026-11-12 against the key on doc.libsodium.org, `RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3` (key id `E7620F1842B4E81F`); trusted comment `timestamp:1775774745 file:libsodium-1.0.22.tar.gz hashed`. `tools/verify-libsodium.sh` repeats the check. The GnuPG signature (`.sig`, key id `62F25B592B6F76DA`) was downloaded but not checked: the documented key is the minisign one. Built static, `--disable-asm`, with the job's compiler and flags. `gz_sc_init` refuses to start unless both the header and the library say 1.0.22.
- **utf8proc 2.12.0** (MIT), GitHub tag tarball, SHA-256 `f564011d38b2888d583d510b08e69ffa15aa117155db1b9b49ef1dfe1fa25111`, for NFC and case folding (spec open point 2: "vendor utf8proc, or another route"; fetched pinned rather than copied into the tree).
- **The EFF large word list** (7,776 words), https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt, SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, licence CC BY 3.0 US (attribution in `sc_wordlist.c`). Not the BIP 39 list. `tools/gen-eff-wordlist.py` generates `sc_wordlist.c` and refuses any other file; the tests check a digest of the words.

## Tests

| CTest | What |
|---|---|
| `storage_vectors` | Section E of `tools/spec-vectors.py`, byte for byte with libsodium: E0 (RFC 8439 2.8.2, XChaCha 2.2.1 and A.3.1, RFC 5869 A.1), E1 to E11 through the product code, E12, E13, E13p and E14 (keyed) from the same primitives, E15's digest; every intermediate key the spec prints; E4, E7 and E11's refusals |
| `storage_vector_e2r` | E2r, Argon2id at 256 MiB |
| `storage_formats` | Tests 2 to 5, 7, 15: every byte of every format altered in turn; the parameter floor and ceilings (including half of physical memory, simulated); the passphrase rules; the key commitment (a wrap that opens under B with a commitment naming A is refused for both); hedging with a repeating random source; a failing random source writes nothing; the attempts delays; the token folder's rules; the start rule's every branch |
| `storage_files` | Set-up and unlock through the real helper; the helper crashing, answering short, exiting 1 or answering nonsense is "could not be checked", never "wrong"; the helper refuses parameters below its own floor; the start rule from the files (anchor, guard, missing or damaged files); 6.3 step 0 with the journal and guard deleted (a new journal and epoch path, the mark file restarted); change, upgrade, words, recovery from the words; test 12's scan of every file for the passphrases, PK, MSK, entropy and seed; test 10: a crash at every operating-system call of set-up, passphrase change, the mark append and the guard replace, with unsynced writes and unsynced renames lost |
| `storage_release_refuses_test_params` | Test 29: the release library refuses E2's key file before deriving |
| `storage_release_has_no_test_entry`, `storage_core_has_no_sodium` | No `gz_sc_test_*` in the release library; no libsodium symbol in `gazpacho_core` (spec 13) |
| `storage_fuzz_sc_*` | The four fuzz targets with the plain driver (libFuzzer in CI) |
| `storage_ctime` | Constant time under valgrind (CI's valgrind job) |

### Results on the build server, 2026-11-12

- **Vectors**: every section E value reproduced byte for byte with libsodium 1.0.22, E2r (256 MiB) included. No mismatch with `tools/spec-vectors.py`.
- gcc Release and gcc ASan+UBSan: all storage tests pass. valgrind memcheck (RelWithDebInfo, `tools/valgrind-tests.py --include '^storage'`): all eight compiled tests clean, E2r excluded. `storage_ctime` passes under memcheck with the one suppression. clang, MSan and libFuzzer run in CI (the build server has no clang).
- Crash test: set-up has 37 operating-system calls; a crash at each left either no wallet (9) or a wallet that starts as a restore (27) or normally (the last call); passphrase change has 13 calls and after each crash exactly one of the two passphrases opens.

### Mutation (`tools/mutate-storage.py`, `tests/mutants.txt`)

95 mutants, among them spec 16's break-checks (offset dropped from the associated data, each hedging input dropped, the key commitment check dropped, step 0 as a normal start, the mark append dropped, the fsyncs and the folder sync dropped): **92 killed, 3 survived**. A first run left 19 survivors; tests were added for 16 of them (forged entries with valid tags but forbidden kinds, lengths or self-offsets; a header for another vault under the same MSK; the slot's key commitment; the 40-byte chunk floor; a mode 2 attempts file with a plain checksum; the generator's rejection sampling; a torn mark tail cut before the append; a power cut right after an append; keys dropped when the journal is another wallet's; MSK compared in full; the format byte) and one redundant clamp was removed from the attempts delay. The three left:

| Survivor | Triage |
|---|---|
| `ceiling_memlimit` (drop the `crypto_pwhash_memlimit_max()` bound) | Equivalent on 64-bit builds: libsodium's limit is 4 TiB there, above the fixed 4 GiB ceiling. It binds on 32-bit builds, which no CI job has (`ci.md`, "What CI does not do") |
| `version_pin` (drop the run-time version check) | Needs a second libsodium to tell; the build-time check of the header stays. Accepted |
| `helper_no_dumps` (the helper keeps core dumps and dumpability) | Not observable by the tests: needs a test that reads the helper's `/proc/<pid>/status` or forces a dump while it runs (spec test 12's dump part). Accepted for now, listed as a gap |

## Choices where the specification is silent

Each is a choice made here, open to the next review of the specification.

1. **The helper's page lock** (8.4). The specification says to raise `RLIMIT_MEMLOCK` and call `mlockall(MCL_CURRENT | MCL_FUTURE)`. With the usual limit of a few MiB, `MCL_FUTURE` makes Argon2's later 256 MiB allocation fail, which would turn "memory not locked" into "could not be checked". The helper locks only when the limit (raised to the hard limit) covers the derivation plus 64 MiB, and otherwise runs unlocked and says so. On the build server the limit is small: `mem_locked` is 0 there. **Specification gap**: 8.4 should say this.
2. **The helper's request format** is not specified: here `"GZKDFRQ1"`, t, m, salt, passphrase length, passphrase; the answer is a status byte (0 ok, 1 parameters refused, 2 failed), a locked byte and PK. The helper checks the parameter rule itself (release floor). A helper that exits non-zero, answers short or answers an unknown status is "could not be checked".
3. **Physical memory unknown** (4.2's third ceiling): the other two ceilings still apply; the device bound is skipped rather than refusing every file.
4. **A new wrap on a small device** (4.7, 11 "bounded by the exporting device's ceiling"): the memory is halved until the device allows it, never below the stored value or the floor; passes are never lowered.
5. **The attempts delays** (`local-api.md` 4.3, D15): one attempt a second whatever the result; after the fifth wrong one in a row the wait is 2, 4, 8 … seconds, at most 900. The strictest state (12.3) is `blocked_until = now + 900`, wrong count 0, and the counter read from the damaged file when its length is right, so it does not fall. A mode 2 file, which Slice 1 cannot check without KB, is read as damaged.
6. **The passphrase rules** (4.1). "The wallet's name with or without digits": both are case-folded (utf8proc) and compared with every ASCII digit and space removed, so "Holiday Fund 2026" against a wallet named "Holiday Fund" is refused and "Holiday Fund 2026!" is not. "Three or more of the wallet's own 24 words in order": the case-folded passphrase is split into runs of ASCII letters, and three of them matching words of the mnemonic at increasing positions (not necessarily adjacent) refuse it. Blocklist entries are compared whole after case folding.
7. **No bundled blocklist** (open point 3 is undecided): the mechanism is built and tested with a test list; `gz_sc_pass_check` ships with an empty list. **Open**: which list and licence.
8. **Export bodies**: flag bits other than bit 0 are refused; profile 2 with bit 0 is refused when built and when opened. The opener allocates up to the file's size; the caller bounds the file size (the specification sets no export size limit; **gap**).
9. **The mark file** accepts equal consecutive points (a repeated append after a crash); only a decrease is damage. **The start rule** applies step 1 (possibly old) before step 2 (behind), so a missing guard with a mark file naming another journal reports "possibly old".
10. **Step 0** (6.3) writes a new journal header and mark file and leaves `guard.gzg` as it is; the restore's first batch (the core's `guard` record) rewrites it through `gz_sc_guard_write`.
11. **The socket token folder** (12.2): the data folder path is hashed as given (it must be absolute; symbolic links in it are not resolved); `XDG_RUNTIME_DIR` that is empty or relative counts as unset.
12. **libsodium is pinned exactly**: `gz_sc_init` refuses any version but 1.0.22 (the specification says 1.0.21 or later; the pin makes the build reproducible and the vectors' confirmation exact).
13. **Key commitment test** (16 test 5): built by giving a key file the commitment of passphrase A over a wrap sealed for passphrase B, which is what the commitment check has to stop; a true multi-key Poly1305 collision (Len, Grubbs, Ristenpart) is not constructed.
14. **E12, E13p, E14 (keyed)**: their files are 1.0.0's; the tests reproduce them from the same primitives and framing, so their bytes are confirmed with libsodium, but no product code reads them yet. **E15**: only the digest of the given canonical bytes is checked; the canonical JSON is the local API's (stream S9).
15. **POSIX only**: Linux is built and tested; the macOS branches (`getentropy`, `F_FULLFSYNC`, `confstr(_CS_DARWIN_USER_TEMP_DIR)`) are written but never compiled in CI; Windows (8.5) is not written.
16. **Core dumps of the main process** (8.3's `setrlimit(RLIMIT_CORE, 0)`, `PR_SET_DUMPABLE`, `MADV_DONTDUMP`) belong to the program's start, which does not exist yet (stream S11); the helper does its own.
