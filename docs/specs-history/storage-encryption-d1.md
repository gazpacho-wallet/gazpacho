# Storage encryption

Specification draft 1, 2026-11-12. Not reviewed. Items marked **(open)** are listed in section 18; values marked **proposed** are first choices the owner has not confirmed.

**Why it exists.** The owner decided on 2026-11-12 that every file the wallet keeps is encrypted from the start, on test networks too, and that the person signs in by typing the **wallet passphrase**, which unlocks the storage key, as in desktop wallets such as Sparrow (owner decisions 13 and 14, recorded in `spec/local-api.md` draft 2). The bar is "elite cryptography quality". This document is the cryptography: how a passphrase becomes a key, how the journal and the other files are sealed, what a thief with a copy of the files learns, and what cannot be defended without state kept elsewhere.

**What it changes elsewhere** (each to be folded in by that document's writer; nothing here edits them):

| Document | Change |
|---|---|
| `spec/journal.md` | Section 2.1's header and section 3's 8-byte checksum are replaced by sections 5.3 and 5.4 here: an authenticated header and an XChaCha20-Poly1305 tag per entry. Entry lengths: minimum 61, exactly 65 for kinds 1 and 3, maximum 8,388,665 (section 7 there). The order rules, the sync mark, the torn-tail rule, group sync and the confirmation rule are unchanged (section 7 here). Section 8.3's guard file is sealed, gains a high-water mark, and is also replaced before a batch with an `exposure` record is confirmed (sections 6.2, 10). Section 10's "key file" is the key file of section 4.5. Open point 1 closes when this is accepted |
| `spec/local-api.md` draft 2 | Its three operations (set up, unlock, drop) are section 8.2; the attempt-limit file it asks for is section 12.3; the passphrase rules are 4.1; a locked wallet keeps watching and leaving alone (8.7), so its 4.7 table changes; the requirements of section 8.6 |
| `spec/exit.md` (being written) | Defines the records of the watch-and-exit bundle, items B1 to B9 of 8.7.2, the fee ladder, and whether a wallet with payments in flight may lock |
| `docs/THREAT-MODEL.md` section 2.7 | "Stolen, locked": stopped by the encryption of this document, limited by the passphrase's strength (section 3.3); the rollback limits of section 6 |
| `docs/notes/wallet-keys.md` section 8 | The plain-text phrase file of `gz-wallet-keys` is a development tool only; the wallet's words live in the key file (section 9) |

## Contents

1. Decisions in one table
2. Sources
3. What is encrypted, and what a copy of the files reveals
4. Keys: the passphrase, Argon2id, the storage key, subkeys, the key file
5. The journal
6. Rollback: what can be detected and what cannot
7. Crash safety
8. Locked and unlocked; keys in memory
9. The seed and the 24 words
10. The guard file
11. Exports and the host's copy
12. Other files
13. The library
14. What the interface says
15. Test vectors (section E of `tools/spec-vectors.py`)
16. Tests
17. Review checklist
18. Open points

## 1. Decisions in one table

| # | Decision | Why, in one line | Section |
|---|---|---|---|
| E-D1 | **Argon2id** (RFC 9106, version 0x13), 1 lane, **256 MiB, 3 passes** by default; floor 64 MiB and 3 passes; salt 16 random bytes | The RFC's recommended family; four times the memory of its second recommended setting; libsodium's "moderate" setting; p = 1 because libsodium has one lane | 4.2 |
| E-D2 | A random 32-byte **storage key** (MSK), wrapped under the passphrase key | Passphrase change and parameter upgrade rewrite 331 bytes, never the journal | 4.1, 4.7 |
| E-D3 | **No verifier.** The wrap's authentication tag is the passphrase check | Checking a guess costs a full Argon2id, so nothing cheaper is stored | 4.6 |
| E-D4 | **XChaCha20-Poly1305** (RFC 8439 with draft-irtf-cfrg-xchacha-03) for every sealed object | 192-bit nonces can be random; constant time in software on every platform; libsodium's recommended AEAD | 5.1 |
| E-D5 | **Hedged nonces**: nonce = HMAC(nonce key, 32 random bytes, associated data, plaintext), first 24 bytes, stored with the ciphertext | Random when the random source works; if it repeats, different contents still get different nonces | 5.2 |
| E-D6 | Every journal entry's associated data binds **file id, offset, kind, incarnation, sequence** | An entry cannot be moved, replayed or spliced from another file without failing | 5.4 |
| E-D7 | The storage key is also wrapped in the journal header **under a key from the seed** | The 24 words alone reopen the journal if the key file is lost or the passphrase forgotten | 5.3 |
| E-D8 | The guard file carries the journal's **high-water mark**, updated before every batch with a `guard` or `exposure` record is confirmed | Detects a journal rolled back or cut while the guard was not, at every point that matters for C7 and key reuse | 6 |
| E-D9 | The **24 words** are sealed under a key from the passphrase, not from the storage key | Revealing them needs the passphrase typed for that purpose; a memory dump of the running program does not hold them | 9 |
| E-D10 | Exports: profile 1 (the person's) opens with the passphrase or the words; profile 2 (the host's copy) **only with the words** | The host is an adversary (`THREAT-MODEL.md` 2.1) and must never hold anything a passphrase guess opens | 11 |
| E-D11 | **libsodium** (ISC licence), version 1.0.18 or later, for all storage cryptography | One small, audited, widely packaged library with Argon2id, XChaCha20-Poly1305, guarded memory and wiping | 13 |
| E-D13 | **A locked wallet keeps watching and leaves alone in time**, from a separately sealed watch-and-exit bundle of already-signed transactions under a key usable without the passphrase | A restart must not stop the protection the design rests on; the bundle can leak privacy but cannot steal | 8.7 |
| E-D12 | Passphrase: NFC, at least **15 characters**, a blocklist, no composition rules; "suggest one" offers six random words | NIST SP 800-63B-4's rules; the offline attack is what matters | 4.1, 14 |

## 2. Sources

Checked 2026-11-12 against the documents themselves.

| Short name | Document | Relied on for |
|---|---|---|
| RFC 9106 | Biryukov, Dinu, Khovratovich, Josefsson, "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106, https://www.rfc-editor.org/rfc/rfc9106 | The algorithm (sections 3.1 to 3.5); "16 bytes is RECOMMENDED for password hashing" (3.1); section 4's FIRST RECOMMENDED (Argon2id, t = 1, p = 4, 2 GiB, 128-bit salt, 256-bit tag) and SECOND RECOMMENDED (t = 3, p = 4, 64 MiB) settings; the Argon2id vector of 5.3 |
| RFC 8439 | Nir, Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, https://www.rfc-editor.org/rfc/rfc8439 | The AEAD construction (2.8) and its vector (2.8.2) |
| XChaCha | Arciszewski, "XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305", draft-irtf-cfrg-xchacha-03, https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03 | HChaCha20 (2.2) and its vector (2.2.1); the AEAD (2.3) and its vector (A.3.1); random 192-bit nonces: a 2^-32 collision chance after about 2^80 messages under one key |
| RFC 5869 | Krawczyk, Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, https://www.rfc-editor.org/rfc/rfc5869 | Subkey derivation; the vector of A.1 |
| RFC 7914 | Percival, Josefsson, "The scrypt Password-Based Key Derivation Function", RFC 7914, https://www.rfc-editor.org/rfc/rfc7914 | The alternative considered (4.2) |
| RFC 8452 | Gueron, Langley, Lindell, "AES-GCM-SIV", RFC 8452, https://www.rfc-editor.org/rfc/rfc8452 | The nonce-misuse-resistant alternative considered (5.1) |
| SP 800-38D | NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: GCM and GMAC", section 8.3, https://csrc.nist.gov/pubs/sp/800/38/d/final | With random 96-bit IVs, at most 2^32 invocations per key; the catastrophic effect of an IV repeated under GCM (considered in 5.1) |
| SP 800-63B-4 | NIST SP 800-63B-4, "Digital Identity Guidelines: Authentication and Authenticator Management", section 3.1.1 (password verifiers), https://pages.nist.gov/800-63-4/sp800-63b.html | Passwords used as a single factor: "a minimum of 15 characters"; at least 64 allowed; each Unicode code point counts as one character; NFC normalisation before hashing; no composition rules; a blocklist checked against the whole password |
| SP 800-132 | NIST SP 800-132, "Recommendation for Password-Based Key Derivation", section 5.1, https://csrc.nist.gov/pubs/sp/800/132/final | The random part of a salt at least 128 bits |
| UAX 15 | Unicode Standard Annex 15, "Unicode Normalization Forms", https://www.unicode.org/reports/tr15/ | NFC |
| libsodium pwhash | libsodium documentation, "Password hashing", https://doc.libsodium.org/password_hashing/default_phf | Argon2id the default since 1.0.15; `crypto_pwhash_SALTBYTES`; the presets (interactive 64 MiB; moderate 256 MiB, "about 0.7 seconds" on a 2.8 GHz Core i7; sensitive 1 GiB, about 3.5 s); "save the actual parameters" rather than rely on presets; the tuning procedure (fix memory, start at 3 passes); a 5-second pause acceptable for a desktop program entered once per session |
| libsodium XChaCha | libsodium documentation, "XChaCha20-Poly1305", https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction | Since 1.0.12; random nonces safe ("the probability of a collision is negligible"); "the recommended AEAD construction" |
| libsodium memory | libsodium documentation, "Secure memory", https://doc.libsodium.org/memory_management | `sodium_memzero`; `sodium_mlock` wraps `mlock()` and `VirtualLock()` and advises the kernel to leave the memory out of core dumps; `sodium_malloc` with guard pages, a canary and locked pages; `sodium_mprotect_noaccess` |
| libsodium HKDF | libsodium documentation, "HKDF", https://doc.libsodium.org/key_derivation/hkdf | `crypto_kdf_hkdf_sha256_*` (in 1.0.19 and later) |
| Audit libsodium | Cryptography Engineering (M. Green) for Private Internet Access, "Libsodium v1.0.12 and v1.0.13 Security Assessment", 2017, https://www.privateinternetaccess.com/blog/libsodium-audit-results/ | Scope included authenticated symmetric encryption and key derivation; no major vulnerabilities; a few low-severity usability issues |
| Audit Monocypher | Cure53, "Pentest-Report Monocypher" (MON-01), 2020, version 3.1.1, https://cure53.de/pentest-report_monocypher.pdf ; Monocypher 4 announcement, https://loup-vaillant.fr/articles/monocypher-4 | The audit predates Monocypher 4, which added Argon2id (13) |
| OpenSSL Argon2 | OpenSSL manual, `EVP_KDF-ARGON2(7)`, https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/ | Argon2id in OpenSSL from 3.2 only (13) |
| Hedged | Rogaway, Shrimpton, "Deterministic Authenticated-Encryption" (SIV), EUROCRYPT 2006; BIP 340's synthetic nonces | A nonce computed from the message and randomness survives a failed random source (5.2) |
| STREAM | Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015 | Chunk index and a final flag in each chunk's associated data stop reordering and truncation of a long sealed stream (11) |
| Padmé | Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019 | Padding that leaks O(log log n) bits of length at most 12 % overhead (open point 6) |
| OS calls | Linux man pages `mlock(2)`, `madvise(2)` (`MADV_DONTDUMP`), `prctl(2)` (`PR_SET_DUMPABLE`), `setrlimit(2)`, `memfd_secret(2)`, `getrandom(2)`; Microsoft documentation for `VirtualLock`, `SetProcessWorkingSetSize`, `CryptProtectMemory`, `BCryptGenRandom`, `MoveFileExW` (`MOVEFILE_WRITE_THROUGH`), `ReplaceFileW`, `FlushFileBuffers`; Apple `fcntl(2)` (`F_FULLFSYNC`) and `CSBackupSetItemExcluded` | Section 8 and section 7 |

Gazpacho documents used: `spec/journal.md` draft 2, `spec/local-api.md` drafts 1 and 2, `spec/safety-rule.md` section 9 (R1 to R7), `spec/signing-round.md` sections 8 and 12.1, `docs/THREAT-MODEL.md`, `docs/DESIGN.md` sections 9 and 13, `docs/OPEN-QUESTIONS.md`, `docs/notes/wallet-keys.md`, and on `main`: `CMakeLists.txt`, `wallet/CMakeLists.txt`, `core/superscalar/src/crypto_aead.c`.

**What is already linked** (`main`, 2026-11-12): libsecp256k1-zkp, fetched at a pinned commit, and the system's OpenSSL libcrypto (`find_package(OpenSSL REQUIRED)`), used for SHA-256, HMAC-SHA512, PBKDF2, RIPEMD-160 and, in the imported `crypto_aead.c`, ChaCha20-Poly1305 with a 96-bit nonce (the BOLT 8 transport). CI builds on Ubuntu 24.04 with OpenSSL 3.0.13; the build server has 3.5.5 (`wallet-keys.md` section 4). Nothing else is vendored. None of it offers Argon2id at CI's version.

## 3. What is encrypted, and what a copy of the files reveals

### 3.1 The files

| File | Holds | Treatment |
|---|---|---|
| `keys.gzk`, the key file | The wrapped storage key, the 24 words, the BIP 39 seed | Sealed (4.5). The only file whose opening needs the passphrase |
| `journal.gzj` | Every record of `journal.md` section 9 and the API's records (its open point 9): terms, signed proposals, the held and exposed sets, funding transactions, host addresses and keys, conditions, activity, settings | Header authenticated, every entry sealed (5) |
| `guard.gzg` | Epochs, key indexes, rounds started (`journal.md` 8.3), the journal's high-water mark | Sealed under a key from the seed (10) |
| `*.gzb`, exports and the host's copies | The journal's entries, the guard, and in profile 1 the words | Sealed (11) |
| `log.gzl`, the program's log | Diagnostic lines; may name hosts, lobbies, amounts | Sealed like the journal (12.1). Nothing is logged to a plain file |
| `watch.gzw`, the watch-and-exit bundle; `watch.gzl`, its log | Already-signed exit, response and fee transactions, outpoints, dates (8.7.2) | Sealed under KB, which the locked program can use (8.7.3). Readable to anyone holding KB: privacy only, no theft (8.7.5) |
| `watch.key` | KB, only on a platform without an OS key store | **Not encrypted** (8.7.3); owner-only |
| `attempts.gza` | Count and time of wrong passphrases (`local-api.md` draft 2, 4.3) | **Not encrypted**: it must be read before unlocking. Holds a count and two times (12.3) |
| `socket.token` | The local socket's bearer token (`local-api.md` draft 2, 4.6) | **Not encrypted**: the command line must read it without the passphrase. New at every unlock, deleted at lock and stop, owner-only permissions; holds no wallet data (12.2) **(open, owner to confirm the exception)** |
| `*.tmp` | Partial copies during an atomic replace | The same format as the file they replace |
| Configuration | None. Anything needed before unlocking (data folder, port) is a command-line option; every setting is a journal record (`local-api.md` 7.5) | No file |

Files the program reads but does not own (a host node's macaroon or rune, `local-api.md` draft 2, 15.5) stay where the person keeps them and are never copied into the data folder.

### 3.2 What a copy of the files reveals

Someone who copies the data folder, once or repeatedly (a stolen disk, a cloud-synchronised folder, an operating-system backup), learns without the passphrase:

| Visible | Why it is visible, and what was done |
|---|---|
| That this is Gazpacho, which network, and which files belong together | The magic, the chain hash and the random `vault_id` and `file_id` are in the clear so a signet file can be refused before the passphrase is asked (journal.md 2.1's rule) and a mismatch named precisely. They are random, so they link files to each other and to nothing else |
| The Argon2id parameters and salt | Needed to derive the key. Public by design (RFC 9106) |
| File sizes; the number, sizes and order of journal entries | Entry lengths are in the clear for the torn-tail scan. A batch's size hints at its records (a proposal is large, a sync mark is always 69 bytes). Padding is **(open)** point 6 |
| The number of program starts and of batches | Incarnation and sequence are in the clear and authenticated (5.4); they could be inferred from sizes and times anyway |
| When the program ran and wrote | File times, and the change history a synchronisation service keeps |
| The number of restores | The guard file grows 8 bytes per epoch |
| How many wrong passphrases were typed recently | `attempts.gza` |

It does **not** learn: any record's contents, any key, the words, amounts, hosts, lobbies, conditions, or history, unless it guesses the passphrase (3.3) or holds the 24 words.

### 3.3 The offline attack

A thief with `keys.gzk` (or a profile 1 export) can test passphrases offline; nothing in the program can slow that. Each guess costs one Argon2id at the stored parameters: at the default, 256 MiB of memory filled and read three times. As an order of magnitude [reasoning, not measured], a high-end graphics card with 24 GB holds about 90 such computations at once and is limited by memory bandwidth to some hundreds to a few thousand guesses per second. The passphrase's strength is therefore what protects a stolen file:

| Passphrase | Guesses (about) | At 1,000 guesses per second |
|---|---|---|
| A common or leaked password | Found in the first million | Minutes. The blocklist refuses these |
| A person-chosen 15-character phrase, typically 30 to 40 bits | 2^30 to 2^40 | Days to decades on one card; quicker on many |
| Six random words from a 7,776-word list (77.5 bits) | 2^77 | Far beyond any attacker |

So: the minimum length and blocklist stop the worst choices; the interface offers a generated passphrase (14); and the host never receives anything a passphrase opens (11).

## 4. Keys

### 4.1 The passphrase

- **Normalisation.** The passphrase is normalised to **NFC** (UAX 15) and encoded as UTF-8 before anything else, as SP 800-63B-4 requires, so the same characters typed on two keyboards give the same key (vector E1). It is never trimmed, case-folded or otherwise changed: spaces count.
- **Where normalisation happens.** The interface applies `String.prototype.normalize("NFC")` before sending (ECMAScript), and the program normalises again with a vendored copy of utf8proc (MIT licence) so the command line and any other client give the same bytes. **(open, point 2: a second, tiny dependency)**
- **Rules, at set-up and change** (SP 800-63B-4, section 3.1.1, password verifiers): at least **15 code points** after NFC; at most 1,024 bytes of UTF-8; no composition rules; refused if, compared whole and case-insensitively, it is on the blocklist (a bundled list of the most common leaked passwords, size **(open)** point 3), is the wallet's name or "gazpacho" with or without digits, or contains three or more of the wallet's own 24 words in order. Typed twice. The reason for a refusal is said.
- **Never stored, never logged** (`local-api.md` draft 2, 4.2). The buffers that held it are wiped as soon as Argon2id has run (8.4).

### 4.2 Passphrase to key: Argon2id

`PK = Argon2id(password = NFC passphrase in UTF-8, salt, t, m, p = 1, T = 32)`, version 0x13, with no secret value K and no associated data X (RFC 9106 3.1), exactly what libsodium's `crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13)` computes with `opslimit = t` and `memlimit = m × 1024`.

| Parameter | Value | Justification |
|---|---|---|
| Function | Argon2id | RFC 9106 section 4 makes Argon2id the choice for both recommended settings: it mixes data-independent addressing in the first half pass (side-channel resistance) with data-dependent addressing (time-memory trade-off resistance). scrypt (RFC 7914) was considered: it is also memory-hard and is in Python's `hashlib`, but one parameter sets both its memory and its time, its memory access depends on the password throughout (no side-channel-resistant phase), RFC 7914 recommends no parameters for this use, and libsodium's own default moved from scrypt to Argon2id in 1.0.15. No dependency argument favours it: libsodium has both |
| Memory m | **262,144 KiB (256 MiB)**, **proposed** | The RFC's procedure is to take as much memory as can be afforded, then the passes. 256 MiB is four times the SECOND RECOMMENDED 64 MiB and is libsodium's "moderate" setting. The FIRST RECOMMENDED 2 GiB is too much for a program that also runs the host service and later phones, and the stored parameters let a device move up later (4.7) |
| Passes t | **3** | The SECOND RECOMMENDED value and libsodium's starting point for tuning ("set opslimit to 3") |
| Lanes p | **1** | libsodium implements one lane. The attacker's cost per guess is memory × passes and does not fall with fewer lanes; only the person's wait grows. About 0.7 s at 256 MiB on a 2.8 GHz Core i7 (libsodium pwhash), within its "5 seconds acceptable once per session" |
| Salt | **16 bytes** from the operating system's random source, new at every wrap | RFC 9106 3.1; SP 800-132 asks for at least 128 random bits |
| Output T | 32 bytes | One 256-bit key; subkeys come from it by HKDF (4.4) |
| Floor (refused below) | t ≥ 3, m ≥ 65,536 KiB | The SECOND RECOMMENDED setting. A key file below it is refused, so a damaged or forged file cannot quietly weaken the key. A test entry point accepts any parameters, for the vectors only (E2) |
| Ceiling (refused above) | t ≤ 16, m ≤ 4,194,304 KiB (4 GiB) | A forged file cannot make unlocking take hours or exhaust memory |

**Calibration at set-up.** The program times one derivation at the default. If it takes more than 3 s, it uses 131,072 KiB; if that still takes more than 3 s, the floor, 65,536 KiB, and the interface says that this device uses the minimum setting. A device that cannot allocate 64 MiB cannot create a wallet. **(open, point 4: phones.)**

### 4.3 The storage key

`MSK`, 32 bytes from the operating system's random source, made once when the wallet is created (or restored, 9.3). Every file key below comes from it or from the seed. Because MSK is random and only wrapped by the passphrase key, changing the passphrase or upgrading the parameters rewrites only the 331-byte key file (4.7); the journal is never re-encrypted for that.

### 4.4 Subkeys

One function derives every key:

```
derive(IKM, label, context) = HKDF-SHA256(salt = "gazpacho/v1/storage", IKM, info = label || 0x00 || context, L = 32)
```

(RFC 5869; the label is ASCII; `||` is concatenation.) Separate labels make the keys independent; the network's chain hash in every context keeps a signet key from ever equalling a mainnet key.

| Key | IKM | Label | Context | Seals |
|---|---|---|---|---|
| KW | PK | `key file wrap` | chain, vault_id | MSK in the key file |
| KD | PK | `words` | chain, vault_id | The 24 words' entropy |
| KS | MSK | `node seed` | chain, vault_id | The BIP 39 seed in the key file |
| KJ | MSK | `journal` | chain, file_id | The journal's header and entries |
| KL | MSK | `log` | chain, file_id of the log | Log entries |
| KR | seed | `journal recovery` | chain, file_id | MSK in the journal header |
| KG | seed | `guard` | chain | The guard file |
| BK | seed | `backup` | chain | The key of every export |
| EK | BK | `export` | chain, export_id | One export's chunks |
| KX | PKx (4.2 over the export's own salt) | `backup wrap` | chain, export_id | BK in a profile 1 export |

"seed" is the 64-byte BIP 39 seed of the wallet's words (empty BIP 39 passphrase). libsodium 1.0.19 and later has `crypto_kdf_hkdf_sha256_*`; on 1.0.18, HKDF is the 25 lines of RFC 5869 over `crypto_auth_hmacsha256`, checked by RFC 5869's vectors (test 1).

### 4.5 The key file `keys.gzk`

331 bytes. Integers big-endian.

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZKEYFIL` |
| 8 | `format` | 1 | 1 |
| 9 | `chain` | 32 | As in the journal header |
| 41 | `vault_id` | 16 | Random, made with the wallet |
| 57 | `kdf` | 1 | 1 = Argon2id version 0x13 |
| 58 | `t` | 4 | Passes |
| 62 | `m` | 4 | Memory in KiB |
| 66 | `p` | 1 | 1 |
| 67 | `salt` | 16 | |
| 83 | wrapped MSK | 24 + 32 + 16 | nonce, ciphertext, tag: `seal(KW, MSK, ad = bytes 0..82)` |
| 155 | words | 24 + 32 + 16 | `seal(KD, entropy, ad = bytes 0..82)` |
| 227 | seed | 24 + 64 + 16 | `seal(KS, seed, ad = bytes 0..56)` |

The seed's associated data stops before the KDF fields so that a passphrase change can copy bytes 227 to 330 unchanged (vector E8).

**Opening** (unlock): check length, magic, format and chain (a wrong chain is refused before the passphrase is asked); check the parameters against the floor and the ceiling; derive PK; open the wrapped MSK with KW; open the seed with KS. A wrong passphrase and a damaged wrap are indistinguishable ("wrong passphrase or damaged key file"); a failure of the seed after the wrap opened is damage. The words are not opened at unlock (9.1).

### 4.6 The passphrase check

No hash of the passphrase, of PK or of MSK is stored. The check **is** the Poly1305 tag of the wrapped MSK: a wrong passphrase gives a different KW and the tag fails, except with probability below 2^-100 for this message length (Poly1305's forgery bound, about 8 × ⌈L / 16⌉ / 2^106 for L bytes). Any test of a guess costs the full Argon2id, so the check adds no shortcut; a stored fast hash would have given one.

When the wallet is already unlocked and someone signs in again (`local-api.md` draft 2, 4.3 step 4) or confirms a fresh sign-in, the program runs the same derivation and opening against the key file on disk, and compares the MSK it gets with the one in memory in constant time (`sodium_memcmp`). That also proves the key file on disk still belongs to the open journal.

Online guessing through the API is limited by `local-api.md`'s attempt rules and by the derivation's own cost: one derivation at a time, never two in parallel, so a flood of guesses cannot exhaust memory.

### 4.7 Upgrade and passphrase change

- **Parameter upgrade.** After a successful unlock, if the stored t or m is below the program's current default and the device's calibration (4.2) allows the default, the program rewraps: a new salt, the default parameters, new nonces, same MSK and same seed bytes. Never automatically downward.
- **Passphrase change** (`local-api.md` draft 2, `POST /api/v1/wallet/passphrase`, 1.0.0, fresh sign-in): the old passphrase opens the words and the wrap; the new one, after the rules of 4.1, gives a new PK under a new salt; the program writes a new key file with the same `vault_id`, MSK, seed bytes and words. The journal is not touched.
- **Both are an atomic replace** (7.3). A crash leaves the old file or the new one, each complete.
- **What a change does not do.** A copy of the old key file made before the change still opens with the old passphrase, and holds the same MSK (vector E8). Changing the passphrase protects only files copied afterwards. If the old passphrase may have leaked together with a copy of the files, the person needs a **new storage key** (4.8), and the interface says so.

### 4.8 A new storage key (1.0.0)

Rekeying makes a new MSK and a new journal. The program writes `journal.gzj.new` (new `file_id`, every entry re-sealed under the new KJ at the same offsets, since sizes are unchanged) and `keys.gzk.new` (new `vault_id`), syncs both, then renames the key file, then the journal, then syncs the folder. On start, a `keys.gzk.new` whose `vault_id` matches the journal header's completes the switch; one that matches nothing is deleted. Old exports keep their own keys (11). **(open, point 5: the exact crash order is to be checked by the fault tests before 1.0.0.)**

## 5. The journal

### 5.1 The AEAD

**XChaCha20-Poly1305**: HChaCha20 makes a subkey from the key and the first 16 nonce bytes, then RFC 8439's ChaCha20-Poly1305 runs with the last 8 (XChaCha 2.3). 32-byte key, 24-byte nonce, 16-byte tag. In libsodium, `crypto_aead_xchacha20poly1305_ietf_encrypt` and `_decrypt`.

| Considered | Against it here |
|---|---|
| AES-256-GCM | 96-bit nonces: random ones are limited to 2^32 invocations per key (SP 800-38D 8.3), and a repeated nonce reveals the authentication key and allows forgeries. Constant time only with AES hardware instructions; a software fallback uses table lookups that leak timing. libsodium offers it only where the hardware has AES-NI |
| AES-256-GCM-SIV (RFC 8452) | Misuse-resistant: a repeated nonce reveals only that two messages are equal. Attractive. But not in libsodium; in OpenSSL only from 3.2, which CI does not have; needs AES hardware for constant time. Hedged nonces (5.2) give the property that matters here with XChaCha20 |
| ChaCha20-Poly1305 with 96-bit nonces (OpenSSL, already linked) | Random 96-bit nonces would be safe at a journal's volume (millions of entries, a collision chance below 10^-16), but leave no margin for counters and a second key per incarnation would be needed. XChaCha's margin costs 16 bytes per entry and nothing else |

ChaCha20 is constant time in plain C on every platform, so the same code is safe on Linux, macOS, Windows and, later, phones without AES instructions.

### 5.2 Nonces

Every sealed object stores its own 24-byte nonce, made by

```
nk    = HMAC-SHA256(K, "gazpacho/v1/nonce key")
nonce = first 24 bytes of HMAC-SHA256(nk, r || u32(len(ad)) || ad || plaintext)
seal(K, plaintext, ad) = nonce || XChaCha20-Poly1305-Encrypt(K, nonce, plaintext, ad)
```

where `r` is 32 fresh bytes from the operating system's random source (`randombytes_buf`: `getrandom` on Linux, `arc4random_buf` on macOS, `RtlGenRandom`/`BCryptGenRandom` on Windows).

- **With a working random source** the nonce is a pseudo-random function of fresh randomness: as good as a random 192-bit nonce (XChaCha: 2^80 messages for a 2^-32 collision chance).
- **If the random source repeats** (a virtual machine resumed twice from one snapshot, a broken generator), two different entries still get different nonces, because the plaintext and the associated data (which holds the offset) are inputs. Only a byte-identical entry at the same offset repeats, and then the ciphertext is identical too, which reveals nothing new. This is the hedging of SIV and of BIP 340's synthetic nonces.
- **Why not counters.** A counter or an offset alone repeats in this journal: after a torn tail is cut, the next start writes a different incarnation entry at the same offset under the same incarnation number (`journal.md` section 5, the last paragraph). Under a counter nonce that would reuse a keystream.
- The cost is one HMAC over each entry, under a microsecond per kilobyte.

A reader never recomputes a nonce; it uses the stored one. Only the writer needs `r`.

### 5.3 The journal header

Replaces `journal.md` 2.1. 185 bytes, written once.

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | `magic` | 8 | ASCII `GZJOURNE` |
| 8 | `format` | 1 | 1 |
| 9 | `chain` | 32 | The network's chain hash, internal order |
| 41 | `vault_id` | 16 | The key file's |
| 57 | `file_id` | 16 | Random, made with this file |
| 73 | recovery | 24 + 32 + 16 | `seal(KR, MSK, ad = bytes 0..72)`: the storage key under a key from the seed |
| 145 | header tag | 24 + 16 | `seal(KJ, empty, ad = bytes 0..144)` |

On start: magic, format and chain are checked before anything is asked (a mainnet build refuses a signet journal, `journal.md` 2.1); then, after unlock, the header tag under KJ. A failure there means the key file and the journal do not belong together: "this journal is not this wallet's", distinct from corruption.

**Why the recovery wrap.** Encryption adds a new way to lose money: a damaged or deleted key file, or a forgotten passphrase, would otherwise make an intact journal, with its held and exposed sets, unreadable. With KR the 24 words alone reopen it (9.3). It weakens nothing: whoever holds the seed can already spend everything.

### 5.4 Entries

Replaces the framing of `journal.md` section 3. Integers big-endian.

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0 | `length` | `u32` | Bytes from `kind` to the end of `tag`: 57 + payload length. At least 61; exactly 65 for kinds 1 and 3; at most 8,388,665 |
| 4 | `kind` | `u8` | 1 incarnation, 2 batch, 3 sync mark |
| 5 | `incarnation` | `u64` | |
| 13 | `sequence` | `u64` | |
| 21 | `nonce` | 24 | 5.2 |
| 45 | ciphertext | `length` − 57 | The payload of `journal.md` 3.1 to 3.3, encrypted |
| 4 + `length` − 16 | `tag` | 16 | |

**Associated data** = `file_id` (16) ‖ `u64` offset of the entry's first byte ‖ bytes 0 to 20 of the entry (`length`, `kind`, `incarnation`, `sequence`).

- **The offset** makes every entry valid only where it was written: moved, replayed or swapped, it fails (vectors E7c, E7e). This makes every entry self-locating, as only the sync mark was before; the mark keeps its `offset` payload and its rule, now redundant.
- **The file id** makes an entry from another journal fail, even one sealed under the same storage key, as after a rekey or an import (E7d). KJ depends on `file_id` too, so the binding is twofold.
- **Kind, incarnation and sequence** are clear so that `journal.md`'s scan and order rules run as written, and authenticated so that changing them fails (E7b).
- The 8-byte SHA-256 check is gone: the tag detects a torn write (a cut entry fails) and tampering, which the checksum could not (`journal.md` 3, "integrity against tampering comes with encryption").

Sizes: an incarnation entry and a sync mark are 69 bytes (37 before); each entry costs 32 bytes more than before.

### 5.5 Reading

`journal.md` section 5 applies with "valid" meaning: the length rules above, a known kind, the tag verifies under KJ with the entry's associated data at its offset, and for a sync mark the decrypted offset equals its own. The torn-tail search looks at each offset p after the damage for a 69-byte candidate with `length` 65 and `kind` 3 and tries to open it at p; a false match needs a Poly1305 forgery. The order rules of `journal.md` 3.4 are checked on the decrypted, authenticated entries. A batch's plaintext must fill its payload exactly, as before.

### 5.6 What is detected, and what is not

| Attack on the journal file | Result |
|---|---|
| Change any byte of an entry | Invalid. Before a valid mark: corruption, refused. After the last mark: cut as a torn tail, like a crash (E7a, E7b) |
| Move, swap or replay an entry | Invalid at the new offset (E7c, E7e) |
| Splice an entry from another journal | Invalid (E7d) |
| Drop an entry from the middle | Every later entry is at a different offset: invalid; corruption if a later mark survives |
| Remove the tail at an entry boundary, or cut inside an entry and remove everything after | A valid, shorter journal, or a torn tail. **Not detectable from the journal alone** (E7g). Section 6 |
| Replace the whole file with an older complete copy | **Not detectable from the journal alone.** Section 6 |
| Replace the header | Fails the header tag, or the recovery wrap names another seed |

## 6. Rollback

### 6.1 The limit

A copy of a journal taken earlier is a perfectly valid journal: every entry authentic, every sync mark in place. Cutting today's journal at an entry boundary gives the same. No cryptography inside the file can tell "older" from "current"; it needs state kept somewhere the attacker did not also roll back. This matters for safety, not only for history: an old journal is a restore that nobody marked as one (`safety-rule.md` R1), so the node would trust a stale key index and stale round records, the case R2 to R5 exist to prevent (`journal.md` 8.2, last paragraph).

### 6.2 The high-water mark

The guard file (`journal.md` 8.3), which already lives outside the journal's backup set and is replaced before any batch with a `key_index` or `round_started` record is confirmed, gains three fields written by the storage layer (section 10): the journal's `file_id`, the current incarnation, and the offset of the sync mark that covers the batch just written.

**Anchored batches.** The storage layer replaces the guard file, with the same core contents and a new high-water mark, before confirming every batch that holds a `guard` record **or an `exposure` record**. The first are the batches whose loss could make a key or a round identifier be used twice; the second are C7's record, whose loss could let a second tree be signed on one funding output (`safety-rule.md` C7). Without the second, an attacker could cut the journal just after a guard batch and remove a later `exposure` record undetected. The cost is one more small file replace per such batch: a few per round, none per payment.

### 6.3 The start rule

After the journal's scan (and any torn-tail cut), and before `gz_node_start`:

1. Open the guard file with KG. If it is absent on a wallet that has started rounds or allocated keys, treat the journal as **possibly old** (step 4).
2. If its `file_id` is not the journal's, or its incarnation is above the journal's highest, or its mark offset is not the offset of a valid sync mark in the journal, or its `counter` is above the newest `guard` record's in the journal: the journal is **behind its guard**. (A legitimate torn-tail cut never trips this: the high-water mark is written only after its mark was synced, so the mark is before any torn tail.)
3. Otherwise the start goes on.
4. Behind, or possibly old: the program does not start the node. It tells the person: "These files are older than this wallet's last saved state. Gazpacho can start them as a restore, with new keys, or stop." Starting as a restore is the restore of `journal.md` 8.2: a restore marker, a new epoch, R2 to R5. Nothing is signed or sent before the person chooses.

Vector E9 shows E7g's cut journal refused by the guard.

### 6.4 What remains

- **The journal and the guard rolled back together** (the whole data folder restored from an operating-system backup, Time Machine, File History, a virtual-machine snapshot, a cloud service's "previous versions") is still not detected. This is `journal.md` 8.2's "a copy of the data folder made by other means" and `THREAT-MODEL.md` 2.7's "copied disk". Encryption does not make it worse, and it is the most likely way a person hits it by accident.
- What is done: the data folder is created inside the per-user, non-roaming application folder (Windows the per-user local application data folder, macOS `~/Library/Application Support`, Linux `$XDG_DATA_HOME`), and on macOS the program marks it excluded from Time Machine (`CSBackupSetItemExcluded`, a property of the folder, not a system setting). Elsewhere the interface tells the person not to restore the folder from a system backup and to use exports instead.
- **Proposed further anchors (open, point 7):** a monotonic counter in the operating system's credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service), which a folder restore does not roll back; a hardware monotonic counter (TPM) later; and a question for `safety-rule.md`: a member could ask its host, at every connection, for the newest round and key index the host has seen from it, and treat "the host knows something newer" as a restore. A lying host can then only force a harmless restore, a denial of service, which is already accepted.

## 7. Crash safety

Encryption is a step inside `journal.md` section 4's step 1, so its order rules hold unchanged.

1. **Append.** The writer seals the entry (nonce, ciphertext, tag) completely in memory, then writes it. A torn write leaves an entry whose tag fails: invalid, exactly as a failed checksum was.
2. **Sync, mark, sync, confirm** as in `journal.md` 4. The mark is sealed the same way. No confirmation is given before the second sync; nothing outward is released before the confirmation. The guard file, now sealed, is replaced before a guard batch is confirmed, as in `journal.md` 8.3.
3. **Atomic replaces** (key file, guard file, attempts file): write `name.tmp` (created exclusively, owner-only from creation), sync it, rename over the name, sync the folder (POSIX). Windows: `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` after `FlushFileBuffers` on the temporary file. macOS: `F_FULLFSYNC` in place of `fsync`.
4. **Creation order.** Creating a wallet: make entropy, seed, MSK, `vault_id`; write and sync `keys.gzk` (atomic); then create the journal (header written to a temporary name, synced, renamed, folder synced, `journal.md` 2.1). A crash after the key file and before the journal: the next unlock finds a key file without a journal and creates the journal. A journal without a key file: refused with "the key file is missing", and the words reopen it (9.3). The words are shown only after both exist (`local-api.md` 12.2: the key file is written before the answer).
5. **Random-source failure** is a storage failure (`gz_runner_storage_failed`). The writer never falls back to a weaker source.
6. **A failed tag on reading is never repaired.** It is either a torn tail (cut, as before) or corruption (refused), by the sync-mark rule.
7. **No retry of a failed seal or sync**, as `journal.md` 4 says for syncs.

Tests 7 to 14 and 25 to 27 of `journal.md` run unchanged on the encrypted format; the vectors J4 and J6 have encrypted counterparts in E7f and E7a.

## 8. Locked and unlocked; keys in memory

### 8.1 States

| State | Keys in memory | The node |
|---|---|---|
| **No wallet** | None | Not started. Only the first-run calls (`local-api.md` draft 2, 4.3) |
| **Locked** (after every start, and after "lock the wallet") | Only KB, the bundle key (8.7). Not the passphrase, not PK, not MSK, not the seed | The node is not started: it cannot read or write the journal and signs nothing new. **The watcher runs** from the watch-and-exit bundle (8.7): it watches, broadcasts the member's already-signed exit and response transactions at their dates, and pays their fees from already-signed children. The interface says which of the two it is doing |
| **Unlocked** | MSK; KJ, KL, KG; KB; the BIP 39 seed (the node derives keys from it, `journal.md` 8.2). Not the words, not PK | Running; the node does the watching and the watcher is idle. Signing out of the browser does not lock (`local-api.md` 4.7) |

"Lock the wallet" stops the node first (the `lock_held` rule of `local-api.md` draft 2 applies while partial signatures are out), makes sure the bundle is current (8.7.4), closes the journal and the log, wipes every key but KB, and starts the watcher.

### 8.2 The operations `local-api.md` uses

| Operation | Does |
|---|---|
| **set up**(passphrase) | 4.1's rules; creates the key file and the journal (7, step 4) |
| **unlock**(passphrase) | 4.5's opening, then the journal header (5.3), the guard check (6.3), then the node starts |
| **check**(passphrase) | While unlocked: 4.6's comparison. For sign-in and fresh sign-in |
| **drop** | 8.1's lock |
| **words**(passphrase) | 9.1: opens the words for one reveal or check |

Each derivation runs one at a time, on a thread of its own so the program keeps answering; at most one is queued.

### 8.3 Memory rules

- **Where secrets live.** Every key, the seed, the words, PK and the passphrase are held in memory from `sodium_malloc` (guard pages before and after, a canary, locked pages where the system allows) and nowhere else. Between uses MSK, the seed and the file keys are `sodium_mprotect_noaccess`; the writer makes them readable for one seal and protects them again. The working copy of the seed inside a key derivation is wiped by the wallet library as today (`wallet-keys.md` 5).
- **Wiping.** `sodium_memzero` on every buffer that held a secret, at the end of each use and on every error path; `sodium_free` wipes before freeing. The HTTP layer wipes a request body that held a passphrase or words before freeing it, and never copies it into a log, an error or an event.
- **Swap.** `sodium_malloc` locks its pages (`mlock`, `VirtualLock`). If locking fails (limits), the program goes on and records "memory not locked" in its status, because refusing to run would stop the node from watching. Linux: the program raises its `RLIMIT_MEMLOCK` soft limit to the hard limit at start. Windows: it raises its minimum working set (`SetProcessWorkingSetSize`) enough for the locked pages, since `VirtualLock` is bounded by it.
- **Core dumps and debuggers.** At start, before reading any file: `setrlimit(RLIMIT_CORE, 0)` (POSIX); Linux `prctl(PR_SET_DUMPABLE, 0)`, which also stops other processes of the same user from attaching with `ptrace`; `sodium_malloc`'s pages are marked `MADV_DONTDUMP` on Linux. macOS: `RLIMIT_CORE` 0. Windows has no core files by default; see 8.5.
- **Argon2id's own memory** (256 MiB) holds passphrase-derived blocks; libsodium wipes and frees it after each derivation. It is not locked (too large); it lives for under a second.
- **Logs and errors** never contain a key, a passphrase, the words, a nonce input `r`, a plaintext record or a ciphertext; the log records "unlock failed" and a count. Test 23.3 of `local-api.md` searches for them.
- **Not defended:** an attacker with the same operating-system account while the wallet is unlocked (it can read process memory unless `PR_SET_DUMPABLE` or the platform stops it, and can install a keylogger); hibernation files and a kernel crash dump (they can capture locked pages); cold-boot attacks. Full-disk encryption (BitLocker, FileVault, LUKS) covers hibernation and swap, and the interface recommends it. This matches `THREAT-MODEL.md`'s "theft of unlocked keys".
- **Later, where available:** Linux `memfd_secret(2)` (pages removed from the kernel's direct map) for MSK and the seed **(open, point 8)**.

### 8.4 The passphrase in transit

The browser sends it in a request body over loopback (`local-api.md` draft 2, 4.3); the program reads the body into a `sodium_malloc` buffer sized from `Content-Length` (at most 4 KiB for these calls), normalises it (4.1) into a second such buffer, wipes the first, runs Argon2id, wipes the second. The interface clears the field and drops its reference (`local-api.md` 12.7's rules). The command line reads it from the terminal with echo off, or from a file descriptor (8.6), never from an argument (argument lists are visible to other users on most systems).

### 8.5 Windows specifics

- **Data folder** under Gazpacho's folder in the per-user local application data folder, never the roaming profile or a OneDrive-redirected folder. Files are created with a security descriptor that grants access to the current user only (and no inherited entries), the equivalent of 0600; `local-api.md`'s token file already requires this.
- **Locking and sync**: `LockFileEx` for the journal lock and `FlushFileBuffers` for sync (`journal.md` 2 and 4); atomic replace as in 7, step 3.
- **Random**: libsodium uses `RtlGenRandom`/`BCryptGenRandom`.
- **Memory**: `VirtualLock` through `sodium_mlock`, with the working-set adjustment of 8.3. Pages locked this way still go to the hibernation file.
- **Crash dumps**: Windows Error Reporting can write a dump of a crashed process when the machine is configured for it (`LocalDumps`). The program does not change that system setting (it is the person's). Instead it keeps MSK and the seed encrypted in place while idle with `CryptProtectMemory(..., CRYPTPROTECTMEMORY_SAME_PROCESS)` as well as `noaccess`, so a dump taken between uses does not hold them in the clear **(proposed)**.
- **Console**: the command line reads the passphrase with echo off through the console API.

### 8.6 What `local-api.md` needs from this (requirements on draft 2)

1. The **words calls** (reveal, check-start, 12.3) carry the passphrase in their own body, because the words key is not kept in memory (9.1). A fresh sign-in alone is not enough for them. **(open, point 9, to settle with the API's writer.)**
2. Unlock, check and set-up take about a second; the API answers them asynchronously or with a long timeout, and runs at most one at a time.
3. `GET /api/v1/status` while locked, with no session, may say what the clear fields say (a wallet exists, its network) and the watcher's state (8.7): watching or not, the number of factories watched, the next height at which it will act, and whether it has broadcast anything. No amounts, outpoints or addresses: any local process can ask.
4. **The attempts file** is section 12.3's (format, strictest state when missing or damaged). **The passphrase strength rules** the API checks at create, restore and change are section 4.1's (at least 15 code points after NFC, at most 1,024 bytes, the blocklist, no composition rules, the refusal reasons of section 14); the API answers a refusal with the reason and the counts.
5. **"Locked" no longer means "does nothing"**: draft 2's 4.7 table ("Stops acting … leaves nothing alone until unlocked") changes to 8.7's: a locked wallet keeps watching and leaves alone by its dates; it does not sign anything new, answer the host, take part in rounds or accept payments.
6. **Unattended unlock** (a host service after a reboot that must also sign and route, which the watcher cannot do) still needs the passphrase. Proposed for 1.0.0: `--passphrase-fd <n>`, so a service manager can pass it from its own protected store (systemd `LoadCredentialEncrypted`, which can bind it to the machine's TPM); never a plain file in the data folder. The interface shows that the wallet unlocks itself on this machine **(open, point 10, owner decision)**.

### 8.7 Watching while locked: the watch-and-exit bundle

**The hazard** (second review of the local API). After every restart the wallet is locked until a person types the passphrase. A locked program cannot read the journal, so without more it watches nothing, answers no old state and cannot leave a factory before the factory's end. A member whose computer restarts while they are away (an update, a power cut) would lose the protection the whole design rests on (`safety-rule.md` sections 7 and 8; `DESIGN.md` 6, "a member's software exits automatically before expiry"). Encryption must not create that hazard.

**The design.** The unlocked program keeps a second, small sealed file, the **watch-and-exit bundle** `watch.gzw`, holding only what is needed to watch and to leave alone with transactions that are **already fully signed**, under a key **KB** that the locked program can use without the passphrase. A locked program runs only the **watcher**: a small loop over the bundle, the chain port and the broadcast port. It holds no private key and can sign nothing.

#### 8.7.1 What the locked program can and cannot do

| Can | Cannot |
|---|---|
| Read the bundle with KB | Read or write the journal; read the key file's secrets |
| Connect to chain servers (the bundle's list) and watch the bundle's outpoints and txids | Connect to the host (that needs the node's key) or any Lightning peer |
| Broadcast a bundle transaction when its condition holds (a date reached, an outpoint spent) | Sign anything: no new transaction, no new fee level, no round contribution, no channel update |
| Pay fees only with the bundle's already-signed fee children (8.7.2, item B7) | Accept or claim payments; answer `round_propose`; move to the next factory |
| Write what it saw and did to `watch.gzl`, sealed under KB, merged into the journal at the next unlock | Change the bundle (only the unlocked program writes it) |
| Answer `GET /api/v1/status` and the passphrase sign-in | Answer any other API call (`423 wallet_locked`) |

#### 8.7.2 Contents: the list `spec/exit.md` points to

Numbered so that `spec/exit.md` can cite items. The exact records and their TLV fields are `spec/exit.md`'s; this list fixes **what may and may not** be in the bundle.

| Item | What | Why the watcher needs it |
|---|---|---|
| B1 | Network (chain hash), `bundle_id`, `counter` (raises at every rewrite), the journal `file_id` and sync-mark offset it was made from | Freshness (8.7.4) |
| B2 | The chain-server list and chain-view settings in force (`local-api.md` 20.3) | To watch at all |
| B3 | Per factory the member is in: a local id (not the lobby id or the host's key), the funding outpoint, and its state (live, unfunded with its funding deadline, abandoned) | What to watch |
| B4 | The member's **exit path**: every fully signed transaction from the funding output down to the member's own leaf output (the held set, `safety-rule.md` C3), each with the height or relative delay from which it is valid and its txid | Leaving alone |
| B5 | The **dates**: the height by which the exit must start (`safety-rule.md` 7, end less exit time less margin), each step's latest safe height, the funding deadline and unfinished deadline (`safety-rule.md` 12) | When to act |
| B6 | **Responses**, one per watched outpoint: "if this outpoint is spent by anything but these txids, broadcast these fully signed transactions". For channels: the member's current commitment, fully signed, and a fully signed penalty transaction for each of the host's revoked states (a watchtower's justice transactions, prepared while unlocked); never the revocation secrets themselves | Answering an old state and a withheld close |
| B7 | **Fee children**: for each transaction above whose fee is paid through a pay-to-anchor output, fully signed child transactions at a fixed ladder of fee rates, each spending the anchor and one small fee coin of the wallet and paying its change back to the wallet's own address. The ladder starts at the owner's 0.1 sat/vB and its steps are `spec/exit.md`'s | Paying fees without a key |
| B8 | The fee coins of B7 (outpoints and amounts) and the destination the exit pays to, for display | Status, and to watch the fee coins |
| B9 | The member's own exposed set entries that a host could publish (`safety-rule.md` C4), as txids to recognise | Telling a host's publication from a theft attempt |

**Never in the bundle:** a private key of any kind (seed, factory key, contribution key, channel keys, the fee coins' keys), a revocation secret, a secret nonce, a preimage, the words, MSK, a host's address or key, a lobby id, terms, conditions, payment history, an unsigned or partly signed transaction, and any revoked commitment of the member's own (broadcasting one would hand the host a penalty). Payments in flight (HTLCs) cannot be claimed without a key; `spec/exit.md` decides whether the wallet refuses to lock while any are pending (proposed) or prepares signed claims.

#### 8.7.3 The bundle key KB and where it lives

KB is 32 random bytes, made with the wallet, independent of the passphrase and of MSK (a key derived from either would need them while locked). The bundle is useless to a thief who has only the data folder **if** KB is kept elsewhere:

| Platform | KB kept in | Unattended at boot |
|---|---|---|
| Windows | `CryptProtectData` (DPAPI), current user, the blob in the per-user local application data folder; opened by the same user's logon | Yes, for a service running as that user |
| macOS | Keychain item, "this device only", access limited to the program | After the user's login; for a launch daemon, a system keychain item |
| Linux, desktop | Secret Service (libsecret) | After login |
| Linux, server | systemd credential (`LoadCredentialEncrypted`, bound to the TPM where present) | Yes |
| Anywhere else | `watch.key`, owner-only, beside the bundle | Yes. The bundle is then readable by anyone who copies the folder; the interface says so |

The unlocked program also keeps KB in the key file, sealed under KS (a 32-byte record appended in a later format; until then re-made and re-stored at each unlock if the store lost it), so KB is recoverable with the passphrase.

#### 8.7.4 Keeping it current: the bundle is part of save before send

A stale bundle is a hazard of its own: it could miss a factory, or, worse, hold a commitment the member has since revoked. So the bundle follows the journal's rules:

1. **Anchored like the guard.** The storage layer rewrites the bundle (atomic replace, 7 step 3), with a higher `counter`, before confirming any batch that changes its contents: a new or ended factory, a signed exit path or response (`round_signed`, `exposure`), a funding status change, a dates change, a new fee coin. Nothing the batch releases leaves before the bundle is replaced.
2. **Revocation.** Before the member releases a revocation secret for its own old commitment, the batch that records it also replaces the bundle with the new commitment and without the old one; the release waits for that confirmation. So no bundle ever on disk after the release holds the revoked commitment.
3. **At lock** the program checks that the bundle reflects the journal's last confirmed batch (B1's offset) before dropping the keys.
4. **At unlock** the program reads `watch.gzl`, saves what the watcher saw and did in the journal (one batch), and compares the bundle's `counter` with the journal's record of the last bundle written; an older bundle on disk is replaced and reported.
5. **The watcher refuses to go backwards**: it remembers the highest `counter` it has opened (in KB's store where possible) and refuses a bundle below it (vector E13).

#### 8.7.5 Threat analysis

| An attacker who has | Gains | Cannot |
|---|---|---|
| The data folder only (KB kept in the OS store) | The bundle's size and times | Read it |
| The data folder and KB (`watch.key`, or the OS account) | **Privacy**: the member's factories, funding outpoints, amounts, exit transactions, the destination address, the fee coins, the dates | **Steal.** Every transaction is already signed and pays the member's own outputs or the miners; changing one breaks its signature |
| The same, acting | **Griefing**: broadcast the exit early, ending the member's place in the factory before its end (the member keeps the funds but pays exit fees and loses the channel); broadcast the highest fee children, spending the fee coins on fees (bounded by the fee coins' value) | Redirect any amount; sign a new state; obtain a key |
| Write access to the data folder and KB | Replace the bundle with an older one. Only a bundle that holds a revoked commitment could cost money, and rule 2 of 8.7.4 means none is written after a revocation; an attacker who kept an older copy and can also defeat rule 5 (by also resetting KB's store) could make the watcher broadcast it | This needs write access as the person's own operating-system user, which already allows a keylogger and is outside what any wallet defends (`local-api.md` 5.7; `THREAT-MODEL.md` "theft of unlocked keys") |

The bundle therefore trades a stated privacy loss, on a device where KB is not in an OS store, for the safety of leaving in time. **Proposed default: on, always.** An option "do not watch while locked" (maximum privacy) exists in Settings, with the warning "While locked, Gazpacho will not watch or leave in time" **(open, point 15, owner decision)**.

#### 8.7.6 Format

`watch.gzw`: `magic` ASCII `GZWATCH1` (8); `format` 1 (1); `chain` (32); `bundle_id` (16); `counter` (`u64`); `next_action_height` (`u32`, the earliest height at which the watcher must act, clear so the status line can show it before opening); then `seal(KB, contents, ad = the 69 bytes before)`. Contents: a TLV stream of `spec/exit.md`'s records, items B1 to B9. `watch.gzl`: the journal's entry format under KB with its own `file_id`. Vectors E12, E13.

## 9. The seed and the 24 words

### 9.1 Where they are and who can open them

- **The BIP 39 seed** (64 bytes) is sealed under KS, a key from MSK, so the running node can open it at unlock and derive per-lobby keys from it (`journal.md` 8.2).
- **The words' entropy** (32 bytes) is sealed under KD, a key from the **passphrase** key, not from MSK. The running program cannot open the words on its own: a reveal or a backup check needs the passphrase typed for that purpose, which re-derives PK, opens the words into a `sodium_malloc` buffer, and wipes PK at once.
- Why the split. The seed in memory already lets a thief of the unlocked process spend everything, so sealing the words separately does not protect the money against that thief. It does make "reveal needs the passphrase" a property of the cryptography rather than of the API's checks, keeps the words out of every memory dump of the running program, and leaves the words, the only thing a person can carry away, exposed for seconds per reveal.

### 9.2 Reveal and check

1. The person asks to see the words, or starts the backup check (`local-api.md` 12.3, 12.7), and types the passphrase.
2. The program runs **words**(passphrase) (8.2): one Argon2id, then KD, then the words. A wrong passphrase counts against the attempt limit as at sign-in.
3. The program converts the entropy to the 24 words, sends them (reveal) or compares the person's answers in constant time (check), then wipes the entropy, the words and every string built from them. The interface's rules (`local-api.md` 12.7: hidden after 2 minutes, cleared from the page) apply.
4. The words are never decrypted for any other purpose.

### 9.3 Restore from the words

- **New device, or no journal:** the person types the 24 words and chooses a passphrase (4.1). The program makes a new MSK, `vault_id` and key file, an empty journal, and marks the start as a restore (`journal.md` 8.2, R2). Factories come back only from an export (11).
- **Same device, key file lost or passphrase forgotten, journal intact:** the program derives the seed from the words, opens the journal's recovery wrap with KR (5.3), checks the header, and writes a new key file (new passphrase, new salt, same MSK, same `vault_id`). Then the guard check of 6.3 decides: a journal not behind its guard starts normally, because it is the current journal; otherwise it starts as a restore. This is the only path where a lost passphrase loses nothing.

## 10. The guard file

Replaces `journal.md` 8.3's format; its rules (where it lives, the storage duty, the order before confirmation) are unchanged.

| Offset | Field | Size |
|---|---|---|
| 0 | `magic`, ASCII `GZGUARDE` | 8 |
| 8 | `format`, 1 | 1 |
| 9 | `chain` | 32 |
| 41 | `seal(KG, contents, ad = bytes 0..40)` | 24 + n + 16 |

Contents: `counter` (`u64`), `n_epochs` (`u16`), per epoch `epoch` and `highest_index` (`u32`, `u32`), `rounds_started` (`u64`), then the high-water mark: journal `file_id` (16), `incarnation` (`u64`), `mark_offset` (`u64`). The 8-byte check of `journal.md` is gone (the tag replaces it). The file is replaced before every anchored batch is confirmed (6.2): those with a `guard` record, as `journal.md` 8.3 already requires, and those with an `exposure` record, where only the high-water mark changes.

KG comes from the **seed**, not from MSK, because the guard must stay readable across a restore that makes a new key file and a new MSK (`safety-rule.md` R6: "a place a restore never overwrites"). Its contents reveal counts, not keys.

## 11. Exports and the host's copy

`DESIGN.md` section 9: the journal is also the backup; the person may export it and the host keeps a copy (Lightning's peer storage, `DESIGN.md` 8). Two profiles of one format, `.gzb`.

| | Profile 1: the person's export | Profile 2: the host's copy |
|---|---|---|
| Opens with | The passphrase **or** the 24 words | **Only the 24 words** |
| Holds | The journal's entries, the guard, **the words' entropy** | The journal's entries, the guard. No words, no seed |
| Restores | Everything, from the file and the passphrase alone | Factories, once the words have restored the keys |
| Strength against a thief of the file | The passphrase's (3.3), at the export's own Argon2id parameters | 256 bits: unbreakable |

**Why the host's copy must not open with the passphrase.** The host keeps every member's copy and is the adversary of `safety-rule.md` section 2. A copy that a passphrase opens would let a host with a graphics card try every member's passphrase offline and, for a weak one, take the words and the money. A copy keyed from the seed gives it nothing.

**Format** (integers big-endian):

| Offset | Field | Size |
|---|---|---|
| 0 | `magic`, ASCII `GZBACKUP` | 8 |
| 8 | `format`, 1 | 1 |
| 9 | `profile`, 1 or 2 | 1 |
| 10 | `chain` | 32 |
| 42 | `export_id`, random | 16 |
| 58 | Profile 1 only, the slot: `kdf` 1, `t` 4, `m` 4, `p` 1, `salt` 16, then `seal(KX, BK, ad = bytes 0..83)` | 26 + 72 |
| 156 (profile 1) or 58 | Chunks, to the end of the file | |

Each chunk is `u32 n` then `seal(EK, part, ad = prefix ‖ u64 index ‖ u8 final)`, where `prefix` is every byte before the first chunk, `index` counts from 0, `final` is 1 on the last chunk and 0 on every other, a part is at most 65,536 bytes, and `n` (40 to 65,576) is the sealed length. The index and final flag in the associated data stop chunks being reordered, dropped, repeated or the file being cut short (the STREAM construction; vector E11). Only the final chunk may be empty.

The plaintext, the chunks' parts joined: `version` (`u8`, 1); `created_ms` (`u64`); `flags` (`u8`, bit 0: the words follow; must be 0 in profile 2); the 32-byte entropy if bit 0; `guard_len` (`u32`) and the guard contents; then every journal entry up to the last valid sync mark, as `kind` (`u8`), `incarnation`, `sequence` (`u64` each), `len` (`u32`), payload. Records keep the journal's odd/even rule.

**Export** (`local-api.md` 12.6, fresh sign-in): profile 1 takes its own Argon2id over a new salt at the key file's parameters, or higher; its slot wraps BK. **Opening**: with the passphrase, the slot gives BK; with the words, BK = derive(seed, `backup`, chain). If the words are given, BK must equal the slot's (the file belongs to these words). **Import** is a restore (`journal.md` 8.2): a new journal with a new `file_id`, the entries re-sealed, a new key file if the device has none, then the restore marker and a new epoch. The guard rule of `journal.md` 8.3 compares the export's guard with any guard file on the device.

The size limit of peer storage (about 64 KB per message) is smaller than a journal; how the host's copy is carried is the backup specification's (`journal.md` open point 4).

## 12. Other files

### 12.1 The log

`log.gzl`: the journal's header and entry format with its own `file_id` and key KL, one entry per line (kind 4, a format of its own, never read by the node), no sync after each line, two files of at most 16 MiB in turn. Before unlock nothing is written to it; the program prints only fixed messages, without data, to its terminal (`local-api.md` draft 2, 4.3). A debug build may print more to the terminal, never to a file.

### 12.2 The socket token

`socket.token` (`local-api.md` draft 2, 4.6) stays plain, owner-only, made at unlock and deleted at lock and stop, so a stolen powered-off disk holds no valid token. Encrypting it would mean the command line needs the passphrase for every call. Owner to confirm this exception to "everything encrypted" **(open, point 11)**.

### 12.3 The attempts file

`attempts.gza`, for `local-api.md` draft 2 4.3's limit across restarts. 64 bytes: `magic` ASCII `GZTRIES1`; `chain` (32); `wrong_in_a_row` (`u32`); `last_wrong_s` (`u64`, Unix seconds); `blocked_until_s` (`u64`); then the first 4 bytes of SHA-256 over the 60 bytes before, against torn writes only. Replaced atomically. It cannot be authenticated without a key, which does not exist before unlock; an attacker who can rewrite it can also copy the key file and guess offline, so nothing is lost. A missing or damaged file means the strictest state (`blocked_until_s` now + 15 minutes), so deleting it does not reset the limit.

## 13. The library

**libsodium**, at least 1.0.18, for Argon2id (`crypto_pwhash`), XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf_*`), HMAC-SHA256 (`crypto_auth_hmacsha256_*`, for HKDF and the nonce), randomness (`randombytes_buf`), guarded memory (`sodium_malloc`, `sodium_mprotect_*`, `sodium_mlock`), wiping (`sodium_memzero`) and constant-time comparison (`sodium_memcmp`). **Proposed; owner yes needed** (a new dependency).

| Option | For | Against |
|---|---|---|
| **libsodium** | Every primitive this document needs, plus the memory functions, in one library. Argon2id and XChaCha20-Poly1305 are its recommended defaults. Audited in 2017 with key derivation and authenticated encryption in scope, no major findings (Audit libsodium). Very widely deployed and stable since 1.0.0. ISC licence: permissive, MIT-compatible, needs only its notice kept (About > Licences, `ux/decisions.md` 7). Packaged on every target: Ubuntu 24.04 and Debian 12 ship 1.0.18; Homebrew current; Windows through vcpkg or the project's own signed MSVC and MinGW builds | A second cryptography library beside OpenSSL. The 1.0.18 in long-term distributions lacks the HKDF functions (written over its HMAC instead, 4.4) |
| OpenSSL only | Already linked; Argon2id (`EVP_KDF-ARGON2`), HKDF, HMAC, ChaCha20-Poly1305, AES-GCM-SIV | Argon2id and GCM-SIV need **3.2 or later**; CI's Ubuntu 24.04 has 3.0.13, so CI and many users' systems would need a newer OpenSSL. No XChaCha20 (96-bit nonces only). Its Argon2 is from 2023 and much less deployed. Memory hardening only through the secure heap (`CRYPTO_secure_malloc_init`), coarser than libsodium's per-allocation guard pages |
| Monocypher 4 | Two files, CC0 or BSD-2, vendored and built anywhere; Argon2id and XChaCha20-Poly1305 | Its Argon2id came with version 4 (2023), after the 2020 Cure53 audit of 3.1.1 (Audit Monocypher). No memory locking or guarded allocation; `crypto_wipe` only |
| Reference Argon2 plus the imported ChaCha20 | No new library for the cipher | Assembling primitives by hand is what the bar forbids |

**Build.** Linux and macOS: `pkg-config libsodium`, version checked at configure (`>= 1.0.18`) and at run time (`sodium_library_version_major`, `_minor`), linked statically in release builds. Windows: vcpkg's `libsodium` port, or the release archive checked against its published minisign signature and a SHA-256 pinned in the repository. The program calls `sodium_init()` before anything else and refuses to start if it fails. CI: a job on each of Linux, macOS and Windows runs the vectors of section 15 against the linked library (`OPEN-QUESTIONS.md` 4: no Windows or macOS CI exists yet).

**Where it is linked.** Only in the outer layer (L4 storage port and L5 programs, `DESIGN.md` 3). The core never sees a key, a nonce or a ciphertext: it hands records to the runner and gets them back from the reader, as now. `tools/check-core-isolation.sh` stays as it is, and a new check refuses any `sodium_` symbol in `gazpacho_core`.

## 14. What the interface says (proposed wording)

Plain words, short sentences, no jargon; the same text in every place.

**Choosing the passphrase (first run, restore):**
> Choose a passphrase. You will type it each time you open Gazpacho on this computer. It locks every file Gazpacho keeps here.
> At least 15 characters. A short sentence you will remember works well. Or let Gazpacho suggest one.
> Nobody can recover it for you. If you forget it, your 24 words still bring the wallet back on this computer, but a backup file you made can then only be opened with the 24 words.

**A refusal:** "This passphrase is too short (12 of 15 characters)." / "This passphrase is too common. Choose another." / "This passphrase uses your 24 words. Choose another."

**Suggest one:** six words drawn at random from a published 7,776-word list that is not the 24-word list (so the two are never confused), shown once, with "Write it down with your 24 words, or keep it in a password manager." The list and its licence are **(open, point 3)**.

**Unlocking:** "Gazpacho is locked. Type your passphrase to unlock. While locked, Gazpacho still watches your factories and leaves them in time if it must, but it cannot take payments or join anything new." (`local-api.md` draft 2's wording for the strip takes precedence where they differ.)

**Changing it:** "Changing your passphrase protects copies of your files made from now on. Copies made before still open with the old one. If you think someone has both an old copy and your old passphrase, choose New storage key as well."

**Exporting:** "This file opens with your passphrase or your 24 words. Keep it as safely as your words: anyone who guesses your passphrase can use it."

**Weak memory protection:** "Your system did not let Gazpacho keep its keys out of the swap file. Full-disk encryption protects against this."

## 15. Test vectors (section E)

Computed by `tools/spec-vectors.py` (run `python -I tools/spec-vectors.py`), which prints them after the earlier sections. Neither Argon2id nor XChaCha20-Poly1305 is in Python's standard library: the tool contains both, written from RFC 9106 and RFC 8439 with the XChaCha draft, and refuses to print anything unless they reproduce the published vectors (E0). That code is slow and not constant time, for vectors only. The implementation's job is to reproduce every value below with libsodium; the vectors are the contract between the two.

All salts, identifiers, keys and nonce inputs are **test values** derived from public strings (`sha256("gazpacho test " + label)`); real files draw them from the random source. The BIP 39 seed is a stand-in, `sha512("gazpacho test bip39 seed")`, because the 24-word list is not in the standard library; the seed's derivation from words is already covered by the 24 official BIP 39 vectors (`wallet_vectors`). The signet chain hash is the one of `terms.md`.

**E0. Primitives.** RFC 8439 2.8.2 (ChaCha20-Poly1305), XChaCha 2.2.1 (HChaCha20) and A.3.1 (XChaCha20-Poly1305), RFC 5869 A.1 (HKDF-SHA256), RFC 9106 5.3 (Argon2id, 4 lanes, with secret and associated data): all reproduce. libsodium cannot run RFC 9106 5.3 (one lane, no secret, no associated data), so E2 is the KDF vector it must match.

**E1. Normalisation.** The passphrase `gazpacho test passphrase, never for coins: café`, typed with U+00E9 or with `e` + U+0301, gives these 48 bytes:

```
67617a706163686f207465737420706173737068726173652c206e6576657220
666f7220636f696e733a20636166c3a9
```

**E2. Argon2id at test parameters** (t = 3, m = 64 KiB, p = 1, 32 bytes; below the floor, so only the test entry point accepts them). Salt `db6c732c92598e0ec4c658b7addec256`. PK:

```
bcc9248a9db077e01fbaa2a93f27041e128273dc0336872fe21f9f69c099904c
```

E2 also agrees with OpenSSL 3.5.5 (`openssl kdf -keylen 32 -kdfopt hexpass:… -kdfopt hexsalt:… -kdfopt iter:3 -kdfopt memcost:64 -kdfopt lanes:1 ARGON2ID`) and with Node 24's `crypto.argon2Sync`, which is built on OpenSSL.

**E2r. The same at the default** (t = 3, m = 262,144 KiB, p = 1). Computed by the tool's reference (with `--slow`, about 30 minutes) and by the same two OpenSSL-based routes, which agree:

```
acfe7a0e9b72c011d3382684f2b9b06a221f61aeb29fe3382299419b6433c945
```

**Still to be confirmed with libsodium**, the implementation's library: `crypto_pwhash(out, 32, pw, 48, salt, 3, 268435456, crypto_pwhash_ALG_ARGON2ID13)`. OpenSSL took about 3 s for it on the machine where this was written, single-threaded and under load; calibration (4.2) decides on each device.

**E3. Key file** at E1's passphrase and E2's parameters and salt; `vault_id` `58e8eff8fffdf8d50e058079eb041465`; MSK `15a191ff9bc84eb40d4af9e03f98e31cdce1bd0a3cbb543b2ca1cc2664d2e8ba`; nonce inputs labelled `key file wrap 1`, `key file words 1`, `key file seed`. KW `c5bb964b729d73609b845b8c8620cc14cf9127fd8c15415b726f88727f0acabc`, KD `24487797d030cb76de0290e7fe5590ebcfcd399f5514158e30623e979906b743`, KS `7236c6a1da88ced5cb0de1d17d579e785177081ffe04a80fb3734c5b6288bee1`. 331 bytes:

```
475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000
004001db6c732c92598e0ec4c658b7addec2562b16d11f34f1db909364109ec3
c9d2ec9b794db7f96f9884cfc5510c92b598ad13a9732b6530ac4d7b10b471aa
860949aae26913de781d1723c8e9dcc0c53bedcdb35dfa48134bde5d113ffddc
c0800812ca4f2043240b9d96b5a52f16cf695605f9c3e573acb82bac85a625d1
fdef3e5455b7bc01e555f0678804a64f595a414ded81bc8eb6ddbf9830b76cee
37777a29ebf0e31cf1325897fe8f6520149761ab099fdf087684d56bc772fa26
477f3d4a9848e522a43e36e2dd76607751b4fa75def5a1bac79ae2a29f639fc2
a566f1e9b0cb3869724477f6d9b17838598d6ba289cc60f75d867a2d7af1e52f
2905743546aab2952bb7b0
```

Opens with the passphrase in either form of E1 and gives MSK and the seed; the words open with the same passphrase.

**E4. Refusals of E3:** the passphrase with a trailing space; byte 65 changed (m = 65 KiB); byte 61 changed (t = 1); a bit of the seed ciphertext flipped (opens the wrap, then "damaged key file"); the chain changed ("other network", before any derivation); and under the release floor, "parameters refused".

**E5. Journal header**, `file_id` `708bd86b189b2130142ec86d6c5a6f22`; KJ `8b6c75058abb5837cc5d7c069066cc9e4c67d523a725033616515e1cd5843875`; KR `9de84e620aee3a44f7d2d7b7efe872b26c5b4d5f1da2b987011281af4f8676d3`. 185 bytes:

```
475a4a4f55524e4501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb041465708bd86b189b21
30142ec86d6c5a6f22c147d6161fcffc99b6330927e2eec8d737655c633dfc35
593047c7e7bfc9a0f7666e6a476bd6aa13da2e84ed3477e45f44a9e0377bb33c
ee0f323a182822287ee4da6c60cf211995aab6243ca4aa7d4da5c7192859be6d
4bc8a32e5ba95d93adee3f393fd9ad6bf32551262f5adcf997
```

Its recovery wrap opens with the seed alone and gives MSK; under another MSK, or with `vault_id` changed, "not this wallet's journal"; with the chain changed, "other network".

**E6. Entries** after E5: the encrypted counterparts of J2, J5, J3 and J6's second mark.

E6a, incarnation 1, clock 1,794,000,000,000 ms, at offset 185 (69 bytes):
```
000000410100000000000000010000000000000000a27fffe7c4fb7fc27306ea
84bfeb60874500df39dc3d818138f03d2c455b9aafede5723b945e2be4eb4095
807fcb7ea9
```
E6b, sync mark at 254 (69 bytes):
```
000000410300000000000000010000000000000000c70a75d9817d3e310632fc
d7c515d538b3eb00f5a73c77a9430e13b92e850c17e5049101f8140cf7c7b5db
f24ac934e4
```
E6c, batch (1, 1) with one record of type `0x7e570001` and bytes `ping`, at 323 (77 bytes):
```
000000490200000000000000010000000000000001f7974bb8f3c6fe91297a4a
82d9354e6ca7c434d105497d041478ba163b65ff3377815316175f42eb6f4441
e30066cbccbe864653db610c35
```
E6d, sync mark at 400 (69 bytes):
```
0000004103000000000000000100000000000000001a744cc9c3431ad9e7d019
d2ef91aae53d930470b347e17b56fec5cbded09cfde8625ad9e59ede46e5c05a
744fb62c41
```

The 469-byte file E5 + E6 reads clean: four entries, last mark at 400. E6c's inner ChaCha20-Poly1305 (after HChaCha20, which E0 checks) also agrees with OpenSSL's `chacha20-poly1305` through Node.

**E7. Tampering** with E5 + E6, each run by the tool's reference reader:

| | Change | Result |
|---|---|---|
| E7a | One bit of E6c's ciphertext | Invalid at 323, a valid mark follows: **corruption, refused** |
| E7b | One bit of E6c's clear `incarnation` | The same |
| E7c | E6c appended again at 469 | Invalid there; no mark follows: **cut as a torn tail**; never read as a second batch |
| E7d | E6c replaced by a batch sealed for another `file_id` under the same MSK | **Corruption** at 323 |
| E7e | E6c and E6d swapped | Invalid at 323; nothing after it is read |
| E7f | The last 3 bytes missing | **Torn tail**, cut to 400 |
| E7g | The file cut at 323, an entry boundary | **Clean**, last mark 254: undetectable from the journal (5.6); caught by E9 |

**E8. Passphrase change** to `gazpacho second test passphrase, never for coins`, salt `sha256("gazpacho test kdf salt 2")[0:16]`, labels `key file wrap 2` and `key file words 2`. Bytes 0 to 66 and 227 to 330 equal E3's; the journal is untouched and opens with the MSK the new file gives; E3 still opens with the old passphrase. 331 bytes:

```
475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000
004001a89b97d1d90598f7626e1c0cb87c4db551f3fd8f12193b4c3d4f984df5
33cb7bf6aed44f90425a2a3f19a0a2f926deba14414055b235261c49d6c84f88
7de10f99e2603fb31c180b7278582b941e9bba3b153e3204278f520dc1117390
2c837528973b0bb6b95e8c8b7bd4af9e11714d3cbacdaa72f319ac7286fd1b25
035aa795072dfa792440812cab2aa2221b8ea2f284023f8954f8465a15c98664
1ec01329ebf0e31cf1325897fe8f6520149761ab099fdf087684d56bc772fa26
477f3d4a9848e522a43e36e2dd76607751b4fa75def5a1bac79ae2a29f639fc2
a566f1e9b0cb3869724477f6d9b17838598d6ba289cc60f75d867a2d7af1e52f
2905743546aab2952bb7b0
```

**E9. Guard file**: counter 3; one epoch, 0, highest index 2; one round started; high-water mark E5's `file_id`, incarnation 1, mark at 400. KG `339b2585661fdf58c0d401e63d10bb836bb3b272b6b7dbb5f3d9e417fb630deb`. 139 bytes:

```
475a47554152444501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42
25e97398810800000075e865ccd58b165c283c344e77be834027b1f5078198cb
23b6a4a6065d9492ffcd374bcf9408b55fd7c05798fa041aa6a3aa6e7bdcff7e
fb2565241dc7447a099a3134e698211339fc6cf975b3ccd88da1553eb8b7d8ec
db84d89f632336bd286714
```

Against E7g's journal (last mark 254) it is ahead: the start is refused as a rolled-back journal (6.3). Against E6 it passes.

**E10. Exports**, `export_id` `eba594bd30df323ee7faf88bd4e4bf81`, slot salt `sha256("gazpacho test export kdf salt")[0:16]`, E2's test parameters, created 1,794,000,100,000 ms, body the entries of E6 and the guard contents of E9. BK `9a4617d2c2e8fb4163ddbe6b6b1968302c0a65114f261b444605aef8cf4e1b00`, EK `e172f2dabc7650d0a79495a05dc2736ae37151ef116fcc2f10dd9d590244ac1f`.

E10b, profile 2 (the host's copy), one chunk, 298 bytes:
```
475a4241434b55500102f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c
4225e973988108000000eba594bd30df323ee7faf88bd4e4bf81000000ec4962
9d5a1ea4189facb6f2b10324fa13ab3a95fd68c48dbb084698740680a03a4a66
680b331385b03d0b66f1bc686aeb876cc025568ccb2135481603234ff824bc95
c804f5ede66b4252b74ad4a6d726af4899eb843a774e8c1faeaee296e8aff858
85de787aebbd0d9d3396dbaf4e870a1992de26bc20f680216dd34dae93992f15
f60784595d20be7c7d4e3f43f9887e4c00f28b1d7f140588942a4f9bda4519bd
47bf131d54bdbd631004a29917914369248228229434b678d888bf51dc6d0474
4ddf70c93d62e4c76460f70b31df04925aa43356b1f1431436b57ec4fcd5f433
41588a867cf0d58591e1
```

E10a, profile 1 (the person's export, with the slot and the words), 428 bytes, is printed by the tool. It opens with E1's passphrase in either form and with the seed.

**E11. Export refusals:** E10a's body sealed in 4 chunks of at most 64 bytes opens; with the last chunk dropped, "truncated"; with chunks 0 and 1 swapped, "damaged"; with the last chunk repeated, "data after the final chunk"; with the slot's memory changed or with E8's passphrase, "wrong passphrase"; with other words, "damaged"; E10b with a passphrase, "needs the 24 words".

**E12. Watch-and-exit bundle** (8.7.6), the envelope only: `bundle_id` `sha256("gazpacho test watch bundle id")[0:16]`, counter 7, KB `sha256("gazpacho test watch bundle key")`, contents one placeholder TLV record (type 2, `test contents: see spec/exit.md`); the records are `spec/exit.md`'s. Printed by the tool.

**E13. Bundle refusals:** E12 with its counter changed, "damaged"; opened after counter 8 was seen, "older than the last bundle seen"; under MSK instead of KB, "damaged".

## 16. Tests

**Primitives and formats**
1. E0 to E11 and E2r reproduce with libsodium, on Linux, macOS and Windows; RFC 5869's three SHA-256 vectors for the HKDF code.
2. Every field of the key file, the journal header, an entry, the guard and an export altered in turn: refused with the stated reason; a damaged length never reads past the file.
3. The parameter floor and ceiling: a key file at t = 2 or m = 65,535, and at t = 17 or m = 4 GiB + 1: refused without running Argon2id.
4. Passphrase rules: 14 and 15 code points (with a 4-byte character), 1,024 and 1,025 bytes, a blocklisted word in other case, the wallet's own words; NFC and NFD input equal.

**Journal (`journal.md` tests on the encrypted format)**
5. `journal.md` tests 1 to 28 pass on the encrypted format; E7a to E7g.
6. Nonce hedging: with the random source forced to return the same bytes every time, two different entries at the same offset after a torn-tail cut get different nonces; two identical entries get identical bytes.
7. Rollback (6.3): a journal cut at each entry boundary after the last anchored batch (a guard batch, and separately an `exposure` batch): refused; a legitimate torn tail after an anchored batch: accepted; the same with the guard file also replaced by its older copy: not detected (records the limit); a journal from another `file_id` beside the guard: refused.
8. Crash at every step of set-up, passphrase change, parameter upgrade and rekey: the next start opens with the old or the new passphrase and never neither; no `.tmp` file is ever opened as the real one.

**Secrets**
9. After a run with every operation, the data folder, every log, every API answer and every event contain none of: the passphrase, PK, MSK, any subkey, the entropy, the words, the seed (byte search, as `journal.md` test 22).
10. With the wallet locked, a memory scan of the process finds none of the above (a test build that reads its own memory).
11. A core dump forced while unlocked (where the platform makes one at all) does not contain MSK or the seed in the clear.
12. A wrong passphrase, a damaged wrap and a wrong network give the stated messages and nothing else (no timing difference that depends on which byte was wrong: the tag check is constant time).

**Restore and export**
13. Key file deleted, journal intact: the words reopen the journal through KR, a new key file is written, the guard check passes, the node starts normally with the same epoch.
14. Profile 2 export never contains the entropy or the seed; profile 1 opens with the passphrase and with the words; an export from another wallet with the right passphrase: refused when the words are given.
15. Import makes a new `file_id`, a restore marker and a new epoch (`journal.md` test 23).

**Watching while locked**
16. The simulator restarts a member and never unlocks it: the watcher broadcasts the exit path by the bundle's dates and the member's leaf output confirms; a host's old state published meanwhile is answered with the bundle's penalty transaction.
17. A crash at every point between a batch that changes the exit data and its confirmation: the bundle on disk is never behind anything already released; after a revocation is released, no bundle on disk holds the revoked commitment (byte search of every bundle version written).
18. Every bundle a run ever writes contains none of: any private key, revocation secret, preimage, secret nonce, the words, MSK, a host address or key, a lobby id (byte search).
19. With the bundle and KB given to a simulated thief: every transaction it can broadcast pays only the member's outputs, the miners, or the fee coins' change to the wallet.
20. An older bundle placed over the current one: the watcher refuses it (rule 5); at unlock it is replaced and reported.

**Break-checks** (as `wallet/tests/break-checks.sh`): remove the offset from the associated data: E7c and E7e must then fail; replace the hedged nonce by a counter: test 6 must fail; drop the guard's high-water mark: test 7 must fail; remove a `sodium_memzero`: test 9 or 10 must fail.

## 17. Review checklist

For the independent review of this draft. Each item is answered yes, no or "not applicable, because".

1. Is every algorithm used as its specification says: Argon2id version 0x13 with p = 1 and empty K and X; XChaCha20-Poly1305 exactly as the draft and libsodium; HKDF exactly as RFC 5869? Do E0 to E11 reproduce with libsodium?
2. Is there any key or nonce reuse across purposes? Check the label table (4.4), the nonce rule (5.2) and every `seal` call's key.
3. Is every byte of every file either authenticated or listed in 3.2 as visible? Is any clear field used before it is authenticated, other than magic, format and chain?
4. Can an entry be moved, replayed, dropped from the middle, or spliced from another file without detection?
5. Is the torn-tail versus corruption decision of `journal.md` unchanged in meaning? Can an attacker turn corruption of a confirmed entry into a silent cut (without also rolling back the guard)?
6. Is the rollback limit stated honestly, and does the guard rule (6.3) send every detected case to the restore path of `safety-rule.md` R2 to R5 rather than to a normal start?
7. Does the passphrase check give an attacker anything cheaper than one Argon2id per guess?
8. Are the Argon2id parameters justified against RFC 9106 section 4 and against the platforms (desktop now, phones later)? Is the floor enforced before the derivation runs?
9. Does the host's copy contain anything that a passphrase guess opens?
10. Is every secret's lifetime in memory bounded, and wiped on every error path? Are passphrase-carrying request bodies wiped?
11. Is the crash order of every replace and of rekeying safe: never a state where neither the old nor the new passphrase opens the wallet?
12. Are the Windows specifics right: owner-only security descriptors, `MOVEFILE_WRITE_THROUGH`, `VirtualLock` and the working set, `CryptProtectMemory`?
13. Is the library choice and its licence acceptable, and is it linked only outside the core?
14. Does the hedged nonce actually stay safe when `r` repeats (test 6)?
15. Does the wording of section 14 say what the cryptography does and no more?
16. Does a locked wallet keep the member safe through its dates (8.7)? Is anything in the bundle a key, or a transaction that could pay anyone but the member and the miners? Can the bundle ever hold a commitment the member has revoked?

## 18. Open points

1. **The owner's yes** to: libsodium as a new dependency (13); Argon2id at 256 MiB, 3 passes, floor 64 MiB (4.2); the minimum of 15 characters and the blocklist (4.1); the host's copy openable only with the words (11); the profile 1 export carrying the words, so that the file and the passphrase alone restore everything (11).
2. **Unicode normalisation in C**: vendor utf8proc (MIT), or accept only what the interface normalised and refuse non-ASCII passphrases from the command line.
3. **The blocklist and the word list for suggestions**: which lists, their size and licences (a list of leaked passwords; a 7,776-word list that is not BIP 39's, for example the EFF long list, CC BY 3.0 US, which needs attribution).
4. **Phones**: the calibration may land on the floor; whether a phone may go below 64 MiB, and what the interface then says.
5. **Rekey** (4.8): the crash order to be proven by fault tests; whether 1.0.0 needs it at all.
6. **Padding** of batch payloads to hide record sizes (Padmé, at most 12 % overhead), which needs a padding length in the batch format of `journal.md` 3.2.
7. **A rollback anchor outside the data folder** (6.4): the credential store, TPM counters, and the host-reported newest round, the last a change for `safety-rule.md` section 9.
8. **`memfd_secret`** on Linux, and the equivalent elsewhere.
9. **The words calls carry the passphrase** (8.6, item 1), to settle with `local-api.md` draft 2.
10. **Unattended unlock** for hosts (8.6, item 6): `--passphrase-fd` and service-manager credentials, and how the interface shows it.
11. **The socket token** stays a plain owner-only file (12.2): the one exception to "everything encrypted".
12. **E2r and every E vector confirmed with libsodium** on the three platforms. E2 and E2r agree today between the tool's reference and OpenSSL; libsodium has not been run (no build exists here).
13. **Folding into `journal.md`**: sections 2.1, 3, 7 and 8.3 there, when its writer is free; until then this document's sections 5 and 10 are normative for the encrypted format.
14. **Independent review** of this draft, with the checklist of section 17, before any code.
15. **The watch-and-exit bundle** (8.7): on by default with no opt-out except "maximum privacy" in Settings (proposed); `watch.key` as the fallback where no OS key store exists (proposed); whether a wallet with payments in flight may lock, and the fee ladder (both `spec/exit.md`'s); the bundle's KB record in the key file (a format 2 of 4.5).
