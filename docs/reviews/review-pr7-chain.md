# Review of pull request 7: chain view (Esplora backend, comparing layer, gz-chain)

Branch `chain-esplora` at `8d4baac`, reviewed 2026-11-11 by an agent that did not write it.

## Verdict: merge after fixes

The parsing and memory-safety work is good: I could not break it. The problems are in what the comparing layer lets through, in a network guard that works by label only, and in the hand-over (a document the code cites does not exist, no report, 6,549 lines).

Findings 1 to 5 should be fixed before merge. Findings 6 to 9 need at least an honest comment and a test. The rest can follow.

## What I ran

All on the build server, in a copy at `/root/gz/review-chain/gazpacho` (the original was not touched).

| Check | Result |
|---|---|
| Release build, `-Wall -Wextra -Werror` | Clean. No warnings from the chain files with `-Wpedantic -Wshadow -Wconversion -Wcast-qual -Wformat=2` either |
| AddressSanitizer + UBSan build, all chain tests | 59 tests, 893 checks, 0 failed |
| Valgrind on the release tests (uninitialised bytes) | 0 reports in all five test programs |
| Builder's `break-checks.sh` (sanitizer build) | 44 removed, 44 caught, 0 survived |
| Builder's mutation loop, 3 other seeds, 200,000 iterations per recorded answer (5 times the default) | 0 invariant violations, 0 forged proofs, no sanitizer report |
| My grammar-based generator for the parsers, 3 seeds, 400,000 inputs each, under ASan/UBSan | 0 violations, no sanitizer report |
| My 96 mutations | 62 caught, 34 survived (list below) |
| libcurl transport against a local hostile server | Behaves as documented (table in finding 11) |
| `gz-chain` live against the two signet servers, read-only | Works; output quoted in findings 1, 2 and 3 |

No clang, libFuzzer or AFL on the server, so there was no coverage-guided fuzzing.

## Findings, most serious first

### 1. One server can count as two (high)

`gz_multi_create` (`multi.c:444-471`) does not check that the servers are different. The same handle given twice, or two backends with the same address, form a "quorum".

- Test: same handle twice gives `create=ok tip=ok confirm_tx=ok state=2 confs=2`. Same URL twice also gives `ok`.
- Live: `gz-chain --server https://mempool.space/signet/api --server https://mempool.space/signet/api tip` prints `verdict: ok (servers agree)` and exits 0.

This is the one path where an answer backed by a single server is presented as agreed. `chain_multi.h:118` only asks the caller to use different operators. Fix: refuse identical `ctx` in `gz_multi_create`; refuse identical host names in the tool and wherever the server list is built.

### 2. Nothing checks that the servers are on the stated network; the mainnet refusal is by label (high)

No genesis hash or any other network identity is checked. The only binding is the proof-of-work limit, and it works in one direction: a signet header fails as mainnet, but a mainnet header passes as signet.

- Live: `gz-chain --network signet --server https://mempool.space/api --server https://blockstream.info/api tip` prints `network: signet ... height 975504 ... verdict: ok (servers agree)`. That is the mainnet tip.
- `gz-chain.c:385` refuses `broadcast` only when the `--network` flag says mainnet. With the command above and `broadcast`, a transaction would go to mainnet servers. I did not run that.

Fix: on first use, ask each server for block 0 and compare with the network's known genesis hash; refuse to do anything otherwise. This also makes "mainnet switched off" a property of the code, not of a flag.

Related, checklist item 22: `GZ_NET_MAINNET = 0` (`chain.h:104`). The checklist records exactly this mistake ("zero meant mainnet"). A zeroed configuration means mainnet. Make zero invalid.

### 3. Fee estimates: one server sets the rate, up to 2,000 sat/vB (high for money, and against the 0.1 sat/vB preference)

`multi_fee_estimates` (`multi.c:396-417`) returns the highest rate any server gives, capped at 2,000,000 sat/kvB (`multi.c:441`).

- Test: one server at 0.1 sat/vB and one at 2,000 gives `ok 1:2000000 2:2000000 ...`.
- Live, today, honest servers: mempool.space says 1.0 for target 1 and 0.1 from target 6; blockstream.info says 10.0 for targets 1 to 6. The combined answer is 10 sat/vB for targets 1 to 6: ten times mempool.space's figure and 100 times the project's 0.1 sat/vB default. The tool prints this under `verdict: ok (servers agree)`, which is not true of fees.
- The single-server parser accepts any rate up to 2.1e15 sat/kvB (`esplora.c:295`; `{"1":2100000000000.0}` is accepted).

Nothing in this pull request sets or uses a 0.1 sat/vB default. Broadcast sends whatever it is given, with no fee check (it cannot know the fee, which is fine, but say so). Fix: return the lowest or the median, not the highest; lower the ceiling by a large factor; state in `chain.h` that the wallet's default rate is 0.1 sat/vB and estimates are only a hint above that floor.

### 4. A document the code relies on does not exist (high for checklist items 4 and 25)

`docs/notes/chain-port.md` is cited in `chain.h:33`, `chain_multi.h:5`, `multi.c:3`, `esplora.c:5` and `esplora_parse.h:9` for "the full reasoning", "the exact shape" and the endpoint examples. It is not in the branch and not on the build server. `.gitignore` has `notes/`, which also matches `docs/notes/`, so if it was written it was silently left out.

The pull request body is two sentences. There is no report of decisions made where the design was silent, no counts and no list of what was not tested (checklist items 12 and 25). No specification was reviewed first (items 1 to 3). No automated check result is attached to the pull request.

### 5. The confirmation count is not checked against headers (medium; a claim on `main` says otherwise)

`confirmations` is `tip - height + 1` from the server's own tip number (`esplora.c:529`). `gz_chain_confirm_tx` fetches one header, the one holding the transaction. No header above it is fetched, and `gz_header_links` is called only by tests.

- Test: a single server that invents its tip gives `confirm_tx=ok confirmations=1000002`. With one honest server the comparing layer returns the lower count (2), which is right. With both lying it returns 1000002.

`DESIGN.md` section 10 says Gazpacho "checks confirmations against [headers], so a server cannot invent a confirmation". The code checks inclusion in one block, not depth. Either walk and link the headers from the block to the agreed tip (bounded, say 6 to 144), or correct the sentence and the comment at `chain.h:373-388`, which does not mention depth at all.

### 6. Merkle proof: the known weaknesses are open, guarded only by a comment (medium)

- A 64-byte transaction is accepted by `gz_txid_from_raw`, and its second half then verifies as a "txid" one level down (test: all three steps return 1). This is the well-known inner-node attack. The cost of forging a chosen txid this way is high (around 2^70 work), so it is not practical today, but there is no code defence.
- An inner node verifies as a txid with a shorter proof (test: 1). `chain.h:356-360` warns about this, but `gz_chain_confirm_tx` and `gz-chain proof` take a bare txid, and `script_outputs` hands out server-supplied txids that a caller will naturally pass on.
- In a block with a duplicated last node, the same leaf verifies at two positions (test: position 2 and position 3 of a 3-transaction block both return 1). So `pos` is not trustworthy as an index.

Fix: refuse 64-byte stripped transactions in `gz_txid_from_raw`; give `gz_chain_confirm_tx` a form that takes the raw transaction, not a bare id; note that `pos` is not unique.

### 7. Any one server, or any third party, can blind the wallet's view of a script (medium, design)

Output lists must match exactly, mempool entries included (`multi.c:200-206`). Test: one server shows one extra unconfirmed 1-sat output; the result is `servers-disagree count=0`, and the confirmed 43,000 sat output is withheld too. Anyone can cause this by sending conflicting unconfirmed transactions to the two servers. The same holds for `outspend` with two conflicting unconfirmed spenders, which matters for watching a factory. It clears at confirmation.

Ordinary lag does the same for a few seconds at each block: a transaction in the newest block is "confirmed" on one server and "mempool" on the other, and the answer is `DISAGREE`, the same code as for a lie.

Suggested: compare confirmed entries strictly, report unconfirmed entries separately as unagreed, and give lag its own result code.

### 8. Broadcast success path has never met a real server (medium, untested)

The builder rightly sent no coins, so only the refusal bodies are recorded. `es_broadcast` requires the answer to be exactly 64 hex characters (`esplora.c:638`). If a server adds a newline, an accepted transaction is reported as `malformed`. A re-sent transaction that is already confirmed comes back as `rejected` with free text that differs between the two operators (`post_known_*.txt`); the caller must then ask `tx_status`. Checklist item 16 requires re-sending to be safe; this needs one sentence in `chain.h` and a first real broadcast on signet under supervision.

### 9. Comments and documents that claim more than the code (checklist item 4)

- `chain_multi.h:2-3`: "asks all of them every question, and answers only when they agree". Broadcast succeeds on one acceptance and fees are the highest of any. Both are stated lower down, but the first sentence and the tool's usage text ("An answer counts only when at least two servers give it and none contradicts it") are too broad.
- `CHAIN-SERVERS.md`: "caches what it can". There is no cache. A checked confirmation over two servers costs 10 requests.
- `CHAIN-SERVERS.md`: "Every answer that matters is asked of at least two servers run by different operators". Not enforced (finding 1).
- `esplora.c:174-176`: says "more than you asked for" can always be told from garbage. True for well-formed entries, not for short junk entries. Harmless.
- What is claimed honestly: `chain.h:327-343` says plainly that the signet block signature is not verified, that proof of work on signet proves nothing, and that retargeting and total work are not checked. The tool repeats this. Good.

### 10. Tests: gaps the mutations found (medium)

See the survivor list. The most important: the comparing layer's proof comparison is only tested with a proof that differs in everything at once (three single-field mutations survive); the libcurl transport has no test in the default run (TLS verification can be switched off and every test passes); the tool's exit codes are untested. There is no randomised test of the comparing layer against an independent model (checklist item 9).

### 11. Transport: correct in my tests, but unguarded (low)

Against a local server, with the real libcurl transport:

| Case | Result |
|---|---|
| 1 MB body with stated length, cap 1,000 | too-large in 1 ms |
| 1 MB chunked body, cap 1,000 | too-large in 2 ms |
| 302 redirect | returned as status 302, not followed |
| Server sleeps 5 s, limit 1 s | timeout at 1,001 ms |
| One byte every 0.3 s, limit 1.5 s | timeout at 1,501 ms |
| gzip-encoded body | not decoded (no decompression bomb) |
| 800 KB of headers | failed |
| Plain http or `file://` with https-only | failed |

Remarks: the return values of `curl_easy_setopt` are not checked (`http_curl.c:52-73`); if `CURLOPT_PROTOCOLS_STR` were refused, plain http would be allowed silently. Proxy environment variables are honoured (useful for Tor, but nobody decided it). `gz_esplora_create` accepts `http://` for any host (test: `http://mempool.space/...` gives `ok`); only the transport flag and the tool stop it.

### 12. Privacy (low; documents mostly honest)

Each query gives both operators the SHA-256 of a watched script, or a txid, or an outpoint, together with the user's network address. `CHAIN-SERVERS.md` says so. Not said: comparing doubles the number of parties who learn it; the `User-Agent: gazpacho-chain/0.0.1` header marks every request as Gazpacho; asking for the status of a transaction tells the server about it before it is broadcast; broadcasting goes to every server.

### 13. Build and portability (low)

- `http_curl.c` is POSIX only (`clock_gettime`, `nanosleep`). `-Wall -Wextra -Werror` is passed unconditionally in `ports/chain/CMakeLists.txt:9`; that breaks under MSVC and makes any new compiler warning a build failure. `break-checks.sh` needs bash and python3.
- 6,549 lines in one pull request (3,290 of code and headers, 3,190 of tests and data). Checklist item 24 was written because 4,000 was too many. It would have split cleanly into tokenizer, Esplora backend, comparing layer and tool.
- No secrets are logged. Server refusal text is cut and reduced to printable ASCII before printing.
- A reorganisation between the three calls of `gz_chain_confirm_tx` shows as `bad-proof`, as if a server had lied. Low.
- Fee values written with an exponent (`1e-05`) are refused as malformed. Neither server sends them today.
- Strict parsing means one new field from one operator turns that server into "malformed" until the code is updated. That is the safe direction; it needs monitoring.

## Mutation survivors

96 mutations of my own, none repeating the builder's 44. 62 caught, 34 survived.

**Real gaps: 19**

| Mutation | Where |
|---|---|
| Transaction with zero inputs accepted | `chain.c:148` |
| Transaction with zero outputs accepted | `chain.c:155` |
| No height bound at the front of `block_header` | `chain.c:206` |
| Signet proof-of-work limit made as easy as regtest | `headers.c:63` |
| Confirm although the server cannot show the block | `verify.c:19` |
| Broadcast: no size limit on what is sent | `esplora.c:618` |
| Backoff not capped at 30 s | `esplora.c:364` |
| Proof height bound raised to 32 bits | `esplora.c:251` |
| Fee answer accepted with any HTTP status | `esplora.c:667` |
| Tip: server ahead with no block at the lower height only dropped, not a disagreement | `multi.c:105` |
| Outputs: confirmed flag, height and block hash not compared | `multi.c:188` |
| Proof: position not compared | `multi.c:315` |
| Proof: nodes not compared | `multi.c:317` |
| Proof: height not compared | `multi.c:315` |
| Broadcast: accepted txid not compared in the comparing layer | `multi.c:347` |
| Outputs: count not compared | `multi.c:201` |
| Create: more servers than the array holds | `multi.c:451` |
| Create: tip slack unbounded | `multi.c:453` |
| Header shorter than 160 characters accepted by the parser (caught later by the hash check, but the parser has no test) | `esplora.c:44` |

**Transport, no test reaches it: 6.** Certificate not verified; host name not verified; redirects followed; size cap not enforced while reading; plain http always allowed; no time limit. The opt-in live test would catch only the plain-http one.

**Tool: 4.** https check removed; exit 0 on disagreement; `proof` exits 0 for an unconfirmed transaction; the one-server warning removed.

**Probably equivalent or a second line of defence: 5.** Skip bound in the transaction reader (later checks still stop it; no sanitizer report); front-of-interface transaction parse before broadcast (backends repeat it); `raw_len > cap` in `es_raw_tx` (cannot be reached given the body cap); comparing layer's own txid recheck of raw transactions; its buffer recheck after a later server fails. The last two are worth a test with a misbehaving non-Esplora backend.

Tests do fail when the fault is absent: each lying-server test asserts `DISAGREE` or `BAD_PROOF`, which can only happen if the lie was served.

## Checklist summary

| Item | State |
|---|---|
| 1-3 specification and test list first | Not met; no specification |
| 4 no overclaiming | Findings 4, 5, 9 |
| 6, 7 negative tests, rule-removed runs | Met for parsing and comparison; not for transport and tool |
| 8 mutation testing by the builder | Done, 44 of 44; my further 96 found 19 real gaps |
| 9 randomised test against a model | Parsers only; none for the comparing layer |
| 12, 25 report with counts, decisions, not-tested | Missing |
| 20 hostile input bounded, parsed strictly, fuzzed | Met; no coverage-guided fuzzer yet |
| 22 distinct types, zero not mainnet | Not met (`GZ_NET_MAINNET = 0`) |
| 23 no warnings, uninitialised bytes checked | Met |
| 24 small pull requests | Not met |

## What I did not test

- Any broadcast, on any network. No coins were sent.
- Mainnet beyond one read-only tip query that shows finding 2.
- A real man-in-the-middle with a bad certificate; TLS verification was read in the code and the options are set, but not attacked.
- Coverage-guided fuzzing (no clang on the server).
- A Windows build.
- Testnet3 and testnet4 live (testnet4 has one server, so the tool can only say no-quorum).
- Real reorganisations, real server lag at a block boundary, and rate limiting by the real servers.
- Concurrency (the library is documented as one thread per instance).
- The automated checks on GitHub: none were attached to the pull request.

## Left behind

The review copy is at `/root/gz/review-chain` on the build server (source copy, two build folders, my test programs in `extra/`). The copy's source is restored to the branch state. Nothing was pushed, committed or posted.
