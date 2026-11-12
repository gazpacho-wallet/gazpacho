# Review of pull request 7, rounds 2 and 3: chain view

*Archived 2026-11-12 from the coordinator's notes, where it was the last record of this review. The file holds round 3 (the confirmation) first and round 2 below it, as the reviewer kept them. Round 3 was written from reading the code: its reruns had not finished. They finished later on the build server; their results were never written into this file and are summarised in `README.md` in this folder. Server folders are named in words, under the rule against local paths.*

## Third round (confirmation): `562af83`, rebased on main `a7d26cc`

Reviewed 2026-11-12. This round is a code read of `2532420` (the fixes for findings A to G) and `562af83` (the wallet tool), with each point checked against the code. My reruns on the build server (the trailing-dot live case, the lag and fee cases, the `user@host` transport URLs, longer model runs, and 47 mutations: the round-two survivors ported to the new code plus 24 against the fixes) were started in a folder on the build server (results in `run.log` there). **They had not finished when this was written**, so the statuses below come from reading the code and are not yet confirmed by a run.

**Verdict: merge after one trivial fix**, provided the pending run shows no surprise.

| Finding | Status (from the code) | Where |
|---|---|---|
| A. Trailing dot, two operators | **Fixed.** `gz_host_normalise` strips one trailing dot, lower-cases, refuses empty labels and non-canonical numeric hosts. The multi layer normalises every described host again. Requests go to the canonical endpoint, not to the spelling given | `chain.c` `normalise_into`; `esplora.c` `url_parse`, `es->base = info.endpoint`; `multi.c` create |
| B. Lag from tips alone | **Fixed as asked.** Lag requires the disputed item to be above the tip of every server lacking it and at or below the tip of every server holding it, tips at most 3 apart on one chain, and the run of lag at most 30 minutes. R2 (liar at 329438 denies a transaction at 329438) and R2c become disagreement: the item's height is not above the lacking server's tip. A raw transaction present on one server only is disagreement | `multi.c` `lagging`, `outputs_lagging`, `lag_still_allowed` |
| C. Fee cut by leaving targets out | **Fixed.** A server "answers for" target T only with its estimate for a target at or below T. A target answered by fewer than a quorum of operators is dropped. `choose` never takes a slower target. R3b (only `{"1008":2}`) gives no rate for 6 blocks (`not-found`), not 2 sat/vB. A server can still lower a target within the factor-3 rule by listing a faster target lower; that is the documented bound | `multi.c` `fee_for`; `chain.c` `gz_chain_choose_fee_rate` |
| D. Confirmations stall when a server is ahead | **Fixed.** Headers are followed only up to the agreed tip | `verify.c` step 6 |
| E. `localhost:1@host` | **Fixed.** `split_url` accepts only host characters in the authority (no `@`, `%` or backslash). libcurl's own parse must name the same host with no user or password, and the parsed handle is the one used (`CURLOPT_CURLU`) | `http_curl.c` `split_url`, `parse_with_curl` |
| F. Untested steps | **Fixed per the builder** (new `chain_confirm` test with fabricated blocks, plus tests for c13, v11, the outputs flag and tool exit codes). Confirmation by my mutation rerun is pending | `tests/test_confirm.c`, `fab_nonces.h` |
| G. Smaller points | Testnet4 second operator noted; mainnet switch still lives in the tool | — |

**The builder's coinbase claim is correct, and my round-two remark was wrong.** I had written that every attack the coinbase steps stop also needs a 64-byte transaction, which is refused earlier. But the 64-byte rule only refuses bytes *we* fetch. A real 64-byte transaction X inside a block, whose second half is the txid of a fabricated transaction F, lets a server prove F one level below X. F's own bytes are an ordinary transaction and pass step 2. The only thing that ties the branch depth to the real tree is the coinbase branch, and the server cannot lengthen that without a 64-byte coinbase. So the coinbase steps are a defence of their own, not a backup. Getting X mined is non-standard and costly on proof-of-work networks; on signet servers can fabricate anyway.

**The lag rule as implemented:**
- *Limits.* The 3-block limit is the binding one: once the disputed item is 3 blocks deep, no tip within 3 of the honest one is below it, so hiding it becomes disagreement whatever the timer says.
- *Timer weakness (minor).* The 30-minute timer is weaker than it looks. The period ends whenever a call sees every server level, and a lying server can report a level tip to `tip` calls and a lower one inside the lag check, restarting the period. The 3-block bound still holds, so this needs only a sentence in the note.
- *Far-ahead side effect.* With tips more than 3 apart, `tip` is disagreement, so `confirm_tx` asked for 2 or more confirmations returns `servers-disagree` (asked for 1, the block is still checked). This fails in the safe direction. With the two-operator default it changes nothing, because one stalled server already blocks.
- *Liveness cost with three operators.* With three operators it is a real liveness cost: one honest server that stalls 4 blocks behind (a stuck indexer is common) blocks every deep confirmation, where it could simply be left out. **Acceptable for merge; follow-up:** count a server more than `tip_slack` *behind* as no reply (it cannot speak about blocks it does not have), while a server that far *ahead* stays disagreement.

**Wallet tool (`tools/gz-wallet-tx/main.c`): changes confirmed correct.**
- It uses the new `gz_http_curl_create(..., NULL)`, `gz_multi_config_default(&mc, GZ_NET_SIGNET)` and a clock (`now_ms` from the transport).
- It names the operators explicitly instead of relying on the host-name rule.
- `--feerate server` now goes through `gz_chain_choose_fee_rate`, which on signet is the fixed 0.1 sat/vB. The old code picked the first target of 6 or more (a slower target), so this is better.
- Script lookup takes the new flag argument (`NULL`).
- `confirm` asks for 6 and prints the checked count, so the printed `confirmations` is now at most 6. Nothing else in the repository parses that line. It is worth one sentence in the tool's usage text.
- `wallet/tests/break-checks.sh` turns off the chain tests with the new `GZ_CHAIN_TESTS=OFF` option, which keeps the wallet's own tests faster.

**New, trivial:** `ports/chain/tests/__pycache__/break_checks.cpython-312.pyc` is committed in `2532420`. Remove it and add `__pycache__/` to `.gitignore`.

**Not done in this round:** the empirical reruns above (pending), a fresh full break-check run, any broadcast, mainnet.

---

## Second round

Branch `chain-esplora` at `14d2dd6` (16 commits on top of `8d4baac`). Reviewed 2026-11-12 by the same independent agent as round one, against my round-one findings (`review-pr7-chain.md`).

## Verdict: merge after fixes (a short list)

Most of round one is fixed properly, with tests that fail when the fix is removed. Four problems remain before merge:

- A trailing dot in a host name defeats the one-operator rule. I confirmed this live.
- The lag rule is loose enough that a lying server can turn any disagreement into "lag".
- On mainnet, one server can cut the fee by leaving targets out.
- The transport's loopback-only check can be fooled with `user@host`.

None of these is large to fix.

## What I ran

Everything ran on the build server, in two copies in a folder on the build server (A for my checks, B for the builder's break-checks). The builder's tree was not touched.

| Check | Result |
|---|---|
| Release and ASan/UBSan builds with `-DGZ_WERROR=ON` | Clean. 0 warnings in all 8 chain files with `-Wpedantic -Wshadow -Wconversion -Wcast-qual -Wformat=2` |
| `ctest`, both builds | 10 of 10 pass, including `chain_local_servers` (transport: 42 checks; tool: 12 cases). Counts match the builder's note exactly: json 105, headers 186, esplora 674, multi 383, model 6, fuzz 10 |
| Builder's `break_checks.py` (125 behaviours), sanitizer build | 125 caught, 0 survived, 0 errors. Matches the claim |
| Model test, seeds 11, 222, 3333, 200,000 rounds each (10 times the default), ASan/UBSan | Pass |
| Builder's fuzz loop, 2 new seeds, 200,000 iterations | Pass |
| My grammar-based fuzz of the parsers, 3 seeds, 400,000 inputs each | 0 invariant violations, no sanitizer reports |
| Valgrind on the release tests | 0 reports |
| My hypothesis checks (fake transport) and transport checks (no request leaves the machine) | Results quoted in the findings |
| Live, read-only, signet and testnet4 | Quoted in the findings. No broadcast, no mainnet except block-0 and tip reads |
| My mutations | 176 run (73 from round one that still apply, 17 ported to moved code, 86 new), plus 7 reruns of ones that did not compile; 23 round-one mutations retired. Results below |

## Round-one findings, one by one

| # | Round-one finding | Status | Evidence |
|---|---|---|---|
| 1 | One server can count as two | **Partly fixed** | Same handle, same address and same host are refused; quorum counts operators; `www.` merges into one operator (live: `no-quorum`, exit 1). **A trailing dot gets through** (new finding A) |
| 2 | No network check; mainnet refusal by label | **Fixed** | Block 0 checked against genesis constants. Live: mainnet servers under `--network signet` give `wrong-network` on both, exit 1. Broadcast refuses any server that identifies as mainnet. `GZ_NET_INVALID = 0` |
| 3 | Fee from the highest server, up to 2,000 sat/vB | **Fixed for test networks; one gap on mainnet** | Test networks always use 0.1 sat/vB and ask no server. Live: `rate that would be used ... 0.100 sat/vB, the fixed test-network rate`. Mainnet takes the lowest, with a factor-3 disagreement rule and a 200 sat/vB ceiling. **Leaving targets out bypasses the factor-3 bound** (new finding C) |
| 4 | Cited document missing; no report | **Fixed** | `docs/notes/chain-port.md` (335 lines): decisions, counts, not-tested list, operators' terms. `.gitignore` is now `/notes/` |
| 5 | Confirmation count not checked against headers | **Fixed** | `checked_confirmations` counts linked headers, at most 144. A tip invented a million blocks up changes only the claim (tested). Live: `6 confirmation(s) checked by linked headers` from both servers. Side effect: new finding D |
| 6 | Merkle weaknesses | **Fixed** | 64-byte stripped transactions refused, including segwit (my R6b: 69 bytes with witness, 64 stripped, refused). Duplicated-node twin rule. Depth must equal the depth for `tx_count`. Coinbase branch pins the depth. Two parts are not tested one by one (finding F) |
| 7 | A third party can blind a script's view | **Fixed** | Unconfirmed differences are flagged, not fatal. Confirmed outputs must match exactly. My m48 (keep an unconfirmed output only one server lists) is caught |
| 8 | Broadcast success path unproven | **Improved; still untestable without coins** | Whitespace trimmed. "Already known" counts as success only if the server then shows the transaction (mutations e33 and e34 caught). A first supervised signet broadcast is still owed |
| 9 | Claims beyond the code | **Fixed, with two new overclaims** | DESIGN section 10, CHAIN-SERVERS and the headers are now honest, including on signet. New overclaims: the fee bound (finding C) and "briefly" for lag (finding B) |
| 10 | Test gaps (19 real survivors) | **Fixed** | Every one of my round-one real gaps is now caught: c1, c2, c7, h5, v1, e10, e22, e25, e29, m5, m10, m11–m13, m16, m23, m24, plus TLS verification off, host check off, redirects and no time limit (t1–t3, t6), and tool exit codes g2–g4. m22 changed meaning (count is now flag-only) and survives as m22' |
| 11 | Transport unguarded | **Mostly fixed** | Every `curl_easy_setopt` is checked. Plain http only for loopback. A local test suite exercises bad certificates, redirects, slow and huge responses. **The loopback check is a prefix test that `user@host` defeats** (new finding E) |

## New findings, most serious first

### A. A trailing dot makes one operator count as two (high; reopens round-one finding 1)

`url_parse` (`esplora.c`) accepts a host ending in `.`. `gz_operator_from_host` (`chain.c`) then keeps the "last two labels" of `mempool.space.` as `space.`. The host strings differ too, so the same-host check misses it.

- Fake transport: `https://mempool.space/signet/api` + `https://mempool.space./signet/api` gives `multi=ok operators=2 [mempool.space] [space.]`. Same for blockstream (`[info.]`).
- Live:

  ```
  gz-chain --server https://mempool.space/signet/api --server https://mempool.space./signet/api tip
  network: signet, 2 server(s) of 2 operator(s) ... verdict: ok (servers of 2 operators give this answer)   exit=0
  ```

  The same works for `blockstream.info.`. Both operators answer on the dotted name and TLS verifies.

This is exactly the "one server's answer presented as agreed" path from round one.

**Fix:** in `url_parse`, refuse a trailing dot, or strip exactly one before storing the host. Add both URL pairs above to `test_multi.c` and to the tool cases in `local-servers.sh`.

Related, and acceptable if stated: `a.co.uk` and `b.co.uk` merge into one operator `co.uk` (the safe direction). Two different numeric addresses count as two operators. The note already says the rule is only a guess from host names.

### B. "Lag" is decided from the tips alone, so a lying server can turn any disagreement into lag, for ever (medium)

`lagging()` (`multi.c:99-122`) only asks whether the tips differ by at most `tip_slack` and lie on one chain. It never asks whether the disputed item could be in a block the lower server has not seen yet. Each case below should be a disagreement:

- **R2.** Honest server at tip 329439; liar at 329438, on the same chain. The liar denies a transaction confirmed at 329438, a block it claims to have. Result: `server-lagging`.
- **R2c.** Honest server at 329440; liar at 329439. The liar denies a transaction confirmed at 329438. Result: `server-lagging`.
- **R2b.** A spend confirmed at 329439, hidden by a server at 329438. This one is the genuine lag shape, and `LAG` is right.

A dishonest server can always report a tip one below the honest one: it just names the honest server's previous block. So it can hold any hidden spend or invented absence at `LAG` indefinitely.

The docs say to treat persistent lag as disagreement. But nothing measures "persistent" (open question 6). And the note's "Cannot: hide a confirmed spend unnoticed... (or, briefly, lag)" is not true: the lag need not be brief.

**Fix:** return `LAG` only if the disputed confirmed item is at a height above the lowest tip and is missing from the server with the lower tip. Otherwise return `DISAGREE`. Add R2 and R2c as tests. The model test cannot catch this: its expected verdicts encode the same loose rule.

### C. Mainnet fee: one server can cut the rate by leaving targets out (medium; mainnet only, which is switched off)

`multi_fee_estimates` keeps only the targets every server lists. `gz_chain_choose_fee_rate` then takes the highest listed target not above the one asked for, or else the first.

- **R3.** Two honest servers: 40 sat/vB chosen for 6 blocks.
- **R3b.** One server answers only `{"1008":2}`. Combined result `{1008: 2}`; chosen for 6 blocks: **2 sat/vB** (honest servers say 40). No disagreement is raised.
- **R3c.** One server at a third of the honest rates gives `servers-disagree`. That is the rule working.
- **R3d.** One server answers `{}`: the call succeeds with 0 entries and `choose` gives `not-found`. Safe.

So the claim in `chain_multi.h` and in section 7 of the note, that a server can lower the rate only "down to the limit that rule allows", is false. Underpaying is slow, not lost, so this is not urgent. But it is a false safety claim (checklist 4).

**Fix:** treat a target that one server lists and another omits as a disagreement, at least for targets at or below the one asked for. Or have `choose` require that the chosen target be close to the requested one. The model test has one fee target only, so it cannot see this. Add R3b as a test.

### D. While one server is a block ahead, every confirmation not yet `want` deep returns LAG (low-medium, availability)

**R5.** Both servers at 329439, want 6: `ok checked 2`. Server one learns of 329440 first: `server-lagging checked 0`. With want 2 (already reachable): `ok checked 2`.

Step 6 of `gz_chain_confirm_tx` asks the comparing backend for headers past the lower tip. One server has the header, the other says not found, and the whole confirmation becomes `LAG`. This happens around every block, for exactly the transactions a wallet is waiting on.

**Fix:** read the agreed tip first and follow headers only up to it.

### E. The transport's loopback-only check can be bypassed with `user@host` (low-medium; defence in depth, checklist 5)

`is_loopback_http` (`http_curl.c`) checks that the URL starts with `http://localhost`, the IPv4 loopback address or `[::1]`, followed by `:`, `/` or the end of the string. In `http://localhost:1@other-host/`, the `localhost:1` part is user information and the real host is `other-host`.

- My transport check against an unresolvable `.invalid` name: `http://localhost:1@review-check.invalid/api`, the same with the IPv4 loopback address before the `@`, and `http://[::1]:80@…` all made the transport try to reach the outside host.
- Plain `curl` on the same URL gives exit code 6 ("could not resolve host review-check.invalid"), which confirms how the URL is parsed.
- `http://localhost/@…` is not a bypass: that `@` is in the path.

The Esplora backend's own `url_parse` refuses `@`, so through the normal path nothing gets out. But the transport claims to refuse a second time, and that second refusal is a deny-list-style prefix test that can be fooled. It is the same class of fault as the two "no input or output" checks recorded in the checklist.

**Fix:** parse the host with `curl_url()` (`CURLUPART_HOST`), or refuse any `@` or `%` in the authority. Add the three URLs above to `not_local` in `test_transport.c`.

### F. Remaining mutation survivors in safety code (low-medium)

Of 176 mutations run, 18 survived. The ones that matter:

- **Coinbase steps of `gz_chain_confirm_tx`, removed one at a time:**
  - v5: summary not checked to name the status block
  - v6: coinbase branch depth not compared
  - v7: coinbase not checked to be a coinbase
  - v8: coinbase branch not verified
  - v9: coinbase accepted at a later position
  - c14: coinbase with more than one input accepted

  The builder's break-check v7 removes the whole block and is caught. But no test shows any single step doing work. The reason: every attack these steps stop also needs a 64-byte transaction, which is refused earlier. So the coinbase check is entirely defence in depth behind the 64-byte rule. The note says this only for the "is a coinbase" and "position below the count" checks. It should say it for all of them, or add a test with the 64-byte rule switched off where the coinbase check catches the attack.
- **c13: the 64-byte rule measured on the full length, witness included.** No test covers a segwit transaction whose stripped size is 64. The code is right (R6b), the test is missing.
- **v11: later headers' proof of work.** A test is trivial: alter the nonce of the last header followed, which still links. The builder lists it as untestable because "all real signet headers pass it". That reason does not hold.
- **v4, v14, v2, e27:** the builder lists v4 and v14 as defence in depth. v2 and e27 are equivalent given the Esplora backend's own checks.
- **m22', m49: the `unconfirmed_differs` flag.** It is not set in two cases and no test notices.
- **g6, g7: tool exit codes.** `fee` exits 0 on disagreement and on lag, and no test checks it.
- **t4 (body cap in `on_body`) and t8 (both protocols allowed):** survive because `CURLOPT_MAXFILESIZE_LARGE` and the URL pre-check catch the same cases with this libcurl. Probably equivalent.

### G. Smaller points

- `docs/CHAIN-SERVERS.md` "To do" says the table is not updated for testnet4. Testnet4 now has two working operators: live, `mempool.space/testnet4` and `blockstream.info/testnet4` agree at 160795. The tool's default testnet4 list still has only one server.
- Signet fee estimates disagree today (mempool.space 1 sat/vB, blockstream.info 10 sat/vB), so `gz-chain fee` exits 1 on signet every time. Harmless, because the rate used is the fixed 0.1, but the exit code is noise on test networks.
- The mainnet protection is a tool-level property: `gz_chain_broadcast` on a comparing backend configured for mainnet will broadcast. That is consistent with "the code for mainnet exists and is switched off", but the switch lives in the tool, not the library. Worth one sentence in `chain.h`.
- Pull request size: now +4,957/−689 on top of the original 6,549. That was expected for a fix round. Splitting it is no longer worth the cost.

## The builder's decisions

| Decision | My view |
|---|---|
| No majority vote: one well-formed contradiction blocks | **Confirm.** For a wallet, a false "confirmed" costs far more than a delay. With three operators it means one bad operator stops confirmations; the note says so. Revisit once there are three real operators and the watch engine can prove a spend (open question 3) |
| Lag recognised from tips alone | **Overrule as written.** Keep lag as its own result, but tie it to the disputed item being above the lower tip and missing from the lower server (finding B). Also set a bound on persistence, for example "LAG for more than N calls or M minutes becomes DISAGREE" |
| Operators identified by host name | **Confirm with a fix.** Normalise the host (trailing dot, finding A) and keep explicit `operator_id` for configured lists. The default lists should name their operators explicitly rather than rely on the label rule |
| Fee spread factor 3 plus 1 sat/vB; 200 sat/vB default ceiling | **Confirm for mainnet**, together with the omission fix (finding C). The fixed 0.1 sat/vB on test networks matches the owner's preference, and I confirmed it live. The lowest-rate rule is the right direction |
| At most 144 headers followed | **Confirm.** One day of blocks; caps the requests. Stop at the agreed tip (finding D) |

## Mutation counts

| Set | Written | Caught | Survived | Did not compile (not rerun) | Retired (code gone or covered elsewhere) |
|---|---|---|---|---|---|
| Round-one list, still matching | 73 | 71 | 2 (e27, t4) | 4, all rerun and caught | 23 |
| Round-one ported to moved code | 17 | 16 | 1 (m22') | 0 | 0 |
| New, round-two code | 86 | 65 | 15 | 9, of which 3 rerun and caught; 6 not rerun | 0 |
| **Total** | **176 (+7 reruns)** | **152** | **18** | **6** | **23** |

The "Caught" column includes the 7 reruns. The 6 never rerun fail to compile only because of unused-variable warnings under `-Werror`: m31 (quorum counts servers, not operators), m40 and m43 (conflicting confirmations ignored), m44 (any unconfirmed spend reported), t7 (plain http to any host) and g8 (tool exit code). The behaviours m31, m40 and m43 test are covered by the builder's break-checks (o-series and d-series), which were caught.

The full list of the 18 survivors: e27, t4, m22', v2, v4, v5, v6, v7, v8, v9, v11, v14, c13, c14, m49, t8, g6, g7.

Both mutation runs restored the source and rebuilt. The tests pass on the unchanged source in both copies.

## What I did not test

- Any broadcast on any network. No coins were moved.
- Mainnet beyond reading block 0 and the tip.
- A real TLS man-in-the-middle from outside the machine. The builder's local bad-certificate servers were run and pass.
- Coverage-guided fuzzing (no clang or libFuzzer on the build server).
- A Windows build (the transport is now documented as POSIX only).
- Real reorganisations and real lag at a block boundary (only simulated, R5).
- How long "persistent lag" should be: not decided anywhere, so not testable.
- The 6 mutations that did not compile and were not rerun.
- Concurrency (single-threaded by design).

## Left behind

Two copies and my scripts are in a folder on the build server. Their sources are restored to `14d2dd6`. The local worktree was removed. Nothing was pushed, committed or posted.
