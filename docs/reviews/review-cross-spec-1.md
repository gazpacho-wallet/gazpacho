# Cross-specification review 1: exit, storage encryption, local API, safety rule

Independent reviewer; I wrote none of these documents. Read from branch `specs-slice1` at `47e831e` (the branch head when fetched on 2026-11-12):

- `spec/exit.md` draft 2
- `spec/storage-encryption.md` draft 3
- `spec/local-api.md` draft 4
- `spec/safety-rule.md` draft 4 (with its "Alignment with exit.md draft 2" section)
- `spec/journal.md` draft 3
- `docs/THREAT-MODEL.md`
- `docs/MULTI-FACTORY.md`

The earlier reviews were read from `docs/reviews/` on the same commit: `review-exit-d1.md`, `review-storage-encryption-d1.md` (both rounds), and `review-local-api-d1.md`, `-d2.md` and `-d3.md`. `terms.md` and `DESIGN.md` were consulted only where these documents point to them.

## Verdict

**Consistent after the listed fixes.** The four safety specifications now tell one story for a locked 1.0.0 member:

- the watcher publishes only the tree path;
- penalties live in the append-only `watch.gzp`;
- no date is stored in the clear;
- the commitment needs an unlock by `unlock_by`;
- the unlock merges the log as untrusted input and sends the commitment first.

Every deadline formula agrees across exit, safety rule and multi-factory:

- H_leaf = E − 10·d;
- `leave_by` = H_leaf − (B − 1) − n·A − M, with n = d + 3;
- `unlock_by`;
- `host_force_by`;
- H18's delta (n + 1)·A + (B − 1) + M_host;
- the numbers E − 50, E − 66, E − 82, E − 42 and E − 36.

No finding of the earlier reviews has been undone in substance.

Two kinds of problem remain:

1. **Real disagreements in behaviour.** These are D1 (the known penalty-file case), D2 (unlock order), D3 (when the bundle is rewritten) and D4 (Slice 1's lock echo).
2. **Mechanical follow-ups.** These are stale names, draft numbers and cross-references, and codes that one document defers and another assumes.

None of them needs a new design. D4 bears on Slice 1 and should be fixed before the lock button is built. The rest can be fixed in the next drafting pass, before Slice 3.

## 1. Disagreements

Severity is for the release that needs the part: S1 means Slice 1, 1.0 means 1.0.0 (Slice 3).

| # | Sev. | Where | Disagreement | Fix |
|---|---|---|---|---|
| **D1** | Medium, 1.0 | exit 5.6 ("`nobody_locked` stays for … a bundle or penalty file refused"), exit 10.2 (reasons `no_bundle`, `no_key_store`, `watcher_off`, `bundle_refused`), exit 11.1 item 8 ("so is a truncated `watch.gzp`" refused); against storage 8.7.4 rule 7, 8.7.5, test 26, and local-api 4.7 / 11.2 / 23.2 item 43 / 24.2 item 31 | Exit refuses a short or damaged penalty file and shows "nobody watching". Storage and the local API keep the watcher running, use what the file holds, and report `watcher_locked` with reason `penalty_file_short` (`at_risk`) | **Storage's rule is the safer one**, see below. Exit must change 5.6, 10.2 and 11.1 item 8 to match |
| **D2** | Medium, 1.0 | exit W1: "At unlock: the watcher stops and writes its last `watch.gzl` entry, then storage unlocks … If the unlock fails, the watcher starts again"; against storage 8.2 steps 1 and 2 and local-api 4.7 steps 1 and 2 | Exit stops the watcher before the key derivation. Storage and the local API derive and open the key file while the watcher keeps running, and stop it only after a correct passphrase | Follow storage. Otherwise every wrong passphrase (or a script spamming `POST /session`) pauses the watcher for an Argon2id run each time. Exit W1 should say "the key file is opened while the watcher runs; then the watcher stops …; a wrong passphrase never stops it" |
| **D3** | Low-Medium, 1.0 | When the bundle is rewritten: exit 3.3 and storage 8.7.4 rule 1 say "before confirming **any** batch that changes" B2 to B5 or B7 to B9; storage 7 step 2 and journal 4 step 4 do it only as part of an **anchored** batch. Storage 6.2 lists `funding_status` (which changes B3) as safe to lose, i.e. not anchored, while rule 1 says "both are part of the anchored batches" | Is a batch that changes only the bundle (a funding status, a date change in `exit_plan`) anchored, with a mark-file entry? There are two readings: the bundle is not rewritten for it (stale dates), or it is rewritten without a mark entry. In the second reading, a legitimate cut of the journal's unanchored tail leaves a bundle "newer than the journal", and storage 6.3 step 3 sends the start to `files_behind`. That contradicts storage test 8's "a cut that loses only batches after the newest anchored batch: accepted" | State one rule. Recommended: every batch that changes the bundle is anchored (add "a batch that changes the bundle or appends a penalty" to 6.2's table), and journal 4 step 4 says the same |
| **D4** | Medium, **S1** | local-api 4.7 and 4.8: locking while anything needs watching needs `confirm_unlock_by_height`, the warning names `[unlock_by]`, and 11.1 defines `watching.unlock_by` as "otherwise the earliest `open_by`". Against exit 10.2: "In Slice 1, `unlock_by` is `null`" | Exit says `unlock_by` is null in Slice 1; the local API needs a height to echo. `open_by` (`open_app_by` = min(`leave_by`, safe absence) − `OPEN_MARGIN`) has no Slice 1 definition: there is no channel, so no revocation window and no safe absence. Also, `GET /factories/{id}/dates` in S1 serves only `factory_ends` and `funding_deadline`. A Slice 1 member in an `awaiting_funding` or `live` factory has `watching.state = this_app`, so its lock needs an echo of a date nobody defines | Define the Slice 1 echo. Two options: (a) `confirm_unlock_by_height` is absent in Slice 1 and the lock takes `confirm: "nobody_watching"` alone; or (b) `watching.unlock_by` in Slice 1 = the earliest still-pending `funding_deadline`, else `factory_ends` − `OPEN_MARGIN`. Then exit 10.2 and local-api 11.1 must say the same |
| D5 | Low, 1.0 | exit 5.6: a deliberate lock "asked for when T ≥ `leave_by` − `WARN_LEAD` is allowed with a warning naming `unlock_by`, and its confirmation echoes `confirm_unlock_by_height`"; local-api 4.7 asks for the echo whenever `watching.state` is not `nothing_to_watch` | The local API is stricter | Exit should say the echo is always needed while something is watched (local-api 4.7), with the stronger warning inside `WARN_LEAD` |
| D6 | Low, 1.0 | exit 5.6: "While a bundle is armed, `watching.state = watcher_locked`"; local-api 11.2 precedence puts `nobody_chain_in_doubt` above `watcher_locked` while locked | With the chain view in doubt the local API says "nobody can watch". Meanwhile the watcher still runs on the clock floor of exit 4.5 and may be publishing tree steps | Either exit 5.6 adds the exception, or the local API keeps `watcher_locked` with a reason `chain_in_doubt`. The second is more accurate, since the watcher does act |
| D7 | Low, 1.0 | exit 10.2 lists the `nobody_locked` reasons without `bundle_key_unavailable`, and the `watcher_locked` reasons without `bundle_kept_as_newer` and `penalty_file_short`; local-api 4.7 and 11.2 and storage 8.7.4 rule 4 have them | Missing values in exit | Add them to exit 5.6 and 10.2 (with D1) |
| D8 | Low, 1.0 | Exit 10.2's new values: attention codes `exit_needs_fee_coin`, `payments_stopped_for_exit`, `exit_step_late`, `exit_step_held_back`, `exit_fee_budget_reached`, `exit_missed`, `funding_double_spent`, `restored_commitment_choice`, `unexplained_spend`; `creation_dead` `params.cause = funding_replaced`; `ended_how = void_funding` | None is in local-api 11.4 or 16.1. Local-api 24.2 item 28 defers them openly, but its list leaves out `exit_step_held_back`. Exit 4.7 and 7 use them as if they existed | Fold them into local-api draft 5 (11.4, 16.1 `ended_how`, section 22 rows). Until then, exit 4.7 should mark them "proposed, not yet in `local-api.md`" |
| D9 | Low, 1.0 | Factory object: exit 10.2 says `exit.transactions` is d + 3 and `exit.blocks` the lead E − `leave_by`; the local-api 16.1 example has depth 2 with `"transactions": 4`, `"blocks": 864` | The example contradicts the rule | Make the example `transactions: 5` and state the rule in 16.1's field notes |
| D10 | Low | Provenance: local-api 7.2 has `leaf_timeout_less_burial_exit_margin`; local-api 16.2 still says "Example provenance … `end_less_exit_less_margin` with the end height, the exit blocks summed … the app's margin" | Draft 3's name survives in 16.2 (a regression of exit review 4.6d inside the local API) | Rewrite 16.2's example with 7.2's code and inputs |
| D11 | Low | Step states: exit 2 says a step's state is `pending`, `due`, `sent`, `confirmed`, `buried` "(`local-api.md` 16.3)"; local-api 16.3's `exit_progress.steps[].state` also has `waiting`, and its `kind` is `tree`/`leaf`/`channel`/`sweep`, against exit's 1 fixed kickoff / 2 leaf kickoff / 3 leaf transaction / commitment | Two enumerations | One list in local-api 16.3, which exit cites; say what `waiting` means (parent not confirmed?) |
| D12 | Low, 1.0 | Bundle header: exit 5.6 B1 has types 18 `anchor_height` and 20 `anchor_time`; storage 8.7.2's B1 item list omits them. Exit B5 includes `CLIMB`; storage 8.7.2's B5 list omits it | The lists differ (exit's TLV table is normative, so storage is only incomplete) | Storage 8.7.2 should copy exit's lists or point to them only |
| D13 | Low, 1.0 | Exit 3.4: "Record names only; numbers are assigned in `journal.md` draft 3"; exit 10.3 asks journal for `exit_plan`, `exit_started`, `exit_step`, `coin_reserved`, `fee_child`, `spend_seen`, `response_sent`, `exit_ended`, `bundle_written` | Journal draft 3 assigns none of them and does not name them | Exit should say "to be numbered in `journal.md` with the channel records (Slice 3)". This blocks Slice 3, not Slice 1 |
| D14 | Low | The name **T3**: exit 4.6 and open point 1 propose "terms **T3**: lifetime 144, wind-down 252"; `terms.md` already uses T3 for a test vector ("T3. Current values, version 2", and tests 1 and 14) | One name for two things | Call the proposed terms something else (for example "T1-S3" or "the Slice 3 terms") |
| D15 | Low | Headline placeholders: the exit 5.6 and local-api 4.7 rows `unlock_before` and `nobody_watching_at_risk` say "Unlock before block [leave_by]"; the locked status carries `leave_by_locked`, not `leave_by` | The value shown is not defined | Say which: with M_locked = 0 on signet they are equal; on mainnet they differ by M_locked. Recommended: show `leave_by_locked` and add the field |
| D16 | Low | Tier of `nobody_watching`: attention item `nobody_watching` is `at_risk` (local-api 11.4); headline `nobody_watching` is `important` (4.7) | Same code, two tiers | Rename one (for example headline `nobody_watching_locked`), or state that the attention item is raised alongside |
| D17 | Low | Stale cross-references (no behaviour change) | Listed under 1.2 | — |

### 1.1 D1 in detail: which is safer, and what exit must change

**Storage's rule is the safer one.** A penalty file that is short, damaged, of another `file_id`, or impossible to open contains, by invariant T, nothing that can harm the member: every entry pays the member and needs the host's revoked state on chain first. What it lacks is only the newest entries. Refusing it and reporting `nobody_locked` has two costs:

1. **It throws away the older penalties.** Those still answer every older revoked host state, which is exactly what a host would publish.
2. **It implies the watcher stops.** Exit 5.6 puts "bundle or penalty file refused" in the list of cases where no watcher runs. So the tree path, which is in the separate and valid bundle, would also stop being published by `leave_by_locked`.

That would turn an attacker's folder-only write (cutting `watch.gzp` needs no KB, storage 8.7.5) into stopping the whole locked protection. Under storage's rule the same write costs at most the newest penalties, and the member is told at once (`at_risk`, "Unlock now: some … answers … are missing").

What exit.md must change:

1. **5.6, strip paragraph.** Make `nobody_locked` "no bundle (`no_bundle`), no OS key store (`no_key_store`), the bundle key unavailable (`bundle_key_unavailable`), the watcher off (`watcher_off`), a **bundle** refused (`bundle_refused`)". Add: "A short, damaged or unrecognised penalty file is used for what it holds; the watcher runs with `watching.state = watcher_locked`, reason `penalty_file_short`; `bundle_kept_as_newer` likewise (storage 8.7.4 rules 4 and 7)."
2. **5.6, headline table.** Add the row `penalty_file_short` ("Unlock now. Some of Gazpacho's answers to your host's old states are missing from this computer.", `at_risk`), placed as local-api 4.7 places it: after "publishing tree steps, on time" and before "old state answered". Also add the `files_behind` row, or a pointer to local-api 4.7 for the rows it adds.
3. **5.6, Can/Cannot table, first row.** Watch "the penalty file's entries, whatever the file's count".
4. **10.2.** The same reason lists.
5. **11.1 item 8.** "a truncated `watch.gzp` is reported short (`penalty_file_short`) while the watcher keeps publishing the tree path and the penalties it holds; at unlock the node rebuilds the missing entries".
6. **10.4, item 2.** Add "a short file is used and reported, never refused" (storage 8.7.4 rule 7).

Two further points:

- A **bundle** refused (counter below `bundle_counter_seen`) does stop the watcher in all three documents. By the same argument (under T an older bundle holds the same tree path, only older dates), running the watcher from it and reporting it might also be safer than stopping. I raise it as a question for the owner, not a disagreement. The cost is that an attacker could put back an older bundle with earlier or later dates. Earlier dates only make the tree publish early, which is griefing. Later dates do not exist under one tree version per output, since H_leaf is absolute. So running from an older bundle looks safe, as long as `unlock_by` is recomputed from the chain and not read from B5.
- `safety-rule.md` 11 has no exclusion for "a penalty file cut while locked, past the revocation window", which storage 8.7.5 states as a loss. Add one line.

### 1.2 Stale references (mechanical)

- **exit.md** header (line 9): "`storage-encryption.md` (draft 2 …)", "`local-api.md` (draft 3)", "`safety-rule.md` (draft 4 …)". Storage and the local API are now drafts 3 and 4.
- **exit.md** 10.4: "Draft 2 already takes in this document's position".
- **exit.md** header: cites the reviews as `notes/review-storage-encryption-d1.md` and `notes/review-local-api-d3.md`; both are archived in `docs/reviews/`.
- **storage-encryption.md** header and open point 14: the archived review "still holds round 1 only" and "archiving round 2". Round 2 is archived on this commit.
- **storage-encryption.md** "What it changes elsewhere", `exit.md` row: "its record table still carries B6 as type 20", "without a clear `next_action_height` (its 5.6 and 10.4 item 3)". Both are already done in exit draft 2.
- **storage-encryption.md** 8.7.6: "`spec/exit.md` 10.4 item 3 asked for clear copies". Exit draft 2's 10.4 item 3 says the opposite.
- **storage-encryption.md** 8.7.6: "`spec/exit.md` 10.4 item 8" for the append-only penalty file. That is item 2; item 8 is siblings.
- **safety-rule.md** companions line: "`journal.md` (draft 2 …)"; journal is draft 3. The line also does not name exit, storage or the local API, which the alignment section uses.
- **safety-rule.md** C12: "the recovery procedure … is not specified in draft 4; it belongs with the exit engine". Exit 5.7 now specifies the 1.0.0 part (ask the host; the person's choice at `host_force_by`).
- **local-api.md** change tables, draft-2 rows N2 and "Storage's requirements": "keeps watching and leaving alone", `locked_watcher`, "the one date readable before unlocking". These are kept as history, but they read as current. One line above them ("superseded by draft 4, 4.7") would do.
- **local-api.md** 7.5 and 11.3: pause applied "(4.7, step 3)". In 4.7's order it is step 7.
- **local-api.md** 7.5: the setting name `lock_after_idle_s`. Idle never locks (4.7, D13); the name should be about sign-out.
- **local-api.md** 23.1 item 22: "every call but the four of 4.7". 4.7 lists five.
- **local-api.md**: the calls allowed while locked are listed three ways (4.7 table; 4.6 with socket unlock; 23.2 item 21 without `start-as-restore`).
- **THREAT-MODEL.md**: only 2.7 was updated.
  - Its header still names rules "H1 to H13" (there are now H14 to H18).
  - 2.2's row "An old channel state against the host" does not cite H14, and exit 9.1 says H14 closes "the host's duty to respond is not written as a rule".
  - 2.4 (chain servers) does not mention exit 4.5's clock floor.
  - Section 3 ("Not defended") lacks five of `safety-rule.md` 11's new exclusions: locked past `unlock_by`; no bundle; pinning of keyless anchors; the second-stage breach while locked; and, after D1, a penalty file cut while locked.

### 1.3 Smaller notes inside one document

- exit 3.6: invariants are listed X-I5, X-I7, X-I6.
- Exit factory block type 22/24 is written "followed by 24, k class bytes". It is unclear whether 24 is a separate TLV record of the factory block or part of 22's value. The vectors promised "with draft 3" should settle it.
- local-api 7.2 example mixes a mainnet `burial` of 6 with signet `margins` of 14 and `allowance` 6.

## 2. Shared terms

"=" means the document uses it the same way; a number in brackets refers to section 1. "—" means not used.

### 2.1 States, codes and values

| Term | exit d2 | storage d3 | local-api d4 | safety-rule d4 | journal d3 / TM / MF |
|---|---|---|---|---|---|
| `watching.state = watcher_locked` | Defines (5.6, 10.2) | = (8.7.1) | = (4.7, 11.2), with precedence under `nobody_chain_in_doubt` [D6] | — | — |
| `watching.state = nobody_locked` | Includes "penalty file refused" [D1] | Short penalty file is not refused [D1] | Defines reasons; follows storage [D1] | — | — |
| Reasons `no_bundle`, `no_key_store`, `watcher_off`, `bundle_refused` | Defines | `no_key_store` (8.7.3) | = | — | — |
| Reason `bundle_key_unavailable` | Missing [D7] | — | Defines | — | — |
| Reasons `penalty_file_short`, `bundle_kept_as_newer` (with `watcher_locked`) | Missing [D1, D7] | Defines (8.7.4 rules 4, 7) | = | — | — |
| `doing.code = wallet_locked`; `params.watcher` = `watching`, `publishing_tree_steps`, `waiting_for_unlock`, `answering_old_state`, `paying_fee`, `off` | `waiting_for_unlock` only | `waiting_for_unlock` | Defines all | — | — |
| `lock.state` = `held_for_signing`, `held_for_payment` | `held_for_payment` (5.6) | "held" (8.1) | = (4.7, 11.1) | — | — |
| `wallet = files_behind` (`params.cause` `behind`, `possibly_old`) | — | Wording (6.3 step 4, 14) | Defines | — | Journal 5 step 6 = |
| `doing.code` `leaving_alone` (9), `left_behind` (10) | Uses (4.7, 5.1) | — | Defines | — | — |
| `factory.state` `exiting`, `winding_down`, `ended` | Uses | — | Defines | — | — |
| `ended_how` `left_alone`, `forced_by_host`, `host_timeout` | Uses | — | = | — | — |
| `ended_how` `void_funding` | Proposes | — | Missing [D8] | — | — |
| Attention codes of exit 10.2 | Proposes | — | Missing, deferred (24.2 item 28) [D8] | — | — |
| `branch_partly_on_chain`, `important` | = | — | = (11.4) | — | — |
| Headline rows (codes) | 5.6 table, no codes | "is `local-api.md` 4.7's table" | Codes; adds `penalty_file_short`, `files_behind`, `nobody_watching` [D1, D15, D16] | — | — |
| Date kinds `start_leaving_by`, `unlock_by`, `open_app_by`, `move_by`, `leave_step_due` | = | — | Defines (7.2) | `start_leaving_by` = `leave_by` (7) | MF 4.1 = |
| Provenance `leaf_timeout_less_burial_exit_margin` | Defines (10.2) | — | 7.2 =; 16.2 stale [D10] | — | — |
| Exit step states and kinds | 2, citing local-api 16.3 | — | 16.3, adds `waiting` [D11] | — | — |
| `exit.transactions`, `exit.blocks` | d + 3; lead | — | Example 4 at d = 2 [D9] | — | — |
| `exit_started` reasons, incl. `deadline_while_locked`, `host_forcing` | Defines (5.1, W3) | — | — | — | — |
| `confirm_unlock_by_height`, `confirm_leave_by_height` (W5) | = | — | = | — | — |
| Slice 1 `unlock_by` | `null` | — | Earliest `open_by` [D4] | — | — |

### 2.2 Records, files, bundle fields and constants

| Term | exit d2 | storage d3 | local-api d4 | safety-rule d4 | journal d3 / TM / MF |
|---|---|---|---|---|---|
| Exit records `exit_plan` … `bundle_written` | Defines names | — | — | — | Journal: absent [D13] |
| Anchored families | CH-10 adds preimage, commitment and revocation records | Defines (6.2) | — | — | Journal 4 step 4 = (bundle rewrite only when anchored) [D3] |
| Files `watch.gzw`, `watch.gzp`, `watch.gzl`, `mark.gzm`, `guard.gzg`, `keys.gzk`, `journal.gzj`, `attempts.gza` | Uses the watch files | Defines (3.1) | Uses | — | Journal 8.3 =; TM 2.7 = |
| Magics `GZWATCH1`, `GZPENALT`, `GZWATLOG` | — | Defines | — | — | — |
| Bundle top-level types 2, 4, 6, 8, 10 | Defines | "exit's TLV stream" | — | — | — |
| B1 types 2 to 20, incl. 18 and 20 (tip anchor) | Defines | Item list omits 18, 20 [D12] | — | — | — |
| B5 constants incl. `CLIMB`, `u16` | Defines | Omits `CLIMB` [D12] | — | — | — |
| Factory block types 2 to 24, 20 withdrawn | Defines | = (no B6) | — | — | — |
| Penalty entry types 2 (`journal_file_id`), 4 (`sync_mark_offset`), 6, 8, 10, 12 (`send_by_delta`), 14 | Defines | = (8.7.6; E13p uses 2, 4 and odd 99) | — | — | — |
| Store record: `bundle_counter_seen`, `penalty_file_id`, `penalty_count`, `attempts_counter` | "count in the OS key store" | Defines (8.7.3) | — | — | TM 2.7 = |
| Constants B 3, A 6, M_safe 6, M_lag 2, M_spike 6, M 14, M_locked 0, M_host 8 | Defines (4.3) | B5 = | Example inputs = | 12 value 6 = | MF = |

### 2.3 Deadline formulas

| Term | exit d2 | storage d3 | local-api d4 | safety-rule d4 | MF |
|---|---|---|---|---|---|
| H_leaf = E − 10·d; kickoff E − 5·(2j − 1) | Defines (4.1) | Uses H_leaf | 7.2 = | C5, 12 value 2 = | 4.1 = |
| `leave_by` = H_leaf − (B − 1) − n·A − M, n = d + 3 | Defines (4.4) | — | 7.2 inputs = | C8, 7 = | 4.1 = |
| `leave_by_locked` = `leave_by` − M_locked | Defines | Uses | Uses | — | — |
| `unlock_by` (`unlock_commit`, `go_on_chain_by`, `second_stage_unlock_by`) | Defines (5.6) | Uses | Uses | 11 = | — |
| T1 numbers E − 50 / E − 66 / E − 82; `unlock_by` E − 42 (E − 54 when late); `host_force_by` E − 36 | Defines (X3) | — | — | 12 value 6 = | — |
| C8 signing check: `leave_by` ≥ funding deadline + B + 1 | 4.4 | — | — | C8 = | — |
| `penalty_send_by` = c + W − B − A − M; `send_by_delta` = W − B − A − M | = | B6 "send-by delta" | — | H14 = | — |
| H18 delta (n + 1)·A + (B − 1) + M_host; `min_final` (n + 1)·A + (B − 1) + M | Defines | — | — | H18 = | (d + 4)·A … = |
| `move_by` E − 212 (d ≤ 3, signet), 807 at mainnet example | X9 | — | — | — | 4.1 = |

### 2.4 Rules and names

| Term | exit d2 | storage d3 | local-api d4 | safety-rule d4 | journal d3 / TM / MF |
|---|---|---|---|---|---|
| Unlock order | W1: watcher stops first [D2] | 8.2: key file first, while the watcher runs | 4.7 = storage | — | — |
| W3: log merged as untrusted; decision from the chain; commitment first, whatever the pause | Defines | 8.2 step 6 = | 4.7 step 6 = | — | — |
| Invariant T ("revoked or superseded"; "cannot move value away … can cost fees and off-chain places") | 5.6, W2, X-I4 = | Defines (8.7.2) | — | — | TM 2.7 = |
| Siblings' cost (funds, channel, H_leaf untouched; lose cheap rotation and whole-factory close; may pay a sweep fee) | Defines (7.1) | 8.7.5 = | 11.4 = | — | — |
| Fee coin released only by spending it | W2 = | Defines | — | — | — |
| Bundle rewrite trigger | Any changing batch | 8.7.4 rule 1: any; 7 step 2: anchored [D3] | — | — | Journal: anchored |
| "Maximum privacy" refusal (W5) | Defines | 8.7.5 = | 4.8, 20.2 = | 11 = | — |
| H14 to H18 | Defines (9) | — | — | 10 = | TM: H1 to H13 only (1.2) |
| Exclusions while locked | 5.6 | 8.7.5 (also the short penalty file) | 4.7 | 11: missing the short-file case [1.1] | TM 3: missing (1.2) |
| T3 (terms) | Proposed Slice 3 terms | — | — | — | `terms.md`: a vector name [D14] |

## 3. Earlier findings: still answered?

### 3.1 `review-exit-d1.md`

| Finding | Status in exit d2 and companions |
|---|---|
| F1 tip estimate | Answered: 4.5 T_dl with the clock floor, counted claims, grace, X5 |
| F2 freeze | Answered: 5.3 steps 0 to 2, X-I3, CH-8, 11.1 item 12 |
| F3 pinning | Answered: 6.4 rule 5, 6.5 table, X8; `safety-rule.md` 11 states the gap. TM 3 does not (1.2) |
| F4 second stage | Answered: 4.4, CH-5 ladder, `second_stage_unlock_by`; storage 8.7.2 B6 and 8.7.5; `safety-rule.md` 11 |
| F5 spend classes | Answered: S9 to S11, watching by outpoint, 10.5's `event.h` changes |
| F6 `unlock_by` | Answered: recomputed from missing steps, rows for a late step and `waiting_for_unlock`, "never unlocks" paragraph, "cannot change a stored date or constant", "commits the member to leaving" |
| F7 siblings | Answered: 7.1, the same words in storage 8.7.5 and local-api 11.4 |
| F8 host side | Answered: H18, H15 row 2 corrected, H17 "normally", H16 requires a change output or P2A |
| F9 T3 | Answered in arithmetic (E − 212, wind-down 252, X9); the name collides with `terms.md` [D14]; terms not yet added (exit 10.5 says so) |
| F10 coinless payments | Answered: 4.4, `UNPROTECTED_MAX`, CH-6 |
| F11 depth prose | Answered in exit 4.2. `notes/factory-paths.md` is still wrong (exit 10.5 lists it; outside this branch's specs) |
| F12 restore vs `DESIGN.md` 6 | Answered: `DESIGN.md` 6 now says "never … automatically" |
| F13 ordering | Answered: W3 "as soon as the leaf transaction is confirmed"; log before each broadcast; decided from the chain |
| F14 encoding | Answered: B5 `u16`, 6.6 example, checklist 1 to 17, X-I7 |
| F15 constants | Answered: `safety-rule.md` C8, 7, 12 value 6 |
| Section 4, items 1 to 4 | Answered (safety rule, `MULTI-FACTORY.md` 4.1) |
| Item 5 (`factory-paths`) | Open, listed in exit 10.5 |
| Item 6 (local API a to f) | Answered in local-api 4.7, 7.2, 11.2, 11.4. Item (d) regressed in 16.2 [D10] |
| Item 7 (storage a to d) | Answered |
| Item 8 (`DESIGN.md`) | Answered (6 and 8) |
| Item 9 (`event.h`) | Listed in exit 10.5 (code change, not a spec) |
| Item 10 (tree-fees hand-off) | Listed in exit 10.5 |
| Item 11 (inside exit) | Answered |

### 3.2 `review-storage-encryption-d1.md`, round 2

| Finding | Status in storage d3 and companions |
|---|---|
| R2-1 penalty freshness | Answered (store record, `penalty_count`, rule 7, E13p, test 26). Not yet followed by exit [D1] |
| R2-2 journal and guard deleted | Answered (6.3 step 0, 7.4, test 8; journal 8.2 =) |
| R2-3 invariant T | Answered (8.7.2; exit 5.6 and 10.4 item 1 =) |
| R2-4 penalty journal position | Answered (8.7.6, E13p; exit penalty entry types 2 and 4; type 20 withdrawn) |
| R2-5 local API and exit on the draft-1 watcher | Answered in local-api d4. Exit W1's unlock order is still the old one [D2] |
| R2-6 helper swap | Answered (8.3, 8.4) |
| R2-7 host families, preimages | Answered (6.2; exit CH-10) |
| R2-8 write cost | Answered (append-only `mark.gzm`, E9m; journal 4, 8.3 =) |
| R2-9 attempts replay | Answered (12.3, E14) |
| R2-10 Windows token | Answered (12.2, 8.5) |
| R2-11 rekey | Answered (4.8) |

Round 1 findings F1 to F25: round 2 marked all fixed except F3, F6, F20 and F21, which draft 3 closes (R2-4/R2-7, R2-2, R2-9, R2-10). I found nothing in draft 3 that reopens any of them.

### 3.3 `review-local-api-d3.md`

R1 to R12 are all answered in local-api d4 4.3, 4.7, 4.8, 7.4, 11.2, 20.2, 22 and 23. Its section 4 table now agrees row by row with storage and exit, except:

- the penalty file [D1];
- the lock echo in Slice 1 [D4].

Draft 4's own small leftovers are in 1.2.

### 3.4 `review-local-api-d1.md` and `review-local-api-d2.md`

F1 to F24, G1 to G14, N1 to N16, gaps 1 to 9 and the D defaults the d2 review changed were checked against the d4 body, by a delegated read of the sections they concern. All are still answered in the body. The exceptions are wording leftovers, none of them a behaviour regression:

- 16.2's provenance name [D10];
- 7.5's `lock_after_idle_s` name (F9);
- the pause "step 3" reference (G9 and gap 9);
- the N2 change-table row still describing the draft-2 watcher.

No cookie, no 5-minute window on a spend, no `locked_watcher`, `confirm_open_by_height` or `lock_held` survives outside history notes.

## 4. The locked 1.0.0 member with a balance, end to end

A member at d = 2 in T1-like terms with a channel balance, from a lock to an unlock or a loss. Each step lists where it is specified and whether the documents agree.

1. **Before locking.** The unlocked node keeps `watch.gzw` current and appends each host revocation's penalty ladder to `watch.gzp` with its journal position and the store count.
   - exit 3.3, 3.4, 5.6, CH-5;
   - storage 7 step 2, 8.7.4 rule 1, 8.7.6;
   - journal 4 step 4.
   - **Agrees, except D3** (is a bundle-only batch anchored?).
2. **Deliberate lock.**
   - Held for signing or a released payment secret: exit 5.6, storage 8.1, local-api 4.7. Agree.
   - Refused while an Open hosted lobby exists: local-api only, consistent.
   - The echo: D5 (exit is looser than the local API).
   - At lock, the bundle and penalty file are checked current with the store record: storage 8.7.4 rule 3, exit W1. Agree.
3. **Unplanned restart.** The program starts locked; only KB subkeys are in memory; the watcher opens the bundle and the penalty file and checks the counters.
   - storage 8.1, 8.7.3, 8.7.4 rule 7; local-api 4.7.
   - A cut penalty file: **D1**.
   - A missing key store or unavailable key: `nobody_locked`, consistent (exit lacks `bundle_key_unavailable`, D7).
4. **Watching while locked.** The tip estimate starts from B1's anchor (exit 4.5, B1 types 18 and 20; storage omits them from its item list, D12).
   - The status serves `leave_by_locked`, `unlock_by` and `next_action` only after the same-user check (local-api 4.7; storage 8.6 item 3).
   - Headline `unlock_before`. Its "[leave_by]" placeholder: D15.
   - With the chain in doubt, the local API says `nobody_chain_in_doubt` while the watcher still acts: D6.
5. **`leave_by_locked` reached.** The watcher publishes the tree path with anchor-only children, logging before each broadcast, and climbs the fee ladder if fee coins were set aside.
   - exit 5.3 step 3, 5.6, 6.2, 6.6; storage 8.7.1; local-api 4.7 (`publishing_tree_steps`).
   - **Agrees.** When every tree step is out: `waiting_for_unlock` in all three.
6. **The host misbehaves while the member is locked.**
   - **Pins a tree step's anchor** (6.4 rule 5): the watcher cannot out-pay it. Headline `tree_step_late` ("Unlock now …"), with `unlock_by` recomputed from the missing steps. exit 5.6 and local-api 4.7 agree.
   - **Publishes a revoked commitment** (S5): the watcher broadcasts the pre-signed penalty ladder from `watch.gzp`, one rung per `CLIMB` (exit 5.6, 8; storage 8.7.1; headline `old_state_answered`). Agree. With a short file, the penalties it lacks are missing: D1, and safety-rule 11 lacks the line.
   - **Moves the revoked state's payment outputs to the second stage:** only the unlocked node can answer, by `second_stage_unlock_by`, which enters `unlock_by`; headline `second_stage_after_breach`; loss bound in exit 4.4, storage 8.7.5 and safety-rule 11. Agree.
   - **Times out the channel output after H_leaf** (S2): loss. Headline `deadline_passed_while_locked`; safety-rule 11. Agree.
   - **Gap: the host forces the member out with its own current commitment while the member is locked** (S4, H-a, or H17 at `host_force_by`). None of the three documents gives this case a headline row or a `params.watcher` value. By first match the strip would then show `waiting_for_unlock`, "After block H_leaf the host can take this balance", which is no longer true once the host's commitment is confirmed. The balance is then safe in the member's output, with no deadline, except incoming payments with released secrets, whose `go_on_chain_by` already sits in `unlock_by`. Exit's Can/Cannot table says the watcher records S1 and S9 but not S4. **Add:**
     - S4 to the watcher's "record" row;
     - a headline row "The host closed this channel. Your balance waits for you; unlock to collect it" (`important`, or `at_risk` while a released payment is pending) above `waiting_for_unlock`;
     - the matching local-api code.
7. **Unlock.**
   - **Order: D2.** Storage and the local API keep the watcher running through the derivation; exit W1 does not.
   - After that, the three agree step for step: journal and start rule; node; chain servers; `watch.gzl` merged as untrusted input; W3's decision from the chain (leaf kickoff or leaf confirmed, channel output unspent, something to take out); `exit_started` with `deadline_while_locked` or `host_forcing`; commitment first, whatever the pause; then the pause, the dates that passed, and the hosts.
   - Files behind: `files_behind`, the watcher again from `.newer` (storage 6.3 step 4; local-api 4.7; exit 5.7 item 4). Agree.
8. **Never unlocking.** The tree path is out and penalties are answered. An honest host forces the member out by `host_force_by` (H17), so the balance waits. A dishonest host takes it from H_leaf + 1. Released incoming payments are lost after h; second-stage outputs after W.
   - exit 5.6, 9.3; safety-rule 10 and 11; storage 8.7.1.
   - **Agree.** TM 3 does not list it (1.2).

Each step is specified once, in exit, and adopted by reference elsewhere, except:

- the unlock order (two versions, D2);
- the penalty-file case (two versions, D1);
- the missing host-closed-while-locked row (step 6).

## 5. Slice 1 readiness

Slice 1 has no locked watcher, no automatic exit, and members owed nothing.

### 5.1 What Slice 1 builds from these documents

- **exit.md.**
  - 4.1 to 4.4, for the signing-time check only: H_leaf, `leave_by` with all steps missing, against the funding deadline + B + 1.
  - The constants of 4.3 copied into the factory's records.
  - 5.1's "nothing to take out" rule (no exit is armed).
  - 5.6's Slice 1 paragraph: `nobody_locked`, `no_bundle`, the Slice 1 headline.
  - Vectors X1 to X3.
  - 4.5 (tip estimate) and 6.2 (anchor-only child) are needed only from Slice 1.5's exits and host recovery; exit's own header lists them with Slice 1, but Slice 1's C8 check uses heights, not the estimate.
- **safety-rule.md.** C1, C2, C5 (reduced), C6 (one tier), C7, C8 (with the new end-height row), C8a, C10, C11, C12 and section 9; H1, H2, H8, H11, H12, H13; section 12 values 1 to 6.
- **storage-encryption.md.** Everything except 8.7:
  - the passphrase rules, Argon2id in the helper, the key file, subkeys, the sealed journal;
  - the mark file and anchored batches (Slice 1 families: `guard`, `exposure`, `round_signed`, `funding_signed`, `start_sent`);
  - the guard file, the start rule (6.3 including step 0 and `files_behind`), crash order, the attempts file, the log, the socket token, 8.1 to 8.6;
  - vectors E0 to E11, E14, E15.
  - Exports are 1.0.0 (the local API's export answers `export_needs_encryption` and is outside 2.1).
- **journal.md draft 3.** All of it, on the encrypted format.
- **local-api.md.** The 2.1 subset, including:
  - `POST /wallet/lock` and `start-as-restore`;
  - the locked shape with `nobody_locked` / `no_bundle` and headline `nothing_needs_you`;
  - `files_behind`, the unlock order with the watcher steps doing nothing.

### 5.2 Still undefined or contradictory for Slice 1

1. **The lock echo (D4).** `POST /wallet/lock` in a Slice 1 factory needs `confirm_unlock_by_height`. Its value, the earliest `open_by`, has no Slice 1 definition, and exit says `unlock_by` is null. This must be decided before the lock call is built.
2. **Does Slice 1 create KB and the store record?**
   - Storage 7.4's creation order makes KB and stores it with the store record.
   - The attempts file uses mode 2 (KA from KB) "whenever KB is available".
   - Slice 1 writes no bundle, and test 22 says `no_bundle` "whatever the store".
   - What none of them says: whether Slice 1 requires an OS key store at all. On the headless Linux build server, which runs the Slice 1 walkthrough, there is no Secret Service and no systemd credential unless one is set up. There the attempts file falls to mode 1 with no replay protection. One sentence is needed: either Slice 1 makes KB where a store exists (for the attempts file only) and runs without one otherwise, or Slice 1 skips KB.
3. **Record type numbers for the API's saved state** (activity entries, request ids, set-aside funds, conditions copies, pause). Local-api 7.5 needs them in Slice 1; journal open point 9 leaves the numbers to `OPEN-QUESTIONS.md` W3. This is a known open point, but it is on Slice 1's path.
4. **Owner choices** that Slice 1's set-up screen and storage depend on, listed as open in storage 18:
   - the blocklist and the six-word passphrase list (point 3);
   - utf8proc for NFC in C (point 2);
   - libsodium 1.0.21 and the Argon2id parameters (point 1);
   - the two pending amendments of owner decisions 13 and 14, which Slice 1 already contradicts: export format; "after lock only the watcher runs", which in Slice 1 is "nothing runs", consistent with decision 14 as written.
5. **Not blocking, but to keep straight.** Exit's header says Slice 1 "can be built from sections 4.1 to 4.5, 6.2". In practice, 4.5 needs chain-port header checking that exists only in tests (exit 4.5's own note, `gz_header_links`). Slice 1 can do without it; Slice 1.5 cannot.

Everything else Slice 1 needs is defined, and the documents agree on it:

- the C8 numbers (E − 50 / − 66 / − 82 against T1);
- the encrypted journal's formats and vectors;
- the start rule and `files_behind`;
- the Slice 1 locked status.

## 6. Spec vectors

`python -I tools/spec-vectors.py` was run in a temporary detached worktree of `origin/specs-slice1` at `47e831e` in a scratch folder. The worktree was removed afterwards.

**Result: exit code 0** after 6 minutes 46 seconds. The run printed both completion lines, "storage-encryption.md: section E done" and "exit.md: section X done", with no failure, assertion or traceback. Every section ran: the earlier sections (messages, terms, journal, discovery D0 to D30), then E and X1 to X9.

These printed numbers were checked against the documents:

| Vector | Printed | Matches |
|---|---|---|
| X3 `leave_by` | E − 50, E − 66, E − 82 at d = 1, 2, 3 | exit 4.6; safety-rule 12 value 6 |
| X3 `host_force_by` | `leave_by` + 6 with every step missing | exit 9.3 |
| X3 `unlock_by` at d = 2 | E − 42 on time; E − 54 with 3 steps missing and late; E − 48 with 2 missing and late | exit 5.6 |

The vectors cover arithmetic and the formats of section E. They do not exercise any of the disagreements above. Penalty-file handling, the unlock order and the lock echo are behaviour, and have no vectors.
