# Review of PR 9 (`m1a-followup`, b3d9312 on 0d6c191): core frame follow-up

Reviewer: independent agent, did not write the code. Date: 2026-11-12.
Work done in `/root/gz/review-m1a/rv3` on the build server (a `git archive` copy of
`/root/gz/gazpacho` at b3d9312, gcc 15.2, valgrind 3.26). Nothing pushed, committed
or posted. Reviewer programs: `rv3/rfuzz.c` (runner against my own model),
`rv3/ntest.c` (stepped start), `rv3/sectest.c` (secret invariant), `rv3/iso.c`,
`rv3/iso.sh` (isolation probes), `rv3/mut.py` (99 mutations), logs `stepA.log`,
`stepB.log`, `stepC.log`, `mut.log`.

## Verdict

**Merge after fixes.** The runner itself is in good shape: 25 million random
operations against an independent model of the contract found no difference, and
it is clean under ASan/UBSan and valgrind. The builder's claims about tests and
seed runs are true and reproduce exactly. But four things need fixing before
merge. Two are in the stepped start: a reply can be recorded as sent without ever
being sent, and a start can be stuck for good. One is the secret invariant, which
judges the wrong thing. The fourth is a set of test and claim gaps, including
an untested one-byte overflow guard in the runner and an untested stack-overflow
guard in the node. The isolation check is better than before, but it is still a
deny-list and can be fooled in at least 14 ways.

## What I verified (the builder's claims)

| Claim | Result |
|---|---|
| 27/27 tests in Release (19 + 8 valgrind) | **Confirmed**, 49.5 s. 3 warnings in the build are all in imported/secp code. |
| 19/19 under ASan+UBSan | **Confirmed**, 75.8 s. |
| 20,000 seeds x 400 steps, 0 failures | **Confirmed** (profile 0, seeds 1001..21000, 168 s). Every total matches the builder's `seeds-followup.txt` to the digit (sent 8869961, stale 485471, restores 39950, ...), which also shows the run is the same across separate builds and runs. |
| 55 break-checks, 54 caught, s55 judged equivalent | I read `/root/gz/scratch/mut5.log`: every listed entry is killed except s55. I did **not** re-run `mutate5.py`, because it writes to `/root/gz/mut5`, which is outside my allowed area. I tested s55 myself (see F9). |
| New faults happen in seed runs | Restores, link changes, reorganisations, clock jumps and dropped stale events all have non-zero counts, and profile 0 `CHECK`s that each one is non-zero. **But** `restore_repeats_random` never has an observable effect in a seed run (F4, S37). |
| Same seed, same run across builds | **Confirmed** for gcc at -O0, -O1, -O2, -O3 -funroll-loops, -Os, ASan/UBSan, -fwrapv -fno-strict-aliasing -fstack-protector-all, and -O3 -march=native. Both known-trace digests match, and the digests combined over all seeds match for profiles 0, 3 and 7. I could not test -m32 (no 32-bit libc on the server) or clang (not installed). |
| Isolation check hardened, 3 documented not-caught cases | The 3 documented cases do pass, as stated. 14 of my 20 probes also pass, and none of them are documented (F6). |
| "start saves its sent records last, in steps of their own" | True in the code (node.c:214-238). This is also the cause of F2. |

## Findings, ranked by severity

### F1 (high): the stepped start can record a reply as sent that it never sent

`start_step` makes two passes over storage (node.c:214-238). Pass 1 resends replies
chunk by chunk. Pass 2 resets `start_done_to = 0` (node.c:232) and walks storage
**again**, choosing the "sent" records it saves from what storage holds **now**
(`pick` and `record_resent`). If a ping record becomes durable between the two
passes, pass 2 records it as sent, even though pass 1 never resent its reply.

Reproduced in `ntest.c` N1: storage holds ping 1; the first start step resends it;
ping 2 then becomes durable; the start completes. Result: the reply to ping 2 was
sent **0 times** and recorded as sent **once**. After that, nothing ever sends it.
This breaks the at-least-once guarantee in node.h:28-42.

When can storage change during a start? The start's own saves already land between
steps, so the storage the start reads is not stable. A batch from the dead program
can also land late. runner.h:85-89 says such a batch "may or may not have become
durable; the restarted node finds out from storage". Neither ports.h nor runner.h
says that storage must be fenced, or that the reader must show a fixed set during
a start. The simulator cannot produce this case, because `rebuild` throws away
everything pending before the start (sim.c:835-837). So the 20,000 seeds say
nothing about it.

Fix, either:
- in pass 2, record only serials no higher than the largest one pass 1 resent; or
- save each chunk's record in the step after its resend; or
- state a fence duty for storage and the reader.

Add the N1 case as a test either way. Engines will copy this pattern.

### F2 (high): a start with more than 256 unsent replies can never complete, and node.h forbids the way out

Each step of the recording pass saves one batch of up to 8 serials. node.h:99 says
"No event may be given to the node before a call has set `*more` to 0". So during a
start, no confirmation reaches the node, and in the simulator none reaches the
runner either. After 32 batches, the 33rd is refused (`GZ_RUNNER_MAX_UNCONFIRMED`).
32 x 8 = 256.

`ntest.c` N2:
- **Mode 0** (how the simulator does it): 256 unsent replies start fine. With 257,
  step 66 is refused (`GZ_ERR_REFUSED`). The start is then fatal, so every later
  start fails the same way: the node can never start again.
- **Mode 1** (storage confirms to the runner between steps, but the node gets no
  event): the node's own `GZ_NODE_MAX_AWAITING` ring fills instead. With 513 unsent
  replies, step 130 fails with `GZ_ERR_NO_SPACE`, again for good.

No document states either limit. The sim never gets near 256, so the seed runs
cannot see the problem. The placeholder makes this unlikely, but the same shape
(resend everything, then save records in bounded batches, with no events allowed)
will hold real engines' starts.

Fix, any of:
- put more serials into each batch (a save may carry many records);
- let a start pause and continue after confirmations, and say so in node.h;
- document a hard bound and test it.

The question "can a save in an early start step hold later sends for ever?" is
answered **no**: no send comes after a start save in the same start.

### F3 (high for the coming signing work): the secret invariant judges draws, not secrets

ports.h:20-36 and the test comment at test_sim.c:962-983 say the draw log lets a
harness check that "a one-time secret is never produced twice".
`test_a_repeating_generator_exposes_a_naive_node` proves less than that.
`sectest.c` copies `no_secret_twice` verbatim and runs three nodes through a
restore that makes the random port repeat:

| Node | Secrets used | Repeated | Invariant says |
|---|---|---|---|
| naive, draws tagged SECRET | 3 | 1 | "drawn twice" (correct) |
| naive, draws tagged OTHER | 4 | **2** | **nothing wrong** |
| careful, tagged SECRET, mixes its never-repeating incarnation into the secret | 3 | **0** | **"drawn twice"** (false alarm) |

So the invariant fails a correct design and passes a naive node that tags its draw
differently. That answers item 3: the test does fail for a naive node, but it does
**not** pass for a correct design.

A secret can also repeat with no draw at all. For example, a nonce made
deterministically from a key and a counter kept in the journal will repeat after
a restore, because the restore rewinds the counter. The draw log sees nothing in
that case.

Fix: the invariant must look at what the node actually uses, such as a log the
node declares of its secrets, or the nonces in its outgoing messages. Change the
ports.h wording to match. The test must include a correct node that passes under
`restore_repeats_random`.

### F4 (medium): `restore_repeats_random` does nothing that any seed run can see (checklist 11)

Profile 7 sets the flag, but no node used in the seed runs ever draws from the
random port: the ping node and the multi node both ignore it. No seed run has a
secret invariant. Mutant S37 (scheduled restores never repeat the generator)
survives. So do S05 and S06 (which stream is repeated, and the restore-to-nothing
case). Only the one hand-driven test exercises the fault.

### F5 (medium): two memory-safety guards have no test

- **N16**: remove the length upper bound in `is_ping_record` (node.c:117-118) and
  every test still passes, including ASan. With that bound gone, a stored record
  longer than 24+64 bytes makes `resend` call `add_pong` with a payload over 64
  bytes, which overflows the stack buffer `reply[68]` (node.c:68-70). Storage is
  input that can be damaged (checklist 20). Add a test with an oversized record.
- **R28**: change the compaction condition in `enqueue` (runner.c:78) by one, and
  a held payload is written one byte past `n_bytes` whenever exactly one byte is
  missing. The mutant survives every test, including ASan. The reason is that
  test_runner.c:206-213 keeps `bytes[4096]` inside a struct, followed by other
  fields, so the overflow lands inside the object where ASan cannot see it. My own
  fuzz uses exactly sized `malloc` blocks, and it passes on the real code. Give the
  runner tests exactly sized heap blocks, or a guard canary after the block.

### F6 (medium): isolation check, 14 of 20 new probes pass

`iso.c` holds the probes, built with the core's exact flags. Results are the same
at -O2 and -O0, except case 13.

**Passed the check (not caught):**
1. `lsl` (processor number), written as inline assembly whose keyword is pasted
   together, so the source scan misses it.
3. A call to an outside function named `__sanitizer_now`. The `__asan_*`,
   `__ubsan_*` and `__sanitizer_*` exemptions (check-core-isolation.sh:58) apply
   **in ordinary builds too**. Demonstrated: the core read the host's clock.
4. `rdpid` through `__attribute__((target))`, with no assembly.
5. `rdfsbase` followed by reading the stack canary: per-process randomness with no
   assembly and no `%fs:` operand.
6. `xbegin`/`xend` (hardware transactions).
7. A function pointer computed as `memcpy + offset`. Demonstrated: the core called
   `time()`.
8. The vsyscall `time` entry, its address assembled at run time. Demonstrated on
   this kernel: the core read the clock.
9. Inline assembly in an included header. The source scan reads only the listed
   `.c` files.
10. `sldt` via the pasted asm keyword.
11. State carried from one call to the next in dead stack memory. Demonstrated:
    41 went in, 41 came out, then 42 and 42.
13. A constructor at -O2. (At -O0 it is caught as `.init_array`.)
16. `stmxcsr`. 17. `rdsspq`. 18. `sgdt`. 19. An `ifunc` resolver.

**Caught:** 2 (`.bss`), 12 (`rdtsc`), 20 (`__cpu_model`).

**Gaps in `--sanitized` mode:** with that flag, case 2 (`.bss` under an `__asan_`
name) passes, and so do 1 and 3.

**False positives:** honest `static const` tables of pointers or functions (cases
14 and 15) are refused as "writable data" in `.data.rel.ro.local`. Engines will
want such tables, and the check will refuse them.

**What follows:**
- Cases 3 and 7 are cheap to close. Allow the sanitizer prefixes only with
  `--sanitized`. Refuse arithmetic on function addresses where possible, or
  document it.
- The rest show what checklist 5 asks for: the instruction scan should be an
  allow-list of mnemonics the compiler emits for this code, not a deny-list.
- The source scan should read the preprocessed output (`-E`), not the raw files.
- Add these probes to the "documented not caught" list, or catch them.

Mutating the check itself (17 mutations, see the mutation section) left 9
survivors. Several deny-list entries (`sysenter`, `rdseed`, `rdtscp`, `%gs:`,
`__asm`/`asm`, the absolute-operand call, weak *definitions*) have no negative
case at all.

### F7 (medium): event-dropping rules are untested in both directions, and the user-command rule is an unrecorded decision

- **S02** (a message does **not** outlive a crash) survives. sim.h:38-43 claims
  queued messages reach the rebuilt node, and nothing tests it.
- **S03** (a user command **does** outlive a crash) survives, so the rule that drops
  user commands is untested too.

On the rules themselves:
- Messages and chain events are safe to hand to the successor: the start re-watches
  first, and the engine must accept messages twice and out of order anyway.
  Delivering a dead program's `SCRIPT_SPENT` is right. Otherwise a spend in a
  block mined between the crash and the re-watch would be lost.
- Old-incarnation confirmations are routed to the new runner, reported stale, and
  kept from the node, which is correct.
- A **user command** silently dropped at a crash is a product decision the design
  does not record (checklist 25). The user gets no answer and no error.
- `PEER_*` events are dropped, which is fine, because the rebuild tells the node
  its links again.

### F8 (low-medium): smaller claim and test gaps

- **S35, S36**: `gz_storage_reader_t.incarnation` and each batch's `id` are never
  used by the node and never checked by a test. Mutating the reader to report 0
  survives. ports.h:72-73 ("every batch in storage has a smaller one") is
  untested. Either use these fields or say they are for engines.
- **N01** (the awaiting ring writes the wrong slot after wrap-around) survives.
  No test has the ring's head and count cross 65.
- **N25** (a confirmation removes two batches when more than 60 are awaiting)
  survives. No test confirms with that many outstanding.
- **N14, N15**: the rollback of `start_done_to` and `start_recording` on a start
  error is untested. It matters only if the program retries a step, which node.h
  forbids, so either delete the rollback or test it.
- **S21** (start steps continue after the program died in an earlier start step)
  and **S27** (an armed crash survives a rebuild) both survive. They only affect
  the harness.
- **Portability**: CMakeLists.txt adds `-mgeneral-regs-only` to the core
  unconditionally. GCC accepts it only on x86 and AArch64. On ARMv7, RISC-V or
  POWER the core will not build. The instruction scan is skipped off x86, and
  check-sneaky.sh skips every x86 case, so on those machines a "PASS" checks
  symbols and sections only. CI runs x86 only.

### F9: is s55 really equivalent?

**Yes, in this simulator, and only because the simulator never fails storage
synchronously.** I removed `gz_runner_storage_failed` from `fail_storage`
(sim.c:332) and compared the complete output of the seeds test. It was
byte-identical for 3,000 seeds of profile 0, 1,000 of profile 3, 3,000 of
profile 7 and 1,000 of profile 9 (40,820 storage failures in the last one).

Why: `fail_storage` is called only from `settle_storage` and `sim_fail_storage`,
always outside the executor, and is always followed at once by a rebuild that
throws the runner away. Whether the runner was told cannot show.

So the mutant is equivalent, but that exposes a gap: the simulator never models
the case runner.h:74-79 was written for. That case is a write that fails inside
the executor, after which the rest of the list must not be carried out. Only
test_runner.c covers it (F2 and F3 in the builder's set). Add a simulator fault
that fails a save synchronously inside `storage_accept`. s55 then stops being
equivalent.

### Items checked with no defect found

- **Runner contract (item 1).** `rfuzz.c` compares `gz_runner` with a model I
  wrote from DESIGN.md section 4 and runner.h. It compares order **and** content
  (kind, ids, payload bytes, batch id, how many held while executing). Each
  operation is chosen at random from: submit, confirm (in order, repeated, skipped,
  zero, never issued, future incarnation, stale), storage failure from inside the
  executor at a random action, re-entry from inside the executor (submit, confirm,
  stale confirm), and crash/restart under a larger incarnation. Capacity is drawn
  from 0, 1, 2, 3, 5, 8 or 64 slots and 0 to 400 bytes, so zero-capacity runners
  are included. Lists are overwritten with 0xee after submit.
  - First run: 25 million operations, 0 mismatches (8 x 2M plain, 3 x 1M ASan/UBSan,
    0.2M valgrind). That run never reached 32 unconfirmed batches.
  - Second run, steered to reach it: 13 million operations, 0 mismatches. Submits
    made at exactly 32 unconfirmed: ~3,900. Submits with freed bytes at the front
    of the block (compaction): ~430,000. Up to 64 actions held at once.
  - Re-entry was always refused correctly.
  - A zero-slot runner is safe: `fits` refuses before `slot_at` could divide by 0.
- **Stepped start under crashes (item 2).** `ntest.c` N6: 3,000 random runs, a real
  runner and a journal of my own, 740,076 pings, 156,062 crashes (35,874 of them
  during a start, at any step, including inside a release). Durable ping records
  whose reply never left: 0. Duplicates beyond at-least-once are expected and
  stated in node.h. The "sent" record is never written before its reply is
  released, both in normal running (runner.c releases inside the same confirm,
  before the node's event) and at start (resends go out at once, because a new
  runner has no unconfirmed batch). The only exception is F1.
- **Incarnation duty (item 3).** runner.h states it honestly, including that a
  repeat cannot be detected and what a restore requires. The simulator keeps the
  counter outside storage, which is the header's first option.
- **Memory (item 10).** Clean under ASan/UBSan and valgrind with
  `--track-origins` across all of my programs. The valgrind tests take 64 s in
  total (`valgrind_sim` 41 s), well inside CI's 600 s limit.
- **CI.** Valgrind was added to apt and the timeout is 600 s. CI uses gcc 13
  (ubuntu-24.04); I tested with gcc 15, so the known-trace digest is unverified on
  gcc 13 until CI runs.

## Mutation testing (my own)

99 mutations of the changed lines: 29 in runner.c, 25 in node.c, 45 in sim.c. Each
was run against the full suite (action, runner, node, sim, known trace, 1,000
seeds of profile 0, profiles 1 to 9), and against ASan/UBSan if it survived.

**Killed: 81. Survived: 18.**

| Survivor | Real gap? |
|---|---|
| R03 sequence-0 test removed | Equivalent (`<= confirmed` already covers it). |
| R11 a failed runner still accepts lists | Nearly equivalent: nothing is executed, only the status differs (REFUSED instead of FAILED when the list also does not fit). Add a status test. |
| R22 byte block not reset to 0 when the queue empties | Equivalent (compaction recovers the space). |
| **R28** compaction off by one: 1-byte overflow | **Real** (F5). |
| **N01** ring write index wraps wrongly | **Real** (F8). |
| N14, N15 start error rollback | Real but minor (F8). |
| **N16** oversized stored ping accepted: stack overflow | **Real** (F5). |
| N25 double pop when more than 60 awaiting | Real, minor (F8). |
| **S02** message dropped at a crash | **Real**: an untested claim (F7). |
| S03 user command kept at a crash | Real, untested rule (F7). |
| S05, S06, **S37** repeating-stream details; scheduled repeats inert | **Real** (F4). |
| S21, S27 harness details | Minor. |
| S35, S36 reader incarnation and ids unused | Real: an untested claim (F8). |

Mutations of the isolation script: 17. **Killed: 8. Survived: 9.** The survivors
are I02 (weak definitions not reported), I05 (only `__asm__` looked for in
sources), I06 (absolute-operand calls), I09 (`sysenter`), I10 (`rdseed`), I11
(`rdtscp`), I14 (`%gs:`), I15 (any `__*_chk` allowed) and I16 (any `mem*`
allowed). All are real: deny-list entries with no negative case.

Builder's break-checks: see the claims table. I read the log, not re-run, and
all were killed except s55.

## What I did not test

- I did not re-run the builder's `mutate5.py` (it writes outside my area). I read
  its log only.
- clang, -m32, and any non-x86 machine. Determinism across compilers other than
  gcc 15 is unverified.
- CI itself (gcc 13 on ubuntu-24.04). I did not run the workflow.
- `tests/scale/tree_shapes.c` (the new BIP 68 version check) beyond it building
  and passing in ctest.
- A storage layer that fails synchronously inside the executor, in the simulator
  (F9). It is covered only by unit tests.
- Long runs beyond 400 steps, and node counts beyond the builder's profiles.
- Docs other than DESIGN.md section 4, KNOWLEDGE-BASE.md and
  ENGINEERING-CHECKLIST.md as they apply to the core. I did not review spec/ files.
