# Engineering checklist

What every piece of work must satisfy before it is handed to review. It is made from what the reviews of the first pull requests found, so that later work does not repeat those mistakes. Add to it whenever a review finds a new class of problem. Created 2026-11-11.

## Before writing code

1. **There is a written specification**, and it has been reviewed by someone who did not write it. Code is not started from an unreviewed specification.
2. **The specification says what is stored, in what order, and what happens on a crash at each point.**
3. **The tests are listed before the code is written**, including the cheating and crash cases.

## Safety claims

4. **No comment, header or document claims more than the code does.** A sentence such as "never misses" or "cannot happen" needs a test that would fail if it were false. Reviews found a false "never misses" in a header and a check whose name promised more than it proved.
5. **A check that guards a boundary is an allow-list, not a deny-list.** Both "this library does no input or output" checks were deny-lists at first, and both were fooled.
6. **Every protection has a negative test**: a deliberately wrong version that the test must catch. The wrong version lives in the tests, never in the library.
7. **Every safety rule has a "rule removed" run** that must fail, in addition to the test that it works.

## Tests

8. **Mutation testing is part of the work, not of the review.** The builder breaks the code on purpose, in many small ways, and reports which breakages no test notices. Reviews found 14 such survivors in the core frame and 15 in the wallet keys after the builders had declared them done.
9. **A randomised test compares against an independent model of the rule**, written from the specification and not from the code, and compares order and content, not only counts.
10. **Tests do not match loosely.** A test that searched output for the letters "prv" failed once in a few hundred runs when those letters appeared in a random address. Match the exact thing.
11. **Fault settings are shown to do something.** Two simulator profiles exercised nothing because every node died first. A test of a fault must fail if the fault never happened.
12. **Results are reported with counts, and with what was not tested.**

## State and storage

13. **Save before send**, enforced by the runner, never by convention in each engine.
14. **Identifiers are never reused**, including across a restart and across a restore from backup.
15. **Anything that makes memory run ahead of storage is fatal for that node**: a refused step, a storage failure, storage answering out of order. The node stops and is rebuilt from what was saved.
16. **After a restart, everything saved and not known to be acknowledged is sent again.** So every message must be safe to receive twice, and out of order with newer messages.
17. **One-time signing secrets are never stored**, and a restored backup must not be able to make one repeat.

## Code

18. **The core calls nothing outside itself**: no files, network, clock, randomness source, environment, printing, or global state. No inline assembly. The isolation check must pass.
19. **Imported files are never edited.** A workaround goes in new code and is reported upstream.
20. **Everything from another party or a server is hostile input**: bounded, strictly parsed, fuzzed.
21. **Secrets are wiped on every path**, never appear in an error message, and are compared in constant time where compared at all.
22. **Arguments that could be confused have distinct types.** A yes/no "is mainnet" flag sat where a network value would be natural, and zero meant mainnet.
23. **No warnings**, in a normal build and under the memory-error checkers. Uninitialised bytes are checked with a tool that can see them.

## Hand-over

24. **Small pull requests.** One piece of work, reviewable in one sitting. The first core pull request was over four thousand lines and needed three rounds.
25. **The report says what was decided where the specification was silent**, so those decisions can be confirmed or overruled.
26. **Nothing is published by the builder.** The branch is fetched, opened as a pull request, reviewed by an agent that did not write it, and merged only when the review and the automated checks pass.


## Added after the M1a follow-up reviews

27. **A multi-step start that reads storage must work from a fixed view, or
    record only what it has actually done.** A start that re-reads storage
    between steps can record an action (a message as "sent") against a record
    that appeared after the step began but was never acted on. Storage may
    grow during a start (late writes from a dead program, the node's own
    saves); a start must still never claim to have done what it has not.
28. **A save made early in a start holds back every later send**, because the
    runner releases nothing outward until earlier saves are confirmed. A start
    that must both resend and record should resend everything first and save
    its records last, so the resends do not wait behind a record's
    confirmation. More generally: order a step's actions so that what must
    leave does not sit behind a save.
29. **An invariant checks the property itself, not a proxy for it.** "No
    one-time secret is reused" is checked on the secret values the engines
    actually use (exposed for the test), not on what they drew from the random
    port: a naive engine can mislabel its draw, and a careful one mixes the
    draw with other material, so the draws are the wrong thing to compare.
30. **A fault the code describes must be one the test harness can produce.**
    The runner's contract allowed storage to fail from inside the executor,
    but the simulator had no way to make it happen, so a mutation that ignored
    that path looked equivalent to correct. Every path a contract names needs
    a fault that exercises it.
