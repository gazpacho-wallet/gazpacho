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
28. **Invariants check the property itself, not a proxy.** An invariant that checks something which usually goes with the property (a count, a flag, a state name) passes when the property fails.
29. **Mutation runners kill their children on timeout.** A mutant that hangs must be stopped with everything it started; hung mutants once loaded the build server for hours. (Added 2026-11-12)
30. **A new protection gets a cross-check against an independent implementation** wherever one can be written. The Python BOLT 8 peer, the independent signature-hash code and the independent parser each paid off. Numbers 27 onwards are added where they belong, not renumbered, so references to earlier items stay valid. (Added 2026-11-12)

## State and storage

13. **Save before send**, enforced by the runner, never by convention in each engine.
14. **Identifiers are never reused**, including across a restart and across a restore from backup.
15. **Anything that makes memory run ahead of storage is fatal for that node**: a refused step, a storage failure, storage answering out of order. The node stops and is rebuilt from what was saved.
16. **After a restart, everything saved and not known to be acknowledged is sent again.** So every message must be safe to receive twice, and out of order with newer messages.
17. **One-time signing secrets are never stored**, and a restored backup must not be able to make one repeat.
27. **A save made early in a start holds back every later send; start records last.** In a node's start step, a save comes before every send that follows it, so a save placed early delays all the resends behind it. Records written at start go last.

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
