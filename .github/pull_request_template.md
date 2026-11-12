<!--
Fill in every section. Write "none" rather than deleting a section.
The full checklist is docs/ENGINEERING-CHECKLIST.md (30 items). The boxes below are the eight that reviews most often find unmet.
Never paste an IP address, a local path or a secret into this description.
-->

## What changed

<!-- One piece of work. What it does, in a few sentences. -->

## Specification it follows

- Specification:
- Its review state (round, file under `docs/reviews/`, and whether the draft built from was itself reviewed; see `docs/reviews/README.md`):

<!-- If the specification was not reviewed before the code, say so plainly; it is an exception to checklist item 1. -->

## Engineering checklist

See [`docs/ENGINEERING-CHECKLIST.md`](../docs/ENGINEERING-CHECKLIST.md) for all 30 items. Tick only what is true, and say why next to any box left empty.

- [ ] 1. The code follows a written specification that someone who did not write it has reviewed.
- [ ] 2. The specification says what is stored, in what order, and what happens on a crash at each point.
- [ ] 4. No comment, header or document claims more than the code does; every "never" or "cannot" has a test that would fail if it were false.
- [ ] 6, 7. Every protection has a negative test, and every safety rule a "rule removed" run that must fail.
- [ ] 8. The builder ran mutation testing and reports the survivors below.
- [ ] 20. Everything from another party or a server is bounded, strictly parsed and fuzzed.
- [ ] 23. No warnings, in a normal build and under the memory-error checkers.
- [ ] 24. The pull request is one piece of work, small enough to review in one sitting (guide: 2,500 lines). If not, say why.

## Tests and counts

<!-- Each test added or changed, what it checks, and how many cases, seeds or inputs ran. Which build: normal, sanitizers, valgrind. Where it ran: GitHub CI or the build server. -->

## Mutation results

<!-- How many mutants, how many killed, and every survivor with its status: equivalent (and why), real gap, or fixed. Link the survivors file if there is one. -->

## Decisions made where the specification was silent

<!-- Checklist item 25. Each decision, so it can be confirmed or overruled. Write "none" if there were none. -->

## What is not tested

<!-- Checklist item 12. Anything not run, not reachable, or left for later, and why. -->
