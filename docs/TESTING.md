# Testing plan

How Gazpacho is shown to work, from single functions up to public test networks. Updated 2026-11-11.

## Principles

1. **Every safety rule has two tests:** one showing the rule stops the attack, and one with the rule removed that must show a loss. The second proves the first can catch the bug it exists for.
2. **The checker is independent of the code it checks.** Money is counted from the transactions themselves, not by the module under test.
3. **Failures can be replayed.** Anything random is driven by a recorded seed.
4. **Nothing is "done" on a claim.** A milestone is finished when its tests pass in the automated checks.

## Levels

| Level | What runs | What it proves | When it runs |
|---|---|---|---|
| 1. Reference values | The imported tree code against recorded transaction IDs from a real SuperScalar run | The foundations still behave exactly as upstream | Every push. In place now |
| 2. Standard vectors | Official test vectors for signatures, group signing, key derivation, recovery phrases, invoices, and Lightning's own message and transaction vectors | We agree with the standards byte for byte | Every push |
| 3. Engine tests | One engine at a time, fed events, checked on the actions it returns | Each engine's rules | Every push |
| 4. Simulator | A host, many members, a pretend chain and a pretend network in one process | The whole system under failure and attack | Short run every push; long runs nightly |
| 5. Regtest | The real programs with a real Bitcoin node and Electrum server | The ports and programs, end to end | Every push for a core set; all scenarios nightly |
| 6. Signet and testnet | Our public host with scripted users | It works on a real network over days | Nightly, once M6 exists |
| 7. Release candidate | Everything above, at full size and length, plus a clean install by hand | Fit to hand to outside reviewers | Before each release candidate |

## The simulator

The main safety net. It is possible because the core does no input or output.

- **Schedules:** a seeded generator picks operations for every party: join, pay, receive, change liquidity, update a layer, rotate, close, exit.
- **Network faults:** each message may be dropped, delayed, duplicated or reordered.
- **Crashes:** each party may be stopped at every point where it saves or sends, and restarted from what it saved.
- **Cheating:** scripted dishonest hosts and members try each attack in the threat list: paying a close to themselves, shrinking a balance, publishing an old state, sending a bad partial signature, withholding a result, altering a nonce.
- **After every step,** the invariants below are checked.
- **On failure,** the seed and schedule are saved so the case becomes a permanent test.

## Invariants

Checked after every simulator step and at the end of every regtest scenario.

1. Money is conserved across every state change.
2. Every member can leave alone with at least what they are owed.
3. A party signs two different transactions that spend the same output only where the safe-to-sign rule allows it (`spec/safety-rule.md` C7): never two trees on one funding output; two cooperative closes only if each pays it at least what it is owed; and one channel state number only for the same state on each of a channel's live anchors, with one revocation secret (section 4.1 rule 1). It never sends two different nonces or partial signatures for one round and item.
4. Nothing is sent before it is saved.
5. No secret nonce survives a restart or is used twice.
6. No party's software publishes a state it has cancelled.
7. Every payment deadline is later than the time needed to exit.
8. The host's funding is never signed before every exit is signed.
9. An honest party is never named as the cause of a failed signing round.

## Regtest scenarios

Each runs through a Bitcoin node and again through an Electrum server.

- Lobby fills to target; lobby starts at the deadline; lobby misses its minimum.
- Join, receive, pay inside the factory, pay out through the host's Lightning node, receive from outside.
- Liquidity change; layer update; rotation into a new factory; cooperative close.
- A member exits alone with the host gone, through to spendable coins.
- The host publishes an old state; a member publishes an old state.
- Restart of each program in the middle of each operation.
- A member away for the whole response window.
- Restore from backup, then recover without publishing.

## Sizes

Routine runs use 4, 8 and 32 members. Nightly runs use 128 and 256. Release candidates run the target of 512.

## Tooling

- Automated checks on every push: a normal build and a build with memory-error and undefined-behaviour checkers. In place now.
- To add as code arrives: fuzzing of every message decoder with a kept corpus; a thread-error checker for anything concurrent; coverage reports; a nightly job for the long runs.
- Compiler warnings are errors.

## Before a release candidate

- Every invariant has passing tests at all three of simulator, regtest and signet.
- Every safety rule has its rule-removed test.
- The long simulator run and the fuzzers have run clean for a day.
- Nightly scenarios have been green for seven nights.
- Each engine has had an independent review, and its findings are closed or recorded as accepted.
- The documents state what is unreviewed.

Outside review then begins; the owner arranges it.
