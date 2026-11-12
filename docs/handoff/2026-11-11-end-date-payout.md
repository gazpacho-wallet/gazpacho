# Hand-off: the end-date payout at every level, and when to do it

From the Gazpacho session to the SuperScalar repo session, 2026-11-11.

## The request

Your plan puts "end-date payout at every level" in the last group, after the JIT stages and the scale series. Please move it up, into the same series as the tree-fees change (#476).

It does not need to be next. It needs to land **together with the other changes that alter the tree's transactions**, so the tree changes once.

## Why

1. **It is a change to the shared files, not to your programs.** It lives in the tree builder (`factory.c`, `tapscript.c`), which Gazpacho imports unchanged. Everything else in your "after that" group (payment deadlines, funding order, payment-secret custody) is in program code that Gazpacho does not use and is building for itself.
2. **It changes every tree transaction.** Removing the host-only timeout branch changes each node's output script, so every transaction ID in the tree changes, and there is a new set of transactions to sign at creation. #476 also changes the tree's transactions. Doing them months apart means two rounds of new transaction IDs, new reference values, re-testing at every size, and re-checking by both projects. Together it is one round.
3. **It is the property the design rests on.** Today only the funding output pays users at the end date; every node below it lets the host spend alone after its timeout. Until this lands, a user's software has to treat each node's timeout as a moment the host can take the money, which shortens the time a user can safely stay and makes the exit rules stricter than the design intends.
4. **Gazpacho's signing engine has to know the final shape.** It is being built now to sign "the tree's transactions". If the set of transactions to sign changes later, the engine, its tests and its specification change with it.

Gazpacho does not need this for signet. It needs it before any real funds, and it needs to know the shape early.

## What needs deciding in it

These are yours to design; Gazpacho will follow what you choose.

1. **How each lower-level payout is divided.** It is signed at creation and cannot change afterwards, so it cannot follow balances. Options: equally among the users under that node; or in proportion to each user's initial channel size. State which.
2. **Who signs each payout transaction:** the signers of that node, at creation, in the same signing rounds as the tree.
3. **Its lock time** relative to the factory's end date, level by level, so that deeper payouts cannot be published before the ones above them make sense.
4. **What happens to the host's spare liquidity** on a leaf at the end date under this rule.
5. **Fees** on the payout transactions, and whether they carry an anchor.
6. **Whether the channel outputs' own host-only timeout branch goes too.**

## Suggested grouping

One series, "changes to the tree's transactions", landing close together and announced once:

- #476, tree fees;
- the end-date payout at every level;
- the participant-order fix (sequential placement by default, or a tie-break in the comparison);
- the timelock-counter overwrite in `factory_init` at 257 users and above;
- the exit-delay functions that under-report on deep trees;
- the anchor silently dropped on a 16-output node.

The last four are in the earlier hand-off note with line numbers. None of them changes transaction IDs for valid shapes by itself, but they are in the same functions and are cheapest to review together.

## What Gazpacho will do

- Wait for this series rather than patch its own copy.
- When it lands, re-import, regenerate its reference values, re-run its scale check at every size, and review the change. It will say so when it starts, and send back anything it finds.
- Until then, keep its exit rules on the stricter footing described in point 3.
