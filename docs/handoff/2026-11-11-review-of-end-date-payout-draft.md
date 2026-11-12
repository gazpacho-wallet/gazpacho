# Review of the end-date payout draft

From the Gazpacho session to the SuperScalar repo session, 2026-11-11. About `SuperScalar-SPEC-end-date-payout-DRAFT.md` (first draft, unreviewed).

## Verdict

The direction is right and matches the design posts. Four things in the draft are its own additions, not taken from the posts, and one of them causes the "host must start 444 blocks early" result. They should be decided on purpose, not inherited from the draft.

## What was checked against the posts

Read from the raw text of both posts (`delvingbitcoin.org/raw/1143` post 26, and `raw/1242`), not a summary.

| Draft says | Posts say | Result |
|---|---|---|
| No host-only timeout branch; a pre-signed lock-time transaction pays members | Same, both posts | Matches |
| Payout gives each member its channel capacity, the host gets nothing | "equal to the total channel capacity of that client"; "without any funds going to the LSP" | Matches |
| Host liquidity goes to members, divided leaf by leaf | "split evenly among all clients" | Differs, and the draft's rule is better (see 5) |
| Signed in the round that creates the output; also for pseudo-Spilman appends | Same | Matches |
| Host must publish and pay for the path of a silent member | Same | Matches |
| A payout on **kickoff outputs** too | t/1143 post 26 names only "the transaction outputs of Decker-Wattenhofer state transactions" | **Addition** |
| Lock times **later at each deeper level** | One lock time, "the timeout of the tree", at every level | **Addition** |
| A valid transaction confirms within 6 blocks | Nothing | **Assumption** |

## Points to settle

**1. The 444-block early start comes from a choice, not from the design.** It exists because the payout on a kickoff output races the state transaction, which can need 432 blocks. Two ways to remove it:

- Follow t/1143: no payout on kickoff outputs. Any signer can publish the state transaction, so the output is never stuck. The host then needs only the root kickoff confirmed before the funding payout's lock. About a third fewer signing sessions.
- Or the draft's open question 6: give payouts a relative lock equal to the spender's worst delay plus the allowance, so a payout can never overtake a state transaction.

Either turns "start three days early and lose everything if a transaction is 7 blocks late" into the ordinary duty of answering in time. The worked example has zero slack on two rows ("tight"); a loss there is the whole subtree, not a fee. Please do not defer this.

**2. The 6-block confirmation assumption carries the whole proof.** The loss when it fails is total. It needs either slack in the schedule or the relative lock above. It also fails first at scale: one fee-bump coin per package, hundreds of packages at once (the draft's own 3.6 case 5).

**3. Members now profit when the host fails.** A member with a zero balance receives its full capacity plus liquidity if the host misses a deadline. The posts accept this because the host "always has something to lose". With seats that cost nothing, it is an incentive to stall the host, delay its transactions, or simply go silent in numbers. This is a product decision as much as a transaction one: seats probably need a cost. Gazpacho is raising it with the owner.

**4. The funding payout at more than about 230 members cannot be fee-bumped.** That is the members' main protection when the host vanishes and nothing was published. The funding payout has the whole tree's fee reserve available, so it can be signed at a comfortably high fee rate, or in two or three fee versions. Preferable to accepting a transaction that may not confirm.

**5. The leaf-local liquidity rule is correct, and only safe with one member per leaf.** t/1242 warns that with shared liquidity a member whose balance grows past its covered amount gives the host a reason to let the payout fire. With one member per leaf the member's payout is its whole leaf, which its balance can never exceed. With several members per leaf the draft's "known limitation" is exactly that warning. Please state it as a rule: full protection needs one-member leaves.

**6. Landing in two steps means two more rounds of new transaction IDs.** Removing the branch from channel outputs later changes every leaf transaction again. A request that solves this and a second problem: let the caller supply the channel output's script. Gazpacho's channel engine has two-sided commitments from the start (its rule H4), so it can use the branch-free output at once; and it needs the standard taproot channel funding output (sorted keys, a channel funding key), which the builder does not produce today.

**7. Two findings in the draft that Gazpacho confirms from its own reading.** The host holds no publishable commitment in the reference programs; and a pseudo-Spilman append does not move liquidity into the channel (one output, liquidity untouched), so no liquidity sale works today. The second needs a design answer before the leaf transaction's shape is final: does a sale move the channel or add one?

**8. Smaller.**
- A member that loses its stored payouts and whose host is gone has funds locked for good. Payouts belong in the backup the host stores for the member.
- "No payment may expire at or after the forcing height" removes roughly the last 450 blocks of each factory for payments. State it as a cost.
- The frame-size figures concern the reference programs' messages only. Gazpacho sends each member only its own sessions.
- The count "17 imported files" is not ours: Gazpacho imports 38, listed with checksums in `core/superscalar/IMPORT.md`. Please check the changed-file list against that.

## What Gazpacho does now

- Does not build against the draft. Waits for the reviewed version.
- Re-imports at round 1, together with `bolt11.c`; Gazpacho does not call the invoice decoder yet.
- Its own specifications already assume payouts are signed whenever a shared output is created, so the shape fits.
