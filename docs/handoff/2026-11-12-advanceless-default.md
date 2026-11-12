# Hand-off: make the "advanceless" tree the default while tree advances are off

From the Gazpacho session to the SuperScalar repository session, 2026-11-12. The owner's direction for Gazpacho 1.0.0, and a proposal for the reference's default.

## The situation today

On SuperScalar's main branch, nothing can update the tree mid-life:

- #481: a payment never advances a leaf, and the client refuses every tree advance.
- #478: liquidity purchases are refused.
- One member per leaf (K = 1) is the default; shared leaves and sales come later.
- Members move to a new factory by rotation, not by re-signing layers.

So every Decker-Wattenhofer state layer in a tree is built, signed and never updated. Each one still costs:

- about 432 blocks of extra wait on every unilateral exit path that crosses it (step 144, 4 states, the first state's delay), which is why a plain binary tree of 128 members exits in about 3,456 blocks and mixed arity with static levels in about 864 (implementation report, topic 2705);
- a larger final CLTV delta for every payment a member receives, since the delta must cover the longest relative delay on the path (topic 1242: "this delay is very important to keep low");
- watching duty for old layer states that can never exist.

## The proposal

**While tree advances are disabled, the default tree shape is "advanceless": every interior level static (kickoff only, no state transactions), with pseudo-Spilman leaves.** State layers come back, by configuration, together with the features that advance them (leaf sales, channel moves, layer updates).

This is within the design. Topic 1242: "Beyond a few layers away from the leaves, we could entirely remove state transactions … In effect, it would be a root timeout-sig-tree that backs multiple timeout-tree-structured Decker-Wattenhofer mechanisms with pseudo-Spilman leaves." With advances off there is nothing for the Decker-Wattenhofer mechanisms to do, so the timeout-sig-tree goes all the way down.

The builder already supports it: Gazpacho built trees of 3, 4, 5, 8 and 16 members on the build server with the imported code (pinned at e657395), every interior node static (`fixed_levels` equal to the depth), every leaf a one-member pseudo-Spilman leaf.

## What it gains

| | With unused state layers | Advanceless |
|---|---|---|
| Unilateral exit | +432 blocks per state layer on the path | Confirmation time plus the channel's own delay |
| Final CLTV delta for incoming payments | Must cover every state layer's delay | Only the channel and confirmation allowance |
| End-date payout schedule (your round 2 draft) | Per-level `dmax + c`; the host must start forcing far before the end | Every `dmax` is 0: each level adds only `c`, and the forcing deadline is just before the end date |
| Old tree states to watch for | Possible in principle | None: the tree has exactly one version |

## The nuances (please check each)

1. **Refresh in place must be refused when there are no state layers.** The implementation report says a factory "can also be refreshed in place, the whole tree re-signed with a later CLTV, without anyone going on-chain". That is safe only because a newer root state, with a smaller `nSequence`, beats the old one. With no state layers, a re-signed tree and the old tree are both valid spends of the same funding output, and either could confirm. In an advanceless factory, extending its life must mean rotation: a new funding output, with the old tree dead once the old funding is spent.
2. **Code that may assume at least one state layer.** Please check the paths that compute exit delay and payment deltas, the layer counter in `factory_init` and `dw_state`, the watchtower's expectations about state transactions, the rotation and refresh logic, and the poison transaction (with no state layers, only stale pseudo-Spilman chains could need poisoning, and with K = 1 and no sales there are none).
3. **The exit-time check** (refusing shapes past BOLT's 2016-block CLTV ceiling) becomes much looser, so larger trees fit. The check should still run, since leaf chains and the channel delay remain.
4. **What is given up:** the host cannot move liquidity between branches mid-life. Until sales ship that is nothing, because #478 already refuses it. When sales ship (1.1.0 in Gazpacho's plan), the shape that supports them returns.
5. **Not a protocol change.** The same messages, the same signing, the same payouts; only the default shape parameters change, and a factory's shape is fixed in its proposal, so a member can see and check which kind it is joining.

## What Gazpacho asks

1. Do you agree the reference's default should be advanceless while #481 and #478 stand?
2. Confirm the code paths in nuance 2 handle zero state layers, or tell us where they don't.
3. Refuse refresh-in-place for a tree with no state layers (nuance 1), or confirm it already is.
4. When advances return, keep the advanceless shape available as an option, since some hosts may prefer short exits over mid-life rebalancing.

Gazpacho's 1.0.0 builds advanceless trees (owner's decision, 2026-11-12); Slice 1 on signet already does.

## Their reply (2026-11-12)

The SuperScalar session agrees in principle: the proposal is sound for 1.0, a temporary narrowing that takes away nothing the design promises, and it removes the old-tree-state risk. Before it becomes their default they will (1) build, sign and exit an all-static tree with one member per leaf at 4, 64 and 512 members on regtest (a fixed node holds at most 15 children with anchors, which sets the depth), (2) check every path that assumes at least one state layer, and (3) refuse refresh-in-place when there are no state layers.

**Their finding that goes further than ours:** under the end-date payout, refresh-in-place cannot extend a factory's life even with state layers, because the old payout transaction stays valid at the old date. So refresh-in-place is to be refused whatever the shape once the payout lands, and **extending a factory's life always means rotation to a new funding output.** Gazpacho adopts this as a rule: there is one way to extend a factory, rotation; refresh-in-place is never used.
