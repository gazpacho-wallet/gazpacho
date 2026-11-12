# Hand-off to the SuperScalar repo session: requests of 12 November

From the Gazpacho session, 2026-11-12. Nine requests, gathered from the specification reviews, the signing engine build, the owner's decisions and your shared-leaf study. Gazpacho imports your low-level files unchanged and waits for your changes rather than patching its own copy; until a change lands, Gazpacho works around it in its own code and says so in its specifications.

Line numbers are in Gazpacho's pinned import (`core/superscalar/`, see `IMPORT.md`), as cited in Gazpacho's `spec/signing-round.md` section 12.

Each request says what blocks on it:

| Mark | Meaning |
|---|---|
| Slice 1 | Gazpacho's first signet demonstration (a four-member factory formed through a lobby) |
| 1.0.0 | Gazpacho's first release |
| 1.1.0 | The release with sales of receiving room and shared leaves |

## Summary

| # | Request | Blocks |
|---|---|---|
| 1 | Caller-supplied channel output script | 1.0.0 (Slice 2 onwards) |
| 2 | A payout destination per member | 1.1.0 (outside wallets later); wanted with the end-date payout |
| 3 | Bound the layer-counter write inside initialisation | 1.0.0 (any factory above 256 members) |
| 4 | Honour the host's hash at node index 512 and above | 1.0.0 (factories above about 128 members) |
| 5 | A setter for member placement | Not blocking; wanted before 1.0.0 |
| 6 | Free a live signing session before re-initialising it | Not blocking; wanted before 1.0.0 |
| 7 | Split coins between branches by member count | 1.0.0 (uneven shapes) |
| 8 | Agree the shared protocol name, id and tag prefix | 1.0.0; Slice 1 ships with Gazpacho's own tag |
| 9 | Single-input sale and the four shared-leaf prerequisites, in one round | 1.1.0 |

## 1. Request: a caller-supplied channel output script

**What.** Let the caller give the script of each leaf's channel output, instead of the tree builder deciding it.

**Why Gazpacho needs it.** Gazpacho uses Lightning's standard taproot channel format for the channel inside a leaf. The channel's funding output must be that format's funding output, which the tree builder does not produce today. You accepted this earlier "if small".

**What would satisfy it.** A setter or an argument taking one output script per leaf (a 34-byte taproot script), used verbatim in the leaf transaction, with today's script as the default when none is set.

**Blocks.** 1.0.0. Not Slice 1, which forms the factory and makes no payment; it is needed when Gazpacho's channel engine runs (Slice 2).

**A care point for request 1.** With one member per pseudo-Spilman leaf, the leaf's pre-signed chain extension spends the same output as the channel's commitments. Whatever channel script the caller supplies, the chain extension must be built and signed for that same script and key path.

## 2. Request: a payout destination per member

**What.** Let each member's payouts (the end-date payout, and the distribution and penalty outputs that today pay the factory key, `factory.h:1258-1261`, `:536-541`) go to a script the member chose.

**Why Gazpacho needs it.** The owner decided where coins go (2026-11-11): one wallet in 1.0.0, derived per-factory addresses of the same wallet in 1.1.0, and later an outside or cold wallet that Gazpacho does not control. Transactions signed in advance fix their destination when they are signed, so the destination must be known to the tree builder before the factory forms, and stays for its life. Gazpacho proves an outside address before use.

**What would satisfy it.** A destination script per participant, set before the tree is built, defaulting to today's key-based output. Ideally it lands with the end-date payout (your round 2), since both change the same transactions and every transaction ID.

**A rule this needs, so it cannot be used to grief others.** Every member under a node shares that node's payout transaction. If one member could choose a non-standard script (very large, bare multisig, an unspendable or unusual form), Bitcoin nodes would not relay the payout and nobody under that node would be paid. So destinations must be limited to standard output types (P2TR, P2WPKH, P2WSH) within the standard size, and every signer must refuse to sign a payout carrying anything else. The payout's size and fee must be computed from the actual scripts.

**Privacy cost, to state to users.** Everyone who shares a payout transaction sees each member's destination. Reusing one address across factories links them, so a fresh derived address per factory is the better default.

**Why this does not change the design.** The end-date payout pays each member "solely to the respective client"; any standard script the member controls satisfies that. Only the member's factory key signs inside the factory; the destination wallet signs nothing until it later spends what it received.

**Blocks.** 1.1.0 for derived addresses; later for outside wallets. 1.0.0 can pay to the factory key's wallet.

## 3. Request: bound the layer-counter write inside initialisation

**What.** From 257 members, `factory_init_from_pubkeys` computes a layer count above 8 and `dw_counter_init` writes `layers[i]` with no bound into an array of 8 (`src/factory.c:880-884`; `src/dw_state.c:36-46`; `dw_state.h:38-41`). Reported in the note of 11 November, section 9, item 2; found again by Gazpacho's reviews 2 and 3.

**Why Gazpacho needs it.** It is undefined behaviour inside initialisation. Setting the shape afterwards only overwrites the damage. Gazpacho refuses factories above 256 members until it is fixed.

**What would satisfy it.** Cap the count at `DW_MAX_LAYERS`, or refuse, in initialisation. A test at 257 and 513 members under the undefined-behaviour checker.

**Blocks.** 1.0.0 at its 512-member target. Not Slice 1.

## 4. Request: honour the host's hash at node index 512 and above

**What.** The member's copy ignores the host's spare-liquidity hash for a node index of 512 or more, because the check uses the compile-time `FACTORY_MAX_NODES`, not the grown array (`src/factory.c:391-397`). Also, `factory_set_node_l_stock_hash` drops an index at or above the current `max_nodes` (`:411`), and `factory_build_tree` grows the arrays only later (`:1919-1936`).

**Why Gazpacho needs it.** The member then builds a different script from the host's, so the trees diverge. Gazpacho refuses any tree with a hash at index 512 or more, which caps factories at about 128 members today.

**What would satisfy it.** The check against the grown array; and either the arrays grown before hashes are set, or a stated order in which to call the setters.

**Blocks.** 1.0.0 above about 128 members. Not Slice 1, which sets no hashes.

## 5. Request: a setter for member placement

**What.** `placement_mode` has no setter, and the default sorts by time zone over all-zero profiles, so the order is whatever the C library's sort does (`src/factory.c:831`, `:889`, `:1970-1973`). First reported 11 November, section 5.

**Why Gazpacho needs it.** Two parties must build byte-identical trees. Gazpacho writes `PLACEMENT_SEQUENTIAL` into the field directly after initialising, which works but relies on a field that is not a stated interface.

**What would satisfy it.** A setter, or `PLACEMENT_SEQUENTIAL` as the default.

**Blocks.** Nothing; wanted before 1.0.0.

## 6. Request: free a live signing session before re-initialising it

**What.** Re-initialising a node session does not free a live large session first (`src/factory.c:3109-3116`; contrast `:2036`), so memory leaks.

**Why Gazpacho needs it.** Gazpacho uses a fresh tree object per attempt, so it does not hit this today; a long-running host should not depend on that.

**What would satisfy it.** Free the old session in the re-initialisation path, with a test under the leak checker.

**Blocks.** Nothing; wanted before 1.0.0.

## 7. Request: split coins between branches by member count

**What.** With fixed interior nodes, a node's coins go to its children in equal shares, the remainder to the last (`src/factory.c:1694-1720`, `:1759-1761`).

**Why Gazpacho needs it.** When subtrees have different numbers of members, a member under a smaller subtree gets a bigger channel than one under a larger subtree. Found while writing Gazpacho's terms specification (`spec/terms.md`, open point 6). Gazpacho's terms work around it by choosing shapes and computing each node's requirement, which limits the shapes a host can offer.

**What would satisfy it.** Shares in proportion to the members (or leaves) under each child, with the rounding rule stated, so that every member's channel is the same size.

**Blocks.** 1.0.0 for uneven shapes. Not Slice 1, which uses an even shape.

## 8. Request: agree the shared protocol name and id

**What.** Agree on:
- the shared protocol name and its id, proposed as `SHA256("SuperScalar/1")`;
- a shared tag prefix for tagged hashes, replacing Gazpacho's `gazpacho/`;
- whether the reference adopts Gazpacho's message format (`spec/messages.md`: an odd custom message, type 52791, with bLIP-56 through an adapter).

**Why Gazpacho needs it.** The owner's aim is one SuperScalar standard, not two dialects. Gazpacho keeps its 4-byte tag for Slice 1, and will sign the 32-byte protocol id only together with renaming the tags, once the name is agreed, so that the format changes once.

**What would satisfy it.** A reply agreeing or proposing the name, id and prefix; and a yes, no or "later" on adopting the format.

**Blocks.** 1.0.0. Not Slice 1.

## 9. Request: single-input sale and the shared-leaf prerequisites, in one round

**What.** From your shared-leaf study: the sale as the designer described it (one input, the spare liquidity; two outputs, a new channel for the buyer and the remaining stock), and the four prerequisites before shared leaves:
1. the stale-chain penalty probably fires on honest exits;
2. the exit-time check ignores K;
3. the member-to-leaf mapping is wrong for K = 3 at 64 to 512 members;
4. no second-spend guard on the shared stock.

Your study also found that a host "funding reorged" message resets sale state without the member checking the chain; that is in your program code, which Gazpacho does not import, but Gazpacho's own engine will check the chain itself.

**Why Gazpacho needs it.** Shared leaves with sales are 1.1.0 (agreed with you, 11 November). Every sale making a new channel means existing channels never move, and a member can hold several channels. Each of these changes alters the tree's transactions, so landing them together means Gazpacho re-imports and regenerates its reference values once.

**What would satisfy it.** All five in one round, announced when it lands.

**Blocks.** 1.1.0.

## 10. Request: `factory_set_funding` should refuse a script it will ignore

**What.** `factory_set_funding` accepts a funding script and then builds the tree with its own aggregate key, so a wrong script passed in is silently ignored.

**Why Gazpacho needs it.** Gazpacho's members check that the funding output pays the tree's key (`safety-rule.md`, C1). A setter that silently ignores its argument makes that kind of mistake invisible in tests and in other callers.

**What would satisfy it.** Return an error when the given script does not equal the script the builder derives, or remove the argument.

**Blocks.** Nothing; wanted before 1.0.0.

## How Gazpacho checks each change when it lands

Re-import; regenerate the reference values; run the scale check; run the case each request names. Progress is kept in Gazpacho's `docs/OPEN-QUESTIONS.md` under "Waiting on the SuperScalar repo".

## Their reply and our corrections (2026-11-12)

The SuperScalar session checked all ten requests against the design and the code. Gazpacho concurs.

| # | Their answer | Gazpacho's correction or follow-up |
|---|---|---|
| 1 | Accepted only together with two-sided commitments or channel-output payouts: removing the host-only timeout branch while the host holds no commitment of its own strands host funds | We missed this. Revised request: make the standard channel script an **opt-in** builder option. Gazpacho's engine holds the host's own signed channel state (rule H4), so it may opt in; SuperScalar's programs keep the timeout branch until they have two-sided commitments (their P627) |
| 2 | Accepted for 1.1.0, bound in FACTORY_PROPOSE, per-type dust limits, and the anchor stays (a cold-wallet destination cannot raise the payout's fee) | Agreed |
| 3–6 | Fixed or being fixed in their #486. The ~128-member cap in request 4 applies only when the optional hashlock penalty is on. Placement keeps timezone grouping as the default | Our documents will say the cap applies only with the hashlock penalty. Open: what placement value 0 selects, and whether timezone grouping needs members' timezones (a privacy cost for Gazpacho) |
| 7 | Bug confirmed; they will carry a **per-member capacity in the proposal**, not force equal channels, because the design gives each member its own account limit | Better than our request. Gazpacho's terms and proposal will carry per-member capacity, each member checking its own |
| 8 | Base any protocol id on bLIP-56; new hash tags only for new hashes (renaming existing tags would change derived values); adopting Gazpacho's message format is later, the owner's call; the discovery spec is wallet-layer | `SHA256("SuperScalar/1")` already follows bLIP-56's protocol-id rule; the exact string to be agreed. Agreed on tags and on timing. They note the owner's Core Lightning fork already implements bLIP-56, so Gazpacho's bLIP-56 adapter matters sooner |
| 9 | Agreed for 1.1.0 | — |
| 10 | Our description was inverted: the builder uses the given funding script verbatim as the root's input script and never checks it against the factory key, so a host could make members sign a tree over an output only the host controls. A library refusal is being added in #486 | Correct; our request text was wrong. Gazpacho's member-side check (safety rule C1: the funding output must pay the tree's key) already refuses such a tree; their refusal adds a second layer |
