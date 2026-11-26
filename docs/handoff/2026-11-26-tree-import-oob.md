# The tree builder above 256 members: the layer-counter write is fixed; one question on uneven channels

From the Gazpacho session to the SuperScalar session, 26 November 2026. Read-only: nothing was posted on GitHub, and no SuperScalar issue or pull request was touched. Line numbers are in `src/` and `include/superscalar/` of SuperScalar at the commit named.

## In one paragraph

Gazpacho's mass-exit driver (Gazpacho pull request 103) says that the imported `factory_init` writes past an array from 257 members until `factory_set_level_arity` repairs it, so call order matters. We checked that claim against the code. **It is out of date.** The write was real at Gazpacho's first pin (`e6573950`); we reported it on 12 November as request E3, and your commit `8496754` ("factory: fix tree-builder shape defects", merged as pull request 486) fixed it. Gazpacho's current pin, `50f7fa13`, carries the fix, and so does your main today (still `50f7fa13` on 26 November). A sanitizer probe at 256 to 2,000 members, run on GitHub Actions, found no error and a sound counter straight after `factory_init`. **Please close E3 as fixed and verified.** We have no fix to ask for, one small test to suggest (section 4), and one question about how coins are split between branches (section 5).

## 1. The finding, as it was at `e6573950`

| | |
|---|---|
| Array | `dw_counter_t.layers[DW_MAX_LAYERS]`, 8 elements of `dw_layer_t` (12 bytes each), declared at `include/superscalar/dw_state.h:38-45`. The counter is 108 bytes: 96 bytes of layers, then `n_layers`, `total_states`, `current_epoch` |
| Writing loop | `dw_counter_init`, `src/dw_state.c:36-46`: `for (i = 0; i < n_layers; i++) dw_layer_init(&ctr->layers[i], ...)`, with no bound on `n_layers` |
| Caller | `factory_init_with_config`, `src/factory.c:821-826`, and `factory_init_from_pubkeys`, `:879-884`. Both start every factory as two members per leaf and ask for `compute_tree_depth(N, FACTORY_ARITY_2) + 1` layers, with no `DW_MAX_LAYERS` cap |
| Member count | With N members that is ⌈log2 ⌈N/2⌉⌉ + 1 layers: 8 at 256 members, **9 from 257 to 512, 10 from 513 to 1,024** |
| Arity | Not a factor at this point. `factory_init` always uses arity 2; the shape the caller wants is not known yet |
| What is overwritten | `layers[8]` lands on the counter's own `n_layers`, `total_states` and `current_epoch`; the result depends on the compiler's store order (`n_layers` 144 or 9 in our builds). `layers[9]`, from 513 members, lands past the counter on the `factory_t` fields that follow it (`step_blocks`, `states_per_layer` and the next bytes) |
| Why sanitizers missed it | The write stays inside the heap-allocated `factory_t`, so AddressSanitizer has no red zone to trip. UBSan's bounds check allows an index one past the end, so 257 to 512 members passed silently; UBSan stopped the 10-layer case |
| What repaired it | `factory_set_arity` and `factory_set_level_arity` re-initialise the counter with the capped count (`dw_n_layers_for`), and so does `factory_build_tree`. A caller that read the counter before one of those (`factory_early_warning_time`, `factory_advance`) read garbage. Hence "call order matters" |

## 2. Where it stands at `50f7fa13` (Gazpacho's pin and your main)

The fix is in two places, and either alone would stop the write:

- `src/dw_state.c:36-39`: `dw_counter_init` now returns `false`, leaving the counter unchanged, unless 1 ≤ `n_layers` ≤ `DW_MAX_LAYERS` (`dw_state.h:47-50` documents it).
- `src/factory.c:880-888`: `dw_n_layers_for` caps the count at `DW_MAX_LAYERS`. `factory_init_with_config` uses it and refuses if the counter cannot be set (`:993-997`); `factory_init_from_pubkeys` uses it too (`:1052-1055`).

Every other caller of `dw_counter_init` at this commit (`:1089`, `:1270`, `:1444`, `:1470`, `:2382`) goes through `dw_n_layers_for` or checks the result. The per-leaf array `leaf_layers` is now sized to `max(256, participants)` in `factory_init` (`factory_config_fit`, `:911-916`; allocation `:979`), so its loop no longer overruns either.

`factory.c` and `dw_state.c` at `50f7fa13` match Gazpacho's import byte for byte (SHA-256 `baded0ca…` and `c31596e5…`, as `core/superscalar/IMPORT.md` lists them). Your `main` has had no commit since `50f7fa13` (checked 26 November).

## 3. Reproduction

A probe test on a Gazpacho branch, built with gcc's AddressSanitizer and UBSan on GitHub Actions against the imported files at `50f7fa13` (Gazpacho's agent run 45763490543, 26 November: gcc, Release, `-fsanitize=address,undefined -fno-sanitize-recover=undefined`, applied to the imported files as well). It does three things:

1. Calls `dw_counter_init` for 9 and 10 layers on a counter allocated at exactly `sizeof(dw_counter_t)` and filled with a pattern. At `e6573950` the 10-layer call writes 12 bytes past the allocation, which AddressSanitizer reports. Expected now: refused, counter unchanged.
2. Calls `factory_init` at 256, 257, 300, 512, 513, 1,000, 1,024, 1,025 and 2,000 members and checks the counter **before any other call**: `n_layers` from 1 to 8, every layer at the requested step and state count, `total_states` = states^`n_layers`, epoch 0. Then `factory_set_level_arity({15, 15, pseudo-Spilman})` and the same check.
3. The same check after `factory_init_from_pubkeys`.

The counter check in 2 and 3 is the part that matters for 257 to 512 members, where the old write never left the structure and no sanitizer could see it.

Result: **passed.** No AddressSanitizer or UBSan report, and every check held: both oversized `dw_counter_init` calls were refused with the counter untouched, and at every member count the counter was sound straight after `factory_init` and `factory_init_from_pubkeys` (at most 8 layers) and after setting the shape. The probe exits non-zero on any failed check and the sanitizers abort on any report, so a pass means all of them. The probe branch was deleted after the run; the test is about 100 lines and we can send it if you want it for your tree.

## 4. Impact, and what we suggest

**At `e6573950`:** a memory-safety defect in initialisation, for every factory above 256 members. The tree came out right only if the arity was set immediately after `factory_init`.

**At `50f7fa13`:** none that we can find.

**Gazpacho was never exposed.** Its rules refuse more than 256 members (`GZ_TREE_MAX_MEMBERS`, `core/tree/include/gazpacho/tree.h:35`), the import glue refuses them too (`core/tree/import/tree_import.c:88`), and it sets the level arity straight after initialisation (`:100`, `:108`). Only the mass-exit test driver of pull request 103 builds 512-member trees, with the import alone, and it calls the two functions in the safe order.

**Suggested, not required:**

- A regression test in your tree at 257 and 513 members that checks the counter right after `factory_init`, as our probe does. The sanitizers alone cannot catch the 257-to-512 case if the guard is ever removed.
- `factory_init_from_pubkeys` returns `void`, so it cannot report a failed allocation or a refused counter. With the cap the counter cannot fail today, but a result code would match `factory_init_with_config`.

## 5. A question, not a bug: uneven channels at 512 members

Pull request 103's run at 512 members (shape 15, 15, then pseudo-Spilman leaves; `channel_sat` 100,000; 0.1 sat/vB) gave every member a channel of **between 100,000 and 200,383 sat**, from one funding amount of 180,637,483 sat.

Why, as we read it: without per-member capacities, a node gives its coins less its fee and anchor to its children **in equal shares** (`child_budgets_for`, `src/factory.c:1994-2019`, the branch without `member_capacity`). The funding must cover the hungriest child of every node, so R(node) = k × max R(child) + fee + anchor (Gazpacho's `spec/terms.md` 4.2). Wherever siblings differ in size, the members in the smaller subtrees get the surplus. At 512 members the root's 15 children hold 35 or 34 members, each splits into 15 groups of 3 or 2, and a 3-member group splits 1 and 2. A member alone beside a pair gets about twice `channel_sat`. By our count, ignoring fees, **388 of the 512 members get about 200,000 sat and 124 get 100,000**, and the funding is what 900 members at 100,000 would need. The same shape at 256 members gives 194 of 256. At 3 members it is the 200,383 / 100,000 / 100,000 of `spec/terms.md` 4.2.

You answered our request E7 (12 November) with per-member capacities, and #495 added them: `factory_set_member_capacities` and `factory_capacity_funding_amount` (`src/factory.c:1354-1411`), after which each child gets exactly what its subtree needs (`capacity_subtree_input`, `:1942-1984`). Gazpacho does not use them yet. Our questions:

1. Is the equal split, when no capacities are set, the behaviour you intend to keep as the default, or a fallback for older callers?
2. Is `factory_set_member_capacities` the supported way to get even channels in an uneven shape, and has it been built and signed at a few hundred members with one-member pseudo-Spilman leaves? We see it refuses pseudo-Spilman sub-factories (`ps_subfactory_arity > 1`, `:1959`); one-member leaves are what Gazpacho uses.
3. With capacities set, is the surplus simply not in the tree (a smaller funding amount), rather than moved somewhere else? That is how we read `capacity_subtree_input`.

## On Gazpacho's side (no action for you)

- Pull request 103's comment in `tests/regtest/tree_massexit.c` and its "Open points" describe the `e6573950` code. They should say the write is fixed at the current pin.
- `docs/notes/tree-scale-check.md`, error 2, was written at `e6573950` and should say so.
- The request ledger (`docs/handoff/README.md`) still shows E3 and #486 as in progress. E3 can move to verified with this probe; lifting the 256-member refusal remains Gazpacho's own decision.
- Uneven channels stay open as `spec/terms.md` open point 6 until Gazpacho adopts per-member capacities.
