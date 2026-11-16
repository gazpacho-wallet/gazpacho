# Imported SuperScalar files

These files are copied byte-for-byte from SuperScalar (MIT licence, see LICENSE in this directory).
Do not edit them. Re-import with tools/update-import.sh. Workarounds go in core/shim/.

Upstream: https://github.com/8144225309/SuperScalar
Pinned commit: 50f7fa138b437af9b7a10acae8cd65986356810f
Commit date: 2026-11-13T20:44:33-05:00
Commit subject: Merge pull request #505 from 8144225309/fix/htlc-claim-core
Imported on: 2026-11-15
secp256k1-zkp pin (from upstream CMakeLists.txt, mirrored in ../../CMakeLists.txt): 6152622613fdf1c5af6f31f74c427c4e9ee120ce

| Local path (relative to core/superscalar) | Upstream path | SHA-256 |
|---|---|---|
| include/superscalar/adaptor.h | include/superscalar/adaptor.h | e59bc4f471365190835849ab0633ae269267f398f3c22cec7a825f587796c34d |
| include/superscalar/bech32m.h | include/superscalar/bech32m.h | f589c120e1ed23e4c0aa21c4906914d83f9e1cfc604cdb0b91b4c7d3bfae8a06 |
| include/superscalar/bip39.h | include/superscalar/bip39.h | 9abe1facdd28860139e9827402844cbbaff794d904a7e6f64f7a6e7156d6e5c4 |
| include/superscalar/bolt11.h | include/superscalar/bolt11.h | 440c94432bbf748e83875a8720e6a5dbe89567a79b1d19d9bb766b3256563915 |
| include/superscalar/channel.h | include/superscalar/channel.h | 7d6363f12eabc3d52b8d7d8d1c8ba430b521d9450a1d5d0d0859db8cd46a03b6 |
| include/superscalar/crypto_aead.h | include/superscalar/crypto_aead.h | 4b32bcae21251eedda081353de00622c7fd2b4a124537ca1c4d2daa9fc352e12 |
| include/superscalar/dw_state.h | include/superscalar/dw_state.h | df4699e20a3b09616fb75c71eeb4faff81800b3d08981d3826ed752e2201740b |
| include/superscalar/factory.h | include/superscalar/factory.h | 69f20688da076229cf55b5297327e9a48927d938034c3565ad27f5545b38db2d |
| include/superscalar/fee_estimator.h | include/superscalar/fee_estimator.h | fe6ec3ea55ad7ace1c192975a36a56c628a70ad64f1662fb993e3055d576908a |
| include/superscalar/fee.h | include/superscalar/fee.h | 7c5ded47499893c7a9e7ffc1334bfa6e3d2c03fc147d9bf4b3cfb04313332dad |
| include/superscalar/hd_key.h | include/superscalar/hd_key.h | 6adde85fc2f4cff08956caf6ce3e81630b96011f6e9538aba68fcb994ff3d1d7 |
| include/superscalar/htlc_fee_bump.h | include/superscalar/htlc_fee_bump.h | 0488b79e75b6aed22beb76f48780b319f9bbdf4e1889d4252c8dce585a5299ce |
| include/superscalar/ladder.h | include/superscalar/ladder.h | 48a7e74d90ee493d88b78f6b8f14faaa71fc86171498b8da913d364e8b494a9f |
| include/superscalar/musig.h | include/superscalar/musig.h | 0e076462b8055de8bceca5a3d8a87529af54d9d2350c9afa10d124ddbabbb08a |
| include/superscalar/sha256.h | include/superscalar/sha256.h | 919b0863ff2aa09b178bb13817035e170b4f227f07a98b253ccae207c02e75fd |
| include/superscalar/shachain.h | include/superscalar/shachain.h | 027bfd938dec93d9083df9400825e6751c0d51c721273c5ddb3828b5182c9d0d |
| include/superscalar/tapscript.h | include/superscalar/tapscript.h | 7403755ad5e3628258d9c3af3a8e5195566a0873c71501c61e1c2c7d786d26fb |
| include/superscalar/tx_builder.h | include/superscalar/tx_builder.h | ffa822a913e4e0888ddd3a8f1f579f2b2131070b5918e9b022cc2727c9cac080 |
| include/superscalar/types.h | include/superscalar/types.h | 8bf4dfc54837f36402e15111152ab4374bb5eda3202cbf490e3221831450a252 |
| src/adaptor.c | src/adaptor.c | cd68bc7096429fae6ee905fa385fa13de7da10d3a5278c1d7d4c83be5a74b75a |
| src/bech32m.c | src/bech32m.c | 56bb3008e56d01cbdb256bd9c3fec537d844cafc017ad46849a52666db6edf04 |
| src/bip39.c | src/bip39.c | 09748c332229dae846768186bd25654d6096a440ac70c186821da6a612b6e4b4 |
| src/bip39_wordlist.h | src/bip39_wordlist.h | 8cdf8e0f0aebc22a196291964a0a685072d48bc78e04463940bf714240b5cff9 |
| src/bolt11.c | src/bolt11.c | 08fe26b202a851fbee0d95e166e563dcf2e3068ae52914452cd76538180632a2 |
| src/crypto_aead.c | src/crypto_aead.c | 772a507379b3f7b007a6cce7a1ee84c530106c387ffe06e41239c2f8c1338596 |
| src/dw_state.c | src/dw_state.c | c31596e5cc1f8245f4d3189907fca5deb7b17c4916ec64414a66b52688511035 |
| src/factory.c | src/factory.c | baded0cadf29b6bb8603caaf6aed5e69cd67647335c3b678780f8a2d19f309fa |
| src/fee.c | src/fee.c | 3f9c85452f89bb123a63d6ea48539d7bd0ead9339fd8ce17096123e326a5ef59 |
| src/fee_estimator_static.c | src/fee_estimator_static.c | 1039ed51f7a47a5c48b6237562f91175e0dd506312f646ff3414c29d5e577937 |
| src/hd_key.c | src/hd_key.c | 671b0d968b965742e5762395686cf4dbe5c87895e5df8d1edb3f6ced92cc78cb |
| src/htlc_fee_bump.c | src/htlc_fee_bump.c | e9a861767543d523599b80b163c1068d6fd60f4c09ebbe6598df6c8eb83e2517 |
| src/ladder.c | src/ladder.c | a18fa7a3dc8bdca64b1ecb2264dc4368e6479821936a158f37bcf40e99336c7a |
| src/musig.c | src/musig.c | 576bc0903fb72b2015010b6d91089e689719b9a38a6255909cc36da039ea85e7 |
| src/shachain.c | src/shachain.c | ac40525991c58cf63de5e2ae7f5a7bebad8a7b129055c0cdd990646f1c1b84b7 |
| src/tapscript.c | src/tapscript.c | 192b1d26a495a51974bd96b87e74e6d9911bb4fe4128662e93be08614a33e188 |
| src/tx_builder.c | src/tx_builder.c | e716e11ec3c377ddb9780e5b71ab8cb347077c9eb00d17314b2594a5d712530f |
| src/util.c | src/util.c | e3dd642fd4a5b19fca9976aafd1e35a9e178100d38e3c8b6ea1ad2f66acf64db |
| LICENSE | LICENSE | 0e9630e6a0a088e988aff20eed0bce3dba695e716ca5390e861ca748947c282b |

## Notes on this pin

Written by hand for the pin above (`50f7fa13`, the merge of SuperScalar pull request 505, 2026-11-13). `tools/update-import.sh` keeps this section as it is; after a re-import to another commit it must be rewritten.

### What is taken, and why

The same file set as the first import: the 17 translation units the tree builder and the signing code need (`factory`, `musig`, `dw_state`, `ladder`, `tx_builder`, `tapscript`, `adaptor`, `shachain`, `util`, `hd_key`, `bip39`, `bech32m`, `crypto_aead`, `fee`, `htlc_fee_bump`, `bolt11`, `fee_estimator_static`) and the headers they include, 38 files with the licence. The script finds the headers by following `#include` lines, so the set did not grow: none of the 14 changed files includes a header that was not already taken.

Not taken, as before: the daemons, the channel engine (`channel.c`; only `channel.h` is included), recovery, CPFP, the watchtower, persistence, the wire code and the payout broadcaster. Gazpacho writes those parts itself.

### Upstream changes since `e6573950` that affect Gazpacho

Changed files: `factory.c`, `factory.h`, `fee.c`, `fee.h`, `tx_builder.c`, `tx_builder.h`, `ladder.c`, `ladder.h`, `dw_state.c`, `dw_state.h`, `bolt11.c`, `channel.h`, `types.h`, `fee_estimator.h`.

| Upstream change | Pull request | Effect on Gazpacho |
|---|---|---|
| Every tree transaction is version 3, TRUC (`FACTORY_TREE_TX_VERSION`) | #476 | Every txid changes. `core/tree/model.c` writes version 3. Exits need Bitcoin Core 29.1 or later, and package submission when a transaction pays less than a server's floor (`spec/exit.md`) |
| The fee per transaction (`fee_per_tx`) and the fee estimator hook are gone. Each tree transaction pays `tree_fee_rate` (sat/kvB) for its own exact signed size; no floor; rate 0 allowed, with a zero-value anchor | #476 | `round_propose` record 30 carries the tree fee rate, which must equal the terms' rate (C8). `core/tree` computes each node's fee from its size (`gz_tree_fee`), and the funding rule R(root) changes (`spec/terms.md` 4.2) |
| `factory_check_tree_fees`: an audit of every built transaction from its bytes (version, one anchor, last, the exact fee) | #476 | Called by the glue after every build; a failure is a refusal (C1) |
| A level wider than its member count no longer makes one multi-member leaf; a node that cannot hold its anchor is refused; the layer counter refuses more than 8 layers | #486 | Former hazards of `signing-round.md` 12. Our own checks stay. `tests/scale/tree_shapes.c defects` now checks they stay fixed |
| `factory_set_level_arity`, `factory_set_funding` and the new `factory_set_placement_mode` return a result; `factory_build_tree` refuses a funding script that is not the root's aggregate | #486, #495 | The glue checks every result. C1's own funding-script check stays |
| The advanceless shape is upstream's default (`factory_advanceless_shape`: fan-out of at least 4 per level) | #494 | Not used: Gazpacho's shape comes from the terms (interior widths, then binary splits under leaf kind 3). Both are inputs to the same builder |
| Per-member channel capacities (`factory_set_member_capacities`) and a caller's channel script (`factory_set_leaf_channel_spk`) | #495 | **Not used yet.** Per-member capacities are a follow-up (`spec/terms.md` open point 6) |
| The distribution transaction: TRUC, paid at the tree rate, at most 230 clients (`FACTORY_MAX_DIST_CLIENTS`), capacities never scaled down | #476, #487 | Not used: a member still refuses a proposal that carries a payout (C8) |
| `channel.h`: the 228-output cap per commitment, on-chain HTLC claims, revocation results that must be checked (`SS_MUST_CHECK`) | #504, #505, #462 | Header only; no Gazpacho code uses it yet |
| Rotation off by default; `ladder.c` checks `factory_set_funding` | #488 | None |

Unchanged for Gazpacho: transaction sizes, every timeout height (`TIMEOUT_STEP_BLOCKS` 5; kickoff at E − 5·(2d − 1), leaf at E − 10·d, `src/factory.c:2053-2070`), the pseudo-Spilman channel output copying the leaf's script (`:1630-1633`), so H_leaf = E − 10·d; the 240-sat anchor at any rate above 0; the secp256k1-zkp pin.

