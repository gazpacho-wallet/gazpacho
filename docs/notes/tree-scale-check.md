# Tree scale check

2026-11-11, revised after review. Milestone M1a, part 1. Answers risk 0 in `docs/KNOWLEDGE-BASE.md` section 7: does one member per pseudo-Spilman leaf, under wide upper levels, build and sign at the sizes Gazpacho plans?

Everything here was run with the imported SuperScalar files as they are at the pinned commit (`core/superscalar/IMPORT.md`). No imported file was edited.

## What was run

`tests/scale/tree_shapes.c` builds a tree, signs every node in one process with all the keys (`factory_sign_all`), and checks every signature twice.

- **Its own check** takes nothing from the imported code but the transaction bytes. It parses each transaction; finds the output it spends by parsing the parent's bytes (amount and script); checks that the transaction ID is the double hash of the bytes, that the input names the double hash of the parent's bytes and the right output, and that the signed transaction is the unsigned one plus a single 64-byte witness; computes the BIP 341 signature hash itself, with OpenSSL's SHA-256 rather than the imported one; and verifies the signature against the key in the spent output's script. As a control it repeats the check for every node with the spent amount wrong by one satoshi, which must fail every time (column "Own check rejects a wrong amount").
- **The second opinion** is the imported `factory_verify_all`.

Exit delays are summed from the sequence field in each transaction's bytes, not from the imported structures.

Inputs, identical for every case:

- participant 0 is the host, 1..N the members; participant i has secret key = 32-byte big-endian integer i+1
- funding outpoint `aa..aa:0`, amount (N+1) x 100,000 + 1,000,000 sats, absolute timeout height 100,000
- 144 blocks per step, 4 states per layer, tree anchors on (`use_tree_anchor = 1`), fee 200 sats per transaction (the imported default)
- placement `PLACEMENT_SEQUENTIAL`, set explicitly: `factory_init` defaults to `PLACEMENT_TIMEZONE_CLUSTER`, which sorts
- the arity is set immediately after `factory_init`, and the program then asserts that the timed-layer counter is in a valid state before building (see error 2 for why)
- signing nonces come from `/dev/urandom` inside the imported `musig_generate_nonce`, so signatures differ from run to run; transaction IDs do not

Shape notation: `ps` is two-way levels all the way down to one-member pseudo-Spilman leaves (`factory_set_arity(FACTORY_ARITY_PS)`). `16,8,ps` is a 16-way root level, an 8-way second level, then two-way levels down to one-member pseudo-Spilman leaves (`factory_set_level_arity` with `{16, 8, FACTORY_ARITY_PS}`). "Fixed levels" is the argument to `factory_set_static_near_root`: that many levels from the root have no replaceable state and no timed layer.

Commands (on the build machine, from an out-of-tree build directory):

```
cmake -S gazpacho -B build-rel -DCMAKE_BUILD_TYPE=Release
cmake --build build-rel --target tree_shapes
./build-rel/tree_shapes                  # the whole table below
./build-rel/tree_shapes 512 16,16,ps 2   # one case: MEMBERS SHAPE FIXED-LEVELS
./build-rel/tree_shapes defects          # errors 4 and 5 below, reproduced directly

cmake -S gazpacho -B build-san -DCMAKE_BUILD_TYPE=Release -DGZ_SANITIZE=ON
cmake --build build-san --target tree_shapes
./build-san/tree_shapes                  # same cases under AddressSanitizer + UBSan
```

Machine: the project build server, Ubuntu 26.04, 4 cores, 15 GB, gcc 15.2.0, Release build at `-O3`. Each case runs in its own child process; time and peak memory are per case.

## Reading of the results

1. **One member per pseudo-Spilman leaf works at every size tried: 16, 32, 64, 127, 255, 256, 512 and 1000 members.** Every valid shape built, signed and verified, in at most a few seconds and about 110 MB.
2. **No compile-time limit stops 512, but every run at 257 members or more passes through a memory error in the imported `factory_init` (error 2).** `FACTORY_MAX_SIGNERS` (256), `FACTORY_MAX_LEAVES` (256) and `FACTORY_MAX_NODES` (512) are only defaults now: `factory_init` grows them to fit the participant count, and `factory_build_tree` grows the node array. But `factory_init` itself writes one element past the timed-layer array for 257 to 512 members, and two for 513 or more. The write is repaired only by the `factory_set_arity` or `factory_set_level_arity` call that follows. A caller that sets the arity immediately after `factory_init`, as this program does, gets a correct tree; a caller that does anything else with the factory first is working on a corrupted counter. So the target size of 512 depends on that call order until the imported code is fixed. The knowledge-base statement that the shared files cap a factory at 256 signers, 256 leaves and 512 transactions is out of date for this single-process path. See "Limits" for what else remains.
3. **Exit delay depends only on how many timed levels are on the path**, at 432 blocks (3 days) each with these settings. The leaf itself adds none. At 512 members: 3,888 blocks (27 days) with two-way levels throughout; 1,296 blocks (9 days) with two 16-way levels; 432 blocks (3 days) with two 16-way levels both fixed. A two-way tree is therefore unusable at this size, and wide upper levels are what make 512 workable.
4. **The imported delay functions under-report on deep trees.** When a tree has more than 8 timed levels, `factory_early_warning_time` and `factory_compute_ewt_for_shape` return 3,024 blocks while the transactions themselves add up to 3,456 (255 and 256 members, `ps`), 3,888 (512, `ps`) and 4,320 (1000, `ps`). The column "Exit delay, blocks (summed from txs)" is the one to trust. The shapes Gazpacho would use have at most 4 timed levels and the two figures agree there.
5. **Three shape rules the imported code does not enforce**, each found by a case that went wrong:
   - A level of width W turns any subtree of W or fewer members into one leaf holding all of them, not a pseudo-Spilman leaf. Nothing reports it. (Rows showing `0 / k` leaves; error 5.) A W-way level is only usable where every subtree arriving at it has more than W members.
   - If such a multi-member leaf sits inside the fixed levels, the build reads outside an array (error 1).
   - A node with 16 child outputs gets no fee anchor: `FACTORY_MAX_OUTPUTS` is 16 and the anchor would be the 17th, so it is left off without an error and its 240 sats go to the fee. (Column "Nodes without anchor"; error 4.) The widest level that keeps its anchor is 15. `15,15,ps` with 2 fixed levels at 512 members has every anchor and an 864-block (6-day) exit.

## Results: Release build

The column "Imported: layers after init / after shape" shows what `factory_init` left in the layer counter and what it held once the shape was set. A first figure above 8 is error 2 showing itself.

| Members | Shape | Fixed levels | Built | Signed | Verified (own check / nodes) | Own check rejects a wrong amount (nodes) | Imported verifier | Nodes | Root signers | Leaves (one-member PS / all) | Txs on longest exit | Timed txs on it | Exit delay, blocks (summed from txs) | Imported: layers after init / after shape | Imported: delay built / by shape | Largest tx, bytes (outputs) | Longest exit, bytes | Nodes without anchor | Build s | Sign s | Verify s | Peak MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 16 | ps | 0 | yes | yes | 62 / 62 | 62 | pass | 62 | 17 | 16 / 16 | 10 | 4 | 1728 | 4 / 5 | 1728 / 1728 | 218 (3) | 1965 | 0 | 0.01 | 0.02 | 0.01 | 7.5 |
| 16 | 4,ps | 0 | yes | yes | 58 / 58 | 58 | pass | 58 | 17 | 16 / 16 | 8 | 3 | 1296 | 4 / 4 | 1296 / 1296 | 304 (5) | 1658 | 0 | 0.01 | 0.02 | 0.01 | 7.4 |
| 16 | 8,ps | 0 | yes | yes | 50 / 50 | 50 | pass | 50 | 17 | 16 / 16 | 6 | 2 | 864 | 4 / 3 | 864 / 864 | 476 (9) | 1437 | 0 | 0.01 | 0.02 | 0.01 | 7.3 |
| 16 | 16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.00 | 0.00 | 0.00 | 6.2 |
| 16 | 16,ps | 1 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.00 | 0.00 | 0.00 | 6.2 |
| 16 | 4,4,ps | 0 | yes | yes | 10 / 10 | 10 | pass | 10 | 17 | 0 / 4 | 4 | 2 | 864 | 4 / 2 | 864 / 864 | 334 (5) | 988 | 4 | 0.01 | 0.01 | 0.00 | 6.3 |
| 16 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 17 | 0 / 8 | 4 | 2 | 864 | 4 / 2 | 864 / 864 | 476 (9) | 1074 | 8 | 0.01 | 0.01 | 0.00 | 6.4 |
| 16 | 8,8,ps | 2 | yes | yes | 17 / 17 | 17 | pass | 17 | 17 | 0 / 8 | 3 | 0 | 0 | 4 / 1 | 432 / 432 | 476 (9) | 899 | 8 | 0.01 | 0.01 | 0.00 | 6.4 |
| 16 | 15,15,ps | 2 | yes | yes | 31 / 31 | 31 | pass | 31 | 17 | 0 / 15 | 3 | 0 | 0 | 4 / 1 | 432 / 432 | 777 (16) | 1200 | 1 | 0.01 | 0.01 | 0.01 | 6.8 |
| 16 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.00 | 0.00 | 0.00 | 6.2 |
| 16 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.00 | 0.00 | 0.00 | 6.2 |
| 16 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.00 | 0.00 | 0.00 | 6.2 |
| 32 | ps | 0 | yes | yes | 126 / 126 | 126 | pass | 126 | 33 | 32 / 32 | 12 | 5 | 2160 | 5 / 6 | 2160 / 2160 | 218 (3) | 2358 | 0 | 0.03 | 0.05 | 0.02 | 9.2 |
| 32 | 4,ps | 0 | yes | yes | 122 / 122 | 122 | pass | 122 | 33 | 32 / 32 | 10 | 4 | 1728 | 5 / 5 | 1728 / 1728 | 304 (5) | 2051 | 0 | 0.02 | 0.05 | 0.02 | 9.0 |
| 32 | 8,ps | 0 | yes | yes | 114 / 114 | 114 | pass | 114 | 33 | 32 / 32 | 8 | 3 | 1296 | 5 / 4 | 1296 / 1296 | 476 (9) | 1830 | 0 | 0.02 | 0.04 | 0.02 | 8.8 |
| 32 | 16,ps | 0 | yes | yes | 98 / 98 | 98 | pass | 98 | 33 | 32 / 32 | 6 | 2 | 864 | 5 / 3 | 864 / 864 | 807 (16) | 1768 | 1 | 0.02 | 0.03 | 0.02 | 8.4 |
| 32 | 16,ps | 1 | yes | yes | 97 / 97 | 97 | pass | 97 | 33 | 32 / 32 | 5 | 1 | 432 | 5 / 2 | 432 / 432 | 807 (16) | 1593 | 1 | 0.02 | 0.03 | 0.02 | 8.4 |
| 32 | 4,4,ps | 0 | yes | yes | 106 / 106 | 106 | pass | 106 | 33 | 32 / 32 | 8 | 3 | 1296 | 5 / 4 | 1296 / 1296 | 304 (5) | 1744 | 0 | 0.02 | 0.04 | 0.02 | 8.7 |
| 32 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 33 | 0 / 8 | 4 | 2 | 864 | 5 / 2 | 864 / 864 | 476 (9) | 1160 | 8 | 0.01 | 0.01 | 0.00 | 6.5 |
| 32 | 8,8,ps | 2 | yes | yes | 17 / 17 | 17 | pass | 17 | 33 | 0 / 8 | 3 | 0 | 0 | 5 / 1 | 432 / 432 | 476 (9) | 985 | 8 | 0.01 | 0.01 | 0.00 | 6.4 |
| 32 | 15,15,ps | 2 | yes | yes | 31 / 31 | 31 | pass | 31 | 33 | 0 / 15 | 3 | 0 | 0 | 5 / 1 | 432 / 432 | 777 (16) | 1243 | 15 | 0.01 | 0.01 | 0.01 | 6.8 |
| 32 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 33 | 0 / 16 | 4 | 2 | 864 | 5 / 2 | 864 / 864 | 807 (16) | 1405 | 17 | 0.01 | 0.02 | 0.01 | 6.9 |
| 32 | 16,16,ps | 2 | yes | yes | 33 / 33 | 33 | pass | 33 | 33 | 0 / 16 | 3 | 0 | 0 | 5 / 1 | 432 / 432 | 807 (16) | 1230 | 17 | 0.01 | 0.01 | 0.01 | 6.8 |
| 32 | 16,16,16,ps | 3 | yes | yes | 33 / 33 | 33 | pass | 33 | 33 | 0 / 16 | 3 | 0 | 0 | 5 / 1 | 432 / 432 | 807 (16) | 1230 | 17 | 0.01 | 0.01 | 0.01 | 6.8 |
| 64 | ps | 0 | yes | yes | 254 / 254 | 254 | pass | 254 | 65 | 64 / 64 | 14 | 6 | 2592 | 6 / 7 | 2592 / 2592 | 218 (3) | 2751 | 0 | 0.06 | 0.12 | 0.05 | 12.3 |
| 64 | 4,ps | 0 | yes | yes | 250 / 250 | 250 | pass | 250 | 65 | 64 / 64 | 12 | 5 | 2160 | 6 / 6 | 2160 / 2160 | 304 (5) | 2444 | 0 | 0.05 | 0.11 | 0.05 | 12.2 |
| 64 | 8,ps | 0 | yes | yes | 242 / 242 | 242 | pass | 242 | 65 | 64 / 64 | 10 | 4 | 1728 | 6 / 5 | 1728 / 1728 | 476 (9) | 2223 | 0 | 0.05 | 0.11 | 0.04 | 11.9 |
| 64 | 16,ps | 0 | yes | yes | 226 / 226 | 226 | pass | 226 | 65 | 64 / 64 | 8 | 3 | 1296 | 6 / 4 | 1296 / 1296 | 807 (16) | 2161 | 1 | 0.04 | 0.08 | 0.04 | 11.5 |
| 64 | 16,ps | 1 | yes | yes | 225 / 225 | 225 | pass | 225 | 65 | 64 / 64 | 7 | 2 | 864 | 6 / 3 | 864 / 864 | 807 (16) | 1986 | 1 | 0.04 | 0.08 | 0.04 | 11.4 |
| 64 | 4,4,ps | 0 | yes | yes | 234 / 234 | 234 | pass | 234 | 65 | 64 / 64 | 10 | 4 | 1728 | 6 / 5 | 1728 / 1728 | 304 (5) | 2137 | 0 | 0.05 | 0.10 | 0.04 | 11.8 |
| 64 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 65 | 0 / 8 | 4 | 2 | 864 | 6 / 2 | 864 / 864 | 506 (9) | 1332 | 8 | 0.02 | 0.02 | 0.00 | 6.5 |
| 64 | 8,8,ps | 2 | yes | yes | 17 / 17 | 17 | pass | 17 | 65 | 0 / 8 | 3 | 0 | 0 | 6 / 1 | 432 / 432 | 506 (9) | 1157 | 8 | 0.02 | 0.02 | 0.00 | 6.5 |
| 64 | 15,15,ps | 2 | yes | yes | 31 / 31 | 31 | pass | 31 | 65 | 0 / 15 | 3 | 0 | 0 | 6 / 1 | 432 / 432 | 777 (16) | 1329 | 15 | 0.02 | 0.02 | 0.01 | 6.8 |
| 64 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 65 | 0 / 16 | 4 | 2 | 864 | 6 / 2 | 864 / 864 | 807 (16) | 1491 | 17 | 0.02 | 0.03 | 0.01 | 6.9 |
| 64 | 16,16,ps | 2 | yes | yes | 33 / 33 | 33 | pass | 33 | 65 | 0 / 16 | 3 | 0 | 0 | 6 / 1 | 432 / 432 | 807 (16) | 1316 | 17 | 0.02 | 0.02 | 0.01 | 6.9 |
| 64 | 16,16,16,ps | 3 | yes | yes | 33 / 33 | 33 | pass | 33 | 65 | 0 / 16 | 3 | 0 | 0 | 6 / 1 | 432 / 432 | 807 (16) | 1316 | 17 | 0.02 | 0.02 | 0.01 | 6.9 |
| 127 | ps | 0 | yes | yes | 506 / 506 | 506 | pass | 506 | 128 | 127 / 127 | 16 | 7 | 3024 | 7 / 8 | 3024 / 3024 | 218 (3) | 3144 | 0 | 0.13 | 0.26 | 0.09 | 18.7 |
| 127 | 4,ps | 0 | yes | yes | 502 / 502 | 502 | pass | 502 | 128 | 127 / 127 | 14 | 6 | 2592 | 7 / 7 | 2592 / 2592 | 304 (5) | 2837 | 0 | 0.11 | 0.24 | 0.09 | 18.4 |
| 127 | 8,ps | 0 | yes | yes | 494 / 494 | 494 | pass | 494 | 128 | 127 / 127 | 12 | 5 | 2160 | 7 / 6 | 2160 / 2160 | 476 (9) | 2616 | 0 | 0.11 | 0.22 | 0.09 | 18.2 |
| 127 | 16,ps | 0 | yes | yes | 478 / 478 | 478 | pass | 478 | 128 | 127 / 127 | 10 | 4 | 1728 | 7 / 5 | 1728 / 1728 | 807 (16) | 2554 | 1 | 0.09 | 0.22 | 0.09 | 17.7 |
| 127 | 16,ps | 1 | yes | yes | 477 / 477 | 477 | pass | 477 | 128 | 127 / 127 | 9 | 3 | 1296 | 7 / 4 | 1296 / 1296 | 807 (16) | 2379 | 1 | 0.09 | 0.18 | 0.09 | 17.6 |
| 127 | 4,4,ps | 0 | yes | yes | 486 / 486 | 486 | pass | 486 | 128 | 127 / 127 | 12 | 5 | 2160 | 7 / 6 | 2160 / 2160 | 304 (5) | 2530 | 0 | 0.11 | 0.22 | 0.09 | 17.9 |
| 127 | 8,8,ps | 0 | yes | yes | 398 / 398 | 398 | pass | 398 | 128 | 127 / 127 | 8 | 3 | 1296 | 7 / 4 | 1296 / 1296 | 476 (9) | 2088 | 0 | 0.07 | 0.16 | 0.07 | 15.8 |
| 127 | 8,8,ps | 2 | yes | yes | 389 / 389 | 389 | pass | 389 | 128 | 127 / 127 | 6 | 1 | 432 | 7 / 2 | 432 / 432 | 476 (9) | 1738 | 0 | 0.07 | 0.13 | 0.07 | 15.4 |
| 127 | 15,15,ps | 2 | yes | yes | 31 / 31 | 31 | pass | 31 | 128 | 0 / 15 | 3 | 0 | 0 | 7 / 1 | 432 / 432 | 777 (16) | 1501 | 15 | 0.03 | 0.04 | 0.01 | 6.9 |
| 127 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 128 | 0 / 16 | 4 | 2 | 864 | 7 / 2 | 864 / 864 | 807 (16) | 1663 | 17 | 0.04 | 0.05 | 0.01 | 7.0 |
| 127 | 16,16,ps | 2 | yes | yes | 33 / 33 | 33 | pass | 33 | 128 | 0 / 16 | 3 | 0 | 0 | 7 / 1 | 432 / 432 | 807 (16) | 1488 | 17 | 0.03 | 0.04 | 0.01 | 6.9 |
| 127 | 16,16,16,ps | 3 | yes | yes | 33 / 33 | 33 | pass | 33 | 128 | 0 / 16 | 3 | 0 | 0 | 7 / 1 | 432 / 432 | 807 (16) | 1488 | 17 | 0.03 | 0.04 | 0.01 | 6.9 |
| 255 | ps | 0 | yes | yes | 1018 / 1018 | 1018 | pass | 1018 | 256 | 255 / 255 | 18 | 8 | 3456 | 8 / 8 | 3024 / 3024 | 218 (3) | 3537 | 0 | 0.35 | 0.57 | 0.18 | 31.5 |
| 255 | 4,ps | 0 | yes | yes | 1014 / 1014 | 1014 | pass | 1014 | 256 | 255 / 255 | 16 | 7 | 3024 | 8 / 8 | 3024 / 3024 | 304 (5) | 3230 | 0 | 0.26 | 0.51 | 0.19 | 31.2 |
| 255 | 8,ps | 0 | yes | yes | 1006 / 1006 | 1006 | pass | 1006 | 256 | 255 / 255 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 476 (9) | 3009 | 0 | 0.23 | 0.51 | 0.18 | 30.9 |
| 255 | 16,ps | 0 | yes | yes | 990 / 990 | 990 | pass | 990 | 256 | 255 / 255 | 12 | 5 | 2160 | 8 / 6 | 2160 / 2160 | 807 (16) | 2947 | 1 | 0.21 | 0.44 | 0.18 | 30.4 |
| 255 | 16,ps | 1 | yes | yes | 989 / 989 | 989 | pass | 989 | 256 | 255 / 255 | 11 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 807 (16) | 2772 | 1 | 0.20 | 0.41 | 0.18 | 30.2 |
| 255 | 4,4,ps | 0 | yes | yes | 998 / 998 | 998 | pass | 998 | 256 | 255 / 255 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 304 (5) | 2923 | 0 | 0.23 | 0.49 | 0.19 | 30.7 |
| 255 | 8,8,ps | 0 | yes | yes | 910 / 910 | 910 | pass | 910 | 256 | 255 / 255 | 10 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 476 (9) | 2481 | 0 | 0.18 | 0.37 | 0.16 | 28.2 |
| 255 | 8,8,ps | 2 | yes | yes | 901 / 901 | 901 | pass | 901 | 256 | 255 / 255 | 8 | 2 | 864 | 8 / 3 | 864 / 864 | 476 (9) | 2131 | 0 | 0.15 | 0.32 | 0.16 | 27.9 |
| 255 | 15,15,ps | 2 | yes | yes | 586 / 586 | 586 | pass | 586 | 256 | 255 / 255 | 6 | 1 | 432 | 8 / 2 | 432 / 432 | 777 (16) | 2340 | 0 | 0.10 | 0.20 | 0.11 | 20.2 |
| 255 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 864 | 0 (0) | 0 | 0 | 0.02 | 0.00 | 0.00 | 6.2 |
| 255 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 6.2 |
| 255 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 6.2 |
| 256 | ps | 0 | yes | yes | 1022 / 1022 | 1022 | pass | 1022 | 257 | 256 / 256 | 18 | 8 | 3456 | 8 / 8 | 3024 / 3024 | 218 (3) | 3537 | 0 | 0.27 | 0.56 | 0.19 | 31.7 |
| 256 | 4,ps | 0 | yes | yes | 1018 / 1018 | 1018 | pass | 1018 | 257 | 256 / 256 | 16 | 7 | 3024 | 8 / 8 | 3024 / 3024 | 304 (5) | 3230 | 0 | 0.25 | 0.52 | 0.19 | 31.4 |
| 256 | 8,ps | 0 | yes | yes | 1010 / 1010 | 1010 | pass | 1010 | 257 | 256 / 256 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 476 (9) | 3009 | 0 | 0.25 | 0.48 | 0.18 | 31.0 |
| 256 | 16,ps | 0 | yes | yes | 994 / 994 | 994 | pass | 994 | 257 | 256 / 256 | 12 | 5 | 2160 | 8 / 6 | 2160 / 2160 | 807 (16) | 2947 | 1 | 0.25 | 0.43 | 0.17 | 30.5 |
| 256 | 16,ps | 1 | yes | yes | 993 / 993 | 993 | pass | 993 | 257 | 256 / 256 | 11 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 807 (16) | 2772 | 1 | 0.19 | 0.39 | 0.17 | 30.4 |
| 256 | 4,4,ps | 0 | yes | yes | 1002 / 1002 | 1002 | pass | 1002 | 257 | 256 / 256 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 304 (5) | 2923 | 0 | 0.22 | 0.46 | 0.18 | 30.8 |
| 256 | 8,8,ps | 0 | yes | yes | 914 / 914 | 914 | pass | 914 | 257 | 256 / 256 | 10 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 476 (9) | 2481 | 0 | 0.18 | 0.37 | 0.16 | 28.4 |
| 256 | 8,8,ps | 2 | yes | yes | 905 / 905 | 905 | pass | 905 | 257 | 256 / 256 | 8 | 2 | 864 | 8 / 3 | 864 / 864 | 476 (9) | 2131 | 0 | 0.15 | 0.33 | 0.16 | 28.0 |
| 256 | 15,15,ps | 2 | yes | yes | 590 / 590 | 590 | pass | 590 | 257 | 256 / 256 | 6 | 1 | 432 | 8 / 2 | 432 / 432 | 777 (16) | 2340 | 0 | 0.10 | 0.20 | 0.11 | 20.4 |
| 256 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 864 | 0 (0) | 0 | 0 | 0.02 | 0.00 | 0.00 | 6.4 |
| 256 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 6.3 |
| 256 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 6.3 |
| 512 | ps | 0 | yes | yes | 2046 / 2046 | 2046 | pass | 2046 | 513 | 512 / 512 | 20 | 9 | 3888 | 9 / 8 | 3024 / 3024 | 218 (3) | 3930 | 0 | 0.59 | 1.23 | 0.37 | 57.6 |
| 512 | 4,ps | 0 | yes | yes | 2042 / 2042 | 2042 | pass | 2042 | 513 | 512 / 512 | 18 | 8 | 3456 | 9 / 8 | 3024 / 3024 | 304 (5) | 3623 | 0 | 0.55 | 1.13 | 0.37 | 57.2 |
| 512 | 8,ps | 0 | yes | yes | 2034 / 2034 | 2034 | pass | 2034 | 513 | 512 / 512 | 16 | 7 | 3024 | 9 / 8 | 3024 / 3024 | 476 (9) | 3402 | 0 | 0.50 | 1.07 | 0.37 | 56.7 |
| 512 | 16,ps | 0 | yes | yes | 2018 / 2018 | 2018 | pass | 2018 | 513 | 512 / 512 | 14 | 6 | 2592 | 9 / 7 | 2592 / 2592 | 807 (16) | 3340 | 1 | 0.46 | 0.96 | 0.38 | 56.0 |
| 512 | 16,ps | 1 | yes | yes | 2017 / 2017 | 2017 | pass | 2017 | 513 | 512 / 512 | 13 | 5 | 2160 | 9 / 6 | 2160 / 2160 | 807 (16) | 3165 | 1 | 0.45 | 0.91 | 0.38 | 55.9 |
| 512 | 4,4,ps | 0 | yes | yes | 2026 / 2026 | 2026 | pass | 2026 | 513 | 512 / 512 | 16 | 7 | 3024 | 9 / 8 | 3024 / 3024 | 304 (5) | 3316 | 0 | 0.51 | 1.06 | 0.37 | 56.5 |
| 512 | 8,8,ps | 0 | yes | yes | 1938 / 1938 | 1938 | pass | 1938 | 513 | 512 / 512 | 12 | 5 | 2160 | 9 / 6 | 2160 / 2160 | 476 (9) | 2874 | 0 | 0.42 | 0.86 | 0.35 | 53.7 |
| 512 | 8,8,ps | 2 | yes | yes | 1929 / 1929 | 1929 | pass | 1929 | 513 | 512 / 512 | 10 | 3 | 1296 | 9 / 4 | 1296 / 1296 | 476 (9) | 2524 | 0 | 0.38 | 0.78 | 0.36 | 53.2 |
| 512 | 15,15,ps | 2 | yes | yes | 1614 / 1614 | 1614 | pass | 1614 | 513 | 512 / 512 | 8 | 2 | 864 | 9 / 3 | 864 / 864 | 777 (16) | 2733 | 0 | 0.27 | 0.62 | 0.30 | 45.2 |
| 512 | 16,16,ps | 0 | yes | yes | 1570 / 1570 | 1570 | pass | 1570 | 513 | 512 / 512 | 8 | 3 | 1296 | 9 / 4 | 1296 / 1296 | 807 (16) | 2750 | 17 | 0.31 | 0.62 | 0.29 | 44.5 |
| 512 | 16,16,ps | 2 | yes | yes | 1553 / 1553 | 1553 | pass | 1553 | 513 | 512 / 512 | 6 | 1 | 432 | 9 / 2 | 432 / 432 | 807 (16) | 2400 | 17 | 0.27 | 0.54 | 0.29 | 43.8 |
| 512 | 16,16,16,ps | 3 | yes | yes | 529 / 529 | 529 | pass | 529 | 513 | 0 / 256 | 4 | 0 | 0 | 9 / 1 | 432 / 432 | 807 (16) | 2037 | 273 | 0.19 | 0.27 | 0.10 | 19.3 |
| 1000 | ps | 0 | yes | yes | 3998 / 3998 | 3998 | pass | 3998 | 1001 | 1000 / 1000 | 22 | 10 | 4320 | 10 / 8 | 3024 / 3024 | 218 (3) | 4323 | 0 | 1.29 | 2.51 | 0.73 | 107.7 |
| 1000 | 4,ps | 0 | yes | yes | 3994 / 3994 | 3994 | pass | 3994 | 1001 | 1000 / 1000 | 20 | 9 | 3888 | 10 / 8 | 3024 / 3024 | 304 (5) | 4016 | 0 | 1.18 | 2.46 | 0.73 | 106.9 |
| 1000 | 8,ps | 0 | yes | yes | 3986 / 3986 | 3986 | pass | 3986 | 1001 | 1000 / 1000 | 18 | 8 | 3456 | 10 / 8 | 3024 / 3024 | 476 (9) | 3795 | 0 | 1.07 | 2.20 | 0.72 | 106.0 |
| 1000 | 16,ps | 0 | yes | yes | 3970 / 3970 | 3970 | pass | 3970 | 1001 | 1000 / 1000 | 16 | 7 | 3024 | 10 / 8 | 3024 / 3024 | 807 (16) | 3733 | 1 | 1.02 | 2.12 | 0.73 | 105.0 |
| 1000 | 16,ps | 1 | yes | yes | 3969 / 3969 | 3969 | pass | 3969 | 1001 | 1000 / 1000 | 15 | 6 | 2592 | 10 / 7 | 2592 / 2592 | 807 (16) | 3558 | 1 | 0.92 | 1.92 | 0.72 | 104.7 |
| 1000 | 4,4,ps | 0 | yes | yes | 3978 / 3978 | 3978 | pass | 3978 | 1001 | 1000 / 1000 | 18 | 8 | 3456 | 10 / 8 | 3024 / 3024 | 304 (5) | 3709 | 0 | 1.06 | 2.21 | 0.74 | 105.9 |
| 1000 | 8,8,ps | 0 | yes | yes | 3890 / 3890 | 3890 | pass | 3890 | 1001 | 1000 / 1000 | 14 | 6 | 2592 | 10 / 7 | 2592 / 2592 | 476 (9) | 3267 | 0 | 0.93 | 1.88 | 0.71 | 102.5 |
| 1000 | 8,8,ps | 2 | yes | yes | 3881 / 3881 | 3881 | pass | 3881 | 1001 | 1000 / 1000 | 12 | 4 | 1728 | 10 / 5 | 1728 / 1728 | 476 (9) | 2917 | 0 | 0.84 | 1.74 | 0.71 | 101.5 |
| 1000 | 15,15,ps | 2 | yes | yes | 3566 / 3566 | 3566 | pass | 3566 | 1001 | 1000 / 1000 | 10 | 3 | 1296 | 10 / 4 | 1296 / 1296 | 777 (16) | 3126 | 0 | 0.74 | 1.32 | 0.64 | 93.0 |
| 1000 | 16,16,ps | 0 | yes | yes | 3522 / 3522 | 3522 | pass | 3522 | 1001 | 1000 / 1000 | 10 | 4 | 1728 | 10 / 5 | 1728 / 1728 | 807 (16) | 3143 | 17 | 0.73 | 1.42 | 0.63 | 92.5 |
| 1000 | 16,16,ps | 2 | yes | yes | 3505 / 3505 | 3505 | pass | 3505 | 1001 | 1000 / 1000 | 8 | 2 | 864 | 10 / 3 | 864 / 864 | 807 (16) | 2793 | 17 | 0.62 | 1.28 | 0.63 | 91.5 |
| 1000 | 16,16,16,ps | 3 | yes | yes | 529 / 529 | 529 | pass | 529 | 1001 | 0 / 256 | 4 | 0 | 0 | 10 / 1 | 432 / 432 | 807 (16) | 2123 | 273 | 0.31 | 0.49 | 0.11 | 20.2 |

63 of 96 cases built, signed, verified and had one member per pseudo-Spilman leaf.

Rows marked `NO` under Built stopped with `Factory: n-way leaf needs 17 outputs > max 16` (a 16-way level given 16 or fewer members per subtree, so 16 members landed in one leaf). Rows with `0 / k` leaves built multi-member leaves; they are kept in the table because the silent change of leaf type is itself a finding.

## Results: AddressSanitizer + UBSan

Same program, same cases, `-fsanitize=address,undefined -fno-sanitize-recover=undefined`.

- **The sanitizers reported nothing** for the 52 cases at 512 members or fewer that are valid shapes (built, signed, verified, every leaf a one-member pseudo-Spilman leaf). Five single cases (`64 8,ps 0`, `255 16,ps 1`, `512 15,15,ps 2`, `512 16,16,ps 2`, `512 ps 0`) were also run in single-case mode, where the leak checker runs at exit: no leaks, no reports.
- **That is not the same as "no memory error".** The 512-member cases in that list make the out-of-bounds write of error 2 inside `factory_init`. Neither sanitizer can see it: the write lands inside the same structure, so AddressSanitizer has no red zone to trip, and UBSan's bounds check allows an index one past the end. "No report" at 257 to 512 members means only that the damage stayed inside the counter and was repaired by the next call.
- 14 cases stopped at `factory.c:148` (error 1) and all 12 cases at 1000 members stopped at `dw_state.c:46` (error 2, where the index reaches 9 and UBSan does object).

Rows the sanitizer run produced (a stopped case prints no row):

| Members | Shape | Fixed levels | Built | Signed | Verified (own check / nodes) | Own check rejects a wrong amount (nodes) | Imported verifier | Nodes | Root signers | Leaves (one-member PS / all) | Txs on longest exit | Timed txs on it | Exit delay, blocks (summed from txs) | Imported: layers after init / after shape | Imported: delay built / by shape | Largest tx, bytes (outputs) | Longest exit, bytes | Nodes without anchor | Build s | Sign s | Verify s | Peak MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 16 | ps | 0 | yes | yes | 62 / 62 | 62 | pass | 62 | 17 | 16 / 16 | 10 | 4 | 1728 | 4 / 5 | 1728 / 1728 | 218 (3) | 1965 | 0 | 0.05 | 0.09 | 0.04 | 31.8 |
| 16 | 4,ps | 0 | yes | yes | 58 / 58 | 58 | pass | 58 | 17 | 16 / 16 | 8 | 3 | 1296 | 4 / 4 | 1296 / 1296 | 304 (5) | 1658 | 0 | 0.04 | 0.08 | 0.04 | 31.0 |
| 16 | 8,ps | 0 | yes | yes | 50 / 50 | 50 | pass | 50 | 17 | 16 / 16 | 6 | 2 | 864 | 4 / 3 | 864 / 864 | 476 (9) | 1437 | 0 | 0.03 | 0.07 | 0.04 | 30.1 |
| 16 | 16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 22.5 |
| 16 | 16,ps | 1 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 22.5 |
| 16 | 4,4,ps | 0 | yes | yes | 10 / 10 | 10 | pass | 10 | 17 | 0 / 4 | 4 | 2 | 864 | 4 / 2 | 864 / 864 | 334 (5) | 988 | 4 | 0.02 | 0.03 | 0.01 | 26.7 |
| 16 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 17 | 0 / 8 | 4 | 2 | 864 | 4 / 2 | 864 / 864 | 476 (9) | 1074 | 8 | 0.02 | 0.04 | 0.01 | 27.6 |
| 16 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 22.5 |
| 16 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 22.5 |
| 16 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 4 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.01 | 0.00 | 0.00 | 22.5 |
| 32 | ps | 0 | yes | yes | 126 / 126 | 126 | pass | 126 | 33 | 32 / 32 | 12 | 5 | 2160 | 5 / 6 | 2160 / 2160 | 218 (3) | 2358 | 0 | 0.10 | 0.23 | 0.08 | 37.5 |
| 32 | 4,ps | 0 | yes | yes | 122 / 122 | 122 | pass | 122 | 33 | 32 / 32 | 10 | 4 | 1728 | 5 / 5 | 1728 / 1728 | 304 (5) | 2051 | 0 | 0.08 | 0.17 | 0.08 | 36.5 |
| 32 | 8,ps | 0 | yes | yes | 114 / 114 | 114 | pass | 114 | 33 | 32 / 32 | 8 | 3 | 1296 | 5 / 4 | 1296 / 1296 | 476 (9) | 1830 | 0 | 0.08 | 0.16 | 0.08 | 35.4 |
| 32 | 16,ps | 0 | yes | yes | 98 / 98 | 98 | pass | 98 | 33 | 32 / 32 | 6 | 2 | 864 | 5 / 3 | 864 / 864 | 807 (16) | 1768 | 1 | 0.06 | 0.12 | 0.06 | 33.8 |
| 32 | 16,ps | 1 | yes | yes | 97 / 97 | 97 | pass | 97 | 33 | 32 / 32 | 5 | 1 | 432 | 5 / 2 | 432 / 432 | 807 (16) | 1593 | 1 | 0.06 | 0.12 | 0.07 | 33.4 |
| 32 | 4,4,ps | 0 | yes | yes | 106 / 106 | 106 | pass | 106 | 33 | 32 / 32 | 8 | 3 | 1296 | 5 / 4 | 1296 / 1296 | 304 (5) | 1744 | 0 | 0.07 | 0.14 | 0.07 | 35.1 |
| 32 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 33 | 0 / 8 | 4 | 2 | 864 | 5 / 2 | 864 / 864 | 476 (9) | 1160 | 8 | 0.04 | 0.05 | 0.01 | 28.4 |
| 32 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 33 | 0 / 16 | 4 | 2 | 864 | 5 / 2 | 864 / 864 | 807 (16) | 1405 | 17 | 0.06 | 0.06 | 0.02 | 29.5 |
| 64 | ps | 0 | yes | yes | 254 / 254 | 254 | pass | 254 | 65 | 64 / 64 | 14 | 6 | 2592 | 6 / 7 | 2592 / 2592 | 218 (3) | 2751 | 0 | 0.20 | 0.41 | 0.17 | 47.8 |
| 64 | 4,ps | 0 | yes | yes | 250 / 250 | 250 | pass | 250 | 65 | 64 / 64 | 12 | 5 | 2160 | 6 / 6 | 2160 / 2160 | 304 (5) | 2444 | 0 | 0.18 | 0.39 | 0.18 | 46.7 |
| 64 | 8,ps | 0 | yes | yes | 242 / 242 | 242 | pass | 242 | 65 | 64 / 64 | 10 | 4 | 1728 | 6 / 5 | 1728 / 1728 | 476 (9) | 2223 | 0 | 0.16 | 0.38 | 0.16 | 45.2 |
| 64 | 16,ps | 0 | yes | yes | 226 / 226 | 226 | pass | 226 | 65 | 64 / 64 | 8 | 3 | 1296 | 6 / 4 | 1296 / 1296 | 807 (16) | 2161 | 1 | 0.14 | 0.29 | 0.15 | 43.2 |
| 64 | 16,ps | 1 | yes | yes | 225 / 225 | 225 | pass | 225 | 65 | 64 / 64 | 7 | 2 | 864 | 6 / 3 | 864 / 864 | 807 (16) | 1986 | 1 | 0.13 | 0.28 | 0.15 | 42.7 |
| 64 | 4,4,ps | 0 | yes | yes | 234 / 234 | 234 | pass | 234 | 65 | 64 / 64 | 10 | 4 | 1728 | 6 / 5 | 1728 / 1728 | 304 (5) | 2137 | 0 | 0.16 | 0.33 | 0.16 | 44.7 |
| 64 | 8,8,ps | 0 | yes | yes | 18 / 18 | 18 | pass | 18 | 65 | 0 / 8 | 4 | 2 | 864 | 6 / 2 | 864 / 864 | 506 (9) | 1332 | 8 | 0.07 | 0.09 | 0.01 | 30.2 |
| 64 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 65 | 0 / 16 | 4 | 2 | 864 | 6 / 2 | 864 / 864 | 807 (16) | 1491 | 17 | 0.07 | 0.10 | 0.02 | 31.2 |
| 127 | ps | 0 | yes | yes | 506 / 506 | 506 | pass | 506 | 128 | 127 / 127 | 16 | 7 | 3024 | 7 / 8 | 3024 / 3024 | 218 (3) | 3144 | 0 | 0.43 | 0.89 | 0.48 | 67.9 |
| 127 | 4,ps | 0 | yes | yes | 502 / 502 | 502 | pass | 502 | 128 | 127 / 127 | 14 | 6 | 2592 | 7 / 7 | 2592 / 2592 | 304 (5) | 2837 | 0 | 0.39 | 0.83 | 0.34 | 65.9 |
| 127 | 8,ps | 0 | yes | yes | 494 / 494 | 494 | pass | 494 | 128 | 127 / 127 | 12 | 5 | 2160 | 7 / 6 | 2160 / 2160 | 476 (9) | 2616 | 0 | 0.36 | 0.75 | 0.32 | 63.8 |
| 127 | 16,ps | 0 | yes | yes | 478 / 478 | 478 | pass | 478 | 128 | 127 / 127 | 10 | 4 | 1728 | 7 / 5 | 1728 / 1728 | 807 (16) | 2554 | 1 | 0.32 | 0.67 | 0.32 | 61.1 |
| 127 | 16,ps | 1 | yes | yes | 477 / 477 | 477 | pass | 477 | 128 | 127 / 127 | 9 | 3 | 1296 | 7 / 4 | 1296 / 1296 | 807 (16) | 2379 | 1 | 0.34 | 0.62 | 0.31 | 60.1 |
| 127 | 4,4,ps | 0 | yes | yes | 486 / 486 | 486 | pass | 486 | 128 | 127 / 127 | 12 | 5 | 2160 | 7 / 6 | 2160 / 2160 | 304 (5) | 2530 | 0 | 0.41 | 0.76 | 0.33 | 63.4 |
| 127 | 8,8,ps | 0 | yes | yes | 398 / 398 | 398 | pass | 398 | 128 | 127 / 127 | 8 | 3 | 1296 | 7 / 4 | 1296 / 1296 | 476 (9) | 2088 | 0 | 0.28 | 0.57 | 0.27 | 55.4 |
| 127 | 8,8,ps | 2 | yes | yes | 389 / 389 | 389 | pass | 389 | 128 | 127 / 127 | 6 | 1 | 432 | 7 / 2 | 432 / 432 | 476 (9) | 1738 | 0 | 0.23 | 0.49 | 0.27 | 53.0 |
| 127 | 16,16,ps | 0 | yes | yes | 34 / 34 | 34 | pass | 34 | 128 | 0 / 16 | 4 | 2 | 864 | 7 / 2 | 864 / 864 | 807 (16) | 1663 | 17 | 0.13 | 0.17 | 0.02 | 34.1 |
| 255 | ps | 0 | yes | yes | 1018 / 1018 | 1018 | pass | 1018 | 256 | 255 / 255 | 18 | 8 | 3456 | 8 / 8 | 3024 / 3024 | 218 (3) | 3537 | 0 | 0.95 | 1.96 | 0.67 | 109.9 |
| 255 | 4,ps | 0 | yes | yes | 1014 / 1014 | 1014 | pass | 1014 | 256 | 255 / 255 | 16 | 7 | 3024 | 8 / 8 | 3024 / 3024 | 304 (5) | 3230 | 0 | 0.89 | 1.74 | 0.66 | 106.3 |
| 255 | 8,ps | 0 | yes | yes | 1006 / 1006 | 1006 | pass | 1006 | 256 | 255 / 255 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 476 (9) | 3009 | 0 | 0.77 | 1.70 | 0.64 | 102.5 |
| 255 | 16,ps | 0 | yes | yes | 990 / 990 | 990 | pass | 990 | 256 | 255 / 255 | 12 | 5 | 2160 | 8 / 6 | 2160 / 2160 | 807 (16) | 2947 | 1 | 0.71 | 1.49 | 0.64 | 98.1 |
| 255 | 16,ps | 1 | yes | yes | 989 / 989 | 989 | pass | 989 | 256 | 255 / 255 | 11 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 807 (16) | 2772 | 1 | 0.66 | 1.53 | 0.68 | 96.6 |
| 255 | 4,4,ps | 0 | yes | yes | 998 / 998 | 998 | pass | 998 | 256 | 255 / 255 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 304 (5) | 2923 | 0 | 0.80 | 1.67 | 0.66 | 102.1 |
| 255 | 8,8,ps | 0 | yes | yes | 910 / 910 | 910 | pass | 910 | 256 | 255 / 255 | 10 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 476 (9) | 2481 | 0 | 0.61 | 1.28 | 0.58 | 90.9 |
| 255 | 8,8,ps | 2 | yes | yes | 901 / 901 | 901 | pass | 901 | 256 | 255 / 255 | 8 | 2 | 864 | 8 / 3 | 864 / 864 | 476 (9) | 2131 | 0 | 0.52 | 1.14 | 0.57 | 87.0 |
| 255 | 15,15,ps | 2 | yes | yes | 586 / 586 | 586 | pass | 586 | 256 | 255 / 255 | 6 | 1 | 432 | 8 / 2 | 432 / 432 | 777 (16) | 2340 | 0 | 0.37 | 0.66 | 0.40 | 66.4 |
| 255 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 864 | 0 (0) | 0 | 0 | 0.08 | 0.00 | 0.00 | 26.1 |
| 255 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.04 | 0.00 | 0.00 | 25.8 |
| 255 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.04 | 0.00 | 0.00 | 25.8 |
| 256 | ps | 0 | yes | yes | 1022 / 1022 | 1022 | pass | 1022 | 257 | 256 / 256 | 18 | 8 | 3456 | 8 / 8 | 3024 / 3024 | 218 (3) | 3537 | 0 | 0.95 | 1.90 | 0.70 | 110.1 |
| 256 | 4,ps | 0 | yes | yes | 1018 / 1018 | 1018 | pass | 1018 | 257 | 256 / 256 | 16 | 7 | 3024 | 8 / 8 | 3024 / 3024 | 304 (5) | 3230 | 0 | 0.87 | 1.80 | 0.68 | 106.6 |
| 256 | 8,ps | 0 | yes | yes | 1010 / 1010 | 1010 | pass | 1010 | 257 | 256 / 256 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 476 (9) | 3009 | 0 | 0.79 | 1.67 | 0.65 | 102.8 |
| 256 | 16,ps | 0 | yes | yes | 994 / 994 | 994 | pass | 994 | 257 | 256 / 256 | 12 | 5 | 2160 | 8 / 6 | 2160 / 2160 | 807 (16) | 2947 | 1 | 0.70 | 1.46 | 0.64 | 98.4 |
| 256 | 16,ps | 1 | yes | yes | 993 / 993 | 993 | pass | 993 | 257 | 256 / 256 | 11 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 807 (16) | 2772 | 1 | 0.71 | 1.40 | 0.63 | 96.8 |
| 256 | 4,4,ps | 0 | yes | yes | 1002 / 1002 | 1002 | pass | 1002 | 257 | 256 / 256 | 14 | 6 | 2592 | 8 / 7 | 2592 / 2592 | 304 (5) | 2923 | 0 | 0.77 | 1.61 | 0.68 | 102.3 |
| 256 | 8,8,ps | 0 | yes | yes | 914 / 914 | 914 | pass | 914 | 257 | 256 / 256 | 10 | 4 | 1728 | 8 / 5 | 1728 / 1728 | 476 (9) | 2481 | 0 | 0.60 | 1.29 | 0.59 | 91.3 |
| 256 | 8,8,ps | 2 | yes | yes | 905 / 905 | 905 | pass | 905 | 257 | 256 / 256 | 8 | 2 | 864 | 8 / 3 | 864 / 864 | 476 (9) | 2131 | 0 | 0.54 | 1.18 | 0.67 | 87.4 |
| 256 | 15,15,ps | 2 | yes | yes | 590 / 590 | 590 | pass | 590 | 257 | 256 / 256 | 6 | 1 | 432 | 8 / 2 | 432 / 432 | 777 (16) | 2340 | 0 | 0.35 | 0.72 | 0.39 | 66.8 |
| 256 | 16,16,ps | 0 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 864 | 0 (0) | 0 | 0 | 0.08 | 0.00 | 0.00 | 26.1 |
| 256 | 16,16,ps | 2 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.04 | 0.00 | 0.00 | 25.9 |
| 256 | 16,16,16,ps | 3 | NO | - | 0 / 0 | 0 | - | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 8 / 0 | 0 / 432 | 0 (0) | 0 | 0 | 0.05 | 0.00 | 0.00 | 25.9 |
| 512 | ps | 0 | yes | yes | 2046 / 2046 | 2046 | pass | 2046 | 513 | 512 / 512 | 20 | 9 | 3888 | 144 / 8 | 3024 / 3024 | 218 (3) | 3930 | 0 | 2.02 | 4.23 | 1.33 | 197.5 |
| 512 | 4,ps | 0 | yes | yes | 2042 / 2042 | 2042 | pass | 2042 | 513 | 512 / 512 | 18 | 8 | 3456 | 144 / 8 | 3024 / 3024 | 304 (5) | 3623 | 0 | 1.83 | 3.82 | 1.31 | 190.5 |
| 512 | 8,ps | 0 | yes | yes | 2034 / 2034 | 2034 | pass | 2034 | 513 | 512 / 512 | 16 | 7 | 3024 | 144 / 8 | 3024 / 3024 | 476 (9) | 3402 | 0 | 1.69 | 3.58 | 1.29 | 183.3 |
| 512 | 16,ps | 0 | yes | yes | 2018 / 2018 | 2018 | pass | 2018 | 513 | 512 / 512 | 14 | 6 | 2592 | 144 / 7 | 2592 / 2592 | 807 (16) | 3340 | 1 | 1.61 | 3.24 | 1.30 | 175.3 |
| 512 | 16,ps | 1 | yes | yes | 2017 / 2017 | 2017 | pass | 2017 | 513 | 512 / 512 | 13 | 5 | 2160 | 144 / 6 | 2160 / 2160 | 807 (16) | 3165 | 1 | 1.56 | 3.19 | 1.32 | 171.9 |
| 512 | 4,4,ps | 0 | yes | yes | 2026 / 2026 | 2026 | pass | 2026 | 513 | 512 / 512 | 16 | 7 | 3024 | 144 / 8 | 3024 / 3024 | 304 (5) | 3316 | 0 | 1.70 | 3.61 | 1.32 | 182.8 |
| 512 | 8,8,ps | 0 | yes | yes | 1938 / 1938 | 1938 | pass | 1938 | 513 | 512 / 512 | 12 | 5 | 2160 | 144 / 6 | 2160 / 2160 | 476 (9) | 2874 | 0 | 1.38 | 2.94 | 1.26 | 164.9 |
| 512 | 8,8,ps | 2 | yes | yes | 1929 / 1929 | 1929 | pass | 1929 | 513 | 512 / 512 | 10 | 3 | 1296 | 144 / 4 | 1296 / 1296 | 476 (9) | 2524 | 0 | 1.24 | 2.63 | 1.23 | 157.5 |
| 512 | 15,15,ps | 2 | yes | yes | 1614 / 1614 | 1614 | pass | 1614 | 513 | 512 / 512 | 8 | 2 | 864 | 144 / 3 | 864 / 864 | 777 (16) | 2733 | 0 | 0.90 | 1.97 | 1.03 | 131.3 |
| 512 | 16,16,ps | 0 | yes | yes | 1570 / 1570 | 1570 | pass | 1570 | 513 | 512 / 512 | 8 | 3 | 1296 | 144 / 4 | 1296 / 1296 | 807 (16) | 2750 | 17 | 0.99 | 2.18 | 1.01 | 134.6 |
| 512 | 16,16,ps | 2 | yes | yes | 1553 / 1553 | 1553 | pass | 1553 | 513 | 512 / 512 | 6 | 1 | 432 | 144 / 2 | 432 / 432 | 807 (16) | 2400 | 17 | 0.88 | 1.85 | 1.13 | 126.8 |

## Errors found in the imported code

Reported, not fixed. File and line are at the pinned commit.

1. **Out-of-bounds read, `src/factory.c:148`** (`node_nsequence`), index -1 into `dw_counter_t.layers[8]`. `build_subtree` (`factory.c:1651-1652`) gives a state node `dw_layer_index = -1` when its depth is inside the fixed levels, and a leaf at that depth is still built as a state node (`factory.c:1669` only clears `is_static`). Any leaf that is not pseudo-Spilman then indexes `layers[-1]`. Triggered by: `8,8,ps` fixed 2 at 16, 32, 64 members; `15,15,ps` fixed 2 at 16 to 127; `16,16,ps` fixed 2 at 32 to 127; `16,16,16,ps` fixed 3 at 32 to 127 and at 512. In the Release build these cases "work" and report a 0-block exit delay taken from whatever sits before the array. One-member pseudo-Spilman leaves do not reach this line.

2. **Out-of-bounds write, `src/dw_state.c:46`** (`dw_counter_init`), reached from `factory_init_with_config` at `src/factory.c:826` (the same code is at `:884` in `factory_init_from_pubkeys`). **It happens in every factory of 257 members or more, including every run at the 512-member target.**

   `factory_init` starts every factory as two-members-per-leaf and asks for depth + 1 timed layers without the `DW_MAX_LAYERS` (8) cap that every later call applies: 9 layers for 257 to 512 members, 10 for 513 to 1024. `dw_counter_init` then writes `layers[8]` (and `layers[9]`) of an 8-element array.

   - `layers[8]` is not outside the counter. `dw_layer_t` is 12 bytes and `dw_counter_t` is 108: `layers[8]` occupies bytes 96 to 107, which are the counter's own `n_layers`, `total_states` and `current_epoch`. So for 257 to 512 members the counter overwrites its own bookkeeping and nothing beyond it.
   - What the counter holds afterwards depends on how the compiler ordered the stores. Calling `dw_counter_init(&counter, 9, 144, 4)` directly on this machine gave `n_layers = 144, total_states = 4` at `-O0`, `-O1`, `-O2` and under the sanitizers, and `n_layers = 9, total_states = 262144` at `-O3`. The Release build here is `-O3`, which is why the Release table shows 9 in "layers after init" at 512 members (and 10 at 1000), while the sanitizer build, whose stores come out in the other order, shows 144 at 512. Neither value is one the counter's own definition allows.
   - Neither sanitizer reports the 257-to-512 case: the write stays inside the enclosing structure, and UBSan's array-bounds check permits an index one past the end. From 513 members the index reaches 9, which UBSan stops (the 12 cases at 1000 members), and the write goes past the counter into the fields of `factory_t` that follow it.
   - The only repair is the next `factory_set_arity` or `factory_set_level_arity` call, which re-initialises the counter with the cap. Until then `counter.n_layers` is wrong, and anything that reads the counter (`factory_early_warning_time`, `factory_advance`, a tree build) reads garbage. `factory_build_tree` also re-initialises it.

   **Rule for callers: set the arity immediately after `factory_init` and before anything else.** `tests/scale/tree_shapes.c` does that and then asserts the counter is valid (layer count 1 to 8, every layer's configuration as requested, total states consistent, epoch 0) before it builds; a case where that assertion failed would be reported as `NO (counter not sane)`. None was.

3. **Wrong exit delay on deep trees**, `factory_early_warning_time` (`src/factory.c:4900`) and `factory_compute_ewt_for_shape` (`:4945`). The counter is capped at 8 layers (`factory.c:716`), deeper levels share the last layer (`factory.c:1653-1654`), and one layer is then subtracted for the pseudo-Spilman leaf even though the leaf was never one of the 8. Result: 432 blocks too few per level beyond 8. Reading item 4 above.

4. **Anchor silently dropped at 16 outputs**, `factory_append_tree_anchor` (`src/factory.c:501`), while its cost is still taken from the node's budget. Reproduced directly by `tree_shapes defects`, which builds 32 members with shape `16,ps` and inspects every node:

   ```
   anchor: 32 members, shape 16,ps, anchors on, fee 200 sats per transaction
     nodes with 16 outputs: 1; of those without an anchor output: 1; of those leaving fee + 240 sats unspent: 1
     all other nodes: 97; with an anchor output: 97; leaving exactly the fee: 97
   ```

   The one 16-output node has no anchor and leaves 440 sats unspent (the 200-sat fee plus the 240 sats set aside for the anchor it did not get). Every other node has its anchor and leaves exactly the fee.

5. **Leaf type silently changed** by `subtree_is_leaf` (`src/factory.c:949-956`) when a wide level meets a small subtree. Reproduced directly by `tree_shapes defects`:

   ```
   leaves: 16 members; a shape ending in ps asks for 16 one-member pseudo-Spilman leaves
     shape 4,ps:   16 leaves, 16 of them one-member pseudo-Spilman
     shape 8,8,ps: 8 leaves, 0 of them one-member pseudo-Spilman; members in the first leaf: 2; factory_build_tree returned success
   ```

   Not a memory error; a shape that looks like one member per leaf is not, and the build reports success.

## Limits

| Limit | Value | What it does today |
|---|---|---|
| `FACTORY_MAX_SIGNERS` | 256 | Default only for the tree: `factory_config_fit` (`factory.c:741`) raises `config.max_signers` to the participant count. Still a hard limit in: the ladder (`ladder.c:35`, stack arrays at `:47`, `:184`, `:202`); the per-input sessions of multi-member sub-factory leaves (`factory.c:2015`, `:3418`, and the 16 KB `input_signer_indices` table inside every node); `factory_session_set_partial_sig_poison` (`factory.c:3667`), which only matters for a node with more than 256 signers and leaves have 2 |
| `FACTORY_MAX_LEAVES` | 256 | Default only; raised to the participant count the same way |
| `FACTORY_MAX_NODES` | 512 | Default only; `factory_build_tree` reallocates (`factory.c:1921`). Still hard in one place that matters: `apply_l_stock_hashlock` (`factory.c:393`) ignores a host-supplied leaf hash for any node whose index is 512 or more. A member's copy of a tree with more than 512 transactions, with the hash-locked penalty switched on, would therefore build different leaf scripts from the host's for the later leaves. Read, not run: it needs the member-side path, which this check does not exercise. One-member leaves pass 512 transactions at about 130 members. The other uses (`factory.c:1022`, `:2167` to `:2229`, `:4783`, `:4958`) are work stacks bounded by depth, not by size |
| `FACTORY_MAX_OUTPUTS` | 16 | Hard. Fixed arrays in every node. Caps a level's width at 16, and at 15 if the node is to keep its anchor |
| `FACTORY_MAX_LEVELS` | 8 | Hard. Longer width lists are cut to 8 entries without an error (`factory.c:1172`). The last entry repeats, so `16,16,ps` needs only 3 |
| `DW_MAX_LAYERS` | 8 | Hard. At most 8 timed layers; errors 2 and 3 above come from it |
| `MUSIG_SESSION_MAX_SIGNERS` | 256 | Defined in `musig.h:64` and used nowhere in the imported sources. Sessions are sized to the signer count. Signed and verified here with 1,001 signers at the root |
| `MUSIG_NONCE_POOL_MAX` | 256 | Hard for the pre-generated nonce pool (`musig.c:179`). The host signs every node, up to 2,046 at 512 members, so it cannot take a whole tree's nonces from one pool. The signing-round specification uses `musig_generate_nonce` directly, which has no such limit |

**Is there a supported way to raise them at run time?** Partly. `factory_init_with_config` takes a `factory_config_t` (`max_signers`, `max_nodes`, `max_leaves`, `max_outputs_per_node`, `dust_limit_sats`), and plain `factory_init` already sizes the first three to the participant count, so nothing needs to be passed. `factory_alloc_default_arrays` is not a way to raise anything: it allocates at the defaults for a zeroed structure and is a no-op once arrays exist. `max_outputs_per_node` can only be lowered in effect, since the arrays are fixed at 16. Levels and timed layers have no run-time setting.

Memory: `sizeof(factory_t)` is 264,408 bytes and `sizeof(factory_node_t)` is 23,816 bytes, so a 2,046-node tree is about 49 MB of nodes before signatures.

## What was not tested, and why

- **Signing by separate parties.** Everything was signed in one process holding every key, through `factory_sign_all`. The split path (`factory_session_*`, one nonce and one partial signature per signer per node, with partial-signature verification) is the signing round engine's job and comes next. Message sizes and round times at 512 members are therefore unknown.
- **Changing state.** No leaf was advanced, no layer updated, no liquidity moved. Only the initial tree.
- **The member's side of the tree** (`factory_init_from_pubkeys`, host-supplied leaf hashes) and the hash-locked penalty. See `FACTORY_MAX_NODES` above.
- **Anything on a chain.** No node was run. Whether these transactions relay and confirm at real fee rates is not shown here. The largest is 807 bytes; the longest exit at 512 members is 6 to 20 transactions and 2.4 to 3.9 kB.
- **Script paths.** The own check verifies the key-path signature of every tree transaction. It does not examine the timeout script branch each output also commits to.
- **Repeatable signatures.** Nonces come from the operating system inside the imported code, so two runs give different signatures.
- **Sizes above 1000**, and 1000 under sanitizers (stopped by error 2).
- **Timing on small machines.** Figures are from one 4-core server.
