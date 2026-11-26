# R6, the mass exit: the sizes it runs at

An amendment to the Slice 1.5 plan (`docs/SLICE-1.5-PLAN.md`, test R6 and item P8). The owner decided on 2026-11-26.

**R6 runs at 128 and 256 members.** 256 is the wallet's real maximum. The plan's 512 is out of scope, for two reasons:

- **The wallet refuses more than 256 members.** The rules cap a tree at `GZ_TREE_MAX_MEMBERS` (256; `core/tree/include/gazpacho/tree.h`, signing-round.md 12), and `gz_tree_params` refuses any count above it.
- **The imported tree builder writes out of bounds from 257 members on.** Its `factory_init` writes past its timed-layer array, and the write is repaired only when `factory_set_level_arity` is called next (`docs/notes/tree-scale-check.md`, finding 2). A test at 512 would rest on that write.

**512 returns when both are true:** the wallet supports more than 256 members, and the import is fixed upstream.

## Where this is applied

- **`tests/regtest/tree_massexit.c` refuses more than 256 members.** So every R6 tree is built twice, by the rules and by the import, and the two must agree byte for byte.
- **`tools/regtest-mass-exit.py`** refuses more than 256 members too.
- **`.github/workflows/regtest-mass-exit.yml`** runs 128 and 256 every night and by default on demand, and refuses sizes above 256.
- **Plan wording:** R6's row in the plan ("at 128 and 512 members") and P8's ("a 128- and a 512-member tree") read 128 and 256.
