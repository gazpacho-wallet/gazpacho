#!/usr/bin/env python3
"""The key port's join window equals the core's pair tries (review of PR 53, L1).

    python3 -I join_window.py SOURCE_DIR

program/keys.h's GZP_KEYS_JOIN_TRIES must equal core/node/lobbyslot.c's
LS_KEY_TRIES (#55), the pairs the core tries for a new slot. A core with no
such skip allocates exactly the first pair after the highest index, which the
window holds too; the test then says so and passes."""
import os
import re
import sys

src = sys.argv[1]
keys = open(os.path.join(src, "program", "keys.h")).read()
core = open(os.path.join(src, "core", "node", "lobbyslot.c")).read()
m = re.search(r"#define GZP_KEYS_JOIN_TRIES (\d+)u", keys)
c = re.search(r"#define LS_KEY_TRIES (\d+)", core)
if not m:
    sys.exit("join window: GZP_KEYS_JOIN_TRIES not found in program/keys.h")
if not c:
    print("join window: the core has no pair skip (no LS_KEY_TRIES): its one pair is in the window of %s" % m.group(1))
    sys.exit(0)
if m.group(1) != c.group(1):
    sys.exit("join window: GZP_KEYS_JOIN_TRIES %s differs from the core's LS_KEY_TRIES %s" % (m.group(1), c.group(1)))
print("join window: GZP_KEYS_JOIN_TRIES equals the core's LS_KEY_TRIES (%s)" % m.group(1))
