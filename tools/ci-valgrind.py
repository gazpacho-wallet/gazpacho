#!/usr/bin/env python3
"""CI's valgrind run: tools/valgrind-tests.py with the arguments CI gives it.

    python3 -I tools/ci-valgrind.py BUILD_DIR [--shard I/N] [--include REGEX] [--exclude REGEX]

The one list of the shorter cases that every test runs with under memcheck,
used by ci.yml's valgrind shards and by agent-run.yml, so an agent's run is
CI's. The 1,000-seed simulator run takes over eight minutes under valgrind;
200 seeds of the same length here, all 1,000 in every other build.
storage_vector_e2r (Argon2id at 256 MiB) is E2's code at more memory and is
always left out. The signing sections run their "tiny" sets (every path, fewer
seeds) and the engine fuzzer a short run: the full sets take hours here.

Without --include or --exclude every --args below is passed, and
valgrind-tests.py fails if one of them names no test, as in CI. With them
(agent runs), only the --args of tests they select are passed. Standard
library only.
"""
import argparse
import os
import re
import subprocess
import sys

ALWAYS_EXCLUDED = r"^storage_vector_e2r$"

ARGS = [
    "sim_seeds=200 400 1 0", "journal_fuzz=3000 7",
    "journal_fuzz_model=200 1", "journal_fuzz_open=3000 1",
    "lobby_sim_profile_0=3 0", "lobby_sim_profile_1=3 1",
    "lobby_sim_profile_2=3 2", "lobby_sim_profile_3=3 3",
    "lobby_fuzz=3000 2", "lobby_fuzz_seq=300 2",
    "api_http_fuzz=3000", "api_json_fuzz=20000",
    "node_fuzz=300", "node_hostile=6 400", "sim_profile_6=25 300 1 6",
    "node_lobby=1500 1", "lobby_hostile=3000 2",
    "chain_fuzz_parse=20000", "chain_fuzz_watch=1500",
    "signing_blocks=blocks tiny", "signing_decoders=decoders tiny",
    "signing_golden=golden tiny", "signing_model=model tiny",
    "signing_faults=faults tiny", "signing_honest=honest tiny",
    "signing_t1=t1 tiny", "signing_crashes=crashes tiny",
    "signing_restores=restores tiny", "signing_errors=errors tiny",
    "signing_fuzz=1000 2",
    "signing_fuzz_replay=1000",
    "fuzz_tree_agree=40",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build")
    ap.add_argument("--shard", default=None)
    ap.add_argument("--include", default=None)
    ap.add_argument("--exclude", default=None)
    a = ap.parse_args()
    exclude = ALWAYS_EXCLUDED + ("|" + a.exclude if a.exclude else "")
    cmd = [sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "valgrind-tests.py"),
           a.build, "--exclude", exclude]
    if a.include:
        cmd += ["--include", a.include]
    if a.shard:
        cmd += ["--shard", a.shard]
    for spec in ARGS:
        name = spec.partition("=")[0]
        if a.include and not re.search(a.include, name):
            continue
        if a.exclude and re.search(a.exclude, name):
            continue
        cmd += ["--args", spec]
    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    sys.exit(main())
