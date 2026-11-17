#!/usr/bin/env python3
"""Test for tools/check-no-addresses.py: link targets, Unix server paths, --rev.

    python3 -I tests/tools/test_check_no_addresses.py

Makes a throwaway git repository with a copy of the check, commits files that
it must refuse (a symbolic link whose target is a server folder, a server path
in a text file, a server path in a commit message, an address) and files it
must accept, and checks the verdict for the work tree and for each commit.
The paths are built from pieces so that this file passes the check itself.
Standard library only; needs git and a system that makes symbolic links.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools", "check-no-addresses.py")
SERVER_DIR = "/" + "ro" + "ot/gz/web/pw/node_modules"
HOME_DIR = "/" + "ho" + "me/alice/notes.txt"
VAR_DIR = "/" + "v" + "ar/lib/thing"
ADDR = ".".join(["8", "8", "4", "4"])
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_NOSYSTEM="1",
           HOME=tempfile.gettempdir())
failures = []


def git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), check=True, capture_output=True, env=ENV).stdout.decode()


def check(repo, *args):
    r = subprocess.run([sys.executable, "-I", os.path.join(repo, "tools", "check-no-addresses.py")] + list(args),
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def expect(what, cond, out=""):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)
        print(out)


def main():
    repo = tempfile.mkdtemp(prefix="addrcheck-")
    try:
        git(repo, "init", "-q", "-b", "main")
        os.makedirs(os.path.join(repo, "tools"))
        shutil.copy(CHECK, os.path.join(repo, "tools", "check-no-addresses.py"))
        with open(os.path.join(repo, "clean.md"), "w") as f:
            f.write("Loopback 127.0.0.1 and a documentation address 192.0.2.7 are fine.\n"
                    "So is a URL path: https://example.org/var/x and a relative path tests/web/README.md.\n"
                    "An XDG note: $XDG_RUNTIME_DIR, not a server folder.\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "clean")
        clean = git(repo, "rev-parse", "HEAD").strip()
        rc, out = check(repo)
        expect("a clean tree passes", rc == 0, out)
        rc, out = check(repo, "--rev", clean)
        expect("a clean commit passes", rc == 0, out)

        os.symlink(SERVER_DIR, os.path.join(repo, "node_modules"))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "a link made by a test run")
        link = git(repo, "rev-parse", "HEAD").strip()
        rc, out = check(repo)
        expect("a link to a server folder is refused (work tree)", rc == 1 and "node_modules (link target)" in out, out)
        rc, out = check(repo, "--rev", link)
        expect("a link to a server folder is refused (--rev)", rc == 1 and "node_modules (link target)" in out, out)

        os.remove(os.path.join(repo, "node_modules"))
        with open(os.path.join(repo, "notes.md"), "w") as f:
            f.write("Built in %s and %s.\n" % (HOME_DIR, VAR_DIR))
            f.write("Refused on purpose: %s  <!-- address-check: allow -->\n" % SERVER_DIR)
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "run it from " + SERVER_DIR)
        paths = git(repo, "rev-parse", "HEAD").strip()
        rc, out = check(repo)
        expect("home and var paths in a file are refused", rc == 1 and out.count("Unix server path") == 1 and "notes.md:1" in out, out)
        expect("a marked line is allowed", "notes.md:2" not in out, out)
        rc, out = check(repo, "--rev", paths)
        expect("a server path in a commit message is refused", rc == 1 and "message" in out, out)
        expect("the link removed is not found in the later commit", "link target" not in out, out)

        with open(os.path.join(repo, "notes.md"), "w") as f:
            f.write("Host %s is not loopback.\n" % ADDR)
        rc, out = check(repo, "notes.md")
        expect("an address in a named file is still refused", rc == 1 and "IPv4 address " + ADDR in out, out)
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    if failures:
        print("FAIL: %d of the checks" % len(failures))
        return 1
    print("PASS: tools/check-no-addresses.py refuses link targets, server paths and commit messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
