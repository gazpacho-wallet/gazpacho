#!/bin/sh
# expect-exit.sh WANT_EXIT REGEX COMMAND...
# Runs COMMAND and passes only if it exits with WANT_EXIT and its output
# (stdout and stderr) matches REGEX. For tool tests whose right answer is a
# refusal (a non-zero exit), so that tools/valgrind-tests.py, which requires
# exit 0 from the programs it runs, lists them as script tests.
want=$1 re=$2
shift 2
out=$("$@" 2>&1)
got=$?
if [ "$got" != "$want" ] || ! printf '%s\n' "$out" | grep -Eq -- "$re"; then
  echo "exit $got (wanted $want)"
  printf '%s\n' "$out"
  exit 1
fi
echo "ok: exit $got, output matches"
