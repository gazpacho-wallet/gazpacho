#!/bin/sh
# List every signing or secret-key symbol used in C code outside signer/
# (docs/notes/signer.md 7.1, step S1).
#
# What it looks at: every *.c and *.h file under the root, except signer/
# (the one library allowed to hold secrets and sign), core/superscalar/
# (imported byte for byte; the object check of signer.md 7.1 allows the
# gazpacho_superscalar library by name), build folders and .git. Comments,
# string literals and character literals are blanked first, so a symbol named
# in a comment is not a use.
#
# What it looks for: the lines of tools/signer-only-symbols.txt.
#   sym NAME    the identifier NAME anywhere in code (a call, a declaration,
#               a function pointer taken);
#   hook NAME   a struct member NAME called, declared as a function pointer or
#               assigned: `x.NAME(`, `x->NAME(`, `(*NAME)(`, `x.NAME = ...`,
#               `.NAME = ...` (the generic hooks: secret(), sign(msg32)).
#
# Modes:
#   --report     (default) print the uses, per file, and how they compare with
#                the allow list; always exit 0. This is S1's mode.
#   --no-growth  as --report, but exit 1 if a use is not on the allow list
#                (GROWTH) or the allow list names more uses than there are
#                (STALE: the list must shrink with the code).
#   --fail       exit 1 on any use at all outside signer/. This is S4's mode.
#
# The allow list (tools/signer-boundary-allowed.txt) holds today's uses as
# FILE<TAB>SYMBOL<TAB>COUNT lines. It may only shrink: S4 empties it.
#
# usage: check-signer-boundary.sh [--report|--no-growth|--fail] [--root DIR]
#            [--symbols FILE] [--allow FILE] [--write-allow FILE]
# --write-allow FILE writes the current uses in the allow list's format (for
# the person shrinking the list; review the diff).
# POSIX sh, find, awk and sort only.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
mode=report
symbols=
allow=
write_allow=
while [ $# -gt 0 ]; do
    case "$1" in
        --report) mode=report ;;
        --no-growth) mode=no-growth ;;
        --fail) mode=fail ;;
        --root) root=$2; shift ;;
        --symbols) symbols=$2; shift ;;
        --allow) allow=$2; shift ;;
        --write-allow) write_allow=$2; shift ;;
        *) echo "usage: $0 [--report|--no-growth|--fail] [--root DIR] [--symbols FILE] [--allow FILE] [--write-allow FILE]" >&2
           exit 2 ;;
    esac
    shift
done
[ -n "$symbols" ] || symbols=$root/tools/signer-only-symbols.txt
[ -n "$allow" ] || allow=$root/tools/signer-boundary-allowed.txt
if [ ! -f "$symbols" ]; then
    echo "check-signer-boundary: no symbol list $symbols" >&2
    exit 2
fi
[ -f "$allow" ] || allow=/dev/null

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The files, as paths relative to the root, in a stable order.
(cd "$root" && find . \( -path ./signer -o -path ./core/superscalar -o -path './build*' -o -path ./.git \
        -o -name _deps \) -prune -o -type f \( -name '*.c' -o -name '*.h' \) -print) |
    sed 's|^\./||' | LC_ALL=C sort > "$tmp/files"

# One line per use: FILE<TAB>SYMBOL<TAB>LINE.
(cd "$root" && awk -v SYMS="$symbols" '
function strip(line,    out, i, c, n) {
    if (!inblk && line !~ /[\/"'"'"']/) return line
    out = ""; n = length(line); i = 1
    while (i <= n) {
        c = substr(line, i, 1)
        if (inblk) {
            if (c == "*" && substr(line, i + 1, 1) == "/") { inblk = 0; out = out "  "; i += 2; continue }
            out = out " "; i++; continue
        }
        if (instr) {
            if (c == "\\") { out = out "  "; i += 2; continue }
            if (c == q) instr = 0
            out = out " "; i++; continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { inblk = 1; out = out "  "; i += 2; continue }
        if (c == "/" && substr(line, i + 1, 1) == "/") break
        if (c == "\"" || c == "'"'"'") { instr = 1; q = c; out = out " "; i++; continue }
        out = out c; i++
    }
    instr = 0
    return out
}
BEGIN {
    ns = 0
    while ((getline l < SYMS) > 0) {
        sub(/#.*/, "", l)
        if (l ~ /^[ \t]*$/) continue
        k = split(l, f, /[ \t]+/)
        if (f[1] == "") { kind = f[2]; name = f[3] } else { kind = f[1]; name = f[2] }
        if (name !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || (kind != "sym" && kind != "hook")) {
            print "check-signer-boundary: bad line in symbol list: " l > "/dev/stderr"; bad = 1; exit 2
        }
        ns++
        label[ns] = (kind == "hook") ? "hook:" name : name
        if (kind == "sym") re[ns] = "(^|[^A-Za-z0-9_])" name "($|[^A-Za-z0-9_])"
        else re[ns] = "((\\.|->)[ \t]*" name "[ \t]*(\\(|=[^=]))|(\\([ \t]*\\*[ \t]*" name "[ \t]*\\)[ \t]*\\()"
    }
    if (ns == 0) { print "check-signer-boundary: empty symbol list" > "/dev/stderr"; bad = 1; exit 2 }
}
FNR == 1 { inblk = 0; instr = 0 }
{
    s0 = strip($0)
    for (j = 1; j <= ns; j++) {
        s = s0
        while (match(s, re[j])) {
            print FILENAME "\t" label[j] "\t" FNR
            # the rest after the match; "^" lets a symbol right after a boundary match again
            s = substr(s, RSTART + RLENGTH)
        }
    }
}
END { if (bad) exit 2 }
' $(cat "$tmp/files") /dev/null) > "$tmp/uses"

# FILE<TAB>SYMBOL<TAB>COUNT
cut -f1,2 "$tmp/uses" | LC_ALL=C sort | uniq -c |
    awk '{ c = $1; sub(/^ *[0-9]+ /, ""); print $0 "\t" c }' | LC_ALL=C sort > "$tmp/counts"
grep -v '^[[:space:]]*#' "$allow" | grep -v '^[[:space:]]*$' | LC_ALL=C sort > "$tmp/allowed" || true

if [ -n "$write_allow" ]; then
    {
        echo "# Uses of signer-only symbols outside signer/ on the day this list was written"
        echo "# (tools/check-signer-boundary.sh). FILE<TAB>SYMBOL<TAB>COUNT. The list may only"
        echo "# shrink; step S4 (docs/notes/signer.md 9) empties it and the check then fails"
        echo "# on any use."
        cat "$tmp/counts"
    } > "$write_allow"
fi

awk -F '\t' -v MODE="$mode" '
FILENAME == ARGV[1] { allowed[$1 "\t" $2] = $3 + 0; next }
{ cur[$1 "\t" $2] = $3 + 0; files[$1] += $3; total += $3; order[++n] = $1 "\t" $2 }
END {
    nf = 0; for (f in files) nf++
    printf "signer boundary (%s mode): %d uses of signer-only symbols outside signer/, in %d files\n", MODE, total, nf
    for (i = 1; i <= n; i++) {
        k = order[i]; split(k, p, "\t")
        if (p[1] != last) { printf "  %s: %d\n", p[1], files[p[1]]; last = p[1] }
        printf "      %-40s %d\n", p[2], cur[k]
    }
    growth = 0; stale = 0
    for (i = 1; i <= n; i++) {
        k = order[i]
        if (!(k in allowed) || cur[k] > allowed[k]) {
            split(k, p, "\t")
            printf "GROWTH %s: %s used %d times, allowed %d\n", p[1], p[2], cur[k], (k in allowed) ? allowed[k] : 0
            growth++
        }
    }
    for (k in allowed) {
        if (!(k in cur) || cur[k] < allowed[k]) {
            split(k, p, "\t")
            printf "STALE %s: %s allowed %d times, used %d: shrink the allow list\n", p[1], p[2], allowed[k], (k in cur) ? cur[k] : 0
            stale++
        }
    }
    if (MODE == "fail" && total > 0) { print "FAIL: signer-only symbols are used outside signer/"; exit 1 }
    if (MODE == "no-growth" && (growth || stale)) { printf "FAIL: %d growth, %d stale\n", growth, stale; exit 1 }
    if (MODE == "report") printf "report only: %d growth, %d stale (not a failure until S4)\n", growth, stale
}' "$tmp/allowed" "$tmp/counts"
