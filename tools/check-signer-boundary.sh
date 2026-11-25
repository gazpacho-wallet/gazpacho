#!/bin/sh
# List every signing or secret-key symbol used in C code outside signer/
# (docs/notes/signer.md 7.1, step S1).
#
# What it looks at: every C, C++ and assembly file under the root, except signer/
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
#   hard NAME, hardprefix PREFIX
#               fail in every mode, report included: the fixed-aux test build
#               (GZ_SG_VECTORS, gz_sgv_*), also in CMakeLists.txt and *.cmake;
#               and any #include of a .c or .inc file of signer/.
# Files scanned: *.c, *.h, *.inc, *.cpp, *.cc, *.S. Pruned: signer/,
# core/superscalar/, and exactly build/, build-*/, _deps/ and .git/ at the root.
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
# --base-allow FILE, --base-symbols FILE: the merge base's allow list and symbol
# list; the first may only shrink, the second may only grow.
# --write-allow FILE writes the current uses in the allow list's format (for
# the person shrinking the list; review the diff).
# POSIX sh, git (ls-files), find, awk, sort and comm only.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
mode=report
symbols=
allow=
write_allow=
base_allow=
base_symbols=
while [ $# -gt 0 ]; do
    case "$1" in
        --report) mode=report ;;
        --no-growth) mode=no-growth ;;
        --fail) mode=fail ;;
        --root) root=$2; shift ;;
        --symbols) symbols=$2; shift ;;
        --allow) allow=$2; shift ;;
        --write-allow) write_allow=$2; shift ;;
        --base-allow) base_allow=$2; shift ;;
        --base-symbols) base_symbols=$2; shift ;;
        *) echo "usage: $0 [--report|--no-growth|--fail] [--root DIR] [--symbols FILE] [--allow FILE] [--write-allow FILE] [--base-allow FILE] [--base-symbols FILE]" >&2
           exit 2 ;;
    esac
    shift
done
root=$(cd "$root" && pwd)   # absolute: the scan runs from inside it
[ -n "$symbols" ] || symbols=$root/tools/signer-only-symbols.txt
[ -n "$allow" ] || allow=$root/tools/signer-boundary-allowed.txt
if [ ! -f "$symbols" ]; then
    echo "check-signer-boundary: no symbol list $symbols" >&2
    exit 2
fi
[ -f "$allow" ] || allow=/dev/null

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# Every file the repository tracks, as paths relative to the root (review B of
# #71, M4): build output is never tracked, so no folder name is pruned, and a
# tracked build-*/ folder is scanned like any other. Outside a git work tree
# (the tools' own fixtures before they are tracked) every file under the root.
# Only signer/ and core/superscalar/ (imported) are left out.
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$root" ls-files > "$tmp/all"
else
    (cd "$root" && find . -path ./.git -prune -o -type f -print | sed 's|^\./||') > "$tmp/all"
fi
grep -v -e '^signer/' -e '^core/superscalar/' "$tmp/all" | LC_ALL=C sort > "$tmp/tracked" || true
grep -E '\.(c|h|inc|cpp|cc|cxx|hpp|hh|S|s)$' "$tmp/tracked" > "$tmp/files" || true

# One line per use: FILE<TAB>SYMBOL<TAB>LINE.
(cd "$root" && awk -v SYMS="$symbols" '
function strip(line,    out, i, c, n, j) {
    if (!inblk && !instr && line !~ /[\/"'"'"']/) return line
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
        if (c == "'"'"'") {
            # a digit separator (1'"'"'000, C23 and C++14) is not a literal: the
            # quote then follows a number token (review B of #71, M4)
            j = i - 1
            while (j >= 1 && substr(line, j, 1) ~ /[0-9A-Za-z_.'"'"']/) j--
            if (j < i - 1 && substr(line, j + 1, 1) ~ /[0-9]/) { out = out c; i++; continue }
        }
        if (c == "\"" || c == "'"'"'") { instr = 1; q = c; out = out " "; i++; continue }
        out = out c; i++
    }
    # a literal continued with a backslash-newline stays open on the next line
    if (!(instr && substr(line, n, 1) == "\\")) instr = 0
    return out
}
BEGIN {
    ns = 0
    while ((getline l < SYMS) > 0) {
        sub(/#.*/, "", l)
        if (l ~ /^[ \t]*$/) continue
        k = split(l, f, /[ \t]+/)
        if (f[1] == "") { kind = f[2]; name = f[3] } else { kind = f[1]; name = f[2] }
        if (name !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || (kind != "sym" && kind != "hook" && kind != "hard" && kind != "hardprefix")) {
            print "check-signer-boundary: bad line in symbol list: " l > "/dev/stderr"; bad = 1; exit 2
        }
        ns++
        label[ns] = (kind == "hook") ? "hook:" name : (kind ~ /^hard/) ? "hard:" name : name
        if (kind == "sym" || kind == "hard") re[ns] = "(^|[^A-Za-z0-9_])" name "($|[^A-Za-z0-9_])"
        else if (kind == "hardprefix") re[ns] = "(^|[^A-Za-z0-9_])" name "[A-Za-z0-9_]*"
        else re[ns] = "((\\.|->)[ \t]*" name "[ \t]*(\\(|=[^=]))|(\\([ \t]*\\*[ \t]*" name "[ \t]*\\)[ \t]*\\()"
    }
    if (ns == 0) { print "check-signer-boundary: empty symbol list" > "/dev/stderr"; bad = 1; exit 2 }
}
FNR == 1 { inblk = 0; instr = 0; pend = ""; pstart = 0 }
{
    # Backslash-newline splicing, as the C preprocessor does it first: a line
    # ending in a backslash is joined with the next, and a finding is reported
    # at the first line of the joined text (review B of #71, M4).
    if (pend != "") { line = pend $0; at = pstart } else { line = $0; at = FNR }
    if (line ~ /\\$/) { pend = substr(line, 1, length(line) - 1); pstart = at; next }
    pend = ""
    # #include of a source file of signer/: a way round the library (H3)
    if (line ~ /^[ \t]*#[ \t]*include[ \t]*["<][^">]*signer\/[^">]*\.(c|inc)[">]/)
        print FILENAME "\thard:include-signer-source\t" at
    # a computed #include (a macro, not a literal) could name anything (M4)
    if (line ~ /^[ \t]*#[ \t]*include[ \t]*[^"< \t]/)
        print FILENAME "\thard:computed-include\t" at
    s0 = strip(line)
    # token pasting onto a gz_sg name: gz_sg##v_sign_envelope (N1)
    if (s0 ~ /gz_sg[A-Za-z0-9_]*[ \t]*##/ || s0 ~ /##[ \t]*gz_sg/)
        print FILENAME "\thard:token-paste-gz_sg\t" at
    for (j = 1; j <= ns; j++) {
        s = s0
        while (match(s, re[j])) {
            print FILENAME "\t" label[j] "\t" at
            # the rest after the match; "^" lets a symbol right after a boundary match again
            s = substr(s, RSTART + RLENGTH)
        }
    }
}
END { if (bad) exit 2 }
' $(cat "$tmp/files") /dev/null) > "$tmp/uses"

# Hard findings fail in every mode, report included, and no allow list holds
# them: the fixed-aux test build named outside signer/, and a source file of
# signer/ included elsewhere (review A of #71, H3). Build files are searched
# for GZ_SG_VECTORS too.
grep "	hard:" "$tmp/uses" > "$tmp/hard" || true
grep -v "	hard:" "$tmp/uses" > "$tmp/uses.soft" || true
mv "$tmp/uses.soft" "$tmp/uses"
# Build and recipe files: CMake, workflows, shell scripts, JSON (presets) and
# Dockerfiles, so that a global -DGZ_SG_VECTORS in a release recipe is seen
# too (review B of #71, M2). This script itself names them, so it is left out.
grep -E '(^|/)(CMakeLists\.txt|[^/]*\.(cmake|yml|yaml|sh|json)|Dockerfile[^/]*)$' "$tmp/tracked" |
    grep -v -x 'tools/check-signer-boundary.sh' > "$tmp/buildfiles" || true
(cd "$root" && while read -r bf; do
        # Substrings, not words: -DGZ_SG_VECTORS, CMAKE_C_FLAGS, an ALIAS of
        # the library, $<TARGET_FILE:...> and a list of signer/ sources all
        # count (review A of #71, N1). A comment is not a use.
        awk -v F="$bf" '{
            l = $0; sub(/#.*/, "", l)
            if (l ~ /GZ_SG_VECTORS/) print F "\thard:GZ_SG_VECTORS-in-build-file\t" FNR
            if (l ~ /gazpacho_signer_vectors/) print F "\thard:gazpacho_signer_vectors-in-build-file\t" FNR
            if (l ~ /signer\/[A-Za-z0-9_.\/${}-]*\.(c|inc)([^A-Za-z0-9_]|$)/) print F "\thard:signer-source-in-build-file\t" FNR
        }' "$bf"
    done < "$tmp/buildfiles") >> "$tmp/hard"
hard_fail=0
if [ -s "$tmp/hard" ]; then
    awk -F '\t' '{ printf "HARD %s:%s: %s (never allowed outside signer/)\n", $1, $3, substr($2, 6) }' "$tmp/hard"
    hard_fail=1
fi

# FILE<TAB>SYMBOL<TAB>COUNT
cut -f1,2 "$tmp/uses" | LC_ALL=C sort | uniq -c |
    awk '{ c = $1; sub(/^ *[0-9]+ /, ""); print $0 "\t" c }' | LC_ALL=C sort > "$tmp/counts"
grep -v '^[[:space:]]*#' "$allow" | grep -v '^[[:space:]]*$' | LC_ALL=C sort > "$tmp/allowed" || true

# --base-allow FILE: the allow list of the merge base. The list may only
# shrink, so no line may be new and no count higher than there (review A of
# #71, M2): otherwise a change could add a use together with its own line.
if [ -n "$base_allow" ]; then
    [ -f "$base_allow" ] || base_allow=/dev/null
    grep -v '^[[:space:]]*#' "$base_allow" | grep -v '^[[:space:]]*$' | LC_ALL=C sort > "$tmp/base" || true
    awk -F '\t' 'FILENAME == ARGV[1] { b[$1 "\t" $2] = $3 + 0; next }
        { k = $1 "\t" $2
          if (!(k in b)) { printf "ALLOW-GROWTH %s: %s is a new line of the allow list (%d)\n", $1, $2, $3; g++ }
          else if ($3 + 0 > b[k]) { printf "ALLOW-GROWTH %s: %s raised from %d to %d\n", $1, $2, b[k], $3; g++ } }
        END { if (g) { printf "FAIL: the allow list grew against the merge base (%d lines)\n", g; exit 1 }
              print "allow list: no growth against the merge base" }' "$tmp/base" "$tmp/allowed" || exit 1
fi

# --base-symbols FILE: the symbol list of the merge base. Every line of it
# must still be in the list, so that deleting a symbol and adding a use of it
# in the same change counts as growth (review A of #71, re-review). Comments
# and spacing do not count.
if [ -n "$base_symbols" ]; then
    [ -f "$base_symbols" ] || base_symbols=/dev/null
    norm() { sed 's/#.*//' "$1" | awk 'NF { print $1 " " $2 }' | LC_ALL=C sort -u; }
    norm "$base_symbols" > "$tmp/base-syms"
    norm "$symbols" > "$tmp/cur-syms"
    LC_ALL=C comm -23 "$tmp/base-syms" "$tmp/cur-syms" > "$tmp/gone-syms"
    if [ -s "$tmp/gone-syms" ]; then
        sed 's/^/SYMBOL-REMOVED /' "$tmp/gone-syms"
        echo "FAIL: the symbol list lost lines against the merge base"
        exit 1
    fi
    echo "symbol list: nothing removed against the merge base"
fi

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
if [ $hard_fail -ne 0 ]; then echo "FAIL: hard findings (in every mode)"; exit 1; fi
