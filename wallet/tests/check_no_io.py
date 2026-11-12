#!/usr/bin/env python3
"""Check that the wallet key library cannot reach the outside world.

usage: check_no_io.py WALLET_LIB [IMPORTED_LIB] [--expect-fail NAME[|NAME...]]

The rule is an allow-list.  Every symbol the wallet library's objects ask the
linker for must be on the list below, or be defined by the wallet library
itself, or be one of the imported SuperScalar functions it is known to use.
Anything else fails the check: a new call to open, fprintf, time, getrandom
or malloc, or to their fortified forms such as __fprintf_chk, is not on the
list, so it cannot slip in under a name nobody thought of.

The wallet library also uses imported SuperScalar objects (IMPORTED_LIB).
The check follows the references into that archive, lists the objects that
are really pulled into a program that links the wallet library (today
bip39.c and util.c), and applies the same allow-list to them, with a short
list of known exceptions that are named below with the reason for each.
Those objects do reference fopen, fread and fclose (an unused function that
reads /dev/urandom) and malloc and free; they are imported unchanged and the
top-level build compiles them as whole objects, so these references cannot
be dropped here and are listed instead.  A new reference of any other kind
in them fails the check.

Global state: the wallet objects must have no writable data, and the imported
objects none beyond the listed exceptions.

What this check cannot see: calls made through function pointers handed in
by a caller (the library takes none), and what the allowed libcrypto and
secp256k1 functions do inside (neither does I/O in the functions used).

--expect-fail turns the result round, for the negative tests: the check must
fail, and one of the given names must be among the symbols it objects to.
"""
import re
import subprocess
import sys

# What the wallet objects may ask for.
ALLOW = {
    # C library: memory and string functions that touch nothing but their arguments
    "memcmp", "memcpy", "memmove", "memset", "strlen", "strnlen", "strcmp", "strncmp", "strchr",
    # the same kind, emitted by clang in place of code we wrote: bcmp for a memcmp
    # whose result is only compared with zero, memchr for a byte-search loop
    "bcmp", "memchr",
    # compiler support
    "__stack_chk_fail", "__stack_chk_guard", "_GLOBAL_OFFSET_TABLE_",
    # libcrypto: hashing, HMAC, constant-time compare, wipe (no I/O, no randomness)
    "SHA256", "HMAC", "EVP_Digest", "EVP_sha512", "EVP_ripemd160",
    "CRYPTO_memcmp", "OPENSSL_cleanse",
    # libsecp256k1: arithmetic on keys handed in (the context is the caller's)
    "secp256k1_ec_seckey_verify", "secp256k1_ec_seckey_tweak_add",
    "secp256k1_ec_pubkey_create", "secp256k1_ec_pubkey_parse",
    "secp256k1_ec_pubkey_serialize", "secp256k1_ec_pubkey_tweak_add",
    "secp256k1_keypair_create", "secp256k1_keypair_xonly_pub",
    "secp256k1_keypair_xonly_tweak_add", "secp256k1_tagged_sha256",
    "secp256k1_xonly_pubkey_parse", "secp256k1_xonly_pubkey_serialize",
    "secp256k1_xonly_pubkey_from_pubkey", "secp256k1_xonly_pubkey_tweak_add",
    "secp256k1_xonly_pubkey_tweak_add_check",
}
# The imported functions the wallet library calls (core/superscalar/src/bip39.c).
IMPORTED_USED = {"bip39_check", "bip39_mnemonic_to_entropy", "bip39_mnemonic_to_seed"}

# Extra symbols the imported objects may ask for, each with its reason.  These
# are exceptions to the rule, in code that is imported unchanged and cannot be
# edited here; none of them is reached from the wallet library's functions
# unless the reason says so.
IMPORTED_EXCEPTIONS = {
    "fopen": "bip39.c: bip39_generate() reads /dev/urandom; the wallet library never calls it",
    "fread": "bip39.c: bip39_generate(), see fopen",
    "fclose": "bip39.c: bip39_generate(), see fopen",
    "malloc": "bip39.c: bip39_mnemonic_to_seed() builds the PBKDF2 salt on the heap and wipes "
              "it before freeing (reached from gzw_phrase_to_seed); bip39_entropy_to_mnemonic() "
              "and util.c's tx_buf helpers also allocate (not called)",
    "free": "bip39.c, util.c: see malloc",
    "realloc": "util.c: tx_buf helpers, in the same object as secure_zero() and sha256(); not called",
    "PKCS5_PBKDF2_HMAC": "bip39.c: the BIP 39 seed stretching (libcrypto, no I/O)",
    "EVP_sha256": "util.c: sha256() and sha256_tagged() through libcrypto (no I/O)",
    "EVP_MD_CTX_new": "util.c: see EVP_sha256 (allocates a digest context inside libcrypto)",
    "EVP_MD_CTX_free": "util.c: see EVP_sha256",
    "EVP_DigestInit_ex": "util.c: see EVP_sha256",
    "EVP_DigestUpdate": "util.c: see EVP_sha256",
    "EVP_DigestFinal_ex": "util.c: see EVP_sha256",
}
# Writable data in the imported objects that are pulled in, each with its reason.
IMPORTED_STATE_EXCEPTIONS = {
    "bip39_wordlist_en": "bip39.c: the word list, an array of non-const pointers; never written",
    "secure_memset_ptr": "util.c: a volatile pointer to memset used by secure_zero() so the "
                         "compiler cannot drop the wipe; set once at load time, never changed",
}
# The one writable object allowed in the wallet library: the imported word
# list, declared in core/superscalar/src/bip39_wordlist.h as an array of
# non-const pointers.  Nothing writes to it.
STATE_EXCEPTIONS = {"bip39_wordlist_en"}

# Sanitizer runtime symbols. clang's AddressSanitizer also adds weak references
# to the bounds of its globals section (__start_asan_globals, __stop_asan_globals)
# and a flag of its own (___asan_globals_registered).
SANITIZER = re.compile(r"^(__asan_|__ubsan_|__sanitizer_|__odr_asan|__tsan_|__msan_|"
                       r"__start_asan_|__stop_asan_)")
# Writable symbols that are not state of ours: sanitizer data, and clang's
# lookup tables for a switch (switch.table.<function>). Those are constant, but
# in some builds (clang with AddressSanitizer, seen in CI) a table of pointers
# is placed in relocated read-only data, which nm shows as data. C code cannot
# declare a name with a dot in it, so only the compiler can make one.
SAN_LOCAL = re.compile(r"^(\.|\*\.|__odr_asan|__asan|___asan|__ubsan|__sanitizer|switch\.table\.)")


def read_archive(path):
    """Return {member: (defined set, undefined set, writable-data set)}."""
    out = subprocess.run(["nm", path], check=True, capture_output=True, text=True).stdout
    members, cur = {}, None
    for line in out.splitlines():
        if line.endswith(":") and " " not in line:
            cur = line[:-1]
            members[cur] = (set(), set(), set())
            continue
        parts = line.split()
        if cur is None or len(parts) < 2:
            continue
        kind, name = parts[-2], parts[-1]
        if kind in ("U", "w", "v"):
            members[cur][1].add(name)
        else:
            members[cur][0].add(name)
            if kind in ("b", "B", "d", "D", "C", "s", "S", "g", "G"):
                members[cur][2].add(name)
    return members


def allowed(name, extra=()):
    if name in ALLOW or name in extra or SANITIZER.match(name):
        return True
    # a fortified form of an allowed function, e.g. __memcpy_chk
    m = re.match(r"^__(\w+)_chk$", name)
    return bool(m and m.group(1) in ALLOW)


def main():
    args = sys.argv[1:]
    expect = None
    if "--expect-fail" in args:
        i = args.index("--expect-fail")
        expect = args[i + 1].split("|")
        del args[i:i + 2]
    wallet = read_archive(args[0])
    imported = read_archive(args[1]) if len(args) > 1 else {}

    problems = []   # (symbol, message)
    w_defined = set().union(*(m[0] for m in wallet.values())) if wallet else set()
    i_defined = {}
    for member, (defined, _, _) in imported.items():
        for name in defined:
            i_defined.setdefault(name, member)

    # 1. the wallet objects
    w_needs = set()
    for member, (_, undefined, state) in sorted(wallet.items()):
        for name in sorted(undefined - w_defined):
            w_needs.add(name)
            if name in i_defined:
                if name not in IMPORTED_USED:
                    problems.append((name, "%s uses the imported function %s, which is not "
                                           "on the list of imported functions it may use"
                                     % (member, name)))
            elif not allowed(name):
                problems.append((name, "%s references %s, which is not on the allow-list"
                                 % (member, name)))
        for name in sorted(state):
            if name in STATE_EXCEPTIONS or SAN_LOCAL.match(name):
                continue
            problems.append((name, "%s has writable data (global state): %s" % (member, name)))

    # 2. the imported objects that a link of the wallet library pulls in
    pulled, todo = [], [i_defined[n] for n in sorted(w_needs) if n in i_defined]
    while todo:
        member = todo.pop()
        if member in pulled:
            continue
        pulled.append(member)
        for name in imported[member][1]:
            if name in i_defined and i_defined[name] not in pulled:
                todo.append(i_defined[name])
    used_exceptions = {}
    imported_state = []
    for member in sorted(pulled):
        _, undefined, state = imported[member]
        for name in sorted(undefined):
            if name in i_defined or allowed(name):
                continue
            # a listed exception, or its fortified form (fread -> __fread_chk)
            m = re.match(r"^__(\w+)_chk$", name)
            base = m.group(1) if m and m.group(1) in IMPORTED_EXCEPTIONS else name
            if base in IMPORTED_EXCEPTIONS:
                used_exceptions.setdefault(base, []).append(member)
                continue
            problems.append((name, "imported %s references %s, which is neither on the "
                                   "allow-list nor a listed exception" % (member, name)))
        for name in sorted(state):
            if SAN_LOCAL.match(name):
                continue
            if name in IMPORTED_STATE_EXCEPTIONS:
                imported_state.append(name)
            else:
                problems.append((name, "imported %s has writable data that is not a listed "
                                       "exception: %s" % (member, name)))

    for _, message in problems:
        print("FAIL: " + message)
    if expect is not None:
        hit = [s for s, _ in problems if s in expect]
        if hit:
            print("check_no_io: failed as it must, objecting to: " + ", ".join(sorted(set(hit))))
            return 0
        print("FAIL: the check was expected to object to one of %s and did not" % expect)
        return 1
    if problems:
        return 1

    print("check_no_io: %d wallet objects reference only allow-listed symbols and have "
          "no global state" % len(wallet))
    if imported:
        print("imported objects pulled in by the wallet library: " + ", ".join(sorted(pulled)))
        print("known exceptions in those imported objects (they are not edited here):")
        for name in sorted(used_exceptions):
            print("  %-18s %s" % (name, IMPORTED_EXCEPTIONS[name]))
        print("writable data in those imported objects (known exceptions):")
        for name in sorted(set(imported_state)):
            print("  %-18s %s" % (name, IMPORTED_STATE_EXCEPTIONS[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
