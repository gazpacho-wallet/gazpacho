/* gz-wallet-keys: make a recovery phrase file and show addresses from it.
 *
 *   gz-wallet-keys new --network NET --out FILE
 *   gz-wallet-keys address --network NET --in FILE [--index N] [--change]
 *   gz-wallet-keys verify-vectors
 *
 * This program is outside the core, so it may read the operating system's
 * random source and the file system.  It never prints a recovery phrase or a
 * private key, and it refuses mainnet in this version.
 *
 * The phrase file holds the 24 words on one line, in plain text, readable by
 * its owner only (mode 0600).  No BIP 39 passphrase is used.
 *
 * How "new" writes the file:
 *   1. the phrase goes to a temporary file FILE.tmp-<random> in the same
 *      directory, created with O_EXCL and mode 0600, and is synced to disk;
 *   2. the temporary file is read back and the address derived again from
 *      what is really on disk;
 *   3. the temporary file is hard-linked to FILE.  link() fails if FILE
 *      exists, so an existing file is never replaced, and FILE never exists
 *      half-written;
 *   4. the temporary name is removed and the directory is synced to disk;
 *   5. only then are the address and the account public key printed.
 * If the program is killed in between, FILE does not exist; a FILE.tmp-*
 * file may be left behind and can be deleted.
 *
 * Exit status: 0 success; 1 failure, nothing was created; 2 wrong usage;
 * 3 ("new" only) the phrase file was created but the address could not be
 * written to standard output: run "address" on the file to see it.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <secp256k1.h>

#include "gazpacho/wallet_keys.h"
#include "official_vectors.h"

#define PHRASE_FILE_MAX 1024

/* Set when standard output was already closed at start (see main). */
static int stdout_was_closed = 0;

static int usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  gz-wallet-keys new --network NET --out FILE\n"
            "      make a 24-word recovery phrase, write it to FILE (never\n"
            "      overwritten, owner-only), print the first receiving address\n"
            "      and the account's extended public key\n"
            "  gz-wallet-keys address --network NET --in FILE [--index N] [--change]\n"
            "      print an address, its scriptPubKey and its derivation path\n"
            "  gz-wallet-keys verify-vectors\n"
            "      run the built-in official BIP test vectors\n"
            "NET is signet, testnet, testnet4 or regtest.  mainnet is refused.\n");
    return 2;
}

/* Push what was printed to standard output and say whether it got there. */
static int stdout_delivered(void) {
    if (stdout_was_closed) return 0;
    if (fflush(stdout) != 0) return 0;
    return !ferror(stdout);
}

/* Fill buf from the operating system's random source. */
static int os_random(unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = getrandom(buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (n == 0) return 0; /* a source that gives nothing is broken */
        got += (size_t)n;
    }
    return 1;
}

static secp256k1_context *make_context(void) {
    unsigned char seed[32];
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return NULL;
    /* Blind the context against side channels. */
    if (!os_random(seed, sizeof(seed)) || !secp256k1_context_randomize(ctx, seed)) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
    gzw_wipe(seed, sizeof(seed));
    return ctx;
}

static int parse_network(const char *name, gzw_network *net) {
    if (!name) {
        fprintf(stderr, "error: --network is required\n");
        return 0;
    }
    if (!gzw_network_from_name(name, net)) {
        fprintf(stderr, "error: unknown network; use signet, testnet, testnet4 or regtest\n");
        return 0;
    }
    if (*net == GZW_NET_MAINNET) {
        fprintf(stderr, "refused: mainnet is switched off in this version of "
                        "gz-wallet-keys; use signet, testnet, testnet4 or regtest\n");
        return 0;
    }
    return 1;
}

/* Read a phrase file into phrase (PHRASE_FILE_MAX + 1 bytes).  The file must
   be a regular file, not reached through a symbolic link, owned by the user
   running the program and readable by nobody else. */
static int read_phrase_file(const char *path, char *phrase) {
    struct stat st;
    size_t got = 0;
    /* O_NOFOLLOW: not through a symbolic link.  O_NONBLOCK: opening a FIFO
       returns at once instead of waiting for a writer (it has no effect on a
       regular file).  O_NOCTTY: a terminal device does not become ours. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    int ok = 0;

    if (fd < 0) {
        if (errno == ELOOP)
            fprintf(stderr, "refused: the phrase file is a symbolic link\n");
        else
            fprintf(stderr, "error: cannot open the phrase file: %s\n", strerror(errno));
        return 0;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "refused: the phrase file is not a regular file\n");
        goto done;
    }
    if (st.st_uid != geteuid()) {
        fprintf(stderr, "refused: the phrase file belongs to another user\n");
        goto done;
    }
    if ((st.st_mode & 077) != 0) {
        fprintf(stderr, "refused: the phrase file can be read by other users; "
                        "set its mode to 0600\n");
        goto done;
    }
    if (st.st_size <= 0 || st.st_size > PHRASE_FILE_MAX) {
        fprintf(stderr, "refused: the phrase file is empty or too large\n");
        goto done;
    }
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, phrase + got, (size_t)st.st_size - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            fprintf(stderr, "error: cannot read the phrase file\n");
            goto done;
        }
        got += (size_t)n;
    }
    phrase[got] = '\0';
    if (strlen(phrase) != got) {
        fprintf(stderr, "refused: the phrase file is not text (it holds a zero byte)\n");
        goto done;
    }
    {
        gzw_phrase_status st2 = gzw_phrase_check(phrase);
        if (st2 != GZW_PHRASE_OK) {
            /* A fixed text; it never includes any word of the phrase. */
            fprintf(stderr, "error: the phrase file does not hold a valid phrase: %s\n",
                    gzw_phrase_status_text(st2));
            goto done;
        }
    }
    ok = 1;

done:
    close(fd);
    if (!ok) gzw_wipe(phrase, PHRASE_FILE_MAX + 1);
    return ok;
}

/* phrase -> master key.  The seed is wiped here. */
static int master_from_phrase(const secp256k1_context *ctx, const char *phrase,
                              gzw_xprv *master) {
    unsigned char seed[64];
    int ok = gzw_phrase_to_seed(phrase, NULL, seed) &&
             gzw_bip32_master(ctx, seed, sizeof(seed), master, NULL);
    gzw_wipe(seed, sizeof(seed));
    return ok;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        done += (size_t)n;
    }
    return 1;
}

/* Sync the directory that holds path, so that the name itself is on disk. */
static int sync_directory_of(const char *path) {
    const char *slash = strrchr(path, '/');
    char *dir;
    int fd, ok;

    if (!slash) {
        dir = strdup(".");
    } else if (slash == path) {
        dir = strdup("/");
    } else {
        dir = strndup(path, (size_t)(slash - path));
    }
    if (!dir) return 0;
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(dir);
    if (fd < 0) return 0;
    ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    return ok;
}

static int cmd_new(const char *network, const char *out_path) {
    static const char hex[] = "0123456789abcdef";
    gzw_network net;
    secp256k1_context *ctx = NULL;
    unsigned char entropy[32], suffix[8];
    char phrase[GZW_PHRASE_MAX];
    char reread[PHRASE_FILE_MAX + 1];
    char xpub_str[GZW_XKEY_STR_MAX], path_str[GZW_PATH_STR_MAX];
    char *tmp_path = NULL;
    struct stat st;
    gzw_xprv master;
    gzw_xpub acct;
    gzw_bip86_output first, check;
    size_t out_len, pos;
    int fd = -1, tmp_created = 0, linked = 0, rc = 1;

    memset(&master, 0, sizeof(master));
    memset(phrase, 0, sizeof(phrase));
    memset(reread, 0, sizeof(reread));
    memset(entropy, 0, sizeof(entropy));

    if (!parse_network(network, &net)) return 1;
    if (!out_path || out_path[0] == '\0') {
        fprintf(stderr, "error: --out FILE is required\n");
        return 1;
    }
    /* Refuse early if the name is taken (by anything, even a dangling
       symbolic link).  The link() below is what guarantees it. */
    if (lstat(out_path, &st) == 0) {
        fprintf(stderr, "refused: the output file already exists; a phrase "
                        "file is never overwritten\n");
        return 1;
    }
    ctx = make_context();
    if (!ctx) {
        fprintf(stderr, "error: cannot set up the signature library\n");
        return 1;
    }

    if (!os_random(entropy, sizeof(entropy)) || !os_random(suffix, sizeof(suffix))) {
        fprintf(stderr, "error: cannot read the system's random source\n");
        goto done;
    }
    if (!gzw_phrase_from_entropy(entropy, phrase) ||
        !master_from_phrase(ctx, phrase, &master) ||
        !gzw_bip86_output_from_master(ctx, &master, net, 0, 0, 0, &first, NULL)) {
        fprintf(stderr, "error: key derivation failed\n");
        goto done;
    }
    gzw_wipe(&master, sizeof(master));

    /* The temporary name: FILE.tmp-<16 hex digits>, in the same directory. */
    out_len = strlen(out_path);
    tmp_path = malloc(out_len + 5 + 2 * sizeof(suffix) + 1);
    if (!tmp_path) {
        fprintf(stderr, "error: out of memory\n");
        goto done;
    }
    memcpy(tmp_path, out_path, out_len);
    memcpy(tmp_path + out_len, ".tmp-", 5);
    pos = out_len + 5;
    for (size_t i = 0; i < sizeof(suffix); i++) {
        tmp_path[pos++] = hex[suffix[i] >> 4];
        tmp_path[pos++] = hex[suffix[i] & 15];
    }
    tmp_path[pos] = '\0';

    /* Mode 0600 from the moment the file exists; it is never wider. */
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "error: cannot create a file next to the output file: %s\n",
                strerror(errno));
        goto done;
    }
    tmp_created = 1;

    if (!write_all(fd, phrase, strlen(phrase)) || !write_all(fd, "\n", 1) ||
        fsync(fd) != 0) {
        fprintf(stderr, "error: cannot write the phrase file\n");
        goto done;
    }
    if (close(fd) != 0) {
        fd = -1;
        fprintf(stderr, "error: cannot close the phrase file\n");
        goto done;
    }
    fd = -1;

    /* Read the file back and derive again from what is really on disk. */
    if (!read_phrase_file(tmp_path, reread) ||
        !master_from_phrase(ctx, reread, &master) ||
        !gzw_bip86_output_from_master(ctx, &master, net, 0, 0, 0, &check, NULL) ||
        strcmp(first.address, check.address) != 0 ||
        !gzw_bip86_account_xpub(ctx, &master, net, 0, &acct, NULL) ||
        !gzw_xpub_to_string(&acct, net, xpub_str) ||
        !gzw_path_to_string(check.path, 3, path_str, sizeof(path_str))) {
        fprintf(stderr, "error: the file read back does not give the same address\n");
        goto done;
    }

    /* Give the file its real name.  link() never replaces an existing name. */
    if (link(tmp_path, out_path) != 0) {
        if (errno == EEXIST)
            fprintf(stderr, "refused: the output file already exists; a phrase "
                            "file is never overwritten\n");
        else
            fprintf(stderr, "error: cannot give the phrase file its name: %s\n",
                    strerror(errno));
        goto done;
    }
    linked = 1;
    if (unlink(tmp_path) != 0) {
        fprintf(stderr, "error: cannot remove the temporary file\n");
        goto done;
    }
    tmp_created = 0;
    /* The name must be on disk before anyone is told the address. */
    if (!sync_directory_of(out_path)) {
        fprintf(stderr, "error: cannot sync the directory of the phrase file\n");
        goto done;
    }

    printf("address: %s\n", check.address);
    printf("account xpub (%s): %s\n", path_str, xpub_str);
    if (!stdout_delivered()) {
        /* The file is complete and on disk; keep it and say how to proceed. */
        fprintf(stderr, "error: the phrase file was written, but the address could "
                        "not be written to standard output; run the address "
                        "command on the file to see it\n");
        rc = 3;
        linked = 0; /* keep the file */
        goto done;
    }
    rc = 0;

done:
    if (fd >= 0) close(fd);
    /* Leave nothing behind that was not completely written and checked. */
    if (tmp_created) unlink(tmp_path);
    if (rc == 1 && linked) unlink(out_path);
    if (tmp_path) {
        gzw_wipe(tmp_path, strlen(tmp_path));
        free(tmp_path);
    }
    gzw_wipe(entropy, sizeof(entropy));
    gzw_wipe(suffix, sizeof(suffix));
    gzw_wipe(phrase, sizeof(phrase));
    gzw_wipe(reread, sizeof(reread));
    gzw_wipe(&master, sizeof(master));
    if (ctx) secp256k1_context_destroy(ctx);
    return rc;
}

static int cmd_address(const char *network, const char *in_path, const char *index_str,
                       int change) {
    gzw_network net;
    secp256k1_context *ctx = NULL;
    char phrase[PHRASE_FILE_MAX + 1];
    char path_str[GZW_PATH_STR_MAX], spk_hex[69];
    gzw_xprv master;
    gzw_bip86_output o;
    gzw_reason why = GZW_REASON_OK;
    unsigned long index = 0;
    int rc = 1;

    memset(&master, 0, sizeof(master));
    memset(phrase, 0, sizeof(phrase));

    if (!parse_network(network, &net)) return 1;
    if (!in_path) {
        fprintf(stderr, "error: --in FILE is required\n");
        return 1;
    }
    if (index_str) {
        char *end = NULL;
        errno = 0;
        index = strtoul(index_str, &end, 10);
        if (errno != 0 || end == index_str || *end != '\0' ||
            index_str[0] < '0' || index_str[0] > '9' || index > 0x7fffffffUL) {
            fprintf(stderr, "error: --index must be a number from 0 to 2147483647\n");
            return 1;
        }
    }
    ctx = make_context();
    if (!ctx) {
        fprintf(stderr, "error: cannot set up the signature library\n");
        return 1;
    }
    if (!read_phrase_file(in_path, phrase)) goto done;
    if (!master_from_phrase(ctx, phrase, &master)) {
        fprintf(stderr, "error: key derivation failed\n");
        goto done;
    }
    if (!gzw_bip86_output_from_master(ctx, &master, net, 0, change ? 1u : 0u,
                                      (uint32_t)index, &o, &why) ||
        !gzw_path_to_string(o.path, 5, path_str, sizeof(path_str))) {
        /* A fixed text; for BIP 32's invalid case it says to use the next index. */
        fprintf(stderr, "error: key derivation failed: %s\n", gzw_reason_text(why));
        goto done;
    }
    for (size_t i = 0; i < 34; i++)
        snprintf(spk_hex + 2 * i, 3, "%02x", (unsigned)o.script_pubkey[i]);

    printf("address: %s\n", o.address);
    printf("scriptPubKey: %s\n", spk_hex);
    printf("path: %s\n", path_str);
    if (!stdout_delivered()) {
        fprintf(stderr, "error: cannot write to standard output\n");
        goto done;
    }
    rc = 0;

done:
    gzw_wipe(phrase, sizeof(phrase));
    gzw_wipe(&master, sizeof(master));
    secp256k1_context_destroy(ctx);
    return rc;
}

static int cmd_verify_vectors(void) {
    gzw_vector_group groups[GZW_VECTOR_GROUPS];
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int all, total = 0, failed = 0;

    if (!ctx) {
        fprintf(stderr, "error: cannot set up the signature library\n");
        return 1;
    }
    all = gzw_official_vectors_run(ctx, groups);
    secp256k1_context_destroy(ctx);
    for (int g = 0; g < GZW_VECTOR_GROUPS; g++) {
        printf("%s  %2d/%2d  %s\n",
               groups[g].failed == 0 && groups[g].cases > 0 ? "pass" : "FAIL",
               groups[g].cases - groups[g].failed, groups[g].cases, groups[g].name);
        total += groups[g].cases;
        failed += groups[g].failed;
    }
    if (all)
        printf("PASS: all %d official vectors pass\n", total);
    else
        printf("FAIL: %d of %d official vectors failed\n", failed, total);
    if (!stdout_delivered()) {
        fprintf(stderr, "error: cannot write to standard output\n");
        return 1;
    }
    return all ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *network = NULL, *out_path = NULL, *in_path = NULL, *index_str = NULL;
    int change = 0;
    struct rlimit no_core = {0, 0};

    /* Keep key material out of core dumps. */
    setrlimit(RLIMIT_CORE, &no_core);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif

    /* If a standard descriptor is closed, the next file opened would take its
       number and output meant for the terminal could land in that file.
       Occupy closed ones with /dev/null, and remember a closed standard
       output so that the commands report that nothing could be printed. */
    for (int fd = 0; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
            int nfd = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
            if (nfd != fd) return 1;
            if (fd == 1) stdout_was_closed = 1;
        }
    }

    if (argc < 2) return usage();
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--change") == 0) {
            change = 1;
        } else if (i + 1 < argc && strcmp(argv[i], "--network") == 0) {
            network = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--out") == 0) {
            out_path = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--in") == 0) {
            in_path = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--index") == 0) {
            index_str = argv[++i];
        } else {
            return usage();
        }
    }

    if (strcmp(argv[1], "new") == 0) {
        if (in_path || index_str || change) return usage();
        return cmd_new(network, out_path);
    }
    if (strcmp(argv[1], "address") == 0) {
        if (out_path) return usage();
        return cmd_address(network, in_path, index_str, change);
    }
    if (strcmp(argv[1], "verify-vectors") == 0) {
        if (argc != 2) return usage();
        return cmd_verify_vectors();
    }
    return usage();
}
