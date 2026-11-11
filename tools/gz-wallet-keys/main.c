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

/* Fill buf from the operating system's random source. */
static int os_random(unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = getrandom(buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
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
   be a regular file that only its owner can read. */
static int read_phrase_file(const char *path, char *phrase) {
    struct stat st;
    size_t got = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int ok = 0;

    if (fd < 0) {
        fprintf(stderr, "error: cannot open the phrase file: %s\n", strerror(errno));
        return 0;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "error: the phrase file is not a regular file\n");
        goto done;
    }
    if ((st.st_mode & 077) != 0) {
        fprintf(stderr, "refused: the phrase file can be read by other users; "
                        "set its mode to 0600\n");
        goto done;
    }
    if (st.st_size <= 0 || st.st_size > PHRASE_FILE_MAX) {
        fprintf(stderr, "error: the phrase file is empty or too large\n");
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
        fprintf(stderr, "error: the phrase file is not text\n");
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
             gzw_bip32_master(ctx, seed, sizeof(seed), master);
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

static int cmd_new(const char *network, const char *out_path) {
    gzw_network net;
    secp256k1_context *ctx = NULL;
    unsigned char entropy[32];
    char phrase[GZW_PHRASE_MAX];
    char reread[PHRASE_FILE_MAX + 1];
    char xpub_str[GZW_XKEY_STR_MAX], path_str[GZW_PATH_STR_MAX];
    gzw_xprv master;
    gzw_xpub acct;
    gzw_bip86_output first, check;
    int fd = -1, created = 0, rc = 1;

    memset(&master, 0, sizeof(master));
    memset(phrase, 0, sizeof(phrase));
    memset(reread, 0, sizeof(reread));
    memset(entropy, 0, sizeof(entropy));

    if (!parse_network(network, &net)) return 1;
    if (!out_path) {
        fprintf(stderr, "error: --out FILE is required\n");
        return 1;
    }
    ctx = make_context();
    if (!ctx) {
        fprintf(stderr, "error: cannot set up the signature library\n");
        return 1;
    }

    /* Create the file first: O_EXCL fails if anything is already there, so an
       existing phrase can never be replaced. */
    fd = open(out_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == EEXIST)
            fprintf(stderr, "refused: the output file already exists; a phrase "
                            "file is never overwritten\n");
        else
            fprintf(stderr, "error: cannot create the output file: %s\n",
                    strerror(errno));
        goto done;
    }
    created = 1;
    if (fchmod(fd, 0600) != 0) {
        fprintf(stderr, "error: cannot set the output file's mode\n");
        goto done;
    }

    if (!os_random(entropy, sizeof(entropy))) {
        fprintf(stderr, "error: cannot read the system's random source\n");
        goto done;
    }
    if (!gzw_phrase_from_entropy(entropy, phrase) ||
        !master_from_phrase(ctx, phrase, &master) ||
        !gzw_bip86_output_from_master(ctx, &master, net, 0, 0, 0, &first)) {
        fprintf(stderr, "error: key derivation failed\n");
        goto done;
    }
    gzw_wipe(&master, sizeof(master));

    if (!write_all(fd, phrase, strlen(phrase)) || !write_all(fd, "\n", 1) ||
        fsync(fd) != 0) {
        fprintf(stderr, "error: cannot write the output file\n");
        goto done;
    }
    if (close(fd) != 0) {
        fd = -1;
        fprintf(stderr, "error: cannot close the output file\n");
        goto done;
    }
    fd = -1;

    /* Read the file back and derive again from what is really on disk. */
    if (!read_phrase_file(out_path, reread) ||
        !master_from_phrase(ctx, reread, &master) ||
        !gzw_bip86_output_from_master(ctx, &master, net, 0, 0, 0, &check) ||
        strcmp(first.address, check.address) != 0 ||
        !gzw_bip86_account_xpub(ctx, &master, net, 0, &acct) ||
        !gzw_xpub_to_string(&acct, 0, xpub_str) ||
        !gzw_path_to_string(check.path, 3, path_str, sizeof(path_str))) {
        fprintf(stderr, "error: the file read back does not give the same address\n");
        goto done;
    }

    printf("address: %s\n", check.address);
    printf("account xpub (%s): %s\n", path_str, xpub_str);
    rc = 0;

done:
    if (fd >= 0) close(fd);
    /* Do not leave a file behind that was not completely written and checked. */
    if (rc != 0 && created) unlink(out_path);
    gzw_wipe(entropy, sizeof(entropy));
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
    if (!master_from_phrase(ctx, phrase, &master) ||
        !gzw_bip86_output_from_master(ctx, &master, net, 0, change ? 1u : 0u,
                                      (uint32_t)index, &o) ||
        !gzw_path_to_string(o.path, 5, path_str, sizeof(path_str))) {
        fprintf(stderr, "error: key derivation failed\n");
        goto done;
    }
    for (size_t i = 0; i < 34; i++)
        snprintf(spk_hex + 2 * i, 3, "%02x", (unsigned)o.script_pubkey[i]);

    printf("address: %s\n", o.address);
    printf("scriptPubKey: %s\n", spk_hex);
    printf("path: %s\n", path_str);
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
        printf("%s  %2d/%2d  %s\n", groups[g].failed == 0 && groups[g].cases > 0 ? "pass" : "FAIL",
               groups[g].cases - groups[g].failed, groups[g].cases, groups[g].name);
        total += groups[g].cases;
        failed += groups[g].failed;
    }
    if (all) {
        printf("PASS: all %d official vectors pass\n", total);
        return 0;
    }
    printf("FAIL: %d of %d official vectors failed\n", failed, total);
    return 1;
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
