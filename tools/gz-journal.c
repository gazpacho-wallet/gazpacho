/* gz-journal: look at a journal without changing it.
 *
 *   gz-journal inspect [--mainnet] FILE      header, verdict, counts, offsets
 *   gz-journal verify  [--mainnet] FILE...   one line per file (below); "-" reads names from stdin
 *   gz-journal dump    [--mainnet] FILE      every kept batch and its records:
 *                                            type, name, length and a digest,
 *                                            NEVER the record bytes
 *
 * verify prints: FILE STATE CUT_TO NEXT_INCARNATION DIGEST, where STATE is
 * clean, torn, corrupt, order, bad_header or unknown_record; CUT_TO is V for
 * torn; NEXT_INCARNATION is what an open would write; DIGEST is SHA-256 over,
 * for each kept batch, incarnation (u64), sequence (u64), kept record count
 * (u32) and each kept record's type (u32), length (u32) and bytes, all
 * big-endian. Fields that do not apply are "-". Exit status: 0 all clean, 1
 * a torn tail, 2 a refusal or an unreadable file.
 *
 * The file is read, never written or locked: a running node's journal may
 * show a torn tail that its next sync completes. The verdict is what an open
 * would decide (spec/journal.md section 5); an open would also cut a torn
 * tail, which this tool never does. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "journal.h"
#include "superscalar/sha256.h"

static const struct { uint32_t type; const char *name; } NAMES[] = {
    {0x00040002, "key_epoch"}, {0x00040004, "key_index"}, {0x00040006, "restored"},
    {0x0004000a, "guard"}, {0x00010002, "lobby_opened"}, {0x00010004, "terms_version"},
    {0x00010006, "seat"}, {0x00010008, "freeze"}, {0x0001000a, "lobby_ended"},
    {0x0001000c, "terms_received"}, {0x0001000e, "joined"}, {0x00010010, "ready_sent"},
    {0x00010012, "host_fault"}, {0x00010014, "start_sent"}, {0x00010016, "start_received"},
    {0x00020002, "round_started"}, {0x00020004, "round_proposal"}, {0x00020006, "exposure"},
    {0x00020008, "round_signed"}, {0x0002000a, "round_completed"}, {0x0002000c, "ack_received"},
    {0x0002000e, "round_ended"}, {0x00030002, "funding_plan"}, {0x00030004, "funding_signed"},
    {0x00030006, "funding_status"}, {0x7e570001, "test_ping"}, {0x7e570002, "test_ping_sent"}};

static const char *type_name(uint32_t t)
{
    for (size_t i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++)
        if (NAMES[i].type == t) return NAMES[i].name;
    return (t & 1) ? "unknown (odd, skipped)" : "unknown";
}

static uint8_t *load(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0, r;
    uint8_t *d = malloc(cap);
    while (d && (r = fread(d + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            uint8_t *e = cap < (2ull << 30) ? realloc(d, cap *= 2) : NULL;
            if (!e) { free(d); d = NULL; }
            else d = e;
        }
    }
    fclose(f);
    *len = n;
    return d;
}

static const char *state_name(const gz_journal_scan_t *s)
{
    if (s->verdict == GZ_JOURNAL_CLEAN) return "clean";
    if (s->verdict == GZ_JOURNAL_TORN) return "torn";
    switch (s->status) {
    case GZ_JOURNAL_ERR_HEADER: case GZ_JOURNAL_ERR_NETWORK: return "bad_header";
    case GZ_JOURNAL_ERR_CORRUPT: return "corrupt";
    case GZ_JOURNAL_ERR_ORDER: return "order";
    default: return "unknown_record";
    }
}

/* Collects the digest input, or prints, per kept batch. */
typedef struct {
    int dump;
    uint8_t *buf;
    size_t len, cap;
} walk_t;

static void put(walk_t *w, const void *p, size_t n)
{
    if (w->len + n > w->cap) {
        size_t cap = (w->cap ? w->cap : 4096);
        while (cap < w->len + n) cap *= 2;
        uint8_t *b = realloc(w->buf, cap);
        if (!b) { fprintf(stderr, "out of memory\n"); exit(2); }
        w->buf = b;
        w->cap = cap;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}
static void put_be(walk_t *w, uint64_t v, int bytes)
{
    uint8_t b[8];
    for (int i = 0; i < bytes; i++) b[i] = (uint8_t)(v >> (8 * (bytes - 1 - i)));
    put(w, b, (size_t)bytes);
}

static void on_batch(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *p, size_t l)
{
    walk_t *w = ctx;
    long n = gz_journal_parse_batch(p, l, NULL, 0, NULL);
    gz_record_t *r = malloc(((size_t)n + 1) * sizeof *r);
    size_t kept = 0;
    if (!r) exit(2);
    gz_journal_parse_batch(p, l, r, (size_t)n, &kept);
    if (w->dump) {
        printf("batch (%llu, %llu) at %llu, %u bytes, %ld records, %zu kept\n",
               (unsigned long long)id.incarnation, (unsigned long long)id.sequence,
               (unsigned long long)off, size, n, kept);
        for (size_t i = 0; i < kept; i++) {
            uint8_t h[32];
            sha256(r[i].bytes.data ? r[i].bytes.data : (const uint8_t *)"", r[i].bytes.len, h);
            printf("  0x%08x %-16s %8zu bytes  sha256 %02x%02x%02x%02x%02x%02x%02x%02x...\n",
                   r[i].type, type_name(r[i].type), r[i].bytes.len, h[0], h[1], h[2], h[3], h[4],
                   h[5], h[6], h[7]);
        }
    } else {
        put_be(w, id.incarnation, 8);
        put_be(w, id.sequence, 8);
        put_be(w, kept, 4);
        for (size_t i = 0; i < kept; i++) {
            put_be(w, r[i].type, 4);
            put_be(w, r[i].bytes.len, 4);
            if (r[i].bytes.len) put(w, r[i].bytes.data, r[i].bytes.len);
        }
    }
    free(r);
}

static int verify_one(const char *path, const uint8_t *chain)
{
    size_t len;
    uint8_t *d = load(path, &len);
    if (!d) { printf("%s unreadable - - -\n", path); return 2; }
    walk_t w = {0, NULL, 0, 0};
    gz_journal_scan_t s;
    gz_journal_scan(d, len, chain, &s, on_batch, &w);
    printf("%s %s ", path, state_name(&s));
    if (s.verdict == GZ_JOURNAL_TORN) printf("%llu ", (unsigned long long)s.valid_end);
    else printf("- ");
    if (s.verdict != GZ_JOURNAL_REFUSED) {
        uint8_t h[32];
        sha256(w.buf ? w.buf : (const uint8_t *)"", w.len, h);
        printf("%llu ", (unsigned long long)s.highest_incarnation + 1);
        for (int i = 0; i < 32; i++) printf("%02x", h[i]);
        printf("\n");
    } else {
        printf("- -\n");
    }
    free(w.buf);
    free(d);
    return s.verdict == GZ_JOURNAL_CLEAN ? 0 : s.verdict == GZ_JOURNAL_TORN ? 1 : 2;
}

static int inspect(const char *path, const uint8_t *chain, int dump)
{
    size_t len;
    uint8_t *d = load(path, &len);
    if (!d) { fprintf(stderr, "%s: cannot read\n", path); return 2; }
    walk_t w = {dump, NULL, 0, 0};
    gz_journal_scan_t s;
    gz_journal_scan(d, len, chain, &s, NULL, NULL);
    if (dump && s.verdict != GZ_JOURNAL_REFUSED) gz_journal_scan(d, len, chain, &s, on_batch, &w);
    if (!dump || s.verdict == GZ_JOURNAL_REFUSED) {
        printf("file           %s, %zu bytes\n", path, len);
        printf("verdict        %s (%s)\n", state_name(&s), gz_journal_status_name(s.status));
        if (s.verdict == GZ_JOURNAL_REFUSED && s.status != GZ_JOURNAL_ERR_HEADER &&
            s.status != GZ_JOURNAL_ERR_NETWORK)
            printf("offending      entry at offset %llu\n", (unsigned long long)s.error_at);
        if (s.status == GZ_JOURNAL_ERR_CORRUPT)
            printf("               valid sync mark after it at %llu: refuse; restore from a backup\n",
                   (unsigned long long)s.mark_at);
        if (s.status == GZ_JOURNAL_ERR_UNKNOWN_RECORD)
            printf("               record type 0x%08x is even and not understood\n", s.bad_type);
        if (s.verdict == GZ_JOURNAL_TORN)
            printf("torn tail      %llu bytes from offset %llu would be cut\n",
                   (unsigned long long)(len - s.valid_end), (unsigned long long)s.valid_end);
        if (s.status != GZ_JOURNAL_ERR_HEADER && s.status != GZ_JOURNAL_ERR_NETWORK) {
            printf("entries        %llu incarnations, %llu batches, %llu sync marks, %llu records\n",
                   (unsigned long long)s.n_incarnations, (unsigned long long)s.n_batches,
                   (unsigned long long)s.n_marks, (unsigned long long)s.n_records);
            printf("incarnation    highest %llu\n", (unsigned long long)s.highest_incarnation);
            if (len >= GZ_JOURNAL_SOFT_LIMIT) printf("size           past the soft limit\n");
        }
    }
    free(w.buf);
    free(d);
    return s.verdict == GZ_JOURNAL_CLEAN ? 0 : s.verdict == GZ_JOURNAL_TORN ? 1 : 2;
}

static int usage(void)
{
    fprintf(stderr, "usage: gz-journal inspect|verify|dump [--mainnet] FILE...\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();
    const char *cmd = argv[1];
    int i = 2;
    const uint8_t *chain = gz_journal_chain_signet;
    if (!strcmp(argv[i], "--mainnet")) { chain = gz_journal_chain_mainnet; i++; }
    if (i >= argc) return usage();
    if (!strcmp(cmd, "inspect")) return inspect(argv[i], chain, 0);
    if (!strcmp(cmd, "dump")) return inspect(argv[i], chain, 1);
    if (strcmp(cmd, "verify")) return usage();
    int worst = 0;
    if (!strcmp(argv[i], "-")) {
        char line[4096];
        while (fgets(line, sizeof line, stdin)) {
            line[strcspn(line, "\n")] = 0;
            if (*line) { int r = verify_one(line, chain); if (r > worst) worst = r; }
        }
        return worst;
    }
    for (; i < argc; i++) { int r = verify_one(argv[i], chain); if (r > worst) worst = r; }
    return worst;
}
