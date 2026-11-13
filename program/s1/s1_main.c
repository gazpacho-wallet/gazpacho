/* gazpacho-slice1: the slice1-attempt program. One process per party:
 *
 *   host:   gazpacho-slice1 --role host --dir D --listen PORT [--target 3 --minimum 3 --channel 100000]
 *           (--fake-chain --fake-tip H | --phrase-in FILE --change-index N [--gate FILE])
 *   member: gazpacho-slice1 --role member --dir D --join KEY@IP:PORT --scope HEX [--bad-conditions]
 *           [--fake-chain --fake-tip H]
 *
 * The host writes D/invite ("KEY@127.0.0.1:PORT SCOPE"). Lines starting
 * S1-RESULT are the outcome. THROWAWAY: never merged. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <secp256k1.h>
#include "peers.h"
#include "envelope.h"
#include "s1.h"

s1_global_t G;
static gz_peers_t *PEERS;
static const char *ROLE = "?";
static int journal_fd = -1;

/* ---- small helpers ---- */
void s1_log(const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    printf("%02d:%02d:%02d.%03ld %s ", tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, ROLE);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}
void s1_hex(char *out, const uint8_t *b, size_t n)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = 0;
}
void s1_hex_rev(char *out, const uint8_t *b, size_t n)
{
    uint8_t t[64];
    for (size_t i = 0; i < n && i < 64; i++) t[i] = b[n - 1 - i];
    s1_hex(out, t, n);
}
void s1_die(const char *why) { s1_log("FATAL: %s", why); exit(1); }
static int unhex(const char *h, uint8_t *out, size_t n)
{
    if (strlen(h) != 2 * n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* ---- ports ---- */
static void rnd_fill(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len)
{
    (void)ctx; (void)p;
    size_t n = 0;
    while (n < len) { ssize_t r = getrandom(out + n, len - n, 0); if (r > 0) n += (size_t)r; else if (errno != EINTR) s1_die("getrandom"); }
}
static void net_fill(void *ctx, uint8_t *out, size_t len) { rnd_fill(ctx, GZ_RANDOM_SECRET, out, len); }
static uint64_t clock_ms(void *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static void illegal(const char *msg, void *data) { (void)data; s1_log("secp256k1 illegal argument: %s", msg); }

/* ---- keys: random per data folder, kept in D/keys (0600) ---- */
static void load_keys(void)
{
    char path[512];
    snprintf(path, sizeof path, "%s/keys", G.dir);
    uint8_t k[64];
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        if (read(fd, k, 64) != 64) s1_die("short key file");
        close(fd);
    } else {
        for (;;) {
            rnd_fill(NULL, GZ_RANDOM_SECRET, k, 64);
            if (secp256k1_ec_seckey_verify(G.secp, k) && secp256k1_ec_seckey_verify(G.secp, k + 32)) break;
        }
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || write(fd, k, 64) != 64 || fsync(fd)) s1_die("cannot write the key file");
        close(fd);
    }
    uint8_t *main_sk = G.host ? G.host_sk : G.ckey_sk, *main_pk = G.host ? G.host_pk : G.ckey_pk;
    memcpy(main_sk, k, 32);
    memcpy(G.fkey_sk, k + 32, 32);
    secp256k1_pubkey p;
    size_t n = 33;
    if (!secp256k1_ec_pubkey_create(G.secp, &p, main_sk)) s1_die("key");
    secp256k1_ec_pubkey_serialize(G.secp, main_pk, &n, &p, SECP256K1_EC_COMPRESSED);
    n = 33;
    if (!secp256k1_ec_pubkey_create(G.secp, &p, G.fkey_sk)) s1_die("key");
    secp256k1_ec_pubkey_serialize(G.secp, G.fkey_pk, &n, &p, SECP256K1_EC_COMPRESSED);
    memset(k, 0, sizeof k);
}

/* ---- connections ---- */
#define MAX_CONN 64
static struct { int used; uint64_t conn; uint8_t key[33]; } CONNS[MAX_CONN];
uint64_t s1_conn_for_key(const uint8_t key[33])
{
    for (int i = 0; i < MAX_CONN; i++) if (CONNS[i].used && !memcmp(CONNS[i].key, key, 33)) return CONNS[i].conn;
    return 0;
}
static void conn_add(uint64_t c, const uint8_t key[33])
{
    for (int i = 0; i < MAX_CONN; i++) if (CONNS[i].used && !memcmp(CONNS[i].key, key, 33)) { CONNS[i].conn = c; return; }
    for (int i = 0; i < MAX_CONN; i++) if (!CONNS[i].used) { CONNS[i].used = 1; CONNS[i].conn = c; memcpy(CONNS[i].key, key, 33); return; }
}
static void conn_del(uint64_t c)
{
    for (int i = 0; i < MAX_CONN; i++) if (CONNS[i].used && CONNS[i].conn == c) CONNS[i].used = 0;
}

/* ---- timers ---- */
#define MAX_TIMERS 64
static struct { int used; uint64_t id, due; } TIMERS[MAX_TIMERS];
static void timer_set(uint64_t id, uint64_t delay)
{
    int free_i = -1;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (TIMERS[i].used && TIMERS[i].id == id) { TIMERS[i].due = mono_ms() + delay; return; }
        if (!TIMERS[i].used && free_i < 0) free_i = i;
    }
    if (free_i < 0) s1_die("timer table full");
    TIMERS[free_i].used = 1; TIMERS[free_i].id = id; TIMERS[free_i].due = mono_ms() + delay;
}
static void timer_cancel(uint64_t id)
{
    for (int i = 0; i < MAX_TIMERS; i++) if (TIMERS[i].used && TIMERS[i].id == id) TIMERS[i].used = 0;
}
#define TIMER_RECONNECT UINT64_C(0x5331000000000001)
static int is_lobby_timer(uint64_t id) { return (id >> 24) == 0x4c; }

/* ---- action lists ---- */
#define LIST_SLOTS 1024
#define LIST_BYTES (4u << 20)
static gz_action_list_t LISTS[8];
static gz_action_t *SLOTS[8];
static uint8_t *BYTES[8];
static int list_depth;
gz_action_list_t *s1_list(void)
{
    int i = list_depth++ % 8;
    if (!SLOTS[i]) { SLOTS[i] = calloc(LIST_SLOTS, sizeof(gz_action_t)); BYTES[i] = malloc(LIST_BYTES); }
    gz_action_list_init(&LISTS[i], SLOTS[i], LIST_SLOTS, BYTES[i], LIST_BYTES);
    return &LISTS[i];
}

static void send_signing(uint64_t conn, const uint8_t *b, size_t n)
{
    static uint8_t rec[70000];
    size_t at = 0;
    rec[at++] = 1;   /* record type 1 (odd), the engine's own message */
    if (n < 0xfd) rec[at++] = (uint8_t)n;
    else if (n <= 0xffff) { rec[at++] = 0xfd; rec[at++] = (uint8_t)(n >> 8); rec[at++] = (uint8_t)n; }
    else { s1_log("signing message of %zu bytes is too big for one test-kind message", n); return; }
    memcpy(rec + at, b, n); at += n;
    static const uint8_t zero[32];
    gz_peers_err_t e = gz_peers_send(PEERS, conn, 32767, zero, rec, at);
    if (e != GZ_PEERS_OK) s1_log("send (signing, %zu bytes) to %llu: %s", n, (unsigned long long)conn, gz_peers_err_name(e));
}

void s1_exec(gz_action_list_t *l)
{
    for (size_t i = 0; i < l->count; i++) {
        const gz_action_t *a = &l->slots[i];
        switch (a->kind) {
        case GZ_ACTION_SAVE: {
            for (size_t r = 0; r < a->u.save.n_records; r++) {
                const gz_record_t *rec = &a->u.save.records[r];
                uint8_t h[8] = {(uint8_t)(rec->type >> 24), (uint8_t)(rec->type >> 16), (uint8_t)(rec->type >> 8), (uint8_t)rec->type,
                                (uint8_t)(rec->bytes.len >> 24), (uint8_t)(rec->bytes.len >> 16), (uint8_t)(rec->bytes.len >> 8), (uint8_t)rec->bytes.len};
                if (write(journal_fd, h, 8) != 8 || write(journal_fd, rec->bytes.data, rec->bytes.len) != (ssize_t)rec->bytes.len)
                    s1_die("journal write");
            }
            if (fsync(journal_fd)) s1_die("journal fsync");
            break;
        }
        case GZ_ACTION_SEND: {
            const uint8_t *b = a->u.send.bytes.data;
            size_t n = a->u.send.bytes.len;
            if (n >= 2 && b[0] == 'G' && b[1] == 'S') send_signing(a->u.send.peer_id, b, n);
            else {
                gz_peers_err_t e = gz_peers_send_raw(PEERS, a->u.send.peer_id, b, n);
                if (e != GZ_PEERS_OK) s1_log("send (lobby, %zu bytes) to %llu: %s", n, (unsigned long long)a->u.send.peer_id, gz_peers_err_name(e));
            }
            break;
        }
        case GZ_ACTION_SET_TIMER: timer_set(a->u.set_timer.timer_id, a->u.set_timer.delay_ms); break;
        case GZ_ACTION_CANCEL_TIMER: timer_cancel(a->u.cancel_timer.timer_id); break;
        case GZ_ACTION_NOTIFY: {
            const uint8_t *b = a->u.notify.bytes.data;
            size_t n = a->u.notify.bytes.len;
            char hx[200];
            s1_hex(hx, b, n > 90 ? 90 : n);
            uint32_t code = a->u.notify.code;
            if (code == 0x4c01 && n == 8) {
                uint64_t c = 0;
                for (int k = 0; k < 8; k++) c = c << 8 | b[k];
                s1_log("lobby: close connection %llu", (unsigned long long)c);
                gz_peers_refuse(PEERS, c, "closed by the lobby");
            } else if (code == 0x4c08 && n == 34) {
                gz_peers_set_seated_key(PEERS, b, b[33]);
                s1_log("lobby: key %s seated %u", hx, b[33]);
            } else if (code == 0x4c02 && n >= 2) {
                s1_log("S1-RESULT member REFUSES the terms: class %u term %u", b[0], b[1]);
            } else if (code == 0x4c06 && n >= 2) {
                s1_log("lobby: seat: lobby state %u seat state %u", b[0], b[1]);
            } else if (code == 0x4c07 && n >= 3) {
                s1_log("lobby: started: role %u signers %u", b[0], (unsigned)(b[1] << 8 | b[2]));
            } else if (code == 0x4c05 && n >= 3) {
                s1_log("S1-RESULT lobby ended: state %u reason %u", b[0], (unsigned)(b[1] << 8 | b[2]));
            } else {
                s1_log("notify 0x%x: %s", code, hx);
            }
            break;
        }
        case GZ_ACTION_BROADCAST: s1_log("broadcast action (%zu bytes) ignored", a->u.broadcast.tx.len); break;
        default: s1_log("action %d ignored", (int)a->kind); break;
        }
    }
    list_depth--;
}

static int accept_any(const uint8_t key[33], void *ctx) { (void)key; (void)ctx; return 1; }

/* ---- member connection ---- */
static char host_ip[64];
static uint16_t host_port;
static void member_connect(void)
{
    uint64_t c;
    gz_peers_err_t e = gz_peers_connect(PEERS, host_ip, host_port, G.host_pk, NULL, &c);
    s1_log("connecting to the host (conn %llu): %s", (unsigned long long)c, gz_peers_err_name(e));
}

static void on_event(const gz_peer_event_t *ev)
{
    switch (ev->type) {
    case GZ_PEER_EV_CONNECTED: {
        char k[67]; s1_hex(k, ev->node_id, 33);
        s1_log("connected: conn %llu key %s", (unsigned long long)ev->conn, k);
        conn_add(ev->conn, ev->node_id);
        if (!G.host) G.host_conn = ev->conn;
        s1_lobby_connected(ev->conn, ev->node_id);
        gz_event_t e = {.kind = GZ_EVENT_PEER_CONNECTED};
        e.u.peer.peer_id = ev->conn;
        s1_sign_event(&e);
        break;
    }
    case GZ_PEER_EV_MESSAGE: {
        if (ev->kind == 32767) {
            gz_env_record_t recs[4];
            int n = gz_env_records(ev->records, ev->records_len, recs, 4);
            const gz_env_record_t *r = n > 0 ? gz_env_find(recs, n, 1) : NULL;
            if (!r) { s1_log("test-kind message without record 1"); break; }
            gz_event_t e = {.kind = GZ_EVENT_MESSAGE_RECEIVED};
            e.u.message.peer_id = ev->conn;
            e.u.message.bytes.data = r->value;
            e.u.message.bytes.len = r->len;
            s1_sign_event(&e);
        } else {
            static uint8_t whole[GZ_ENV_MAX_WHOLE + 64];
            size_t len = 0;
            if (gz_env_write(ev->kind, ev->scope, ev->records, ev->records_len, whole, sizeof whole, &len)) {
                s1_log("cannot rebuild a kind %u message of %zu record bytes", ev->kind, ev->records_len);
                break;
            }
            s1_lobby_message(ev->conn, whole, len);
        }
        break;
    }
    case GZ_PEER_EV_WARNING: s1_log("warning from conn %llu: %s", (unsigned long long)ev->conn, ev->text); break;
    case GZ_PEER_EV_CLOSED:
        s1_log("closed: conn %llu why %s %s", (unsigned long long)ev->conn, gz_peer_why_name(ev->why), ev->text);
        if (ev->was_connected) {
            s1_lobby_disconnected(ev->conn);
            gz_event_t e = {.kind = GZ_EVENT_PEER_DISCONNECTED};
            e.u.peer.peer_id = ev->conn;
            s1_sign_event(&e);
        }
        conn_del(ev->conn);
        if (!G.host) timer_set(TIMER_RECONNECT, 3000);
        break;
    }
}

int main(int argc, char **argv)
{
    const char *role = NULL, *join = NULL, *scope_hex = NULL;
    unsigned listen_port = 0, target = 3, minimum = 3;
    unsigned long long channel = 100000;
    for (int i = 1; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
#define OPT(name) (!strcmp(k, name) && v && ++i)
        if (OPT("--role")) role = v;
        else if (OPT("--dir")) G.dir = v;
        else if (OPT("--listen")) listen_port = (unsigned)atoi(v);
        else if (OPT("--target")) target = (unsigned)atoi(v);
        else if (OPT("--minimum")) minimum = (unsigned)atoi(v);
        else if (OPT("--channel")) channel = strtoull(v, NULL, 10);
        else if (OPT("--join")) join = v;
        else if (OPT("--scope")) scope_hex = v;
        else if (OPT("--fake-tip")) G.tip = (uint32_t)atoi(v);
        else if (OPT("--phrase-in")) G.phrase_in = v;
        else if (OPT("--change-index")) G.change_index = (uint32_t)atoi(v);
        else if (OPT("--gate")) G.gate = v;
        else if (!strcmp(k, "--fake-chain")) G.fake_chain = 1;
        else if (!strcmp(k, "--bad-conditions")) G.member_bad = 1;
        else { fprintf(stderr, "unknown option %s\n", k); return 2; }
    }
    if (!role || !G.dir || (strcmp(role, "host") && strcmp(role, "member"))) { fprintf(stderr, "need --role and --dir\n"); return 2; }
    G.host = !strcmp(role, "host");
    ROLE = G.host ? "HOST  " : (G.member_bad ? "MEMBER*" : "MEMBER");
    mkdir(G.dir, 0700);
    char path[512];
    snprintf(path, sizeof path, "%s/journal", G.dir);
    journal_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (journal_fd < 0) s1_die("journal open");

    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context_set_illegal_callback(secp, illegal, NULL);
    G.secp = secp;
    G.ports.random.fill = rnd_fill;
    G.ports.clock.now_ms = clock_ms;
    load_keys();

    if (!G.fake_chain) {
        if (!s1_chain_open()) s1_die("chain servers");
        if (!s1_chain_tip(&G.tip)) s1_die("no chain tip");
        s1_log("chain: signet tip %u (both operators)", G.tip);
        if (G.host) {
            if (!G.phrase_in) s1_die("the host needs --phrase-in");
            if (!s1_fund_prepare()) s1_die("no coins");
        }
    } else s1_log("fake chain: tip %u", G.tip);

    gz_peers_config_t pc;
    gz_peers_default_config(&pc);
    pc.secp = secp;
    memcpy(pc.static_key, G.host ? G.host_sk : G.ckey_sk, 32);
    pc.random.fill = net_fill;
    pc.random.ctx = NULL;
    pc.is_member = accept_any;
    PEERS = gz_peers_new(&pc);
    if (!PEERS) s1_die("peers");

    uint8_t scope[32];
    if (G.host) {
        uint16_t bound = 0;
        gz_peers_err_t e = gz_peers_listen(PEERS, "127.0.0.1", (uint16_t)listen_port, &bound);
        if (e != GZ_PEERS_OK) s1_die("listen");
        s1_lobby_host_open((uint16_t)target, (uint16_t)minimum, channel, scope);
        char k[67], s[65];
        s1_hex(k, G.host_pk, 33); s1_hex(s, scope, 32);
        snprintf(path, sizeof path, "%s/invite", G.dir);
        FILE *f = fopen(path, "w");
        if (!f) s1_die("invite");
        fprintf(f, "%s@127.0.0.1:%u %s\n", k, bound, s);
        fclose(f);
        s1_log("S1-RESULT invite %s@127.0.0.1:%u scope %s", k, bound, s);
    } else {
        if (!join || !scope_hex || !unhex(scope_hex, scope, 32)) s1_die("member needs --join KEY@IP:PORT --scope HEX");
        const char *at = strchr(join, '@'), *colon = strrchr(join, ':');
        char kh[67];
        if (!at || !colon || at - join != 66) s1_die("bad --join");
        memcpy(kh, join, 66); kh[66] = 0;
        if (!unhex(kh, G.host_pk, 33)) s1_die("bad host key");
        size_t il = (size_t)(colon - at - 1);
        if (il >= sizeof host_ip) s1_die("bad address");
        memcpy(host_ip, at + 1, il); host_ip[il] = 0;
        host_port = (uint16_t)atoi(colon + 1);
        s1_lobby_member_init(scope, G.host_pk);
        member_connect();
    }

    static struct pollfd fds[256];
    uint64_t next_tip = mono_ms() + 60000;
    for (;;) {
        int to = 200;
        size_t n = gz_peers_pollfds(PEERS, fds, 256, &to);
        uint64_t now = mono_ms();
        int t = 200;
        if (to >= 0 && to < t) t = to;
        for (int i = 0; i < MAX_TIMERS; i++)
            if (TIMERS[i].used) { int d = TIMERS[i].due > now ? (int)(TIMERS[i].due - now) : 0; if (d < t) t = d; }
        poll(fds, n, t);
        gz_peers_dispatch(PEERS, fds, n);
        gz_peer_event_t ev;
        while (gz_peers_poll(PEERS, 0, &ev)) on_event(&ev);
        now = mono_ms();
        for (int i = 0; i < MAX_TIMERS; i++) {
            if (!TIMERS[i].used || TIMERS[i].due > now) continue;
            TIMERS[i].used = 0;
            uint64_t id = TIMERS[i].id;
            if (id == TIMER_RECONNECT) member_connect();
            else if (is_lobby_timer(id)) s1_lobby_timer(id);
            else s1_sign_timer(id);
        }
        if (!G.fake_chain && now >= next_tip) {
            next_tip = now + 60000;
            uint32_t tip;
            if (s1_chain_tip(&tip) && tip != G.tip) { G.tip = tip; s1_log("chain: tip %u", tip); }
        }
        s1_sign_poll();
    }
}
