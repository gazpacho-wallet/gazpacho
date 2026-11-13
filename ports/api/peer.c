/* SPDX-License-Identifier: MIT */
/* The same-user check (spec/local-api.md 3.4): on every accepted loopback
 * connection, before a byte is read, ask Linux which account owns the other
 * end, and refuse every account but the program's own. NETLINK_SOCK_DIAG with
 * an exact inet_diag_req_v2 lookup first (sock_diag(7)); the uid column of
 * /proc/net/tcp or /proc/net/tcp6 when the netlink family is unavailable
 * (proc_pid_net(5)). A peer that is not found, because it closed before the
 * lookup or the system does not list it, is refused. The local socket uses
 * SO_PEERCRED (unix(7)). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#if defined(__linux__)
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#endif

#include "internal.h"

#define FOUND 1
#define NOT_FOUND 0
#define UNAVAILABLE -1

/* TCP states as Linux numbers them (include/net/tcp_states.h), in sock_diag
 * and in the st column of /proc/net/tcp. */
#define TCP_STATE_SYN_RECV 3
#define TCP_STATE_TIME_WAIT 6
/* /proc rows read per lookup at most (review F5.4): the loop never reads an
 * unbounded table; a peer not found within them is refused. */
#define PROC_MAX_ROWS 8192

#if defined(__linux__)
static int netlink_uid(const struct sockaddr_storage *peer, const struct sockaddr_storage *local,
                       uint32_t *uid)
{
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req;
    struct sockaddr_nl sa;
    union {
        struct nlmsghdr h;
        char b[8192];
    } ans;
    struct timeval tv = {0, 10000};                      /* 10 ms: a local diag answer is immediate (P5: the loop never waits long) */
    ssize_t n;
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return UNAVAILABLE;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.r.sdiag_family = (uint8_t)peer->ss_family;
    req.r.sdiag_protocol = IPPROTO_TCP;
    req.r.idiag_states = ~0u;
    req.r.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.r.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    /* the peer's socket: its source is the peer's address and port, its
     * destination the program's */
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *p = (const struct sockaddr_in *)peer, *l = (const struct sockaddr_in *)local;
        req.r.id.idiag_sport = p->sin_port;
        req.r.id.idiag_dport = l->sin_port;
        memcpy(req.r.id.idiag_src, &p->sin_addr, 4);
        memcpy(req.r.id.idiag_dst, &l->sin_addr, 4);
    } else {
        const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)peer, *l = (const struct sockaddr_in6 *)local;
        req.r.id.idiag_sport = p->sin6_port;
        req.r.id.idiag_dport = l->sin6_port;
        memcpy(req.r.id.idiag_src, &p->sin6_addr, 16);
        memcpy(req.r.id.idiag_dst, &l->sin6_addr, 16);
    }
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&sa, sizeof sa) != (ssize_t)sizeof req) {
        close(fd);
        return UNAVAILABLE;
    }
    n = recv(fd, &ans, sizeof ans, 0);
    close(fd);
    if (n < (ssize_t)sizeof(struct nlmsghdr)) return UNAVAILABLE;
    if (ans.h.nlmsg_len < sizeof(struct nlmsghdr) || ans.h.nlmsg_len > (size_t)n) return UNAVAILABLE;
    if (ans.h.nlmsg_type == NLMSG_ERROR) {
        const struct nlmsgerr *e = NLMSG_DATA(&ans.h);
        if (ans.h.nlmsg_len < NLMSG_LENGTH(sizeof *e)) return UNAVAILABLE;
        return e->error == -ENOENT ? NOT_FOUND : UNAVAILABLE;
    }
    if (ans.h.nlmsg_type == SOCK_DIAG_BY_FAMILY &&
        ans.h.nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
        const struct inet_diag_msg *m = NLMSG_DATA(&ans.h);
        /* the answer must be the socket asked for */
        if (m->id.idiag_sport != req.r.id.idiag_sport || m->id.idiag_dport != req.r.id.idiag_dport ||
            memcmp(m->id.idiag_src, req.r.id.idiag_src, sizeof m->id.idiag_src) != 0 ||
            memcmp(m->id.idiag_dst, req.r.id.idiag_dst, sizeof m->id.idiag_dst) != 0)
            return NOT_FOUND;
        /* An orphan (closed before accept) becomes a TIME-WAIT socket, which
         * sock_diag reports as uid 0 with no inode: its owner is unknown, so
         * it is not found (review F1). A SYN-RECV entry has no owner either. */
        if (m->idiag_state == TCP_STATE_TIME_WAIT || m->idiag_state == TCP_STATE_SYN_RECV || m->idiag_inode == 0)
            return NOT_FOUND;
        *uid = m->idiag_uid;
        return FOUND;
    }
    return UNAVAILABLE;
}
#endif

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* /proc/net/tcp prints each 32-bit word of the address as the host-order
 * integer whose memory is the network-order bytes (%08X). */
static int parse_addr(const char *hex, size_t n, uint8_t *out)
{
    size_t w, k;
    if (n != 8 && n != 32) return -1;
    for (w = 0; w < n / 8; w++) {
        uint32_t v = 0;
        for (k = 0; k < 8; k++) {
            int d = hexval(hex[w * 8 + k]);
            if (d < 0) return -1;
            v = (v << 4) | (uint32_t)d;
        }
        memcpy(out + 4 * w, &v, 4);
    }
    return (int)(n / 2);
}

static int proc_uid(const struct sockaddr_storage *peer, const struct sockaddr_storage *local, uint32_t *uid)
{
    const char *file = peer->ss_family == AF_INET ? "/proc/net/tcp" : "/proc/net/tcp6";
    FILE *f = fopen(file, "re");
    char line[512];
    uint8_t pa[16], la[16];
    unsigned pport, lport;
    size_t alen;
    int result = NOT_FOUND, rows = 0;
    if (!f) return UNAVAILABLE;
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *p = (const struct sockaddr_in *)peer, *l = (const struct sockaddr_in *)local;
        memcpy(pa, &p->sin_addr, 4);
        memcpy(la, &l->sin_addr, 4);
        pport = ntohs(p->sin_port);
        lport = ntohs(l->sin_port);
        alen = 4;
    } else {
        const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)peer, *l = (const struct sockaddr_in6 *)local;
        memcpy(pa, &p->sin6_addr, 16);
        memcpy(la, &l->sin6_addr, 16);
        pport = ntohs(p->sin6_port);
        lport = ntohs(l->sin6_port);
        alen = 16;
    }
    if (!fgets(line, sizeof line, f)) { fclose(f); return UNAVAILABLE; }   /* the title row */
    while (rows++ < PROC_MAX_ROWS && fgets(line, sizeof line, f)) {
        char lhex[40], rhex[40];
        unsigned lp, rp, st, u;
        unsigned long inode;
        uint8_t a1[16], a2[16];
        if (sscanf(line, " %*u: %39[0-9A-Fa-f]:%x %39[0-9A-Fa-f]:%x %x %*x:%*x %*x:%*x %*x %u %*d %lu", lhex, &lp,
                   rhex, &rp, &st, &u, &inode) != 7)
            continue;
        if (parse_addr(lhex, strlen(lhex), a1) != (int)alen || parse_addr(rhex, strlen(rhex), a2) != (int)alen)
            continue;
        /* the peer's row: its local end is the peer, its remote end the program */
        if (lp == pport && rp == lport && memcmp(a1, pa, alen) == 0 && memcmp(a2, la, alen) == 0) {
            /* a TIME-WAIT or SYN-RECV row, or no inode: no owner (review F1) */
            if (st == TCP_STATE_TIME_WAIT || st == TCP_STATE_SYN_RECV || inode == 0) break;
            *uid = u;
            result = FOUND;
            break;
        }
    }
    fclose(f);
    return result;
}

int gz_peer_check_available(gz_api_server *srv)
{
    int mode = srv->cfg.peer_mode;
    FILE *f;
    if (mode == GZ_API_PEER_UNAVAILABLE) return 0;
#if defined(__linux__)
    if (mode != GZ_API_PEER_PROC_ONLY) {
        int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if (fd >= 0) { close(fd); return 1; }
        if (mode == GZ_API_PEER_NETLINK_ONLY) return 0;
    }
#endif
    f = fopen("/proc/net/tcp", "re");
    if (f) { fclose(f); return 1; }
    return 0;
}

int gz_peer_same_user(gz_api_server *srv, int fd)
{
    struct sockaddr_storage peer, local;
    socklen_t pl = sizeof peer, ll = sizeof local;
    uint32_t uid = UINT32_MAX;                         /* no account's: a lookup that fails matches nobody */
    int r = UNAVAILABLE;
    if (getpeername(fd, (struct sockaddr *)&peer, &pl) != 0 || getsockname(fd, (struct sockaddr *)&local, &ll) != 0)
        return 0;
    if (peer.ss_family == AF_UNIX) {
#if defined(SO_PEERCRED)
        struct ucred cr;
        socklen_t cl = sizeof cr;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 || cl != sizeof cr) return 0;
        return (int64_t)cr.uid == srv->expect_uid;
#else
        return 0;
#endif
    }
    if (peer.ss_family != AF_INET && peer.ss_family != AF_INET6) return 0;
    if (!srv->peer_check_ok) return 1;                 /* reported as unavailable in status (3.4) */
#if defined(__linux__)
    if (srv->cfg.peer_mode != GZ_API_PEER_PROC_ONLY) r = netlink_uid(&peer, &local, &uid);
#endif
    if (r == UNAVAILABLE && srv->cfg.peer_mode != GZ_API_PEER_NETLINK_ONLY) r = proc_uid(&peer, &local, &uid);
    if (r != FOUND) return 0;                          /* not found or not readable: refused */
    return (int64_t)uid == srv->expect_uid;
}
