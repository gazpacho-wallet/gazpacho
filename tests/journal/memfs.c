/* In-memory file system with fault injection. See memfs.h. */
#include "memfs.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) abort();
    return q;
}

static uint64_t mix(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

/* A numbered point. Returns 2 if the program has crashed (at this point or
 * before): the call must fail and change nothing, so the disk stays exactly
 * as it was at the crash while the program unwinds and frees what it holds.
 * Returns 1 if this point is the one to fail, else 0. */
static int point(memfs_t *m, int is_sync)
{
    if (m->crashed) return 2;
    if (m->fail_only_sync && !is_sync) return 0;
    m->points++;
    if (m->fail_at && m->points > m->fail_at && is_sync != 2) m->after_fail++; /* 2: an unlink, cleanup */
    if (m->crash_at && m->points == m->crash_at) {
        m->crashed = 1;
        return 2;
    }
    return m->fail_at && m->points == m->fail_at;
}

static int find(const memfs_name_t *names, const char *path)
{
    for (int i = 0; i < MEMFS_FILES; i++)
        if (names[i].inode >= 0 && strcmp(names[i].name, path) == 0) return i;
    return -1;
}

static int add_name(memfs_name_t *names, const char *path, int inode)
{
    for (int i = 0; i < MEMFS_FILES; i++)
        if (names[i].inode < 0) {
            strncpy(names[i].name, path, sizeof names[i].name - 1);
            names[i].name[sizeof names[i].name - 1] = 0;
            names[i].inode = inode;
            return 0;
        }
    abort();
}

static int new_inode(memfs_t *m)
{
    for (int i = 0; i < MEMFS_FILES; i++)
        if (!m->inode[i].used) {
            memfs_inode_t *n = &m->inode[i];
            memset(n, 0, sizeof *n);
            n->used = 1;
            n->lock_fd = -1;
            return i;
        }
    abort();
}

static uint64_t used_space(const memfs_t *m)
{
    uint64_t t = 0;
    for (int i = 0; i < MEMFS_FILES; i++)
        if (m->inode[i].used) t += m->inode[i].vol_len;
    return t;
}

static void apply(uint8_t **buf, size_t *len, const memfs_op_t *op, size_t take)
{
    if (op->truncate) {
        *buf = xrealloc(*buf, op->off);
        if (op->off > *len) memset(*buf + *len, 0, op->off - *len);
        *len = op->off;
        return;
    }
    if (op->off + take > *len) {
        *buf = xrealloc(*buf, op->off + take);
        if (op->off > *len) memset(*buf + *len, 0, op->off - *len);
        *len = op->off + take;
    }
    memcpy(*buf + op->off, op->data, take);
}

static void push_op(memfs_inode_t *n, uint64_t off, const void *data, size_t len, int trunc)
{
    if (n->n_ops == n->cap_ops) {
        n->cap_ops = n->cap_ops ? 2 * n->cap_ops : 8;
        n->ops = xrealloc(n->ops, n->cap_ops * sizeof *n->ops);
    }
    memfs_op_t *op = &n->ops[n->n_ops++];
    op->off = off;
    op->len = len;
    op->truncate = trunc;
    op->data = NULL;
    if (len) {
        op->data = xrealloc(NULL, len);
        memcpy(op->data, data, len);
    }
    apply(&n->vol, &n->vol_len, op, len);
}

static void clear_ops(memfs_inode_t *n)
{
    for (size_t i = 0; i < n->n_ops; i++) free(n->ops[i].data);
    n->n_ops = 0;
}

/* The dirty writes reach the disk, and the size the file has now (bytes of
 * a failed sync that a later write did not cover are zeros there). */
static void persist(memfs_inode_t *n)
{
    for (size_t k = 0; k < n->n_ops; k++) apply(&n->dur, &n->dur_len, &n->ops[k], n->ops[k].len);
    clear_ops(n);
    if (n->dur_len != n->vol_len) {
        n->dur = xrealloc(n->dur, n->vol_len);
        if (n->vol_len > n->dur_len) memset(n->dur + n->dur_len, 0, n->vol_len - n->dur_len);
        n->dur_len = n->vol_len;
    }
}

/* Free every file no name (current or durable) and no descriptor refers to:
 * a replaced guard or marker file, once the folder's names no longer hold it. */
static void gc(memfs_t *m)
{
    for (int i = 0; i < MEMFS_FILES; i++) {
        if (!m->inode[i].used) continue;
        int ref = 0;
        for (int k = 0; k < MEMFS_FILES; k++) ref |= m->vol[k].inode == i || m->dur[k].inode == i;
        for (int k = 0; k < MEMFS_FDS; k++) ref |= m->fd_inode[k] == i;
        if (ref) continue;
        memfs_inode_t *n = &m->inode[i];
        for (size_t o = 0; o < n->n_ops; o++) free(n->ops[o].data);
        free(n->ops); free(n->dur); free(n->vol);
        memset(n, 0, sizeof *n);
    }
}

static int fd_ok(memfs_t *m, int fd)
{
    return fd >= 0 && fd < MEMFS_FDS && m->fd_inode[fd] >= 0;
}

/* --- the table ------------------------------------------------------------ */

static int m_open(void *ctx, const char *path, int how)
{
    memfs_t *m = ctx;
    int ino = -1, k = find(m->vol, path);
    if (how == GZ_JOURNAL_OPEN_READ || how == GZ_JOURNAL_OPEN_RW) {
        if (k < 0) { errno = ENOENT; return -1; }
        if (m->fail_path && m->fail_path_how == 1 && strcmp(path, m->fail_path) == 0) {
            errno = m->fail_path_errno ? m->fail_path_errno : EIO;
            return -1;
        }
        ino = m->vol[k].inode;
    } else if (how == GZ_JOURNAL_OPEN_CREATE && k >= 0) {
        ino = m->vol[k].inode; /* opened as it is: not a point */
    } else {
        if (point(m, 0)) { errno = EIO; return -1; }
        if (k >= 0 && how == GZ_JOURNAL_OPEN_CREATE_EXCL) { errno = EEXIST; return -1; }
        if (k >= 0) {
            ino = m->vol[k].inode;
            push_op(&m->inode[ino], 0, NULL, 0, 1);
        } else {
            ino = new_inode(m);
            add_name(m->vol, path, ino);
        }
    }
    for (int fd = 3; fd < MEMFS_FDS; fd++)
        if (m->fd_inode[fd] < 0) {
            m->fd_inode[fd] = ino;
            return fd;
        }
    errno = EMFILE;
    return -1;
}

static int m_close(void *ctx, int fd)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { m->bad_closes++; errno = EBADF; return -1; }
    memfs_inode_t *n = &m->inode[m->fd_inode[fd]];
    if (n->lock_fd == fd) n->lock_fd = -1;
    m->fd_inode[fd] = -1;
    gc(m);
    return 0;
}

/* fail_path with how 2: every read through a descriptor on it fails. */
static int read_fails(memfs_t *m, int fd)
{
    if (!m->fail_path || m->fail_path_how != 2) return 0;
    int k = find(m->vol, m->fail_path);
    if (k < 0 || m->vol[k].inode != m->fd_inode[fd]) return 0;
    errno = m->fail_path_errno ? m->fail_path_errno : EIO;
    return 1;
}

static long m_pread(void *ctx, int fd, void *buf, size_t len, uint64_t off)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    if (read_fails(m, fd)) return -1;
    memfs_inode_t *n = &m->inode[m->fd_inode[fd]];
    if (off >= n->vol_len) return 0;
    if (len > n->vol_len - off) len = n->vol_len - (size_t)off;
    if (m->max_read && len > m->max_read) len = m->max_read;
    memcpy(buf, n->vol + off, len);
    return (long)len;
}

static long m_pwrite(void *ctx, int fd, const void *buf, size_t len, uint64_t off)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    memfs_inode_t *n = &m->inode[m->fd_inode[fd]];
    int pt = point(m, 0);
    if (pt == 2) { errno = EIO; return -1; }
    if (pt) {
        if (m->fail_mode == MEMFS_FAIL_SHORT && len > 1) len /= 2;
        else { errno = m->fail_mode == MEMFS_FAIL_NOSPACE ? ENOSPC : EIO; return -1; }
    }
    if (m->capacity && off + len > n->vol_len) {
        uint64_t grow = off + len - n->vol_len, used = used_space(m);
        if (used + grow > m->capacity) {
            uint64_t room = m->capacity > used ? m->capacity - used : 0;
            if (room == 0) { errno = ENOSPC; return -1; }
            len -= (size_t)(grow - room);
        }
    }
    push_op(n, off, buf, len, 0);
    return (long)len;
}

static int m_sync(void *ctx, int fd)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    int ino = m->fd_inode[fd];
    memfs_inode_t *n = &m->inode[ino];
    int pt = point(m, 1);
    if (pt == 2) { errno = EIO; return -1; }
    if (pt) {
        if (m->sync_fail_drops) {
            /* The older model: the failed writes vanish from view too. */
            clear_ops(n);
            n->vol = xrealloc(n->vol, n->dur_len);
            if (n->dur_len) memcpy(n->vol, n->dur, n->dur_len);
            n->vol_len = n->dur_len;
        } else {
            /* Linux (ext4, XFS): the pages are marked clean and kept, with
             * the bytes, in the cache; the disk never gets them. */
            clear_ops(n);
        }
        errno = EIO;
        return -1;
    }
    persist(n);
    if (m->on_sync) m->on_sync(m->on_sync_ctx, ino, n->dur_len);
    return 0;
}

/* The disk side of a pread: what the device holds. The journal calls it
 * only after a successful sync, so no write is dirty; the clean cache is
 * then dropped (posix_fadvise DONTNEED). */
static long m_pread_device(void *ctx, int fd, void *buf, size_t len, uint64_t off)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    if (read_fails(m, fd)) return -1;
    memfs_inode_t *n = &m->inode[m->fd_inode[fd]];
    if (n->n_ops == 0) {
        n->vol = xrealloc(n->vol, n->dur_len);
        if (n->dur_len) memcpy(n->vol, n->dur, n->dur_len);
        n->vol_len = n->dur_len;
    }
    if (off >= n->dur_len) return 0;
    if (len > n->dur_len - off) len = n->dur_len - (size_t)off;
    if (m->max_read && len > m->max_read) len = m->max_read;
    memcpy(buf, n->dur + off, len);
    return (long)len;
}

static int m_sync_dir(void *ctx, const char *dir)
{
    memfs_t *m = ctx;
    (void)dir;
    if (point(m, 1)) { errno = EIO; return -1; }
    memcpy(m->dur, m->vol, sizeof m->dur);
    gc(m);
    return 0;
}

static int m_truncate(void *ctx, int fd, uint64_t len)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    if (point(m, 0)) { errno = EIO; return -1; }
    push_op(&m->inode[m->fd_inode[fd]], len, NULL, 0, 1);
    return 0;
}

static int m_size(void *ctx, int fd, uint64_t *out)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    *out = m->inode[m->fd_inode[fd]].vol_len;
    return 0;
}

static int m_lock(void *ctx, int fd)
{
    memfs_t *m = ctx;
    if (!fd_ok(m, fd)) { errno = EBADF; return -1; }
    memfs_inode_t *n = &m->inode[m->fd_inode[fd]];
    if (n->lock_fd >= 0 && n->lock_fd != fd) { errno = EWOULDBLOCK; return -1; }
    n->lock_fd = fd;
    return 0;
}

static int m_link(void *ctx, const char *from, const char *to)
{
    memfs_t *m = ctx;
    if (point(m, 0)) { errno = EIO; return -1; }
    if (m->no_links) { errno = m->no_links; return -1; }
    int a = find(m->vol, from);
    if (a < 0) { errno = ENOENT; return -1; }
    if (find(m->vol, to) >= 0) { errno = EEXIST; return -1; }
    return add_name(m->vol, to, m->vol[a].inode);
}

static int m_rename(void *ctx, const char *from, const char *to)
{
    memfs_t *m = ctx;
    if (point(m, 0)) { errno = EIO; return -1; }
    int a = find(m->vol, from);
    if (a < 0) { errno = ENOENT; return -1; }
    int b = find(m->vol, to);
    if (b >= 0) m->vol[b].inode = -1;
    strncpy(m->vol[a].name, to, sizeof m->vol[a].name - 1);
    gc(m);
    return 0;
}

static int m_unlink(void *ctx, const char *path)
{
    memfs_t *m = ctx;
    if (point(m, 2)) { errno = EIO; return -1; }
    int a = find(m->vol, path);
    if (a < 0) { errno = ENOENT; return -1; }
    m->vol[a].inode = -1;
    gc(m);
    return 0;
}

void memfs_init(memfs_t *m)
{
    memset(m, 0, sizeof *m);
    for (int i = 0; i < MEMFS_FILES; i++) m->vol[i].inode = m->dur[i].inode = -1;
    for (int i = 0; i < MEMFS_FDS; i++) m->fd_inode[i] = -1;
    gz_journal_os_t os = {m_open, m_close, m_pread, m_pwrite, m_sync, m_sync_dir, m_truncate,
                          m_size, m_lock, m_link, m_rename, m_unlink, m_pread_device, m};
    m->os = os;
}

void memfs_free(memfs_t *m)
{
    for (int i = 0; i < MEMFS_FILES; i++) {
        clear_ops(&m->inode[i]);
        free(m->inode[i].ops);
        free(m->inode[i].dur);
        free(m->inode[i].vol);
    }
    memset(m->inode, 0, sizeof m->inode);
}

void memfs_settle(memfs_t *m, int mode, uint64_t seed)
{
    uint64_t s = seed * 2 + 1;
    for (int i = 0; i < MEMFS_FILES; i++) {
        memfs_inode_t *n = &m->inode[i];
        if (!n->used) continue;
        if (mode == MEMFS_KEEP) {
            /* A kill: the dirty writes reach the disk in time; the page cache,
             * with any bytes of a failed sync, stays as it is. */
            persist(n);
            n->lock_fd = -1;
            continue;
        } else if (mode == MEMFS_REORDER) {
            size_t torn = n->n_ops ? (size_t)(mix(&s) % (2 * n->n_ops)) : 0; /* >= n_ops: none */
            for (size_t k = 0; k < n->n_ops; k++) {
                if (mix(&s) & 1) continue; /* this write was lost */
                size_t take = n->ops[k].len;
                if (k == torn && take) take = (size_t)(mix(&s) % take);
                apply(&n->dur, &n->dur_len, &n->ops[k], take);
            }
        }
        clear_ops(n);
        n->vol = xrealloc(n->vol, n->dur_len);
        if (n->dur_len) memcpy(n->vol, n->dur, n->dur_len);
        n->vol_len = n->dur_len;
        n->lock_fd = -1;
    }
    /* A kill (KEEP) leaves the folder's names as they are: current, and
     * durable only as far as a folder sync made them (review B, B5). */
    if (mode == MEMFS_REORDER && (mix(&s) & 1))
        memcpy(m->dur, m->vol, sizeof m->dur);
    else if (mode != MEMFS_KEEP)
        memcpy(m->vol, m->dur, sizeof m->vol);
    /* Free inodes no name refers to. */
    for (int i = 0; i < MEMFS_FILES; i++) {
        int named = 0;
        for (int k = 0; k < MEMFS_FILES; k++) named |= m->vol[k].inode == i || m->dur[k].inode == i;
        if (m->inode[i].used && !named) {
            free(m->inode[i].ops); free(m->inode[i].dur); free(m->inode[i].vol);
            memset(&m->inode[i], 0, sizeof m->inode[i]);
        }
    }
    for (int i = 0; i < MEMFS_FDS; i++) m->fd_inode[i] = -1;
    m->crashed = 0;
    m->crash_at = m->fail_at = 0;
}

const uint8_t *memfs_get(const memfs_t *m, const char *path, size_t *len)
{
    int k = find(m->vol, path);
    if (k < 0) return NULL;
    *len = m->inode[m->vol[k].inode].vol_len;
    return m->inode[m->vol[k].inode].vol;
}

const uint8_t *memfs_disk(const memfs_t *m, const char *path, size_t *len)
{
    int k = find(m->vol, path);
    if (k < 0) return NULL;
    *len = m->inode[m->vol[k].inode].dur_len;
    return m->inode[m->vol[k].inode].dur;
}

void memfs_put(memfs_t *m, const char *path, const uint8_t *data, size_t len)
{
    int k = find(m->vol, path), ino;
    if (k < 0) {
        ino = new_inode(m);
        add_name(m->vol, path, ino);
        memcpy(m->dur, m->vol, sizeof m->dur);
    } else {
        ino = m->vol[k].inode;
    }
    memfs_inode_t *n = &m->inode[ino];
    clear_ops(n);
    n->vol = xrealloc(n->vol, len);
    n->dur = xrealloc(n->dur, len);
    if (len) { memcpy(n->vol, data, len); memcpy(n->dur, data, len); }
    n->vol_len = n->dur_len = len;
}

int memfs_open_fds(const memfs_t *m)
{
    int n = 0;
    for (int i = 0; i < MEMFS_FDS; i++) n += m->fd_inode[i] >= 0;
    return n;
}

void memfs_copy(memfs_t *dst, const memfs_t *src)
{
    memfs_init(dst);
    for (int i = 0; i < MEMFS_FILES; i++)
        if (src->vol[i].inode >= 0) {
            const memfs_inode_t *n = &src->inode[src->vol[i].inode];
            memfs_put(dst, src->vol[i].name, n->vol, n->vol_len);
        }
}
