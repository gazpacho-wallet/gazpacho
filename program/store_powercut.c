/* SPDX-License-Identifier: MIT */
/* gazpacho-test only: --test-power-cut-at K (store.h; review A of PR 54, M3).
 *
 * A model of what a disk keeps through a power cut, kept over the storage
 * layer's and the journal's file calls (their OS tables call the hooks):
 *   - a file's data as of its last fsync (a file made and never synced is
 *     empty);
 *   - a folder's names as of its last folder sync (a rename, a new file or a
 *     removal not followed by one is undone).
 * The kill at K (gzp_store_test_tick) first puts every name this process
 * touched back to that state, so a missing fsync or folder sync loses its
 * write, as on a real disk, where a SIGKILL alone keeps the page cache.
 * Names this process never touched are left alone; a name is taken as
 * durable as it was when first touched. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "store.h"

#define PC_NAMES 256
#define PC_INODES 4096
#define PC_FDS 1024

typedef struct {
    uint8_t *data; /* the durable bytes: as of the last fsync */
    size_t len;
} pc_inode_t;

typedef struct {
    char *path;
    int cur; /* the inode the name points at now, or -1 */
    int dur; /* the inode it points at as of the folder's last sync, or -1 */
} pc_name_t;

static int on;
static pc_inode_t ino[PC_INODES];
static int n_ino;
static pc_name_t names[PC_NAMES];
static int n_names;
static int fd_ino[PC_FDS];
static char *fd_dir[PC_FDS];

static void full(const char *what)
{
    printf("test-power-cut model full (%s)\n", what);
    fflush(stdout);
    _exit(97);
}

void gzp_store_test_power_cut(void)
{
    on = 1;
    for (int i = 0; i < PC_FDS; i++) fd_ino[i] = -1;
}

static int read_fd(int fd, uint8_t **d, size_t *l)
{
    struct stat st;
    size_t n, got = 0;
    uint8_t *b;
    *d = NULL;
    *l = 0;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    n = (size_t)st.st_size;
    b = malloc(n ? n : 1);
    if (!b) full("memory");
    while (got < n) {
        ssize_t r = pread(fd, b + got, n - got, (off_t)got);
        if (r <= 0) {
            free(b);
            return -1;
        }
        got += (size_t)r;
    }
    *d = b;
    *l = n;
    return 0;
}

static int new_inode(uint8_t *d, size_t l)
{
    if (n_ino == PC_INODES) full("inodes");
    ino[n_ino].data = d;
    ino[n_ino].len = l;
    return n_ino++;
}

static pc_name_t *find(const char *p)
{
    for (int i = 0; i < n_names; i++)
        if (!strcmp(names[i].path, p)) return &names[i];
    return NULL;
}

/* The name as it is now, taken as durable: nothing of this process has
 * touched it before. */
static pc_name_t *track(const char *p)
{
    pc_name_t *n = find(p);
    int fd;
    if (n) return n;
    if (n_names == PC_NAMES) full("names");
    n = &names[n_names++];
    n->path = strdup(p);
    if (!n->path) full("memory");
    n->cur = n->dur = -1;
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        uint8_t *d;
        size_t l;
        if (read_fd(fd, &d, &l) == 0) n->cur = n->dur = new_inode(d, l);
        close(fd);
    }
    return n;
}

int gzp_pc_pre(const char *p)
{
    struct stat st;
    if (!on) return 0;
    if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) return 1;
    return track(p)->cur >= 0;
}

void gzp_pc_opened(const char *p, int fd, int existed)
{
    struct stat st;
    pc_name_t *n;
    if (!on || fd < 0) return;
    if (fd >= PC_FDS) full("descriptors");
    free(fd_dir[fd]);
    fd_dir[fd] = NULL;
    fd_ino[fd] = -1;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        fd_dir[fd] = strdup(p);
        if (!fd_dir[fd]) full("memory");
        return;
    }
    n = track(p);
    if (!existed || n->cur < 0) n->cur = new_inode(NULL, 0); /* made now: nothing of it is durable yet */
    fd_ino[fd] = n->cur;
}

void gzp_pc_closed(int fd)
{
    if (!on || fd < 0 || fd >= PC_FDS) return;
    fd_ino[fd] = -1;
    free(fd_dir[fd]);
    fd_dir[fd] = NULL;
}

void gzp_pc_dir_synced(const char *d)
{
    size_t dl;
    if (!on || !d) return;
    dl = strlen(d);
    while (dl > 1 && d[dl - 1] == '/') dl--;
    for (int i = 0; i < n_names; i++) {
        const char *s = strrchr(names[i].path, '/');
        if (s && (size_t)(s - names[i].path) == dl && !strncmp(names[i].path, d, dl)) names[i].dur = names[i].cur;
    }
}

void gzp_pc_synced(int fd)
{
    uint8_t *d;
    size_t l;
    int i;
    if (!on || fd < 0 || fd >= PC_FDS) return;
    if (fd_dir[fd]) {
        gzp_pc_dir_synced(fd_dir[fd]);
        return;
    }
    i = fd_ino[fd];
    if (i < 0) return;
    {
        /* The descriptor may be write-only: read the same file through
         * /proc/self/fd (Linux), which opens it again for reading. */
        char pp[64];
        int rfd;
        snprintf(pp, sizeof pp, "/proc/self/fd/%d", fd);
        rfd = open(pp, O_RDONLY | O_CLOEXEC);
        if (rfd < 0) full("a synced file cannot be read back");
        if (read_fd(rfd, &d, &l) != 0) {
            close(rfd);
            full("a synced file cannot be read back");
        }
        close(rfd);
    }
    free(ino[i].data);
    ino[i].data = d;
    ino[i].len = l;
}

void gzp_pc_renamed(const char *from, const char *to)
{
    pc_name_t *a, *b;
    if (!on) return;
    a = track(from);
    b = track(to);
    b->cur = a->cur;
    a->cur = -1;
}

void gzp_pc_linked(const char *from, const char *to)
{
    if (!on) return;
    track(to)->cur = track(from)->cur;
}

void gzp_pc_unlinked(const char *p)
{
    if (!on) return;
    track(p)->cur = -1;
}

void gzp_pc_cut(void)
{
    char tmp[4352];
    int kept = 0, gone = 0;
    if (!on) return;
    for (int i = 0; i < n_names; i++) {
        pc_name_t *n = &names[i];
        int fd;
        if (n->dur < 0) {
            if (unlink(n->path) == 0) gone++;
            continue;
        }
        snprintf(tmp, sizeof tmp, "%s.power-cut", n->path);
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) continue;
        if (ino[n->dur].len && write(fd, ino[n->dur].data, ino[n->dur].len) != (ssize_t)ino[n->dur].len) {
            close(fd);
            unlink(tmp);
            continue;
        }
        close(fd);
        if (rename(tmp, n->path) == 0) kept++;
    }
    printf("test-power-cut names=%d kept=%d removed=%d\n", n_names, kept, gone);
}
