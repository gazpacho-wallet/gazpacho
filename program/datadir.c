/* SPDX-License-Identifier: MIT */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "datadir.h"
#include "gzp.h"

int gzp_datadir_path(const gzp_datadir_t *d, const char *name, char out[GZP_PATH_MAX])
{
    int n = snprintf(out, GZP_PATH_MAX, "%s/%s", d->dir, name);
    return n < 0 || n >= GZP_PATH_MAX ? -1 : 0;
}

int gzp_datadir_sync(const gzp_datadir_t *d)
{
    int fd = open(d->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int rc;
    if (fd < 0) return -1;
    rc = fsync(fd);
    close(fd);
    return rc;
}

static int read_small(const char *path, char *buf, size_t cap, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t r;
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    r = read(fd, buf, cap);
    close(fd);
    if (r < 0) return -1;
    *len = (size_t)r;
    return 0;
}

/* Write a new file whole, then sync it and the folder. */
static int write_new(const gzp_datadir_t *d, const char *path, const char *buf, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int ok;
    if (fd < 0) return -1;
    ok = write(fd, buf, len) == (ssize_t)len && fsync(fd) == 0;
    close(fd);
    if (!ok) {
        unlink(path);
        return -1;
    }
    return gzp_datadir_sync(d);
}

int gzp_datadir_open(gzp_datadir_t *d, const char *dir, const char *role, const char *network)
{
    struct stat st;
    char path[GZP_PATH_MAX], want[64], have[64], pid[32];
    size_t n = 0;
    int r;
    memset(d, 0, sizeof *d);
    d->lock_fd = -1;
    if (strlen(dir) >= GZP_PATH_MAX - 32) {
        fprintf(stderr, "gazpacho: data folder path too long\n");
        return GZP_EXIT_DATA;
    }
    strcpy(d->dir, dir);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "gazpacho: cannot create the data folder %s: %s\n", dir, strerror(errno));
        return GZP_EXIT_DATA;
    }
    /* The lock is on the folder itself (review of PR 27, M3): a file in it
     * can be deleted from under a running program, and a second program
     * would then lock a new file and share the folder. A directory cannot be
     * removed while it holds files, and its lock goes with its descriptor,
     * so a crash leaves no stale lock. */
    d->lock_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (d->lock_fd < 0 || fstat(d->lock_fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "gazpacho: %s is not a folder\n", dir);
        if (d->lock_fd >= 0) close(d->lock_fd);
        d->lock_fd = -1;
        return GZP_EXIT_DATA;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077)) {
        fprintf(stderr, "gazpacho: the data folder %s must belong to this user and be closed to others (chmod 700)\n", dir);
        close(d->lock_fd); /* review B of PR 27, N4 */
        d->lock_fd = -1;
        return GZP_EXIT_DATA;
    }
    gzp_datadir_path(d, "lock", path);
    if (flock(d->lock_fd, LOCK_EX | LOCK_NB) != 0) {
        int pf = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t got = pf >= 0 ? pread(pf, pid, sizeof pid - 1, 0) : 0;
        if (pf >= 0) close(pf);
        pid[got > 0 ? got : 0] = 0;
        pid[strcspn(pid, "\n")] = 0;
        fprintf(stderr, "gazpacho: the data folder %s is in use by another gazpacho%s%s%s\n", dir,
                pid[0] ? " (pid " : "", pid, pid[0] ? ")" : "");
        close(d->lock_fd);
        d->lock_fd = -1;
        return GZP_EXIT_LOCKED;
    }
    /* `lock` holds the pid, only for the message above; the lock is the folder's. */
    {
        int pf = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        snprintf(pid, sizeof pid, "%ld\n", (long)getpid());
        if (pf >= 0) {
            if (write(pf, pid, strlen(pid)) < 0) {
                /* the message only */
            }
            close(pf);
        }
    }    /* Identity: one role and one network per folder. */
    snprintf(want, sizeof want, "%s %s\n", role, network);
    gzp_datadir_path(d, "identity", path);
    r = read_small(path, have, sizeof have - 1, &n);
    if (r < 0) {
        fprintf(stderr, "gazpacho: cannot read %s\n", path);
        return GZP_EXIT_DATA;
    }
    if (r == 1) {
        if (write_new(d, path, want, strlen(want)) != 0) {
            fprintf(stderr, "gazpacho: cannot write %s\n", path);
            return GZP_EXIT_DATA;
        }
    } else {
        have[n] = 0;
        if (strcmp(have, want)) {
            have[strcspn(have, "\n")] = 0;
            fprintf(stderr, "gazpacho: the data folder %s belongs to a %s; refusing to start it as a %s %s\n",
                    dir, have, role, network);
            return GZP_EXIT_DATA;
        }
    }
    return 0;
}

void gzp_datadir_close(gzp_datadir_t *d)
{
    if (d->lock_fd >= 0) close(d->lock_fd); /* releases the lock */
    d->lock_fd = -1;
}

int gzp_datadir_secret(const gzp_datadir_t *d, const char *name, uint8_t out[32],
                       int (*check)(const uint8_t key[32], void *ctx), void *ctx)
{
    char path[GZP_PATH_MAX], buf[80];
    size_t n = 0;
    struct stat st;
    int r;
    if (gzp_datadir_path(d, name, path) != 0) return GZP_EXIT_DATA;
    r = read_small(path, buf, sizeof buf, &n);
    if (r < 0) {
        fprintf(stderr, "gazpacho: cannot read %s\n", path);
        return GZP_EXIT_DATA;
    }
    if (r == 1) {
        do {
            gzp_os_random(out, 32);
        } while (check && !check(out, ctx));
        gzp_hex(out, 32, buf);
        buf[64] = '\n';
        r = write_new(d, path, buf, 65);
        OPENSSL_cleanse(buf, sizeof buf);
        if (r != 0) {
            OPENSSL_cleanse(out, 32);
            fprintf(stderr, "gazpacho: cannot write %s\n", path);
            return GZP_EXIT_DATA;
        }
        return 0;
    }
    if (stat(path, &st) != 0 || (st.st_mode & 077)) {
        OPENSSL_cleanse(buf, sizeof buf);
        fprintf(stderr, "gazpacho: %s must be closed to others (chmod 600)\n", path);
        return GZP_EXIT_DATA;
    }
    if (n > 64 && buf[n - 1] == '\n') n--;
    r = gzp_unhex(buf, n, out, 32) && (!check || check(out, ctx));
    OPENSSL_cleanse(buf, sizeof buf);
    if (!r) {
        OPENSSL_cleanse(out, 32);
        fprintf(stderr, "gazpacho: %s is not 64 hex digits of a usable key\n", path);
        return GZP_EXIT_DATA;
    }
    return 0;
}
