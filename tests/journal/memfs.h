/* An in-memory file system for the journal's tests, with fault injection.
 *
 * Each file has the bytes a sync made durable and a list of writes since. The
 * folder has the names a folder sync made durable and the names now. Every
 * write, sync, truncate, create, link, rename and unlink is a numbered
 * "point". A test can make point N fail (an error, a short write, a full
 * disk) or crash the program just before it. From a crash on, every point
 * fails and changes nothing, so the disk stays as it was at that moment while
 * the program unwinds normally and frees what it holds (no memory is
 * abandoned, so the crash tests run under the leak checkers too). Nothing
 * the program does after the crash can reach the disk or be confirmed: a
 * confirmation needs a successful sync. The test then turns the crash into
 * what the disk holds after a power cut:
 *
 *   MEMFS_LOSE     nothing unsynced survives;
 *   MEMFS_KEEP     everything written survives (a process kill: the page
 *                  cache is kept); folder names stay as they are, durable
 *                  only as far as a folder sync made them;
 *   MEMFS_REORDER  a random subset of the unsynced writes survives, in any
 *                  combination, one of them possibly torn, and either the old
 *                  or the new folder names.
 *
 * A FAILED SYNC behaves as Linux's ext4 and XFS do after a writeback error
 * (review A, R1): the call reports EIO, the writes it covered are marked
 * clean without reaching the disk, and they stay readable through pread
 * (the page cache) while the disk lacks them; a later successful sync does
 * not write them (only the file's size, with zeros). pread_device reads the
 * disk and drops the clean cache. A power cut (LOSE, REORDER) shows the
 * disk; a process kill (KEEP) writes the dirty writes and keeps the cache.
 * `sync_fail_drops` selects the older model instead: the failed writes are
 * dropped from the readable contents too.
 *
 * Test code only; never linked into the journal. */
#ifndef GZ_TEST_MEMFS_H
#define GZ_TEST_MEMFS_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"

#define MEMFS_FILES 16
#define MEMFS_FDS   16

enum { MEMFS_LOSE = 0, MEMFS_KEEP, MEMFS_REORDER };
enum { MEMFS_FAIL_ERROR = 1, MEMFS_FAIL_SHORT, MEMFS_FAIL_NOSPACE };

typedef struct {
    uint64_t off;
    size_t len;          /* for a truncate: 0, and `off` is the new length */
    int truncate;
    uint8_t *data;
} memfs_op_t;

typedef struct {
    int used;
    uint8_t *dur, *vol;
    size_t dur_len, vol_len;
    memfs_op_t *ops;
    size_t n_ops, cap_ops;
    int lock_fd;         /* -1 when unlocked */
} memfs_inode_t;

typedef struct {
    char name[160];
    int inode;           /* -1: no such name */
} memfs_name_t;

typedef struct {
    memfs_inode_t inode[MEMFS_FILES];
    memfs_name_t vol[MEMFS_FILES], dur[MEMFS_FILES];
    int fd_inode[MEMFS_FDS];           /* -1: closed */
    uint64_t points;                   /* points passed so far */
    uint64_t crash_at;                 /* crash just before this point (1-based); 0: never */
    uint64_t fail_at;                  /* fail this point; 0: never */
    int fail_mode;
    uint64_t fail_only_sync;           /* with fail_at: count only syncs */
    uint64_t capacity;                 /* 0: unlimited */
    size_t max_read;                   /* a read returns at most this; 0: unlimited */
    int bad_closes;                    /* closes of a descriptor that was not open */
    uint64_t after_fail;               /* points passed after the failed one */
    int crashed;                       /* set at the crash point; cleared by settle */
    int sync_fail_drops;               /* 1: a failed sync drops the failed writes from view too */
    int no_links;                      /* nonzero: link fails with this errno (EPERM: FAT, exFAT) */
    /* Reading this path fails (not a point): how 1 its open for reading or
     * writing, 2 every pread through a descriptor on it; errno, 0: EIO. */
    const char *fail_path;
    int fail_path_how, fail_path_errno;
    uint64_t random_ctr;               /* the next "random" byte (a counter) */
    int random_fails;                  /* 1: the random source fails */
    /* Called after every successful file sync with the inode's durable length. */
    void (*on_sync)(void *ctx, int inode, size_t durable_len);
    void *on_sync_ctx;
    gz_journal_os_t os;
} memfs_t;

void memfs_init(memfs_t *m);
void memfs_free(memfs_t *m);
/* After a crash: settle the disk as `mode` says, using `seed` for REORDER,
 * and close every descriptor. */
void memfs_settle(memfs_t *m, int mode, uint64_t seed);
/* Current contents of a named file, as a read sees them (NULL if absent). */
const uint8_t *memfs_get(const memfs_t *m, const char *path, size_t *len);
/* What the disk holds for a named file now (NULL if no such current name). */
const uint8_t *memfs_disk(const memfs_t *m, const char *path, size_t *len);
/* Replace a file's contents, durably (to set up a test). */
void memfs_put(memfs_t *m, const char *path, const uint8_t *data, size_t len);
void memfs_copy(memfs_t *dst, const memfs_t *src);
/* Number of descriptors open now. */
int memfs_open_fds(const memfs_t *m);

#endif
