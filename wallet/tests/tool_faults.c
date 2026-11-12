/* Fault injection for gz-wallet-keys, used by test_tool_faults.sh.
 *
 * This file is linked into a second build of the tool, gz-wallet-keys-faults,
 * with the linker option --wrap for each function below, so that the tool's
 * own calls go through these wrappers.  The environment variable GZ_FAULT
 * selects one fault; without it the wrappers pass everything through.
 * (Adapted from the reviewer's LD_PRELOAD shim; --wrap is used instead so
 * that the same test also runs under AddressSanitizer.)
 *
 *   rand_fail          the random source fails
 *   rand_short         the random source gives one byte at a time
 *   rand_zero          the random source gives no bytes
 *   write_enospc       every write to a regular file fails (disk full)
 *   write_late         writes are short, and fail after the third
 *   write_short        writes take at most 7 bytes at a time
 *   write_eintr        every other write is interrupted
 *   die_in_write       the process dies at the first write to a regular file
 *   fsync_file_fail    syncing a regular file fails
 *   fsync_dir_fail     syncing a directory fails
 *   link_fail          giving the file its name fails
 *   die_in_link        the process dies just before the file gets its name
 *   race_create        another file appears under the name just before that
 *   read_short         reads return at most 5 bytes
 *   read_eintr         every other read is interrupted
 *   other_uid          the process appears to be another user
 *   check_core         fail the random source unless core dumps are off
 *   check_create       refuse to create a file unless asked for mode 0600,
 *                      exclusively, without following a symbolic link
 *   wrap_report        print which wrappers are in use to standard error
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

ssize_t __real_getrandom(void *buf, size_t len, unsigned flags);
ssize_t __real_write(int fd, const void *buf, size_t len);
ssize_t __real_read(int fd, void *buf, size_t len);
int __real_fsync(int fd);
int __real_link(const char *from, const char *to);
int __real_open(const char *path, int flags, ...);
uid_t __real_geteuid(void);

static int fault(const char *name) {
    const char *m = getenv("GZ_FAULT");
    return m && strcmp(m, name) == 0;
}

static void report(const char *what) {
    if (fault("wrap_report")) {
        char line[64];
        int n = snprintf(line, sizeof(line), "wrapped: %s\n", what);
        if (n > 0 && __real_write(2, line, (size_t)n) < 0) return;
    }
}

static int is_regular(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
}

static int is_directory(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
}

ssize_t __wrap_getrandom(void *buf, size_t len, unsigned flags) {
    report("getrandom");
    if (fault("rand_fail")) {
        errno = ENOSYS;
        return -1;
    }
    if (fault("rand_zero")) return 0;
    if (fault("rand_short") && len > 1) return __real_getrandom(buf, 1, flags);
    if (fault("check_core")) {
        struct rlimit lim;
        if (getrlimit(RLIMIT_CORE, &lim) != 0 || lim.rlim_cur != 0 || lim.rlim_max != 0) {
            errno = EPERM;
            return -1;
        }
#ifdef __linux__
        if (prctl(PR_GET_DUMPABLE) != 0) {
            errno = EPERM;
            return -1;
        }
#endif
    }
    return __real_getrandom(buf, len, flags);
}

ssize_t __wrap_write(int fd, const void *buf, size_t len) {
    static int n;
    if (fd > 2 && is_regular(fd)) {
        report("write");
        n++;
        if (fault("die_in_write")) _exit(137);
        if (fault("write_enospc") || (fault("write_late") && n > 3)) {
            errno = ENOSPC;
            return -1;
        }
        if (fault("write_short") || fault("write_late"))
            return __real_write(fd, buf, len > 7 ? 7 : len);
        if (fault("write_eintr") && (n & 1)) {
            errno = EINTR;
            return -1;
        }
    }
    return __real_write(fd, buf, len);
}

ssize_t __wrap_read(int fd, void *buf, size_t len) {
    static int n;
    if (fd > 2 && is_regular(fd)) {
        report("read");
        n++;
        if (fault("read_short")) return __real_read(fd, buf, len > 5 ? 5 : len);
        if (fault("read_eintr") && (n & 1)) {
            errno = EINTR;
            return -1;
        }
    }
    return __real_read(fd, buf, len);
}

int __wrap_fsync(int fd) {
    report(is_directory(fd) ? "fsync-directory" : "fsync-file");
    if ((fault("fsync_file_fail") && is_regular(fd)) ||
        (fault("fsync_dir_fail") && is_directory(fd))) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

int __wrap_link(const char *from, const char *to) {
    report("link");
    if (fault("die_in_link")) _exit(137);
    if (fault("link_fail")) {
        errno = EPERM;
        return -1;
    }
    if (fault("race_create")) {
        /* Somebody else creates the file at the last moment. */
        int fd = __real_open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            if (__real_write(fd, "theirs\n", 7) < 0) _exit(99);
            close(fd);
        }
    }
    return __real_link(from, to);
}

int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        report("open-create");
        if (fault("check_create") &&
            (mode != 0600 || !(flags & O_EXCL) || !(flags & O_NOFOLLOW))) {
            errno = EACCES;
            return -1;
        }
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

uid_t __wrap_geteuid(void) {
    report("geteuid");
    if (fault("other_uid")) return __real_geteuid() + 1;
    return __real_geteuid();
}
