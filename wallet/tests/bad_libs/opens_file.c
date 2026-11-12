/* Negative test for check_no_io.py: a "library" that creates and writes a file. */
#include <fcntl.h>
#include <unistd.h>

int gzw_bad_opens_file(const char *path);
int gzw_bad_opens_file(const char *path) {
    int fd = openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 0;
    if (pwrite(fd, "x", 1, 0) < 0) {
        close(fd);
        return 0;
    }
    return close(fd) == 0;
}
