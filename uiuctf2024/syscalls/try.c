#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>

int main() {
    const char *filename = "flag.txt";
    int fd = openat(-100, filename, 0);

    char *buffer[4096];
    struct iovec iov[1];
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);

    ssize_t bytes_read = preadv2(fd, iov, 1, 1, 0);

    ssize_t bytes_written = pwritev2(1, iov, 1, -1, 0);

    return 0;
}
