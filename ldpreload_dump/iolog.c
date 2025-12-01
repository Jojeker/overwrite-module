#define _GNU_SOURCE
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

static int log_fd = -1;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void hex_dump(const void *buf, size_t len) {
    const unsigned char *p = buf;
    char line[128];

    size_t offset = 0;
    while (offset < len) {
        size_t n = (len - offset > 16) ? 16 : (len - offset);

        int pos = snprintf(line, sizeof(line), "  %04zx: ", offset);
        for (size_t i = 0; i < n; i++)
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", p[offset + i]);

        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (size_t i = 0; i < n; i++) {
            unsigned char c = p[offset + i];
            line[pos++] = (c >= 32 && c <= 126) ? c : '.';
        }
        line[pos++] = '|';
        line[pos++] = '\n';
        line[pos] = 0;

        syscall(SYS_write, log_fd, line, pos);
        offset += n;
    }
}


/* Timestamp helper */
static void make_timestamp(char *buf, size_t len) {
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(buf, len, "%F %T", &tm);
}

/* Log using raw SYS_write (to avoid our own write() wrapper) */
static void log_msg(const char *fmt, ...) {
    if (log_fd < 0)
        return;

    char msg[512];
    char ts[32];
    make_timestamp(ts, sizeof(ts));

    va_list ap;
    va_start(ap, fmt);
    int n = snprintf(msg, sizeof(msg), "[%s pid=%d] ", ts, getpid());
    if (n < 0 || n >= (int)sizeof(msg)) {
        va_end(ap);
        return;
    }
    int m = vsnprintf(msg + n, sizeof(msg) - n, fmt, ap);
    va_end(ap);
    if (m < 0)
        return;

    int total = n + m;
    if (total > (int)sizeof(msg))
        total = sizeof(msg);

    int saved = errno;
    pthread_mutex_lock(&log_lock);
    syscall(SYS_write, log_fd, msg, total);
    pthread_mutex_unlock(&log_lock);
    errno = saved;
}

/* "Real" syscalls – we never call glibc open/read/write here, only the kernel */

static int real_open_sys(const char *pathname, int flags, mode_t mode) {
    /* On AArch64, open(2) is implemented via openat(2) */
    return syscall(SYS_openat, AT_FDCWD, pathname, flags, mode);
}

static ssize_t real_read_sys(int fd, void *buf, size_t count) {
    return syscall(SYS_read, fd, buf, count);
}

static ssize_t real_write_sys(int fd, const void *buf, size_t count) {
    return syscall(SYS_write, fd, buf, count);
}

static int real_close_sys(int fd) {
    return syscall(SYS_close, fd);
}

/* Constructor / destructor */

__attribute__((constructor))
static void iolog_init(void) {
    const char *path = getenv("IOLOG_FILE");
    if (!path || !*path)
        path = "/tmp/iolog.txt";

    /* Use syscall so we don't depend on glibc open() */
    log_fd = real_open_sys(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (log_fd >= 0) {
        log_msg("=== iolog preload initialized (logging to %s) ===\n", path);
    }
}

__attribute__((destructor))
static void iolog_fini(void) {
    if (log_fd >= 0) {
        log_msg("=== iolog preload finalized ===\n");
        real_close_sys(log_fd);
        log_fd = -1;
    }
}

/* Wrappers that intercept the libc symbols */

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    int fd = real_open_sys(pathname, flags, mode);
    if (fd >= 0 && fd != log_fd) {
        log_msg("open(\"%s\", 0x%x) = %d\n", pathname, flags, fd);
    }
    return fd;
}

/* For systems that still use open64; harmless if unused */
int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    int fd = real_open_sys(pathname, flags, mode);
    if (fd >= 0 && fd != log_fd) {
        log_msg("open64(\"%s\", 0x%x) = %d\n", pathname, flags, fd);
    }
    return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t ret = real_read_sys(fd, buf, count);

    if (fd != log_fd) {
        log_msg("read(fd=%d, count=%zu) = %zd\n", fd, count, ret);

        if (ret > 0) {
            size_t dump_len = ret;
            if (dump_len > 512)
                dump_len = 512;

            log_msg("read data (hex, %zu bytes shown):\n", dump_len);
            hex_dump(buf, dump_len);
        }
    }
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t ret = real_write_sys(fd, buf, count);

    if (fd != log_fd) {
        log_msg("write(fd=%d, count=%zu) = %zd\n", fd, count, ret);

        if (count > 0) {
            size_t dump_len = count;
            if (dump_len > 512)
                dump_len = 512;

            log_msg("write data (hex, %zu bytes shown):\n", dump_len);
            hex_dump(buf, dump_len);
        }
    }
    return ret;
}

int close(int fd) {

    if (fd == log_fd) {
        /* Prevent the program from closing our log file */
        log_msg("close(fd=%d) [IGNORED for logger]\n", fd);
        return 0; /* pretend success */
    }

    int ret = real_close_sys(fd);
    log_msg("close(fd=%d) = %d\n", fd, ret);

    return ret;
}

