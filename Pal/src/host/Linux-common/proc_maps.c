#include <asm/errno.h>
#include <asm/fcntl.h>
#include <linux/limits.h>

#include "api.h"
#include "linux_utils.h"
#include "log.h"
#include "syscall.h"

#define LINE_BUF_SIZE (PATH_MAX + 128)

static int parse_proc_maps_line(const char* line, proc_maps_callback_t callback, void* arg) {
    uintptr_t start, end;
    size_t offset;
    const char* name;

    const char* next = line;

#define PARSE_NUMBER(base)                               \
    ({                                                   \
        unsigned long val;                               \
        if (str_to_ulong(next, (base), &val, &next) < 0) \
            return -EINVAL;                              \
        val;                                             \
    })

#define SKIP_CHAR(c)        \
    do {                    \
        if (*next != (c))   \
            return -EINVAL; \
        next++;             \
    } while(0)

#define SKIP_FIELD()                        \
    do {                                    \
        next++;                             \
    } while (*next != '\0' && *next != ' ')

    /* address */
    start = PARSE_NUMBER(16);
    SKIP_CHAR('-');
    end = PARSE_NUMBER(16);

    /* perms */
    SKIP_CHAR(' ');
    SKIP_FIELD();

    /* offset */
    SKIP_CHAR(' ');
    offset = PARSE_NUMBER(16);

    /* dev */
    SKIP_CHAR(' ');
    SKIP_FIELD();

    /* inode */
    SKIP_CHAR(' ');
    SKIP_FIELD();

    /* pathname */
    while (*next == ' ')
        next++;

    if (*next == '\0') {
        name = NULL;
    } else {
        name = next;
    }

#undef PARSE_NUMBER
#undef SKIP_CHAR
#undef SKIP_FIELD

    return callback(start, end, offset, name, arg);
}

int parse_proc_maps(proc_maps_callback_t callback, void* arg) {
    int ret;

    int fd = DO_SYSCALL(open, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0)
        return fd;

    char* buf = malloc(LINE_BUF_SIZE);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    size_t len = 0;
    bool eof = false;
    while (!eof) {
        ssize_t n = DO_SYSCALL(read, fd, &buf[len], LINE_BUF_SIZE - 1 - len);
        if (n == -EINTR) {
            continue;
        } else if (n < 0) {
            ret = n;
            goto out;
        }
        len += n;
        eof = (n == 0);

        char* line_end;
        while ((line_end = memchr(buf, '\n', len)) != NULL) {
            size_t line_len = line_end - buf;
            buf[line_len] = '\0';
            ret = parse_proc_maps_line(buf, callback, arg);
            if (ret < 0)
                goto out;
            memmove(buf, &buf[line_len + 1], len - line_len - 1);
            len = len - line_len - 1;
        }
        if (len == LINE_BUF_SIZE - 1) {
            log_error("%s: line too long", __func__);
            ret = -EINVAL;
            goto out;
        }
    }
    if (len > 0) {
        log_error("%s: file doesn't end with newline", __func__);
        ret = -EINVAL;
        goto out;
    }
    ret = 0;

out:
    free(buf);
    int close_ret = DO_SYSCALL(close, fd);
    if (close_ret < 0) {
        log_error("%s: close() failed", __func__);
        return close_ret;
    }
    return ret;
}
