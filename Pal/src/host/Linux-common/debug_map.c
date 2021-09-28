/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <asm/errno.h>

#include "api.h"
#include "debug_map.h"
#include "linux_utils.h"
#include "pal_linux.h"
#include "spinlock.h"

struct debug_map* _Atomic g_debug_map = NULL;

/* Lock for modifying g_debug_map on our end. Even though the list can be read at any
 * time, we need to prevent concurrent modification. */
static spinlock_t g_debug_map_lock = INIT_SPINLOCK_UNLOCKED;

static struct debug_map* debug_map_new(const char* name, void* addr) {
    struct debug_map* map;

    if (!(map = malloc(sizeof(*map))))
        return NULL;

    if (!(map->name = strdup(name))) {
        free(map);
        return NULL;
    }

    map->addr = addr;
    map->next = NULL;
    return map;
}

/* This function is hooked by our gdb integration script and should be left as is. */
__attribute__((__noinline__)) void debug_map_update_debugger(void) {
    __asm__ volatile(""); // Required in addition to __noinline__ to prevent deleting this function.
                          // See GCC docs.
}

int debug_map_add(const char* name, void* addr) {
    struct debug_map* map = debug_map_new(name, addr);
    if (!map)
        return -ENOMEM;

    spinlock_lock(&g_debug_map_lock);

    map->next = g_debug_map;
    g_debug_map = map;

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    return 0;
}

int debug_map_remove(void* addr) {
    spinlock_lock(&g_debug_map_lock);

    struct debug_map* prev = NULL;
    struct debug_map* map = g_debug_map;
    while (map) {
        if (map->addr == addr)
            break;
        prev = map;
        map = map->next;
    }
    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return -EINVAL;
    }
    if (prev) {
        prev->next = map->next;
    } else {
        g_debug_map = map->next;
    }

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    free(map->name);
    free(map);

    return 0;
}

/* Search for a debug map the address belongs to. We don't store map sizes, so this searches for the
 * closest one. */
static int debug_map_find(void* addr, char** out_name, uintptr_t* out_offset) {
    int ret;

    spinlock_lock(&g_debug_map_lock);

    const char* best_name = NULL;
    void* best_addr = NULL;
    struct debug_map* map = g_debug_map;
    while (map) {
        if ((uintptr_t)map->addr <= (uintptr_t)addr && (uintptr_t)map->addr > (uintptr_t)best_addr) {
            best_name = map->name;
            best_addr = map->addr;
        }
        map = map->next;
    }

    if (!best_name) {
        ret = -ENOENT;
        goto out;
    }

    char* name = strdup(best_name);
    if (!name) {
        ret = -ENOMEM;
        goto out;
    }

    *out_name = name;
    *out_offset = (uintptr_t)addr - (uintptr_t)best_addr;
    ret = 0;

out:
    spinlock_unlock(&g_debug_map_lock);
    return ret;
}

/* Example output: "func_name at source_file.c:123" */
static int run_addr2line(const char* name, uintptr_t offset, char* buf, size_t buf_size) {
    char addr_buf[20];
    snprintf(addr_buf, sizeof(addr_buf), "0x%lx", offset);

    const char* argv[] = {
        "/usr/bin/addr2line",
        "--exe", name,
        "--functions",
        "--basename",
        "--pretty-print",
        addr_buf,
        NULL,
    };

    size_t len;
    int ret = run_command(argv[0], argv, buf, buf_size - 1, &len);
    if (ret < 0)
        return ret;

    buf[len] = '\0';

    /* Strip trailing newline */
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

struct proc_maps_find_data {
    uintptr_t addr;
    char* name;
    uintptr_t offset;
};

static int proc_maps_find_callback(uintptr_t start, uintptr_t end, size_t offset, const char* name,
                                   void* arg) {
    struct proc_maps_find_data* data = arg;

    /* address not in range */
    if (!(start <= data->addr && data->addr < end))
        return 0;

    /* not a file */
    if (!name)
        return 0;

    /* [vvar], [vdso] etc. */
    if (name[0] == '[')
        return 0;

    /* /dev/sgx etc. */
    if (strstartswith(name, "/dev/"))
        return 0;

    data->name = strdup(name);
    if (!name)
        return -ENOMEM;
    data->offset = data->addr - start + offset;
    return 0;
}

/* Example output: "func_name at source_file.c:123, libpal.so+0x456" */
int debug_describe_location(void* addr, char* buf, size_t buf_size) {
    int ret;

    char* name;
    uintptr_t offset;

    /* First, look for a mapped file in `/proc/self/maps`. This is necessary for files mapped by the
     * system (e.g. PAL in direct mode), because we don't add the to debug maps. */
    struct proc_maps_find_data data = {
        .addr = (uintptr_t)addr,
        .name = NULL,
        .offset = 0,
    };
    ret = parse_proc_maps(&proc_maps_find_callback, &data);
    if (ret == 0 && data.name) {
        name = data.name;
        offset = data.offset;
    } else {
        /* We haven't found the file in `/proc/self/maps`. Look in our debug maps. */
        ret = debug_map_find(addr, &name, &offset);
        if (ret < 0)
            return ret;
    }

    const char* basename = name;
    for (const char* s = name; *s != '\0'; s++) {
        if (*s == '/')
            basename = s + 1;
    }

    ret = run_addr2line(name, offset, buf, buf_size);
    if (ret < 0 || buf[0] == '\0') {
        /* addr2line failed, display just name and offset */
        snprintf(buf, buf_size, "%s+0x%lx", basename, offset);
    } else {
        size_t len = strlen(buf);
        snprintf(&buf[len], buf_size - len, ", %s+0x%lx", basename, offset);
    }

    free(name);
    return 0;
}
