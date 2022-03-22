/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * This file contains the APIs to expose host topology information.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>

#include "api.h"
#include "bitmap.h"
#include "pal_linux.h"
#include "syscall.h"
#include "topo_info.h"

/* Opens a pseudo-file describing HW resources and simply reads the value stored in the file.
 * Returns UNIX error code on failure and 0 on success. */
// static int get_hw_resource_value(const char* filename, size_t* out_value) {
//     assert(out_value);

//     char str[PAL_SYSFS_BUF_FILESZ];
//     int ret = read_file_buffer(filename, str, sizeof(str) - 1);
//     if (ret < 0)
//         return ret;

//     str[ret] = '\0'; /* ensure null-terminated buf even in partial read */

//     char* end;
//     long val = strtol(str, &end, 10);
//     if (val < 0)
//         return -EINVAL;

//     if (*end != '\n' && *end != '\0' && *end != 'K') {
//         /* Illegal character found */
//         return -EINVAL;
//     }

//     if (*end == 'K') {
//         if (__builtin_mul_overflow(val, 1024, &val))
//             return -EOVERFLOW;
//     }

//     *out_value = val;
//     return 0;
// }

static int read_numbers_from_file(const char* path, size_t* out_arr, size_t count) {
    char str[PAL_SYSFS_BUF_FILESZ];
    int ret = read_file_buffer(path, str, sizeof(str) - 1);
    if (ret < 0)
        return ret;
    str[ret] = '\0';

    char* inp_pos = str;
    char* end;
    for (size_t i = 0; i < count; i++) {
        long val = strtol(inp_pos, &end, 10);
        if (val < 0 || end == inp_pos)
            return -EINVAL;
        inp_pos = end;
        out_arr[i] = (size_t)val;
    }
    return 0;

}

// Not suitable for untrusted inputs! (due to overflows and liberal parsing)
static int iterate_ranges_from_file(const char* path, int (*callback)(size_t index, void* arg),
                                    void* callback_arg) {
    char buf[PAL_SYSFS_BUF_FILESZ];
    int ret = read_file_buffer(path, buf, sizeof(buf) - 1);
    if (ret < 0)
        return ret;
    buf[ret] = '\0';

    char* buf_it = buf;
    long prev = -1;
    while (*buf_it) {
        char* parse_end;
        long val = strtol(buf_it, &parse_end, 10);
        if (val < 0)
            return -EINVAL;

        if (parse_end == buf_it)
            break;
        buf_it = parse_end;

        if (*buf_it == ',' || *buf_it == '\n') {
            if (prev == -1) {
                // single index
                ret = callback(val, callback_arg);
                if (ret < 0)
                    return ret;
            } else {
                // range
                for (size_t i = prev; i <= (size_t)val; i++) {
                    ret = callback(i, callback_arg);
                    if (ret < 0)
                        return ret;
                }
            }
            prev = -1;
        } else if (*buf_it == '-') {
            // range start
            prev = val;
        } else {
            log_error("Invalid range format when parsing %s", path);
            return -EINVAL;
        }
        buf_it++;
    }
    return 0;
}

// ehh... time for macroized for loops maybe?

struct two_arg_call {
    int (*f)(size_t index, void* arg1, void* arg2);
    void* arg1;
    void* arg2;
};

struct three_arg_call {
    int (*f)(size_t index, void* arg1, void* arg2, void* arg3);
    void* arg1;
    void* arg2;
    void* arg3;
};

struct four_arg_call {
    int (*f)(size_t index, void* arg1, void* arg2, void* arg3, void* arg4);
    void* arg1;
    void* arg2;
    void* arg3;
    void* arg4;
};

static int do_two_arg_call(size_t index, void* _call) {
    struct two_arg_call* call = (struct two_arg_call*)_call;
    return call->f(index, call->arg1, call->arg2);
}

static int do_three_arg_call(size_t index, void* _call) {
    struct three_arg_call* call = (struct three_arg_call*)_call;
    return call->f(index, call->arg1, call->arg2, call->arg3);
}

static int do_four_arg_call(size_t index, void* _call) {
    struct four_arg_call* call = (struct four_arg_call*)_call;
    return call->f(index, call->arg1, call->arg2, call->arg3, call->arg4);
}

static int iterate_ranges_from_file2(const char* path,
                                     int (*callback)(size_t index, void* arg1, void* arg2),
                                     void* callback_arg1, void* callback_arg2) {
    struct two_arg_call call = {
        .f = callback,
        .arg1 = callback_arg1,
        .arg2 = callback_arg2,
    };
    return iterate_ranges_from_file(path, do_two_arg_call, &call);
}

static int iterate_ranges_from_file3(const char* path,
                                     int (*callback)(size_t index, void* arg1, void* arg2, void* arg3),
                                     void* callback_arg1, void* callback_arg2, void* callback_arg3) {
    struct three_arg_call call = {
        .f = callback,
        .arg1 = callback_arg1,
        .arg2 = callback_arg2,
        .arg3 = callback_arg3,
    };
    return iterate_ranges_from_file(path, do_three_arg_call, &call);
}

static int iterate_ranges_from_file4(const char* path,
                                     int (*callback)(size_t index, void* arg1, void* arg2, void* arg3, void* arg4),
                                     void* callback_arg1, void* callback_arg2, void* callback_arg3, void* callback_arg4) {
    struct four_arg_call call = {
        .f = callback,
        .arg1 = callback_arg1,
        .arg2 = callback_arg2,
        .arg3 = callback_arg3,
        .arg4 = callback_arg4,
    };
    return iterate_ranges_from_file(path, do_four_arg_call, &call);
}

ssize_t read_file_buffer(const char* filename, char* buf, size_t count) {
    int fd = DO_SYSCALL(open, filename, O_RDONLY);
    if (fd < 0)
        return fd;

    ssize_t ret = DO_SYSCALL(read, fd, buf, count);
    DO_SYSCALL(close, fd);
    if (ret < 0)
        return ret;

    return ret;
}

#define READ_FILE_BUFFER(filepath, buf, failure_label)                           \
    ({                                                                           \
        ret = read_file_buffer(filepath, buf, ARRAY_SIZE(buf)-1);                \
        if (ret < 0)                                                             \
            goto failure_label;                                                  \
        buf[ret] = '\0';                                                         \
    })

/* This function stores the number of cache levels present on the system by counting "indexX" dir
 * entries under `/sys/devices/system/cpu/cpuX/cache` in `out_cache_indices_cnt`. Returns 0 on
 * success and negative UNIX error code on failure. */
// static int get_cache_levels_cnt(const char* path, size_t* out_cache_indices_cnt) {
//     assert(out_cache_indices_cnt);

//     char buf[1024];
//     int ret;
//     size_t dirs_cnt = 0;

//     int fd = DO_SYSCALL(open, path, O_RDONLY | O_DIRECTORY);
//     if (fd < 0)
//         return fd;

//     while (true) {
//         int nread = DO_SYSCALL(getdents64, fd, buf, 1024);
//         if (nread < 0) {
//             ret = nread;
//             goto out;
//         }

//         if (nread == 0)
//             break;

//         for (int bpos = 0; bpos < nread;) {
//             struct linux_dirent64* dirent64 = (struct linux_dirent64*)(buf + bpos);
//             if (dirent64->d_type == DT_DIR && strstartswith(dirent64->d_name, "index"))
//                 dirs_cnt++;
//             bpos += dirent64->d_reclen;
//         }
//     }

//     if (!dirs_cnt) {
//         ret = -ENOENT;
//         goto out;
//     }

//     *out_cache_indices_cnt = dirs_cnt;
//     ret = 0;

// out:
//     DO_SYSCALL(close, fd);
//     return ret;
// }

// static int set_bit_in_bitmap(size_t pos, void* _bitmap) {
//     struct bitmap* bitmap = (struct bitmap*)_bitmap;
//     return bitmap_set(bitmap, pos);
// }

// static int get_cache_topo_info(size_t cache_indices_cnt, size_t core_idx,
//                                struct pal_core_cache_info** out_cache_info_arr) {
//     int ret;

//     struct pal_core_cache_info* cache_info_arr =
//         malloc(cache_indices_cnt * sizeof(*cache_info_arr));
//     if (!cache_info_arr) {
//         return -ENOMEM;
//     }

//     char dirname[PAL_SYSFS_PATH_SIZE];
//     char filename[PAL_SYSFS_PATH_SIZE];
//     for (size_t cache_idx = 0; cache_idx < cache_indices_cnt; cache_idx++) {
//         struct pal_core_cache_info* ci = &cache_info_arr[cache_idx];

//         ret = snprintf(dirname, sizeof(dirname), "/sys/devices/system/cpu/cpu%zu/cache/index%zu",
//                        core_idx, cache_idx);
//         if (ret < 0)
//             goto fail;

//         ret = snprintf(filename, sizeof(filename), "%s/shared_cpu_list", dirname);
//         if (ret < 0)
//             goto fail;

//         bitmap_init(&ci->shared_cpus);
//         ret = iterate_ranges_from_file(filename, set_bit_in_bitmap, &ci->shared_cpus);
//         if (ret < 0)
//             goto fail;

//         ret = snprintf(filename, sizeof(filename), "%s/level", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = get_hw_resource_value(filename, &ci->level);
//         if (ret < 0)
//             goto fail;

//         char type[PAL_SYSFS_BUF_FILESZ] = {'\0'};
//         ret = snprintf(filename, sizeof(filename), "%s/type", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = read_file_buffer(filename, type, sizeof(type) - 1);
//         if (ret < 0)
//             goto fail;
//         type[ret] = '\0';

//         if (!strcmp(type, "Unified\n")) {
//            ci->type = CACHE_TYPE_UNIFIED;
//         } else if (!strcmp(type, "Instruction\n")) {
//            ci->type = CACHE_TYPE_INSTRUCTION;
//         } else if (!strcmp(type, "Data\n")) {
//            ci->type = CACHE_TYPE_DATA;
//         } else {
//             ret = -EINVAL;
//             goto fail;
//         }

//         ret = snprintf(filename, sizeof(filename), "%s/size", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = get_hw_resource_value(filename, &ci->size);
//         if (ret < 0)
//             goto fail;

//         ret = snprintf(filename, sizeof(filename), "%s/coherency_line_size", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = get_hw_resource_value(filename, &ci->coherency_line_size);
//         if (ret < 0)
//             goto fail;

//         ret = snprintf(filename, sizeof(filename), "%s/number_of_sets", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = get_hw_resource_value(filename, &ci->number_of_sets);
//         if (ret < 0)
//             goto fail;

//         ret = snprintf(filename, sizeof(filename), "%s/physical_line_partition", dirname);
//         if (ret < 0)
//             goto fail;
//         ret = get_hw_resource_value(filename, &ci->physical_line_partition);
//         if (ret < 0)
//             goto fail;
//     }
//     *out_cache_info_arr = cache_info_arr;
//     return 0;

// fail:
//     free(cache_info_arr);
//     return ret;
// }

static int get_ranges_end(size_t ind, void* _arg) {
    *(size_t*)_arg = ind + 1;
    return 0;
}

static int set_thread_online(size_t ind, void* _threads) {
    struct pal_cpu_thread_info* threads = (struct pal_cpu_thread_info*)_threads;
    threads[ind].is_online = true;
    return 0;
}

static int set_numa_node_online(size_t ind, void* _numa_nodes) {
    struct pal_numa_node_info* numa_nodes = (struct pal_numa_node_info*)_numa_nodes;
    numa_nodes[ind].is_online = true;
    return 0;
}

static int set_core_id(size_t ind, void* _threads, void* _id) {
    struct pal_cpu_thread_info* threads = (struct pal_cpu_thread_info*)_threads;
    size_t id = *(size_t*)_id;
    threads[ind].core_id = id;
    return 0;
}

static int set_socket_id(size_t ind, void* _threads, void* _cores, void* _id) {
    struct pal_cpu_thread_info* threads = (struct pal_cpu_thread_info*)_threads;
    struct pal_cpu_core_info* cores = (struct pal_cpu_core_info*)_cores;
    size_t id = *(size_t*)_id;
    cores[threads[ind].core_id].socket_id = id;
    return 0;
}

static int set_node_id(size_t ind, void* _threads, void* _cores, void* _sockets, void* _id) {
    struct pal_cpu_thread_info* threads = (struct pal_cpu_thread_info*)_threads;
    struct pal_cpu_core_info* cores = (struct pal_cpu_core_info*)_cores;
    struct pal_socket_info* sockets = (struct pal_socket_info*)_sockets;
    size_t id = *(size_t*)_id;
    sockets[cores[threads[ind].core_id].socket_id].node_id = id;
    return 0;
}

int get_topology_info(struct pal_topo_info* topo_info) {
    size_t threads_cnt = 0;
    int ret = iterate_ranges_from_file("/sys/devices/system/cpu/possible", get_ranges_end, &threads_cnt);
    if (ret < 0)
        return ret;
    size_t nodes_cnt = 0;
    ret = iterate_ranges_from_file("/sys/devices/system/node/possible", get_ranges_end, &nodes_cnt);
    if (ret < 0)
        return ret;

    // ret = get_cache_levels_cnt("/sys/devices/system/cpu/cpu0/cache", &topo_info->cache_indices_cnt);
    // if (ret < 0)
    //     return ret;

    struct pal_cpu_thread_info* threads = malloc(threads_cnt * sizeof(*threads));
    size_t caches_cnt = 0;
    struct pal_cache_info* caches = malloc(threads_cnt * sizeof(*caches) * MAX_CACHES); // overapproximate the count
    size_t cores_cnt = 0;
    struct pal_cpu_core_info* cores = malloc(threads_cnt * sizeof(*cores)); // overapproximate the count
    size_t sockets_cnt = 0;
    struct pal_socket_info* sockets = malloc(threads_cnt * sizeof(*sockets)); // overapproximate the count
    struct pal_numa_node_info* numa_nodes = malloc(nodes_cnt * sizeof(*numa_nodes));
    size_t* distances = malloc(nodes_cnt * nodes_cnt * sizeof(*distances));
    if (!threads || !caches || !cores || !sockets || !numa_nodes || !distances) {
        ret = -ENOMEM;
        goto out;
    }

    for (size_t i = 0; i < threads_cnt; i++) {
        threads[i].is_online = false;
        threads[i].core_id = -1;
        cores[i].socket_id = -1;
        sockets[i].node_id = -1;
    }
    for (size_t i = 0; i < nodes_cnt; i++)
        numa_nodes[i].is_online = false;

    ret = iterate_ranges_from_file("/sys/devices/system/cpu/online", set_thread_online, threads);
    if (ret < 0)
        return ret;
    ret = iterate_ranges_from_file("/sys/devices/system/node/online", set_numa_node_online,
                                   numa_nodes);
    if (ret < 0)
        return ret;


    char path[PAL_SYSFS_PATH_SIZE];
    for (size_t i = 0; i < threads_cnt; i++) {
        if (!threads[i].is_online)
            /* no information is available for offline threads */
            continue;

        if (threads[i].core_id == (size_t)-1) {
            // insert new core to the list
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%zu/topology/thread_siblings_list", i); // includes ourselves
            ret = iterate_ranges_from_file2(path, set_core_id, threads, &cores_cnt);
            if (ret < 0)
                goto out;
            cores_cnt++;
        }
    }

    for (size_t i = 0; i < threads_cnt; i++) {
        if (!threads[i].is_online)
            continue;

        size_t core_id = threads[i].core_id;
        if (cores[core_id].socket_id == (size_t)-1) {
            // insert new socket to the list
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%zu/topology/core_siblings_list", i);
            ret = iterate_ranges_from_file3(path, set_socket_id, threads, cores, &sockets_cnt);
            if (ret < 0)
                goto out;
            sockets_cnt++;
        }
    }

    for (size_t i = 0; i < nodes_cnt; i++) {
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%zu/cpulist", i);
        ret = iterate_ranges_from_file4(path, set_node_id, threads, cores, sockets, &i);
        if (ret < 0)
            goto out;

        ret = snprintf(path, sizeof(path), "/sys/devices/system/node/node%zu/distance", i);
        if (ret < 0)
            goto out;
        ret = read_numbers_from_file(path, distances + i * nodes_cnt, nodes_cnt);
        if (ret < 0)
            goto out;

        /* Since our sysfs doesn't support writes, set persistent hugepages to their default value
         * of zero */
        numa_nodes[i].nr_hugepages[HUGEPAGES_2M] = 0;
        numa_nodes[i].nr_hugepages[HUGEPAGES_1G] = 0;
        // TODO: where are the others set?
    }

    size_t (*thread_to_cache)[MAX_CACHES];
    for (size_t i = 0; i < threads_cnt; i++) {
        if (!threads[i].is_online)
            continue;

        for (size_t lvl = 0; lvl < MAX_CACHES; lvl++) {
            size_t core_id = threads[i].core_id;
            if (cores[core_id].socket_id == (size_t)-1) {
                // insert new cache to the list
                snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%zu/topology/core_siblings_list", i);
                ret = iterate_ranges_from_file3(path, set_socket_id, threads, cores, &sockets_cnt);
                if (ret < 0)
                    goto out;
                caches_cnt++;
            }
        }
    }    

    // ret = get_cache_topo_info(topo_info->cache_indices_cnt, i,
    //                           &threads[i].cache_info_arr);
    // if (ret < 0)
    //     goto out;

    /* TODO: add realloc to save memory after we know the final sizes of all the buffers (after we
     * implement realloc()). */

    topo_info->caches_cnt     = caches_cnt;
    topo_info->threads_cnt    = threads_cnt;
    topo_info->cores_cnt      = cores_cnt;
    topo_info->sockets_cnt    = sockets_cnt;
    topo_info->numa_nodes_cnt = nodes_cnt;
    topo_info->caches               = caches;
    topo_info->threads              = threads;
    topo_info->cores                = cores;
    topo_info->sockets              = sockets;
    topo_info->numa_nodes           = numa_nodes;
    topo_info->numa_distance_matrix = distances;
    return 0;

out:
    free(caches);
    free(threads);
    free(cores);
    free(sockets);
    free(numa_nodes);
    free(distances);
    return ret;
}
