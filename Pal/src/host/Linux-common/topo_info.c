/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the APIs to expose host topology information.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <limits.h>

#include "api.h"
#include "pal_linux.h"
#include "syscall.h"
#include "topo_info.h"

/* Opens a pseudo-file describing HW resources and simply reads the value stored in the file.
 * Returns UNIX error code on failure and 0 on success. */
static int get_hw_resource_value(const char* filename, size_t* retval) {
    assert(retval);

    char str[PAL_SYSFS_BUF_FILESZ];
    int ret = read_file_buffer(filename, str, sizeof(str) - 1);
    if (ret < 0)
        return ret;

    str[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* end;
    long val = strtol(str, &end, 10);
    if (val < 0 || val > INT_MAX)
        return -ENOENT;

    if (*end != '\n' && *end != '\0' && *end != 'K') {
        /* Illegal character found */
        return -EINVAL;
    }

    if (*end == 'K') {
        ret = __builtin_mul_overflow(val, 1024, &val);
        if (ret < 0)
            return -EINVAL;

        /* Ensure the size hasn't exceed max threshold after multiplying by size qualifier */
        if (val > INT_MAX)
            return -EINVAL;
    }

    *retval = val;
    return 0;
}

/* Opens a pseudo-file describing HW resources such as online CPUs and counts the number of
 * HW resources and their ranges present in the file. The result is stored in `res_info`.
 * Returns UNIX error code on failure and 0 on success.
 * N.B: Understands complex formats like "1,3-5,6".
 */
static int get_hw_resource_range(const char* filename, struct pal_res_range_info* res_info) {
    assert(res_info);

    /* Clear user supplied buffer */
    res_info->resource_cnt = 0;
    res_info->range_cnt = 0;
    res_info->ranges_arr = NULL;

    char str[PAL_SYSFS_BUF_FILESZ];
    int ret = read_file_buffer(filename, str, sizeof(str) - 1);
    if (ret < 0)
        return ret;

    str[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* ptr = str;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        char* end;
        long start_val = strtol(ptr, &end, 10);
        if (start_val < 0 || start_val > INT_MAX) {
            ret = -ENOENT;
            goto fail;
        }

        if (ptr == end)
            break;

        size_t range_start;
        size_t range_end;

        if (*end == '\0' || *end == ',' || *end == '\n' || *end == ' ') {
            range_start = start_val;
            range_end = start_val;
            res_info->resource_cnt++;
        } else if (*end == '-') {
            ptr = end + 1;
            long end_val = strtol(ptr, &end, 10);
            if (end_val < 0 || end_val > INT_MAX || end_val < start_val) {
                ret = -EINVAL;
                goto fail;
            }

            range_start = start_val;
            range_end = end_val;

            size_t diff = end_val - start_val;
            size_t total_cnt;
            if (__builtin_add_overflow(res_info->resource_cnt, diff, &total_cnt) ||
                                       total_cnt >= INT_MAX) {
                ret = -EINVAL;
                goto fail;
            }
            res_info->resource_cnt += diff + 1; /* +1 because of inclusive range */
        } else {
            /* Illegal character found */
            ret = -EINVAL;
            goto fail;
        }

        /* Update range info */
        res_info->range_cnt++;

        /* Realloc the array of ranges (expand by one range) */
        size_t new_size = sizeof(struct pal_range_info) * res_info->range_cnt;
        size_t old_size = new_size - sizeof(struct pal_range_info);
        struct pal_range_info* tmp = malloc(new_size);
        if (!tmp) {
            ret = -ENOMEM;
            goto fail;
        }

        if (res_info->ranges_arr) {
            memcpy(tmp, res_info->ranges_arr, old_size);
            free(res_info->ranges_arr);
        }
        res_info->ranges_arr = tmp;
        res_info->ranges_arr[res_info->range_cnt - 1].start = range_start;
        res_info->ranges_arr[res_info->range_cnt - 1].end = range_end;

        ptr = end;
    }

    if (!res_info->resource_cnt || !res_info->range_cnt) {
        ret = -EINVAL;
        goto fail;
    }

    return 0;

fail:
    if (res_info->ranges_arr)
        free(res_info->ranges_arr);

    res_info->resource_cnt = 0;
    res_info->range_cnt = 0;
    res_info->ranges_arr = NULL;

    return ret;
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

/* Returns number of cache levels present on this system by counting "indexX" dir entries under
 * `/sys/devices/system/cpu/cpuX/cache` on success and negative UNIX error code on failure. */
static int get_cache_levels_cnt(const char* path, size_t* cache_indices_cnt) {
    assert(cache_indices_cnt);

    char buf[1024];
    int ret;
    int dirs_cnt = 0;

    int fd = DO_SYSCALL(open, path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return fd;

    while (true) {
        int nread = DO_SYSCALL(getdents64, fd, buf, 1024);
        if (nread < 0) {
            ret = nread;
            goto out;
        }

        if (nread == 0)
            break;

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64* dirent64 = (struct linux_dirent64*)(buf + bpos);
            if (dirent64->d_type == DT_DIR && strstartswith(dirent64->d_name, "index"))
                dirs_cnt++;
            bpos += dirent64->d_reclen;
        }
    }

    if (!dirs_cnt) {
        ret = -ENOENT;
        goto out;
    }

    *cache_indices_cnt = dirs_cnt;
    ret = 0;

out:
    DO_SYSCALL(close, fd);
    return ret;
}

static int get_cache_topo_info(size_t cache_indices_cnt, size_t core_idx,
                               struct pal_core_cache_info** out_cache_info_arr) {
    int ret;

    struct pal_core_cache_info* cache_info_arr =
        malloc(cache_indices_cnt * sizeof(*cache_info_arr));
    if (!cache_info_arr) {
        return -ENOMEM;
    }

    char dirname[PAL_SYSFS_PATH_LEN];
    char filename[PAL_SYSFS_PATH_LEN];
    for (size_t cache_idx = 0; cache_idx < cache_indices_cnt; cache_idx++) {
        snprintf(dirname, sizeof(dirname), "/sys/devices/system/cpu/cpu%zu/cache/index%zu",
                 core_idx, cache_idx);

        snprintf(filename, sizeof(filename), "%s/shared_cpu_list", dirname);
        ret = get_hw_resource_range(filename, &cache_info_arr[cache_idx].shared_cpu_map);
        if (ret < 0)
            goto fail;

        snprintf(filename, sizeof(filename), "%s/level", dirname);
        ret = get_hw_resource_value(filename, &cache_info_arr[cache_idx].level);
        if (ret < 0)
            goto fail;

        char type[PAL_SYSFS_BUF_FILESZ] = {'\0'};
        snprintf(filename, sizeof(filename), "%s/type", dirname);
        ret = read_file_buffer(filename, type, sizeof(type) - 1);
        if (ret < 0)
            goto fail;
        type[ret] = '\0';

        if (!strcmp(type, "Unified\n")) {
            cache_info_arr[cache_idx].type = CACHE_TYPE_UNIFIED;
        } else if (!strcmp(type, "Instruction\n")) {
            cache_info_arr[cache_idx].type = CACHE_TYPE_INSTRUCTION;
        } else if (!strcmp(type, "Data\n")) {
            cache_info_arr[cache_idx].type = CACHE_TYPE_DATA;
        } else {
            ret = -EINVAL;
            goto fail;
        }

        snprintf(filename, sizeof(filename), "%s/size", dirname);
        ret = get_hw_resource_value(filename, &cache_info_arr[cache_idx].size);
        if (ret < 0)
            goto fail;

        snprintf(filename, sizeof(filename), "%s/coherency_line_size", dirname);
        ret = get_hw_resource_value(filename, &cache_info_arr[cache_idx].coherency_line_size);
        if (ret < 0)
            goto fail;

        snprintf(filename, sizeof(filename), "%s/number_of_sets", dirname);
        ret = get_hw_resource_value(filename, &cache_info_arr[cache_idx].number_of_sets);
        if (ret < 0)
            goto fail;

        snprintf(filename, sizeof(filename), "%s/physical_line_partition", dirname);
        ret = get_hw_resource_value(filename, &cache_info_arr[cache_idx].physical_line_partition);
        if (ret < 0)
            goto fail;
    }
    *out_cache_info_arr = cache_info_arr;
    return 0;

fail:
    free(cache_info_arr);
    return ret;
}

/* Get core topology-related info */
static int get_core_topo_info(struct pal_topo_info* topo_info) {
    int ret = get_hw_resource_range("/sys/devices/system/cpu/online",
                                    &topo_info->online_logical_cores);
    if (ret < 0)
        return ret;

    ret = get_hw_resource_range("/sys/devices/system/cpu/possible",
                                &topo_info->possible_logical_cores);
    if (ret < 0)
        return ret;

    if (topo_info->online_logical_cores.resource_cnt > INT32_MAX)
        return -EINVAL;
    size_t online_logical_cores_cnt = topo_info->online_logical_cores.resource_cnt;

    if (topo_info->possible_logical_cores.resource_cnt > INT32_MAX)
        return -EINVAL;
    size_t possible_logical_cores_cnt = topo_info->possible_logical_cores.resource_cnt;

    /* TODO: correctly support offline cores */
    if (possible_logical_cores_cnt > online_logical_cores_cnt) {
        log_error("Some CPUs seem to be offline; Gramine currently doesn't support core offlining");
        return -EINVAL;
    }

    ret = get_cache_levels_cnt("/sys/devices/system/cpu/cpu0/cache", &topo_info->cache_indices_cnt);
    if (ret < 0)
        return ret;

    struct pal_core_topo_info* core_topology_arr =
        malloc(online_logical_cores_cnt * sizeof(*core_topology_arr));
    if (!core_topology_arr)
        return -ENOMEM;

    size_t current_max_socket = 0;
    char dirname[PAL_SYSFS_PATH_LEN];
    char filename[PAL_SYSFS_PATH_LEN];
    for (size_t idx = 0; idx < online_logical_cores_cnt; idx++) {
        snprintf(dirname, sizeof(dirname), "/sys/devices/system/cpu/cpu%zu", idx);

        /* cpu0 is always online and thus the "online" file is not present. */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "%s/online", dirname);
            ret = get_hw_resource_value(filename, &core_topology_arr[idx].is_logical_core_online);
            if (ret < 0)
                goto out;
        }

        snprintf(filename, sizeof(filename), "%s/topology/core_id", dirname);
        ret = get_hw_resource_value(filename, &core_topology_arr[idx].core_id);
        if (ret < 0)
            goto out;

        snprintf(filename, sizeof(filename), "%s/topology/core_siblings_list", dirname);
        ret = get_hw_resource_range(filename, &core_topology_arr[idx].core_siblings);
        if (ret < 0)
            goto out;

        snprintf(filename, sizeof(filename), "%s/topology/thread_siblings_list", dirname);
        ret = get_hw_resource_range(filename, &core_topology_arr[idx].thread_siblings);
        if (ret < 0)
            goto out;

        snprintf(filename, sizeof(filename), "%s/topology/physical_package_id", dirname);
        ret = get_hw_resource_value(filename, &core_topology_arr[idx].socket_id);
        if (ret < 0)
            goto out;

        if (core_topology_arr[idx].socket_id > current_max_socket)
            current_max_socket = core_topology_arr[idx].socket_id;

        ret = get_cache_topo_info(topo_info->cache_indices_cnt, idx,
                                  &core_topology_arr[idx].cache_info_arr);
        if (ret < 0)
            goto out;
    }

    topo_info->core_topology_arr = core_topology_arr;
    topo_info->sockets_cnt = current_max_socket + 1;
    topo_info->physical_cores_per_socket = core_topology_arr[0].core_siblings.resource_cnt /
                                           core_topology_arr[0].thread_siblings.resource_cnt;
    return 0;

out:
    free(core_topology_arr);
    return ret;
}

/* Get NUMA topology-related info */
static int get_numa_topo_info(struct pal_topo_info* topo_info) {
    int ret = get_hw_resource_range("/sys/devices/system/node/online", &topo_info->online_nodes);
    if (ret < 0)
        return ret;
    size_t online_nodes_cnt = topo_info->online_nodes.resource_cnt;

    struct pal_numa_topo_info* numa_topology_arr =
        malloc(online_nodes_cnt * sizeof(*numa_topology_arr));
    if (!numa_topology_arr)
        return -ENOMEM;

    char filename[PAL_SYSFS_PATH_LEN];
    for (size_t idx = 0; idx < online_nodes_cnt; idx++) {
        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%zu/cpulist", idx);
        ret = get_hw_resource_range(filename, &numa_topology_arr[idx].cpumap);
        if (ret < 0)
            goto out;

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%zu/distance", idx);
        ret = get_hw_resource_range(filename, &numa_topology_arr[idx].distance);
        if (ret < 0)
            goto out;

        /* Since our /sys fs doesn't support writes, set persistent hugepages to their default value
         * of zero */
        numa_topology_arr[idx].nr_hugepages[HUGEPAGES_2M] = 0;
        numa_topology_arr[idx].nr_hugepages[HUGEPAGES_1G] = 0;
    }
    topo_info->numa_topology_arr = numa_topology_arr;
    return 0;

out:
    free(numa_topology_arr);
    return ret;
}

int get_topology_info(struct pal_topo_info* topo_info) {
    /* Get CPU topology information */
    int ret = get_core_topo_info(topo_info);
    if (ret < 0)
        return ret;

    /* Get NUMA topology information */
    ret = get_numa_topo_info(topo_info);
    if (ret < 0)
        return ret;

    return 0;
}
