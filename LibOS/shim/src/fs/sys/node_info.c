/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include <stdbool.h>

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

static bool is_online(size_t ind, const void* _topo_info) {
    struct pal_topo_info* topo_info = (struct pal_topo_info*)_topo_info;
    return topo_info->numa_topo_arr[ind].is_online;
}

static bool return_true(size_t ind, const void* arg) {
    __UNUSED(ind);
    __UNUSED(arg);
    return true;
}

int sys_node_general_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    const struct pal_topo_info* topo_info = &g_pal_public_state->topo_info;
    const char* name = dent->name;
    char str[PAL_SYSFS_BUF_FILESZ];
    if (strcmp(name, "online") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->nodes_cnt, is_online, topo_info);
    } else if (strcmp(name, "possible") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->nodes_cnt, return_true, NULL);
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

int sys_node_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int node_ind;
    ret = sys_resource_find(dent, "node", &node_ind);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    const struct pal_topo_info* topo_info = &g_pal_public_state->topo_info;
    const struct pal_numa_node_info* numa_topo = &topo_info->numa_topo_arr[node_ind];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "cpumap") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&numa_topo->cpumap, str, sizeof(str));
    } else if (strcmp(name, "distance") == 0) {
        size_t* distances = topo_info->numa_distance_matrix + node_ind * topo_info->nodes_cnt;
        size_t str_pos = 0;
        for (size_t i = 0; i < topo_info->nodes_cnt; i++) {
            ret = snprintf(str + str_pos, sizeof(str) - str_pos,
                           "%zu%s", distances[i], i != (topo_info->nodes_cnt - 1) ? " " : "\n");
            if (ret < 0)
                return ret;
            if ((size_t)ret >= sizeof(str) - str_pos)
                return -EOVERFLOW;
            str_pos += ret;
        }
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = dent->parent->name;
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_topo->nr_hugepages[HUGEPAGES_2M]);
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            ret = snprintf(str, sizeof(str), "%zu\n", numa_topo->nr_hugepages[HUGEPAGES_1G]);
        } else {
            log_debug("unrecognized hugepage file: %s", parent_name);
            ret = -ENOENT;
        }
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}
