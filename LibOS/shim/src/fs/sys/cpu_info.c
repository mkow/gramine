/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/cpu` and its sub-directories
 * (except for `cache`, which is implemented in cache_info.c).
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

static bool is_online(size_t ind, const void* _topo_info) {
    struct pal_topo_info* topo_info = (struct pal_topo_info*)_topo_info;
    return topo_info->threads[ind].is_online;
}

static bool return_true(size_t ind, const void* arg) {
    __UNUSED(ind);
    __UNUSED(arg);
    return true;
}

int sys_cpu_general_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    const struct pal_topo_info* topo_info = &g_pal_public_state->topo_info;
    const char* name = dent->name;
    char str[PAL_SYSFS_BUF_FILESZ];

    if (strcmp(name, "online") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->threads_cnt, is_online, topo_info);
    } else if (strcmp(name, "possible") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->threads_cnt, return_true, NULL);
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

static bool is_in_same_core(size_t pos, const void* _arg) {
    size_t arg_id = *(const size_t*)_arg;
    return g_pal_public_state->topo_info.cores[pos].socket_id == arg_id;
}

static bool is_in_same_socket(size_t pos, const void* _arg) {
    size_t arg_id = *(const size_t*)_arg;
    return g_pal_public_state->topo_info.threads[pos].core_id == arg_id;
}

int sys_cpu_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int thread_num;
    ret = sys_resource_find(dent, "cpu", &thread_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    struct pal_topo_info* topo_info = &g_pal_public_state->topo_info;
    struct pal_cpu_thread_info* thread_info = &topo_info->threads[thread_num];
    struct pal_cpu_core_info*   core_info   = &topo_info->cores[thread_info->core_id];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "online") == 0) {
        /* `cpu/cpuX/online` is not present for cpu0 */
        if (thread_num == 0)
            return -ENOENT;
        ret = snprintf(str, sizeof(str), "%d\n", (int)thread_info->is_online);
    } else if (strcmp(name, "core_id") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", thread_info->core_id);
    } else if (strcmp(name, "physical_package_id") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", core_info->socket_id);
    } else if (strcmp(name, "thread_siblings") == 0) {
        ret = sys_print_as_bitmask(str, sizeof(str), topo_info->threads_cnt, is_in_same_core,
                                   &thread_info->core_id);
    } else if (strcmp(name, "core_siblings") == 0) {
        ret = sys_print_as_bitmask(str, sizeof(str), topo_info->cores_cnt, is_in_same_socket,
                                   &core_info->socket_id);
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

bool sys_cpu_online_name_exists(struct shim_dentry* parent, const char* name) {
    if (strcmp(name, "online") != 0)
        return false;

    int ret;
    unsigned int thread_num;
    ret = sys_resource_find(parent, "cpu", &thread_num);
    if (ret < 0)
        return false;

    return thread_num != 0;
}

int sys_cpu_online_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    int ret;
    unsigned int thread_num;
    ret = sys_resource_find(parent, "cpu", &thread_num);
    if (ret < 0)
        return ret;

    if (thread_num != 0) {
        ret = callback("online", arg);
        if (ret < 0)
            return ret;
    }

    return 0;
}
