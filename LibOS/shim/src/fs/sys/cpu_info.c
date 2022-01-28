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
    return topo_info->cores[ind].is_online;
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
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->cores_cnt, is_online, topo_info);
    } else if (strcmp(name, "possible") == 0) {
        ret = sys_print_as_ranges(str, sizeof(str), topo_info->cores_cnt, return_true, NULL);
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

int sys_cpu_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int cpu_num;
    ret = sys_resource_find(dent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    struct pal_core_info* core_info = &g_pal_public_state->topo_info.cores[cpu_num];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "online") == 0) {
        /* `cpu/cpuX/online` is not present for cpu0 */
        if (cpu_num == 0)
            return -ENOENT;
        ret = snprintf(str, sizeof(str), "%d\n", (int)core_info->is_online);
    } else if (strcmp(name, "core_id") == 0) {
        /* Linux docs: "the CPU core ID of cpuX. Typically it is the hardware platform’s identifier
         * (rather than the kernel’s). The actual value is architecture and platform dependent."
         * So, let's just output the kernel ID instead and everything should be fine.
         *
         * TODO: can this trash hyper-threading-aware scheduling? or rather the libraries use
         * *_siblings fields?
         */
        ret = snprintf(str, sizeof(str), "%u\n", cpu_num);
    } else if (strcmp(name, "physical_package_id") == 0) {
        ret = snprintf(str, sizeof(str), "%zu\n", core_info->socket_id);
    } else if (strcmp(name, "core_siblings") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&core_info->core_siblings, str, sizeof(str));
    } else if (strcmp(name, "thread_siblings") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&core_info->thread_siblings, str, sizeof(str));
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
    unsigned int cpu_num;
    ret = sys_resource_find(parent, "cpu", &cpu_num);
    if (ret < 0)
        return false;

    return cpu_num != 0;
}

int sys_cpu_online_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    int ret;
    unsigned int cpu_num;
    ret = sys_resource_find(parent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    if (cpu_num != 0) {
        ret = callback("online", arg);
        if (ret < 0)
            return ret;
    }

    return 0;
}
