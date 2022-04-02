/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_print_as_ranges(char* buf, size_t buf_size, size_t count,
                        bool (*is_present)(size_t ind, const void* arg), const void* callback_arg) {
    size_t buf_pos = 0;
    const char* sep = "";
    for (size_t i = 0; i < count;) {
        while (i < count && !is_present(i, callback_arg))
            i++;
        size_t range_start = i;
        while (i < count && is_present(i, callback_arg))
            i++;
        size_t range_end = i; // exclusive

        if (range_start == range_end)
            break;
        int ret;
        if (range_start + 1 == range_end) {
            ret = snprintf(buf + buf_pos, buf_size - buf_pos, "%s%zu", sep, range_start);
        } else {
            ret = snprintf(buf + buf_pos, buf_size - buf_pos, "%s%zu-%zu", sep, range_start,
                           range_end - 1);
        }
        sep = ",";
        if (ret < 0)
            return ret;
        if ((size_t)ret >= buf_size - buf_pos)
            return -EOVERFLOW;
        buf_pos += ret;
    }
    if (buf_pos + 2 > buf_size)
        return -EOVERFLOW;
    buf[buf_pos] =   '\n';
    buf[buf_pos+1] = '\0';
    return 0;
}

int sys_print_as_bitmask(char* buf, size_t buf_size, size_t count,
                         bool (*is_present)(size_t ind, const void* arg),
                         const void* callback_arg) {
    size_t buf_pos = 0;
    int ret;

    size_t pos = count ? count - 1 : 0;
    uint32_t word = 0;
    while (1) {
        if (is_present(pos, callback_arg))
            word |= (1 << pos % 32);
        if (pos % 32 == 0) {
            if (count <= 32) // Linux sysfs quirk for small bitmasks
                ret = snprintf(buf, buf_size, "%x\n", word); // pos == 0, loop exits afterwards
            else
                ret = snprintf(buf + buf_pos, buf_size - buf_pos,
                               "%08x%c", word, pos != 0 ? ',' : '\n');
            if (ret < 0)
                return ret;
            if ((size_t)ret >= buf_size - buf_pos)
                return -EOVERFLOW;
            buf_pos += ret;
            word = 0;
        }

        if (pos == 0)
            break;
        pos--;
    }
    return 0;
}

static int sys_resource(struct shim_dentry* parent, const char* name, unsigned int* out_num,
                        readdir_callback_t callback, void* arg) {
    const char* parent_name = parent->name;
    size_t total;
    const char* prefix;
    const struct pal_topo_info* ti = &g_pal_public_state->topo_info;

    if (strcmp(parent_name, "node") == 0) {
        total = ti->numa_nodes_cnt;
        prefix = "node";
    } else if (strcmp(parent_name, "cpu") == 0) {
        total = ti->threads_cnt;
        prefix = "cpu";
    } else if (strcmp(parent_name, "cache") == 0) {
        total = 0;
        /* Find the largest cache index used. */
        for (size_t i = 0; i < ti->threads_cnt; i++) {
            for (size_t j = 0; j < MAX_CACHES; j++) {
                if (ti->threads[i].caches_ids[j] != (size_t)-1)
                    total = MAX(total, j) + 1;
            }
        }
        prefix = "index";
    } else {
        log_debug("unrecognized resource: %s", parent_name);
        return -ENOENT;
    }

    if (name) {
        if (total == 0)
            return -ENOENT;

        if (!strstartswith(name, prefix))
            return -ENOENT;
        size_t prefix_len = strlen(prefix);
        unsigned long n;
        if (pseudo_parse_ulong(&name[prefix_len], total - 1, &n) < 0)
            return -ENOENT;

        if (out_num)
            *out_num = n;
        return 0;
    } else {
        for (size_t i = 0; i < total; i++) {
            char ent_name[42];
            snprintf(ent_name, sizeof(ent_name), "%s%zu", prefix, i);
            int ret = callback(ent_name, arg);
            if (ret < 0)
                return ret;
        }
        return 0;
    }
}

int sys_resource_find(struct shim_dentry* dent, const char* name, unsigned int* num) {
    struct shim_dentry* parent = dent->parent;
    while (parent) {
        if (strcmp(parent->name, name) == 0) {
            return sys_resource(parent, dent->name, num, /*callback=*/NULL, /*arg=*/NULL);
        }

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

bool sys_resource_name_exists(struct shim_dentry* parent, const char* name) {
    int ret = sys_resource(parent, name, /*num=*/NULL, /*callback=*/NULL, /*arg=*/NULL);
    return ret == 0;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource(parent, /*name=*/NULL, /*num=*/NULL, callback, arg);
}

int sys_load(const char* str, char** out_data, size_t* out_size) {
    assert(str);

    /* Use the string (without null terminator) as file data */
    size_t size = strlen(str);
    char* data = malloc(size);
    if (!data)
        return -ENOMEM;
    memcpy(data, str, size);
    *out_data = data;
    *out_size = size;
    return 0;
}

static void init_cpu_dir(struct pseudo_node* cpu) {
    pseudo_add_str(cpu, "online", &sys_cpu_general_load);
    pseudo_add_str(cpu, "possible", &sys_cpu_general_load);

    struct pseudo_node* cpuX = pseudo_add_dir(cpu, NULL);
    cpuX->name_exists = &sys_resource_name_exists;
    cpuX->list_names = &sys_resource_list_names;

    /* Create a node for `cpu/cpuX/online`. We provide name callbacks instead of a hardcoded name,
     * because we want the file to exist for all CPUs *except* `cpu0`. */
    struct pseudo_node* online = pseudo_add_str(cpuX, NULL, &sys_cpu_load);
    online->name_exists = &sys_cpu_online_name_exists;
    online->list_names = &sys_cpu_online_list_names;

    struct pseudo_node* topology = pseudo_add_dir(cpuX, "topology");
    pseudo_add_str(topology, "core_id", &sys_cpu_load);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_load);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_load);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_load);

    struct pseudo_node* cache = pseudo_add_dir(cpuX, "cache");
    struct pseudo_node* indexX = pseudo_add_dir(cache, NULL);
    indexX->name_exists = &sys_resource_name_exists;
    indexX->list_names = &sys_resource_list_names;

    pseudo_add_str(indexX, "shared_cpu_map", &sys_cache_load);
    pseudo_add_str(indexX, "level", &sys_cache_load);
    pseudo_add_str(indexX, "type", &sys_cache_load);
    pseudo_add_str(indexX, "size", &sys_cache_load);
    pseudo_add_str(indexX, "coherency_line_size", &sys_cache_load);
    pseudo_add_str(indexX, "number_of_sets", &sys_cache_load);
    pseudo_add_str(indexX, "physical_line_partition", &sys_cache_load);
}

static void init_node_dir(struct pseudo_node* node) {
    pseudo_add_str(node, "online", &sys_node_general_load);
    pseudo_add_str(node, "possible", &sys_node_general_load);

    struct pseudo_node* nodeX = pseudo_add_dir(node, NULL);
    nodeX->name_exists = &sys_resource_name_exists;
    nodeX->list_names = &sys_resource_list_names;

    pseudo_add_str(nodeX, "cpumap", &sys_node_load);
    pseudo_add_str(nodeX, "distance", &sys_node_load);

    struct pseudo_node* hugepages = pseudo_add_dir(nodeX, "hugepages");
    struct pseudo_node* hugepages_2m = pseudo_add_dir(hugepages, "hugepages-2048kB");
    pseudo_add_str(hugepages_2m, "nr_hugepages", &sys_node_load);
    struct pseudo_node* hugepages_1g = pseudo_add_dir(hugepages, "hugepages-1048576kB");
    pseudo_add_str(hugepages_1g, "nr_hugepages", &sys_node_load);
}

int init_sysfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("sys");
    struct pseudo_node* devices = pseudo_add_dir(root, "devices");
    struct pseudo_node* system = pseudo_add_dir(devices, "system");

    struct pseudo_node* cpu = pseudo_add_dir(system, "cpu");
    init_cpu_dir(cpu);

    struct pseudo_node* node = pseudo_add_dir(system, "node");
    init_node_dir(node);

    return 0;
}
