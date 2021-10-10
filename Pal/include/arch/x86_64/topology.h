/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#ifndef TOPOLOGY_H
#define TOPOLOGY_H

#include <stdint.h>

extern PAL_TOPO_INFO g_topo_info;

/* Used to represent plain integers (only numeric values) */
#define PAL_SYSFS_INT_FILESZ 16
/* Used to represent buffers having numeric values with text. E.g "1024576K" */
#define PAL_SYSFS_BUF_FILESZ 64
/* Used to represent cpumaps like "00000000,ffffffff,00000000,ffffffff" */
#define PAL_SYSFS_MAP_FILESZ 256

enum {
    HUGEPAGES_2M = 0,
    HUGEPAGES_1G,
    HUGEPAGES_MAX,
};

/* PAL_CPU_INFO holds /proc/cpuinfo data */
typedef struct PAL_CPU_INFO_ {
    /* Number of logical cores available in the host */
    uint64_t online_logical_cores;
    /* Max number of logical cores available in the host */
    uint64_t possible_logical_cores;
    /* Number of physical cores in a socket (physical package) */
    uint64_t physical_cores_per_socket;
    /* array of "logical core -> socket" mappings; has online_logical_cores elements */
    int* cpu_to_socket;
    const char* cpu_vendor;
    const char* cpu_brand;
    uint64_t cpu_family;
    uint64_t cpu_model;
    uint64_t cpu_stepping;
    double  cpu_bogomips;
    const char* cpu_flags;
} PAL_CPU_INFO;

typedef struct PAL_CORE_CACHE_INFO_ {
    char shared_cpu_map[PAL_SYSFS_MAP_FILESZ];
    char level[PAL_SYSFS_INT_FILESZ];
    char type[PAL_SYSFS_BUF_FILESZ];
    char size[PAL_SYSFS_BUF_FILESZ];
    char coherency_line_size[PAL_SYSFS_INT_FILESZ];
    char number_of_sets[PAL_SYSFS_INT_FILESZ];
    char physical_line_partition[PAL_SYSFS_INT_FILESZ];
} PAL_CORE_CACHE_INFO;

typedef struct PAL_CORE_TOPO_INFO_ {
    /* [0] element is uninitialized because core 0 is always online */
    char is_logical_core_online[PAL_SYSFS_INT_FILESZ];
    char core_id[PAL_SYSFS_INT_FILESZ];
    char core_siblings[PAL_SYSFS_MAP_FILESZ];
    char thread_siblings[PAL_SYSFS_MAP_FILESZ];
    PAL_CORE_CACHE_INFO* cache; /* Array of cache_index_cnt elements, owned by this struct */
} PAL_CORE_TOPO_INFO;

typedef struct PAL_NUMA_HUGEPAGE_INFO_ {
    char nr_hugepages[PAL_SYSFS_INT_FILESZ];
} PAL_NUMA_HUGEPAGE_INFO;

typedef struct PAL_NUMA_TOPO_INFO_ {
    char cpumap[PAL_SYSFS_MAP_FILESZ];
    char distance[PAL_SYSFS_BUF_FILESZ];
    PAL_NUMA_HUGEPAGE_INFO hugepages[HUGEPAGES_MAX];
} PAL_NUMA_TOPO_INFO;

/* This struct takes ~1.6KB. On a single socket, 4 logical core system, with 3 cache levels
 * it would take ~8KB in memory. */
// TODO: ^ ???? ^ the size is constant...
typedef struct PAL_TOPO_INFO_ {
    uint64_t physical_cores_per_socket;

    int* cpu_to_socket;

    size_t online_logical_cores_cnt;
    char online_logical_cores[PAL_SYSFS_BUF_FILESZ];

    size_t possible_logical_cores_cnt;
    char possible_logical_cores[PAL_SYSFS_BUF_FILESZ];

    size_t online_nodes_cnt; /* Number of nodes available in the host */
    char online_nodes[PAL_SYSFS_BUF_FILESZ];

    /* cache index corresponds to number of cache levels (such as L2 or L3) available on the host */
    size_t cache_index_cnt;
    PAL_CORE_TOPO_INFO* core_topology; /* Array of logical core topology info, owned by this struct */
    PAL_NUMA_TOPO_INFO* numa_topology; /* Array of numa topology info, owned by this struct */
} PAL_TOPO_INFO;


#endif /* TOPOLOGY_H */
