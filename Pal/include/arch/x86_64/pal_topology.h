/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

#ifndef PAL_TOPOLOGY_H
#define PAL_TOPOLOGY_H

#include <stdbool.h>

#include "bitmap.h"

/* Used to represent buffers having numeric values and unit suffixes if present, e.g. "1024576K".
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_BUF_FILESZ 64
/* Used to represent cpumaps like "00000000,ffffffff,00000000,ffffffff".
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_MAP_FILESZ 256

/* Used to represent length of file/directory paths.
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_PATH_SIZE 128

/* Max SMT siblings currently supported on x86 processors */
#define MAX_HYPERTHREADS_PER_CORE 4

#define MAX_CACHE_LEVELS          3

enum {
    HUGEPAGES_2M = 0,
    HUGEPAGES_1G,
    HUGEPAGES_MAX,
};

enum cache_type {
    CACHE_TYPE_DATA,
    CACHE_TYPE_INSTRUCTION,
    CACHE_TYPE_UNIFIED,
};

struct pal_range_info {
    size_t start;
    size_t end; /* inclusive */
};

struct pal_res_range_info {
    /* Total number of resources present. E.g. if output of `/sys/devices/system/cpu/online` was
     * 0-15,21,32-63 then `resource_cnt` will be 49 */
    size_t resource_cnt;

    /* Total number of ranges present. E.g. if output of `/sys/devices/system/cpu/online` was
     * 0-15,21,32-63 then `ranges_cnt` will be 3 */
    size_t ranges_cnt;

    /* Array of ranges, with `ranges_cnt` items. E.g. if output of `/sys/devices/system/cpu/online`
     * was 0-12,16-30,31 then `ranges_arr` will be [{0, 12}, {16, 30}, {31, 31}].
     * Note: The ranges should not overlap */
    struct pal_range_info* ranges_arr;
};

struct pal_core_cache_info {
    struct bitmap shared_cpus; // excludes offline CPUs, includes itself
    size_t level;
    enum cache_type type;
    size_t size;
    size_t coherency_line_size;
    size_t number_of_sets;
    size_t physical_line_partition;
};

struct pal_core_info {
    bool is_online;
    /* Everything below is valid only if the core is online! */

    /* Socket (physical package) where the core is present */
    size_t socket_id; /* "physical package id of cpuX. Typically corresponds to a physical socket number, but the actual value is architecture and platform dependent." */
    struct pal_res_range_info core_siblings;   // excludes offline CPUs, includes itself
    struct pal_res_range_info thread_siblings; // excludes offline CPUs, includes itself
    /* Array with cache_indices_cnt elements, owned by this struct */
    struct pal_core_cache_info* cache_info_arr;
};

// TODO: move info from struct pal_cpu_info to here
struct pal_numa_node_info {
    bool is_online;
    /* Everything below is valid only if the node is online! */

    struct bitmap cpu_map; // excludes offline CPUs
    size_t nr_hugepages[HUGEPAGES_MAX];
};

struct pal_topo_info {
    /* Array of information about logical cores, owned by this struct. */
    size_t cores_cnt;
    struct pal_core_info* cores; // logical // TODO: embed "logical" in the var name?

    /* Array with `nodes_cnt` elements, owned by this struct. */
    size_t nodes_cnt;
    struct pal_numa_node_info* numa_topo_arr;

    /* Has `nodes_cnt` x `nodes_cnt` elements.
     * numa_distance_matrix[i*nodes_cnt + j] is NUMA distance from node i to node j. */
    size_t* numa_distance_matrix; // inline inside nodes?

    /* Number of physical packages in the system. */
    size_t sockets_cnt;
    /* Number of physical cores in a socket (physical package). */
    size_t physical_cores_per_socket;

    /* Number of caches (such as L1i, L1d, L2, etc.) available. */
    size_t cache_indices_cnt;
};

#endif /* PAL_TOPOLOGY_H */
