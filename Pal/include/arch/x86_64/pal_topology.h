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

struct pal_core_cache_info {
    // struct bitmap shared_cpus; // excludes offline CPUs, includes itself
    size_t level;
    enum cache_type type;
    size_t size;
    size_t coherency_line_size;
    size_t number_of_sets;
    size_t physical_line_partition;
};

struct pal_cpu_thread_info {
    bool is_online;
    /* Everything below is valid only if the core is online! */

    size_t core_id; // containing core; index into pal_topo_info::cores

    // TODO: extract
    // struct pal_core_cache_info* cache_info_arr;
};

// TODO: move info from struct pal_cpu_info to here
struct pal_cpu_core_info {
    /* We have our own numbering of physical cores (not takes from the host), so we can just ignore
     * offline cores and thus skip `is_online` from here. */

    size_t socket_id;
};

struct pal_socket_info {
    /* We have our own numbering of sockets (not takes from the host), so we can just ignore
     * offline sockets and thus skip `is_online` from here. */

    size_t node_id;
};

struct pal_numa_node_info {
    bool is_online;
    /* Everything below is valid only if the node is online! */

    size_t nr_hugepages[HUGEPAGES_MAX];
};

struct pal_topo_info {
    size_t threads_cnt;
    struct pal_cpu_thread_info* threads;

    size_t cores_cnt;
    struct pal_cpu_core_info* cores;

    size_t sockets_cnt;
    struct pal_socket_info* sockets;

    size_t numa_nodes_cnt;
    struct pal_numa_node_info* numa_nodes; // TODO: maybe just "nodes"?

    /* Has `numa_nodes_cnt` x `numa_nodes_cnt` elements.
     * numa_distance_matrix[i*numa_nodes_cnt + j] is NUMA distance from node i to node j. */
    size_t* numa_distance_matrix; // inline inside nodes? arg for keeping here: less nesting of structure pointers in untrusted interface

    // TODO: delete
    /* Number of caches (such as L1i, L1d, L2, etc.) available. */
    // size_t cache_indices_cnt;
};

#endif /* PAL_TOPOLOGY_H */
