/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 * Copyright (C) 2022 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

#ifndef PAL_TOPOLOGY_H
#define PAL_TOPOLOGY_H

/* Used to represent buffers having numeric values with unit suffixes. E.g "1024576K".
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_BUF_FILESZ 64
/* Used to represent cpumaps like "00000000,ffffffff,00000000,ffffffff".
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_MAP_FILESZ 256

/* Used to represent length of file/directory paths.
 * NOTE: Used to allocate on stack; increase with caution or use malloc instead. */
#define PAL_SYSFS_PATH_LEN 128

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
    size_t end;
};

struct pal_res_range_info {
    /* Total number of resources present. Eg. if output of `/sys/devices/system/cpu/online` were
     * 0-15,21,32-63 then `resource_cnt` will be 49 */
    size_t resource_cnt;

    /* Total number of ranges present. Eg. if output of `/sys/devices/system/cpu/online` were
     * 0-15,21,32-63 then `range_cnt` will be 3 */
    size_t range_cnt;

    /* Array of ranges, with `range_cnt` items. Eg. if output of `/sys/devices/system/cpu/online`
     * were 0-15,21,32-63 then `ranges_arr` will be [{0, 15}, {21, 21}, {32 63}]. When there is only
     * a single number instead of range both start and end are assigned start value.
     * Note: The ranges should not overlap */
    struct pal_range_info* ranges_arr;
};

struct pal_core_cache_info {
    struct pal_res_range_info shared_cpu_map;
    size_t level;
    enum cache_type type;
    /* Total cache size is always in kB. So to get actual cache size multiply this value by 1024.
     * Pls ref: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-system-cpu */
    size_t size;
    size_t coherency_line_size;
    size_t number_of_sets;
    size_t physical_line_partition;
};

struct pal_core_topo_info {
    /* [0] element is uninitialized because core 0 is always online */
    size_t is_logical_core_online;
    size_t core_id;
    /* Socket (physical package) where the core is present */
    size_t socket_id;
    struct pal_res_range_info core_siblings;
    struct pal_res_range_info thread_siblings;
    /* Array of size cache_indices_cnt, owned by this struct */
    struct pal_core_cache_info* cache_info_arr;
};

struct pal_numa_topo_info {
    struct pal_res_range_info cpumap;
    struct pal_res_range_info distance;
    size_t nr_hugepages[HUGEPAGES_MAX];
};

struct pal_topo_info {
    struct pal_res_range_info possible_logical_cores;

    struct pal_res_range_info online_logical_cores;
    /* Array of logical core topology info, owned by this struct.
     * Has online_logical_cores.resource_cnt elements. */
    struct pal_core_topo_info* core_topology_arr;

    struct pal_res_range_info online_nodes;
    /* Array of numa topology info, owned by this struct. Has online_nodes.resource_cnt elements. */
    struct pal_numa_topo_info* numa_topology_arr;

    /* Number of physical packages in the system */
    size_t sockets_cnt;
    /* Number of physical cores in a socket (physical package). */
    size_t physical_cores_per_socket;

    /* Number of cache levels (such as L2 or L3) available on the host. */
    size_t cache_indices_cnt;
};

#endif /* PAL_TOPOLOGY_H */
