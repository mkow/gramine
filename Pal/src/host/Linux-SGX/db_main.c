/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "api.h"
#include "ecall_types.h"
#include "elf/elf.h"
#include "enclave_pages.h"
#include "enclave_pf.h"
#include "enclave_tf.h"
#include "init.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_rtld.h"
#include "pal_state.h"
#include "protected_files.h"
#include "toml.h"
#include "toml_utils.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_state g_pal_state;
PAL_TOPO_INFO g_topo_info;

PAL_SESSION_KEY g_master_key = {0};

/* Limit of PAL memory available for _DkVirtualMemoryAlloc(PAL_ALLOC_INTERNAL) */
size_t g_pal_internal_mem_size = PAL_INITIAL_MEM_SIZE;

const size_t g_page_size = PRESET_PAGESIZE;

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    *start = (PAL_PTR)g_pal_state.heap_min;
    *end   = (PAL_PTR)g_pal_state.heap_max;

    /* Keep some heap for internal PAL objects allocated at runtime (recall that LibOS does not keep
     * track of PAL memory, so without this limit it could overwrite internal PAL memory). See also
     * `enclave_pages.c`. */
    *end = SATURATED_P_SUB(*end, g_pal_internal_mem_size, *start);

    if (*end <= *start) {
        log_error("Not enough enclave memory, please increase enclave size!");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
}

/*
 * Takes a pointer+size to an untrusted memory region containing a
 * NUL-separated list of strings. It builds an argv-style list in trusted memory
 * with those strings.
 *
 * It is responsible for handling the access to untrusted memory safely
 * (returns NULL on error) and ensures that all strings are properly
 * terminated. The content of the strings is NOT further sanitized.
 *
 * The argv-style list is allocated on the heap and the caller is responsible
 * to free it (For argv and envp we rely on auto free on termination in
 * practice).
 */
static const char** make_argv_list(void* uptr_src, size_t src_size) {
    const char** argv;

    if (src_size == 0) {
        argv = malloc(sizeof(char*));
        if (argv)
            argv[0] = NULL;
        return argv;
    }

    char* data = malloc(src_size);
    if (!data) {
        return NULL;
    }

    if (!sgx_copy_to_enclave(data, src_size, uptr_src, src_size)) {
        goto fail;
    }
    data[src_size - 1] = '\0';

    size_t argc = 0;
    for (size_t i = 0; i < src_size; i++) {
        if (data[i] == '\0') {
            argc++;
        }
    }

    size_t argv_size;
    if (__builtin_mul_overflow(argc + 1, sizeof(char*), &argv_size)) {
        goto fail;
    }
    argv = malloc(argv_size);
    if (!argv) {
        goto fail;
    }
    argv[argc] = NULL;

    size_t data_i = 0;
    for (size_t arg_i = 0; arg_i < argc; arg_i++) {
        argv[arg_i] = &data[data_i];
        while (data[data_i] != '\0') {
            data_i++;
        }
        data_i++;
    }

    return argv;

fail:
    free(data);
    return NULL;
}

/* This function extracts first positive integer present in the buffer. For example 31 will be
 * returned when input "31" is provided. If buffer contains valid size indicators such as "48K",
 * then just numeric value (48 in this case) is returned. Returns negative unix error code if the
 * buffer is malformed E.g., "20abc" or "3,4,5" or "xyz123" or "512H".
 * Use case: To extract integer from /sys/devices/system/cpu/cpuX/cache/index0/size path. */
static long extract_long_from_buffer(const char* buf) {
    const char* end = NULL;
    unsigned long intval;

    while (*buf == ' ' || *buf == '\t')
        buf++;

    /* Intentionally using unsigned long to adapt for variable bitness. */
    if (str_to_ulong(buf, 10, &intval, &end) < 0 || intval > LONG_MAX)
        return -EINVAL;

    if (end[0] != '\0') {
        if (end[0] != '\n' && end[0] != 'K' && end[0] != 'M' && end[0] != 'G')
            return -EINVAL;

        end += 1;
        if (end[0] != '\0' && end[0] != '\n' && end[1] != '\0')
            return -EINVAL;
    }
    return (long)intval;
}

/* This function counts bits set in buffer. For example 2 will be returned when input buffer
 * "00000000,80000000,00000000,80000000" is provided. Returns negative UNIX error code on error and
 * actual count on success.
 * Use case: To count bits set in /sys/devices/system/cpu/cpu95/topology/core_siblings bitmaps. */
static long count_bits_set_from_resource_map(const char* buf) {
    unsigned long count = 0;
    unsigned long bitmap;
    while (*buf) {
        while (*buf == ' ' || *buf == '\t' || *buf == ',' || *buf == '\n')
            buf++;

        if (*buf == '\0')
            break;

        const char* end = NULL;
        /* Linux uses different bitmap size depending on the host arch. We intentionally use
         * unsigned long to adapt for this variable bitness. */
        if (str_to_ulong(buf, 16, &bitmap, &end) < 0)
            return -EINVAL;

        if (*end != '\0' && *end != ',' && *end != '\n')
            return -EINVAL;

        count += count_ulong_bits_set(bitmap);
        if (count > LONG_MAX)
            return -EINVAL;

        buf = end;
    }
    return (long)count;
}

/* This function counts number of hw resources present in buffer. There are 2 options available,
 * 1) ordered == true, which ensures that buffer doesn't have overlapping range like "1-5,3-4" or
 * malformed like "1-5,7-1".
 * 2) ordered == false which simply counts the range of numbers. For example "1-5, 3-4, 7-1" will
 * return 14 as count.
 * Returns negative unix error if buf is empty or contains invalid data and number of hw resources
 * present in the buffer on success. */
static long sanitize_hw_resource_count(const char* buf, bool ordered) {
    bool init_done = false;
    unsigned long current_maxint = 0;
    unsigned long resource_cnt = 0;
    while (*buf) {
        while (*buf == ' ' || *buf == '\t' || *buf == ',' || *buf == '\n')
            buf++;

        if (*buf == '\0')
            break;

        const char* end = NULL;
        unsigned long firstint;
        /* Intentionally using unsigned long to adapt for variable bitness. */
        if (str_to_ulong(buf, 10, &firstint, &end) < 0 || firstint > LONG_MAX)
            return -EINVAL;

        if (ordered) {
            if (init_done && firstint <= current_maxint)
                return -EINVAL;
            current_maxint = firstint;
            init_done = true;
        }

        /* count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n' || *end == ' ') {
            /* single HW resource index, count as one more */
            resource_cnt++;
        } else if (*end == '-') {
            /* HW resource range, count how many HW resources are in range */
            buf = end + 1;
            unsigned long secondint;
            if (str_to_ulong(buf, 10, &secondint, &end) < 0 || secondint > LONG_MAX)
                return -EINVAL;

            unsigned long diff;
            if (secondint > firstint) {
                if (ordered)
                    current_maxint = secondint;

                diff = secondint - firstint;
                if (diff >= LONG_MAX || resource_cnt + diff + 1 > LONG_MAX)
                    return -EINVAL;
                resource_cnt += diff + 1; /* inclusive (e.g. 0-7) */
            } else {
                diff = firstint - secondint;
                if (ordered || diff >= LONG_MAX || resource_cnt + diff + 1 > LONG_MAX)
                    return -EINVAL;
                resource_cnt += diff + 1;
            }
        }
        buf = end;
    }
    return (long)resource_cnt ?: -EINVAL;
}

static int sanitize_cache_topology_info(PAL_CORE_CACHE_INFO* cache, uint64_t cache_lvls,
                                        uint64_t num_cores) {
    for (uint64_t lvl = 0; lvl < cache_lvls; lvl++) {
        uint64_t shared_cpu_map = count_bits_set_from_resource_map(cache[lvl].shared_cpu_map);
        if (!IS_IN_RANGE_INCL(shared_cpu_map, 1u, num_cores))
            return -EINVAL;

        uint64_t level = extract_long_from_buffer(cache[lvl].level);
        if (!IS_IN_RANGE_INCL(level, 1, 3))      /* x86 processors have max of 3 cache levels */
            return -EINVAL;

        char* type = cache[lvl].type;
        if (!strstartswith(type, "Data") && !strstartswith(type, "Instruction") &&
            !strstartswith(type, "Unified")) {
            return -EINVAL;
        }

        uint64_t size = extract_long_from_buffer(cache[lvl].size);
        if (!IS_IN_RANGE_INCL(size, 1, 1 << 30))
            return -EINVAL;

        uint64_t coherency_line_size = extract_long_from_buffer(cache[lvl].coherency_line_size);
        if (!IS_IN_RANGE_INCL(coherency_line_size, 1, 1 << 16))
            return -EINVAL;

        uint64_t number_of_sets = extract_long_from_buffer(cache[lvl].number_of_sets);
        if (!IS_IN_RANGE_INCL(number_of_sets, 1, 1 << 30))
            return -EINVAL;

        uint64_t physical_line_partition =
            extract_long_from_buffer(cache[lvl].physical_line_partition);
        if (!IS_IN_RANGE_INCL(physical_line_partition, 1, 1 << 16))
            return -EINVAL;
    }
    return 0;
}

static bool is_untrusted_core_topology_info_ok(PAL_CORE_TOPO_INFO* core_topology, int64_t num_cores,
                                               int64_t cache_lvls) {
    if (num_cores == 0 || cache_lvls == 0)
        return false;

    for (int64_t idx = 0; idx < num_cores; idx++) {
        if (idx != 0) {     /* core 0 is always online */
            int64_t is_core_online =
                extract_long_from_buffer(core_topology[idx].is_logical_core_online);
            if (is_core_online != 0 && is_core_online != 1)
                return false;
        }

        int64_t core_id = extract_long_from_buffer(core_topology[idx].core_id);
        if (!IS_IN_RANGE_INCL(core_id, 0, num_cores - 1))
            return false;

        int64_t core_siblings = count_bits_set_from_resource_map(core_topology[idx].core_siblings);
        if (!IS_IN_RANGE_INCL(core_siblings, 1, num_cores))
            return false;

        int64_t thread_siblings =
            count_bits_set_from_resource_map(core_topology[idx].thread_siblings);
        if (!IS_IN_RANGE_INCL(thread_siblings, 1, 4)) /* x86 processors have max of 4 SMT siblings */
            return false;

        if (sanitize_cache_topology_info(core_topology[idx].cache, cache_lvls, num_cores) < 0)
            return false;
    }
    return true;
}

static bool is_untrusted_socket_info_ok(int* cpu_to_socket, int64_t num_cores) {
    if (num_cores == 0)
        return false;

    for (int64_t idx = 0; idx < num_cores; idx++) {
        /* Virtual environments such as QEMU may assign each core to a separate socket/package with
         * one or more NUMA nodes. So we check against the number of online logical cores. */
        if (!IS_IN_RANGE_INCL(cpu_to_socket[idx], 0, num_cores - 1))
            return false;
    }
    return true;
}

static bool is_untrusted_numa_topology_info_ok(PAL_NUMA_TOPO_INFO* numa_topology, int64_t num_nodes,
                                               int64_t num_cores) {
    if (num_nodes == 0 || num_cores == 0)
        return false;

    for (int64_t idx = 0; idx < num_nodes; idx++) {
        int64_t cpumap = count_bits_set_from_resource_map(numa_topology[idx].cpumap);
        if (!IS_IN_RANGE_INCL(cpumap, 1, num_cores))
            return false;

        int64_t cnt = sanitize_hw_resource_count(numa_topology[idx].distance, /*ordered=*/false);
        if (cnt < 0 || num_nodes != cnt)
            return false;
    }
    return true;
}

/* This function does't clean up resources on failure: we terminate the process anyway. */
static int parse_host_topo_info(PAL_TOPO_INFO* uptr_topo_info,
                                bool enable_sysfs_topology,
                                PAL_TOPO_INFO* out_topo_info) {
    /* Some magic to fold the repetitive sanitization. Warning: contains return!
     * Quite ugly, but still better than a huge, error-prone copy-paste. */
    #define VERIFY(expr) do {                                                         \
        if (!(expr)) {                                                                \
            log_error("Sanitization failed: " #expr " is not true!");                 \
            return -EINVAL;                                                           \
        }                                                                             \
    } while (0)
    #define VERIFY_RANGE_AND_COPY(field, min_allowed, max_allowed) do {               \
        VERIFY(IS_IN_RANGE_INCL(untrusted_topo_info.field, min_allowed, max_allowed)) \
        out_topo_info->field = untrusted_topo_info.field;                             \
    } while (0)
    #define SAFE_ARRAY_COPY(field, count) do {                                                    \
        size_t size;                                                                              \
        VERIFY(!__builtin_mul_overflow(sizeof(*uptr_topo_info->field), count, &size));            \
        VERIFY(out_topo_info->field = malloc(size));                                              \
        VERIFY(sgx_copy_to_enclave(out_topo_info->field, size, untrusted_topo_info.field, size)); \
    } while (0)

    /* Beware: This is only a shallow copy! All the pointers inside are still untrusted and can't be
     * dereferenced directly! */
    PAL_TOPO_INFO untrusted_topo_info;
    if (!sgx_copy_to_enclave(&untrusted_topo_info, sizeof(untrusted_topo_info), uptr_topo_info, sizeof(*uptr_topo_info))) {
        return -EACCES;
    }
    uptr_topo_info = NULL; // Ensure that the code below won't use that pointer anymore.

    VERIFY_RANGE_AND_COPY(online_logical_cores_cnt,   1u, 1u << 16);
    VERIFY_RANGE_AND_COPY(possible_logical_cores_cnt, 1u, 1u << 16);
    VERIFY_RANGE_AND_COPY(physical_cores_per_socket,  1u, 1u << 13);
    VERIFY(online_logical_cores_cnt <= possible_logical_cores_cnt);
    SAFE_ARRAY_COPY(cpu_to_socket, online_logical_cores_cnt);
    VERIFY(is_untrusted_socket_info_ok(cpu_to_socket, online_logical_cores_cnt));

    if (!enable_sysfs_topology) {
        /* TODO: temporary measure, remove it once sysfs topology is thoroughly validated */
        return 0;
    }

    VERIFY_RANGE_AND_COPY(online_nodes_cnt, 1u, 1u << 8);
    VERIFY_RANGE_AND_COPY(cache_index_cnt,  1u, 1u << 4);

    /* The checks below have a bit ugly signed -> unsigned conversion and hidden error handling, but
     * will be reworked soon anyways (with the rework of topology structures). */
    VERIFY(sanitize_hw_resource_count(unstrusted_topo_info.online_logical_cores, /*ordered=*/true) == online_logical_cores_cnt);
    VERIFY(sanitize_hw_resource_count(unstrusted_topo_info.possible_logical_cores, /*ordered=*/true) == possible_logical_cores_cnt);
    VERIFY(sanitize_hw_resource_count(unstrusted_topo_info.online_nodes, /*ordered=*/true) == online_nodes_cnt);
    COPY_ARRAY(g_topo_info.online_logical_cores, unstrusted_topo_info.online_logical_cores);
    COPY_ARRAY(g_topo_info.possible_logical_cores, unstrusted_topo_info.possible_logical_cores);
    COPY_ARRAY(g_topo_info.online_nodes, unstrusted_topo_info.online_nodes);

    SAFE_ARRAY_COPY(core_topology, online_logical_cores_cnt);
    for (size_t i = 0; i < online_logical_cores_cnt; i++)
        SAFE_ARRAY_COPY(core_topology[i].cache, cache_index_cnt);
    SAFE_ARRAY_COPY(numa_topology, online_nodes_cnt);

    VERIFY(is_untrusted_core_topology_info_ok(core_topology, online_logical_cores_cnt, cache_index_cnt));
    VERIFY(is_untrusted_numa_topology_info_ok(numa_topology, online_nodes_cnt, online_logical_cores_cnt));
    return 0;
#undef SAFE_ARRAY_COPY
#undef VERIFY_RANGE_AND_COPY
#undef VERIFY
}

extern void* g_enclave_base;
extern void* g_enclave_top;
extern bool g_allowed_files_warn;

static int print_warnings_on_insecure_configs(bool has_parent) {
    int ret;

    if (has_parent) {
        /* Warn only in the first process. */
        return 0;
    }

    bool verbose_log_level = false;
    bool sgx_debug         = false;
    bool use_cmdline_argv  = false;
    bool use_host_env      = false;
    bool disable_aslr      = false;
    bool allow_eventfd     = false;
    bool allow_all_files   = false;
    bool use_allowed_files = g_allowed_files_warn;
    bool enable_sysfs_topo = false;

    char* log_level_str = NULL;
    ret = toml_string_in(g_pal_common_state.manifest_root, "loader.log_level", &log_level_str);
    if (ret < 0)
        goto out;
    if (log_level_str && strcmp(log_level_str, "none") && strcmp(log_level_str, "error"))
        verbose_log_level = true;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "sgx.debug", /*defaultval=*/false, &sgx_debug);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "loader.insecure__use_cmdline_argv",
                       /*defaultval=*/false, &use_cmdline_argv);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "loader.insecure__use_host_env",
                       /*defaultval=*/false, &use_host_env);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "loader.insecure__disable_aslr",
                       /*defaultval=*/false, &disable_aslr);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "sys.insecure__allow_eventfd",
                       /*defaultval=*/false, &allow_eventfd);
    if (ret < 0)
        goto out;

    if (get_file_check_policy() == FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG)
        allow_all_files = true;

    ret = toml_bool_in(g_pal_common_state.manifest_root, "fs.experimental__enable_sysfs_topology",
                       /*defaultval=*/false, &enable_sysfs_topo);
    if (ret < 0)
        goto out;

    if (!verbose_log_level && !sgx_debug && !use_cmdline_argv && !use_host_env && !disable_aslr &&
            !allow_eventfd && !allow_all_files && !use_allowed_files && !enable_sysfs_topo) {
        /* there are no insecure configurations, skip printing */
        ret = 0;
        goto out;
    }

    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------");
    log_always("Gramine detected the following insecure configurations:\n");

    if (sgx_debug)
        log_always("  - sgx.debug = true                           "
                   "(this is a debug enclave)");

    if (verbose_log_level)
        log_always("  - loader.log_level = warning|debug|trace|all "
                   "(verbose log level, may leak information)");

    if (use_cmdline_argv)
        log_always("  - loader.insecure__use_cmdline_argv = true   "
                   "(forwarding command-line args from untrusted host to the app)");

    if (use_host_env)
        log_always("  - loader.insecure__use_host_env = true       "
                   "(forwarding environment vars from untrusted host to the app)");

    if (disable_aslr)
        log_always("  - loader.insecure__disable_aslr = true       "
                   "(Address Space Layout Randomization is disabled)");

    if (allow_eventfd)
        log_always("  - sys.insecure__allow_eventfd = true         "
                   "(host-based eventfd is enabled)");

    if (allow_all_files)
        log_always("  - sgx.file_check_policy = allow_all_but_log  "
                   "(all files are passed through from untrusted host without verification)");

    if (use_allowed_files)
        log_always("  - sgx.allowed_files = [ ... ]                "
                   "(some files are passed through from untrusted host without verification)");

    if (enable_sysfs_topo)
        log_always("  - fs.experimental__enable_sysfs_topology = true "
                   "(forwarding sysfs topology from untrusted host to the app)");

    log_always("\nGramine will continue application execution, but this configuration must not be "
               "used in production!");
    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------\n");

    ret = 0;
out:
    free(log_level_str);
    return ret;
}

__attribute_no_sanitize_address
static void do_preheat_enclave(void) {
    for (uint8_t* i = g_pal_state.heap_min; i < (uint8_t*)g_pal_state.heap_max; i += g_page_size)
        READ_ONCE(*(size_t*)i);
}

/* Gramine uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with a default canary and then updates it to a random one, so we disable stack protector here */
__attribute_no_stack_protector
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             int parent_stream_fd, int host_euid, int host_egid,
                             sgx_target_info_t* uptr_qe_targetinfo,
                             PAL_TOPO_INFO* uptr_topo_info) {
    /* All our arguments are coming directly from the urts. We are responsible to check them. */
    int ret;

    /* Relocate PAL */
    ret = setup_pal_binary();
    if (ret < 0) {
        log_error("Relocation of the PAL binary failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0) {
        log_error("_DkSystemTimeQuery() failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    call_init_array();

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_common_state.alloc_align = g_page_size;
    assert(IS_POWER_OF_2(g_pal_common_state.alloc_align));

    g_pal_state.heap_min = GET_ENCLAVE_TLS(heap_min);
    g_pal_state.heap_max = GET_ENCLAVE_TLS(heap_max);

    /* Skip URI_PREFIX_FILE. */
    if (libpal_uri_len < URI_PREFIX_FILE_LEN) {
        log_error("Invalid libpal_uri length (missing \"%s\" prefix?)", URI_PREFIX_FILE);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_uri_len -= URI_PREFIX_FILE_LEN;
    uptr_libpal_uri += URI_PREFIX_FILE_LEN;

    /* At this point we don't yet have memory manager, so we cannot allocate memory dynamically. */
    static char libpal_path[1024 + 1];
    if (libpal_uri_len >= sizeof(libpal_path)
            || !sgx_copy_to_enclave(libpal_path, sizeof(libpal_path) - 1, uptr_libpal_uri,
                                    libpal_uri_len)) {
        log_error("Copying libpal_path into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_path[libpal_uri_len] = '\0';

    /* Now that we have `libpal_path`, set name for PAL map */
    set_pal_binary_name(libpal_path);

    /* We can't verify the following arguments from the urts. So we copy them directly but need to
     * be careful when we use them. */
    if (!sgx_copy_to_enclave(&g_pal_state.untrusted_qe_targetinfo,
                             sizeof(g_pal_state.untrusted_qe_targetinfo),
                             uptr_qe_targetinfo,
                             sizeof(*uptr_qe_targetinfo))) {
        log_error("Copying qe_targetinfo into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* Set up page allocator and slab manager. There is no need to provide any initial memory pool,
     * because the slab manager can use normal allocations (`_DkVirtualMemoryAlloc`) right away. */
    init_enclave_pages();
    init_slab_mgr(/*mem_pool=*/NULL, /*mem_pool_size=*/0);
    init_untrusted_slab_mgr();

    /* initialize enclave properties */
    ret = init_enclave();
    if (ret) {
        log_error("Failed to initialize enclave properties: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (args_size > MAX_ARGS_SIZE || env_size > MAX_ENV_SIZE) {
        log_error("Invalid args_size (%lu) or env_size (%lu)", args_size, env_size);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        log_error("Creating arguments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        log_error("Creating environments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_pal_common_state.host_euid = host_euid;
    g_pal_common_state.host_egid = host_egid;

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

    /* initialize "Invariant TSC" HW feature for fast and accurate gettime and immediately probe
     * RDTSC instruction inside SGX enclave (via dummy get_tsc) -- it is possible that
     * the CPU supports invariant TSC but doesn't support executing RDTSC inside SGX enclave, in
     * this case the SIGILL exception is generated and leads to emulate_rdtsc_and_print_warning()
     * which unsets invariant TSC, and we end up falling back to the slower ocall_gettime() */
    init_tsc();
    (void)get_tsc(); /* must be after `ready_for_exceptions=1` since it may generate SIGILL */

    /* initialize master key (used for pipes' encryption for all enclaves of an application); it
     * will be overwritten below in init_child_process() with inherited-from-parent master key if
     * this enclave is child */
    ret = _DkRandomBitsRead(&g_master_key, sizeof(g_master_key));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* if there is a parent, create parent handle */
    PAL_HANDLE parent = NULL;
    uint64_t instance_id = 0;
    if (parent_stream_fd != -1) {
        if ((ret = init_child_process(parent_stream_fd, &parent, &instance_id)) < 0) {
            log_error("Failed to initialize child process: %d", ret);
            ocall_exit(1, /*is_exitgroup=*/true);
        }
    }

    uint64_t manifest_size = GET_ENCLAVE_TLS(manifest_size);
    void* manifest_addr = g_enclave_top - ALIGN_UP_PTR_POW2(manifest_size, g_page_size);

    ret = add_preloaded_range((uintptr_t)manifest_addr, (uintptr_t)manifest_addr + manifest_size,
                              "manifest");
    if (ret < 0) {
        log_error("Failed to initialize manifest preload range: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* TOML parser (for whatever reason) allocates a lot of memory when parsing the manifest into an
     * in-memory struct. We heuristically pre-allocate additional PAL internal memory if the
     * manifest file looks large enough. Hopefully below sizes are sufficient for any manifest.
     *
     * FIXME: this is a quick hack, we need proper memory allocation in PAL. */
    if (manifest_size > 10 * 1024 * 1024) {
        log_always("Detected a huge manifest, preallocating 128MB of internal memory.");
        g_pal_internal_mem_size += 128 * 1024 * 1024; /* 10MB manifest -> 64 + 128 MB PAL mem */
    } else if (manifest_size > 5 * 1024 * 1024) {
        log_always("Detected a huge manifest, preallocating 64MB of internal memory.");
        g_pal_internal_mem_size += 64 * 1024 * 1024; /* 5MB manifest -> 64 + 64 MB PAL mem */
    }

    /* parse manifest */
    char errbuf[256];
    toml_table_t* manifest_root = toml_parse(manifest_addr, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        log_error("PAL failed at parsing the manifest: %s", errbuf);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_common_state.raw_manifest_data = manifest_addr;
    g_pal_common_state.manifest_root = manifest_root;

    /* parse and store host topology info into g_topo_info struct */
    bool enable_sysfs_topology;     /* TODO: remove this manifest option once sysfs topo is stable */
    ret = toml_bool_in(g_pal_common_state.manifest_root, "fs.experimental__enable_sysfs_topology",
                       /*defaultval=*/false, &enable_sysfs_topology);
    if (ret < 0) {
        log_error("Cannot parse 'fs.experimental__enable_sysfs_topology' (the value must be `true` "
                  "or `false`)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    ret = parse_host_topo_info(uptr_topo_info, enable_sysfs_topology, &g_topo_info);
    if (ret < 0) {
        log_error("Cannot parse host topology info (cores, caches, NUMA nodes): %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    bool preheat_enclave;
    ret = toml_bool_in(g_pal_common_state.manifest_root, "sgx.preheat_enclave",
                       /*defaultval=*/false, &preheat_enclave);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.preheat_enclave' (the value must be `true` or `false`)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    if (preheat_enclave)
        do_preheat_enclave();

    /* For backward compatibility, `loader.pal_internal_mem_size` does not include
     * PAL_INITIAL_MEM_SIZE */
    size_t extra_mem_size;
    ret = toml_sizestring_in(g_pal_common_state.manifest_root, "loader.pal_internal_mem_size",
                             /*defaultval=*/0, &extra_mem_size);
    if (ret < 0) {
        log_error("Cannot parse 'loader.pal_internal_mem_size'");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (extra_mem_size + PAL_INITIAL_MEM_SIZE < g_pal_internal_mem_size) {
        log_error("Too small `loader.pal_internal_mem_size`, need at least %luMB because the "
                  "manifest is large",
                  (g_pal_internal_mem_size - PAL_INITIAL_MEM_SIZE) / 1024 / 1024);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_internal_mem_size = extra_mem_size + PAL_INITIAL_MEM_SIZE;

    if ((ret = init_file_check_policy()) < 0) {
        log_error("Failed to load the file check policy: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_allowed_files()) < 0) {
        log_error("Failed to initialize allowed files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_trusted_files()) < 0) {
        log_error("Failed to initialize trusted files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if ((ret = init_protected_files()) < 0) {
        log_error("Failed to initialize protected files: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* this should be placed *after all* initialize-from-manifest routines */
    if ((ret = print_warnings_on_insecure_configs(!!parent)) < 0) {
        log_error("Cannot parse the manifest (while checking for insecure configurations)");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* set up thread handle */
    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    if (!first_thread) {
        log_error("Out of memory");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    init_handle_hdr(HANDLE_HDR(first_thread), PAL_TYPE_THREAD);
    first_thread->thread.tcs = g_enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    /* child threads are assigned TIDs 2,3,...; see pal_start_thread() */
    first_thread->thread.tid = 1;
    g_pal_control.first_thread = first_thread;
    SET_ENCLAVE_TLS(thread, &first_thread->thread);

    uint64_t stack_protector_canary;
    ret = _DkRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);

    assert(!g_pal_state.enclave_initialized);
    g_pal_state.enclave_initialized = true;

    /* call main function */
    pal_main(instance_id, parent, first_thread, arguments, environments);
}
