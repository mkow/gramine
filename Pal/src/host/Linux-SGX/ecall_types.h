/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#ifndef ECALL_TYPES_H
#define ECALL_TYPES_H

#include <stddef.h>

#include "topology.h"
#include "sgx_arch.h"

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_THREAD_RESET,
    ECALL_NR,
};

struct rpc_queue;

typedef struct {
    char*                 ms_libpal_uri;
    size_t                ms_libpal_uri_len;
    char*                 ms_args;
    size_t                ms_args_size;
    char*                 ms_env;
    size_t                ms_env_size;
    int                   ms_parent_stream_fd;
    int                   ms_host_euid;
    int                   ms_host_egid;
    sgx_target_info_t*    ms_qe_targetinfo;
    PAL_TOPO_INFO*        ms_topo_info;
    struct rpc_queue*     rpc_queue; /* pointer to RPC queue in untrusted mem */
} ms_ecall_enclave_start_t;

#endif /* ECALL_TYPES_H */
