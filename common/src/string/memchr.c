/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "api.h"

void* memchr(const void* s, int c, size_t n) {
    const unsigned char* end = (const unsigned char*)s + n;
    for (const unsigned char* cur = s; cur < end; cur++) {
        if (*cur == c)
            return (void*)cur;
    }
    return NULL;
}
