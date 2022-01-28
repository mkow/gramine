/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "bitmap.h"

#include <errno.h>

#include "api.h"

void bitmap_init(struct bitmap* bitmap) {
    bitmap->buckets_cnt = 0;
}

struct bitmap* bitmap_create(void) {
    struct bitmap* res = malloc(sizeof(*res));
    if (res)
        bitmap_init(res);
    return res;
}

#define BITS_PER_BUCKET  (sizeof(_bitmap_bucket_t) * 8)
#define BIT_SIZE(bitmap) ((bitmap)->buckets_cnt * BITS_PER_BUCKET)

int bitmap_set(struct bitmap* bitmap, size_t pos) {
    if (pos >= BIT_SIZE(bitmap)) {
        /* Grow bitmap */
        // TODO: change to realloc once we have it
        size_t new_buckets_cnt = UDIV_ROUND_UP(pos + 1, BITS_PER_BUCKET);
        _bitmap_bucket_t* new_buf = malloc(new_buckets_cnt * sizeof(_bitmap_bucket_t));
        if (!new_buf)
            return -ENOMEM;
        memcpy(new_buf, bitmap->buckets, bitmap->buckets_cnt * sizeof(_bitmap_bucket_t));
        memset(new_buf + bitmap->buckets_cnt * sizeof(_bitmap_bucket_t), 0,
               (new_buckets_cnt - bitmap->buckets_cnt) * sizeof(_bitmap_bucket_t));
        bitmap->buckets_cnt = new_buckets_cnt;
        bitmap->buckets = new_buf;
    }
    bitmap->buckets[pos / BITS_PER_BUCKET] |= (_bitmap_bucket_t)1 << (pos % BITS_PER_BUCKET);
    return 0;
}

void bitmap_unset(struct bitmap* bitmap, size_t pos) {
    if (pos < BIT_SIZE(bitmap))
        bitmap->buckets[pos / BITS_PER_BUCKET] &= ~((_bitmap_bucket_t)1 << (pos % BITS_PER_BUCKET));
}

bool bitmap_get(const struct bitmap* bitmap, size_t pos) {
    return pos < BIT_SIZE(bitmap)
        && ((bitmap->buckets[pos / BITS_PER_BUCKET] >> pos % BITS_PER_BUCKET) & 1);
}

size_t bitmap_get_end(const struct bitmap* bitmap) {
    size_t res = 0;
    for (size_t i = 0; i < bitmap->buckets_cnt * BITS_PER_BUCKET; i++) {
        if (bitmap_get(bitmap, i))
            res = i + 1;
    }
    return res;
}

/* Iterates over bits which are `true`. */
int bitmap_iterate(const struct bitmap* bitmap, int (*callback)(size_t pos, void* arg),
                   void* callback_arg) {
    for (size_t i = 0; i < bitmap->buckets_cnt * BITS_PER_BUCKET; i++) {
        if (bitmap_get(bitmap, i)) {
            int ret = callback(i, callback_arg);
            if (ret < 0)
                return ret;
        }
    }
    return 0;
}
