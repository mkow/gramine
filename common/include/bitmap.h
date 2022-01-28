/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#ifndef BITMAP_H
#define BITMAP_H

/* Emulates a bitmap, potentially infinite. All unset bits are `false` (the indices may exceed the
 * allocated/set range).
 *
 * Does _not_ downscale used memory after unsetting bits.
 */

#include <stdbool.h>
#include <stddef.h>

typedef size_t _bitmap_bucket_t; /* Should be useful only to the code in bitmap.c. */

struct bitmap {
    size_t buckets_cnt;
    _bitmap_bucket_t* buckets;
};

struct bitmap* bitmap_create(void);
void bitmap_init(struct bitmap* bitmap);
/* careful: may fail! (and return -ENOMEM) */
int bitmap_set(struct bitmap* bitmap, size_t pos);
void bitmap_unset(struct bitmap* bitmap, size_t pos);
bool bitmap_get(const struct bitmap* bitmap, size_t pos);
size_t bitmap_get_end(const struct bitmap* bitmap);
/* Iterates over bits which are `true`. Can fail only if the callback failed. */
int bitmap_iterate(const struct bitmap* bitmap, int (*callback)(size_t pos, void* arg),
                   void* callback_arg);

#endif /* BITMAP_H */
