/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <stdio.h>
#include <string.h>

#include "generated-offsets-build.h"

static void print_usage(const char* prog) {
    fprintf(stderr, "usage: %s [--h|--py]\n", prog);
}

static void print_offsets_h(void) {
    printf("/* DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED. */\n");
    printf("#ifndef %s_ASM_OFFSETS_H_\n", generated_offsets_name);
    printf("#define %s_ASM_OFFSETS_H_\n", generated_offsets_name);
    printf("\n");

    const struct generated_offset* gen;
    for (gen = &generated_offsets[0]; gen->name; gen++) {
        printf("#ifndef %s\n", gen->name);
        printf("#define %s %zu\n", gen->name, gen->offset);
        printf("#endif\n");
    }

    printf("\n");
    printf("#endif /* %s_ASM_OFFSETS_H_ */\n", generated_offsets_name);
}

static void print_offsets_py(void) {
    printf("# DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED.\n");
    printf("\n");

    const struct generated_offset* gen;
    for (gen = &generated_offsets[0]; gen->name; gen++) {
        printf("%s = %zu\n", gen->name, gen->offset);
    }
}

int main(int argc, const char** argv) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "--h")) {
        print_offsets_h();
    } else if (!strcmp(argv[1], "--py")) {
        print_offsets_py();
    } else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}
