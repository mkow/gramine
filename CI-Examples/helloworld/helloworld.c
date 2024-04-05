/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <err.h>

#define REPORT_SIZE 432

int main(void) {
    FILE* f = fopen("/dev/attestation/report", "rb");
    if (!f)
        err(1, "fopen");
    char buf[REPORT_SIZE];
    // for (int i=0; i<3; i++){
    // while (1) {
    if (fread(buf, REPORT_SIZE, 1, f) != 1)
        err(1, "fread");
        // rewind(f);
        // fwrite(buf, REPORT_SIZE, 1, stdout);
    // }
    return 0;
}
