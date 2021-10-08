#ifndef GENERATED_OFFSETS_BUILD_H
#define GENERATED_OFFSETS_BUILD_H

#include <stddef.h>

struct generated_offset {
    const char* name;
    size_t offset;
};

extern const struct generated_offset generated_offsets[];
extern const char* generated_offsets_name;

#define DEFINE(name, value) { #name, value }

#define OFFSET(name, str, member)     DEFINE(name, offsetof(struct str, member))
#define OFFSET_T(name, str_t, member) DEFINE(name, offsetof(str_t, member))

#define OFFSET_END { NULL, 0 }

#endif /* GENERATED_OFFSETS_BUILD_H */
