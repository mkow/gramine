
#include "api.h"
#include "callbacks.h"

void default_describe_location(void* ip, char* buf, size_t buf_size) {
    snprintf(buf, buf_size, "%p", ip);
}

void describe_location(void* ip, char* buf, size_t buf_size)
    __attribute__((weak, alias("default_describe_location")));
