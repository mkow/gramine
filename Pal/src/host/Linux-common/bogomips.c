#include "api.h"
#include "linux_utils.h"
#include "pal_internal.h"
#include "topo_info.h"

/* This version is too dumb to be shared by the whole repository and should be removed once we get
 * a proper stdlib (like musl). */
static double proc_cpuinfo_atod(const char* s) {
    double ret = 0.0;
    char* end = NULL;
    double base, fractional;

    base = strtol(s, &end, 10);

    if (*end == '.') {
        s = end + 1;
        fractional = strtol(s, &end, 10);
        while (s != end) {
            fractional /= 10.0;
            s++;
        }
        ret = base + fractional;
    }

    return ret;
}

static double sanitize_bogomips_value(double v) {
    if (!__builtin_isnormal(v) || v < 0.0) {
        return 0.0;
    }
    return v;
}

static int parse_line(const char* line, void* arg, bool* out_stop) {
    double* res = (double*)arg;
    *out_stop = false;

    if (!strstartswith(line, "bogomips"))
        return 0;

    size_t pos = 0;
    for (; line[pos] && line[pos + 1]; pos++) {
        if (line[pos] == ':' && line[pos + 1] == ' ') {
            *res = proc_cpuinfo_atod(line + pos + 2);
            *out_stop = true;
            return 0;
        }
    }
    return -1; /* incorrect/unsupported format? */
}

double _DkGetBogomips(void) {
    double bogomips;
    int ret = read_text_file_iter_lines("/proc/cpuinfo", parse_line, &bogomips);
    if (ret < 0)
        return 0.0;
    return sanitize_bogomips_value(bogomips);
}
