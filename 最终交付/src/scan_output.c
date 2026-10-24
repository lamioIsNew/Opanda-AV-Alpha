#include "scan_output.h"

#include <stdio.h>
#include <stdarg.h>

static int g_scan_out_enabled = 1;

void scan_out_set_enabled(int enabled) {
    g_scan_out_enabled = enabled ? 1 : 0;
}

int scan_out_enabled(void) {
    return g_scan_out_enabled;
}

void scan_out(const char *fmt, ...) {
    va_list ap;
    if (!g_scan_out_enabled || !fmt) return;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}
