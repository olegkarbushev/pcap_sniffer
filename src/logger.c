#include "logger.h"

loglevel_t g_loglevel = LOG_INFO;

void log_printf(loglevel_t loglevel, char *fmt, ...) {
    va_list arg_ptr;

    va_start(arg_ptr, fmt);

    if (loglevel == LOG_ERROR) {
        vfprintf(stderr, fmt, arg_ptr);
    } else if ( loglevel <= g_loglevel ) {
        vprintf(fmt, arg_ptr);
    }

    va_end(arg_ptr);
}
