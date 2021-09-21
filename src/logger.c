#include "logger.h"

#include <errno.h>
#include <string.h>

loglevel_t g_loglevel = LOG_INFO;
FILE *logfile = NULL;

void log_printf(loglevel_t loglevel, char *fmt, ...) {
    va_list arg_ptr;
    va_list f_arg_ptr;

    va_start(arg_ptr, fmt);
    va_copy(f_arg_ptr, arg_ptr);

    if (loglevel == LOG_ERROR) {
        vfprintf(stderr, fmt, arg_ptr);
        if (logfile) vfprintf(logfile, fmt, f_arg_ptr);
    } else if ( loglevel <= g_loglevel ) {
        vprintf(fmt, arg_ptr);
        if (logfile) vfprintf(logfile, fmt, f_arg_ptr);
    }

    va_end(f_arg_ptr);
    va_end(arg_ptr);
}

void log_open_file(char *filename) {
    logfile = fopen(filename, "w+");
    if (!logfile)
        printf("File opening error: %s \r\n", strerror(errno));
}

void log_close_file() {
    if (logfile)
        fclose(logfile);
}
