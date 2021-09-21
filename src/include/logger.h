#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

typedef enum {
    LOG_ERROR=0,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG,
    LOG_VERBOSE
} loglevel_t;


void log_printf(loglevel_t loglevel, char *fmt, ...);

void log_open_file(char *filename);
void log_close_file();

#endif // LOGGER_H
