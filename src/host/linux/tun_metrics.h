#ifndef QLINQ_TUN_METRICS_H
#define QLINQ_TUN_METRICS_H

#include <stdbool.h>
#include <stddef.h>

/* format a bounded status reply; caller owns the returned buffer */
char *tm_format(const char *name, const char *reply, size_t *size);
/* atomically replace a textfile; leave the previous file intact on failure */
bool tm_write_file(const char *path, const char *text, size_t size);

#endif
