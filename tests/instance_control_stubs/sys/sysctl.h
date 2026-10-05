#ifndef ZFTPD_TEST_SYS_SYSCTL_H
#define ZFTPD_TEST_SYS_SYSCTL_H
#include <stddef.h>
int sysctl(const int *name, unsigned int count, void *out, size_t *size,
           const void *value, size_t value_size);
#endif
