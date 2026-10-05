/* Minimal console process record for the host-side instance control tests. */
#ifndef ZFTPD_TEST_SYS_USER_H
#define ZFTPD_TEST_SYS_USER_H
#include <sys/types.h>
struct kinfo_proc {
  int ki_structsize;
  unsigned char padding[68];
  pid_t ki_pid;
  unsigned char ki_stat;
  unsigned char tail[391];
};
#endif
