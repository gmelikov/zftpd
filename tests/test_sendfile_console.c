/* Run console mount policy on the host; dangerous native calls are counted. */
#include "pal_fileio.h"
#include "pal_network.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static const char *mount_type;
static int mount_error, native_calls, send_error, read_error;
static size_t send_limit;
static size_t read_size;
static int read_calls;

static int mock_fstatfs(int fd, struct statfs *fs) {
  (void)fd;
  if (mount_error) { errno = EIO; return -1; }
  memset(fs, 0, sizeof(*fs));
  (void)snprintf(fs->f_fstypename, sizeof(fs->f_fstypename), "%s", mount_type);
  return 0;
}
static ssize_t mock_pread(int fd, void *data, size_t size, off_t offset) {
  read_calls++;
  read_size = size;
  if (read_error) { errno = read_error; read_error = 0; return -1; }
  return pread(fd, data, size, offset);
}
static ssize_t mock_send(int fd, const void *data, size_t size, int flags) {
  if (send_error) { errno = send_error; send_error = 0; return -1; }
  if (send_limit != 0U && size > send_limit) size = send_limit;
  return send(fd, data, size, flags);
}
#if defined(__APPLE__) && defined(__MACH__)
static int mock_sendfile(int file, int sock, off_t offset, off_t *size,
                         struct sf_hdtr *headers, int flags) {
  (void)file; (void)sock; (void)offset; (void)size; (void)headers; (void)flags;
  native_calls++;
  return 0;
}
#else
static ssize_t mock_sendfile(int sock, int file, off_t *offset, size_t count) {
  (void)sock; (void)file;
  native_calls++;
  *offset += (off_t)count;
  return (ssize_t)count;
}
#endif

#define PLATFORM_PS5 1
#define _fstatfs mock_fstatfs
#define pread mock_pread
#define send mock_send
#define sendfile mock_sendfile
#define pal_sendfile test_sendfile
#define pal_sendfile_retry test_sendfile_retry
ssize_t test_sendfile(int sock_fd, int file_fd, off_t *offset, size_t count);
ssize_t test_sendfile_retry(int sock_fd, int file_fd, off_t *offset, size_t count,
                           unsigned retries, unsigned sleep_us);
#include "../src/platform/fileio/sendfile.c"

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
  return 1; \
} } while (0)

static int check_buffered(int file, int writer, int reader) {
  native_calls = 0;
  off_t offset = 2; /* FTP REST and HTTP Range must retain positional semantics. */
  char actual[16] = {0};
  size_t remaining = 8U;
  while (remaining > 0U) {
    ssize_t n = test_sendfile_retry(writer, file, &offset, remaining, 2U, 0U);
    CHECK(n > 0 && (size_t)n <= remaining);
    remaining -= (size_t)n;
  }
  CHECK(offset == 10 && native_calls == 0);
  CHECK(recv(reader, actual, 8U, MSG_WAITALL) == 8);
  CHECK(memcmp(actual, "23456789", 8U) == 0);
  CHECK(lseek(file, 0, SEEK_CUR) == 0); /* pread leaves file position unchanged */
  return 0;
}

int main(void) {
  char path[] = "/tmp/zftpd-sendfile-XXXXXX";
  int file = mkstemp(path);
  CHECK(file >= 0);
  CHECK(unlink(path) == 0);
  CHECK(write(file, "0123456789abcdef", 16U) == 16);
  CHECK(lseek(file, 0, SEEK_SET) == 0);
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);

  static const char *const unsafe[] = {
      "exfatfs", "exfat", "msdosfs", "nullfs", "pfsmnt", "pfs", ""};
  for (size_t i = 0U; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
    mount_type = unsafe[i];
    CHECK(check_buffered(file, pair[0], pair[1]) == 0);
  }
  mount_type = "ufs"; mount_error = 1;
  CHECK(check_buffered(file, pair[0], pair[1]) == 0);
  mount_error = 0;
  off_t offset = 0;
  CHECK(test_sendfile(pair[0], file, &offset, 4U) == 4);
  CHECK(native_calls == 1 && offset == 4);

  mount_type = "exfatfs";
  send_limit = 3U; send_error = EAGAIN;
  CHECK(check_buffered(file, pair[0], pair[1]) == 0);
  read_error = EINTR;
  CHECK(check_buffered(file, pair[0], pair[1]) == 0);

  offset = 2;
  send_error = EAGAIN;
  CHECK(test_sendfile(pair[0], file, &offset, 4U) == -1);
  CHECK(errno == EAGAIN && offset == 2);
  read_error = EIO;
  read_calls = 0;
  CHECK(test_sendfile_retry(pair[0], file, &offset, 4U, 2U, 0U) == -1);
  CHECK(errno == EIO && offset == 2 && native_calls == 0 && read_calls == 1);
  offset = 0;
  CHECK(test_sendfile(pair[0], file, &offset, (size_t)FTP_BUFFER_SIZE + 1U) == 3);
  CHECK(read_size == (size_t)FTP_BUFFER_SIZE && offset == 3);
  char prefix[3];
  CHECK(recv(pair[1], prefix, sizeof(prefix), MSG_WAITALL) == 3);
  CHECK(memcmp(prefix, "012", sizeof(prefix)) == 0);
  offset = 16;
  errno = EAGAIN;
  CHECK(test_sendfile_retry(pair[0], file, &offset, 4U, 2U, 0U) == 0);
  CHECK(offset == 16 && native_calls == 0);
  CHECK(test_sendfile(pair[0], file, NULL, 4U) == -1 && errno == EINVAL);
  CHECK(close(file) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("test_sendfile_console: ok");
  return 0;
}
