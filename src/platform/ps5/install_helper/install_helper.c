/*
 * Installer helper for PS5.
 *
 * The system installer API is not usable from a payload process, so this small
 * program is delivered to elfldr on 127.0.0.1:9021 and drives the installation
 * itself.  It connects back to zftpd on a loopback port, receives one request
 * and reports the outcome.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ps5/kernel.h>

#define IPC_PORT 39481
#define REQUEST_MAX 2048
#define SHELLCORE_AUTHID 0x4800000000000006ULL

typedef struct {
  const char *uri;
  const char *ex_uri;
  const char *playgo_scenario_id;
  const char *content_id;
  const char *content_name;
  const char *icon_url;
} pkg_metadata_t;

typedef struct {
  char content_id[0x30];
  int content_type;
  int content_platform;
} pkg_info_t;

typedef struct {
  char languages[30][8];
  char playgo_scenario_ids[64][3];
  char content_ids[64][0x30];
  unsigned char reserved[6480];
} playgo_info_t;

typedef struct {
  int32_t error_code;
  int32_t version;
  char description[512];
  char type[9];
} install_error_info_t;

typedef struct {
  char status[16];
  char src_type[8];
  uint32_t remain_time;
  uint64_t downloaded_size;
  uint64_t initial_chunk_size;
  uint64_t total_size;
  uint32_t promote_progress;
  install_error_info_t error_info;
  int32_t local_copy_percent;
  uint8_t is_copy_only;
} install_status_t;

#if defined(__PROSPERO__) || defined(PLATFORM_PS5)
extern int sceAppInstUtilInitialize(void);
extern int sceAppInstUtilAppUnInstall(const char *title_id, int *, int *);
extern int sceAppInstUtilTerminate(void);
extern int sceAppInstUtilInstallByPackage(const pkg_metadata_t *, pkg_info_t *,
                                          playgo_info_t *);
extern int sceAppInstUtilGetInstallStatus(const char *, install_status_t *);
#endif

static int connect_back(void) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(IPC_PORT);
  if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    return -1;
  }

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = 10;
  tv.tv_usec = 0;
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    (void)close(fd);
    return -1;
  }

  return fd;
}

static void send_line(int fd, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void send_line(int fd, const char *format, ...) {
  char line[512];
  va_list args;
  va_start(args, format);
  int n = vsnprintf(line, sizeof(line) - 2, format, args);
  va_end(args);
  if (n < 0) {
    return;
  }
  if ((size_t)n > sizeof(line) - 2) {
    n = (int)(sizeof(line) - 2);
  }
  line[n] = '\n';
  line[n + 1] = '\0';
  (void)send(fd, line, (size_t)n + 1, 0);
}

static int read_line(int fd, char *out, size_t out_size) {
  size_t used = 0;
  while (used + 1U < out_size) {
    char ch = '\0';
    ssize_t got = recv(fd, &ch, 1, 0);
    if (got <= 0) {
      return -1;
    }
    if (ch == '\n') {
      break;
    }
    out[used++] = ch;
  }
  out[used] = '\0';
  return 0;
}

int main(void) {
#if defined(__PROSPERO__) || defined(PLATFORM_PS5)
  /* Escalate to the SYSTEM_PROCESS auth id (what etaHEN's DPI uses) so the
   * installer/uninstall API's privilege check passes. The SDK's
   * kernel_set_ucred_authid uses a stale double-indirection layout on 13.60,
   * so write cr_sceAuthID at ucred+0x58 directly via kernel_copyin. */
  {
    intptr_t ucred = kernel_get_proc_ucred(getpid());
    if (ucred != 0) {
      uint64_t authid = SHELLCORE_AUTHID;
      (void)kernel_copyin(&authid, ucred + 0x58, 8); /* cr_sceAuthID */
    }
  }
#endif

  int fd = connect_back();
  if (fd < 0) {
    return 1;
  }

  char line[REQUEST_MAX];
  for (;;) {
    if (read_line(fd, line, sizeof(line)) != 0) {
      break;
    }

    char kind[16] = {0};
    char destination[24] = {0};
    char url[REQUEST_MAX] = {0};
    int overwrite = 0;
    char *first = strchr(line, ' ');
    char *second = first != NULL ? strchr(first + 1, ' ') : NULL;
    char *last = second != NULL ? strrchr(second + 1, ' ') : NULL;
    if (first == NULL || second == NULL || last == NULL ||
        first == line || second == first + 1 || last == second + 1 ||
        strlen(last + 1) != 1U || (last[1] != '0' && last[1] != '1') ||
        (size_t)(first - line) >= sizeof(kind) ||
        (size_t)(second - first - 1) >= sizeof(destination) ||
        (size_t)(last - second - 1) >= sizeof(url)) {
      send_line(fd, "ERROR 0 bad request");
      continue;
    }
    memcpy(kind, line, (size_t)(first - line));
    memcpy(destination, first + 1, (size_t)(second - first - 1));
    memcpy(url, second + 1, (size_t)(last - second - 1));
    overwrite = last[1] == '1';

    if (strcmp(kind, "INSTALL") != 0 && strcmp(kind, "UNINSTALL") != 0) {
      send_line(fd, "ERROR 0 unknown request");
      continue;
    }

    if (strcmp(kind, "UNINSTALL") == 0) {
      if (destination[0] == '\0') {
        send_line(fd, "ERROR 0 bad request");
        continue;
      }
      int init_rc = sceAppInstUtilInitialize();
      if (init_rc != 0) {
        send_line(fd, "ERROR 0x%08X installer init", (unsigned)init_rc);
        continue;
      }
      int rc = sceAppInstUtilAppUnInstall(destination, NULL, NULL);
      if (rc < 0) {
        send_line(fd, "ERROR 0x%08X uninstall", (unsigned)rc);
      } else {
        send_line(fd, "DONE 0");
      }
      break;
    }

    int init_rc = sceAppInstUtilInitialize();
    if (init_rc != 0) {
      send_line(fd, "ERROR 0x%08X installer init", (unsigned)init_rc);
      continue;
    }

    pkg_metadata_t metadata;
    memset(&metadata, 0, sizeof(metadata));
    metadata.uri = url;
    metadata.ex_uri = "";
    metadata.content_id = "";
    metadata.content_name = "zftpd";
    metadata.playgo_scenario_id = "";
    metadata.icon_url = "";

    pkg_info_t pkg_info;
    playgo_info_t playgo_info;
    memset(&pkg_info, 0, sizeof(pkg_info));
    memset(&playgo_info, 0, sizeof(playgo_info));

    send_line(fd, "STATE installing");
    int result = sceAppInstUtilInstallByPackage(&metadata, &pkg_info, &playgo_info);
    (void)overwrite;
    (void)destination;

    if (result != 0) {
      send_line(fd, "ERROR 0x%08X install request", (unsigned)result);
      continue;
    }

    if (pkg_info.content_id[0] == '\0') {
      send_line(fd, "ERROR 0 installer returned no content id");
      continue;
    }
    pkg_info.content_id[sizeof(pkg_info.content_id) - 1U] = '\0';

    int completed = 0;
    int reported_error = 0;
    for (int step = 0; step < 3600; step++) {
      install_status_t status;
      memset(&status, 0, sizeof(status));
      int status_rc = sceAppInstUtilGetInstallStatus(pkg_info.content_id, &status);
      if (status_rc == 0) {
        status.status[sizeof(status.status) - 1U] = '\0';
        if (status.error_info.error_code != 0) {
          send_line(fd, "ERROR 0x%08X installer status",
                    (unsigned)status.error_info.error_code);
          reported_error = 1;
          break;
        }
        unsigned long total = (unsigned long)status.total_size;
        unsigned long done = (unsigned long)status.downloaded_size;
        int percent = total > 0UL ? (int)((done * 100UL) / total) :
                      (int)status.promote_progress;
        if (percent > 100) percent = 100;
        if (percent < 0) percent = 0;
        send_line(fd, "PROGRESS %d %lu %lu", percent, done, total);
        if (strcmp(status.status, "playable") == 0 ||
            strcmp(status.status, "completed") == 0 ||
            strcmp(status.status, "installed") == 0) {
          send_line(fd, "DONE 0");
          completed = 1;
          break;
        }
      } else if (step > 15) {
        send_line(fd, "ERROR 0x%08X installer status unavailable",
                  (unsigned)status_rc);
        reported_error = 1;
        break;
      }
      usleep(2000000);
    }
    if (!completed && !reported_error)
      send_line(fd, "ERROR 0 install did not complete before timeout");
    (void)sceAppInstUtilTerminate();
    break;
  }

  (void)close(fd);
  return 0;
}
