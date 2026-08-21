#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <dirent.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#define MAX_DEVICES 64
#define MAX_MOUNTS_PER_DEVICE 64
#define MAX_UNIQUE_MOUNTS 256
#define STR_SMALL 128
#define STR_MED 512
#define STR_PATH 4096
#define IO_SAMPLE_MS 250
#define PRE_IO_CORRELATION_MS 2000

typedef enum { PWR_UNKNOWN = 0, PWR_STANDBY = 1, PWR_ACTIVE = 2 } power_state_t;

typedef struct {
    int valid;
    int64_t ts_ms;
    pid_t pid;
    char event[24];
    char comm[STR_SMALL];
    char exe[STR_MED];
    char path[STR_PATH];
    char container_id[128];
    char container[256];
    char confidence[16];
    char evidence[24];
} candidate_t;

typedef struct {
    char dev[64];
    char name[STR_SMALL];
    char mounts[MAX_MOUNTS_PER_DEVICE][STR_PATH];
    dev_t mount_dev_ids[MAX_MOUNTS_PER_DEVICE];
    int mount_count;
    power_state_t state;
    int64_t standby_observed_ms;
    int64_t last_wake_ms;
    uint64_t prev_io_ticks;
    int io_initialized;
    int io_pending;
    int64_t io_onset_ms;
    candidate_t recent_event;
    candidate_t candidate;
} device_t;

static volatile sig_atomic_t running = 1;
static device_t devices[MAX_DEVICES];
static int device_count = 0;
static char unique_mounts[MAX_UNIQUE_MOUNTS][STR_PATH];
static int unique_mount_count = 0;

static char map_file[STR_PATH] = "/var/local/emhttp/disk_wake_devices.tsv";
static char history_file[STR_PATH] = "/boot/config/plugins/disk.activity/wake-history.jsonl";
static char state_file[STR_PATH] = "/var/local/emhttp/disk_wake_state.json";
static char cfg_file[STR_PATH] = "/boot/config/plugins/disk.activity/disk.activity.cfg";
static int poll_seconds = 10;
static int tracking_enabled = 1;
static int verbose = 0;
static int trace_events = 0;
static char wake_detector[24] = "auto";
static char test_open_fds_dev[64] = "";

static int find_device(const char *dev);

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static const char *state_name(power_state_t s) {
    switch (s) {
        case PWR_STANDBY: return "standby";
        case PWR_ACTIVE: return "active";
        default: return "unknown";
    }
}

static void trim(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void json_escape(FILE *f, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '\\': fputs("\\\\", f); break;
            case '"':  fputs("\\\"", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (*p < 0x20) fprintf(f, "\\u%04x", *p);
                else fputc(*p, f);
        }
    }
}

static void read_proc_text(pid_t pid, const char *leaf, char *out, size_t outsz) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, leaf);
    FILE *fp = fopen(path, "r");
    if (!fp) { out[0] = '\0'; return; }
    if (!fgets(out, (int)outsz, fp)) out[0] = '\0';
    fclose(fp);
    trim(out);
}

static void read_proc_exe(pid_t pid, char *out, size_t outsz) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, out, outsz - 1);
    if (n < 0) out[0] = '\0';
    else out[n] = '\0';
}

static int extract_hex_id(const char *s, char *out, size_t outsz) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        size_t j = i;
        while (j < n && isxdigit((unsigned char)s[j])) j++;
        size_t run = j - i;
        if (run >= 64) {
            size_t copy = 64;
            if (copy >= outsz) copy = outsz - 1;
            memcpy(out, s + i, copy);
            out[copy] = '\0';
            return 1;
        }
        if (j > i) i = j - 1;
    }
    return 0;
}

static void get_container_id(pid_t pid, char *out, size_t outsz) {
    out[0] = '\0';
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
