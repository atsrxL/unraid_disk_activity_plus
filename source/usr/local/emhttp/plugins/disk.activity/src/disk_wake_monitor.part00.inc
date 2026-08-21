#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
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
#define MAX_OPEN_FILES 512
#define MAX_OPEN_IDENTITIES 512
#define STR_SMALL 128
#define STR_MED 512
#define STR_PATH 4096
#define IO_SAMPLE_MS 250
#define OPEN_FILES_SAMPLE_MS 5000
#define PRE_IO_CORRELATION_MS 2000
#define HISTORY_PRUNE_INTERVAL_MS (24LL * 60LL * 60LL * 1000LL)
#define DEFAULT_HISTORY_DAYS 90
#define DEFAULT_HISTORY_MAX 20000

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
    char evidence[32];
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
    int ambiguous_count;
    candidate_t recent_event;
    candidate_t candidate;
} device_t;

typedef struct {
    pid_t pid;
    int fd_num;
    char process[STR_SMALL];
    char exe[STR_MED];
    char container_id[128];
    char container[256];
    char device[64];
    char disk[STR_SMALL];
    char path[STR_PATH];
} open_file_t;

typedef struct {
    char id[128];
    char name[256];
} container_cache_t;

static volatile sig_atomic_t running = 1;
static device_t devices[MAX_DEVICES];
static int device_count = 0;
static char unique_mounts[MAX_UNIQUE_MOUNTS][STR_PATH];
static int unique_mount_count = 0;
static container_cache_t container_cache[128];
static int container_cache_count = 0;

static char map_file[STR_PATH] = "/var/local/emhttp/disk_wake_devices.tsv";
static char history_file[STR_PATH] = "/boot/config/plugins/disk.activity/wake-history.jsonl";
static char state_file[STR_PATH] = "/var/local/emhttp/disk_wake_state.json";
static char open_files_file[STR_PATH] = "/var/local/emhttp/disk_open_files.json";
static char cfg_file[STR_PATH] = "/boot/config/plugins/disk.activity/disk.activity.cfg";
static int poll_seconds = 10;
static int tracking_enabled = 1;
static int open_files_enabled = 1;
static int open_files_limit = 100;
static int history_days = DEFAULT_HISTORY_DAYS;
static int history_max = DEFAULT_HISTORY_MAX;
static int verbose = 0;
static int trace_events = 0;
static char wake_detector[24] = "auto";
static char test_open_fds_dev[64] = "";

static int find_device(const char *dev);
static void get_container_id(pid_t pid, char *out, size_t outsz);
static void resolve_container_name(const char *id, char *out, size_t outsz);

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
