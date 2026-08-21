#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
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
#define MAX_OPEN_FILES 500
#define MAX_OPEN_IDENTITIES 512
#define MAX_CONTAINER_CACHE 256
#define MAX_USER_SHARE_EVENTS 32
#define MAX_DIRECT_EVENTS 32
#define STR_SMALL 128
#define STR_MED 512
#define STR_PATH 4096
#define IO_SAMPLE_MS 250
#define OPEN_FILES_SAMPLE_MS 5000
#define PRE_IO_CORRELATION_MS 2000
#define HISTORY_PRUNE_INTERVAL_MS (24LL * 60LL * 60LL * 1000LL)
#define HISTORY_DAYS 60
#define HISTORY_MAX 5000
#define CONTAINER_CACHE_TTL_MS (10LL * 60LL * 1000LL)
#define CONTAINER_CACHE_NEGATIVE_TTL_MS (30LL * 1000LL)
#define CONTAINER_INSPECT_TIMEOUT_MS 1000
#define SMARTCTL_TIMEOUT_MS 1500
#define CHILD_TERM_GRACE_MS 200
#define CHILD_KILL_REAP_GRACE_MS 200
#ifndef MAX_PENDING_CHILDREN
#define MAX_PENDING_CHILDREN 256
#endif
#define OPEN_FD_ATTRIBUTION_BUDGET_MS 250
#define OPEN_FD_ATTRIBUTION_CYCLE_BUDGET_MS 500
#define OPEN_FD_ATTRIBUTION_MAX_PIDS 4096
#define OPEN_FD_ATTRIBUTION_MAX_FDS 32768
#define OPEN_FILES_SCAN_BUDGET_MS 1000
#define OPEN_FILES_SCAN_MAX_PIDS 8192
#define OPEN_FILES_SCAN_MAX_FDS 65536
#define POWER_CHECK_BUDGET_MS 3000
#define FANOTIFY_PROCESS_BUDGET_MS 100
#define FANOTIFY_PROCESS_MAX_EVENTS 4096

#ifndef DAP_VERSION
#define DAP_VERSION "dev"
#endif

typedef enum { PWR_UNKNOWN = 0, PWR_STANDBY = 1, PWR_ACTIVE = 2 } power_state_t;

typedef struct {
    int valid;
    int64_t ts_ms;
    int64_t mono_ms;
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
    int64_t io_onset_mono_ms;
    int ambiguous_count;
    char uncertain_evidence[32];
    candidate_t recent_events[MAX_DIRECT_EVENTS];
    int recent_event_count;
    int64_t recent_event_overflow_mono_ms;
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
    int64_t expires_ms;
    int64_t last_used_ms;
} container_cache_t;

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_requested = 0;
static device_t devices[MAX_DEVICES];
static int device_count = 0;
static char unique_mounts[MAX_UNIQUE_MOUNTS][STR_PATH];
static int unique_mount_count = 0;
static container_cache_t container_cache[MAX_CONTAINER_CACHE];
static int container_cache_count = 0;
static candidate_t user_share_events[MAX_USER_SHARE_EVENTS];
static int user_share_event_count = 0;
static int64_t user_share_overflow_mono_ms = 0;
static int64_t fanotify_poisoned_until_mono_ms = 0;
static int64_t open_fd_cycle_deadline_mono_ms = 0;
static int64_t container_command_deadline_mono_ms = 0;
static pid_t pending_children[MAX_PENDING_CHILDREN];
static int pending_child_count = 0;

static char map_file[STR_PATH] = "/var/local/emhttp/disk_wake_devices.tsv";
static char history_file[STR_PATH] = "/boot/config/plugins/disk.activity/wake-history.jsonl";
static char history_lock_file[STR_PATH] = "/var/lock/disk_activity_plus_history.lock";
static char state_file[STR_PATH] = "/var/local/emhttp/disk_wake_state.json";
static char open_files_file[STR_PATH] = "/var/local/emhttp/disk_open_files.json";
static char cfg_file[STR_PATH] = "/boot/config/plugins/disk.activity/disk.activity.cfg";
static int poll_seconds = 10;
static int tracking_enabled = 1;
static int open_files_limit = 100;
static int verbose = 0;
static int trace_events = 0;
static char wake_detector[24] = "auto";
static char test_open_fds_dev[64] = "";

static int find_device(const char *dev);
static void get_container_id(pid_t pid, char *out, size_t outsz);
static void resolve_container_name(const char *id, char *out, size_t outsz);

static void on_term_signal(int sig) {
    (void)sig;
    running = 0;
}

static void on_hup_signal(int sig) {
    (void)sig;
    reload_requested = 1;
}

static int64_t clock_ms(clockid_t clock_id) {
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int64_t realtime_ms(void) {
    return clock_ms(CLOCK_REALTIME);
}

static int64_t monotonic_ms(void) {
    return clock_ms(CLOCK_MONOTONIC);
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
            case '"': fputs("\\\"", f); break;
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

static int strict_container_id(const char *id) {
    if (!id || strlen(id) != 64) return 0;
    for (const unsigned char *p = (const unsigned char *)id; *p; p++) {
        if (!isxdigit(*p)) return 0;
    }
    return 1;
}

static void get_container_id(pid_t pid, char *out, size_t outsz) {
    out[0] = '\0';
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (extract_hex_id(line, out, outsz)) break;
    }
    fclose(fp);
    if (!strict_container_id(out)) out[0] = '\0';
}

static void reap_pending_children(void) {
    int keep = 0;
    for (int i = 0; i < pending_child_count; i++) {
        int status = 0;
        pid_t child = pending_children[i];
        pid_t rc = waitpid(child, &status, WNOHANG);
        if (rc == child || (rc < 0 && errno == ECHILD)) continue;
        pending_children[keep++] = child;
    }
    pending_child_count = keep;
}

static void remember_pending_child(pid_t child) {
    reap_pending_children();
    for (int i = 0; i < pending_child_count; i++) {
        if (pending_children[i] == child) return;
    }
    if (pending_child_count < MAX_PENDING_CHILDREN) {
        pending_children[pending_child_count++] = child;
    } else {
        fprintf(stderr, "pending child reap queue full; pid=%d remains owned by monitor\n", child);
    }
}

static void terminate_and_reap(pid_t child) {
    int status = 0;
    pid_t rc = waitpid(child, &status, WNOHANG);
    if (rc == child || (rc < 0 && errno == ECHILD)) return;

    (void)kill(child, SIGTERM);
    int64_t deadline = monotonic_ms() + CHILD_TERM_GRACE_MS;
    while (monotonic_ms() < deadline) {
        rc = waitpid(child, &status, WNOHANG);
        if (rc == child || (rc < 0 && errno == ECHILD)) return;
        if (rc < 0 && errno != EINTR) break;
        (void)poll(NULL, 0, 20);
    }

    (void)kill(child, SIGKILL);
    deadline = monotonic_ms() + CHILD_KILL_REAP_GRACE_MS;
    while (monotonic_ms() < deadline) {
        rc = waitpid(child, &status, WNOHANG);
        if (rc == child || (rc < 0 && errno == ECHILD)) return;
        if (rc < 0 && errno != EINTR) break;
        (void)poll(NULL, 0, 20);
    }
    remember_pending_child(child);
}

static int run_command_capture(char *const argv[], int merge_stderr, int require_zero,
                               int timeout_ms, char *out, size_t outsz) {
    if (!argv || !argv[0] || !out || outsz == 0) return 0;
    reap_pending_children();
    out[0] = '\0';
    if (pending_child_count >= MAX_PENDING_CHILDREN) {
        fprintf(stderr, "pending child reap queue full; external command suppressed\n");
        return 0;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return 0;
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }
    if (child == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        (void)setenv("LC_ALL", "C", 1);
        int nullfd = -1;
        if (!merge_stderr) nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        if (merge_stderr) {
            if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(126);
        } else if (nullfd >= 0 && dup2(nullfd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(pipefd[0]);
        close(pipefd[1]);
        if (nullfd > STDERR_FILENO) close(nullfd);
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t used = 0;
    int status = 0;
    int child_done = 0;
    int wait_error = 0;
    int timed_out = 0;
    int64_t deadline = monotonic_ms() + timeout_ms;

    while (!child_done) {
        char chunk[1024];
        ssize_t n;
        while ((n = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
            size_t copy = (size_t)n;
            if (copy > outsz - 1 - used) copy = outsz - 1 - used;
            if (copy) {
                memcpy(out + used, chunk, copy);
                used += copy;
                out[used] = '\0';
            }
        }

        pid_t rc = waitpid(child, &status, WNOHANG);
        if (rc == child) {
            child_done = 1;
            break;
        }
        if (rc < 0 && errno != EINTR) {
            wait_error = 1;
            child_done = 1;
            break;
        }

        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0 || !running) {
            timed_out = 1;
            break;
        }
        int wait_ms = remaining > 50 ? 50 : (int)remaining;
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        (void)poll(&pfd, 1, wait_ms);
    }

    if (!child_done) terminate_and_reap(child);

    char chunk[1024];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
        size_t copy = (size_t)n;
        if (copy > outsz - 1 - used) copy = outsz - 1 - used;
        if (copy) {
            memcpy(out + used, chunk, copy);
            used += copy;
            out[used] = '\0';
        }
    }
    close(pipefd[0]);

    if (timed_out || wait_error || !child_done || !WIFEXITED(status) ||
        (require_zero && WEXITSTATUS(status) != 0)) {
        out[0] = '\0';
        return 0;
    }
    trim(out);
    return out[0] != '\0';
}

static int inspect_container_runtime(const char *runtime, const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!strict_container_id(id)) return 0;
    int timeout_ms = CONTAINER_INSPECT_TIMEOUT_MS;
    if (container_command_deadline_mono_ms > 0) {
        int64_t remaining = container_command_deadline_mono_ms - monotonic_ms();
        if (remaining <= 0) return 0;
        if (remaining < timeout_ms) timeout_ms = (int)remaining;
    }
    char *const argv[] = {(char *)runtime, "inspect", "--format", "{{.Name}}", (char *)id, NULL};
    if (!run_command_capture(argv, 0, 1, timeout_ms, out, outsz)) return 0;
    while (out[0] == '/') memmove(out, out + 1, strlen(out));
    return out[0] != '\0';
}

static void resolve_container_name_uncached(const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!strict_container_id(id)) return;
    if (inspect_container_runtime("docker", id, out, outsz)) return;
    (void)inspect_container_runtime("podman", id, out, outsz);
}

static void resolve_container_name(const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!strict_container_id(id)) return;

    int64_t now = monotonic_ms();
    int slot = -1;
    int oldest = 0;
    for (int i = 0; i < container_cache_count; i++) {
        if (!strcmp(container_cache[i].id, id)) {
            slot = i;
            break;
        }
        if (container_cache[i].last_used_ms < container_cache[oldest].last_used_ms) oldest = i;
    }

    if (slot >= 0 && container_cache[slot].expires_ms > now) {
        container_cache[slot].last_used_ms = now;
        snprintf(out, outsz, "%s", container_cache[slot].name);
        return;
    }

    char resolved[256] = "";
    if (container_command_deadline_mono_ms > 0 && now >= container_command_deadline_mono_ms) return;
    resolve_container_name_uncached(id, resolved, sizeof(resolved));

    // A cycle deadline can prevent trying every runtime. Do not negative-cache
    // that incomplete lookup; a later bounded cycle may resolve it.
    if (!resolved[0] && container_command_deadline_mono_ms > 0) return;

    if (slot < 0) {
        if (container_cache_count < MAX_CONTAINER_CACHE) slot = container_cache_count++;
        else slot = oldest;
    }

    snprintf(container_cache[slot].id, sizeof(container_cache[slot].id), "%s", id);
    snprintf(container_cache[slot].name, sizeof(container_cache[slot].name), "%s", resolved);
    container_cache[slot].last_used_ms = now;
    container_cache[slot].expires_ms = now + (resolved[0] ? CONTAINER_CACHE_TTL_MS : CONTAINER_CACHE_NEGATIVE_TTL_MS);
    snprintf(out, outsz, "%s", resolved);
}

static int path_matches_mount(const char *path, const char *mount) {
    size_t n = strlen(mount);
    if (!n || strncmp(path, mount, n) != 0) return 0;
    return path[n] == '\0' || path[n] == '/';
}

static int device_matches_dev_id(const device_t *d, dev_t dev_id) {
    for (int i = 0; i < d->mount_count; i++) {
        if (d->mount_dev_ids[i] != 0 && d->mount_dev_ids[i] == dev_id) return 1;
    }
    return 0;
}

static int device_has_known_dev_id(const device_t *d) {
    for (int i = 0; i < d->mount_count; i++) {
        if (d->mount_dev_ids[i] != 0) return 1;
    }
    return 0;
}

static void logical_label_for_device(const device_t *d, char *out, size_t outsz) {
    out[0] = '\0';
    for (int i = 0; i < d->mount_count; i++) {
        const char *m = d->mounts[i];
        if (strncmp(m, "/mnt/", 5) != 0) continue;
        const char *start = m + 5;
        const char *slash = strchr(start, '/');
        size_t n = slash ? (size_t)(slash - start) : strlen(start);
        if (n > 0) {
            if (n >= outsz) n = outsz - 1;
            memcpy(out, start, n); out[n] = '\0';
            return;
        }
    }
    snprintf(out, outsz, "%s", d->name);
}

static int find_device_for_path_or_stat(const char *path, const struct stat *stp) {
    if (stp) {
        for (int i = 0; i < device_count; i++) {
            if (device_matches_dev_id(&devices[i], stp->st_dev)) return i;
        }
    }
    for (int i = 0; i < device_count; i++) {
        for (int m = 0; m < devices[i].mount_count; m++) {
            if (!path_matches_mount(path, devices[i].mounts[m])) continue;
            if (stp && device_has_known_dev_id(&devices[i])) continue;
            return i;
        }
    }
    return -1;
}

static const char *mask_name(uint64_t mask) {
    if (mask & FAN_MODIFY) return "MODIFY";
    if (mask & FAN_ACCESS) return "ACCESS";
    if (mask & FAN_OPEN_EXEC) return "OPEN_EXEC";
    if (mask & FAN_OPEN) return "OPEN";
    if (mask & FAN_CLOSE_WRITE) return "CLOSE_WRITE";
    if (mask & FAN_CLOSE_NOWRITE) return "CLOSE";
    return "OTHER";
}

static void clear_candidate(device_t *d) {
    memset(&d->candidate, 0, sizeof(d->candidate));
    d->ambiguous_count = 0;
    d->uncertain_evidence[0] = '\0';
}

static void clear_recent_events(device_t *d) {
    memset(d->recent_events, 0, sizeof(d->recent_events));
    d->recent_event_count = 0;
    d->recent_event_overflow_mono_ms = 0;
}

static void clear_wake_window(device_t *d) {
    clear_recent_events(d);
    clear_candidate(d);
    d->io_pending = 0;
    d->io_onset_ms = 0;
    d->io_onset_mono_ms = 0;
}

static void fill_candidate(candidate_t *c, pid_t pid, uint64_t mask, const char *path,
                           const char *confidence, const char *evidence) {
    memset(c, 0, sizeof(*c));
    c->valid = 1;
    c->ts_ms = realtime_ms();
    c->mono_ms = monotonic_ms();
    c->pid = pid;
    snprintf(c->event, sizeof(c->event), "%s", mask_name(mask));
    snprintf(c->path, sizeof(c->path), "%s", path);
    read_proc_text(pid, "comm", c->comm, sizeof(c->comm));
    read_proc_exe(pid, c->exe, sizeof(c->exe));
    get_container_id(pid, c->container_id, sizeof(c->container_id));
    snprintf(c->confidence, sizeof(c->confidence), "%s", confidence);
    snprintf(c->evidence, sizeof(c->evidence), "%s", evidence);
}

static int is_user_share_path(const char *path) {
    return path_matches_mount(path, "/mnt/user") || path_matches_mount(path, "/mnt/user0");
}

static void capture_user_share_event(pid_t pid, uint64_t mask, const char *path) {
    if (!tracking_enabled || pid <= 0 || pid == getpid() || !is_user_share_path(path)) return;

    int64_t now = monotonic_ms();
    int keep = 0;
    for (int i = 0; i < user_share_event_count; i++) {
        int64_t age = now - user_share_events[i].mono_ms;
        if (age >= 0 && age <= PRE_IO_CORRELATION_MS) {
            if (keep != i) user_share_events[keep] = user_share_events[i];
            keep++;
        }
    }
    user_share_event_count = keep;

    for (int i = 0; i < user_share_event_count; i++) {
        if (user_share_events[i].pid == pid) {
            fill_candidate(&user_share_events[i], pid, mask, path, "high", "fanotify_user_share");
            return;
        }
    }

    if (user_share_event_count >= MAX_USER_SHARE_EVENTS) {
        user_share_overflow_mono_ms = now;
        memmove(&user_share_events[0], &user_share_events[1],
                sizeof(user_share_events[0]) * (MAX_USER_SHARE_EVENTS - 1));
        user_share_event_count = MAX_USER_SHARE_EVENTS - 1;
    }

    candidate_t *c = &user_share_events[user_share_event_count++];
    fill_candidate(c, pid, mask, path, "high", "fanotify_user_share");
    if (trace_events) {
        fprintf(stderr, "fanotify user-share pid=%d event=%s path=%s\n", pid, mask_name(mask), path);
    }
}

static int select_user_share_candidate(int64_t io_ts, candidate_t *out, int *ambiguous) {
    pid_t pids[MAX_USER_SHARE_EVENTS];
    int pid_count = 0;
    candidate_t latest;
    memset(&latest, 0, sizeof(latest));

    if (io_ts <= fanotify_poisoned_until_mono_ms) {
        if (ambiguous) *ambiguous = 0;
        return 0;
    }
    if (io_ts - user_share_overflow_mono_ms >= 0 &&
        io_ts - user_share_overflow_mono_ms <= PRE_IO_CORRELATION_MS) {
        if (ambiguous) *ambiguous = MAX_USER_SHARE_EVENTS + 1;
        return 0;
    }

    for (int i = 0; i < user_share_event_count; i++) {
        candidate_t *c = &user_share_events[i];
        int64_t age = io_ts - c->mono_ms;
        if (age < 0 || age > PRE_IO_CORRELATION_MS) continue;

        int seen = 0;
        for (int p = 0; p < pid_count; p++) {
            if (pids[p] == c->pid) { seen = 1; break; }
        }
        if (!seen && pid_count < MAX_USER_SHARE_EVENTS) pids[pid_count++] = c->pid;
        if (!latest.valid || c->mono_ms > latest.mono_ms) latest = *c;
    }

    if (ambiguous) *ambiguous = pid_count;
    if (pid_count == 1 && latest.valid) {
        *out = latest;
        return 1;
    }
    return 0;
}

static void capture_recent_event(device_t *d, pid_t pid, uint64_t mask, const char *path,
                                 const struct stat *stp) {
    if (!tracking_enabled || pid <= 0 || pid == getpid()) return;
    int matches = stp && device_matches_dev_id(d, stp->st_dev);
    if (!matches && stp && device_has_known_dev_id(d)) return;
    if (!matches) {
        for (int i = 0; i < d->mount_count; i++) {
            if (path_matches_mount(path, d->mounts[i])) { matches = 1; break; }
        }
    }
    if (!matches) return;
    if (trace_events) {
        fprintf(stderr, "fanotify %s/%s state=%s pid=%d event=%s path=%s\n",
                d->name, d->dev, state_name(d->state), pid, mask_name(mask), path);
    }
    if (d->state != PWR_STANDBY || d->io_pending) return;

    int64_t now = monotonic_ms();
    int keep = 0;
    for (int i = 0; i < d->recent_event_count; i++) {
        int64_t age = now - d->recent_events[i].mono_ms;
        if (age >= 0 && age <= PRE_IO_CORRELATION_MS) {
            if (keep != i) d->recent_events[keep] = d->recent_events[i];
            keep++;
        }
    }
    d->recent_event_count = keep;

    for (int i = 0; i < d->recent_event_count; i++) {
        if (d->recent_events[i].pid == pid) {
            fill_candidate(&d->recent_events[i], pid, mask, path, "high", "fanotify");
            return;
        }
    }

    if (d->recent_event_count >= MAX_DIRECT_EVENTS) {
        d->recent_event_overflow_mono_ms = now;
        memmove(&d->recent_events[0], &d->recent_events[1],
                sizeof(d->recent_events[0]) * (MAX_DIRECT_EVENTS - 1));
        d->recent_event_count = MAX_DIRECT_EVENTS - 1;
    }
    fill_candidate(&d->recent_events[d->recent_event_count++], pid, mask, path,
                   "high", "fanotify");
}

static int select_direct_candidate(device_t *d, int64_t io_mono_ms,
                                   candidate_t *out, int *ambiguous) {
    if (ambiguous) *ambiguous = 0;
    if (io_mono_ms <= fanotify_poisoned_until_mono_ms) {
        snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "fanotify_overflow");
        return 0;
    }
    if (io_mono_ms - d->recent_event_overflow_mono_ms >= 0 &&
        io_mono_ms - d->recent_event_overflow_mono_ms <= PRE_IO_CORRELATION_MS) {
        if (ambiguous) *ambiguous = MAX_DIRECT_EVENTS + 1;
        snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "fanotify_ambiguous");
        return 0;
    }

    pid_t pids[MAX_DIRECT_EVENTS];
    int pid_count = 0;
    candidate_t latest;
    memset(&latest, 0, sizeof(latest));
    for (int i = 0; i < d->recent_event_count; i++) {
        candidate_t *c = &d->recent_events[i];
        int64_t age = io_mono_ms - c->mono_ms;
        if (age < 0 || age > PRE_IO_CORRELATION_MS) continue;
        int seen = 0;
        for (int p = 0; p < pid_count; p++) {
            if (pids[p] == c->pid) { seen = 1; break; }
        }
        if (!seen) pids[pid_count++] = c->pid;
        if (!latest.valid || c->mono_ms > latest.mono_ms) latest = *c;
    }
    if (ambiguous) *ambiguous = pid_count;
    if (pid_count == 1 && latest.valid) {
        *out = latest;
        return 1;
    }
    if (pid_count > 1) {
        snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "fanotify_ambiguous");
    }
    return 0;
}

static int candidate_is_shfs(const candidate_t *c) {
    if (!c || !c->valid) return 0;
    if (!strcmp(c->comm, "shfs")) return 1;
    const char *base = strrchr(c->exe, '/');
    base = base ? base + 1 : c->exe;
    return !strcmp(base, "shfs");
}

static void fill_open_fd_candidate(candidate_t *c, pid_t pid, const char *path,
                                   int64_t real_ts, int64_t mono_ts) {
    memset(c, 0, sizeof(*c));
    c->valid = 1;
    c->ts_ms = real_ts;
    c->mono_ms = mono_ts;
    c->pid = pid;
    snprintf(c->event, sizeof(c->event), "OPEN_FD");
    snprintf(c->path, sizeof(c->path), "%s", path);
    read_proc_text(pid, "comm", c->comm, sizeof(c->comm));
    read_proc_exe(pid, c->exe, sizeof(c->exe));
    get_container_id(pid, c->container_id, sizeof(c->container_id));
    resolve_container_name(c->container_id, c->container, sizeof(c->container));
    snprintf(c->confidence, sizeof(c->confidence), "medium");
    snprintf(c->evidence, sizeof(c->evidence), "open_fd_unique");
}

static int capture_open_fd_candidate(device_t *d, int64_t real_ts, int64_t mono_ts) {
    if (!tracking_enabled) return 0;
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    candidate_t unique;
    memset(&unique, 0, sizeof(unique));
    int identity_count = 0;
    int pids_scanned = 0;
    int fds_scanned = 0;
    int scan_limited = 0;
    int64_t deadline = monotonic_ms() + OPEN_FD_ATTRIBUTION_BUDGET_MS;
    if (open_fd_cycle_deadline_mono_ms > 0 && open_fd_cycle_deadline_mono_ms < deadline) {
        deadline = open_fd_cycle_deadline_mono_ms;
    }
    struct dirent *pe;

    while ((pe = readdir(proc)) != NULL) {
        if (pids_scanned >= OPEN_FD_ATTRIBUTION_MAX_PIDS || monotonic_ms() >= deadline) {
            scan_limited = 1;
            break;
        }
        char *end = NULL;
        long parsed = strtol(pe->d_name, &end, 10);
        if (!pe->d_name[0] || !end || *end || parsed <= 0 || parsed > INT_MAX) continue;
        pid_t pid = (pid_t)parsed;
        if (pid == getpid()) continue;
        pids_scanned++;

        char fd_dir_path[128];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;
        int matched_pid = 0;
        candidate_t current;
        memset(&current, 0, sizeof(current));

        struct dirent *fe;
        while ((fe = readdir(fd_dir)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            if (fds_scanned >= OPEN_FD_ATTRIBUTION_MAX_FDS || monotonic_ms() >= deadline) {
                scan_limited = 1;
                break;
            }
            fds_scanned++;
            char fd_path[160], target[STR_PATH];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%.31s", pid, fe->d_name);
            ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            struct stat st;
            if (stat(fd_path, &st) != 0) continue;
            if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) continue;
            if (!device_matches_dev_id(d, st.st_dev)) {
                if (device_has_known_dev_id(d)) continue;
                int prefix_match = 0;
                for (int m = 0; m < d->mount_count; m++) {
                    if (path_matches_mount(target, d->mounts[m])) { prefix_match = 1; break; }
                }
                if (!prefix_match) continue;
            }

            current.valid = 1;
            current.ts_ms = real_ts;
            current.mono_ms = mono_ts;
            current.pid = pid;
            snprintf(current.path, sizeof(current.path), "%s", target);
            matched_pid = 1;
            break;
        }
        closedir(fd_dir);

        if (scan_limited) break;

        if (matched_pid) {
            identity_count++;
            if (identity_count == 1) unique = current;
            else unique.valid = 0;
            if (identity_count >= MAX_OPEN_IDENTITIES) {
                scan_limited = 1;
                break;
            }
        }
    }
    closedir(proc);

    if (scan_limited) {
        d->ambiguous_count = identity_count;
        snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "open_fd_scan_limited");
        return 0;
    }
    if (identity_count == 1 && unique.valid) {
        fill_open_fd_candidate(&d->candidate, unique.pid, unique.path, real_ts, mono_ts);
        d->ambiguous_count = 0;
        d->uncertain_evidence[0] = '\0';
        return 1;
    }
    d->ambiguous_count = identity_count;
    if (identity_count > 1) {
        snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "open_fd_ambiguous");
    }
    return 0;
}

static void observe_io_tick(device_t *d, uint64_t ticks, int64_t real_ts, int64_t mono_ts) {
    if (!d->io_initialized) {
        d->prev_io_ticks = ticks;
        d->io_initialized = 1;
        return;
    }

    if (d->state == PWR_STANDBY && !d->io_pending && ticks > d->prev_io_ticks) {
        d->io_pending = 1;
        d->io_onset_ms = real_ts;
        d->io_onset_mono_ms = mono_ts;
        clear_candidate(d);

        candidate_t direct_candidate;
        memset(&direct_candidate, 0, sizeof(direct_candidate));
        int direct_ambiguous = 0;
        int have_direct = tracking_enabled &&
                          select_direct_candidate(d, mono_ts, &direct_candidate, &direct_ambiguous);
        if (direct_ambiguous > 1) {
            d->ambiguous_count = direct_ambiguous;
        }

        if (tracking_enabled && d->ambiguous_count <= 1 &&
            (!have_direct || candidate_is_shfs(&direct_candidate))) {
            candidate_t shared_candidate;
            memset(&shared_candidate, 0, sizeof(shared_candidate));
            int shared_ambiguous = 0;
            if (select_user_share_candidate(mono_ts, &shared_candidate, &shared_ambiguous)) {
                d->candidate = shared_candidate;
                d->ambiguous_count = 0;
            } else if (shared_ambiguous > 1) {
                d->ambiguous_count = shared_ambiguous;
                snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence),
                         "fanotify_user_share_ambiguous");
            } else if (have_direct) {
                d->candidate = direct_candidate;
            }
        } else if (have_direct) {
            d->candidate = direct_candidate;
        }

        if (tracking_enabled && !d->candidate.valid && d->ambiguous_count <= 1) {
            capture_open_fd_candidate(d, real_ts, mono_ts);
        }

        if (d->candidate.valid && d->candidate.container_id[0] && !d->candidate.container[0]) {
            resolve_container_name(d->candidate.container_id, d->candidate.container,
                                   sizeof(d->candidate.container));
        }

        if (verbose) {
            fprintf(stderr, "physical I/O onset %s/%s ticks=%llu candidate=%s evidence=%s ambiguous=%d\n",
                    d->name, d->dev, (unsigned long long)ticks,
                    d->candidate.valid ? d->candidate.comm : "unknown",
                    d->candidate.valid ? d->candidate.evidence : "none",
                    d->ambiguous_count);
        }
    }
    d->prev_io_ticks = ticks;
}

static void sample_diskstats(void) {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) return;
    char line[1024];
    int64_t real_ts = realtime_ms();
    int64_t mono_ts = monotonic_ms();
    open_fd_cycle_deadline_mono_ms = mono_ts + OPEN_FD_ATTRIBUTION_CYCLE_BUDGET_MS;
    container_command_deadline_mono_ms = open_fd_cycle_deadline_mono_ms;
    while (fgets(line, sizeof(line), fp)) {
        char work[1024];
        snprintf(work, sizeof(work), "%s", line);
        char *save = NULL;
        char *tok = strtok_r(work, " \t\n", &save);
        int field = 0;
        char dev[64] = "";
        uint64_t ticks = 0;
        int have_ticks = 0;
        while (tok) {
            if (field == 2) snprintf(dev, sizeof(dev), "%s", tok);
            else if (field == 12) { ticks = strtoull(tok, NULL, 10); have_ticks = 1; break; }
            field++;
            tok = strtok_r(NULL, " \t\n", &save);
        }
        if (!have_ticks || !dev[0]) continue;
        int idx = find_device(dev);
        if (idx >= 0) observe_io_tick(&devices[idx], ticks, real_ts, mono_ts);
    }
    fclose(fp);
    open_fd_cycle_deadline_mono_ms = 0;
    container_command_deadline_mono_ms = 0;
}

static void load_runtime_config(void) {
    FILE *fp = fopen(cfg_file, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        trim(line);
        trim(eq);
        if (*eq == '"') {
            memmove(eq, eq + 1, strlen(eq));
            char *q = strrchr(eq, '"');
            if (q) *q = '\0';
        }

        if (!strcmp(line, "wake_tracking")) {
            tracking_enabled = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        } else if (!strcmp(line, "wake_poll")) {
            int v = atoi(eq);
            if (v >= 2 && v <= 60) poll_seconds = v;
        } else if (!strcmp(line, "wake_verbose")) {
            verbose = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        } else if (!strcmp(line, "open_files_limit")) {
            int v = atoi(eq);
            if (v >= 10 && v <= MAX_OPEN_FILES) open_files_limit = v;
        } else if (!strcmp(line, "wake_detector")) {
            if (!strcasecmp(eq, "auto") || !strcasecmp(eq, "unraid") || !strcasecmp(eq, "smartctl")) {
                snprintf(wake_detector, sizeof(wake_detector), "%s", eq);
            }
        }
    }
    fclose(fp);
}

static int find_device(const char *dev) {
    for (int i = 0; i < device_count; i++) if (!strcmp(devices[i].dev, dev)) return i;
    return -1;
}

static int add_unique_mount(const char *mount) {
    for (int i = 0; i < unique_mount_count; i++) if (!strcmp(unique_mounts[i], mount)) return 0;
    if (unique_mount_count >= MAX_UNIQUE_MOUNTS) return -1;
    snprintf(unique_mounts[unique_mount_count++], STR_PATH, "%s", mount);
    return 0;
}

static int load_map(void) {
    FILE *fp = fopen(map_file, "r");
    if (!fp) {
        fprintf(stderr, "cannot open map file %s: %s\n", map_file, strerror(errno));
        return -1;
    }
    char line[STR_PATH + 512];
    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        char *dev = strtok(line, "\t");
        char *name = strtok(NULL, "\t");
        char *mount = strtok(NULL, "\t");
        if (!dev || !name || !mount || mount[0] != '/') continue;
        int idx = find_device(dev);
        if (idx < 0) {
            if (device_count >= MAX_DEVICES) break;
            idx = device_count++;
            memset(&devices[idx], 0, sizeof(devices[idx]));
            snprintf(devices[idx].dev, sizeof(devices[idx].dev), "%s", dev);
            snprintf(devices[idx].name, sizeof(devices[idx].name), "%s", name);
            devices[idx].state = PWR_UNKNOWN;
        }
        device_t *d = &devices[idx];
        int exists = 0;
        for (int i = 0; i < d->mount_count; i++) if (!strcmp(d->mounts[i], mount)) exists = 1;
        if (!exists && d->mount_count < MAX_MOUNTS_PER_DEVICE) {
            struct stat st;
            int mount_idx = d->mount_count;
            snprintf(d->mounts[mount_idx], STR_PATH, "%s", mount);
            d->mount_dev_ids[mount_idx] = stat(mount, &st) == 0 ? st.st_dev : 0;
            d->mount_count++;
            add_unique_mount(mount);
        }
    }
    fclose(fp);
    return device_count ? 0 : -1;
}

static power_state_t query_unraid_power(const char *dev) {
    FILE *fp = fopen("/var/local/emhttp/disks.ini", "r");
    if (!fp) return PWR_UNKNOWN;
    char line[1024], section_dev[64] = "", color[128] = "";
    power_state_t result = PWR_UNKNOWN;
    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '[') {
            if (!strcmp(section_dev, dev)) {
                if (strstr(color, "blink")) result = PWR_STANDBY;
                else if (strstr(color, "-on") || strstr(color, "green-on") || strstr(color, "yellow-on")) result = PWR_ACTIVE;
                if (result != PWR_UNKNOWN) break;
            }
            section_dev[0] = color[0] = '\0';
            continue;
        }
        if (!strncmp(line, "device=", 7)) {
            snprintf(section_dev, sizeof(section_dev), "%.63s", line + 7);
            trim(section_dev);
            if (section_dev[0] == '"') memmove(section_dev, section_dev + 1, strlen(section_dev));
            char *q = strrchr(section_dev, '"'); if (q) *q = '\0';
        } else if (!strncmp(line, "color=", 6)) {
            snprintf(color, sizeof(color), "%.127s", line + 6);
            trim(color);
            if (color[0] == '"') memmove(color, color + 1, strlen(color));
            char *q = strrchr(color, '"'); if (q) *q = '\0';
        }
    }
    if (result == PWR_UNKNOWN && !strcmp(section_dev, dev)) {
        if (strstr(color, "blink")) result = PWR_STANDBY;
        else if (strstr(color, "-on") || strstr(color, "green-on") || strstr(color, "yellow-on")) result = PWR_ACTIVE;
    }
    fclose(fp);
    return result;
}

static power_state_t query_smartctl_power(const char *dev) {
    char device_path[96];
    snprintf(device_path, sizeof(device_path), "/dev/%.63s", dev);
    char out[8192];
    char *const argv[] = {"smartctl", "-n", "standby", "-i", device_path, NULL};
    if (!run_command_capture(argv, 1, 0, SMARTCTL_TIMEOUT_MS, out, sizeof(out))) return PWR_UNKNOWN;
    for (char *p = out; *p; p++) *p = (char)toupper((unsigned char)*p);
    if (strstr(out, "STANDBY") || strstr(out, "SLEEP")) return PWR_STANDBY;
    if (strstr(out, "ACTIVE") || strstr(out, "IDLE") || strstr(out, "START OF INFORMATION") || strstr(out, "DEVICE MODEL") || strstr(out, "PRODUCT:")) return PWR_ACTIVE;
    return PWR_UNKNOWN;
}

static power_state_t query_power(const char *dev) {
    if (strcasecmp(wake_detector, "smartctl")) {
        power_state_t s = query_unraid_power(dev);
        if (s != PWR_UNKNOWN || !strcasecmp(wake_detector, "unraid")) return s;
    }
    return query_smartctl_power(dev);
}

static int64_t extract_json_ts(const char *line) {
    const char *p = strstr(line, "\"ts\":");
    if (!p) return 0;
    p += 5;
    return strtoll(p, NULL, 10);
}

static int acquire_history_lock(int operation) {
    int fd = open(history_lock_file, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    if (flock(fd, operation) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void release_history_lock(int fd) {
    if (fd < 0) return;
    flock(fd, LOCK_UN);
    close(fd);
}

static void prune_history(void) {
    int lockfd = acquire_history_lock(LOCK_EX);
    if (lockfd < 0) return;

    FILE *fp = fopen(history_file, "r");
    if (!fp) {
        release_history_lock(lockfd);
        return;
    }

    size_t cap = 1024, count = 0;
    char **lines = calloc(cap, sizeof(char *));
    if (!lines) {
        fclose(fp);
        release_history_lock(lockfd);
        return;
    }

    int allocation_ok = 1;
    int64_t cutoff = realtime_ms() - (int64_t)HISTORY_DAYS * 86400000LL;
    char *line = NULL;
    size_t n = 0;
    errno = 0;
    while (getline(&line, &n, fp) >= 0) {
        int64_t ts = extract_json_ts(line);
        if (ts && ts < cutoff) continue;
        if (count == cap) {
            if (cap > SIZE_MAX / 2 / sizeof(char *)) {
                allocation_ok = 0;
                break;
            }
            size_t newcap = cap * 2;
            char **tmp_lines = realloc(lines, newcap * sizeof(char *));
            if (!tmp_lines) {
                allocation_ok = 0;
                break;
            }
            lines = tmp_lines;
            cap = newcap;
        }
        lines[count] = strdup(line);
        if (!lines[count]) {
            allocation_ok = 0;
            break;
        }
        count++;
    }
    if (ferror(fp) || errno == ENOMEM) allocation_ok = 0;
    free(line);
    fclose(fp);

    if (!allocation_ok) {
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        release_history_lock(lockfd);
        return;
    }

    size_t start = count > (size_t)HISTORY_MAX ? count - (size_t)HISTORY_MAX : 0;
    char tmp_path[STR_PATH + 64];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", history_file, getpid());
    FILE *out = fopen(tmp_path, "w");
    if (out) {
        int write_ok = 1;
        for (size_t i = start; i < count; i++) {
            if (lines[i] && fputs(lines[i], out) == EOF) {
                write_ok = 0;
                break;
            }
        }
        if (fflush(out) != 0 || fsync(fileno(out)) != 0) write_ok = 0;
        if (fclose(out) != 0) write_ok = 0;
        if (write_ok) {
            if (rename(tmp_path, history_file) != 0) unlink(tmp_path);
        } else {
            unlink(tmp_path);
        }
    }

    for (size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);
    release_history_lock(lockfd);
}

static void append_wake_event(device_t *d, int64_t detected_ms) {
    char container_id[128] = "", container[256] = "";
    candidate_t *c = &d->candidate;
    if (c->valid) {
        snprintf(container_id, sizeof(container_id), "%s", c->container_id);
        snprintf(container, sizeof(container), "%s", c->container);
        if (!container_id[0]) get_container_id(c->pid, container_id, sizeof(container_id));
        if (!container[0]) resolve_container_name(container_id, container, sizeof(container));
    }

    int lockfd = acquire_history_lock(LOCK_EX);
    if (lockfd < 0) return;
    FILE *fp = fopen(history_file, "a");
    if (!fp) {
        fprintf(stderr, "cannot append history %s: %s\n", history_file, strerror(errno));
        release_history_lock(lockfd);
        return;
    }

    int64_t event_ts = c->valid ? c->ts_ms : (d->io_onset_ms ? d->io_onset_ms : detected_ms);
    fprintf(fp, "{\"ts\":%lld,\"io_ts\":%lld,\"detected_ts\":%lld,\"device\":\"",
            (long long)event_ts, (long long)d->io_onset_ms, (long long)detected_ms);
    json_escape(fp, d->dev);
    fputs("\",\"disk\":\"", fp); json_escape(fp, d->name);
    fputs("\",\"pid\":", fp); fprintf(fp, "%d", c->valid ? c->pid : 0);
    fputs(",\"process\":\"", fp); json_escape(fp, c->valid && c->comm[0] ? c->comm : "unknown");
    fputs("\",\"exe\":\"", fp); json_escape(fp, c->valid ? c->exe : "");
    fputs("\",\"container_id\":\"", fp); json_escape(fp, container_id);
    fputs("\",\"container\":\"", fp); json_escape(fp, container);
    fputs("\",\"event\":\"", fp); json_escape(fp, c->valid ? c->event : "UNKNOWN");
    fputs("\",\"path\":\"", fp); json_escape(fp, c->valid ? c->path : "");
    fputs("\",\"confidence\":\"", fp); json_escape(fp, c->valid && c->confidence[0] ? c->confidence : "unknown");
    fputs("\",\"evidence\":\"", fp);
    if (c->valid && c->evidence[0]) json_escape(fp, c->evidence);
    else if (d->uncertain_evidence[0]) json_escape(fp, d->uncertain_evidence);
    else if (d->ambiguous_count > 1) json_escape(fp, "open_fd_ambiguous");
    else json_escape(fp, "none");
    fprintf(fp, "\",\"ambiguous_candidates\":%d}\n", d->ambiguous_count);
    fflush(fp);
    fclose(fp);
    release_history_lock(lockfd);
    d->last_wake_ms = detected_ms;
}

static void write_state_snapshot(void) {
    char tmp[STR_PATH + 32];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", state_file, getpid());
    FILE *fp = fopen(tmp, "w");
    if (!fp) return;
    fprintf(fp, "{\"updated\":%lld,\"tracking\":%s,\"poll_seconds\":%d,\"detector\":\"",
            (long long)realtime_ms(), tracking_enabled ? "true" : "false", poll_seconds);
    json_escape(fp, wake_detector);
    fputs("\",\"devices\":[", fp);
    for (int i = 0; i < device_count; i++) {
        device_t *d = &devices[i];
        if (i) fputc(',', fp);
        fputs("{\"device\":\"", fp); json_escape(fp, d->dev);
        fputs("\",\"disk\":\"", fp); json_escape(fp, d->name);
        fputs("\",\"state\":\"", fp); fputs(state_name(d->state), fp);
        fprintf(fp, "\",\"last_wake\":%lld,\"io_pending\":%s,\"io_ts\":%lld,\"candidate\":%s,\"ambiguous\":%d}",
                (long long)d->last_wake_ms, d->io_pending ? "true" : "false",
                (long long)d->io_onset_ms, d->candidate.valid ? "true" : "false", d->ambiguous_count);
    }
    fputs("]}\n", fp);
    fclose(fp);
    rename(tmp, state_file);
}

static void check_power_states(void) {
    static int cursor = 0;
    load_runtime_config();
    int checked = 0;
    int start = device_count > 0 ? cursor % device_count : 0;
    int64_t deadline = monotonic_ms() + POWER_CHECK_BUDGET_MS;
    container_command_deadline_mono_ms = deadline;
    while (checked < device_count) {
        if (checked > 0 && monotonic_ms() >= deadline) break;
        int idx = (start + checked) % device_count;
        device_t *d = &devices[idx];
        power_state_t old = d->state;
        power_state_t cur = query_power(d->dev);
        int64_t t = realtime_ms();
        checked++;
        if (cur == PWR_UNKNOWN) continue;
        if (old == PWR_UNKNOWN) {
            d->state = cur;
            if (cur == PWR_STANDBY) { d->standby_observed_ms = t; clear_wake_window(d); }
            continue;
        }
        if (old != cur) {
            if (verbose) fprintf(stderr, "power %s/%s %s -> %s\n", d->name, d->dev, state_name(old), state_name(cur));
            if (old == PWR_STANDBY && cur == PWR_ACTIVE) {
                if (tracking_enabled) append_wake_event(d, t);
                clear_wake_window(d);
            } else if (cur == PWR_STANDBY) {
                d->standby_observed_ms = t;
                clear_wake_window(d);
            }
            d->state = cur;
        }
    }
    if (device_count > 0) cursor = (start + checked) % device_count;
    container_command_deadline_mono_ms = 0;
    write_state_snapshot();
}

static int open_file_duplicate(open_file_t *files, int count, pid_t pid, const char *path) {
    for (int i = 0; i < count; i++) if (files[i].pid == pid && !strcmp(files[i].path, path)) return 1;
    return 0;
}

static void write_open_files_snapshot(void) {
    char tmp[STR_PATH + 32];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", open_files_file, getpid());
    FILE *out = fopen(tmp, "w");
    if (!out) return;

    open_file_t *files = calloc((size_t)open_files_limit, sizeof(open_file_t));
    if (!files) { fclose(out); unlink(tmp); return; }
    int count = 0, truncated = 0;
    int pids_scanned = 0, fds_scanned = 0;
    int64_t deadline = monotonic_ms() + OPEN_FILES_SCAN_BUDGET_MS;
    container_command_deadline_mono_ms = deadline;
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *pe;
        while ((pe = readdir(proc)) != NULL) {
            if (pids_scanned >= OPEN_FILES_SCAN_MAX_PIDS || monotonic_ms() >= deadline) {
                truncated = 1;
                break;
            }
            char *end = NULL;
            long parsed = strtol(pe->d_name, &end, 10);
            if (!pe->d_name[0] || !end || *end || parsed <= 0 || parsed > INT_MAX) continue;
            pid_t pid = (pid_t)parsed;
            if (pid == getpid()) continue;
            pids_scanned++;
            char fd_dir_path[128]; snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
            DIR *fd_dir = opendir(fd_dir_path); if (!fd_dir) continue;
            char comm[STR_SMALL] = "", exe[STR_MED] = "", cid[128] = "", cname[256] = "";
            int identity_loaded = 0;
            struct dirent *fe;
            while ((fe = readdir(fd_dir)) != NULL) {
                if (fe->d_name[0] == '.') continue;
                if (fds_scanned >= OPEN_FILES_SCAN_MAX_FDS || monotonic_ms() >= deadline) {
                    truncated = 1;
                    break;
                }
                fds_scanned++;
                char fd_path[160], target[STR_PATH];
                snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%.31s", pid, fe->d_name);
                ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
                if (n <= 0) continue;
                target[n] = '\0';
                if (target[0] != '/') continue;

                struct stat st;
                if (stat(fd_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                int idx = find_device_for_path_or_stat(target, &st);
                if (idx < 0) continue;
                if (open_file_duplicate(files, count, pid, target)) continue;
                if (count >= open_files_limit) { truncated = 1; break; }
                if (!identity_loaded) {
                    read_proc_text(pid, "comm", comm, sizeof(comm));
                    read_proc_exe(pid, exe, sizeof(exe));
                    get_container_id(pid, cid, sizeof(cid));
                    resolve_container_name(cid, cname, sizeof(cname));
                    identity_loaded = 1;
                }
                open_file_t *of = &files[count++];
                of->pid = pid;
                of->fd_num = atoi(fe->d_name);
                snprintf(of->process, sizeof(of->process), "%s", comm);
                snprintf(of->exe, sizeof(of->exe), "%s", exe);
                snprintf(of->container_id, sizeof(of->container_id), "%s", cid);
                snprintf(of->container, sizeof(of->container), "%s", cname);
                snprintf(of->device, sizeof(of->device), "%s", devices[idx].dev);
                logical_label_for_device(&devices[idx], of->disk, sizeof(of->disk));
                snprintf(of->path, sizeof(of->path), "%s", target);
            }
            closedir(fd_dir);
            if (truncated) break;
        }
        closedir(proc);
    }

    fprintf(out, "{\"updated\":%lld,\"enabled\":true,\"truncated\":%s,\"files\":[",
            (long long)realtime_ms(), truncated ? "true" : "false");
    for (int i = 0; i < count; i++) {
        if (i) fputc(',', out);
        open_file_t *of = &files[i];
        fprintf(out, "{\"pid\":%d,\"fd\":%d,\"process\":\"", of->pid, of->fd_num);
        json_escape(out, of->process);
        fputs("\",\"exe\":\"", out); json_escape(out, of->exe);
        fputs("\",\"container_id\":\"", out); json_escape(out, of->container_id);
        fputs("\",\"container\":\"", out); json_escape(out, of->container);
        fputs("\",\"device\":\"", out); json_escape(out, of->device);
        fputs("\",\"disk\":\"", out); json_escape(out, of->disk);
        fputs("\",\"path\":\"", out); json_escape(out, of->path);
        fputs("\"}", out);
    }
    fputs("]}\n", out);
    fclose(out);
    free(files);
    container_command_deadline_mono_ms = 0;
    rename(tmp, open_files_file);
}

static int mark_fanotify_path(int fd, const char *path, const char *label) {
    if (!path || !path[0] || access(path, F_OK) != 0) return 0;
    uint64_t mask = FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN_EXEC;
    int fs_rc = -1;
#ifdef FAN_MARK_FILESYSTEM
    fs_rc = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, path);
#endif
    int mount_rc = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, path);
    if (fs_rc == 0 || mount_rc == 0) {
        if (verbose) {
            fprintf(stderr, "watch %s %s fs=%s mount=%s\n", label, path,
                    fs_rc == 0 ? "yes" : "no", mount_rc == 0 ? "yes" : "no");
        }
        return 1;
    }
    if (verbose) fprintf(stderr, "cannot watch %s %s: %s\n", label, path, strerror(errno));
    return 0;
}

static int setup_fanotify(void) {
    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "fanotify_init failed: %s\n", strerror(errno));
        return -1;
    }

    int marks = 0;
    for (int i = 0; i < unique_mount_count; i++) {
        marks += mark_fanotify_path(fd, unique_mounts[i], "filesystem");
    }

    // Docker/SMB commonly access Unraid storage through the shfs user-share layer.
    // These events cannot be mapped to a physical disk by path alone, so they are
    // only promoted when one unique PID occurs immediately before physical I/O.
    marks += mark_fanotify_path(fd, "/mnt/user", "user-share");
    marks += mark_fanotify_path(fd, "/mnt/user0", "user-share");

    if (!marks) {
        close(fd);
        fprintf(stderr, "no mountpoints could be watched\n");
        return -1;
    }
    return fd;
}

static void poison_fanotify_candidates(void) {
    int64_t now = monotonic_ms();
    fanotify_poisoned_until_mono_ms = now + PRE_IO_CORRELATION_MS;
    memset(user_share_events, 0, sizeof(user_share_events));
    user_share_event_count = 0;
    user_share_overflow_mono_ms = 0;
    for (int i = 0; i < device_count; i++) {
        device_t *d = &devices[i];
        clear_recent_events(d);
        if (d->candidate.valid && !strncmp(d->candidate.evidence, "fanotify", 9)) {
            memset(&d->candidate, 0, sizeof(d->candidate));
            d->ambiguous_count = 0;
            snprintf(d->uncertain_evidence, sizeof(d->uncertain_evidence), "fanotify_overflow");
        }
    }
    if (verbose || trace_events) fprintf(stderr, "fanotify queue overflow; attribution window invalidated\n");
}

static void process_fanotify(int fanfd) {
    char buf[64 * 1024];
    int processed = 0;
    int64_t deadline = monotonic_ms() + FANOTIFY_PROCESS_BUDGET_MS;
    while (1) {
        ssize_t len = read(fanfd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        if (len == 0) return;

        struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(m, len)) {
            if (processed >= FANOTIFY_PROCESS_MAX_EVENTS || monotonic_ms() >= deadline) {
                poison_fanotify_candidates();
                while (FAN_EVENT_OK(m, len)) {
                    if (m->fd >= 0) close(m->fd);
                    m = FAN_EVENT_NEXT(m, len);
                }
                return;
            }
            processed++;
            if (m->vers != FANOTIFY_METADATA_VERSION) break;
            if (m->mask & FAN_Q_OVERFLOW) {
                poison_fanotify_candidates();
                if (m->fd >= 0) close(m->fd);
                m = FAN_EVENT_NEXT(m, len);
                continue;
            }
            if (m->fd >= 0) {
                char link[64], path[STR_PATH];
                snprintf(link, sizeof(link), "/proc/self/fd/%d", m->fd);
                ssize_t n = readlink(link, path, sizeof(path) - 1);
                if (n > 0) {
                    path[n] = '\0';
                    capture_user_share_event(m->pid, m->mask, path);
                    struct stat st;
                    struct stat *stp = fstat(m->fd, &st) == 0 ? &st : NULL;
                    for (int i = 0; i < device_count; i++) {
                        capture_recent_event(&devices[i], m->pid, m->mask, path, stp);
                    }
                }
                close(m->fd);
            }
            m = FAN_EVENT_NEXT(m, len);
        }
    }
}

static void usage(FILE *out, const char *argv0) {
    fprintf(out,
            "Usage: %s [--map FILE] [--history FILE] [--state FILE] [--open-files FILE] "
            "[--config FILE] [--verbose] [--trace-events] [--test-open-fds DEV] [--help] [--version]\n",
            argv0);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--map") && i + 1 < argc) snprintf(map_file, sizeof(map_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--history") && i + 1 < argc) snprintf(history_file, sizeof(history_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc) snprintf(state_file, sizeof(state_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--open-files") && i + 1 < argc) snprintf(open_files_file, sizeof(open_files_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--config") && i + 1 < argc) snprintf(cfg_file, sizeof(cfg_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--verbose")) verbose = 1;
        else if (!strcmp(argv[i], "--trace-events")) trace_events = 1;
        else if (!strcmp(argv[i], "--test-open-fds") && i + 1 < argc) snprintf(test_open_fds_dev, sizeof(test_open_fds_dev), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--help")) { usage(stdout, argv[0]); return 0; }
        else if (!strcmp(argv[i], "--version")) { printf("disk_wake_monitor %s\n", DAP_VERSION); return 0; }
        else { usage(stderr, argv[0]); return 2; }
    }

    signal(SIGINT, on_term_signal);
    signal(SIGTERM, on_term_signal);
    signal(SIGHUP, on_hup_signal);

    load_runtime_config();
    if (load_map() != 0) return 3;
    if (test_open_fds_dev[0]) {
        int idx = find_device(test_open_fds_dev);
        if (idx < 0) return 5;
        if (!capture_open_fd_candidate(&devices[idx], realtime_ms(), monotonic_ms())) {
            fprintf(stdout, "ambiguous=%d\n", devices[idx].ambiguous_count);
            return 6;
        }
        candidate_t *c = &devices[idx].candidate;
        fprintf(stdout, "pid=%d process=%s container_id=%s container=%s path=%s confidence=%s evidence=%s\n",
                c->pid, c->comm, c->container_id, c->container, c->path, c->confidence, c->evidence);
        return 0;
    }

    prune_history();
    int fanfd = setup_fanotify();
    if (fanfd < 0) {
        fprintf(stderr, "fanotify unavailable; continuing with open-FD/UNKNOWN attribution and open-file snapshots\n");
    }

    sample_diskstats();
    check_power_states();
    write_open_files_snapshot();

    int64_t now = monotonic_ms();
    int64_t next_power = now + (int64_t)poll_seconds * 1000;
    int64_t next_io = now + IO_SAMPLE_MS;
    int64_t next_open = now + OPEN_FILES_SAMPLE_MS;
    int64_t next_prune = now + HISTORY_PRUNE_INTERVAL_MS;

    while (running) {
        reap_pending_children();
        now = monotonic_ms();
        int64_t wait_ms = next_io > now ? next_io - now : 0;
        int64_t d = next_power > now ? next_power - now : 0;
        if (d < wait_ms) wait_ms = d;
        d = next_open > now ? next_open - now : 0;
        if (d < wait_ms) wait_ms = d;
        d = next_prune > now ? next_prune - now : 0;
        if (d < wait_ms) wait_ms = d;
        if (wait_ms > 1000) wait_ms = 1000;

        int rc;
        if (fanfd >= 0) {
            struct pollfd pfd = {.fd = fanfd, .events = POLLIN};
            rc = poll(&pfd, 1, (int)wait_ms);
            if (rc > 0 && (pfd.revents & POLLIN)) process_fanotify(fanfd);
        } else {
            rc = poll(NULL, 0, (int)wait_ms);
        }
        (void)rc;

        now = monotonic_ms();
        if (reload_requested) {
            reload_requested = 0;
            load_runtime_config();
            next_power = now + (int64_t)poll_seconds * 1000;
            if (verbose) fprintf(stderr, "configuration reloaded after SIGHUP\n");
        }
        if (now >= next_io) {
            sample_diskstats();
            next_io = monotonic_ms() + IO_SAMPLE_MS;
        }
        if (now >= next_power) {
            sample_diskstats();
            check_power_states();
            next_power = monotonic_ms() + (int64_t)poll_seconds * 1000;
        }
        if (now >= next_open) {
            load_runtime_config();
            write_open_files_snapshot();
            next_open = monotonic_ms() + OPEN_FILES_SAMPLE_MS;
        }
        if (now >= next_prune) {
            prune_history();
            next_prune = monotonic_ms() + HISTORY_PRUNE_INTERVAL_MS;
        }
    }

    if (fanfd >= 0) close(fanfd);
    reap_pending_children();
    unlink(open_files_file);
    return 0;
}
