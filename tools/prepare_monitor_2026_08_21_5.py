#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / 'source/usr/local/emhttp/plugins/disk.activity/src'
parts = sorted(SRC_DIR.glob('disk_wake_monitor.part*.inc'))
if not parts:
    raise SystemExit('no monitor source parts found')

source = ''.join(p.read_text() for p in parts)


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f'{label}: expected 1 exact match, got {count}')
    source = source.replace(old, new, 1)


def regex_once(pattern: str, replacement: str, label: str) -> None:
    global source
    source2, count = re.subn(pattern, lambda _m: replacement, source, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError(f'{label}: expected 1 regex match, got {count}')
    source = source2


replace_once(
    '#include <sys/file.h>\n',
    '#include <sys/file.h>\n#include <sys/wait.h>\n',
    'wait header',
)

replace_once(
    '#define MAX_OPEN_FILES 512\n#define MAX_OPEN_IDENTITIES 512\n',
    '#define MAX_OPEN_FILES 500\n#define MAX_OPEN_IDENTITIES 512\n#define MAX_CONTAINER_CACHE 256\n#define MAX_USER_SHARE_EVENTS 32\n',
    'limits',
)

replace_once(
    '#define DEFAULT_HISTORY_DAYS 90\n#define DEFAULT_HISTORY_MAX 20000\n',
    '#define HISTORY_DAYS 60\n#define HISTORY_MAX 5000\n#define CONTAINER_CACHE_TTL_MS (10LL * 60LL * 1000LL)\n#define CONTAINER_CACHE_NEGATIVE_TTL_MS (30LL * 1000LL)\n\n#ifndef DAP_VERSION\n#define DAP_VERSION "dev"\n#endif\n',
    'history/cache constants',
)

replace_once(
    '''typedef struct {\n    char id[128];\n    char name[256];\n} container_cache_t;\n''',
    '''typedef struct {\n    char id[128];\n    char name[256];\n    int64_t expires_ms;\n    int64_t last_used_ms;\n} container_cache_t;\n''',
    'container cache struct',
)

replace_once(
    '''static volatile sig_atomic_t running = 1;\nstatic device_t devices[MAX_DEVICES];\nstatic int device_count = 0;\nstatic char unique_mounts[MAX_UNIQUE_MOUNTS][STR_PATH];\nstatic int unique_mount_count = 0;\nstatic container_cache_t container_cache[128];\nstatic int container_cache_count = 0;\n''',
    '''static volatile sig_atomic_t running = 1;\nstatic volatile sig_atomic_t reload_requested = 0;\nstatic device_t devices[MAX_DEVICES];\nstatic int device_count = 0;\nstatic char unique_mounts[MAX_UNIQUE_MOUNTS][STR_PATH];\nstatic int unique_mount_count = 0;\nstatic container_cache_t container_cache[MAX_CONTAINER_CACHE];\nstatic int container_cache_count = 0;\nstatic candidate_t user_share_events[MAX_USER_SHARE_EVENTS];\nstatic int user_share_event_count = 0;\n''',
    'globals',
)

replace_once(
    '''static char history_file[STR_PATH] = "/boot/config/plugins/disk.activity/wake-history.jsonl";\nstatic char state_file[STR_PATH] = "/var/local/emhttp/disk_wake_state.json";\n''',
    '''static char history_file[STR_PATH] = "/boot/config/plugins/disk.activity/wake-history.jsonl";\nstatic char history_lock_file[STR_PATH] = "/var/lock/disk_activity_plus_history.lock";\nstatic char state_file[STR_PATH] = "/var/local/emhttp/disk_wake_state.json";\n''',
    'history lock path',
)

replace_once(
    '''static int tracking_enabled = 1;\nstatic int open_files_enabled = 1;\nstatic int open_files_limit = 100;\nstatic int history_days = DEFAULT_HISTORY_DAYS;\nstatic int history_max = DEFAULT_HISTORY_MAX;\n''',
    '''static int tracking_enabled = 1;\nstatic int open_files_limit = 100;\n''',
    'runtime globals',
)

replace_once(
    '''static void on_signal(int sig) {\n    (void)sig;\n    running = 0;\n}\n''',
    '''static void on_term_signal(int sig) {\n    (void)sig;\n    running = 0;\n}\n\nstatic void on_hup_signal(int sig) {\n    (void)sig;\n    reload_requested = 1;\n}\n''',
    'signal handlers',
)

container_block = r'''static int extract_hex_id\(const char \*s, char \*out, size_t outsz\) \{.*?\nstatic int path_matches_mount'''
container_replacement = r'''static int extract_hex_id(const char *s, char *out, size_t outsz) {
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

static int inspect_container_runtime(const char *runtime, const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!strict_container_id(id)) return 0;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return 0;

    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }
    if (child == 0) {
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        dup2(pipefd[1], STDOUT_FILENO);
        if (nullfd >= 0) dup2(nullfd, STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        if (nullfd > STDERR_FILENO) close(nullfd);
        execlp(runtime, runtime, "inspect", "--format", "{{.Name}}", id, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    FILE *fp = fdopen(pipefd[0], "r");
    if (fp) {
        if (fgets(out, (int)outsz, fp)) trim(out);
        fclose(fp);
    } else {
        close(pipefd[0]);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) out[0] = '\0';
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

    int64_t now = now_ms();
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
    resolve_container_name_uncached(id, resolved, sizeof(resolved));

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

static int path_matches_mount'''
regex_once(container_block, container_replacement, 'container resolution block')

insert_before_capture = r'''static void fill_candidate(candidate_t *c, pid_t pid, uint64_t mask, const char *path,
                           const char *confidence, const char *evidence) {
    memset(c, 0, sizeof(*c));
    c->valid = 1;
    c->ts_ms = now_ms();
    c->pid = pid;
    snprintf(c->event, sizeof(c->event), "%s", mask_name(mask));
    snprintf(c->path, sizeof(c->path), "%s", path);
    read_proc_text(pid, "comm", c->comm, sizeof(c->comm));
    read_proc_exe(pid, c->exe, sizeof(c->exe));
    get_container_id(pid, c->container_id, sizeof(c->container_id));
    resolve_container_name(c->container_id, c->container, sizeof(c->container));
    snprintf(c->confidence, sizeof(c->confidence), "%s", confidence);
    snprintf(c->evidence, sizeof(c->evidence), "%s", evidence);
}

static int is_user_share_path(const char *path) {
    return path_matches_mount(path, "/mnt/user") || path_matches_mount(path, "/mnt/user0");
}

static void capture_user_share_event(pid_t pid, uint64_t mask, const char *path) {
    if (!tracking_enabled || pid <= 0 || pid == getpid() || !is_user_share_path(path)) return;

    int64_t now = now_ms();
    int keep = 0;
    for (int i = 0; i < user_share_event_count; i++) {
        int64_t age = now - user_share_events[i].ts_ms;
        if (age >= 0 && age <= PRE_IO_CORRELATION_MS) {
            if (keep != i) user_share_events[keep] = user_share_events[i];
            keep++;
        }
    }
    user_share_event_count = keep;

    if (user_share_event_count >= MAX_USER_SHARE_EVENTS) {
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

    for (int i = 0; i < user_share_event_count; i++) {
        candidate_t *c = &user_share_events[i];
        int64_t age = io_ts - c->ts_ms;
        if (age < 0 || age > PRE_IO_CORRELATION_MS) continue;

        int seen = 0;
        for (int p = 0; p < pid_count; p++) {
            if (pids[p] == c->pid) { seen = 1; break; }
        }
        if (!seen && pid_count < MAX_USER_SHARE_EVENTS) pids[pid_count++] = c->pid;
        if (!latest.valid || c->ts_ms > latest.ts_ms) latest = *c;
    }

    if (ambiguous) *ambiguous = pid_count;
    if (pid_count == 1 && latest.valid) {
        *out = latest;
        return 1;
    }
    return 0;
}

'''
replace_once('static void capture_recent_event(device_t *d, pid_t pid, uint64_t mask, const char *path) {\n', insert_before_capture + 'static void capture_recent_event(device_t *d, pid_t pid, uint64_t mask, const char *path) {\n', 'user-share helpers')

regex_once(
    r'''static void observe_io_tick\(device_t \*d, uint64_t ticks, int64_t t\) \{.*?\n\}\n\nstatic void sample_diskstats''',
    r'''static void observe_io_tick(device_t *d, uint64_t ticks, int64_t t) {
    if (!d->io_initialized) {
        d->prev_io_ticks = ticks;
        d->io_initialized = 1;
        return;
    }

    if (d->state == PWR_STANDBY && !d->io_pending && ticks > d->prev_io_ticks) {
        d->io_pending = 1;
        d->io_onset_ms = t;
        clear_candidate(d);

        if (d->recent_event.valid) {
            int64_t age = t - d->recent_event.ts_ms;
            if (age >= 0 && age <= PRE_IO_CORRELATION_MS) d->candidate = d->recent_event;
        }

        if (tracking_enabled && !d->candidate.valid) {
            candidate_t shared_candidate;
            memset(&shared_candidate, 0, sizeof(shared_candidate));
            int shared_ambiguous = 0;
            if (select_user_share_candidate(t, &shared_candidate, &shared_ambiguous)) {
                d->candidate = shared_candidate;
                d->ambiguous_count = 0;
            } else if (shared_ambiguous > 1) {
                d->ambiguous_count = shared_ambiguous;
            }
        }

        if (tracking_enabled && !d->candidate.valid && d->ambiguous_count <= 1) {
            capture_open_fd_candidate(d, t);
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

static void sample_diskstats''',
    'observe io correlation',
)

regex_once(
    r'''static void load_runtime_config\(void\) \{.*?\n\}\n\nstatic int find_device''',
    r'''static void load_runtime_config(void) {
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

static int find_device''',
    'runtime config',
)

history_block = r'''static void prune_history\(void\) \{.*?\n\}\n\nstatic void write_state_snapshot'''
history_replacement = r'''static int acquire_history_lock(int operation) {
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

    int64_t cutoff = now_ms() - (int64_t)HISTORY_DAYS * 86400000LL;
    char *line = NULL;
    size_t n = 0;
    while (getline(&line, &n, fp) >= 0) {
        int64_t ts = extract_json_ts(line);
        if (ts && ts < cutoff) continue;
        if (count == cap) {
            size_t newcap = cap * 2;
            char **tmp_lines = realloc(lines, newcap * sizeof(char *));
            if (!tmp_lines) break;
            lines = tmp_lines;
            cap = newcap;
        }
        lines[count++] = strdup(line);
    }
    free(line);
    fclose(fp);

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
    else if (d->ambiguous_count > 1) json_escape(fp, "open_fd_ambiguous");
    else json_escape(fp, "none");
    fprintf(fp, "\",\"ambiguous_candidates\":%d}\n", d->ambiguous_count);
    fflush(fp);
    fclose(fp);
    release_history_lock(lockfd);
    d->last_wake_ms = detected_ms;
}

static void write_state_snapshot'''
regex_once(history_block, history_replacement, 'atomic history block')

replace_once(
    '''    if (!open_files_enabled) {\n        fprintf(out, "{\\\"updated\\\":%lld,\\\"enabled\\\":false,\\\"files\\\":[]}\\n", (long long)now_ms());\n        fclose(out); rename(tmp, open_files_file); return;\n    }\n\n''',
    '',
    'remove disabled open-files branch',
)

# Replace fanotify setup/process and main tail in one pass so the resulting source is self-contained.
regex_once(
    r'''static int setup_fanotify\(void\) \{.*\Z''',
    r'''static int mark_fanotify_path(int fd, const char *path, const char *label) {
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

static void process_fanotify(int fanfd) {
    char buf[64 * 1024];
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
            if (m->vers != FANOTIFY_METADATA_VERSION) break;
            if (m->fd >= 0) {
                char link[64], path[STR_PATH];
                snprintf(link, sizeof(link), "/proc/self/fd/%d", m->fd);
                ssize_t n = readlink(link, path, sizeof(path) - 1);
                if (n > 0) {
                    path[n] = '\0';
                    capture_user_share_event(m->pid, m->mask, path);
                    for (int i = 0; i < device_count; i++) {
                        capture_recent_event(&devices[i], m->pid, m->mask, path);
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
        if (!capture_open_fd_candidate(&devices[idx], now_ms())) {
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

    int64_t now = now_ms();
    int64_t next_power = now + (int64_t)poll_seconds * 1000;
    int64_t next_io = now + IO_SAMPLE_MS;
    int64_t next_open = now + OPEN_FILES_SAMPLE_MS;
    int64_t next_prune = now + HISTORY_PRUNE_INTERVAL_MS;

    while (running) {
        now = now_ms();
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

        now = now_ms();
        if (reload_requested) {
            reload_requested = 0;
            load_runtime_config();
            next_power = now + (int64_t)poll_seconds * 1000;
            if (verbose) fprintf(stderr, "configuration reloaded after SIGHUP\n");
        }
        if (now >= next_io) {
            sample_diskstats();
            next_io = now + IO_SAMPLE_MS;
        }
        if (now >= next_power) {
            sample_diskstats();
            check_power_states();
            next_power = now + (int64_t)poll_seconds * 1000;
        }
        if (now >= next_open) {
            load_runtime_config();
            write_open_files_snapshot();
            next_open = now + OPEN_FILES_SAMPLE_MS;
        }
        if (now >= next_prune) {
            prune_history();
            next_prune = now + HISTORY_PRUNE_INTERVAL_MS;
        }
    }

    if (fanfd >= 0) close(fanfd);
    unlink(open_files_file);
    return 0;
}
''',
    'fanotify/main tail',
)

out = SRC_DIR / 'disk_wake_monitor.c'
out.write_text(source)
for p in parts:
    p.unlink()
print(f'wrote {out} ({len(source)} bytes) and removed {len(parts)} source fragments')
