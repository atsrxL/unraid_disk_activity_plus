        if (extract_hex_id(line, out, outsz)) break;
    }
    fclose(fp);
}

static void resolve_container_name(const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!id || strlen(id) < 12) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "docker inspect --format '{{.Name}}' %.64s 2>/dev/null", id);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(out, (int)outsz, fp)) {
            trim(out);
            while (out[0] == '/') memmove(out, out + 1, strlen(out));
        }
        pclose(fp);
    }
    if (out[0]) return;
    snprintf(cmd, sizeof(cmd), "podman inspect --format '{{.Name}}' %.64s 2>/dev/null", id);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(out, (int)outsz, fp)) trim(out);
        pclose(fp);
    }
}

static int path_matches_mount(const char *path, const char *mount) {
    size_t n = strlen(mount);
    if (strncmp(path, mount, n) != 0) return 0;
    return path[n] == '\0' || path[n] == '/';
}

static int device_matches_dev_id(const device_t *d, dev_t dev_id) {
    for (int i = 0; i < d->mount_count; i++) {
        if (d->mount_dev_ids[i] != 0 && d->mount_dev_ids[i] == dev_id) return 1;
    }
    return 0;
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
}

static void clear_wake_window(device_t *d) {
    memset(&d->recent_event, 0, sizeof(d->recent_event));
    clear_candidate(d);
    d->io_pending = 0;
    d->io_onset_ms = 0;
}

static void capture_recent_event(device_t *d, pid_t pid, uint64_t mask, const char *path) {
    if (!tracking_enabled) return;
    if (pid <= 0 || pid == getpid()) return;

    int matches = 0;
    for (int i = 0; i < d->mount_count; i++) {
        if (path_matches_mount(path, d->mounts[i])) { matches = 1; break; }
    }
    if (!matches) return;

    if (trace_events) {
        fprintf(stderr, "fanotify %s/%s state=%s pid=%d event=%s path=%s\n",
                d->name, d->dev, state_name(d->state), pid, mask_name(mask), path);
    }
    if (d->state != PWR_STANDBY || d->io_pending) return;

    candidate_t *c = &d->recent_event;
    memset(c, 0, sizeof(*c));
    c->valid = 1;
    c->ts_ms = now_ms();
    c->pid = pid;
    snprintf(c->event, sizeof(c->event), "%s", mask_name(mask));
    snprintf(c->path, sizeof(c->path), "%s", path);
    read_proc_text(pid, "comm", c->comm, sizeof(c->comm));
    read_proc_exe(pid, c->exe, sizeof(c->exe));
    get_container_id(pid, c->container_id, sizeof(c->container_id));
    snprintf(c->confidence, sizeof(c->confidence), "high");
    snprintf(c->evidence, sizeof(c->evidence), "fanotify");

    if (verbose) {
        fprintf(stderr, "recent %s/%s pid=%d %s %s\n", d->name, d->dev, pid, c->comm, c->path);
    }
}

static int capture_open_fd_candidate(device_t *d, int64_t t) {
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    candidate_t best;
    memset(&best, 0, sizeof(best));
    int best_score = -1;
    struct dirent *pe;

    while ((pe = readdir(proc)) != NULL) {
        char *end = NULL;
        long parsed = strtol(pe->d_name, &end, 10);
        if (!pe->d_name[0] || !end || *end || parsed <= 0 || parsed > INT_MAX) continue;
        pid_t pid = (pid_t)parsed;
        if (pid == getpid()) continue;

        char fd_dir_path[128];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;

        struct dirent *fe;
        while ((fe = readdir(fd_dir)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            char fd_path[160];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%.31s", pid, fe->d_name);

            struct stat st;
            if (stat(fd_path, &st) != 0 || !device_matches_dev_id(d, st.st_dev)) continue;

            candidate_t current;
            memset(&current, 0, sizeof(current));
            current.valid = 1;
            current.ts_ms = t;
            current.pid = pid;
            snprintf(current.event, sizeof(current.event), "OPEN_FD");
            ssize_t n = readlink(fd_path, current.path, sizeof(current.path) - 1);
            if (n > 0) current.path[n] = '\0';
            else current.path[0] = '\0';
            read_proc_text(pid, "comm", current.comm, sizeof(current.comm));
            read_proc_exe(pid, current.exe, sizeof(current.exe));
            get_container_id(pid, current.container_id, sizeof(current.container_id));
            snprintf(current.confidence, sizeof(current.confidence), "medium");
            snprintf(current.evidence, sizeof(current.evidence), "open_fd");

            int score = current.container_id[0] ? 100 : 10;
            if (S_ISREG(st.st_mode)) score += 5;
            if (current.path[0]) score += 1;
            if (score > best_score) {
                best = current;
                best_score = score;
            }
            // One matching descriptor is enough to identify this process.
            break;
        }
        closedir(fd_dir);
    }
    closedir(proc);

    if (best_score < 0) return 0;
    d->candidate = best;
    if (verbose) {
        fprintf(stderr, "open-fd candidate %s/%s pid=%d process=%s container=%s path=%s\n",
                d->name, d->dev, best.pid, best.comm,
                best.container[0] ? best.container : "host", best.path);
    }
    return 1;
}

static void observe_io_tick(device_t *d, uint64_t ticks, int64_t t) {
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
            if (age >= 0 && age <= PRE_IO_CORRELATION_MS) {
                d->candidate = d->recent_event;
            }
        }
        if (!d->candidate.valid) capture_open_fd_candidate(d, t);
        if (verbose) {
            fprintf(stderr, "physical I/O onset %s/%s ticks=%llu candidate=%s age_ms=%lld\n",
                    d->name, d->dev, (unsigned long long)ticks,
                    d->candidate.valid ? d->candidate.comm : "unknown",
                    (long long)(d->candidate.valid ? t - d->candidate.ts_ms : -1));
        }
    }
    d->prev_io_ticks = ticks;
}

static void sample_diskstats(void) {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) return;
    char line[1024];
    int64_t t = now_ms();
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
        if (idx >= 0) observe_io_tick(&devices[idx], ticks, t);
    }
    fclose(fp);
}

static void load_runtime_config(void) {
    FILE *fp = fopen(cfg_file, "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
