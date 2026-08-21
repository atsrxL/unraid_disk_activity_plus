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
    if (!tracking_enabled || d->state != PWR_STANDBY || d->io_pending) return;
    if (pid <= 0 || pid == getpid()) return;

    int matches = 0;
    for (int i = 0; i < d->mount_count; i++) {
        if (path_matches_mount(path, d->mounts[i])) { matches = 1; break; }
    }
    if (!matches) return;

    candidate_t *c = &d->recent_event;
    memset(c, 0, sizeof(*c));
    c->valid = 1;
    c->ts_ms = now_ms();
    c->pid = pid;
    snprintf(c->event, sizeof(c->event), "%s", mask_name(mask));
    snprintf(c->path, sizeof(c->path), "%s", path);
    read_proc_text(pid, "comm", c->comm, sizeof(c->comm));
    read_proc_exe(pid, c->exe, sizeof(c->exe));

    if (verbose) {
        fprintf(stderr, "recent %s/%s pid=%d %s %s\n", d->name, d->dev, pid, c->comm, c->path);
    }
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
