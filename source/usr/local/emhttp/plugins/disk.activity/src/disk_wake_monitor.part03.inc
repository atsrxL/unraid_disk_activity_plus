    }
    d->ambiguous_count = identity_count;
    return 0;
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
            if (age >= 0 && age <= PRE_IO_CORRELATION_MS) d->candidate = d->recent_event;
        }
        if (tracking_enabled && !d->candidate.valid) capture_open_fd_candidate(d, t);
        if (verbose) {
            fprintf(stderr, "physical I/O onset %s/%s ticks=%llu candidate=%s ambiguous=%d\n",
                    d->name, d->dev, (unsigned long long)ticks,
                    d->candidate.valid ? d->candidate.comm : "unknown", d->ambiguous_count);
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
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        trim(line); trim(eq);
        if (*eq == '"') {
            memmove(eq, eq + 1, strlen(eq));
            char *q = strrchr(eq, '"'); if (q) *q = '\0';
        }
        if (!strcmp(line, "wake_tracking")) tracking_enabled = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        else if (!strcmp(line, "wake_poll")) { int v = atoi(eq); if (v >= 2 && v <= 60) poll_seconds = v; }
        else if (!strcmp(line, "wake_verbose")) verbose = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        else if (!strcmp(line, "open_files_dashboard")) open_files_enabled = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        else if (!strcmp(line, "open_files_limit")) { int v = atoi(eq); if (v >= 10 && v <= MAX_OPEN_FILES) open_files_limit = v; }
        else if (!strcmp(line, "history_days")) { int v = atoi(eq); if (v >= 7 && v <= 3650) history_days = v; }
        else if (!strcmp(line, "history_max")) { int v = atoi(eq); if (v >= 1000 && v <= 200000) history_max = v; }
        else if (!strcmp(line, "wake_detector")) {
            if (!strcasecmp(eq, "auto") || !strcasecmp(eq, "unraid") || !strcasecmp(eq, "smartctl")) snprintf(wake_detector, sizeof(wake_detector), "%s", eq);
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
