    for (int i = 0; i < device_count; i++) {
        for (int m = 0; m < devices[i].mount_count; m++) {
            if (path_matches_mount(path, devices[i].mounts[m])) return i;
        }
    }
    if (stp) {
        for (int i = 0; i < device_count; i++) {
            if (device_matches_dev_id(&devices[i], stp->st_dev)) return i;
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
}

static void clear_wake_window(device_t *d) {
    memset(&d->recent_event, 0, sizeof(d->recent_event));
    clear_candidate(d);
    d->io_pending = 0;
    d->io_onset_ms = 0;
}

static void capture_recent_event(device_t *d, pid_t pid, uint64_t mask, const char *path) {
    if (!tracking_enabled || pid <= 0 || pid == getpid()) return;
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
    resolve_container_name(c->container_id, c->container, sizeof(c->container));
    snprintf(c->confidence, sizeof(c->confidence), "high");
    snprintf(c->evidence, sizeof(c->evidence), "fanotify");
}

static int capture_open_fd_candidate(device_t *d, int64_t t) {
    if (!tracking_enabled) return 0;
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    candidate_t unique;
    memset(&unique, 0, sizeof(unique));
    pid_t identities[MAX_OPEN_IDENTITIES];
    int identity_count = 0;
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
        int matched_pid = 0;
        candidate_t current;
        memset(&current, 0, sizeof(current));

        struct dirent *fe;
        while ((fe = readdir(fd_dir)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            char fd_path[160], target[STR_PATH];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%.31s", pid, fe->d_name);
            ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            struct stat st;
            if (stat(fd_path, &st) != 0) continue;
            if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) continue;
            if (!device_matches_dev_id(d, st.st_dev)) {
                int prefix_match = 0;
                for (int m = 0; m < d->mount_count; m++) {
                    if (path_matches_mount(target, d->mounts[m])) { prefix_match = 1; break; }
                }
                if (!prefix_match) continue;
            }

            current.valid = 1;
            current.ts_ms = t;
            current.pid = pid;
            snprintf(current.event, sizeof(current.event), "OPEN_FD");
            snprintf(current.path, sizeof(current.path), "%s", target);
            read_proc_text(pid, "comm", current.comm, sizeof(current.comm));
            read_proc_exe(pid, current.exe, sizeof(current.exe));
            get_container_id(pid, current.container_id, sizeof(current.container_id));
            resolve_container_name(current.container_id, current.container, sizeof(current.container));
            snprintf(current.confidence, sizeof(current.confidence), "medium");
            snprintf(current.evidence, sizeof(current.evidence), "open_fd_unique");
            matched_pid = 1;
            break;
        }
        closedir(fd_dir);

        if (matched_pid) {
            int seen = 0;
            for (int i = 0; i < identity_count; i++) if (identities[i] == pid) { seen = 1; break; }
            if (!seen && identity_count < MAX_OPEN_IDENTITIES) {
                identities[identity_count++] = pid;
                if (identity_count == 1) unique = current;
                else if (identity_count > 1) unique.valid = 0;
            }
        }
    }
    closedir(proc);

    if (identity_count == 1 && unique.valid) {
        d->candidate = unique;
        d->ambiguous_count = 0;
        return 1;
