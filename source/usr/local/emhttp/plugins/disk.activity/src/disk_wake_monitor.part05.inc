            (long long)now_ms(), tracking_enabled ? "true" : "false", poll_seconds);
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
    load_runtime_config();
    int64_t t = now_ms();
    for (int i = 0; i < device_count; i++) {
        device_t *d = &devices[i];
        power_state_t old = d->state;
        power_state_t cur = query_power(d->dev);
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

    if (!open_files_enabled) {
        fprintf(out, "{\"updated\":%lld,\"enabled\":false,\"files\":[]}\n", (long long)now_ms());
        fclose(out); rename(tmp, open_files_file); return;
    }

    open_file_t *files = calloc((size_t)open_files_limit, sizeof(open_file_t));
    if (!files) { fclose(out); unlink(tmp); return; }
    int count = 0, truncated = 0;
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *pe;
        while ((pe = readdir(proc)) != NULL) {
            char *end = NULL;
            long parsed = strtol(pe->d_name, &end, 10);
            if (!pe->d_name[0] || !end || *end || parsed <= 0 || parsed > INT_MAX) continue;
            pid_t pid = (pid_t)parsed;
            if (pid == getpid()) continue;
            char fd_dir_path[128]; snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
            DIR *fd_dir = opendir(fd_dir_path); if (!fd_dir) continue;
            char comm[STR_SMALL] = "", exe[STR_MED] = "", cid[128] = "", cname[256] = "";
            int identity_loaded = 0;
            struct dirent *fe;
            while ((fe = readdir(fd_dir)) != NULL) {
                if (fe->d_name[0] == '.') continue;
                char fd_path[160], target[STR_PATH];
                snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%.31s", pid, fe->d_name);
                ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
                if (n <= 0) continue;
                target[n] = '\0';
                if (target[0] != '/') continue;

                int idx = find_device_for_path_or_stat(target, NULL);
                struct stat st;
                if (idx < 0) {
                    if (stat(fd_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                    idx = find_device_for_path_or_stat(target, &st);
                } else {
                    if (stat(fd_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                }
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
            (long long)now_ms(), truncated ? "true" : "false");
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
