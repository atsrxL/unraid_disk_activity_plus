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
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "LC_ALL=C smartctl -n standby -i /dev/%.63s 2>&1", dev);
    FILE *fp = popen(cmd, "r");
    if (!fp) return PWR_UNKNOWN;
    char out[8192]; size_t used = 0; out[0] = '\0';
    while (used + 1 < sizeof(out) && fgets(out + used, (int)(sizeof(out) - used), fp)) used = strlen(out);
    pclose(fp);
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

static void prune_history(void) {
    if (history_days <= 0 || history_max <= 0) return;
    FILE *fp = fopen(history_file, "r+");
    if (!fp) return;
    if (flock(fileno(fp), LOCK_EX) != 0) { fclose(fp); return; }

    size_t cap = 1024, count = 0;
    char **lines = calloc(cap, sizeof(char *));
    if (!lines) { flock(fileno(fp), LOCK_UN); fclose(fp); return; }
    int64_t cutoff = now_ms() - (int64_t)history_days * 86400000LL;
    char *line = NULL; size_t n = 0;
    while (getline(&line, &n, fp) >= 0) {
        int64_t ts = extract_json_ts(line);
        if (ts && ts < cutoff) continue;
        if (count == cap) {
            size_t newcap = cap * 2;
            char **tmp = realloc(lines, newcap * sizeof(char *));
            if (!tmp) break;
            lines = tmp; cap = newcap;
        }
        lines[count++] = strdup(line);
    }
    free(line);

    size_t start = count > (size_t)history_max ? count - (size_t)history_max : 0;
    rewind(fp);
    if (ftruncate(fileno(fp), 0) == 0) {
        for (size_t i = start; i < count; i++) if (lines[i]) fputs(lines[i], fp);
        fflush(fp);
    }
    for (size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
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
    FILE *fp = fopen(history_file, "a");
    if (!fp) {
        fprintf(stderr, "cannot append history %s: %s\n", history_file, strerror(errno));
        return;
    }
    if (flock(fileno(fp), LOCK_EX) != 0) { fclose(fp); return; }
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
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    d->last_wake_ms = detected_ms;
}

static void write_state_snapshot(void) {
    char tmp[STR_PATH + 32];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", state_file, getpid());
    FILE *fp = fopen(tmp, "w");
    if (!fp) return;
    fprintf(fp, "{\"updated\":%lld,\"tracking\":%s,\"poll_seconds\":%d,\"detector\":\"",
