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
    fputs("\",\"evidence\":\"", fp); json_escape(fp, c->valid && c->evidence[0] ? c->evidence : "none");
    fputs("\"}\n", fp);
    fclose(fp);
    d->last_wake_ms = detected_ms;
}

static void write_state_snapshot(void) {
    char tmp[STR_PATH + 16];
    snprintf(tmp, sizeof(tmp), "%s.tmp", state_file);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return;
    fprintf(fp, "{\"updated\":%lld,\"tracking\":%s,\"poll_seconds\":%d,\"detector\":\"", (long long)now_ms(), tracking_enabled ? "true" : "false", poll_seconds);
    json_escape(fp, wake_detector);
    fputs("\",\"devices\":[", fp);
    for (int i = 0; i < device_count; i++) {
        device_t *d = &devices[i];
        if (i) fputc(',', fp);
        fputs("{\"device\":\"", fp); json_escape(fp, d->dev);
        fputs("\",\"disk\":\"", fp); json_escape(fp, d->name);
        fputs("\",\"state\":\"", fp); fputs(state_name(d->state), fp);
        fprintf(fp, "\",\"last_wake\":%lld,\"io_pending\":%s,\"io_ts\":%lld,\"candidate\":%s}",
                (long long)d->last_wake_ms, d->io_pending ? "true" : "false",
                (long long)d->io_onset_ms, d->candidate.valid ? "true" : "false");
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
            if (cur == PWR_STANDBY) {
                d->standby_observed_ms = t;
                clear_wake_window(d);
            }
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
