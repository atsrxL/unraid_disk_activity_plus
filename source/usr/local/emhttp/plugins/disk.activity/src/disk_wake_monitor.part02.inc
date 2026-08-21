        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        trim(line); trim(eq);
        if (*eq == '"') {
            memmove(eq, eq + 1, strlen(eq));
            char *q = strrchr(eq, '"'); if (q) *q = '\0';
        }
        if (!strcmp(line, "wake_tracking")) tracking_enabled = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        else if (!strcmp(line, "wake_poll")) {
            int v = atoi(eq); if (v >= 2 && v <= 60) poll_seconds = v;
        }
        else if (!strcmp(line, "wake_verbose")) verbose = (!strcasecmp(eq, "yes") || !strcmp(eq, "1") || !strcasecmp(eq, "true"));
        else if (!strcmp(line, "wake_detector")) {
            if (!strcasecmp(eq, "auto") || !strcasecmp(eq, "unraid") || !strcasecmp(eq, "smartctl"))
                snprintf(wake_detector, sizeof(wake_detector), "%s", eq);
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
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "LC_ALL=C smartctl -n standby -i /dev/%.63s 2>&1", dev);
