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
}

static void resolve_container_name_uncached(const char *id, char *out, size_t outsz) {
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

static void resolve_container_name(const char *id, char *out, size_t outsz) {
    out[0] = '\0';
    if (!id || !id[0]) return;
    for (int i = 0; i < container_cache_count; i++) {
        if (!strcmp(container_cache[i].id, id)) {
            snprintf(out, outsz, "%s", container_cache[i].name);
            return;
        }
    }
    resolve_container_name_uncached(id, out, outsz);
    if (container_cache_count < (int)(sizeof(container_cache) / sizeof(container_cache[0]))) {
        snprintf(container_cache[container_cache_count].id, sizeof(container_cache[container_cache_count].id), "%s", id);
        snprintf(container_cache[container_cache_count].name, sizeof(container_cache[container_cache_count].name), "%s", out);
        container_cache_count++;
    }
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
