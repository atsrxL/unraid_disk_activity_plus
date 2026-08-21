            d->state = cur;
        }
    }
    write_state_snapshot();
}

static int setup_fanotify(void) {
    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "fanotify_init failed: %s\n", strerror(errno));
        return -1;
    }
    uint64_t mask = FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN_EXEC;
    int marks = 0;
    for (int i = 0; i < unique_mount_count; i++) {
        int fs_rc = -1;
#ifdef FAN_MARK_FILESYSTEM
        fs_rc = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, unique_mounts[i]);
#endif
        // Some filesystems accept FAN_MARK_FILESYSTEM but do not emit events
        // for bind-mounted container access. Add a mount mark as well; duplicate
        // notifications are harmless because only the newest candidate is kept.
        int mount_rc = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, unique_mounts[i]);
        if (fs_rc == 0 || mount_rc == 0) {
            marks++;
            if (verbose) fprintf(stderr, "watch filesystem %s fs=%s mount=%s\n", unique_mounts[i],
                                 fs_rc == 0 ? "yes" : "no", mount_rc == 0 ? "yes" : "no");
        } else if (verbose) {
            fprintf(stderr, "cannot watch %s: %s\n", unique_mounts[i], strerror(errno));
        }
    }
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
                    for (int i = 0; i < device_count; i++) capture_recent_event(&devices[i], m->pid, m->mask, path);
                }
                close(m->fd);
            }
            m = FAN_EVENT_NEXT(m, len);
        }
    }
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s [--map FILE] [--history FILE] [--state FILE] [--config FILE] [--verbose] [--trace-events] [--test-open-fds DEV]\n", argv0);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--map") && i + 1 < argc) snprintf(map_file, sizeof(map_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--history") && i + 1 < argc) snprintf(history_file, sizeof(history_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc) snprintf(state_file, sizeof(state_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--config") && i + 1 < argc) snprintf(cfg_file, sizeof(cfg_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--verbose")) verbose = 1;
        else if (!strcmp(argv[i], "--trace-events")) trace_events = 1;
        else if (!strcmp(argv[i], "--test-open-fds") && i + 1 < argc) snprintf(test_open_fds_dev, sizeof(test_open_fds_dev), "%s", argv[++i]);
        else { usage(argv[0]); return 2; }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);

    load_runtime_config();
    if (load_map() != 0) return 3;
    if (test_open_fds_dev[0]) {
        int idx = find_device(test_open_fds_dev);
        if (idx < 0) return 5;
        if (!capture_open_fd_candidate(&devices[idx], now_ms())) return 6;
        candidate_t *c = &devices[idx].candidate;
        resolve_container_name(c->container_id, c->container, sizeof(c->container));
        fprintf(stdout, "pid=%d process=%s container_id=%s container=%s path=%s confidence=%s evidence=%s\n",
                c->pid, c->comm, c->container_id, c->container, c->path, c->confidence, c->evidence);
        return 0;
    }
    int fanfd = setup_fanotify();
    if (fanfd < 0) return 4;

    sample_diskstats();
    check_power_states();
    int64_t next_power = now_ms() + (int64_t)poll_seconds * 1000;
    int64_t next_io = now_ms() + IO_SAMPLE_MS;

    while (running) {
        int64_t now = now_ms();
        int64_t until_power = next_power > now ? next_power - now : 0;
        int64_t until_io = next_io > now ? next_io - now : 0;
        int64_t wait_ms = until_power < until_io ? until_power : until_io;
        if (wait_ms > 1000) wait_ms = 1000; // reload config/respond to stop quickly
        struct pollfd pfd = { .fd = fanfd, .events = POLLIN };
        int rc = poll(&pfd, 1, (int)wait_ms);
        if (rc > 0 && (pfd.revents & POLLIN)) process_fanotify(fanfd);
        now = now_ms();
        if (now >= next_io) {
            sample_diskstats();
            next_io = now + IO_SAMPLE_MS;
        }
        if (now >= next_power) {
            sample_diskstats();
            check_power_states();
            next_power = now + (int64_t)poll_seconds * 1000;
        }
    }

    close(fanfd);
    return 0;
}
