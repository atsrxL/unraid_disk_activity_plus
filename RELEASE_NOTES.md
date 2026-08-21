## Disk Activity Plus 2026.08.21.5

This release hardens the wake tracker and targets the largest remaining attribution gap: Docker/SMB accesses that go through Unraid user shares instead of directly through the underlying ZFS/physical mount path.

### Attribution improvements
- Add best-effort fanotify watches for `/mnt/user` and `/mnt/user0`.
- Correlate user-share events with the first real physical block-I/O onset.
- Promote a user-share candidate to **HIGH** only when exactly one unique PID is observed in the 2-second correlation window; multiple plausible PIDs remain UNKNOWN.
- Keep direct monitored-filesystem fanotify events as the strongest HIGH evidence.
- Preserve the conservative unique-open-FD MEDIUM fallback.

### Security / robustness
- Actually validate the current Unraid CSRF token before Reset Wake Statistics.
- Replace shell-based Docker/Podman name lookup with `fork`/`exec` and strict 64-character hex container IDs.
- Add bounded container-name TTL caching with eviction.
- Coordinate history append, read, prune and reset through one shared lock.
- Prune/reset history with atomic replacement so a crash cannot leave a half-truncated history file.
- SIGHUP now requests a config reload instead of terminating the monitor.

### Simplified UI / retention
- Remove the Dashboard Open Files tile; Open Files remains available inside the plugin troubleshooting page.
- Fix wake-history retention at **60 days** and at most **5,000 events**.
- Remove obsolete dashboard/history-retention settings from existing configs during upgrade.
- Refactor repeated frontend helpers into a readable shared JavaScript asset.

### Maintainability
- Replace the seven numbered C source fragments with one normal `disk_wake_monitor.c` source file.
- Add `--help` and `--version` to the native monitor.
- Keep `-Wall -Wextra -Werror` compilation in the release build.

`/proc/diskstats` is still read in RAM by the wake monitor only to confirm the first real physical-I/O onset; the old Activity % sampler remains removed.

<!-- release-build-trigger: 2026.08.21.5 -->
