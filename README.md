# Unraid Disk Activity Plus

A fork of [DerekChan65535/unraid-disk-activity](https://github.com/DerekChan65535/unraid-disk-activity) that keeps the real-time disk activity column and adds **HDD wake attribution** for Unraid 7.3+.

## Added in Plus

- Detect physical rotational-drive `STANDBY → ACTIVE` transitions.
- Correlate userspace filesystem access with the first real block I/O seen in `/proc/diskstats`.
- Record PID, process, Docker/Podman container, operation, path and attribution confidence.
- ZFS-aware mapping from physical pool members to mounted datasets.
- Disk Wake History page with 24-hour / 7-day wake counts, 7-day daily average and source share.
- Conservative `HIGH` / `UNKNOWN` attribution: kernel/ZFS activity is not guessed as a userspace culprit.
- Low boot-flash wear: only confirmed wake events are persisted.

## Install

Paste this URL into **Unraid → Plugins → Install Plugin**:

```text
https://raw.githubusercontent.com/atsrxL/unraid_disk_activity_plus/main/disk.activity.plg
```

> This fork intentionally keeps the internal plugin name `disk.activity`, so install it **instead of** the original Disk Activity plugin, not alongside it.

## Wake history

After installation open **Settings → Disk Wake History**.

Default detector mode is `auto`: use Unraid's cached spin state first, with `smartctl -n standby` only as a fallback.

Wake history is stored at `/boot/config/plugins/disk.activity/wake-history.jsonl`.

## Attribution model

A wake receives `HIGH` confidence only when a userspace fanotify event occurs within the attribution window immediately before the first physical block-I/O change while the disk is believed to be asleep, followed by confirmation that the disk became active.

If the disk wakes but there is not enough evidence, the source is recorded as `UNKNOWN` rather than guessing. Metadata-only syscalls and some ZFS/kernel paths can therefore appear as unknown; eBPF metadata syscall tracing is a possible future enhancement.

## Credits

Based on the original Disk Activity plugin by DerekChan65535. Plus wake-attribution work maintained in this repository.
