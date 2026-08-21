## Disk Activity Plus 2026.08.21

First Plus release based on upstream Disk Activity 2026.06.08.

### New
- HDD wake attribution with STANDBY → ACTIVE event history.
- PID/process/container/path correlation.
- ZFS physical-device to dataset mapping.
- 24h / 7d wake statistics and wake-source percentages.
- Conservative HIGH/UNKNOWN attribution.

### Notes
This fork uses the same internal plugin name (`disk.activity`) as upstream and is intended to replace the original plugin, not run alongside it.
