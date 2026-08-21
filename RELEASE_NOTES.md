## Disk Activity Plus 2026.08.21.4

This release removes the original Activity % subsystem and keeps Disk Activity Plus focused on HDD wake diagnostics.

### Removed
- Main-page Activity % column injection.
- Separate `disk_activity` daemon that sampled `/proc/diskstats` every 2 seconds.
- Legacy `DiskActivity.php` API and Activity CSS.
- Activity display-style and averaging-window settings.

### Kept
- HDD ACTIVE/STANDBY state tracking.
- Physical STANDBY → ACTIVE wake history and per-disk statistics.
- HIGH/MEDIUM/UNKNOWN process attribution.
- Live open-file snapshots and Dashboard tile.
- Reset Wake Statistics, bounded history retention, and RAM caching.

### Upgrade cleanup
- Old Activity files are explicitly removed before and after package upgrade.
- Stale `display=` and `window=` keys are removed from existing plugin configuration.
- Legacy `DiskActivitySettings.page` cleanup remains in place so only the User Utilities entry is visible.
