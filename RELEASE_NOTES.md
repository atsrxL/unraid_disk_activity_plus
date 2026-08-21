## Disk Activity Plus 2026.08.21.3

This hotfix removes the legacy settings page that could remain installed after upgrading from earlier builds and cause a second Disk Activity icon under System/Other Settings.

### Fixed
- Explicitly remove `/usr/local/emhttp/plugins/disk.activity/DiskActivitySettings.page` before and after package upgrade.
- Keep only **Settings → User Utilities → Disk Activity Plus** as the visible plugin entry.
- Preserve the two tabs: **Activity / Open Files** and **Wake History**.

### Included from 2026.08.21.2
- Correct Unraid `Type="xmenu"` + `Tabs="true"` tab container.
- Native Dashboard open-files tile, wake history/reset, conservative attribution, RAM-only open-file snapshots and bounded history retention.
