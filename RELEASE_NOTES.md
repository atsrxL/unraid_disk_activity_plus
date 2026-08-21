## Disk Activity Plus 2026.08.21.2

This hotfix corrects the blank Disk Activity Plus page introduced by the 2026.08.21.1 UI consolidation.

### Fixed
- Use Unraid's correct `Type="xmenu"` + `Tabs="true"` container for a single plugin entry with multiple child tabs.
- Keep **Settings → User Utilities → Disk Activity Plus** as one icon while rendering **Activity / Open Files** and **Wake History** as tabs.

### Included from 2026.08.21.1
- Native sortable Dashboard tile showing files currently open on monitored HDD pools.
- Reset button for wake statistics/history.
- Conservative HIGH/MEDIUM/UNKNOWN wake attribution.
- RAM-only `/proc` open-file snapshots with Docker/Podman attribution.
- Bounded wake-history retention and RAM API caching.
- Mounted-only ZFS dataset mapping and hardened immutable release pipeline.
