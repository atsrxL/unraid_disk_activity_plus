## Disk Activity Plus 2026.08.21.1

This release turns the wake-attribution prototype into a safer long-running Unraid utility.

### UI
- Single **Settings → User Utilities → Disk Activity Plus** entry with two tabs: **Activity / Open Files** and **Wake History**.
- Native sortable Dashboard tile showing files currently open on monitored HDD pools.
- Reset button for wake statistics/history.

### Attribution and reliability
- HIGH is reserved for fanotify access immediately preceding physical disk I/O.
- MEDIUM is emitted only when exactly one process has a matching open descriptor at I/O onset.
- Multiple plausible open-FD processes stay UNKNOWN/ambiguous and do not pollute named source percentages.
- Docker/Podman names are retained and current open files are generated from `/proc` into RAM.
- ZFS mapping now ignores datasets that are not actually mounted.

### Long-running behavior
- Wake history is bounded by age and maximum event count.
- Wake-history API caches unchanged results in RAM instead of reparsing persistent history every poll.
- Dashboard and open-file pages only read RAM snapshots; they do not scan the file tree.

### Release safety
- Release builds validate PHP, shell and C source.
- Releases are immutable and tags point at the exact commit that was built.
