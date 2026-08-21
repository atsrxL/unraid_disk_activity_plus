## Disk Activity Plus 2026.08.21.7

This release hardens wake attribution, WebGUI freshness and the complete install/runtime lifecycle.

### WebGUI and API

- Keep live tracker and disk power state outside the history cache.
- Recompute rolling 24-hour/7-day statistics at minute boundaries.
- Prevent monitored file paths from escaping HTML attributes.
- Resume polling after browser back/forward cache restores.
- Keep Reset Wake Statistics simple: POST plus explicit action, rejecting only browser requests explicitly marked cross-site.

### Wake monitor

- Require one unique PID in the correlation window before assigning HIGH confidence.
- Prefer the original `/mnt/user` caller over the intermediate `shfs` process; ambiguous callers remain UNKNOWN.
- Invalidate attribution windows after fanotify queue overflow.
- Use monotonic scheduling and bounded Docker/Podman, smartctl and `/proc` work.
- Reject explicit filesystem-device mismatches and preserve history if pruning runs out of memory.

### Installation and release safety

- Build byte-reproducible txz packages with every archive entry owned by root:root.
- Enforce the release package MD5 from the plugin definition before installation.
- Keep the existing monitor running until the replacement package has downloaded, verified and installed.
- Serialize service lifecycle operations and verify PID executable/start time before signaling.
- Publish only by explicit dispatch from the final current `main` commit, with repeat-build and checksum validation.
