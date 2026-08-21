#!/bin/bash
set -euo pipefail
VERSION="${1:-$(date +%Y.%m.%d)}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
PLUGIN="$ROOT/source/usr/local/emhttp/plugins/disk.activity"
OUT="$ROOT/build"
mkdir -p "$PLUGIN/bin" "$OUT"
SRC="$PLUGIN/src/disk_wake_monitor.c"
PARTS=("$PLUGIN"/src/disk_wake_monitor.part*.inc)
[ -e "${PARTS[0]}" ] || { echo "Missing disk_wake_monitor source parts" >&2; exit 1; }
cat "${PARTS[@]}" > "$SRC"
CC="${CC:-gcc}"
"$CC" -O2 -static -s -Wall -Wextra -Werror -o "$PLUGIN/bin/disk_wake_monitor" "$SRC"
rm -f "$SRC"
chmod +x "$PLUGIN/bin/disk_wake_monitor" "$PLUGIN/scripts/disk_activity" "$PLUGIN/scripts/rc.disk_activity" "$PLUGIN/scripts/disk_wake_tracker" "$PLUGIN/event/started/disk_activity_start" "$PLUGIN/event/stopping_svcs/disk_activity_stop"
for f in "$PLUGIN"/*.page "$PLUGIN"/include/*.php; do php -l "$f" >/dev/null; done
bash -n "$PLUGIN/scripts/disk_activity"
bash -n "$PLUGIN/scripts/rc.disk_activity"
bash -n "$PLUGIN/scripts/disk_wake_tracker"
cd "$ROOT/source"
tar cJf "$OUT/disk.activity-$VERSION.txz" usr/
md5sum "$OUT/disk.activity-$VERSION.txz" | awk '{print $1}' > "$OUT/disk.activity-$VERSION.md5"
sha256sum "$OUT/disk.activity-$VERSION.txz" | awk '{print $1}' > "$OUT/disk.activity-$VERSION.sha256"
echo "Built: $OUT/disk.activity-$VERSION.txz"
