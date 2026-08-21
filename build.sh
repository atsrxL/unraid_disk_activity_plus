#!/bin/bash
set -euo pipefail
umask 022

VERSION="${1:-$(date +%Y.%m.%d)}"
if [[ ! "$VERSION" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}([.][0-9]+)?$ ]]; then
  echo "Invalid version: $VERSION" >&2
  exit 1
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
PLUGIN="$ROOT/source/usr/local/emhttp/plugins/disk.activity"
OUT="$ROOT/build"
SRC="$PLUGIN/src/disk_wake_monitor.c"
PACKAGE_NAME="disk.activity-$VERSION.txz"
PACKAGE="$OUT/$PACKAGE_NAME"
MD5_NAME="disk.activity-$VERSION.md5"
SHA256_NAME="disk.activity-$VERSION.sha256"

IFS=. read -r RELEASE_YEAR RELEASE_MONTH RELEASE_DAY RELEASE_REVISION <<<"$VERSION"
RELEASE_REVISION="${RELEASE_REVISION:-0}"
DATE_BIN=$(command -v date)
if ! "$DATE_BIN" -u -d '2000-01-01 00:00:00 UTC' +%s >/dev/null 2>&1; then
  if command -v gdate >/dev/null 2>&1; then
    DATE_BIN=$(command -v gdate)
  else
    echo "GNU date is required to derive a reproducible package timestamp" >&2
    exit 1
  fi
fi
RELEASE_EPOCH=$("$DATE_BIN" -u -d "$RELEASE_YEAR-$RELEASE_MONTH-$RELEASE_DAY 00:00:00 UTC" +%s) || {
  echo "Invalid calendar date in version: $VERSION" >&2
  exit 1
}
SOURCE_DATE_EPOCH=$((RELEASE_EPOCH + 10#$RELEASE_REVISION))
export SOURCE_DATE_EPOCH

TAR_BIN="${TAR:-tar}"
if ! "$TAR_BIN" --version 2>/dev/null | head -n 1 | grep -q 'GNU tar'; then
  if command -v gtar >/dev/null 2>&1; then
    TAR_BIN=gtar
  else
    echo "GNU tar is required so package ownership can be normalized to root:root" >&2
    exit 1
  fi
fi

mkdir -p "$PLUGIN/bin" "$OUT"
rm -f "$PACKAGE" "$OUT/$MD5_NAME" "$OUT/$SHA256_NAME"
[ -f "$SRC" ] || { echo "Missing monitor source: $SRC" >&2; exit 1; }

CC="${CC:-gcc}"
"$CC" -O2 -static -s -Wall -Wextra -Werror \
  -DDAP_VERSION="\"$VERSION\"" \
  -o "$PLUGIN/bin/disk_wake_monitor" "$SRC"

"$PLUGIN/bin/disk_wake_monitor" --version
"$PLUGIN/bin/disk_wake_monitor" --help >/dev/null

chmod +x \
  "$PLUGIN/bin/disk_wake_monitor" \
  "$PLUGIN/scripts/rc.disk_activity" \
  "$PLUGIN/scripts/disk_wake_tracker" \
  "$PLUGIN/event/started/disk_activity_start" \
  "$PLUGIN/event/stopping_svcs/disk_activity_stop"

for f in "$PLUGIN"/*.page "$PLUGIN"/include/*.php; do
  php -l "$f" >/dev/null
done
bash -n "$PLUGIN/scripts/rc.disk_activity"
bash -n "$PLUGIN/scripts/disk_wake_tracker"
bash -n "$PLUGIN/event/started/disk_activity_start"
bash -n "$PLUGIN/event/stopping_svcs/disk_activity_stop"

cd "$ROOT/source"
"$TAR_BIN" \
  --owner=0 --group=0 --numeric-owner \
  --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
  -cJf "$PACKAGE" usr/

# Slackware installpkg/upgradepkg preserves archive ownership. Refuse to publish
# a package that could change /usr or plugin files to the CI runner's UID/GID.
bad_owner=$("$TAR_BIN" --numeric-owner -tvJf "$PACKAGE" | awk '$2 != "0/0" { print; exit }')
if [ -n "$bad_owner" ]; then
  echo "Package contains a non-root owner/group: $bad_owner" >&2
  exit 1
fi

if "$TAR_BIN" -tf "$PACKAGE" | awk '
  /^\// || $0 ~ /(^|\/)\.\.($|\/)/ { bad=1 }
  $0 !~ /^usr\// { bad=1 }
  END { exit bad ? 0 : 1 }
'; then
  echo "Package contains an unsafe or unexpected path" >&2
  exit 1
fi

(
  cd "$OUT"
  md5sum "$PACKAGE_NAME" > "$MD5_NAME"
  sha256sum "$PACKAGE_NAME" > "$SHA256_NAME"
  md5sum -c "$MD5_NAME"
  sha256sum -c "$SHA256_NAME"
)

echo "Built: $PACKAGE"
