#!/usr/bin/env bash
# install.sh - symlink the nfx-* tools into a bin directory on PATH (default /usr/local/bin).
# The tools resolve their own location, so the checkout can live anywhere (USB stick, /opt, ~).
set -eu
DEST="${1:-/usr/local/bin}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DEST"
for t in "$HERE"/bin/nfx-*; do
  chmod +x "$t"
  ln -sf "$t" "$DEST/$(basename "$t")"
done
echo "linked $(ls "$HERE"/bin/nfx-* | wc -l | tr -d ' ') tools into $DEST"
