#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${1:-"$ROOT_DIR/release-assets.json"}"

if [[ ! -f "$MANIFEST" ]]; then
  echo "manifest not found: $MANIFEST" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated. Run: gh auth refresh -h github.com" >&2
  exit 1
fi

read_manifest() {
  python3 - "$MANIFEST" "$1" <<'PY'
import json, sys
from pathlib import Path
m=json.loads(Path(sys.argv[1]).read_text())
key=sys.argv[2]
print(m[key])
PY
}

REPO="$(read_manifest repo)"
TAG="$(read_manifest release_tag)"
ASSET_DIR="$HOME/projects/Others/wechat-raw-data-release-assets/$TAG"

if [[ ! -d "$ASSET_DIR" ]]; then
  echo "asset staging dir not found: $ASSET_DIR" >&2
  exit 1
fi

if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  echo "release exists: $TAG"
else
  gh release create "$TAG" \
    --repo "$REPO" \
    --title "WeChat raw data $TAG" \
    --notes "Private large-file assets for wechat-raw-data. Restore with scripts/download-release-assets.sh."
fi

gh release upload "$TAG" "$ASSET_DIR"/* --repo "$REPO" --clobber
echo "uploaded assets for $TAG"
