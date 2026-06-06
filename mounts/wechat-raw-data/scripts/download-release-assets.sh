#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${1:-"$ROOT_DIR/release-assets.json"}"

if [[ ! -f "$MANIFEST" ]]; then
  echo "manifest not found: $MANIFEST" >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  mapfile -t ITEMS < <(python3 - "$MANIFEST" <<'PY'
import json, sys
from pathlib import Path
m=json.loads(Path(sys.argv[1]).read_text())
for a in m.get("assets", []):
    print("\t".join([a["path"], a["asset_name"], a["download_url"], str(a["size"]), a["sha256"]]))
PY
)
else
  echo "python3 is required" >&2
  exit 1
fi

read_manifest() {
  python3 - "$MANIFEST" "$1" <<'PY'
import json, sys
from pathlib import Path
m=json.loads(Path(sys.argv[1]).read_text())
print(m[sys.argv[2]])
PY
}

REPO="$(read_manifest repo)"
TAG="$(read_manifest release_tag)"
GH_AUTHENTICATED=0
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  GH_AUTHENTICATED=1
fi

download_one() {
  local rel="$1"
  local asset_name="$2"
  local url="$3"
  local size="$4"
  local sha="$5"
  local out="$ROOT_DIR/$rel"
  local tmp="$out.download"
  local tmp_dir
  mkdir -p "$(dirname "$out")"

  if [[ -f "$out" ]] && [[ "$(wc -c < "$out" | tr -d ' ')" == "$size" ]]; then
    if command -v shasum >/dev/null 2>&1; then
      local actual
      actual="$(shasum -a 256 "$out" | awk '{print $1}')"
      if [[ "$actual" == "$sha" ]]; then
        echo "OK existing: $rel"
        return
      fi
    fi
  fi

  echo "download: $rel"
  if [[ "$GH_AUTHENTICATED" == "1" ]]; then
    tmp_dir="$(mktemp -d)"
    gh release download "$TAG" \
      --repo "$REPO" \
      --pattern "$asset_name" \
      --dir "$tmp_dir" \
      --clobber
    mv "$tmp_dir/$asset_name" "$tmp"
    rmdir "$tmp_dir"
  elif command -v curl >/dev/null 2>&1; then
    if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
      curl -L --fail --retry 3 \
        --header "Authorization: Bearer ${GH_TOKEN:-$GITHUB_TOKEN}" \
        --output "$tmp" "$url"
    else
      curl -L --fail --retry 3 --output "$tmp" "$url"
    fi
  else
    echo "gh or curl is required" >&2
    exit 1
  fi

  if command -v shasum >/dev/null 2>&1; then
    local actual
    actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
    if [[ "$actual" != "$sha" ]]; then
      echo "sha256 mismatch for $rel" >&2
      echo "expected $sha" >&2
      echo "actual   $actual" >&2
      exit 1
    fi
  fi
  mv "$tmp" "$out"
}

for item in "${ITEMS[@]}"; do
  IFS=$'\t' read -r rel asset_name url size sha <<< "$item"
  download_one "$rel" "$asset_name" "$url" "$size" "$sha"
done

echo "all release assets restored"
