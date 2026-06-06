#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files}"
TARGET="${TARGET:-luowei@lwds920.local:/volume1/data/MyBigData/Wechats/xwechat_files}"

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "源目录不存在: $SOURCE_DIR" >&2
  exit 1
fi

echo "源目录: $SOURCE_DIR"
echo "目标目录: $TARGET"

ssh_target="${TARGET%%:*}"
remote_path="${TARGET#*:}"

if [[ "$ssh_target" == "$TARGET" || -z "$remote_path" ]]; then
  echo "TARGET 必须是 user@host:/absolute/path 格式" >&2
  exit 1
fi

ssh -o BatchMode=yes "$ssh_target" "mkdir -p '$remote_path'"

echo "开始 rsync 增量备份..."
rsync -aE --partial --append-verify --stats --human-readable \
  "$SOURCE_DIR/" \
  "$TARGET/"

echo "远端容量与关键目录检查:"
ssh -o BatchMode=yes "$ssh_target" \
  "du -sh '$remote_path' '$remote_path/luowei505050_6b7a/db_storage' '$remote_path/luowei505050_6b7a/msg' 2>/dev/null; \
   printf 'files='; find '$remote_path' -type f | wc -l; \
   printf 'dirs='; find '$remote_path' -type d | wc -l; \
   test -f '$remote_path/README.md' && echo README_OK"
