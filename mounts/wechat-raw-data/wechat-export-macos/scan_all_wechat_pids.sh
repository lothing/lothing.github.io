#!/bin/sh
set -eu

cd "$(dirname "$0")"

mkdir -p scan_logs
rm -f scan_logs/all_keys.*.json scan_logs/scan_pid_*.log scan_logs/merged_keys.json

ps -ax -o pid= -o args= \
  | awk '/\/Applications\/WeChat\.app\// && !/crashpad_handler/ && !/scan_all_wechat_pids/ {print $1}' \
  | sort -n \
  | while read -r pid; do
      [ -n "$pid" ] || continue
      echo "=== scanning pid $pid ==="
      sudo ./find_all_keys_macos "$pid" 2>&1 | tee "scan_logs/scan_pid_${pid}.log"
      if python3 - "$pid" <<'PY'
import json
import os
import sys

pid = sys.argv[1]
path = "all_keys.json"
if not os.path.exists(path):
    raise SystemExit(1)
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    raise SystemExit(1)
entries = {k: v for k, v in data.items() if not k.startswith("_")}
print(f"pid {pid}: key entries={len(entries)}")
raise SystemExit(0 if entries else 1)
PY
      then
        cp all_keys.json "scan_logs/all_keys.${pid}.json"
      fi
    done

python3 - <<'PY'
import glob
import json
import os

merged = {}
for path in sorted(glob.glob("scan_logs/all_keys.*.json")):
    with open(path) as f:
        data = json.load(f)
    for key, value in data.items():
        if key.startswith("_"):
            continue
        merged[key] = value

with open("scan_logs/merged_keys.json", "w") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2)
    f.write("\n")

with open("all_keys.json", "w") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2)
    f.write("\n")

print(f"merged key entries={len(merged)}")
print("wrote scan_logs/merged_keys.json")
print("wrote all_keys.json")
PY
