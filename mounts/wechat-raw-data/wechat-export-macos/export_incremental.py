#!/usr/bin/env python3
"""
微信增量消息导出脚本

与 export_all_chats_jsonl.py（全量导出）配对使用。
读取上一次导出的最后时间戳，只导出该时间之后的增量消息，
追加到现有 JSONL 文件末尾，并更新 manifest。

用法：
  # 首次运行：无基线文件时为全量导出
  python3 export_incremental.py --output messages.jsonl

  # 增量导出（基于上次的 checkpoint）
  python3 export_incremental.py --output messages.jsonl --checkpoint .export_checkpoint.json

  # 指定起始时间（覆盖 checkpoint）
  python3 export_incremental.py --output messages.jsonl --since "2026-06-01T00:00:00"

输出：
  - 增量 JSONL 追加到 --output 文件
  - checkpoint 更新为本次导出的最后时间戳
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import load_config


MSG_TYPES = {
    1: "文本",
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "表情",
    48: "位置",
    49: "链接/文件/小程序",
    50: "语音/视频通话",
    51: "系统消息",
    10000: "系统提示",
    10002: "撤回消息",
}


def iso_to_unix(iso_str):
    """ISO timestamp → Unix milliseconds (WeChat format)."""
    if not iso_str:
        return 0
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return 0


def load_checkpoint(checkpoint_path):
    """Load the last export checkpoint."""
    if not checkpoint_path or not os.path.exists(checkpoint_path):
        return None
    try:
        with open(checkpoint_path, "r") as f:
            cp = json.load(f)
        return cp
    except (json.JSONDecodeError, KeyError):
        return None


def save_checkpoint(checkpoint_path, last_timestamp_ms, message_count, source_files):
    """Save export checkpoint for next incremental run."""
    cp = {
        "last_timestamp_ms": last_timestamp_ms,
        "last_timestamp_iso": datetime.fromtimestamp(
            last_timestamp_ms / 1000, tz=timezone.utc
        ).isoformat(),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_exported_increment": message_count,
        "source_files": source_files,
    }
    os.makedirs(os.path.dirname(checkpoint_path) or ".", exist_ok=True)
    with open(checkpoint_path, "w") as f:
        json.dump(cp, f, ensure_ascii=False, indent=2)
    return cp


def compute_hash(text):
    """Compute a salted hash for speaker/conversation identifiers."""
    if not text:
        return ""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def export_incremental_messages(cfg, since_ms, output_path, message_dbs):
    """Export messages after since_ms from all message DBs."""
    decrypted_dir = Path(cfg["decrypted_dir"])
    count = 0
    last_ts = since_ms
    exported_dbs = []

    for db_name in message_dbs:
        db_path = decrypted_dir / db_name
        if not db_path.exists():
            print(f"  [SKIP] {db_name} (not found)", file=sys.stderr)
            continue

        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            print(f"  [ERR] {db_name}: {e}", file=sys.stderr)
            continue

        # Check table exists
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='MsgTable'"
        ).fetchone()
        if not table:
            conn.close()
            continue

        sql = "SELECT * FROM MsgTable WHERE CreateTime > ? ORDER BY CreateTime ASC"
        rows = conn.execute(sql, (since_ms,))
        db_count = 0

        with open(output_path, "a", encoding="utf-8") as out_f:
            for r in rows:
                obj = dict(r)
                ts = obj.get("CreateTime", 0)
                if ts > last_ts:
                    last_ts = ts

                msg_type = MSG_TYPES.get(obj.get("Type", -1), f"未知({obj.get('Type')})")
                speaker = obj.get("Talker", "") or ""
                content = obj.get("StrContent", "") or ""

                out_f.write(json.dumps({
                    "timestamp": datetime.fromtimestamp(
                        ts / 1000, tz=timezone.utc
                    ).isoformat(),
                    "timestamp_ms": ts,
                    "conversation_hash": f"conversation:{compute_hash(speaker)}",
                    "speaker_hash": f"speaker:{compute_hash(speaker)}",
                    "type": msg_type,
                    "text": content if isinstance(content, str) else str(content),
                    "source_db": db_name,
                }, ensure_ascii=False) + "\n")
                db_count += 1

        conn.close()
        count += db_count
        if db_count > 0:
            exported_dbs.append({"db": db_name, "new_messages": db_count})
        print(f"  [{db_name}]: +{db_count} messages", file=sys.stderr)

    return count, last_ts, exported_dbs


def main():
    parser = argparse.ArgumentParser(
        description="Incremental WeChat message export (appends to JSONL)"
    )
    parser.add_argument("--output", "-o", required=True,
                        help="JSONL output path (appended to)")
    parser.add_argument("--checkpoint", "-c",
                        default=".wechat_export_checkpoint.json",
                        help="Checkpoint file path")
    parser.add_argument("--since", default=None,
                        help="ISO timestamp override (e.g. 2026-06-01T00:00:00)")
    parser.add_argument("--decrypted-dir", default=None)
    args = parser.parse_args()

    cfg = load_config()
    decrypted_dir = Path(args.decrypted_dir or cfg["decrypted_dir"])

    # Determine since timestamp
    if args.since:
        since_ms = iso_to_unix(args.since)
        print(f"[INFO] Using --since override: {args.since} ({since_ms})")
    else:
        cp = load_checkpoint(args.checkpoint)
        if cp and cp.get("last_timestamp_ms"):
            since_ms = cp["last_timestamp_ms"]
            print(f"[INFO] Checkpoint loaded: last export at {cp.get('last_timestamp_iso')}")
        else:
            since_ms = 0
            print("[INFO] No checkpoint found — performing full export")

    # Discover message DBs
    message_dbs = sorted(
        [f"message/message_{i}.db" for i in range(20)
         if (decrypted_dir / f"message/message_{i}.db").exists()]
    )
    biz_dbs = sorted(
        [f"message/biz_message_{i}.db" for i in range(20)
         if (decrypted_dir / f"message/biz_message_{i}.db").exists()]
    )

    print(f"[INFO] Decrypted dir: {decrypted_dir}")
    print(f"[INFO] Message DBs found: {len(message_dbs)} message + {len(biz_dbs)} biz")
    print(f"[INFO] Since timestamp: {since_ms} ms")
    print(f"[INFO] Output: {args.output}")

    total, last_ts, exported = export_incremental_messages(
        cfg, since_ms, args.output, message_dbs + biz_dbs
    )

    if total > 0:
        cp = save_checkpoint(args.checkpoint, last_ts, total, exported)
        print(f"\n[DONE] Exported {total} incremental messages")
        print(f"[DONE] Checkpoint: {cp['last_timestamp_iso']}")
    else:
        print("\n[DONE] No new messages since last export")

    # Print summary
    print(f"\nSummary:")
    print(f"  Total new messages: {total}")
    print(f"  Output file: {args.output}")
    print(f"  Checkpoint: {args.checkpoint}")


if __name__ == "__main__":
    main()
