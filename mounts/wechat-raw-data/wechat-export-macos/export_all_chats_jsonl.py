#!/usr/bin/env python3
"""Export all decrypted WeChat message tables to JSONL.

The output is intended as private local input for the agent-harness WeChat
normalizer. It does not resolve or print contact names by default.
"""

import argparse
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

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


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=os.path.expanduser("~/.agents/knowledge/wechat/raw/exports/wechat-all-messages.jsonl"),
        help="Private JSONL output path",
    )
    return parser.parse_args()


def message_dbs(decrypted_dir):
    msg_dir = os.path.join(decrypted_dir, "message")
    if not os.path.isdir(msg_dir):
        return []
    files = []
    for name in sorted(os.listdir(msg_dir)):
        is_message = name.startswith("message_") and "fts" not in name
        is_biz = name.startswith("biz_message_")
        if (is_message or is_biz) and name.endswith(".db"):
            files.append(os.path.join(msg_dir, name))
    return files


def load_name2id(conn):
    try:
        return {
            rowid: user_name
            for rowid, user_name in conn.execute("SELECT rowid, user_name FROM Name2Id")
        }
    except sqlite3.Error:
        return {}


def iter_msg_tables(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    ).fetchall()
    return [row[0] for row in rows]


def table_to_conversation_hash(table_name):
    return table_name.replace("Msg_", "", 1)


def export_all(output_path):
    cfg = load_config()
    decrypted_dir = cfg["decrypted_dir"]
    dbs = message_dbs(decrypted_dir)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    total = 0
    by_db = {}
    with open(output_path, "w", encoding="utf-8") as out:
        for db_path in dbs:
            db_name = os.path.basename(db_path)
            conn = sqlite3.connect(db_path)
            try:
                name2id = load_name2id(conn)
                for table in iter_msg_tables(conn):
                    conversation = table_to_conversation_hash(table)
                    try:
                        rows = conn.execute(
                            f"""
                            SELECT local_id, server_id, local_type, create_time,
                                   real_sender_id, message_content, source
                            FROM {table}
                            ORDER BY create_time ASC
                            """
                        )
                    except sqlite3.Error:
                        continue

                    for row in rows:
                        content = row[5]
                        if isinstance(content, bytes):
                            content = "[BINARY_CONTENT]"
                        elif content is None:
                            content = ""
                        sender = name2id.get(row[4], "")
                        sender_hash = hashlib.sha256(sender.encode("utf-8")).hexdigest()[:16] if sender else ""
                        timestamp = row[3] or 0
                        record = {
                            "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
                            if timestamp
                            else "",
                            "create_time": timestamp,
                            "conversation": conversation,
                            "speaker": sender_hash,
                            "type": row[2],
                            "type_name": MSG_TYPES.get(row[2], f"未知({row[2]})"),
                            "content": str(content),
                            "server_id": row[1],
                            "local_id": row[0],
                            "db": db_name,
                        }
                        out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                        total += 1
                        by_db[db_name] = by_db.get(db_name, 0) + 1
            finally:
                conn.close()

    print(f"wrote {output_path}")
    print(f"messages={total}")
    for db_name, count in sorted(by_db.items()):
        print(f"{db_name}: {count}")
    return total


def main():
    args = parse_args()
    export_all(os.path.expanduser(args.output))


if __name__ == "__main__":
    main()
