#!/usr/bin/env python3
"""Export decrypted WeChat auxiliary databases to JSONL.

This exporter is intentionally key-agnostic: it reads plaintext SQLite files
from decrypted_dir. Public projects such as wx-cli/wechat-decrypt already
implement these parsers, but they all require per-DB keys first. Once keys are
captured and decrypt_db.py produces plaintext DBs, rerun this script.
"""

import argparse
import base64
import binascii
import hashlib
import html
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:
    import zstandard as zstd
except Exception:
    zstd = None

from config import load_config


SNS_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
XML_UNSAFE_RE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
XML_MAX_LEN = 200_000
INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
BARE_AMP_RE = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
CDATA_BLOCK_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
TEXT_ONLY_NODES = (
    "content",
    "title",
    "description",
    "nickname",
    "contentDesc",
    "appname",
    "sourceName",
    "sourcename",
    "poiName",
    "displayName",
    "feeddesc",
)
TEXT_NODE_RE = re.compile(
    r"(<(" + "|".join(TEXT_ONLY_NODES) + r")\b[^>]*>)(.*?)(</\2>)",
    re.DOTALL,
)


def iso_time(ts):
    if not ts:
        return ""
    if ts > 9_999_999_999:
        ts = ts / 1000
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def connect(path, binary_safe=False):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # When binary_safe=True, use bytes for text_factory to avoid UTF-8
    # decode errors on binary columns (e.g., general.db fmessage_detail_buf_).
    # The row_to_jsonable function handles the bytes→text/binary decision.
    if binary_safe:
        conn.text_factory = bytes
    return conn


def table_exists(conn, table):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def columns(conn, table):
    try:
        return [r["name"] for r in conn.execute(f"PRAGMA table_info([{table}])")]
    except sqlite3.Error:
        return []


def row_to_jsonable(row, base64_blobs=False):
    """Convert a sqlite3.Row to a JSON-serializable dict.

    Because connect() sets text_factory=bytes, ALL column values arrive as
    bytes.  We try to decode each value as UTF-8 text; if that fails we
    treat it as a binary blob (hash + optional base64).
    """
    out = {}
    for key in row.keys():
        value = row[key]
        if value is None:
            out[key] = None
        elif isinstance(value, bytes):
            # Try UTF-8 decode first — most text columns will succeed
            try:
                decoded = value.decode("utf-8")
                # Heuristic: if the decoded string contains control characters
                # (except common whitespace), treat as binary
                if _looks_like_binary(decoded):
                    raise UnicodeDecodeError("binary heuristic", value, 0, len(value), "binary content")
                out[key] = decoded
            except (UnicodeDecodeError, UnicodeError):
                blob_info = {
                    "blob_sha256": hashlib.sha256(value).hexdigest(),
                    "blob_size": len(value),
                }
                if base64_blobs and len(value) > 0:
                    blob_info["blob_base64"] = base64.b64encode(value).decode("ascii")
                out[key] = blob_info
        else:
            out[key] = value
    return out


def _looks_like_binary(text):
    """Heuristic: does a decoded string look like binary data?

    Returns True if the string contains a high proportion of non-printable
    control characters (excluding common whitespace: \\t \\n \\r).
    """
    if not text:
        return False
    control_count = sum(
        1 for ch in text
        if ord(ch) < 0x20 and ch not in ("\t", "\n", "\r")
    )
    # Consider binary if >10% control chars or contains null bytes
    if "\x00" in text:
        return True
    if len(text) > 0 and control_count / len(text) > 0.1:
        return True
    return False


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def decode_sns_content(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        raw = value
        if raw.startswith(SNS_ZSTD_MAGIC) and zstd is not None:
            try:
                raw = zstd.ZstdDecompressor().decompress(raw)
            except Exception:
                pass
        return html.unescape(raw.decode("utf-8", errors="ignore").strip())
    text = str(value).strip()
    if not text:
        return ""
    if text.lstrip().startswith("<"):
        return html.unescape(text)
    compact = "".join(text.split())
    if len(compact) >= 16 and len(compact) % 2 == 0 and HEX_RE.match(compact):
        try:
            return decode_sns_content(bytes.fromhex(compact))
        except ValueError:
            pass
    if len(compact) >= 24 and len(compact) % 4 == 0 and BASE64_RE.match(compact):
        try:
            return decode_sns_content(base64.b64decode(compact, validate=True))
        except (ValueError, binascii.Error):
            pass
    return html.unescape(text)


def sanitize_xml(xml_text):
    s = INVALID_CTRL_RE.sub("", xml_text)
    parts = []
    last = 0
    for match in CDATA_BLOCK_RE.finditer(s):
        head = s[last : match.start()]
        parts.append(BARE_AMP_RE.sub("&amp;", head))
        parts.append(match.group(0))
        last = match.end()
    parts.append(BARE_AMP_RE.sub("&amp;", s[last:]))
    out = "".join(parts)

    def esc(match):
        open_tag, _, text, close_tag = match.group(1), match.group(2), match.group(3), match.group(4)
        return open_tag + text.replace("<", "&lt;").replace(">", "&gt;") + close_tag

    return TEXT_NODE_RE.sub(esc, out)


def xml_find_text(root, tag):
    node = root.find(f".//{tag}")
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def parse_sns_xml(content):
    text = decode_sns_content(content)
    if not text or len(text) > XML_MAX_LEN or XML_UNSAFE_RE.search(text):
        return {}
    try:
        root = ET.fromstring(sanitize_xml(text))
    except ET.ParseError:
        return {"raw_preview": text[:500]}
    timeline = root if root.tag == "TimelineObject" else root.find(".//TimelineObject")
    if timeline is None:
        timeline = root
    media = []
    for m in timeline.findall(".//ContentObject/mediaList/media"):
        item = {}
        for child in m:
            if child.text and child.text.strip():
                item[child.tag] = child.text.strip()
            for attr_key, attr_val in child.attrib.items():
                item[f"{child.tag}_{attr_key}"] = attr_val
        if item:
            media.append(item)
    return {
        "create_time": xml_find_text(timeline, "createTime"),
        "author_username": xml_find_text(timeline, "username"),
        "content": xml_find_text(timeline, "contentDesc"),
        "location": (timeline.find(".//location").attrib.get("poiName", "") if timeline.find(".//location") is not None else ""),
        "media_count": len(media),
        "media": media,
    }


def export_contacts(db_path, out_dir, base64_blobs=False):
    with connect(db_path) as conn:
        if not table_exists(conn, "contact"):
            return {"status": "missing_table", "table": "contact"}
        cols = columns(conn, "contact")
        wanted = [c for c in ("id", "username", "alias", "remark", "nick_name", "type", "verify_flag", "extra_buffer") if c in cols]
        sql = f"SELECT {', '.join(wanted)} FROM contact"
        def rows():
            for r in conn.execute(sql):
                obj = row_to_jsonable(r, base64_blobs=base64_blobs)
                obj["source_table"] = "contact"
                yield obj
        count = write_jsonl(out_dir / "contacts.jsonl", rows())
        if table_exists(conn, "contact_label"):
            count_labels = write_jsonl(
                out_dir / "contact_labels.jsonl",
                (row_to_jsonable(r, base64_blobs=base64_blobs) for r in conn.execute("SELECT * FROM contact_label")),
            )
        else:
            count_labels = 0
        if table_exists(conn, "chatroom_member"):
            count_members = write_jsonl(
                out_dir / "chatroom_members.jsonl",
                (row_to_jsonable(r, base64_blobs=base64_blobs) for r in conn.execute("SELECT * FROM chatroom_member")),
            )
        else:
            count_members = 0
    return {"contacts": count, "contact_labels": count_labels, "chatroom_members": count_members}


def export_favorites(db_path, out_dir, base64_blobs=False):
    with connect(db_path) as conn:
        if not table_exists(conn, "fav_db_item"):
            return {"status": "missing_table", "table": "fav_db_item"}
        def rows():
            for r in conn.execute("SELECT * FROM fav_db_item ORDER BY update_time DESC"):
                obj = row_to_jsonable(r, base64_blobs=base64_blobs)
                ts = obj.get("update_time") or obj.get("time")
                obj["time_iso"] = iso_time(ts) if isinstance(ts, (int, float)) else ""
                yield obj
        return {"favorites": write_jsonl(out_dir / "favorites.jsonl", rows())}


def export_sns(db_path, out_dir, base64_blobs=False):
    counts = {}
    with connect(db_path) as conn:
        if table_exists(conn, "SnsTimeLine"):
            def timeline_rows():
                for r in conn.execute("SELECT tid, user_name, content FROM SnsTimeLine WHERE content IS NOT NULL ORDER BY tid DESC"):
                    parsed = parse_sns_xml(r["content"])
                    yield {
                        "tid": r["tid"],
                        "user_name_column": r["user_name"],
                        "author_username": parsed.get("author_username") or r["user_name"],
                        "content": parsed.get("content", ""),
                        "create_time": parsed.get("create_time", ""),
                        "media_count": parsed.get("media_count", 0),
                        "media": parsed.get("media", []),
                        "location": parsed.get("location", ""),
                        "raw_preview": parsed.get("raw_preview", ""),
                    }
            counts["sns_timeline"] = write_jsonl(out_dir / "sns_timeline.jsonl", timeline_rows())
        if table_exists(conn, "SnsMessage_tmp3"):
            def msg_rows():
                for r in conn.execute("SELECT * FROM SnsMessage_tmp3 ORDER BY create_time DESC"):
                    obj = row_to_jsonable(r, base64_blobs=base64_blobs)
                    if isinstance(obj.get("create_time"), (int, float)):
                        obj["time_iso"] = iso_time(obj["create_time"])
                    yield obj
            counts["sns_notifications"] = write_jsonl(out_dir / "sns_notifications.jsonl", msg_rows())
    return counts or {"status": "no_known_sns_tables"}


def export_message_resource(db_path, out_dir, base64_blobs=False):
    with connect(db_path) as conn:
        table_names = [
            r["name"]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        ]
        counts = {}
        for table in table_names:
            if table.startswith("sqlite_"):
                continue
            def rows(table=table):
                for r in conn.execute(f"SELECT * FROM [{table}]"):
                    yield row_to_jsonable(r, base64_blobs=base64_blobs)
            counts[table] = write_jsonl(out_dir / f"message_resource__{table}.jsonl", rows())
    return counts


def _bytes_row_to_str_dict(row):
    """Convert a sqlite3.Row (with bytes values) to a dict with decoded strings."""
    out = {}
    for key in row.keys():
        val = row[key]
        if isinstance(val, bytes):
            try:
                out[key] = val.decode("utf-8")
            except UnicodeDecodeError:
                out[key] = f"<binary:{hashlib.sha256(val).hexdigest()[:12]}>"
        elif val is None:
            out[key] = None
        else:
            out[key] = val
    return out


def generic_dump(db_path, out_dir, rel_key, max_rows, base64_blobs=False):
    with connect(db_path, binary_safe=True) as conn:
        # Schema must be text-decoded (sqlite_master rows arrive as bytes)
        schema = [
            _bytes_row_to_str_dict(r)
            for r in conn.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
            )
        ]
        schema_path = out_dir / "schemas" / (rel_key.replace("/", "__") + ".schema.json")
        schema_path.parent.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
        counts = {}
        for item in schema:
            if item["type"] != "table" or item["name"].startswith("sqlite_"):
                continue
            table = item["name"]
            sql = f"SELECT * FROM [{table}]"
            if max_rows:
                sql += f" LIMIT {int(max_rows)}"
            def rows(table=table, sql=sql):
                for r in conn.execute(sql):
                    yield row_to_jsonable(r, base64_blobs=base64_blobs)
            fname = rel_key.replace("/", "__").replace(".db", "") + f"__{table}.jsonl"
            counts[table] = write_jsonl(out_dir / "generic" / fname, rows())
    return {"schema": str(schema_path), "tables": counts}


def main():
    parser = argparse.ArgumentParser(description="Export decrypted WeChat auxiliary DBs")
    parser.add_argument("--decrypted-dir", default=None)
    parser.add_argument(
        "--output-dir",
        default=str(Path.home() / "projects/Others/wechat-raw-data/aux-exports"),
    )
    parser.add_argument("--generic-max-rows", type=int, default=0, help="0 means full generic table dump")
    parser.add_argument("--base64-blobs", action="store_true",
                        help="Include base64-encoded copies of binary (bytes) columns in JSONL output")
    args = parser.parse_args()

    cfg = load_config()
    decrypted_dir = Path(args.decrypted_dir or cfg["decrypted_dir"])
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    specialized = {
        "contact/contact.db": export_contacts,
        "favorite/favorite.db": export_favorites,
        "sns/sns.db": export_sns,
        "message/message_resource.db": export_message_resource,
    }
    targets = [
        "contact/contact.db",
        "contact/contact_fts.db",
        "favorite/favorite.db",
        "favorite/favorite_fts.db",
        "message/message_resource.db",
        "message/media_0.db",
        "message/message_fts.db",
        "sns/sns.db",
        "hardlink/hardlink.db",
        "head_image/head_image.db",
        "emoticon/emoticon.db",
        "bizchat/bizchat.db",
        "general/general.db",
        "solitaire/solitaire.db",
        "message/weclaw.db",
        "message/biz_message_1.db",
        "message/biz_message_2.db",
        "message/biz_message_3.db",
        "message/biz_message_4.db",
    ]

    manifest = {
        "decrypted_dir": str(decrypted_dir),
        "output_dir": str(out_dir),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "sources": {},
        "missing": [],
    }
    b64 = args.base64_blobs
    for rel in targets:
        db_path = decrypted_dir / rel
        if not db_path.exists():
            manifest["missing"].append(rel)
            continue
        try:
            if rel in specialized:
                result = specialized[rel](db_path, out_dir, base64_blobs=b64)
            else:
                result = generic_dump(db_path, out_dir, rel, args.generic_max_rows, base64_blobs=b64)
            manifest["sources"][rel] = {"status": "exported", "result": result}
            print(f"[OK] {rel}: {result}")
        except Exception as exc:
            manifest["sources"][rel] = {"status": "error", "error": str(exc)}
            print(f"[ERR] {rel}: {exc}", file=sys.stderr)
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"manifest: {manifest_path}")
    if manifest["missing"]:
        print(f"missing decrypted DBs: {len(manifest['missing'])}")


if __name__ == "__main__":
    main()
