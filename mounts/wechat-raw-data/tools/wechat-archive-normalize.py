#!/usr/bin/env python3
"""Normalize a WeChat export into local redacted JSONL for agent retrieval.

The tool intentionally writes message-level output to ignored local directories.
Tracked wiki output is only a summary seed and should be reviewed before commit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TEXT_FIELDS = ("text", "content", "message", "msg", "msgStr", "StrContent", "plain_text")
TIME_FIELDS = ("timestamp", "time", "createTime", "CreateTime", "datetime", "date")
SPEAKER_FIELDS = ("speaker", "sender", "from", "talker", "nickname", "remark", "is_sender")
CONVERSATION_FIELDS = ("conversation", "room", "chat", "talker", "contact", "peer", "wxid")

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://\S+|www\.\S+")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d -]{6,}\d)(?!\d)")
ID_CARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
WHITESPACE_RE = re.compile(r"\s+")
HTML_TAG_RE = re.compile(r"<[^>]+>")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="CSV, JSONL, TXT, or HTML export path")
    parser.add_argument(
        "--output-root",
        default="~/.agents/knowledge/wechat",
        help="WeChat knowledge root, default: ~/.agents/knowledge/wechat",
    )
    parser.add_argument("--format", choices=("auto", "csv", "jsonl", "txt", "html"), default="auto")
    parser.add_argument("--text-field", default="", help="Override message text field")
    parser.add_argument("--time-field", default="", help="Override timestamp field")
    parser.add_argument("--speaker-field", default="", help="Override speaker field")
    parser.add_argument("--conversation-field", default="", help="Override conversation field")
    parser.add_argument("--max-text-chars", type=int, default=1200)
    return parser.parse_args()


def detect_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    if suffix in (".html", ".htm"):
        return "html"
    return "txt"


def ensure_salt(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    salt = secrets.token_hex(32)
    path.write_text(salt + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return salt


def stable_hash(value: str, salt: str, prefix: str = "") -> str:
    digest = hashlib.sha256((salt + "\n" + value).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}{digest}"


def pick_field(row: dict[str, Any], override: str, candidates: Iterable[str]) -> Any:
    if override and override in row:
        return row.get(override)
    for key in candidates:
        if key in row and row.get(key) not in (None, ""):
            return row.get(key)
    lowered = {str(key).lower(): key for key in row}
    for key in candidates:
        matched = lowered.get(key.lower())
        if matched and row.get(matched) not in (None, ""):
            return row.get(matched)
    return ""


def clean_text(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    text = html.unescape(text)
    text = HTML_TAG_RE.sub(" ", text)
    text = EMAIL_RE.sub("[EMAIL]", text)
    text = URL_RE.sub("[URL]", text)
    text = ID_CARD_RE.sub("[ID_CARD]", text)
    text = PHONE_RE.sub("[PHONE]", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "..."
    return text


def read_csv(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        yield from csv.DictReader(handle)


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                value = {"text": stripped}
            if isinstance(value, dict):
                value.setdefault("source_line", line_no)
                yield value
            else:
                yield {"text": str(value), "source_line": line_no}


def read_textish(path: Path) -> Iterable[dict[str, Any]]:
    content = path.read_text(encoding="utf-8", errors="replace")
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", content) if p.strip()]
    for index, paragraph in enumerate(paragraphs, start=1):
        yield {"text": paragraph, "source_line": index}


def iter_rows(path: Path, fmt: str) -> Iterable[dict[str, Any]]:
    if fmt == "csv":
        return read_csv(path)
    if fmt == "jsonl":
        return read_jsonl(path)
    return read_textish(path)


def source_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_root = Path(args.output_root).expanduser().resolve()
    if not input_path.exists():
        raise SystemExit(f"input not found: {input_path}")

    fmt = detect_format(input_path, args.format)
    private_dir = output_root / "private"
    normalized_dir = output_root / "normalized"
    wiki_dir = output_root / "wiki"
    private_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)
    wiki_dir.mkdir(parents=True, exist_ok=True)

    salt = ensure_salt(private_dir / "hash_salt.txt")
    source_hash = source_sha256(input_path)
    output_path = normalized_dir / "messages.redacted.jsonl"

    total = 0
    empty_text = 0
    conversations: dict[str, int] = {}
    speakers: dict[str, int] = {}
    first_time = ""
    last_time = ""

    with output_path.open("w", encoding="utf-8") as out:
        for row in iter_rows(input_path, fmt):
            total += 1
            text = clean_text(pick_field(row, args.text_field, TEXT_FIELDS), args.max_text_chars)
            if not text:
                empty_text += 1
            timestamp = str(pick_field(row, args.time_field, TIME_FIELDS) or "")
            speaker_raw = str(pick_field(row, args.speaker_field, SPEAKER_FIELDS) or "unknown")
            conversation_raw = str(
                pick_field(row, args.conversation_field, CONVERSATION_FIELDS) or "unknown"
            )
            speaker = stable_hash(speaker_raw, salt, "speaker:")
            conversation = stable_hash(conversation_raw, salt, "conversation:")
            speakers[speaker] = speakers.get(speaker, 0) + 1
            conversations[conversation] = conversations.get(conversation, 0) + 1
            if timestamp:
                first_time = timestamp if not first_time else min(first_time, timestamp)
                last_time = timestamp if not last_time else max(last_time, timestamp)
            record = {
                "source": f"wechat:sha256:{source_hash[:16]}",
                "source_line": row.get("source_line", total),
                "timestamp": timestamp,
                "conversation_hash": conversation,
                "speaker_hash": speaker,
                "text_redacted": text,
            }
            out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    manifest = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "input_path": str(input_path),
        "input_format": fmt,
        "source_sha256": source_hash,
        "message_rows": total,
        "empty_text_rows": empty_text,
        "conversation_count": len(conversations),
        "speaker_count": len(speakers),
        "first_timestamp": first_time,
        "last_timestamp": last_time,
        "normalized_output": str(output_path),
        "top_conversations": sorted(conversations.items(), key=lambda item: item[1], reverse=True)[:20],
        "top_speakers": sorted(speakers.items(), key=lambda item: item[1], reverse=True)[:20],
    }
    manifest_path = private_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    wiki_path = wiki_dir / "wechat-archive-index.md"
    wiki_path.write_text(
        "\n".join(
            [
                "# WeChat Archive Index",
                "",
                "- Status: EXTRACTED",
                f"- Updated: {datetime.now().date().isoformat()}",
                f"- Sources: `wechat:sha256:{source_hash[:16]}`",
                "",
                "## Summary",
                "",
                f"- Message rows: {total}",
                f"- Empty text rows: {empty_text}",
                f"- Conversations: {len(conversations)}",
                f"- Speakers: {len(speakers)}",
                f"- First timestamp: `{first_time or 'unknown'}`",
                f"- Last timestamp: `{last_time or 'unknown'}`",
                "",
                "## Local Files",
                "",
                "- `normalized/messages.redacted.jsonl`: private local retrieval corpus, ignored by git.",
                "- `private/manifest.json`: private local manifest, ignored by git.",
                "",
                "## Review Notes",
                "",
                "- Contact and conversation names are salted hashes.",
                "- Message text has basic email, URL, phone, and ID-card redaction.",
                "- Review this page before committing any generated change.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(f"wrote {output_path}")
    print(f"wrote {manifest_path}")
    print(f"wrote {wiki_path}")
    print(f"messages={total} conversations={len(conversations)} speakers={len(speakers)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
