"""Small, strict primitives used at trust boundaries."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with timezone")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp requires an explicit timezone")
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_bytes(path: str | Path, limit: int = MAX_FILE) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} bytes: {Path(path).name}")
    return data


def load_json(path):
    def reject(value):
        raise ValueError(f"invalid JSON numeric constant: {value}")
    return json.loads(read_bytes(path), parse_constant=reject)


def write_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2,
                                 allow_nan=False) + "\n")


def atomic_write(path, text: str):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sentinel-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def integer(value, minimum=0, maximum=100):
    if isinstance(value, bool):
        raise ValueError("boolean is not an integer here")
    number = int(value)
    if str(number) != str(value) or not minimum <= number <= maximum:
        raise ValueError(f"integer must be in [{minimum}, {maximum}]")
    return number
