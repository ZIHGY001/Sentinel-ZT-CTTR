"""Small, strict primitives used at trust boundaries."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("timestamp must be an ISO 8601 string with timezone")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        raise ValueError("invalid ISO 8601 timestamp") from None
    if dt.tzinfo is None:
        raise ValueError("timestamp requires an explicit timezone")
    try:
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("timestamp is outside the supported UTC range") from None


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
    return strict_json(read_bytes(path))


def strict_json(raw):
    """Reject ambiguous keys, non-finite numbers, deep trees and invalid Unicode."""
    def reject(value):
        raise ValueError("non-finite JSON number")

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate JSON object key")
            obj[key] = value
        return obj

    try:
        value = json.loads(raw, parse_constant=reject, object_pairs_hook=pairs)
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            if depth > 64:
                raise ValueError("JSON nesting exceeds 64 levels")
            if isinstance(item, dict):
                stack.extend((x, depth + 1) for x in item.keys())
                stack.extend((x, depth + 1) for x in item.values())
            elif isinstance(item, list):
                stack.extend((x, depth + 1) for x in item)
            elif isinstance(item, float) and not math.isfinite(item):
                reject(item)
            elif isinstance(item, str):
                item.encode("utf-8", errors="strict")
        return value
    except (RecursionError, UnicodeError, OverflowError) as exc:
        raise ValueError("invalid or excessively nested JSON") from exc


def ip_literal(value):
    """IP text only: no integer coercion or IPv6 interface/zone expressions."""
    if not isinstance(value, str) or "%" in value or value != value.strip():
        raise ValueError("IP must be an unscoped address string")
    return ipaddress.ip_address(value)


def strict_integer(value, minimum=0, maximum=100):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"integer must be in [{minimum}, {maximum}]")
    return value


def private_directory(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError("private data directory cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and
            (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
        raise ValueError("private data directory must be current-user-owned with mode 0700")
    return path


def private_file(path):
    """Create/validate sensitive files without following links; parent is private."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (os.name == "posix" and
                (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            raise ValueError("private file must be regular, unlinked and current-user-owned with mode 0600")
    finally:
        os.close(fd)


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
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"integer must be in [{minimum}, {maximum}]") from None
    if str(number) != str(value) or not minimum <= number <= maximum:
        raise ValueError(f"integer must be in [{minimum}, {maximum}]")
    return number
