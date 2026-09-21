"""Offline IOC import. STIX support deliberately rejects complex patterns."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, asdict
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

from .common import canonical, digest, integer, ip_literal, iso, read_bytes, strict_json, timestamp

MAX_HIT_BYTES = 8 * 1024 * 1024

PATTERNS = {
    "ipv4-addr:value": "ip", "ipv6-addr:value": "ip",
    "domain-name:value": "domain", "url:value": "url",
    "file:hashes.'SHA-256'": "sha256", "file:hashes.'SHA-1'": "sha1",
    "file:hashes.MD5": "md5", "file:hashes.'MD5'": "md5",
}


def normalize(kind, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC value must be a nonempty string")
    value = value.strip()
    if kind == "ip":
        return str(ip_literal(value))
    if kind == "domain":
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                                       for x in value.split(".")):
            raise ValueError("invalid domain IOC")
        return value
    if kind in {"sha256", "sha1", "md5"}:
        lengths = {"sha256": 64, "sha1": 40, "md5": 32}
        if not re.fullmatch(r"[a-fA-F0-9]{%d}" % lengths[kind], value):
            raise ValueError(f"invalid {kind} hash length/encoding")
        return value.lower()
    if kind == "url":
        p = urlsplit(value)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname or p.username or p.password:
            raise ValueError("URL IOC must be HTTP(S), without embedded credentials")
        host = p.hostname.encode("idna").decode("ascii").lower()
        if ":" in host:
            host = "[" + str(ipaddress.ip_address(host)) + "]"
        port = p.port
        netloc = host + (f":{port}" if port and (p.scheme.lower(), port) not in
                          {("http", 80), ("https", 443)} else "")
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
    raise ValueError(f"unsupported IOC type: {kind}")


@dataclass(frozen=True)
class Indicator:
    id: str
    type: str
    value: str
    source: str
    confidence: int
    valid_from: str
    valid_until: str
    revoked: bool = False
    tags: tuple = ()
    tlp: str = "AMBER"

    @classmethod
    def parse(cls, row):
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k].strip()
                                           for k in ("type", "value", "source", "valid_from", "valid_until")):
            raise ValueError("IOC requires string type, value, source, valid_from and valid_until")
        if any(len(row[k]) > 4096 for k in ("type", "value", "source", "valid_from", "valid_until")):
            raise ValueError("IOC string field exceeds 4096 characters")
        if "id" in row and (not isinstance(row["id"], str) or len(row["id"]) > 160):
            raise ValueError("IOC id must be a string of at most 160 characters")
        kind = row["type"]
        value = normalize(kind, row["value"])
        source = str(row.get("source", "")).strip()
        if not source:
            raise ValueError("IOC source is required")
        start = timestamp(row["valid_from"])
        end = timestamp(row["valid_until"])
        if end <= start:
            raise ValueError("IOC valid_until must follow valid_from")
        revoked = row.get("revoked", False)
        if isinstance(revoked, str) and revoked.lower() in {"true", "false", ""}:
            revoked = revoked.lower() == "true"
        if type(revoked) is not bool:
            raise ValueError("revoked must be boolean")
        tags = row.get("tags", [])
        if isinstance(tags, str):
            tags = [x for x in tags.split(";") if x]
        if (not isinstance(tags, (list, tuple)) or len(tags) > 32
                or any(not isinstance(x, str) or len(x) > 128 for x in tags)):
            raise ValueError("tags must be an array of strings")
        if not isinstance(row.get("tlp", "AMBER"), str):
            raise ValueError("TLP must be a string")
        tlp = row.get("tlp", "AMBER").upper().removeprefix("TLP:")
        if tlp not in {"CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"}:
            raise ValueError("unknown TLP value")
        ident = str(row.get("id") or "ioc-" + digest([kind, value, source])[:20])
        return cls(ident, kind, value, source, integer(row.get("confidence", 50)),
                   iso(start), iso(end), revoked, tuple(tags), tlp)


def load_intel(path, fmt="auto"):
    raw = read_bytes(path).decode("utf-8-sig")
    warnings = []
    if fmt == "auto":
        fmt = "json" if raw.lstrip().startswith(("{", "[")) else "csv"
    if fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(raw)))
    else:
        obj = strict_json(raw)
        if not isinstance(obj, (dict, list)):
            raise ValueError("intel must be an array or object")
        if isinstance(obj, dict) and obj.get("type") == "bundle":
            rows = []
            # Latest version wins, including a later revocation.
            versions = {}
            for item in obj.get("objects", []):
                if item.get("type") != "indicator":
                    continue
                ident = item.get("id")
                if not ident:
                    raise ValueError("STIX indicator id missing")
                modified = timestamp(item["modified"])
                if ident not in versions or modified > versions[ident][0]:
                    versions[ident] = (modified, item)
            for _, item in versions.values():
                pattern = item.get("pattern", "")
                match = re.fullmatch(r"\[([^=]+?)\s*=\s*'([^'\\]*)'\s*\]", pattern)
                if item.get("pattern_type") != "stix" or not match or match[1].strip() not in PATTERNS:
                    warnings.append(f"unsupported STIX pattern skipped: {item['id']}")
                    continue
                start = timestamp(item["valid_from"])
                end = item.get("valid_until")
                if not end:
                    end = iso(start + timedelta(days=30))
                    warnings.append(f"{item['id']}: local 30-day expiry applied")
                rows.append({"id": item["id"], "type": PATTERNS[match[1].strip()],
                             "value": match[2], "source": item.get("created_by_ref", "STIX-import"),
                             "confidence": item.get("confidence", 50), "valid_from": iso(start),
                             "valid_until": end, "revoked": item.get("revoked", False),
                             "tags": item.get("labels", []), "tlp": "AMBER"})
        else:
            rows = obj if isinstance(obj, list) else obj.get("indicators", [])
    if not isinstance(rows, list):
        raise ValueError("intel must contain an indicators array")
    result = []
    for i, row in enumerate(rows, 1):
        try:
            result.append(Indicator.parse(row))
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"invalid IOC row {i}: {exc}") from exc
    return result, warnings


class IntelIndex:
    def __init__(self, indicators, now, min_confidence=60):
        self.index = {}
        self.hit_bytes = 0
        self.item_sizes = {}
        if len(indicators) > 10000:
            raise ValueError("IOC limit 10000 exceeded; split the investigation")
        self.ignored = {"expired": 0, "future": 0, "revoked": 0, "low_confidence": 0}
        # A revocation of the same source/id always wins within this import batch.
        revoked = {(x.source, x.id) for x in indicators if x.revoked}
        seen = set()
        for item in indicators:
            if (item.source, item.id) in revoked:
                self.ignored["revoked"] += 1
            elif timestamp(item.valid_until) <= now:
                self.ignored["expired"] += 1
            elif timestamp(item.valid_from) > now:
                self.ignored["future"] += 1
            elif item.confidence < min_confidence:
                self.ignored["low_confidence"] += 1
            else:
                key = (item.type, item.value, item.source, item.id)
                if key not in seen:
                    bucket = self.index.setdefault((item.type, item.value), [])
                    if len(bucket) >= 100:
                        raise ValueError("IOC source fan-out exceeds 100 per observable")
                    bucket.append(item)
                    self.item_sizes[item] = len(canonical(asdict(item)))
                    seen.add(key)

    def match(self, event):
        values = [("ip", event.get("src_ip"), "src_ip"),
                  ("ip", event.get("dst_ip"), "dst_ip"),
                  ("domain", event.get("domain"), "domain"),
                  ("url", event.get("url"), "url")]
        values += [(k, event.get(k), k) for k in ("sha256", "sha1", "md5")]
        hits = []
        for kind, value, field in values:
            if not value:
                continue
            try:
                normalized = normalize(kind, value)
            except ValueError:
                continue
            for item in self.index.get((kind, normalized), []):
                # Both event-time and analysis-time validity are required.
                if timestamp(item.valid_from) <= timestamp(event["timestamp"]) < timestamp(item.valid_until):
                    self.hit_bytes += self.item_sizes[item]
                    if self.hit_bytes > MAX_HIT_BYTES:
                        raise ValueError("IOC match expansion exceeds 8 MiB; narrow the feed or split events")
                    hits.append({**asdict(item), "field": field})
        return hits
