"""Canonical JSONL, Sysmon JSON, Suricata EVE and nginx combined adapters."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .common import digest, ip_literal, iso, read_bytes, strict_json, timestamp

MAX_EVENTS = 10000
DERIVED_FIELDS = {"id", "evidence", "process_name", "parent_process_name", "path_normalized", "query_normalized"}

NGINX = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (.*?) HTTP/[^" ]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?')


def process_name(value):
    return str(value).replace("\\", "/").rsplit("/", 1)[-1].lower()


def canonical_event(row, source, line):
    if not isinstance(row, dict):
        raise ValueError("each event must be an object")
    for key in ("timestamp", "host", "event_type"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError(f"event requires nonempty {key}")
    result = {k: v for k, v in row.items() if k not in DERIVED_FIELDS}
    for key in ("process", "parent_process", "url", "path", "query", "domain", "command_line",
                "file_path", "registry_path", "action", "tool", "method", "product", "uploaded_filename",
                "sha256", "sha1", "md5", "src_ip", "dst_ip"):
        if row.get(key) is not None and not isinstance(row[key], str):
            raise ValueError(f"{key} must be a string")
    result["timestamp"] = iso(timestamp(row["timestamp"]))
    for key in ("authenticated", "authorized", "approved", "verified", "webroot"):
        if key in row and type(row[key]) is not bool:
            raise ValueError(f"{key} must be boolean; missing means unknown")
    for key in ("src_ip", "dst_ip"):
        if row.get(key):
            result[key] = str(ip_literal(row[key]))
    for key in ("src_port", "dst_port", "status"):
        if row.get(key) is not None:
            v = row[key]
            if isinstance(v, bool) or not str(v).isdigit() or not 0 <= int(v) <= 65535:
                raise ValueError(f"invalid {key}")
            result[key] = int(v)
    for key in ("process", "parent_process"):
        if row.get(key):
            result[key + "_name"] = process_name(row[key])
    # Never normalize away the original request or infer authentication from HTTP status.
    target = row.get("url") or row.get("path", "")
    if target:
        p = urlsplit("http://sentinel.invalid" + target if target.startswith("/") else target)
        if p.query and row.get("query") is not None and row["query"] != p.query:
            raise ValueError("conflicting query representations")
        result["path_normalized"] = unquote(unquote(p.path)).lower()
        result["query_normalized"] = unquote(unquote(row.get("query") or p.query)).lower()
        if p.hostname and not target.startswith("/") and not row.get("domain"):
            result["domain"] = p.hostname
    # The caller's event ID remains metadata, never a deduplication or trust key.
    result.pop("id", None)
    result.pop("evidence", None)
    result["id"] = "evt-" + digest(result)[:24]
    result["evidence"] = {"source": source, "line": line, "raw_sha256": digest(row)}
    return result


def sysmon(row):
    event = row.get("Event", row)
    system = event.get("System", {})
    data = event.get("EventData", {})
    if isinstance(data, dict) and "Data" in data:
        data = data["Data"]
    if isinstance(data, list):
        data = {x.get("@Name", x.get("Name")): x.get("#text", x.get("Value", "")) for x in data}
    event_id = system.get("EventID", event.get("EventID"))
    if isinstance(event_id, dict):
        event_id = event_id.get("#text", event_id.get("Value"))
    event_id = int(event_id)
    types = {1: "process_start", 3: "network", 11: "file_write", 13: "registry", 22: "dns"}
    if event_id not in types:
        return None
    time = data.get("UtcTime") or system.get("TimeCreated", {}).get("@SystemTime")
    if not time:
        raise ValueError("Sysmon event has no time")
    # UtcTime is defined by Sysmon as UTC, even when its serialized string has no suffix.
    if "Z" not in time and "+" not in time:
        time = time.replace(" ", "T") + "Z"
    result = {"timestamp": time, "host": system.get("Computer", event.get("Computer", "")),
              "event_type": types[event_id], "process": data.get("Image", ""),
              "parent_process": data.get("ParentImage", ""), "command_line": data.get("CommandLine", ""),
              "user": data.get("User", ""), "process_guid": data.get("ProcessGuid", ""),
              "parent_guid": data.get("ParentProcessGuid", ""), "sysmon_event_id": event_id}
    if event_id == 3:
        result.update(src_ip=data.get("SourceIp"), dst_ip=data.get("DestinationIp"),
                      src_port=data.get("SourcePort"), dst_port=data.get("DestinationPort"))
        if data.get("Initiated") in ("true", "false", True, False):
            result["direction"] = "outbound" if data["Initiated"] in ("true", True) else "inbound"
    if event_id == 11:
        result["file_path"] = data.get("TargetFilename", "")
    if event_id == 13:
        result["registry_path"] = data.get("TargetObject", "")
    if event_id == 22:
        result["domain"] = data.get("QueryName", "")
    for pair in data.get("Hashes", "").split(","):
        if "=" in pair:
            name, value = pair.split("=", 1)
            key = name.lower().replace("-", "")
            if key in {"sha256", "sha1", "md5"}:
                result[key] = value
    return result


def eve(row, host):
    if not host:
        raise ValueError("Suricata requires --host (monitored endpoint asset, not sensor name)")
    kind = row.get("event_type")
    if kind not in {"alert", "http", "dns", "flow", "tls"}:
        return None
    result = {"timestamp": row["timestamp"], "host": host,
              "event_type": "http" if kind == "http" else "dns" if kind == "dns" else "network",
              "src_ip": row.get("src_ip"), "dst_ip": row.get("dest_ip"),
              "src_port": row.get("src_port"), "dst_port": row.get("dest_port"),
              "sensor_event_type": kind}
    if kind == "http":
        data = row.get("http", {})
        result.update(path=data.get("url", ""), domain=data.get("hostname", ""),
                      method=data.get("http_method", ""), status=data.get("status"))
    elif kind == "dns":
        data = row.get("dns", {})
        result["domain"] = data.get("rrname", "") or next(
            (x.get("rrname", "") for x in data.get("queries", []) if x.get("rrname")), "")
    elif kind == "tls":
        result["domain"] = row.get("tls", {}).get("sni", "")
    elif kind == "alert":
        result["alert_signature"] = row.get("alert", {}).get("signature", "")
    return result


def nginx(line, host):
    if not host:
        raise ValueError("nginx input requires --host")
    m = NGINX.match(line)
    if not m:
        raise ValueError("not a supported nginx combined/common log line")
    return {"timestamp": iso(datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z")),
            "host": host, "event_type": "http", "src_ip": m[1],
            "method": m[3], "path": m[4], "status": int(m[5]),
            "direction": "inbound", "user_agent": m[8] or ""}


def load_events(paths, fmt="canonical", host=None):
    events, manifests = [], []
    seen = set()
    duplicates = ignored = 0
    for path in paths:
        raw = read_bytes(path)
        manifests.append({"source": Path(path).name, "sha256": hashlib.sha256(raw).hexdigest(),
                          "size_bytes": len(raw)})
        for number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            if len(line) > 1024 * 1024:
                raise ValueError(f"line too long: {Path(path).name}:{number}")
            try:
                if fmt == "nginx":
                    row = nginx(line, host)
                else:
                    row = strict_json(line)
                    if fmt == "sysmon":
                        row = sysmon(row)
                    elif fmt == "suricata":
                        row = eve(row, host)
                if row is None:
                    ignored += 1
                    continue
                event = canonical_event(row, Path(path).name, number)
                # Hash the actual imported line, not a lossy adapter projection.
                event["evidence"]["raw_sha256"] = hashlib.sha256(line.encode("utf-8")).hexdigest()
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ValueError(f"invalid event {Path(path).name}:{number}: {exc}") from exc
            if event["id"] in seen:
                duplicates += 1
            else:
                events.append(event)
                seen.add(event["id"])
            if len(events) > MAX_EVENTS:
                raise ValueError(f"event limit {MAX_EVENTS} exceeded; split the investigation")
    return sorted(events, key=lambda x: (timestamp(x["timestamp"]), x["id"])), manifests, {
        "duplicates": duplicates, "unsupported_events": ignored}
