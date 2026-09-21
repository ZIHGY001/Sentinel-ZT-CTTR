"""Read-only Linux process snapshot. No memory dumps or credential collection."""
import hashlib
import os
import socket
from pathlib import Path
from .common import atomic_write, canonical, iso, write_json


def collect(destination, now, host=None):
    proc = Path("/proc")
    if not proc.is_dir():
        raise ValueError("collector requires Linux /proc")
    host = host or socket.gethostname()
    events, warnings = [], []
    for entry in sorted(proc.iterdir(), key=lambda p: p.name):
        if not entry.name.isdigit():
            continue
        try:
            executable = os.readlink(entry / "exe")
            fields = {}
            for line in (entry / "status").read_text().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fields[k] = v.strip()
            parent = fields.get("PPid", "0")
            try:
                parent_exe = os.readlink(proc / parent / "exe")
            except OSError:
                parent_exe = ""
            # Snapshot is NOT process_start: no synthetic execution-time detections.
            events.append({"timestamp": iso(now), "event_type": "process_snapshot", "host": host,
                           "pid": int(entry.name), "ppid": int(parent), "process": executable,
                           "parent_process": parent_exe, "uid": fields.get("Uid", "").split()[0]})
        except (OSError, IndexError, ValueError):
            warnings.append(f"PID {entry.name}: unavailable (exited or permission denied)")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    data = b"\n".join(canonical(e) for e in events) + b"\n"
    atomic_write(destination / "processes.jsonl", data.decode())
    manifest = {"collected_at": iso(now), "host": host, "collector": "linux-proc-snapshot",
                "files": [{"path": "processes.jsonl", "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}],
                "warnings": warnings, "limitations": ["Live /proc snapshot is not atomic or a forensic disk image.",
                "No command lines, environment variables, memory or secret files collected.",
                "Use Sysmon/EDR/audit logs for historical process-start evidence."]}
    write_json(destination / "manifest.json", manifest)
    return manifest
