"""Synthetic training fixtures, never real report IOCs or customer details."""
from datetime import timedelta
from pathlib import Path
from .common import canonical, iso, write_json, atomic_write


def fixtures(now):
    policy = {"schema_version": 1, "min_intel_confidence": 60, "response_threshold": 75,
              "analysis_window_seconds": 86400, "max_evidence_age_seconds": 900,
              "block_ttl_seconds": 300, "plan_ttl_seconds": 600, "posture_max_age_seconds": 300,
              "protected_networks": ["127.0.0.0/8", "::1/128", "192.0.2.254/32"],
              "operators": ["lab-analyst"], "suppressions": [], "assets": {}}
    for index, name in enumerate(["workstation-demo", "web-demo", "agent-demo", "clean-demo"], 10):
        policy["assets"][name] = {"ips": [f"192.0.2.{index}"], "response_enabled": True,
                                  "criticality": "normal", "local_hostname": "CONFIGURE-YOUR-HOSTNAME",
                                  "permissions": {"analyst-demo": ["read"]}}
    events = []

    def add(host, seconds, kind, **kwargs):
        events.append({"timestamp": iso(now - timedelta(seconds=seconds)), "host": host,
                       "event_type": kind, **kwargs})

    add("workstation-demo", 600, "process_start", process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Office\\WINWORD.EXE", user="demo-user")
    add("workstation-demo", 590, "file_write", file_path="C:\\Users\\demo\\Downloads\\offer\u202efdp.exe")
    add("workstation-demo", 550, "persistence", action="scheduled_task", approved=False)
    for i in range(6):
        add("workstation-demo", 500-i*60, "network", src_ip="192.0.2.10", dst_ip="203.0.113.50", dst_port=443)
    add("web-demo", 480, "http", path="/sys/dict/getDictItems/demo?filterSql=select%20example",
        method="GET", status=200, src_ip="198.51.100.20")
    add("web-demo", 450, "process_start", parent_process="/usr/bin/java", process="/bin/sh")
    add("web-demo", 400, "file_write", file_path="/var/www/html/demo.jsp", webroot=True, approved=False)
    add("web-demo", 350, "network", src_ip="192.0.2.11", dst_ip="203.0.113.51", dst_port=443)
    add("web-demo", 340, "http", product="kubepi", path="/kubepi/api/v1/sso", method="PUT", authenticated=False, status=200)
    add("web-demo", 320, "identity", action="role_grant", authorized=False)
    add("agent-demo", 400, "agent", action="skill_install", verified=False, skill="example-unverified")
    add("agent-demo", 380, "agent", tool="shell", authorized=False)
    add("agent-demo", 360, "file_read", file_path="/var/run/secrets/kubernetes.io/serviceaccount/token", authorized=False)
    add("agent-demo", 340, "network", src_ip="192.0.2.12", dst_ip="192.0.2.90", dst_port=6443, authorized=False)
    add("agent-demo", 320, "network", src_ip="192.0.2.12", dst_ip="203.0.113.50", dst_port=443)
    add("agent-demo", 300, "dns", domain="updates.example.test")
    add("clean-demo", 60, "http", path="/health", method="GET", authenticated=True, status=200)
    add("clean-demo", 50, "process_start", process="/usr/bin/python3", parent_process="/bin/bash")
    intel = []
    for kind, value in [("ip", "203.0.113.50"), ("ip", "203.0.113.51"), ("domain", "updates.example.test")]:
        intel.append({"type": kind, "value": value, "source": "synthetic-training-feed",
                      "confidence": 90, "valid_from": iso(now - timedelta(days=1)),
                      "valid_until": iso(now + timedelta(days=1)), "tags": ["synthetic"], "tlp": "CLEAR"})
    request = {"subject": "analyst-demo", "resource": "clean-demo", "action": "read",
               "identity_verified": True, "mfa_verified": True, "device_managed": True,
               "device_compliant": True, "token_valid": True, "posture_checked_at": iso(now)}
    return events, intel, policy, request


def write_fixtures(destination, now):
    destination = Path(destination)
    events, intel, policy, request = fixtures(now)
    atomic_write(destination / "events.jsonl", "\n".join(canonical(e).decode() for e in events) + "\n")
    write_json(destination / "intel.json", {"indicators": intel})
    write_json(destination / "policy.json", policy)
    write_json(destination / "access-request.json", request)
