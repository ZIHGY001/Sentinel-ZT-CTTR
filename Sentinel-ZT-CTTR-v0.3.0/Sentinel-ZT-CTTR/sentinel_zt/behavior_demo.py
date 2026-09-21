"""Synthetic no-IOC exercise: workstation deviations and expected bastion activity."""
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

from . import baselines
from .common import atomic_write, canonical, iso, write_json


def fixtures(now):
    cfg = baselines.template(now)
    asset = cfg["assets"].pop("workstation-example")
    cfg["assets"]["workstation-demo"] = asset
    profile = cfg["behavior_baselines"]["workstation"]
    profile.update(enabled=True, reviewed_by="synthetic-lab-review", valid_from=iso(now-timedelta(days=1)),
                   valid_until=iso(now+timedelta(days=7)))
    profile["network"]["allowed_flows"] = [{"dst_network": "192.0.2.30/32", "dst_ports": [22],
                                            "transport": "tcp", "reason": "synthetic approved bastion path"}]
    profile["identity"]["allowed_changes"] = [{"actor": "iam-service", "action": "role_grant",
        "target_user": "employee-demo", "target_role": "Reader", "reason": "synthetic reviewed provisioning"}]
    profile["privilege"]["allowed_transitions"] = [{"user": "patch-service", "target_user": "root",
        "process": "/usr/bin/sudo", "reason": "synthetic patch workflow"}]
    bastion = deepcopy(profile); bastion["role"] = "bastion"
    bastion["network"]["allowed_flows"] = [{"dst_network": "192.0.2.0/24", "dst_ports": [22, 445, 3389, 5985],
                                            "transport": "tcp", "reason": "synthetic reviewed bastion administration"}]
    cfg["behavior_baselines"]["bastion"] = bastion
    cfg["assets"]["bastion-demo"] = {"ips": ["192.0.2.30"], "role": "bastion", "baseline_profile": "bastion",
                                      "response_enabled": False, "criticality": "normal", "permissions": {}}
    rows = []
    def add(host, ago, kind, **fields):
        rows.append({"timestamp": iso(now-timedelta(seconds=ago)), "host": host, "event_type": kind, **fields})
    add("workstation-demo", 290, "identity", actor="helpdesk-demo", action="role_grant",
        target_user="alice-demo", target_role="DomainAdmin", outcome="success")
    add("workstation-demo", 260, "privilege", user="alice-demo", action="elevate", target_user="root",
        process="/usr/bin/sudo", outcome="success")
    for i, port in enumerate((445, 3389, 5985)):
        add("workstation-demo", 230-i*10, "network", src_ip="192.0.2.10", dst_ip=f"192.0.2.{20+i}",
            dst_port=port, transport="tcp", user="alice-demo")
        add("bastion-demo", 200-i*10, "network", src_ip="192.0.2.30", dst_ip=f"192.0.2.{20+i}",
            dst_port=port, transport="tcp", user="admin-demo")
    add("workstation-demo", 150, "network", src_ip="192.0.2.10", dst_ip="192.0.2.30", dst_port=22,
        transport="tcp", user="employee-demo")
    add("workstation-demo", 140, "identity", actor="iam-service", action="role_grant", target_user="employee-demo",
        target_role="Reader", outcome="success")
    add("workstation-demo", 130, "privilege", user="patch-service", action="elevate", target_user="root",
        process="/usr/bin/sudo", outcome="success")
    return rows, cfg


def write_fixtures(destination, now):
    root = Path(destination); root.mkdir(parents=True, exist_ok=True)
    rows, config = fixtures(now)
    atomic_write(root / "events.jsonl", "\n".join(canonical(e).decode() for e in rows) + "\n")
    write_json(root / "policy.json", config)
    return root
