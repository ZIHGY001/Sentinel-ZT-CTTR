"""Manual access-policy handoff, NOT a vendor management API or isolation adapter.

The supplied SDKs control the calling client's tunnel. No SDK or tenant secret
is loaded here. A local mapping file expresses analyst-verified references;
it does not attest identity or configure cloud policy.
"""
from datetime import timedelta
from collections import defaultdict

from .common import digest, strict_integer, iso, timestamp


def _text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 160 or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field} must be a nonempty string of at most 160 characters")
    if "*" in value or value.strip().lower() in {"all", "any", "全部", "所有"}:
        raise ValueError(f"{field} cannot select all resources")
    return value


def validate(config):
    if not isinstance(config, dict) or type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise ValueError("Yunmai mapping schema_version must be 1")
    _text(config.get("tenant_ref"), "tenant_ref")
    for name, lo, hi, default in [("mapping_max_age_seconds", 60, 86400, 3600),
                                   ("evidence_max_age_seconds", 30, 3600, 900),
                                   ("review_ttl_seconds", 60, 900, 600),
                                   ("restriction_ttl_seconds", 60, 3600, 900)]:
        strict_integer(config.get(name, default), lo, hi)
    protected = config.get("protected_application_refs")
    if not isinstance(protected, list) or not protected:
        raise ValueError("register at least the console/forensics applications as protected")
    for ref in protected:
        _text(ref, "protected application reference")
    bindings = config.get("bindings")
    if not isinstance(bindings, list) or len(bindings) > 10000:
        raise ValueError("bindings must be an array of at most 10000 mappings")
    seen = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise ValueError("binding must be an object")
        host = _text(binding.get("host"), "host")
        if host in seen:
            raise ValueError("one mapping per host is required; resolve ambiguous identity first")
        seen.add(host)
        subject = binding.get("subject", {})
        # A single user is supported by the supplied console guide. No group-wide ban.
        if not isinstance(subject, dict) or subject.get("type") != "user":
            raise ValueError("handoff targets must be individually verified users")
        _text(subject.get("ref"), "subject reference")
        _text(binding.get("verified_by"), "verified_by")
        timestamp(binding.get("verified_at"))
        applications = binding.get("application_refs")
        if not isinstance(applications, list) or not 1 <= len(applications) <= 20:
            raise ValueError("map 1..20 specific application references")
        for ref in applications:
            _text(ref, "application reference")
            if ref in protected:
                raise ValueError("a restriction cannot include a protected management/forensics application")
        if len(set(applications)) != len(applications):
            raise ValueError("duplicate application reference")
    return config


def handoff(analysis, config, now):
    validate(config)
    bindings = {b["host"]: b for b in config["bindings"]}
    events = {e["id"]: e for e in analysis["events"]}
    behavior_by_host = defaultdict(set)
    for finding in analysis["findings"]:
        if finding["rule_id"].startswith(("B", "C")):
            behavior_by_host[finding["host"]].update(finding["evidence_ids"])
    items = []
    for incident in analysis["incidents"]:
        binding = bindings.get(incident["host"])
        gates = []
        if incident["risk"] < 70:
            gates.append("risk_below_review_threshold")
        if not any(rule.startswith(("B", "C")) for rule in incident["rule_ids"]):
            gates.append("behavior_evidence_required")
        evidence = [events[e] for e in incident["evidence_ids"] if e in events]
        behavior_ids = behavior_by_host[incident["host"]]
        fresh_behavior = any(e["id"] in behavior_ids and
                             0 <= (now - timestamp(e["timestamp"])).total_seconds()
                             <= config.get("evidence_max_age_seconds", 900) for e in evidence)
        if not fresh_behavior:
            gates.append("fresh_behavior_evidence_required")
        if binding is None:
            gates.append("verified_user_application_mapping_required")
        elif not 0 <= (now - timestamp(binding["verified_at"])).total_seconds() <= config.get("mapping_max_age_seconds", 3600):
            gates.append("mapping_stale_or_future")
        item = {"incident_id": incident["id"], "host": incident["host"], "risk": incident["risk"],
                "status": "blocked" if gates else "ready_for_manual_review", "gates": gates,
                "evidence_ids": incident["evidence_ids"], "rule_ids": incident["rule_ids"],
                "executable": False, "changes_applied": False}
        if binding and not gates:
            item["proposal"] = {
                "operation": "temporary_deny_user_to_applications",
                "subject": {"type": "user", "ref": binding["subject"]["ref"]},
                "application_refs": binding["application_refs"],
                "requested_duration_seconds": config.get("restriction_ttl_seconds", 900),
                "mapping_verified_by": binding["verified_by"], "mapping_verified_at": binding["verified_at"],
                "effect": "用户到指定应用的访问限制；可能影响该用户的其他设备，并非主机网络隔离。",
            }
        items.append(item)
    document = {
        "schema_version": 1, "integration": "yunmai_sase", "mode": "manual_console_handoff",
        "tenant_ref": config["tenant_ref"], "created_at": iso(now),
        "review_before": iso(now + timedelta(seconds=config.get("review_ttl_seconds", 600))),
        "analysis_digest": digest(analysis), "mapping_digest": digest(config),
        "cloud_status": "not_submitted", "changes_applied": False,
        "protected_application_refs": config["protected_application_refs"], "items": items,
        "operator_steps": [
            "核验告警、用户与终端归属、业务影响及该用户其他设备；确认租户和具体应用。",
            "在云脉控制台保存当前有效策略、顺序与审计依据；核实管理和取证通道不受影响。",
            "审批后创建仅针对该用户和指定应用的临时禁止策略，核对优先级及明确的到期时间。",
            "对新连接与已有会话分别测试；既有会话是否即时切断须按租户版本验证。",
            "保存策略 ID、操作员、审批单、变更时间与云脉审计记录；导出文件本身不是执行回执。",
            "到期复核策略状态与连通性；恢复时仅撤销本次临时策略，并检查期间其他策略变更。",
        ],
        "limitations": [
            "No management API request was sent. This file is not a vendor import format or an authorization token.",
            "Yunmai tunnel connection and client SDK state do not attest application identity.",
            "SASE access restrictions do not replace endpoint/EDR containment or block unrelated Internet traffic.",
        ],
    }
    document["id"] = "yunmai-handoff-" + digest(document)[:20]
    return document
