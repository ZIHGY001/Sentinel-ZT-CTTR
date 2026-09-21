"""Reviewed role baselines and bounded ATT&CK behavior analytics; no IOC required."""
from collections import Counter, defaultdict, deque
from datetime import timedelta
import ipaddress

from .common import ip_literal, iso, strict_integer, timestamp

REMOTE_PORTS = [22, 135, 139, 445, 3389, 5900, 5985, 5986]
CHANGE_ACTIONS = {"role_grant", "permission_grant", "group_add"}
MODELS = [
    {"id": "B101", "title": "远程服务访问偏离资产角色基线", "score": 55, "stage": "lateral_movement",
     "attack": ["T1021"], "rationale": "已注册源资产访问内部远程服务，目标、端口或协议组合不在已审核基线中；连接观察不证明登录成功。",
     "false_positives": "临时运维、发布或灾备切换；核对跳板路径与变更工单。", "telemetry": ["network"], "status": "experimental"},
    {"id": "B102", "title": "短时间访问多个基线外远程服务目标", "score": 75, "stage": "lateral_movement",
     "attack": ["T1021"], "rationale": "滑动时间窗口内，基线外远程服务连接达到不同目标数门槛；是横向活动假设，不证明成功入侵。",
     "false_positives": "资产运维、巡检和批量发布；仅对已核验的精确路径建立例外。", "telemetry": ["network"], "status": "experimental"},
    {"id": "B103", "title": "授权变更偏离已审核身份基线", "score": 75, "stage": "privilege_escalation",
     "attack": ["T1098"], "rationale": "成功的角色、权限或组变更不匹配已审核的操作者、动作、目标账户与权限组合。",
     "false_positives": "正常入离职或权限调整；核验身份审计、审批单与实际变更。", "telemetry": ["identity"], "status": "experimental"},
    {"id": "B104", "title": "权限提升偏离资产角色基线", "score": 75, "stage": "privilege_escalation",
     "attack": ["T1548"], "rationale": "成功的权限提升不匹配已审核的用户、目标身份与程序路径；需核验具体提权机制。",
     "false_positives": "获批 sudo、运维代理或安装程序；核验操作主体与变更时间。", "telemetry": ["privilege"], "status": "experimental"},
    {"id": "C101", "title": "异常权限变化后出现横向访问偏离", "score": 85, "stage": "correlation",
     "attack": ["T1098", "T1548", "T1021"], "rationale": "同资产、同一活动账户的权限变化之后，15 分钟内出现基线外远程服务访问；须进一步核验会话与因果关系。",
     "false_positives": "审批后的管理员工作流；同名用户不足以证明同一真实身份。", "telemetry": ["identity or privilege", "network.user"], "status": "experimental"},
]
EXCEPTION_FIELDS = {
    "B101": {"src_ip", "dst_ip", "dst_port", "transport"},
    "B103": {"actor", "action", "target_user", "target_role"},
    "B104": {"user", "action", "target_user", "process"},
}


def catalog():
    return [{**m, "ioc_required": False, "automatic_containment": False} for m in MODELS]


def text(value, field):
    if (not isinstance(value, str) or not value or value != value.strip() or len(value) > 512
            or "*" in value or any(ord(c) < 32 for c in value)):
        raise ValueError(f"baseline {field} requires exact nonempty text, without wildcards or control characters")
    return value


def object_fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError("baseline object has missing or unknown fields")


def records(value, maximum=100):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"baseline list must contain at most {maximum} entries")
    return value


def validity(value, maximum):
    start, end = timestamp(value["valid_from"]), timestamp(value["valid_until"])
    if not 0 < (end - start).total_seconds() <= maximum:
        raise ValueError("baseline validity exceeds its permitted window")
    text(value["reviewed_by"], "reviewed_by")


def ports(value):
    for port in records(value):
        strict_integer(port, 1, 65535)
    if not value or len(set(value)) != len(value):
        raise ValueError("baseline ports must be nonempty and unique")


def network(value):
    if not isinstance(value, str):
        raise ValueError("baseline network must be CIDR text")
    return ipaddress.ip_network(value, strict=True)


def validate(config):
    profiles = config.get("behavior_baselines", {})
    if not isinstance(profiles, dict) or len(profiles) > 100:
        raise ValueError("behavior_baselines must contain at most 100 profiles")
    for name, profile in profiles.items():
        text(name, "profile name")
        object_fields(profile, {"enabled", "revision", "role", "reviewed_by", "valid_from", "valid_until"},
                      {"network", "identity", "privilege"})
        if type(profile["enabled"]) is not bool:
            raise ValueError("baseline enabled must be boolean")
        for field in ("revision", "role"):
            text(profile[field], field)
        validity(profile, 90 * 86400)
        if not {"network", "identity", "privilege"} & profile.keys():
            raise ValueError("baseline requires at least one behavior section")
        if "network" in profile:
            n = profile["network"]
            object_fields(n, {"internal_networks", "remote_ports", "allowed_flows", "fanout_window_seconds", "fanout_threshold"})
            if not records(n["internal_networks"]):
                raise ValueError("baseline internal networks cannot be empty")
            for cidr in n["internal_networks"]:
                network(cidr)
            ports(n["remote_ports"])
            strict_integer(n["fanout_window_seconds"], 30, 900)
            strict_integer(n["fanout_threshold"], 2, 100)
            for flow in records(n["allowed_flows"]):
                object_fields(flow, {"dst_network", "dst_ports", "transport", "reason"})
                network(flow["dst_network"]); ports(flow["dst_ports"])
                if flow["transport"] not in ("tcp", "udp"):
                    raise ValueError("baseline transport must be tcp or udp")
                text(flow["reason"], "flow reason")
        for section, list_name, keys in [
                ("identity", "allowed_changes", {"actor", "action", "target_user", "target_role", "reason"}),
                ("privilege", "allowed_transitions", {"user", "target_user", "process", "reason"})]:
            if section not in profile:
                continue
            object_fields(profile[section], {list_name})
            for item in records(profile[section][list_name]):
                object_fields(item, keys)
                for key in keys:
                    text(item[key], key)
                if section == "identity" and item["action"] not in CHANGE_ACTIONS:
                    raise ValueError("unsupported identity baseline action")
    for asset in config.get("assets", {}).values():
        for field in ("role", "environment", "owner"):
            if field in asset:
                text(asset[field], field)
        name = asset.get("baseline_profile")
        if name is not None:
            text(name, "asset profile")
            if name not in profiles:
                raise ValueError("asset references an unknown baseline profile")
            if asset.get("role", profiles[name]["role"]) != profiles[name]["role"]:
                raise ValueError("asset role and baseline role disagree")
    seen = set()
    for item in records(config.get("behavior_exceptions", [])):
        object_fields(item, {"id", "host", "rule_id", "match", "valid_from", "valid_until", "reason", "reviewed_by"})
        for field in ("id", "host", "rule_id", "reason"):
            text(item[field], field)
        if item["id"] in seen or item["host"] not in config.get("assets", {}):
            raise ValueError("baseline exception id is duplicated or asset is not registered")
        seen.add(item["id"])
        if item["rule_id"] not in EXCEPTION_FIELDS:
            raise ValueError("baseline exceptions support only B101, B103 and B104")
        object_fields(item["match"], EXCEPTION_FIELDS[item["rule_id"]])
        for key, value in item["match"].items():
            if key == "dst_port":
                strict_integer(value, 1, 65535)
            elif key in {"src_ip", "dst_ip"}:
                if str(ip_literal(value)) != value:
                    raise ValueError("exception IP must be canonical")
            else:
                text(value, key)
        validity(item, 86400)
    return config


def profile_status(profile, now):
    if profile is None:
        return "unconfigured"
    if not profile["enabled"]:
        return "draft"
    if now < timestamp(profile["valid_from"]):
        return "not_yet_valid"
    if now >= timestamp(profile["valid_until"]):
        return "expired"
    return "active"


def evaluate(events, config, now, add):
    """All exceptions are reviewed policy data, never imported event claims."""
    profiles = config.get("behavior_baselines", {})
    models = {m["id"]: m for m in MODELS}
    exceptions = defaultdict(list)
    for item in config.get("behavior_exceptions", []):
        if timestamp(item["valid_from"]) <= now < timestamp(item["valid_until"]):
            exceptions[(item["host"], item["rule_id"])].append(item)
    hosts = defaultdict(list)
    for event in events:
        hosts[event["host"]].append(event)
    summaries, applied = [], []
    for host in sorted(set(hosts) | set(config.get("assets", {}))):
        observations = hosts[host]
        asset = config.get("assets", {}).get(host, {})
        profile_name = asset.get("baseline_profile")
        profile = profiles.get(profile_name)
        status = profile_status(profile, now)
        summary = {"host": host, "registered": bool(asset), "profile": profile_name,
                   "role": asset.get("role", profile.get("role") if profile else None),
                   "criticality": asset.get("criticality", "unknown"), "status": status,
                   "evaluated_events": 0, "expected_events": 0, "exception_events": 0,
                   "deviations": 0, "gaps": [], "observed_types": sorted({e["event_type"] for e in observations})}
        summaries.append(summary)
        if status != "active":
            summary["gaps"].append("reviewed_active_baseline_required")
            continue
        summary.update(revision=profile["revision"], valid_until=profile["valid_until"])
        gaps, lateral, elevated = set(), [], []
        n = profile.get("network")
        internal = [network(c) for c in n["internal_networks"]] if n else []
        flows = [(network(f["dst_network"]), f) for f in n["allowed_flows"]] if n else []

        def emit(rule_id, evidence, actual, reason):
            for exception in exceptions[(host, rule_id)]:
                if (all(timestamp(exception["valid_from"]) <= timestamp(e["timestamp"]) < timestamp(exception["valid_until"]) for e in evidence)
                        and all(evidence[0].get(k) == v and type(evidence[0].get(k)) is type(v)
                                for k, v in exception["match"].items())
                        and evidence[0].get("authorized") is not False):
                    summary["exception_events"] += 1
                    applied.append({"exception_id": exception["id"], "rule_id": rule_id,
                                    "event_id": evidence[0]["id"], "reason": exception["reason"],
                                    "valid_until": exception["valid_until"]})
                    return False
            finding = add(models[rule_id], evidence)
            if finding is not None:
                finding["baseline"] = {"profile": profile_name, "revision": profile["revision"],
                                       "valid_until": profile["valid_until"],
                                       "reason": reason, "observed": actual, "ioc_required": False}
                summary["deviations"] += 1
                return True
            return False

        for e in observations:
            if not timestamp(profile["valid_from"]) <= timestamp(e["timestamp"]) < timestamp(profile["valid_until"]):
                gaps.add("event_outside_baseline_validity"); continue
            kind = e["event_type"]
            if kind == "network" and n:
                if not all(e.get(k) is not None for k in ("src_ip", "dst_ip", "dst_port", "transport")):
                    gaps.add("network_fields_missing"); continue
                if e["src_ip"] not in asset.get("ips", []):
                    gaps.add("network_source_not_registered_asset"); continue
                if e["transport"] not in {"tcp", "udp"}:
                    gaps.add("network_transport_unknown"); continue
                summary["evaluated_events"] += 1
                dst = ip_literal(e["dst_ip"])
                if e["dst_port"] not in n["remote_ports"] or not any(dst in net for net in internal):
                    continue
                if (e.get("authorized") is not False and any(dst in net and e["dst_port"] in f["dst_ports"]
                        and e["transport"] == f["transport"] for net, f in flows)):
                    summary["expected_events"] += 1; continue
                if emit("B101", [e], {k: e[k] for k in EXCEPTION_FIELDS["B101"]}, "remote_flow_not_expected"):
                    lateral.append(e)
            elif kind == "identity" and "identity" in profile and e.get("action") in CHANGE_ACTIONS:
                fields = EXCEPTION_FIELDS["B103"]
                if not all(isinstance(e.get(k), str) and e[k] for k in fields) or e.get("outcome") not in {"success", "failure"}:
                    gaps.add("identity_change_fields_missing"); continue
                summary["evaluated_events"] += 1
                if e["outcome"] != "success":
                    continue
                if (e.get("authorized") is not False and any(all(e[k] == item[k] for k in fields)
                        for item in profile["identity"]["allowed_changes"])):
                    summary["expected_events"] += 1; continue
                if emit("B103", [e], {k: e[k] for k in fields}, "identity_change_not_expected"):
                    elevated.append((e, e["target_user"]))
            elif kind == "privilege" and "privilege" in profile and e.get("action") == "elevate":
                fields = EXCEPTION_FIELDS["B104"]
                if not all(isinstance(e.get(k), str) and e[k] for k in fields) or e.get("outcome") not in {"success", "failure"}:
                    gaps.add("privilege_fields_missing"); continue
                summary["evaluated_events"] += 1
                if e["outcome"] != "success":
                    continue
                if (e.get("authorized") is not False and any(all(e[k] == item[k] for k in fields - {"action"})
                        for item in profile["privilege"]["allowed_transitions"])):
                    summary["expected_events"] += 1; continue
                if emit("B104", [e], {k: e[k] for k in fields}, "privilege_transition_not_expected"):
                    elevated.append((e, e["user"]))
        lateral.sort(key=lambda e: timestamp(e["timestamp"]))
        if n:
            window, counts = deque(), Counter()
            for e in lateral:
                window.append(e); counts[e["dst_ip"]] += 1
                while (timestamp(e["timestamp"]) - timestamp(window[0]["timestamp"])).total_seconds() > n["fanout_window_seconds"]:
                    old = window.popleft(); counts[old["dst_ip"]] -= 1
                    if not counts[old["dst_ip"]]: del counts[old["dst_ip"]]
                if len(counts) >= n["fanout_threshold"]:
                    evidence = list({item["dst_ip"]: item for item in window}.values())
                    emit("B102", evidence, {"unique_targets": len(counts), "window_seconds": n["fanout_window_seconds"],
                                           "threshold": n["fanout_threshold"]}, "remote_fanout_threshold_exceeded")
                    break
        # Merge chronological streams; actor equality is mandatory for this chain.
        timeline = sorted([(timestamp(e["timestamp"]), 1, e, actor) for e, actor in elevated] +
                          [(timestamp(e["timestamp"]), 0, e, e.get("user")) for e in lateral], key=lambda x: (x[0], x[1]))
        latest = {}
        for at, kind, e, actor in timeline:
            if kind:
                latest[actor] = e
            elif actor and actor in latest and 0 < (at - timestamp(latest[actor]["timestamp"])).total_seconds() <= 900:
                emit("C101", [latest[actor], e], {"account_join": "exact", "window_seconds": 900}, "privilege_then_lateral_same_account")
                break
        for section, event_type in (("network", "network"), ("identity", "identity"), ("privilege", "privilege")):
            if section in profile and event_type not in summary["observed_types"]:
                gaps.add(section + "_telemetry_absent")
        if not summary["evaluated_events"]:
            gaps.add("no_evaluable_behavior_events")
        summary["gaps"] = sorted(gaps)
    return {"configured": bool(profiles), "ioc_required": False, "assets": summaries,
            "exceptions_applied": applied, "models": catalog(),
            "notice": "Baselines are reviewed policy, not proof of safety. Missing telemetry is a coverage gap."}


def template(now):
    return {"schema_version": 1, "operators": [], "suppressions": [], "behavior_exceptions": [],
            "protected_networks": ["127.0.0.0/8", "::1/128"],
            "assets": {"workstation-example": {"ips": ["192.0.2.10"], "role": "workstation",
                        "baseline_profile": "workstation", "response_enabled": False, "criticality": "normal", "permissions": {}}},
            "behavior_baselines": {"workstation": {
                "enabled": False, "revision": "review-1", "role": "workstation", "reviewed_by": "REPLACE-WITH-REVIEWER",
                "valid_from": iso(now), "valid_until": iso(now + timedelta(days=30)),
                "network": {"internal_networks": ["192.0.2.0/24"], "remote_ports": REMOTE_PORTS.copy(),
                            "allowed_flows": [], "fanout_window_seconds": 300, "fanout_threshold": 3},
                "identity": {"allowed_changes": []}, "privilege": {"allowed_transitions": []}}}}
