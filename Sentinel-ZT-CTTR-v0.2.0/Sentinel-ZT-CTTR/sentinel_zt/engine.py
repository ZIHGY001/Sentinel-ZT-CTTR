"""Correlate evidence without confusing hypotheses with confirmed incidents."""
from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from datetime import timedelta

from .common import digest, iso, timestamp
from .intel import IntelIndex
from .rules import detect, get_rules


def analyze(events, indicators, now, config):
    rules = get_rules()
    index = IntelIndex(indicators, now, config.get("min_intel_confidence", 60))
    findings, hosts, event_hits = [], defaultdict(list), {}
    stats = {"future_events": 0, "stale_events": 0, "suppressed_findings": 0}
    suppressions = config.get("suppressions", [])
    window = config.get("analysis_window_seconds", 86400)
    eligible = []
    for event in events:
        dt = timestamp(event["timestamp"])
        if dt > now:
            stats["future_events"] += 1
            continue
        if (now - dt).total_seconds() > window:
            stats["stale_events"] += 1
            continue
        eligible.append(event)
        hosts[event["host"]].append(event)

    def add(rule, evidence, hits=None):
        host = evidence[0]["host"]
        for suppression in suppressions:
            if (suppression.get("rule_id") == rule["id"] and suppression.get("host") == host
                    and suppression.get("reason") and timestamp(suppression["expires_at"]) > now):
                stats["suppressed_findings"] += 1
                return
        finding = {"id": "finding-" + digest([rule["id"], [e["id"] for e in evidence]])[:20],
                   "rule_id": rule["id"], "title": rule["title"], "host": host,
                   "score": rule["score"], "stage": rule["stage"],
                   "attack": rule.get("attack", []), "rationale": rule["rationale"],
                   "false_positives": rule.get("false_positives", ""),
                   "evidence_ids": [e["id"] for e in evidence], "intel": hits or [],
                   "first_seen": min(e["timestamp"] for e in evidence),
                   "last_seen": max(e["timestamp"] for e in evidence),
                   "verdict": "correlated_hypothesis" if rule["id"].startswith("C") else "suspicious_observation"}
        findings.append(finding)

    for event in eligible:
        for rule in detect(event, rules):
            add(rule, [event])
        hits = index.match(event)
        if hits:
            event_hits[event["id"]] = hits
            add({"id": "I001", "title": "有效威胁情报精确命中", "score": 60,
                 "stage": "intelligence", "attack": [],
                 "rationale": "来源、置信度、分析时点和事件时点有效期均已核验；命中不等于失陷。",
                 "false_positives": "共享IP、已转移域名、误报情报。"}, [event], hits)

    # Behavioral chains require ordered observations on the SAME asset within 15 minutes.
    chains = [
        ("C001", "文档执行后出现情报命中外联", {"B001"}, {"I001"}, 80),
        ("C002", "Web异常请求后出现服务进程执行", {"B006", "B008", "B009", "B010", "B015"}, {"B002", "B014"}, 80),
        ("C003", "Agent扩展或工具异常后访问凭据或内网", {"B003", "B004"}, {"B005", "B016"}, 85),
        ("C004", "可疑执行后创建持久化", {"B001", "B002", "B004"}, {"B011", "B014", "B017"}, 85),
    ]
    by_host = defaultdict(list)
    event_map = {e["id"]: e for e in eligible}
    for f in findings:
        by_host[f["host"]].append(f)
    for host, host_findings in by_host.items():
        for rule_id, title, first_rules, second_rules, score in chains:
            firsts = [f for f in host_findings if f["rule_id"] in first_rules]
            seconds = [f for f in host_findings if f["rule_id"] in second_rules]
            selected = None
            for a in firsts:
                for b in seconds:
                    delta = (timestamp(b["first_seen"]) - timestamp(a["last_seen"])).total_seconds()
                    if 0 < delta <= 900:
                        a_event, b_event = event_map[a["evidence_ids"][0]], event_map[b["evidence_ids"][0]]
                        if rule_id == "C001" and (b_event["event_type"] != "network"
                                                   or not b_event.get("dst_ip")):
                            continue
                        if rule_id == "C001":
                            local = config.get("assets", {}).get(host, {}).get("ips", [])
                            if b_event.get("src_ip") not in local or not any(h["field"] == "dst_ip" for h in b["intel"]):
                                continue
                        selected = [a_event, b_event]
                        break
                if selected:
                    break
            if selected:
                add({"id": rule_id, "title": title, "score": score, "stage": "correlation",
                     "rationale": "同一资产、先后有序、15分钟内的关联假设；尚未证明进程或会话因果关系。",
                     "false_positives": "同一主机上互不相关的活动；请核验进程GUID和会话。"}, selected)

    # Conservative, transparent periodicity heuristic; deduplicated timestamps required.
    groups = defaultdict(list)
    for event in eligible:
        if event["event_type"] == "network" and event.get("dst_ip"):
            groups[(event["host"], event.get("src_ip"), event["dst_ip"], event.get("dst_port"))].append(event)
    for sequence in groups.values():
        sequence.sort(key=lambda x: x["timestamp"])
        times = sorted(set(timestamp(e["timestamp"]) for e in sequence))
        if len(times) < 6:
            continue
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        average = statistics.mean(gaps)
        if 10 <= average <= 600 and statistics.pstdev(gaps) / average <= 0.15:
            add({"id": "B018", "title": "连接间隔高度规律，疑似心跳通信", "score": 40,
                 "stage": "command_and_control", "attack": ["T1071"],
                 "rationale": f"{len(times)}次连接，平均间隔{average:.1f}秒，间隔变异系数≤0.15。",
                 "false_positives": "监控心跳、正常轮询、软件更新；单独出现不得判定C2。"}, sequence)

    incidents = []
    for host in sorted(hosts):
        fs = [f for f in findings if f["host"] == host]
        if not fs:
            continue
        rule_ids = sorted({f["rule_id"] for f in fs})
        stages = sorted({f["stage"] for f in fs if f["stage"] not in {"intelligence", "correlation"}})
        behavior = [f for f in fs if f["rule_id"] != "I001"]
        base = max(f["score"] for f in fs)
        diversity = min(16, max(0, len(stages) - 1) * 8)
        intel_boost = 15 if behavior and "I001" in rule_ids else 0
        risk = min(99, base + diversity + intel_boost)
        evidence_ids = sorted({i for f in fs for i in f["evidence_ids"]})
        incidents.append({"id": "case-" + digest([host, rule_ids, evidence_ids])[:20],
                          "host": host, "risk": risk,
                          "severity": "critical" if risk >= 85 else "high" if risk >= 70 else "medium" if risk >= 40 else "low",
                          "scoring": {"max_signal": base, "stage_diversity": diversity, "intel_corroboration": intel_boost},
                          "rule_ids": rule_ids, "stages": stages, "evidence_ids": evidence_ids,
                          "finding_ids": [f["id"] for f in fs],
                          "last_seen": max(f["last_seen"] for f in fs),
                          "verdict": "requires_analyst_validation"})
    return {"schema_version": 1, "generated_at": iso(now), "policy_digest": digest(config),
            "rules_digest": digest(rules), "events": eligible, "findings": findings,
            "incidents": sorted(incidents, key=lambda x: (-x["risk"], x["host"])),
            "statistics": {"input_events": len(events), "analyzed_events": len(eligible), **stats},
            "intel_ignored": index.ignored,
            "limitations": ["分数是可解释启发式优先级，不是失陷概率。", "同资产时间关联不证明因果关系。",
                            "未命中规则不代表系统安全；本工具不是漏洞利用验证器。"]}


def protected_ip(value, config):
    ip = ipaddress.ip_address(value)
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    return any(ip in ipaddress.ip_network(net) for net in config.get("protected_networks", []))


def make_plan(analysis, config, now):
    actions = []
    events = {e["id"]: e for e in analysis["events"]}
    for incident in analysis["incidents"]:
        host = incident["host"]
        asset = config.get("assets", {}).get(host, {})
        local_ips = {str(ipaddress.ip_address(x)) for x in asset.get("ips", [])}
        evidence = [events[x] for x in incident["evidence_ids"]]
        manual = ["保存原始日志与文件哈希，核验时间和资产归属", "核对变更、进程GUID、会话与业务影响"]
        if "credential_access" in incident["stages"] or "privilege_escalation" in incident["stages"]:
            manual += ["在身份平台撤销受影响会话并轮换相关密钥；核验异常授权"]
        if "persistence" in incident["stages"]:
            manual += ["保全样本后核验并清除异常持久化，按业务恢复流程复测"]
        actions.append({"id": "action-" + digest([incident["id"], "investigate"])[:20],
                        "type": "manual_investigation", "host": host, "incident_id": incident["id"],
                        "steps": manual, "executable": False})
        # Only IOC matched IPs observed as actual peers of a registered asset can be blocked.
        peers = {}
        for f in analysis["findings"]:
            if f["host"] != host or f["rule_id"] != "I001":
                continue
            e = events[f["evidence_ids"][0]]
            if e["event_type"] != "network":
                continue
            for hit in f["intel"]:
                if hit["type"] != "ip":
                    continue
                value, field = hit["value"], hit["field"]
                opposite = e.get("src_ip" if field == "dst_ip" else "dst_ip")
                if opposite in local_ips and value not in local_ips:
                    peers.setdefault(value, []).append(e["id"])
        for peer, ids in sorted(peers.items()):
            reasons = []
            if incident["risk"] < config.get("response_threshold", 75):
                reasons.append("risk_below_threshold")
            if len(incident["rule_ids"]) < 2 or all(r == "I001" for r in incident["rule_ids"]):
                reasons.append("independent_behavior_required")
            if asset.get("response_enabled") is not True:
                reasons.append("asset_response_not_enabled")
            if protected_ip(peer, config):
                reasons.append("protected_peer")
            if asset.get("criticality") == "critical":
                reasons.append("critical_asset_manual_response_only")
            last_peer_evidence = max(events[i]["timestamp"] for i in ids)
            if (now - timestamp(last_peer_evidence)).total_seconds() > config.get("max_evidence_age_seconds", 900):
                reasons.append("stale_evidence")
            actions.append({"id": "action-" + digest([incident["id"], "block_peer", peer])[:20],
                            "type": "block_peer", "host": host, "peer_ip": peer,
                            "incident_id": incident["id"], "risk": incident["risk"],
                            "evidence_ids": sorted(set(ids)), "ttl_seconds": config.get("block_ttl_seconds", 300),
                            "last_evidence_at": last_peer_evidence,
                            "executable": not reasons, "gates": reasons,
                            "scope": "local_host_input_output", "requires_approval": True,
                            "rollback": "delete_only_action_owned_nft_table"})
    plan = {"schema_version": 1, "created_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=config.get("plan_ttl_seconds", 600))),
            "policy_digest": digest(config), "analysis_digest": digest(analysis), "actions": actions}
    plan["id"] = "plan-" + digest(plan)[:20]
    return plan
