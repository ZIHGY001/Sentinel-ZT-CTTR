"""Correlate evidence without confusing hypotheses with confirmed incidents."""
from __future__ import annotations

import ipaddress
import statistics
from bisect import bisect_right
from collections import defaultdict
from datetime import timedelta

from .common import digest, ip_literal, iso, timestamp
from .events import MAX_EVENTS
from .intel import IntelIndex
from .rules import detect, get_rules
from . import baselines, runbooks


def analyze(events, indicators, now, config):
    if len(events) > MAX_EVENTS:
        raise ValueError(f"event limit {MAX_EVENTS} exceeded; split the investigation")
    rules = get_rules()
    index = IntelIndex(indicators, now, config.get("min_intel_confidence", 60))
    findings, hosts, event_hits = [], defaultdict(list), {}
    stats = {"future_events": 0, "stale_events": 0, "suppressed_findings": 0}
    suppressions = {(s["rule_id"], s["host"]) for s in config.get("suppressions", [])
                    if s.get("reason") and timestamp(s["expires_at"]) > now}
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

    associations = 0

    def add(rule, evidence, hits=None):
        nonlocal associations
        host = evidence[0]["host"]
        if (rule["id"], host) in suppressions:
            stats["suppressed_findings"] += 1
            return
        associations += len(evidence) + len(hits or [])
        if len(findings) >= 20000 or associations > 50000:
            raise ValueError("analysis expansion budget exceeded; split events or narrow the IOC feed")
        finding = {"id": "finding-" + digest([rule["id"], [e["id"] for e in evidence]])[:20],
                   "rule_id": rule["id"], "title": rule["title"], "host": host,
                   "score": rule["score"], "stage": rule["stage"],
                   "attack": rule.get("attack", []), "rationale": rule["rationale"],
                   "false_positives": rule.get("false_positives", ""),
                   "evidence_ids": [e["id"] for e in evidence], "intel": hits or [],
                   "first_seen": min((e["timestamp"] for e in evidence), key=timestamp),
                   "last_seen": max((e["timestamp"] for e in evidence), key=timestamp),
                   "verdict": "correlated_hypothesis" if rule["id"].startswith("C") else "suspicious_observation"}
        findings.append(finding)
        return finding

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

    baseline_context = baselines.evaluate(eligible, config, now, add)

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
            if rule_id == "C001":
                local = config.get("assets", {}).get(host, {}).get("ips", [])
                seconds = [f for f in seconds if
                           event_map[f["evidence_ids"][0]]["event_type"] == "network"
                           and event_map[f["evidence_ids"][0]].get("src_ip") in local
                           and event_map[f["evidence_ids"][0]].get("dst_ip")
                           and any(h["field"] == "dst_ip" for h in f["intel"])]
            seconds.sort(key=lambda f: timestamp(f["first_seen"]))
            second_times = [timestamp(f["first_seen"]) for f in seconds]
            selected = None
            for a in firsts:
                start = timestamp(a["last_seen"])
                idx = bisect_right(second_times, start)
                if idx < len(seconds) and (second_times[idx] - start).total_seconds() <= 900:
                    selected = [event_map[a["evidence_ids"][0]], event_map[seconds[idx]["evidence_ids"][0]]]
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
        sequence.sort(key=lambda x: timestamp(x["timestamp"]))
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
    all_findings_by_host = defaultdict(list)
    for f in findings:
        all_findings_by_host[f["host"]].append(f)
    for host in sorted(hosts):
        fs = all_findings_by_host[host]
        if not fs:
            continue
        rule_ids = sorted({f["rule_id"] for f in fs})
        stages = sorted({f["stage"] for f in fs if f["stage"] not in {"intelligence", "correlation"}})
        behavior = [f for f in fs if f["rule_id"] != "I001"]
        base = max(f["score"] for f in fs)
        diversity = min(16, max(0, len(stages) - 1) * 8)
        intel_boost = 15 if behavior and "I001" in rule_ids else 0
        registered = config.get("assets", {}).get(host, {})
        asset_priority = 8 if registered.get("criticality") == "critical" and any(f.get("baseline") for f in fs) else 0
        risk = min(99, base + diversity + intel_boost + asset_priority)
        evidence_ids = sorted({i for f in fs for i in f["evidence_ids"]})
        incidents.append({"id": "case-" + digest([host, rule_ids, evidence_ids])[:20],
                          "host": host, "risk": risk,
                          "severity": "critical" if risk >= 85 else "high" if risk >= 70 else "medium" if risk >= 40 else "low",
                          "scoring": {"max_signal": base, "stage_diversity": diversity,
                                      "intel_corroboration": intel_boost, "asset_priority": asset_priority},
                          "asset_profile": {"registered": bool(registered), "role": registered.get("role"),
                                            "criticality": registered.get("criticality", "unknown"),
                                            "baseline_profile": registered.get("baseline_profile")},
                          "rule_ids": rule_ids, "stages": stages, "evidence_ids": evidence_ids,
                          "finding_ids": [f["id"] for f in fs],
                          "last_seen": max((f["last_seen"] for f in fs), key=timestamp),
                          "verdict": "requires_analyst_validation"})
    result = {"schema_version": 1, "generated_at": iso(now), "policy_digest": digest(config),
            "rules_digest": digest({"rules": rules, "baseline_models": baselines.catalog()}),
            "events": eligible, "findings": findings, "behavior_baseline": baseline_context,
            "incidents": sorted(incidents, key=lambda x: (-x["risk"], x["host"])),
            "statistics": {"input_events": len(events), "analyzed_events": len(eligible), **stats},
            "intel_ignored": index.ignored,
            "limitations": ["分数是可解释启发式优先级，不是失陷概率。", "同资产时间关联不证明因果关系。",
                            "未命中规则不代表系统安全；本工具不是漏洞利用验证器。"]}
    runbooks.enrich(result)
    return result


def protected_ip(value, config):
    ip = ip_literal(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return True  # mapped addresses are not native IPv6 firewall peers
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    return any(ip in ipaddress.ip_network(net) for net in config.get("protected_networks", []))


def fresh_behaviors(analysis, now, max_age):
    """Choose complete, recent B-rule evidence; a C-chain's new IOC is not behavior."""
    events = {e["id"]: e for e in analysis["events"]}
    selected = {}
    for finding in analysis["findings"]:
        if not finding["rule_id"].startswith("B") or not finding["evidence_ids"]:
            continue
        evidence = [events[eid] for eid in finding["evidence_ids"] if eid in events]
        if len(evidence) != len(finding["evidence_ids"]) or any(e["host"] != finding["host"] for e in evidence):
            continue
        times = [timestamp(e["timestamp"]) for e in evidence]
        oldest = min(times)
        if max(times) > now or not 0 <= (now - oldest).total_seconds() < max_age:
            continue
        deadline = oldest + timedelta(seconds=max_age)
        if finding.get("baseline"):
            deadline = min(deadline, timestamp(finding["baseline"]["valid_until"]))
        if now >= deadline:
            continue
        previous = selected.get(finding["host"])
        if previous is None or oldest > timestamp(previous["observed_at"]):
            selected[finding["host"]] = {"finding_id": finding["id"], "rule_id": finding["rule_id"],
                                        "evidence_ids": finding["evidence_ids"], "observed_at": iso(oldest),
                                        "valid_until": iso(deadline)}
    return selected


def make_plan(analysis, config, now):
    actions = []
    behavior = fresh_behaviors(analysis, now, config.get("max_evidence_age_seconds", 900))
    events = {e["id"]: e for e in analysis["events"]}
    ioc_findings = defaultdict(list)
    for f in analysis["findings"]:
        if f["rule_id"] == "I001":
            ioc_findings[f["host"]].append(f)
    for incident in analysis["incidents"]:
        host = incident["host"]
        asset = config.get("assets", {}).get(host, {})
        local_ips = {str(ipaddress.ip_address(x)) for x in asset.get("ips", [])}
        evidence = [events[x] for x in incident["evidence_ids"]]
        manual = ["保存原始日志与文件哈希，核验时间和资产归属", "核对变更、进程GUID、会话与业务影响"]
        if any(r in incident["rule_ids"] for r in ("B101", "B102", "B103", "B104", "C101")):
            manual += ["核验资产角色、基线版本和临时例外；缺少 IOC 不作为忽略行为告警的理由",
                       "按已核验用户和应用生成云脉待审核交接单；限制最小访问范围并保留管理通道"]
        if "lateral_movement" in incident["stages"]:
            manual += ["关联源端进程与目标登录日志，核验跨主机账户和会话；复核跳板访问路径"]
        if "credential_access" in incident["stages"] or "privilege_escalation" in incident["stages"]:
            manual += ["在身份平台撤销受影响会话并轮换相关密钥；核验异常授权"]
        if "persistence" in incident["stages"]:
            manual += ["保全样本后核验并清除异常持久化，按业务恢复流程复测"]
        actions.append({"id": "action-" + digest([incident["id"], "investigate"])[:20],
                        "type": "manual_investigation", "host": host, "incident_id": incident["id"],
                        "steps": manual, "executable": False})
        # Only IOC matched IPs observed as actual peers of a registered asset can be blocked.
        peers, supports = {}, {}
        for f in ioc_findings[host]:
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
                    deadline = min(timestamp(hit["valid_until"]), timestamp(e["timestamp"]) +
                                   timedelta(seconds=config.get("max_evidence_age_seconds", 900)))
                    if value not in supports or deadline > supports[value][0]:
                        supports[value] = (deadline, {**hit, "evidence_id": e["id"],
                                                     "observed_at": e["timestamp"]})
        for peer, ids in sorted(peers.items()):
            reasons = []
            if incident["risk"] < config.get("response_threshold", 75):
                reasons.append("risk_below_threshold")
            if len(incident["rule_ids"]) < 2 or all(r == "I001" for r in incident["rule_ids"]):
                reasons.append("independent_behavior_required")
            if host not in behavior:
                reasons.append("fresh_behavior_evidence_required")
            if asset.get("response_enabled") is not True:
                reasons.append("asset_response_not_enabled")
            if protected_ip(peer, config):
                reasons.append("protected_peer")
            if asset.get("criticality") == "critical":
                reasons.append("critical_asset_manual_response_only")
            support = supports[peer][1]
            last_peer_evidence = support["observed_at"]
            if timestamp(support["valid_until"]) <= now:
                reasons.append("expired_intelligence")
            if not 0 <= (now - timestamp(last_peer_evidence)).total_seconds() < config.get("max_evidence_age_seconds", 900):
                reasons.append("stale_evidence")
            actions.append({"id": "action-" + digest([incident["id"], "block_peer", peer])[:20],
                            "type": "block_peer", "host": host, "peer_ip": peer,
                            "incident_id": incident["id"], "risk": incident["risk"],
                            "evidence_ids": sorted(set(ids)), "ttl_seconds": config.get("block_ttl_seconds", 300),
                            "last_evidence_at": last_peer_evidence,
                            "intel_evidence": support,
                            "behavior_evidence_at": behavior.get(host, {}).get("observed_at"),
                            "behavior_evidence_ids": behavior.get(host, {}).get("evidence_ids", []),
                            "behavior_rule_id": behavior.get(host, {}).get("rule_id"),
                            "executable": not reasons, "gates": reasons,
                            "scope": "local_host_input_output", "requires_approval": True,
                            "rollback": "delete_only_action_owned_nft_table"})
    plan = {"schema_version": 1, "created_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=config.get("plan_ttl_seconds", 600))),
            "policy_digest": digest(config), "analysis_digest": digest(analysis), "actions": actions}
    plan["id"] = "plan-" + digest(plan)[:20]
    return plan
