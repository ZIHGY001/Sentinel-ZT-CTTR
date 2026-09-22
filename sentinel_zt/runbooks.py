"""Offline investigation guidance. Never execute commands or change detection/response policy."""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import re

from .common import digest, iso, load_json, timestamp

PLATFORMS = {"unknown", "linux", "windows"}
STATUSES = {"pending", "suspicious", "not_observed", "needs_data", "not_applicable"}
MAX_REVISIONS = 200


@lru_cache(maxsize=1)
def _catalog():
    return load_json(Path(__file__).parent / "data" / "runbooks.json")


def catalog():
    return deepcopy(_catalog())


def recommend(incident, platform="unknown"):
    if platform not in PLATFORMS:
        raise ValueError("platform must be unknown, linux or windows")
    result = []
    for book in _catalog()["runbooks"]:
        matches = sorted(set(incident["rule_ids"]) & set(book["rule_ids"]))
        if book["platform"] not in {"any", platform}:
            continue
        if not book["always"] and not matches:
            continue
        result.append({**deepcopy(book), "matched_rules": matches,
                       "selection_reason": "rule_match" if matches else "platform_or_core_review"})
    return result


def enrich(analysis):
    for incident in analysis["incidents"]:
        incident["runbook_recommendations"] = [
            {k: b[k] for k in ("id", "title", "platform", "matched_rules", "selection_reason")}
            for b in recommend(incident)]


def create(analysis, incident_id, platform, now):
    incident = next((c for c in analysis["incidents"] if c["id"] == incident_id), None)
    if incident is None:
        raise ValueError("incident not found in this investigation")
    books = recommend(incident, platform)
    checks = []
    for book in books:
        for check in book["checks"]:
            checks.append({**deepcopy(check), "runbook_id": book["id"], "status": "pending",
                           "review": None})
    incident_evidence = set(incident["evidence_ids"])
    evidence = [{"id": e["id"], "timestamp": e["timestamp"], "event_type": e["event_type"]}
                for e in analysis["events"] if e["id"] in incident_evidence and e["host"] == incident["host"]]
    return {"schema_version": 1, "catalog_version": _catalog()["version"],
            "catalog_digest": digest(_catalog()), "incident_id": incident_id,
            "host": incident["host"], "platform": platform, "platform_origin": "analyst_declared",
            "created_at": iso(now), "revision": 0, "analysis_generated_at": analysis["generated_at"],
            "policy_digest": analysis["policy_digest"], "asset_profile": deepcopy(incident.get("asset_profile", {})),
            "rule_ids": list(incident["rule_ids"]), "available_evidence": evidence,
            "sources": deepcopy(_catalog()["sources"]),
            "runbooks": [{k: b[k] for k in ("id", "title", "matched_rules", "selection_reason")} for b in books],
            "checks": checks, "history": [], "changes_applied": False,
            "notice": "人工调查记录；平台不执行命令。核验结果不修改风险分、基线或处置授权。"}


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{label} must be nonempty text, at most {maximum} characters")
    return value.strip()


def review(document, check_id, payload, now):
    """Validate evidence binding and append a revision; prior observations stay available."""
    required = {"expected_revision", "status", "reviewer", "observation", "evidence_ids", "artifacts"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid review fields")
    expected = payload["expected_revision"]
    if type(expected) is not int or expected != document["revision"]:
        raise ValueError("stale worksheet revision; reload before saving")
    if document["revision"] >= MAX_REVISIONS:
        raise ValueError("worksheet revision limit reached; archive the investigation")
    check = next((c for c in document["checks"] if c["id"] == check_id), None)
    if check is None:
        raise ValueError("check not found in this worksheet")
    status = payload["status"]
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("invalid check status")
    reviewer = _text(payload["reviewer"], "reviewer", 100)
    observation = _text(payload["observation"], "observation", 2000)
    ids = payload["evidence_ids"]
    allowed = {e["id"] for e in document["available_evidence"]}
    if (not isinstance(ids, list) or len(ids) > 30 or any(not isinstance(i, str) for i in ids)
            or len(ids) != len(set(ids)) or not set(ids) <= allowed):
        raise ValueError("evidence must reference unique events from this incident")
    artifacts = payload["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > 10:
        raise ValueError("at most 10 external evidence descriptors are allowed")
    clean_artifacts = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "collected_at"}:
            raise ValueError("artifact requires name, sha256 and collected_at")
        name = _text(artifact["name"], "artifact name", 200)
        sha = artifact["sha256"]
        if not isinstance(sha, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha):
            raise ValueError("artifact SHA256 must be 64 hex characters")
        if not isinstance(artifact["collected_at"], str):
            raise ValueError("artifact collection time must be an ISO timestamp")
        collected = timestamp(artifact["collected_at"])
        if collected > now:
            raise ValueError("artifact collection time cannot be in the future")
        clean_artifacts.append({"name": name, "sha256": sha.lower(), "collected_at": iso(collected),
                                "verification": "analyst_supplied_not_verified"})
    if status in {"suspicious", "not_observed"} and not ids and not clean_artifacts:
        raise ValueError("a finding or negative conclusion requires evidence; otherwise use needs_data")
    result = deepcopy(document)
    entry = {"revision": expected + 1, "check_id": check_id, "status": status, "reviewer": reviewer,
             "reviewer_identity": "self_declared_shared_token", "observation": observation,
             "evidence_ids": ids[:], "artifacts": clean_artifacts, "recorded_at": iso(now)}
    updated = next(c for c in result["checks"] if c["id"] == check_id)
    updated.update(status=status, review=entry)
    result["history"].append(entry)
    result["revision"] += 1
    return result


def summarize(document):
    counts = {s: sum(c["status"] == s for c in document["checks"]) for s in sorted(STATUSES)}
    return {"total": len(document["checks"]), "counts": counts,
            "reviewed": sum(c["status"] in {"suspicious", "not_observed", "not_applicable"} for c in document["checks"]),
            "unresolved": counts["pending"] + counts["needs_data"],
            "assurance": "checklist_progress_only_not_proof_of_safety"}


def feedback(document):
    """Only draft review tasks: no executable policy or automatic suppression output."""
    tasks = [{"check_id": c["id"], "status": c["status"], "recommendation": c["baseline_feedback"],
              "review": deepcopy(c["review"])} for c in document["checks"] if c["status"] != "pending"]
    return {"schema_version": 1, "type": "baseline_review_tasks", "incident_id": document["incident_id"],
            "host": document["host"], "worksheet_revision": document["revision"],
            "policy_digest": document["policy_digest"], "enabled": False, "changes_applied": False,
            "tasks": tasks, "notice": "复盘建议需另行审核；本文件不是可加载的策略，不会生成允许项或屏蔽告警。"}
