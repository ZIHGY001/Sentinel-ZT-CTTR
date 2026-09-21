"""Policy validation and per-request zero-trust decisions (PDP, not an IdP)."""
import ipaddress
from .common import digest, strict_integer, ip_literal, iso, timestamp


def validate(config):
    if not isinstance(config, dict) or type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise ValueError("policy schema_version must be 1")
    for field, minimum, maximum, default in [
        ("min_intel_confidence", 0, 100, 60), ("response_threshold", 70, 99, 75),
        ("analysis_window_seconds", 60, 604800, 86400),
        ("max_evidence_age_seconds", 30, 3600, 900), ("block_ttl_seconds", 30, 3600, 300),
        ("plan_ttl_seconds", 30, 900, 600), ("posture_max_age_seconds", 30, 3600, 300),
    ]:
        strict_integer(config.get(field, default), minimum, maximum)
    for field in ("protected_networks", "operators", "suppressions"):
        if not isinstance(config.get(field, []), list) or len(config.get(field, [])) > 10000:
            raise ValueError(f"{field} must be an array of at most 10000 items")
    for network in config.get("protected_networks", []):
        if not isinstance(network, str):
            raise ValueError("protected network must be a CIDR string")
        ipaddress.ip_network(network)
    if not isinstance(config.get("assets"), dict) or len(config["assets"]) > 10000:
        raise ValueError("policy assets must be an object")
    all_ips = set()
    for name, asset in config["assets"].items():
        if not isinstance(name, str) or not name.strip() or not isinstance(asset, dict):
            raise ValueError("invalid asset registry")
        if type(asset.get("response_enabled", False)) is not bool:
            raise ValueError("asset response_enabled must be boolean")
        if asset.get("criticality", "normal") not in ("normal", "critical"):
            raise ValueError("asset criticality must be normal or critical")
        if not isinstance(asset.get("ips", []), list):
            raise ValueError("asset ips must be an array")
        permissions = asset.get("permissions", {})
        if not isinstance(permissions, dict):
            raise ValueError("permissions must map subjects to arrays of exact actions")
        for subject, actions in permissions.items():
            if (not isinstance(subject, str) or not subject.strip() or not isinstance(actions, list)
                    or any(not isinstance(x, str) or not x.strip() for x in actions)):
                raise ValueError("permissions must map subjects to arrays of exact actions")
        for value in asset.get("ips", []):
            ip = str(ip_literal(value))
            if ip != value:
                raise ValueError("asset IP must use canonical address text")
            if ip in all_ips:
                raise ValueError("an IP may belong to only one registered asset")
            all_ips.add(ip)
    if not isinstance(config.get("operators", []), list) or any(
            not isinstance(x, str) or not x for x in config.get("operators", [])):
        raise ValueError("operators must be an array of nonempty names")
    for s in config.get("suppressions", []):
        if not isinstance(s, dict):
            raise ValueError("suppression must be an object")
        if not all(s.get(x) for x in ("rule_id", "host", "reason", "expires_at")):
            raise ValueError("suppression needs rule_id, host, reason and expires_at")
        timestamp(s["expires_at"])
    return config


def access_decision(request, config, now, risk=0):
    """Inputs MUST be attested by an upstream IdP/EDR/PEP, not client-supplied claims."""
    validate(config)
    strict_integer(risk, 0, 99)
    if not isinstance(request, dict) or any(not isinstance(request.get(k), str) or not request[k].strip()
                                           for k in ("subject", "resource", "action")):
        raise ValueError("access request requires nonempty subject, resource and action strings")
    reasons = []
    asset = config["assets"].get(request.get("resource"))
    if asset is None:
        reasons.append("unknown_resource")
    if request.get("identity_verified") is not True:
        reasons.append("identity_unverified")
    if request.get("device_managed") is not True or request.get("device_compliant") is not True:
        reasons.append("device_not_verified_compliant")
    if request.get("token_valid") is not True:
        reasons.append("invalid_token")
    try:
        age = (now - timestamp(request["posture_checked_at"])).total_seconds()
        if not 0 <= age <= config.get("posture_max_age_seconds", 300):
            reasons.append("stale_device_posture")
    except (ValueError, KeyError, TypeError):
        reasons.append("missing_device_posture_time")
    if asset and request.get("action") not in asset.get("permissions", {}).get(request.get("subject"), []):
        reasons.append("no_explicit_subject_permission")
    if risk >= 70:
        reasons.append("active_high_risk_incident")
    if reasons:
        decision, ttl = "deny", 0
    elif request.get("mfa_verified") is not True or risk >= 40:
        decision, ttl = "step_up", 0
        reasons.append("fresh_step_up_and_risk_review_required")
    else:
        decision, ttl = "allow", 60
        reasons.append("explicit_identity_device_resource_checks_passed")
    return {"decision": decision, "reasons": reasons, "lease_seconds": ttl,
            "evaluated_at": iso(now), "policy_digest": digest(config),
            "subject": request.get("subject"), "resource": request.get("resource"),
            "action": request.get("action"), "risk": risk,
            "integration": "PEP must enforce decision and re-evaluate at lease expiry"}
