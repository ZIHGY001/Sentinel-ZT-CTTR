"""Public CLI. Analysis is unprivileged; mutations require explicit --live."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .common import digest, load_json, now_utc, timestamp, write_json, read_bytes
from . import assets, collect, demo, engine, events, intel, knowledge, policy, report, response


def run_analysis(inputs, intel_paths, config, destination, at, fmt="canonical", host=None, asset_snapshot=None, kb=None):
    policy.validate(config)
    ev, manifest, ingest = events.load_events(inputs, fmt, host)
    indicators, warnings = [], []
    for path in intel_paths:
        loaded, notes = intel.load_intel(path)
        indicators.extend(loaded)
        warnings.extend(notes)
    analysis = engine.analyze(ev, indicators, at, config)
    analysis["input_manifest"] = manifest
    analysis["warnings"] = warnings
    analysis["statistics"].update(ingest)
    if asset_snapshot:
        assets.enrich(analysis, asset_snapshot, config, at)
    if kb:
        knowledge.enrich(analysis, kb)
    plan = engine.make_plan(analysis, config, at)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    write_json(destination / "analysis.json", analysis)
    write_json(destination / "plan.json", plan)
    report.render(analysis, plan, destination / "report.html")
    return {"events": len(ev), "findings": len(analysis["findings"]),
            "incidents": len(analysis["incidents"]), "report": str(destination / "report.html"),
            "plan": str(destination / "plan.json"), "changes_applied": False}


def parser():
    p = argparse.ArgumentParser(prog="sentinel-zt-cttr", description="Threat intelligence + behavior evidence + bounded zero-trust response")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="generate and analyze synthetic training events")
    d.add_argument("--out", default="output/demo")
    a = sub.add_parser("analyze", help="offline log analysis; never executes response")
    a.add_argument("--events", nargs="+", required=True)
    a.add_argument("--intel", nargs="*", default=[])
    a.add_argument("--policy", required=True)
    a.add_argument("--format", choices=["canonical", "sysmon", "suricata", "nginx"], default="canonical")
    a.add_argument("--host", help="required for nginx/Suricata; must be the monitored endpoint")
    a.add_argument("--at", help="ISO timestamp for historical replay; never used by apply/approve")
    a.add_argument("--out", required=True)
    a.add_argument("--assets", help="normalized Quake asset snapshot")
    a.add_argument("--knowledge", help="article title/link index")
    i = sub.add_parser("intel-import", help="normalize JSON, CSV or STIX 2.1 equality indicators")
    i.add_argument("--input", required=True)
    i.add_argument("--format", choices=["auto", "json", "csv", "stix"], default="auto")
    i.add_argument("--out", required=True)
    c = sub.add_parser("collect", help="read-only Linux process snapshot with hashes")
    c.add_argument("--out", required=True)
    c.add_argument("--host")
    k = sub.add_parser("keygen", help="create a new local response signing key")
    k.add_argument("--out", required=True)
    ap = sub.add_parser("approve", help="sign one reviewed action for up to five minutes")
    for name in ("plan", "action", "policy", "operator", "key", "out"):
        ap.add_argument("--" + name, required=True)
    ap.add_argument("--lifetime", type=int, default=300)
    ex = sub.add_parser("apply", help="preview or explicitly execute a signed local peer block")
    for name in ("plan", "approval", "policy", "key", "state", "local-asset"):
        ex.add_argument("--" + name, required=True)
    ex.add_argument("--live", action="store_true", help="change local nftables after all policy checks")
    rb = sub.add_parser("rollback", help="remove only a journaled action's owned nftables table")
    for name in ("action", "key", "state", "local-asset"):
        rb.add_argument("--" + name, required=True)
    rb.add_argument("--live", action="store_true")
    au = sub.add_parser("audit", help="verify local keyed audit chain")
    au.add_argument("--key", required=True)
    au.add_argument("--state", required=True)
    ac = sub.add_parser("access", help="evaluate an attested request using fresh incident context")
    for name in ("request", "policy", "analysis"):
        ac.add_argument("--" + name, required=True)
    ac.add_argument("--out")
    sub.add_parser("rules", help="list built-in behavior rules")
    q = sub.add_parser("quake-search", help="query Quake passively within declared asset scope")
    q.add_argument("--query", default="service:http")
    q.add_argument("--scope", required=True)
    q.add_argument("--policy")
    q.add_argument("--limit", type=int, default=100)
    q.add_argument("--page-size", type=int, default=50)
    q.add_argument("--out", required=True)
    qi = sub.add_parser("quake-import", help="normalize an offline Quake service JSON response")
    for name in ("input", "scope", "out"):
        qi.add_argument("--"+name, required=True)
    qi.add_argument("--policy")
    diff = sub.add_parser("asset-diff", help="compare two passive discovery snapshots")
    for name in ("before", "after", "out"):
        diff.add_argument("--"+name, required=True)
    ks = sub.add_parser("knowledge-sync", help="fetch only the public wechat README title/link index")
    ks.add_argument("--revision", default="main")
    ks.add_argument("--out", required=True)
    ki = sub.add_parser("knowledge-index", help="index a local copy of wechat README")
    ki.add_argument("--input", required=True)
    ki.add_argument("--revision", default="main")
    ki.add_argument("--out", required=True)
    kq = sub.add_parser("knowledge-search", help="find article references without executing content")
    kq.add_argument("--index", required=True)
    kq.add_argument("--query", required=True)
    kq.add_argument("--limit", type=int, default=10)
    return p


def dispatch(args):
    now = now_utc()
    cmd = args.command
    if cmd == "demo":
        base = Path(args.out)
        inputs = base / "inputs"
        demo.write_fixtures(inputs, now)
        return run_analysis([inputs / "events.jsonl"], [inputs / "intel.json"],
                            load_json(inputs / "policy.json"), base, now)
    if cmd == "analyze":
        return run_analysis(args.events, args.intel, load_json(args.policy), args.out,
                            timestamp(args.at) if args.at else now, args.format, args.host,
                            load_json(args.assets) if args.assets else None,
                            load_json(args.knowledge) if args.knowledge else None)
    if cmd in {"quake-search", "quake-import"}:
        cfg = policy.validate(load_json(args.policy)) if args.policy else None
        scope = load_json(args.scope)
        if cmd == "quake-search":
            result = assets.search(args.query, scope, now, cfg, args.limit, args.page_size)
        else:
            raw = load_json(args.input)
            records = raw if isinstance(raw, list) else raw.get("data", [])
            result = assets.normalize_assets(records, scope, now, cfg)
        write_json(args.out, result)
        return {"assets": len(result["assets"]), "out_of_scope": result["out_of_scope"], "warnings": result["warnings"], "out": args.out}
    if cmd == "asset-diff":
        result = assets.asset_diff(load_json(args.before), load_json(args.after))
        write_json(args.out, result)
        return result
    if cmd in {"knowledge-sync", "knowledge-index"}:
        result = knowledge.sync(args.revision, now) if cmd == "knowledge-sync" else knowledge.index_readme(read_bytes(args.input), args.revision, now)
        write_json(args.out, result)
        return {"indexed": len(result["entries"]), "out": args.out}
    if cmd == "knowledge-search":
        return knowledge.search(load_json(args.index), args.query, args.limit)
    if cmd == "intel-import":
        loaded, warnings = intel.load_intel(args.input, args.format)
        write_json(args.out, {"indicators": [asdict(x) for x in loaded]})
        return {"imported": len(loaded), "warnings": warnings, "out": args.out}
    if cmd == "collect":
        return collect.collect(args.out, now, args.host)
    if cmd == "keygen":
        response.new_key(args.out)
        return {"key_created": args.out, "note": "Keep private; never commit this file."}
    if cmd == "approve":
        token = response.approve(load_json(args.plan), args.action, load_json(args.policy),
                                 args.operator, response.key_bytes(args.key), now, args.lifetime)
        write_json(args.out, token)
        return {"approval": args.out, "expires_at": token["payload"]["expires_at"]}
    if cmd == "apply":
        return response.apply(load_json(args.plan), load_json(args.approval), load_json(args.policy),
                              response.key_bytes(args.key), now, args.state, args.local_asset, args.live)
    if cmd == "rollback":
        return response.rollback(args.action, response.key_bytes(args.key), args.state, now,
                                 args.local_asset, args.live)
    if cmd == "audit":
        journal = response.Journal(args.state, response.key_bytes(args.key))
        try:
            return journal.verify()
        finally:
            journal.close()
    if cmd == "access":
        req, cfg, analysis = load_json(args.request), load_json(args.policy), load_json(args.analysis)
        policy.validate(cfg)
        age = (now - timestamp(analysis["generated_at"])).total_seconds()
        if analysis.get("policy_digest") != digest(cfg) or not 0 <= age <= cfg.get("max_evidence_age_seconds", 900):
            raise ValueError("fresh analysis under current policy is required")
        resource = req.get("resource")
        if not any(e["host"] == resource for e in analysis.get("events", [])):
            raise ValueError("no telemetry for this resource; access cannot be granted")
        risk = max((x["risk"] for x in analysis["incidents"] if x["host"] == resource), default=0)
        result = policy.access_decision(req, cfg, now, risk)
        if args.out:
            write_json(args.out, result)
        return result
    if cmd == "rules":
        from .rules import get_rules
        return [{k: r[k] for k in ("id", "title", "score", "stage", "status")} for r in get_rules()]
    raise ValueError("unknown command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = dispatch(args)
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
