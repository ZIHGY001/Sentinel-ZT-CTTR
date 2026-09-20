"""Single-process local FastAPI console. No privileged response HTTP endpoint."""
from __future__ import annotations

import hmac
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field

from . import __version__, assets, demo, engine, events, intel, knowledge, policy, report
from .common import atomic_write, canonical, digest, iso, load_json, now_utc, write_json


class AnalysisInput(BaseModel):
    events_text: str = Field(min_length=1, max_length=4_000_000)
    indicators: list[dict] = Field(default_factory=list, max_length=10000)
    policy_config: dict | None = None
    format: Literal["canonical", "sysmon", "suricata", "nginx"] = "canonical"
    host: str | None = None


class QuakeInput(BaseModel):
    query: str = Field(default="service:http", min_length=1, max_length=2048)
    limit: int = Field(default=50, ge=1, le=1000)


class QuakeImport(BaseModel):
    records: list[dict] = Field(max_length=10000)
    scope: dict


class KnowledgeInput(BaseModel):
    readme: str = Field(min_length=1, max_length=4_000_000)
    revision: str = Field(default="main", max_length=100)


class AgentInput(BaseModel):
    case_id: str
    question: str = Field(min_length=1, max_length=3000)
    consent_to_model: bool = False


def agent_context(analysis, plan):
    """Only allowlisted summary fields leave the backend; raw logs/IPs/users do not."""
    aliases = {c["host"]: f"asset-{i+1}" for i, c in enumerate(analysis["incidents"])}
    return {
        "incidents": [{"id": c["id"], "asset": aliases[c["host"]], "risk": c["risk"],
                       "rule_ids": c["rule_ids"], "stages": c["stages"], "verdict": c["verdict"]}
                      for c in analysis["incidents"]],
        "findings": [{"id": f["id"], "rule_id": f["rule_id"], "title": f["title"],
                      "rationale": f["rationale"], "evidence_ids": f["evidence_ids"],
                      "false_positives": f["false_positives"]} for f in analysis["findings"]][:200],
        "actions": [{"id": a["id"], "type": a["type"], "asset": aliases.get(a["host"], "unknown"),
                     "executable": a["executable"], "gates": a.get("gates", []),
                     "steps": a.get("steps", []), "ttl_seconds": a.get("ttl_seconds")}
                    for a in plan["actions"]],
        "limitations": analysis["limitations"],
    }


def create_app(data_dir=None, token=None, testing=False):
    token = token or os.environ.get("SENTINEL_API_TOKEN", "")
    if len(token) < 32:
        raise ValueError("set SENTINEL_API_TOKEN to a random secret of at least 32 characters")
    root = Path(data_dir or os.environ.get("SENTINEL_DATA_DIR", ".sentinel-data")).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    app = FastAPI(title="Sentinel-ZT-CTTR", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    allowed_hosts = ["127.0.0.1", "localhost", "[::1]"] + (["testserver"] if testing else [])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    origins = {"http://127.0.0.1:8000", "http://localhost:8000"}
    origins.update(x for x in os.environ.get("SENTINEL_ALLOWED_ORIGINS", "").split(",") if x)

    def db():
        con = sqlite3.connect(root / "cases.sqlite3")
        con.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, at TEXT, analysis TEXT, plan TEXT)")
        return con

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.url.path != "/api/health":
            authorization = request.headers.get("authorization", "")
            if not hmac.compare_digest(authorization, "Bearer " + token):
                return JSONResponse({"detail": "API token required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and origin not in origins:
                return JSONResponse({"detail": "origin not allowed"}, status_code=403)
        if request.method in {"POST", "PUT", "PATCH"}:
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > 8 * 1024 * 1024:
                    return JSONResponse({"detail": "request exceeds 8 MiB"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        result = await call_next(request)
        result.headers["Cache-Control"] = "no-store"
        result.headers["X-Content-Type-Options"] = "nosniff"
        result.headers["Referrer-Policy"] = "no-referrer"
        result.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return result

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    def save_case(analysis, plan):
        ident = str(uuid.uuid4())
        with db() as con:
            con.execute("INSERT INTO cases VALUES (?,?,?,?)", (ident, analysis["generated_at"],
                        canonical(analysis).decode(), canonical(plan).decode()))
        return {"id": ident, "analysis": analysis, "plan": plan}

    def get_case(ident):
        try:
            uuid.UUID(ident)
        except ValueError:
            raise HTTPException(404, "case not found")
        with db() as con:
            row = con.execute("SELECT analysis,plan FROM cases WHERE id=?", (ident,)).fetchone()
        if not row:
            raise HTTPException(404, "case not found")
        return {"id": ident, "analysis": json.loads(row[0]), "plan": json.loads(row[1])}

    def analyze_rows(raw_rows, indicators, cfg):
        now = now_utc()
        policy.validate(cfg)
        # Canonical input also receives deduplication, even in the demo/API path.
        ev = list({e["id"]: e for e in raw_rows}.values())
        ev.sort(key=lambda e: (e["timestamp"], e["id"]))
        a = engine.analyze(ev, indicators, now, cfg)
        if (root / "assets.json").exists():
            assets.enrich(a, load_json(root / "assets.json"), cfg, now)
        if (root / "knowledge.json").exists():
            knowledge.enrich(a, load_json(root / "knowledge.json"))
        return save_case(a, engine.make_plan(a, cfg, now))

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/status")
    def status():
        return {"quake_configured": bool(os.environ.get("QUAKE_API_KEY")),
                "scope_configured": bool(os.environ.get("SENTINEL_SCOPE")),
                "agent_enabled": os.environ.get("SENTINEL_PI_ENABLED") == "1",
                "knowledge_indexed": (root / "knowledge.json").exists(),
                "live_response": "CLI only"}

    @app.get("/api/cases")
    def cases():
        with db() as con:
            rows = con.execute("SELECT id,at,analysis FROM cases ORDER BY at DESC LIMIT 100").fetchall()
        return [{"id": x[0], "created_at": x[1], "incidents": len(json.loads(x[2])["incidents"])} for x in rows]

    @app.get("/api/cases/{ident}")
    def case(ident: str):
        return get_case(ident)

    @app.post("/api/demo")
    def run_demo():
        now = now_utc()
        rows, ti, cfg, _ = demo.fixtures(now)
        ev = [events.canonical_event(x, "synthetic-demo", i+1) for i, x in enumerate(rows)]
        return analyze_rows(ev, [intel.Indicator.parse(x) for x in ti], cfg)

    @app.post("/api/analyze")
    def analyze_input(payload: AnalysisInput):
        cfg = payload.policy_config or demo.fixtures(now_utc())[2]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "uploaded-events.jsonl"
            path.write_text(payload.events_text, encoding="utf-8")
            ev, manifest, stats = events.load_events([path], payload.format, payload.host)
        result = analyze_rows(ev, [intel.Indicator.parse(x) for x in payload.indicators], cfg)
        # Store provenance in both returned record and persisted analysis, then rebind plan digest.
        result["analysis"]["input_manifest"] = manifest
        result["analysis"]["statistics"].update(stats)
        result["plan"] = engine.make_plan(result["analysis"], cfg, now_utc())
        with db() as con:
            con.execute("UPDATE cases SET analysis=?,plan=? WHERE id=?", (canonical(result["analysis"]).decode(),
                        canonical(result["plan"]).decode(), result["id"]))
        return result

    @app.get("/api/cases/{ident}/report")
    def download_report(ident: str):
        item = get_case(ident)
        target = root / (ident + ".html")
        report.render(item["analysis"], item["plan"], target)
        return FileResponse(target, filename="sentinel-zt-cttr-report.html", media_type="text/html")

    @app.get("/api/assets")
    def asset_list():
        return load_json(root / "assets.json") if (root / "assets.json").exists() else {"assets": []}

    @app.post("/api/assets/quake")
    def quake_live(payload: QuakeInput):
        scope_path = os.environ.get("SENTINEL_SCOPE")
        if not scope_path or not os.environ.get("QUAKE_API_KEY"):
            raise HTTPException(409, "服务端尚未配置 QUAKE_API_KEY 与 SENTINEL_SCOPE")
        snapshot = assets.search(payload.query, load_json(scope_path), now_utc(), limit=payload.limit)
        write_json(root / "assets.json", snapshot)
        return snapshot

    @app.post("/api/assets/import")
    def quake_offline(payload: QuakeImport):
        snapshot = assets.normalize_assets(payload.records, payload.scope, now_utc())
        write_json(root / "assets.json", snapshot)
        return snapshot

    @app.post("/api/knowledge/index")
    def knowledge_index(payload: KnowledgeInput):
        index = knowledge.index_readme(payload.readme.encode(), payload.revision, now_utc())
        write_json(root / "knowledge.json", index)
        return {"indexed": len(index["entries"])}

    @app.get("/api/knowledge/search")
    def knowledge_search(q: str):
        if not (root / "knowledge.json").exists():
            return {"results": [], "configured": False}
        return {"results": knowledge.search(load_json(root / "knowledge.json"), q), "configured": True}

    @app.post("/api/agent")
    def agent(payload: AgentInput):
        if not payload.consent_to_model:
            raise HTTPException(400, "请确认将问题与脱敏事件摘要发送到已配置的模型服务")
        if os.environ.get("SENTINEL_PI_ENABLED") != "1":
            raise HTTPException(409, "Pi Agent 未启用，请配置模型凭证并设置 SENTINEL_PI_ENABLED=1")
        item = get_case(payload.case_id)
        bridge = Path(__file__).resolve().parent.parent / "agent" / "bridge.mjs"
        # The optional model runtime does not inherit web, Quake or response secrets.
        allowed_env = {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR",
                       "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
                       "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                       "PI_PROVIDER", "PI_MODEL"}
        provider = os.environ.get("PI_PROVIDER", "anthropic")
        model_key = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}.get(provider)
        if model_key:
            allowed_env.add(model_key)
        child_env = {key: value for key, value in os.environ.items() if key in allowed_env}
        try:
            result = subprocess.run(["node", str(bridge)], input=json.dumps({"question": payload.question,
                                    "context": agent_context(item["analysis"], item["plan"])}, ensure_ascii=False),
                                    text=True, capture_output=True, timeout=90, check=False, env=child_env)
        except (OSError, subprocess.TimeoutExpired):
            raise HTTPException(503, "Pi Agent 启动失败或超时，请检查本地 Node 和模型配置") from None
        if result.returncode or len(result.stdout) > 1_000_000:
            raise HTTPException(503, "Pi Agent 调用失败，请检查模型与凭证配置；未执行处置")
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise HTTPException(503, "Pi Agent 响应格式无效") from None

    dist = Path(__file__).resolve().parent.parent / "web" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="console")
    return app
