"""Single-process local FastAPI console. No privileged response HTTP endpoint."""
from __future__ import annotations

import hmac
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
import anyio

from . import __version__, assets, demo, deployment, engine, events, intel, knowledge, policy, report, yunmai
from .common import canonical, load_json, now_utc, private_directory, private_file, strict_json, timestamp, write_json


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
    root = private_directory(data_dir or os.environ.get("SENTINEL_DATA_DIR", ".sentinel-data"))
    private_file(root / "cases.sqlite3")
    app = FastAPI(title="Sentinel-ZT-CTTR", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    deploy = deployment.settings(testing=testing)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=deploy["hosts"])
    origins = deploy["origins"]

    @contextmanager
    def db():
        con = sqlite3.connect(root / "cases.sqlite3")
        try:
            with con:
                con.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, at TEXT, analysis TEXT, plan TEXT)")
                yield con
        finally:
            con.close()

    post_slots = threading.BoundedSemaphore(2)
    agent_slot = threading.BoundedSemaphore(1)

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        mutation = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        if mutation and not request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "method not allowed"}, status_code=405)
        public_health = request.url.path == "/api/health" and request.method in {"GET", "HEAD"}
        if request.url.path.startswith("/api/") and not public_health:
            authorization = request.headers.get("authorization", "")
            if not hmac.compare_digest(authorization.encode(), ("Bearer " + token).encode()):
                return JSONResponse({"detail": "API token required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and origin not in origins:
                return JSONResponse({"detail": "origin not allowed"}, status_code=403)
        if request.method in {"POST", "PUT", "PATCH"}:
            if not post_slots.acquire(blocking=False):
                return JSONResponse({"detail": "workbench busy; retry later"}, status_code=429,
                                    headers={"Retry-After": "2"})
            try:
                chunks, total = [], 0
                with anyio.fail_after(15):
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > 8 * 1024 * 1024:
                            return JSONResponse({"detail": "request exceeds 8 MiB"}, status_code=413)
                        chunks.append(chunk)
                request._body = b"".join(chunks)
                if request._body:
                    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                        return JSONResponse({"detail": "application/json required"}, status_code=415)
                    strict_json(request._body)
                result = await call_next(request)
            except TimeoutError:
                return JSONResponse({"detail": "request body timeout"}, status_code=408)
            except ValueError:
                return JSONResponse({"detail": "invalid JSON body"}, status_code=400)
            finally:
                post_slots.release()
        else:
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
        encoded_analysis, encoded_plan = canonical(analysis), canonical(plan)
        if len(encoded_analysis) + len(encoded_plan) > 16 * 1024 * 1024:
            raise ValueError("case exceeds 16 MiB; split the investigation")
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            if con.execute("SELECT count(*) FROM cases").fetchone()[0] >= 500:
                raise HTTPException(409, "500-case workspace limit reached; archive this workspace before continuing")
            con.execute("INSERT INTO cases VALUES (?,?,?,?)", (ident, analysis["generated_at"],
                        encoded_analysis.decode(), encoded_plan.decode()))
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

    def analyze_rows(raw_rows, indicators, cfg, manifest=None, stats=None):
        now = now_utc()
        policy.validate(cfg)
        # Canonical input also receives deduplication, even in the demo/API path.
        ev = list({e["id"]: e for e in raw_rows}.values())
        ev.sort(key=lambda e: (timestamp(e["timestamp"]), e["id"]))
        a = engine.analyze(ev, indicators, now, cfg)
        if manifest is not None:
            a["input_manifest"] = manifest
            a["statistics"].update(stats or {})
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
        return {"deployment_mode": deploy["mode"],
                "quake_configured": bool(os.environ.get("QUAKE_API_KEY")),
                "scope_configured": bool(os.environ.get("SENTINEL_SCOPE")),
                "agent_enabled": os.environ.get("SENTINEL_PI_ENABLED") == "1",
                "knowledge_indexed": (root / "knowledge.json").exists(),
                "live_response": "CLI only"}

    @app.get("/api/integrations/yunmai")
    def yunmai_status():
        mapping_path = os.environ.get("SENTINEL_YUNMAI_MAPPING")
        mappings = yunmai.validate(load_json(mapping_path)) if mapping_path else None
        return {"deployment_mode": deploy["mode"], "public_origin": deploy["public_origin"],
                "mapping_configured": mappings is not None,
                "mapping_count": len(mappings["bindings"]) if mappings else 0,
                "integration_mode": "manual_console_handoff", "cloud_connection_verified": False,
                "automatic_response": False, "application_authentication": "local_bearer_token"}

    @app.post("/api/cases/{ident}/yunmai-handoff")
    def yunmai_handoff(ident: str):
        mapping_path = os.environ.get("SENTINEL_YUNMAI_MAPPING")
        if not mapping_path:
            raise HTTPException(409, "服务端尚未配置 SENTINEL_YUNMAI_MAPPING，请先核验用户和应用映射")
        item = get_case(ident)
        draft = yunmai.handoff(item["analysis"], load_json(mapping_path), now_utc())
        write_json(root / "handoffs" / (draft["id"] + ".json"), draft)
        return draft

    @app.get("/api/cases")
    def cases():
        with db() as con:
            rows = con.execute("SELECT id,at,analysis FROM cases ORDER BY at DESC LIMIT 100")
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
        cfg = payload.policy_config if payload.policy_config is not None else {
            "schema_version": 1, "assets": {}, "operators": []}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "uploaded-events.jsonl"
            path.write_text(payload.events_text, encoding="utf-8")
            ev, manifest, stats = events.load_events([path], payload.format, payload.host)
        return analyze_rows(ev, [intel.Indicator.parse(x) for x in payload.indicators], cfg, manifest, stats)

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
    def knowledge_search(q: str = Query(min_length=1, max_length=512)):
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
        bridge_input = json.dumps({"question": payload.question,
                                   "context": agent_context(item["analysis"], item["plan"])}, ensure_ascii=False)
        if len(bridge_input.encode("utf-8")) > 512000:
            raise HTTPException(413, "Pi context exceeds 512000 bytes; split the investigation")
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
        if not agent_slot.acquire(blocking=False):
            raise HTTPException(429, "Pi Agent is busy; retry later")
        try:
            result = subprocess.run(["node", str(bridge)], input=bridge_input,
                                    text=True, capture_output=True, timeout=90, check=False, env=child_env)
        except (OSError, subprocess.TimeoutExpired):
            raise HTTPException(503, "Pi Agent 启动失败或超时，请检查本地 Node 和模型配置") from None
        finally:
            agent_slot.release()
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
