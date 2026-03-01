"""
BASzy Ai API Server.

FastAPI-based REST API powering the GUI dashboard.
Provides endpoints for scan management, findings, payloads, and AI operations.
Proprietary - All Rights Reserved.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field

# ─── Request/Response Models ────────────────────────────────────────


class ScanRequest(BaseModel):
    target: str
    modules: list[str] = Field(default_factory=lambda: [
        "discovery", "sqli", "xss", "command_injection", "ssti", "ssrf", "jwt", "auth_bypass",
        "xxe", "deserialization", "open_redirect", "cors", "crlf", "path_traversal",
        "prototype_pollution", "file_upload", "idor", "csrf", "cache_deception",
        "request_smuggling", "graphql", "websocket", "nosqli", "ldap", "xpath", "hpp",
        "port_scan", "dir_brute", "subdomain_enum", "credential_test",
    ])
    auth_level: str = "low_impact"
    authorized_by: str
    dry_run: bool = False
    max_rps: int = 10
    proxy: str = ""
    enable_zeroday: bool = False
    enable_evasion: bool = False
    ai_model: str = "llama3.2"
    attack_params: list[str] = Field(default_factory=lambda: ["id", "q", "search", "name", "input", "url"])
    attack_paths: list[str] = Field(default_factory=lambda: ["/"])


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    target: str
    progress: float
    modules_completed: list[str]
    modules_remaining: list[str]
    findings_count: int
    start_time: str
    elapsed_seconds: float


class FindingResponse(BaseModel):
    finding_id: str
    title: str
    severity: str
    module: str
    target: str
    description: str
    evidence: str
    payload: str = ""
    mitre_technique_id: str = ""
    remediation: str = ""
    timestamp: str = ""


class PayloadSearchRequest(BaseModel):
    query: str
    category: str = ""
    limit: int = 50


class ModuleInfo(BaseModel):
    name: str
    description: str
    category: str
    mitre_techniques: list[str]
    auth_level: str
    tags: list[str]


# ─── Application State ──────────────────────────────────────────────

class AppState:
    """Shared application state for the API server."""

    def __init__(self):
        self.scans: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, list[dict[str, Any]]] = {}
        self.payload_db: Any = None
        self.model_manager: Any = None
        self.ai_available: bool = False


state = AppState()


# ─── App Factory ─────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="BASzy Ai",
        description="AI-Driven Breach & Attack Simulation Platform",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Serve GUI
    gui_dir = Path(__file__).parent.parent / "gui"
    if (gui_dir / "static").exists():
        app.mount("/static", StaticFiles(directory=str(gui_dir / "static")), name="static")

    @app.on_event("startup")
    async def startup():
        from bas.payloads.loader import PayloadLoader
        from bas.ai.model_manager import ModelManager, ModelConfig

        # Load payloads
        repo_path = Path(__file__).parent.parent.parent
        loader = PayloadLoader(repo_path, ":memory:")
        state.payload_db = await loader.load_all()

        # Initialize AI
        try:
            state.model_manager = ModelManager(ModelConfig())
            await state.model_manager.initialize()
            state.ai_available = True
        except Exception:
            state.ai_available = False

    @app.on_event("shutdown")
    async def shutdown():
        if state.payload_db:
            await state.payload_db.close()

    # ─── Routes ──────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        template_path = gui_dir / "templates" / "dashboard.html"
        if template_path.exists():
            return HTMLResponse(template_path.read_text())
        return HTMLResponse("<h1>BASzy Ai</h1><p>Dashboard loading...</p>")

    @app.get("/api/status")
    async def api_status():
        return {
            "engine": "BASzy Ai",
            "version": "1.0.0",
            "ai_available": state.ai_available,
            "payload_db_loaded": state.payload_db is not None,
            "active_scans": len([s for s in state.scans.values() if s["status"] == "running"]),
            "total_scans": len(state.scans),
            "total_modules": 35,
        }

    @app.get("/api/modules", response_model=list[ModuleInfo])
    async def list_modules():
        # Original modules
        from bas.modules.injection.sqli import SQLInjectionModule
        from bas.modules.injection.xss import XSSModule
        from bas.modules.injection.command_injection import CommandInjectionModule
        from bas.modules.injection.ssti import SSTIModule
        from bas.modules.ssrf.ssrf import SSRFModule
        from bas.modules.auth.jwt import JWTModule
        from bas.modules.auth.auth_bypass import AuthBypassModule
        from bas.modules.recon.discovery import DiscoveryModule
        # Web modules
        from bas.modules.web.xxe import XXEModule
        from bas.modules.web.deserialization import DeserializationModule
        from bas.modules.web.open_redirect import OpenRedirectModule
        from bas.modules.web.cors import CORSModule
        from bas.modules.web.crlf import CRLFModule
        from bas.modules.web.path_traversal import PathTraversalModule
        from bas.modules.web.prototype_pollution import PrototypePollutionModule
        from bas.modules.web.file_upload import FileUploadModule
        from bas.modules.web.idor import IDORModule
        from bas.modules.web.csrf import CSRFModule
        from bas.modules.web.cache_deception import CacheDeceptionModule
        from bas.modules.web.request_smuggling import RequestSmugglingModule
        from bas.modules.web.graphql import GraphQLModule
        from bas.modules.web.websocket import WebSocketModule
        from bas.modules.web.nosqli import NoSQLiModule
        from bas.modules.web.ldap import LDAPiModule
        from bas.modules.web.xpath import XPathiModule
        from bas.modules.web.hpp import HPPModule
        # Network modules
        from bas.modules.network.port_scanner import PortScannerModule
        from bas.modules.network.directory_brute import DirectoryBruteModule
        from bas.modules.network.subdomain_enum import SubdomainEnumModule
        from bas.modules.network.credential_tester import CredentialTesterModule
        # Evasion modules
        from bas.modules.evasion.edr_evasion import EDREvasionModule
        from bas.modules.evasion.waf_bypass import WAFBypassModule
        from bas.modules.evasion.amsi_bypass import AMSIBypassModule
        from bas.modules.evasion.traffic_shaping import TrafficShapingModule

        module_classes = [
            DiscoveryModule, SQLInjectionModule, XSSModule,
            CommandInjectionModule, SSTIModule, SSRFModule,
            JWTModule, AuthBypassModule,
            XXEModule, DeserializationModule, OpenRedirectModule,
            CORSModule, CRLFModule, PathTraversalModule,
            PrototypePollutionModule, FileUploadModule, IDORModule,
            CSRFModule, CacheDeceptionModule, RequestSmugglingModule,
            GraphQLModule, WebSocketModule, NoSQLiModule,
            LDAPiModule, XPathiModule, HPPModule,
            PortScannerModule, DirectoryBruteModule,
            SubdomainEnumModule, CredentialTesterModule,
            EDREvasionModule, WAFBypassModule,
            AMSIBypassModule, TrafficShapingModule,
        ]
        result = []
        for cls in module_classes:
            m = cls().metadata
            result.append(ModuleInfo(
                name=m.name,
                description=m.description,
                category=m.category,
                mitre_techniques=m.mitre_technique_ids,
                auth_level=m.auth_level_required.value,
                tags=m.tags,
            ))
        return result

    @app.post("/api/scans", response_model=ScanStatus)
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        if not req.authorized_by:
            raise HTTPException(400, "authorized_by is required")

        scan_id = f"BASZY-{uuid.uuid4().hex[:8]}"
        scan_data = {
            "scan_id": scan_id,
            "status": "starting",
            "target": req.target,
            "modules": req.modules,
            "modules_completed": [],
            "findings": [],
            "progress": 0.0,
            "start_time": datetime.now().isoformat(),
            "config": req.model_dump(),
        }
        state.scans[scan_id] = scan_data
        state.findings[scan_id] = []

        background_tasks.add_task(_run_scan_background, scan_id, req)

        return ScanStatus(
            scan_id=scan_id,
            status="starting",
            target=req.target,
            progress=0.0,
            modules_completed=[],
            modules_remaining=req.modules,
            findings_count=0,
            start_time=scan_data["start_time"],
            elapsed_seconds=0.0,
        )

    @app.get("/api/scans")
    async def list_scans():
        return [
            {
                "scan_id": s["scan_id"],
                "status": s["status"],
                "target": s["target"],
                "progress": s["progress"],
                "findings_count": len(state.findings.get(s["scan_id"], [])),
                "start_time": s["start_time"],
            }
            for s in state.scans.values()
        ]

    @app.get("/api/scans/{scan_id}", response_model=ScanStatus)
    async def get_scan(scan_id: str):
        if scan_id not in state.scans:
            raise HTTPException(404, "Scan not found")
        s = state.scans[scan_id]
        start = datetime.fromisoformat(s["start_time"])
        elapsed = (datetime.now() - start).total_seconds()
        return ScanStatus(
            scan_id=s["scan_id"],
            status=s["status"],
            target=s["target"],
            progress=s["progress"],
            modules_completed=s["modules_completed"],
            modules_remaining=[m for m in s["modules"] if m not in s["modules_completed"]],
            findings_count=len(state.findings.get(scan_id, [])),
            start_time=s["start_time"],
            elapsed_seconds=elapsed,
        )

    @app.post("/api/scans/{scan_id}/stop")
    async def stop_scan(scan_id: str):
        if scan_id not in state.scans:
            raise HTTPException(404, "Scan not found")
        state.scans[scan_id]["status"] = "stopped"
        return {"message": "Scan stopped", "scan_id": scan_id}

    @app.get("/api/scans/{scan_id}/findings", response_model=list[FindingResponse])
    async def get_findings(scan_id: str):
        if scan_id not in state.findings:
            raise HTTPException(404, "Scan not found")
        return [FindingResponse(**f) for f in state.findings[scan_id]]

    @app.post("/api/payloads/search")
    async def search_payloads(req: PayloadSearchRequest):
        if not state.payload_db:
            raise HTTPException(503, "Payload database not loaded")
        results = await state.payload_db.search_payloads(req.query, limit=req.limit)
        return {"results": results, "count": len(results)}

    @app.get("/api/payloads/categories")
    async def payload_categories():
        if not state.payload_db:
            raise HTTPException(503, "Payload database not loaded")
        return await state.payload_db.get_categories()

    @app.get("/api/payloads/stats")
    async def payload_stats():
        if not state.payload_db:
            raise HTTPException(503, "Payload database not loaded")
        return await state.payload_db.get_stats()

    @app.get("/api/mitre/coverage")
    async def mitre_coverage():
        from bas.config.mitre_mapping import get_coverage_matrix, MITRE_TECHNIQUES, MODULE_TECHNIQUE_MAP
        all_modules = list(MODULE_TECHNIQUE_MAP.keys())
        coverage = get_coverage_matrix(all_modules)
        return {
            "coverage": coverage,
            "total_techniques": len(MITRE_TECHNIQUES),
            "techniques_covered": sum(len(v) for v in coverage.values()),
        }

    @app.get("/api/ai/status")
    async def ai_status():
        if not state.ai_available or not state.model_manager:
            return {"available": False, "models": []}
        try:
            models = await state.model_manager.list_available_models()
            return {"available": True, "models": models}
        except Exception:
            return {"available": False, "models": []}

    return app


async def _run_scan_background(scan_id: str, req: ScanRequest):
    """Execute a scan in the background."""
    from bas.config.settings import BASSettings
    from bas.core.scope import ScopeConfig, AuthorizationLevel
    from bas.core.engine import BASEngine
    from bas.core.reporter import Finding, Severity
    from bas.ai.planner import AttackPlanner
    from bas.ai.analyzer import ResultAnalyzer
    from bas.utils.logging import AuditLogger

    scan = state.scans[scan_id]
    scan["status"] = "running"

    try:
        settings = BASSettings(
            engagement_id=scan_id,
            targets=[req.target],
            auth_level=req.auth_level,
            authorized_by=req.authorized_by,
            dry_run=req.dry_run,
            max_rps=req.max_rps,
            proxy=req.proxy,
            modules=req.modules,
            ai_model=req.ai_model,
            enable_zeroday=req.enable_zeroday,
            attack_params=req.attack_params,
            attack_paths=req.attack_paths,
        )

        scope_config = settings.to_scope_config()
        audit = AuditLogger(engagement_id=scan_id, console_output=False)

        planner = AttackPlanner(state.model_manager) if state.ai_available else None
        analyzer = ResultAnalyzer(state.model_manager) if state.ai_available else None

        engine = BASEngine(scope_config=scope_config, ai_planner=planner, audit_logger=audit)

        # Import and register all modules
        from bas.__main__ import _register_modules
        _register_modules(engine, req.modules, state.payload_db, analyzer,
                         state.model_manager, req.enable_zeroday, req.enable_evasion)

        # Plan and execute
        plan = await engine.plan_attack(objectives=["Full vulnerability assessment"], targets=[req.target])
        engine.approve_plan(plan.plan_id)

        total_phases = len(plan.phases)
        for i, phase in enumerate(plan.phases):
            if scan["status"] == "stopped":
                break

            phase.status = "running"
            scan["progress"] = (i / total_phases) * 100

            module = engine._modules.get(phase.module_name)
            if module:
                try:
                    event = await module.execute(
                        targets=phase.targets,
                        scope=engine.scope,
                        options={
                            "params": req.attack_params,
                            "path": req.attack_paths[0] if req.attack_paths else "/",
                            "max_payloads": 50,
                            "max_rps": req.max_rps,
                        },
                    )

                    for result in event.detail.get("results", []):
                        finding = {
                            "finding_id": f"F-{uuid.uuid4().hex[:6]}",
                            "title": f"{event.module}: {result.get('evidence', '')[:80]}",
                            "severity": result.get("severity", "info"),
                            "module": event.module,
                            "target": result.get("target", req.target),
                            "description": result.get("evidence", ""),
                            "evidence": result.get("evidence", ""),
                            "payload": result.get("payload", ""),
                            "mitre_technique_id": "",
                            "remediation": "",
                            "timestamp": datetime.now().isoformat(),
                        }
                        state.findings[scan_id].append(finding)

                except Exception as exc:
                    audit.log("module_error", {"module": phase.module_name, "error": str(exc)}, level="error")

            scan["modules_completed"].append(phase.module_name)

        scan["progress"] = 100.0
        scan["status"] = "complete"

    except Exception as exc:
        scan["status"] = "error"
        scan["error"] = str(exc)
