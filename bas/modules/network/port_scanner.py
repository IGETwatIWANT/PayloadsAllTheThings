"""
TCP Port Scanner module.
MITRE ATT&CK: T1046 - Network Service Discovery
"""
from __future__ import annotations
import asyncio, socket, uuid
from datetime import datetime
from typing import Any
from bas.core.scope import AuthorizationLevel, ScopeEnforcer
from bas.core.engine import EngineEvent
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus
from bas.core.executor import AttackRequest, AttackResponse

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017]

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

class PortScannerModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="port_scan", description="TCP port scanning and service detection",
            category="recon", mitre_technique_ids=["T1046"],
            mitre_technique_names=["Network Service Discovery"],
            auth_level_required=AuthorizationLevel.READ_ONLY, cwe_ids=["CWE-200"],
            tags=["recon", "network", "ports"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        ports = options.get("ports", COMMON_PORTS)
        return [str(p) for p in ports]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"port-{p}", target=target, path=f"/{p}") for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        return ModuleResult(module_name="port_scan", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=0, elapsed_ms=0)

    async def execute(self, targets: list[str], payloads: list[str] | None = None,
                      scope: ScopeEnforcer | None = None, options: dict[str, Any] | None = None) -> EngineEvent:
        options = options or {}
        ports = options.get("ports", COMMON_PORTS)
        timeout = options.get("scan_timeout", 2.0)
        all_open: list[dict[str, Any]] = []

        for target in targets:
            if scope: scope.validate_target(target)
            host = target.split("//")[-1].split("/")[0].split(":")[0]
            if scope and scope.is_dry_run:
                continue

            sem = asyncio.Semaphore(options.get("max_concurrent", 50))
            async def scan_port(port: int) -> dict[str, Any] | None:
                async with sem:
                    try:
                        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                        writer.close()
                        await writer.wait_closed()
                        service = SERVICE_BANNERS.get(port, "unknown")
                        return {"host": host, "port": port, "service": service, "state": "open"}
                    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                        return None

            results = await asyncio.gather(*[scan_port(p) for p in ports])
            open_ports = [r for r in results if r is not None]
            all_open.extend(open_ports)

        return EngineEvent(timestamp=datetime.now(), event_type="module_complete", module="port_scan",
            target=",".join(targets), severity="info" if not all_open else "medium",
            detail={"total_tests": len(ports) * len(targets), "open_ports": all_open,
                "vulnerabilities_found": 0, "results": [
                    {"target": p["host"], "status": "potentially_vulnerable",
                     "evidence": f"Port {p['port']} open ({p['service']})", "severity": "info",
                     "payload": str(p["port"]), "elapsed_ms": 0}
                    for p in all_open]})
