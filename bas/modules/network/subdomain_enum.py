"""
Subdomain Enumeration module.
MITRE ATT&CK: T1595.002 - Vulnerability Scanning
"""
from __future__ import annotations
import asyncio, socket, uuid
from datetime import datetime
from typing import Any
from bas.core.scope import AuthorizationLevel, ScopeEnforcer
from bas.core.engine import EngineEvent
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus
from bas.core.executor import AttackRequest, AttackResponse

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "app", "portal", "secure", "login", "vpn", "remote", "git", "gitlab",
    "jenkins", "ci", "cd", "build", "deploy", "monitor", "grafana", "kibana",
    "elastic", "redis", "db", "database", "mysql", "postgres", "mongo",
    "internal", "intranet", "corp", "exchange", "owa", "autodiscover",
    "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap", "webmail",
    "cloud", "cdn", "static", "assets", "media", "img", "images",
    "support", "help", "docs", "wiki", "jira", "confluence",
    "sso", "auth", "oauth", "identity", "iam",
]

class SubdomainEnumModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="subdomain_enum", description="DNS subdomain enumeration",
            category="recon", mitre_technique_ids=["T1595"],
            mitre_technique_names=["Active Scanning"],
            auth_level_required=AuthorizationLevel.READ_ONLY, cwe_ids=["CWE-200"],
            tags=["recon", "dns", "subdomain", "enumeration"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        extra = options.get("extra_subdomains", [])
        return COMMON_SUBDOMAINS + extra

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"sub-{p}", target=target, path=f"/{p}") for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        return ModuleResult(module_name="subdomain_enum", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=0, elapsed_ms=0)

    async def execute(self, targets: list[str], payloads: list[str] | None = None,
                      scope: ScopeEnforcer | None = None, options: dict[str, Any] | None = None) -> EngineEvent:
        options = options or {}
        subdomains = options.get("subdomains", COMMON_SUBDOMAINS)
        found: list[dict[str, Any]] = []

        for target in targets:
            domain = target.split("//")[-1].split("/")[0].split(":")[0]

            async def check_subdomain(sub: str) -> dict[str, Any] | None:
                fqdn = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    result = await loop.getaddrinfo(fqdn, None, family=socket.AF_INET)
                    if result:
                        ip = result[0][4][0]
                        return {"subdomain": fqdn, "ip": ip}
                except (socket.gaierror, OSError):
                    return None

            if scope and scope.is_dry_run:
                continue

            results = await asyncio.gather(*[check_subdomain(s) for s in subdomains])
            found.extend([r for r in results if r is not None])

        return EngineEvent(timestamp=datetime.now(), event_type="module_complete", module="subdomain_enum",
            target=",".join(targets), severity="info",
            detail={"total_tests": len(subdomains) * len(targets), "subdomains_found": found,
                "vulnerabilities_found": 0, "results": [
                    {"target": s["subdomain"], "status": "potentially_vulnerable",
                     "evidence": f"Subdomain found: {s['subdomain']} -> {s['ip']}", "severity": "info",
                     "payload": s["subdomain"], "elapsed_ms": 0}
                    for s in found]})
