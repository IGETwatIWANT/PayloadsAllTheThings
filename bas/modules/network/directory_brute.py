"""
Directory / Path Brute Force module.
MITRE ATT&CK: T1595 - Active Scanning
"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

COMMON_DIRS = [
    "/admin", "/login", "/dashboard", "/api", "/api/v1", "/api/v2", "/swagger", "/docs",
    "/wp-admin", "/wp-login.php", "/administrator", "/phpmyadmin", "/console", "/debug",
    "/backup", "/backups", "/db", "/database", "/config", "/conf", "/settings",
    "/internal", "/private", "/secret", "/hidden", "/test", "/staging", "/dev",
    "/.env", "/.git", "/.svn", "/.htaccess", "/web.config", "/crossdomain.xml",
    "/server-status", "/server-info", "/info.php", "/phpinfo.php",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics", "/health",
    "/graphql", "/graphiql", "/playground", "/__debug__",
    "/wp-json", "/wp-content", "/xmlrpc.php", "/feed", "/sitemap.xml",
    "/cgi-bin", "/cgi-bin/admin", "/manager/html", "/jmx-console",
    "/solr", "/jenkins", "/nagios", "/kibana", "/grafana",
    "/.well-known/security.txt", "/robots.txt", "/humans.txt",
    "/api/swagger.json", "/api/openapi.json", "/v2/api-docs",
    "/trace", "/elmah.axd", "/error_log", "/errors.log",
]

class DirectoryBruteModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="dir_brute", description="Directory and path brute force discovery",
            category="recon", mitre_technique_ids=["T1595"],
            mitre_technique_names=["Active Scanning"],
            auth_level_required=AuthorizationLevel.READ_ONLY, cwe_ids=["CWE-200"],
            tags=["recon", "discovery", "directory", "brute_force"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        extra = options.get("extra_dirs", [])
        return COMMON_DIRS + extra

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"dir-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=p, headers={"X-BAS-Path": p}, follow_redirects=False) for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        path = request.headers.get("X-BAS-Path", payload)
        if response.status_code in (200, 301, 302) and response.status_code != 404:
            severity = "info"
            status = VulnStatus.POTENTIALLY_VULNERABLE
            if any(s in path for s in [".env", ".git", "backup", "config", "phpinfo", "actuator/env"]):
                severity = "high"
                status = VulnStatus.VULNERABLE
            elif any(s in path for s in ["admin", "dashboard", "console", "debug", "private"]):
                severity = "medium"
            return ModuleResult(module_name="dir_brute", target=request.target, status=status,
                payload_used=path, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Path discovered: {path} (HTTP {response.status_code})",
                severity=severity, mitre_technique_id="T1595")
        return ModuleResult(module_name="dir_brute", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=path, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
