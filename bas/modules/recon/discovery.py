"""
Service Discovery and Reconnaissance module.

Performs passive and active reconnaissance:
- HTTP header analysis
- Technology fingerprinting
- Security header audit
- Common endpoint discovery
- Information leakage detection

MITRE ATT&CK: T1595 - Active Scanning
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


DISCOVERY_PATHS = [
    # Common sensitive endpoints
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/web.config",
    "/crossdomain.xml",
    "/.well-known/security.txt",
    # API documentation
    "/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    "/graphiql",
    # Admin panels
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/manager",
    "/console",
    "/_debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    # Backup / config files
    "/backup.sql",
    "/database.sql",
    "/config.yml",
    "/config.json",
    "/settings.json",
    "/.htaccess",
    "/server-status",
    "/server-info",
    # Error pages for tech fingerprinting
    "/404_not_found_test_bas",
    "/test.php",
    "/test.asp",
    "/test.jsp",
]

# Required security headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing - no enforcement of HTTPS",
    "Content-Security-Policy": "CSP missing - no XSS mitigation",
    "X-Content-Type-Options": "X-Content-Type-Options missing - MIME sniffing possible",
    "X-Frame-Options": "X-Frame-Options missing - clickjacking possible",
    "X-XSS-Protection": "X-XSS-Protection missing (legacy but still recommended)",
    "Referrer-Policy": "Referrer-Policy missing - referrer leakage possible",
    "Permissions-Policy": "Permissions-Policy missing - browser features unrestricted",
}

# Technology fingerprints in headers
TECH_FINGERPRINTS = {
    "X-Powered-By": "Technology disclosure",
    "Server": "Server version disclosure",
    "X-AspNet-Version": "ASP.NET version disclosure",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
    "X-Generator": "Generator disclosure",
}


class DiscoveryModule(BaseAttackModule):
    """Reconnaissance and service discovery module."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="discovery",
            description="Reconnaissance - headers, tech fingerprinting, endpoint discovery",
            category="recon",
            mitre_technique_ids=["T1595", "T1592"],
            mitre_technique_names=["Active Scanning", "Gather Victim Host Information"],
            auth_level_required=AuthorizationLevel.READ_ONLY,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200"],
            tags=["recon", "discovery", "fingerprint"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        paths = list(DISCOVERY_PATHS)
        extra_paths = options.get("extra_paths", [])
        paths.extend(extra_paths)
        return paths

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        for path in payloads:
            req_id = str(uuid.uuid4())[:8]
            requests.append(AttackRequest(
                request_id=f"disc-{req_id}",
                target=target,
                method="GET",
                path=path,
                headers={"X-BAS-Path": path},
                follow_redirects=False,
            ))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        path = request.headers.get("X-BAS-Path", payload)
        body = response.body_text

        # Sensitive file exposure
        sensitive_indicators = {
            "/.env": [("DB_PASSWORD", "critical"), ("SECRET_KEY", "critical"), ("API_KEY", "critical")],
            "/.git/config": [("[core]", "high"), ("repositoryformatversion", "high")],
            "/.git/HEAD": [("ref:", "high")],
            "/robots.txt": [("Disallow:", "info")],
            "/server-status": [("Apache Server Status", "medium")],
            "/actuator/env": [("activeProfiles", "high"), ("propertySources", "high")],
            "/swagger.json": [("swagger", "medium"), ("openapi", "medium")],
        }

        if path in sensitive_indicators and response.status_code == 200:
            for indicator, severity in sensitive_indicators[path]:
                if indicator.lower() in body.lower():
                    return ModuleResult(
                        module_name="discovery",
                        target=request.target,
                        status=VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=path,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Sensitive file exposed at {path}: contains '{indicator}'",
                        severity=severity,
                        mitre_technique_id="T1595",
                        detail={"detection_type": "sensitive_file", "path": path},
                    )

        # Security header analysis (only for main page)
        if path == DISCOVERY_PATHS[0] or response.status_code == 200:
            missing_headers = []
            for header, issue in SECURITY_HEADERS.items():
                if header.lower() not in {k.lower() for k in response.headers}:
                    missing_headers.append(issue)

            tech_disclosures = []
            for header, issue in TECH_FINGERPRINTS.items():
                value = response.headers.get(header, "")
                if value:
                    tech_disclosures.append(f"{header}: {value}")

            if missing_headers or tech_disclosures:
                detail: dict[str, Any] = {}
                if missing_headers:
                    detail["missing_security_headers"] = missing_headers
                if tech_disclosures:
                    detail["technology_disclosures"] = tech_disclosures

                severity = "medium" if len(missing_headers) > 3 else "low"
                if tech_disclosures:
                    severity = "medium"

                return ModuleResult(
                    module_name="discovery",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=path,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Security issues: {len(missing_headers)} missing headers, {len(tech_disclosures)} tech disclosures",
                    severity=severity,
                    mitre_technique_id="T1592",
                    detail={**detail, "detection_type": "header_analysis"},
                )

        return ModuleResult(
            module_name="discovery",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=path,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
