"""Open Redirect testing. MITRE ATT&CK: T1189"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "/\\evil.com", "https:evil.com",
    "http://evil.com%2F%2F", "////evil.com", "https://evil.com/..;/",
    "///evil.com", "/%0d/evil.com", "/evil.com%00.internal", "/.evil.com",
    "https://evil.com#@trusted.com", "https://trusted.com@evil.com",
    "javascript:alert(1)//", "data:text/html,<script>alert(1)</script>",
    "https://evil.com%23.trusted.com",
]

class OpenRedirectModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="open_redirect", description="Open redirect testing", category="open_redirect",
            mitre_technique_ids=["T1189"], mitre_technique_names=["Drive-by Compromise"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-601"], tags=["redirect", "phishing"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("open_redirect", limit=50)
            if p: return p
        return DEFAULT_REDIRECT_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["redirect", "url", "next", "return", "returnTo", "goto", "redir", "destination", "continue"])
        return [AttackRequest(request_id=f"redir-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), params={param: p}, follow_redirects=False,
            headers={"X-BAS-Payload": p}) for p in payloads for param in params[:3]]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        location = response.headers.get("location", response.headers.get("Location", ""))
        if response.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
            return ModuleResult(module_name="open_redirect", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Open redirect to external domain: Location={location}", severity="medium",
                mitre_technique_id="T1189", detail={"redirect_location": location})
        return ModuleResult(module_name="open_redirect", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
