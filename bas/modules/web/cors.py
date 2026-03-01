"""CORS Misconfiguration testing. MITRE ATT&CK: T1189"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

class CORSModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="cors", description="CORS misconfiguration testing", category="cors",
            mitre_technique_ids=["T1189"], mitre_technique_names=["Drive-by Compromise"],
            auth_level_required=AuthorizationLevel.READ_ONLY, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-942"], tags=["cors", "misconfiguration"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return ["https://evil.com", "null", "https://target.internal.evil.com",
                f"https://{target.split('//')[1] if '//' in target else target}.evil.com",
                "https://evil.com%60.target.com", "http://localhost"]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"cors-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), headers={"Origin": p, "X-BAS-Payload": p}) for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        acao = response.headers.get("access-control-allow-origin", response.headers.get("Access-Control-Allow-Origin", ""))
        acac = response.headers.get("access-control-allow-credentials", "")
        origin = request.headers.get("Origin", "")
        if acao == origin and "evil" in origin:
            sev = "high" if acac.lower() == "true" else "medium"
            return ModuleResult(module_name="cors", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"CORS reflects arbitrary origin: {acao} (credentials: {acac})",
                severity=sev, mitre_technique_id="T1189")
        if acao == "*":
            return ModuleResult(module_name="cors", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="CORS allows all origins (*)", severity="low", mitre_technique_id="T1189")
        if acao == "null":
            return ModuleResult(module_name="cors", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="CORS allows null origin", severity="medium", mitre_technique_id="T1189")
        return ModuleResult(module_name="cors", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
