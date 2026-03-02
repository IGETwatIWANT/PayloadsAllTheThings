"""CSRF testing. MITRE ATT&CK: T1189"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

class CSRFModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="csrf", description="Cross-Site Request Forgery detection", category="csrf",
            mitre_technique_ids=["T1189"], mitre_technique_names=["Drive-by Compromise"],
            auth_level_required=AuthorizationLevel.READ_ONLY, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-352"], tags=["csrf", "state_change"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return ["no_token", "empty_token", "cross_origin"]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        paths = options.get("state_change_paths", ["/api/settings", "/api/password", "/api/transfer", "/api/delete"])
        requests = []
        for path in paths:
            requests.append(AttackRequest(request_id=f"csrf-{uuid.uuid4().hex[:8]}", target=target,
                method="POST", path=path, body="action=test", content_type="application/x-www-form-urlencoded",
                headers={"Origin": "https://evil.com", "Referer": "https://evil.com/attack"}))
            requests.append(AttackRequest(request_id=f"csrf-{uuid.uuid4().hex[:8]}", target=target,
                method="GET", path=path, headers={"X-BAS-Check": "csrf_get"}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if response.status_code in (200, 201, 204):
            origin = request.headers.get("Origin", "")
            if "evil.com" in origin:
                return ModuleResult(module_name="csrf", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                    evidence=f"State-changing endpoint accepts cross-origin requests from {origin}",
                    severity="medium", mitre_technique_id="T1189")
        return ModuleResult(module_name="csrf", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
