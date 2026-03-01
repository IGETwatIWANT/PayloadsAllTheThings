"""
EDR Evasion Testing module.
Tests whether payloads can bypass Endpoint Detection and Response systems.
MITRE ATT&CK: T1027 - Obfuscated Files or Information
MITRE ATT&CK: T1140 - Deobfuscate/Decode Files or Information

For authorized penetration testing only. Validates that EDR solutions
properly detect obfuscated and encoded attack patterns.
"""
from __future__ import annotations
import base64
import uuid
import random
import string
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Encoding and obfuscation techniques for payload delivery testing
ENCODING_TECHNIQUES = [
    "base64", "double_base64", "hex", "url_double", "unicode_escape",
    "html_entity", "octal", "binary_string", "rot13", "xor_single",
    "case_swap", "null_byte_insert", "comment_injection", "concat_split",
    "char_code", "string_fromcharcode", "template_literal",
]

# Common EDR trigger patterns to test encoding against
TRIGGER_PATTERNS = [
    "eval(", "exec(", "system(", "passthru(", "shell_exec(",
    "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
    "WScript.Shell", "ScriptBlock", "Invoke-Expression",
    "document.cookie", "XMLHttpRequest", "fetch(",
    "<script>", "javascript:", "on[a-z]+=",
]


class EDREvasionModule(BaseAttackModule):
    """Tests EDR bypass techniques for authorized security assessment."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="edr_evasion",
            description="EDR evasion technique testing - validates detection capabilities",
            category="evasion",
            mitre_technique_ids=["T1027", "T1140", "T1036"],
            mitre_technique_names=["Obfuscated Files or Information", "Deobfuscate/Decode", "Masquerading"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-116"],
            tags=["evasion", "edr", "obfuscation", "encoding", "bypass"],
        )

    def _encode_payload(self, payload: str, technique: str) -> str:
        """Apply encoding/obfuscation technique to a payload."""
        if technique == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif technique == "double_base64":
            return base64.b64encode(base64.b64encode(payload.encode())).decode()
        elif technique == "hex":
            return payload.encode().hex()
        elif technique == "url_double":
            return "".join(f"%25{ord(c):02x}" for c in payload)
        elif technique == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif technique == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif technique == "octal":
            return "".join(f"\\{ord(c):03o}" for c in payload)
        elif technique == "rot13":
            result = []
            for c in payload:
                if 'a' <= c <= 'z':
                    result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= c <= 'Z':
                    result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(c)
            return "".join(result)
        elif technique == "xor_single":
            key = random.randint(1, 255)
            return f"XOR({key}):" + "".join(f"{ord(c) ^ key:02x}" for c in payload)
        elif technique == "case_swap":
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        elif technique == "null_byte_insert":
            return "\x00".join(payload)
        elif technique == "comment_injection":
            # Insert SQL/code comments between characters
            separators = ["/**/", "/*BAS*/", "//\n"]
            sep = random.choice(separators)
            return sep.join(payload)
        elif technique == "concat_split":
            mid = len(payload) // 2
            return f"'{payload[:mid]}'+'{payload[mid:]}'"
        elif technique == "char_code":
            return ",".join(str(ord(c)) for c in payload)
        elif technique == "string_fromcharcode":
            chars = ",".join(str(ord(c)) for c in payload)
            return f"String.fromCharCode({chars})"
        elif technique == "template_literal":
            return f"${{`{payload}`}}"
        return payload

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Generate encoded payloads for EDR evasion testing."""
        techniques = options.get("techniques", ENCODING_TECHNIQUES[:8])
        base_payloads = options.get("base_payloads", TRIGGER_PATTERNS[:6])
        payloads = []
        for base in base_payloads:
            for tech in techniques:
                encoded = self._encode_payload(base, tech)
                payloads.append(f"{tech}:{encoded}")
        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        test_path = options.get("path", "/")
        params = options.get("params", ["input", "data", "payload", "cmd"])
        for payload in payloads:
            tech, encoded = payload.split(":", 1)
            for param in params[:2]:
                # Test via query parameter
                requests.append(AttackRequest(
                    request_id=f"edr-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET",
                    path=f"{test_path}?{param}={encoded}",
                    headers={"X-BAS-Technique": tech, "X-BAS-Param": param},
                ))
                # Test via POST body
                requests.append(AttackRequest(
                    request_id=f"edr-{uuid.uuid4().hex[:8]}",
                    target=target, method="POST",
                    path=test_path,
                    body=f"{param}={encoded}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Technique": tech, "X-BAS-Param": param},
                ))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        tech = request.headers.get("X-BAS-Technique", "unknown")
        blocked_indicators = [
            "blocked", "forbidden", "waf", "firewall", "security",
            "not acceptable", "request denied", "access denied",
        ]
        body_lower = response.body_text.lower()
        is_blocked = (
            response.status_code in (403, 406, 429, 503)
            or any(ind in body_lower for ind in blocked_indicators)
        )

        if not is_blocked and response.status_code in (200, 301, 302):
            return ModuleResult(
                module_name="edr_evasion", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Encoded payload not blocked (technique: {tech}, HTTP {response.status_code})",
                severity="high", mitre_technique_id="T1027",
                detail={"technique": tech, "detection_bypassed": True},
            )
        return ModuleResult(
            module_name="edr_evasion", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"technique": tech, "detection_bypassed": False},
        )
