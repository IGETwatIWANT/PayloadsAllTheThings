"""
Traffic Shaping / Network Evasion module.
Tests network-level evasion techniques against IDS/IPS systems.
MITRE ATT&CK: T1071 - Application Layer Protocol
MITRE ATT&CK: T1090 - Proxy

Validates that network monitoring solutions detect anomalous traffic patterns.
For authorized penetration testing only.
"""
from __future__ import annotations
import uuid
import random
import time
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

# Traffic shaping techniques
EVASION_TECHNIQUES = {
    "slow_drip": {
        "description": "Slow-drip request pattern to evade rate-based detection",
        "headers": {"X-BAS-Timing": "slow"},
    },
    "header_stuffing": {
        "description": "Excessive headers to confuse header-based inspection",
        "extra_headers": {f"X-Custom-{i}": f"value-{i}" for i in range(20)},
    },
    "user_agent_rotation": {
        "description": "Rotating user agents to evade fingerprinting",
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/8.1.2",
            "python-httpx/0.27.0",
        ],
    },
    "fragment_request": {
        "description": "Fragmented request patterns",
        "headers": {"Transfer-Encoding": "chunked"},
    },
    "pipeline_abuse": {
        "description": "HTTP pipelining to bypass per-request inspection",
        "headers": {"Connection": "keep-alive", "X-BAS-Pipeline": "true"},
    },
    "encoding_mix": {
        "description": "Mixed content encoding to confuse inspectors",
        "headers": {"Accept-Encoding": "gzip, deflate, br, zstd, identity"},
    },
    "cache_poison_probe": {
        "description": "Cache key manipulation for detection evasion",
        "headers": {
            "X-Forwarded-Host": "internal.target",
            "X-Host": "internal.target",
            "X-Forwarded-Server": "internal.target",
        },
    },
    "ip_rotation_test": {
        "description": "Test detection of IP rotation via headers",
        "headers": {
            "X-Forwarded-For": "192.168.1.1",
            "X-Real-IP": "10.0.0.1",
            "X-Client-IP": "172.16.0.1",
            "True-Client-IP": "192.168.1.100",
        },
    },
}


class TrafficShapingModule(BaseAttackModule):
    """Tests network traffic evasion for authorized IDS/IPS validation."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="traffic_shaping",
            description="Network traffic evasion testing - validates IDS/IPS detection",
            category="evasion",
            mitre_technique_ids=["T1071", "T1090"],
            mitre_technique_names=["Application Layer Protocol", "Proxy"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-693"],
            tags=["evasion", "ids", "ips", "traffic", "network", "stealth"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        techniques = options.get("techniques", list(EVASION_TECHNIQUES.keys()))
        return [t for t in techniques if t in EVASION_TECHNIQUES]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        test_path = options.get("path", "/")

        for technique_name in payloads:
            technique = EVASION_TECHNIQUES[technique_name]
            headers = {"X-BAS-Technique": technique_name, "X-BAS-Module": "traffic_shaping"}

            if technique_name == "user_agent_rotation":
                for ua in technique["user_agents"]:
                    headers["User-Agent"] = ua
                    requests.append(AttackRequest(
                        request_id=f"tshape-{uuid.uuid4().hex[:8]}",
                        target=target, method="GET", path=test_path,
                        headers=dict(headers),
                    ))
            elif technique_name == "header_stuffing":
                combined = {**headers, **technique.get("extra_headers", {})}
                requests.append(AttackRequest(
                    request_id=f"tshape-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET", path=test_path,
                    headers=combined,
                ))
            elif technique_name == "ip_rotation_test":
                combined = {**headers, **technique.get("headers", {})}
                requests.append(AttackRequest(
                    request_id=f"tshape-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET", path=test_path,
                    headers=combined,
                ))
            elif technique_name == "cache_poison_probe":
                combined = {**headers, **technique.get("headers", {})}
                requests.append(AttackRequest(
                    request_id=f"tshape-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET", path=test_path,
                    headers=combined,
                ))
            else:
                extra = technique.get("headers", {})
                combined = {**headers, **extra}
                requests.append(AttackRequest(
                    request_id=f"tshape-{uuid.uuid4().hex[:8]}",
                    target=target, method="GET", path=test_path,
                    headers=combined,
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        technique = request.headers.get("X-BAS-Technique", "unknown")

        blocked_indicators = ["blocked", "forbidden", "rate limit", "too many", "denied"]
        body = response.body_text.lower()
        is_blocked = (
            response.status_code in (403, 429, 503)
            or any(i in body for i in blocked_indicators)
        )

        if not is_blocked and response.status_code in (200, 301, 302):
            return ModuleResult(
                module_name="traffic_shaping", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Traffic evasion technique undetected: {technique}",
                severity="medium", mitre_technique_id="T1071",
                detail={"technique": technique, "detected": False},
            )
        return ModuleResult(
            module_name="traffic_shaping", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"technique": technique, "detected": True},
        )
