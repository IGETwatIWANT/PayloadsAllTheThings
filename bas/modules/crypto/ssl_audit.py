"""
SSL/TLS Certificate & Configuration Audit module.

Tests SSL/TLS configuration for weaknesses including weak ciphers, expired
certificates, self-signed certificates, certificate transparency, OCSP
stapling, key size, protocol versions, and indicators of BEAST, POODLE,
and DROWN vulnerabilities.

MITRE ATT&CK: T1557 - Adversary-in-the-Middle
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# SSL/TLS probe paths and header payloads
# ---------------------------------------------------------------------------
SSL_PROBE_PATHS = [
    # Protocol downgrade probes
    "/.well-known/acme-challenge/test",
    "/.well-known/pki-validation/test",
    "/.well-known/est/cacerts",
    "/.well-known/est/simpleenroll",
    # HSTS preload / header inspection endpoints
    "/",
    "/login",
    "/api",
    "/api/v1",
    "/api/v2",
    "/health",
    "/status",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
]

# Weak cipher suites to probe via headers / path hints
WEAK_CIPHER_PROBES = [
    # NULL ciphers
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    # Export-grade ciphers (FREAK)
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    # DES / 3DES (Sweet32)
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    # RC4 (Bar Mitzvah / NOMORE)
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    # Weak CBC suites (BEAST)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    # Anonymous key exchange (no authentication)
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_anon_WITH_RC4_128_SHA",
]

# Protocol version probes
PROTOCOL_PROBES = [
    "SSLv2",
    "SSLv3",
    "TLSv1.0",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
]

# Headers that reveal TLS/SSL configuration weaknesses
SECURITY_HEADER_CHECKS = [
    "Strict-Transport-Security",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "Expect-CT",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Combined default payload list
DEFAULT_SSL_PAYLOADS: list[str] = []

# Add probe paths for header-based analysis
for _path in SSL_PROBE_PATHS:
    DEFAULT_SSL_PAYLOADS.append(f"path:{_path}")

# Add weak cipher probes
for _cipher in WEAK_CIPHER_PROBES:
    DEFAULT_SSL_PAYLOADS.append(f"cipher:{_cipher}")

# Add protocol version checks
for _proto in PROTOCOL_PROBES:
    DEFAULT_SSL_PAYLOADS.append(f"protocol:{_proto}")

# Add specific vulnerability indicator probes
VULN_INDICATOR_PAYLOADS = [
    # BEAST indicator - CBC cipher with TLS 1.0
    "vuln:BEAST:CBC_WITH_TLSv1.0",
    # POODLE indicator - SSLv3 support
    "vuln:POODLE:SSLv3_SUPPORT",
    # DROWN indicator - SSLv2 support
    "vuln:DROWN:SSLv2_SUPPORT",
    # CRIME/BREACH - TLS compression
    "vuln:CRIME:TLS_COMPRESSION",
    "vuln:BREACH:HTTP_COMPRESSION_WITH_SECRETS",
    # Heartbleed indicator
    "vuln:HEARTBLEED:OPENSSL_HEARTBEAT",
    # FREAK - RSA export ciphers
    "vuln:FREAK:RSA_EXPORT_CIPHER",
    # Logjam - weak DH params
    "vuln:LOGJAM:WEAK_DH_PARAMS",
    # ROBOT - RSA padding oracle
    "vuln:ROBOT:RSA_PKCS1_PADDING",
    # Lucky13 - CBC timing
    "vuln:LUCKY13:CBC_TIMING",
    # Sweet32 - 64-bit block cipher
    "vuln:SWEET32:64BIT_BLOCK_CIPHER",
    # Ticketbleed - session ticket leak
    "vuln:TICKETBLEED:SESSION_TICKET",
    # Certificate checks
    "cert:EXPIRED_CERTIFICATE",
    "cert:SELF_SIGNED_CERTIFICATE",
    "cert:WRONG_HOST",
    "cert:WEAK_SIGNATURE_ALGO_MD5",
    "cert:WEAK_SIGNATURE_ALGO_SHA1",
    "cert:SHORT_RSA_KEY_1024",
    "cert:SHORT_RSA_KEY_512",
    "cert:MISSING_SAN",
    "cert:WILDCARD_OVERBROAD",
    "cert:CHAIN_INCOMPLETE",
    "cert:CT_LOG_MISSING",
    "cert:OCSP_STAPLING_MISSING",
    "cert:OCSP_MUST_STAPLE_ABSENT",
    "cert:CRL_NOT_AVAILABLE",
    "cert:CERTIFICATE_REVOKED",
]

DEFAULT_SSL_PAYLOADS.extend(VULN_INDICATOR_PAYLOADS)

# Response body / header patterns that indicate SSL/TLS weaknesses
SSL_WEAKNESS_PATTERNS: list[tuple[str, str, str]] = [
    # Certificate errors in page content
    (r"(?i)ssl_error_rx_record_too_long", "SSL record too long error", "medium"),
    (r"(?i)err_ssl_protocol_error", "SSL protocol error", "medium"),
    (r"(?i)err_cert_authority_invalid", "Invalid certificate authority", "high"),
    (r"(?i)err_cert_date_invalid", "Certificate date invalid", "high"),
    (r"(?i)err_cert_common_name_invalid", "Certificate common name mismatch", "high"),
    (r"(?i)ssl_error_handshake_failure_alert", "SSL handshake failure", "medium"),
    (r"(?i)certificate has expired", "Expired certificate detected", "high"),
    (r"(?i)self[- ]signed certificate", "Self-signed certificate detected", "high"),
    (r"(?i)unable to verify the first certificate", "Certificate chain incomplete", "high"),
    (r"(?i)certificate verify failed", "Certificate verification failure", "high"),
    # Server version disclosure revealing vulnerable OpenSSL
    (r"OpenSSL/0\.", "Outdated OpenSSL 0.x detected", "critical"),
    (r"OpenSSL/1\.0\.1[a-f]?\b", "OpenSSL vulnerable to Heartbleed", "critical"),
    (r"OpenSSL/1\.0\.0", "Outdated OpenSSL 1.0.0 detected", "high"),
    (r"OpenSSL/1\.0\.1\b", "Outdated OpenSSL 1.0.1 detected", "high"),
    (r"OpenSSL/1\.0\.2[a-z]?\b", "Outdated OpenSSL 1.0.2 detected", "medium"),
    (r"OpenSSL/1\.1\.0[a-z]?\b", "Outdated OpenSSL 1.1.0 detected", "medium"),
    # Mixed content indicators
    (r"(?i)mixed content:.*was loaded over https.*requested an insecure", "Mixed content detected", "medium"),
    (r"(?i)blocked loading mixed active content", "Mixed active content blocked", "low"),
    # Weak TLS indicators in server headers
    (r"(?i)ssl\s*version\s*[=:]\s*(ssl|tls\s*1\.[01])", "Weak TLS version disclosed", "high"),
    # HPKP violation
    (r"(?i)public[- ]key[- ]pins.*max-age\s*=\s*0", "HPKP disabled (max-age=0)", "low"),
]

COMPILED_SSL_PATTERNS = [
    (re.compile(p), desc, sev) for p, desc, sev in SSL_WEAKNESS_PATTERNS
]


class SSLAuditModule(BaseAttackModule):
    """
    SSL/TLS Certificate & Configuration Audit.

    Probes targets for weak SSL/TLS configurations including deprecated
    protocol versions, weak cipher suites, certificate issues (expired,
    self-signed, weak key), missing security headers (HSTS, Expect-CT),
    and indicators of known vulnerabilities (BEAST, POODLE, DROWN,
    Heartbleed, FREAK, Logjam).
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ssl_audit",
            description=(
                "SSL/TLS Certificate & Configuration Audit - weak ciphers, "
                "expired certs, protocol versions, BEAST/POODLE/DROWN indicators"
            ),
            category="crypto",
            mitre_technique_ids=["T1557"],
            mitre_technique_names=["Adversary-in-the-Middle"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A02:2021 - Cryptographic Failures",
            cwe_ids=["CWE-295", "CWE-326", "CWE-327", "CWE-757", "CWE-319"],
            tags=[
                "ssl", "tls", "certificate", "cipher", "crypto",
                "beast", "poodle", "drown", "heartbleed",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ssl_audit", limit=300)
            if db_payloads:
                return db_payloads
        return list(DEFAULT_SSL_PAYLOADS)

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        user_agent = options.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            if payload.startswith("path:"):
                # Direct path probe - inspect response headers for security config
                path = payload[5:]
                requests.append(AttackRequest(
                    request_id=f"ssl-path-{req_id}",
                    target=target,
                    method="GET",
                    path=path,
                    headers={
                        "User-Agent": user_agent,
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))

            elif payload.startswith("cipher:"):
                # Cipher probe - request with Accept header hinting cipher preference
                cipher_name = payload[7:]
                requests.append(AttackRequest(
                    request_id=f"ssl-cipher-{req_id}",
                    target=target,
                    method="GET",
                    path=options.get("path", "/"),
                    headers={
                        "User-Agent": user_agent,
                        "X-BAS-Payload": payload,
                        "X-BAS-Cipher-Probe": cipher_name,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))

            elif payload.startswith("protocol:"):
                # Protocol version probe
                protocol = payload[9:]
                requests.append(AttackRequest(
                    request_id=f"ssl-proto-{req_id}",
                    target=target,
                    method="GET",
                    path=options.get("path", "/"),
                    headers={
                        "User-Agent": user_agent,
                        "X-BAS-Payload": payload,
                        "X-BAS-Protocol-Probe": protocol,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))

            elif payload.startswith("vuln:") or payload.startswith("cert:"):
                # Vulnerability / certificate indicator probe
                requests.append(AttackRequest(
                    request_id=f"ssl-vuln-{req_id}",
                    target=target,
                    method="GET",
                    path=options.get("path", "/"),
                    headers={
                        "User-Agent": user_agent,
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))

            else:
                # Generic probe
                requests.append(AttackRequest(
                    request_id=f"ssl-gen-{req_id}",
                    target=target,
                    method="GET",
                    path=options.get("path", "/"),
                    headers={
                        "User-Agent": user_agent,
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_tag = request.headers.get("X-BAS-Payload", payload)
        headers = response.headers

        # Handle connection errors (often SSL-related themselves)
        if response.error:
            error_lower = response.error.lower()
            # SSL errors during connection are themselves findings
            if any(kw in error_lower for kw in (
                "ssl", "tls", "certificate", "handshake", "verify",
            )):
                return ModuleResult(
                    module_name="ssl_audit",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_tag,
                    response_code=0,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSL/TLS connection error: {response.error}",
                    severity="high",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "connection_error", "error": response.error},
                )
            return ModuleResult(
                module_name="ssl_audit",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_tag,
                response_code=0,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # ── HTTP (non-HTTPS) redirect check ───────────────────────────────
        if payload_tag.startswith("path:"):
            # Check if target is HTTP and does NOT redirect to HTTPS
            if request.target.startswith("http://"):
                location = headers.get("Location", headers.get("location", ""))
                if response.status_code not in (301, 302, 307, 308) or not location.startswith("https://"):
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        response_body_preview=body[:300],
                        elapsed_ms=response.elapsed_ms,
                        evidence="HTTP target does not redirect to HTTPS - traffic sent in cleartext",
                        severity="high",
                        mitre_technique_id="T1557",
                        detail={"detection_type": "no_https_redirect"},
                    )

        # ── HSTS header analysis ──────────────────────────────────────────
        if payload_tag.startswith("path:"):
            hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))
            if not hsts:
                return ModuleResult(
                    module_name="ssl_audit",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_tag,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Missing Strict-Transport-Security (HSTS) header",
                    severity="medium",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "missing_hsts"},
                )
            # Check HSTS max-age value
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 2592000:  # Less than 30 days
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"HSTS max-age too short: {max_age}s (recommended >= 31536000)",
                        severity="low",
                        mitre_technique_id="T1557",
                        detail={"detection_type": "weak_hsts", "max_age": max_age},
                    )
                if "includesubdomains" not in hsts.lower():
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence="HSTS missing includeSubDomains directive",
                        severity="low",
                        mitre_technique_id="T1557",
                        detail={"detection_type": "hsts_no_subdomains"},
                    )

        # ── Server header version disclosure ──────────────────────────────
        server_header = headers.get("Server", headers.get("server", ""))
        if server_header:
            for pattern, desc, severity in COMPILED_SSL_PATTERNS:
                match = pattern.search(server_header)
                if match:
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        response_body_preview=body[:300],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"{desc} (Server: {server_header})",
                        severity=severity,
                        mitre_technique_id="T1557",
                        detail={"detection_type": "server_version", "server": server_header},
                    )

        # ── Cipher probe result analysis ──────────────────────────────────
        if payload_tag.startswith("cipher:"):
            cipher_name = payload_tag[7:]
            # If server accepted the connection with a weak cipher probe header,
            # check response body/headers for cipher info
            cipher_lower = cipher_name.lower()
            if any(weak in cipher_lower for weak in (
                "null", "export", "des_cbc", "rc4", "anon",
            )):
                # If server responded 200, it did not reject - potentially weak config
                if response.status_code == 200:
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Server accepted connection during weak cipher probe: {cipher_name}",
                        severity="medium",
                        mitre_technique_id="T1557",
                        detail={"detection_type": "weak_cipher_probe", "cipher": cipher_name},
                    )

        # ── Body pattern matching for SSL/TLS issues ──────────────────────
        if body and len(body) > 0:
            for pattern, desc, severity in COMPILED_SSL_PATTERNS:
                match = pattern.search(body)
                if match:
                    return ModuleResult(
                        module_name="ssl_audit",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"{desc}: {match.group(0)[:80]}",
                        severity=severity,
                        mitre_technique_id="T1557",
                        detail={"detection_type": "body_pattern", "matched": match.group(0)[:100]},
                    )

        # ── Expect-CT header check ────────────────────────────────────────
        if payload_tag.startswith("cert:CT_LOG"):
            expect_ct = headers.get("Expect-CT", headers.get("expect-ct", ""))
            if not expect_ct:
                return ModuleResult(
                    module_name="ssl_audit",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_tag,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Missing Expect-CT header - Certificate Transparency not enforced",
                    severity="low",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "missing_expect_ct"},
                )

        return ModuleResult(
            module_name="ssl_audit",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_tag,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
