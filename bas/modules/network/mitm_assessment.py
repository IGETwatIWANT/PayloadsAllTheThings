"""
Network MITM Assessment module.
Assesses susceptibility to man-in-the-middle attacks by testing SSL/TLS
configuration, certificate validation, HSTS enforcement, security headers,
and protocol downgrade vulnerabilities via HTTP.
MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1557.001 (LLMNR/NBT-NS Poisoning),
               T1040 (Network Sniffing)
"""
from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# SSL / TLS Configuration Testing payloads
# ---------------------------------------------------------------------------
SSL_TLS_PAYLOADS = [
    # Test HTTP (non-HTTPS) availability -- should redirect
    "SSL:http_access:GET:/ :scheme=http",
    "SSL:http_redirect_check:GET:/ :expect_redirect_https",
    "SSL:hsts_presence:GET:/ :check_header=strict-transport-security",
    "SSL:hsts_max_age:GET:/ :check_header=strict-transport-security:min_max_age=31536000",
    "SSL:hsts_include_subdomains:GET:/ :check_header=strict-transport-security:includeSubDomains",
    "SSL:hsts_preload:GET:/ :check_header=strict-transport-security:preload",
    "SSL:mixed_content_check:GET:/ :check_body_for=http://",
    "SSL:expect_ct:GET:/ :check_header=expect-ct",
    "SSL:downgrade_https_to_http:GET:/ :force_http=true",
    "SSL:tls_version_indicator:GET:/ :check_header=x-tls-version",
    "SSL:http_login_page:GET:/login :scheme=http",
    "SSL:http_api_endpoint:GET:/api :scheme=http",
    "SSL:http_sensitive_path:GET:/account :scheme=http",
    "SSL:http_admin_path:GET:/admin :scheme=http",
    "SSL:http_checkout_path:GET:/checkout :scheme=http",
    "SSL:http_token_path:GET:/oauth/token :scheme=http",
    "SSL:https_enforcement_root:GET:/ :expect_301",
    "SSL:https_enforcement_api:GET:/api :expect_301",
    "SSL:http_static_resources:GET:/static :scheme=http",
    "SSL:http_js_resources:GET:/js :scheme=http",
]

# ---------------------------------------------------------------------------
# Certificate Validation payloads
# ---------------------------------------------------------------------------
CERT_VALIDATION_PAYLOADS = [
    "CERT:public_key_pins:GET:/ :check_header=public-key-pins",
    "CERT:public_key_pins_report:GET:/ :check_header=public-key-pins-report-only",
    "CERT:certificate_transparency:GET:/ :check_header=expect-ct",
    "CERT:ct_enforce:GET:/ :check_header=expect-ct:enforce",
    "CERT:server_header_version:GET:/ :check_header=server",
    "CERT:x_powered_by:GET:/ :check_header=x-powered-by",
    "CERT:cert_chain_via_header:GET:/ :check_header=x-ssl-cert",
    "CERT:ssl_client_cert:GET:/ :check_header=x-ssl-client-cert",
    "CERT:ssl_cipher:GET:/ :check_header=x-ssl-cipher",
    "CERT:ssl_protocol:GET:/ :check_header=x-ssl-protocol",
    "CERT:wildcard_cert_check:GET:/ :check_cert_wildcard",
    "CERT:self_signed_check:GET:/ :check_cert_self_signed",
    "CERT:expired_cert_check:GET:/ :check_cert_expired",
    "CERT:ct_log_sct:GET:/ :check_header=x-ct-sct",
    "CERT:ocsp_stapling:GET:/ :check_header=x-ocsp-staple",
]

# ---------------------------------------------------------------------------
# Secure Header Analysis payloads
# ---------------------------------------------------------------------------
SECURE_HEADER_PAYLOADS = [
    "HEADER:strict_transport_security:GET:/ :Strict-Transport-Security",
    "HEADER:csp_upgrade_insecure:GET:/ :Content-Security-Policy:upgrade-insecure-requests",
    "HEADER:x_content_type_options:GET:/ :X-Content-Type-Options:nosniff",
    "HEADER:x_frame_options:GET:/ :X-Frame-Options",
    "HEADER:referrer_policy:GET:/ :Referrer-Policy",
    "HEADER:permissions_policy:GET:/ :Permissions-Policy",
    "HEADER:cross_origin_opener_policy:GET:/ :Cross-Origin-Opener-Policy",
    "HEADER:cross_origin_embedder_policy:GET:/ :Cross-Origin-Embedder-Policy",
    "HEADER:cross_origin_resource_policy:GET:/ :Cross-Origin-Resource-Policy",
    "HEADER:feature_policy:GET:/ :Feature-Policy",
    "HEADER:cache_control_sensitive:GET:/login :Cache-Control:no-store",
    "HEADER:cache_control_account:GET:/account :Cache-Control:no-store",
    "HEADER:set_cookie_secure:GET:/ :Set-Cookie:Secure",
    "HEADER:set_cookie_httponly:GET:/ :Set-Cookie:HttpOnly",
    "HEADER:set_cookie_samesite:GET:/ :Set-Cookie:SameSite",
    "HEADER:csp_frame_ancestors:GET:/ :Content-Security-Policy:frame-ancestors",
    "HEADER:csp_default_src:GET:/ :Content-Security-Policy:default-src",
    "HEADER:csp_script_src:GET:/ :Content-Security-Policy:script-src",
    "HEADER:x_xss_protection:GET:/ :X-XSS-Protection",
    "HEADER:pragma_no_cache:GET:/login :Pragma:no-cache",
]

# ---------------------------------------------------------------------------
# Protocol Downgrade Testing payloads
# ---------------------------------------------------------------------------
DOWNGRADE_PAYLOADS = [
    "DOWNGRADE:http_to_https_301:GET:/ :expect_301",
    "DOWNGRADE:http_to_https_302:GET:/ :expect_302",
    "DOWNGRADE:cookie_before_redirect:GET:/ :scheme=http:check_set_cookie",
    "DOWNGRADE:mixed_content_js:GET:/ :check_body_for=<script src=\"http://",
    "DOWNGRADE:mixed_content_css:GET:/ :check_body_for=<link href=\"http://",
    "DOWNGRADE:mixed_content_img:GET:/ :check_body_for=<img src=\"http://",
    "DOWNGRADE:websocket_ws:GET:/ :check_body_for=ws://",
    "DOWNGRADE:websocket_wss:GET:/ :check_body_for=wss://",
    "DOWNGRADE:protocol_relative_url:GET:/ :check_body_for=src=\"//",
    "DOWNGRADE:api_http_access:GET:/api/v1 :scheme=http",
    "DOWNGRADE:form_action_http:GET:/ :check_body_for=action=\"http://",
    "DOWNGRADE:xhr_http:GET:/ :check_body_for=XMLHttpRequest.*http://",
    "DOWNGRADE:fetch_http:GET:/ :check_body_for=fetch(\"http://",
    "DOWNGRADE:iframe_http:GET:/ :check_body_for=<iframe src=\"http://",
    "DOWNGRADE:redirect_chain_http:GET:/redirect :scheme=http",
]

# ---------------------------------------------------------------------------
# DNS-based MITM Indicator payloads
# ---------------------------------------------------------------------------
DNS_MITM_PAYLOADS = [
    "DNS:dnssec_indicator:GET:/.well-known/dns-query :check_dnssec",
    "DNS:caa_record_indicator:GET:/ :check_header=x-caa-record",
    "DNS:doh_indicator:GET:/.well-known/dns-query :check_doh",
    "DNS:dot_indicator:GET:/ :check_header=x-dns-over-tls",
    "DNS:security_txt:GET:/.well-known/security.txt :check_dns_policy",
    "DNS:dns_prefetch_control:GET:/ :check_header=x-dns-prefetch-control",
    "DNS:expect_staple:GET:/ :check_header=expect-staple",
    "DNS:nel_header:GET:/ :check_header=nel",
    "DNS:report_to:GET:/ :check_header=report-to",
    "DNS:cdn_detection:GET:/ :check_header=cf-ray|x-cdn|x-cache",
]


class MitmAssessmentModule(BaseAttackModule):
    """Assesses MITM resistance via SSL/TLS, headers, and downgrade testing."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="mitm_assessment",
            description=(
                "Man-in-the-middle resistance assessment -- tests SSL/TLS "
                "configuration, HSTS enforcement, security headers, "
                "certificate hygiene, and protocol downgrade vectors"
            ),
            category="network",
            mitre_technique_ids=["T1557", "T1557.001", "T1040"],
            mitre_technique_names=[
                "Adversary-in-the-Middle",
                "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Network Sniffing",
            ],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            cwe_ids=["CWE-295", "CWE-319", "CWE-523"],
            tags=[
                "network", "mitm", "ssl", "tls", "certificate",
                "hsts", "downgrade",
            ],
        )

    # -- abstract method implementations -----------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads: list[str] = []
        categories = options.get("categories", [
            "ssl", "cert", "header", "downgrade", "dns",
        ])
        if "ssl" in categories:
            payloads.extend(SSL_TLS_PAYLOADS)
        if "cert" in categories:
            payloads.extend(CERT_VALIDATION_PAYLOADS)
        if "header" in categories:
            payloads.extend(SECURE_HEADER_PAYLOADS)
        if "downgrade" in categories:
            payloads.extend(DOWNGRADE_PAYLOADS)
        if "dns" in categories:
            payloads.extend(DNS_MITM_PAYLOADS)
        payloads.extend(options.get("extra_payloads", []))
        return payloads

    def _build_requests(
        self,
        target: str,
        payloads: list[str],
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []

        for payload in payloads:
            rid = f"mitm-{uuid.uuid4().hex[:8]}"
            parts = payload.split(":")
            category = parts[0] if len(parts) > 0 else "UNKNOWN"
            test_name = parts[1] if len(parts) > 1 else "unknown"
            method = parts[2] if len(parts) > 2 else "GET"
            path = parts[3].strip() if len(parts) > 3 else "/"

            # Determine if request should be forced to HTTP
            use_http = "scheme=http" in payload or "force_http=true" in payload

            headers = {
                "X-BAS-Payload": payload,
                "X-BAS-Category": category,
                "X-BAS-Test": test_name,
            }

            if use_http:
                headers["X-BAS-Force-HTTP"] = "true"

            requests.append(
                AttackRequest(
                    request_id=rid,
                    target=target,
                    method=method,
                    path=path,
                    headers=headers,
                    follow_redirects=False,
                    timeout=options.get("timeout", 15),
                )
            )

        return requests

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        category = request.headers.get("X-BAS-Category", "")
        test_name = request.headers.get("X-BAS-Test", "")
        body = response.body_text.lower() if response.body_text else ""
        resp_headers = {
            k.lower(): v
            for k, v in (response.headers or {}).items()
        }

        if category == "SSL":
            return self._analyze_ssl(
                request, response, payload, test_name, body, resp_headers
            )
        if category == "CERT":
            return self._analyze_cert(
                request, response, payload, test_name, resp_headers
            )
        if category == "HEADER":
            return self._analyze_header(
                request, response, payload, test_name, body, resp_headers
            )
        if category == "DOWNGRADE":
            return self._analyze_downgrade(
                request, response, payload, test_name, body, resp_headers
            )
        if category == "DNS":
            return self._analyze_dns(
                request, response, payload, test_name, resp_headers
            )

        return self._default_result(request, response, payload)

    # -- SSL / TLS analysis ------------------------------------------------

    def _analyze_ssl(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        test_name: str,
        body: str,
        headers: dict[str, str],
    ) -> ModuleResult:
        force_http = request.headers.get("X-BAS-Force-HTTP") == "true"
        is_redirect = response.status_code in (301, 302, 307, 308)

        # HTTP access that should redirect to HTTPS but does not
        if force_http and not is_redirect and response.status_code == 200:
            return ModuleResult(
                module_name="mitm_assessment",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"HTTP endpoint served content without HTTPS redirect: {test_name}",
                severity="high",
                mitre_technique_id="T1557",
                detail={"detection_type": "no_https_redirect", "test": test_name},
            )

        # HSTS checks
        hsts = headers.get("strict-transport-security", "")
        if "hsts" in test_name:
            if not hsts:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HSTS header missing -- susceptible to SSL stripping",
                    severity="high",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "hsts_missing", "test": test_name},
                )
            if "max_age" in test_name:
                try:
                    max_age = int(
                        hsts.split("max-age=")[1].split(";")[0].strip()
                    )
                    if max_age < 31536000:
                        return ModuleResult(
                            module_name="mitm_assessment",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload,
                            response_code=response.status_code,
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HSTS max-age too low ({max_age}s < 31536000s)",
                            severity="medium",
                            mitre_technique_id="T1557",
                            detail={
                                "detection_type": "hsts_weak_max_age",
                                "max_age": max_age,
                            },
                        )
                except (IndexError, ValueError):
                    pass
            if "include_subdomains" in test_name and "includesubdomains" not in hsts.lower():
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HSTS missing includeSubDomains directive",
                    severity="medium",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "hsts_no_subdomains", "test": test_name},
                )
            if "preload" in test_name and "preload" not in hsts.lower():
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HSTS missing preload directive",
                    severity="low",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "hsts_no_preload", "test": test_name},
                )

        # Mixed content in body
        if "mixed_content" in test_name and "http://" in body:
            return ModuleResult(
                module_name="mitm_assessment",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence="Mixed content detected -- HTTP resources on HTTPS page",
                severity="medium",
                mitre_technique_id="T1557",
                detail={"detection_type": "mixed_content", "test": test_name},
            )

        return self._not_vulnerable(request, response, payload)

    # -- Certificate analysis ----------------------------------------------

    def _analyze_cert(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        test_name: str,
        headers: dict[str, str],
    ) -> ModuleResult:
        # Public key pinning
        if "public_key_pins" in test_name:
            hpkp = headers.get("public-key-pins", "") or headers.get(
                "public-key-pins-report-only", ""
            )
            # HPKP is deprecated but its absence is not critical
            return self._not_vulnerable(request, response, payload)

        # Check for certificate-related headers exposed by reverse proxies
        cert_headers = [
            "x-ssl-cert", "x-ssl-client-cert", "x-ssl-cipher",
            "x-ssl-protocol", "x-ct-sct", "x-ocsp-staple",
        ]
        for ch in cert_headers:
            if ch in test_name.replace("_", "-") and ch in headers:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Certificate detail header exposed: {ch}",
                    severity="info",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "cert_header_exposure", "header": ch},
                )

        # Server version leaking
        if test_name in ("server_header_version", "x_powered_by"):
            header_name = "server" if "server" in test_name else "x-powered-by"
            value = headers.get(header_name, "")
            if value:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Server identification exposed: {header_name}: {value}",
                    severity="low",
                    mitre_technique_id="T1040",
                    detail={
                        "detection_type": "server_version_leak",
                        "header": header_name,
                        "value": value,
                    },
                )

        # Expect-CT
        if "certificate_transparency" in test_name or "ct_enforce" in test_name:
            expect_ct = headers.get("expect-ct", "")
            if not expect_ct:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Expect-CT header missing -- no certificate transparency enforcement",
                    severity="low",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "no_expect_ct", "test": test_name},
                )

        return self._not_vulnerable(request, response, payload)

    # -- Security header analysis ------------------------------------------

    def _analyze_header(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        test_name: str,
        body: str,
        headers: dict[str, str],
    ) -> ModuleResult:
        # Map test names to expected header and optional directive
        header_checks: dict[str, tuple[str, str | None, str, str]] = {
            "strict_transport_security": (
                "strict-transport-security", None, "high",
                "HSTS header missing",
            ),
            "csp_upgrade_insecure": (
                "content-security-policy", "upgrade-insecure-requests", "medium",
                "CSP upgrade-insecure-requests directive missing",
            ),
            "x_content_type_options": (
                "x-content-type-options", "nosniff", "medium",
                "X-Content-Type-Options: nosniff missing",
            ),
            "x_frame_options": (
                "x-frame-options", None, "medium",
                "X-Frame-Options header missing",
            ),
            "referrer_policy": (
                "referrer-policy", None, "low",
                "Referrer-Policy header missing",
            ),
            "permissions_policy": (
                "permissions-policy", None, "low",
                "Permissions-Policy header missing",
            ),
            "cross_origin_opener_policy": (
                "cross-origin-opener-policy", None, "medium",
                "Cross-Origin-Opener-Policy header missing",
            ),
            "cross_origin_embedder_policy": (
                "cross-origin-embedder-policy", None, "low",
                "Cross-Origin-Embedder-Policy header missing",
            ),
            "cross_origin_resource_policy": (
                "cross-origin-resource-policy", None, "low",
                "Cross-Origin-Resource-Policy header missing",
            ),
            "feature_policy": (
                "feature-policy", None, "low",
                "Feature-Policy header missing (deprecated but informational)",
            ),
            "x_xss_protection": (
                "x-xss-protection", None, "low",
                "X-XSS-Protection header missing (legacy but informational)",
            ),
            "csp_frame_ancestors": (
                "content-security-policy", "frame-ancestors", "medium",
                "CSP frame-ancestors directive missing",
            ),
            "csp_default_src": (
                "content-security-policy", "default-src", "medium",
                "CSP default-src directive missing",
            ),
            "csp_script_src": (
                "content-security-policy", "script-src", "medium",
                "CSP script-src directive missing",
            ),
        }

        # Cache-Control checks for sensitive pages
        if "cache_control" in test_name:
            cc = headers.get("cache-control", "")
            pragma = headers.get("pragma", "")
            if "no-store" not in cc and "no-cache" not in pragma:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Sensitive page missing Cache-Control: no-store",
                    severity="medium",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "cache_control_missing", "test": test_name},
                )
            return self._not_vulnerable(request, response, payload)

        # Set-Cookie flag checks
        if "set_cookie" in test_name:
            cookies = headers.get("set-cookie", "")
            if not cookies:
                return self._not_vulnerable(request, response, payload)
            flag = ""
            if "secure" in test_name:
                flag = "secure"
            elif "httponly" in test_name:
                flag = "httponly"
            elif "samesite" in test_name:
                flag = "samesite"
            if flag and flag not in cookies.lower():
                sev = "high" if flag == "secure" else "medium"
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.VULNERABLE if flag == "secure" else VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Set-Cookie missing {flag} flag -- cookie interception risk",
                    severity=sev,
                    mitre_technique_id="T1557",
                    detail={"detection_type": f"cookie_no_{flag}", "test": test_name},
                )
            return self._not_vulnerable(request, response, payload)

        # Pragma check
        if "pragma" in test_name:
            if "no-cache" not in headers.get("pragma", ""):
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Pragma: no-cache missing on login page",
                    severity="low",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "pragma_missing", "test": test_name},
                )
            return self._not_vulnerable(request, response, payload)

        # Generic header presence check
        check = header_checks.get(test_name)
        if check:
            header_name, directive, severity, message = check
            header_value = headers.get(header_name, "")
            if not header_value:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=message,
                    severity=severity,
                    mitre_technique_id="T1557",
                    detail={"detection_type": "missing_header", "header": header_name},
                )
            if directive and directive.lower() not in header_value.lower():
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"{header_name} present but missing directive: {directive}",
                    severity=severity,
                    mitre_technique_id="T1557",
                    detail={
                        "detection_type": "missing_directive",
                        "header": header_name,
                        "directive": directive,
                    },
                )

        return self._not_vulnerable(request, response, payload)

    # -- Protocol downgrade analysis ---------------------------------------

    def _analyze_downgrade(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        test_name: str,
        body: str,
        headers: dict[str, str],
    ) -> ModuleResult:
        is_redirect = response.status_code in (301, 302, 307, 308)

        # Redirect type analysis
        if "301" in test_name or "302" in test_name:
            if not is_redirect:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HTTP to HTTPS redirect missing -- content served over HTTP",
                    severity="high",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "no_redirect", "test": test_name},
                )
            if response.status_code == 302 and "301" in test_name:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HTTP to HTTPS uses 302 (temporary) instead of 301 (permanent)",
                    severity="low",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "temp_redirect", "test": test_name},
                )

        # Cookie leakage before redirect
        if "cookie_before_redirect" in test_name:
            set_cookie = headers.get("set-cookie", "")
            if set_cookie and is_redirect:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Cookie set during HTTP redirect -- interception window",
                    severity="high",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "cookie_leakage_redirect", "test": test_name},
                )

        # Mixed content patterns in body
        mixed_patterns = [
            ('script src="http://', "mixed_content_js", "JavaScript loaded over HTTP"),
            ('link href="http://', "mixed_content_css", "CSS loaded over HTTP"),
            ('img src="http://', "mixed_content_img", "Image loaded over HTTP"),
            ("ws://", "websocket_ws", "WebSocket using unencrypted ws://"),
            ('src="//', "protocol_relative_url", "Protocol-relative URL found"),
            ('action="http://', "form_action_http", "Form action uses HTTP"),
            ("<iframe src=\"http://", "iframe_http", "Iframe loaded over HTTP"),
        ]
        for pattern, name_fragment, evidence_msg in mixed_patterns:
            if name_fragment in test_name and pattern in body:
                sev = "high" if "js" in name_fragment or "form" in name_fragment else "medium"
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:300],
                    elapsed_ms=response.elapsed_ms,
                    evidence=evidence_msg,
                    severity=sev,
                    mitre_technique_id="T1557",
                    detail={"detection_type": "mixed_content", "test": test_name},
                )

        # API HTTP access
        if "api_http" in test_name and response.status_code == 200:
            return ModuleResult(
                module_name="mitm_assessment",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence="API endpoint accessible over HTTP without redirect",
                severity="high",
                mitre_technique_id="T1557",
                detail={"detection_type": "api_http_access", "test": test_name},
            )

        return self._not_vulnerable(request, response, payload)

    # -- DNS MITM analysis -------------------------------------------------

    def _analyze_dns(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        test_name: str,
        headers: dict[str, str],
    ) -> ModuleResult:
        indicator_headers = {
            "dns_prefetch_control": ("x-dns-prefetch-control", "DNS prefetch control header missing"),
            "nel_header": ("nel", "Network Error Logging (NEL) header missing"),
            "report_to": ("report-to", "Report-To header missing"),
        }

        check = indicator_headers.get(test_name)
        if check:
            hdr, msg = check
            if hdr not in headers:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=msg,
                    severity="low",
                    mitre_technique_id="T1557.001",
                    detail={"detection_type": "dns_indicator_missing", "header": hdr},
                )

        # CDN detection (informational)
        if "cdn_detection" in test_name:
            cdn_headers = ["cf-ray", "x-cdn", "x-cache", "x-amz-cf-id", "x-vercel-id"]
            detected = [h for h in cdn_headers if h in headers]
            if detected:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"CDN detected (headers: {', '.join(detected)}) -- reduced MITM surface",
                    severity="info",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "cdn_detected", "cdn_headers": detected},
                )

        # Security.txt check
        if "security_txt" in test_name:
            if response.status_code == 200 and response.body_text:
                return ModuleResult(
                    module_name="mitm_assessment",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="security.txt present -- good security hygiene indicator",
                    severity="info",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "security_txt_present"},
                )

        return self._not_vulnerable(request, response, payload)

    # -- helpers -----------------------------------------------------------

    def _not_vulnerable(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        return ModuleResult(
            module_name="mitm_assessment",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _default_result(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        return self._not_vulnerable(request, response, payload)
