"""
Credential Phishing Surface Assessment module.

Performs passive analysis of an application's phishing attack surface by:
- Discovering login and authentication pages
- Analyzing authentication flow security (CSRF, autocomplete, enumeration)
- Identifying exposed brand assets usable for impersonation
- Assessing email security posture (MTA-STS, DMARC indicators)
- Evaluating SSO/OAuth configuration exposure

This is a LOW_IMPACT (passive analysis) module — it does NOT send phishing
emails or create cloned pages. It assesses the *potential* for credential
phishing attacks against the target.

For AUTHORIZED red team engagements only.

MITRE ATT&CK:
  T1566 - Phishing
  T1598 - Phishing for Information
  T1078 - Valid Accounts
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Payload constants organized by category
# ---------------------------------------------------------------------------

# 1. Login Page Discovery (20 paths)
LOGIN_DISCOVERY_PATHS = [
    "DISCOVER:/login",
    "DISCOVER:/signin",
    "DISCOVER:/sign-in",
    "DISCOVER:/auth",
    "DISCOVER:/authenticate",
    "DISCOVER:/admin/login",
    "DISCOVER:/wp-login.php",
    "DISCOVER:/user/login",
    "DISCOVER:/sso/login",
    "DISCOVER:/oauth/authorize",
    "DISCOVER:/remote/login",
    "DISCOVER:/vpn/login",
    "DISCOVER:/webmail",
    "DISCOVER:/owa",
    "DISCOVER:/adfs/ls",
    "DISCOVER:/saml/login",
    "DISCOVER:/auth/login",
    "DISCOVER:/accounts/login",
    "DISCOVER:/portal/login",
    "DISCOVER:/api/auth/login",
]

# 2. Authentication Flow Analysis (15 payloads)
AUTH_FLOW_ANALYSIS = [
    # POST with test credentials to check responses
    "AUTH_FLOW:test_creds_admin_admin",
    "AUTH_FLOW:test_creds_admin_password",
    "AUTH_FLOW:test_creds_test_test",
    # Check CSRF protection on login form
    "AUTH_FLOW:csrf_check",
    "AUTH_FLOW:csrf_missing_token",
    # Check autocomplete attribute on password fields
    "AUTH_FLOW:autocomplete_check",
    # Username enumeration via different error messages
    "AUTH_FLOW:enum_valid_user",
    "AUTH_FLOW:enum_invalid_user",
    "AUTH_FLOW:enum_timing_diff",
    # Account lockout testing
    "AUTH_FLOW:lockout_threshold",
    # Rate limiting check
    "AUTH_FLOW:rate_limit_check",
    # Password field type verification
    "AUTH_FLOW:password_field_type",
    # Form action analysis
    "AUTH_FLOW:form_action_check",
    # Login over HTTP (not HTTPS) check
    "AUTH_FLOW:http_login_check",
    # Password policy disclosure
    "AUTH_FLOW:password_policy_check",
]

# 3. Brand Asset Exposure (15 paths)
BRAND_ASSET_EXPOSURE = [
    "BRAND:/favicon.ico",
    "BRAND:/apple-touch-icon.png",
    "BRAND:/assets/images/logo.png",
    "BRAND:/assets/images/logo.svg",
    "BRAND:/img/logo.png",
    "BRAND:/img/logo.svg",
    "BRAND:/static/logo.png",
    "BRAND:/static/images/logo.png",
    "BRAND:/images/logo.png",
    "BRAND:/brand",
    "BRAND:/style-guide",
    "BRAND:/press-kit",
    "BRAND:/static/css/main.css",
    "BRAND:/assets/css/style.css",
    "BRAND:/static/fonts/brand-font.woff2",
]

# 4. Email Security Assessment (10 paths)
EMAIL_SECURITY_PATHS = [
    "EMAIL:/.well-known/mta-sts.txt",
    "EMAIL:/.well-known/security.txt",
    "EMAIL:/autodiscover/autodiscover.xml",
    "EMAIL:/mail",
    "EMAIL:/webmail",
    "EMAIL:/roundcube",
    "EMAIL:/zimbra",
    "EMAIL:/exchange",
    "EMAIL:/.well-known/autoconfig/mail/config-v1.1.xml",
    "EMAIL:/ews/exchange.asmx",
]

# 5. SSO/OAuth Analysis (10 paths)
SSO_OAUTH_ANALYSIS = [
    "SSO:/.well-known/openid-configuration",
    "SSO:/oauth/authorize?response_type=code&client_id=test&redirect_uri=https://example.com",
    "SSO:/saml/metadata",
    "SSO:/adfs/ls",
    "SSO:/auth/realms/master/.well-known/openid-configuration",
    "SSO:/.well-known/oauth-authorization-server",
    "SSO:/oauth/.well-known/openid-configuration",
    "SSO:/auth/realms",
    "SSO:/.well-known/webfinger",
    "SSO:/federation/metadata",
]

# Patterns for detecting login forms in HTML
LOGIN_FORM_PATTERNS = [
    r'<form[^>]*action=["\']([^"\']*(?:login|signin|auth)[^"\']*)["\']',
    r'<input[^>]*type=["\']password["\']',
    r'<input[^>]*name=["\'](?:username|email|user|login)["\']',
    r'<input[^>]*name=["\'](?:password|passwd|pass|pwd)["\']',
    r'<input[^>]*name=["\'](?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']',
]

# Anti-phishing / anti-clone indicators in HTML
ANTI_CLONE_INDICATORS = [
    r'integrity=["\']sha\d+-',
    r'<meta[^>]*content-security-policy',
    r'nonce=["\'][a-zA-Z0-9+/=]+["\']',
    r'captcha',
    r'recaptcha',
    r'hcaptcha',
    r'turnstile',
    r'data-sitekey',
    r'__cf_bm',           # Cloudflare bot management
    r'challenge-platform', # Cloudflare challenge
    r'x-frame-options',
    r'frame-ancestors',
]

# Brand-related CSS patterns
BRAND_CSS_PATTERNS = [
    r'--(?:brand|primary|accent)-color',
    r'#[0-9a-fA-F]{3,8}',  # hex colors
    r'font-family:\s*["\']([^"\']+)["\']',
    r'@font-face\s*\{',
    r'url\(["\']?([^"\')\s]+\.(?:woff2?|ttf|eot|otf))',
]

# Email security indicators
EMAIL_SECURITY_INDICATORS = {
    "mta_sts": ["version: STSv1", "mode: enforce", "mode: testing", "mode: none"],
    "security_txt": ["Contact:", "Expires:", "Encryption:", "Policy:"],
    "spf": ["v=spf1"],
    "dmarc": ["v=DMARC1"],
    "dkim": ["v=DKIM1"],
}


class CredentialPhishingModule(BaseAttackModule):
    """
    Credential Phishing Surface Assessment module.

    Passively analyzes the target's login pages, authentication flows,
    brand asset exposure, email security posture, and SSO configuration
    to assess vulnerability to credential phishing attacks.

    Requires AuthorizationLevel.LOW_IMPACT — all tests are passive
    (GET requests and non-destructive POST probes).
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="credential_phishing",
            description=(
                "Credential phishing surface assessment — login discovery, auth flow "
                "analysis, brand asset exposure, email security, SSO/OAuth analysis"
            ),
            category="auth",
            mitre_technique_ids=["T1566", "T1598", "T1078"],
            mitre_technique_names=[
                "Phishing",
                "Phishing for Information",
                "Valid Accounts",
            ],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            cwe_ids=["CWE-287", "CWE-352"],
            tags=["auth", "phishing", "credential_theft", "social_engineering", "brand_impersonation"],
        )

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Return 70+ payloads across all five categories.

        Options:
            categories (list[str]): limit to specific categories
            extra_login_paths (list[str]): additional login paths to probe
        """
        selected = options.get("categories", [])
        payloads: list[str] = []

        if not selected or "discover" in selected:
            payloads.extend(LOGIN_DISCOVERY_PATHS)
            for extra in options.get("extra_login_paths", []):
                payloads.append(f"DISCOVER:{extra}")

        if not selected or "auth_flow" in selected:
            payloads.extend(AUTH_FLOW_ANALYSIS)

        if not selected or "brand" in selected:
            payloads.extend(BRAND_ASSET_EXPOSURE)

        if not selected or "email" in selected:
            payloads.extend(EMAIL_SECURITY_PATHS)

        if not selected or "sso" in selected:
            payloads.extend(SSO_OAUTH_ANALYSIS)

        return payloads

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def _build_requests(
        self,
        target: str,
        payloads: list[str],
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        """
        Construct requests from payloads.

        Discovery, brand, email, and SSO payloads use GET.
        Auth flow payloads use POST with test credentials or GET for form analysis.
        """
        requests: list[AttackRequest] = []

        for payload in payloads:
            parts = payload.split(":", 1)
            category = parts[0] if len(parts) == 2 else "UNKNOWN"
            value = parts[1] if len(parts) == 2 else payload

            req_id = str(uuid.uuid4())[:8]

            if category == "DISCOVER":
                requests.append(self._build_discovery_request(req_id, target, value, payload))

            elif category == "AUTH_FLOW":
                requests.extend(
                    self._build_auth_flow_requests(req_id, target, value, payload, options)
                )

            elif category == "BRAND":
                requests.append(self._build_brand_request(req_id, target, value, payload))

            elif category == "EMAIL":
                requests.append(self._build_email_request(req_id, target, value, payload))

            elif category == "SSO":
                requests.append(self._build_sso_request(req_id, target, value, payload))

            else:
                requests.append(AttackRequest(
                    request_id=f"phish-{req_id}",
                    target=target,
                    method="GET",
                    path=value,
                    headers={
                        "X-BAS-Attack-Type": category,
                        "X-BAS-Payload": payload,
                    },
                ))

        return requests

    # --- Individual request builders ------------------------------------------------

    def _build_discovery_request(
        self, req_id: str, target: str, path: str, payload: str,
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"phish-disc-{req_id}",
            target=target,
            method="GET",
            path=path,
            headers={
                "X-BAS-Attack-Type": "DISCOVER",
                "X-BAS-Payload": payload,
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            },
            follow_redirects=True,
        )

    def _build_auth_flow_requests(
        self, req_id: str, target: str, value: str, payload: str,
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        """Build auth flow analysis requests (may produce multiple requests)."""
        login_path = options.get("login_path", "/login")
        requests: list[AttackRequest] = []
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "AUTH_FLOW",
            "X-BAS-Payload": payload,
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }

        if value.startswith("test_creds_"):
            # Extract test credentials from payload value
            cred_parts = value.replace("test_creds_", "").split("_", 1)
            username = cred_parts[0] if len(cred_parts) >= 1 else "admin"
            password = cred_parts[1] if len(cred_parts) >= 2 else "admin"
            requests.append(AttackRequest(
                request_id=f"phish-auth-{req_id}",
                target=target,
                method="POST",
                path=login_path,
                headers=headers,
                body=json.dumps({"username": username, "password": password}),
                content_type="application/json",
                follow_redirects=False,
            ))

        elif value == "csrf_check" or value == "csrf_missing_token":
            # GET the login form to check for CSRF token presence
            requests.append(AttackRequest(
                request_id=f"phish-csrf-{req_id}",
                target=target,
                method="GET",
                path=login_path,
                headers=headers,
                follow_redirects=True,
            ))
            if value == "csrf_missing_token":
                # Also POST without CSRF token
                requests.append(AttackRequest(
                    request_id=f"phish-csrf-post-{req_id}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({"username": "test", "password": "test"}),
                    content_type="application/json",
                    follow_redirects=False,
                ))

        elif value.startswith("enum_"):
            if "valid" in value:
                requests.append(AttackRequest(
                    request_id=f"phish-enum-{req_id}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({"username": "admin", "password": "wrongpassword123"}),
                    content_type="application/json",
                    follow_redirects=False,
                ))
            elif "invalid" in value:
                requests.append(AttackRequest(
                    request_id=f"phish-enum-{req_id}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({
                        "username": f"nonexistent_user_{req_id}",
                        "password": "wrongpassword123",
                    }),
                    content_type="application/json",
                    follow_redirects=False,
                ))
            elif "timing" in value:
                # Two requests to compare timing
                requests.append(AttackRequest(
                    request_id=f"phish-enum-t1-{req_id}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({"username": "admin", "password": "wrong"}),
                    content_type="application/json",
                    follow_redirects=False,
                ))
                requests.append(AttackRequest(
                    request_id=f"phish-enum-t2-{req_id}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({
                        "username": f"definitely_not_a_user_{req_id}",
                        "password": "wrong",
                    }),
                    content_type="application/json",
                    follow_redirects=False,
                ))

        elif value == "lockout_threshold":
            # Send a small burst to detect lockout
            for i in range(5):
                requests.append(AttackRequest(
                    request_id=f"phish-lockout-{req_id}-{i}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({"username": "admin", "password": f"wrong_{i}"}),
                    content_type="application/json",
                    follow_redirects=False,
                ))

        elif value == "rate_limit_check":
            # Rapid requests to detect rate limiting
            for i in range(3):
                requests.append(AttackRequest(
                    request_id=f"phish-rate-{req_id}-{i}",
                    target=target,
                    method="POST",
                    path=login_path,
                    headers=headers,
                    body=json.dumps({"username": "test", "password": "test"}),
                    content_type="application/json",
                    follow_redirects=False,
                ))

        else:
            # autocomplete_check, password_field_type, form_action_check,
            # http_login_check, password_policy_check — all fetch the login page
            requests.append(AttackRequest(
                request_id=f"phish-auth-{req_id}",
                target=target,
                method="GET",
                path=login_path,
                headers=headers,
                follow_redirects=True,
            ))

        return requests

    def _build_brand_request(
        self, req_id: str, target: str, path: str, payload: str,
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"phish-brand-{req_id}",
            target=target,
            method="GET",
            path=path,
            headers={
                "X-BAS-Attack-Type": "BRAND",
                "X-BAS-Payload": payload,
            },
            follow_redirects=True,
        )

    def _build_email_request(
        self, req_id: str, target: str, path: str, payload: str,
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"phish-email-{req_id}",
            target=target,
            method="GET",
            path=path,
            headers={
                "X-BAS-Attack-Type": "EMAIL",
                "X-BAS-Payload": payload,
            },
            follow_redirects=True,
        )

    def _build_sso_request(
        self, req_id: str, target: str, path: str, payload: str,
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"phish-sso-{req_id}",
            target=target,
            method="GET",
            path=path,
            headers={
                "X-BAS-Attack-Type": "SSO",
                "X-BAS-Payload": payload,
            },
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        """
        Analyze response based on the payload category.

        - DISCOVER: check if a login page was found, analyze its structure
        - AUTH_FLOW: check CSRF, autocomplete, enumeration, lockout, rate limiting
        - BRAND: check if brand assets are accessible for impersonation
        - EMAIL: check email security configuration
        - SSO: check SSO/OAuth configuration exposure
        """
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")

        # Handle errors
        if response.error == "timeout":
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.TIMEOUT,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        if response.error:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.ERROR,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type, "error": response.error},
            )

        # Route to category-specific analyzer
        if attack_type == "DISCOVER":
            return self._analyze_discovery(request, response, payload)
        elif attack_type == "AUTH_FLOW":
            return self._analyze_auth_flow(request, response, payload)
        elif attack_type == "BRAND":
            return self._analyze_brand(request, response, payload)
        elif attack_type == "EMAIL":
            return self._analyze_email(request, response, payload)
        elif attack_type == "SSO":
            return self._analyze_sso(request, response, payload)
        else:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

    # --- Category-specific analyzers ------------------------------------------------

    def _analyze_discovery(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze a login page discovery result."""
        body = response.body_text
        body_lower = body.lower()

        if response.status_code not in (200, 301, 302):
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "DISCOVER"},
            )

        # Check if this is actually a login page
        has_password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', body, re.I))
        has_login_form = bool(
            re.search(r'<form[^>]*action=["\']([^"\']*(?:login|signin|auth)[^"\']*)["\']', body, re.I)
        )
        has_username_field = bool(
            re.search(r'<input[^>]*name=["\'](?:username|email|user|login)["\']', body, re.I)
        )

        is_login_page = has_password_field or (has_login_form and has_username_field)

        if not is_login_page:
            # Might be a redirect page pointing to login
            if "login" in body_lower or "sign in" in body_lower:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Login-related page found at {request.path} but no login form detected",
                    severity="low",
                    mitre_technique_id="T1566",
                    detail={"attack_type": "DISCOVER", "page_type": "login_related"},
                )
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "DISCOVER"},
            )

        # It is a login page — assess phishing clonability
        clonability_score = self._compute_clonability_score(body)

        # Check for anti-clone measures
        anti_clone_count = sum(
            1 for pattern in ANTI_CLONE_INDICATORS
            if re.search(pattern, body, re.I)
        )

        # Check CSRF on the discovered form
        has_csrf = bool(
            re.search(
                r'<input[^>]*name=["\'](?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']',
                body, re.I,
            )
        )

        # Check autocomplete
        has_autocomplete_off = bool(
            re.search(r'autocomplete=["\'](?:off|new-password)["\']', body, re.I)
        )

        evidence_parts = [
            f"Login page discovered at {request.path}",
            f"Phishing clonability score: {clonability_score}/10",
            f"Anti-clone measures: {anti_clone_count}",
            f"CSRF protection: {'yes' if has_csrf else 'NO'}",
            f"Autocomplete disabled: {'yes' if has_autocomplete_off else 'NO'}",
        ]

        if clonability_score >= 7:
            status = VulnStatus.VULNERABLE
            severity = "high"
        elif clonability_score >= 4:
            status = VulnStatus.POTENTIALLY_VULNERABLE
            severity = "medium"
        else:
            status = VulnStatus.NOT_VULNERABLE
            severity = "low"

        return ModuleResult(
            module_name="credential_phishing",
            target=request.target,
            status=status,
            payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:500],
            elapsed_ms=response.elapsed_ms,
            evidence=" | ".join(evidence_parts),
            severity=severity,
            mitre_technique_id="T1566",
            detail={
                "attack_type": "DISCOVER",
                "is_login_page": True,
                "has_password_field": has_password_field,
                "has_login_form": has_login_form,
                "has_csrf": has_csrf,
                "has_autocomplete_off": has_autocomplete_off,
                "anti_clone_measures": anti_clone_count,
                "clonability_score": clonability_score,
            },
        )

    def _analyze_auth_flow(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze authentication flow security properties."""
        body = response.body_text
        body_lower = body.lower()
        payload_value = payload.split(":", 1)[1] if ":" in payload else payload

        detail: dict[str, Any] = {"attack_type": "AUTH_FLOW", "test": payload_value}

        # ---- CSRF check ----
        if "csrf" in payload_value:
            has_csrf = bool(
                re.search(
                    r'<input[^>]*name=["\'](?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']',
                    body, re.I,
                )
            )
            # For POST without CSRF: if server accepted it (2xx), CSRF is missing
            if request.method == "POST" and response.status_code in (200, 201, 302):
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Login form accepted POST without CSRF token — vulnerable to CSRF-based credential theft",
                    severity="high",
                    mitre_technique_id="T1566",
                    detail={**detail, "csrf_missing": True},
                )
            # For GET: report whether CSRF token found in form
            if not has_csrf:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Login form does not appear to contain CSRF token",
                    severity="medium",
                    mitre_technique_id="T1566",
                    detail={**detail, "csrf_missing": True},
                )
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence="CSRF token present in login form",
                severity="info",
                detail={**detail, "csrf_present": True},
            )

        # ---- Username enumeration ----
        if "enum" in payload_value:
            # Analyze response for enumeration indicators
            enum_indicators = [
                "user not found",
                "invalid username",
                "no account found",
                "username does not exist",
                "email not registered",
                "we couldn't find",
                "account not found",
            ]
            generic_indicators = [
                "invalid credentials",
                "invalid username or password",
                "authentication failed",
                "login failed",
            ]

            has_specific_error = any(ind in body_lower for ind in enum_indicators)
            has_generic_error = any(ind in body_lower for ind in generic_indicators)

            if has_specific_error:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        "Username enumeration possible — server provides specific error "
                        "messages distinguishing valid from invalid usernames"
                    ),
                    severity="medium",
                    mitre_technique_id="T1598",
                    detail={**detail, "enumeration_type": "specific_error"},
                )

            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence="Generic error message — enumeration not directly possible" if has_generic_error else "No clear enumeration signal",
                severity="info",
                detail={**detail, "generic_error": has_generic_error},
            )

        # ---- Lockout check ----
        if "lockout" in payload_value:
            lockout_indicators = [
                "account locked",
                "too many attempts",
                "temporarily locked",
                "account disabled",
                "try again later",
                "exceeded maximum",
            ]
            has_lockout = any(ind in body_lower for ind in lockout_indicators)
            if response.status_code == 429 or has_lockout:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Account lockout mechanism detected",
                    severity="info",
                    detail={**detail, "lockout_detected": True},
                )
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="No account lockout detected after multiple failed attempts",
                severity="medium",
                mitre_technique_id="T1078",
                detail={**detail, "lockout_detected": False},
            )

        # ---- Rate limiting check ----
        if "rate_limit" in payload_value:
            if response.status_code == 429:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Rate limiting active on login endpoint (429 received)",
                    severity="info",
                    detail={**detail, "rate_limited": True},
                )
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="No rate limiting detected on login endpoint — brute force may be possible",
                severity="medium",
                mitre_technique_id="T1078",
                detail={**detail, "rate_limited": False},
            )

        # ---- Autocomplete / password field / form action / HTTP login / password policy ----
        if "autocomplete" in payload_value or "password_field" in payload_value:
            has_autocomplete_off = bool(
                re.search(r'autocomplete=["\'](?:off|new-password)["\']', body, re.I)
            )
            has_password_type = bool(
                re.search(r'<input[^>]*type=["\']password["\']', body, re.I)
            )
            issues: list[str] = []
            if not has_autocomplete_off:
                issues.append("autocomplete not disabled on password field")
            if not has_password_type:
                issues.append("no input with type=password found")

            if issues:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Login form issues: {'; '.join(issues)}",
                    severity="low",
                    mitre_technique_id="T1566",
                    detail={
                        **detail,
                        "has_autocomplete_off": has_autocomplete_off,
                        "has_password_type": has_password_type,
                    },
                )

        if "form_action" in payload_value:
            form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I)
            if form_match:
                action = form_match.group(1)
                # Check if form posts to a different domain
                if action.startswith("http") and request.target not in action:
                    return ModuleResult(
                        module_name="credential_phishing",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload,
                        response_code=response.status_code,
                        response_body_preview=response.body_text[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Login form posts to external domain: {action}",
                        severity="critical",
                        mitre_technique_id="T1566",
                        detail={**detail, "form_action": action},
                    )

        if "http_login" in payload_value:
            # Check if target uses HTTP (not HTTPS) for login
            if request.target.startswith("http://"):
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Login page served over HTTP — credentials transmitted in cleartext",
                    severity="critical",
                    mitre_technique_id="T1566",
                    detail={**detail, "http_login": True},
                )

        if "password_policy" in payload_value:
            policy_patterns = [
                r'(?:password\s+(?:must|should|requires?))',
                r'(?:minimum\s+\d+\s+characters)',
                r'(?:at\s+least\s+\d+)',
            ]
            has_policy = any(re.search(p, body, re.I) for p in policy_patterns)
            if has_policy:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Password policy information disclosed on login page — useful for crafting phishing pages",
                    severity="low",
                    mitre_technique_id="T1598",
                    detail={**detail, "password_policy_disclosed": True},
                )

        # Default for auth flow tests
        return ModuleResult(
            module_name="credential_phishing",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail=detail,
        )

    def _analyze_brand(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze brand asset accessibility for impersonation potential."""
        content_type = response.headers.get("content-type", "").lower()

        if response.status_code != 200:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "BRAND"},
            )

        # Determine if this is an actual brand asset
        is_image = any(t in content_type for t in ["image/", "svg"])
        is_css = "css" in content_type or request.path.endswith(".css")
        is_font = any(t in content_type for t in ["font/", "woff", "ttf", "otf"])
        is_page = "html" in content_type

        if not any([is_image, is_css, is_font, is_page]):
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "BRAND", "content_type": content_type},
            )

        # Check caching headers (easier to steal if cached)
        cache_control = response.headers.get("cache-control", "").lower()
        is_cached = "public" in cache_control or "max-age" in cache_control

        # Check for CORS allowing cross-origin access
        acao = response.headers.get("access-control-allow-origin", "")
        allows_cross_origin = acao == "*" or acao != ""

        # For CSS: analyze for brand colors and fonts
        brand_details: dict[str, Any] = {
            "attack_type": "BRAND",
            "asset_type": "image" if is_image else ("css" if is_css else ("font" if is_font else "page")),
            "content_type": content_type,
            "content_length": len(response.body),
            "is_cached": is_cached,
            "allows_cross_origin": allows_cross_origin,
        }

        if is_css:
            body_text = response.body_text
            colors_found = re.findall(r'#[0-9a-fA-F]{3,8}', body_text)
            fonts_found = re.findall(r'font-family:\s*["\']?([^"\'};]+)', body_text)
            brand_details["colors"] = list(set(colors_found))[:10]
            brand_details["fonts"] = list(set(fonts_found))[:5]

        evidence = (
            f"Brand asset accessible at {request.path} "
            f"({brand_details['asset_type']}, {len(response.body)} bytes)"
        )
        if allows_cross_origin:
            evidence += " — CORS allows cross-origin access"

        return ModuleResult(
            module_name="credential_phishing",
            target=request.target,
            status=VulnStatus.POTENTIALLY_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:200] if is_css or is_page else "(binary asset)",
            elapsed_ms=response.elapsed_ms,
            evidence=evidence,
            severity="low",
            mitre_technique_id="T1566",
            detail=brand_details,
        )

    def _analyze_email(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze email security configuration."""
        body = response.body_text
        body_lower = body.lower()
        detail: dict[str, Any] = {"attack_type": "EMAIL", "path": request.path}

        if response.status_code != 200:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail=detail,
            )

        # MTA-STS analysis
        if "mta-sts" in request.path:
            has_enforce = "mode: enforce" in body_lower
            has_testing = "mode: testing" in body_lower
            has_none = "mode: none" in body_lower

            if has_enforce:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="MTA-STS policy in enforce mode — email transport is secured",
                    severity="info",
                    detail={**detail, "mta_sts_mode": "enforce"},
                )
            elif has_testing:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="MTA-STS policy in testing mode — email interception may be possible",
                    severity="medium",
                    mitre_technique_id="T1566",
                    detail={**detail, "mta_sts_mode": "testing"},
                )
            elif has_none:
                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="MTA-STS policy set to none — no email transport security",
                    severity="high",
                    mitre_technique_id="T1566",
                    detail={**detail, "mta_sts_mode": "none"},
                )

        # security.txt
        if "security.txt" in request.path:
            has_contact = "contact:" in body_lower
            detail["security_txt_found"] = True
            detail["has_contact"] = has_contact
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="security.txt found — organization has vulnerability disclosure process",
                severity="info",
                detail=detail,
            )

        # Autodiscover
        if "autodiscover" in request.path:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    "Autodiscover endpoint exposed — may leak email configuration "
                    "details useful for phishing infrastructure setup"
                ),
                severity="medium",
                mitre_technique_id="T1598",
                detail={**detail, "autodiscover_exposed": True},
            )

        # Webmail interfaces
        webmail_indicators = ["roundcube", "zimbra", "outlook", "exchange", "horde", "squirrelmail"]
        if any(ind in body_lower for ind in webmail_indicators):
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Webmail interface detected at {request.path} — phishing target",
                severity="medium",
                mitre_technique_id="T1566",
                detail={**detail, "webmail_detected": True},
            )

        # Generic email endpoint found
        return ModuleResult(
            module_name="credential_phishing",
            target=request.target,
            status=VulnStatus.POTENTIALLY_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:500],
            elapsed_ms=response.elapsed_ms,
            evidence=f"Email-related endpoint accessible at {request.path}",
            severity="low",
            mitre_technique_id="T1598",
            detail=detail,
        )

    def _analyze_sso(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze SSO/OAuth configuration exposure."""
        body = response.body_text
        body_lower = body.lower()
        detail: dict[str, Any] = {"attack_type": "SSO", "path": request.path}

        if response.status_code != 200:
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail=detail,
            )

        # OpenID Configuration
        if "openid-configuration" in request.path:
            try:
                oidc_config = json.loads(body)
                detail["issuer"] = oidc_config.get("issuer", "")
                detail["authorization_endpoint"] = oidc_config.get("authorization_endpoint", "")
                detail["token_endpoint"] = oidc_config.get("token_endpoint", "")
                detail["grant_types"] = oidc_config.get("grant_types_supported", [])
                detail["scopes"] = oidc_config.get("scopes_supported", [])

                # Check for risky configurations
                issues: list[str] = []
                grant_types = oidc_config.get("grant_types_supported", [])
                if "implicit" in grant_types:
                    issues.append("implicit flow supported (token exposure risk)")
                if "password" in grant_types:
                    issues.append("resource owner password credentials flow supported")

                response_types = oidc_config.get("response_types_supported", [])
                if "token" in response_types:
                    issues.append("direct token response type supported")

                if issues:
                    return ModuleResult(
                        module_name="credential_phishing",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload,
                        response_code=response.status_code,
                        response_body_preview=response.body_text[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=(
                            f"OpenID Configuration exposed with risky settings: "
                            f"{'; '.join(issues)}"
                        ),
                        severity="medium",
                        mitre_technique_id="T1078",
                        detail={**detail, "issues": issues},
                    )

                return ModuleResult(
                    module_name="credential_phishing",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        "OpenID Configuration exposed — reveals SSO infrastructure details "
                        "useful for crafting phishing flows"
                    ),
                    severity="low",
                    mitre_technique_id="T1598",
                    detail=detail,
                )

            except (json.JSONDecodeError, KeyError):
                pass

        # SAML metadata
        if "saml" in request.path.lower() and ("entityid" in body_lower or "saml" in body_lower):
            # Extract entity ID and endpoints from SAML metadata
            entity_match = re.search(r'entityID=["\']([^"\']+)["\']', body)
            if entity_match:
                detail["entity_id"] = entity_match.group(1)

            sso_match = re.search(r'SingleSignOnService[^>]*Location=["\']([^"\']+)["\']', body)
            if sso_match:
                detail["sso_endpoint"] = sso_match.group(1)

            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    "SAML metadata exposed — reveals SSO endpoints and entity IDs "
                    "useful for crafting SSO-based phishing attacks"
                ),
                severity="medium",
                mitre_technique_id="T1598",
                detail=detail,
            )

        # ADFS
        if "adfs" in request.path.lower():
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="ADFS endpoint accessible — Active Directory Federation Services may be targeted",
                severity="medium",
                mitre_technique_id="T1566",
                detail={**detail, "adfs_detected": True},
            )

        # Keycloak realms
        if "realms" in request.path.lower():
            return ModuleResult(
                module_name="credential_phishing",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Keycloak realm endpoint accessible — reveals identity provider configuration",
                severity="low",
                mitre_technique_id="T1598",
                detail={**detail, "keycloak_detected": True},
            )

        # Generic SSO endpoint found
        return ModuleResult(
            module_name="credential_phishing",
            target=request.target,
            status=VulnStatus.POTENTIALLY_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:500],
            elapsed_ms=response.elapsed_ms,
            evidence=f"SSO/OAuth endpoint accessible at {request.path}",
            severity="low",
            mitre_technique_id="T1598",
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_clonability_score(self, html: str) -> int:
        """
        Compute a 0-10 score for how easily the login page can be cloned
        for phishing.

        Higher score = easier to clone (more vulnerable to phishing).
        """
        score = 5  # baseline: most pages are moderately clonable

        html_lower = html.lower()

        # Factors that make cloning EASIER (increase score)
        # Simple static form
        if html_lower.count("<script") < 3:
            score += 1
        # No SRI on scripts/styles
        if "integrity=" not in html_lower:
            score += 1
        # No CSP meta tag
        if "content-security-policy" not in html_lower:
            score += 1
        # No nonce-based CSP
        if "nonce=" not in html_lower:
            score += 1

        # Factors that make cloning HARDER (decrease score)
        # Has CAPTCHA
        if any(cap in html_lower for cap in ["captcha", "recaptcha", "hcaptcha", "turnstile"]):
            score -= 2
        # Has WebAuthn/FIDO
        if "webauthn" in html_lower or "fido" in html_lower:
            score -= 1
        # Uses complex JavaScript frameworks
        if any(fw in html_lower for fw in ["__next", "__nuxt", "react-root", "ng-app", "vue-app"]):
            score -= 1
        # Dynamic token generation
        if re.search(r'<meta[^>]*name=["\']csrf', html, re.I):
            score -= 1

        # Clamp to 0-10
        return max(0, min(10, score))
