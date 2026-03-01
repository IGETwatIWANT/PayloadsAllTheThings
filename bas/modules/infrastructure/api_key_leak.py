"""
API Key Leakage testing module.

Tests for exposed API keys, tokens, and secrets in JavaScript files, HTML
source, HTTP response headers, error messages, and common API documentation
endpoints.  Pattern-matches AWS access keys (AKIA...), JWT tokens, OAuth
tokens, database connection strings, and provider-specific key formats.

MITRE ATT&CK: T1552 - Unsecured Credentials
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Paths likely to contain JavaScript / source with embedded keys ─────────────
JS_SOURCE_PATHS = [
    "/app.js",
    "/main.js",
    "/bundle.js",
    "/vendor.js",
    "/runtime.js",
    "/polyfills.js",
    "/chunk.js",
    "/config.js",
    "/env.js",
    "/settings.js",
    "/constants.js",
    "/app.min.js",
    "/main.min.js",
    "/dist/main.js",
    "/dist/bundle.js",
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/static/js/app.js",
    "/assets/js/app.js",
    "/assets/application.js",
    "/js/app.js",
    "/js/config.js",
    "/js/main.js",
    "/build/static/js/main.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/webpack.js",
]

# ── HTML / template pages that might embed keys ───────────────────────────────
HTML_PATHS = [
    "/",
    "/index.html",
    "/login",
    "/register",
    "/signup",
    "/dashboard",
    "/admin",
    "/api",
    "/home",
    "/app",
]

# ── API documentation endpoints ───────────────────────────────────────────────
API_DOC_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api/v1/docs",
    "/api/v2/docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/graphql/playground",
    "/altair",
    "/voyager",
    "/__graphql",
]

# ── Error / debug endpoints that may leak keys in output ──────────────────────
ERROR_DEBUG_PATHS = [
    "/error",
    "/debug",
    "/debug/vars",
    "/trace",
    "/_debug",
    "/500",
    "/404",
    "/test",
    "/__test__",
    "/status",
    "/health",
    "/healthcheck",
    "/info",
    "/_info",
    "/version",
    "/config",
    "/env",
    "/_env",
    "/actuator/env",
    "/actuator/configprops",
    "/elmah.axd",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
]

# ── Header names to inspect for leaked keys ────────────────────────────────────
SENSITIVE_HEADERS = [
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-secret-key",
    "x-amz-security-token",
    "x-csrf-token",
    "x-forwarded-authorization",
    "x-real-ip",
    "x-debug-token",
    "x-powered-by",
    "server",
    "set-cookie",
    "www-authenticate",
]

# ── Key / secret patterns ─────────────────────────────────────────────────────
API_KEY_PATTERNS: list[tuple[str, str, str]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID (AKIA*)", "critical"),
    (r"ASIA[0-9A-Z]{16}", "AWS Temporary Access Key (ASIA*)", "critical"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key[\s:=\"']+[A-Za-z0-9/+=]{40}", "AWS Secret Access Key", "critical"),
    (r"(?i)aws[_-]?access[_-]?key[_-]?id[\s:=\"']+AKIA[0-9A-Z]{16}", "AWS Access Key in assignment", "critical"),
    # GCP
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "high"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "medium"),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Access Token", "critical"),
    (r"(?i)\"type\"\s*:\s*\"service_account\"", "GCP Service Account JSON key file", "critical"),
    # Azure
    (r"(?i)(?:DefaultEndpointsProtocol|AccountKey)=[A-Za-z0-9/+=]+;", "Azure Storage Connection String", "critical"),
    (r"(?i)azure[_-]?(?:client|tenant)[_-]?(?:id|secret)\s*[=:]\s*['\"][0-9a-f\-]{36}['\"]",
     "Azure AD Client/Tenant ID or Secret", "high"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token (ghp_)", "critical"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token (gho_)", "critical"),
    (r"ghu_[A-Za-z0-9]{36}", "GitHub User-to-Server Token (ghu_)", "critical"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Server-to-Server Token (ghs_)", "critical"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-Grained PAT", "critical"),
    # GitLab
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token", "critical"),
    # Slack
    (r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "Slack Bot Token (xoxb)", "critical"),
    (r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}", "Slack User Token (xoxp)", "critical"),
    (r"xoxs-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{10,}", "Slack Session Token", "critical"),
    (r"xoxa-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "Slack App Token (xoxa)", "critical"),
    (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Incoming Webhook", "high"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "critical"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key", "high"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", "medium"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key", "critical"),
    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API Key", "critical"),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key (SK)", "high"),
    (r"AC[0-9a-fA-F]{32}", "Twilio Account SID (AC)", "medium"),
    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", "high"),
    (r"(?i)api\.mailgun\.net/v3/[^\s\"']+", "Mailgun API endpoint with domain", "medium"),
    # Square
    (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square Access Token", "critical"),
    (r"sq0csp-[0-9A-Za-z\-_]{43}", "Square OAuth Secret", "critical"),
    # PayPal
    (r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}", "PayPal Access Token (production)", "critical"),
    # Shopify
    (r"shppa_[a-fA-F0-9]{32}", "Shopify Private App Password", "critical"),
    (r"shpat_[a-fA-F0-9]{32}", "Shopify Access Token", "critical"),
    (r"shpca_[a-fA-F0-9]{32}", "Shopify Custom App Token", "critical"),
    (r"shpss_[a-fA-F0-9]{32}", "Shopify Shared Secret", "critical"),
    # Telegram
    (r"[0-9]{5,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", "high"),
    # Discord
    (r"(?i)(?:discord|bot)\s+[A-Za-z0-9\-_.]{50,}", "Discord Bot Token", "high"),
    # JWT
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", "JSON Web Token (JWT)", "high"),
    # OAuth Bearer in source
    (r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}", "OAuth Bearer Token in source", "critical"),
    # Basic Auth in URL
    (r"(?i)https?://[A-Za-z0-9\-_.]+:[A-Za-z0-9\-_.]+@[A-Za-z0-9\-_.]+", "Credentials in URL (Basic Auth)", "critical"),
    # Database connection strings
    (r"(?i)mongodb(?:\+srv)?://[^\s\"'<>]{10,}", "MongoDB Connection String", "critical"),
    (r"(?i)postgres(?:ql)?://[^\s\"'<>]{10,}", "PostgreSQL Connection String", "critical"),
    (r"(?i)mysql://[^\s\"'<>]{10,}", "MySQL Connection String", "critical"),
    (r"(?i)redis://[^\s\"'<>]{10,}", "Redis Connection String", "critical"),
    (r"(?i)amqp://[^\s\"'<>]{10,}", "AMQP/RabbitMQ Connection String", "critical"),
    (r"(?i)mssql://[^\s\"'<>]{10,}", "MSSQL Connection String", "critical"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key Material", "critical"),
    # NPM tokens
    (r"//registry\.npmjs\.org/:_authToken=[^\s\"']+", "NPM Auth Token", "critical"),
    # Datadog
    (r"(?i)(?:dd|datadog)[_-]?api[_-]?key[\s:=\"']+[a-f0-9]{32}", "Datadog API Key", "high"),
    # New Relic
    (r"NRAK-[A-Z0-9]{27}", "New Relic API Key (NRAK)", "high"),
    (r"(?i)new[_-]?relic[_-]?license[_-]?key[\s:=\"']+[a-f0-9]{40}", "New Relic License Key", "high"),
    # Sentry
    (r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+", "Sentry DSN with auth token", "medium"),
    # Firebase
    (r"(?i)apiKey[\s:=\"']+AIza[0-9A-Za-z\-_]{35}", "Firebase API Key in config", "high"),
    # Mapbox
    (r"pk\.[a-zA-Z0-9]{60,}", "Mapbox Public Token", "medium"),
    (r"sk\.[a-zA-Z0-9]{60,}", "Mapbox Secret Token", "high"),
    # Algolia
    (r"(?i)algolia[_-]?api[_-]?key[\s:=\"']+[a-f0-9]{32}", "Algolia API Key", "high"),
    # Cloudinary
    (r"cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9]+", "Cloudinary URL", "high"),
]

COMPILED_KEY_PATTERNS = [(re.compile(p), desc, sev) for p, desc, sev in API_KEY_PATTERNS]


def _all_paths() -> list[str]:
    """Combine all probe paths into a single list."""
    seen: set[str] = set()
    paths: list[str] = []
    for path_list in (JS_SOURCE_PATHS, HTML_PATHS, API_DOC_PATHS, ERROR_DEBUG_PATHS):
        for p in path_list:
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


ALL_PROBE_PATHS = _all_paths()


class APIKeyLeakModule(BaseAttackModule):
    """
    API key leakage testing.

    Probes JavaScript files, HTML source, API documentation endpoints, error
    pages, and debug endpoints for exposed API keys, tokens, credentials, and
    connection strings using 55+ provider-specific regex patterns.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="api_key_leak",
            description=(
                "API key leakage testing – JS files, HTML source, headers, error "
                "pages, API docs; 55+ patterns for AWS, GCP, Azure, GitHub, Slack, "
                "Stripe, JWT, DB connection strings, and more"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1552"],
            mitre_technique_names=["Unsecured Credentials"],
            auth_level_required=AuthorizationLevel.READ_ONLY,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200", "CWE-312", "CWE-522", "CWE-798"],
            tags=["api_key", "credentials", "leakage", "javascript", "secrets", "infrastructure"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("api_key_leak", limit=300)
            if db_payloads:
                return db_payloads

        paths = list(ALL_PROBE_PATHS)

        # Add custom JS paths from options
        extra_js = options.get("js_paths", [])
        paths.extend(p for p in extra_js if p not in paths)

        return paths

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []

        for path in payloads:
            req_id = str(uuid.uuid4())[:8]
            headers: dict[str, str] = {
                "X-BAS-Payload": path,
                "User-Agent": options.get(
                    "user_agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                          "application/javascript,*/*;q=0.8",
            }

            requests.append(AttackRequest(
                request_id=f"apikey-{req_id}",
                target=target,
                method="GET",
                path=path,
                headers=headers,
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", True),
            ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        if response.error:
            return ModuleResult(
                module_name="api_key_leak",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Skip non-success responses
        if response.status_code not in (200, 201, 301, 302, 500):
            return ModuleResult(
                module_name="api_key_leak",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
            )

        findings: list[dict[str, str]] = []
        highest_severity = "info"
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        # ── Check response headers for leaked tokens ──────────────────────
        for header_name in SENSITIVE_HEADERS:
            header_val = response.headers.get(header_name, "")
            if not header_val:
                # Case-insensitive fallback
                for k, v in response.headers.items():
                    if k.lower() == header_name:
                        header_val = v
                        break
            if header_val:
                for pattern, desc, sev in COMPILED_KEY_PATTERNS:
                    match = pattern.search(header_val)
                    if match:
                        findings.append({
                            "source": f"header:{header_name}",
                            "type": desc,
                            "severity": sev,
                            "preview": match.group(0)[:80],
                        })
                        if severity_order.get(sev, 0) > severity_order.get(highest_severity, 0):
                            highest_severity = sev

        # ── Scan response body for key patterns ───────────────────────────
        if body:
            for pattern, desc, sev in COMPILED_KEY_PATTERNS:
                match = pattern.search(body)
                if match:
                    matched_text = match.group(0)
                    # Skip very short matches as likely false positives
                    if len(matched_text) < 8:
                        continue
                    findings.append({
                        "source": f"body:{payload_used}",
                        "type": desc,
                        "severity": sev,
                        "preview": matched_text[:80],
                    })
                    if severity_order.get(sev, 0) > severity_order.get(highest_severity, 0):
                        highest_severity = sev

        if findings:
            # Deduplicate by type
            seen_types: set[str] = set()
            unique_findings: list[dict[str, str]] = []
            for f in findings:
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    unique_findings.append(f)

            evidence_parts = [f"{f['type']} ({f['severity']}) in {f['source']}" for f in unique_findings[:10]]
            return ModuleResult(
                module_name="api_key_leak",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"API keys/secrets found: {'; '.join(evidence_parts)}",
                severity=highest_severity,
                mitre_technique_id="T1552",
                detail={
                    "detection_type": "api_key_pattern",
                    "findings_count": len(unique_findings),
                    "findings": unique_findings[:20],
                },
            )

        # ── Check for API documentation exposure ──────────────────────────
        if any(d in payload_used for d in ("swagger", "api-docs", "openapi", "graphql", "graphiql")):
            doc_indicators = ['"swagger"', '"openapi"', '"paths"', '"info"', '"query"', "GraphiQL",
                              "__schema", "graphql-playground"]
            if response.status_code == 200 and any(ind in body for ind in doc_indicators):
                return ModuleResult(
                    module_name="api_key_leak",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"API documentation exposed at {payload_used} – may reveal endpoints and auth details",
                    severity="medium",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "api_docs_exposure"},
                )

        return ModuleResult(
            module_name="api_key_leak",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
