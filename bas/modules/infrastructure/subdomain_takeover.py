"""
Subdomain Takeover testing module.

Tests for dangling CNAME records pointing to deprovisioned cloud services
(S3, Heroku, GitHub Pages, Azure, Fastly, Shopify, Surge.sh, Tumblr,
WordPress, Pantheon, Cargo, etc.).  Checks DNS records and matches
response body / status fingerprints against known takeover signatures.

MITRE ATT&CK: T1584 - Compromise Infrastructure
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Takeover fingerprints ──────────────────────────────────────────────────────
# Each entry: (service_name, cname_pattern_regex, body_fingerprints[], http_status, severity)
# Body fingerprints: if any string is found in the response body, the service
# is considered deprovisioned and potentially claimable.

TAKEOVER_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "service": "Amazon S3",
        "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-website[\.-].*\.amazonaws\.com$",
                           r"\.s3\.[\w-]+\.amazonaws\.com$"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Amazon CloudFront",
        "cname_patterns": [r"\.cloudfront\.net$"],
        "fingerprints": ["Bad request", "ERROR: The request could not be satisfied"],
        "status_codes": [403],
        "severity": "high",
    },
    {
        "service": "Amazon Elastic Beanstalk",
        "cname_patterns": [r"\.elasticbeanstalk\.com$"],
        "fingerprints": [],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": [r"\.github\.io$", r"\.githubusercontent\.com$"],
        "fingerprints": ["There isn't a GitHub Pages site here.",
                         "For root URLs (like http://example.com/) you must provide an index.html file"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Heroku",
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokussl\.com$", r"\.herokudns\.com$"],
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app.html",
                         "There's nothing here, yet."],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Azure (various)",
        "cname_patterns": [r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$",
                           r"\.cloudapp\.net$", r"\.azurefd\.net$",
                           r"\.blob\.core\.windows\.net$", r"\.azure-api\.net$",
                           r"\.azurecontainer\.io$", r"\.database\.windows\.net$",
                           r"\.azurecr\.io$", r"\.search\.windows\.net$",
                           r"\.servicebus\.windows\.net$", r"\.visualstudio\.com$",
                           r"\.trafficmanager\.net$"],
        "fingerprints": ["404 Web Site not found", "Azure Web App - Your web app is running and waiting",
                         "Error 404 - Web app not found"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$", r"\.map\.fastly\.net$"],
        "fingerprints": ["Fastly error: unknown domain", "Fastly - Unknown Domain"],
        "status_codes": [500],
        "severity": "high",
    },
    {
        "service": "Shopify",
        "cname_patterns": [r"\.myshopify\.com$"],
        "fingerprints": ["Sorry, this shop is currently unavailable.",
                         "Only one step left!"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Netlify",
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$", r"\.bitballoon\.com$"],
        "fingerprints": ["Not Found - Request ID:", "Page Not Found"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Pantheon",
        "cname_patterns": [r"\.pantheonsite\.io$", r"\.pantheon\.io$"],
        "fingerprints": ["The gods are wise, but do not yet know of this site.",
                         "404 Unknown Site"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Tumblr",
        "cname_patterns": [r"\.tumblr\.com$"],
        "fingerprints": ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "WordPress.com",
        "cname_patterns": [r"\.wordpress\.com$"],
        "fingerprints": ["Do you want to register"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [r"\.surge\.sh$"],
        "fingerprints": ["project not found", "If you're the site owner"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Fly.io",
        "cname_patterns": [r"\.fly\.dev$", r"\.edgeapp\.net$"],
        "fingerprints": ["404 Not Found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Vercel",
        "cname_patterns": [r"\.vercel\.app$", r"\.now\.sh$", r"cname\.vercel-dns\.com$"],
        "fingerprints": ["The deployment could not be found on Vercel"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Render",
        "cname_patterns": [r"\.onrender\.com$"],
        "fingerprints": ["Not Found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Google Cloud Storage",
        "cname_patterns": [r"\.storage\.googleapis\.com$", r"c\.storage\.googleapis\.com$"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Firebase",
        "cname_patterns": [r"\.firebaseapp\.com$", r"\.web\.app$"],
        "fingerprints": ["Site Not Found"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Zendesk",
        "cname_patterns": [r"\.zendesk\.com$"],
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Unbounce",
        "cname_patterns": [r"\.unbounce\.com$", r"unbouncepages\.com$"],
        "fingerprints": ["The requested URL was not found on this server",
                         "The page you're looking for can't be found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Cargo Collective",
        "cname_patterns": [r"\.cargocollective\.com$"],
        "fingerprints": ["404 Not Found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "HubSpot",
        "cname_patterns": [r"\.hubspot\.net$", r"\.hs-sites\.com$"],
        "fingerprints": ["Domain not found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "LaunchRock",
        "cname_patterns": [r"\.launchrock\.com$"],
        "fingerprints": ["It looks like you may have taken a wrong turn"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Desk.com (Salesforce)",
        "cname_patterns": [r"\.desk\.com$"],
        "fingerprints": ["Sorry, We Couldn't Find That Page", "Please try again or head back"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Tilda",
        "cname_patterns": [r"\.tildacdn\.com$"],
        "fingerprints": ["Domain has been assigned", "Please renew your subscription"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Agile CRM",
        "cname_patterns": [r"\.agilecrm\.com$"],
        "fingerprints": ["Sorry, this page is no longer available"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": [r"\.bitbucket\.io$"],
        "fingerprints": ["Repository not found"],
        "status_codes": [404],
        "severity": "high",
    },
    {
        "service": "Feedpress",
        "cname_patterns": [r"redirect\.feedpress\.me$"],
        "fingerprints": ["The feed has not been found"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Ghost",
        "cname_patterns": [r"\.ghost\.io$"],
        "fingerprints": ["The thing you were looking for is no longer here"],
        "status_codes": [404],
        "severity": "medium",
    },
    {
        "service": "Readme.io",
        "cname_patterns": [r"\.readme\.io$"],
        "fingerprints": ["Project doesnt exist... yet!"],
        "status_codes": [404],
        "severity": "medium",
    },
]

# Pre-compile CNAME regex patterns for all services
for _fp in TAKEOVER_FINGERPRINTS:
    _fp["_compiled_cname"] = [re.compile(p, re.IGNORECASE) for p in _fp["cname_patterns"]]


class SubdomainTakeoverModule(BaseAttackModule):
    """
    Subdomain takeover testing.

    Tests for dangling CNAME records pointing to deprovisioned cloud services.
    Checks response bodies and HTTP status codes against known takeover
    fingerprints for 25+ cloud/SaaS providers.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="subdomain_takeover",
            description=(
                "Subdomain takeover testing – dangling CNAME detection for S3, "
                "Heroku, GitHub Pages, Azure, Fastly, Shopify, and 20+ more"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1584"],
            mitre_technique_names=["Compromise Infrastructure"],
            auth_level_required=AuthorizationLevel.READ_ONLY,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200", "CWE-672"],
            tags=["subdomain", "takeover", "dns", "cname", "infrastructure", "cloud"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Payloads are the subdomains to test.  If none are provided via
        options['subdomains'], we test the target itself plus common prefixes.
        """
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("subdomain_takeover", limit=500)
            if db_payloads:
                return db_payloads

        subdomains = options.get("subdomains")
        if subdomains:
            return subdomains

        # Generate common subdomain prefixes to check
        from urllib.parse import urlparse
        parsed = urlparse(target) if "://" in target else None
        domain = parsed.hostname if parsed else target.split(":")[0]

        common_prefixes = [
            "", "www", "app", "api", "dev", "staging", "stage", "stg",
            "test", "testing", "uat", "qa", "demo", "beta", "alpha",
            "cdn", "assets", "static", "media", "img", "images",
            "mail", "email", "smtp", "pop", "imap", "mx",
            "blog", "docs", "documentation", "help", "support", "status",
            "admin", "portal", "dashboard", "panel", "manage",
            "shop", "store", "checkout", "payments", "pay",
            "auth", "login", "sso", "id", "identity", "accounts",
            "go", "link", "links", "redirect", "redir",
            "sandbox", "preview", "canary", "internal",
            "vpn", "remote", "gateway", "gw",
            "ns1", "ns2", "dns", "dns1", "dns2",
        ]

        targets = []
        for prefix in common_prefixes:
            if prefix:
                targets.append(f"http://{prefix}.{domain}")
            else:
                targets.append(f"http://{domain}")

        return targets

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []

        for subdomain_url in payloads:
            req_id = str(uuid.uuid4())[:8]
            requests.append(AttackRequest(
                request_id=f"takeover-{req_id}",
                target=subdomain_url,
                method="GET",
                path="/",
                headers={
                    "X-BAS-Payload": subdomain_url,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
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
            # Connection refused or DNS failure may indicate dangling record
            error_lower = response.error.lower() if response.error else ""
            if any(ind in error_lower for ind in ("name resolution", "getaddrinfo", "dns", "nxdomain")):
                return ModuleResult(
                    module_name="subdomain_takeover",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=0,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"DNS resolution failed for {payload_used} – potential dangling record (NXDOMAIN)",
                    severity="medium",
                    mitre_technique_id="T1584",
                    detail={"detection_type": "dns_failure", "error": response.error},
                )

            return ModuleResult(
                module_name="subdomain_takeover",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=0,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Check body against all fingerprints
        for fp in TAKEOVER_FINGERPRINTS:
            for fingerprint in fp["fingerprints"]:
                if fingerprint.lower() in body.lower():
                    # Additional status code confirmation
                    status_match = (
                        not fp["status_codes"] or response.status_code in fp["status_codes"]
                    )
                    if status_match:
                        return ModuleResult(
                            module_name="subdomain_takeover",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=(
                                f"Subdomain takeover: {fp['service']} – "
                                f"fingerprint matched: '{fingerprint}'"
                            ),
                            severity=fp["severity"],
                            mitre_technique_id="T1584",
                            detail={
                                "detection_type": "fingerprint_match",
                                "service": fp["service"],
                                "fingerprint": fingerprint,
                            },
                        )
                    else:
                        return ModuleResult(
                            module_name="subdomain_takeover",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=(
                                f"Possible subdomain takeover: {fp['service']} – "
                                f"body fingerprint matched but status code {response.status_code} "
                                f"differs from expected {fp['status_codes']}"
                            ),
                            severity="medium",
                            mitre_technique_id="T1584",
                            detail={
                                "detection_type": "partial_fingerprint",
                                "service": fp["service"],
                            },
                        )

        # Check for CNAME-based indicators in response headers
        via_header = response.headers.get("via", response.headers.get("Via", ""))
        server_header = response.headers.get("server", response.headers.get("Server", ""))
        combined_headers = f"{via_header} {server_header}".lower()

        cname_services = [
            ("cloudfront", "Amazon CloudFront"),
            ("herokuapp", "Heroku"),
            ("github", "GitHub Pages"),
            ("fastly", "Fastly"),
            ("netlify", "Netlify"),
            ("vercel", "Vercel"),
        ]
        for keyword, service in cname_services:
            if keyword in combined_headers and response.status_code in (404, 403, 500):
                return ModuleResult(
                    module_name="subdomain_takeover",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Potential takeover: response served by {service} ({keyword} in headers) "
                        f"with status {response.status_code}"
                    ),
                    severity="medium",
                    mitre_technique_id="T1584",
                    detail={"detection_type": "header_hint", "service": service},
                )

        return ModuleResult(
            module_name="subdomain_takeover",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
