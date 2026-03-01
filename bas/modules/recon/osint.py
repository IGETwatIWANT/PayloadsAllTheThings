"""
OSINT (Open Source Intelligence) Reconnaissance module.

Performs comprehensive passive information gathering against authorized targets
using publicly available data sources. Probes for:

- Organizational information exposure (team pages, user APIs, sitemaps)
- Technology stack fingerprinting (CMS detection, headers, cookies)
- Email harvesting from response bodies and contact pages
- Metadata exposure (debug endpoints, server info, profilers)
- Infrastructure disclosure via security headers (CSP, CORS)

Designed for authorized red team engagements where understanding the
target's public-facing attack surface is a critical first step.

MITRE ATT&CK: T1592 - Gather Victim Host Information
                T1595 - Active Scanning
                T1589 - Gather Victim Identity Information
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# =============================================================================
# Probe paths organized by OSINT category
# =============================================================================

OSINT_PROBES: dict[str, list[str]] = {
    # ── Organizational Enumeration ──────────────────────────────────────────
    "org_enum": [
        "/humans.txt",
        "/about",
        "/about-us",
        "/about/team",
        "/team",
        "/our-team",
        "/staff",
        "/people",
        "/leadership",
        "/management",
        "/board",
        "/directors",
        "/executives",
        "/founders",
        "/careers",
        "/jobs",
        "/contact",
        "/contact-us",
        "/sitemap.xml",
        "/robots.txt",
        "/security.txt",
        "/.well-known/security.txt",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/users?per_page=100",
        "/api/users",
        "/api/v1/users",
        "/api/v2/users",
        "/api/v1/members",
        "/api/v1/people",
        "/api/v1/employees",
        "/api/v1/team",
        "/readme.html",
        "/README.md",
        "/CHANGELOG.md",
        "/CONTRIBUTORS.md",
        "/AUTHORS",
        "/AUTHORS.txt",
        "/THANKS.txt",
        "/credits",
        "/press",
        "/newsroom",
        "/investors",
        "/partners",
    ],

    # ── Technology Stack Fingerprinting ─────────────────────────────────────
    "tech_fingerprint": [
        # WordPress
        "/wp-admin",
        "/wp-login.php",
        "/wp-includes/version.php",
        "/wp-includes/js/jquery/jquery.js",
        "/wp-content/",
        "/xmlrpc.php",
        "/wp-cron.php",
        "/wp-json/",
        "/wp-json/wp/v2/",
        "/feed/",
        "/feed/atom/",
        # Joomla
        "/administrator",
        "/administrator/index.php",
        "/index.php",
        "/configuration.php~",
        "/language/en-GB/en-GB.xml",
        "/plugins/system/",
        "/media/system/js/",
        # Drupal
        "/user/login",
        "/node/1",
        "/core/CHANGELOG.txt",
        "/INSTALL.txt",
        "/core/install.php",
        "/core/INSTALL.txt",
        "/modules/",
        "/profiles/",
        "/sites/default/settings.php",
        "/CHANGELOG.txt",
        "/update.php",
        # Django
        "/admin/login",
        "/admin/login/",
        "/static/admin/css/base.css",
        "/static/admin/js/core.js",
        # Ruby on Rails
        "/rails/info/properties",
        "/rails/info/routes",
        "/rails/mailers",
        # Laravel
        "/telescope",
        "/horizon",
        "/nova",
        "/_ignition/health-check",
        # ASP.NET
        "/trace.axd",
        "/elmah.axd",
        "/webresource.axd",
        "/scriptresource.axd",
        # Node.js / Express
        "/package.json",
        "/node_modules/",
        # Java / Spring
        "/actuator",
        "/actuator/info",
        "/actuator/health",
        "/actuator/env",
        "/jolokia/",
        "/jolokia/list",
        # Generic CMS / framework indicators
        "/misc/drupal.js",
        "/skin/frontend/",
        "/magento_version",
        "/admin/config.do",
        "/struts/webconsole.html",
        "/version",
        "/version.txt",
        "/VERSION",
        "/build.txt",
    ],

    # ── Email and Contact Harvesting ────────────────────────────────────────
    "email_harvest": [
        "/contact",
        "/contact-us",
        "/contactus",
        "/about",
        "/about-us",
        "/team",
        "/staff",
        "/people",
        "/support",
        "/help",
        "/feedback",
        "/press",
        "/media",
        "/pr",
        "/investor-relations",
        "/privacy",
        "/privacy-policy",
        "/terms",
        "/legal",
        "/imprint",
        "/impressum",
        "/disclaimer",
    ],

    # ── Metadata and Debug Exposure ─────────────────────────────────────────
    "metadata_exposure": [
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/elmah.axd",
        "/trace.axd",
        "/server-info",
        "/server-status",
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
        "/test.php",
        "/i.php",
        "/_profiler",
        "/_profiler/phpinfo",
        "/_debugbar",
        "/_debugbar/open",
        "/debug",
        "/debug/default/view",
        "/debug/vars",
        "/debug/pprof/",
        "/__debug__",
        "/__debug__/",
        "/console",
        "/webconsole",
        "/.well-known/openid-configuration",
        "/openid-configuration",
        "/oauth/discovery/keys",
        "/metrics",
        "/prometheus/metrics",
        "/health",
        "/healthz",
        "/readyz",
        "/livez",
        "/status",
        "/_status",
        "/status.html",
        "/jmx-console/",
        "/web-console/",
        "/admin-console/",
        "/manager/html",
        "/manager/status",
    ],

    # ── Infrastructure and DNS Disclosure ───────────────────────────────────
    "infra_disclosure": [
        "/",
        "/favicon.ico",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/change-password",
        "/.well-known/dnt-policy.txt",
        "/.well-known/host-meta",
        "/.well-known/host-meta.json",
        "/.well-known/nodeinfo",
        "/.well-known/webfinger",
        "/cdn-cgi/trace",
        "/cdn-cgi/",
        "/_next/data/",
        "/__nextjs_original-stack-frame",
        "/api/v1/health",
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/v1/version",
        "/manifest.json",
        "/asset-manifest.json",
        "/browserconfig.xml",
        "/apple-touch-icon.png",
    ],
}

# Build a flat list of all unique probe paths with categories for quick lookup
_ALL_PROBES: list[tuple[str, str]] = []
_SEEN_PROBES: set[str] = set()
for _cat, _paths in OSINT_PROBES.items():
    for _p in _paths:
        if _p not in _SEEN_PROBES:
            _ALL_PROBES.append((_cat, _p))
            _SEEN_PROBES.add(_p)

# ── Email extraction regex ──────────────────────────────────────────────────
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
MAILTO_PATTERN = re.compile(
    r"mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)

# ── Technology fingerprint patterns in response bodies ──────────────────────
TECH_BODY_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, technology_name, version_capture_hint)
    (r"WordPress\s*([\d.]+)?", "WordPress", "version"),
    (r"wp-content/themes/([a-zA-Z0-9_-]+)", "WordPress Theme", "theme_name"),
    (r"wp-content/plugins/([a-zA-Z0-9_-]+)", "WordPress Plugin", "plugin_name"),
    (r"Joomla!\s*([\d.]+)?", "Joomla", "version"),
    (r"Drupal\s*([\d.]+)?", "Drupal", "version"),
    (r"Drupal\.settings", "Drupal", "js_settings"),
    (r"Django", "Django", "framework"),
    (r"laravel", "Laravel", "framework"),
    (r"symfony", "Symfony", "framework"),
    (r"codeigniter", "CodeIgniter", "framework"),
    (r"express", "Express.js", "framework"),
    (r"next\.js|__next|_next/static", "Next.js", "framework"),
    (r"nuxt|__nuxt", "Nuxt.js", "framework"),
    (r"angular|ng-version", "Angular", "framework"),
    (r"react|reactDOM|__REACT", "React", "library"),
    (r"vue\.js|v-cloak|vue-router", "Vue.js", "framework"),
    (r"jquery[/\-]?([\d.]+)?\.(?:min\.)?js", "jQuery", "version"),
    (r"bootstrap[/\-]?([\d.]+)?", "Bootstrap", "version"),
    (r"powered by ([a-zA-Z0-9\s.]+)", "Powered By", "disclosure"),
    (r"generator\"\s+content=\"([^\"]+)\"", "Meta Generator", "disclosure"),
    (r"Shopify", "Shopify", "platform"),
    (r"Squarespace", "Squarespace", "platform"),
    (r"Wix\.com", "Wix", "platform"),
    (r"Adobe Experience Manager|/content/dam/", "Adobe AEM", "platform"),
    (r"Magento|Mage\.Cookies", "Magento", "platform"),
    (r"PrestaShop", "PrestaShop", "platform"),
    (r"Cloudflare", "Cloudflare", "cdn"),
    (r"Akamai", "Akamai", "cdn"),
    (r"Fastly", "Fastly", "cdn"),
    (r"CloudFront", "AWS CloudFront", "cdn"),
    (r"Varnish", "Varnish", "cache"),
]

COMPILED_TECH_PATTERNS = [
    (re.compile(p, re.IGNORECASE), name, hint) for p, name, hint in TECH_BODY_PATTERNS
]

# ── Cookie-based technology fingerprints ────────────────────────────────────
COOKIE_FINGERPRINTS: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet/JSP)",
    "ASP.NET_SessionId": "ASP.NET",
    ".AspNetCore.": "ASP.NET Core",
    "CFID": "ColdFusion",
    "CFTOKEN": "ColdFusion",
    "ci_session": "CodeIgniter",
    "laravel_session": "Laravel",
    "symfony": "Symfony",
    "rack.session": "Ruby (Rack)",
    "_rails_session": "Ruby on Rails",
    "_session_id": "Ruby on Rails",
    "connect.sid": "Node.js (Express/Connect)",
    "PLAY_SESSION": "Play Framework",
    "SERVERID": "HAProxy",
    "csrftoken": "Django",
    "django_language": "Django",
    "wp-settings-": "WordPress",
    "wordpress_": "WordPress",
    "joomla_user_state": "Joomla",
    "DotNetNukeAnonymous": "DotNetNuke",
    "fe_typo_user": "TYPO3",
    "AWSALB": "AWS Application Load Balancer",
    "AWSALBCORS": "AWS ALB (CORS)",
    "AWSELB": "AWS Elastic Load Balancer",
    "GCLB": "Google Cloud Load Balancer",
    "__cfduid": "Cloudflare",
    "cf_clearance": "Cloudflare",
    "_gh_sess": "GitHub",
    "ROUTEID": "Apache mod_proxy_balancer",
    "BIGipServer": "F5 BIG-IP",
}

# ── Header-based technology / infrastructure fingerprints ───────────────────
HEADER_FINGERPRINTS: dict[str, str] = {
    "server": "Server software disclosure",
    "x-powered-by": "Technology stack disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    "x-generator": "Site generator disclosure",
    "x-drupal-cache": "Drupal cache header",
    "x-drupal-dynamic-cache": "Drupal dynamic cache header",
    "x-varnish": "Varnish cache proxy",
    "x-cache": "Cache layer disclosure",
    "x-cdn": "CDN provider disclosure",
    "x-amz-cf-id": "AWS CloudFront distribution",
    "x-amz-cf-pop": "AWS CloudFront POP location",
    "x-amz-request-id": "AWS S3/API Gateway",
    "x-amz-id-2": "AWS S3 extended request ID",
    "x-azure-ref": "Azure Front Door / CDN",
    "x-ms-request-id": "Azure request identifier",
    "x-goog-generation": "Google Cloud Storage",
    "x-guploader-uploadid": "Google Cloud Storage upload",
    "cf-ray": "Cloudflare Ray ID",
    "cf-cache-status": "Cloudflare cache status",
    "fly-request-id": "Fly.io",
    "x-vercel-id": "Vercel deployment",
    "x-vercel-cache": "Vercel edge cache",
    "x-netlify-request-id": "Netlify",
    "x-heroku-queue-depth": "Heroku",
    "x-render-origin-server": "Render.com",
    "x-railway-request-id": "Railway.app",
    "x-firebase-hosting": "Firebase Hosting",
    "x-fastly-request-id": "Fastly CDN",
    "x-served-by": "Fastly / CDN node",
    "x-timer": "Fastly timer",
    "x-litespeed-cache": "LiteSpeed cache",
    "x-turbo-charged-by": "LiteSpeed",
    "x-sucuri-id": "Sucuri WAF",
    "x-sucuri-cache": "Sucuri cache",
    "x-pingback": "WordPress XML-RPC pingback",
    "link": "WordPress REST API link header",
    "x-redirect-by": "WordPress redirect",
}

# ── CSP / CORS indicators for infrastructure mapping ───────────────────────
INFRA_HEADER_KEYS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "x-frame-options",
    "strict-transport-security",
    "report-to",
    "nel",
    "expect-ct",
]

# ── Organizational / people indicators in HTML ──────────────────────────────
ORG_INDICATORS = [
    re.compile(r"(?:CEO|CTO|CFO|COO|VP|Director|Manager|Engineer|Developer|Founder|President)", re.IGNORECASE),
    re.compile(r"(?:linkedin\.com/(?:in|company)/[a-zA-Z0-9_-]+)", re.IGNORECASE),
    re.compile(r"(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+", re.IGNORECASE),
    re.compile(r"(?:facebook\.com|fb\.com)/[a-zA-Z0-9_.]+", re.IGNORECASE),
    re.compile(r"(?:github\.com)/[a-zA-Z0-9_-]+", re.IGNORECASE),
    re.compile(r"(?:instagram\.com)/[a-zA-Z0-9_.]+", re.IGNORECASE),
]

# ── WordPress user enumeration indicators ──────────────────────────────────
WP_USER_INDICATORS = [
    re.compile(r'"slug"\s*:\s*"([^"]+)"'),
    re.compile(r'"name"\s*:\s*"([^"]+)"'),
]

# ── Robots.txt interesting directives ──────────────────────────────────────
ROBOTS_INTERESTING = re.compile(
    r"(?:Disallow|Allow|Sitemap):\s*(.+)",
    re.IGNORECASE | re.MULTILINE,
)

# ── Version string patterns ───────────────────────────────────────────────
VERSION_PATTERNS = [
    re.compile(r"(?:version|ver|v)[:\s\"'=]*([\d]+\.[\d]+(?:\.[\d]+)?(?:[-.\w]*))", re.IGNORECASE),
    re.compile(r"(?:Apache|Nginx|IIS|LiteSpeed|Caddy)[/\s]*([\d]+\.[\d]+(?:\.[\d]+)?)", re.IGNORECASE),
    re.compile(r"PHP[/\s]*([\d]+\.[\d]+(?:\.[\d]+)?)", re.IGNORECASE),
    re.compile(r"OpenSSL[/\s]*([\d]+\.[\d]+\.[\d]+\w*)", re.IGNORECASE),
]

# ── Security.txt standard fields ──────────────────────────────────────────
SECURITY_TXT_FIELDS = re.compile(
    r"^(Contact|Encryption|Acknowledgments|Preferred-Languages|Canonical|Policy|Hiring|Expires):\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

# Ignore addresses that are almost certainly generic / false positives
_FP_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org", "localhost",
    "sentry.io", "wixpress.com",
    "w3.org", "schema.org",
    "yourcompany.com", "yourdomain.com",
    "company.com", "email.com",
}


class OSINTModule(BaseAttackModule):
    """
    OSINT (Open Source Intelligence) reconnaissance module.

    Performs passive information gathering against authorized targets by
    probing publicly accessible endpoints and analyzing responses for:

    - Organizational data (team members, user listings, social profiles)
    - Technology stack details (CMS, framework, server, CDN)
    - Email addresses and contact information
    - Exposed metadata, debug interfaces, and server diagnostics
    - Infrastructure details leaked via HTTP headers (CSP, CORS, CDN)

    All probes use standard GET requests with no authentication,
    simulating what a public attacker could learn before any exploitation.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="osint",
            description=(
                "OSINT reconnaissance - organizational enumeration, technology "
                "fingerprinting, email harvesting, metadata exposure, and "
                "infrastructure disclosure via public-facing endpoints"
            ),
            category="recon",
            mitre_technique_ids=["T1592", "T1595", "T1589"],
            mitre_technique_names=[
                "Gather Victim Host Information",
                "Active Scanning",
                "Gather Victim Identity Information",
            ],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200", "CWE-213", "CWE-497", "CWE-538"],
            tags=["recon", "osint", "enumeration", "fingerprinting", "information_gathering"],
        )

    # ── Payload generation ──────────────────────────────────────────────────

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Return a list of ``"category|path"`` strings from :data:`OSINT_PROBES`.

        If a PayloadDatabase is available and contains OSINT payloads, those
        are used instead.  Additional paths can be supplied via
        ``options["extra_paths"]`` as a list of ``"category|path"`` strings.
        """
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("osint", limit=500)
            if db_payloads:
                return db_payloads

        payloads: list[str] = []
        seen: set[str] = set()

        # Determine which categories to include
        enabled_categories = options.get("categories", list(OSINT_PROBES.keys()))

        for cat, paths in OSINT_PROBES.items():
            if cat not in enabled_categories:
                continue
            for path in paths:
                key = f"{cat}|{path}"
                if key not in seen:
                    payloads.append(key)
                    seen.add(key)

        # Optional extra paths from caller
        extras: list[str] = options.get("extra_paths", [])
        for extra in extras:
            if extra not in seen:
                payloads.append(extra)
                seen.add(extra)

        return payloads

    # ── Request construction ────────────────────────────────────────────────

    def _build_requests(
        self,
        target: str,
        payloads: list[str],
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        """
        Build one GET request per payload.

        Each payload is ``"category|path"``.  The category is stored in
        ``X-BAS-Category`` so that :meth:`_analyze_response` can dispatch
        to the correct analysis logic.
        """
        requests: list[AttackRequest] = []
        user_agent = options.get(
            "user_agent",
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        for payload in payloads:
            parts = payload.split("|", 1)
            if len(parts) == 2:
                category, path = parts
            else:
                category, path = "general", parts[0]

            req_id = str(uuid.uuid4())[:8]

            headers: dict[str, str] = {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "X-BAS-Payload": payload,
                "X-BAS-Category": category,
            }

            # For API-style endpoints, prefer JSON
            if any(seg in path for seg in ("/api/", "/wp-json/", "/actuator", "/jolokia")):
                headers["Accept"] = "application/json, text/html;q=0.9, */*;q=0.8"

            requests.append(AttackRequest(
                request_id=f"osint-{req_id}",
                target=target,
                method="GET",
                path=path,
                headers=headers,
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", True),
            ))

        return requests

    # ── Response analysis ───────────────────────────────────────────────────

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        """Dispatch analysis based on the probe category."""
        category = request.headers.get("X-BAS-Category", "general")
        payload_used = request.headers.get("X-BAS-Payload", payload)

        # Handle errors early
        if response.error:
            status = VulnStatus.TIMEOUT if response.error == "timeout" else VulnStatus.ERROR
            return ModuleResult(
                module_name="osint",
                target=request.target,
                status=status,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error, "category": category},
            )

        # Skip obviously uninteresting responses
        if response.status_code in (404, 410, 451):
            return self._not_vulnerable(request, response, payload_used, category)

        # Dispatch to category-specific analyzers
        if category == "org_enum":
            return self._analyze_org_enum(request, response, payload_used, category)
        elif category == "tech_fingerprint":
            return self._analyze_tech_fingerprint(request, response, payload_used, category)
        elif category == "email_harvest":
            return self._analyze_email_harvest(request, response, payload_used, category)
        elif category == "metadata_exposure":
            return self._analyze_metadata_exposure(request, response, payload_used, category)
        elif category == "infra_disclosure":
            return self._analyze_infra_disclosure(request, response, payload_used, category)
        else:
            # Generic analysis for unrecognized categories
            return self._analyze_generic(request, response, payload_used, category)

    # ── Category-specific analyzers ─────────────────────────────────────────

    def _analyze_org_enum(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Analyze responses for organizational information leaks."""
        body = response.body_text
        path = request.path
        evidence_parts: list[str] = []
        detail: dict[str, Any] = {"category": category, "detection_type": "org_enum"}

        if response.status_code in (401, 403, 405, 301, 302):
            return self._not_vulnerable(request, response, payload_used, category)

        # ── WordPress user enumeration ──────────────────────────────────
        if "wp-json" in path and "users" in path and response.status_code == 200:
            users_found: list[str] = []
            for pattern in WP_USER_INDICATORS:
                matches = pattern.findall(body)
                users_found.extend(matches)
            if users_found:
                unique_users = list(dict.fromkeys(users_found))[:20]
                evidence_parts.append(f"WordPress user enumeration: {len(unique_users)} user(s) found")
                detail["users"] = unique_users
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="medium",
                    mitre_technique_id="T1589",
                    detail=detail,
                )

        # ── Generic API user listing ────────────────────────────────────
        if "/api/" in path and "user" in path.lower() and response.status_code == 200:
            # Heuristic: if the response is JSON-like and has user-ish keys
            user_keys = ['"username"', '"email"', '"user"', '"login"', '"name"', '"full_name"']
            found_keys = [k for k in user_keys if k in body.lower()]
            if found_keys:
                evidence_parts.append(f"API user listing exposed at {path} (keys: {', '.join(found_keys)})")
                detail["user_keys_found"] = found_keys
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="medium",
                    mitre_technique_id="T1589",
                    detail=detail,
                )

        # ── robots.txt analysis ─────────────────────────────────────────
        if path.rstrip("/") == "/robots.txt" and response.status_code == 200:
            directives = ROBOTS_INTERESTING.findall(body)
            if directives:
                interesting = [d.strip() for d in directives if d.strip() not in ("/", "")]
                if interesting:
                    evidence_parts.append(f"robots.txt exposes {len(interesting)} path(s)")
                    detail["robots_paths"] = interesting[:30]
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="info",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── security.txt analysis ───────────────────────────────────────
        if "security.txt" in path and response.status_code == 200:
            fields = SECURITY_TXT_FIELDS.findall(body)
            if fields:
                field_dict = {k: v.strip() for k, v in fields}
                evidence_parts.append(f"security.txt found with {len(field_dict)} field(s)")
                detail["security_txt"] = field_dict
                # Extract emails from contact fields
                emails = self._extract_emails(body)
                if emails:
                    detail["emails"] = emails
                    evidence_parts.append(f"{len(emails)} email(s) found")
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="info",
                    mitre_technique_id="T1589",
                    detail=detail,
                )

        # ── sitemap.xml ─────────────────────────────────────────────────
        if "sitemap.xml" in path and response.status_code == 200:
            loc_count = body.lower().count("<loc>")
            if loc_count > 0:
                evidence_parts.append(f"sitemap.xml found with {loc_count} URL(s)")
                detail["url_count"] = loc_count
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="info",
                    mitre_technique_id="T1592",
                    detail=detail,
                )

        # ── humans.txt ──────────────────────────────────────────────────
        if "humans.txt" in path and response.status_code == 200 and len(body.strip()) > 10:
            evidence_parts.append("humans.txt found - may contain team/developer names")
            emails = self._extract_emails(body)
            if emails:
                detail["emails"] = emails
                evidence_parts.append(f"{len(emails)} email(s) harvested")
            return ModuleResult(
                module_name="osint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="; ".join(evidence_parts),
                severity="low",
                mitre_technique_id="T1589",
                detail=detail,
            )

        # ── README / CHANGELOG / CONTRIBUTORS ──────────────────────────
        if any(f in path.upper() for f in ("README", "CHANGELOG", "CONTRIBUTORS", "AUTHORS", "THANKS")) \
                and response.status_code == 200 and len(body.strip()) > 20:
            evidence_parts.append(f"Documentation file exposed at {path}")
            emails = self._extract_emails(body)
            if emails:
                detail["emails"] = emails
                evidence_parts.append(f"{len(emails)} email(s) found")
            # Check for version info
            for vp in VERSION_PATTERNS:
                m = vp.search(body)
                if m:
                    detail["version_found"] = m.group(0)
                    evidence_parts.append(f"Version string: {m.group(0)}")
                    break
            return ModuleResult(
                module_name="osint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="; ".join(evidence_parts),
                severity="low",
                mitre_technique_id="T1592",
                detail=detail,
            )

        # ── Generic org / team / people pages ──────────────────────────
        if response.status_code == 200 and len(body) > 100:
            social_profiles: list[str] = []
            roles_found: list[str] = []
            for indicator in ORG_INDICATORS:
                matches = indicator.findall(body)
                if matches:
                    if "linkedin" in indicator.pattern.lower() or "twitter" in indicator.pattern.lower() \
                            or "facebook" in indicator.pattern.lower() or "github" in indicator.pattern.lower() \
                            or "instagram" in indicator.pattern.lower():
                        social_profiles.extend(matches[:10])
                    else:
                        roles_found.extend(matches[:10])

            emails = self._extract_emails(body)

            if social_profiles or roles_found or emails:
                if social_profiles:
                    detail["social_profiles"] = list(dict.fromkeys(social_profiles))[:15]
                    evidence_parts.append(f"{len(detail['social_profiles'])} social profile(s)")
                if roles_found:
                    detail["roles_found"] = list(dict.fromkeys(roles_found))[:10]
                    evidence_parts.append(f"{len(detail['roles_found'])} role/title mention(s)")
                if emails:
                    detail["emails"] = emails
                    evidence_parts.append(f"{len(emails)} email(s)")

                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Organizational info at {path}: " + "; ".join(evidence_parts),
                    severity="low",
                    mitre_technique_id="T1589",
                    detail=detail,
                )

        return self._not_vulnerable(request, response, payload_used, category)

    def _analyze_tech_fingerprint(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Analyze responses for technology stack indicators."""
        body = response.body_text
        path = request.path
        evidence_parts: list[str] = []
        detail: dict[str, Any] = {"category": category, "detection_type": "tech_fingerprint"}

        technologies_found: list[dict[str, str]] = []

        # ── Header-based fingerprinting ─────────────────────────────────
        header_disclosures: list[str] = []
        for header_key, description in HEADER_FINGERPRINTS.items():
            # Case-insensitive header lookup
            value = ""
            for rh_key, rh_val in response.headers.items():
                if rh_key.lower() == header_key.lower():
                    value = rh_val
                    break
            if value:
                header_disclosures.append(f"{header_key}: {value}")
                technologies_found.append({
                    "source": "header",
                    "header": header_key,
                    "value": value,
                    "description": description,
                })

        # ── Cookie-based fingerprinting ─────────────────────────────────
        cookie_disclosures: list[str] = []
        set_cookie = ""
        for hk, hv in response.headers.items():
            if hk.lower() == "set-cookie":
                set_cookie += hv + "; "
        if set_cookie:
            for cookie_name, tech in COOKIE_FINGERPRINTS.items():
                if cookie_name.lower() in set_cookie.lower():
                    cookie_disclosures.append(f"{cookie_name} -> {tech}")
                    technologies_found.append({
                        "source": "cookie",
                        "cookie": cookie_name,
                        "technology": tech,
                    })

        # ── Body-based fingerprinting ───────────────────────────────────
        body_techs: list[str] = []
        if response.status_code == 200 and len(body) > 0:
            for pattern, tech_name, hint in COMPILED_TECH_PATTERNS:
                match = pattern.search(body)
                if match:
                    version_str = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                    label = f"{tech_name}" + (f" {version_str}" if version_str else "")
                    if label not in body_techs:
                        body_techs.append(label)
                        technologies_found.append({
                            "source": "body",
                            "technology": tech_name,
                            "version": version_str,
                            "hint": hint,
                        })

        # ── Version string extraction from body ─────────────────────────
        versions_found: list[str] = []
        if response.status_code == 200 and body:
            for vp in VERSION_PATTERNS:
                matches = vp.findall(body)
                for m in matches[:3]:
                    v_str = m if isinstance(m, str) else m[0] if m else ""
                    if v_str and v_str not in versions_found:
                        versions_found.append(v_str)

        # ── CMS-specific endpoint confirmation ─────────────────────────
        cms_confirmed = ""
        if response.status_code == 200:
            if "wp-admin" in path or "wp-login" in path:
                if "wordpress" in body.lower() or "wp-" in body.lower():
                    cms_confirmed = "WordPress"
            elif path.startswith("/administrator") and "joomla" in body.lower():
                cms_confirmed = "Joomla"
            elif "/user/login" in path and ("drupal" in body.lower() or "Drupal.settings" in body):
                cms_confirmed = "Drupal"
            elif "/admin/login" in path and "django" in body.lower():
                cms_confirmed = "Django Admin"
            elif "/rails/info" in path and response.status_code == 200:
                cms_confirmed = "Ruby on Rails (debug info exposed)"
            elif "/_ignition" in path and response.status_code == 200:
                cms_confirmed = "Laravel (Ignition debug)"
            elif "/telescope" in path and response.status_code == 200 and "telescope" in body.lower():
                cms_confirmed = "Laravel Telescope"
            elif "/horizon" in path and response.status_code == 200 and "horizon" in body.lower():
                cms_confirmed = "Laravel Horizon"
        elif response.status_code in (301, 302):
            # Login redirects still confirm the platform exists
            if "wp-login" in path or "wp-admin" in path:
                cms_confirmed = "WordPress (redirect to login)"
            elif path.startswith("/administrator"):
                cms_confirmed = "Joomla (redirect to login)"

        if cms_confirmed:
            technologies_found.append({"source": "endpoint", "technology": cms_confirmed})
            evidence_parts.append(f"CMS confirmed: {cms_confirmed}")

        # ── Build result ────────────────────────────────────────────────
        if technologies_found:
            detail["technologies"] = technologies_found
            if header_disclosures:
                detail["header_disclosures"] = header_disclosures
                evidence_parts.append(f"{len(header_disclosures)} header disclosure(s)")
            if cookie_disclosures:
                detail["cookie_disclosures"] = cookie_disclosures
                evidence_parts.append(f"{len(cookie_disclosures)} cookie fingerprint(s)")
            if body_techs:
                detail["body_technologies"] = body_techs
                evidence_parts.append(f"Body tech: {', '.join(body_techs[:5])}")
            if versions_found:
                detail["versions"] = versions_found
                evidence_parts.append(f"Version(s): {', '.join(versions_found[:5])}")

            severity = "low"
            if versions_found or cms_confirmed:
                severity = "medium"
            if any("debug" in t.get("technology", "").lower() or "ignition" in t.get("technology", "").lower()
                   for t in technologies_found):
                severity = "high"

            return ModuleResult(
                module_name="osint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Technology fingerprinting at {path}: " + "; ".join(evidence_parts),
                severity=severity,
                mitre_technique_id="T1592",
                detail=detail,
            )

        return self._not_vulnerable(request, response, payload_used, category)

    def _analyze_email_harvest(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Analyze response bodies for email addresses."""
        body = response.body_text
        path = request.path
        detail: dict[str, Any] = {"category": category, "detection_type": "email_harvest"}

        if response.status_code in (401, 403, 405, 301, 302, 404):
            return self._not_vulnerable(request, response, payload_used, category)

        if response.status_code == 200 and len(body) > 0:
            emails = self._extract_emails(body)

            # Also extract mailto links specifically
            mailto_matches = MAILTO_PATTERN.findall(body)
            for em in mailto_matches:
                normalized = em.lower().strip()
                domain = normalized.split("@")[1] if "@" in normalized else ""
                if domain and domain not in _FP_EMAIL_DOMAINS and normalized not in emails:
                    emails.append(normalized)

            if emails:
                detail["emails"] = emails
                detail["email_count"] = len(emails)
                # Extract unique domains
                domains = list({e.split("@")[1] for e in emails if "@" in e})
                detail["email_domains"] = domains

                severity = "low"
                if len(emails) >= 10:
                    severity = "medium"
                if len(emails) >= 25:
                    severity = "high"

                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Email harvesting at {path}: {len(emails)} address(es) across {len(domains)} domain(s)",
                    severity=severity,
                    mitre_technique_id="T1589",
                    detail=detail,
                )

        return self._not_vulnerable(request, response, payload_used, category)

    def _analyze_metadata_exposure(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Analyze responses for exposed metadata, debug interfaces, and server diagnostics."""
        body = response.body_text
        path = request.path
        evidence_parts: list[str] = []
        detail: dict[str, Any] = {"category": category, "detection_type": "metadata_exposure"}

        if response.status_code in (401, 403, 405, 301, 302, 404):
            return self._not_vulnerable(request, response, payload_used, category)

        # ── phpinfo() exposure ──────────────────────────────────────────
        if any(p in path for p in ("phpinfo", "info.php", "i.php", "test.php")):
            if response.status_code == 200 and ("phpinfo()" in body or "PHP Version" in body or "PHP Credits" in body):
                evidence_parts.append("phpinfo() exposed - full server configuration visible")
                detail["php_version"] = ""
                php_ver_match = re.search(r"PHP Version\s*([\d.]+)", body)
                if php_ver_match:
                    detail["php_version"] = php_ver_match.group(1)
                    evidence_parts.append(f"PHP {php_ver_match.group(1)}")
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="high",
                    mitre_technique_id="T1592",
                    detail=detail,
                )

        # ── Apache server-status / server-info ──────────────────────────
        if "server-status" in path or "server-info" in path:
            if response.status_code == 200:
                if "Apache Server Status" in body or "Server Version" in body or "Apache Server Information" in body:
                    evidence_parts.append(f"Apache diagnostic page exposed at {path}")
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="high",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── elmah.axd / trace.axd (.NET diagnostics) ───────────────────
        if "elmah.axd" in path or "trace.axd" in path:
            if response.status_code == 200 and len(body) > 100:
                if "error log" in body.lower() or "trace" in body.lower() or "exception" in body.lower():
                    evidence_parts.append(f".NET diagnostic handler exposed at {path}")
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="high",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── Symfony / Laravel debug toolbar ─────────────────────────────
        if "_profiler" in path or "_debugbar" in path:
            if response.status_code == 200 and len(body) > 50:
                if "profiler" in body.lower() or "debugbar" in body.lower() or "symfony" in body.lower():
                    evidence_parts.append(f"Debug toolbar/profiler exposed at {path}")
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="high",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── Go pprof / debug/vars ───────────────────────────────────────
        if "debug" in path and ("pprof" in path or "vars" in path):
            if response.status_code == 200 and len(body) > 20:
                if "cmdline" in body or "memstats" in body or '"' in body:
                    evidence_parts.append(f"Debug endpoint exposed at {path}")
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="high",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── Spring Boot Actuator ────────────────────────────────────────
        if "actuator" in path:
            if response.status_code == 200:
                actuator_keys = ['"status"', '"activeProfiles"', '"beans"', '"mappings"', '"_links"']
                found_keys = [k for k in actuator_keys if k in body]
                if found_keys:
                    evidence_parts.append(f"Spring Boot Actuator exposed at {path}")
                    detail["actuator_keys"] = found_keys
                    severity = "high" if "activeProfiles" in body or "beans" in body else "medium"
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity=severity,
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── JMX / Web console ───────────────────────────────────────────
        if any(c in path for c in ("jmx-console", "web-console", "admin-console", "manager/html")):
            if response.status_code == 200 and len(body) > 100:
                evidence_parts.append(f"Management console accessible at {path}")
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="high",
                    mitre_technique_id="T1592",
                    detail=detail,
                )

        # ── crossdomain.xml / clientaccesspolicy.xml ────────────────────
        if "crossdomain.xml" in path or "clientaccesspolicy.xml" in path:
            if response.status_code == 200:
                if "allow-access-from" in body.lower() or "cross-domain-policy" in body.lower() \
                        or "cross-domain-access" in body.lower():
                    # Check for overly permissive policies
                    is_wildcard = 'domain="*"' in body
                    severity = "medium" if is_wildcard else "low"
                    evidence_parts.append(f"Cross-domain policy at {path}")
                    if is_wildcard:
                        evidence_parts.append("WARNING: wildcard domain access allowed")
                    detail["wildcard_access"] = is_wildcard
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE if is_wildcard else VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity=severity,
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── Metrics / Prometheus ────────────────────────────────────────
        if "metrics" in path or "prometheus" in path:
            if response.status_code == 200 and len(body) > 50:
                if "# HELP" in body or "# TYPE" in body or "process_" in body:
                    evidence_parts.append(f"Prometheus metrics endpoint exposed at {path}")
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="medium",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        # ── OpenID Configuration ────────────────────────────────────────
        if "openid-configuration" in path and response.status_code == 200:
            if "issuer" in body and "authorization_endpoint" in body:
                evidence_parts.append(f"OpenID Connect configuration exposed at {path}")
                detail["oauth_provider"] = True
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="; ".join(evidence_parts),
                    severity="info",
                    mitre_technique_id="T1592",
                    detail=detail,
                )

        # ── Health / status endpoints (info-level) ──────────────────────
        if any(h in path for h in ("/health", "/healthz", "/readyz", "/livez", "/status")):
            if response.status_code == 200 and len(body.strip()) > 2:
                # Only flag if it reveals internal info beyond just "ok"
                interesting_keys = ['"database"', '"redis"', '"disk"', '"components"',
                                    '"details"', '"uptime"', '"version"', '"hostname"']
                found = [k for k in interesting_keys if k in body.lower()]
                if found:
                    evidence_parts.append(f"Health endpoint with internal details at {path}")
                    detail["health_keys"] = found
                    return ModuleResult(
                        module_name="osint",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="; ".join(evidence_parts),
                        severity="low",
                        mitre_technique_id="T1592",
                        detail=detail,
                    )

        return self._not_vulnerable(request, response, payload_used, category)

    def _analyze_infra_disclosure(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Analyze headers for infrastructure and DNS-related disclosures."""
        body = response.body_text
        path = request.path
        evidence_parts: list[str] = []
        detail: dict[str, Any] = {"category": category, "detection_type": "infra_disclosure"}

        if response.error:
            return self._not_vulnerable(request, response, payload_used, category)

        # ── CSP header analysis for infrastructure mapping ──────────────
        csp_domains: list[str] = []
        for hk, hv in response.headers.items():
            if hk.lower() in ("content-security-policy", "content-security-policy-report-only"):
                # Extract domain references from CSP directives
                domain_pattern = re.compile(
                    r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})"
                )
                domains = domain_pattern.findall(hv)
                csp_domains.extend(domains)

        if csp_domains:
            unique_domains = list(dict.fromkeys(csp_domains))
            detail["csp_domains"] = unique_domains[:30]
            evidence_parts.append(f"CSP reveals {len(unique_domains)} domain(s)")

        # ── CORS header analysis ────────────────────────────────────────
        cors_origin = ""
        for hk, hv in response.headers.items():
            if hk.lower() == "access-control-allow-origin":
                cors_origin = hv
                break
        if cors_origin and cors_origin != "*":
            detail["cors_origin"] = cors_origin
            evidence_parts.append(f"CORS origin: {cors_origin}")

        # ── Technology headers ──────────────────────────────────────────
        tech_headers: dict[str, str] = {}
        for header_key, description in HEADER_FINGERPRINTS.items():
            for rh_key, rh_val in response.headers.items():
                if rh_key.lower() == header_key.lower():
                    tech_headers[header_key] = rh_val
                    break

        if tech_headers:
            detail["technology_headers"] = tech_headers
            evidence_parts.append(f"{len(tech_headers)} technology header(s)")

        # ── Cookie fingerprinting ───────────────────────────────────────
        cookie_techs: list[str] = []
        for hk, hv in response.headers.items():
            if hk.lower() == "set-cookie":
                for cookie_name, tech in COOKIE_FINGERPRINTS.items():
                    if cookie_name.lower() in hv.lower():
                        cookie_techs.append(f"{cookie_name} -> {tech}")
        if cookie_techs:
            detail["cookie_technologies"] = cookie_techs
            evidence_parts.append(f"{len(cookie_techs)} cookie tech fingerprint(s)")

        # ── Cloudflare trace endpoint ───────────────────────────────────
        if "cdn-cgi/trace" in path and response.status_code == 200:
            if "fl=" in body or "colo=" in body or "ip=" in body:
                evidence_parts.append("Cloudflare trace endpoint - edge location and config exposed")
                # Parse trace fields
                trace_fields: dict[str, str] = {}
                for line in body.strip().split("\n"):
                    if "=" in line:
                        k, _, v = line.partition("=")
                        trace_fields[k.strip()] = v.strip()
                detail["cloudflare_trace"] = trace_fields

        # ── manifest.json / asset-manifest.json ─────────────────────────
        if "manifest.json" in path and response.status_code == 200:
            if '"name"' in body or '"short_name"' in body or '"start_url"' in body:
                evidence_parts.append(f"Web app manifest exposed at {path}")
                detail["web_manifest"] = True

        # ── .well-known endpoints ───────────────────────────────────────
        if ".well-known" in path and response.status_code == 200 and len(body.strip()) > 5:
            evidence_parts.append(f"Well-known endpoint exposed at {path}")
            detail["well_known"] = path

        # ── Next.js data ────────────────────────────────────────────────
        if "_next" in path and response.status_code == 200:
            evidence_parts.append("Next.js application detected")
            detail["nextjs"] = True

        # ── Build result ────────────────────────────────────────────────
        if evidence_parts:
            severity = "info"
            if csp_domains and len(csp_domains) > 5:
                severity = "low"
            if tech_headers:
                severity = "low"
            if "cloudflare_trace" in detail:
                severity = "low"

            return ModuleResult(
                module_name="osint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Infrastructure disclosure at {path}: " + "; ".join(evidence_parts),
                severity=severity,
                mitre_technique_id="T1592",
                detail=detail,
            )

        return self._not_vulnerable(request, response, payload_used, category)

    def _analyze_generic(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Fallback analysis for unrecognized categories."""
        body = response.body_text
        detail: dict[str, Any] = {"category": category, "detection_type": "generic"}

        if response.status_code == 200 and len(body) > 50:
            emails = self._extract_emails(body)
            techs: list[str] = []
            for pattern, tech_name, _ in COMPILED_TECH_PATTERNS:
                if pattern.search(body):
                    techs.append(tech_name)

            if emails or techs:
                if emails:
                    detail["emails"] = emails
                if techs:
                    detail["technologies"] = techs
                return ModuleResult(
                    module_name="osint",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Information found at {request.path}: {len(emails)} email(s), {len(techs)} tech(s)",
                    severity="low",
                    mitre_technique_id="T1592",
                    detail=detail,
                )

        return self._not_vulnerable(request, response, payload_used, category)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _extract_emails(self, text: str) -> list[str]:
        """Extract unique, non-false-positive email addresses from text."""
        raw_matches = EMAIL_PATTERN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for email in raw_matches:
            normalized = email.lower().strip()
            if normalized in seen:
                continue
            domain = normalized.split("@")[1] if "@" in normalized else ""
            # Filter out common false positives
            if domain in _FP_EMAIL_DOMAINS:
                continue
            # Skip image/asset filenames that look like emails
            if normalized.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js", ".woff", ".woff2")):
                continue
            seen.add(normalized)
            result.append(normalized)
        return result[:50]  # Cap to avoid noise

    def _not_vulnerable(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload_used: str,
        category: str,
    ) -> ModuleResult:
        """Return a standard NOT_VULNERABLE result."""
        return ModuleResult(
            module_name="osint",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"category": category},
        )
