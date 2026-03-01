"""
HUMINT (Human Intelligence) Social Engineering Reconnaissance module.

Tests for exposed employee data, organizational structure, communication
platforms, phishing attack surface, and social engineering vectors.
Performs passive reconnaissance against authorized targets to assess
human-factor attack surface.

MITRE ATT&CK: T1589 - Gather Victim Identity Information
               T1592 - Gather Victim Host Information
               T1598 - Phishing for Information

For authorized penetration testing and red team engagements only.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import (
    BaseAttackModule,
    ModuleMetadata,
    ModuleResult,
    VulnStatus,
)

# ── Employee Enumeration Paths ───────────────────────────────────────────────

EMPLOYEE_ENUM_PATHS = [
    # Team / About pages
    "/about", "/about-us", "/about/team", "/team", "/our-team",
    "/people", "/staff", "/leadership", "/management", "/executives",
    "/board", "/board-of-directors", "/advisors", "/partners",
    "/directory", "/employee-directory", "/phonebook", "/contact-directory",
    "/org-chart", "/organization", "/hierarchy", "/departments",
    # WordPress user enumeration
    "/wp-json/wp/v2/users", "/wp-json/wp/v2/users?per_page=100",
    "/wp-json/wp/v2/users?per_page=100&page=1",
    "/?author=1", "/?author=2", "/?author=3", "/?author=4", "/?author=5",
    "/author/admin", "/author/administrator",
    # API user endpoints
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/people", "/api/team", "/api/members", "/api/employees",
    "/api/directory", "/api/staff",
    "/graphql",  # GraphQL user queries
    # Feed-based enumeration (author names in feeds)
    "/feed", "/feed/rss", "/feed/atom", "/rss.xml", "/atom.xml",
    "/sitemap.xml", "/sitemap-authors.xml", "/author-sitemap.xml",
    # WebFinger / identity
    "/.well-known/webfinger",
    # Other disclosure
    "/humans.txt", "/CONTRIBUTORS.md", "/AUTHORS", "/AUTHORS.txt",
    "/MAINTAINERS.md", "/CODEOWNERS",
]

# ── Social Profile & Job Posting Paths ───────────────────────────────────────

SOCIAL_PROFILE_PATHS = [
    # Contact pages
    "/contact", "/contact-us", "/get-in-touch", "/reach-us",
    "/support", "/help", "/customer-support",
    # Social media / external profiles
    "/social", "/connect", "/follow-us", "/community",
    # Career / job postings (reveal tech stack, team structure)
    "/careers", "/jobs", "/join-us", "/hiring", "/work-with-us",
    "/open-positions", "/opportunities", "/job-openings",
    "/careers/engineering", "/careers/security", "/careers/it",
    # Press / media (reveal leadership, partnerships)
    "/press", "/newsroom", "/media", "/media-kit", "/press-releases",
    "/news", "/blog", "/blog/authors", "/announcements",
    # Investor / financial (reveal org structure)
    "/investors", "/ir", "/investor-relations", "/annual-report",
    "/sec-filings", "/governance", "/proxy",
    # Legal pages (reveal entity info)
    "/legal", "/privacy", "/privacy-policy", "/terms",
    "/compliance", "/gdpr", "/ccpa",
]

# ── Document & Metadata Exposure ─────────────────────────────────────────────

DOCUMENT_EXPOSURE_PATHS = [
    # Documentation
    "/docs", "/documentation", "/wiki", "/confluence",
    "/knowledge-base", "/kb", "/faq", "/help-center",
    # File repositories
    "/uploads", "/files", "/documents", "/attachments",
    "/downloads", "/resources", "/assets/documents",
    "/public", "/shared", "/internal",
    # Reports / presentations
    "/reports", "/presentations", "/whitepapers",
    "/case-studies", "/datasheets",
    # Org-specific documents
    "/handbook", "/employee-handbook", "/onboarding",
    "/policies", "/procedures", "/sop",
    "/training", "/training-materials",
]

# ── Communication Platform Detection ─────────────────────────────────────────

COMM_PLATFORM_PATHS = [
    # Email infrastructure
    "/autodiscover/autodiscover.xml",
    "/Autodiscover/Autodiscover.xml",
    "/mail", "/webmail", "/email",
    "/owa", "/owa/auth/logon.aspx",
    "/ecp", "/EWS/Exchange.asmx",
    "/Microsoft-Server-ActiveSync",
    "/rpc/rpcproxy.dll",
    "/mapi/nspi/",
    # ADFS / SSO
    "/adfs/ls", "/adfs/ls/IdpInitiatedSignon.aspx",
    "/adfs/services/trust/mex",
    "/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
    # Collaboration
    "/teams", "/slack", "/chat",
    "/jira", "/confluence", "/bitbucket",
    "/gitlab", "/gitea", "/gogs",
    # VPN portals
    "/remote", "/vpn", "/sslvpn",
    "/dana-na/auth/url_default/welcome.cgi",
    "/global-protect/portal/css/login.css",
    "/remote/logincheck",
    "/+CSCOE+/logon.html",
    "/remote/fgt_lang",
    "/ssl-vpn/login.html",
    # Calendar / scheduling
    "/.well-known/caldav", "/.well-known/carddav",
    "/calendar", "/booking", "/schedule",
    # Video conferencing
    "/zoom", "/webex", "/meet",
]

# ── Phishing Surface Assessment ──────────────────────────────────────────────

PHISHING_SURFACE_PATHS = [
    # Login pages (templates for phishing)
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/sso", "/sso/login", "/oauth/authorize",
    "/admin/login", "/admin", "/administrator",
    "/wp-login.php", "/user/login", "/account/login",
    "/portal", "/portal/login",
    # Email security
    "/.well-known/mta-sts.txt",
    "/.well-known/security.txt",
    "/security.txt",
    # Brand assets (for impersonation)
    "/favicon.ico", "/apple-touch-icon.png",
    "/logo.png", "/logo.svg", "/images/logo.png",
    "/assets/images/logo.png", "/static/images/logo.png",
    "/brand", "/style-guide", "/press-kit/logos",
    "/assets/css/main.css", "/static/css/style.css",
]

# ── Regex Patterns ───────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

PHONE_PATTERN = re.compile(
    r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
)

NAME_PATTERN = re.compile(
    r"(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
)

TITLE_PATTERN = re.compile(
    r"(?:CEO|CTO|CFO|CIO|CISO|COO|VP|Director|Manager|Engineer|"
    r"Developer|Analyst|Architect|Lead|Head|Principal|Senior|Junior|"
    r"President|Founder|Co-Founder|Partner|Consultant|Specialist|"
    r"Coordinator|Administrator|Officer|Supervisor)",
    re.IGNORECASE,
)

SOCIAL_LINK_PATTERN = re.compile(
    r"https?://(?:www\.)?(?:linkedin\.com|twitter\.com|x\.com|"
    r"facebook\.com|github\.com|instagram\.com|youtube\.com|"
    r"medium\.com|glassdoor\.com)/[^\s\"'<>]+",
    re.IGNORECASE,
)

TECH_STACK_PATTERN = re.compile(
    r"(?:experience with|proficiency in|knowledge of|familiar with|"
    r"working with|using|stack includes?|technologies?:?)\s*"
    r"([A-Za-z0-9,\s/+#.]+)",
    re.IGNORECASE,
)

# False positive domains to exclude from email harvesting
EMAIL_FP_DOMAINS = {
    "example.com", "example.org", "example.net",
    "schema.org", "w3.org", "xmlns.com",
    "sentry.io", "gravatar.com",
}


class HUMINTModule(BaseAttackModule):
    """
    HUMINT social engineering reconnaissance for authorized red teams.

    Discovers exposed employee information, organizational structure,
    communication platforms, and phishing attack surface to assess
    human-factor security risk.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="humint",
            description=(
                "HUMINT social engineering reconnaissance - discovers exposed "
                "employee data, org structure, communication platforms, and "
                "phishing attack surface"
            ),
            category="recon",
            mitre_technique_ids=["T1589", "T1592", "T1598"],
            mitre_technique_names=[
                "Gather Victim Identity Information",
                "Gather Victim Host Information",
                "Phishing for Information",
            ],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            cwe_ids=["CWE-200", "CWE-213", "CWE-538"],
            tags=[
                "recon", "humint", "social_engineering", "osint",
                "employee_enum", "phishing_recon", "org_structure",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        categories = options.get("humint_categories", [
            "employee_enum", "social_profile", "document_exposure",
            "comm_platform", "phishing_surface",
        ])
        payloads: list[str] = []
        path_map = {
            "employee_enum": EMPLOYEE_ENUM_PATHS,
            "social_profile": SOCIAL_PROFILE_PATHS,
            "document_exposure": DOCUMENT_EXPOSURE_PATHS,
            "comm_platform": COMM_PLATFORM_PATHS,
            "phishing_surface": PHISHING_SURFACE_PATHS,
        }
        for cat in categories:
            if cat in path_map:
                for path in path_map[cat]:
                    payloads.append(f"{cat}|{path}")
        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        for payload in payloads:
            cat, path = payload.split("|", 1)
            req_id = f"humint-{uuid.uuid4().hex[:8]}"

            headers = {
                "X-BAS-Category": cat,
                "X-BAS-Module": "humint",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }

            # GraphQL needs a POST with introspection query
            if path == "/graphql" and cat == "employee_enum":
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=path,
                    body='{"query":"{ __schema { types { name fields { name } } } }"}',
                    content_type="application/json",
                    headers=headers,
                    follow_redirects=True,
                ))
            else:
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=path,
                    headers=headers,
                    follow_redirects=True,
                ))

        return requests

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        cat = request.headers.get("X-BAS-Category", "unknown")

        # Skip non-200 responses
        if response.status_code not in (200, 301, 302):
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"category": cat},
            )

        body = response.body_text
        body_lower = body.lower()

        if cat == "employee_enum":
            return self._analyze_employee_enum(request, response, payload, body, body_lower)
        elif cat == "social_profile":
            return self._analyze_social_profile(request, response, payload, body, body_lower)
        elif cat == "document_exposure":
            return self._analyze_document_exposure(request, response, payload, body, body_lower)
        elif cat == "comm_platform":
            return self._analyze_comm_platform(request, response, payload, body, body_lower)
        elif cat == "phishing_surface":
            return self._analyze_phishing_surface(request, response, payload, body, body_lower)

        return ModuleResult(
            module_name="humint",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"category": cat},
        )

    # ── Category Analyzers ───────────────────────────────────────────────

    def _analyze_employee_enum(
        self, request: AttackRequest, response: AttackResponse,
        payload: str, body: str, body_lower: str,
    ) -> ModuleResult:
        findings: list[str] = []
        detail: dict[str, Any] = {"category": "employee_enum"}

        # Extract emails
        emails = set(EMAIL_PATTERN.findall(body))
        emails = {e for e in emails if e.split("@")[1].lower() not in EMAIL_FP_DOMAINS}
        if emails:
            findings.append(f"Emails found: {len(emails)}")
            detail["emails"] = sorted(emails)[:50]

        # Extract names with titles
        names = set(NAME_PATTERN.findall(body))
        if names:
            findings.append(f"Named individuals: {len(names)}")
            detail["names"] = sorted(names)[:30]

        # Extract titles/roles
        titles = set(TITLE_PATTERN.findall(body))
        if titles:
            findings.append(f"Roles/titles: {', '.join(sorted(titles)[:15])}")
            detail["titles"] = sorted(titles)

        # WordPress user enumeration
        if "wp-json" in request.path:
            try:
                import json as _json
                users = _json.loads(body)
                if isinstance(users, list) and users:
                    wp_users = [u.get("name", u.get("slug", "")) for u in users if isinstance(u, dict)]
                    if wp_users:
                        findings.append(f"WordPress users: {', '.join(wp_users[:10])}")
                        detail["wp_users"] = wp_users
            except Exception:
                pass

        # Author archive detection
        if "author=" in request.path or "/author/" in request.path:
            if response.status_code == 200 and len(body) > 500:
                findings.append("Author archive accessible (user enumeration)")

        # RSS/Atom feed author extraction
        if any(x in request.path for x in ("/feed", "/rss", "/atom")):
            author_matches = re.findall(r"<(?:author|dc:creator)>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</(?:author|dc:creator)>", body)
            if author_matches:
                feed_authors = list(set(author_matches))
                findings.append(f"Feed authors: {', '.join(feed_authors[:10])}")
                detail["feed_authors"] = feed_authors

        # API user listing
        if "/api/" in request.path and response.status_code == 200:
            user_indicators = ["username", "email", "first_name", "last_name", "full_name", "display_name"]
            if any(ind in body_lower for ind in user_indicators):
                findings.append("API endpoint exposes user data")
                detail["api_user_exposure"] = True

        # Sitemap author URLs
        if "sitemap" in request.path.lower():
            author_urls = re.findall(r"<loc>[^<]*author[^<]*</loc>", body, re.IGNORECASE)
            if author_urls:
                findings.append(f"Sitemap author URLs: {len(author_urls)}")
                detail["sitemap_authors"] = len(author_urls)

        if findings:
            severity = "high" if len(emails) > 5 or detail.get("wp_users") else "medium"
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Employee data exposure: {'; '.join(findings)}",
                severity=severity,
                mitre_technique_id="T1589",
                detail=detail,
            )

        return ModuleResult(
            module_name="humint", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail=detail,
        )

    def _analyze_social_profile(
        self, request: AttackRequest, response: AttackResponse,
        payload: str, body: str, body_lower: str,
    ) -> ModuleResult:
        findings: list[str] = []
        detail: dict[str, Any] = {"category": "social_profile"}

        # Social media links
        social_links = set(SOCIAL_LINK_PATTERN.findall(body))
        if social_links:
            platforms: dict[str, int] = {}
            for link in social_links:
                for platform in ["linkedin", "twitter", "x.com", "facebook", "github", "instagram"]:
                    if platform in link.lower():
                        platforms[platform] = platforms.get(platform, 0) + 1
            findings.append(f"Social profiles: {', '.join(f'{k}({v})' for k, v in platforms.items())}")
            detail["social_links"] = sorted(social_links)[:30]
            detail["platforms"] = platforms

        # Job postings - tech stack disclosure
        if any(x in request.path for x in ("/careers", "/jobs", "/hiring", "/join", "/open-positions")):
            tech_matches = TECH_STACK_PATTERN.findall(body)
            if tech_matches:
                findings.append(f"Tech stack disclosed in job postings")
                detail["tech_stack_mentions"] = tech_matches[:20]

            # Common technology keywords in job posts
            tech_keywords = [
                "kubernetes", "docker", "aws", "azure", "gcp", "terraform",
                "jenkins", "gitlab", "jira", "confluence", "slack",
                "python", "java", "golang", "rust", "react", "angular",
                "postgresql", "mongodb", "redis", "elasticsearch",
                "okta", "auth0", "crowdstrike", "splunk", "datadog",
                "palo alto", "fortinet", "cisco", "zscaler",
            ]
            found_tech = [t for t in tech_keywords if t in body_lower]
            if found_tech:
                findings.append(f"Technologies revealed: {', '.join(found_tech)}")
                detail["technologies"] = found_tech

        # Emails on contact pages
        emails = set(EMAIL_PATTERN.findall(body))
        emails = {e for e in emails if e.split("@")[1].lower() not in EMAIL_FP_DOMAINS}
        if emails:
            findings.append(f"Contact emails: {len(emails)}")
            detail["emails"] = sorted(emails)[:20]

        # Phone numbers
        phones = set(PHONE_PATTERN.findall(body))
        if phones:
            findings.append(f"Phone numbers: {len(phones)}")
            detail["phones"] = sorted(phones)[:10]

        # Organizational structure from investor/press pages
        if any(x in request.path for x in ("/investors", "/ir", "/press", "/newsroom")):
            names = set(NAME_PATTERN.findall(body))
            titles = set(TITLE_PATTERN.findall(body))
            if names or titles:
                findings.append(f"Leadership info: {len(names)} names, {len(titles)} titles")
                detail["leadership_names"] = sorted(names)[:20]
                detail["leadership_titles"] = sorted(titles)

        if findings:
            severity = "medium" if detail.get("technologies") else "low"
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Social engineering surface: {'; '.join(findings)}",
                severity=severity,
                mitre_technique_id="T1589",
                detail=detail,
            )

        return ModuleResult(
            module_name="humint", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail=detail,
        )

    def _analyze_document_exposure(
        self, request: AttackRequest, response: AttackResponse,
        payload: str, body: str, body_lower: str,
    ) -> ModuleResult:
        findings: list[str] = []
        detail: dict[str, Any] = {"category": "document_exposure"}

        if response.status_code != 200 or len(body) < 100:
            return ModuleResult(
                module_name="humint", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail=detail,
            )

        # Directory listing detection
        dir_indicators = ["index of", "parent directory", "directory listing", "<pre>", "last modified"]
        if any(ind in body_lower for ind in dir_indicators):
            findings.append("Directory listing exposed")
            detail["directory_listing"] = True

            # Count file types
            file_extensions = re.findall(r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv|zip|bak)\b", body_lower)
            if file_extensions:
                findings.append(f"Downloadable files: {len(file_extensions)}")
                detail["file_types"] = list(set(file_extensions))

        # Document content indicators
        doc_indicators = [
            "confidential", "internal only", "do not distribute",
            "proprietary", "restricted", "draft", "employee",
            "onboarding", "policy", "procedure", "handbook",
        ]
        found_indicators = [ind for ind in doc_indicators if ind in body_lower]
        if found_indicators:
            findings.append(f"Sensitive document indicators: {', '.join(found_indicators)}")
            detail["sensitivity_indicators"] = found_indicators

        # Wiki / knowledge base access
        wiki_indicators = ["wiki", "confluence", "notion", "knowledge base", "documentation"]
        if any(ind in body_lower for ind in wiki_indicators):
            if any(x in body_lower for x in ["login", "sign in", "authenticate"]):
                pass  # Login required
            else:
                findings.append("Knowledge base accessible without authentication")
                detail["unauthenticated_wiki"] = True

        if findings:
            severity = "high" if detail.get("directory_listing") else "medium"
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Document exposure: {'; '.join(findings)}",
                severity=severity,
                mitre_technique_id="T1213",
                detail=detail,
            )

        return ModuleResult(
            module_name="humint", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail=detail,
        )

    def _analyze_comm_platform(
        self, request: AttackRequest, response: AttackResponse,
        payload: str, body: str, body_lower: str,
    ) -> ModuleResult:
        findings: list[str] = []
        detail: dict[str, Any] = {"category": "comm_platform"}

        path_lower = request.path.lower()

        # Exchange / OWA detection
        exchange_indicators = ["outlook web", "owa", "exchange", "microsoft-server-activesync", "ecp"]
        if any(ind in body_lower or ind in path_lower for ind in exchange_indicators):
            if response.status_code in (200, 301, 302):
                findings.append("Microsoft Exchange/OWA detected")
                detail["exchange_detected"] = True
                # Version extraction
                version_match = re.search(r"(?:X-OWA-Version|X-FEServer):\s*([^\r\n]+)", str(response.headers))
                if version_match:
                    detail["exchange_version"] = version_match.group(1)

        # ADFS detection
        if "adfs" in path_lower:
            if response.status_code in (200, 301, 302):
                findings.append("ADFS endpoint accessible")
                detail["adfs_detected"] = True

        # OpenID Configuration
        if "openid-configuration" in path_lower:
            if response.status_code == 200:
                findings.append("OpenID Configuration exposed")
                detail["oidc_exposed"] = True
                # Extract issuer
                issuer_match = re.search(r'"issuer"\s*:\s*"([^"]+)"', body)
                if issuer_match:
                    detail["oidc_issuer"] = issuer_match.group(1)

        # VPN portal detection
        vpn_indicators = {
            "fortinet": ["fortigate", "fortios", "fgt_lang", "remote/logincheck"],
            "palo_alto": ["global-protect", "globalprotect"],
            "cisco_anyconnect": ["cscoe", "webvpn", "anyconnect"],
            "pulse_secure": ["dana-na", "pulse secure"],
            "citrix": ["netscaler", "citrix gateway", "nsg"],
            "sonicwall": ["sonicwall", "sslvpn"],
            "f5": ["f5 networks", "big-ip", "my.policy"],
        }
        for vendor, indicators in vpn_indicators.items():
            if any(ind in body_lower or ind in path_lower for ind in indicators):
                findings.append(f"VPN portal detected: {vendor}")
                detail[f"vpn_{vendor}"] = True

        # Collaboration platform detection
        collab_indicators = {
            "jira": ["jira", "atlassian.net"],
            "confluence": ["confluence"],
            "gitlab": ["gitlab"],
            "bitbucket": ["bitbucket"],
            "slack": ["slack.com/api", "slack workspace"],
            "teams": ["microsoft teams", "teams.microsoft"],
        }
        for platform, indicators in collab_indicators.items():
            if any(ind in body_lower for ind in indicators):
                findings.append(f"Collaboration platform: {platform}")
                detail[f"collab_{platform}"] = True

        # Autodiscover exposure
        if "autodiscover" in path_lower and response.status_code == 200:
            findings.append("Autodiscover endpoint exposed (email config)")
            detail["autodiscover_exposed"] = True

        # Webmail detection
        webmail_indicators = ["roundcube", "squirrelmail", "horde", "zimbra", "rainloop"]
        for wm in webmail_indicators:
            if wm in body_lower:
                findings.append(f"Webmail: {wm}")
                detail[f"webmail_{wm}"] = True

        if findings:
            severity = "high" if detail.get("autodiscover_exposed") or any(k.startswith("vpn_") for k in detail) else "medium"
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Communication platform exposure: {'; '.join(findings)}",
                severity=severity,
                mitre_technique_id="T1592",
                detail=detail,
            )

        return ModuleResult(
            module_name="humint", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail=detail,
        )

    def _analyze_phishing_surface(
        self, request: AttackRequest, response: AttackResponse,
        payload: str, body: str, body_lower: str,
    ) -> ModuleResult:
        findings: list[str] = []
        detail: dict[str, Any] = {"category": "phishing_surface"}

        path_lower = request.path.lower()

        # Login page analysis
        login_keywords = ["login", "signin", "sign-in", "authenticate", "logon"]
        if any(kw in path_lower for kw in login_keywords) and response.status_code == 200:
            findings.append("Login page accessible")
            detail["login_page"] = True

            # Check for anti-phishing measures
            anti_phish_score = 0
            if "captcha" in body_lower or "recaptcha" in body_lower:
                anti_phish_score += 2
                detail["has_captcha"] = True
            if "integrity=" in body_lower:
                anti_phish_score += 1
                detail["has_sri"] = True
            if "content-security-policy" in str(response.headers).lower():
                anti_phish_score += 1
                detail["has_csp"] = True
            if "nonce=" in body_lower:
                anti_phish_score += 1
                detail["has_nonce"] = True
            if "webauthn" in body_lower or "fido" in body_lower:
                anti_phish_score += 2
                detail["has_webauthn"] = True

            # CSRF token presence
            csrf_match = re.search(r'name=["\']?(?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']?\s+value=["\']?([^"\'>\s]+)', body)
            if csrf_match:
                detail["has_csrf"] = True
            else:
                findings.append("Login form missing CSRF protection")
                detail["missing_csrf"] = True

            # Check autocomplete
            if 'autocomplete="off"' not in body_lower and 'autocomplete="new-password"' not in body_lower:
                detail["autocomplete_enabled"] = True

            # Phishing clonability score (0-10, higher = easier to clone)
            clonability = 10 - anti_phish_score
            detail["phishing_clonability_score"] = max(0, clonability)
            findings.append(f"Phishing clonability score: {max(0, clonability)}/10")

        # MTA-STS policy
        if "mta-sts" in path_lower and response.status_code == 200:
            findings.append("MTA-STS policy found")
            if "mode: enforce" in body_lower:
                detail["mta_sts_enforce"] = True
            elif "mode: testing" in body_lower:
                detail["mta_sts_testing"] = True
                findings.append("MTA-STS in testing mode (not enforcing)")
            elif "mode: none" in body_lower:
                detail["mta_sts_none"] = True
                findings.append("MTA-STS mode: none (no protection)")

        # Security.txt analysis
        if "security.txt" in path_lower and response.status_code == 200:
            findings.append("security.txt found")
            detail["security_txt"] = True
            contact_match = re.search(r"Contact:\s*(.+)", body)
            if contact_match:
                detail["security_contact"] = contact_match.group(1).strip()

        # Brand asset exposure
        brand_paths = ["/favicon", "/logo", "/brand", "/style-guide", "/press-kit"]
        if any(bp in path_lower for bp in brand_paths):
            if response.status_code == 200:
                ct = str(response.headers.get("content-type", ""))
                if "image" in ct or "css" in ct or len(body) > 100:
                    findings.append("Brand asset accessible (usable for impersonation)")
                    detail["brand_asset_exposed"] = True

        if findings:
            clonability = detail.get("phishing_clonability_score", 5)
            severity = "high" if clonability >= 7 or detail.get("missing_csrf") else "medium"
            return ModuleResult(
                module_name="humint",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Phishing surface: {'; '.join(findings)}",
                severity=severity,
                mitre_technique_id="T1598",
                detail=detail,
            )

        return ModuleResult(
            module_name="humint", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail=detail,
        )
