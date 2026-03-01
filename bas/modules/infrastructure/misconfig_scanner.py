"""
Security Misconfiguration scanner module.

Tests for dangerous or missing HTTP security headers (CSP, HSTS,
X-Frame-Options, X-Content-Type-Options, Permissions-Policy),
server information disclosure, default error pages, debug modes,
exposed admin panels, directory listings, and backup files.

MITRE ATT&CK: T1592 - Gather Victim Host Information
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Required security headers and expected values ─────────────────────────────
# (header_name, missing_desc, severity_if_missing, bad_value_regex, bad_desc)
SECURITY_HEADERS: list[dict[str, Any]] = [
    {
        "header": "Strict-Transport-Security",
        "missing_desc": "HSTS header missing – susceptible to protocol downgrade attacks",
        "missing_severity": "medium",
        "good_pattern": r"max-age=\d{5,}",  # at least 10000 seconds
        "bad_values": [
            (r"max-age=0", "HSTS max-age is 0 – effectively disabled", "medium"),
            (r"max-age=[0-9]{1,3}$", "HSTS max-age too short (< 1000s)", "medium"),
        ],
    },
    {
        "header": "Content-Security-Policy",
        "missing_desc": "CSP header missing – no XSS mitigation at browser level",
        "missing_severity": "medium",
        "good_pattern": None,
        "bad_values": [
            (r"unsafe-inline", "CSP allows unsafe-inline – weakened XSS protection", "medium"),
            (r"unsafe-eval", "CSP allows unsafe-eval – weakened XSS protection", "medium"),
            (r"\*", "CSP uses wildcard (*) source – overly permissive", "medium"),
            (r"data:", "CSP allows data: URIs – potential XSS vector", "low"),
        ],
    },
    {
        "header": "X-Frame-Options",
        "missing_desc": "X-Frame-Options missing – susceptible to clickjacking",
        "missing_severity": "medium",
        "good_pattern": r"(?i)^(DENY|SAMEORIGIN)$",
        "bad_values": [
            (r"(?i)ALLOW-FROM", "X-Frame-Options uses deprecated ALLOW-FROM", "low"),
        ],
    },
    {
        "header": "X-Content-Type-Options",
        "missing_desc": "X-Content-Type-Options missing – MIME type sniffing possible",
        "missing_severity": "low",
        "good_pattern": r"(?i)nosniff",
        "bad_values": [],
    },
    {
        "header": "X-XSS-Protection",
        "missing_desc": "X-XSS-Protection missing (deprecated but still useful for older browsers)",
        "missing_severity": "info",
        "good_pattern": r"1;\s*mode=block",
        "bad_values": [
            (r"^0$", "X-XSS-Protection explicitly disabled", "low"),
        ],
    },
    {
        "header": "Referrer-Policy",
        "missing_desc": "Referrer-Policy missing – full URL may leak in Referer header",
        "missing_severity": "low",
        "good_pattern": r"(?i)(no-referrer|strict-origin|same-origin|strict-origin-when-cross-origin)",
        "bad_values": [
            (r"(?i)unsafe-url", "Referrer-Policy set to unsafe-url – full URL leaked", "medium"),
        ],
    },
    {
        "header": "Permissions-Policy",
        "missing_desc": "Permissions-Policy (Feature-Policy) missing – browser features unrestricted",
        "missing_severity": "low",
        "good_pattern": None,
        "bad_values": [],
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "missing_desc": "COOP header missing – Spectre-class side-channel attacks not mitigated",
        "missing_severity": "low",
        "good_pattern": r"(?i)same-origin",
        "bad_values": [],
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "missing_desc": "CORP header missing – resources may be loaded cross-origin",
        "missing_severity": "low",
        "good_pattern": r"(?i)(same-origin|same-site)",
        "bad_values": [],
    },
    {
        "header": "Cross-Origin-Embedder-Policy",
        "missing_desc": "COEP header missing – cross-origin isolation not enforced",
        "missing_severity": "info",
        "good_pattern": r"(?i)require-corp",
        "bad_values": [],
    },
]

# ── Headers that leak server information ──────────────────────────────────────
INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "X-Cache",
    "X-Request-Id",
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-Litespeed-Cache",
    "X-Turbo-Charged-By",
]

# ── Admin panel and management paths ──────────────────────────────────────────
ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/admin/login",
    "/admin/dashboard",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/manager",
    "/manager/html",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/pma",
    "/adminer.php",
    "/adminer",
    "/cpanel",
    "/webmail",
    "/cPanel",
    "/_admin",
    "/admin.php",
    "/user/login",
    "/console",
    "/jmx-console",
    "/web-console",
    "/solr/",
    "/solr/admin",
    "/kibana",
    "/jenkins",
    "/jenkins/login",
    "/grafana",
    "/grafana/login",
    "/nagios",
    "/cacti",
    "/zabbix",
]

# ── Directory listing detection paths ─────────────────────────────────────────
DIRECTORY_LISTING_PATHS = [
    "/",
    "/images/",
    "/img/",
    "/assets/",
    "/uploads/",
    "/files/",
    "/documents/",
    "/media/",
    "/static/",
    "/css/",
    "/js/",
    "/scripts/",
    "/fonts/",
    "/data/",
    "/backup/",
    "/backups/",
    "/temp/",
    "/tmp/",
    "/logs/",
    "/log/",
    "/config/",
    "/includes/",
    "/inc/",
    "/lib/",
    "/cgi-bin/",
]

# ── Backup / leftover files ───────────────────────────────────────────────────
BACKUP_FILE_PATHS = [
    "/index.html.bak",
    "/index.php.bak",
    "/index.php~",
    "/index.php.old",
    "/index.php.save",
    "/index.php.swp",
    "/index.php.swo",
    "/.index.php.swp",
    "/config.php.bak",
    "/config.php.old",
    "/config.php~",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/web.config.bak",
    "/web.config.old",
    "/.htaccess.bak",
    "/.htaccess.old",
    "/database.sql",
    "/dump.sql",
    "/backup.sql",
    "/db.sql",
    "/data.sql",
    "/backup.tar.gz",
    "/backup.zip",
    "/backup.tar",
    "/site.zip",
    "/www.zip",
    "/public.zip",
    "/archive.zip",
    "/latest.tar.gz",
    "/deploy.tar.gz",
    "/.git.tar.gz",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
    "/.DS_Store",
    "/Thumbs.db",
    "/desktop.ini",
    # Common editor swap files
    "/.swp",
    "/.swo",
    "/~",
]

# ── Debug mode indicators in response body ────────────────────────────────────
DEBUG_INDICATORS: list[tuple[str, str, str]] = [
    ("Traceback (most recent call last)", "Python debug traceback exposed", "high"),
    ("DJANGO_SETTINGS_MODULE", "Django debug mode enabled", "high"),
    ("Debug mode: on", "Debug mode explicitly enabled", "high"),
    ("Werkzeug Debugger", "Werkzeug interactive debugger exposed", "critical"),
    ("WEB_DEBUG", "Web debug flag enabled", "high"),
    ("Laravel", "Laravel debug/error page exposed", "high"),
    ("Symfony Exception", "Symfony debug exception page", "high"),
    ("Whoops!", "Whoops error handler (Laravel/PHP) exposed", "high"),
    ("Stack Trace:", "Stack trace exposed in error page", "high"),
    ("at java.", "Java stack trace exposed", "medium"),
    ("at org.apache.", "Apache/Java stack trace exposed", "medium"),
    ("Microsoft .NET Framework", ".NET error page with framework info", "medium"),
    ("Application Trace", "Rails application trace exposed", "high"),
    ("Action Controller: Exception caught", "Rails exception page exposed", "high"),
    ("showsource", "PHP show source enabled", "high"),
    ("Parse error:", "PHP parse error exposed", "medium"),
    ("Fatal error:", "PHP fatal error exposed", "medium"),
    ("Warning:", "PHP warning exposed", "low"),
    ("Notice:", "PHP notice exposed", "low"),
    ("SQLSTATE", "SQL error state exposed in response", "high"),
    ("You are running Vue in development mode", "Vue.js development mode", "low"),
    ("React Developer Tools", "React development build", "low"),
    ("webpack-dev-server", "Webpack dev server in production", "medium"),
    ("sourceMappingURL", "JavaScript source map available", "low"),
]

# ── Default error page fingerprints ───────────────────────────────────────────
DEFAULT_ERROR_PAGES: list[tuple[str, str, str]] = [
    ("Apache/", "Default Apache error page – version disclosed", "low"),
    ("nginx/", "Default nginx error page – version disclosed", "low"),
    ("Microsoft-IIS/", "Default IIS error page – version disclosed", "low"),
    ("Apache Tomcat/", "Default Tomcat error page – version disclosed", "medium"),
    ("Jetty(", "Default Jetty error page – version disclosed", "low"),
    ("LiteSpeed", "LiteSpeed server default page", "low"),
    ("Caddy", "Caddy server default page", "low"),
    ("Welcome to nginx!", "Default nginx welcome page – not configured", "medium"),
    ("It works!", "Default Apache welcome page – not configured", "medium"),
    ("IIS Windows Server", "Default IIS welcome page", "medium"),
    ("Apache2 Ubuntu Default Page", "Default Apache Ubuntu page", "medium"),
    ("Test Page for the Apache", "Default Apache test page", "medium"),
    ("Welcome to CentOS", "Default CentOS page", "medium"),
]


def _all_paths() -> list[str]:
    """Combine all path lists; use the main target root for header checks."""
    seen: set[str] = set()
    paths: list[str] = []
    # Start with root for header analysis
    for p in ["/"]:
        if p not in seen:
            seen.add(p)
            paths.append(p)
    for path_list in (ADMIN_PATHS, DIRECTORY_LISTING_PATHS, BACKUP_FILE_PATHS):
        for p in path_list:
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


ALL_MISCONFIG_PATHS = _all_paths()


class MisconfigScanner(BaseAttackModule):
    """
    Security misconfiguration scanner.

    Tests for missing or weak HTTP security headers, server info disclosure,
    default error pages, debug modes, exposed admin panels, directory listings,
    and backup files.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="misconfig_scanner",
            description=(
                "Security misconfiguration scanner – HTTP security headers, server "
                "info disclosure, debug modes, admin panels, directory listings, "
                "backup files"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1592"],
            mitre_technique_names=["Gather Victim Host Information"],
            auth_level_required=AuthorizationLevel.READ_ONLY,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-16", "CWE-200", "CWE-209", "CWE-215", "CWE-352", "CWE-693"],
            tags=["misconfiguration", "headers", "disclosure", "admin", "backup", "infrastructure"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("misconfig_scanner", limit=300)
            if db_payloads:
                return db_payloads
        return ALL_MISCONFIG_PATHS

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
            }

            requests.append(AttackRequest(
                request_id=f"misconfig-{req_id}",
                target=target,
                method="GET",
                path=path,
                headers=headers,
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", False),
            ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        if response.error:
            return ModuleResult(
                module_name="misconfig_scanner",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        findings: list[dict[str, str]] = []
        highest_severity = "info"
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        def _update_severity(sev: str) -> None:
            nonlocal highest_severity
            if severity_order.get(sev, 0) > severity_order.get(highest_severity, 0):
                highest_severity = sev

        # ═══════════════════════════════════════════════════════════════════
        # Header analysis (primarily on root path "/")
        # ═══════════════════════════════════════════════════════════════════
        if payload_used == "/":
            # Build case-insensitive header lookup
            resp_headers_lower: dict[str, str] = {
                k.lower(): v for k, v in response.headers.items()
            }

            # Check required security headers
            for hdr_check in SECURITY_HEADERS:
                header_name = hdr_check["header"]
                header_val = resp_headers_lower.get(header_name.lower(), "")

                if not header_val:
                    findings.append({
                        "type": "missing_header",
                        "header": header_name,
                        "desc": hdr_check["missing_desc"],
                        "severity": hdr_check["missing_severity"],
                    })
                    _update_severity(hdr_check["missing_severity"])
                else:
                    # Check for bad values
                    for bad_re, bad_desc, bad_sev in hdr_check.get("bad_values", []):
                        if re.search(bad_re, header_val):
                            findings.append({
                                "type": "weak_header",
                                "header": header_name,
                                "value": header_val[:200],
                                "desc": bad_desc,
                                "severity": bad_sev,
                            })
                            _update_severity(bad_sev)

            # Server information disclosure headers
            for hdr_name in INFO_DISCLOSURE_HEADERS:
                val = resp_headers_lower.get(hdr_name.lower(), "")
                if val:
                    sev = "low"
                    # Version numbers are more concerning
                    if re.search(r"\d+\.\d+", val):
                        sev = "medium"
                    if "debug" in hdr_name.lower():
                        sev = "high"
                    findings.append({
                        "type": "info_disclosure",
                        "header": hdr_name,
                        "value": val[:200],
                        "desc": f"{hdr_name} header exposes: {val[:100]}",
                        "severity": sev,
                    })
                    _update_severity(sev)

            # Check for cookie security flags
            set_cookie = resp_headers_lower.get("set-cookie", "")
            if set_cookie:
                cookie_issues = []
                if "secure" not in set_cookie.lower():
                    cookie_issues.append("Secure flag missing")
                if "httponly" not in set_cookie.lower():
                    cookie_issues.append("HttpOnly flag missing")
                if "samesite" not in set_cookie.lower():
                    cookie_issues.append("SameSite attribute missing")
                if cookie_issues:
                    findings.append({
                        "type": "cookie_flags",
                        "desc": f"Cookie security issues: {', '.join(cookie_issues)}",
                        "severity": "medium",
                    })
                    _update_severity("medium")

        # ═══════════════════════════════════════════════════════════════════
        # Admin panel detection
        # ═══════════════════════════════════════════════════════════════════
        if payload_used in ADMIN_PATHS:
            if response.status_code == 200:
                admin_indicators = [
                    "login", "password", "username", "sign in", "log in",
                    "admin", "dashboard", "control panel", "management",
                    "phpmyadmin", "adminer", "phpMyAdmin",
                ]
                body_lower = body.lower()
                if any(ind in body_lower for ind in admin_indicators):
                    sev = "high"
                    if any(a in payload_used for a in ("/phpmyadmin", "/adminer", "/jmx-console",
                                                        "/web-console", "/solr", "/jenkins",
                                                        "/kibana", "/grafana")):
                        sev = "critical"
                    findings.append({
                        "type": "admin_panel",
                        "path": payload_used,
                        "desc": f"Admin panel accessible at {payload_used}",
                        "severity": sev,
                    })
                    _update_severity(sev)
            elif response.status_code in (401, 403):
                # Protected but present – information disclosure
                findings.append({
                    "type": "admin_panel_protected",
                    "path": payload_used,
                    "desc": f"Admin panel exists at {payload_used} (HTTP {response.status_code})",
                    "severity": "low",
                })
                _update_severity("low")

        # ═══════════════════════════════════════════════════════════════════
        # Directory listing detection
        # ═══════════════════════════════════════════════════════════════════
        if payload_used in DIRECTORY_LISTING_PATHS:
            dir_listing_indicators = [
                "Index of /", "Directory listing for", "Parent Directory",
                "<title>Index of", "[To Parent Directory]",
                "Directory Listing For", "ListBucketResult",
            ]
            if response.status_code == 200:
                for indicator in dir_listing_indicators:
                    if indicator in body:
                        findings.append({
                            "type": "directory_listing",
                            "path": payload_used,
                            "desc": f"Directory listing enabled at {payload_used}",
                            "severity": "medium",
                        })
                        _update_severity("medium")
                        break

        # ═══════════════════════════════════════════════════════════════════
        # Backup / leftover file detection
        # ═══════════════════════════════════════════════════════════════════
        if payload_used in BACKUP_FILE_PATHS:
            if response.status_code == 200 and len(body.strip()) > 0:
                # Check it is not just a generic error page
                if not any(ep in body for ep in ("Page Not Found", "404", "not found")):
                    sev = "medium"
                    if any(ext in payload_used for ext in (".sql", ".tar", ".zip", ".gz")):
                        sev = "critical"
                    elif any(ext in payload_used for ext in (".bak", ".old", ".swp", ".swo", "~")):
                        sev = "high"
                    findings.append({
                        "type": "backup_file",
                        "path": payload_used,
                        "desc": f"Backup/leftover file accessible at {payload_used}",
                        "severity": sev,
                    })
                    _update_severity(sev)

        # ═══════════════════════════════════════════════════════════════════
        # Debug mode / error page detection (any path)
        # ═══════════════════════════════════════════════════════════════════
        if response.status_code in (200, 500, 502, 503):
            for indicator, desc, sev in DEBUG_INDICATORS:
                if indicator in body:
                    findings.append({
                        "type": "debug_mode",
                        "path": payload_used,
                        "desc": desc,
                        "severity": sev,
                    })
                    _update_severity(sev)
                    break  # one debug finding per response is enough

        # Default error page fingerprinting
        if response.status_code in (200, 403, 404, 500, 502):
            for indicator, desc, sev in DEFAULT_ERROR_PAGES:
                if indicator in body or indicator.lower() in response.headers.get("Server", "").lower():
                    findings.append({
                        "type": "default_page",
                        "path": payload_used,
                        "desc": desc,
                        "severity": sev,
                    })
                    _update_severity(sev)
                    break

        # ═══════════════════════════════════════════════════════════════════
        # Return result
        # ═══════════════════════════════════════════════════════════════════
        if findings:
            # Determine overall status
            if severity_order.get(highest_severity, 0) >= severity_order.get("high", 0):
                status = VulnStatus.VULNERABLE
            elif severity_order.get(highest_severity, 0) >= severity_order.get("medium", 0):
                status = VulnStatus.POTENTIALLY_VULNERABLE
            else:
                status = VulnStatus.POTENTIALLY_VULNERABLE

            evidence_parts = [f['desc'] for f in findings[:10]]
            return ModuleResult(
                module_name="misconfig_scanner",
                target=request.target,
                status=status,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="; ".join(evidence_parts),
                severity=highest_severity,
                mitre_technique_id="T1592",
                detail={
                    "detection_type": "misconfiguration",
                    "findings_count": len(findings),
                    "findings": findings[:25],
                },
            )

        return ModuleResult(
            module_name="misconfig_scanner",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
