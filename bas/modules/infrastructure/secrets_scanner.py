"""
Secrets and credential scanning module.

Tests for exposed API keys (AWS, GCP, Azure, GitHub, Slack, Stripe,
SendGrid), .env files, configuration files, git history leaks, debug
endpoints, and environment variable exposure.

MITRE ATT&CK: T1552 - Unsecured Credentials
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Paths to probe for secret / config file exposure ──────────────────────────
SECRET_FILE_PATHS = [
    # Environment files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.save",
    "/.env.example",
    "/.env.dev",
    "/.env.prod",
    "/.env.test",
    # Configuration files
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.xml",
    "/config.php",
    "/config.py",
    "/config.js",
    "/config.ini",
    "/config.toml",
    "/configuration.php",
    "/settings.py",
    "/settings.json",
    "/settings.yaml",
    "/application.yml",
    "/application.properties",
    "/application-prod.yml",
    "/appsettings.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/parameters.yml",
    "/database.yml",
    "/secrets.json",
    "/secrets.yaml",
    "/credentials.json",
    "/credentials.xml",
    "/service-account.json",
    # Docker / compose
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.prod.yml",
    "/Dockerfile",
    # CI/CD
    "/.gitlab-ci.yml",
    "/.travis.yml",
    "/.circleci/config.yml",
    "/.github/workflows/main.yml",
    "/Jenkinsfile",
    "/bitbucket-pipelines.yml",
    # Git
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/main",
    "/.git/refs/heads/master",
    "/.gitignore",
    # Package managers / lock files (can leak private registry tokens)
    "/.npmrc",
    "/.yarnrc",
    "/.yarnrc.yml",
    "/pip.conf",
    "/.pypirc",
    "/composer.json",
    "/Gemfile",
    "/requirements.txt",
    # SSH / keys
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/.ssh/config",
    # Web server
    "/.htpasswd",
    "/.htaccess",
    "/web.config",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/xmlrpc.php",
    # Cloud provider credentials
    "/.aws/credentials",
    "/.aws/config",
    "/.boto",
    "/.gcloud/credentials.db",
    "/.azure/accessTokens.json",
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/application_default_credentials.json",
    # Terraform
    "/terraform.tfvars",
    "/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    # Kubernetes
    "/.kube/config",
    "/kubeconfig",
    # Misc
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/Thumbs.db",
    "/debug/vars",
    "/debug/pprof/",
    "/_debug/vars",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/health",
    "/actuator/info",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/jolokia/",
    "/console",
    "/swagger.json",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
]

# ── Debug and status endpoints ─────────────────────────────────────────────────
DEBUG_ENDPOINTS = [
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/_debug",
    "/__debug__",
    "/trace",
    "/_trace",
    "/metrics",
    "/prometheus/metrics",
    "/health",
    "/healthz",
    "/status",
    "/_status",
    "/info",
    "/env",
    "/_env",
    "/elmah.axd",
    "/errorlog",
    "/errors",
]

# ── Regex patterns for secret detection in response bodies ─────────────────────
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "AWS Secret Access Key", "critical"),
    (r"(?i)aws_session_token\s*[=:]\s*[A-Za-z0-9/+=]+", "AWS Session Token", "critical"),
    (r"ASIA[0-9A-Z]{16}", "AWS Temporary Access Key", "critical"),
    # GCP
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "high"),
    (r"(?i)\"type\"\s*:\s*\"service_account\"", "GCP Service Account JSON", "critical"),
    (r"(?i)\"private_key\"\s*:\s*\"-----BEGIN", "GCP Private Key in JSON", "critical"),
    (r"[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "medium"),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Access Token", "critical"),
    # Azure
    (r"(?i)azure[_-]?(?:storage|account)[_-]?key\s*[=:]\s*[A-Za-z0-9/+=]{88}", "Azure Storage Key", "critical"),
    (r"(?i)AccountKey=[A-Za-z0-9/+=]{88}", "Azure Connection String Key", "critical"),
    (r"(?i)SharedAccessSignature=", "Azure SAS Token", "high"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "critical"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "critical"),
    (r"ghu_[A-Za-z0-9]{36}", "GitHub User-to-Server Token", "critical"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Server-to-Server Token", "critical"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-Grained PAT", "critical"),
    # GitLab
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token", "critical"),
    # Slack
    (r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "Slack Bot Token", "critical"),
    (r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}", "Slack User Token", "critical"),
    (r"xoxs-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{10,}", "Slack Session Token", "critical"),
    (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook URL", "high"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "critical"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key", "high"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", "medium"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key", "critical"),
    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API Key", "critical"),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", "high"),
    (r"AC[0-9a-fA-F]{32}", "Twilio Account SID", "medium"),
    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", "high"),
    # Square
    (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square Access Token", "critical"),
    (r"sq0csp-[0-9A-Za-z\-_]{43}", "Square OAuth Secret", "critical"),
    # Heroku
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Heroku/UUID API Key", "medium"),
    # JWT
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JSON Web Token", "high"),
    # Private keys
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", "critical"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key", "critical"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key", "critical"),
    (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key", "critical"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", "critical"),
    # Database connection strings
    (r"(?i)mongodb(?:\+srv)?://[^\s\"'<>]+", "MongoDB Connection String", "critical"),
    (r"(?i)postgres(?:ql)?://[^\s\"'<>]+", "PostgreSQL Connection String", "critical"),
    (r"(?i)mysql://[^\s\"'<>]+", "MySQL Connection String", "critical"),
    (r"(?i)redis://[^\s\"'<>]+", "Redis Connection String", "critical"),
    (r"(?i)amqp://[^\s\"'<>]+", "RabbitMQ Connection String", "critical"),
    (r"(?i)mssql://[^\s\"'<>]+", "MSSQL Connection String", "critical"),
    # Generic secrets in config
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Password in config", "critical"),
    (r"(?i)(?:secret|api[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Secret/API key in config", "critical"),
    (r"(?i)(?:access[_-]?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Access token in config", "critical"),
    # NPM tokens
    (r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+", "NPM Auth Token", "critical"),
    # Firebase
    (r"(?i)firebase[A-Za-z0-9]*\s*[=:]\s*['\"][A-Za-z0-9\-_]+['\"]", "Firebase credential", "high"),
    # Datadog
    (r"(?i)dd[_-]?api[_-]?key\s*[=:]\s*[a-f0-9]{32}", "Datadog API Key", "high"),
    # Sentry
    (r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+", "Sentry DSN", "medium"),
]

COMPILED_SECRET_PATTERNS = [(re.compile(p, re.IGNORECASE), desc, sev) for p, desc, sev in SECRET_PATTERNS]


class SecretsScanner(BaseAttackModule):
    """
    Secrets and credential scanning.

    Probes web targets for exposed configuration files, environment files,
    debug endpoints, git repositories, and scans response bodies for API keys,
    tokens, connection strings, and private key material.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="secrets_scanner",
            description=(
                "Secrets and credential scanning – .env files, config files, "
                "git history, debug endpoints, API key pattern matching"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1552"],
            mitre_technique_names=["Unsecured Credentials"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200", "CWE-312", "CWE-522", "CWE-532"],
            tags=["secrets", "credentials", "api_keys", "config", "exposure", "infrastructure"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("secrets_scanner", limit=300)
            if db_payloads:
                return db_payloads

        paths = list(SECRET_FILE_PATHS)
        if options.get("include_debug", True):
            paths.extend(DEBUG_ENDPOINTS)
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
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ),
            }

            requests.append(AttackRequest(
                request_id=f"secrets-{req_id}",
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
                module_name="secrets_scanner",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Skip obviously non-interesting responses
        if response.status_code in (404, 403, 401, 405, 301, 302):
            return ModuleResult(
                module_name="secrets_scanner",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
            )

        # ── .git/HEAD detection ────────────────────────────────────────────
        if ".git/" in payload_used:
            if "ref: refs/" in body or response.status_code == 200:
                if "ref: refs/" in body or "pack" in body.lower() or "DIRC" in body[:4]:
                    return ModuleResult(
                        module_name="secrets_scanner",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Git repository exposed at {payload_used} – source code and history downloadable",
                        severity="critical",
                        mitre_technique_id="T1552",
                        detail={"detection_type": "git_exposure"},
                    )

        # ── .env file detection ────────────────────────────────────────────
        if ".env" in payload_used:
            env_patterns = [
                r"(?i)^[A-Z_]+=.+",          # KEY=value lines
                r"(?i)DB_PASSWORD=",
                r"(?i)SECRET_KEY=",
                r"(?i)API_KEY=",
                r"(?i)DATABASE_URL=",
                r"(?i)AWS_",
                r"(?i)STRIPE_",
                r"(?i)SENDGRID_",
            ]
            if response.status_code == 200:
                for pattern in env_patterns:
                    if re.search(pattern, body, re.MULTILINE):
                        return ModuleResult(
                            module_name="secrets_scanner",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"Environment file exposed at {payload_used} – secrets visible",
                            severity="critical",
                            mitre_technique_id="T1552",
                            detail={"detection_type": "env_file"},
                        )

        # ── phpinfo detection ──────────────────────────────────────────────
        if "phpinfo" in payload_used or "info.php" in payload_used:
            if "phpinfo()" in body or "PHP Version" in body:
                return ModuleResult(
                    module_name="secrets_scanner",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="phpinfo() exposed – server configuration and environment variables visible",
                    severity="high",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "phpinfo"},
                )

        # ── Spring Boot actuator ───────────────────────────────────────────
        if "actuator" in payload_used:
            actuator_indicators = [
                ("\"property\":", "Spring Boot actuator /configprops exposed", "critical"),
                ("\"activeProfiles\"", "Spring Boot actuator /env exposed", "critical"),
                ("\"beans\"", "Spring Boot actuator /beans exposed", "high"),
                ("\"contexts\"", "Spring Boot actuator /mappings exposed", "high"),
                ("\"heapdump\"", "Spring Boot heapdump endpoint accessible", "critical"),
            ]
            for indicator, desc, severity in actuator_indicators:
                if indicator in body:
                    return ModuleResult(
                        module_name="secrets_scanner",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=desc,
                        severity=severity,
                        mitre_technique_id="T1552",
                        detail={"detection_type": "actuator"},
                    )

        # ── Swagger / OpenAPI exposure ─────────────────────────────────────
        if any(s in payload_used for s in ("swagger", "api-docs", "openapi")):
            if response.status_code == 200 and any(k in body for k in ('"swagger"', '"openapi"', '"paths"', '"info"')):
                return ModuleResult(
                    module_name="secrets_scanner",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="API documentation endpoint exposed – attack surface visible",
                    severity="medium",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "api_docs"},
                )

        # ── Cloud credential files ─────────────────────────────────────────
        if any(c in payload_used for c in (".aws/", ".gcloud/", ".azure/", ".boto", ".kube/")):
            if response.status_code == 200 and len(body.strip()) > 5:
                return ModuleResult(
                    module_name="secrets_scanner",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Cloud credential file exposed at {payload_used}",
                    severity="critical",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "cloud_credentials"},
                )

        # ── Private key detection ──────────────────────────────────────────
        if ".ssh/" in payload_used or "id_rsa" in payload_used:
            if "PRIVATE KEY" in body:
                return ModuleResult(
                    module_name="secrets_scanner",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSH private key exposed at {payload_used}",
                    severity="critical",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "ssh_key"},
                )

        # ── Terraform state / vars ─────────────────────────────────────────
        if "terraform" in payload_used:
            if response.status_code == 200 and any(t in body for t in ('"terraform_version"', '"resources"', '"outputs"')):
                return ModuleResult(
                    module_name="secrets_scanner",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Terraform state file exposed – infrastructure secrets visible",
                    severity="critical",
                    mitre_technique_id="T1552",
                    detail={"detection_type": "terraform_state"},
                )

        # ── Generic body scanning with compiled patterns ───────────────────
        if response.status_code == 200 and len(body) > 0:
            for pattern, desc, severity in COMPILED_SECRET_PATTERNS:
                match = pattern.search(body)
                if match:
                    # Avoid false positives on very generic patterns matching HTML
                    matched_text = match.group(0)
                    if len(matched_text) < 6:
                        continue
                    return ModuleResult(
                        module_name="secrets_scanner",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Secret detected in response: {desc} (match: {matched_text[:60]}...)",
                        severity=severity,
                        mitre_technique_id="T1552",
                        detail={
                            "detection_type": "pattern_match",
                            "secret_type": desc,
                            "matched_preview": matched_text[:80],
                        },
                    )

        return ModuleResult(
            module_name="secrets_scanner",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
