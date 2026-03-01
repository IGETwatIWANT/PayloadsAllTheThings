"""
Default Credential Testing module.
Tests for default/common credentials on discovered services.
MITRE ATT&CK: T1078.001 - Default Accounts
"""
from __future__ import annotations
import uuid
from typing import Any
from urllib.parse import urlencode
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

# Default credentials by service/product
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("root", "root"), ("root", "toor"),
    ("admin", ""), ("administrator", "administrator"),
    ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("admin", "changeme"), ("admin", "default"), ("admin", "letmein"),
    # Web frameworks
    ("admin", "admin1234"), ("admin", "P@ssw0rd"), ("admin", "qwerty"),
    # Database defaults
    ("sa", ""), ("sa", "sa"), ("root", ""), ("postgres", "postgres"),
    ("mongodb", ""), ("redis", ""),
    # Network devices
    ("admin", "cisco"), ("admin", "Cisco"), ("cisco", "cisco"),
    ("admin", "1234"), ("admin", "12345"),
    # CMS defaults
    ("admin", "wordpress"), ("admin", "drupal"), ("admin", "joomla"),
]

class CredentialTesterModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="credential_test", description="Default and common credential testing",
            category="auth", mitre_technique_ids=["T1078"],
            mitre_technique_names=["Valid Accounts"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A07:2021 - Identification and Authentication Failures",
            cwe_ids=["CWE-798", "CWE-521"], tags=["credentials", "default", "brute_force", "auth"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        extra_creds = options.get("extra_creds", [])
        all_creds = list(DEFAULT_CREDS) + [(c[0], c[1]) for c in extra_creds]
        return [f"{u}:{p}" for u, p in all_creds]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        login_path = options.get("login_path", "/login")
        username_field = options.get("username_field", "username")
        password_field = options.get("password_field", "password")
        requests = []
        for cred in payloads:
            parts = cred.split(":", 1)
            username, password = parts[0], parts[1] if len(parts) > 1 else ""
            # Form-based login
            body = urlencode({username_field: username, password_field: password})
            requests.append(AttackRequest(request_id=f"cred-{uuid.uuid4().hex[:8]}", target=target,
                method="POST", path=login_path, body=body,
                content_type="application/x-www-form-urlencoded",
                headers={"X-BAS-Username": username}))
            # JSON-based login
            import json
            json_body = json.dumps({username_field: username, password_field: password})
            requests.append(AttackRequest(request_id=f"cred-{uuid.uuid4().hex[:8]}", target=target,
                method="POST", path=login_path, body=json_body, content_type="application/json",
                headers={"X-BAS-Username": username}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text.lower()
        username = request.headers.get("X-BAS-Username", "unknown")
        # Success indicators
        success_indicators = ["dashboard", "welcome", "logout", "token", "session", "authenticated", "success"]
        fail_indicators = ["invalid", "incorrect", "failed", "wrong", "denied", "error", "unauthorized"]
        is_redirect_to_app = response.status_code in (301, 302) and "login" not in response.headers.get("location", "").lower()
        has_success = any(s in body for s in success_indicators)
        has_fail = any(s in body for s in fail_indicators)

        if (response.status_code in (200, 302) and has_success and not has_fail) or is_redirect_to_app:
            return ModuleResult(module_name="credential_test", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload, response_code=response.status_code,
                response_body_preview=response.body_text[:500], elapsed_ms=response.elapsed_ms,
                evidence=f"Default credential accepted: {payload}", severity="critical",
                mitre_technique_id="T1078", detail={"username": username, "detection_type": "default_credential"})
        return ModuleResult(module_name="credential_test", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms)
