"""Tests for attack modules - verify detection logic works correctly."""

import pytest
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.injection.sqli import SQLInjectionModule, DEFAULT_SQLI_PAYLOADS
from bas.modules.injection.xss import XSSModule, DEFAULT_XSS_PAYLOADS
from bas.modules.injection.command_injection import CommandInjectionModule
from bas.modules.injection.ssti import SSTIModule
from bas.modules.ssrf.ssrf import SSRFModule
from bas.modules.auth.jwt import JWTModule
from bas.modules.auth.auth_bypass import AuthBypassModule
from bas.modules.recon.discovery import DiscoveryModule
from bas.modules.base_module import VulnStatus


def make_response(body: str, status_code: int = 200, elapsed_ms: float = 100.0, headers: dict | None = None) -> AttackResponse:
    return AttackResponse(
        request_id="test-001",
        target="https://target.internal",
        status_code=status_code,
        headers=headers or {"Content-Type": "text/html"},
        body=body.encode(),
        elapsed_ms=elapsed_ms,
    )


def make_request(payload: str = "", headers: dict | None = None) -> AttackRequest:
    return AttackRequest(
        request_id="test-001",
        target="https://target.internal",
        method="GET",
        path="/",
        params={"q": payload},
        headers=headers or {},
    )


class TestSQLInjectionModule:
    def setup_method(self):
        self.module = SQLInjectionModule()

    def test_metadata(self):
        meta = self.module.metadata
        assert meta.name == "sqli"
        assert "T1190" in meta.mitre_technique_ids
        assert meta.auth_level_required == AuthorizationLevel.LOW_IMPACT

    def test_detects_mysql_error(self):
        response = make_response("You have an error in your SQL syntax; check the manual")
        request = make_request("' OR 1=1--")
        result = self.module._analyze_response(request, response, "' OR 1=1--")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "high"

    def test_detects_postgres_error(self):
        response = make_response('ERROR: syntax error at or near "test"')
        request = make_request("'")
        result = self.module._analyze_response(request, response, "'")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_mssql_error(self):
        response = make_response("Microsoft OLE DB Provider for SQL Server")
        request = make_request("'")
        result = self.module._analyze_response(request, response, "'")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_time_based_blind(self):
        response = make_response("OK", elapsed_ms=5200.0)
        request = make_request("1' AND SLEEP(5)--")
        result = self.module._analyze_response(request, response, "1' AND SLEEP(5)--")
        assert result.status == VulnStatus.POTENTIALLY_VULNERABLE

    def test_no_false_positive_on_normal_response(self):
        response = make_response("<html><body>Welcome to our site</body></html>")
        request = make_request("' OR 1=1--")
        result = self.module._analyze_response(request, response, "' OR 1=1--")
        assert result.status == VulnStatus.NOT_VULNERABLE

    def test_has_default_payloads(self):
        assert len(DEFAULT_SQLI_PAYLOADS) > 10


class TestXSSModule:
    def setup_method(self):
        self.module = XSSModule()

    def test_metadata(self):
        meta = self.module.metadata
        assert meta.name == "xss"
        assert "CWE-79" in meta.cwe_ids

    def test_detects_reflected_xss_with_canary(self):
        canary = "BAStest1234XSS"
        response = make_response(f"<html>Search: <script>alert('{canary}')</script></html>")
        request = make_request(
            f"<script>alert('{canary}')</script>",
            headers={"X-BAS-Canary": canary}
        )
        result = self.module._analyze_response(request, response, "<script>alert(1)</script>")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_potential_xss(self):
        response = make_response("<html>Value: <script>something</script></html>")
        request = make_request(
            "<script>alert(1)</script>",
            headers={"X-BAS-Canary": "nomatch"}
        )
        result = self.module._analyze_response(request, response, "<script>alert(1)</script>")
        assert result.status == VulnStatus.POTENTIALLY_VULNERABLE

    def test_no_false_positive(self):
        response = make_response("<html><body>No reflection here</body></html>")
        request = make_request("<script>alert(1)</script>", headers={"X-BAS-Canary": "test123"})
        result = self.module._analyze_response(request, response, "<script>alert(1)</script>")
        assert result.status == VulnStatus.NOT_VULNERABLE

    def test_has_default_payloads(self):
        assert len(DEFAULT_XSS_PAYLOADS) > 10


class TestCommandInjectionModule:
    def setup_method(self):
        self.module = CommandInjectionModule()

    def test_detects_canary_in_response(self):
        canary = "abc12345"
        response = make_response(f"Result: BAS_CMDI_{canary}")
        request = make_request(f"; echo BAS_CMDI_{canary}", headers={"X-BAS-Canary": canary})
        result = self.module._analyze_response(request, response, f"; echo BAS_CMDI_{canary}")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "critical"

    def test_detects_etc_passwd(self):
        response = make_response("root:x:0:0:root:/root:/bin/bash")
        request = make_request("| cat /etc/passwd", headers={"X-BAS-Canary": ""})
        result = self.module._analyze_response(request, response, "| cat /etc/passwd")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_time_based(self):
        response = make_response("", elapsed_ms=5500.0)
        request = make_request("; sleep 5", headers={"X-BAS-Canary": ""})
        result = self.module._analyze_response(request, response, "; sleep 5")
        assert result.status == VulnStatus.POTENTIALLY_VULNERABLE


class TestSSTIModule:
    def setup_method(self):
        self.module = SSTIModule()

    def test_detects_jinja2(self):
        response = make_response("Your name is 49")
        request = make_request("{{7*7}}", headers={"X-BAS-Payload": "{{7*7}}"})
        result = self.module._analyze_response(request, response, "{{7*7}}")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_jinja2_string_multiply(self):
        response = make_response("Result: 7777777")
        request = make_request("{{7*'7'}}", headers={"X-BAS-Payload": "{{7*'7'}}"})
        result = self.module._analyze_response(request, response, "{{7*'7'}}")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_template_error(self):
        response = make_response("jinja2.exceptions.TemplateSyntaxError: unexpected '}'")
        request = make_request("{{", headers={"X-BAS-Payload": "{{"})
        result = self.module._analyze_response(request, response, "{{")
        assert result.status == VulnStatus.POTENTIALLY_VULNERABLE


class TestSSRFModule:
    def setup_method(self):
        self.module = SSRFModule()

    def test_detects_aws_metadata(self):
        response = make_response("ami-id\ninstance-id\nhostname")
        request = make_request(
            "http://169.254.169.254/latest/meta-data/",
            headers={"X-BAS-Payload": "http://169.254.169.254/latest/meta-data/"}
        )
        result = self.module._analyze_response(request, response, "http://169.254.169.254/latest/meta-data/")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "critical"

    def test_detects_etc_passwd_via_file(self):
        response = make_response("root:x:0:0:root:/root:/bin/bash")
        request = make_request("file:///etc/passwd", headers={"X-BAS-Payload": "file:///etc/passwd"})
        result = self.module._analyze_response(request, response, "file:///etc/passwd")
        assert result.status == VulnStatus.VULNERABLE

    def test_detects_redis(self):
        response = make_response("redis_version:6.0.9\nconnected_clients:1")
        request = make_request("dict://127.0.0.1:6379/INFO", headers={"X-BAS-Payload": "dict://127.0.0.1:6379/INFO"})
        result = self.module._analyze_response(request, response, "dict://127.0.0.1:6379/INFO")
        assert result.status == VulnStatus.VULNERABLE


class TestJWTModule:
    def setup_method(self):
        self.module = JWTModule()

    def test_detects_accepted_none_algorithm(self):
        response = make_response('{"user": "admin", "role": "admin"}', status_code=200)
        request = make_request(headers={"X-BAS-Attack-Type": "ALG_NONE"})
        result = self.module._analyze_response(request, response, "ALG_NONE:token")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "critical"

    def test_rejects_401_response(self):
        response = make_response('{"error": "unauthorized"}', status_code=401)
        request = make_request(headers={"X-BAS-Attack-Type": "ALG_NONE"})
        result = self.module._analyze_response(request, response, "ALG_NONE:token")
        assert result.status == VulnStatus.NOT_VULNERABLE


class TestAuthBypassModule:
    def setup_method(self):
        self.module = AuthBypassModule()

    def test_detects_admin_access(self):
        response = make_response("<html><h1>Admin Dashboard</h1><p>Users management</p></html>")
        request = make_request(headers={"X-BAS-Attack-Type": "header_bypass"})
        result = self.module._analyze_response(request, response, "HEADER:X-Forwarded-For=127.0.0.1")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "critical"

    def test_rejects_403(self):
        response = make_response("Forbidden", status_code=403)
        request = make_request(headers={"X-BAS-Attack-Type": "header_bypass"})
        result = self.module._analyze_response(request, response, "HEADER:X-Forwarded-For=127.0.0.1")
        assert result.status == VulnStatus.NOT_VULNERABLE


class TestDiscoveryModule:
    def setup_method(self):
        self.module = DiscoveryModule()

    def test_detects_env_file(self):
        response = make_response("DB_PASSWORD=secret\nSECRET_KEY=mysecret\nAPI_KEY=abc123")
        request = make_request(headers={"X-BAS-Path": "/.env"})
        result = self.module._analyze_response(request, response, "/.env")
        assert result.status == VulnStatus.VULNERABLE
        assert result.severity == "critical"

    def test_detects_git_config(self):
        response = make_response("[core]\n\trepositoryformatversion = 0\n\tbare = false")
        request = make_request(headers={"X-BAS-Path": "/.git/config"})
        result = self.module._analyze_response(request, response, "/.git/config")
        assert result.status == VulnStatus.VULNERABLE
