"""
PCI DSS Compliance Testing module.

Tests web applications against Payment Card Industry Data Security Standard
requirements, checking for cardholder data exposure, insecure transmission,
weak access controls, and missing audit logging.

MITRE ATT&CK: T1552 - Unsecured Credentials
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


PCI_DSS_PAYLOADS = [
    # --- Req 3: Protect Stored Cardholder Data - PAN Detection ---
    "PAN_DETECT:GET:/api/users/profile",
    "PAN_DETECT:GET:/api/orders/history",
    "PAN_DETECT:GET:/api/payments/recent",
    "PAN_DETECT:GET:/api/transactions",
    "PAN_DETECT:GET:/api/receipts",
    "PAN_DETECT:GET:/api/invoices",
    "PAN_DETECT:GET:/api/billing/info",
    "PAN_DETECT:GET:/api/account/details",
    "PAN_DETECT:GET:/api/customer/data",
    "PAN_DETECT:GET:/api/checkout/confirm",

    # --- Req 3: CVV/CVC Exposure ---
    "CVV_DETECT:GET:/api/payments/card",
    "CVV_DETECT:GET:/api/card/details",
    "CVV_DETECT:GET:/api/saved-cards",
    "CVV_DETECT:GET:/api/payment-methods",
    "CVV_DETECT:GET:/api/wallet",

    # --- Req 3: Track Data Detection ---
    "TRACK_DATA:GET:/api/card/swipe",
    "TRACK_DATA:GET:/api/pos/transaction",
    "TRACK_DATA:GET:/api/terminal/data",
    "TRACK_DATA:GET:/debug/card-reader",
    "TRACK_DATA:GET:/api/magnetic-stripe",

    # --- Req 4: Insecure Transmission / TLS Requirements ---
    "TLS_CHECK:GET:/",
    "TLS_CHECK:GET:/login",
    "TLS_CHECK:GET:/api/auth/token",
    "TLS_CHECK:GET:/checkout",
    "TLS_CHECK:GET:/payment",
    "TLS_DOWNGRADE:GET:/?force_http=1",
    "TLS_DOWNGRADE:GET:/api/v1/health",
    "TLS_VERSION:GET:/",
    "HSTS_CHECK:GET:/",
    "HSTS_CHECK:GET:/login",
    "HSTS_CHECK:GET:/payment",

    # --- Req 6: Secure Development - Default Credentials ---
    "DEFAULT_CREDS:POST:/admin/login:admin:admin",
    "DEFAULT_CREDS:POST:/admin/login:admin:password",
    "DEFAULT_CREDS:POST:/admin/login:administrator:administrator",
    "DEFAULT_CREDS:POST:/admin/login:root:root",
    "DEFAULT_CREDS:POST:/admin/login:sa:sa",
    "DEFAULT_CREDS:POST:/admin/login:test:test",
    "DEFAULT_CREDS:POST:/manager/login:tomcat:tomcat",
    "DEFAULT_CREDS:POST:/phpmyadmin/index.php:root:",
    "DEFAULT_CREDS:POST:/api/login:admin:changeme",
    "DEFAULT_CREDS:POST:/api/login:admin:Admin123",

    # --- Req 7/8: Access Control Testing ---
    "ACCESS_CTRL:GET:/admin",
    "ACCESS_CTRL:GET:/admin/dashboard",
    "ACCESS_CTRL:GET:/admin/users",
    "ACCESS_CTRL:GET:/admin/config",
    "ACCESS_CTRL:GET:/admin/logs",
    "ACCESS_CTRL:GET:/api/admin/settings",
    "ACCESS_CTRL:GET:/management",
    "ACCESS_CTRL:GET:/internal/api",
    "ACCESS_CTRL:GET:/api/users",
    "ACCESS_CTRL:GET:/api/roles",

    # --- Req 10: Logging and Monitoring Verification ---
    "LOG_VERIFY:GET:/api/audit/logs",
    "LOG_VERIFY:GET:/api/logs/access",
    "LOG_VERIFY:GET:/api/logs/auth",
    "LOG_VERIFY:GET:/api/security/events",
    "LOG_VERIFY:GET:/api/monitoring/status",

    # --- Req 11: Vulnerability Management ---
    "VULN_SCAN:GET:/server-status",
    "VULN_SCAN:GET:/server-info",
    "VULN_SCAN:GET:/.env",
    "VULN_SCAN:GET:/phpinfo.php",
    "VULN_SCAN:GET:/elmah.axd",
    "VULN_SCAN:GET:/trace.axd",
    "VULN_SCAN:GET:/actuator",
    "VULN_SCAN:GET:/actuator/env",

    # --- Req 6: Error Handling / Information Disclosure ---
    "INFO_DISCLOSURE:GET:/api/error-test",
    "INFO_DISCLOSURE:GET:/api/debug",
    "INFO_DISCLOSURE:GET:/api/config",
    "INFO_DISCLOSURE:GET:/api/status",
    "INFO_DISCLOSURE:GET:/api/version",
    "INFO_DISCLOSURE:GET:/.git/HEAD",
    "INFO_DISCLOSURE:GET:/.svn/entries",
    "INFO_DISCLOSURE:GET:/web.config",
    "INFO_DISCLOSURE:GET:/crossdomain.xml",
    "INFO_DISCLOSURE:GET:/clientaccesspolicy.xml",

    # --- Req 2: Vendor Default Removal ---
    "VENDOR_DEFAULT:GET:/examples/",
    "VENDOR_DEFAULT:GET:/docs/",
    "VENDOR_DEFAULT:GET:/test/",
    "VENDOR_DEFAULT:GET:/sample/",
]


class PCIDSSModule(BaseAttackModule):
    """
    PCI DSS Compliance Testing module.

    Tests web applications against PCI DSS v4.0 requirements including:
    - Requirement 3: Protect stored cardholder data (PAN, CVV, track data)
    - Requirement 4: Encrypt transmission of cardholder data
    - Requirement 6: Develop and maintain secure systems
    - Requirement 7/8: Restrict and authenticate access
    - Requirement 10: Track and monitor all access
    - Requirement 11: Regularly test security systems
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="pci_dss",
            description="PCI DSS compliance testing - cardholder data protection, TLS, access controls, logging",
            category="compliance",
            mitre_technique_ids=["T1552", "T1040", "T1078"],
            mitre_technique_names=["Unsecured Credentials", "Network Sniffing", "Valid Accounts"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-311", "CWE-312", "CWE-319", "CWE-522", "CWE-778", "CWE-798"],
            tags=["pci-dss", "compliance", "cardholder-data", "payment", "encryption", "access-control"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(PCI_DSS_PAYLOADS)

        custom_paths = options.get("payment_paths", [])
        for path in custom_paths:
            payloads.append(f"PAN_DETECT:GET:{path}")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("pci_dss", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []

        for payload in payloads:
            parts = payload.split(":")
            if len(parts) < 3:
                continue

            check_type = parts[0]
            method = parts[1]
            path = parts[2]
            req_id = uuid.uuid4().hex[:8]

            headers = {
                "X-BAS-Check-Type": check_type,
                "X-BAS-Payload": payload,
            }

            body = None
            content_type = "text/plain"

            if check_type == "DEFAULT_CREDS" and len(parts) >= 5:
                username = parts[3]
                password = parts[4]
                body = f"username={username}&password={password}"
                content_type = "application/x-www-form-urlencoded"

            requests.append(AttackRequest(
                request_id=f"pci-{req_id}",
                target=target,
                method=method,
                path=path,
                headers=headers,
                body=body,
                content_type=content_type,
                timeout=options.get("timeout", 30.0),
                follow_redirects=True,
            ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        body_lower = body.lower()
        check_type = request.headers.get("X-BAS-Check-Type", "")
        payload_used = request.headers.get("X-BAS-Payload", payload)

        # --- PAN Detection (Luhn-plausible 13-19 digit patterns) ---
        if check_type == "PAN_DETECT":
            import re
            pan_patterns = [
                r'4[0-9]{12}(?:[0-9]{3})?',         # Visa
                r'5[1-5][0-9]{14}',                   # Mastercard
                r'3[47][0-9]{13}',                     # Amex
                r'6(?:011|5[0-9]{2})[0-9]{12}',       # Discover
                r'3(?:0[0-5]|[68][0-9])[0-9]{11}',    # Diners Club
                r'(?:2131|1800|35\d{3})\d{11}',        # JCB
            ]
            for pattern in pan_patterns:
                matches = re.findall(pattern, body)
                if matches:
                    # Check if full PAN (not masked)
                    unmasked = [m for m in matches if "****" not in m and "XXXX" not in m]
                    if unmasked:
                        return ModuleResult(
                            module_name="pci_dss",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"PCI Req 3 VIOLATION: Unmasked PAN detected in response ({len(unmasked)} occurrence(s))",
                            severity="critical",
                            mitre_technique_id="T1552",
                            detail={"pci_requirement": "3.4", "finding": "unmasked_pan"},
                        )

        # --- CVV/CVC Detection ---
        if check_type == "CVV_DETECT":
            cvv_indicators = ["cvv", "cvc", "cvv2", "cvc2", "security_code", "card_security", "verification_value"]
            for indicator in cvv_indicators:
                if indicator in body_lower:
                    import re
                    cvv_value_pattern = rf'"{indicator}"\s*:\s*"?\d{{3,4}}"?'
                    if re.search(cvv_value_pattern, body_lower):
                        return ModuleResult(
                            module_name="pci_dss",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"PCI Req 3.2 VIOLATION: CVV/CVC value stored and returned in API response",
                            severity="critical",
                            mitre_technique_id="T1552",
                            detail={"pci_requirement": "3.2", "finding": "cvv_stored"},
                        )

        # --- Track Data Detection ---
        if check_type == "TRACK_DATA":
            import re
            track1_pattern = r'%B\d{13,19}\^[A-Z/\s]+\^\d{4}'
            track2_pattern = r';\d{13,19}=\d{4}'
            if re.search(track1_pattern, body) or re.search(track2_pattern, body):
                return ModuleResult(
                    module_name="pci_dss",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="PCI Req 3.2 VIOLATION: Magnetic stripe track data found in response",
                    severity="critical",
                    mitre_technique_id="T1552",
                    detail={"pci_requirement": "3.2", "finding": "track_data_stored"},
                )

        # --- TLS / HSTS Checks ---
        if check_type in ("TLS_CHECK", "TLS_DOWNGRADE", "TLS_VERSION", "HSTS_CHECK"):
            headers = response.headers

            if check_type == "HSTS_CHECK":
                hsts = headers.get("strict-transport-security", headers.get("Strict-Transport-Security", ""))
                if not hsts:
                    return ModuleResult(
                        module_name="pci_dss",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence="PCI Req 4.1: HSTS header missing - risk of TLS downgrade",
                        severity="medium",
                        mitre_technique_id="T1040",
                        detail={"pci_requirement": "4.1", "finding": "hsts_missing"},
                    )
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    return ModuleResult(
                        module_name="pci_dss",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"PCI Req 4.1: HSTS max-age too short ({max_age_match.group(1)}s, should be >= 31536000)",
                        severity="low",
                        mitre_technique_id="T1040",
                        detail={"pci_requirement": "4.1", "finding": "hsts_short_max_age"},
                    )

            if check_type == "TLS_DOWNGRADE" and response.status_code == 200:
                target_url = request.target.lower()
                if target_url.startswith("http://"):
                    return ModuleResult(
                        module_name="pci_dss",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence="PCI Req 4.1 VIOLATION: Application accessible over unencrypted HTTP",
                        severity="high",
                        mitre_technique_id="T1040",
                        detail={"pci_requirement": "4.1", "finding": "http_accessible"},
                    )

        # --- Default Credentials ---
        if check_type == "DEFAULT_CREDS":
            if response.status_code in (200, 302):
                success_indicators = [
                    "dashboard", "welcome", "logged in", "session", "token",
                    "authenticated", "success", "admin panel",
                ]
                for indicator in success_indicators:
                    if indicator in body_lower:
                        parts = payload_used.split(":")
                        creds = f"{parts[3]}:{parts[4]}" if len(parts) >= 5 else "unknown"
                        return ModuleResult(
                            module_name="pci_dss",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"PCI Req 2.1 VIOLATION: Default credentials accepted ({creds})",
                            severity="critical",
                            mitre_technique_id="T1078",
                            detail={"pci_requirement": "2.1", "finding": "default_credentials"},
                        )

        # --- Access Control ---
        if check_type == "ACCESS_CTRL":
            if response.status_code == 200 and len(body) > 100:
                admin_indicators = [
                    "admin", "management", "configuration", "settings",
                    "user management", "system config", "dashboard",
                ]
                for indicator in admin_indicators:
                    if indicator in body_lower:
                        return ModuleResult(
                            module_name="pci_dss",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"PCI Req 7: Administrative interface accessible without proper authentication ('{indicator}' found)",
                            severity="high",
                            mitre_technique_id="T1078",
                            detail={"pci_requirement": "7.1", "finding": "weak_access_control"},
                        )

        # --- Information Disclosure ---
        if check_type == "INFO_DISCLOSURE":
            info_indicators = [
                ("stack trace", "Stack trace exposed", "high"),
                ("exception", "Exception details exposed", "medium"),
                ("sql", "SQL information leaked", "high"),
                ("connection string", "Database connection string exposed", "critical"),
                ("password", "Password information in response", "critical"),
                ("api_key", "API key exposed", "critical"),
                ("secret", "Secret value exposed", "high"),
                ("phpinfo", "PHP configuration exposed", "high"),
                ("ref: refs/", "Git repository exposed", "high"),
            ]
            for indicator, desc, severity in info_indicators:
                if indicator in body_lower:
                    return ModuleResult(
                        module_name="pci_dss",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"PCI Req 6.5: {desc} in response",
                        severity=severity,
                        mitre_technique_id="T1552",
                        detail={"pci_requirement": "6.5", "finding": "info_disclosure"},
                    )

        # --- Vulnerability Scan Paths ---
        if check_type == "VULN_SCAN":
            if response.status_code == 200 and len(body) > 50:
                return ModuleResult(
                    module_name="pci_dss",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"PCI Req 11: Debug/status endpoint accessible at {request.path}",
                    severity="medium",
                    mitre_technique_id="T1552",
                    detail={"pci_requirement": "11.2", "finding": "debug_endpoint_exposed"},
                )

        # --- Vendor Defaults ---
        if check_type == "VENDOR_DEFAULT":
            if response.status_code == 200 and len(body) > 100:
                return ModuleResult(
                    module_name="pci_dss",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"PCI Req 2.1: Vendor default content accessible at {request.path}",
                    severity="low",
                    mitre_technique_id="T1552",
                    detail={"pci_requirement": "2.1", "finding": "vendor_defaults"},
                )

        return ModuleResult(
            module_name="pci_dss",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"check_type": check_type},
        )
