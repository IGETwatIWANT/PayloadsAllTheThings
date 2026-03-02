"""
HIPAA Security Assessment module.

Tests web applications against HIPAA (Health Insurance Portability and
Accountability Act) technical safeguards, including PHI exposure, access
controls, audit logging, encryption requirements, session management,
emergency access procedures, and integrity controls.

MITRE ATT&CK: T1552 - Unsecured Credentials
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


HIPAA_PAYLOADS = [
    # --- 164.312(a)(1): Access Control - Unique User Identification ---
    "ACCESS_CTRL:GET:/api/patients",
    "ACCESS_CTRL:GET:/api/patients/1",
    "ACCESS_CTRL:GET:/api/medical-records",
    "ACCESS_CTRL:GET:/api/health-records",
    "ACCESS_CTRL:GET:/api/ehr",
    "ACCESS_CTRL:GET:/api/emr",
    "ACCESS_CTRL:GET:/api/claims",
    "ACCESS_CTRL:GET:/api/prescriptions",
    "ACCESS_CTRL:GET:/api/lab-results",
    "ACCESS_CTRL:GET:/api/diagnoses",
    "ACCESS_CTRL:GET:/api/appointments",
    "ACCESS_CTRL:GET:/api/insurance",

    # --- 164.312(a)(2)(i): Emergency Access Procedure ---
    "EMERGENCY_ACCESS:GET:/api/emergency-access",
    "EMERGENCY_ACCESS:GET:/api/break-glass",
    "EMERGENCY_ACCESS:GET:/admin/emergency-override",
    "EMERGENCY_ACCESS:POST:/api/emergency-access/activate",

    # --- 164.312(a)(2)(iii): Automatic Logoff ---
    "SESSION_MGMT:GET:/api/session/info",
    "SESSION_MGMT:GET:/api/auth/session",
    "SESSION_MGMT:GET:/api/session/timeout",
    "SESSION_MGMT:GET:/api/user/session-config",

    # --- 164.312(b): Audit Controls ---
    "AUDIT_LOG:GET:/api/audit/logs",
    "AUDIT_LOG:GET:/api/audit/trail",
    "AUDIT_LOG:GET:/api/logs/access",
    "AUDIT_LOG:GET:/api/logs/phi-access",
    "AUDIT_LOG:GET:/api/compliance/audit",
    "AUDIT_LOG:GET:/api/security/events",
    "AUDIT_LOG:GET:/api/hipaa/audit-log",

    # --- 164.312(c)(1): Integrity Controls ---
    "INTEGRITY:GET:/api/data/checksum",
    "INTEGRITY:GET:/api/records/integrity",
    "INTEGRITY:GET:/api/hash-verification",
    "INTEGRITY:PUT:/api/patients/1:tamper_test",
    "INTEGRITY:PATCH:/api/medical-records/1:modify_test",

    # --- 164.312(d): Person or Entity Authentication ---
    "AUTH_CHECK:POST:/api/login:user:password",
    "AUTH_CHECK:POST:/api/auth/login:admin:admin",
    "AUTH_CHECK:POST:/api/auth/login:nurse:nurse",
    "AUTH_CHECK:POST:/api/auth/login:doctor:doctor",
    "AUTH_CHECK:GET:/api/auth/status",

    # --- 164.312(e)(1): Transmission Security ---
    "ENCRYPT_TRANSIT:GET:/",
    "ENCRYPT_TRANSIT:GET:/api/patients",
    "ENCRYPT_TRANSIT:GET:/portal/login",
    "ENCRYPT_TRANSIT:GET:/fhir/Patient",
    "ENCRYPT_TRANSIT:GET:/api/health/status",

    # --- PHI Exposure Detection ---
    "PHI_DETECT:GET:/api/patients/search?q=*",
    "PHI_DETECT:GET:/api/patients/export",
    "PHI_DETECT:GET:/api/reports/patient-list",
    "PHI_DETECT:GET:/api/fhir/Patient",
    "PHI_DETECT:GET:/api/hl7/messages",
    "PHI_DETECT:GET:/api/records/dump",
    "PHI_DETECT:GET:/api/billing/details",
    "PHI_DETECT:GET:/api/pharmacy/records",
    "PHI_DETECT:GET:/api/imaging/reports",
    "PHI_DETECT:GET:/api/mental-health/notes",
    "PHI_DETECT:GET:/api/substance-abuse/records",

    # --- 164.312(a)(2)(iv): Encryption at Rest Indicators ---
    "ENCRYPT_REST:GET:/api/storage/config",
    "ENCRYPT_REST:GET:/api/database/info",
    "ENCRYPT_REST:GET:/api/backup/status",
    "ENCRYPT_REST:GET:/api/system/encryption",

    # --- Minimum Necessary Standard ---
    "MIN_NECESSARY:GET:/api/patients/1/full",
    "MIN_NECESSARY:GET:/api/patients/1/summary",
    "MIN_NECESSARY:GET:/api/records/bulk-export",
    "MIN_NECESSARY:GET:/api/patients/all",

    # --- Business Associate Indicators ---
    "BA_EXPOSURE:GET:/api/third-party/access",
    "BA_EXPOSURE:GET:/api/integrations",
    "BA_EXPOSURE:GET:/api/external/data-share",
    "BA_EXPOSURE:GET:/api/partners/data",
]


class HIPAAAuditModule(BaseAttackModule):
    """
    HIPAA Security Assessment module.

    Tests web applications against HIPAA technical safeguards:
    - 164.312(a)(1): Access Control (unique user ID, emergency access, auto logoff)
    - 164.312(b): Audit Controls (logging of PHI access)
    - 164.312(c)(1): Integrity Controls (data tampering protection)
    - 164.312(d): Person or Entity Authentication
    - 164.312(e)(1): Transmission Security (encryption in transit)
    - PHI Exposure Detection (18 HIPAA identifiers)
    - Minimum Necessary Standard compliance
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hipaa_audit",
            description="HIPAA security assessment - PHI exposure, access controls, audit logging, encryption safeguards",
            category="compliance",
            mitre_technique_ids=["T1552", "T1530", "T1213"],
            mitre_technique_names=["Unsecured Credentials", "Data from Cloud Storage", "Data from Information Repositories"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-311", "CWE-312", "CWE-359", "CWE-532", "CWE-778"],
            tags=["hipaa", "compliance", "phi", "healthcare", "encryption", "audit-logging"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(HIPAA_PAYLOADS)

        custom_phi_paths = options.get("phi_endpoints", [])
        for path in custom_phi_paths:
            payloads.append(f"PHI_DETECT:GET:{path}")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("hipaa", limit=50)
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

            if check_type == "AUTH_CHECK" and method == "POST" and len(parts) >= 5:
                body = f'{{"username": "{parts[3]}", "password": "{parts[4]}"}}'
                content_type = "application/json"
            elif check_type == "INTEGRITY" and method in ("PUT", "PATCH") and len(parts) >= 4:
                body = '{"test_field": "tampered_value", "integrity_check": "bas_test"}'
                content_type = "application/json"

            requests.append(AttackRequest(
                request_id=f"hipaa-{req_id}",
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

        # --- PHI Exposure Detection (18 HIPAA identifiers) ---
        if check_type == "PHI_DETECT":
            phi_indicators = [
                ("social security", "SSN detected in response", "critical"),
                ("ssn", "SSN field detected in response", "critical"),
                ("\\d{3}-\\d{2}-\\d{4}", "SSN pattern detected", "critical"),
                ("date of birth", "Date of birth exposed", "high"),
                ("dob", "DOB field exposed", "high"),
                ("medical record", "Medical record number exposed", "high"),
                ("mrn", "MRN exposed", "high"),
                ("diagnosis", "Diagnosis information exposed", "high"),
                ("icd-10", "ICD-10 codes exposed", "high"),
                ("icd-9", "ICD-9 codes exposed", "high"),
                ("prescription", "Prescription data exposed", "high"),
                ("medication", "Medication data exposed", "high"),
                ("insurance_id", "Insurance ID exposed", "high"),
                ("member_id", "Member ID exposed", "high"),
                ("health_plan", "Health plan information exposed", "medium"),
                ("lab_result", "Lab results exposed", "high"),
                ("blood_type", "Blood type exposed", "medium"),
                ("allergy", "Allergy data exposed", "medium"),
            ]

            for indicator, desc, severity in phi_indicators:
                if indicator in body_lower:
                    return ModuleResult(
                        module_name="hipaa_audit",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"HIPAA VIOLATION: {desc} - PHI accessible without proper authorization",
                        severity=severity,
                        mitre_technique_id="T1552",
                        detail={"hipaa_section": "164.502", "finding": "phi_exposure", "indicator": indicator},
                    )

        # --- Access Control ---
        if check_type == "ACCESS_CTRL":
            if response.status_code == 200 and len(body) > 100:
                phi_fields = [
                    "patient", "medical", "health", "diagnosis", "treatment",
                    "prescription", "lab_result", "record", "ssn", "insurance",
                ]
                for field in phi_fields:
                    if field in body_lower:
                        return ModuleResult(
                            module_name="hipaa_audit",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HIPAA 164.312(a)(1): PHI endpoint accessible without authentication ('{field}' in response)",
                            severity="critical",
                            mitre_technique_id="T1552",
                            detail={"hipaa_section": "164.312(a)(1)", "finding": "access_control_failure"},
                        )

        # --- Emergency Access ---
        if check_type == "EMERGENCY_ACCESS":
            if response.status_code == 200:
                if any(k in body_lower for k in ["break-glass", "emergency", "override", "bypass"]):
                    return ModuleResult(
                        module_name="hipaa_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="HIPAA 164.312(a)(2)(ii): Emergency access procedure endpoint found - verify audit logging",
                        severity="medium",
                        mitre_technique_id="T1552",
                        detail={"hipaa_section": "164.312(a)(2)(ii)", "finding": "emergency_access_check"},
                    )

        # --- Session Management / Auto Logoff ---
        if check_type == "SESSION_MGMT":
            if response.status_code == 200 and "timeout" in body_lower:
                import re
                timeout_match = re.search(r'timeout["\s:=]+(\d+)', body_lower)
                if timeout_match:
                    timeout_val = int(timeout_match.group(1))
                    # Sessions should auto-logoff within reasonable time (15-30 min)
                    if timeout_val > 1800:
                        return ModuleResult(
                            module_name="hipaa_audit",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HIPAA 164.312(a)(2)(iii): Session timeout too long ({timeout_val}s > 1800s recommended)",
                            severity="medium",
                            mitre_technique_id="T1552",
                            detail={"hipaa_section": "164.312(a)(2)(iii)", "finding": "session_timeout_long"},
                        )

        # --- Audit Logging ---
        if check_type == "AUDIT_LOG":
            if response.status_code == 200 and len(body) > 50:
                if "audit" in body_lower or "log" in body_lower:
                    return ModuleResult(
                        module_name="hipaa_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="HIPAA 164.312(b): Audit log endpoint accessible - verify access controls on logs",
                        severity="medium",
                        mitre_technique_id="T1213",
                        detail={"hipaa_section": "164.312(b)", "finding": "audit_log_accessible"},
                    )
            elif response.status_code == 404:
                return ModuleResult(
                    module_name="hipaa_audit",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HIPAA 164.312(b): No audit log endpoint found - verify audit controls exist",
                    severity="low",
                    mitre_technique_id="T1213",
                    detail={"hipaa_section": "164.312(b)", "finding": "audit_log_missing"},
                )

        # --- Integrity Controls ---
        if check_type == "INTEGRITY":
            if response.status_code in (200, 204):
                if request.method in ("PUT", "PATCH"):
                    return ModuleResult(
                        module_name="hipaa_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="HIPAA 164.312(c)(1): Record modification accepted without integrity verification",
                        severity="high",
                        mitre_technique_id="T1552",
                        detail={"hipaa_section": "164.312(c)(1)", "finding": "integrity_bypass"},
                    )

        # --- Authentication Check ---
        if check_type == "AUTH_CHECK":
            if response.status_code == 200 and request.method == "POST":
                success_indicators = ["token", "session", "authenticated", "success", "welcome"]
                for indicator in success_indicators:
                    if indicator in body_lower:
                        parts = payload_used.split(":")
                        creds = f"{parts[3]}:{parts[4]}" if len(parts) >= 5 else "unknown"
                        return ModuleResult(
                            module_name="hipaa_audit",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HIPAA 164.312(d): Default/weak credentials accepted ({creds})",
                            severity="critical",
                            mitre_technique_id="T1552",
                            detail={"hipaa_section": "164.312(d)", "finding": "weak_auth"},
                        )

        # --- Transmission Security ---
        if check_type == "ENCRYPT_TRANSIT":
            hsts = response.headers.get("strict-transport-security",
                                        response.headers.get("Strict-Transport-Security", ""))
            if not hsts and request.target.startswith("http://"):
                return ModuleResult(
                    module_name="hipaa_audit",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="HIPAA 164.312(e)(1): PHI transmitted without encryption (no HSTS, HTTP accessible)",
                    severity="critical",
                    mitre_technique_id="T1040",
                    detail={"hipaa_section": "164.312(e)(1)", "finding": "no_encryption_transit"},
                )

        # --- Encryption at Rest ---
        if check_type == "ENCRYPT_REST":
            if response.status_code == 200:
                unencrypted_indicators = [
                    "encryption: false", "encrypted: false", "unencrypted",
                    "plaintext", "no encryption", "encryption_enabled: false",
                ]
                for indicator in unencrypted_indicators:
                    if indicator in body_lower:
                        return ModuleResult(
                            module_name="hipaa_audit",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HIPAA 164.312(a)(2)(iv): Storage not encrypted at rest ('{indicator}' in config)",
                            severity="critical",
                            mitre_technique_id="T1530",
                            detail={"hipaa_section": "164.312(a)(2)(iv)", "finding": "no_encryption_rest"},
                        )

        # --- Minimum Necessary ---
        if check_type == "MIN_NECESSARY":
            if response.status_code == 200 and len(body) > 500:
                import re
                field_count = len(re.findall(r'"[a-zA-Z_]+":', body))
                if field_count > 20:
                    return ModuleResult(
                        module_name="hipaa_audit",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"HIPAA Minimum Necessary: Endpoint returns excessive data ({field_count} fields)",
                        severity="medium",
                        mitre_technique_id="T1213",
                        detail={"hipaa_section": "164.502(b)", "finding": "excessive_data", "field_count": field_count},
                    )

        # --- Business Associate Exposure ---
        if check_type == "BA_EXPOSURE":
            if response.status_code == 200 and len(body) > 50:
                ba_indicators = ["third-party", "partner", "integration", "external", "api_key", "webhook"]
                for indicator in ba_indicators:
                    if indicator in body_lower:
                        return ModuleResult(
                            module_name="hipaa_audit",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"HIPAA: Third-party data sharing endpoint accessible - verify BAA compliance",
                            severity="medium",
                            mitre_technique_id="T1213",
                            detail={"hipaa_section": "164.502(e)", "finding": "ba_exposure"},
                        )

        return ModuleResult(
            module_name="hipaa_audit",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"check_type": check_type},
        )
