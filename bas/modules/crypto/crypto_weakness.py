"""
Cryptographic Implementation Testing module.

Tests for weak cryptographic implementations in web applications including
weak hashing algorithms (MD5/SHA1 in responses), predictable tokens,
insufficient randomness, weak password hashing indicators, insecure key
derivation, ECB mode detection, and padding oracle indicators.

MITRE ATT&CK: T1552 - Unsecured Credentials
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Paths and endpoints likely to reveal cryptographic implementation details
# ---------------------------------------------------------------------------
CRYPTO_PROBE_PATHS = [
    # Authentication endpoints (token / session generation)
    "/login",
    "/signin",
    "/auth",
    "/auth/login",
    "/api/auth",
    "/api/login",
    "/api/authenticate",
    "/api/v1/auth",
    "/api/v1/login",
    "/api/v2/auth",
    "/oauth/token",
    "/oauth/authorize",
    "/token",
    "/session",
    # Password reset (token generation)
    "/forgot-password",
    "/password/reset",
    "/api/password/reset",
    "/api/forgot-password",
    "/reset-password",
    "/account/recover",
    # Registration (password hashing)
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/api/v1/register",
    # User / profile endpoints
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/me",
    "/api/account",
    "/user/settings",
    # Debug / info endpoints
    "/debug",
    "/debug/crypto",
    "/info",
    "/health",
    "/status",
    "/phpinfo.php",
    "/server-info",
    # Download / file endpoints
    "/download",
    "/export",
    "/api/export",
    "/api/download",
]

# ---------------------------------------------------------------------------
# Weak crypto patterns detected in response bodies
# ---------------------------------------------------------------------------
WEAK_CRYPTO_PATTERNS: list[tuple[str, str, str]] = [
    # MD5 hashes in responses (32 hex chars often indicate MD5)
    (r"(?i)\"?(?:hash|checksum|md5|digest)\"?\s*[=:]\s*\"?[a-f0-9]{32}\"?", "MD5 hash detected in response", "medium"),
    (r"(?i)md5\s*\(\s*[\"'][^\"']+[\"']\s*\)", "MD5 function call exposed", "medium"),
    (r"(?i)content-md5\s*:\s*[a-zA-Z0-9+/=]+", "Content-MD5 header present", "low"),

    # SHA1 hashes in responses
    (r"(?i)\"?(?:hash|sha1|digest)\"?\s*[=:]\s*\"?[a-f0-9]{40}\"?", "SHA1 hash detected in response", "medium"),
    (r"(?i)sha1\s*\(\s*[\"'][^\"']+[\"']\s*\)", "SHA1 function call exposed", "medium"),

    # Weak password hashing indicators
    (r"(?i)(?:password_hash|pwd_hash|passhash)\s*[=:]\s*\"?[a-f0-9]{32}\"?", "Password stored with MD5", "critical"),
    (r"(?i)(?:password_hash|pwd_hash|passhash)\s*[=:]\s*\"?[a-f0-9]{40}\"?", "Password stored with SHA1", "critical"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*\"?[a-f0-9]{32}\"?", "MD5 password hash exposed", "high"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*\"?[a-f0-9]{64}\"?", "Unsalted SHA256 password hash exposed", "high"),

    # DES / 3DES usage indicators
    (r"(?i)(?:des|3des|triple.?des|desede)\s*(?:encrypt|decrypt|cipher)", "DES/3DES usage detected", "high"),
    (r"(?i)algorithm\s*[=:]\s*[\"']?(?:DES|3DES|DESede|TripleDES)", "DES algorithm configuration exposed", "high"),

    # ECB mode indicators
    (r"(?i)(?:ecb|ECB)\s*mode", "ECB mode usage detected", "high"),
    (r"(?i)cipher\s*[=:]\s*[\"']?AES/ECB", "AES-ECB mode configured", "high"),
    (r"(?i)algorithm\s*[=:]\s*[\"']?[A-Z]+/ECB/", "ECB block cipher mode detected", "high"),

    # Weak random / predictable tokens
    (r"(?i)Math\.random\(\)", "Math.random() used (not cryptographically secure)", "medium"),
    (r"(?i)random\.random\(\)", "Python random.random() used (not cryptographically secure)", "medium"),
    (r"(?i)rand\(\s*\)", "Weak rand() function used", "medium"),
    (r"(?i)srand\(\s*time\(", "srand seeded with time (predictable)", "high"),
    (r"(?i)mt_rand\(\)", "PHP mt_rand() used (not cryptographically secure)", "medium"),
    (r"(?i)java\.util\.Random", "Java Random used (not SecureRandom)", "medium"),

    # Insecure key derivation
    (r"(?i)pbkdf2.*iterations?\s*[=:]\s*(?:[0-9]{1,3}|1000)\b", "PBKDF2 with low iteration count", "high"),
    (r"(?i)(?:key_derivation|kdf)\s*[=:]\s*[\"']?(?:md5|sha1)", "Weak key derivation function", "high"),

    # Hardcoded encryption keys / IVs
    (r"(?i)(?:encryption|aes|cipher)[_-]?key\s*[=:]\s*[\"'][^\"']{8,}[\"']", "Hardcoded encryption key", "critical"),
    (r"(?i)(?:secret|private)[_-]?key\s*[=:]\s*[\"'][^\"']{8,}[\"']", "Hardcoded secret key", "critical"),
    (r"(?i)iv\s*[=:]\s*[\"'][a-f0-9]{16,32}[\"']", "Hardcoded IV detected", "high"),
    (r"(?i)initialization[_-]?vector\s*[=:]\s*[\"'][^\"']+[\"']", "Hardcoded initialization vector", "high"),
    (r"(?i)nonce\s*[=:]\s*[\"'][a-f0-9]{16,}[\"']", "Hardcoded nonce detected", "high"),

    # Deprecated / insecure algorithms
    (r"(?i)algorithm\s*[=:]\s*[\"']?RC4", "RC4 algorithm usage detected", "high"),
    (r"(?i)algorithm\s*[=:]\s*[\"']?Blowfish", "Blowfish algorithm usage detected", "medium"),
    (r"(?i)algorithm\s*[=:]\s*[\"']?ROT13", "ROT13 used (not encryption)", "high"),
    (r"(?i)base64[_-]?(?:encode|decode)", "Base64 used as encryption (not secure)", "medium"),
    (r"(?i)(?:xor|XOR)\s*(?:encrypt|cipher|encode)", "XOR cipher detected (weak)", "high"),

    # Padding oracle indicators
    (r"(?i)padding\s*(?:error|invalid|incorrect|bad|exception)", "Padding error message exposed", "high"),
    (r"(?i)PKCS[57]\s*(?:padding|error)", "PKCS padding error disclosed", "high"),
    (r"(?i)javax\.crypto\.BadPaddingException", "Java BadPaddingException exposed", "critical"),
    (r"(?i)System\.Security\.Cryptography\.CryptographicException", ".NET CryptographicException exposed", "critical"),
    (r"(?i)OpenSSL::Cipher::CipherError", "Ruby OpenSSL CipherError exposed", "high"),

    # Weak SSL/TLS in code
    (r"(?i)ssl_verify\s*[=:]\s*(?:false|0|no|off)", "SSL verification disabled", "critical"),
    (r"(?i)verify\s*[=:]\s*false.*ssl", "SSL verification disabled", "critical"),
    (r"(?i)CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)", "cURL SSL peer verification disabled", "critical"),
    (r"(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0", "Node.js TLS rejection disabled", "critical"),

    # Plaintext credential indicators
    (r"(?i)(?:encrypt|hash)\s*[=:]\s*[\"']?(?:none|plaintext|plain|off|false)", "Encryption disabled", "critical"),
    (r"(?i)password[_-]?(?:encryption|hashing)\s*[=:]\s*[\"']?(?:none|off|false)", "Password hashing disabled", "critical"),
]

COMPILED_CRYPTO_PATTERNS = [
    (re.compile(p), desc, sev) for p, desc, sev in WEAK_CRYPTO_PATTERNS
]

# ---------------------------------------------------------------------------
# Cookie / header indicators of weak crypto
# ---------------------------------------------------------------------------
WEAK_TOKEN_PATTERNS: list[tuple[str, str, str]] = [
    # Sequential / predictable session IDs
    (r"^[0-9]{1,10}$", "Numeric-only session token (predictable)", "high"),
    (r"^[0-9a-f]{8}$", "Very short hex token (8 chars)", "high"),
    (r"^[a-f0-9]{16}$", "Short hex token (16 chars, possibly MD5-truncated)", "medium"),
    # Timestamp-based tokens
    (r"^1[0-9]{9}", "Token appears timestamp-based (epoch seconds)", "medium"),
    (r"^1[0-9]{12}", "Token appears timestamp-based (epoch milliseconds)", "medium"),
    # Base64 without sufficient entropy
    (r"^[A-Za-z0-9+/]{4,12}={0,2}$", "Very short base64 token (low entropy)", "medium"),
]

COMPILED_TOKEN_PATTERNS = [
    (re.compile(p), desc, sev) for p, desc, sev in WEAK_TOKEN_PATTERNS
]


class CryptoWeaknessModule(BaseAttackModule):
    """
    Cryptographic Implementation Testing.

    Scans web application responses for indicators of weak cryptographic
    implementations including insecure hash algorithms, predictable tokens,
    ECB mode usage, padding oracle errors, hardcoded keys, disabled SSL
    verification, and insecure random number generation.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="crypto_weakness",
            description=(
                "Cryptographic Implementation Testing - weak hashing, "
                "predictable tokens, ECB mode, padding oracle indicators"
            ),
            category="crypto",
            mitre_technique_ids=["T1552"],
            mitre_technique_names=["Unsecured Credentials"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT,
            owasp_category="A02:2021 - Cryptographic Failures",
            cwe_ids=[
                "CWE-327", "CWE-328", "CWE-330", "CWE-331",
                "CWE-338", "CWE-916", "CWE-329", "CWE-347",
            ],
            tags=[
                "crypto", "hashing", "md5", "sha1", "ecb",
                "padding_oracle", "weak_random", "key_derivation",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("crypto_weakness", limit=300)
            if db_payloads:
                return db_payloads
        return list(CRYPTO_PROBE_PATHS)

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        user_agent = options.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            # GET probe to inspect response
            requests.append(AttackRequest(
                request_id=f"crypto-get-{req_id}",
                target=target,
                method="GET",
                path=payload,
                headers={
                    "User-Agent": user_agent,
                    "X-BAS-Payload": payload,
                    "Accept": "application/json, text/html, */*",
                },
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", True),
            ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_tag = request.headers.get("X-BAS-Payload", payload)
        headers = response.headers

        if response.error:
            return ModuleResult(
                module_name="crypto_weakness",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_tag,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Skip non-interesting responses
        if response.status_code in (404, 405, 301, 302):
            return ModuleResult(
                module_name="crypto_weakness",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_tag,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
            )

        # ── Cookie / Set-Cookie analysis ──────────────────────────────────
        set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        if set_cookie:
            # Check for missing Secure flag on session cookies
            cookie_lower = set_cookie.lower()
            if "session" in cookie_lower or "sid" in cookie_lower or "token" in cookie_lower:
                if "secure" not in cookie_lower:
                    return ModuleResult(
                        module_name="crypto_weakness",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Session cookie missing Secure flag: {set_cookie[:120]}",
                        severity="medium",
                        mitre_technique_id="T1552",
                        detail={"detection_type": "insecure_cookie"},
                    )
                if "httponly" not in cookie_lower:
                    return ModuleResult(
                        module_name="crypto_weakness",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Session cookie missing HttpOnly flag: {set_cookie[:120]}",
                        severity="medium",
                        mitre_technique_id="T1552",
                        detail={"detection_type": "insecure_cookie"},
                    )

            # Extract cookie value and check token strength
            cookie_value_match = re.search(r"=([^;]+)", set_cookie)
            if cookie_value_match:
                token_value = cookie_value_match.group(1)
                for pattern, desc, severity in COMPILED_TOKEN_PATTERNS:
                    if pattern.match(token_value):
                        return ModuleResult(
                            module_name="crypto_weakness",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_tag,
                            response_code=response.status_code,
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"{desc}: {token_value[:40]}",
                            severity=severity,
                            mitre_technique_id="T1552",
                            detail={"detection_type": "weak_token", "token_preview": token_value[:40]},
                        )

        # ── X-Powered-By / Server version for crypto lib detection ────────
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered_by:
            # Old PHP versions with known weak crypto defaults
            php_match = re.search(r"PHP/([0-9]+\.[0-9]+)", powered_by)
            if php_match:
                version = float(php_match.group(1))
                if version < 7.0:
                    return ModuleResult(
                        module_name="crypto_weakness",
                        target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"PHP {php_match.group(1)} detected - may use weak crypto defaults",
                        severity="medium",
                        mitre_technique_id="T1552",
                        detail={"detection_type": "outdated_runtime", "version": powered_by},
                    )

        # ── Body pattern matching ─────────────────────────────────────────
        if body and response.status_code == 200:
            for pattern, desc, severity in COMPILED_CRYPTO_PATTERNS:
                match = pattern.search(body)
                if match:
                    matched_text = match.group(0)
                    if len(matched_text) < 4:
                        continue
                    return ModuleResult(
                        module_name="crypto_weakness",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_tag,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"{desc}: {matched_text[:80]}",
                        severity=severity,
                        mitre_technique_id="T1552",
                        detail={
                            "detection_type": "crypto_weakness_pattern",
                            "weakness_type": desc,
                            "matched": matched_text[:100],
                        },
                    )

        # ── Check for insecure password hashing in error messages ─────────
        if body and response.status_code in (400, 500, 422):
            error_patterns = [
                (r"(?i)bcrypt.*cost\s*[=:]\s*([0-9]+)", "bcrypt_low_cost"),
                (r"(?i)scrypt.*(?:N|cost)\s*[=:]\s*([0-9]+)", "scrypt_low_cost"),
                (r"(?i)argon2.*(?:t_cost|time_cost)\s*[=:]\s*([0-9]+)", "argon2_low_cost"),
            ]
            for ep, etype in error_patterns:
                ematch = re.search(ep, body)
                if ematch:
                    cost = int(ematch.group(1))
                    threshold = {"bcrypt_low_cost": 10, "scrypt_low_cost": 14, "argon2_low_cost": 2}
                    if cost < threshold.get(etype, 10):
                        return ModuleResult(
                            module_name="crypto_weakness",
                            target=request.target,
                            status=VulnStatus.POTENTIALLY_VULNERABLE,
                            payload_used=payload_tag,
                            response_code=response.status_code,
                            response_body_preview=body[:500],
                            elapsed_ms=response.elapsed_ms,
                            evidence=f"Low hash cost detected ({etype}): cost={cost}",
                            severity="medium",
                            mitre_technique_id="T1552",
                            detail={"detection_type": etype, "cost": cost},
                        )

        return ModuleResult(
            module_name="crypto_weakness",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_tag,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
