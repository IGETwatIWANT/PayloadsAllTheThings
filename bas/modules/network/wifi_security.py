"""
WiFi Security Testing module.
Tests WiFi infrastructure security by probing network management interfaces,
captive portals, and wireless configuration endpoints via HTTP.
MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing), T1021 (Remote Services)
"""
from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Access Point Management Interface paths (vendor-specific)
# ---------------------------------------------------------------------------
AP_MANAGEMENT_PATHS = [
    # Ubiquiti UniFi
    "/login", "/api/login", "/manage", "/api/s/default/rest/wlanconf",
    "/api/s/default/get/setting", "/api/self", "/api/s/default/stat/sysinfo",
    "/api/s/default/cmd/sitemgr", "/api/s/default/rest/user",
    # Cisco
    "/webauth/login.html", "/screens/frameset.html", "/level/15/exec/-/show/run",
    "/cgi-bin/login", "/RSA/applet.htm",
    # Aruba
    "/screens/wms/wms.login", "/arubaui/", "/api/v1/configuration/object/ap_group",
    "/screens/dashboard/dashboard.html",
    # MikroTik
    "/winbox", "/webfig/", "/rest/system/resource", "/rest/interface/wireless",
    "/rest/ip/address",
    # Ruckus
    "/admin/", "/admin/login.jsp", "/admin/dashboard.jsp",
    "/intune/dashboard",
    # TP-Link
    "/userRpm/", "/webpages/", "/userRpm/LoginRpm.htm",
    "/userRpm/StatusRpm.htm",
    # Netgear
    "/currentsetting.htm", "/MNU_top.htm", "/start.htm",
    "/WLG_wireless.htm",
    # Fortinet
    "/remote/login", "/remote/logincheck", "/api/v2/cmdb/wireless-controller/wtp",
    "/api/v2/monitor/wifi/managed_ap",
    # Meraki
    "/login/dashboard", "/api/v1/networks", "/api/v1/organizations",
    # pfSense
    "/index.php", "/diag_command.php", "/status_dhcp_leases.php",
    # OpenWrt
    "/cgi-bin/luci", "/cgi-bin/luci/admin/network/wireless",
    "/cgi-bin/luci/admin/status/overview",
    # Generic
    "/admin/wireless.asp", "/admin/management.asp",
    "/setup.cgi", "/apply.cgi",
]

# Default credential pairs per vendor (username:password format)
AP_DEFAULT_CREDENTIALS = [
    "admin:admin", "admin:password", "admin:1234", "admin:",
    "admin:ubnt", "ubnt:ubnt",                        # Ubiquiti
    "admin:cisco", "cisco:cisco", "Cisco:Cisco",      # Cisco
    "admin:aruba", "admin:admin123",                   # Aruba
    "admin:mikrotik", "admin:",                        # MikroTik
    "super:sp-admin", "admin:ruckus",                  # Ruckus
    "admin:admin", "admin:tplink",                     # TP-Link
    "admin:password", "admin:netgear",                 # Netgear
    "admin:fortinet", "admin:",                        # Fortinet
    "admin:meraki",                                    # Meraki
    "admin:pfsense",                                   # pfSense
    "root:openwrt", "root:",                           # OpenWrt
    "root:root", "admin:default", "admin:changeme",
]

# ---------------------------------------------------------------------------
# Captive Portal Testing paths
# ---------------------------------------------------------------------------
CAPTIVE_PORTAL_PATHS = [
    # Standard captive-portal detection endpoints
    "/generate_204",                      # Android
    "/hotspot-detect.html",               # Apple
    "/connecttest.txt",                   # Windows
    "/ncsi.txt",                          # Windows NCSI
    "/success.txt",                       # Firefox
    "/canonical.html",                    # Chromium
    # Common portal entry points
    "/portal", "/portal/", "/guest", "/guest/",
    "/guest/s/default/", "/guest/s/default/login",
    "/captiveportal", "/captive-portal",
    "/hotspot", "/hotspot/login",
    "/splash", "/splash/",
    # Captive portal bypass probes
    "/portal?bypass=true", "/guest?mac=00:11:22:33:44:55",
    "/portal?url=http://evil.com",
    # MAC / client enumeration endpoints
    "/api/clients", "/api/devices",
    "/api/s/default/stat/sta",
    "/api/s/default/list/user",
    # Guest network isolation testing
    "/guest/status", "/guest/info",
    "/portal/health", "/portal/config",
]

# ---------------------------------------------------------------------------
# Wireless Controller API paths
# ---------------------------------------------------------------------------
CONTROLLER_API_PATHS = [
    # UniFi Controller
    "/api/s/default/stat/sta",           # connected clients
    "/api/s/default/stat/device",        # managed devices
    "/api/s/default/stat/health",        # health info
    "/api/s/default/rest/wlanconf",      # WLAN configuration
    "/api/s/default/stat/rogueap",       # rogue AP list
    "/api/s/default/cmd/stamgr",         # client management
    "/api/s/default/rest/networkconf",   # network config
    "/api/s/default/stat/event",         # event log
    # Cisco WCS / Prime
    "/webacs/api/v4/data/AccessPoints.json",
    "/webacs/api/v4/data/Clients.json",
    "/webacs/api/v4/data/WlanProfiles.json",
    # Generic wireless APIs
    "/api/v1/wireless", "/rest/wireless",
    "/api/wireless/clients", "/api/wireless/config",
    "/api/v1/accesspoints", "/api/v1/wlans",
    "/api/v1/controllers", "/api/v1/rf-profiles",
    # Aruba APIs
    "/api/v1/configuration/object/ssid_prof",
    "/api/v1/monitoring/client",
    "/api/v1/monitoring/ap",
]

# ---------------------------------------------------------------------------
# Network Configuration Exposure paths
# ---------------------------------------------------------------------------
CONFIG_EXPOSURE_PATHS = [
    # System and status endpoints
    "/api/network", "/api/system", "/api/settings",
    "/status", "/system-status", "/wan-status",
    "/status.html", "/sysinfo", "/deviceinfo",
    # Configuration backup / export
    "/config/backup", "/system/backup", "/backup.cfg",
    "/cgi-bin/config.exp", "/download/config",
    "/system/config/backup", "/admin/backup.tar.gz",
    # SNMP / management data via web interface
    "/snmp-config", "/api/snmp", "/cgi-bin/snmpconf",
    "/snmpwalk", "/community",
    # WPS status
    "/wps/status", "/api/wps", "/wireless/wps",
    # Firmware info
    "/firmware", "/firmware/version", "/api/firmware",
    "/upgrade", "/fwupgrade.html",
    # SSID / PSK / wireless-key exposure
    "/api/psk", "/wireless/security", "/api/wireless/psk",
    "/wireless/key", "/api/ssid",
    "/wireless/settings", "/api/network/wireless",
    # Debug / diagnostic
    "/debug", "/diag", "/diagnostic",
    "/cgi-bin/syslog.cgi", "/log",
]


class WiFiSecurityModule(BaseAttackModule):
    """Tests WiFi infrastructure security via HTTP-accessible management interfaces."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="wifi_security",
            description=(
                "WiFi infrastructure security testing -- probes AP management "
                "interfaces, captive portals, wireless controllers, and "
                "configuration endpoints for exposure and default credentials"
            ),
            category="network",
            mitre_technique_ids=["T1557", "T1040", "T1021"],
            mitre_technique_names=[
                "Adversary-in-the-Middle",
                "Network Sniffing",
                "Remote Services",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-287", "CWE-319", "CWE-306"],
            tags=[
                "network", "wifi", "wireless", "access_point",
                "captive_portal", "wpa",
            ],
        )

    # -- payload helpers ---------------------------------------------------

    @staticmethod
    def _all_paths() -> list[str]:
        """Return the combined deduplicated list of all probe paths."""
        seen: set[str] = set()
        combined: list[str] = []
        for path in (
            AP_MANAGEMENT_PATHS
            + CAPTIVE_PORTAL_PATHS
            + CONTROLLER_API_PATHS
            + CONFIG_EXPOSURE_PATHS
        ):
            if path not in seen:
                seen.add(path)
                combined.append(path)
        return combined

    # -- abstract method implementations -----------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        extra = options.get("extra_paths", [])
        payloads = self._all_paths() + extra
        if options.get("include_default_creds", True):
            payloads.extend(
                [f"CRED:{cred}" for cred in AP_DEFAULT_CREDENTIALS]
            )
        return payloads

    def _build_requests(
        self,
        target: str,
        payloads: list[str],
        options: dict[str, Any],
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        login_path = options.get("login_path", "/login")

        for payload in payloads:
            rid = f"wifi-{uuid.uuid4().hex[:8]}"

            if payload.startswith("CRED:"):
                # Default-credential POST attempt
                cred = payload[5:]
                parts = cred.split(":", 1)
                username = parts[0]
                password = parts[1] if len(parts) > 1 else ""
                import json as _json

                json_body = _json.dumps(
                    {"username": username, "password": password}
                )
                requests.append(
                    AttackRequest(
                        request_id=rid,
                        target=target,
                        method="POST",
                        path=login_path,
                        body=json_body,
                        content_type="application/json",
                        headers={
                            "X-BAS-Payload": payload,
                            "X-BAS-Category": "default_credential",
                        },
                        timeout=options.get("timeout", 10),
                    )
                )
            else:
                # GET probe for management / config endpoints
                requests.append(
                    AttackRequest(
                        request_id=rid,
                        target=target,
                        method="GET",
                        path=payload,
                        headers={
                            "X-BAS-Payload": payload,
                            "X-BAS-Category": self._categorize_path(payload),
                        },
                        follow_redirects=False,
                        timeout=options.get("timeout", 10),
                    )
                )

        return requests

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        category = request.headers.get("X-BAS-Category", "")
        body = response.body_text.lower() if response.body_text else ""

        # -- Default credential check --------------------------------------
        if category == "default_credential":
            return self._analyze_credential_response(
                request, response, payload, body
            )

        # -- Management interface exposure ---------------------------------
        if category == "ap_management":
            return self._analyze_management_response(
                request, response, payload, body
            )

        # -- Captive portal exposure ---------------------------------------
        if category == "captive_portal":
            return self._analyze_portal_response(
                request, response, payload, body
            )

        # -- Controller API exposure ---------------------------------------
        if category == "controller_api":
            return self._analyze_controller_response(
                request, response, payload, body
            )

        # -- Configuration exposure ----------------------------------------
        if category == "config_exposure":
            return self._analyze_config_response(
                request, response, payload, body
            )

        # -- Fallback: generic detection -----------------------------------
        return self._analyze_generic(request, response, payload, body)

    # -- per-category analysis helpers -------------------------------------

    def _analyze_credential_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        success_indicators = [
            "dashboard", "welcome", "logout", "token",
            "session", "authenticated", "success", "200",
        ]
        fail_indicators = [
            "invalid", "incorrect", "failed", "wrong",
            "denied", "error", "unauthorized", "forbidden",
        ]
        has_success = any(ind in body for ind in success_indicators)
        has_fail = any(ind in body for ind in fail_indicators)
        redirect_to_app = (
            response.status_code in (301, 302)
            and "login" not in response.headers.get("location", "").lower()
        )

        if (
            response.status_code in (200, 302)
            and has_success
            and not has_fail
        ) or redirect_to_app:
            return ModuleResult(
                module_name="wifi_security",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Default AP credential accepted: {payload[5:]}",
                severity="critical",
                mitre_technique_id="T1021",
                detail={
                    "detection_type": "default_credential",
                    "credential": payload[5:],
                },
            )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _analyze_management_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        login_indicators = [
            "login", "username", "password", "sign in", "log in",
            "authenticate", "webui", "management", "mikrotik",
            "ubiquiti", "aruba", "cisco", "ruckus", "fortinet",
            "unifi", "openwrt", "luci", "pfsense",
        ]
        if response.status_code in (200, 301, 302):
            exposed = any(ind in body for ind in login_indicators)
            if exposed:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"AP management interface exposed: {payload}",
                    severity="high",
                    mitre_technique_id="T1021",
                    detail={"detection_type": "management_interface", "path": payload},
                )
            # Responsive but no obvious login UI -- still notable
            return ModuleResult(
                module_name="wifi_security",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Path accessible (HTTP {response.status_code}): {payload}",
                severity="medium",
                mitre_technique_id="T1021",
                detail={"detection_type": "accessible_path", "path": payload},
            )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _analyze_portal_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        portal_indicators = [
            "captive", "portal", "guest", "hotspot",
            "redirect", "splash", "accept", "terms",
            "connect", "network", "welcome",
        ]
        bypass_indicators = [
            "bypass", "success", "connected", "authenticated",
            "allowed",
        ]
        if response.status_code in (200, 302):
            is_bypass = any(ind in body for ind in bypass_indicators)
            is_portal = any(ind in body for ind in portal_indicators)
            if is_bypass:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Captive portal bypass possible: {payload}",
                    severity="high",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "portal_bypass", "path": payload},
                )
            if is_portal:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:300],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Captive portal detected: {payload}",
                    severity="medium",
                    mitre_technique_id="T1557",
                    detail={"detection_type": "captive_portal", "path": payload},
                )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _analyze_controller_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        data_indicators = [
            "mac", "ip", "essid", "ssid", "bssid", "client",
            "hostname", "ap_name", "radio", "channel", "signal",
            "rx_bytes", "tx_bytes", "uptime", "model", "serial",
            "firmware", "access_point", "wlan", "rogueap",
        ]
        if response.status_code == 200:
            exposed_fields = [ind for ind in data_indicators if ind in body]
            if len(exposed_fields) >= 2:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Wireless controller API exposed: {payload} "
                        f"(fields: {', '.join(exposed_fields[:5])})"
                    ),
                    severity="critical",
                    mitre_technique_id="T1040",
                    detail={
                        "detection_type": "controller_api",
                        "path": payload,
                        "exposed_fields": exposed_fields,
                    },
                )
            if exposed_fields:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:300],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Controller endpoint responds: {payload}",
                    severity="high",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "controller_api", "path": payload},
                )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _analyze_config_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        sensitive_indicators = [
            "psk", "passphrase", "wpa_key", "wep_key", "pre-shared",
            "password", "secret", "community", "snmp",
        ]
        config_indicators = [
            "ssid", "channel", "frequency", "bandwidth",
            "firmware", "version", "serial", "model", "config",
            "interface", "subnet", "gateway", "dns",
            "wps", "upnp",
        ]
        if response.status_code == 200:
            has_sensitive = any(ind in body for ind in sensitive_indicators)
            has_config = any(ind in body for ind in config_indicators)
            if has_sensitive:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Sensitive WiFi config exposed (credentials/keys): {payload}",
                    severity="critical",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "config_exposure_sensitive", "path": payload},
                )
            if has_config:
                return ModuleResult(
                    module_name="wifi_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:300],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Network configuration data exposed: {payload}",
                    severity="high",
                    mitre_technique_id="T1040",
                    detail={"detection_type": "config_exposure", "path": payload},
                )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    def _analyze_generic(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
        body: str,
    ) -> ModuleResult:
        """Fallback analysis when category is unknown."""
        if response.status_code in (200, 301, 302) and len(body) > 50:
            return ModuleResult(
                module_name="wifi_security",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Endpoint accessible: {payload} (HTTP {response.status_code})",
                severity="info",
                mitre_technique_id="T1021",
                detail={"detection_type": "generic", "path": payload},
            )
        return ModuleResult(
            module_name="wifi_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    # -- helper ------------------------------------------------------------

    @staticmethod
    def _categorize_path(path: str) -> str:
        """Classify a path into one of the payload categories."""
        if path in AP_MANAGEMENT_PATHS:
            return "ap_management"
        if path in CAPTIVE_PORTAL_PATHS:
            return "captive_portal"
        if path in CONTROLLER_API_PATHS:
            return "controller_api"
        if path in CONFIG_EXPOSURE_PATHS:
            return "config_exposure"
        return "generic"
