"""
Memory Forensics simulation module.

Tests for memory artifact detection indicators relevant to DFIR validation.
Simulates detection of process hollowing, reflective DLL injection, LSASS
credential dumping, memory-resident malware signatures, shellcode injection,
process doppelganging, thread hijacking, and API hooking.

MITRE ATT&CK: T1003 - OS Credential Dumping, T1055 - Process Injection
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---- Response signatures indicating memory forensics artifact exposure ----

MEMORY_ARTIFACT_SIGNATURES = [
    # Crash dump / memory dump exposure
    r"minidump",
    r"mdmp",
    r"\.dmp\b",
    r"full\s*memory\s*dump",
    r"kernel\s*dump",
    r"crash\s*dump",
    r"dbghelp\.dll",
    r"MiniDumpWriteDump",
    r"comsvcs\.dll",
    # LSASS credential indicators
    r"lsass\.exe",
    r"sekurlsa",
    r"wdigest",
    r"kerberos\s*ticket",
    r"ntlm\s*hash",
    r"credential\s*guard",
    r"dpapi",
    r"lsass\.dmp",
    r"procdump",
    # Process injection indicators
    r"VirtualAllocEx",
    r"WriteProcessMemory",
    r"CreateRemoteThread",
    r"NtCreateThreadEx",
    r"RtlCreateUserThread",
    r"QueueUserAPC",
    r"NtQueueApcThread",
    r"SetThreadContext",
    r"NtMapViewOfSection",
    r"NtUnmapViewOfSection",
    # Shellcode signatures
    r"\\x90\\x90\\x90",
    r"nop\s*sled",
    r"egg\s*hunter",
    r"\\xcc\\xcc\\xcc",
    r"shellcode",
    r"meterpreter",
    r"beacon\.dll",
    r"cobalt\s*strike",
    # Heap spray indicators
    r"heap\s*spray",
    r"0x0c0c0c0c",
    r"0x41414141",
    r"0x90909090",
    # ROP chain artifacts
    r"rop\s*chain",
    r"rop\s*gadget",
    r"return\s*oriented",
    r"stack\s*pivot",
    # API hooking indicators
    r"iat\s*hook",
    r"inline\s*hook",
    r"trampoline",
    r"detour",
    r"splicing",
    r"eat\s*hook",
    r"ssdt\s*hook",
    # Reflective loading indicators
    r"reflective\s*(dll|load|inject)",
    r"pe\s*header",
    r"dos\s*stub",
    r"MZ.*PE\x00\x00",
    r"image_dos_header",
    r"image_nt_headers",
    # Memory-mapped file indicators
    r"mapped\s*file",
    r"memory.mapped",
    r"CreateFileMapping",
    r"MapViewOfFile",
    r"NtCreateSection",
    r"section\s*object",
    r"pagefile\.sys",
    r"hiberfil\.sys",
]

COMPILED_MEMORY_SIGNATURES = [re.compile(sig, re.IGNORECASE) for sig in MEMORY_ARTIFACT_SIGNATURES]

# Header signatures that indicate memory artifact exposure
MEMORY_HEADER_SIGNATURES = [
    "application/octet-stream",
    "application/x-dmp",
    "application/x-minidump",
    "application/vnd.ms-cab-compressed",
    "application/x-msdownload",
]

# ---- Payload categories ----

# Process hollowing detection payloads
PROCESS_HOLLOWING_PAYLOADS = [
    "/debug/proc/hollowed/svchost",
    "/debug/proc/hollowed/explorer",
    "/debug/proc/hollowed/csrss",
    "/debug/proc/hollowed/lsass",
    "/debug/proc/hollowed/smss",
    "/debug/proc/hollowed/winlogon",
    "/debug/proc/hollowed/services",
    "/debug/proc/hollowed/wininit",
    "/debug/proc/hollowed/taskhost",
    "/debug/proc/hollowed/rundll32",
    "/api/memory/process-hollowing/detect",
    "/api/memory/process-hollowing/indicators",
    "/api/forensics/hollowing/image-mismatch",
    "/api/forensics/hollowing/peb-manipulation",
    "/api/forensics/hollowing/unmapped-sections",
    "/api/forensics/hollowing/memory-permissions",
    "/api/forensics/hollowing/vad-analysis",
    "/api/forensics/hollowing/thread-start-address",
    "/api/forensics/hollowing/parent-child-mismatch",
    "/api/forensics/hollowing/base-address-mismatch",
    "/forensics/memory/hollowing/NtUnmapViewOfSection",
    "/forensics/memory/hollowing/ZwUnmapViewOfSection",
    "/forensics/memory/hollowing/NtWriteVirtualMemory",
    "/forensics/memory/hollowing/NtResumeThread",
    "/forensics/memory/hollowing/SetThreadContext",
    "/forensics/memory/hollowing/NtSetContextThread",
    "/forensics/memory/hollowing/WriteProcessMemory",
    "/forensics/memory/hollowing/NtAllocateVirtualMemory",
    "/forensics/memory/hollowing/suspended-process-analysis",
    "/forensics/memory/hollowing/cross-process-write-detect",
    "/forensics/memory/hollowing/image-section-mismatch",
    "/forensics/memory/hollowing/entropy-anomaly",
    "/forensics/memory/hollowing/pe-header-analysis",
    "/forensics/memory/hollowing/vad-tag-mismatch",
    "/forensics/memory/hollowing/working-set-anomaly",
]

# Reflective DLL injection detection payloads
REFLECTIVE_DLL_PAYLOADS = [
    "/debug/reflective/dll/inject-detect",
    "/debug/reflective/dll/pe-headers",
    "/debug/reflective/dll/loader-stub",
    "/debug/reflective/dll/export-table",
    "/debug/reflective/dll/image-base",
    "/api/forensics/reflective-dll/memory-scan",
    "/api/forensics/reflective-dll/rwe-sections",
    "/api/forensics/reflective-dll/unbacked-executable",
    "/api/forensics/reflective-dll/floating-code",
    "/api/forensics/reflective-dll/pe-anomalies",
    "/api/forensics/reflective-dll/module-list-mismatch",
    "/api/forensics/reflective-dll/peb-ldr-mismatch",
    "/api/forensics/reflective-dll/vad-tag-analysis",
    "/api/forensics/reflective-dll/thread-analysis",
    "/api/forensics/reflective-dll/headers-wiped",
    "/api/forensics/reflective-dll/relocations-applied",
    "/api/forensics/reflective-dll/import-resolution",
    "/api/forensics/reflective-dll/dos-header-scan",
    "/api/forensics/reflective-dll/nt-header-scan",
    "/api/forensics/reflective-dll/section-entropy",
    "/forensics/reflective/ReflectiveLoader",
    "/forensics/reflective/LdrLoadDll-hook",
    "/forensics/reflective/RtlInitUnicodeString-detect",
    "/forensics/reflective/NtAllocateVirtualMemory-trace",
    "/forensics/reflective/VirtualProtect-trace",
    "/forensics/reflective/manual-mapping-detect",
    "/forensics/reflective/memory-only-module",
    "/forensics/reflective/phantom-dll",
    "/forensics/reflective/stomped-module",
    "/forensics/reflective/concealed-module",
    "/forensics/reflective/gargoyle-technique",
    "/forensics/reflective/module-overloading",
    "/forensics/reflective/dll-hollowing",
    "/forensics/reflective/transacted-hollowing",
]

# LSASS credential dump detection payloads
LSASS_DUMP_PAYLOADS = [
    "/debug/lsass/dump",
    "/debug/lsass/minidump",
    "/debug/lsass/full-dump",
    "/debug/lsass/process-snapshot",
    "/api/forensics/lsass/dump-detect",
    "/api/forensics/lsass/comsvcs-detect",
    "/api/forensics/lsass/procdump-detect",
    "/api/forensics/lsass/task-manager-dump",
    "/api/forensics/lsass/sqldumper-detect",
    "/api/forensics/lsass/createdump-detect",
    "/api/forensics/lsass/silentprocessexit",
    "/api/forensics/lsass/rdrleakdiag-detect",
    "/api/forensics/lsass/werfault-detect",
    "/api/forensics/lsass/ppldump-detect",
    "/api/forensics/lsass/nanodump-detect",
    "/api/forensics/lsass/handlekatz-detect",
    "/api/forensics/lsass/credential-guard-bypass",
    "/api/forensics/lsass/mimikatz-detect",
    "/api/forensics/lsass/sekurlsa-logonpasswords",
    "/api/forensics/lsass/sekurlsa-wdigest",
    "/api/forensics/lsass/sekurlsa-kerberos",
    "/api/forensics/lsass/sekurlsa-msv",
    "/api/forensics/lsass/sekurlsa-tspkg",
    "/api/forensics/lsass/sekurlsa-ssp",
    "/api/forensics/lsass/sekurlsa-credman",
    "/api/forensics/lsass/dpapi-masterkey",
    "/api/forensics/lsass/ntds-secrets",
    "/api/forensics/lsass/sam-dump",
    "/api/forensics/lsass/lsa-secrets",
    "/api/forensics/lsass/dcsync-detect",
    "/forensics/lsass/MiniDumpWriteDump-trace",
    "/forensics/lsass/NtReadVirtualMemory-trace",
    "/forensics/lsass/OpenProcess-lsass",
    "/forensics/lsass/handle-duplication",
    "/forensics/lsass/sspi-exfil",
]

# Memory-resident malware signature detection payloads
MEMORY_MALWARE_PAYLOADS = [
    "/api/forensics/memory-malware/fileless-detect",
    "/api/forensics/memory-malware/powershell-cradle",
    "/api/forensics/memory-malware/wmi-persistence",
    "/api/forensics/memory-malware/dotnet-assembly-load",
    "/api/forensics/memory-malware/amsi-bypass-detect",
    "/api/forensics/memory-malware/etw-patch-detect",
    "/api/forensics/memory-malware/cobalt-strike-beacon",
    "/api/forensics/memory-malware/meterpreter-detect",
    "/api/forensics/memory-malware/sliver-implant",
    "/api/forensics/memory-malware/covenant-grunt",
    "/api/forensics/memory-malware/mythic-agent",
    "/api/forensics/memory-malware/empire-stager",
    "/api/forensics/memory-malware/poshc2-implant",
    "/api/forensics/memory-malware/brute-ratel-badger",
    "/api/forensics/memory-malware/havoc-demon",
    "/api/forensics/memory-malware/nighthawk-implant",
    "/api/forensics/memory-malware/macro-payload",
    "/api/forensics/memory-malware/hta-payload",
    "/api/forensics/memory-malware/vba-stomping-detect",
    "/api/forensics/memory-malware/xll-payload",
    "/api/forensics/memory-malware/com-hijack",
    "/api/forensics/memory-malware/registry-resident",
    "/api/forensics/memory-malware/wmic-execution",
    "/api/forensics/memory-malware/mshta-execution",
    "/api/forensics/memory-malware/msbuild-abuse",
    "/api/forensics/memory-malware/installutil-abuse",
    "/api/forensics/memory-malware/regasm-abuse",
    "/api/forensics/memory-malware/cscript-wscript-abuse",
    "/api/forensics/memory-malware/certutil-download",
    "/api/forensics/memory-malware/bitsadmin-download",
    "/api/forensics/memory-malware/rundll32-abuse",
    "/api/forensics/memory-malware/regsvr32-abuse",
    "/forensics/memory-malware/string-deobfuscation",
    "/forensics/memory-malware/config-extraction",
    "/forensics/memory-malware/c2-url-extraction",
    "/forensics/memory-malware/encryption-key-dump",
]

# Shellcode injection pattern detection payloads
SHELLCODE_INJECTION_PAYLOADS = [
    "/api/forensics/shellcode/nop-sled-detect",
    "/api/forensics/shellcode/egg-hunter-detect",
    "/api/forensics/shellcode/staged-payload-detect",
    "/api/forensics/shellcode/stageless-payload-detect",
    "/api/forensics/shellcode/encoder-detect",
    "/api/forensics/shellcode/xor-encoded",
    "/api/forensics/shellcode/shikata-ga-nai",
    "/api/forensics/shellcode/alpha-mixed",
    "/api/forensics/shellcode/alpha-upper",
    "/api/forensics/shellcode/countdown-detect",
    "/api/forensics/shellcode/unicode-detect",
    "/api/forensics/shellcode/custom-encoder",
    "/api/forensics/shellcode/reverse-shell-detect",
    "/api/forensics/shellcode/bind-shell-detect",
    "/api/forensics/shellcode/exec-payload-detect",
    "/api/forensics/shellcode/download-exec-detect",
    "/api/forensics/shellcode/VirtualAlloc-trace",
    "/api/forensics/shellcode/VirtualProtect-trace",
    "/api/forensics/shellcode/HeapCreate-trace",
    "/api/forensics/shellcode/NtAllocateVirtualMemory-trace",
    "/api/forensics/shellcode/RWX-allocation-detect",
    "/api/forensics/shellcode/thread-execution-hijack",
    "/api/forensics/shellcode/fiber-execution",
    "/api/forensics/shellcode/callback-execution",
    "/api/forensics/shellcode/apc-injection",
    "/api/forensics/shellcode/syscall-direct",
    "/api/forensics/shellcode/syscall-indirect",
    "/api/forensics/shellcode/hells-gate",
    "/api/forensics/shellcode/heavens-gate",
    "/api/forensics/shellcode/syswhispers",
    "/forensics/shellcode/entropy-analysis",
    "/forensics/shellcode/memory-permissions",
    "/forensics/shellcode/unbacked-rwx",
    "/forensics/shellcode/call-stack-anomaly",
    "/forensics/shellcode/return-address-overwrite",
]

# Process doppelganging detection payloads
PROCESS_DOPPELGANGING_PAYLOADS = [
    "/api/forensics/doppelganging/detect",
    "/api/forensics/doppelganging/ntfs-transaction",
    "/api/forensics/doppelganging/NtCreateTransaction",
    "/api/forensics/doppelganging/NtCreateSection-txf",
    "/api/forensics/doppelganging/NtRollbackTransaction",
    "/api/forensics/doppelganging/NtCreateProcessEx",
    "/api/forensics/doppelganging/transacted-file",
    "/api/forensics/doppelganging/image-mismatch",
    "/api/forensics/doppelganging/section-backed-anomaly",
    "/api/forensics/doppelganging/file-rollback-detect",
    "/api/forensics/doppelganging/txf-api-monitor",
    "/api/forensics/doppelganging/phantom-process",
    "/api/forensics/doppelganging/herpaderping",
    "/api/forensics/doppelganging/ghosting",
    "/api/forensics/doppelganging/process-reimaging",
    "/forensics/doppelganging/etw-transaction-trace",
    "/forensics/doppelganging/kernel-callback-detect",
    "/forensics/doppelganging/minifilter-detect",
    "/forensics/doppelganging/file-lock-anomaly",
    "/forensics/doppelganging/pending-delete-detect",
    "/forensics/doppelganging/mapped-vs-ondisk-hash",
    "/forensics/doppelganging/authenticode-mismatch",
    "/forensics/doppelganging/amsi-scan-result",
    "/forensics/doppelganging/ppl-bypass-detect",
    "/forensics/doppelganging/ci-violation-detect",
    "/forensics/doppelganging/signed-binary-proxy",
    "/forensics/doppelganging/catalog-mismatch",
    "/forensics/doppelganging/version-info-anomaly",
    "/forensics/doppelganging/resource-anomaly",
    "/forensics/doppelganging/timestamp-anomaly",
    "/forensics/doppelganging/digital-signature-verify",
    "/forensics/doppelganging/entropy-comparison",
    "/forensics/doppelganging/section-hash-mismatch",
    "/forensics/doppelganging/import-table-anomaly",
]

# Thread hijacking detection payloads
THREAD_HIJACKING_PAYLOADS = [
    "/api/forensics/thread-hijack/SuspendThread-trace",
    "/api/forensics/thread-hijack/GetThreadContext-trace",
    "/api/forensics/thread-hijack/SetThreadContext-trace",
    "/api/forensics/thread-hijack/ResumeThread-trace",
    "/api/forensics/thread-hijack/NtSuspendThread-trace",
    "/api/forensics/thread-hijack/NtGetContextThread-trace",
    "/api/forensics/thread-hijack/NtSetContextThread-trace",
    "/api/forensics/thread-hijack/instruction-pointer-hijack",
    "/api/forensics/thread-hijack/stack-pivot-detect",
    "/api/forensics/thread-hijack/return-address-tamper",
    "/api/forensics/thread-hijack/cross-process-thread",
    "/api/forensics/thread-hijack/thread-pool-abuse",
    "/api/forensics/thread-hijack/fiber-local-storage",
    "/api/forensics/thread-hijack/teb-manipulation",
    "/api/forensics/thread-hijack/wow64-transition",
    "/forensics/thread-hijack/context-switch-anomaly",
    "/forensics/thread-hijack/call-stack-spoof",
    "/forensics/thread-hijack/unwinding-anomaly",
    "/forensics/thread-hijack/cet-bypass-detect",
    "/forensics/thread-hijack/shadow-stack-violation",
    "/forensics/thread-hijack/rip-hijack-detect",
    "/forensics/thread-hijack/rsp-pivot-detect",
    "/forensics/thread-hijack/threadpool-wait-callback",
    "/forensics/thread-hijack/timer-callback-hijack",
    "/forensics/thread-hijack/tp-work-insertion",
    "/forensics/thread-hijack/tp-alpc-callback",
    "/forensics/thread-hijack/tp-io-callback",
    "/forensics/thread-hijack/tp-timer-callback",
    "/forensics/thread-hijack/tp-wait-callback",
    "/forensics/thread-hijack/early-bird-apc",
    "/forensics/thread-hijack/special-user-apc",
    "/forensics/thread-hijack/NtTestAlert-trigger",
    "/forensics/thread-hijack/alertable-thread-detect",
    "/forensics/thread-hijack/instrumentation-callback",
]

# API hooking detection payloads
API_HOOKING_PAYLOADS = [
    "/api/forensics/api-hook/iat-hook-detect",
    "/api/forensics/api-hook/eat-hook-detect",
    "/api/forensics/api-hook/inline-hook-detect",
    "/api/forensics/api-hook/trampoline-detect",
    "/api/forensics/api-hook/detours-detect",
    "/api/forensics/api-hook/minhook-detect",
    "/api/forensics/api-hook/splicing-detect",
    "/api/forensics/api-hook/veh-hook-detect",
    "/api/forensics/api-hook/hwbp-hook-detect",
    "/api/forensics/api-hook/page-guard-hook",
    "/api/forensics/api-hook/ssdt-hook-detect",
    "/api/forensics/api-hook/idt-hook-detect",
    "/api/forensics/api-hook/ntdll-unhook-detect",
    "/api/forensics/api-hook/syscall-stub-overwrite",
    "/api/forensics/api-hook/wow64-hook-detect",
    "/api/forensics/api-hook/callback-table-hook",
    "/api/forensics/api-hook/nirvana-hook-detect",
    "/api/forensics/api-hook/ldr-notification-hook",
    "/api/forensics/api-hook/dll-notification-hook",
    "/api/forensics/api-hook/tls-callback-hook",
    "/forensics/api-hook/module-hash-compare",
    "/forensics/api-hook/code-integrity-check",
    "/forensics/api-hook/prologue-byte-scan",
    "/forensics/api-hook/jmp-instruction-detect",
    "/forensics/api-hook/function-redirect-detect",
    "/forensics/api-hook/vtable-hook-detect",
    "/forensics/api-hook/com-interface-hook",
    "/forensics/api-hook/wmi-provider-hook",
    "/forensics/api-hook/etw-provider-hook",
    "/forensics/api-hook/security-callback-hook",
    "/forensics/api-hook/audit-hook-detect",
    "/forensics/api-hook/debug-register-abuse",
    "/forensics/api-hook/exception-handler-hook",
    "/forensics/api-hook/ki-user-hook-detect",
]


class MemoryForensicsModule(BaseAttackModule):
    """
    Memory forensics artifact detection simulation for DFIR validation.

    Tests endpoint responses for indicators of memory forensics artifact
    exposure, including crash dump availability, credential material
    leakage, process injection indicators, and memory-resident malware
    signatures. Useful for validating that memory artifacts are not
    inadvertently exposed through web interfaces or debug endpoints.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="memory_forensics",
            description=(
                "Memory forensics artifact detection simulation - process hollowing, "
                "reflective DLL injection, LSASS dumps, shellcode injection, "
                "process doppelganging, thread hijacking, API hooking"
            ),
            category="forensics",
            mitre_technique_ids=["T1003", "T1003.001", "T1055", "T1055.001", "T1055.003", "T1055.012"],
            mitre_technique_names=[
                "OS Credential Dumping",
                "OS Credential Dumping: LSASS Memory",
                "Process Injection",
                "Process Injection: Dynamic-link Library Injection",
                "Process Injection: Thread Execution Hijacking",
                "Process Injection: Process Hollowing",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200", "CWE-538", "CWE-497", "CWE-215"],
            tags=[
                "forensics", "memory", "dfir", "process_injection",
                "credential_dumping", "shellcode", "hooking",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Assemble memory forensics detection payloads across all categories."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("memory_forensics", limit=500)
            if db_payloads:
                return db_payloads

        payloads: list[str] = []

        categories = options.get("categories", [
            "process_hollowing", "reflective_dll", "lsass_dump",
            "memory_malware", "shellcode_injection",
            "process_doppelganging", "thread_hijacking", "api_hooking",
        ])

        if "process_hollowing" in categories:
            payloads.extend(PROCESS_HOLLOWING_PAYLOADS)
        if "reflective_dll" in categories:
            payloads.extend(REFLECTIVE_DLL_PAYLOADS)
        if "lsass_dump" in categories:
            payloads.extend(LSASS_DUMP_PAYLOADS)
        if "memory_malware" in categories:
            payloads.extend(MEMORY_MALWARE_PAYLOADS)
        if "shellcode_injection" in categories:
            payloads.extend(SHELLCODE_INJECTION_PAYLOADS)
        if "process_doppelganging" in categories:
            payloads.extend(PROCESS_DOPPELGANGING_PAYLOADS)
        if "thread_hijacking" in categories:
            payloads.extend(THREAD_HIJACKING_PAYLOADS)
        if "api_hooking" in categories:
            payloads.extend(API_HOOKING_PAYLOADS)

        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        """Build memory forensics detection requests from payloads."""
        requests: list[AttackRequest] = []
        base_path = options.get("base_path", "")

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]
            path = f"{base_path}{payload}" if not payload.startswith("http") else payload

            # Determine the attack type category from payload path
            attack_type = "memory_forensics"
            if "hollowing" in payload or "hollowed" in payload:
                attack_type = "process_hollowing"
            elif "reflective" in payload:
                attack_type = "reflective_dll_injection"
            elif "lsass" in payload:
                attack_type = "lsass_dump"
            elif "memory-malware" in payload:
                attack_type = "memory_malware"
            elif "shellcode" in payload:
                attack_type = "shellcode_injection"
            elif "doppelganging" in payload or "herpaderping" in payload or "ghosting" in payload:
                attack_type = "process_doppelganging"
            elif "thread-hijack" in payload:
                attack_type = "thread_hijacking"
            elif "api-hook" in payload:
                attack_type = "api_hooking"

            # GET request to probe for exposed forensics artifacts
            requests.append(AttackRequest(
                request_id=f"memforensics-{req_id}",
                target=target,
                method="GET",
                path=path,
                headers={
                    "X-BAS-Attack-Type": attack_type,
                    "Accept": "application/json, application/octet-stream, text/plain",
                    "X-Forensics-Scan": "true",
                },
                timeout=options.get("timeout", 30.0),
            ))

            # POST request to test for artifact generation endpoints
            if options.get("include_post", True):
                post_req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"memforensics-post-{post_req_id}",
                    target=target,
                    method="POST",
                    path=path,
                    body=f'{{"action":"detect","target":"{payload.split("/")[-1]}","format":"raw"}}',
                    content_type="application/json",
                    headers={
                        "X-BAS-Attack-Type": attack_type,
                        "X-Forensics-Scan": "true",
                    },
                    timeout=options.get("timeout", 30.0),
                ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        """Analyze response for memory forensics artifact indicators."""
        body_lower = response.body_text.lower()
        attack_type = request.headers.get("X-BAS-Attack-Type", "memory_forensics")

        # Map attack types to MITRE technique IDs
        technique_map = {
            "process_hollowing": "T1055.012",
            "reflective_dll_injection": "T1055.001",
            "lsass_dump": "T1003.001",
            "memory_malware": "T1055",
            "shellcode_injection": "T1055",
            "process_doppelganging": "T1055.013",
            "thread_hijacking": "T1055.003",
            "api_hooking": "T1055",
            "memory_forensics": "T1003",
        }
        technique_id = technique_map.get(attack_type, "T1003")

        # Map attack types to severity levels
        severity_map = {
            "lsass_dump": "critical",
            "process_hollowing": "high",
            "reflective_dll_injection": "high",
            "shellcode_injection": "high",
            "process_doppelganging": "high",
            "thread_hijacking": "high",
            "api_hooking": "medium",
            "memory_malware": "high",
            "memory_forensics": "medium",
        }
        base_severity = severity_map.get(attack_type, "medium")

        # Check for binary content type headers (potential dump file exposure)
        response_content_type = response.headers.get("content-type", "").lower()
        for sig_header in MEMORY_HEADER_SIGNATURES:
            if sig_header in response_content_type:
                return ModuleResult(
                    module_name="memory_forensics",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Memory artifact exposure via content type: {response_content_type}. "
                        f"Endpoint returned binary data suggestive of memory dump material."
                    ),
                    severity="critical",
                    mitre_technique_id=technique_id,
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "content_type_header",
                        "content_type": response_content_type,
                    },
                )

        # Check for memory forensics artifact signatures in response body
        matched_signatures: list[str] = []
        for pattern in COMPILED_MEMORY_SIGNATURES:
            match = pattern.search(body_lower)
            if match:
                matched_signatures.append(match.group(0))

        if len(matched_signatures) >= 3:
            # Multiple forensics artifact signatures detected - strong indicator
            return ModuleResult(
                module_name="memory_forensics",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Multiple memory forensics artifacts detected ({len(matched_signatures)} signatures): "
                    f"{', '.join(matched_signatures[:5])}. "
                    f"Endpoint exposes detailed memory analysis data."
                ),
                severity=base_severity,
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "detection_method": "multi_signature_match",
                    "matched_signatures": matched_signatures[:10],
                    "signature_count": len(matched_signatures),
                },
            )

        if len(matched_signatures) == 1 or len(matched_signatures) == 2:
            # Single or double signature match - potential indicator
            return ModuleResult(
                module_name="memory_forensics",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Memory forensics artifact indicator detected: "
                    f"{', '.join(matched_signatures)}. "
                    f"Response may contain partial memory analysis data."
                ),
                severity="medium" if base_severity == "critical" else "low",
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "detection_method": "single_signature_match",
                    "matched_signatures": matched_signatures,
                },
            )

        # Check for large response bodies that may indicate dump data exposure
        if response.status_code == 200 and len(response.body_text) > 50000:
            return ModuleResult(
                module_name="memory_forensics",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Large response body ({len(response.body_text)} bytes) returned from "
                    f"forensics endpoint - may indicate memory data exposure."
                ),
                severity="low",
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "detection_method": "large_response_body",
                    "response_size": len(response.body_text),
                },
            )

        # Check for debug/diagnostic information disclosure via status codes
        if response.status_code == 200 and attack_type == "lsass_dump":
            # Any 200 response to LSASS-related endpoints is suspicious
            if any(keyword in body_lower for keyword in ["success", "completed", "dump", "created"]):
                return ModuleResult(
                    module_name="memory_forensics",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"LSASS-related endpoint returned success response - "
                        f"may indicate credential dump capability."
                    ),
                    severity="high",
                    mitre_technique_id="T1003.001",
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "lsass_success_response",
                    },
                )

        # Not vulnerable - endpoint properly handled
        return ModuleResult(
            module_name="memory_forensics",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
