"""
Disk Forensics and Anti-Forensics testing module.

Tests for disk artifact detection indicators and anti-forensic technique
evidence. Simulates detection of timestomping, alternate data streams (ADS),
deleted file recovery, log tampering, MFT anomalies, file slack space analysis,
volume shadow copy access, and recycle bin forensics.

MITRE ATT&CK: T1070 - Indicator Removal, T1006 - Direct Volume Access
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---- Response signatures indicating disk forensics artifact exposure ----

DISK_ARTIFACT_SIGNATURES = [
    # Timestomping indicators
    r"\$STANDARD_INFORMATION",
    r"\$FILE_NAME",
    r"timestamp\s*mismatch",
    r"MACE\s*value",
    r"modified.*accessed.*created.*entry",
    r"timestomp",
    r"SetFileTime",
    r"NtSetInformationFile",
    r"creation\s*time.*modification\s*time",
    r"birth\s*time",
    # Alternate Data Stream indicators
    r"alternate\s*data\s*stream",
    r"ADS\s*detected",
    r"zone\.identifier",
    r":\$DATA",
    r"named\s*stream",
    r"NtCreateFile.*stream",
    r"NTFS\s*stream",
    # MFT indicators
    r"master\s*file\s*table",
    r"\$MFT",
    r"\$MFTMirr",
    r"\$LogFile",
    r"\$UsnJrnl",
    r"\$Bitmap",
    r"\$Boot",
    r"\$Extend",
    r"FILE\s*record",
    r"file\s*record\s*header",
    r"MFT\s*entry",
    r"resident\s*attribute",
    r"non.resident\s*attribute",
    r"fixup\s*array",
    # Volume Shadow Copy
    r"shadow\s*cop(y|ies)",
    r"vssadmin",
    r"vss\s*snapshot",
    r"Win32_ShadowCopy",
    r"volsnap",
    r"previous\s*version",
    r"snapshot\s*set",
    # Log tampering indicators
    r"event\s*log\s*(clear|wipe|tamper|delete)",
    r"security\.evtx",
    r"system\.evtx",
    r"application\.evtx",
    r"wevtutil\s*cl",
    r"Clear-EventLog",
    r"ElfClearEventLog",
    r"log\s*rotation\s*anomal",
    r"log\s*gap\s*detect",
    r"syslog.*delete",
    # Deleted file recovery
    r"deleted\s*file",
    r"undelete",
    r"file\s*recovery",
    r"carv(e|ing)",
    r"orphan\s*file",
    r"unallocated\s*(cluster|space)",
    r"\$Recycle\.Bin",
    r"INFO2\s*file",
    r"\$I\d{6}",
    r"\$R\d{6}",
    # File slack space
    r"slack\s*space",
    r"file\s*slack",
    r"ram\s*slack",
    r"drive\s*slack",
    r"residual\s*data",
    r"cluster\s*tip",
    r"sector\s*slack",
    # Disk wiping / anti-forensics indicators
    r"secure\s*erase",
    r"disk\s*wipe",
    r"sdelete",
    r"cipher\s*/w",
    r"eraser\s*tool",
    r"dban",
    r"data\s*sanitiz",
    r"zero.?fill",
    r"overwrite\s*pass",
    # Filesystem metadata
    r"inode",
    r"journal\s*entry",
    r"superblock",
    r"ext[234]\s*journal",
    r"ntfs\s*journal",
    r"change\s*journal",
]

COMPILED_DISK_SIGNATURES = [re.compile(sig, re.IGNORECASE) for sig in DISK_ARTIFACT_SIGNATURES]

# Header signatures indicating disk artifact exposure
DISK_HEADER_SIGNATURES = [
    "application/x-raw-disk-image",
    "application/x-vmdk",
    "application/x-vhd",
    "application/x-ewf",
    "application/x-aff",
    "application/x-tar",
    "application/x-gzip",
    "application/vnd.ms-cab-compressed",
]

# ---- Payload categories ----

# Timestomping detection payloads
TIMESTOMPING_PAYLOADS = [
    "/api/forensics/timestomp/detect",
    "/api/forensics/timestomp/si-fn-mismatch",
    "/api/forensics/timestomp/mace-analysis",
    "/api/forensics/timestomp/mft-timeline",
    "/api/forensics/timestomp/usnjrnl-compare",
    "/api/forensics/timestomp/logfile-compare",
    "/api/forensics/timestomp/creation-before-modify",
    "/api/forensics/timestomp/future-timestamp",
    "/api/forensics/timestomp/epoch-zero-detect",
    "/api/forensics/timestomp/year-anomaly",
    "/api/forensics/timestomp/nanosecond-zero",
    "/api/forensics/timestomp/bulk-timestamp-match",
    "/api/forensics/timestomp/rounded-timestamp",
    "/api/forensics/timestomp/timezone-anomaly",
    "/api/forensics/timestomp/SetFileTime-trace",
    "/api/forensics/timestomp/NtSetInformationFile-trace",
    "/api/forensics/timestomp/SetFileInformationByHandle-trace",
    "/api/forensics/timestomp/powershell-timestamp-set",
    "/api/forensics/timestomp/wmi-timestamp-modify",
    "/api/forensics/timestomp/copy-timestamp-from",
    "/forensics/timestomp/compilation-vs-creation",
    "/forensics/timestomp/pe-timestamp-analysis",
    "/forensics/timestomp/exif-metadata-mismatch",
    "/forensics/timestomp/filesystem-journal-delta",
    "/forensics/timestomp/parent-child-time-anomaly",
    "/forensics/timestomp/access-time-disabled-check",
    "/forensics/timestomp/last-access-anomaly",
    "/forensics/timestomp/ntfs-tunneling-detect",
    "/forensics/timestomp/timestamp-entropy-analysis",
    "/forensics/timestomp/batch-timestomp-detect",
    "/forensics/timestomp/si-attribute-analysis",
    "/forensics/timestomp/fn-attribute-analysis",
    "/forensics/timestomp/cross-volume-time-check",
    "/forensics/timestomp/daylight-saving-anomaly",
    "/forensics/timestomp/leap-second-anomaly",
]

# Alternate Data Stream (ADS) enumeration payloads
ADS_ENUMERATION_PAYLOADS = [
    "/api/forensics/ads/enumerate",
    "/api/forensics/ads/zone-identifier",
    "/api/forensics/ads/hidden-stream-detect",
    "/api/forensics/ads/executable-in-ads",
    "/api/forensics/ads/malware-in-ads",
    "/api/forensics/ads/data-hiding-detect",
    "/api/forensics/ads/stream-size-analysis",
    "/api/forensics/ads/NtCreateFile-stream",
    "/api/forensics/ads/NtQueryInformationFile-stream",
    "/api/forensics/ads/FindFirstStreamW-trace",
    "/api/forensics/ads/BackupRead-detect",
    "/api/forensics/ads/dir-slash-r-analysis",
    "/api/forensics/ads/streams-exe-scan",
    "/api/forensics/ads/powershell-get-item-stream",
    "/api/forensics/ads/wmic-ads-detect",
    "/api/forensics/ads/type-command-stream",
    "/api/forensics/ads/notepad-stream-access",
    "/api/forensics/ads/makecab-stream-extract",
    "/api/forensics/ads/expand-stream-extract",
    "/api/forensics/ads/esentutl-stream-copy",
    "/forensics/ads/thumbnail-cache-stream",
    "/forensics/ads/summary-information-stream",
    "/forensics/ads/document-summary-stream",
    "/forensics/ads/encryptable-stream",
    "/forensics/ads/compressible-stream",
    "/forensics/ads/reparse-point-stream",
    "/forensics/ads/default-data-stream",
    "/forensics/ads/resource-fork-stream",
    "/forensics/ads/security-descriptor-stream",
    "/forensics/ads/ea-information-stream",
    "/forensics/ads/object-id-stream",
    "/forensics/ads/logged-utility-stream",
    "/forensics/ads/motw-bypass-detect",
    "/forensics/ads/smartscreen-bypass-ads",
    "/forensics/ads/applocker-bypass-ads",
]

# Deleted file recovery indicator payloads
DELETED_FILE_RECOVERY_PAYLOADS = [
    "/api/forensics/deleted/file-carving",
    "/api/forensics/deleted/header-carving",
    "/api/forensics/deleted/footer-carving",
    "/api/forensics/deleted/mft-deleted-entries",
    "/api/forensics/deleted/recycle-bin-analysis",
    "/api/forensics/deleted/unallocated-scan",
    "/api/forensics/deleted/orphan-mft-entries",
    "/api/forensics/deleted/journal-deleted-trace",
    "/api/forensics/deleted/usnjrnl-delete-events",
    "/api/forensics/deleted/shadow-copy-recovery",
    "/api/forensics/deleted/photorec-scan",
    "/api/forensics/deleted/foremost-scan",
    "/api/forensics/deleted/scalpel-scan",
    "/api/forensics/deleted/bulk-extractor-scan",
    "/api/forensics/deleted/magicrescue-scan",
    "/api/forensics/deleted/ntfs-undelete",
    "/api/forensics/deleted/ext4-undelete",
    "/api/forensics/deleted/fat-undelete",
    "/api/forensics/deleted/hfs-undelete",
    "/api/forensics/deleted/apfs-snapshot-recovery",
    "/api/forensics/deleted/btrfs-snapshot-recovery",
    "/api/forensics/deleted/zfs-snapshot-recovery",
    "/api/forensics/deleted/thumbnail-cache-recovery",
    "/api/forensics/deleted/prefetch-recovery",
    "/api/forensics/deleted/shellbag-recovery",
    "/api/forensics/deleted/lnk-file-recovery",
    "/api/forensics/deleted/jumplists-recovery",
    "/api/forensics/deleted/browser-cache-recovery",
    "/api/forensics/deleted/swap-partition-carving",
    "/api/forensics/deleted/pagefile-carving",
    "/forensics/deleted/signature-based-carve",
    "/forensics/deleted/entropy-based-carve",
    "/forensics/deleted/fragment-recovery",
    "/forensics/deleted/cluster-chain-analysis",
    "/forensics/deleted/directory-entry-recovery",
]

# Log tampering detection payloads
LOG_TAMPERING_PAYLOADS = [
    "/api/forensics/log-tamper/event-log-clear-detect",
    "/api/forensics/log-tamper/security-log-gap",
    "/api/forensics/log-tamper/system-log-gap",
    "/api/forensics/log-tamper/application-log-gap",
    "/api/forensics/log-tamper/powershell-log-gap",
    "/api/forensics/log-tamper/sysmon-log-gap",
    "/api/forensics/log-tamper/event-1102-detect",
    "/api/forensics/log-tamper/event-104-detect",
    "/api/forensics/log-tamper/wevtutil-cl-trace",
    "/api/forensics/log-tamper/Clear-EventLog-trace",
    "/api/forensics/log-tamper/ElfClearEventLog-trace",
    "/api/forensics/log-tamper/EvtClearLog-trace",
    "/api/forensics/log-tamper/etw-tamper-detect",
    "/api/forensics/log-tamper/etw-provider-disable",
    "/api/forensics/log-tamper/etw-session-stop",
    "/api/forensics/log-tamper/NtTraceControl-tamper",
    "/api/forensics/log-tamper/syslog-deletion",
    "/api/forensics/log-tamper/auth-log-gap",
    "/api/forensics/log-tamper/kern-log-gap",
    "/api/forensics/log-tamper/wtmp-tamper",
    "/api/forensics/log-tamper/utmp-tamper",
    "/api/forensics/log-tamper/btmp-tamper",
    "/api/forensics/log-tamper/lastlog-tamper",
    "/api/forensics/log-tamper/journal-vacuum",
    "/api/forensics/log-tamper/logrotate-abuse",
    "/api/forensics/log-tamper/iis-log-tamper",
    "/api/forensics/log-tamper/apache-log-tamper",
    "/api/forensics/log-tamper/nginx-log-tamper",
    "/api/forensics/log-tamper/audit-log-tamper",
    "/api/forensics/log-tamper/auditd-stop-detect",
    "/forensics/log-tamper/sequence-number-gap",
    "/forensics/log-tamper/record-number-anomaly",
    "/forensics/log-tamper/timestamp-discontinuity",
    "/forensics/log-tamper/log-file-truncation",
    "/forensics/log-tamper/log-file-overwrite",
]

# MFT anomaly detection payloads
MFT_ANOMALY_PAYLOADS = [
    "/api/forensics/mft/anomaly-detect",
    "/api/forensics/mft/entry-analysis",
    "/api/forensics/mft/resident-data-extract",
    "/api/forensics/mft/non-resident-analysis",
    "/api/forensics/mft/attribute-list-analysis",
    "/api/forensics/mft/filename-attribute-check",
    "/api/forensics/mft/si-attribute-check",
    "/api/forensics/mft/data-attribute-check",
    "/api/forensics/mft/index-root-analysis",
    "/api/forensics/mft/index-allocation-analysis",
    "/api/forensics/mft/bitmap-analysis",
    "/api/forensics/mft/reparse-point-analysis",
    "/api/forensics/mft/ea-attribute-analysis",
    "/api/forensics/mft/object-id-analysis",
    "/api/forensics/mft/security-descriptor-analysis",
    "/api/forensics/mft/volume-name-analysis",
    "/api/forensics/mft/volume-information-analysis",
    "/api/forensics/mft/logfile-analysis",
    "/api/forensics/mft/usnjrnl-analysis",
    "/api/forensics/mft/usnjrnl-j-parse",
    "/api/forensics/mft/orphan-entry-detect",
    "/api/forensics/mft/slack-entry-detect",
    "/api/forensics/mft/fixup-array-anomaly",
    "/api/forensics/mft/sequence-number-anomaly",
    "/api/forensics/mft/parent-reference-anomaly",
    "/api/forensics/mft/hard-link-anomaly",
    "/forensics/mft/raw-mft-parse",
    "/forensics/mft/mft-mirror-compare",
    "/forensics/mft/deleted-entry-recover",
    "/forensics/mft/timeline-generation",
    "/forensics/mft/cluster-allocation-analysis",
    "/forensics/mft/extent-analysis",
    "/forensics/mft/fragmentation-analysis",
    "/forensics/mft/compression-unit-analysis",
    "/forensics/mft/sparse-file-analysis",
]

# File slack space analysis payloads
SLACK_SPACE_PAYLOADS = [
    "/api/forensics/slack/file-slack-analysis",
    "/api/forensics/slack/ram-slack-detect",
    "/api/forensics/slack/drive-slack-detect",
    "/api/forensics/slack/cluster-tip-analysis",
    "/api/forensics/slack/sector-slack-analysis",
    "/api/forensics/slack/partition-slack-analysis",
    "/api/forensics/slack/inter-partition-gap",
    "/api/forensics/slack/volume-slack-analysis",
    "/api/forensics/slack/hidden-data-detect",
    "/api/forensics/slack/residual-data-extract",
    "/api/forensics/slack/overwritten-data-detect",
    "/api/forensics/slack/partial-overwrite-detect",
    "/api/forensics/slack/steganography-detect",
    "/api/forensics/slack/entropy-analysis",
    "/api/forensics/slack/pattern-analysis",
    "/api/forensics/slack/keyword-search-slack",
    "/api/forensics/slack/carve-slack-data",
    "/api/forensics/slack/hpa-analysis",
    "/api/forensics/slack/dco-analysis",
    "/api/forensics/slack/firmware-area-check",
    "/forensics/slack/ntfs-cluster-slack",
    "/forensics/slack/fat-cluster-slack",
    "/forensics/slack/ext4-block-slack",
    "/forensics/slack/hfs-allocation-slack",
    "/forensics/slack/xfs-extent-slack",
    "/forensics/slack/btrfs-extent-slack",
    "/forensics/slack/zfs-block-slack",
    "/forensics/slack/swap-space-analysis",
    "/forensics/slack/free-space-carving",
    "/forensics/slack/unallocated-space-scan",
    "/forensics/slack/bad-cluster-analysis",
    "/forensics/slack/reserved-sector-analysis",
    "/forensics/slack/boot-sector-slack",
    "/forensics/slack/mbr-gap-analysis",
    "/forensics/slack/gpt-gap-analysis",
]

# Volume shadow copy access payloads
SHADOW_COPY_PAYLOADS = [
    "/api/forensics/vss/list-shadows",
    "/api/forensics/vss/mount-snapshot",
    "/api/forensics/vss/diff-analysis",
    "/api/forensics/vss/deleted-file-recovery",
    "/api/forensics/vss/previous-version-access",
    "/api/forensics/vss/snapshot-timeline",
    "/api/forensics/vss/vssadmin-list-shadows",
    "/api/forensics/vss/wmic-shadowcopy-list",
    "/api/forensics/vss/diskshadow-expose",
    "/api/forensics/vss/mklink-shadow-access",
    "/api/forensics/vss/esentutl-shadow-copy",
    "/api/forensics/vss/ntdsutil-ifm-create",
    "/api/forensics/vss/vshadow-expose",
    "/api/forensics/vss/harvestv-shadow-parse",
    "/api/forensics/vss/volrest-recovery",
    "/api/forensics/vss/snapshot-catalog-parse",
    "/api/forensics/vss/diff-area-analysis",
    "/api/forensics/vss/copy-on-write-analysis",
    "/api/forensics/vss/provider-analysis",
    "/api/forensics/vss/writer-analysis",
    "/api/forensics/vss/shadow-delete-detect",
    "/api/forensics/vss/vssadmin-delete-shadows",
    "/api/forensics/vss/wmic-shadowcopy-delete",
    "/api/forensics/vss/resize-maxsize-detect",
    "/api/forensics/vss/vss-disable-detect",
    "/forensics/vss/registry-key-analysis",
    "/forensics/vss/scheduled-task-analysis",
    "/forensics/vss/com-object-analysis",
    "/forensics/vss/service-analysis",
    "/forensics/vss/driver-analysis",
    "/forensics/vss/timestamp-analysis",
    "/forensics/vss/snapshot-metadata-parse",
    "/forensics/vss/block-level-diff",
    "/forensics/vss/file-level-diff",
    "/forensics/vss/ntds-dit-extraction",
]

# Recycle bin forensics payloads
RECYCLE_BIN_PAYLOADS = [
    "/api/forensics/recycle-bin/enumerate",
    "/api/forensics/recycle-bin/i-file-parse",
    "/api/forensics/recycle-bin/r-file-recover",
    "/api/forensics/recycle-bin/metadata-extract",
    "/api/forensics/recycle-bin/original-path",
    "/api/forensics/recycle-bin/deletion-timestamp",
    "/api/forensics/recycle-bin/file-size-analysis",
    "/api/forensics/recycle-bin/sid-analysis",
    "/api/forensics/recycle-bin/orphaned-r-files",
    "/api/forensics/recycle-bin/cross-user-analysis",
    "/api/forensics/recycle-bin/network-drive-recycle",
    "/api/forensics/recycle-bin/info2-legacy-parse",
    "/api/forensics/recycle-bin/empty-recycle-detect",
    "/api/forensics/recycle-bin/secure-delete-detect",
    "/api/forensics/recycle-bin/bulk-deletion-detect",
    "/api/forensics/recycle-bin/timeline-analysis",
    "/api/forensics/recycle-bin/pattern-analysis",
    "/api/forensics/recycle-bin/file-type-distribution",
    "/api/forensics/recycle-bin/size-distribution",
    "/api/forensics/recycle-bin/frequency-analysis",
    "/forensics/recycle-bin/trash-info-parse",
    "/forensics/recycle-bin/xdg-trash-analysis",
    "/forensics/recycle-bin/macos-trash-analysis",
    "/forensics/recycle-bin/dsstore-analysis",
    "/forensics/recycle-bin/putback-info-parse",
    "/forensics/recycle-bin/spotlight-metadata",
    "/forensics/recycle-bin/finder-plist-analysis",
    "/forensics/recycle-bin/atime-analysis",
    "/forensics/recycle-bin/ctime-analysis",
    "/forensics/recycle-bin/mtime-analysis",
    "/forensics/recycle-bin/dtime-analysis",
    "/forensics/recycle-bin/ext4-journal-recovery",
    "/forensics/recycle-bin/btrfs-subvol-snapshot",
    "/forensics/recycle-bin/zfs-snapshot-diff",
    "/forensics/recycle-bin/apfs-snapshot-diff",
]


class DiskForensicsModule(BaseAttackModule):
    """
    Disk forensics artifact detection and anti-forensics testing module.

    Tests endpoint responses for indicators of disk forensics artifact
    exposure and evidence of anti-forensic techniques. Validates that
    forensics-relevant data such as deleted file metadata, MFT entries,
    alternate data streams, volume shadow copies, and log files are not
    inadvertently accessible through web interfaces or API endpoints.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="disk_forensics",
            description=(
                "Disk forensics artifact detection and anti-forensics testing - "
                "timestomping, ADS enumeration, deleted file recovery, log tampering, "
                "MFT anomalies, slack space analysis, volume shadow copies, recycle bin"
            ),
            category="forensics",
            mitre_technique_ids=[
                "T1070", "T1070.001", "T1070.003", "T1070.004",
                "T1070.006", "T1006", "T1564.004",
            ],
            mitre_technique_names=[
                "Indicator Removal",
                "Indicator Removal: Clear Windows Event Logs",
                "Indicator Removal: Clear Command History",
                "Indicator Removal: File Deletion",
                "Indicator Removal: Timestomp",
                "Direct Volume Access",
                "Hide Artifacts: NTFS File Attributes",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="A05:2021 - Security Misconfiguration",
            cwe_ids=["CWE-200", "CWE-538", "CWE-532", "CWE-117"],
            tags=[
                "forensics", "disk", "dfir", "anti-forensics",
                "timestomping", "log_tampering", "mft", "ads",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Assemble disk forensics detection payloads across all categories."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("disk_forensics", limit=500)
            if db_payloads:
                return db_payloads

        payloads: list[str] = []

        categories = options.get("categories", [
            "timestomping", "ads_enumeration", "deleted_file_recovery",
            "log_tampering", "mft_anomaly", "slack_space",
            "shadow_copy", "recycle_bin",
        ])

        if "timestomping" in categories:
            payloads.extend(TIMESTOMPING_PAYLOADS)
        if "ads_enumeration" in categories:
            payloads.extend(ADS_ENUMERATION_PAYLOADS)
        if "deleted_file_recovery" in categories:
            payloads.extend(DELETED_FILE_RECOVERY_PAYLOADS)
        if "log_tampering" in categories:
            payloads.extend(LOG_TAMPERING_PAYLOADS)
        if "mft_anomaly" in categories:
            payloads.extend(MFT_ANOMALY_PAYLOADS)
        if "slack_space" in categories:
            payloads.extend(SLACK_SPACE_PAYLOADS)
        if "shadow_copy" in categories:
            payloads.extend(SHADOW_COPY_PAYLOADS)
        if "recycle_bin" in categories:
            payloads.extend(RECYCLE_BIN_PAYLOADS)

        return payloads

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        """Build disk forensics detection requests from payloads."""
        requests: list[AttackRequest] = []
        base_path = options.get("base_path", "")

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]
            path = f"{base_path}{payload}" if not payload.startswith("http") else payload

            # Determine the attack type category from payload path
            attack_type = "disk_forensics"
            if "timestomp" in payload:
                attack_type = "timestomping"
            elif "ads/" in payload or "stream" in payload.lower():
                attack_type = "ads_enumeration"
            elif "deleted" in payload or "carv" in payload or "undelete" in payload:
                attack_type = "deleted_file_recovery"
            elif "log-tamper" in payload:
                attack_type = "log_tampering"
            elif "mft/" in payload:
                attack_type = "mft_anomaly"
            elif "slack/" in payload:
                attack_type = "slack_space"
            elif "vss/" in payload or "shadow" in payload:
                attack_type = "shadow_copy"
            elif "recycle-bin" in payload or "trash" in payload:
                attack_type = "recycle_bin"

            # GET request to probe for exposed forensics artifacts
            requests.append(AttackRequest(
                request_id=f"diskforensics-{req_id}",
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

            # POST request to test for artifact retrieval endpoints
            if options.get("include_post", True):
                post_req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"diskforensics-post-{post_req_id}",
                    target=target,
                    method="POST",
                    path=path,
                    body=f'{{"action":"analyze","target":"{payload.split("/")[-1]}","depth":"full"}}',
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
        """Analyze response for disk forensics artifact and anti-forensics indicators."""
        body_lower = response.body_text.lower()
        attack_type = request.headers.get("X-BAS-Attack-Type", "disk_forensics")

        # Map attack types to MITRE technique IDs
        technique_map = {
            "timestomping": "T1070.006",
            "ads_enumeration": "T1564.004",
            "deleted_file_recovery": "T1070.004",
            "log_tampering": "T1070.001",
            "mft_anomaly": "T1006",
            "slack_space": "T1006",
            "shadow_copy": "T1006",
            "recycle_bin": "T1070.004",
            "disk_forensics": "T1070",
        }
        technique_id = technique_map.get(attack_type, "T1070")

        # Map attack types to severity levels
        severity_map = {
            "log_tampering": "critical",
            "timestomping": "high",
            "ads_enumeration": "high",
            "deleted_file_recovery": "medium",
            "mft_anomaly": "high",
            "slack_space": "medium",
            "shadow_copy": "high",
            "recycle_bin": "medium",
            "disk_forensics": "medium",
        }
        base_severity = severity_map.get(attack_type, "medium")

        # Check for suspicious content type headers (raw disk/image data)
        response_content_type = response.headers.get("content-type", "").lower()
        for sig_header in DISK_HEADER_SIGNATURES:
            if sig_header in response_content_type:
                return ModuleResult(
                    module_name="disk_forensics",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Disk forensics artifact exposure via content type: {response_content_type}. "
                        f"Endpoint returned data suggestive of raw disk or image content."
                    ),
                    severity="critical",
                    mitre_technique_id=technique_id,
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "content_type_header",
                        "content_type": response_content_type,
                    },
                )

        # Check for disk forensics artifact signatures in response body
        matched_signatures: list[str] = []
        for pattern in COMPILED_DISK_SIGNATURES:
            match = pattern.search(body_lower)
            if match:
                matched_signatures.append(match.group(0))

        if len(matched_signatures) >= 3:
            # Multiple disk forensics artifact signatures - strong indicator
            return ModuleResult(
                module_name="disk_forensics",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Multiple disk forensics artifacts detected ({len(matched_signatures)} signatures): "
                    f"{', '.join(matched_signatures[:5])}. "
                    f"Endpoint exposes detailed disk analysis data."
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
                module_name="disk_forensics",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Disk forensics artifact indicator detected: "
                    f"{', '.join(matched_signatures)}. "
                    f"Response may contain partial disk forensics data."
                ),
                severity="medium" if base_severity in ("critical", "high") else "low",
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "detection_method": "single_signature_match",
                    "matched_signatures": matched_signatures,
                },
            )

        # Check for evidence of anti-forensic activity confirmation
        anti_forensic_confirmations = [
            "cleared", "wiped", "erased", "deleted successfully",
            "logs removed", "history cleared", "timestamps modified",
            "shadow copies deleted", "recycle bin emptied",
            "event log cleared", "journal truncated",
        ]
        for indicator in anti_forensic_confirmations:
            if indicator in body_lower:
                return ModuleResult(
                    module_name="disk_forensics",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Anti-forensic activity confirmation detected: '{indicator}'. "
                        f"Endpoint may facilitate evidence destruction."
                    ),
                    severity="critical",
                    mitre_technique_id=technique_id,
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "anti_forensic_confirmation",
                        "matched_indicator": indicator,
                    },
                )

        # Check for large response bodies that may indicate raw data exposure
        if response.status_code == 200 and len(response.body_text) > 50000:
            return ModuleResult(
                module_name="disk_forensics",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=(
                    f"Large response body ({len(response.body_text)} bytes) returned from "
                    f"disk forensics endpoint - may indicate raw data exposure."
                ),
                severity="low",
                mitre_technique_id=technique_id,
                detail={
                    "attack_type": attack_type,
                    "detection_method": "large_response_body",
                    "response_size": len(response.body_text),
                },
            )

        # Check for log tampering endpoints returning success
        if response.status_code == 200 and attack_type == "log_tampering":
            if any(keyword in body_lower for keyword in ["success", "completed", "cleared", "removed"]):
                return ModuleResult(
                    module_name="disk_forensics",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Log tampering endpoint returned success response - "
                        f"may indicate capability to clear or modify audit logs."
                    ),
                    severity="high",
                    mitre_technique_id="T1070.001",
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "log_tamper_success_response",
                    },
                )

        # Check for shadow copy deletion endpoints returning success
        if response.status_code == 200 and attack_type == "shadow_copy":
            if any(keyword in body_lower for keyword in ["deleted", "removed", "destroyed", "purged"]):
                return ModuleResult(
                    module_name="disk_forensics",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Volume shadow copy endpoint indicates deletion capability - "
                        f"may facilitate destruction of backup forensic evidence."
                    ),
                    severity="high",
                    mitre_technique_id="T1490",
                    detail={
                        "attack_type": attack_type,
                        "detection_method": "shadow_copy_deletion_response",
                    },
                )

        # Not vulnerable - endpoint properly handled
        return ModuleResult(
            module_name="disk_forensics",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
