"""
Azure Security Assessment module.

Tests for Azure-specific attack vectors including Blob storage exposure,
Azure AD endpoints, Function App exposure, App Service misconfiguration,
Key Vault probing, Azure DevOps exposure, and management API endpoints.

MITRE ATT&CK: T1530 - Data from Cloud Storage Object
               T1078.004 - Valid Accounts: Cloud Accounts
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Azure Blob Storage exposure payloads
# ---------------------------------------------------------------------------
BLOB_STORAGE_PAYLOADS = [
    # Container enumeration
    "/?comp=list",
    "/?restype=container&comp=list",
    "/{target}?restype=container&comp=list",
    "/$web?restype=container&comp=list",
    "/$logs?restype=container&comp=list",
    "/insights-logs?restype=container&comp=list",
    "/azure-webjobs-hosts?restype=container&comp=list",
    "/azure-webjobs-secrets?restype=container&comp=list",
    "/backups?restype=container&comp=list",
    "/data?restype=container&comp=list",
    "/uploads?restype=container&comp=list",
    "/assets?restype=container&comp=list",
    "/media?restype=container&comp=list",
    "/private?restype=container&comp=list",
    "/config?restype=container&comp=list",
    "/secrets?restype=container&comp=list",
    # Blob properties / metadata
    "/?comp=metadata",
    "/?comp=properties",
    "/?comp=stats",
    # SAS token probe
    "/?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacuptfx&se=2030-01-01T00:00:00Z&st=2020-01-01T00:00:00Z&spr=https&sig=test",
]

# ---------------------------------------------------------------------------
# Azure AD / Entra ID endpoint payloads
# ---------------------------------------------------------------------------
AZURE_AD_PAYLOADS = [
    # OpenID configuration
    "/.well-known/openid-configuration",
    "/v2.0/.well-known/openid-configuration",
    "/common/.well-known/openid-configuration",
    "/organizations/.well-known/openid-configuration",
    "/consumers/.well-known/openid-configuration",
    # OAuth2 endpoints
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/v2.0/authorize",
    "/oauth2/v2.0/token",
    "/oauth2/v2.0/devicecode",
    # Azure AD enumeration
    "/.well-known/openid-configuration?appid={target}",
    "/common/discovery/keys",
    "/common/discovery/instance",
    "/common/userrealm/{target}@{target}.onmicrosoft.com?api-version=2.1",
    "/GetUserRealm.srf?login={target}@{target}.onmicrosoft.com",
    # Tenant discovery
    "/{target}.onmicrosoft.com/.well-known/openid-configuration",
    "/getuserrealm.srf?login=test@{target}.onmicrosoft.com",
]

# ---------------------------------------------------------------------------
# Azure Function App exposure payloads
# ---------------------------------------------------------------------------
FUNCTION_APP_PAYLOADS = [
    # Function endpoint discovery
    "/api/",
    "/api/HttpTrigger",
    "/api/HttpTrigger1",
    "/api/webhook",
    "/api/health",
    "/api/status",
    "/api/ping",
    "/api/test",
    "/api/debug",
    "/api/admin",
    "/api/config",
    # Function admin endpoints
    "/admin/functions",
    "/admin/host/status",
    "/admin/host/keys",
    "/admin/host/systemkeys",
    "/admin/host/ping",
    "/admin/extensions",
    "/admin/functions/{target}/keys",
    # Kudu/SCM access
    "/.scm/",
    "/basicauth",
    "/api/vfs/",
    "/api/zip/site/wwwroot/",
    "/api/settings",
    "/api/deployments",
    "/api/diagnostics/runtime",
    "/webssh/host",
    "/DebugConsole",
    "/api/logstream",
]

# ---------------------------------------------------------------------------
# App Service misconfiguration payloads
# ---------------------------------------------------------------------------
APP_SERVICE_PAYLOADS = [
    # Default / debug endpoints
    "/.env",
    "/web.config",
    "/web.config.bak",
    "/appsettings.json",
    "/local.settings.json",
    "/host.json",
    "/function.json",
    # Azure-specific paths
    "/.git/config",
    "/.git/HEAD",
    "/robots.txt",
    "/elmah.axd",
    "/trace.axd",
    "/applicationinsights/",
    "/ai.aspx",
    # Authentication endpoints
    "/.auth/login/aad",
    "/.auth/login/aad/callback",
    "/.auth/me",
    "/.auth/refresh",
    "/.auth/logout",
    "/.auth/login/microsoftaccount",
    "/.auth/login/google",
    "/.auth/login/facebook",
    "/.auth/login/twitter",
]

# ---------------------------------------------------------------------------
# Azure Key Vault probing payloads
# ---------------------------------------------------------------------------
KEY_VAULT_PAYLOADS = [
    "/keys?api-version=7.3",
    "/secrets?api-version=7.3",
    "/certificates?api-version=7.3",
    "/keys?api-version=7.4",
    "/secrets?api-version=7.4",
    "/certificates?api-version=7.4",
    "/storage?api-version=7.3",
    "/deletedsecrets?api-version=7.3",
    "/deletedkeys?api-version=7.3",
    "/deletedcertificates?api-version=7.3",
]

# ---------------------------------------------------------------------------
# Azure DevOps exposure payloads
# ---------------------------------------------------------------------------
DEVOPS_PAYLOADS = [
    "/_apis/projects?api-version=7.0",
    "/_apis/git/repositories?api-version=7.0",
    "/_apis/build/builds?api-version=7.0",
    "/_apis/release/releases?api-version=7.0",
    "/_apis/distributedtask/variablegroups?api-version=7.0",
    "/_apis/serviceendpoint/endpoints?api-version=7.0",
    "/_apis/pipelines?api-version=7.0",
    "/_apis/connectionData",
    "/_apis/securitynamespaces?api-version=7.0",
    "/_apis/accesscontrollists?api-version=7.0",
    "/_apis/tokenadmin/personalaccesstokens?api-version=7.0",
]

# ---------------------------------------------------------------------------
# Azure Management API endpoint payloads
# ---------------------------------------------------------------------------
MANAGEMENT_API_PAYLOADS = [
    "/subscriptions?api-version=2020-01-01",
    "/providers?api-version=2020-01-01",
    "/tenants?api-version=2020-01-01",
    "/resourcegroups?api-version=2021-04-01",
    "/providers/Microsoft.Compute/virtualMachines?api-version=2021-07-01",
    "/providers/Microsoft.Storage/storageAccounts?api-version=2021-02-01",
    "/providers/Microsoft.Sql/servers?api-version=2021-02-01",
    "/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01",
    "/providers/Microsoft.Web/sites?api-version=2021-02-01",
    "/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-05-01",
]

# Combine all payloads
ALL_AZURE_PAYLOADS = (
    BLOB_STORAGE_PAYLOADS
    + AZURE_AD_PAYLOADS
    + FUNCTION_APP_PAYLOADS
    + APP_SERVICE_PAYLOADS
    + KEY_VAULT_PAYLOADS
    + DEVOPS_PAYLOADS
    + MANAGEMENT_API_PAYLOADS
)

# ---------------------------------------------------------------------------
# Vulnerability indicators
# ---------------------------------------------------------------------------
AZURE_INDICATORS: list[tuple[str, str, str]] = [
    # Blob Storage indicators
    ("<EnumerationResults", "Azure Blob container listing exposed", "critical"),
    ("<Blobs>", "Azure Blob objects listed", "critical"),
    ("<Blob>", "Azure Blob object accessible", "high"),
    ("BlobNotFound", "Azure Blob endpoint exists", "info"),
    ("ContainerNotFound", "Azure Blob container endpoint exists", "info"),
    ("AuthenticationFailed", "Azure storage auth required (resource exists)", "low"),
    ("AuthorizationFailure", "Azure storage auth failure (resource exists)", "low"),
    ("ResourceNotFound", "Azure resource not found", "info"),
    ("PublicAccessNotPermitted", "Public access blocked (secure config)", "info"),
    ("<SignedIdentifiers", "Azure Blob signed identifiers exposed", "medium"),
    # Azure AD indicators
    ("token_endpoint", "Azure AD token endpoint discovered", "medium"),
    ("authorization_endpoint", "Azure AD auth endpoint discovered", "medium"),
    ("issuer", "Azure AD issuer URL exposed", "medium"),
    ("tenant_discovery_endpoint", "Azure AD tenant discovery", "medium"),
    ("NameSpaceType", "Azure AD namespace type exposed (tenant exists)", "medium"),
    ("ManagedDomain", "Azure AD managed domain confirmed", "medium"),
    ("FederatedDomain", "Azure AD federated domain confirmed", "medium"),
    ("DomainName", "Azure AD domain name exposed", "medium"),
    ("CloudInstanceName", "Azure cloud instance name exposed", "low"),
    # Function App indicators
    ("Functions", "Azure Functions listing exposed", "high"),
    ("masterKey", "Azure Functions master key exposed", "critical"),
    ("functionKeys", "Azure Functions keys exposed", "critical"),
    ("systemKeys", "Azure Functions system keys exposed", "critical"),
    ("hostName", "Azure Function host name exposed", "medium"),
    ("extensionBundle", "Azure Function extension config exposed", "low"),
    # App Service indicators
    ("WEBSITE_", "Azure App Service environment variable exposed", "high"),
    ("APPSETTING_", "Azure App Service setting exposed", "high"),
    ("AzureWebJobsStorage", "Azure WebJobs storage connection string exposed", "critical"),
    ("FUNCTIONS_WORKER_RUNTIME", "Azure Functions runtime config exposed", "medium"),
    ("SCM_DO_BUILD_DURING_DEPLOYMENT", "Azure SCM config exposed", "medium"),
    ("ApplicationInsights", "Application Insights config exposed", "medium"),
    # Key Vault indicators
    ("value", "Azure Key Vault values accessible", "critical"),
    ("kid", "Azure Key Vault key ID exposed", "high"),
    ("sid", "Azure Key Vault secret ID exposed", "high"),
    ("Unauthorized", "Azure Key Vault exists - auth required", "low"),
    # DevOps indicators
    ("repositories", "Azure DevOps repositories listed", "high"),
    ("variableGroups", "Azure DevOps variable groups exposed", "critical"),
    ("serviceEndpoints", "Azure DevOps service endpoints exposed", "critical"),
    ("personalAccessTokens", "Azure DevOps PATs exposed", "critical"),
    ("pipelines", "Azure DevOps pipelines listed", "high"),
    # Management API indicators
    ("subscriptionId", "Azure subscription ID exposed", "high"),
    ("tenantId", "Azure tenant ID exposed", "medium"),
    ("resourceGroup", "Azure resource group exposed", "medium"),
    ("provisioningState", "Azure resource provisioning state exposed", "medium"),
    # Connection string patterns
    ("DefaultEndpointsProtocol", "Azure storage connection string exposed", "critical"),
    ("AccountKey=", "Azure storage account key exposed", "critical"),
    ("SharedAccessSignature=", "Azure SAS token exposed", "high"),
    ("Server=tcp:", "Azure SQL connection string exposed", "critical"),
]


class AzureSecurityModule(BaseAttackModule):
    """
    Azure Security Assessment module.

    Performs comprehensive testing of Azure-specific attack surfaces including
    Blob storage exposure, Azure AD/Entra ID endpoints, Function App exposure,
    App Service misconfiguration, Key Vault probing, Azure DevOps exposure,
    and management API endpoints.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="azure_security",
            description=(
                "Azure security assessment - Blob storage exposure, Azure AD endpoints, "
                "Function App exposure, App Service misconfig, Key Vault probing, "
                "Azure DevOps exposure, management API endpoints"
            ),
            category="cloud",
            mitre_technique_ids=["T1530", "T1078.004"],
            mitre_technique_names=[
                "Data from Cloud Storage Object",
                "Valid Accounts: Cloud Accounts",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200", "CWE-264", "CWE-522", "CWE-284"],
            tags=[
                "azure", "blob", "azure-ad", "entra-id", "function-app",
                "app-service", "key-vault", "devops", "cloud", "misconfiguration",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Retrieve Azure security testing payloads."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("azure_security", limit=300)
            if db_payloads:
                return db_payloads

        target_name = self._extract_target_name(target)
        resolved: list[str] = []
        for payload in ALL_AZURE_PAYLOADS:
            resolved.append(payload.replace("{target}", target_name))
        return resolved

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        target_name = self._extract_target_name(target)

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            # Blob storage enumeration (path-based or direct)
            if "restype=container" in payload or "comp=list" in payload:
                # Try both direct target and blob-specific URL
                blob_url = f"https://{target_name}.blob.core.windows.net"
                requests.append(AttackRequest(
                    request_id=f"azure-blob-{req_id}",
                    target=blob_url,
                    method="GET",
                    path=payload,
                    headers={
                        "x-ms-version": "2021-06-08",
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))
                continue

            # Azure AD / login endpoints
            if any(keyword in payload for keyword in ("openid-configuration", "oauth2", "userrealm", "GetUserRealm", "getuserrealm", "discovery")):
                ad_url = "https://login.microsoftonline.com"
                requests.append(AttackRequest(
                    request_id=f"azure-ad-{req_id}",
                    target=ad_url,
                    method="GET",
                    path=payload,
                    headers={"X-BAS-Payload": payload},
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=True,
                ))
                continue

            # Key Vault probing
            if payload.startswith(("/keys?", "/secrets?", "/certificates?", "/storage?", "/deleted")):
                vault_url = f"https://{target_name}.vault.azure.net"
                requests.append(AttackRequest(
                    request_id=f"azure-kv-{req_id}",
                    target=vault_url,
                    method="GET",
                    path=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # DevOps API endpoints
            if payload.startswith("/_apis/"):
                devops_url = f"https://dev.azure.com/{target_name}"
                requests.append(AttackRequest(
                    request_id=f"azure-devops-{req_id}",
                    target=devops_url,
                    method="GET",
                    path=payload,
                    headers={"X-BAS-Payload": payload},
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Management API endpoints
            if payload.startswith(("/subscriptions", "/providers", "/tenants", "/resourcegroups")):
                mgmt_url = "https://management.azure.com"
                requests.append(AttackRequest(
                    request_id=f"azure-mgmt-{req_id}",
                    target=mgmt_url,
                    method="GET",
                    path=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Default: probe against target
            requests.append(AttackRequest(
                request_id=f"azure-probe-{req_id}",
                target=target,
                method="GET",
                path=payload,
                headers={"X-BAS-Payload": payload},
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", False),
            ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        if response.error:
            return ModuleResult(
                module_name="azure_security",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Check against indicator list
        for indicator, desc, severity in AZURE_INDICATORS:
            if indicator in body:
                status = VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE
                return ModuleResult(
                    module_name="azure_security",
                    target=request.target,
                    status=status,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Azure security issue: {desc} (indicator: '{indicator}')",
                    severity=severity,
                    mitre_technique_id="T1530",
                    detail={
                        "detection_type": "azure_indicator",
                        "indicator": indicator,
                        "headers": dict(response.headers),
                    },
                )

        # Credential / connection string regex checks
        cred_patterns = [
            (r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+", "Azure storage connection string exposed", "critical"),
            (r"(?i)SharedAccessSignature=sv=[^&]+&", "Azure SAS token exposed", "high"),
            (r"(?i)AccountKey=[A-Za-z0-9/+=]{44,}", "Azure storage account key exposed", "critical"),
            (r"(?i)Server=tcp:[^;]+;.*Password=[^;]+", "Azure SQL connection string with password", "critical"),
            (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT/OAuth token found in response", "critical"),
            (r"(?i)client_secret\s*[=:]\s*[A-Za-z0-9_~.-]{30,}", "Azure AD client secret exposed", "critical"),
            (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Azure GUID (tenant/subscription/app ID)", "low"),
        ]
        for pattern, desc, severity in cred_patterns:
            match = re.search(pattern, body)
            if match:
                final_severity = severity
                status = VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE
                return ModuleResult(
                    module_name="azure_security",
                    target=request.target,
                    status=status,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Azure credential leak: {desc} (match: '{match.group()[:60]}')",
                    severity=final_severity,
                    mitre_technique_id="T1078.004",
                    detail={"detection_type": "credential_regex", "pattern": pattern},
                )

        # Azure-specific 200 responses on sensitive paths
        if response.status_code == 200 and len(body.strip()) > 10:
            sensitive_paths = [
                "/admin/", "/.auth/me", "/.scm/", "/api/vfs/",
                "/api/settings", "/api/deployments", "/appsettings.json",
                "/local.settings.json", "/web.config",
            ]
            if any(sp in (request.path or "") for sp in sensitive_paths):
                return ModuleResult(
                    module_name="azure_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Sensitive Azure path returned content: {request.path}",
                    severity="medium",
                    mitre_technique_id="T1530",
                    detail={"detection_type": "sensitive_path_content"},
                )

        return ModuleResult(
            module_name="azure_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    @staticmethod
    def _extract_target_name(target: str) -> str:
        """Extract a clean name from the target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        name = hostname.replace("www.", "").split(".")[0]
        return name if name else "target"
