"""
AWS Security Assessment module.

Tests for AWS-specific attack vectors including S3 bucket enumeration and
misconfiguration, IAM role probing, Lambda function exposure, API Gateway
misconfigurations, CloudFront bypass, AWS CLI endpoint exposure,
STS assume-role testing, and ECS/EKS endpoint exposure.

MITRE ATT&CK: T1530 - Data from Cloud Storage Object
               T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# S3 bucket enumeration and misconfiguration payloads
# ---------------------------------------------------------------------------
S3_BUCKET_PAYLOADS = [
    # Direct bucket access patterns
    "GET /{target}-backup HTTP/1.1",
    "GET /{target}-dev HTTP/1.1",
    "GET /{target}-staging HTTP/1.1",
    "GET /{target}-prod HTTP/1.1",
    "GET /{target}-assets HTTP/1.1",
    "GET /{target}-logs HTTP/1.1",
    "GET /{target}-data HTTP/1.1",
    "GET /{target}-uploads HTTP/1.1",
    "GET /{target}-media HTTP/1.1",
    "GET /{target}-static HTTP/1.1",
    "GET /{target}-private HTTP/1.1",
    "GET /{target}-public HTTP/1.1",
    "GET /{target}-internal HTTP/1.1",
    "GET /{target}-config HTTP/1.1",
    "GET /{target}-secrets HTTP/1.1",
    "GET /{target}-db-backups HTTP/1.1",
    # S3 ACL/policy probe paths
    "/?acl",
    "/?policy",
    "/?cors",
    "/?lifecycle",
    "/?versioning",
    "/?website",
    "/?logging",
    "/?encryption",
    "/?tagging",
    "/?replication",
    "/?analytics",
    "/?inventory",
    "/?metrics",
    "/?accelerate",
    "/?requestPayment",
    "/?object-lock",
    "/?public-access-block",
]

# ---------------------------------------------------------------------------
# IAM & STS probing payloads
# ---------------------------------------------------------------------------
IAM_STS_PAYLOADS = [
    # STS endpoints
    "/?Action=GetCallerIdentity&Version=2011-06-15",
    "/?Action=GetSessionToken&Version=2011-06-15",
    "/?Action=AssumeRole&RoleArn=arn:aws:iam::123456789012:role/admin&RoleSessionName=test&Version=2011-06-15",
    "/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15",
    "/?Action=AssumeRoleWithSAML&Version=2011-06-15",
    "/?Action=GetAccessKeyInfo&AccessKeyId=AKIAIOSFODNN7EXAMPLE&Version=2019-11-01",
    # IAM enumeration endpoints
    "/?Action=ListRoles&Version=2010-05-08",
    "/?Action=ListUsers&Version=2010-05-08",
    "/?Action=ListPolicies&Version=2010-05-08",
    "/?Action=ListGroups&Version=2010-05-08",
    "/?Action=GetAccountSummary&Version=2010-05-08",
    "/?Action=ListAccessKeys&Version=2010-05-08",
    "/?Action=ListMFADevices&Version=2010-05-08",
    "/?Action=GetAccountAuthorizationDetails&Version=2010-05-08",
    "/?Action=SimulatePrincipalPolicy&Version=2010-05-08",
    "/?Action=GetCredentialReport&Version=2010-05-08",
]

# ---------------------------------------------------------------------------
# Lambda function exposure payloads
# ---------------------------------------------------------------------------
LAMBDA_PAYLOADS = [
    "/2015-03-31/functions/",
    "/2015-03-31/functions/{target}-function/invocations",
    "/2015-03-31/functions/{target}-api/invocations",
    "/2015-03-31/functions/{target}-auth/invocations",
    "/2015-03-31/functions/{target}-webhook/invocations",
    "/2015-03-31/functions/{target}-handler/invocations",
    "/2015-03-31/functions/{target}-processor/invocations",
    "/.aws-lambda/",
    "/runtime/invocation/next",
    "/2018-06-01/runtime/invocation/next",
    "/2018-06-01/runtime/init/error",
    "/runtime/invocation/response",
    "/_lambda_",
    "/lambda/",
]

# ---------------------------------------------------------------------------
# API Gateway misconfiguration payloads
# ---------------------------------------------------------------------------
API_GATEWAY_PAYLOADS = [
    # Stage exposure
    "/prod/",
    "/dev/",
    "/staging/",
    "/test/",
    "/v1/",
    "/v2/",
    "/api/",
    # API Gateway specific endpoints
    "/@connections",
    "/@connections/test",
    "/restapis",
    "/apikeys",
    "/usageplans",
    "/domainnames",
    # Gateway response probing
    "/nonexistent-endpoint-probe",
    "/{proxy+}",
    # Auth bypass
    "/?x-api-key=test",
    "/?apikey=test",
    # Export/documentation
    "/export?accepts=application/yaml",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
]

# ---------------------------------------------------------------------------
# CloudFront bypass payloads
# ---------------------------------------------------------------------------
CLOUDFRONT_BYPASS_PAYLOADS = [
    # Origin header manipulation
    "X-Forwarded-Host: {target}.s3.amazonaws.com",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
    "X-Forwarded-For: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Forwarded-Proto: https",
    "X-Forwarded-Scheme: https",
    "CF-Connecting-IP: 127.0.0.1",
    "True-Client-IP: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    # CloudFront cache key manipulation
    "Host: {target}.s3.amazonaws.com",
    "Host: {target}.s3-website.amazonaws.com",
    "Host: s3.amazonaws.com/{target}",
]

# ---------------------------------------------------------------------------
# AWS CLI / console endpoint exposure
# ---------------------------------------------------------------------------
AWS_ENDPOINT_PAYLOADS = [
    "/.aws/credentials",
    "/.aws/config",
    "/.aws/cli/cache/",
    "/aws-config.yml",
    "/aws-exports.js",
    "/aws-exports.json",
    "/amplify-meta.json",
    "/.env.aws",
    "/aws-credentials",
    "/serverless.yml",
    "/serverless.json",
    "/sam-template.yaml",
    "/template.yaml",
    "/cloudformation-template.json",
    "/cdk.json",
    "/cdk.out/",
]

# ---------------------------------------------------------------------------
# ECS / EKS endpoint payloads
# ---------------------------------------------------------------------------
ECS_EKS_PAYLOADS = [
    # ECS metadata
    "/v2/metadata",
    "/v2/metadata/",
    "/v2/stats",
    "/v2/stats/",
    "/v3/",
    "/v3/task",
    "/v3/task/stats",
    "/v4/",
    "/v4/{uuid}/task",
    "/v4/{uuid}/stats",
    # ECS task metadata endpoint
    "http://169.254.170.2/v2/credentials/",
    "http://169.254.170.2/v2/metadata",
    # EKS endpoints
    "/api/v1/namespaces",
    "/api/v1/nodes",
    "/api/v1/pods",
    "/apis/",
    "/healthz",
    "/readyz",
    "/livez",
    "/version",
    "/.well-known/openid-configuration",
    "/openid/v1/jwks",
]

# Combine all payloads
ALL_AWS_PAYLOADS = (
    S3_BUCKET_PAYLOADS
    + IAM_STS_PAYLOADS
    + LAMBDA_PAYLOADS
    + API_GATEWAY_PAYLOADS
    + CLOUDFRONT_BYPASS_PAYLOADS
    + AWS_ENDPOINT_PAYLOADS
    + ECS_EKS_PAYLOADS
)

# ---------------------------------------------------------------------------
# Vulnerability indicators
# ---------------------------------------------------------------------------
AWS_INDICATORS: list[tuple[str, str, str]] = [
    # S3 indicators
    ("<ListBucketResult", "S3 bucket listing exposed", "critical"),
    ("<ListAllMyBucketsResult", "S3 full bucket listing accessible", "critical"),
    ("NoSuchBucket", "S3 bucket does not exist (potential takeover)", "high"),
    ("AllAccessDisabled", "S3 bucket exists but access denied", "info"),
    ("AccessDenied", "S3 bucket exists - access denied", "info"),
    ("<AccessControlPolicy", "S3 ACL exposed", "high"),
    ("<BucketPolicy", "S3 bucket policy exposed", "high"),
    ("<CORSConfiguration", "S3 CORS configuration exposed", "medium"),
    ("<VersioningConfiguration", "S3 versioning status exposed", "low"),
    ("<WebsiteConfiguration", "S3 website configuration exposed", "medium"),
    ("<LifecycleConfiguration", "S3 lifecycle configuration exposed", "low"),
    ("<LoggingEnabled", "S3 logging configuration exposed", "low"),
    ("<ServerSideEncryptionConfiguration", "S3 encryption config exposed", "medium"),
    ("PermanentRedirect", "S3 bucket permanent redirect", "low"),
    # IAM / STS indicators
    ("GetCallerIdentityResponse", "STS GetCallerIdentity responded - IAM info leak", "critical"),
    ("<Arn>arn:aws:", "AWS ARN exposed via STS", "high"),
    ("<Account>", "AWS account ID exposed", "high"),
    ("<UserId>", "AWS user ID exposed", "high"),
    ("ListRolesResponse", "IAM roles enumerated", "critical"),
    ("ListUsersResponse", "IAM users enumerated", "critical"),
    ("ListPoliciesResponse", "IAM policies enumerated", "critical"),
    ("GetAccountSummaryResponse", "IAM account summary exposed", "critical"),
    ("GetCredentialReportResponse", "IAM credential report exposed", "critical"),
    ("AssumeRoleResponse", "STS AssumeRole succeeded", "critical"),
    ("InvalidClientTokenId", "AWS endpoint exists but token invalid", "low"),
    ("SignatureDoesNotMatch", "AWS endpoint exists - signature mismatch", "low"),
    # Lambda indicators
    ("FunctionName", "Lambda function name exposed", "high"),
    ("FunctionArn", "Lambda function ARN exposed", "high"),
    ("Runtime", "Lambda runtime info exposed", "medium"),
    ("CodeSize", "Lambda code size exposed", "medium"),
    ("RequestId", "Lambda request processed", "medium"),
    ("Lambda.Unknown", "Lambda function error - function exists", "medium"),
    ("ResourceNotFoundException", "Lambda function not found", "info"),
    ("ServiceException", "Lambda service error", "low"),
    # API Gateway indicators
    ("x-amzn-requestid", "API Gateway response detected", "low"),
    ("x-amz-apigw-id", "API Gateway ID exposed", "medium"),
    ("Forbidden", "API Gateway auth enforced", "info"),
    ("Missing Authentication Token", "API Gateway missing auth", "medium"),
    ("message", "API Gateway custom error", "info"),
    # ECS / EKS indicators
    ("TaskARN", "ECS task ARN exposed", "critical"),
    ("ClusterARN", "ECS cluster ARN exposed", "critical"),
    ("ContainerARN", "ECS container ARN exposed", "high"),
    ("DockerId", "ECS Docker container ID exposed", "high"),
    ("DesiredStatus", "ECS task status exposed", "medium"),
    # CloudFront indicators
    ("x-amz-cf-id", "CloudFront distribution ID exposed", "low"),
    ("x-amz-cf-pop", "CloudFront POP location exposed", "low"),
    # Credential / config indicators
    ("aws_access_key_id", "AWS access key in config file", "critical"),
    ("aws_secret_access_key", "AWS secret key in config file", "critical"),
    ("aws_session_token", "AWS session token in config file", "critical"),
    ("AKIA", "AWS access key ID pattern found", "critical"),
    ("aws_cognito_identity_pool_id", "Cognito identity pool ID exposed", "high"),
    ("aws_user_pools_id", "Cognito user pool ID exposed", "high"),
    ("aws_project_region", "AWS project region exposed", "low"),
    # Serverless / IaC indicators
    ("AWSTemplateFormatVersion", "CloudFormation template exposed", "high"),
    ("Resources:", "Infrastructure template exposed", "high"),
    ("serverless", "Serverless configuration exposed", "high"),
]


class AWSSecurityModule(BaseAttackModule):
    """
    AWS Security Assessment module.

    Performs comprehensive testing of AWS-specific attack surfaces including
    S3 bucket enumeration and misconfiguration, IAM role probing, Lambda
    function exposure, API Gateway misconfiguration, CloudFront bypass,
    AWS CLI endpoint exposure, STS assume-role testing, and ECS/EKS endpoints.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="aws_security",
            description=(
                "AWS security assessment - S3 bucket enum/misconfig, IAM role probing, "
                "Lambda exposure, API Gateway misconfig, CloudFront bypass, AWS CLI "
                "endpoint exposure, STS assume-role, ECS/EKS endpoints"
            ),
            category="cloud",
            mitre_technique_ids=["T1530", "T1552.005"],
            mitre_technique_names=[
                "Data from Cloud Storage Object",
                "Unsecured Credentials: Cloud Instance Metadata API",
            ],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200", "CWE-264", "CWE-522", "CWE-284"],
            tags=[
                "aws", "s3", "iam", "lambda", "api-gateway", "cloudfront",
                "ecs", "eks", "sts", "cloud", "enumeration", "misconfiguration",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Retrieve AWS security testing payloads."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("aws_security", limit=300)
            if db_payloads:
                return db_payloads

        # Resolve target name for bucket enum
        target_name = self._extract_target_name(target)
        resolved: list[str] = []
        for payload in ALL_AWS_PAYLOADS:
            resolved.append(payload.replace("{target}", target_name).replace("{uuid}", uuid.uuid4().hex[:8]))

        return resolved

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        target_name = self._extract_target_name(target)

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            # Header-based payloads (CloudFront bypass)
            if payload.startswith(("X-", "CF-", "True-", "Host:")):
                header_name, _, header_value = payload.partition(": ")
                header_value = header_value.replace("{target}", target_name)
                requests.append(AttackRequest(
                    request_id=f"aws-cfbypass-{req_id}",
                    target=target,
                    method="GET",
                    path="/",
                    headers={
                        header_name.strip(): header_value.strip(),
                        "X-BAS-Payload": payload,
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=False,
                ))
                continue

            # S3 bucket enumeration payloads
            if payload.startswith("GET /"):
                bucket_name = payload.split(" ")[1].lstrip("/").replace("{target}", target_name)
                s3_url = f"https://{bucket_name}.s3.amazonaws.com"
                requests.append(AttackRequest(
                    request_id=f"aws-s3enum-{req_id}",
                    target=s3_url,
                    method="GET",
                    path="/",
                    headers={"X-BAS-Payload": payload},
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # ECS task metadata (direct IP)
            if payload.startswith("http://169.254.170.2"):
                from urllib.parse import urlparse
                parsed = urlparse(payload)
                requests.append(AttackRequest(
                    request_id=f"aws-ecs-{req_id}",
                    target=f"{parsed.scheme}://{parsed.netloc}",
                    method="GET",
                    path=parsed.path,
                    headers={"X-BAS-Payload": payload},
                    timeout=options.get("timeout", 5.0),
                    follow_redirects=False,
                ))
                continue

            # Path-based payloads (IAM, Lambda, API GW, configs)
            requests.append(AttackRequest(
                request_id=f"aws-probe-{req_id}",
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
                module_name="aws_security",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Check against indicator list
        for indicator, desc, severity in AWS_INDICATORS:
            if indicator in body or indicator.lower() in response.headers.get("x-amzn-requestid", "").lower():
                status = VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE
                return ModuleResult(
                    module_name="aws_security",
                    target=request.target,
                    status=status,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"AWS security issue: {desc} (indicator: '{indicator}')",
                    severity=severity,
                    mitre_technique_id="T1530",
                    detail={
                        "detection_type": "aws_indicator",
                        "indicator": indicator,
                        "headers": dict(response.headers),
                    },
                )

        # Credential regex patterns
        cred_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS access key ID found", "critical"),
            (r"(?i)aws_secret_access_key\s*[=:]\s*\S+", "AWS secret access key exposed", "critical"),
            (r"(?i)aws_session_token\s*[=:]\s*\S+", "AWS session token exposed", "critical"),
            (r"(?i)\"AccessKeyId\"\s*:\s*\"[A-Z0-9]+\"", "AWS temporary access key in response", "critical"),
            (r"(?i)\"SecretAccessKey\"\s*:\s*\"[A-Za-z0-9/+=]+\"", "AWS temporary secret key in response", "critical"),
            (r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:", "AWS ARN exposed", "high"),
            (r"(?i)cognito-idp\.[a-z0-9-]+\.amazonaws\.com", "Cognito endpoint exposed", "medium"),
            (r"(?i)execute-api\.[a-z0-9-]+\.amazonaws\.com", "API Gateway execute endpoint exposed", "medium"),
        ]
        for pattern, desc, severity in cred_patterns:
            match = re.search(pattern, body)
            if match:
                return ModuleResult(
                    module_name="aws_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"AWS credential/resource leak: {desc} (match: '{match.group()[:60]}')",
                    severity=severity,
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "credential_regex", "pattern": pattern},
                )

        # S3 bucket existence check via HTTP status
        if "s3.amazonaws.com" in request.target:
            if response.status_code == 200:
                return ModuleResult(
                    module_name="aws_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="S3 bucket publicly accessible (HTTP 200)",
                    severity="high",
                    mitre_technique_id="T1530",
                    detail={"detection_type": "s3_public_access"},
                )
            elif response.status_code == 403:
                return ModuleResult(
                    module_name="aws_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    elapsed_ms=response.elapsed_ms,
                    evidence="S3 bucket exists but access denied (HTTP 403)",
                    severity="low",
                    mitre_technique_id="T1530",
                    detail={"detection_type": "s3_exists_denied"},
                )

        # Generic 200 with content on sensitive paths
        sensitive_paths = [
            "/.aws/", "/credentials", "/serverless", "/template.yaml",
            "/cdk.json", "/aws-exports", "/amplify",
        ]
        if response.status_code == 200 and len(body.strip()) > 0:
            if any(sp in (request.path or "") for sp in sensitive_paths):
                return ModuleResult(
                    module_name="aws_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Sensitive AWS path returned content: {request.path}",
                    severity="medium",
                    mitre_technique_id="T1552.005",
                    detail={"detection_type": "sensitive_path_content"},
                )

        return ModuleResult(
            module_name="aws_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    @staticmethod
    def _extract_target_name(target: str) -> str:
        """Extract a clean name from the target URL for bucket enumeration."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        # Strip common prefixes/suffixes
        name = hostname.replace("www.", "").split(".")[0]
        return name if name else "target"
