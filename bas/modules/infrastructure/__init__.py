"""Infrastructure attack modules – cloud metadata, container escape, secrets, subdomain takeover, API key leaks, misconfigurations."""

from bas.modules.infrastructure.cloud_metadata import CloudMetadataModule
from bas.modules.infrastructure.container_escape import ContainerEscapeModule
from bas.modules.infrastructure.secrets_scanner import SecretsScanner
from bas.modules.infrastructure.subdomain_takeover import SubdomainTakeoverModule
from bas.modules.infrastructure.api_key_leak import APIKeyLeakModule
from bas.modules.infrastructure.misconfig_scanner import MisconfigScanner

__all__ = [
    "CloudMetadataModule",
    "ContainerEscapeModule",
    "SecretsScanner",
    "SubdomainTakeoverModule",
    "APIKeyLeakModule",
    "MisconfigScanner",
]
