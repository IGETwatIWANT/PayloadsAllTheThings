"""Cloud security assessment modules."""
from bas.modules.cloud.aws_security import AWSSecurityModule
from bas.modules.cloud.azure_security import AzureSecurityModule

__all__ = [
    "AWSSecurityModule",
    "AzureSecurityModule",
]
