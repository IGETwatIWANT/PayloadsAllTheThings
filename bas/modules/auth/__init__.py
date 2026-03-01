"""Authentication and authorization testing modules."""
from bas.modules.auth.jwt import JWTModule
from bas.modules.auth.auth_bypass import AuthBypassModule
from bas.modules.auth.mfa_bypass import MFABypassModule
from bas.modules.auth.credential_phishing import CredentialPhishingModule
__all__ = ["JWTModule", "AuthBypassModule", "MFABypassModule", "CredentialPhishingModule"]
