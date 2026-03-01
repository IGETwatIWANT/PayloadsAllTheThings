"""
Advanced attack modules for BASzy AI.

Provides sophisticated attack simulation capabilities beyond basic injection
and authentication testing, including DNS rebinding, race conditions, HTTP/2
smuggling, advanced JWT attacks, API abuse patterns, and SSI injection.
"""

from bas.modules.advanced.dns_rebinding import DNSRebindingModule
from bas.modules.advanced.race_condition import RaceConditionModule
from bas.modules.advanced.http2_smuggling import HTTP2SmugglingModule
from bas.modules.advanced.jwt_advanced import JWTAdvancedModule
from bas.modules.advanced.api_abuse import APIAbuseModule
from bas.modules.advanced.ssi_injection import SSIInjectionModule

__all__ = [
    "DNSRebindingModule",
    "RaceConditionModule",
    "HTTP2SmugglingModule",
    "JWTAdvancedModule",
    "APIAbuseModule",
    "SSIInjectionModule",
]
