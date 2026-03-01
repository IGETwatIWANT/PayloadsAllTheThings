"""
Scope enforcement and authorization controls.

This is the MOST CRITICAL safety component. Every attack operation must pass
through scope validation before execution. Prevents accidental targeting of
out-of-scope systems.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class AuthorizationLevel(str, Enum):
    """Level of authorization for operations."""
    READ_ONLY = "read_only"           # Passive recon only
    LOW_IMPACT = "low_impact"         # Non-destructive tests
    STANDARD = "standard"             # Standard pentest operations
    AGGRESSIVE = "aggressive"         # Includes DoS testing, brute force
    FULL = "full"                     # No restrictions within scope


class ScopeConfig(BaseModel):
    """Defines the authorized scope for a BAS engagement."""

    engagement_id: str = Field(description="Unique engagement identifier")
    engagement_name: str = Field(description="Human-readable engagement name")
    authorized_by: str = Field(description="Person/team who authorized this engagement")
    authorization_ref: str = Field(default="", description="Reference to authorization document (RoE, SOW)")

    # Target scope
    target_hosts: list[str] = Field(default_factory=list, description="Allowed hostnames and IPs")
    target_cidrs: list[str] = Field(default_factory=list, description="Allowed CIDR ranges")
    target_ports: list[int] = Field(default_factory=list, description="Allowed ports (empty = all)")
    target_urls: list[str] = Field(default_factory=list, description="Allowed URL patterns (regex)")

    # Exclusions - these ALWAYS take precedence
    excluded_hosts: list[str] = Field(default_factory=list, description="Never target these hosts")
    excluded_cidrs: list[str] = Field(default_factory=list, description="Never target these CIDRs")
    excluded_paths: list[str] = Field(default_factory=list, description="Never target these URL paths")

    # Authorization level
    auth_level: AuthorizationLevel = Field(default=AuthorizationLevel.LOW_IMPACT)

    # Time window restrictions
    allowed_start_time: Optional[str] = Field(default=None, description="Earliest time to run (HH:MM)")
    allowed_end_time: Optional[str] = Field(default=None, description="Latest time to run (HH:MM)")
    allowed_days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6], description="Allowed days (0=Mon)")

    # Rate limiting
    max_requests_per_second: int = Field(default=10, ge=1, le=1000)
    max_concurrent_operations: int = Field(default=5, ge=1, le=50)

    # Safety
    require_confirmation_above: AuthorizationLevel = Field(
        default=AuthorizationLevel.STANDARD,
        description="Require human confirmation for operations at or above this level"
    )
    emergency_stop_enabled: bool = Field(default=True)
    dry_run: bool = Field(default=False, description="Log actions without executing")


class ScopeViolation(Exception):
    """Raised when an operation would violate the defined scope."""

    def __init__(self, message: str, target: str = "", operation: str = ""):
        self.target = target
        self.operation = operation
        super().__init__(f"SCOPE VIOLATION: {message} [target={target}, op={operation}]")


class ScopeEnforcer:
    """
    Validates all operations against the defined scope.

    This enforcer MUST be called before every network operation.
    It is designed to fail-closed: if validation cannot be determined,
    the operation is denied.
    """

    def __init__(self, config: ScopeConfig):
        self._config = config
        self._compiled_urls: list[re.Pattern] = []
        self._compiled_exclusions: list[re.Pattern] = []
        self._target_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Pre-compile regex patterns and parse CIDR ranges."""
        for pattern in self._config.target_urls:
            self._compiled_urls.append(re.compile(pattern, re.IGNORECASE))
        for pattern in self._config.excluded_paths:
            self._compiled_exclusions.append(re.compile(pattern, re.IGNORECASE))
        for cidr in self._config.target_cidrs:
            self._target_networks.append(ipaddress.ip_network(cidr, strict=False))
        for cidr in self._config.excluded_cidrs:
            self._excluded_networks.append(ipaddress.ip_network(cidr, strict=False))

    def validate_target(self, target: str) -> bool:
        """
        Check if a target host/URL is within scope.
        Returns True if allowed, raises ScopeViolation if not.
        """
        # Check exclusions FIRST (they always win)
        if self._is_excluded(target):
            raise ScopeViolation(
                f"Target is in exclusion list",
                target=target,
                operation="target_validation"
            )

        # Check time window
        if not self._in_time_window():
            raise ScopeViolation(
                "Operation outside allowed time window",
                target=target,
                operation="time_check"
            )

        # Validate against allowed targets
        if self._is_in_scope(target):
            return True

        raise ScopeViolation(
            "Target is not in the authorized scope",
            target=target,
            operation="target_validation"
        )

    def validate_operation(self, operation_level: AuthorizationLevel, target: str) -> bool:
        """Check if an operation at the given authorization level is permitted."""
        self.validate_target(target)

        level_order = list(AuthorizationLevel)
        if level_order.index(operation_level) > level_order.index(self._config.auth_level):
            raise ScopeViolation(
                f"Operation requires {operation_level.value} but engagement is limited to {self._config.auth_level.value}",
                target=target,
                operation=operation_level.value
            )

        return True

    def requires_confirmation(self, operation_level: AuthorizationLevel) -> bool:
        """Check if an operation level requires human confirmation."""
        level_order = list(AuthorizationLevel)
        return (
            level_order.index(operation_level)
            >= level_order.index(self._config.require_confirmation_above)
        )

    @property
    def is_dry_run(self) -> bool:
        return self._config.dry_run

    def _is_excluded(self, target: str) -> bool:
        """Check if target matches any exclusion rule."""
        parsed = urlparse(target) if "://" in target else None
        hostname = parsed.hostname if parsed else target.split(":")[0]

        # Check excluded hosts
        if hostname in self._config.excluded_hosts:
            return True

        # Check excluded CIDRs
        try:
            addr = ipaddress.ip_address(hostname)
            for network in self._excluded_networks:
                if addr in network:
                    return True
        except ValueError:
            pass

        # Check excluded paths
        if parsed and parsed.path:
            for pattern in self._compiled_exclusions:
                if pattern.search(parsed.path):
                    return True

        return False

    def _is_in_scope(self, target: str) -> bool:
        """Check if target matches any inclusion rule."""
        parsed = urlparse(target) if "://" in target else None
        hostname = parsed.hostname if parsed else target.split(":")[0]
        port = parsed.port if parsed else None

        # Check URL patterns
        if parsed:
            for pattern in self._compiled_urls:
                if pattern.search(target):
                    return True

        # Check allowed hosts
        if hostname in self._config.target_hosts:
            if self._port_allowed(port):
                return True

        # Check allowed CIDRs
        try:
            addr = ipaddress.ip_address(hostname)
            for network in self._target_networks:
                if addr in network and self._port_allowed(port):
                    return True
        except ValueError:
            pass

        return False

    def _port_allowed(self, port: int | None) -> bool:
        """Check if a port is allowed (empty list = all ports allowed)."""
        if not self._config.target_ports:
            return True
        if port is None:
            return True
        return port in self._config.target_ports

    def _in_time_window(self) -> bool:
        """Check if current time is within the allowed window."""
        now = datetime.now()

        # Check day of week
        if now.weekday() not in self._config.allowed_days:
            return False

        # Check time range
        if self._config.allowed_start_time and self._config.allowed_end_time:
            start = time.fromisoformat(self._config.allowed_start_time)
            end = time.fromisoformat(self._config.allowed_end_time)
            current = now.time()
            if start <= end:
                return start <= current <= end
            else:
                # Wraps midnight
                return current >= start or current <= end

        return True
