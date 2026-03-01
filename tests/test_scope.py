"""Tests for scope enforcement - the most critical safety component."""

import pytest
from bas.core.scope import (
    AuthorizationLevel,
    ScopeConfig,
    ScopeEnforcer,
    ScopeViolation,
)


def make_scope(**kwargs) -> ScopeEnforcer:
    defaults = {
        "engagement_id": "TEST-001",
        "engagement_name": "Test Engagement",
        "authorized_by": "Test User",
        "target_hosts": ["target.internal"],
        "target_cidrs": ["10.0.0.0/24"],
        "auth_level": AuthorizationLevel.STANDARD,
    }
    defaults.update(kwargs)
    return ScopeEnforcer(ScopeConfig(**defaults))


class TestScopeEnforcer:
    def test_allows_in_scope_host(self):
        scope = make_scope()
        assert scope.validate_target("target.internal") is True

    def test_allows_in_scope_url(self):
        scope = make_scope(target_urls=[".*target\\.internal.*"])
        assert scope.validate_target("https://target.internal/api/test") is True

    def test_allows_in_scope_cidr(self):
        scope = make_scope()
        assert scope.validate_target("10.0.0.50") is True

    def test_rejects_out_of_scope_host(self):
        scope = make_scope()
        with pytest.raises(ScopeViolation):
            scope.validate_target("evil.external.com")

    def test_rejects_out_of_scope_ip(self):
        scope = make_scope()
        with pytest.raises(ScopeViolation):
            scope.validate_target("192.168.1.1")

    def test_exclusions_override_inclusions(self):
        scope = make_scope(
            target_cidrs=["10.0.0.0/24"],
            excluded_hosts=["10.0.0.1"],
        )
        # 10.0.0.1 is in CIDR but excluded
        with pytest.raises(ScopeViolation):
            scope.validate_target("10.0.0.1")
        # 10.0.0.2 is in CIDR and not excluded
        assert scope.validate_target("10.0.0.2") is True

    def test_excluded_cidr(self):
        scope = make_scope(
            target_cidrs=["10.0.0.0/16"],
            excluded_cidrs=["10.0.1.0/24"],
        )
        with pytest.raises(ScopeViolation):
            scope.validate_target("10.0.1.50")

    def test_excluded_path(self):
        scope = make_scope(
            target_urls=[".*target\\.internal.*"],
            excluded_paths=["/admin/delete"],
        )
        with pytest.raises(ScopeViolation):
            scope.validate_target("https://target.internal/admin/delete/user")

    def test_auth_level_enforcement(self):
        scope = make_scope(auth_level=AuthorizationLevel.LOW_IMPACT)
        # LOW_IMPACT should allow READ_ONLY
        assert scope.validate_operation(AuthorizationLevel.READ_ONLY, "target.internal") is True
        # LOW_IMPACT should allow LOW_IMPACT
        assert scope.validate_operation(AuthorizationLevel.LOW_IMPACT, "target.internal") is True
        # LOW_IMPACT should reject STANDARD
        with pytest.raises(ScopeViolation):
            scope.validate_operation(AuthorizationLevel.STANDARD, "target.internal")

    def test_port_filtering(self):
        scope = make_scope(
            target_hosts=["target.internal"],
            target_ports=[80, 443, 8080],
        )
        assert scope.validate_target("target.internal") is True

    def test_dry_run_flag(self):
        scope = make_scope(dry_run=True)
        assert scope.is_dry_run is True

    def test_confirmation_threshold(self):
        scope = make_scope(require_confirmation_above=AuthorizationLevel.STANDARD)
        assert scope.requires_confirmation(AuthorizationLevel.READ_ONLY) is False
        assert scope.requires_confirmation(AuthorizationLevel.LOW_IMPACT) is False
        assert scope.requires_confirmation(AuthorizationLevel.STANDARD) is True
        assert scope.requires_confirmation(AuthorizationLevel.AGGRESSIVE) is True
