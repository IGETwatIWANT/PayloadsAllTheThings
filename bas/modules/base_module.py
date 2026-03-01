"""
Base attack module - all attack modules inherit from this.

Provides standard interface for payload loading, execution, and result analysis.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from bas.core.executor import AttackExecutor, AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel, ScopeEnforcer
from bas.core.engine import EngineEvent
from bas.payloads.database import PayloadDatabase


class VulnStatus(str, Enum):
    VULNERABLE = "vulnerable"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class ModuleMetadata:
    """Metadata about an attack module."""
    name: str
    description: str
    category: str
    mitre_technique_ids: list[str]
    mitre_technique_names: list[str]
    auth_level_required: AuthorizationLevel
    owasp_category: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    """Result from executing an attack module."""
    module_name: str
    target: str
    status: VulnStatus
    payload_used: str = ""
    response_code: int = 0
    response_body_preview: str = ""
    elapsed_ms: float = 0.0
    evidence: str = ""
    severity: str = "info"
    mitre_technique_id: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class BaseAttackModule(ABC):
    """
    Abstract base class for all attack modules.

    Subclasses must implement:
    - metadata: module identification and classification
    - _get_payloads: retrieve relevant payloads
    - _build_requests: construct attack requests from payloads
    - _analyze_response: determine if a response indicates vulnerability
    """

    def __init__(self, payload_db: PayloadDatabase | None = None, ai_analyzer: Any = None):
        self._payload_db = payload_db
        self._ai_analyzer = ai_analyzer

    @property
    @abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Return module metadata."""
        ...

    @abstractmethod
    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Get payloads for this module. Override to customize payload selection."""
        ...

    @abstractmethod
    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        """Build attack requests from payloads."""
        ...

    @abstractmethod
    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        """Analyze a response for vulnerability indicators."""
        ...

    async def execute(
        self,
        targets: list[str],
        payloads: list[str] | None = None,
        scope: ScopeEnforcer | None = None,
        options: dict[str, Any] | None = None,
    ) -> EngineEvent:
        """
        Execute this module against the specified targets.

        This is the main entry point called by the engine.
        """
        options = options or {}
        all_results: list[ModuleResult] = []

        for target in targets:
            # Scope check
            if scope:
                scope.validate_operation(self.metadata.auth_level_required, target)

            # Get payloads
            if payloads:
                target_payloads = payloads
            else:
                target_payloads = await self._get_payloads(target, options)

            if not target_payloads:
                all_results.append(ModuleResult(
                    module_name=self.metadata.name,
                    target=target,
                    status=VulnStatus.ERROR,
                    detail={"error": "No payloads available"},
                ))
                continue

            # Build and execute requests
            max_payloads = options.get("max_payloads", 50)
            target_payloads = target_payloads[:max_payloads]

            requests = self._build_requests(target, target_payloads, options)

            async with AttackExecutor(
                scope=scope or self._create_permissive_scope(),
                max_rps=options.get("max_rps", 10),
                max_concurrent=options.get("max_concurrent", 5),
                proxy=options.get("proxy"),
            ) as executor:
                for i, request in enumerate(requests):
                    if scope and scope.is_dry_run:
                        result = ModuleResult(
                            module_name=self.metadata.name,
                            target=target,
                            status=VulnStatus.NOT_VULNERABLE,
                            payload_used=target_payloads[i] if i < len(target_payloads) else "",
                            detail={"dry_run": True},
                        )
                    else:
                        response = await executor.execute_single(request)
                        payload = target_payloads[i] if i < len(target_payloads) else ""
                        result = self._analyze_response(request, response, payload)

                    all_results.append(result)

                    # AI-enhanced analysis for potential findings
                    if self._ai_analyzer and result.status in (VulnStatus.VULNERABLE, VulnStatus.POTENTIALLY_VULNERABLE):
                        try:
                            ai_result = await self._ai_analyzer.analyze_response(
                                module=self.metadata.name,
                                target=target,
                                test_type=self.metadata.category,
                                status_code=result.response_code,
                                elapsed_ms=result.elapsed_ms,
                                body=result.response_body_preview,
                                headers=result.detail.get("headers", {}),
                                payload=result.payload_used,
                            )
                            result.detail["ai_analysis"] = ai_result
                            if ai_result.get("severity"):
                                result.severity = ai_result["severity"]
                        except Exception:
                            pass

        # Build engine event
        vuln_count = sum(1 for r in all_results if r.status == VulnStatus.VULNERABLE)
        potential_count = sum(1 for r in all_results if r.status == VulnStatus.POTENTIALLY_VULNERABLE)

        return EngineEvent(
            timestamp=datetime.now(),
            event_type="module_complete",
            module=self.metadata.name,
            target=",".join(targets),
            detail={
                "total_tests": len(all_results),
                "vulnerabilities_found": vuln_count,
                "potential_vulnerabilities": potential_count,
                "results": [
                    {
                        "target": r.target,
                        "status": r.status.value,
                        "payload": r.payload_used,
                        "severity": r.severity,
                        "evidence": r.evidence,
                        "elapsed_ms": r.elapsed_ms,
                    }
                    for r in all_results
                    if r.status in (VulnStatus.VULNERABLE, VulnStatus.POTENTIALLY_VULNERABLE)
                ],
            },
            severity="high" if vuln_count > 0 else ("medium" if potential_count > 0 else "info"),
        )

    def _create_permissive_scope(self) -> ScopeEnforcer:
        """Create a permissive scope for testing (should not be used in production)."""
        from bas.core.scope import ScopeConfig
        return ScopeEnforcer(ScopeConfig(
            engagement_id="test",
            engagement_name="test",
            authorized_by="test",
            target_cidrs=["0.0.0.0/0"],
            auth_level=AuthorizationLevel.FULL,
        ))
