"""
BAS Engine - Main orchestration engine.

Coordinates attack planning, execution, and reporting. All operations
are mediated through scope enforcement and audit logging.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from bas.core.scope import AuthorizationLevel, ScopeConfig, ScopeEnforcer
from bas.utils.logging import AuditLogger


class EngineState(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class EngineEvent:
    """An event produced during engine operation."""
    timestamp: datetime
    event_type: str
    module: str
    target: str
    detail: dict[str, Any]
    severity: str = "info"


@dataclass
class AttackPlan:
    """AI-generated attack plan for an engagement."""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    phases: list[AttackPhase] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    estimated_duration_minutes: int = 0
    risk_assessment: str = ""
    approved: bool = False


@dataclass
class AttackPhase:
    """A single phase in an attack plan."""
    phase_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    module_name: str = ""
    targets: list[str] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    auth_level_required: AuthorizationLevel = AuthorizationLevel.LOW_IMPACT
    depends_on: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"


class BASEngine:
    """
    Main orchestration engine for Breach and Attack Simulation.

    Responsibilities:
    - Accept engagement scope and configuration
    - Coordinate with AI planner for attack strategy
    - Execute attack phases through modules
    - Enforce scope at every step
    - Collect results and generate reports
    """

    def __init__(
        self,
        scope_config: ScopeConfig,
        ai_planner: Any = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.scope = ScopeEnforcer(scope_config)
        self.scope_config = scope_config
        self._state = EngineState.IDLE
        self._ai_planner = ai_planner
        self._audit = audit_logger or AuditLogger(engagement_id=scope_config.engagement_id)
        self._modules: dict[str, Any] = {}
        self._current_plan: AttackPlan | None = None
        self._events: list[EngineEvent] = []
        self._stop_event = asyncio.Event()
        self._engagement_id = scope_config.engagement_id

    @property
    def state(self) -> EngineState:
        return self._state

    @property
    def engagement_id(self) -> str:
        return self._engagement_id

    def register_module(self, name: str, module: Any) -> None:
        """Register an attack module with the engine."""
        self._modules[name] = module
        self._audit.log("module_registered", {"module": name})

    def list_modules(self) -> list[str]:
        """List all registered attack modules."""
        return list(self._modules.keys())

    async def plan_attack(self, objectives: list[str], targets: list[str]) -> AttackPlan:
        """
        Use AI planner to generate an attack plan.

        The plan is generated but NOT executed until approved.
        """
        self._state = EngineState.PLANNING
        self._audit.log("planning_started", {
            "objectives": objectives,
            "targets": targets,
        })

        # Validate all targets are in scope
        for target in targets:
            self.scope.validate_target(target)

        if self._ai_planner:
            plan = await self._ai_planner.generate_plan(
                objectives=objectives,
                targets=targets,
                available_modules=list(self._modules.keys()),
                scope_config=self.scope_config,
            )
        else:
            # Fallback: create a basic sequential plan
            plan = self._create_default_plan(objectives, targets)

        self._current_plan = plan
        self._audit.log("plan_generated", {
            "plan_id": plan.plan_id,
            "phases": len(plan.phases),
            "mitre_techniques": plan.mitre_techniques,
        })

        return plan

    def approve_plan(self, plan_id: str) -> bool:
        """Approve a plan for execution. Requires human confirmation."""
        if not self._current_plan or self._current_plan.plan_id != plan_id:
            return False
        self._current_plan.approved = True
        self._audit.log("plan_approved", {"plan_id": plan_id})
        return True

    async def execute(self, plan: AttackPlan | None = None) -> list[EngineEvent]:
        """
        Execute an approved attack plan.

        All operations pass through scope enforcement.
        Emergency stop can halt execution at any time.
        """
        plan = plan or self._current_plan
        if not plan:
            raise RuntimeError("No attack plan available. Call plan_attack() first.")
        if not plan.approved:
            raise RuntimeError("Attack plan must be approved before execution. Call approve_plan().")

        self._state = EngineState.EXECUTING
        self._audit.log("execution_started", {"plan_id": plan.plan_id})
        results: list[EngineEvent] = []

        try:
            for phase in plan.phases:
                if self._stop_event.is_set():
                    self._state = EngineState.STOPPED
                    self._audit.log("execution_stopped", {"reason": "emergency_stop"})
                    break

                # Check dependencies
                if phase.depends_on:
                    unmet = [d for d in phase.depends_on if not self._phase_complete(plan, d)]
                    if unmet:
                        phase.status = "skipped"
                        continue

                # Scope check per phase
                for target in phase.targets:
                    self.scope.validate_operation(phase.auth_level_required, target)

                # Confirmation check
                if self.scope.requires_confirmation(phase.auth_level_required):
                    self._audit.log("confirmation_required", {
                        "phase": phase.name,
                        "auth_level": phase.auth_level_required.value,
                    })
                    # In production, this would pause for human input
                    phase.status = "awaiting_confirmation"
                    continue

                phase.status = "running"
                self._audit.log("phase_started", {
                    "phase_id": phase.phase_id,
                    "module": phase.module_name,
                    "targets": phase.targets,
                })

                # Execute via module
                module = self._modules.get(phase.module_name)
                if module:
                    if self.scope.is_dry_run:
                        event = EngineEvent(
                            timestamp=datetime.now(),
                            event_type="dry_run",
                            module=phase.module_name,
                            target=",".join(phase.targets),
                            detail={"payloads": phase.payloads},
                        )
                    else:
                        event = await module.execute(
                            targets=phase.targets,
                            payloads=phase.payloads,
                            scope=self.scope,
                        )
                    results.append(event)
                    phase.results = event.detail
                    phase.status = "complete"
                else:
                    phase.status = "error"
                    self._audit.log("module_not_found", {"module": phase.module_name})

        except Exception as exc:
            self._state = EngineState.ERROR
            self._audit.log("execution_error", {"error": str(exc)})
            raise
        else:
            self._state = EngineState.COMPLETE
            self._audit.log("execution_complete", {
                "plan_id": plan.plan_id,
                "events": len(results),
            })

        self._events.extend(results)
        return results

    def emergency_stop(self) -> None:
        """Immediately halt all operations."""
        self._stop_event.set()
        self._state = EngineState.STOPPED
        self._audit.log("emergency_stop_triggered", {})

    def _phase_complete(self, plan: AttackPlan, phase_id: str) -> bool:
        return any(p.phase_id == phase_id and p.status == "complete" for p in plan.phases)

    def _create_default_plan(self, objectives: list[str], targets: list[str]) -> AttackPlan:
        """Create a basic plan when no AI planner is available."""
        phases = []
        for i, module_name in enumerate(self._modules):
            phases.append(AttackPhase(
                name=f"Phase {i + 1}: {module_name}",
                description=f"Execute {module_name} against targets",
                module_name=module_name,
                targets=targets,
            ))
        return AttackPlan(
            phases=phases,
            risk_assessment="Default sequential plan - review before approval",
        )
