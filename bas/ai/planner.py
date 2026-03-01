"""
AI-Driven Attack Planner.

Uses local LLMs to generate intelligent attack plans based on:
- Target information and reconnaissance data
- Available attack modules and payloads
- Engagement scope and authorization level
- MITRE ATT&CK framework mapping
"""

from __future__ import annotations

import json
import logging
from typing import Any

from bas.ai.model_manager import ModelManager
from bas.core.scope import AuthorizationLevel, ScopeConfig

logger = logging.getLogger(__name__)

PLANNER_SYSTEM_PROMPT = """You are a security assessment planning AI for an authorized Breach and Attack Simulation (BAS) engine. Your role is to create structured attack plans for testing the security of systems that the operator is AUTHORIZED to test.

You must ALWAYS:
1. Respect the scope boundaries provided
2. Map techniques to MITRE ATT&CK framework
3. Prioritize non-destructive tests unless aggressive mode is authorized
4. Consider dependencies between attack phases
5. Provide risk assessments for each phase

Output your plans as valid JSON matching the required schema."""

PLAN_GENERATION_PROMPT = """Generate an attack plan for the following engagement:

**Objectives:** {objectives}
**Targets:** {targets}
**Available Modules:** {modules}
**Authorization Level:** {auth_level}
**Scope Restrictions:** {scope_summary}

Create a phased attack plan. For each phase, specify:
- name: descriptive phase name
- description: what this phase does and why
- module_name: which module to use (from available modules)
- targets: which targets to test (from authorized targets)
- payloads: suggested payload categories
- auth_level_required: minimum auth level needed (read_only, low_impact, standard, aggressive, full)
- depends_on: list of phase names this depends on (empty for independent phases)
- mitre_technique_id: relevant MITRE ATT&CK technique ID
- mitre_technique_name: technique name
- risk_level: low, medium, high

Respond with JSON:
{{
    "phases": [...],
    "mitre_techniques": ["T1190", ...],
    "estimated_duration_minutes": <int>,
    "risk_assessment": "<overall risk summary>"
}}"""

ADAPTIVE_PROMPT = """Based on the following results from previous attack phases, adapt the remaining plan:

**Completed Results:**
{results}

**Remaining Phases:**
{remaining}

**Engagement Context:**
{context}

Analyze the results and suggest modifications:
1. Should any remaining phases be skipped, modified, or reordered?
2. Are there new attack vectors revealed by the results?
3. What follow-up tests would be most valuable?

Respond with JSON:
{{
    "modifications": [...],
    "new_phases": [...],
    "skip_phases": [...],
    "analysis": "<summary>"
}}"""


class AttackPlanner:
    """
    AI-powered attack planning engine.

    Generates and adapts attack plans using local LLMs.
    """

    def __init__(self, model_manager: ModelManager):
        self._model = model_manager

    async def generate_plan(
        self,
        objectives: list[str],
        targets: list[str],
        available_modules: list[str],
        scope_config: ScopeConfig,
    ) -> dict[str, Any]:
        """Generate an attack plan using AI."""
        scope_summary = {
            "auth_level": scope_config.auth_level.value,
            "target_hosts": scope_config.target_hosts,
            "excluded_hosts": scope_config.excluded_hosts,
            "max_rps": scope_config.max_requests_per_second,
            "dry_run": scope_config.dry_run,
        }

        prompt = PLAN_GENERATION_PROMPT.format(
            objectives=json.dumps(objectives),
            targets=json.dumps(targets),
            modules=json.dumps(available_modules),
            auth_level=scope_config.auth_level.value,
            scope_summary=json.dumps(scope_summary, indent=2),
        )

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=PLANNER_SYSTEM_PROMPT,
                temperature=0.3,
            )
            plan = self._parse_plan_response(response)
            logger.info(f"AI generated plan with {len(plan.get('phases', []))} phases")
            return plan
        except Exception as exc:
            logger.warning(f"AI planning failed, using fallback: {exc}")
            return self._fallback_plan(objectives, targets, available_modules, scope_config)

    async def adapt_plan(
        self,
        completed_results: list[dict[str, Any]],
        remaining_phases: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Adapt the attack plan based on results from completed phases."""
        prompt = ADAPTIVE_PROMPT.format(
            results=json.dumps(completed_results, indent=2),
            remaining=json.dumps(remaining_phases, indent=2),
            context=json.dumps(context, indent=2),
        )

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=PLANNER_SYSTEM_PROMPT,
                temperature=0.4,
            )
            return self._parse_json_response(response)
        except Exception as exc:
            logger.warning(f"Adaptive planning failed: {exc}")
            return {"modifications": [], "new_phases": [], "skip_phases": [], "analysis": "Adaptation failed"}

    async def assess_risk(self, phase_description: str, target: str) -> dict[str, Any]:
        """Get AI risk assessment for a specific attack phase."""
        prompt = f"""Assess the risk of the following attack simulation phase:

Phase: {phase_description}
Target: {target}

Provide:
1. Risk level (low/medium/high/critical)
2. Potential impact on target availability
3. Detection likelihood
4. Recommended precautions

Respond as JSON: {{"risk_level": "...", "availability_impact": "...", "detection_likelihood": "...", "precautions": [...]}}"""

        try:
            response = await self._model.generate(prompt=prompt, system=PLANNER_SYSTEM_PROMPT)
            return self._parse_json_response(response)
        except Exception:
            return {"risk_level": "unknown", "availability_impact": "unknown", "detection_likelihood": "unknown", "precautions": []}

    def _parse_plan_response(self, response: str) -> dict[str, Any]:
        """Extract JSON plan from AI response."""
        return self._parse_json_response(response)

    def _parse_json_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from AI response, handling markdown code blocks."""
        text = response.strip()

        # Strip markdown code fences
        if "```json" in text:
            text = text.split("```json", 1)[1]
            text = text.split("```", 1)[0]
        elif "```" in text:
            text = text.split("```", 1)[1]
            text = text.split("```", 1)[0]

        return json.loads(text.strip())

    def _fallback_plan(
        self,
        objectives: list[str],
        targets: list[str],
        available_modules: list[str],
        scope_config: ScopeConfig,
    ) -> dict[str, Any]:
        """Generate a basic plan when AI is unavailable."""
        phases = []
        phase_order = [
            ("recon", "Reconnaissance", "T1595", "Active Scanning", AuthorizationLevel.READ_ONLY),
            ("discovery", "Service Discovery", "T1046", "Network Service Discovery", AuthorizationLevel.READ_ONLY),
            ("sqli", "SQL Injection Testing", "T1190", "Exploit Public-Facing Application", AuthorizationLevel.LOW_IMPACT),
            ("xss", "XSS Testing", "T1189", "Drive-by Compromise", AuthorizationLevel.LOW_IMPACT),
            ("command_injection", "Command Injection Testing", "T1059", "Command and Scripting Interpreter", AuthorizationLevel.STANDARD),
            ("ssrf", "SSRF Testing", "T1090", "Proxy", AuthorizationLevel.LOW_IMPACT),
            ("ssti", "SSTI Testing", "T1190", "Exploit Public-Facing Application", AuthorizationLevel.STANDARD),
            ("jwt", "JWT Testing", "T1550", "Use Alternate Authentication Material", AuthorizationLevel.LOW_IMPACT),
            ("auth_bypass", "Authentication Bypass", "T1078", "Valid Accounts", AuthorizationLevel.STANDARD),
        ]

        for module_name, phase_name, technique_id, technique_name, required_level in phase_order:
            if module_name in available_modules:
                level_order = list(AuthorizationLevel)
                if level_order.index(required_level) <= level_order.index(scope_config.auth_level):
                    phases.append({
                        "name": phase_name,
                        "description": f"Execute {phase_name.lower()} against targets",
                        "module_name": module_name,
                        "targets": targets,
                        "payloads": ["default"],
                        "auth_level_required": required_level.value,
                        "depends_on": [],
                        "mitre_technique_id": technique_id,
                        "mitre_technique_name": technique_name,
                        "risk_level": "low" if required_level in (AuthorizationLevel.READ_ONLY, AuthorizationLevel.LOW_IMPACT) else "medium",
                    })

        return {
            "phases": phases,
            "mitre_techniques": list({p["mitre_technique_id"] for p in phases}),
            "estimated_duration_minutes": len(phases) * 5,
            "risk_assessment": "Fallback plan - sequential module execution within authorized scope",
        }
