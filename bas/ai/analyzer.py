"""
AI-Driven Result Analyzer.

Analyzes attack simulation results to:
- Classify vulnerability severity
- Generate remediation guidance
- Identify attack chains and lateral paths
- Map findings to compliance frameworks
"""

from __future__ import annotations

import json
import logging
from typing import Any

from bas.ai.model_manager import ModelManager

logger = logging.getLogger(__name__)

ANALYZER_SYSTEM_PROMPT = """You are a security analysis AI for a Breach and Attack Simulation (BAS) engine. Your role is to analyze the results of authorized security tests and provide:

1. Accurate vulnerability classification (CVSS-aligned severity)
2. Clear, actionable remediation guidance
3. MITRE ATT&CK technique mapping
4. Attack chain identification
5. Compliance impact assessment

Always provide practical, implementation-ready remediation steps. Prioritize findings by actual exploitability and business impact."""

ANALYSIS_PROMPT = """Analyze the following BAS test results:

**Module:** {module}
**Target:** {target}
**Test Type:** {test_type}

**Response Data:**
- Status Code: {status_code}
- Response Time: {elapsed_ms}ms
- Response Body (truncated): {body_preview}
- Headers: {headers}

**Payload Used:** {payload}
**Expected Behavior:** {expected}

Determine:
1. Is this a confirmed vulnerability, potential vulnerability, or false positive?
2. Severity rating (critical/high/medium/low/info)
3. MITRE ATT&CK technique mapping
4. Specific remediation steps
5. Evidence summary

Respond as JSON:
{{
    "classification": "confirmed|potential|false_positive",
    "severity": "critical|high|medium|low|info",
    "title": "<vulnerability title>",
    "description": "<detailed description>",
    "mitre_technique_id": "<T-number>",
    "mitre_technique_name": "<name>",
    "evidence": "<what proves this finding>",
    "remediation": "<specific steps to fix>",
    "confidence": <0.0-1.0>
}}"""

CHAIN_ANALYSIS_PROMPT = """Analyze the following set of findings for potential attack chains:

**Findings:**
{findings_json}

Identify:
1. Multi-step attack paths (e.g., XSS -> session hijack -> admin access)
2. Privilege escalation paths
3. Lateral movement opportunities
4. Data exfiltration risks

For each chain, rate the overall risk and provide a narrative.

Respond as JSON:
{{
    "chains": [
        {{
            "name": "<chain name>",
            "steps": ["<step1>", "<step2>", ...],
            "finding_ids": ["<id1>", "<id2>", ...],
            "overall_risk": "critical|high|medium|low",
            "narrative": "<attack narrative>",
            "impact": "<business impact>"
        }}
    ],
    "summary": "<overall security posture assessment>"
}}"""


class ResultAnalyzer:
    """
    AI-powered analysis of BAS results.

    Classifies findings, generates remediation, and identifies attack chains.
    """

    def __init__(self, model_manager: ModelManager):
        self._model = model_manager
        # Common vulnerability indicators for fast pre-screening
        self._indicators = {
            "sqli": [
                "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
                "you have an error in your sql", "unclosed quotation",
                "microsoft ole db", "odbc drivers",
            ],
            "xss": [
                "<script>", "javascript:", "onerror=", "onload=",
                "alert(", "confirm(", "prompt(",
            ],
            "ssti": [
                "49", "7777777", "${", "{{", "{%",  # 7*7, 7*'7'
            ],
            "ssrf": [
                "root:x:", "localhost", "127.0.0.1", "metadata",
                "internal server", "connection refused",
            ],
            "cmdi": [
                "uid=", "root:", "/bin/", "windows", "volume serial",
                "directory of",
            ],
            "path_traversal": [
                "root:x:0:0", "[boot loader]", "[extensions]",
                "/etc/passwd", "win.ini",
            ],
        }

    async def analyze_response(
        self,
        module: str,
        target: str,
        test_type: str,
        status_code: int,
        elapsed_ms: float,
        body: str,
        headers: dict[str, str],
        payload: str,
        expected: str = "",
    ) -> dict[str, Any]:
        """Analyze a single attack response for vulnerabilities."""
        # Fast pre-screening with pattern matching
        indicators = self._check_indicators(test_type, body)
        if not indicators and status_code in (400, 403, 404, 405, 503):
            return {
                "classification": "false_positive",
                "severity": "info",
                "title": f"No vulnerability detected - {test_type}",
                "description": "Response indicates the payload was blocked or the endpoint is not vulnerable.",
                "confidence": 0.9,
            }

        # AI deep analysis
        prompt = ANALYSIS_PROMPT.format(
            module=module,
            target=target,
            test_type=test_type,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            body_preview=body[:2000],
            headers=json.dumps(dict(list(headers.items())[:20])),
            payload=payload[:500],
            expected=expected or "Payload should be sanitized/rejected",
        )

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=ANALYZER_SYSTEM_PROMPT,
                temperature=0.2,
            )
            result = self._parse_json_response(response)
            # Boost confidence if indicators match
            if indicators:
                result["indicators_matched"] = indicators
                result["confidence"] = min(1.0, result.get("confidence", 0.5) + 0.2)
            return result
        except Exception as exc:
            logger.warning(f"AI analysis failed: {exc}")
            return self._heuristic_analysis(test_type, status_code, body, indicators)

    async def analyze_findings(self, findings: list[Any]) -> str:
        """Generate an overall analysis of all findings."""
        findings_data = [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "module": f.module,
                "target": f.target,
                "mitre": f.mitre_technique_id,
            }
            for f in findings
        ]

        prompt = f"""Provide an executive security assessment based on these BAS findings:

{json.dumps(findings_data, indent=2)}

Include:
1. Overall security posture rating
2. Top 3 most critical risks
3. Recommended immediate actions
4. Strategic improvement areas"""

        try:
            return await self._model.generate(
                prompt=prompt,
                system=ANALYZER_SYSTEM_PROMPT,
                temperature=0.3,
            )
        except Exception:
            return "AI analysis unavailable. Review individual findings for details."

    async def suggest_remediation(self, finding: Any) -> str:
        """Generate specific remediation guidance for a finding."""
        prompt = f"""Provide specific, implementation-ready remediation steps for:

Vulnerability: {finding.title}
Severity: {finding.severity.value}
Module: {finding.module}
Target: {finding.target}
Description: {finding.description}
Evidence: {finding.evidence}

Provide concrete code examples or configuration changes where applicable."""

        try:
            return await self._model.generate(
                prompt=prompt,
                system=ANALYZER_SYSTEM_PROMPT,
                temperature=0.2,
            )
        except Exception:
            return "Remediation guidance unavailable. Consult OWASP guidelines for this vulnerability class."

    async def identify_attack_chains(self, findings: list[Any]) -> dict[str, Any]:
        """Identify multi-step attack chains from findings."""
        findings_json = json.dumps([
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "module": f.module,
                "target": f.target,
                "description": f.description,
                "mitre": f.mitre_technique_id,
            }
            for f in findings
        ], indent=2)

        prompt = CHAIN_ANALYSIS_PROMPT.format(findings_json=findings_json)

        try:
            response = await self._model.generate(
                prompt=prompt,
                system=ANALYZER_SYSTEM_PROMPT,
                temperature=0.3,
            )
            return self._parse_json_response(response)
        except Exception:
            return {"chains": [], "summary": "Chain analysis unavailable."}

    def _check_indicators(self, test_type: str, body: str) -> list[str]:
        """Fast pattern-matching pre-screen."""
        body_lower = body.lower()
        matched = []
        patterns = self._indicators.get(test_type, [])
        for pattern in patterns:
            if pattern in body_lower:
                matched.append(pattern)
        return matched

    def _heuristic_analysis(
        self,
        test_type: str,
        status_code: int,
        body: str,
        indicators: list[str],
    ) -> dict[str, Any]:
        """Fallback heuristic analysis when AI is unavailable."""
        if indicators:
            return {
                "classification": "potential",
                "severity": "medium",
                "title": f"Potential {test_type.upper()} vulnerability detected",
                "description": f"Response contains indicators of {test_type}: {', '.join(indicators)}",
                "evidence": f"Matched patterns: {indicators}",
                "confidence": 0.4 + (0.1 * len(indicators)),
                "remediation": f"Investigate {test_type} indicators in the response. Apply input validation and output encoding.",
            }
        return {
            "classification": "false_positive",
            "severity": "info",
            "title": f"No {test_type} indicators found",
            "description": "No vulnerability indicators detected in the response.",
            "confidence": 0.6,
        }

    def _parse_json_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from AI response."""
        text = response.strip()
        if "```json" in text:
            text = text.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in text:
            text = text.split("```", 1)[1].split("```", 1)[0]
        return json.loads(text.strip())
