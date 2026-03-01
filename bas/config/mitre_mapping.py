"""
MITRE ATT&CK technique mapping for BAS Engine.

Maps BAS modules and findings to MITRE ATT&CK Enterprise techniques
for compliance reporting and threat intelligence correlation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MITRETechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str


# MITRE ATT&CK Enterprise techniques relevant to BAS
MITRE_TECHNIQUES: dict[str, MITRETechnique] = {
    "T1595": MITRETechnique("T1595", "Active Scanning", "Reconnaissance", "Adversaries may scan victim IP blocks to gather information.", "https://attack.mitre.org/techniques/T1595"),
    "T1592": MITRETechnique("T1592", "Gather Victim Host Information", "Reconnaissance", "Gather information about the victim's hosts.", "https://attack.mitre.org/techniques/T1592"),
    "T1190": MITRETechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "Adversaries may exploit vulnerabilities in internet-facing software.", "https://attack.mitre.org/techniques/T1190"),
    "T1189": MITRETechnique("T1189", "Drive-by Compromise", "Initial Access", "Adversaries may compromise web applications visited by a target.", "https://attack.mitre.org/techniques/T1189"),
    "T1078": MITRETechnique("T1078", "Valid Accounts", "Initial Access", "Adversaries may use credentials of existing accounts.", "https://attack.mitre.org/techniques/T1078"),
    "T1059": MITRETechnique("T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters.", "https://attack.mitre.org/techniques/T1059"),
    "T1059.007": MITRETechnique("T1059.007", "JavaScript", "Execution", "Adversaries may abuse JavaScript for execution.", "https://attack.mitre.org/techniques/T1059/007"),
    "T1203": MITRETechnique("T1203", "Exploitation for Client Execution", "Execution", "Adversaries may exploit client software vulnerabilities.", "https://attack.mitre.org/techniques/T1203"),
    "T1090": MITRETechnique("T1090", "Proxy", "Command and Control", "Adversaries may use proxies to direct network traffic.", "https://attack.mitre.org/techniques/T1090"),
    "T1550": MITRETechnique("T1550", "Use Alternate Authentication Material", "Defense Evasion", "Use non-standard auth material like tokens.", "https://attack.mitre.org/techniques/T1550"),
    "T1548": MITRETechnique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "Circumvent access control mechanisms.", "https://attack.mitre.org/techniques/T1548"),
    "T1552": MITRETechnique("T1552", "Unsecured Credentials", "Credential Access", "Search for insecurely stored credentials.", "https://attack.mitre.org/techniques/T1552"),
    "T1552.005": MITRETechnique("T1552.005", "Cloud Instance Metadata API", "Credential Access", "Access cloud metadata APIs for credentials.", "https://attack.mitre.org/techniques/T1552/005"),
    "T1046": MITRETechnique("T1046", "Network Service Discovery", "Discovery", "Enumerate services running on network hosts.", "https://attack.mitre.org/techniques/T1046"),
}

# Map module names to their primary MITRE techniques
MODULE_TECHNIQUE_MAP: dict[str, list[str]] = {
    "discovery": ["T1595", "T1592", "T1046"],
    "sqli": ["T1190"],
    "xss": ["T1189", "T1059.007"],
    "command_injection": ["T1059"],
    "ssti": ["T1190"],
    "ssrf": ["T1090", "T1552.005"],
    "jwt": ["T1550", "T1078"],
    "auth_bypass": ["T1078", "T1548"],
    "zeroday": ["T1190", "T1203"],
}


def get_technique(technique_id: str) -> MITRETechnique | None:
    """Get a MITRE technique by ID."""
    return MITRE_TECHNIQUES.get(technique_id)


def get_techniques_for_module(module_name: str) -> list[MITRETechnique]:
    """Get all MITRE techniques mapped to a module."""
    ids = MODULE_TECHNIQUE_MAP.get(module_name, [])
    return [MITRE_TECHNIQUES[tid] for tid in ids if tid in MITRE_TECHNIQUES]


def get_coverage_matrix(modules_executed: list[str]) -> dict[str, list[str]]:
    """Get MITRE ATT&CK coverage matrix for executed modules."""
    coverage: dict[str, list[str]] = {}
    for module in modules_executed:
        techniques = get_techniques_for_module(module)
        for tech in techniques:
            if tech.tactic not in coverage:
                coverage[tech.tactic] = []
            coverage[tech.tactic].append(f"{tech.technique_id}: {tech.name}")
    return coverage
