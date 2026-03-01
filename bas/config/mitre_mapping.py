"""
MITRE ATT&CK technique mapping for BASzy Ai.

Maps BASzy Ai modules and findings to MITRE ATT&CK Enterprise techniques
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


# MITRE ATT&CK Enterprise techniques relevant to BASzy Ai
MITRE_TECHNIQUES: dict[str, MITRETechnique] = {
    # Reconnaissance
    "T1595": MITRETechnique("T1595", "Active Scanning", "Reconnaissance", "Adversaries may scan victim IP blocks to gather information.", "https://attack.mitre.org/techniques/T1595"),
    "T1595.002": MITRETechnique("T1595.002", "Vulnerability Scanning", "Reconnaissance", "Scan for vulnerabilities in victim systems.", "https://attack.mitre.org/techniques/T1595/002"),
    "T1592": MITRETechnique("T1592", "Gather Victim Host Information", "Reconnaissance", "Gather information about the victim's hosts.", "https://attack.mitre.org/techniques/T1592"),
    # Initial Access
    "T1190": MITRETechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "Adversaries may exploit vulnerabilities in internet-facing software.", "https://attack.mitre.org/techniques/T1190"),
    "T1189": MITRETechnique("T1189", "Drive-by Compromise", "Initial Access", "Adversaries may compromise web applications visited by a target.", "https://attack.mitre.org/techniques/T1189"),
    "T1078": MITRETechnique("T1078", "Valid Accounts", "Initial Access", "Adversaries may use credentials of existing accounts.", "https://attack.mitre.org/techniques/T1078"),
    "T1078.001": MITRETechnique("T1078.001", "Default Accounts", "Initial Access", "Use default credentials to access accounts.", "https://attack.mitre.org/techniques/T1078/001"),
    # Execution
    "T1059": MITRETechnique("T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters.", "https://attack.mitre.org/techniques/T1059"),
    "T1059.007": MITRETechnique("T1059.007", "JavaScript", "Execution", "Adversaries may abuse JavaScript for execution.", "https://attack.mitre.org/techniques/T1059/007"),
    "T1203": MITRETechnique("T1203", "Exploitation for Client Execution", "Execution", "Adversaries may exploit client software vulnerabilities.", "https://attack.mitre.org/techniques/T1203"),
    # Persistence
    "T1505.003": MITRETechnique("T1505.003", "Web Shell", "Persistence", "Adversaries may upload web shells for persistent access.", "https://attack.mitre.org/techniques/T1505/003"),
    # Defense Evasion
    "T1550": MITRETechnique("T1550", "Use Alternate Authentication Material", "Defense Evasion", "Use non-standard auth material like tokens.", "https://attack.mitre.org/techniques/T1550"),
    "T1036": MITRETechnique("T1036", "Masquerading", "Defense Evasion", "Manipulate features to make artifacts appear legitimate.", "https://attack.mitre.org/techniques/T1036"),
    "T1055": MITRETechnique("T1055", "Process Injection", "Defense Evasion", "Inject code into processes to evade detection.", "https://attack.mitre.org/techniques/T1055"),
    "T1027": MITRETechnique("T1027", "Obfuscated Files or Information", "Defense Evasion", "Make payloads or data difficult to discover.", "https://attack.mitre.org/techniques/T1027"),
    "T1140": MITRETechnique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "Use obfuscation to hide command execution.", "https://attack.mitre.org/techniques/T1140"),
    "T1562.001": MITRETechnique("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Disable security tools to evade detection.", "https://attack.mitre.org/techniques/T1562/001"),
    # Privilege Escalation
    "T1548": MITRETechnique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "Circumvent access control mechanisms.", "https://attack.mitre.org/techniques/T1548"),
    "T1068": MITRETechnique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Exploit software vulnerability for elevated privileges.", "https://attack.mitre.org/techniques/T1068"),
    # Credential Access
    "T1552": MITRETechnique("T1552", "Unsecured Credentials", "Credential Access", "Search for insecurely stored credentials.", "https://attack.mitre.org/techniques/T1552"),
    "T1552.005": MITRETechnique("T1552.005", "Cloud Instance Metadata API", "Credential Access", "Access cloud metadata APIs for credentials.", "https://attack.mitre.org/techniques/T1552/005"),
    "T1110": MITRETechnique("T1110", "Brute Force", "Credential Access", "Use brute force techniques to obtain credentials.", "https://attack.mitre.org/techniques/T1110"),
    "T1556": MITRETechnique("T1556", "Modify Authentication Process", "Credential Access", "Modify authentication to access credentials.", "https://attack.mitre.org/techniques/T1556"),
    # Discovery
    "T1046": MITRETechnique("T1046", "Network Service Discovery", "Discovery", "Enumerate services running on network hosts.", "https://attack.mitre.org/techniques/T1046"),
    "T1087": MITRETechnique("T1087", "Account Discovery", "Discovery", "Get listing of accounts on a system or domain.", "https://attack.mitre.org/techniques/T1087"),
    "T1018": MITRETechnique("T1018", "Remote System Discovery", "Discovery", "Discover remote systems on a network.", "https://attack.mitre.org/techniques/T1018"),
    # Lateral Movement
    "T1210": MITRETechnique("T1210", "Exploitation of Remote Services", "Lateral Movement", "Exploit remote services to move laterally.", "https://attack.mitre.org/techniques/T1210"),
    # Collection
    "T1005": MITRETechnique("T1005", "Data from Local System", "Collection", "Search local file systems for sensitive data.", "https://attack.mitre.org/techniques/T1005"),
    "T1530": MITRETechnique("T1530", "Data from Cloud Storage", "Collection", "Access data from cloud storage.", "https://attack.mitre.org/techniques/T1530"),
    "T1213": MITRETechnique("T1213", "Data from Information Repositories", "Collection", "Collect data from information repositories.", "https://attack.mitre.org/techniques/T1213"),
    # Command and Control
    "T1090": MITRETechnique("T1090", "Proxy", "Command and Control", "Adversaries may use proxies to direct network traffic.", "https://attack.mitre.org/techniques/T1090"),
    "T1071": MITRETechnique("T1071", "Application Layer Protocol", "Command and Control", "Communicate using application layer protocols.", "https://attack.mitre.org/techniques/T1071"),
    # Impact
    "T1499": MITRETechnique("T1499", "Endpoint Denial of Service", "Impact", "Perform denial of service on endpoints.", "https://attack.mitre.org/techniques/T1499"),
    # Exfiltration
    "T1048": MITRETechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Exfiltrate data over alternative protocols.", "https://attack.mitre.org/techniques/T1048"),
}

# Map module names to their primary MITRE techniques
MODULE_TECHNIQUE_MAP: dict[str, list[str]] = {
    # Original modules
    "discovery": ["T1595", "T1592", "T1046"],
    "sqli": ["T1190"],
    "xss": ["T1189", "T1059.007"],
    "command_injection": ["T1059"],
    "ssti": ["T1190", "T1059"],
    "ssrf": ["T1090", "T1552.005"],
    "jwt": ["T1550", "T1078"],
    "auth_bypass": ["T1078", "T1548"],
    "zeroday": ["T1190", "T1203"],
    # Web modules
    "xxe": ["T1190", "T1005"],
    "deserialization": ["T1190", "T1059"],
    "open_redirect": ["T1189"],
    "cors": ["T1190", "T1548"],
    "crlf": ["T1190"],
    "path_traversal": ["T1005", "T1190"],
    "prototype_pollution": ["T1059.007"],
    "file_upload": ["T1505.003", "T1190"],
    "idor": ["T1548", "T1213"],
    "csrf": ["T1189"],
    "cache_deception": ["T1036", "T1190"],
    "request_smuggling": ["T1190", "T1090"],
    "graphql": ["T1190", "T1213"],
    "websocket": ["T1071", "T1189"],
    "nosqli": ["T1190"],
    "ldap": ["T1190", "T1087"],
    "xpath": ["T1190"],
    "hpp": ["T1190"],
    # Network modules
    "port_scan": ["T1046", "T1595"],
    "dir_brute": ["T1595", "T1595.002"],
    "subdomain_enum": ["T1595.002", "T1018"],
    "credential_test": ["T1078.001", "T1110"],
    # Evasion modules
    "edr_evasion": ["T1027", "T1140", "T1036"],
    "waf_bypass": ["T1027", "T1190"],
    "amsi_bypass": ["T1562.001"],
    "traffic_shaping": ["T1071", "T1090"],
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
