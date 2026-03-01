"""Tests for MITRE ATT&CK mapping."""

from bas.config.mitre_mapping import (
    get_technique,
    get_techniques_for_module,
    get_coverage_matrix,
    MITRE_TECHNIQUES,
    MODULE_TECHNIQUE_MAP,
)


class TestMITREMapping:
    def test_technique_lookup(self):
        tech = get_technique("T1190")
        assert tech is not None
        assert tech.name == "Exploit Public-Facing Application"
        assert tech.tactic == "Initial Access"

    def test_module_technique_mapping(self):
        sqli_techniques = get_techniques_for_module("sqli")
        assert len(sqli_techniques) > 0
        assert any(t.technique_id == "T1190" for t in sqli_techniques)

    def test_coverage_matrix(self):
        modules = ["discovery", "sqli", "xss", "ssrf"]
        matrix = get_coverage_matrix(modules)
        assert "Reconnaissance" in matrix
        assert "Initial Access" in matrix

    def test_all_modules_have_mappings(self):
        required_modules = ["discovery", "sqli", "xss", "command_injection", "ssti", "ssrf", "jwt", "auth_bypass"]
        for module in required_modules:
            assert module in MODULE_TECHNIQUE_MAP, f"Module {module} missing MITRE mapping"
            assert len(MODULE_TECHNIQUE_MAP[module]) > 0

    def test_all_technique_ids_valid(self):
        for module, technique_ids in MODULE_TECHNIQUE_MAP.items():
            for tid in technique_ids:
                assert tid in MITRE_TECHNIQUES, f"Module {module} references unknown technique {tid}"
