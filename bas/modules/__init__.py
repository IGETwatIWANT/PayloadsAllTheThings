"""
Attack modules for BAS Engine.

Each module implements a specific attack category and can:
- Load payloads from the database
- Execute attacks against in-scope targets
- Analyze responses for vulnerability indicators
- Report findings with MITRE ATT&CK mapping
"""

from bas.modules.base_module import BaseAttackModule, ModuleResult, ModuleMetadata

__all__ = ["BaseAttackModule", "ModuleResult", "ModuleMetadata"]
