"""
BAS Engine configuration settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from bas.ai.model_manager import ModelConfig, ModelBackend
from bas.core.scope import AuthorizationLevel, ScopeConfig


class BASSettings(BaseModel):
    """Top-level BAS Engine configuration."""

    # Engagement
    engagement_id: str = ""
    engagement_name: str = "BAS Engagement"
    authorized_by: str = ""

    # Targets
    targets: list[str] = Field(default_factory=list)
    target_cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)

    # Authorization
    auth_level: str = "low_impact"
    dry_run: bool = False

    # Rate limiting
    max_rps: int = 10
    max_concurrent: int = 5

    # Modules to run
    modules: list[str] = Field(default_factory=lambda: [
        "discovery", "sqli", "xss", "command_injection",
        "ssti", "ssrf", "jwt", "auth_bypass",
    ])

    # AI configuration
    ai_backend: str = "ollama"
    ai_model: str = "llama3.2"
    ai_host: str = "http://localhost:11434"
    ai_model_path: str = ""
    ai_context_length: int = 8192
    ai_temperature: float = 0.3
    enable_zeroday: bool = False

    # Paths
    repo_path: str = "."
    payload_db_path: str = "./bas_data/payloads.db"
    output_dir: str = "./bas_output"
    log_dir: str = "./bas_logs"
    skills_dir: str = ""

    # Proxy
    proxy: str = ""

    # Attack options
    attack_params: list[str] = Field(default_factory=lambda: ["id", "q", "search", "name", "input", "url"])
    attack_paths: list[str] = Field(default_factory=lambda: ["/"])
    max_payloads_per_module: int = 50

    # Time window
    allowed_start_time: str = ""
    allowed_end_time: str = ""

    def to_scope_config(self) -> ScopeConfig:
        """Convert to a ScopeConfig for the engine."""
        return ScopeConfig(
            engagement_id=self.engagement_id,
            engagement_name=self.engagement_name,
            authorized_by=self.authorized_by,
            target_hosts=[t.split("/")[2] if "://" in t else t.split(":")[0] for t in self.targets],
            target_cidrs=self.target_cidrs,
            target_urls=[f".*{t}.*" for t in self.targets] if self.targets else [],
            excluded_hosts=self.excluded_hosts,
            auth_level=AuthorizationLevel(self.auth_level),
            max_requests_per_second=self.max_rps,
            max_concurrent_operations=self.max_concurrent,
            dry_run=self.dry_run,
            allowed_start_time=self.allowed_start_time or None,
            allowed_end_time=self.allowed_end_time or None,
        )

    def to_model_config(self) -> ModelConfig:
        """Convert to a ModelConfig for AI."""
        return ModelConfig(
            backend=ModelBackend(self.ai_backend),
            model_name=self.ai_model,
            model_path=self.ai_model_path,
            context_length=self.ai_context_length,
            temperature=self.ai_temperature,
            ollama_host=self.ai_host,
        )


def load_config(path: str | Path) -> BASSettings:
    """Load configuration from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return BASSettings(**data)
