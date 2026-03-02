"""
Skill system for BAS AI models.

Skills are structured prompts + training data that teach local models
specific security testing capabilities. They can be loaded, trained,
and swapped without changing the base model.

Skills are lightweight - they work via prompt engineering + few-shot
examples, not model fine-tuning (though that's also supported).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    """A trainable skill for the AI model."""
    name: str
    description: str
    version: str = "1.0"
    system_prompt: str = ""
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)
    training_data_path: str = ""
    tags: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_messages(self, user_prompt: str) -> list[dict[str, str]]:
        """Convert skill into a message sequence for the model."""
        messages = []

        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})

        # Few-shot examples
        for example in self.few_shot_examples:
            if "user" in example:
                messages.append({"role": "user", "content": example["user"]})
            if "assistant" in example:
                messages.append({"role": "assistant", "content": example["assistant"]})

        messages.append({"role": "user", "content": user_prompt})
        return messages

    @classmethod
    def from_yaml(cls, path: str | Path) -> Skill:
        """Load a skill from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        """Save skill to a YAML file."""
        data = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "system_prompt": self.system_prompt,
            "few_shot_examples": self.few_shot_examples,
            "training_data_path": self.training_data_path,
            "tags": self.tags,
            "parameters": self.parameters,
        }
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


class SkillRegistry:
    """Registry for managing AI skills."""

    def __init__(self, skills_dir: str | Path | None = None):
        self._skills: dict[str, Skill] = {}
        self._skills_dir = Path(skills_dir) if skills_dir else None
        if self._skills_dir:
            self._load_skills()

    def _load_skills(self) -> None:
        """Load all skills from the skills directory."""
        if not self._skills_dir or not self._skills_dir.exists():
            return

        for skill_file in self._skills_dir.glob("*.yaml"):
            try:
                skill = Skill.from_yaml(skill_file)
                self._skills[skill.name] = skill
                logger.info(f"Loaded skill: {skill.name} v{skill.version}")
            except Exception as exc:
                logger.warning(f"Failed to load skill from {skill_file}: {exc}")

        for skill_file in self._skills_dir.glob("*.yml"):
            try:
                skill = Skill.from_yaml(skill_file)
                self._skills[skill.name] = skill
            except Exception as exc:
                logger.warning(f"Failed to load skill from {skill_file}: {exc}")

    def register(self, skill: Skill) -> None:
        """Register a skill."""
        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill | None:
        """Get a skill by name."""
        return self._skills.get(name)

    def list_skills(self) -> list[dict[str, str]]:
        """List all registered skills."""
        return [
            {"name": s.name, "description": s.description, "version": s.version, "tags": ", ".join(s.tags)}
            for s in self._skills.values()
        ]

    def get_by_tag(self, tag: str) -> list[Skill]:
        """Get skills by tag."""
        return [s for s in self._skills.values() if tag in s.tags]
