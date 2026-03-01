"""Tests for the skills and training system."""

import pytest
from pathlib import Path

from bas.ai.skills.base_skill import Skill, SkillRegistry


class TestSkill:
    def test_create_skill(self):
        skill = Skill(
            name="test_skill",
            description="A test skill",
            system_prompt="You are a test AI.",
            few_shot_examples=[
                {"user": "Test input", "assistant": "Test output"},
            ],
            tags=["test"],
        )
        assert skill.name == "test_skill"
        assert len(skill.few_shot_examples) == 1

    def test_to_messages(self):
        skill = Skill(
            name="test",
            description="Test",
            system_prompt="System prompt here",
            few_shot_examples=[
                {"user": "Example input", "assistant": "Example output"},
            ],
        )
        messages = skill.to_messages("User query")
        assert len(messages) == 4  # system + user example + assistant example + user query
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert messages[2]["role"] == "assistant"
        assert messages[3]["role"] == "user"
        assert messages[3]["content"] == "User query"

    def test_yaml_roundtrip(self, tmp_path):
        skill = Skill(
            name="roundtrip_test",
            description="Testing YAML roundtrip",
            version="2.0",
            system_prompt="Test prompt",
            few_shot_examples=[{"user": "Q", "assistant": "A"}],
            tags=["test", "roundtrip"],
        )

        yaml_path = tmp_path / "test_skill.yaml"
        skill.to_yaml(yaml_path)

        loaded = Skill.from_yaml(yaml_path)
        assert loaded.name == "roundtrip_test"
        assert loaded.version == "2.0"
        assert loaded.system_prompt == "Test prompt"
        assert len(loaded.few_shot_examples) == 1
        assert loaded.tags == ["test", "roundtrip"]


class TestSkillRegistry:
    def test_register_and_retrieve(self):
        registry = SkillRegistry()
        skill = Skill(name="test", description="Test skill", tags=["alpha"])
        registry.register(skill)

        retrieved = registry.get("test")
        assert retrieved is not None
        assert retrieved.name == "test"

    def test_list_skills(self):
        registry = SkillRegistry()
        registry.register(Skill(name="a", description="Skill A"))
        registry.register(Skill(name="b", description="Skill B"))
        skills = registry.list_skills()
        assert len(skills) == 2

    def test_get_by_tag(self):
        registry = SkillRegistry()
        registry.register(Skill(name="attack", description="Attack", tags=["offensive"]))
        registry.register(Skill(name="analyze", description="Analyze", tags=["defensive"]))
        registry.register(Skill(name="both", description="Both", tags=["offensive", "defensive"]))

        offensive = registry.get_by_tag("offensive")
        assert len(offensive) == 2

    def test_load_from_directory(self):
        # Load the built-in skills
        skills_dir = Path(__file__).parent.parent / "bas" / "ai" / "skills"
        if skills_dir.exists():
            registry = SkillRegistry(skills_dir)
            skills = registry.list_skills()
            assert len(skills) > 0

    def test_get_nonexistent(self):
        registry = SkillRegistry()
        assert registry.get("nonexistent") is None
