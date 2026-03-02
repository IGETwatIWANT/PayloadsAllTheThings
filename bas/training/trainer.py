"""
Model training framework for BAS Engine.

Supports:
- Creating training datasets from BAS engagement results
- Few-shot prompt optimization
- Generating skill files from engagement data
- Model evaluation against known vulnerabilities
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bas.ai.skills.base_skill import Skill

logger = logging.getLogger(__name__)


@dataclass
class TrainingExample:
    """A single training example."""
    input_text: str
    output_text: str
    category: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ModelTrainer:
    """
    Creates training data and skill files from BAS engagement results.

    This doesn't fine-tune models directly (that requires GPU infrastructure),
    but it creates:
    1. JSONL training datasets compatible with fine-tuning pipelines
    2. Optimized skill files (few-shot prompts) for immediate use
    3. Evaluation benchmarks to measure model effectiveness
    """

    def __init__(self, output_dir: str | Path = "./bas_training"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._examples: list[TrainingExample] = []

    def add_example(self, example: TrainingExample) -> None:
        """Add a training example."""
        self._examples.append(example)

    def add_from_engagement(self, findings: list[dict[str, Any]], responses: list[dict[str, Any]]) -> int:
        """Generate training examples from engagement results."""
        count = 0
        for finding, response in zip(findings, responses):
            if finding.get("status") in ("vulnerable", "potentially_vulnerable"):
                example = TrainingExample(
                    input_text=json.dumps({
                        "module": finding.get("module", ""),
                        "target": finding.get("target", ""),
                        "status_code": response.get("status_code", 0),
                        "body_preview": response.get("body", "")[:1000],
                        "payload": finding.get("payload", ""),
                    }),
                    output_text=json.dumps({
                        "classification": "confirmed" if finding["status"] == "vulnerable" else "potential",
                        "severity": finding.get("severity", "medium"),
                        "evidence": finding.get("evidence", ""),
                        "remediation": finding.get("remediation", ""),
                    }),
                    category=finding.get("module", "unknown"),
                    metadata={"engagement_id": finding.get("engagement_id", "")},
                )
                self._examples.append(example)
                count += 1

        return count

    def export_jsonl(self, filename: str = "training_data.jsonl") -> Path:
        """Export training data as JSONL (compatible with fine-tuning)."""
        output_path = self._output_dir / filename
        with open(output_path, "w") as f:
            for example in self._examples:
                entry = {
                    "messages": [
                        {"role": "user", "content": example.input_text},
                        {"role": "assistant", "content": example.output_text},
                    ],
                    "category": example.category,
                }
                f.write(json.dumps(entry) + "\n")

        logger.info(f"Exported {len(self._examples)} training examples to {output_path}")
        return output_path

    def generate_skill(self, skill_name: str, description: str, category: str = "") -> Skill:
        """Generate an optimized skill from training examples."""
        # Select best examples for few-shot
        relevant = [e for e in self._examples if not category or e.category == category]
        # Pick diverse examples
        selected = relevant[:5]

        few_shot = []
        for example in selected:
            few_shot.append({
                "user": example.input_text,
                "assistant": example.output_text,
            })

        skill = Skill(
            name=skill_name,
            description=description,
            system_prompt=f"You are a security analysis AI trained on real BAS engagement data for {category or 'general'} vulnerability detection.",
            few_shot_examples=few_shot,
            tags=[category, "trained", "engagement-data"],
        )

        # Save to file
        skill_path = self._output_dir / f"{skill_name}.yaml"
        skill.to_yaml(skill_path)
        logger.info(f"Generated skill '{skill_name}' with {len(few_shot)} examples at {skill_path}")

        return skill

    def generate_evaluation_set(self, filename: str = "eval_set.jsonl") -> Path:
        """Generate an evaluation benchmark from training data."""
        output_path = self._output_dir / filename
        # Use a subset for evaluation
        eval_examples = self._examples[::3]  # Every 3rd example

        with open(output_path, "w") as f:
            for example in eval_examples:
                entry = {
                    "input": example.input_text,
                    "expected_output": example.output_text,
                    "category": example.category,
                }
                f.write(json.dumps(entry) + "\n")

        return output_path
