"""
Rule loader for Sigma-style YAML/JSON detection rules.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Sequence

import yaml
from pydantic import ValidationError

from src.soc.detection.rule_model import DetectionRule

logger = logging.getLogger(__name__)

MITRE_PATTERN = re.compile(r"^attack\.t?(\d+(\.\d+)?)$", re.IGNORECASE)


def _extract_mitre_techniques(tags: list[str]) -> list[str]:
    """Extract standard MITRE ATT&CK technique IDs from tags list."""
    techniques: list[str] = []
    for tag in tags:
        m = MITRE_PATTERN.match(tag.strip())
        if m:
            technique_num = m.group(1).upper()
            if not technique_num.startswith("T"):
                technique_num = f"T{technique_num}"
            techniques.append(technique_num)
    return sorted(list(set(techniques)))


class RuleLoader:
    """Loads and manages Sigma-style detection rules from disk."""

    def __init__(self, rules_dir: Path | str | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else None
        self._rules: dict[str, DetectionRule] = {}
        self._load_errors: list[dict[str, str]] = []

    @property
    def rules(self) -> list[DetectionRule]:
        """Return list of all currently loaded rules."""
        return list(self._rules.values())

    @property
    def load_errors(self) -> list[dict[str, str]]:
        """Return list of load errors encountered during rule discovery."""
        return self._load_errors

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def load_from_file(self, file_path: Path | str) -> DetectionRule | None:
        """Load and validate a single rule file (YAML or JSON)."""
        path = Path(file_path)
        if not path.is_file():
            logger.error(f"Rule file not found: {path}")
            self._load_errors.append({"file": str(path), "error": "File not found"})
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                raise ValueError("Rule file content must be a YAML dictionary")

            # Extract MITRE attack tags if not present
            tags = data.get("tags", [])
            if "mitre_attack" not in data or not data["mitre_attack"]:
                data["mitre_attack"] = _extract_mitre_techniques(tags)

            rule = DetectionRule(**data)
            self._rules[rule.id] = rule
            logger.info(f"Loaded detection rule: {rule.id} ('{rule.title}') from {path.name}")
            return rule

        except (yaml.YAMLError, ValidationError, ValueError, Exception) as exc:
            error_msg = str(exc)
            logger.warning(f"Failed to load rule from {path}: {error_msg}")
            self._load_errors.append({"file": str(path), "error": error_msg})
            return None

    def load_from_directory(self, directory: Path | str | None = None) -> list[DetectionRule]:
        """
        Recursively scan a directory for .yml, .yaml, and .json rule files.
        Clears existing rules and populates new ones.
        """
        target_dir = Path(directory) if directory else self.rules_dir
        if not target_dir or not target_dir.exists():
            logger.warning(f"Rules directory does not exist: {target_dir}")
            return []

        self._rules.clear()
        self._load_errors.clear()

        # Find all .yaml, .yml, .json files
        rule_files = sorted(
            [
                p
                for p in target_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in (".yml", ".yaml", ".json")
            ]
        )

        for file_path in rule_files:
            self.load_from_file(file_path)

        logger.info(f"Loaded {len(self._rules)} rules from {target_dir} ({len(self._load_errors)} errors)")
        return self.rules

    def add_rules(self, rules: Sequence[DetectionRule]) -> None:
        """Directly register in-memory DetectionRule instances."""
        for rule in rules:
            self._rules[rule.id] = rule
