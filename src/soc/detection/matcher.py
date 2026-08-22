"""
Detection engine and stream matcher for evaluating SecurityEvents against Sigma-style rules.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from src.shared.event_schema import Entity, SecurityEvent
from src.soc.detection.rule_model import DetectionRule, RuleMatch, ThresholdConfig

logger = logging.getLogger(__name__)


def _get_nested_field(event: SecurityEvent, field_path: str) -> Any:
    """
    Retrieve a field value from a SecurityEvent using dotted notation.
    Supports:
      - Direct model attributes: 'event_type', 'source', 'severity', 'timestamp'
      - Nested models: 'entity.ip', 'entity.user', 'entity.host', 'entity.hash'
      - Nested dicts: 'raw.command', 'raw.status', 'enrichment.risk_level'
    """
    parts = field_path.split(".")
    current: Any = event

    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return None

    return current


def _match_single_value(actual: Any, expected: Any, modifier: str | None = None) -> bool:
    """Compare an extracted event field against the rule condition."""
    if actual is None:
        return False

    # Handle list of expected values (OR condition within field)
    if isinstance(expected, list) and modifier != "in":
        return any(_match_single_value(actual, item, modifier) for item in expected)

    # String representations for text comparisons
    act_str = str(actual).strip()
    exp_str = str(expected).strip()

    if modifier == "contains":
        return exp_str.lower() in act_str.lower()
    elif modifier == "startswith":
        return act_str.lower().startswith(exp_str.lower())
    elif modifier == "endswith":
        return act_str.lower().endswith(exp_str.lower())
    elif modifier == "re":
        try:
            return bool(re.search(exp_str, act_str, re.IGNORECASE))
        except re.error:
            logger.warning(f"Invalid regex in rule pattern: {exp_str}")
            return False
    elif modifier == "in":
        if isinstance(expected, (list, set, tuple)):
            return actual in expected or act_str.lower() in [str(x).lower() for x in expected]
        return False
    elif modifier == "gt":
        try:
            return float(actual) > float(expected)
        except (ValueError, TypeError):
            return False
    elif modifier == "gte":
        try:
            return float(actual) >= float(expected)
        except (ValueError, TypeError):
            return False
    elif modifier == "lt":
        try:
            return float(actual) < float(expected)
        except (ValueError, TypeError):
            return False
    elif modifier == "lte":
        try:
            return float(actual) <= float(expected)
        except (ValueError, TypeError):
            return False
    else:
        # Exact equality (case-insensitive for strings)
        if isinstance(actual, str) and isinstance(expected, str):
            return act_str.lower() == exp_str.lower()
        return actual == expected


def _evaluate_criteria_dict(event: SecurityEvent, criteria: dict[str, Any]) -> bool:
    """
    Evaluate a dictionary of field criteria against an event.
    All criteria must match (AND logic).
    Key format: 'field_name' or 'field_name|modifier'.
    """
    if not criteria:
        return True

    for key_with_mod, expected_val in criteria.items():
        if "|" in key_with_mod:
            field_path, modifier = key_with_mod.split("|", 1)
        else:
            field_path, modifier = key_with_mod, None

        actual_val = _get_nested_field(event, field_path)
        if not _match_single_value(actual_val, expected_val, modifier):
            return False

    return True


class ThresholdStateTracker:
    """Maintains in-memory sliding window state for aggregation / threshold rules."""

    def __init__(self) -> None:
        # Key: (rule_id, group_key) -> deque of (timestamp, event_id, event)
        self._windows: dict[tuple[str, str], deque[tuple[float, str, SecurityEvent]]] = defaultdict(deque)
        # Track last trigger time to prevent continuous spamming on every subsequent event
        self._last_triggered: dict[tuple[str, str], float] = {}

    def _get_group_key(self, event: SecurityEvent, by_fields: list[str]) -> str:
        """Extract composite group key from event."""
        parts: list[str] = []
        for field in by_fields:
            val = _get_nested_field(event, field)
            parts.append(str(val) if val is not None else "unknown")
        return ":".join(parts) if parts else "global"

    def record_and_check(
        self,
        rule_id: str,
        threshold: ThresholdConfig,
        event: SecurityEvent,
    ) -> list[str] | None:
        """
        Record a matching event and check if threshold condition is reached.
        Returns list of matched event_ids if threshold met, else None.
        """
        group_key = self._get_group_key(event, threshold.by)
        state_key = (rule_id, group_key)
        now_ts = event.timestamp.timestamp() if event.timestamp else datetime.now(timezone.utc).timestamp()

        window = self._windows[state_key]
        window.append((now_ts, event.event_id, event))

        # Evict events older than sliding timeframe
        cutoff = now_ts - threshold.timeframe
        while window and window[0][0] < cutoff:
            window.popleft()

        if len(window) >= threshold.count:
            # Check debounce (don't re-trigger in same 5s window unless threshold replenished)
            last_ts = self._last_triggered.get(state_key, 0.0)
            if now_ts - last_ts < 2.0 and len(window) == threshold.count:
                return None

            self._last_triggered[state_key] = now_ts
            matched_ids = [eid for _, eid, _ in window]
            # Clear or slide window after trigger to reset count
            window.clear()
            return matched_ids

        return None

    def clear(self) -> None:
        """Reset state tracking."""
        self._windows.clear()
        self._last_triggered.clear()


class DetectionEngine:
    """Core detection engine evaluating SecurityEvents against Sigma rules."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self._rules: list[DetectionRule] = rules or []
        self._tracker = ThresholdStateTracker()

    @property
    def rules(self) -> list[DetectionRule]:
        return self._rules

    def set_rules(self, rules: list[DetectionRule]) -> None:
        """Replace active rules in engine."""
        self._rules = rules

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a single rule."""
        self._rules.append(rule)

    def evaluate(self, event: SecurityEvent) -> list[RuleMatch]:
        """
        Evaluate a single SecurityEvent against all loaded rules.
        Returns a list of RuleMatch objects for any triggered rules.
        """
        matches: list[RuleMatch] = []

        for rule in self._rules:
            if rule.status == "deprecated":
                continue

            cond = rule.detection
            # 1. Evaluate selection
            selection_matches = _evaluate_criteria_dict(event, cond.selection)
            if not selection_matches:
                continue

            # 2. Evaluate filter (if present, matching filter suppresses detection)
            if cond.filter and _evaluate_criteria_dict(event, cond.filter):
                continue

            # 3. Handle Threshold rules vs Single-event rules
            if cond.threshold is not None:
                matched_ids = self._tracker.record_and_check(rule.id, cond.threshold, event)
                if matched_ids:
                    matches.append(
                        RuleMatch(
                            rule_id=rule.id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            matched_event_ids=matched_ids,
                            entity=event.entity or Entity(),
                            tags=rule.tags,
                            context={
                                "rule_description": rule.description,
                                "threshold_count": len(matched_ids),
                                "threshold_timeframe": cond.threshold.timeframe,
                                "mitre_attack": rule.mitre_attack,
                                "latest_event": event.model_dump(mode="json"),
                            },
                        )
                    )
            else:
                # Immediate single-event match
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        matched_event_ids=[event.event_id],
                        entity=event.entity or Entity(),
                        tags=rule.tags,
                        context={
                            "rule_description": rule.description,
                            "mitre_attack": rule.mitre_attack,
                            "trigger_event": event.model_dump(mode="json"),
                        },
                    )
                )

        return matches

    def evaluate_batch(self, events: list[SecurityEvent]) -> list[RuleMatch]:
        """Evaluate a batch of SecurityEvents sequentially."""
        all_matches: list[RuleMatch] = []
        for ev in events:
            all_matches.extend(self.evaluate(ev))
        return all_matches

    def reset_state(self) -> None:
        """Reset internal threshold and state tracking."""
        self._tracker.clear()
