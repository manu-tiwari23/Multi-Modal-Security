"""
SOC Detection package: Sigma-style rule models, loaders, and stream matchers.
"""

from src.soc.detection.matcher import DetectionEngine, ThresholdStateTracker
from src.soc.detection.rule_loader import RuleLoader
from src.soc.detection.rule_model import (
    DetectionCondition,
    DetectionRule,
    RuleMatch,
    ThresholdConfig,
)

__all__ = [
    "DetectionRule",
    "DetectionCondition",
    "ThresholdConfig",
    "RuleMatch",
    "RuleLoader",
    "DetectionEngine",
    "ThresholdStateTracker",
]
