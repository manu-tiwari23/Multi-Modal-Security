"""
SOC Scoring package: transparent risk scoring for incidents.
"""

from src.soc.scoring.calculator import ScoreBreakdown, score_incident

__all__ = [
    "ScoreBreakdown",
    "score_incident",
]
