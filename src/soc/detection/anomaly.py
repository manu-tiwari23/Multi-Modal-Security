"""Explainable event-rate anomaly detection with warm-up and robust baselines."""
from copy import deepcopy
import json
from pathlib import Path
from statistics import median

from pydantic import BaseModel, ConfigDict, Field

from .rule_model import RuleMatch
from src.shared.event_schema import Entity


class RateAnomalyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    bucket_seconds: int = Field(default=60, ge=10, le=3600)
    history_buckets: int = Field(default=30, ge=10, le=120)
    warmup_buckets: int = Field(default=10, ge=5, le=120)
    minimum_rate: int = Field(default=20, ge=5, le=10000)
    deviation_multiplier: float = Field(default=6, ge=3, le=20)
    max_groups: int = Field(default=1000, ge=1, le=10000)


def load_anomaly_config():
    config = RateAnomalyConfig.model_validate_json((Path(__file__).parent.parent / "anomaly.json").read_text(encoding="utf-8"))
    if config.warmup_buckets > config.history_buckets:
        raise ValueError("Anomaly warm-up exceeds history size")
    return config


class RateAnomalyDetector:
    def __init__(self, config):
        self.config = config
        self.groups = {}

    def snapshot(self):
        return deepcopy(self.groups)

    def restore(self, state):
        self.groups = deepcopy(state)

    def evaluate(self, event):
        cfg = self.config
        if not cfg.enabled:
            return []
        host = event.entity.host if event.entity else None
        key = json.dumps([event.source, event.event_type, host or "unattributed"], separators=(",", ":"))
        bucket = int(event.timestamp.timestamp()) // cfg.bucket_seconds
        state = self.groups.get(key)
        if state is None or bucket - state["bucket"] > cfg.history_buckets:
            if key not in self.groups and len(self.groups) >= cfg.max_groups:
                oldest = min(self.groups, key=lambda group: self.groups[group]["bucket"])
                del self.groups[oldest]
            state = {"bucket": bucket, "ids": [], "history": [], "alerted": False}
            self.groups[key] = state
        if bucket < state["bucket"]:
            return []  # Late events still receive rule analysis, not a false current-rate signal.
        if bucket > state["bucket"]:
            gap = bucket - state["bucket"]
            state["history"] = (state["history"] + [len(state["ids"])] + [0] * (gap - 1))[-cfg.history_buckets:]
            state.update(bucket=bucket, ids=[], alerted=False)
        if event.event_id in state["ids"] or len(state["ids"]) >= 10000:
            return []
        state["ids"].append(event.event_id)
        if state["alerted"] or len(state["history"]) < cfg.warmup_buckets:
            return []
        center = median(state["history"])
        deviation = median(abs(value - center) for value in state["history"])
        threshold = max(cfg.minimum_rate, center + cfg.deviation_multiplier * max(1.0, 1.4826 * deviation))
        count = len(state["ids"])
        if count <= threshold:
            return []
        state["alerted"] = True
        return [RuleMatch(rule_id="SOC-ANOMALY-RATE", rule_title="Unusual event-rate increase", severity="high",
            matched_event_ids=list(state["ids"]), entity=event.entity or Entity(), tags=["anomaly", "event_rate"],
            context={"observed_count": count, "bucket_seconds": cfg.bucket_seconds, "baseline_median": center,
                "baseline_mad": deviation, "history_buckets": len(state["history"]), "threshold": threshold,
                "group": {"source": event.source, "event_type": event.event_type, "host": host},
                "rule_description": f"Observed {count} events in the current {cfg.bucket_seconds}-second bucket; baseline median {center:g}, MAD {deviation:g}, threshold {threshold:g}.",
                "limitations": "Rate anomaly, not proof of compromise. Warm-up required; late buckets ignored; idle groups reset; per-bucket counts capped at 10000."})]
