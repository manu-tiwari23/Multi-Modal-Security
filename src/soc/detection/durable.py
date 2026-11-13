"""Shared threshold counters and replay-stable rule matches across workers."""
import hashlib
import json

from psycopg2 import sql
from psycopg2.extras import Json

from .matcher import DetectionEngine
from .rule_model import RuleMatch


class DurableDetectionEngine:
    def __init__(self, rules, repository, anomaly_config=None):
        self.rules = rules
        self.repository = repository
        self.anomaly_config = anomaly_config
        encoded = json.dumps({"rules": [rule.model_dump(mode="json") for rule in rules],
            "anomaly": anomaly_config.model_dump() if anomaly_config else None}, sort_keys=True).encode()
        self.rule_version = hashlib.sha256(encoded).hexdigest()

    def evaluate(self, event):
        repository = self.repository
        with repository.connection() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-detection:{repository.schema}",))
            cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (rule_version TEXT PRIMARY KEY, snapshot JSONB NOT NULL)").format(repository.table("mms_detection_state")))
            cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (event_id TEXT PRIMARY KEY, matches JSONB NOT NULL)").format(repository.table("mms_detection_results")))
            cursor.execute(sql.SQL("SELECT matches FROM {} WHERE event_id=%s").format(repository.table("mms_detection_results")), (event.event_id,))
            previous = cursor.fetchone()
            if previous:
                return [RuleMatch.model_validate(item) for item in previous[0]]
            cursor.execute(sql.SQL("SELECT snapshot FROM {} WHERE rule_version=%s").format(repository.table("mms_detection_state")), (self.rule_version,))
            row = cursor.fetchone()
            engine = DetectionEngine(self.rules, self.anomaly_config)
            if row:
                engine.restore_state(row[0])
            matches = engine.evaluate(event)
            cursor.execute(sql.SQL("INSERT INTO {}(rule_version,snapshot) VALUES (%s,%s) ON CONFLICT(rule_version) DO UPDATE SET snapshot=EXCLUDED.snapshot").format(repository.table("mms_detection_state")), (self.rule_version, Json(engine.export_state())))
            cursor.execute(sql.SQL("INSERT INTO {}(event_id,matches) VALUES (%s,%s)").format(repository.table("mms_detection_results")), (event.event_id, Json([match.model_dump(mode="json") for match in matches])))
            return matches
