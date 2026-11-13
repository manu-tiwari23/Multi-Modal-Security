"""Local lexical vector retrieval over stored incident summaries.

Vectors are sparse normalized term-frequency embeddings, not neural semantic
embeddings. Exact cosine ranking is reproducible and uses no paid API calls.
"""
from collections import Counter
from datetime import datetime, timezone
import math
import re
from threading import RLock

from psycopg2 import sql
from psycopg2.extras import Json

from .audit import PostgresCopilotAudit, digest

STOP_WORDS = frozenset("a an and are as at be by for from how i in is it of on or our please show system the this to was were what with incident incidents similar previous past find review".split())


def vectorize(text):
    terms = [term for term in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", text.lower()) if len(term) > 1 and term not in STOP_WORDS]
    counts = Counter(terms)
    weights = {term: 1 + math.log(count) for term, count in counts.items()}
    norm = math.sqrt(sum(weight * weight for weight in weights.values()))
    return {term: weight / norm for term, weight in weights.items()} if norm else {}


def summary_document(incident):
    fields = ("incident_id", "title", "description", "severity", "status", "risk_score", "event_count", "updated_at", "mitre_techniques", "tags")
    document = {key: incident.get(key) for key in fields}
    # Summaries omit raw event bodies, entities, credentials and evidence contents.
    document["event_types"] = sorted({item.get("event_type", "") for item in incident.get("timeline", [])})
    text = " ".join(str(document.get(key) or "") for key in ("title", "description", "mitre_techniques", "tags", "event_types"))
    return {"document": document, "vector": vectorize(text), "digest": digest(document)}


class MemoryHistoryStore:
    def __init__(self):
        self.items = {}
        self.lock = RLock()

    def sync(self, items):
        with self.lock:
            self.items = {item["document"]["incident_id"]: item for item in items}

    def list_items(self):
        with self.lock:
            return list(self.items.values())


class PostgresHistoryStore:
    def __init__(self, dsn, schema="public", timeout=5):
        # Shared audit connection lifecycle supplies schema validation, timeouts and
        # fail-closed storage errors; vector rows are separate from immutable audits.
        self.database = PostgresCopilotAudit(dsn, schema, timeout)

    def sync(self, items):
        db = self.database
        with db.connection() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-history-vectors:{db.schema}",))
            cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (incident_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, item JSONB NOT NULL)").format(db.table("mms_incident_vectors")))
            for item in items:
                cursor.execute(sql.SQL("INSERT INTO {}(incident_id,content_hash,item) VALUES (%s,%s,%s) ON CONFLICT(incident_id) DO UPDATE SET content_hash=EXCLUDED.content_hash,item=EXCLUDED.item WHERE {}.content_hash<>EXCLUDED.content_hash").format(db.table("mms_incident_vectors"), sql.Identifier("mms_incident_vectors")), (item["document"]["incident_id"], item["digest"], Json(item)))

    def list_items(self):
        db = self.database
        with db.connection() as cursor:
            cursor.execute(sql.SQL("SELECT item FROM {}").format(db.table("mms_incident_vectors")))
            return [row[0] for row in cursor.fetchall()]


class PastIncidentRetriever:
    def __init__(self, source, store):
        self.source, self.store = source, store

    def search(self, query, exclude_incident_id=None, limit=5):
        query_vector = vectorize(query)
        if not query_vector:
            return {"incidents": [], "limitations": ["Supply attack terms, event types or technique IDs to search past incidents."]}
        documents = [summary_document(item) for item in self.source()]
        current_ids = {item["document"]["incident_id"] for item in documents}
        self.store.sync(documents)
        matches = []
        for item in self.store.list_items():
            document = item["document"]
            if document["incident_id"] == exclude_incident_id or document["incident_id"] not in current_ids:
                continue
            similarity = sum(weight * item["vector"].get(term, 0) for term, weight in query_vector.items())
            if similarity > 0:
                matches.append({**document, "similarity": round(similarity, 6), "historical_reference": True})
        matches.sort(key=lambda item: (-item["similarity"], item["incident_id"]))
        return {"incidents": matches[:limit], "matching_count": len(matches),
            "retrieval_method": "local lexical vector cosine", "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "limitations": ["Similarity measures shared recorded terms, not shared cause or proof of the same attack.",
                "Local lexical embeddings do not infer synonyms or semantic equivalence. Historical records are context, not evidence for the current incident.",
                f"Showing at most {limit} incident summaries from the available stored incidents."]}
