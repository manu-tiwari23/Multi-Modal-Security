"""Append-only query provenance. Raw prompts, evidence and secrets are not retained."""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

from src.shared.config import settings

_active_audit = ContextVar("copilot_active_audit", default=None)


class CopilotAuditUnavailable(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


class MemoryCopilotAudit:
    def __init__(self):
        self.entries = []
        self.lock = RLock()

    def append(self, audit_id, actor, kind, detail):
        with self.lock:
            self.entries.append({"audit_id": audit_id, "actor": actor, "kind": kind,
                "recorded_at": datetime.now(timezone.utc).isoformat(), "detail": deepcopy(detail)})

    def read(self, audit_id):
        with self.lock:
            return deepcopy([entry for entry in self.entries if entry["audit_id"] == audit_id])


class PostgresCopilotAudit:
    def __init__(self, dsn, schema="public", timeout=5):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid Copilot audit schema")
        self.dsn, self.schema, self.timeout = dsn, schema, timeout
        self.ready = False
        self.lock = RLock()

    def table(self, name):
        return sql.Identifier(self.schema, name)

    @contextmanager
    def connection(self):
        connection = None
        try:
            connection = psycopg2.connect(self.dsn, connect_timeout=self.timeout,
                options=f"-c statement_timeout={self.timeout * 1000}")
            with connection, connection.cursor() as cursor:
                with self.lock:
                    if not self.ready:
                        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-copilot-audit:{self.schema}",))
                        cursor.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
                        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (sequence BIGSERIAL PRIMARY KEY, audit_id TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL, detail JSONB NOT NULL, recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").format(self.table("mms_copilot_audit")))
                        cursor.execute(sql.SQL("CREATE INDEX IF NOT EXISTS mms_copilot_audit_id_idx ON {}(audit_id)").format(self.table("mms_copilot_audit")))
                        cursor.execute(sql.SQL("CREATE OR REPLACE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Copilot audit is append-only'; END; $$").format(self.table("mms_copilot_audit_immutable")))
                        cursor.execute(sql.SQL("DROP TRIGGER IF EXISTS immutable_audit ON {}").format(self.table("mms_copilot_audit")))
                        cursor.execute(sql.SQL("CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON {} FOR EACH STATEMENT EXECUTE FUNCTION {}()").format(self.table("mms_copilot_audit"), self.table("mms_copilot_audit_immutable")))
                yield cursor
            self.ready = True
        except psycopg2.Error as exc:
            raise CopilotAuditUnavailable("Copilot audit storage unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def append(self, audit_id, actor, kind, detail):
        with self.connection() as cursor:
            cursor.execute(sql.SQL("INSERT INTO {}(audit_id,actor,kind,detail) VALUES (%s,%s,%s,%s)").format(self.table("mms_copilot_audit")), (audit_id, actor, kind, Json(detail)))

    def read(self, audit_id):
        with self.connection() as cursor:
            cursor.execute(sql.SQL("SELECT audit_id,actor,kind,detail,recorded_at FROM {} WHERE audit_id=%s ORDER BY sequence").format(self.table("mms_copilot_audit")), (audit_id,))
            return [{"audit_id": row[0], "actor": row[1], "kind": row[2], "detail": row[3], "recorded_at": row[4].isoformat()} for row in cursor.fetchall()]


@lru_cache
def get_copilot_audit():
    if settings.copilot_audit_mode == "memory":
        return MemoryCopilotAudit()
    return PostgresCopilotAudit(settings.postgres_url, settings.copilot_audit_db_schema, settings.storage_timeout_seconds)


@contextmanager
def audit_query(store, audit_id, actor, query):
    store.append(audit_id, actor, "query_started", {"query_sha256": digest(query.model_dump(mode="json")),
        "incident_id": query.incident_id, "mode": query.mode, "history_count": len(query.history)})
    token = _active_audit.set((store, audit_id, actor))
    try:
        yield
    except Exception as exc:
        store.append(audit_id, actor, "query_failed", {"error_type": type(exc).__name__})
        raise
    finally:
        _active_audit.reset(token)


def record_tool(record):
    context = _active_audit.get()
    if context is None:
        return
    store, audit_id, actor = context
    store.append(audit_id, actor, "tool_retrieval", {"tool": record.tool_name,
        "arguments_sha256": digest(record.arguments), "source_ids": record.retrieved_ids,
        "output_sha256": record.result_sha256, "success": record.success,
        "timestamp": record.timestamp.isoformat()})


def finish_query(store, audit_id, actor, response):
    response.audit_id = audit_id
    store.append(audit_id, actor, "query_completed", {"answer_sha256": digest(response.answer),
        "response_sha256": digest(response.model_dump(mode="json")), "model": response.model,
        "usage": response.usage, "citations": [{"type": citation.type, "id": citation.id} for citation in response.citations],
        "execution_time_ms": response.execution_time_ms})
