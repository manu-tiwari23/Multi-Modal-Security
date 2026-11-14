"""Transactional response records and append-only analyst audit storage."""

from contextlib import contextmanager
from copy import deepcopy
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json


class ResponseStoreUnavailable(RuntimeError):
    pass


def empty_record(incident_id):
    return {"incident_id": incident_id, "state": None, "plans": {}, "actions": {},
            "approvals": {}, "results": {}, "claims": {}}


class MemoryResponseRepository:
    mode = "memory"

    def __init__(self):
        self._records = {}
        self._audit = []
        self._lock = RLock()

    @contextmanager
    def transaction(self, incident_id):
        with self._lock:
            record = deepcopy(self._records.get(incident_id, empty_record(incident_id)))
            audit = []
            yield record, audit
            self._records[incident_id] = deepcopy(record)
            self._audit.extend(deepcopy(audit))

    def get(self, incident_id):
        with self._lock:
            return deepcopy(self._records.get(incident_id))

    def list_records(self):
        with self._lock:
            return deepcopy(list(self._records.values()))

    def find_owner(self, reference):
        with self._lock:
            for incident_id, record in self._records.items():
                if reference in record["actions"] or reference in record["approvals"]:
                    return incident_id
        return None

    def audit(self, incident_id):
        with self._lock:
            return deepcopy([entry for entry in self._audit if entry["incident_id"] == incident_id])


class PostgresResponseRepository:
    mode = "persistent"

    def __init__(self, dsn, schema="public", timeout=5):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid response database schema")
        self._dsn, self._schema, self._timeout = dsn, schema, timeout
        self._ready = False
        self._lock = RLock()

    def table(self, name):
        return sql.Identifier(self._schema, name)

    @contextmanager
    def _connection(self):
        connection = None
        try:
            connection = psycopg2.connect(self._dsn, connect_timeout=self._timeout,
                options=f"-c statement_timeout={self._timeout * 1000} -c lock_timeout={self._timeout * 1000}")
            with connection, connection.cursor() as cursor:
                with self._lock:
                    if not self._ready:
                        self._initialize(cursor)
                        connection.commit()
                        self._ready = True
                yield cursor
            self._ready = True
        except psycopg2.Error as exc:
            raise ResponseStoreUnavailable("Response storage unavailable; no action was acknowledged") from exc
        finally:
            if connection is not None:
                connection.close()

    def _initialize(self, cursor):
        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-response-schema:{self._schema}",))
        cursor.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self._schema)))
        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (incident_id TEXT PRIMARY KEY, record JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").format(self.table("mms_response_records")))
        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (reference TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES {}(incident_id))").format(self.table("mms_response_refs"), self.table("mms_response_records")))
        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (sequence BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL, entry JSONB NOT NULL, recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").format(self.table("mms_response_audit")))
        cursor.execute(sql.SQL("""CREATE OR REPLACE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Response audit is append-only'; END; $$""").format(self.table("mms_response_audit_immutable")))
        cursor.execute(sql.SQL("DROP TRIGGER IF EXISTS immutable_audit ON {}").format(self.table("mms_response_audit")))
        cursor.execute(sql.SQL("CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON {} FOR EACH STATEMENT EXECUTE FUNCTION {}()").format(self.table("mms_response_audit"), self.table("mms_response_audit_immutable")))

    @contextmanager
    def transaction(self, incident_id):
        with self._connection() as cursor:
            cursor.execute(sql.SQL("INSERT INTO {}(incident_id,record) VALUES (%s,%s) ON CONFLICT DO NOTHING").format(self.table("mms_response_records")), (incident_id, Json(empty_record(incident_id))))
            cursor.execute(sql.SQL("SELECT record FROM {} WHERE incident_id=%s FOR UPDATE").format(self.table("mms_response_records")), (incident_id,))
            record = cursor.fetchone()[0]
            audit = []
            yield record, audit
            cursor.execute(sql.SQL("UPDATE {} SET record=%s,updated_at=NOW() WHERE incident_id=%s").format(self.table("mms_response_records")), (Json(record), incident_id))
            for reference in (*record["actions"], *record["approvals"]):
                cursor.execute(sql.SQL("INSERT INTO {}(reference,incident_id) VALUES (%s,%s) ON CONFLICT DO NOTHING").format(self.table("mms_response_refs")), (reference, incident_id))
            for entry in audit:
                cursor.execute(sql.SQL("INSERT INTO {}(incident_id,entry) VALUES (%s,%s)").format(self.table("mms_response_audit")), (incident_id, Json(entry)))

    def get(self, incident_id):
        with self._connection() as cursor:
            cursor.execute(sql.SQL("SELECT record FROM {} WHERE incident_id=%s").format(self.table("mms_response_records")), (incident_id,))
            row = cursor.fetchone()
            return row[0] if row else None

    def list_records(self):
        with self._connection() as cursor:
            cursor.execute(sql.SQL("SELECT record FROM {} ORDER BY updated_at DESC").format(self.table("mms_response_records")))
            return [row[0] for row in cursor.fetchall()]

    def find_owner(self, reference):
        with self._connection() as cursor:
            cursor.execute(sql.SQL("SELECT incident_id FROM {} WHERE reference=%s").format(self.table("mms_response_refs")), (reference,))
            row = cursor.fetchone()
            return row[0] if row else None

    def audit(self, incident_id):
        with self._connection() as cursor:
            cursor.execute(sql.SQL("SELECT entry FROM {} WHERE incident_id=%s ORDER BY sequence").format(self.table("mms_response_audit")), (incident_id,))
            return [row[0] for row in cursor.fetchall()]
