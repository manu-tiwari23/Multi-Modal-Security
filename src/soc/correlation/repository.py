"""Postgres incident snapshots and durable event deduplication."""
from contextlib import contextmanager
from datetime import timedelta
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

from .incident_model import Incident


class IncidentStoreUnavailable(RuntimeError):
    pass


class PostgresIncidentRepository:
    def __init__(self, dsn, schema="public", timeout=5):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid incident database schema")
        self.dsn, self.schema, self.timeout = dsn, schema, timeout
        self._ready = False
        self._lock = RLock()

    def table(self, name):
        return sql.Identifier(self.schema, name)

    @contextmanager
    def connection(self):
        connection = None
        try:
            connection = psycopg2.connect(self.dsn, connect_timeout=self.timeout,
                options=f"-c statement_timeout={self.timeout * 1000} -c lock_timeout={self.timeout * 1000}")
            with connection, connection.cursor() as cursor:
                with self._lock:
                    if not self._ready:
                        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-incident-schema:{self.schema}",))
                        cursor.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
                        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (incident_id TEXT PRIMARY KEY, updated_at TIMESTAMPTZ NOT NULL, snapshot JSONB NOT NULL)").format(self.table("mms_incidents")))
                        cursor.execute(sql.SQL("CREATE INDEX IF NOT EXISTS mms_incidents_updated_idx ON {}(updated_at)").format(self.table("mms_incidents")))
                        cursor.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (event_id TEXT PRIMARY KEY, incident_id TEXT REFERENCES {}(incident_id), recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").format(self.table("mms_correlated_events"), self.table("mms_incidents")))
                yield cursor
            self._ready = True
        except psycopg2.Error as exc:
            raise IncidentStoreUnavailable("Incident storage unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def correlate(self, event, window, callback):
        with self.connection() as cursor:
            # Serialize entity linking across workers; independent processes cannot create
            # two incidents from simultaneous events for the same entity.
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-correlation:{self.schema}",))
            cursor.execute(sql.SQL("SELECT incident_id FROM {} WHERE event_id=%s").format(self.table("mms_correlated_events")), (event.event_id,))
            previous = cursor.fetchone()
            if previous:
                if previous[0] is None:
                    return None
                cursor.execute(sql.SQL("SELECT snapshot FROM {} WHERE incident_id=%s").format(self.table("mms_incidents")), (previous[0],))
                return Incident.model_validate(cursor.fetchone()[0])
            delta = timedelta(seconds=window)
            cursor.execute(sql.SQL("SELECT snapshot FROM {} WHERE updated_at BETWEEN %s AND %s").format(self.table("mms_incidents")), (event.timestamp - delta, event.timestamp + delta))
            candidates = [Incident.model_validate(row[0]) for row in cursor.fetchall()]
            incident = callback(candidates)
            if incident is not None:
                cursor.execute(sql.SQL("INSERT INTO {}(incident_id,updated_at,snapshot) VALUES (%s,%s,%s) ON CONFLICT(incident_id) DO UPDATE SET updated_at=EXCLUDED.updated_at,snapshot=EXCLUDED.snapshot").format(self.table("mms_incidents")), (incident.incident_id, incident.updated_at, Json(incident.model_dump(mode="json"))))
            cursor.execute(sql.SQL("INSERT INTO {}(event_id,incident_id) VALUES (%s,%s)").format(self.table("mms_correlated_events")), (event.event_id, incident.incident_id if incident else None))
            return incident

    def get(self, incident_id):
        with self.connection() as cursor:
            cursor.execute(sql.SQL("SELECT snapshot FROM {} WHERE incident_id=%s").format(self.table("mms_incidents")), (incident_id,))
            row = cursor.fetchone()
            return Incident.model_validate(row[0]) if row else None

    def list_incidents(self):
        with self.connection() as cursor:
            cursor.execute(sql.SQL("SELECT snapshot FROM {} ORDER BY updated_at DESC").format(self.table("mms_incidents")))
            return [Incident.model_validate(row[0]) for row in cursor.fetchall()]
