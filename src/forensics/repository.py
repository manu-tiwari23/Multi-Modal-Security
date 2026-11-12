"""Evidence metadata repositories; raw evidence bytes never enter this store."""

from contextlib import contextmanager
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

from .models import ChainOfCustodyEntry, EvidenceMetadata


class EvidenceStoreUnavailable(RuntimeError):
    """Storage is unavailable; callers must not silently fall back to memory."""


class MemoryMetadataRepository:
    """Ephemeral repository used by isolated tests and explicit memory mode."""

    def __init__(self):
        self._records = {}
        self._lock = RLock()

    def create(self, metadata: EvidenceMetadata):
        with self._lock:
            if metadata.evidence_id in self._records:
                raise ValueError("Evidence already exists")
            self._records[metadata.evidence_id] = metadata

    def get(self, evidence_id: str) -> EvidenceMetadata:
        with self._lock:
            return self._records[evidence_id]

    def list(self, case_id=None):
        with self._lock:
            return [m for m in self._records.values() if case_id is None or m.case_id == case_id]

    def append(self, evidence_id, entry: ChainOfCustodyEntry, tampered=False):
        with self._lock:
            metadata = self._records[evidence_id]
            if entry.evidence_id != evidence_id:
                raise ValueError("Custody entry belongs to another evidence item")
            if not any(c.custody_id == entry.custody_id for c in metadata.custody_history):
                metadata.custody_history.append(entry)
            metadata.is_tampered = metadata.is_tampered or tampered
            return metadata


class PostgresMetadataRepository:
    """Immutable intake metadata and append-only custody, serialized per item.

    A separate connection/transaction per operation supports threads and multiple
    gateway processes. Row locks prevent custody updates from overwriting each
    other. Database triggers prohibit rewriting intake fields or custody records.
    """

    def __init__(self, dsn: str, schema="public", timeout_seconds=5):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid database schema name")
        self._dsn = dsn
        self._schema = schema
        self._timeout = timeout_seconds
        self._initialize()

    def table(self, name):
        return sql.Identifier(self._schema, name)

    @contextmanager
    def connection(self):
        connection = None
        try:
            connection = psycopg2.connect(self._dsn, connect_timeout=self._timeout,
                options=f"-c statement_timeout={self._timeout * 1000}")
            with connection:
                yield connection
        except psycopg2.Error as exc:
            raise EvidenceStoreUnavailable("Forensic metadata storage is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def _initialize(self):
        with self.connection() as conn, conn.cursor() as cur:
            # Serialize idempotent bootstrap across gateway workers.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-forensics:{self._schema}",))
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self._schema)))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                evidence_id TEXT PRIMARY KEY, case_id TEXT, metadata JSONB NOT NULL,
                is_tampered BOOLEAN NOT NULL DEFAULT FALSE)""").format(self.table("mms_evidence")))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                sequence BIGSERIAL PRIMARY KEY, custody_id TEXT UNIQUE NOT NULL,
                evidence_id TEXT NOT NULL REFERENCES {}(evidence_id), entry JSONB NOT NULL)""").format(
                    self.table("mms_evidence_custody"), self.table("mms_evidence")))
            cur.execute(sql.SQL("CREATE INDEX IF NOT EXISTS mms_evidence_case_idx ON {} (case_id)").format(self.table("mms_evidence")))
            cur.execute(sql.SQL("CREATE INDEX IF NOT EXISTS mms_custody_evidence_idx ON {} (evidence_id, sequence)").format(self.table("mms_evidence_custody")))
            cur.execute(sql.SQL("""CREATE OR REPLACE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'Custody records are append-only'; END $$""").format(self.table("mms_reject_custody_rewrite")))
            cur.execute(sql.SQL("""CREATE OR REPLACE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Evidence records cannot be deleted'; END IF;
                    IF NEW.metadata IS DISTINCT FROM OLD.metadata OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
                        OR NEW.case_id IS DISTINCT FROM OLD.case_id OR (OLD.is_tampered AND NOT NEW.is_tampered)
                    THEN RAISE EXCEPTION 'Evidence provenance is immutable'; END IF;
                    RETURN NEW;
                END $$""").format(self.table("mms_guard_evidence")))
            for table, trigger, function in (
                ("mms_evidence_custody", "mms_custody_immutable", "mms_reject_custody_rewrite"),
                ("mms_evidence", "mms_evidence_immutable", "mms_guard_evidence"),
            ):
                cur.execute(sql.SQL("DROP TRIGGER IF EXISTS {} ON {}").format(sql.Identifier(trigger), self.table(table)))
                cur.execute(sql.SQL("CREATE TRIGGER {} BEFORE UPDATE OR DELETE ON {} FOR EACH ROW EXECUTE FUNCTION {}()").format(
                    sql.Identifier(trigger), self.table(table), self.table(function)))

    def create(self, metadata: EvidenceMetadata):
        document = metadata.model_dump(mode="json", exclude={"custody_history", "is_tampered"})
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute(sql.SQL("INSERT INTO {} (evidence_id, case_id, metadata, is_tampered) VALUES (%s,%s,%s,%s)").format(self.table("mms_evidence")),
                        (metadata.evidence_id, metadata.case_id, Json(document), metadata.is_tampered))
            for entry in metadata.custody_history:
                self._insert_entry(cur, entry)

    def _insert_entry(self, cur, entry):
        cur.execute(sql.SQL("INSERT INTO {} (custody_id, evidence_id, entry) VALUES (%s,%s,%s) ON CONFLICT (custody_id) DO NOTHING").format(self.table("mms_evidence_custody")),
                    (entry.custody_id, entry.evidence_id, Json(entry.model_dump(mode="json"))))

    def _get(self, cur, evidence_id):
        cur.execute(sql.SQL("SELECT metadata, is_tampered FROM {} WHERE evidence_id=%s").format(self.table("mms_evidence")), (evidence_id,))
        row = cur.fetchone()
        if row is None:
            raise KeyError(evidence_id)
        cur.execute(sql.SQL("SELECT entry FROM {} WHERE evidence_id=%s ORDER BY sequence").format(self.table("mms_evidence_custody")), (evidence_id,))
        return EvidenceMetadata.model_validate({**row[0], "is_tampered": row[1], "custody_history": [r[0] for r in cur.fetchall()]})

    def get(self, evidence_id):
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            return self._get(cur, evidence_id)

    def list(self, case_id=None):
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute(sql.SQL("SELECT evidence_id FROM {} WHERE (%s IS NULL OR case_id=%s) ORDER BY evidence_id").format(self.table("mms_evidence")), (case_id, case_id))
            return [self._get(cur, evidence_id) for (evidence_id,) in cur.fetchall()]

    def append(self, evidence_id, entry: ChainOfCustodyEntry, tampered=False):
        if entry.evidence_id != evidence_id:
            raise ValueError("Custody entry belongs to another evidence item")
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT evidence_id FROM {} WHERE evidence_id=%s FOR UPDATE").format(self.table("mms_evidence")), (evidence_id,))
            if cur.fetchone() is None:
                raise KeyError(evidence_id)
            self._insert_entry(cur, entry)
            if tampered:
                cur.execute(sql.SQL("UPDATE {} SET is_tampered=TRUE WHERE evidence_id=%s").format(self.table("mms_evidence")), (evidence_id,))
            return self._get(cur, evidence_id)
