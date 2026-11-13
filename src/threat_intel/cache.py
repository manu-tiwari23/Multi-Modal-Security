"""Bounded expiring reputation cache with optional Postgres durability."""

from collections import OrderedDict
from datetime import datetime, timezone
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

from .models import LookupResult


class CacheUnavailable(RuntimeError):
    pass


class MemoryCache:
    def __init__(self, capacity=5000):
        self.capacity = capacity
        self._items = OrderedDict()
        self._lock = RLock()

    def get(self, key):
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if item.expires_at <= datetime.now(timezone.utc):
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return item.model_copy(deep=True)

    def put(self, key, result):
        with self._lock:
            self._items[key] = result.model_copy(deep=True)
            self._items.move_to_end(key)
            while len(self._items) > self.capacity:
                self._items.popitem(last=False)


class PostgresCache:
    def __init__(self, dsn, schema="public", capacity=5000, timeout=2):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid cache schema")
        self._dsn, self._schema = dsn, schema
        self._capacity, self._timeout = capacity, timeout
        self._ready = False
        self._lock = RLock()

    def _table(self):
        return sql.Identifier(self._schema, "mms_threat_intel_cache")

    def _connect(self):
        return psycopg2.connect(self._dsn, connect_timeout=self._timeout,
                               options=f"-c statement_timeout={self._timeout * 1000}")

    def _run(self, callback):
        connection = None
        try:
            connection = self._connect()
            with connection, connection.cursor() as cur:
                with self._lock:
                    if not self._ready:
                        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mms-threat-cache:{self._schema}",))
                        cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self._schema)))
                        cur.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (cache_key TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL, result JSONB NOT NULL)").format(self._table()))
                value = callback(cur)
            self._ready = True
            return value
        except (psycopg2.Error, ValueError, TypeError) as exc:
            raise CacheUnavailable("Threat intelligence cache is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def get(self, key):
        def query(cur):
            cur.execute(sql.SQL("SELECT result FROM {} WHERE cache_key=%s AND expires_at>NOW()").format(self._table()), (key,))
            row = cur.fetchone()
            return LookupResult.model_validate(row[0]) if row else None
        return self._run(query)

    def put(self, key, result):
        def write(cur):
            cur.execute(sql.SQL("INSERT INTO {} (cache_key, expires_at, result) VALUES (%s,%s,%s) ON CONFLICT (cache_key) DO UPDATE SET expires_at=EXCLUDED.expires_at, result=EXCLUDED.result").format(self._table()),
                        (key, result.expires_at, Json(result.model_dump(mode="json"))))
            cur.execute(sql.SQL("DELETE FROM {} WHERE expires_at<=NOW()").format(self._table()))
            cur.execute(sql.SQL("DELETE FROM {} WHERE cache_key IN (SELECT cache_key FROM {} ORDER BY expires_at DESC OFFSET %s)").format(self._table(), self._table()), (self._capacity,))
        self._run(write)
