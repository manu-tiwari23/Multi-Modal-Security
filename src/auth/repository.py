"""Atomic account/session operations. The memory backend is for explicit tests."""

from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
import re
from threading import RLock

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json, RealDictCursor

from .models import AuthError, AuthStoreUnavailable


class MemoryAuthRepository:
    def __init__(self):
        self.users, self.sessions, self.attempts, self.audit = {}, {}, {}, []
        self.lock = RLock()

    def add_user(self, user, actor):
        with self.lock:
            if user["username"] in self.users:
                raise AuthError("Account already exists", 409)
            self.users[user["username"]] = deepcopy(user)
            self.audit.append({"actor": actor, "action": "account_created", "target": user["username"]})

    def get_user(self, username):
        with self.lock:
            return deepcopy(self.users.get(username))

    def list_users(self):
        with self.lock:
            return [{k: v for k, v in u.items() if k != "password_hash"} for u in self.users.values()]

    def change_user(self, username, changes, actor):
        with self.lock:
            user = self.users.get(username)
            if not user:
                raise AuthError("Account not found", 404)
            updated = {**user, **changes}
            if user["role"] == "admin" and not user["disabled"] and (updated["disabled"] or updated["role"] != "admin"):
                if sum(u["role"] == "admin" and not u["disabled"] for u in self.users.values()) <= 1:
                    raise AuthError("Keep at least one enabled administrator", 409)
            self.users[username] = updated
            for session in self.sessions.values():
                if session["username"] == username:
                    session["revoked"] = True
            self.audit.append({"actor": actor, "action": "account_updated", "target": username})

    def consume_attempt(self, key, now, window, limit):
        with self.lock:
            self.attempts = {k: v for k, v in self.attempts.items() if v[0] > now}
            until, count = self.attempts.get(key, (now + timedelta(seconds=window), 0))
            self.attempts[key] = (until, count + 1)
            return count < limit

    def create_session(self, session, expected_password):
        with self.lock:
            user = self.users.get(session["username"])
            if not user or user["disabled"] or user["password_hash"] != expected_password:
                raise AuthError("Invalid username or password")
            self.sessions = {k: v for k, v in self.sessions.items() if v["expires_at"] > session["last_seen"] and not v["revoked"]}
            self.sessions[session["token_hash"]] = deepcopy(session)
            self.audit.append({"actor": user["username"], "action": "login"})

    def resolve_session(self, token_hash, now, idle_seconds, touch):
        with self.lock:
            session = self.sessions.get(token_hash)
            if not session or session["revoked"] or session["expires_at"] <= now or session["last_seen"] <= now - timedelta(seconds=idle_seconds):
                return None
            user = self.users.get(session["username"])
            if not user or user["disabled"]:
                return None
            if touch:
                session["last_seen"] = now
            return {"username": user["username"], "role": user["role"], "expires_at": session["expires_at"], "session_hash": token_hash}

    def revoke_session(self, token_hash, actor):
        with self.lock:
            if token_hash in self.sessions:
                self.sessions[token_hash]["revoked"] = True
            self.audit.append({"actor": actor, "action": "logout"})

    def failed_login(self, username):
        with self.lock:
            self.audit.append({"actor": username, "action": "login_failed"})


class PostgresAuthRepository:
    def __init__(self, dsn, schema="public", timeout=5):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Invalid authentication schema")
        self.dsn, self.schema, self.timeout = dsn, schema, timeout
        self._initialize()

    def table(self, name):
        return sql.Identifier(self.schema, name)

    @contextmanager
    def transaction(self):
        connection = None
        try:
            connection = psycopg2.connect(self.dsn, connect_timeout=self.timeout,
                options=f"-c statement_timeout={self.timeout * 1000}")
            with connection, connection.cursor(cursor_factory=RealDictCursor) as cursor:
                yield cursor
        except psycopg2.Error as exc:
            raise AuthStoreUnavailable("Authentication storage unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def _initialize(self):
        with self.transaction() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("mms-auth:" + self.schema,))
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
                disabled BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL)""").format(self.table("mms_users")))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES {}(username),
                expires_at TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE)""").format(self.table("mms_sessions"), self.table("mms_users")))
            cur.execute(sql.SQL("CREATE INDEX IF NOT EXISTS mms_session_username ON {} (username)").format(self.table("mms_sessions")))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                key TEXT PRIMARY KEY, until TIMESTAMPTZ NOT NULL, attempts INTEGER NOT NULL)""").format(self.table("mms_login_limits")))
            cur.execute(sql.SQL("""CREATE TABLE IF NOT EXISTS {} (
                sequence BIGSERIAL PRIMARY KEY, happened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                actor TEXT NOT NULL, action TEXT NOT NULL, detail JSONB NOT NULL)""").format(self.table("mms_auth_audit")))
            cur.execute(sql.SQL("""CREATE OR REPLACE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'Authentication audit is append-only'; END $$""").format(self.table("mms_auth_audit_guard")))
            cur.execute(sql.SQL("DROP TRIGGER IF EXISTS mms_auth_audit_immutable ON {}").format(self.table("mms_auth_audit")))
            cur.execute(sql.SQL("CREATE TRIGGER mms_auth_audit_immutable BEFORE UPDATE OR DELETE ON {} FOR EACH ROW EXECUTE FUNCTION {}()").format(
                self.table("mms_auth_audit"), self.table("mms_auth_audit_guard")))

    def _audit(self, cur, actor, action, detail=None):
        cur.execute(sql.SQL("INSERT INTO {} (actor, action, detail) VALUES (%s,%s,%s)").format(self.table("mms_auth_audit")),
                    (actor, action, Json(detail or {})))

    def add_user(self, user, actor):
        with self.transaction() as cur:
            cur.execute(sql.SQL("INSERT INTO {} (username,password_hash,role,disabled,created_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING username").format(self.table("mms_users")),
                        tuple(user[key] for key in ("username", "password_hash", "role", "disabled", "created_at")))
            if cur.fetchone() is None:
                raise AuthError("Account already exists", 409)
            self._audit(cur, actor, "account_created", {"username": user["username"], "role": user["role"]})

    def get_user(self, username):
        with self.transaction() as cur:
            cur.execute(sql.SQL("SELECT * FROM {} WHERE username=%s").format(self.table("mms_users")), (username,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_users(self):
        with self.transaction() as cur:
            cur.execute(sql.SQL("SELECT username,role,disabled,created_at FROM {} ORDER BY username").format(self.table("mms_users")))
            return [dict(row) for row in cur.fetchall()]

    def change_user(self, username, changes, actor):
        if not changes or set(changes) - {"password_hash", "role", "disabled"}:
            raise ValueError("Invalid account update")
        with self.transaction() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("mms-auth-users:" + self.schema,))
            cur.execute(sql.SQL("SELECT * FROM {} WHERE username=%s FOR UPDATE").format(self.table("mms_users")), (username,))
            user = cur.fetchone()
            if not user:
                raise AuthError("Account not found", 404)
            updated = {**user, **changes}
            if user["role"] == "admin" and not user["disabled"] and (updated["disabled"] or updated["role"] != "admin"):
                cur.execute(sql.SQL("SELECT COUNT(*) AS count FROM {} WHERE role='admin' AND disabled=FALSE").format(self.table("mms_users")))
                if cur.fetchone()["count"] <= 1:
                    raise AuthError("Keep at least one enabled administrator", 409)
            assignments = sql.SQL(",").join(sql.SQL("{}=%s").format(sql.Identifier(k)) for k in changes)
            cur.execute(sql.SQL("UPDATE {} SET {} WHERE username=%s").format(self.table("mms_users"), assignments), (*changes.values(), username))
            cur.execute(sql.SQL("UPDATE {} SET revoked=TRUE WHERE username=%s").format(self.table("mms_sessions")), (username,))
            self._audit(cur, actor, "account_updated", {"username": username, "fields": list(changes)})

    def consume_attempt(self, key, now, window, limit):
        until = now + timedelta(seconds=window)
        with self.transaction() as cur:
            cur.execute(sql.SQL("DELETE FROM {} WHERE until <= %s").format(self.table("mms_login_limits")), (now,))
            cur.execute(sql.SQL("""INSERT INTO {} AS limits (key,until,attempts) VALUES (%s,%s,1)
                ON CONFLICT (key) DO UPDATE SET attempts=limits.attempts+1 RETURNING attempts""").format(self.table("mms_login_limits")), (key, until))
            return cur.fetchone()["attempts"] <= limit

    def create_session(self, session, expected_password):
        with self.transaction() as cur:
            cur.execute(sql.SQL("SELECT password_hash,disabled FROM {} WHERE username=%s FOR UPDATE").format(self.table("mms_users")), (session["username"],))
            user = cur.fetchone()
            if not user or user["disabled"] or user["password_hash"] != expected_password:
                raise AuthError("Invalid username or password")
            cur.execute(sql.SQL("DELETE FROM {} WHERE expires_at<=%s OR revoked=TRUE").format(self.table("mms_sessions")), (session["last_seen"],))
            cur.execute(sql.SQL("INSERT INTO {} (token_hash,username,expires_at,last_seen) VALUES (%s,%s,%s,%s)").format(self.table("mms_sessions")),
                        tuple(session[k] for k in ("token_hash", "username", "expires_at", "last_seen")))
            self._audit(cur, session["username"], "login")

    def resolve_session(self, token_hash, now, idle_seconds, touch):
        with self.transaction() as cur:
            cur.execute(sql.SQL("""SELECT u.username,u.role,s.expires_at,s.token_hash AS session_hash
                FROM {} s JOIN {} u ON s.username=u.username
                WHERE s.token_hash=%s AND s.revoked=FALSE AND u.disabled=FALSE
                AND s.expires_at>%s AND s.last_seen>%s FOR UPDATE OF s""").format(self.table("mms_sessions"), self.table("mms_users")),
                        (token_hash, now, now - timedelta(seconds=idle_seconds)))
            row = cur.fetchone()
            if row and touch:
                cur.execute(sql.SQL("UPDATE {} SET last_seen=%s WHERE token_hash=%s").format(self.table("mms_sessions")), (now, token_hash))
            return dict(row) if row else None

    def revoke_session(self, token_hash, actor):
        with self.transaction() as cur:
            cur.execute(sql.SQL("UPDATE {} SET revoked=TRUE WHERE token_hash=%s").format(self.table("mms_sessions")), (token_hash,))
            self._audit(cur, actor, "logout")

    def failed_login(self, username):
        with self.transaction() as cur:
            self._audit(cur, username, "login_failed")
