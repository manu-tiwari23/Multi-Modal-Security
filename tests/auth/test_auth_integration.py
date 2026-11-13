from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from src.auth.models import AuthError, UserInput
from src.auth.repository import PostgresAuthRepository
from src.auth.service import AuthService
from src.shared.config import settings

pytestmark = pytest.mark.integration


@pytest.fixture
def durable_auth():
    schema = "mms_auth_test_" + uuid4().hex
    try:
        connection = psycopg2.connect(settings.postgres_url, connect_timeout=2)
        connection.close()
    except psycopg2.Error:
        pytest.skip("Live PostgreSQL required")
    repository = PostgresAuthRepository(settings.postgres_url, schema)
    yield repository, schema
    assert schema.startswith("mms_auth_test_") and len(schema) == len("mms_auth_test_") + 32
    with psycopg2.connect(settings.postgres_url) as connection, connection.cursor() as cur:
        cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
    connection.close()


def test_session_survives_service_restart_then_revokes_and_audit_is_immutable(durable_auth):
    repository, schema = durable_auth
    first = AuthService(repository)
    first.create_user(UserInput(username="persistent-analyst", password="Synthetic durable test password!"), "qa_operator")
    token, _ = first.login("persistent-analyst", "Synthetic durable test password!", "qa_client")
    second = AuthService(PostgresAuthRepository(settings.postgres_url, schema))
    principal = second.authenticate(token)
    assert principal.username == "persistent-analyst"
    second.logout(principal)
    with pytest.raises(AuthError):
        first.authenticate(token)
    with repository.transaction() as cur:
        cur.execute(sql.SQL("SELECT action FROM {} ORDER BY sequence").format(repository.table("mms_auth_audit")))
        assert [row["action"] for row in cur.fetchall()] == ["account_created", "login", "logout"]
    from src.auth.models import AuthStoreUnavailable
    with pytest.raises(AuthStoreUnavailable):
        with repository.transaction() as cur:
            cur.execute(sql.SQL("DELETE FROM {}").format(repository.table("mms_auth_audit")))


def test_login_throttle_is_atomic_across_workers(durable_auth):
    repository, schema = durable_auth
    second = PostgresAuthRepository(settings.postgres_url, schema)
    now = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=5) as pool:
        allowed = list(pool.map(lambda i: (repository if i % 2 else second).consume_attempt("shared-test-key", now, 60, 5), range(12)))
    assert sum(allowed) == 5
