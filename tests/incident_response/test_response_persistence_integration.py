"""Live Postgres checks queued for the consolidated verification pass."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import sys
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from src.incident_response.executor import MockFirewallBackend
from src.incident_response.models import ResponseAction, ResponsePlan
from src.incident_response.repository import PostgresResponseRepository, ResponseStoreUnavailable
from src.incident_response.service import ResponseError, ResponseService
from src.shared.config import settings

pytestmark = pytest.mark.integration


@pytest.fixture
def durable_response():
    schema = "mms_response_test_" + uuid4().hex
    repository = PostgresResponseRepository(settings.postgres_url, schema)
    # Availability failures should fail the completion gate rather than silently skip it.
    repository.list_records()
    try:
        yield repository, schema
    finally:
        assert schema.startswith("mms_response_test_") and len(schema) == 50
        connection = psycopg2.connect(settings.postgres_url, connect_timeout=5)
        try:
            with connection, connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        finally:
            connection.close()


def create_workflow(repository):
    service = ResponseService(repository, [MockFirewallBackend()])
    action = ResponseAction(action_type="block_ip", title="Synthetic block", target_entity={"ip": "192.0.2.10"})
    plan = ResponsePlan(incident_id="persistent-incident", actions=[action])
    request = service.add_plan(plan, "analyst")["approval_requests"][0]
    return service, action, request


def test_fresh_process_reads_committed_workflow_and_result(durable_response):
    repository, schema = durable_response
    service, action, request = create_workflow(repository)
    service.decide(request["request_id"], True, "analyst", "Synthetic review")
    service.execute(action.action_id, "operator")
    code = """
import json, os
from src.incident_response.repository import PostgresResponseRepository
repo = PostgresResponseRepository(os.environ['MMS_TEST_RESPONSE_DSN'], os.environ['MMS_TEST_RESPONSE_SCHEMA'])
record = repo.get('persistent-incident')
print(json.dumps({'state': record['state'], 'results': record['results'], 'audit': repo.audit('persistent-incident')}))
"""
    environment = dict(os.environ, MMS_TEST_RESPONSE_DSN=settings.postgres_url, MMS_TEST_RESPONSE_SCHEMA=schema)
    result = subprocess.run([sys.executable, "-c", code], env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, "Fresh process could not read committed response records"
    recovered = json.loads(result.stdout)
    assert recovered["results"][action.action_id]["success"]
    assert recovered["state"]["executed_action_ids"] == [action.action_id]
    assert recovered["audit"][-1]["actor"] == "operator"


def test_workers_execute_once_and_audit_rejects_rewrites(durable_response):
    repository, schema = durable_response
    service, action, request = create_workflow(repository)
    service.decide(request["request_id"], True, "analyst")
    backends = [MockFirewallBackend(), MockFirewallBackend()]
    workers = [ResponseService(PostgresResponseRepository(settings.postgres_url, schema), [backend]) for backend in backends]
    def execute(index):
        try:
            return workers[index % 2].execute(action.action_id, f"operator{index}")
        except ResponseError as exc:
            assert exc.status == 409
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(execute, range(6)))
    assert any(result and result["result"]["success"] for result in results)
    audit = repository.audit("persistent-incident")
    assert sum(entry["event"] == "execution_claimed" for entry in audit) == 1
    assert sum(entry["event"] == "execution_completed" for entry in audit) == 1
    assert sum("192.0.2.10" in backend.blocked_ips for backend in backends) == 1
    with pytest.raises(ResponseStoreUnavailable):
        with repository._connection() as cursor:
            cursor.execute(sql.SQL("DELETE FROM {}").format(repository.table("mms_response_audit")))
