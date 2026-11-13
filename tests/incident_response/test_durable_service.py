"""Queued for the consolidated verification pass."""
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.incident_response.models import ActionResult, ActionType, ResponseAction, ResponsePlan
from src.incident_response.repository import MemoryResponseRepository
from src.incident_response.service import ResponseError, ResponseService


class CountingBackend:
    name = "synthetic-counting"
    supported_actions = [ActionType.BLOCK_IP]

    def __init__(self):
        self.calls = 0

    def execute(self, action):
        self.calls += 1
        return ActionResult(action_id=action.action_id, success=True, backend=self.name)


def setup_workflow():
    repository = MemoryResponseRepository()
    backend = CountingBackend()
    service = ResponseService(repository, [backend])
    action = ResponseAction(action_type="block_ip", title="Block synthetic address", target_entity={"ip": "192.0.2.1"})
    plan = ResponsePlan(incident_id="incident-synthetic", actions=[action])
    response = service.add_plan(plan, "analyst")
    return service, backend, action, response["approval_requests"][0]


def test_decision_and_result_survive_service_recreation():
    service, backend, action, request = setup_workflow()
    service.decide(request["request_id"], True, "analyst", "Synthetic review")
    replacement = ResponseService(service.repository, [backend])
    first = replacement.execute(action.action_id, "operator")
    assert first["result"]["success"]
    assert replacement.execute(action.action_id, "operator") == first
    assert backend.calls == 1
    audit = service.repository.audit("incident-synthetic")
    assert audit[-1]["actor"] == "operator"
    assert audit[-2]["detail"]["approved_by"] == "analyst"


def test_unapproved_and_modified_targets_do_not_execute():
    service, backend, action, request = setup_workflow()
    with pytest.raises(ResponseError, match="approval"):
        service.execute(action.action_id, "operator")
    service.decide(request["request_id"], True, "analyst")
    with service.repository.transaction("incident-synthetic") as (record, audit):
        record["actions"][action.action_id]["target_entity"] = {"ip": "192.0.2.2"}
    with pytest.raises(ResponseError, match="differs"):
        service.execute(action.action_id, "operator")
    assert backend.calls == 0


def test_claim_without_result_is_not_retried():
    service, backend, action, request = setup_workflow()
    service.decide(request["request_id"], True, "analyst")
    with service.repository.transaction("incident-synthetic") as (record, audit):
        record["claims"][action.action_id] = {"claim": "interrupted-worker"}
        record["actions"][action.action_id]["execution_status"] = "executing"
    with pytest.raises(ResponseError, match="unknown"):
        ResponseService(service.repository, [backend]).execute(action.action_id, "operator")
    assert backend.calls == 0


def test_concurrent_decisions_have_one_winner():
    service, backend, action, request = setup_workflow()
    def decide(index):
        try:
            service.decide(request["request_id"], index % 2 == 0, f"analyst{index}")
            return True
        except ResponseError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(decide, range(8))) == 1
    assert backend.calls == 0


def test_lifecycle_is_validated_and_audited():
    service, _, _, _ = setup_workflow()
    with pytest.raises(ResponseError, match="not allowed"):
        service.transition("incident-synthetic", "remediated", "analyst")
    service.transition("incident-synthetic", "investigating", "analyst", "Review evidence")
    workflow = service.workflow("incident-synthetic")
    assert workflow["state"]["phase"] == "investigating"
    assert workflow["state"]["transitions"][-1]["reason"] == "Review evidence"
