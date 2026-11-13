import json

import httpx
import pytest

from src.incident_response.firewall_http import HttpFirewallBackend
from src.incident_response.models import ResponseAction, ResponsePlan
from src.incident_response.repository import MemoryResponseRepository
from src.incident_response.service import ResponseError, ResponseService


def test_mock_transport_contract_and_required_approval():
    received = []
    def handler(request):
        received.append(request)
        body = json.loads(request.content)
        assert request.headers["authorization"] == "Bearer synthetic-token"
        assert request.headers["idempotency-key"] == body["action_id"]
        return httpx.Response(200, json={**body, "status": "applied"})
    backend = HttpFirewallBackend("https://firewall.test/actions", "synthetic-token", transport=httpx.MockTransport(handler))
    service = ResponseService(MemoryResponseRepository(), [backend], mode="firewall_http")
    action = ResponseAction(action_type="block_ip", title="Synthetic block", target_entity={"ip": "192.0.2.1"})
    result = service.add_plan(ResponsePlan(incident_id="synthetic", actions=[action]), "analyst")
    with pytest.raises(ResponseError):
        service.execute(action.action_id, "operator")
    assert received == []
    service.decide(result["approval_requests"][0]["request_id"], True, "analyst")
    assert service.execute(action.action_id, "operator")["result"]["success"]
    service.execute(action.action_id, "operator")
    assert len(received) == 1


def test_redirect_is_not_followed_and_wrong_target_is_rejected():
    action = ResponseAction(action_type="block_ip", title="Synthetic", target_entity={"ip": "192.0.2.1"})
    calls = []
    def redirect(request):
        calls.append(request)
        return httpx.Response(307, headers={"location": "https://other.test/"})
    backend = HttpFirewallBackend("https://firewall.test/actions", "synthetic", transport=httpx.MockTransport(redirect))
    assert not backend.execute(action).success
    assert len(calls) == 1
    backend.transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"action_id": action.action_id, "action_type": "block_ip", "status": "applied", "ip": "192.0.2.2"}))
    with pytest.raises(ValueError, match="does not match"):
        backend.execute(action)


def test_changed_endpoint_cannot_reuse_approval():
    repository = MemoryResponseRepository()
    backend = HttpFirewallBackend("https://first.test/actions", "synthetic")
    service = ResponseService(repository, [backend], mode="firewall_http")
    action = ResponseAction(action_type="block_ip", title="Synthetic", target_entity={"ip": "192.0.2.1"})
    request = service.add_plan(ResponsePlan(incident_id="synthetic", actions=[action]), "analyst")["approval_requests"][0]
    service.decide(request["request_id"], True, "analyst")
    changed = ResponseService(repository, [HttpFirewallBackend("https://second.test/actions", "synthetic")], mode="firewall_http")
    with pytest.raises(ResponseError, match="configuration"):
        changed.execute(action.action_id, "operator")
