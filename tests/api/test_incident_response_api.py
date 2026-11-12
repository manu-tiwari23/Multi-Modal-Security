"""
API tests for Phase 7 Incident Response endpoints using FastAPI TestClient.
"""

from fastapi.testclient import TestClient

from src.api.main import app, correlation_engine
from src.shared.event_schema import Entity
from src.soc.correlation.incident_model import Incident, IncidentTimelineEntry

client = TestClient(app)


def test_api_ir_full_workflow_with_approval_gate():
    inc_id = "inc-api-ir-001"
    incident = Incident(
        incident_id=inc_id,
        title="SSH Brute Force from 203.0.113.88",
        severity="high",
        risk_score=75.0,
        primary_entity=Entity(ip="203.0.113.88", user="admin"),
        mitre_techniques=["T1110"],
        tags=["brute_force"],
        timeline=[
            IncidentTimelineEntry(
                event_id="evt-api-1",
                event_type="auth_failure",
                source="soc",
                severity="high",
                description="SSH brute force",
                entity=Entity(ip="203.0.113.88", user="admin"),
            )
        ],
    )
    correlation_engine._incidents[inc_id] = incident

    # 1. Recommend plan & generate approval requests
    res = client.post(f"/api/ir/recommend/{inc_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["plan"]["incident_id"] == inc_id
    assert len(data["approval_requests"]) >= 1

    block_req = next(
        r for r in data["approval_requests"] if r["action_type"] == "block_ip"
    )
    action_id = block_req["action_id"]
    request_id = block_req["request_id"]

    # 2. Attempting execution before approval MUST return 403 Forbidden
    exec_unapproved = client.post(f"/api/ir/execute/{action_id}")
    assert exec_unapproved.status_code == 403

    # 3. Attempting approval as "copilot" MUST return 400
    bad_approve = client.post(
        f"/api/ir/approvals/{request_id}/approve",
        json={"analyst_id": "copilot", "reason": "auto"},
    )
    assert bad_approve.status_code == 400

    # 4. Analyst approves
    approve_res = client.post(
        f"/api/ir/approvals/{request_id}/approve",
        json={"analyst_id": "alice@soc", "reason": "Confirmed brute force"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["decision"]["status"] == "approved"

    # 5. Transition incident state: new -> investigating -> containing
    t1 = client.post(
        f"/api/ir/incidents/{inc_id}/transition",
        json={"to_phase": "investigating", "actor": "alice@soc", "reason": "Triage"},
    )
    assert t1.status_code == 200
    t2 = client.post(
        f"/api/ir/incidents/{inc_id}/transition",
        json={"to_phase": "containing", "actor": "alice@soc", "reason": "Blocking IP"},
    )
    assert t2.status_code == 200

    # 6. Execute approved action
    exec_res = client.post(f"/api/ir/execute/{action_id}")
    assert exec_res.status_code == 200
    assert exec_res.json()["result"]["success"] is True
    assert exec_res.json()["action_status"] == "completed"

    # 7. Transition to contained & check state + stats
    t3 = client.post(
        f"/api/ir/incidents/{inc_id}/transition",
        json={"to_phase": "contained", "actor": "alice@soc", "reason": "IP blocked"},
    )
    assert t3.status_code == 200

    state_res = client.get(f"/api/ir/incidents/{inc_id}/state")
    assert state_res.status_code == 200
    state_data = state_res.json()
    assert state_data["phase"] == "contained"
    assert action_id in state_data["executed_action_ids"]
    assert len(state_data["transitions"]) == 4

    stats_res = client.get("/api/ir/stats")
    assert stats_res.status_code == 200
    assert "203.0.113.88" in stats_res.json()["blocked_ips"]


def test_api_ir_reject_blocks_execution():
    inc_id = "inc-api-ir-002"
    incident = Incident(
        incident_id=inc_id,
        title="Reconnaissance scan",
        severity="low",
        risk_score=15.0,
        primary_entity=Entity(ip="198.51.100.44"),
        mitre_techniques=["T1046"],
        tags=["port_scan"],
    )
    correlation_engine._incidents[inc_id] = incident

    res = client.post(f"/api/ir/recommend/{inc_id}")
    assert res.status_code == 200
    req = res.json()["approval_requests"][0]

    rej = client.post(
        f"/api/ir/approvals/{req['request_id']}/reject",
        json={"analyst_id": "bob@soc", "reason": "Authorized internal scanner"},
    )
    assert rej.status_code == 200
    assert rej.json()["request"]["status"] == "rejected"

    exec_res = client.post(f"/api/ir/execute/{req['action_id']}")
    assert exec_res.status_code == 403

