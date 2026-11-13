import base64
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import src.api.auth as auth_api
import src.api.main as api
from src.api.auth import COOKIE_NAME
from src.auth.models import AuthStoreUnavailable, UserInput
from src.auth.repository import MemoryAuthRepository
from src.auth.service import AuthService
from src.forensics.evidence_vault import EvidenceVault
import src.forensics.runtime as forensic_runtime
from src.shared.event_schema import Entity
from src.soc.correlation.incident_model import Incident

pytestmark = pytest.mark.authentication
PASSWORD = "Synthetic login passphrase 2026!"
ORIGIN = "http://localhost:5173"


@pytest.fixture
def context(monkeypatch):
    service = AuthService(MemoryAuthRepository())
    for name, role in (("alice", "analyst"), ("reader", "viewer"), ("admin", "admin")):
        service.create_user(UserInput(username=name, password=PASSWORD, role=role), "local_operator")
    monkeypatch.setattr(auth_api, "get_auth_service", lambda: service)
    monkeypatch.setattr(api, "get_auth_service", lambda: service)
    monkeypatch.setattr(api, "_get_os", lambda: None)
    old_overrides = dict(api.app.dependency_overrides)
    api.app.dependency_overrides.clear()
    client = TestClient(api.app)
    yield client, service
    client.close()
    api.app.dependency_overrides = old_overrides


def login(client, name="alice"):
    response = client.post("/api/auth/login", json={"username": name, "password": PASSWORD}, headers={"Origin": ORIGIN})
    assert response.status_code == 200, response.text
    client.headers.update({"Origin": ORIGIN, "X-MMS-CSRF": response.json()["csrf_token"]})
    return response


@pytest.mark.parametrize("method,path", [("get", "/api/events"), ("get", "/api/ir/approvals"),
    ("post", "/api/copilot/chat"), ("post", "/api/ir/execute/missing"),
    ("get", "/api/forensics/evidence"), ("get", "/api/reports/threats"),
    ("get", "/api/auth/users")])
def test_protected_routes_require_login_before_data_or_validation(context, method, path):
    client, _ = context
    assert getattr(client, method)(path).status_code == 401


def test_cookie_session_csrf_origin_and_logout(context):
    client, service = context
    response = login(client)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    token = client.cookies.get(COOKIE_NAME)
    assert token not in response.text and token not in str(service.repository.sessions)
    assert client.get("/api/auth/session").json()["user"]["username"] == "alice"
    assert client.post("/api/copilot/chat", json={"prompt": "hello", "mode": "local"}, headers={"X-MMS-CSRF": "wrong"}).status_code == 403
    assert client.post("/api/copilot/chat", json={"prompt": "hello", "mode": "local"}, headers=[(b"X-MMS-CSRF", b"\xff"), (b"Origin", ORIGIN.encode())]).status_code == 403
    assert client.post("/api/copilot/chat", json={"prompt": "hello", "mode": "local"}, headers={"Origin": "https://evil.invalid"}).status_code == 403
    assert client.post("/api/copilot/chat", json={"prompt": "hello", "mode": "local"}).status_code == 200
    assert client.post("/api/auth/logout").status_code == 204
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/api/events").status_code == 401


def test_viewer_can_read_but_cannot_mutate_or_administer(context):
    client, _ = context
    login(client, "reader")
    assert client.get("/api/events").status_code == 200
    assert client.post("/api/ir/approvals/missing/approve", json={"reason": "x"}).status_code == 403
    assert client.post("/api/simulate/attack", json={}).status_code == 403
    assert client.get("/api/auth/users").status_code == 403
    assert client.post("/api/auth/logout").status_code == 204


def test_approval_and_transition_are_bound_to_real_analyst(context):
    client, _ = context
    login(client)
    incident = Incident(incident_id="auth-" + uuid4().hex, title="Synthetic auth test", severity="high",
        risk_score=80, primary_entity=Entity(ip="203.0.113.7"), mitre_techniques=["T1110"], tags=["brute_force"])
    api.correlation_engine._incidents[incident.incident_id] = incident
    result = client.post(f"/api/ir/recommend/{incident.incident_id}")
    assert result.status_code == 200
    approval = result.json()["approval_requests"][0]
    path = f"/api/ir/approvals/{approval['request_id']}/approve"
    assert client.post(path, json={"analyst_id": "mallory", "reason": "spoof"}).status_code == 403
    assert client.post(f"/api/ir/execute/{approval['action_id']}").status_code == 403
    decision = client.post(path, json={"reason": "Reviewed synthetic evidence"})
    assert decision.status_code == 200
    assert decision.json()["decision"]["decided_by"] == "alice"
    transition = f"/api/ir/incidents/{incident.incident_id}/transition"
    assert client.post(transition, json={"to_phase": "investigating", "actor": "mallory"}).status_code == 403
    assert client.post(transition, json={"to_phase": "investigating"}).json()["transition"]["transitioned_by"] == "alice"


def test_forged_incident_override_cannot_generate_response_actions(context):
    client, _ = context
    login(client)
    response = client.post("/api/ir/recommend/does-not-exist", json={"incident_id": "fake", "title": "Fake", "severity": "critical"})
    assert response.status_code == 404


def test_forensic_custody_uses_session_identity(context, monkeypatch):
    client, _ = context
    login(client)
    # The router's lazy provider resolves the cached runtime vault in memory during tests.
    monkeypatch.setattr(forensic_runtime, "_vault", EvidenceVault())
    body = {"filename": "auth-test.log", "case_id": "auth-" + uuid4().hex,
            "content_base64": base64.b64encode(b"synthetic auth evidence").decode()}
    assert client.post("/api/forensics/evidence", json={**body, "acquired_by": "mallory"}).status_code == 403
    created = client.post("/api/forensics/evidence", json=body)
    assert created.status_code == 201, created.text
    item = created.json()
    assert item["acquired_by"] == "alice"
    result = client.post(f"/api/forensics/evidence/{item['evidence_id']}/analyze")
    assert result.status_code == 200
    assert {entry["actor"] for entry in result.json()["evidence"]["custody_history"]} == {"alice"}


def test_admin_management_revokes_sessions_and_protects_last_admin(context):
    client, service = context
    token, _ = service.login("alice", PASSWORD, "other-browser")
    login(client, "admin")
    assert client.patch("/api/auth/users/admin", json={"disabled": True}).status_code == 409
    assert client.patch("/api/auth/users/alice", json={"disabled": True}).status_code == 204
    from src.auth.models import AuthError
    with pytest.raises(AuthError):
        service.authenticate(token)
    users = client.get("/api/auth/users").json()
    assert "password_hash" not in str(users)


def test_websocket_requires_session_and_allowed_origin_and_revokes(context):
    client, service = context
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/events/live", headers={"Origin": ORIGIN}):
            pass
    login(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/events/live", headers={"Origin": "https://evil.invalid"}):
            pass
    with client.websocket_connect("/api/events/live", headers={"Origin": ORIGIN}) as socket:
        principal = service.authenticate(client.cookies.get(COOKIE_NAME))
        service.logout(principal)
        socket.send_text("ping")
        with pytest.raises(WebSocketDisconnect) as error:
            socket.receive_text()
        assert error.value.code == 1008


def test_auth_storage_outage_fails_closed_without_secret_details(context, monkeypatch):
    client, _ = context
    login(client)
    def failed():
        raise AuthStoreUnavailable("postgres://private-credential")
    monkeypatch.setattr(auth_api, "get_auth_service", failed)
    response = client.get("/api/events")
    assert response.status_code == 503
    assert "private-credential" not in response.text
