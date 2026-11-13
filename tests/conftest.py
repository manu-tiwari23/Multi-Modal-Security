"""Tests are offline with respect to paid AI providers, regardless of local .env."""

import os
import sys

import pytest

# Set before test modules import the application's settings singleton. Tests of the
# OpenAI integration must inject a mocked client; real API use is a separate manual check.
os.environ["OPENAI_API_KEY"] = " "
os.environ["FORENSICS_STORAGE_MODE"] = "memory"
os.environ["THREAT_INTEL_CACHE_MODE"] = "memory"
os.environ["AUTH_STORAGE_MODE"] = "memory"
os.environ["RESPONSE_STORAGE_MODE"] = "memory"
os.environ["INCIDENT_STORAGE_MODE"] = "memory"
os.environ["COPILOT_AUDIT_MODE"] = "memory"
os.environ["IR_EXECUTION_MODE"] = "simulation"
os.environ["VT_API_KEY"] = " "
os.environ["ABUSEIPDB_API_KEY"] = " "


@pytest.fixture(autouse=True)
def isolate_unit_api_storage(request, monkeypatch):
    """Unit/API tests must not index synthetic events into a developer's live store."""
    if request.node.get_closest_marker("integration"):
        return
    api = sys.modules.get("src.api.main")
    if api is not None:
        monkeypatch.setattr(api, "_get_os", lambda: None)


@pytest.fixture(autouse=True)
def authorize_existing_api_tests(request):
    """Legacy feature checks use an explicit principal; auth tests use real sessions."""
    if request.node.get_closest_marker("authentication"):
        yield
        return
    from src.api.auth import authorize_request
    from src.auth.models import Principal
    api = sys.modules.get("src.api.main")
    old = dict(api.app.dependency_overrides) if api is not None else None
    if api is not None:
        api.app.dependency_overrides[authorize_request] = lambda: Principal(username="analyst", role="admin")
    yield
    if api is not None:
        api.app.dependency_overrides = old


@pytest.fixture
def authenticated_test_app():
    """Opt-in authenticated principal for standalone router fixtures."""
    from src.api.auth import authorize_request
    from src.auth.models import Principal
    def configure(app):
        app.dependency_overrides[authorize_request] = lambda: Principal(username="analyst", role="admin")
        return app
    return configure
