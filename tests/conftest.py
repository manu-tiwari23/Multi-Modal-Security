"""Tests are offline with respect to paid AI providers, regardless of local .env."""

import os
import sys

import pytest

# Set before test modules import the application's settings singleton. Tests of the
# OpenAI integration must inject a mocked client; real API use is a separate manual check.
os.environ["OPENAI_API_KEY"] = " "
os.environ["FORENSICS_STORAGE_MODE"] = "memory"


@pytest.fixture(autouse=True)
def isolate_unit_api_storage(request, monkeypatch):
    """Unit/API tests must not index synthetic events into a developer's live store."""
    if request.node.get_closest_marker("integration"):
        return
    api = sys.modules.get("src.api.main")
    if api is not None:
        monkeypatch.setattr(api, "_get_os", lambda: None)
