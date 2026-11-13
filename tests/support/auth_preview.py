"""Isolated browser-QA server: synthetic accounts, memory stores, no external AI."""
import os

for key in ("OPENAI_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY"):
    os.environ[key] = " "
os.environ["AUTH_STORAGE_MODE"] = "memory"
os.environ["RESPONSE_STORAGE_MODE"] = "memory"
os.environ["INCIDENT_STORAGE_MODE"] = "memory"
os.environ["COPILOT_AUDIT_MODE"] = "memory"
os.environ["IR_EXECUTION_MODE"] = "simulation"
os.environ["FORENSICS_STORAGE_MODE"] = "memory"
os.environ["THREAT_INTEL_CACHE_MODE"] = "memory"
os.environ["AUTH_ALLOWED_ORIGINS"] = '["http://127.0.0.1:5174"]'

from contextlib import asynccontextmanager
import src.api.main as gateway
from src.auth.models import UserInput
from src.auth.runtime import get_auth_service

service = get_auth_service()
service.create_user(UserInput(username="ui-analyst", password="Synthetic UI login passphrase!", role="analyst"), "qa_setup")
service.create_user(UserInput(username="ui-viewer", password="Synthetic UI login passphrase!", role="viewer"), "qa_setup")


@asynccontextmanager
async def isolated_lifespan(app):
    yield


gateway._get_os = lambda: None
gateway.app.router.lifespan_context = isolated_lifespan
app = gateway.app
