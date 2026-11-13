"""Lazy response service; database outages never select volatile fallback."""

from functools import lru_cache

from src.shared.config import settings
from .executor import MockEDRBackend, MockFirewallBackend, MockWorkflowBackend
from .repository import MemoryResponseRepository, PostgresResponseRepository
from .service import ResponseService
from .firewall_http import HttpFirewallBackend


@lru_cache
def get_response_service():
    repository = MemoryResponseRepository() if settings.response_storage_mode == "memory" else PostgresResponseRepository(
        settings.postgres_url, settings.response_db_schema, settings.storage_timeout_seconds)
    if settings.ir_execution_mode == "firewall_http":
        if settings.response_storage_mode != "persistent":
            raise ValueError("Live firewall execution requires persistent response storage")
        backends = [HttpFirewallBackend(settings.ir_firewall_api_url, settings.ir_firewall_api_token.get_secret_value(), settings.ir_backend_timeout_seconds)]
    else:
        backends = [MockFirewallBackend(), MockEDRBackend(), MockWorkflowBackend()]
    return ResponseService(repository, backends, approval_ttl=settings.ir_approval_ttl_seconds,
                           mode=settings.ir_execution_mode)
