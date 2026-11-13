import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.copilot.audit import MemoryCopilotAudit, audit_query, finish_query, record_tool
from src.copilot.models import CopilotQuery, CopilotResponse, ToolCallRecord


def test_provenance_retains_sources_without_raw_prompt_arguments_or_answer():
    store = MemoryCopilotAudit()
    query = CopilotQuery(prompt="Investigate secret-marker in this uploaded evidence", mode="local")
    response = CopilotResponse(query=query.prompt, answer="sensitive-answer-marker")
    with audit_query(store, "audit-one", "analyst", query):
        record_tool(ToolCallRecord(tool_name="query_logs", arguments={"query": "private-argument-marker"},
            retrieved_ids=["event-123"], result_sha256="a" * 64))
        finish_query(store, "audit-one", "analyst", response)
    entries = store.read("audit-one")
    assert [entry["kind"] for entry in entries] == ["query_started", "tool_retrieval", "query_completed"]
    assert entries[1]["detail"]["source_ids"] == ["event-123"]
    assert entries[1]["detail"]["output_sha256"] == "a" * 64
    assert response.audit_id == "audit-one"
    serialized = json.dumps(entries)
    for secret in ("secret-marker", "sensitive-answer-marker", "private-argument-marker"):
        assert secret not in serialized


def test_concurrent_queries_keep_actor_and_tool_records_separate():
    store = MemoryCopilotAudit()
    def query(index):
        with audit_query(store, f"audit-{index}", f"analyst-{index}", CopilotQuery(prompt="Review events")):
            record_tool(ToolCallRecord(tool_name="query_logs", retrieved_ids=[f"event-{index}"]))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(query, range(10)))
    for index in range(10):
        entries = store.read(f"audit-{index}")
        assert len(entries) == 2
        assert all(entry["actor"] == f"analyst-{index}" for entry in entries)
        assert entries[1]["detail"]["source_ids"] == [f"event-{index}"]


def test_failed_query_records_exception_type_without_exception_content():
    store = MemoryCopilotAudit()
    with pytest.raises(ValueError):
        with audit_query(store, "failed", "analyst", CopilotQuery(prompt="Review events")):
            raise ValueError("private-error-marker")
    entries = store.read("failed")
    assert entries[-1]["kind"] == "query_failed"
    assert entries[-1]["detail"] == {"error_type": "ValueError"}
    record_tool(ToolCallRecord(tool_name="query_logs"))
    assert len(store.read("failed")) == 2
