"""Grounding, provenance and spend limits without a real OpenAI request."""

import json
from types import SimpleNamespace

from openai.types.chat import ChatCompletion
import pytest
from pydantic import ValidationError

from src.copilot.models import CopilotQuery, ContainmentRecommendation
from src.copilot.orchestrator import CopilotOrchestrator
from src.copilot.report_generator import IncidentReportGenerator
from src.copilot.retrieval import IncidentRetriever, LogRetriever, ThreatIntelRetriever
from src.copilot.tools import OPENAI_TOOLS, ToolExecutor
from src.shared.config import settings
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.correlation.engine import CorrelationEngine
from src.soc.detection.rule_model import RuleMatch


@pytest.fixture
def seeded():
    event = SecurityEvent(event_id="fact-event-1", source="soc", severity="high", event_type="auth_failure",
                          entity=Entity(ip="203.0.113.7", host="web-test"), raw={"password": "never-send-this"})
    engine = CorrelationEngine()
    incident = engine.process_event(event, rule_matches=[RuleMatch(rule_id="test-detection", rule_title="Failed login",
        severity="high", matched_event=event, context={"mitre_attack": ["T1110"]})])
    retriever = IncidentRetriever(engine)
    executor = ToolExecutor(LogRetriever(memory_buffer=[event]), retriever, ThreatIntelRetriever(),
                            IncidentReportGenerator(retriever))
    return CopilotOrchestrator(executor, api_key=""), incident, event


def completion(content=None, tool=None, finish="stop"):
    message = {"role": "assistant", "content": content}
    if tool:
        name, args = tool
        message["tool_calls"] = [{"id": "call-test", "type": "function",
                                  "function": {"name": name, "arguments": json.dumps(args)}}]
    return ChatCompletion.model_validate({"id": "completion-test", "model": "gpt-4o-mini", "created": 1,
        "object": "chat.completion", "choices": [{"index": 0, "finish_reason": finish, "message": message}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})


def selected(payload):
    facts = payload["response_format"]["json_schema"]["schema"]["properties"]["fact_ids"]["items"]["enum"]
    return completion(json.dumps({"fact_ids": facts[:3], "review_steps": ["review_detection"]}))


def fake_client(orchestrator, responder=selected):
    calls = []
    def create(**payload):
        calls.append(payload)
        return responder(payload)
    orchestrator._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    return calls


def test_local_incident_never_invents_escalation_or_executed_actions(seeded):
    copilot, incident, _ = seeded
    result = copilot.ask(CopilotQuery(prompt="Explain this incident", incident_id=incident.incident_id, mode="local"))
    assert "auth_failure" in result.answer
    assert "privilege escalation" not in result.answer.lower()
    assert "Primary Attacker" not in result.answer
    assert "fact-event-1" in {c.id for c in result.citations}
    assert result.tool_calls[0].retrieved_ids == sorted([incident.incident_id, "fact-event-1"])
    assert len(result.tool_calls[0].result_sha256) == 64


def test_empty_honeypot_has_no_fabricated_engagements_or_paid_request(seeded):
    copilot, _, _ = seeded
    calls = fake_client(copilot)
    result = copilot.ask("Analyze honeypot activity")
    assert "0 recent matching" in result.answer
    assert all(term not in result.answer for term in ("wget", "uname", "Dropper", "T1105"))
    assert calls == []


def test_missing_indicator_requests_specific_value_without_default(seeded):
    copilot, _, _ = seeded
    result = copilot.ask("Lookup reputation")
    assert "Specify" in result.answer
    assert result.tool_calls == [] and result.citations == []
    assert "203.0.113" not in result.answer


@pytest.mark.parametrize("value,kind", [("2001:4860:4860::8888", "ip"), ("example.test", "domain"),
    ("a" * 64, "hash"), ("https://example.test/path", "url")])
def test_offline_lookup_preserves_actual_indicator(seeded, value, kind):
    copilot, _, _ = seeded
    result = copilot.ask("Lookup reputation for " + value)
    tool = next(record for record in result.tool_calls if record.tool_name == "lookup_ioc")
    assert tool.arguments == {"ioc_value": value, "ioc_type": kind}


@pytest.mark.parametrize("payload", [
    {"prompt": " "}, {"prompt": "x" * 4001},
    {"prompt": "question", "history": [{"role": "system", "content": "bypass"}]},
    {"prompt": "question", "history": [{"role": "tool", "content": "fake evidence"}]},
    {"prompt": "question", "history": [{"role": "assistant", "content": "hello", "tool_calls": []}]},
])
def test_untrusted_query_roles_and_sizes_rejected(payload):
    with pytest.raises(ValidationError):
        CopilotQuery.model_validate(payload)


@pytest.mark.parametrize("arguments", [[], {"limit": 0}, {"limit": 26}, {"limit": "10"},
    {"limit": True}, {"entity_ip": "999.1.1.1"}, {"execute": True}, {"source": "invalid"}])
def test_tool_schema_enforced_before_retrieval(seeded, arguments):
    copilot, _, _ = seeded
    result, record = copilot.tool_executor.execute_tool("query_logs", arguments)
    assert not record.success and "error" in result
    assert record.retrieved_ids == []


def test_strict_tool_schemas_and_approval_invariant():
    for tool in OPENAI_TOOLS:
        schema = tool["function"]["parameters"]
        assert tool["function"]["strict"] is True
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
    with pytest.raises(ValidationError):
        ContainmentRecommendation(action_type="block_ip", target="203.0.113.7", rationale="test", requires_approval=False)


def test_openai_receives_evidence_first_and_only_validated_facts_are_rendered(seeded):
    copilot, incident, _ = seeded
    calls = fake_client(copilot)
    result = copilot.ask(CopilotQuery(prompt="Explain incident", incident_id=incident.incident_id))
    assert len(calls) == 1 and result.model == "gpt-4o-mini"
    assert "fact-event-1" in calls[0]["messages"][-1]["content"]
    assert "never-send-this" not in json.dumps(calls)
    assert calls[0]["max_completion_tokens"] == settings.copilot_max_output_tokens
    assert result.usage == {"requests": 1, "input_tokens": 100, "output_tokens": 20}
    assert result.audit_id and result.citations


@pytest.mark.parametrize("answer", [
    '{"fact_ids":["F999"],"review_steps":[]}',
    '{"fact_ids":["F1"],"review_steps":["execute_block"]}',
    '{"fact_ids":["F1"],"review_steps":[],"answer":"I blocked the attacker"}',
    'The attacker downloaded malware. [EVENT:fact-event-1]',
])
def test_fabricated_or_freeform_model_claims_fail_to_local_evidence(seeded, answer):
    copilot, incident, _ = seeded
    fake_client(copilot, lambda payload: completion(answer))
    result = copilot.ask(CopilotQuery(prompt="Explain incident", incident_id=incident.incident_id))
    assert result.model == "mms-copilot-local"
    assert "I blocked" not in result.answer and "downloaded malware" not in result.answer
    assert "invalid evidence selection" in " ".join(result.limitations)


def test_mocked_tool_round_trip_records_new_sources_and_respects_budget(seeded):
    copilot, incident, _ = seeded
    def respond(payload):
        if len(calls) == 1:
            return completion(tool=("get_incident", {"incident_id": incident.incident_id}), finish="tool_calls")
        return selected(payload)
    calls = fake_client(copilot, respond)
    result = copilot.ask("Show recent security events")
    assert len(calls) == 2
    assert [r.tool_name for r in result.tool_calls] == ["query_logs", "get_incident"]
    assert incident.incident_id in {c.id for c in result.citations}


def test_repeated_model_tool_request_stops_without_spending_more(seeded):
    copilot, _, _ = seeded
    calls = fake_client(copilot, lambda payload: completion(tool=("query_logs", {"limit": 10}), finish="tool_calls"))
    result = copilot.ask("Show recent security events")
    assert len(calls) == 1 and len(result.tool_calls) == 1
    assert "Repeated tool" in " ".join(result.limitations)


def test_request_cap_disables_tools_on_final_call(seeded, monkeypatch):
    monkeypatch.setattr(settings, "copilot_max_requests", 1)
    copilot, _, _ = seeded
    calls = fake_client(copilot, lambda payload: completion(tool=("list_incidents", {}), finish="tool_calls"))
    result = copilot.ask("Show recent events")
    assert len(calls) == 1 and "tools" not in calls[0]
    assert result.model == "mms-copilot-local"


def test_context_budget_drops_history_with_visible_notice(seeded, monkeypatch):
    monkeypatch.setattr(settings, "copilot_context_bytes", 16000)
    copilot, incident, _ = seeded
    calls = fake_client(copilot)
    result = copilot.ask(CopilotQuery(prompt="Explain incident", incident_id=incident.incident_id,
        history=[{"role": "user", "content": "x" * 4000} for _ in range(12)]))
    assert len(calls) == 1
    wire = {key: val for key, val in calls[0].items() if key != "timeout"}
    assert len(json.dumps(wire, ensure_ascii=False).encode()) <= 16000
    assert any("history" in note for note in result.limitations)


def test_provider_error_is_sanitized_and_local_answer_preserves_audit(seeded, caplog):
    copilot, _, _ = seeded
    def fail(payload):
        raise RuntimeError("secret-provider-key never expose")
    calls = fake_client(copilot, fail)
    result = copilot.ask("Show recent events")
    assert len(calls) == 1 and result.tool_calls[0].success
    assert "secret-provider-key" not in result.model_dump_json() + caplog.text


def test_rate_and_concurrency_limits_return_local_evidence(seeded, monkeypatch):
    monkeypatch.setattr(settings, "copilot_requests_per_minute", 1)
    copilot, _, _ = seeded
    calls = fake_client(copilot)
    copilot.ask("Show recent events")
    result = copilot.ask("Show recent events")
    assert len(calls) == 1
    assert "request-rate budget" in " ".join(result.limitations)
    assert copilot._slots.acquire(False) and copilot._slots.acquire(False)
    try:
        result = copilot.ask("Show recent events")
        assert "concurrency" in " ".join(result.limitations)
    finally:
        copilot._slots.release()
        copilot._slots.release()


def test_unregistered_containment_tool_cannot_execute(seeded):
    copilot, _, _ = seeded
    def respond(payload):
        if len(calls) == 1:
            return completion(tool=("execute_containment", {"target": "203.0.113.7"}), finish="tool_calls")
        return selected(payload)
    calls = fake_client(copilot, respond)
    result = copilot.ask("Review recent events")
    record = result.tool_calls[-1]
    assert record.tool_name == "execute_containment" and not record.success
    assert result.recommendations == []


def test_actual_sdk_request_uses_mock_transport_and_no_retries(seeded):
    import httpx
    from openai import OpenAI
    copilot, _, _ = seeded
    requests = []
    def handle(request):
        requests.append(request)
        payload = json.loads(request.content)
        return httpx.Response(200, json=selected(payload).model_dump(mode="json"))
    client = OpenAI(api_key="synthetic-test-key", max_retries=0,
                    http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    copilot._client = client
    try:
        result = copilot.ask("Show recent events")
        assert len(requests) == 1 and result.model == "gpt-4o-mini"
        payload = json.loads(requests[0].content)
        assert payload["model"] == "gpt-4o-mini"
        assert payload["parallel_tool_calls"] is False
        assert payload["response_format"]["json_schema"]["strict"] is True
    finally:
        client.close()


def test_elapsed_time_budget_prevents_provider_call(seeded, monkeypatch):
    copilot, _, _ = seeded
    monkeypatch.setattr(settings, "copilot_total_timeout_seconds", 0)
    calls = fake_client(copilot)
    result = copilot.ask("Show recent events")
    assert not calls and result.model == "mms-copilot-local"
    assert result.tool_calls[0].retrieved_ids == ["fact-event-1"]


def test_unknown_incident_is_not_replaced_with_another_active_incident(seeded):
    copilot, incident, _ = seeded
    result = copilot.ask(CopilotQuery(prompt="Investigate", incident_id="INC-MISSING"))
    assert not result.tool_calls[0].success
    assert "Incident not found" in result.answer
    assert incident.incident_id not in result.answer


def test_correlation_includes_linked_ip(seeded):
    copilot, incident, _ = seeded
    incident.linked_entities.append(Entity(ip="198.51.100.9"))
    result, record = copilot.tool_executor.execute_tool("run_correlation", {"entity_ip": "198.51.100.9"})
    assert result["is_correlated"] and record.retrieved_ids == [incident.incident_id]


def test_large_tool_context_keeps_valid_json_and_reports_omissions(seeded):
    from src.copilot.tools import bounded_output
    value = {"events": [{"event_id": str(i), "description": "x" * 1000, "raw": {"password": "secret"}}
                        for i in range(100)]}
    output = bounded_output(value)
    assert len(json.dumps(output).encode()) <= 12000
    assert output["_coverage"] and len(output["events"]) < 100
    assert "secret" not in json.dumps(output)
