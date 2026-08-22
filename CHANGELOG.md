# CHANGELOG.md

All notable changes to MMS are logged here, one entry per completed and tested feature. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- SOC: Rule-based detection engine supporting Sigma-style YAML rules, field modifiers, MITRE ATT&CK tagging, and sliding-window threshold tracking
- SOC: Default Sigma rule pack in `src/soc/rules/` (SSH brute force, sudo escalation, firewall port scan, invalid user auth, suspicious root session)
- SOC: Correlation engine with sliding-window entity linking (`ip`, `user`, `host`, `hash`), multi-stage attack aggregation, severity escalation, and chronological timeline generation
- SOC: Transparent risk scoring calculator (0-100) with documented weighted formula — base severity + event frequency + MITRE breadth + asset criticality + threat intel + multi-source bonus — and per-component `ScoreBreakdown` for analyst explainability
- SOC: Alert Manager with incident-to-alert deduplication, P1–P4 priority bucketing (score thresholds 80/50/25), configurable noise floor (`min_score_to_alert`), pluggable `on_alert` callback for Redis Streams/OpenSearch publishing, and full-pipeline end-to-end integration (correlation → scoring → alerting)
- Honeypot: Deceptive service subsystem with `VirtualShell` sandboxed command emulation (`uname`, `whoami`, `cat /etc/passwd`, `wget`, etc.) and `DeceptionService`
- Honeypot: Memory-bounded thread-safe `SessionRecorder` for tracking interactive credential attempts, commands, and payload artifacts
- Honeypot: `CowrieLogParser` for decoding raw Cowrie JSON log streams into honeypot sessions and normalized events
- Honeypot: Event normalizer converting honeypot interactions into canonical `SecurityEvent` models (`source: honeypot`) with automatic MITRE ATT&CK tagging (`T1110`, `T1059`, `T1105`, `T1082`, `T1548.003`)
- Honeypot: `BehaviorAnalyzer` for clustering sessions by MITRE TTPs, building `AttackerProfile` aggregations, and categorizing attack campaign archetypes (Automated Dropper, Interactive Recon, Multi-Stage Intrusion)
- Honeypot: Cross-modal correlation with SOC engine awarding multi-source risk score bonus (+5.0)
- Dashboard: Upgraded React command center with 5 dedicated views: SOC Alerts & Incidents with auditable Score Breakdown drawer, Honeypot Deception & Campaign Archetype clusters, Live Telemetry feed, Sigma Rules catalog, and Interactive Real-Time Attack Simulator

### Changed
- _(nothing yet)_

### Fixed
- Tests: marked `test_api_e2e.py` with `@pytest.mark.integration` to isolate pure unit tests

## [0.1.0] - 2026-08-17

### Added
- Core: common event schema (`SecurityEvent` Pydantic model) with JSON round-trip and OpenSearch serialisation
- Core: Docker Compose infrastructure (Redis, OpenSearch, OpenSearch Dashboards, PostgreSQL, MinIO, Mosquitto)
- Core: Redis Streams event bus client (publisher + consumer-group consumer)
- Core: centralised config via `pydantic-settings` + `.env`
- SOC: syslog normaliser (SSH auth, firewall, sudo, session, system error classification)
- SOC: log ingestion service (file-watching, normalise → Redis Streams → OpenSearch)
- API: FastAPI gateway with REST `/api/events` + WebSocket `/api/events/live` (Redis relay)
- Dashboard: React + Vite minimal event feed with live WebSocket, severity stats, glassmorphism dark theme
- Tools: synthetic syslog generator (`tools/generate_logs.py`) with weighted event distribution
- Infra: `.env.example`, `pyproject.toml`, `requirements.txt`

---

## How to Add an Entry

After a feature is implemented and tested (per `TEST_REPORT.md`), add a line under the relevant heading in `[Unreleased]`:

```
### Added
- SOC: basic log ingestion service reading from sample syslog source
- Honeypot: Cowrie SSH honeypot deployed and publishing sessions to event bus
```

When you reach a meaningful milestone (e.g. "Phase 1 complete", "MVP demo-ready"), cut a dated version:

```
## [0.1.0] - 2026-08-20
### Added
- Core event pipeline: ingestion → event bus → OpenSearch → basic dashboard
```

Keep entries short — one line per feature, written for a human skimming history, not a full description (that belongs in `DECISIONS.md` if it needs explaining).
