# CHANGELOG.md

All notable changes to MMS are logged here, one entry per completed and tested feature. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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

### Changed
- _(nothing yet)_

### Fixed
- _(nothing yet)_

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
