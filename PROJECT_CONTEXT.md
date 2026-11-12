# PROJECT_CONTEXT.md

Living document. Update this as the project evolves — it should always reflect the *current real state*, not the plan. The agent reads this at the start of every session.

_Last updated: 2026-11-12 — update this line every time you edit the file_

## Tech Stack (current, as actually implemented)

| Layer | Chosen | Notes |
|---|---|---|
| Language(s) | Python (backend services), JavaScript/React (frontend) | |
| Event bus | Redis Streams (redis:7-alpine) | Decided in D005 — see DECISIONS.md |
| Log/alert store | OpenSearch | |
| Relational store | PostgreSQL | |
| Object storage | MinIO | |
| API layer | FastAPI | |
| Frontend | React | |
| AI Copilot | OpenAI API | |
| MQTT broker | Mosquitto | |
| Containerization | Docker Compose | |

## Repository Layout

```
src/
├── soc/
├── copilot/
├── honeypot/
├── phishing/
├── forensics/
├── threat-intel/
├── incident_response/
├── alert-esp32/
├── dashboard/
tests/
├── soc/
├── copilot/
├── honeypot/
├── phishing/
├── forensics/
├── threat-intel/
├── incident_response/
├── alert-esp32/
├── dashboard/
```

_Update this if the real folder structure diverges from the plan._

## Environment / Local Setup

| Variable | Purpose | Example |
|---|---|---|
| `OPENSEARCH_URL` | OpenSearch connection | `http://localhost:9200` |
| `POSTGRES_URL` | Postgres connection | `postgresql://user:pass@localhost:5432/mms` |
| `MINIO_ENDPOINT` | Object storage | `localhost:9000` |
| `MQTT_BROKER_URL` | Mosquitto broker | `mqtt://localhost:1883` |
| `OPENAI_API_KEY` | AI Copilot | (secret, in `.env`, never committed) |
| `VT_API_KEY` | VirusTotal (threat intel) | (secret) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (threat intel) | (secret) |
| `IR_APPROVAL_TTL_SECONDS` | Approval request TTL (seconds) | `3600` |
| `IR_FIREWALL_API_URL` | Firewall API integration endpoint | `mock://firewall.local/api/v1` |

_Add new variables here the moment they're introduced in code._

## External Integrations

| Service | Used by | Status |          
|---|---|---|
| VirusTotal API | Threat Intelligence module | Not yet integrated |
| AbuseIPDB API | Threat Intelligence module | Not yet integrated |
| OpenAI API | AI Copilot | Integrated (`gpt-4o-mini` with tool calling & local fallback) |
| MISP (self-hosted) | Threat Intelligence module | Deferred — see DECISIONS.md |

## Current Implementation Status (snapshot)

| Module | Status |
|---|---|
| SOC | Phase 2 complete — normalization, detection, correlation, scoring, alerting all implemented and tested (107 unit tests) |
| AI Copilot | Phase 4 complete — RAG retrieval, OpenAI tool-calling, response composer with citations, report generator, security guardrails, and React chat UI (26 unit/API tests) |
| Honeypot | Phase 3 complete — deceptive virtual shell, bounded recorder, Cowrie parser, event normalizer, TTP clustering, & cross-modal correlation tested (35 unit tests) |
| Phishing Detection | Phase 5 complete — All 4 features implemented and tested: Email header & content analyzer (41 tests), URL reputation scanner (50 tests), Static attachment analyzer (31 tests), Explanation generator + labeled precision/recall eval (8 tests), and FastAPI REST Gateway endpoints (/scan/url, /scan/email, /scan/attachment, /scan/composite, /explain, /stats, attack simulation) tested (130 phishing unit tests, 11 API tests, 371/371 total passing) |
| Digital Forensics | Phase 6 complete — All 6 features implemented and tested: Evidence vault & chain of custody, file analysis & deleted file recovery, metadata extraction, browser artifact analysis, USB activity forensics, and automated integrity re-verification jobs with pipeline tamper alerting (63 unit tests, 231 total passing) |
| Threat Intelligence | Not started |
| Incident Response | Phase 7 complete — All 4 features implemented and tested: Response recommender (`src/incident_response/recommender.py`), Analyst approval workflow (`src/incident_response/approval.py`), Pluggable action executor (`src/incident_response/executor.py`), Incident state tracker (`src/incident_response/state_tracker.py`), and REST API endpoints (`/api/ir/recommend/{incident_id}`, `/api/ir/approvals`, `/api/ir/execute/{action_id}`, `/api/ir/incidents/{incident_id}/state`, `/api/ir/incidents/{incident_id}/transition`, `/api/ir/stats`) (92 IR unit tests + 2 API tests) |
| Reporting | Three generators implemented: incident, forensic case and threat activity; JSON/HTML/Markdown APIs. Full suite 508 passed including live tests (2026-11-12); dashboard integration and report visual QA pending |
| Physical Alert (ESP32) | Deferred by user request (2026-11-12) |
| Dashboard | Phase 1 complete (live event feed) |

_Update per-module status as features land — keep this in sync with `TODO.md`, this is just the high-level view._

## Known Constraints

- Latest verification (2026-11-12): **508 tests passed**, including five live Redis/OpenSearch/API integration tests; existing frontend production build passed. Redis, OpenSearch, PostgreSQL and MinIO started with Compose and healthy. This does not certify the outstanding goal gates in `COMPLETION_AUDIT.md`.

- Threat analysis report: `GET /api/reports/threats?format=json|html|markdown` summarizes retained incidents (including closed) and deduplicated recent/timeline events. It explicitly states coverage limits and does not substitute local counts for external reputation data.

- Forensic workflow API: `POST /api/forensics/evidence` accepts `filename`, `content_base64`, `case_id`, `acquired_by`, optional `source_host`; SHA-256/MD5 calculated on intake. `GET /api/forensics/evidence?case_id=...` lists evidence; `GET /api/forensics/evidence/{id}` returns metadata/custody; `POST /api/forensics/evidence/{id}/analyze` verifies bytes and runs static file analysis. `GET /api/reports/forensics/{case_id}?format=json|html|markdown` verifies and analyzes all case evidence, rejects integrity failures with 409, and publishes critical forensic events through the gateway pipeline. Metadata omits storage paths. Upload limit: `EVIDENCE_MAX_BYTES` (default 10485760, range 1–104857600).
- Forensic gateway defaults to durable MinIO bytes/Postgres metadata and append-only custody, verified across a fresh Python process and concurrent workers. `FORENSICS_STORAGE_MODE=persistent|memory` (default persistent), `FORENSICS_DB_SCHEMA=public`, `MINIO_SECURE=false`, `STORAGE_TIMEOUT_SECONDS=5` (1–30). Storage initializes on first forensic request; failures return 503 without fallback and subsequent requests retry. Metadata/custody changes are committed before acknowledgement. Unacknowledged object bytes may remain after an ambiguous metadata commit; do not delete them blindly. Acquirer identity is still caller-provided pending authenticated actor integration. Browser, USB and metadata API workflows remain pending.

- Reporting API: `GET /api/reports/incidents/{incident_id}?format=json|html|markdown` generates an evidence snapshot without paid AI calls. HTML downloads are standalone, escaped and printable. Missing incident returns 404; unsupported format returns 422.
- Active completion goal: finish software integrations and replace the dashboard; ESP32 deferred by user request on 2026-11-12. See `COMPLETION_AUDIT.md`; previous module-complete labels do not prove production integration or restart durability.

- SOC Correlation Engine sliding window: 300 seconds (5 minutes) per entity (`ip`, `user`, `host`, `hash`)
- Honeypot must remain network-isolated from anything real (see `AGENTS.md` guardrails)
- ESP32 receives severity/type metadata only, never raw data
- All containment actions require human approval — no fully autonomous response
