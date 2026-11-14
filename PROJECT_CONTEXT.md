# PROJECT_CONTEXT.md

Living document. Update this as the project evolves — it should always reflect the *current real state*, not the plan. The agent reads this at the start of every session.

_Last updated: 2026-11-14 — update this line every time you edit the file_

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
├── threat_intel/
├── incident_response/
├── alert-esp32/
├── dashboard/
tests/
├── soc/
├── copilot/
├── honeypot/
├── phishing/
├── forensics/
├── threat_intel/
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

Local `.env` now includes blank `VT_API_KEY` and `ABUSEIPDB_API_KEY` placeholders. Fill these with provider keys and restart the backend (settings and provider instances are cached). In Intelligence, enable "Allow external provider lookup" when requesting provider reports. Reserved simulation indicators continue using local demo results.

| Service | Used by | Status |          
|---|---|---|
| VirusTotal API | Threat Intelligence module | Report-lookup provider implemented and mock-tested; explicit analyst opt-in, no live provider test performed |
| AbuseIPDB API | Threat Intelligence module | IP check provider implemented and mock-tested; explicit analyst opt-in, no live provider test performed |
| OpenAI API | AI Copilot | Integrated (`gpt-4o-mini` with tool calling & local fallback) |
| MISP (self-hosted) | Threat Intelligence module | Deferred — see DECISIONS.md |

## Current Implementation Status (snapshot)

| Module | Status |
|---|---|
| SOC | Phase 2 complete — normalization, detection, correlation, scoring, alerting all implemented and tested (107 unit tests) |
| AI Copilot | Evidence-first gpt-4o-mini read-only tools and validated fact selection, local fallback, request/context limits, citations and report generator. 71 focused checks and 618-test combined suite pass. Durable audit/past-incident vector retrieval and refreshed UI remain open. |
| Honeypot | Phase 3 complete — deceptive virtual shell, bounded recorder, Cowrie parser, event normalizer, TTP clustering, & cross-modal correlation tested (35 unit tests) |
| Phishing Detection | Phase 5 complete — All 4 features implemented and tested: Email header & content analyzer (41 tests), URL reputation scanner (50 tests), Static attachment analyzer (31 tests), Explanation generator + labeled precision/recall eval (8 tests), and FastAPI REST Gateway endpoints (/scan/url, /scan/email, /scan/attachment, /scan/composite, /explain, /stats, attack simulation) tested (130 phishing unit tests, 11 API tests, 371/371 total passing) |
| Digital Forensics | Phase 6 complete — All 6 features implemented and tested: Evidence vault & chain of custody, file analysis & deleted file recovery, metadata extraction, browser artifact analysis, USB activity forensics, and automated integrity re-verification jobs with pipeline tamper alerting (63 unit tests, 231 total passing) |
| Threat Intelligence | Validated IP/domain/URL/hash provider service, TTL cache, API and cached Copilot integration implemented. The exact four Simulation Lab indicators have explicitly synthetic local demo records; ordinary indicators still require cached/configured provider evidence. Live Postgres cache/expiry verified. |
| Incident Response | Phase 7 complete — All 4 features implemented and tested: Response recommender (`src/incident_response/recommender.py`), Analyst approval workflow (`src/incident_response/approval.py`), Pluggable action executor (`src/incident_response/executor.py`), Incident state tracker (`src/incident_response/state_tracker.py`), and REST API endpoints (`/api/ir/recommend/{incident_id}`, `/api/ir/approvals`, `/api/ir/execute/{action_id}`, `/api/ir/incidents/{incident_id}/state`, `/api/ir/incidents/{incident_id}/transition`, `/api/ir/stats`) (92 IR unit tests + 2 API tests) |
| Reporting | Three generators implemented: incident, forensic case and threat activity; JSON/HTML/Markdown APIs. Full suite 508 passed including live tests (2026-11-12); dashboard integration and report visual QA pending |
| Physical Alert (ESP32) | Deferred by user request (2026-11-12) |
| Dashboard | Complete presentation workspace: responsive overview/globe, incidents, telemetry, honeypot, phishing, forensics, intelligence, response, reports, account controls, Copilot and a guided Simulation Lab. Demo topology persists with reserved IP labels and publishes synthetic telemetry; lab analytics include phishing/source counts, recent activity and severity. Standalone Detection Rules view removed. Production build and authenticated browser showcase verified 2026-11-14. |

_Update per-module status as features land — keep this in sync with `TODO.md`, this is just the high-level view._

## Known Constraints

- Copilot: `POST /api/copilot/chat` supports `mode=auto|local` (auto), optional incident ID and up to 12 user/assistant history messages; prompts/messages max 4,000 characters. Only four recent history messages enter AI context, with explicit further omissions if needed. `mode=local` guarantees no model call. The model selects verified server facts/review steps or invokes validated read-only tools; free-form model claims and unknown fact IDs are rejected. Responses include `audit_id`, tool source IDs/output hashes, `limitations`, and usage counts. These are logged/returned; append-only Postgres audit and vector retrieval remain pending. The synchronous chat route runs in FastAPI's worker pool.
- Copilot environment defaults: `COPILOT_MAX_REQUESTS=3` (1–5), `COPILOT_MAX_OUTPUT_TOKENS=700` (128–2000), `COPILOT_CONTEXT_BYTES=24000` (16000–64000), `COPILOT_REQUEST_TIMEOUT_SECONDS=12` (1–30), `COPILOT_TOTAL_TIMEOUT_SECONDS=30` (1–90), `COPILOT_REQUESTS_PER_MINUTE=12` (1–60), `COPILOT_MAX_CONCURRENT=2` (1–4). Rate/concurrency limits are per process; total timeout is checked before requests, with HTTP inactivity timeout bounded by remaining budget. SDK retries disabled. Model remains `gpt-4o-mini`; automated tests never use real keys.

- Threat intelligence API: `POST /api/threat-intel/lookup` with `value`, optional `type` (`ip|domain|url|hash`) and `allow_external` (default false). Explicit external lookups disclose the indicator to configured providers; private/reserved/test values are kept local. `GET /api/threat-intel/status` reports configured provider names without keys. Results include provenance, status, checked/expiry timestamps, cached flag, score/unknown and coverage limitations. Copilot only consumes local/cached results; provider invocation is an analyst API action. Runtime settings: `THREAT_INTEL_CACHE_MODE=persistent|memory` (persistent), `THREAT_INTEL_DB_SCHEMA=public`, `THREAT_INTEL_CACHE_CAPACITY=5000`, `THREAT_INTEL_CACHE_TTL_SECONDS=3600`, `THREAT_INTEL_TIMEOUT_SECONDS=2`. Tests inject mock HTTP transports and blank provider keys; no live external lookups are required for regression.

- Forensic parsers: `POST /api/forensics/evidence/{id}/analyze?kind=file|metadata|browser|usb_setupapi|usb_registry|usb_syslog` verifies content and appends analysis custody. Browser SQLite snapshots support Chromium/Firefox history and cookie metadata, copied/read-only queries; unknown timestamps remain unknown. `FORENSICS_MAX_ARTIFACT_ROWS=10000` (1–100000) and `FORENSICS_QUERY_TIMEOUT_SECONDS=3` (1–30) bound query work; excess limits return 422. Metadata ZIP limits: 250 members, 512 KiB per XML property file, no XML entity declarations. `POST /api/forensics/evidence/{id}/verify` and `/api/forensics/cases/{case_id}/verify` audit integrity; `GET /api/forensics/evidence/{id}/download` verifies/audits attachment export; `POST /api/forensics/evidence/{id}/carve/{artifact_index}` stores a new derived evidence item with parent provenance. APIs never accept host filesystem paths. Browser-cache/WAL collection and authenticated actor integration remain audit work.

- Latest verification (2026-11-13): **618 tests passed**, including live Redis/OpenSearch/API, forensic Postgres/MinIO recovery, intelligence cache and mocked Copilot tests. All four Compose data services healthy. Existing frontend build passed on November 12; replacement still pending. This does not certify the outstanding goal gates in `COMPLETION_AUDIT.md`.

- Threat analysis report: `GET /api/reports/threats?format=json|html|markdown` summarizes retained incidents (including closed) and deduplicated recent/timeline events. It explicitly states coverage limits and does not substitute local counts for external reputation data.

- Forensic workflow API: `POST /api/forensics/evidence` accepts `filename`, `content_base64`, `case_id`, `acquired_by`, optional `source_host`; SHA-256/MD5 calculated on intake. `GET /api/forensics/evidence?case_id=...` lists evidence; `GET /api/forensics/evidence/{id}` returns metadata/custody; `POST /api/forensics/evidence/{id}/analyze` verifies bytes and runs static file analysis. `GET /api/reports/forensics/{case_id}?format=json|html|markdown` verifies and analyzes all case evidence, rejects integrity failures with 409, and publishes critical forensic events through the gateway pipeline. Metadata omits storage paths. Upload limit: `EVIDENCE_MAX_BYTES` (default 10485760, range 1–104857600).
- Forensic gateway defaults to durable MinIO bytes/Postgres metadata and append-only custody, verified across a fresh Python process and concurrent workers. `FORENSICS_STORAGE_MODE=persistent|memory` (default persistent), `FORENSICS_DB_SCHEMA=public`, `MINIO_SECURE=false`, `STORAGE_TIMEOUT_SECONDS=5` (1–30). Storage initializes on first forensic request; failures return 503 without fallback and subsequent requests retry. Metadata/custody changes are committed before acknowledgement. Unacknowledged object bytes may remain after an ambiguous metadata commit; do not delete them blindly. Acquirer identity is still caller-provided pending authenticated actor integration. Browser, USB and metadata API workflows remain pending.

- Reporting API: `GET /api/reports/incidents/{incident_id}?format=json|html|markdown` generates an evidence snapshot without paid AI calls. HTML downloads are standalone, escaped and printable. Missing incident returns 404; unsupported format returns 422.
- Active completion goal: finish software integrations and replace the dashboard; ESP32 deferred by user request on 2026-11-12. See `COMPLETION_AUDIT.md`; previous module-complete labels do not prove production integration or restart durability.

- SOC Correlation Engine sliding window: 300 seconds (5 minutes) per entity (`ip`, `user`, `host`, `hash`)
- Honeypot must remain network-isolated from anything real (see `AGENTS.md` guardrails)
- ESP32 receives severity/type metadata only, never raw data
- All containment actions require human approval — no fully autonomous response

## Dashboard construction checkpoint (2026-11-13)

The new local React workspace has a globe Overview, corner Copilot dialog and dedicated intelligence, phishing, forensics, reports, response and account pages alongside existing incident/telemetry/honeypot/rule views. These latest pages are implemented but not yet build/browser verified; consolidated checks follow the build-first pass.

`GET /api/ir/incidents/{incident_id}/workflow` returns current lifecycle, allowed transitions, approval/action/result records and explicit execution/storage modes. Current backends are simulated and response state is still process-local; persistence and configurable execution remain outstanding.

Authentication is implemented (superseding earlier actor-pending notes): cookie sessions, CSRF, viewer/analyst/admin roles, CLI bootstrap, session-bound forensic and response actors. `/api/auth/session`, `/api/auth/password` and administrator `/api/auth/users` endpoints support the account UI. Auth configuration: `AUTH_STORAGE_MODE=persistent|memory` (persistent), `AUTH_DB_SCHEMA=public`, `AUTH_COOKIE_SECURE=false` (enable for HTTPS), `AUTH_SESSION_SECONDS=28800`, `AUTH_IDLE_SECONDS=1800`, `AUTH_LOGIN_ATTEMPTS=10`, `AUTH_LOGIN_WINDOW_SECONDS=300`, `AUTH_ALLOWED_ORIGINS` (JSON list of allowed frontend origins). Initial account: `python -m src.auth.cli create admin --role admin` with hidden password prompts. Vite can use `MMS_API_TARGET` to override the default local backend at `http://localhost:8000`.

Durable response service construction: `RESPONSE_STORAGE_MODE=persistent|memory` (persistent), `RESPONSE_DB_SCHEMA=public`, and `IR_APPROVAL_TTL_SECONDS=3600` (60–86400) configure the new response runtime. It uses `POSTGRES_URL` and `STORAGE_TIMEOUT_SECONDS`. Repository/service code and regression cases exist; gateway migration is still pending, so current API response state remains volatile. No durable-runtime verification is claimed yet.

Response migration update: gateway response endpoints now use the durable runtime by default; no automatic memory fallback. `GET /api/ir/incidents/{incident_id}/audit` exposes the append-only analyst audit. Reports read durable response lifecycle and can use the incident snapshot retained when its plan was created. Stats are recorded action outcomes, not live containment checks. General SOC incident recovery and lifecycle synchronization remain pending. The migration has not yet passed consolidated verification.

SOC durability construction: `INCIDENT_STORAGE_MODE=persistent|memory` (persistent) and `INCIDENT_DB_SCHEMA=public` configure Postgres snapshots and durable event deduplication. Correlation transactions serialize across workers and only load snapshots within the 300-second window. Read/correlation statuses project authoritative response phases via an API-injected callback, preserving module isolation. New persistence tests are written but not run. Alert recovery and reliable Redis backlog/retry consumption are still outstanding.

Relay update: gateway uses the Redis `mms-gateway` consumer group on `events:raw`, consumes backlog from 0-0, retries pending failures and reclaims abandoned entries after 60 seconds. `events:invalid` retains malformed payloads and source IDs; quarantine and acknowledgement are atomic. Persistent ingestion requires OpenSearch indexing before acknowledgement. Active alerts are reconstructed from durable incidents with stable IDs. These changes await consolidated verification; deployment should remain single gateway worker until WebSocket fan-out audit is complete.

Shared processing update: persistent mode now uses transactionally stored detection threshold counters and cached per-event rule matches in the incident schema. Rule configuration hash selects counter state; replay returns the original result. Gateway workers publish processed payloads to Redis `mms:live:processed`, suppress their own echo, and broadcast remote updates to authenticated local sockets. Dashboard snapshot polling recovers pub/sub disconnect gaps. Implementation awaits consolidated verification.

Copilot audit implementation: `COPILOT_AUDIT_MODE=persistent|memory` (persistent), `COPILOT_AUDIT_DB_SCHEMA=public`, `POSTGRES_URL` and `STORAGE_TIMEOUT_SECONDS` configure append-only provenance storage. Query execution records the signed-in analyst, query hash, every tool/source set and output digest, response hash/citations/model usage. Raw prompts, tool arguments, evidence and answer bodies are not retained. `/api/copilot/audit/{audit_id}` is readable by its owner or an administrator. Audit outages return 503 rather than an unaudited answer. Tests written; final verification pending.

Historical Copilot retrieval now uses a Postgres local lexical vector store (same schema/mode as Copilot audit) with normalized term-frequency vectors and exact cosine ranking. `search_past_incidents` accepts query, optional current-incident exclusion and 1–10 results; normal pre-model retrieval uses five. Stored summaries include historical/closed incidents and are refreshed from authoritative incident records. This provides lexical similarity, not neural semantic equivalence; returned facts are explicitly historical context and source-cited. No embedding provider/API spend. Verification pending.

Configurable response adapter: `IR_EXECUTION_MODE=simulation|firewall_http` (simulation). Live mode requires persistent response storage, `IR_FIREWALL_API_URL` pointing to the full adapter action endpoint, `IR_FIREWALL_API_TOKEN`, and `IR_BACKEND_TIMEOUT_SECONDS=5` (1–30). Only `block_ip`/`block_egress` are supported live; no simulated fallback for other actions. Contract: POST JSON `{action_id, action_type, ip}` with bearer authentication and `Idempotency-Key: action_id`; HTTP 200 must return exactly `{action_id, action_type, ip, status}` where status is applied/rejected. Confirmed values must match. Adapter must enforce idempotency and supply an operator reconciliation facility for ambiguous outcomes. HTTPS required except loopback. Plans bind the execution mode and endpoint fingerprint; a changed configuration cannot execute prior approvals. Mock-transport tests written, not executed; no live firewall deployment or containment performed.

Forensics parser additions: `kind=browser_bundle` accepts a bounded ZIP with root `History`, `Cookies`, `places.sqlite`, `cookies.sqlite`, matching `-wal` files and optional `cache.har`. `kind=browser_cache_har` analyzes HAR cache metadata, distinguishing reported hits from unknown state. Paths, duplicate members, encryption, orphan WAL and expanded size over `EVIDENCE_MAX_BYTES` are rejected. HAR row count uses `FORENSICS_MAX_ARTIFACT_ROWS`; bodies, cookies, authorization headers and URL queries are omitted. This supports exported cache metadata, not proprietary binary cache formats. UI wired; regression tests written, not run.

Deleted-file API: `POST /api/forensics/recover-deleted` with `metadata_evidence_id` and `content_evidence_id` verifies both vault objects, requires the same case, validates matching Windows $I/$R filenames and recorded size or FreeDesktop .trashinfo/content names, then preserves content as a new evidence item with both parent IDs/hashes. Metadata paths are descriptive only, never host file paths. Missing/naive timestamps stay unknown; Trash filename pairing cannot prove historical content identity. Dashboard form added; verification pending.

SOC anomaly layer: enabled by `src/soc/anomaly.json`, grouping source/event type/host into 60-second buckets with 30-bucket history and 10-bucket warm-up. Alert when current count exceeds max(20, prior median + 6 × max(1, 1.4826 × MAD)). Emit once per bucket, ignore older buckets for rate analysis, reset after long idle gaps, cap groups at 1000 and unique events per bucket at 10000. Baselines persist with detection state; `/api/rules` returns configuration. Anomalies are rate deviations, not proof of compromise. Regression cases written; verification pending.
