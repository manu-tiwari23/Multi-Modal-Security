# TODO.md

Single source of truth for build progress. Update this every time a feature starts, finishes, or gets paused. The agent reads the "Currently Working On" section first, every session.

## Currently Working On

**Active goal — Complete and verify all software features; rebuild the dashboard.**

**Currently implementing:** Forensic parser workflows (metadata, browser artifacts, USB logs, integrity checks) on verified stored evidence. Durable MinIO/Postgres storage is implemented and tested (11 persistence tests including four live, 83 existing targeted regressions). Dashboard replacement remains pending.

**Resume notes:** All changes are uncommitted, including pre-existing phishing/IR work. New reporting files live under `src/reporting/`, API adapters in `src/api/reports.py` and `src/api/forensics.py`; tests mirror these. Forensic gateway still uses `EvidenceVault()` memory storage: next wire durable MinIO bytes + Postgres metadata/custody, then parser workflows, standalone threat intelligence, authenticated response/persistence, dashboard replacement and browser QA. Docker Desktop and the four core services were started successfully; recheck current Compose state before live tests. Pytest disables paid OpenAI calls by default. Do not infer that current module checkboxes prove full goal completion.

ESP32 is deferred by user request (2026-11-12). Copilot remains on `gpt-4o-mini`; automated tests must use offline or mocked responses without spending API credits.

**Completion plan:** Reporting → forensic API/workflows → standalone threat intelligence → integration/security/persistence repairs → dashboard replacement with interactive 3D incident exploration and usable 2D fallback → full workflow, browser and infrastructure verification. Each feature is tested and logged before the next starts. See `COMPLETION_AUDIT.md` for evidence and remaining gates.

Previous milestone: **Phase 7 — Incident Response: implemented with simulated execution backends; full integration audit pending.**

- [x] Response recommender (`src/incident_response/models.py`, `src/incident_response/recommender.py`) — Tested (46 unit tests, 417/417 total passing)
- [x] Approval workflow (`src/incident_response/approval.py`) — Tested (21 unit tests, 438/438 total passing)
- [x] Action executor (`src/incident_response/executor.py`) — Tested (14 unit tests, 452/452 total passing)
- [x] Incident state tracking (`src/incident_response/state_tracker.py`, `src/api/main.py` `/api/ir/*`) — Tested (11 unit/E2E tests + 2 API tests, 465/465 total passing)

**Next:** Complete durable forensic workflows and standalone threat intelligence, then integration/security repairs and the dashboard rebuild.

---

## Build Order

Work top to bottom. Do not start a module's later features before its earlier ones are tested, unless a module is explicitly parallel (marked below).

### Phase 1 — Core Pipeline (foundation, do first)
- [x] Define common event schema (JSON structure used by all modules)
- [x] Stand up event bus (Redis Streams) via Docker Compose
- [x] Stand up OpenSearch, Postgres, MinIO via Docker Compose
- [x] Build basic log ingestion service → event bus → OpenSearch
- [x] Build minimal dashboard that shows raw ingested events (proves the pipeline end-to-end)

### Phase 2 — SOC
- [x] Log normalization for at least one real source (syslog: SSH auth, firewall, sudo, sessions)
- [x] Rule-based detection engine (basic Sigma-style rules)
- [x] Correlation engine (group related events into an incident)
- [x] Risk scoring
- [x] Alert manager (dedupe, prioritize, publish to dashboard)

### Phase 3 — Honeypot (can run parallel to Phase 4+)
- [x] Deploy one deceptive service (e.g. Cowrie SSH honeypot)
- [x] Session recorder → normalized event → event bus
- [x] Confirm honeypot events show up correlated in SOC dashboard
- [x] Attacker behavior clustering view

### Phase 4 — AI Copilot (needs Phase 1–2 data to be useful)
- [x] Retrieval layer: query OpenSearch for relevant logs/incidents
- [x] Tool-calling setup with OpenAI API
- [x] Tool: query_logs()
- [x] Tool: get_incident()
- [x] Tool: lookup_ioc()
- [x] Tool: draft_report()
- [x] Response composer with citations

### Phase 5 — Phishing Detection (can run parallel)
- [x] Email header/content analyzer
- [x] URL reputation scanner
- [x] Attachment analyzer
- [x] Explanation generator (why it scored the way it did)

### Phase 6 — Digital Forensics (can run parallel, mostly standalone)
- [x] Evidence intake + hashing + chain-of-custody record
- [x] File-level analysis + deleted file recovery
- [x] Metadata extraction (ExifTool)
- [x] Browser artifact analysis
- [x] USB activity analysis
- [x] Integrity re-verification job

### Phase 7 — Incident Response
- [x] Response recommender (rules per incident type)
- [x] Approval workflow (analyst sign-off required)
- [x] Action executor (start with one integration, e.g. block IP via firewall API)
- [x] Incident state tracking

### Phase 8 — Reporting
- [x] Incident report generator — evidence-grounded JSON/HTML/Markdown API and Copilot narrative correction; 36 targeted tests passed
- [x] Forensic report generator — verified evidence, hashes/custody/indicators, JSON/HTML/Markdown; supporting upload/analyze API; 88 targeted tests passed. Gateway durability remains pending.
- [x] Threat analysis report generator — deduplicated telemetry counts, source/technique/entity provenance, explicit coverage and reputation limits; 21 reporting/API tests passed

### Phase 9 — Physical Alert System (ESP32) — DEFERRED by user request
- [ ] Alert Notifier Service (subscribes to critical/high alerts, publishes to MQTT)
- [ ] Mosquitto broker set up with auth
- [ ] ESP32 firmware: Wi-Fi connect + MQTT subscribe
- [ ] LED behavior per severity level
- [ ] Buzzer behavior for high/critical
- [ ] Acknowledge button → publish ack → mute buzzer

### Phase 10 — Dashboard Polish
- [ ] Full alert/incident views
- [ ] Attack timeline visualization
- [ ] Forensic investigation interface
- [ ] Risk/severity statistics view

### Software completion gates (added 2026-11-12)
- [ ] Forensic API: evidence intake, analysis, custody, integrity and report downloads
- [ ] Standalone threat intelligence: IP/domain/URL/hash providers, caching, honest unavailable states, API and Copilot integration
- [ ] Existing feature audit: detection/anomaly coverage, parsers, honeypot service and event-bus workflows
- [ ] Persistence and restart recovery for investigations, evidence metadata and response audit records
- [ ] Authenticated analyst approval and consistent incident lifecycle across API/dashboard
- [ ] Explicit execution mode and verified configurable response integration
- [ ] Redesigned responsive dashboard: overview, incidents, timeline/3D exploration, phishing, forensics, intelligence, response, reports, Copilot
- [ ] Offline/mocked Copilot tests, bounded gpt-4o-mini requests and grounded citations
- [ ] Browser workflow/accessibility checks, production build, regression and live infrastructure tests
- [ ] Updated setup guide and requirement-by-requirement completion audit

---

## How to Use This File

- Check a box only after the feature is implemented **and tested** (see `TEST_REPORT.md`)
- Move to "Currently Working On" before starting a new item, and clear it when done
- If you stop mid-feature, leave clear resume notes — don't leave it blank
