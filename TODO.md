# TODO.md

Single source of truth for build progress. Update this every time a feature starts, finishes, or gets paused. The agent reads the "Currently Working On" section first, every session.

## Currently Working On

**Documentation delivery (2026-11-13):** Prepared the academic MMS report for Manu Tiwari and Mayank Shakya using the supplied new college template, with separate generated concepts and editable diagram assets. Report artifacts are under `C:\Users\manut\OneDrive - Gamers Flight\Desktop\Report\MMS_Final_Report`. This documentation work did not implement or verify the pending software features; the software goal and resume notes below remain active. Existing software work remains uncommitted.

**Active goal — Complete and verify all software features; rebuild the dashboard.**

**Currently implementing:** Connected network systems 3D globe visualization completed. Removed continent dot shapes; the 3D globe now models network infrastructure where each dot corresponds to an active connected system/host (1 system = 1 dot, 2 systems = 2 dots, N systems = N dots). Per-system threat status is displayed directly on the nodes (Green = normal/healthy, Orange = mild warning/medium activity, Red = active attack with pulsing beacons, HUD leader tags, and local shockwaves). Added inter-system mesh links with traversing data packets and a node selector in the HUD. Production build verified cleanly.

**Resume notes:** Modernized Overview (`OverviewView.jsx`), realistic 3D threat globe (`GlobeOverview.jsx`), and charts (`recharts`, `lucide-react`) are active and verified. Both Vite dev server (port 5173) and FastAPI backend (port 8000) are operational.

ESP32 is deferred by user request (2026-11-12). Copilot remains on `gpt-4o-mini`; automated tests must use offline or mocked responses without spending API credits.

**Completion plan (user update):** Implement remaining software and the simple globe dashboard first; then run one consolidated verification pass and fix observed issues. Avoid repeated full-suite runs during construction. Homepage should stay uncluttered, with attack markers and Copilot in a corner; detailed workflows belong on separate pages. ESP32 remains deferred and paid AI testing remains disabled. See `COMPLETION_AUDIT.md` for outstanding requirements.

**Latest resume note:** Added configurable robust event-rate anomaly detection alongside Sigma rules. `src/soc/anomaly.json` defines warm-up, bucket/history sizes, minimum rate, MAD multiplier and group cap. API loads it; persistent detection state now includes baseline counters/config digest. Rule results include observed count/baseline/threshold and caveats; `/api/rules` exposes configuration. Three synthetic regression cases written, not run. Next: isolated honeypot deployment/intake and dashboard refinement, then consolidated verification and fixes. All changes uncommitted.

Previous milestone: **Phase 7 — Incident Response: implemented with simulated execution backends; full integration audit pending.**

- [x] Response recommender (`src/incident_response/models.py`, `src/incident_response/recommender.py`) — Tested (46 unit tests, 417/417 total passing)
- [x] Approval workflow (`src/incident_response/approval.py`) — Tested (21 unit tests, 438/438 total passing)
- [x] Action executor (`src/incident_response/executor.py`) — Tested (14 unit tests, 452/452 total passing)
- [x] Incident state tracking (`src/incident_response/state_tracker.py`, `src/api/main.py` `/api/ir/*`) — Tested (11 unit/E2E tests + 2 API tests, 465/465 total passing)

**Next:** Complete remaining dashboard workflows and durable incident/response state, then remaining integration repairs and consolidated verification.

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
- [x] Forensic report generator — verified evidence, hashes/custody/indicators, JSON/HTML/Markdown; supporting upload/analyze API. Gateway durability subsequently verified with live restart/concurrency tests.
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
- [x] Forensic API: evidence intake, analysis, custody, integrity and report/download workflows (storage/parser tests passed; auth and remaining artifact-format audit tracked separately)
- [x] Standalone threat intelligence: IP/domain/URL/hash providers, caching, honest unavailable states, API and Copilot integration — live cache/expiry and combined 576-test suite passed
- [ ] Existing feature audit: detection/anomaly coverage, parsers, honeypot service and event-bus workflows
- [ ] Persistence and restart recovery for investigations, evidence metadata and response audit records
- [ ] Authenticated analyst approval and consistent incident lifecycle across API/dashboard
- [ ] Explicit execution mode and verified configurable response integration
- [ ] Redesigned responsive dashboard: overview, incidents, timeline/3D exploration, phishing, forensics, intelligence, response, reports, Copilot
- [x] Offline/mocked Copilot tests, bounded gpt-4o-mini requests and grounded citations — 71 focused checks passed
- [ ] Durable Copilot query/retrieval audit and past-incident/vector retrieval
- [ ] Browser workflow/accessibility checks, production build, regression and live infrastructure tests
- [ ] Updated setup guide and requirement-by-requirement completion audit

---

## How to Use This File

- Check a box only after the feature is implemented **and tested** (see `TEST_REPORT.md`)
- Move to "Currently Working On" before starting a new item, and clear it when done
- If you stop mid-feature, leave clear resume notes — don't leave it blank
