# TODO.md

Single source of truth for build progress. Update this every time a feature starts, finishes, or gets paused. The agent reads the "Currently Working On" section first, every session.

## Currently Working On

**Incident ID display/copy implemented (2026-11-14):** Always-visible selectable incident ID and Copy ID control on incident cards, plus accessible clipboard feedback. Build passes; browser clipboard verification pending. Changes remain uncommitted.

**Phishing demo section added (2026-11-14):** Simulation Lab now offers direct email loading, URL analysis handoff and campaign launch. Email opens in Raw email mode using the existing inert .eml asset. Build and 11 API tests pass; browser interaction check remains pending. Changes uncommitted.

**AbuseIPDB applicability fixed (2026-11-14):** Non-IP lookups skip the IP-only provider; dashboard explains applicability and handles older cached unsupported cards. IPv4/IPv6 mocked routing verified; 49 tests and dashboard build pass. Live key validation not performed.

**Provider configuration prepared (2026-11-14):** Added blank VT_API_KEY and ABUSEIPDB_API_KEY to ignored local .env; existing provider runtime already reads both. 44 focused service/API tests pass. User must supply keys and restart backend; live provider verification awaits keys.

**Overview graph follow-up completed (2026-11-14):** Removed the shared max-width constraint collapsing Recharts wrappers, replacing the earlier lab-only workaround. Production build and visual check of the actual Overview component with synthetic events pass. Changes remain uncommitted with existing user work.

**Simulation Lab chart rendering fixed (2026-11-14):** Recent activity and Severity Breakdown now render at their full measured width after opening the initially hidden Simulation Lab view. Production build and authenticated visual browser QA pass; both graph SVGs report non-zero dimensions and are visibly populated.

**Persistent demo topology and Simulation Lab telemetry completed (2026-11-14):** Demo globe nodes now retain their reserved IPs and persist across tab changes/reloads. Adding a node publishes a clearly synthetic low-severity event into the real telemetry pipeline. Simulation Lab now contains live Recent activity, Severity Breakdown, source totals including Phishing, and a recent demo-event stream. Its four bundled indicators resolve through an explicitly synthetic local intelligence dataset with non-external demo scores; ordinary unlisted indicators remain unknown. Production build, 55 focused tests and authenticated browser workflows pass.

**Windows startup guide repaired (2026-11-14):** `HOW_TO_RUN.md` now reflects the persistent authenticated runtime: start and health-check Docker services before the API, use `.venv312` Python directly, create the first account, verify `/api/health`, handle a stale port 8000 process, launch Vite from the dashboard directory, and authenticate protected simulation requests. Reproduced the former 503 state with Docker stopped, then verified the corrected sequence returns HTTP 200.

**Simulation Lab showcase completed (2026-11-14):** Rebuilt the lab as a guided presentation workspace with five safe scenarios, visible pipeline stages/results, one-click links into the related workflows, and a downloadable demo-data kit containing reserved IP/domain/URL indicators plus inert email, attachment, log and presenter-guide files. Removed the standalone Detection Rules page from dashboard navigation/rendering; detection remains active in the backend and incident evidence. Production build, asset delivery, focused API tests and authenticated browser execution passed.

**Dashboard completion checkpoint (2026-11-14):** Dashboard refinement and browser workflow verification are complete. The globe preserves the connected-system visualization while distinguishing observed systems from clearly labelled simulated layout nodes. Fabricated empty-state metrics, placeholder hosts/IPs, service-health claims and Copilot quick prompts were removed. Telemetry cards now remain readable at tablet/mobile widths, incident cards open the selected response workflow directly, and Copilot remains read-only with one non-duplicated citation drawer.

Current consolidated verification: **689 tests passed, zero failures/skips** in 110.18 seconds, including the newly uploaded ESP32 notifier tests and live Redis/OpenSearch/Postgres/MinIO integration. The production dashboard build passes. Browser checks cover analyst sign-in, simulation/live counters, incident details, response-plan creation and approval gating, phishing URL analysis, local intelligence, forensics empty state, honeypot session inspection, telemetry expansion, report download and offline evidence-grounded Copilot.

**Currently working on next:** Audit and verify the uploaded ESP32 firmware/hardware path. Firmware, notifier service, circuit documentation and flashing utilities are present. Server-side notifier tests pass; physical LED/buzzer/acknowledgement checks still require explicit verification before Phase 9 is marked complete.

**Resume notes:** Current changes remain uncommitted and include user work. Dashboard remains on port 5173; the port-8000 API used for Simulation Lab browser QA was an isolated memory-auth session and should not be treated as a production service. Copilot automated checks use offline/mocked providers; live firewall execution was not exercised and remains approval-gated simulation by default. Current full-suite log: `data/verification-dashboard-final.log`.

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

### Phase 9 — Physical Alert System (ESP32)
- [x] Alert Notifier Service (subscribes to critical/high alerts, publishes sanitized metadata to MQTT)
- [x] Mosquitto broker configuration (docker-compose & local config)
- [x] ESP32 firmware: Wi-Fi auto-reconnect + MQTT subscribe & compile verified
- [x] LED behavior per severity level (GPIO 18 Green, GPIO 19 Yellow, GPIO 21 Red)
- [x] Buzzer behavior for high/critical (GPIO 22 active buzzer)
- [x] Acknowledge button → publish ack → mute buzzer (GPIO 23 push button to GND)

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
