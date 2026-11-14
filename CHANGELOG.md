# CHANGELOG.md

### Added — 2026-11-14 incident ID copy
- Display full incident IDs on collapsed and expanded cards with Copy ID and success/failure feedback. Missing IDs show Unavailable instead of substituting an alert ID. Dashboard build passes.

### Added — 2026-11-14 explicit phishing demo
- Added a dedicated Simulation Lab phishing demo section with sample email preview, one-click loading into Raw email analysis, URL handoff and campaign launch. Reuses the existing reserved-domain sample and simulation endpoint.
- Production build and 11 phishing API tests pass.

### Fixed — 2026-11-14 AbuseIPDB indicator routing
- Skip AbuseIPDB for domains, URLs and hashes; display an applicability note instead of an unsupported result card, including older cached responses. Failure timestamps now say Checked rather than Observed.
- Added non-IP routing and mocked public IPv4/IPv6 lookup regressions: 49 focused tests pass; dashboard production build passes.

### Configuration — 2026-11-14 threat intelligence keys
- Added missing VirusTotal and AbuseIPDB placeholders to ignored local .env, preserving existing settings. Documented backend restart and explicit external lookup in .env.example. Existing integration verified with 44 passing service/API tests; no live provider call made.

### Fixed — 2026-11-14 Overview graph follow-up
- Removed the shared Recharts wrapper max-width rule that collapsed graphs against an intentionally zero-width measuring parent. Removed the lab-only workaround; verified visible Overview activity curves and severity bars using synthetic events and passed the production build.

### Fixed — 2026-11-14 Simulation Lab blank graphs
- Corrected the Recharts measuring wrapper that remained `0x0` when Simulation Lab was mounted off-screen, causing both populated chart SVGs to render at zero width.
- Scoped the sizing correction to Simulation Lab chart canvases. Authenticated visual QA now shows the activity curve and severity bars, with SVG widths matching their responsive containers.
- Production dashboard build passes with the existing non-blocking bundle-size warning.

### Fixed — 2026-11-14 persistent demo topology and lab analytics
- Persisted clearly simulated topology nodes in browser-local state, assigned reserved `192.0.2.x` addresses, and added host/IP labels to both canvas callouts and node status pills.
- Added the `node_activity` simulation path: adding a demo node publishes a low-severity synthetic event through the normal indexing, correlation and WebSocket pipeline so it appears in Telemetry.
- Added live Recent activity and Severity Breakdown charts, per-source counts including Phishing, and a recent demonstration-event stream to Simulation Lab.
- Added a local `mms_demo_dataset` provider for only the four bundled demo indicators. Results are prominently labeled synthetic presentation data; unlisted indicators and external-provider-disabled lookups retain honest unknown states.
- Production dashboard build passes; **55 focused threat-intelligence/API tests pass**; authenticated browser QA verified node persistence, IP display, telemetry creation, phishing analytics and the scored intelligence handoff.

### Fixed — 2026-11-14 Windows startup instructions
- Replaced activation-dependent and unauthenticated commands in `HOW_TO_RUN.md` with a verified Windows sequence using the repository's `.venv312` Python directly.
- Documented that the full persistent platform requires healthy Redis, OpenSearch, PostgreSQL and MinIO services before backend startup, plus first-account creation and authenticated/CSRF-protected simulations.
- Added health verification, port-8000 diagnosis, common 503/module/sign-in troubleshooting, safe shutdown, and a concise repeat-start section.

### Added — 2026-11-14 Simulation Lab presentation kit
- Rebuilt Simulation Lab into a responsive guided showcase with five synthetic scenarios, pipeline-stage explanations, live result metrics and direct investigation links.
- Added copyable reserved IP/domain/URL/hash indicators and four downloadable inert demo files for phishing, attachment analysis, forensics and presenter guidance. Workflow links now prefill the selected demo indicator without enabling external lookup.
- Removed the standalone Detection Rules view, route and navigation entry from the dashboard while preserving backend detection and incident-level rule evidence.
- Verified production build, four HTTP-served demo assets, 25 focused API/auth tests, authenticated showcase execution and responsive browser rendering.

### Fixed — 2026-11-14 dashboard completion and consolidated verification
- Removed fabricated empty-state graph counts, placeholder topology hosts/IPs, inferred service-health claims and hard-coded Copilot attacker prompts. Manual topology additions are now explicitly simulated and excluded from observed-system counts.
- Reworked responsive width containment and added complete Telemetry card styling, keyboard expansion and bounded raw-event rendering. Incident response actions now open the selected durable workflow directly.
- Kept Copilot read-only in the UI, removed its decorative authorization control and eliminated duplicate citation rendering. Verified report download and the major dashboard workflows in an authenticated browser session.
- Renamed the ESP32 compatibility test copy to avoid Python module-name collision while preserving both uploaded layouts.
- Production dashboard build passes; consolidated result is **689 passed, zero failures/skips** with live infrastructure integrations.

### Fixed — 2026-11-13 runtime verification
- Generate unique executable action IDs for each recommendation, preventing approvals/results from another incident being reused through template IDs. Added a cross-incident approval regression.
- Commit schema initialization before correlation/response operations acquire transaction locks, eliminating the observed concurrent correlation deadlock.
- Current consolidated suite: 681 passed, no skips. All four data services healthy; dashboard/browser refinement in progress.

### Documentation — 2026-11-13 academic report
- Created an editable Word mini-project report using the supplied current template and sample typography, with student/guide details, implemented and planned scope, dated verification evidence, literature references and AI/ML appendices. Included 13 figures and supplied 11 editable SVG diagrams separately. No pending software completion gate was marked complete. Artifact formatting/package/render checks are recorded in TEST_REPORT.md; synthetic empty-state dashboard chart fallback was recorded in BUGS.md.

### In progress — 2026-11-13 dashboard rebuild
- Added account password/user/role/access controls and incident-response plan, approval, execution, lifecycle and result views. Added authenticated read-only response workflow endpoint with explicit simulation/process-local status. Consolidated verification pending.
- Added dedicated phishing scan/result workflows, report downloads, and forensic evidence intake/list/detail/custody/verify/analyze/carve/download controls. UI verification remains deferred to the consolidated pass.
- Added compact sidebar workspace, dedicated intelligence lookup with external-provider consent, and corner Copilot dialog. Globe remains the focused homepage. Implementation only: consolidated build/browser verification pending; remaining module pages are unfinished.

All notable changes to MMS are logged here, one entry per completed and tested feature. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Phase 9 ESP32 Physical Alert System:
  - Created `AlertNotifierService` (`src/alert_esp32/service.py`) and `AlertNotification` model (`src/alert_esp32/models.py`) with strict data sanitization (metadata only: severity, incident_type, source, timestamp; zero raw logs, IOCs, or credentials). Subscribes to `alerts/ack` for physical button feedback.
  - Developed full Arduino C++ firmware (`src/alert-esp32/firmware/mms_alert_esp32/mms_alert_esp32.ino`) implementing Wi-Fi auto-reconnection, MQTT subscription, multi-state LED logic (Green: GPIO 18, Yellow: GPIO 19, Red: GPIO 21), Active Buzzer driver (GPIO 22), and debounced physical acknowledge button (GPIO 23). Verified compilation with Arduino CLI (`esp32:esp32:esp32`).
  - Added full hardware connection schematic, ASCII breadboard diagram, and pinout documentation in `src/alert-esp32/circuit_diagram.md`.
  - Added automated flashing tool script `src/alert-esp32/flash_firmware.bat` targeting COM6.
  - Added unit test suite `tests/alert_esp32/test_notifier.py` covering sanitization, severity mapping, MQTT publishing, and acknowledge callback (4 tests passing).
  - Integrated `AlertNotifierService` into FastAPI gateway `src/api/main.py` lifespan and `ingest_pipeline_event`.
- Connected Network Systems Node Addition Button (`OverviewView.jsx` & `GlobeOverview.jsx`):
  - Added "+ Add Normal Node ({count})" and "Reset Nodes" buttons on the Dashboard Homepage Analyst Quick Actions bar and Globe HUD.
  - Dynamically injects nominal hosts (green dots) onto the 3D topology globe with active mesh links and host information pills.
- Connected Network Systems 3D Globe: Re-architected `GlobeOverview.jsx` from geographical continent clouds to a network node topology visualizer. Each dot on the 3D globe represents an actual connected system/host (1 system connected = 1 dot, 2 systems = 2 dots, N systems = N dots). System nodes reflect live health: GREEN for nominal/secure nodes, ORANGE for mild activity, and RED for attacked systems with localized ground shockwaves, beacon leader lines, and HUD info pills. Added animated inter-system network mesh links with traveling packet indicators and an interactive node count selector (`1 Dot`, `2 Dots`, `3 Dots`, `Auto`).
- Simplified & Categorized Incidents View (`AlertsView.jsx`): Transformed the Incidents tab activity cards to be clean, scannable, and low-clutter by default (showing priority/severity badge, title, host/IP quick chips, risk score meter, and toggle button). Clicking any activity expands dedicated categorized panels: `📋 Overview & Entities`, `🎯 Detection & MITRE`, `📊 Score Breakdown`, and `⚡ Response Actions`.

### Fixed
- 3D Globe Drag Direction: Inverted horizontal mouse delta projection (`rotationY.current -= dx * 0.007`) so the globe rotates smoothly and intuitively in the exact direction the user drags their cursor.
- Dashboard Command Center Overview & Analytics: Integrated modernized telemetry views inspired by reference design (`OverviewView.jsx`), including 4 high-density metric cards (Events Ingested, Active Incidents, Critical Alerts, Honeypot Sessions) with `lucide-react` icons, an Analyst Quick Actions toolbar (direct attack simulation trigger, phishing email scan, threat intel lookup, and AI security copilot), and two `recharts` activity panels: Event Telemetry Rate (`AreaChart` with amber/rose gradients) and Severity Breakdown (`BarChart`).
- Realistic 3D Cyber Threat Globe & Dynamic Attack Visualization: Completely upgraded `GlobeOverview.jsx` with 18 realistic continental landmass coordinate clusters, atmospheric halo glow, backface culling, latitude/longitude graticules, interactive pointer drag-to-rotate, ground shockwave ripples on impact sites, and animated attack vectors. Added dynamic movie-like color morphing where the entire globe's atmosphere corona, inner planetary gradient, graticules, and continental landmasses transition from calm cyber teal/cyan to molten red/orange attack heat (`#ff3b30` / `#ff922b`) when an attack is simulated or critical/high severity alerts are detected.
- Copilot grounding and usage limits: retrieve evidence before AI, validate read-only tools/history, render only server-generated facts selected by the model, reject invented sources/free-form claims, and preserve unknown results. Added source IDs/output digests, complete timeline citations, explicit coverage, local mode, bounded context/output/request/time/rate/concurrency, no SDK retries and sanitized fallback. Corrected incident UUID targeting and removed invented default indicators/attack narratives (B012). Seventy-one focused checks pass with mocked OpenAI traffic.
- Threat intelligence: Validated IP/domain/URL/hash lookup API, VirusTotal/AbuseIPDB report providers with explicit external opt-in, bounded TTL cache in Postgres, and local/cached Copilot integration. Missing configuration, errors and absent reputation remain unknown. Removed fabricated attribution. Live database cache/expiry passed; combined regression 576 passed without paid AI or live vendor requests.
- Forensic workflows: Metadata/browser/USB analysis through verified evidence APIs, per-analysis custody entries, individual/case integrity checks, verified attachment downloads, and carving into new hashed evidence with parent/byte-range provenance. Bounded SQLite/XML parsing, explicit unsupported-schema errors, unknown browser timestamps preserved, uploaded text never interpreted as host paths. 36 workflow/API/browser checks passed.
- Forensics persistence: Gateway defaults to MinIO object bytes and Postgres immutable intake metadata/append-only custody. Records survive fresh-process restart; concurrent audit writes are serialized per evidence item. Storage failures return 503 without memory fallback or false tamper classification. Eleven new persistence tests (including four live integration tests) and 83 existing targeted regressions passed.
- API query verification: Corrected total event counts independently of page size, with filtered counts for both OpenSearch and memory. Live API tests now use an isolated temporary index; offline tests avoid indexing into developer stores. Six live/query checks passed with Redis/OpenSearch running (B011).
- Forensic integrity hardening: Removed the optional hash-verification bypass, retained historical tamper flags after bytes are restored, and fixed silent encoded-marker parsing failures (B008/B009). Added offline-by-default pytest configuration to conserve OpenAI credits. 78 forensic/API tests passed.
- Reporting: Threat activity report (`GET /api/reports/threats`) in JSON/HTML/Markdown, covering retained incidents including closed cases and deduplicated recent/timeline events; source counts, severity, observed entities and technique citations with explicit coverage/reputation limitations. Fixed `/api/incidents` calling a nonexistent engine method (B010). 21 reporting/API tests passed.
- Reporting/Forensics: Verified case report downloads, bounded evidence upload/list/detail/static-analysis API, full hashes and custody history, case-isolated indicators, integrity failure blocking with critical pipeline alerts. Configurable `EVIDENCE_MAX_BYTES`. 88 targeted tests passed; gateway still uses in-memory storage pending persistence work.
- Reporting: Evidence-grounded incident report API (`GET /api/reports/incidents/{incident_id}?format=json|html|markdown`), escaped standalone HTML and Markdown downloads, chronological event evidence, indicator references, detection annotations and response audit. Corrected Copilot's unsupported generic attack narrative (B005); 36 targeted tests passed.
- Incident Response: Finite-state `IncidentStateTracker` (`new` -> `investigating` -> `containing` -> `contained` -> `remediating` -> `remediated` -> `closed`) with transition validation, plan/action linking, audit history, and REST API endpoints (`/api/ir/recommend/{incident_id}`, `/api/ir/approvals`, `/api/ir/approvals/{request_id}/approve`, `/api/ir/approvals/{request_id}/reject`, `/api/ir/execute/{action_id}`, `/api/ir/incidents/{incident_id}/state`, `/api/ir/incidents/{incident_id}/transition`, `/api/ir/stats`)
- Incident Response: Pluggable `ActionExecutor` with hard analyst-approval verification (`UnapprovedActionError` on unapproved/pending/rejected/expired actions), simulated `MockFirewallBackend` (IP/egress/domain/URL blocking + rollback), `MockEDRBackend`, `MockWorkflowBackend`, and execution audit logging
- Incident Response: Analyst `ApprovalManager` workflow with TTL expiration, human-only approver identity validation, double-decision protection, and append-only approval audit logging
- Incident Response: Rule-based `ResponseRecommender` with 8 default playbooks (brute force, privilege escalation, phishing, malware, data exfiltration, honeypot intrusion, evidence tampering, reconnaissance), MITRE/severity/source matching, target entity auto-population, action deduplication, and mandatory `requires_approval=True` validator
- Phishing: Structured explanation generator (`ExplanationGenerator`, `StructuredExplanation`) synthesizing ranked `SignalAttribution` and `CategoryContribution` score breakdowns, score-cap reporting, MITRE ATT&CK tactic/technique context, human-in-the-loop recommended actions, ASCII-safe text/Markdown formatting, cross-vector `explain_composite()` fusion across email/URL/attachment verdicts, REST endpoints (`POST /api/phishing/explain`, `POST /api/phishing/scan/composite`), and labeled synthetic dataset precision/recall evaluation
- Phishing: Static attachment analyzer (`AttachmentAnalyzer`, `AttachmentFeatureExtractor`) with magic-byte vs. extension spoofing checks, RTLO (`U+202E`) and double-extension detection, in-memory OOXML VBA macro and external template injection inspection, legacy OLE2/RTF checks, PDF active-content tags, HTML/SVG smuggling detection, bounded in-memory ZIP member & encryption inspection, thread-safe SHA-256 `HashReputationCache` with pluggable providers (`SyntheticHashBlocklistProvider`, `VirusTotalHashProvider`), `POST /api/phishing/scan/attachment` REST endpoint, and canonical `SecurityEvent` mapping
- Phishing: REST API endpoints (`/api/phishing/scan/url`, `/api/phishing/scan/email`, `/api/phishing/stats`) with optional automatic pipeline ingestion into SOC correlation and scoring
- Phishing: Attack simulation scenario (`"phishing"`) added to `/api/simulate/attack` and integrated into the multi-stage attack sequence
- Phishing: Stage 6 Phishing Detection & Brand Lookalike Analysis added to `demo_pipeline.py` with multi-source SOC correlation
- Phishing: URL reputation scanning engine (`URLScanner`) with lexical feature extraction (`URLFeatureExtractor`), IDN homograph and Punycode attack detection, optical and Levenshtein typosquatting analysis against protected brand catalogs, obfuscated IP representation decoding (dotted decimal, dword/integer, octal, hex), link shortener and credential harvesting detection, high-risk TLD checks, thread-safe TTL reputation caching (`URLReputationCache`), pluggable threat intelligence providers with graceful timeout degradation (`MockThreatIntelProvider`, `SyntheticBlocklistProvider`, `VirusTotalLookupProvider`), and canonical `SecurityEvent` pipeline mapping
- Phishing: Email header and content analysis engine (`EmailAnalyzer` & `EmailParser`) supporting RFC 822 parsing, authentication validation (SPF, DKIM, DMARC), header anomaly detection (Reply-To/Return-Path mismatch), sender reputation, brand impersonation, urgency/coercion language analysis, deceptive URL detection, attachment risk flags, hidden HTML / form detection, score normalization (0-100), auditable signal breakdown, and `SecurityEvent` pipeline mapping
- Forensics: Automated evidence integrity re-verification engine (`IntegrityVerifierJob`) supporting full vault sweeps, case-filtered audits, and periodic background daemon scheduling with dual-hash recalculation (SHA-256 + MD5), immediate chain-of-custody logging (`CustodyAction.VERIFY` with `VERIFIED` or `MISMATCH`), storage corruption / missing file detection, critical pipeline alert publishing (`SecurityEvent` with `event_type="evidence_tampering_detected"` / `"evidence_missing_detected"`), and defensible forensic audit certificates in structured dict and Markdown formats
- Forensics: USB device connection and activity forensics engine (`USBAnalyzer`) parsing Windows setupapi device installation logs (`setupapi.dev.log` / `setupapi.offline.log`), Windows Registry artifacts (`USBSTOR`, `USB`, and `MountedDevices` drive letter mapping), and Linux syslog/dmesg records with known vendor ID resolution (SanDisk, Kingston, Apple, etc.), BadUSB / keystroke injection hardware detection (Rubber Ducky, Teensy, Flipper Zero, Digispark, Arduino Leonardo), firmware default serial pattern matching, and unified multi-source chronological connection timelines
- Forensics: Browser artifact analysis engine (`BrowserAnalyzer`) parsing Chromium (Chrome, Edge, Brave, Opera) and Mozilla Firefox navigation history, cookies, and file downloads with WebKit and Mozilla PRTime epoch conversion, lock-free SQLite querying, suspicious keyword search detection (credential theft, anti-forensics, defense evasion), and dangerous executable/direct-IP download detection
- Forensics: Comprehensive metadata extraction engine (`MetadataExtractor`) parsing Office OpenXML (Dublin Core properties, revisions, application, and embedded VBA macro detection), PDF (/Info dictionary and critical weaponization indicators: /Launch, /JavaScript, /OpenAction), raster/vector images (EXIF camera make/model, software, timestamps, GPS decimal coordinates, PNG tEXt chunks), Windows PE executables (compilation timestamp, machine architecture, section entropy), filesystem MACB timestamps, and optional ExifTool CLI fallback mapping
- Forensics: File-level analysis engine (`FileAnalyzer`) with Shannon entropy packing/encryption detection, magic byte format verification, critical extension spoofing detection, dual ASCII/UTF-16LE string and IOC extraction (IPs, URLs, emails), Base64 payload decoding, signature-based file carving (JPEG, PNG, PDF, ZIP, PE), and deleted file recovery for Windows Recycle Bin ($I/$R metadata pairs) and Linux/macOS Trash (.trashinfo)
- Forensics: Tamper-evident evidence vault (`EvidenceVault`) with immediate streaming SHA-256 and MD5 hashing on intake, pluggable storage backends (Memory/LocalStorage/MinIO), isolated copy retrieval to prevent in-place mutation, chronological `ChainOfCustodyEntry` audit log, batch integrity verification jobs, markdown report exporter, and `SecurityEvent` pipeline publishing
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
- Copilot: RAG retrieval layer over OpenSearch `mms-events` index and in-memory buffer (`LogRetriever`, `IncidentRetriever`, `ThreatIntelRetriever`)
- Copilot: OpenAI Tool definitions and `ToolExecutor` (`query_logs`, `get_incident`, `lookup_ioc`, `run_correlation`, `draft_report`)
- Copilot: Response Composer with evidence citation grounding engine (`[EVENT]`, `[INCIDENT]`, `[IOC]`) and human-in-the-loop containment recommendation gates (`requires_approval: true`)
- Copilot: Automated `IncidentReportGenerator` synthesizing executive summaries, chronological attack timelines, IOC registries, MITRE technique matrices, and containment actions
- Copilot: Multi-turn `CopilotOrchestrator` with prompt injection / containment bypass security guardrails and intelligent offline fallback engine
- Copilot: REST API endpoints (`/api/copilot/chat`, `/api/copilot/tools`, `/api/copilot/reports/generate`)
- Dashboard: Dedicated AI Security Copilot Command Center tab (`CopilotView.jsx`) with quick investigation prompt suggestions, real-time tool execution badges, collapsible citation cards, and markdown report modal previewer with 1-click clipboard copy

### Changed
- API: Added throttling (15s interval) to `_get_os()` OpenSearch ping checks, preventing connection timeouts from delaying event ingestion and pipeline test execution when running in standalone mode

### Fixed
- Phishing: `URLScanner.to_security_event` mapped `PhishingSeverity.SAFE` to `low` and removed invalid `url` field from `Entity`, fixing Pydantic `ValidationError` (Bug B003)
- Phishing: `LookalikeAnalyzer` and `URLScanner` enforced `safe_ascii()` unicode codepoint escaping across all lookalike signal descriptions and evidence, preventing `UnicodeEncodeError: 'charmap'` crashes on Windows consoles (Bug B004)
- Tests: `test_api_e2e.py` health assertion updated to validate required fields on enriched telemetry status and added OpenSearch ping skip guard to handle standalone unit test execution gracefully (Bug B001)
- Tests: marked `test_api_e2e.py` with `@pytest.mark.integration` to isolate pure unit tests
- API: Removed duplicate return block in `/api/simulate/attack` endpoint (Bug B002)
- Demo: Updated `demo_pipeline.py` unit test breakdown to 328 tests covering Phishing, Copilot, and Forensics modules

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

### In progress — durable incident response
- Added transactional Postgres response repository, append-only audit, durable approval/lifecycle/result service and pre-execution claims. Added five regression cases for the consolidated pass. Gateway migration and live persistence verification remain pending.

- Durable response construction: migrated response API, workflow/audit, stats and incident report lifecycle to the transactional runtime; retained plan-time incident snapshots for report recovery. Added live Postgres fresh-process/concurrency/audit tests for consolidated execution.

- SOC durability construction: added Postgres incident snapshots, transactional event deduplication, multi-worker serialized correlation and response lifecycle projection; added live recovery/concurrency/closed-incident test cases for the consolidated pass.

- Pipeline construction: replaced lossy Redis cursor relay with pending/acknowledgement/reclaim/quarantine handling; require indexing for durable ingestion and recover active alerts from stored incidents. Added relay and alert-recovery regression cases, not yet executed.

- Added persistent shared detection state and replay-stable matches, cross-worker live-update fan-out, orderly background shutdown and dashboard snapshot recovery polling. New regression cases await consolidated execution.

- Copilot construction: added append-only persistent query/tool/source/response audit, owner/admin read endpoint, hashed sensitive content and fail-closed audit availability. Added concurrency/privacy/failure regression cases for the consolidated pass.

- Copilot construction: added persistent local lexical vector retrieval for historical incidents, strict read-only search tool, pre-generation retrieval, historical-only fact rendering and source citations. Added ranking/exclusion/privacy regression cases for the consolidated pass.

- Response construction: added opt-in HTTP firewall adapter, strict matching confirmation, persistent-storage requirement and approval binding to execution mode/endpoint; mock-transport regression cases queued for consolidated verification.

- Forensic construction: added verified browser ZIP database/WAL analysis and HAR cache metadata parser with bounded archives, member hashes and sensitive-field omission; dashboard selectors and regression cases added.

- Forensic construction: added paired deleted-file recovery API/UI, same-case and partner/size validation, safe recovered names, unknown-time preservation and parent-hash custody provenance. Regression cases queued for consolidated verification.

- SOC construction: added robust event-rate anomaly detector with data-driven thresholds, warm-up, persisted baseline, explained observations and bounded state; configuration API and regression cases added.
