# CHANGELOG.md

All notable changes to MMS are logged here, one entry per completed and tested feature. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
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
