# TEST_REPORT.md

Log of test results, one entry per feature, added *before* checking it off in `TODO.md`. This is what makes "tested before moving to the next feature" verifiable rather than just claimed.

## Log

### Incident ID copy control (2026-11-14)
- Dashboard production build passed. Added full selectable incident IDs and clipboard action outside the expandable header, with success/failure feedback and disabled copy for missing IDs. Browser clipboard verification not performed.

### Phishing demo entry point (2026-11-14)
- Dashboard production build passed; phishing/simulation API regression: **11 passed in 9.50s**. Existing bundle-size warning remains. Browser interaction verification not performed in this change.

### AbuseIPDB indicator applicability (2026-11-14)
- Threat intelligence service/API suite: **49 passed in 10.69s**. New tests ensure domains, URLs and hashes never invoke AbuseIPDB while other providers still run; IPv4 and IPv6 reach the mocked check endpoint with the correct IP parameter.
- Dashboard production build passed, with existing bundle-size warning. No live provider requests or key validation performed.

### Provider key configuration (2026-11-14)
- `tests/threat_intel/test_service.py` and `tests/api/test_threat_intel_api.py`: **44 passed in 2.90s**. Confirmed runtime uses settings.vt_api_key/settings.abuseipdb_api_key and Settings reads .env; git check-ignore confirms .env is ignored. Live API verification pending user-supplied keys.

### Overview blank graph follow-up (2026-11-14)
- Previous fix only covered Simulation Lab. Root cause is the shared `max-width:100% !important` rule constraining Recharts' pixel-sized wrapper against its deliberately zero-width measuring parent.
- Removed that constraint and the lab workaround. Production build passed. Actual OverviewView rendered with 40 synthetic events in a temporary isolated browser fixture: activity and severity SVGs measured 744x240 and 419x240, with visible curves and bars confirmed by screenshot. Fixture removed after verification. Signed-in live backend data was not verified in this check.

### Simulation Lab chart rendering regression (2026-11-14)

- Reproduced the defect in an authenticated browser: both Recharts containers had normal 230px height, but their internal measuring wrappers and SVGs had computed width `0`, leaving the cards blank.
- Frontend production build: **passed** with Vite 8.2.1 and 2,477 transformed modules. Existing bundle-size warning remains non-blocking.
- Authenticated visual browser QA: reopened Simulation Lab after reload and confirmed Recent activity is visibly drawn at 541.7px and Severity Breakdown at 299.9px; both SVG widths match their responsive containers.

### Persistent topology and Simulation Lab analytics (2026-11-14)

- Frontend production build: **passed** with Vite 8.2.1 and 2,477 transformed modules. Existing bundle-size warning remains non-blocking.
- Focused regression: **55 passed** in 6.76s across threat-intelligence service, intelligence API and phishing/simulation API tests.
- Authenticated isolated browser QA: added `demo-node-01`, verified IP `192.0.2.10` in the globe status UI, confirmed its synthetic activity reached Telemetry, switched to Simulation Lab and observed SOC/Phishing/Honeypot source totals plus Recent activity and Severity Breakdown, then returned to Overview and reloaded with the node still present.
- Intelligence workflow QA: opened the bundled IP from Simulation Lab, ran lookup with external providers disabled, and received the local `mms_demo_dataset` result with demo score 86 plus explicit synthetic/non-external limitations.

### Windows startup guide verification (2026-11-14)

- Reproduced the reported condition: an API process occupied port 8000 while all Compose services were stopped; `/api/health` returned HTTP 503 with incident storage unavailable.
- Started `redis`, `opensearch`, `postgres`, `minio`, and `mosquitto`, waited until all health-checked data services reported healthy, then launched the documented command with `.venv312\Scripts\python.exe -m uvicorn` from the repository root.
- Corrected startup returned **HTTP 200** from `/api/health` with `status: ok`. Confirmed the virtual environment provides Python 3.12.10 and Uvicorn 0.54.0.
- Documentation-only verification; no full regression suite or external provider request was needed.

### Simulation Lab and demo-data showcase (2026-11-14)

- Frontend production build: **passed** with Vite 8.2.1 and 2,476 transformed modules. The existing main-bundle size warning remains non-blocking.
- Focused API/auth regression: **25 passed** in 71.65s (`tests/api/test_phishing_api.py`, `tests/api/test_auth_api.py`). No paid AI or live reputation-provider calls.
- Browser QA used an isolated memory-auth analyst account: confirmed Detection Rules is absent from dashboard navigation; all five scenario cards and four demo indicators/files are exposed; the full showcase completed with eight returned pipeline results and an incident; the URL handoff opened Phishing with the reserved `.test` URL prefilled.
- Asset delivery: `phishing-demo.eml`, `auth-telemetry.log`, `suspicious-invoice.txt` and `demo-data-guide.txt` each returned HTTP 200. The displayed SHA-256 matches `suspicious-invoice.txt`.

### Academic report artifact verification (2026-11-13)

- Report-only QA: final Word document rendered using installed Microsoft Word PDF export and the packaged render_docx.py rasterizer through a task-local conversion bridge (LibreOffice unavailable). Source/final render diff and visual page review completed; final length 43 pages. Confirmed 13 embedded/report figure assets plus the retained college logo, 11 separate editable SVG diagrams, five native tables, three refreshed contents/list fields, sequential page numbers and source page geometry.
- Structural/content/font/package checks passed: template hash unchanged; preserve-only original package parts remain byte-identical; title/heading/body typography and author identities checked; no field errors, blank pages or text outside margins. QA scripts/results are retained in the Report folder's `_mms_work` directory.
- These are document checks. No application test suite, live AI/provider request, new firewall action or hardware test was run to prepare the report. Historical software test counts in the report remain explicitly dated and do not certify subsequent work.

### Software completion audit runs (2026-11-13)

- Corrected real-session/auth persistence suite: **24 passed** (36.93s), covering real API login/CSRF/origins, roles, actor binding, no arbitrary-incident override, forensic custody identity, WebSocket login/revocation, outages, password hashing/expiry/revocation, last-admin protection, and live Postgres recovery/audit/throttling.
- Browser QA on an isolated memory-backed preview with synthetic accounts and all paid/external providers disabled: invalid password error, analyst sign-in, live WebSocket connection, authenticated local Copilot request, reload session restoration, logout and viewer-only navigation all verified. Sign-in form checked at 390×844 with no horizontal overflow; desktop/mobile screenshots inspected. Preview uses no production accounts or evidence.

- Authentication rerun with live PostgreSQL: **23 passed, 1 failed** (38.51s). Live session recovery/revocation, immutable auth audit and concurrent throttling passed. Remaining failure is the new test's transition actor field name; checking the actual schema. Frontend production build **passed** (27 modules, 407ms).

- First real authentication tests: **20 passed, 2 failed** (35.34s). Failures were new test assumptions: approval decisions expose a different actor field, and the forensic runtime uses a locked singleton rather than `lru_cache`. Correcting fixtures/assertions before rerun; no live AI calls.

- Authentication wiring baseline: **54 passed** (13.67s), existing API and forensic-storage feature tests with explicit test principals. This checks compatibility only; real-session authorization tests and sign-in UI verification are still in progress.

- Combined regression after Copilot changes: **618 passed, zero skipped/deselected** (15.57s), including live infrastructure/persistence tests and mocked AI/provider tests. `git diff --check` passed (only Windows line-ending notices). No paid AI or live threat-provider queries.

- Completed Copilot grounding/budget regression: **71 passed** (2.87s). Added actual OpenAI SDK serialization over a mock HTTP transport, elapsed-time cutoff, nonexistent-incident isolation, linked-entity correlation, bounded context/redaction notices, authoritative empty OpenSearch results, all returned event citations, typed-ID deduplication, no action extraction from negated prose, and API role/local-mode validation. No paid requests.

- Copilot grounding/budget first regression: **62 passed** (2.94s). Local incident/honeypot facts, UUID/indicator selection, strict argument/history validation, mocked evidence-first OpenAI calls, source selection rejection, tool round trips, rate/concurrency/context/request limits, sanitized failure fallback and containment allowlist. No paid requests.

- Combined regression after forensic workflows and standalone intelligence: **576 passed, zero skipped/deselected** (15.26s), including live Redis/OpenSearch, forensic Postgres/MinIO recovery, and intelligence-cache tests. Added malformed numeric-host, empty-userinfo and scoped-IPv6 URL rejection. External provider/AI calls mocked or disabled.

- Recovered infrastructure: all four Compose data services healthy; no previous pytest process remained. Durable threat-intelligence cache rerun: **1 passed** (0.48s), verifying retrieval from a new service instance and expiry against live PostgreSQL with a synthetic provider.

- Threat intelligence/Copilot/API: **61 passed** (3.13s), provider endpoints via mock transports (no live external requests), input normalization, private/synthetic indicator exclusion, opt-in/caching/coalescing, provider outages/rate limits/redirects, unknown states, API and cached Copilot evidence. Removed fabricated local reputation records.
- First durable reputation-cache check: **4 passed, 1 skipped** (5.53s); live Postgres connection was unavailable, so persistence is not yet verified. Rechecking infrastructure before rerun.

- Completed forensic workflows (including download and positive USB API cases): **36 passed** (1.99s). Verified metadata/browser parsing, size/entity/row limits, malformed inputs, unknown timestamps, no host-path reads, case/item integrity APIs, derived evidence provenance and audited download refusal after tampering.

- Initial parser workflow regression: **23 passed** (4.03s), covering existing browser, forensic API and report tests after API adapters.
- New parser/API/browser checks first run: **31 passed, 2 setup errors** (4.63s). The large parameter value produced an oversized test identifier; added concise explicit parameter IDs. Corrected run: **32 passed** (3.16s), including metadata bounds, browser schema/rows/timestamps, input/path isolation, integrity and carving tests.

### Software completion audit runs (2026-11-12)

- Durable forensic storage regression: **83 passed** (4.22s), existing forensic, report and API tests after repository/MinIO wiring.
- Durable storage tests: **11 passed** (18.23s), including four live Postgres/MinIO tests: recovery in a fresh Python process and API, 16 concurrent reads across two vault instances without custody loss, tamper history after restart/restored bytes, and DB rejection of custody/provenance rewrites. Unit failures cover audit/metadata outages, lazy recovery, schema validation and no false tamper alert on storage outage. Unique test schemas/buckets cleaned after use.

- Baseline: `.venv312/Scripts/python.exe -m pytest -q -m "not integration"` with `OPENAI_API_KEY` set to whitespace to disable paid requests: **465 passed, 5 deselected**, 40.38s. Live infrastructure tests remain unverified.
- Incident reporting first targeted run: **35 passed, 1 failed** (11.48s). The download test expected an unescaped hyphen in Markdown; corrected the assertion to accept the intentionally escaped source ID.
- Incident reporting corrected targeted run: **36 passed** (10.54s), covering evidence-only summaries, offset-aware timeline ordering, indicator deduplication/citations, missing evidence, safe HTML/Markdown, response history, all download formats, 404/422 handling and Copilot regression. No paid API calls.
- Forensic reporting/workflow: **88 passed** (5.71s), including report provenance/hashes, upload/analyze/download, case isolation, corrupted/missing bytes causing 409 plus critical pipeline events, invalid filenames/base64/actors, empty files and size limits; existing forensic tests included.
- Forensic workflow after environment-configurable upload limit: **88 passed** (17.48s). No external AI calls.
- Threat analysis reporting: **21 passed** (3.85s), covering unique event/incident counts, deduplicated technique/entity sources, empty snapshots, risk ordering, closed-incident coverage and three API download formats; incident listing regression included.
- Forensic integrity/parser repairs: **78 passed** (2.57s), including verification bypass rejection, restored bytes retaining tamper history, safe encoded-marker detection/negative control and forensic API regression. Added default test configuration disabling paid OpenAI calls regardless of `.env`.
- Full offline regression after all changes above: **502 passed, 5 deselected** (35.23s), using `.venv312/Scripts/python.exe -m pytest -q -m "not integration"`. No paid API calls.
- Existing frontend baseline: `npm run build` **passed** (Vite 8.2.1, 24 modules). This is a compile check of the old dashboard, not validation of the requested replacement.
- `git diff --check` **passed**. Docker initially unavailable (`dockerDesktopLinuxEngine` pipe missing); launched installed Docker Desktop hidden. Live integration verification remains pending engine/container readiness.
- Started Redis, OpenSearch, Postgres and MinIO via Compose; all four report healthy. Live pipeline/query verification: **6 passed** (38.79s), including Redis pub/sub, OpenSearch indexing, API filtering/pagination and an offline total-count check. Repaired API totals and replaced reliance on pre-existing event data with a unique disposable test index.
- Final combined regression for this work: `.venv312/Scripts/python.exe -m pytest -q` — **508 passed, zero skipped/deselected** (14.55s), including all five existing live integration tests. Ordinary API tests isolate OpenSearch writes; AI tests remain offline. `git diff --check` passed again. This validates current tested behavior, not the remaining dashboard/persistence/auth/intelligence requirements.

| Date | Module | Feature | Test Type | Result | Notes |
|---|---|---|---|---|---|
| 2026-08-17 | shared | SecurityEvent schema creation, validation, JSON round-trip | unit | Pass | 11/11 tests passing |
| 2026-08-17 | soc | Syslog normaliser — all event types + malformed input | unit | Pass | 15/15 tests passing (fixed session_open regex) |
| 2026-08-17 | soc | Redis Streams pub/sub + OpenSearch indexing | integration | Pass | 4/4 integration tests passing against live containers |
| 2026-08-17 | api | FastAPI REST endpoints (/api/health, /api/events filtering) | integration | Pass | Verified against live OpenSearch index |
| 2026-08-17 | dashboard | React + Vite frontend production bundle | unit | Pass | Production build compiled cleanly |
| 2026-08-22 | soc | Rule-based detection engine (Sigma YAML parser + stream matcher + sliding window thresholds) | unit | Pass | 21/21 tests passing (47/47 total unit tests) |
| 2026-08-22 | soc | Sliding-window correlation engine & multi-stage incident tracking | unit | Pass | 9/9 tests passing (56/56 total unit tests) |
| 2026-08-22 | soc | Transparent risk scoring calculator (weighted formula + explainability) | unit | Pass | 27/27 tests passing (83/83 total unit tests) |
| 2026-08-22 | soc | Alert Manager (dedup, priority, threshold, callback, full pipeline) | unit | Pass | 24/24 tests passing (107/107 total unit tests) |
| 2026-08-22 | honeypot | Deceptive service, bounded session recorder, Cowrie parser, event normalizer, TTP clustering, & cross-modal correlation | unit | Pass | 35/35 tests passing (142/142 total unit tests) |
| 2026-08-22 | copilot | RAG retrieval, OpenAI tool-calling, response composer with citations, report generator, guardrails, and API endpoints | unit | Pass | 26/26 tests passing (168/168 total unit tests) |
| 2026-10-04 | forensics | Evidence intake + immediate SHA-256/MD5 hashing + chain-of-custody logging + tamper detection on access | unit | Pass | 12/12 tests passing (180/180 total unit tests) |
| 2026-10-04 | forensics | File-level analysis (entropy, magic bytes, extension spoofing, IOC extraction, carving, deleted file recovery) | unit | Pass | 12/12 tests passing (192/192 total unit tests) |
| 2026-10-04 | forensics | Metadata extraction (OOXML docProps, PDF Info & weaponization, EXIF camera/GPS, PNG chunks, PE compilation/sections, MACB) | unit | Pass | 10/10 tests passing (202/202 total unit tests) |
| 2026-10-04 | forensics | Browser artifact analysis (Chrome/Firefox history, downloads, cookies, WebKit/Mozilla epoch timestamps, suspicious queries, dangerous downloads) | unit | Pass | 7/7 tests passing (209/209 total unit tests) |
| 2026-10-04 | forensics | USB activity analysis (Windows setupapi.dev.log, Registry USBSTOR/MountedDevices drive mapping, Linux syslog/dmesg, BadUSB/Flipper Zero detection) | unit | Pass | 11/11 tests passing (220/220 total unit tests) |
| 2026-10-04 | forensics | Integrity re-verification job (full vault sweeps, case-filtered audits, tamper detection, missing file alerts, background daemon, audit reports) | unit | Pass | 11/11 tests passing (231/231 total unit tests, 63/63 forensics) |
| 2026-10-05 | phishing | Email header & content analyzer (models, EmailParser, 8 detection modules, synthetic samples, SecurityEvent mapping) | unit | Pass | 41/41 tests passing (272/272 total unit tests) |
| 2026-10-06 | phishing | URL reputation scanner (URLFeatureExtractor, LookalikeAnalyzer, homographs, IP obfuscation, URLReputationCache, threat intel providers, SecurityEvent mapping) | unit | Pass | 50/50 tests passing (322/322 total unit tests, 91/91 phishing) |
| 2026-10-06 | api/phishing | Phishing REST API endpoints (/scan/url, /scan/email, /stats), attack simulation, & bug fixes (B003, B004) | unit | Pass | 6/6 tests passing (328/328 total unit tests, 9/9 API tests) |
| 2026-11-12 | phishing | Static attachment analyzer (magic bytes, spoofing, RTLO, OOXML macros/templates, PDF active tags, HTML smuggling, ZIP inspection, hash cache & /scan/attachment API) | unit | Pass | 31/31 attachment tests + 2/2 API tests passing (361/361 total unit tests, 122/122 phishing) |
| 2026-11-12 | phishing | Explanation generator (structured signal/category attribution, score-cap reporting, MITRE mapping, composite explanations, /explain & /scan/composite APIs, labeled precision/recall eval) | unit/integration | Pass | 8/8 explanation & labeled-dataset tests + 2/2 API tests passing (371/371 total unit tests, 130/130 phishing, 11/11 API) |
| 2026-11-12 | incident_response | Response recommender (declarative playbooks per incident type/MITRE/severity, target entity population, deduplication, priority sorting, requires_approval=True guardrail) | unit | Pass | 46/46 tests passing (417/417 total unit tests) |
| 2026-11-12 | incident_response | Approval workflow (`ApprovalManager` request/approve/reject, human-only approver identity check, double-decision guard, TTL expiry, audit log) | unit | Pass | 21/21 tests passing (438/438 total unit tests) |
| 2026-11-12 | incident_response | Action executor (`ActionExecutor` mandatory approval gate, `MockFirewallBackend`, `MockEDRBackend`, `MockWorkflowBackend`, rollback & audit log) | unit | Pass | 14/14 tests passing (452/452 total unit tests) |
| 2026-11-12 | incident_response/api | Incident state tracking (`IncidentStateTracker` FSM, plan/action linking, transition audit) & REST API endpoints (`/api/ir/*`) | unit/integration | Pass | 11/11 state tracker & E2E IR tests + 2/2 API tests passing (465/465 total unit tests, 92/92 IR, 13/13 API) |
| 2026-11-14 | alert-esp32 | AlertNotifierService (strict metadata sanitization, severity mapping, mock MQTT publish, physical ack callback) | unit | Pass | 4/4 tests passing (`tests/alert_esp32/test_notifier.py`) |
| 2026-11-14 | alert-esp32 | ESP32 C++ firmware compilation with esp32:esp32 core & bundled PubSubClient | unit | Pass | 0 compile errors (914,371 bytes flash, 46,832 bytes RAM) |
| 2026-11-14 | dashboard | Add Normal Node (+ Add Normal Node button, dynamic green dot topology, mesh links) | unit | Pass | Vite production build passing (2,477 modules, 0 errors) |

**Test Type** — one of: `unit`, `integration`, `manual`
**Result** — one of: `Pass`, `Fail`, `Pass with issues` (if it works but a bug was logged in `BUGS.md`)

---

## Example Entry

```
| 2026-08-20 | soc | Log ingestion service normalizes syslog into common event schema | unit | Pass | 12/12 tests passing, covers malformed input |
| 2026-08-20 | soc | Ingested events appear in OpenSearch within 2s | integration | Pass | Verified manually with sample syslog stream |
| 2026-08-21 | honeypot | Cowrie session data publishes to event bus | integration | Pass with issues | Works, but timestamp timezone bug — logged as B002 |
```

## How to Use This File

1. Implement the feature
2. Write and run tests (unit and/or integration as appropriate)
3. Add a row here with the real result — log failures too, don't only record passes
4. If it passed (or passed with a logged issue), check it off in `TODO.md` and add an entry to `CHANGELOG.md`
5. If it failed, keep working — don't move to the next feature until this resolves or you've explicitly decided to defer it (log the deferral in `DECISIONS.md`)

## 2026-11-13 — Current software verification and dashboard repair

- Initial consolidated run: 673 passed, 2 failed, 5 skipped while infrastructure was starting. Failures identified reused playbook action IDs and concurrent correlation schema/correlation lock inversion.
- Focused repair verification: 108 passed.
- Consolidated rerun after repairs and cross-incident approval regression: **681 passed, zero skipped**, 54.09 seconds. Includes live Redis/OpenSearch/Postgres/MinIO integration tests. AI and reputation providers disabled by test configuration; no paid calls or live containment. Logs: `data/verification-current.log`, `data/verification-fixes.log`, `data/verification-final.log`.
- Dashboard browser verification ongoing; empty snapshots no longer invent counts, hosts, addresses or service health.

## 2026-11-14 — Dashboard completion and uploaded ESP32 regression

- Fixed duplicate ESP32 test-module collection by retaining the canonical `tests/alert_esp32/test_notifier.py` and renaming the compatibility-layout copy to `tests/alert-esp32/test_notifier_legacy.py`.
- Consolidated command: `.\.venv312\Scripts\python.exe -m pytest -q --tb=short -ra`.
- Result: **689 passed, zero failures/skips** in **110.18 seconds**. Live Redis, OpenSearch, PostgreSQL and MinIO integration cases ran; paid AI and external reputation calls remained disabled/mocked.
- Dashboard production build: Vite transformed 2,477 modules and completed successfully. A non-blocking bundle-size warning remains for the 688.51 kB main chunk.
- Authenticated browser verification passed for simulation/live counters, observed-vs-simulated globe nodes, incident categories, incident-to-response routing, response plan creation/approval gate, phishing URL analysis, local threat-intelligence lookup, forensic evidence empty state, honeypot view, responsive telemetry cards, threat-report download and offline Copilot evidence/citations.
- Main gateway restarted with `python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000`; dashboard remains available on port 5173.
