# TODO.md

Single source of truth for build progress. Update this every time a feature starts, finishes, or gets paused. The agent reads the "Currently Working On" section first, every session.

## Currently Working On

**Phase 2 — SOC: COMPLETE ✅**

All Phase 2 SOC features are implemented and tested (107/107 unit tests passing):

- [x] Log normalization (syslog: SSH auth, firewall, sudo, sessions)
- [x] Rule-based detection engine (Sigma-style YAML rules, 21 tests)
- [x] Correlation engine (sliding-window, multi-stage aggregation, 9 tests)
- [x] Risk scoring (weighted formula + explainability, 27 tests)
- [x] Alert manager (dedup, priority, threshold, callback, full pipeline, 24 tests)

**Next:** Phase 3 — Honeypot

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
- [ ] Deploy one deceptive service (e.g. Cowrie SSH honeypot)
- [ ] Session recorder → normalized event → event bus
- [ ] Confirm honeypot events show up correlated in SOC dashboard
- [ ] Attacker behavior clustering view

### Phase 4 — AI Copilot (needs Phase 1–2 data to be useful)
- [ ] Retrieval layer: query OpenSearch for relevant logs/incidents
- [ ] Tool-calling setup with OpenAI API
- [ ] Tool: query_logs()
- [ ] Tool: get_incident()
- [ ] Tool: lookup_ioc()
- [ ] Tool: draft_report()
- [ ] Response composer with citations

### Phase 5 — Phishing Detection (can run parallel)
- [ ] Email header/content analyzer
- [ ] URL reputation scanner
- [ ] Attachment analyzer
- [ ] Explanation generator (why it scored the way it did)

### Phase 6 — Digital Forensics (can run parallel, mostly standalone)
- [ ] Evidence intake + hashing + chain-of-custody record
- [ ] File-level analysis + deleted file recovery
- [ ] Metadata extraction (ExifTool)
- [ ] Browser artifact analysis
- [ ] USB activity analysis
- [ ] Integrity re-verification job

### Phase 7 — Incident Response
- [ ] Response recommender (rules per incident type)
- [ ] Approval workflow (analyst sign-off required)
- [ ] Action executor (start with one integration, e.g. block IP via firewall API)
- [ ] Incident state tracking

### Phase 8 — Reporting
- [ ] Incident report generator
- [ ] Forensic report generator
- [ ] Threat analysis report generator

### Phase 9 — Physical Alert System (ESP32)
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

---

## How to Use This File

- Check a box only after the feature is implemented **and tested** (see `TEST_REPORT.md`)
- Move to "Currently Working On" before starting a new item, and clear it when done
- If you stop mid-feature, leave clear resume notes — don't leave it blank
