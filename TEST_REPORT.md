# TEST_REPORT.md

Log of test results, one entry per feature, added *before* checking it off in `TODO.md`. This is what makes "tested before moving to the next feature" verifiable rather than just claimed.

## Log

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
