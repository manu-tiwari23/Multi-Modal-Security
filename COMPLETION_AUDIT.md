# Software completion audit

User goal (2026-11-12): complete and test the software, replace the provisional dashboard with a polished interactive dashboard (3D where useful), use gpt-4o-mini with minimal paid testing, defer ESP32.

Recorded test results are historical evidence, not proof of the current running application. Completion requires current tests and workflow verification. Existing uncommitted user work is preserved.

| Requirement | Current evidence | Remaining verification/work |
|---|---|---|
| SOC ingestion, detection, correlation, scoring, alerting | Python implementation and tests exist | Run baseline; audit anomaly coverage and real Redis-to-dashboard flow |
| Honeypot | Virtual shell, recorder, parser, behavior engine | Verify isolated service/intake workflow and correlated dashboard data |
| Copilot | gpt-4o-mini tool loop and local fallback | Offline test isolation, cost limits, provider mock tests, citations; existing report invents activity |
| Phishing | Email/URL/attachment/composite APIs and tests | Negative/size tests; usable dashboard workflow |
| Forensics | Intake/static-analysis/report APIs; durable MinIO/Postgres verified by restart/concurrency tests | Complete metadata/browser/USB/integrity workflows, authenticated actors and report/dashboard UI |
| Threat intelligence | Local Copilot retriever and phishing provider hooks | Standalone provider service, cache, API and integrations; unavailable is not clean |
| Incident response | Recommender, approval, mock execution and state tracker | Authentication, durable audit/state, consistency with SOC, explicit mode, configurable integration |
| Reporting | Existing Copilot JSON/Markdown report | Grounded incident, forensic and threat reports, safe HTML/downloads, API tests |
| Dashboard | Provisional React views | Replace design and complete all software workflows; interactive 3D with accessible fallback |
| Persistence/infrastructure | Compose and event indexing | Restart recovery and live service integration verification |
| Delivery | Setup documents exist but test counts are stale | Accurate instructions, current regression/browser/build evidence |
| ESP32 | Deferred by user | No hardware work required for this goal |

## Working state

- Incident reporting implemented and verified with 36 targeted tests; report/Copilot evidence narrative fixed. Browser rendering remains part of final visual verification.
- Forensic reporting and supporting upload/static-analysis API verified with 88 targeted tests, including tamper/missing-file failure paths. Durable gateway storage, parser API workflows and authenticated identities remain pending.
- Threat analysis reporting verified with 21 reporting/API tests; fixed incident listing runtime failure. Reporting's three planned generators now exist; external threat intelligence and complete historical persistence are still pending.
- Forensic integrity/parser repairs verified with 78 forensic/API tests. Optional verification now rejected; historical tamper flags survive restoration; encoded-marker detector fixed. Pytest disables paid OpenAI calls by default.
- Combined regression: **508 passed, zero skipped/deselected** (14.55s), including the five live integration tests. Existing dashboard build and diff whitespace check pass. Replacement dashboard and browser verification are not yet implemented.
- Docker Desktop and Redis/OpenSearch/Postgres/MinIO started successfully; all four services healthy. API query totals fixed; live API test now uses isolated seeded data. Recheck live state before next infrastructure work.
- Durable MinIO/Postgres forensic storage implemented: 11 persistence tests pass including four live restart/concurrency/immutability checks; 83 existing targeted tests pass. Ordinary pytest defaults to explicit memory mode; live tests use unique storage resources.
- Next: forensic parser APIs, threat intelligence, remaining security/integration gates and dashboard replacement. Goal remains active; changes uncommitted.
- Baseline and subsequent test runs are recorded in `TEST_REPORT.md`.
- Changes remain uncommitted, including pre-existing phishing and incident-response changes.
