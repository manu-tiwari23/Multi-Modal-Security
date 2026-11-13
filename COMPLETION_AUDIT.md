# Software completion audit

User goal (2026-11-12): complete and test the software, replace the provisional dashboard with a polished interactive dashboard (3D where useful), use gpt-4o-mini with minimal paid testing, defer ESP32.

Recorded test results are historical evidence, not proof of the current running application. Completion requires current tests and workflow verification. Existing uncommitted user work is preserved.

| Requirement | Current evidence | Remaining verification/work |
|---|---|---|
| SOC ingestion, detection, correlation, scoring, alerting | Python implementation and tests exist | Run baseline; audit anomaly coverage and real Redis-to-dashboard flow |
| Honeypot | Virtual shell, recorder, parser, behavior engine | Verify isolated service/intake workflow and correlated dashboard data |
| Copilot | Evidence-first gpt-4o-mini tool/fact selection, strict schemas, cached intelligence, bounded context/requests, local fallback and full returned-source citations; 71 focused checks pass | Durable query/retrieval audit, past-incident/vector retrieval, refreshed dashboard workflow |
| Phishing | Email/URL/attachment/composite APIs and tests | Negative/size tests; usable dashboard workflow |
| Forensics | Intake/parser/verification/download/report APIs; durable MinIO/Postgres verified by restart/concurrency tests | Remaining browser-cache/WAL and deleted-file-pair coverage; authenticated actors and report/dashboard UI |
| Threat intelligence | Standalone provider service/API, persistent TTL cache and cached Copilot integration; live cache and mocked vendor tests pass | Dashboard lookup workflow and explicit disclosure UI |
| Incident response | Recommender, approval, mock execution and state tracker | Authentication, durable audit/state, consistency with SOC, explicit mode, configurable integration |
| Reporting | Incident/forensic/threat JSON/HTML/Markdown APIs tested | Dashboard downloads and rendered-report visual verification |
| Dashboard | Provisional React views | Replace design and complete all software workflows; interactive 3D with accessible fallback |
| Persistence/infrastructure | Compose/event indexing plus forensic and intelligence storage verified live | Durable incidents, response state and append-only analyst/Copilot audit; restart recovery of complete workflows |
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
- Forensic byte-only parser workflows, verification, derived carving and downloads now pass 36 workflow/API/browser checks. Browser-cache/WAL formats and full deleted-file-pair recovery remain in the requirements audit; no complete-artifact coverage is claimed.
- Next: threat intelligence, remaining security/integration gates and dashboard replacement. Goal remains active; recheck Git status before checkpointing.
- Baseline and subsequent test runs are recorded in `TEST_REPORT.md`.
- November 13 checkpoint: **576 passed, zero skipped/deselected**, including live forensic storage and threat-intelligence cache. Standalone intelligence backend complete; Copilot grounding/budget feature underway. Dashboard and authentication/incident persistence remain open.
- Subsequent Copilot checkpoint: **618 passed, zero skipped/deselected** (15.57s). Grounding/limits feature verified with 71 targeted checks, including actual SDK mock transport. B012 resolved. Next feature is authentication/actor binding; no authentication code has been added yet. Worktree remains uncommitted.
- Changes remain uncommitted, including pre-existing phishing and incident-response changes.

- Latest construction checkpoint: authentication/actor binding implemented with 24 focused tests and sign-in browser checks. Dashboard now includes compact sidebar, globe Overview, corner Copilot dialog and intelligence lookup/disclosure UI. New UI remains unverified; remaining workflow pages, persistence and final combined checks remain open. This supersedes older authentication-not-started notes above.

- Dashboard construction: phishing URL/email/attachment/composite forms, reporting downloads and forensic case/evidence/custody/parser/carving workflows now wired to existing APIs. Implementation evidence only: no new build/browser/test result claimed. Incident-response and account/settings interfaces remain to implement.

- Account controls and response workflow UI now implemented. New workflow snapshot API exposes allowed transitions and current approval/action/result state. Execution remains simulated and state remains process-local; these labels must change only with authoritative backend implementation. New API/UI awaits consolidated tests.

- Response persistence migration implemented: APIs now use Postgres by default, durable claims/results and append-only analyst audit. Unit and live Postgres tests are written but unexecuted. B007 remains open until SOC incident recovery, lifecycle consistency and actual restart/concurrency verification pass.
