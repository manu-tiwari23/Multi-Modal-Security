# BUGS.md

Known issues tracker. Log a bug the moment you find one, even if you don't fix it immediately — don't let issues live only in memory across a session boundary.

## Open

- Pipeline audit: old Redis cursor loss path replaced with consumer-group retries/reclaim/quarantine; verification pending. Multi-worker WebSocket fan-out and replay-stable shared detection are now implemented; live verification remains pending.

| ID | Module | Description | Severity | Found | Notes |
|---|---|---|---|---|---|
| B006 | api/incident_response | Approval endpoints trust caller-provided analyst identity; no authenticated principal binds approval | High | 2026-11-12 | Completion gate: authenticated analyst workflow |
| B007 | api | Incidents, response actions/audits and other investigation state are process-local | High | 2026-11-12 | Completion gate: persistence and restart verification |

## Resolved

- AbuseIPDB non-IP routing (2026-11-14): domain/URL/hash lookups displayed an unsupported card with a misleading Observed timestamp. Skip incompatible provider routing and show applicability guidance; five new routing regressions pass.

- B017 follow-up (2026-11-14): initial fix missed Overview. Removed shared `.recharts-wrapper` max-width constraint; the zero-width measuring parent is intentional Recharts structure, not a hidden-mount failure. Actual Overview component verified visually with synthetic events.

- Dashboard synthetic empty-state telemetry (2026-11-14): removed generated activity curves and placeholder totals. Topology demo nodes are explicitly labelled simulated and excluded from observed counts; browser/build verification passed.

| ID | Module | Description | Severity | Found | Resolved | Fix Summary |
|---|---|---|---|---|---|---|
| B017 | dashboard/simulation | Recent activity and Severity Breakdown contained data but rendered blank because the Recharts measuring wrapper remained 0x0 after opening the initially hidden view | Medium | 2026-11-14 | 2026-11-14 | Scoped the internal measuring wrapper to the chart canvas dimensions; build and authenticated visual QA confirm non-zero, visible SVGs |
| B016 | dashboard/simulation/intelligence | Demo nodes disappeared after tab changes, lacked IP/telemetry, Simulation Lab omitted analytics, and bundled intelligence examples returned unexplained unknown results | Medium | 2026-11-14 | 2026-11-14 | Persisted reserved-IP nodes, published synthetic node events, added activity/severity/phishing analytics, and introduced an explicitly synthetic four-indicator local demo dataset |
| B015 | documentation/runtime | Windows guide called Docker optional, omitted first-account setup, depended on shell activation, and showed unauthenticated protected API calls | High | 2026-11-14 | 2026-11-14 | Reproduced storage 503; documented and verified infrastructure health, direct venv Python startup, account creation, authenticated simulation and troubleshooting |
| B012 | copilot | Deterministic incident/honeypot answers invented attack stages and used a default example IP | High | 2026-11-13 | 2026-11-13 | Evidence-first local facts and validated model fact selection; missing indicator requests clarification; 71 mocked/unit/API checks pass |
| B013 | copilot/intelligence | Mock reputation entries were presented as factual attribution, including an empty-file hash labeled malware | High | 2026-11-13 | 2026-11-13 | Removed fabricated database; provider-backed/cached or explicitly unknown results, no fabricated honeypot reputation score; 61 targeted checks pass |
| B014 | forensics | Invalid browser timestamps were replaced with current time | Medium | 2026-11-13 | 2026-11-13 | Preserve unknown timestamps and omit undated records from timelines; workflow tests cover it |
| B011 | api/tests | Event query `total` equaled page length; live API test assumed 20 pre-existing events | Medium | 2026-11-12 | 2026-11-12 | Correct total hits/count semantics for OpenSearch and memory; seed/clean a unique test index; six targeted checks pass |
| B008 | forensics | Encoded command-marker detection silently failed due to `.encode()` on bytes | Medium | 2026-11-12 | 2026-11-12 | Compare bytes directly; inert positive/negative fixtures pass |
| B009 | forensics | Callers could bypass hash verification; restoring bytes silently cleared prior tamper flags | High | 2026-11-12 | 2026-11-12 | Reject disabled verification, retain historical tamper state and block analysis pending reacquisition; regression tests pass |
| B010 | api | `/api/incidents` called nonexistent `get_active_incidents()` and failed at runtime | High | 2026-11-12 | 2026-11-12 | Use public `active_incidents` property; API regression passes |
| B005 | copilot/reporting | Incident report invented attack stages regardless of evidence | High | 2026-11-12 | 2026-11-12 | Replaced narrative with observed events, citations and validation limits; added regression test |
| B001 | api | `test_api_e2e` health assertion failed on enriched metrics payload and lacked live OpenSearch ping guard | Low | 2026-10-04 | 2026-10-04 | Validated specific health keys and added OpenSearch ping skip guard |
| B002 | api | Duplicate return block in /api/simulate/attack endpoint | Low | 2026-10-04 | 2026-10-04 | Removed duplicated unreachable return block in simulate_attack handler |
| B003 | phishing | `URLScanner.to_security_event` passed unmapped `safe` severity to `SecurityEvent`, causing Pydantic validation failure | Medium | 2026-10-06 | 2026-10-06 | Added severity mapping (`SAFE` -> `low`) and removed invalid `url` field from `Entity` |
| B004 | phishing | Unescaped non-ASCII Cyrillic homoglyphs in lookalike evidence caused `UnicodeEncodeError` on Windows consoles | Medium | 2026-10-06 | 2026-10-06 | Enforced `safe_ascii()` unicode codepoint escaping across all lookalike signal descriptions and evidence |

---

## Severity Guide

| Severity | Meaning |
|---|---|
| Critical | Breaks core pipeline / data loss / security hole in the platform itself |
| High | Feature doesn't work as required, blocks dependent work |
| Medium | Feature works but has edge-case failures |
| Low | Cosmetic, minor, or non-blocking |

## How to Log a Bug

```
| B001 | soc | Correlation engine doesn't dedupe alerts from the same source within 1s window | Medium | 2026-08-20 | Needs a debounce; see event bus consumer loop |
```

Move it to the "Resolved" table with a one-line fix summary once fixed, and reference the bug ID in the relevant `CHANGELOG.md` entry.
