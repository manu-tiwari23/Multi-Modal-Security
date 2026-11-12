# BUGS.md

Known issues tracker. Log a bug the moment you find one, even if you don't fix it immediately — don't let issues live only in memory across a session boundary.

## Open

| ID | Module | Description | Severity | Found | Notes |
|---|---|---|---|---|---|
| B006 | api/incident_response | Approval endpoints trust caller-provided analyst identity; no authenticated principal binds approval | High | 2026-11-12 | Completion gate: authenticated analyst workflow |
| B007 | api | Incidents, response actions/audits and other investigation state are process-local | High | 2026-11-12 | Completion gate: persistence and restart verification |

## Resolved

| ID | Module | Description | Severity | Found | Resolved | Fix Summary |
|---|---|---|---|---|---|---|
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
