# BUGS.md

Known issues tracker. Log a bug the moment you find one, even if you don't fix it immediately — don't let issues live only in memory across a session boundary.

## Open

| ID | Module | Description | Severity | Found | Notes |
|---|---|---|---|---|---|
| _(none yet)_ | | | | | |

## Resolved

| ID | Module | Description | Severity | Found | Resolved | Fix Summary |
|---|---|---|---|---|---|---|
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
