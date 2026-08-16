# BUGS.md

Known issues tracker. Log a bug the moment you find one, even if you don't fix it immediately — don't let issues live only in memory across a session boundary.

## Open

| ID | Module | Description | Severity | Found | Notes |
|---|---|---|---|---|---|
| _(none yet)_ | | | | | |

## Resolved

| ID | Module | Description | Severity | Found | Resolved | Fix Summary |
|---|---|---|---|---|---|---|
| _(none yet)_ | | | | | | |

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
