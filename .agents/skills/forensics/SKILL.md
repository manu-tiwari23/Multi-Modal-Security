---
name: forensics-module
description: Use when implementing or modifying anything under src/forensics/ — evidence intake, file analysis, metadata extraction, browser artifacts, or USB activity investigation.
---

## Conventions

- Every piece of evidence gets SHA-256 hashed **immediately on intake**, before any analysis touches it, and a chain-of-custody record starts at that moment (who/what uploaded it, when, original hash).
- Re-verify the hash on every subsequent access — if it doesn't match, halt the investigation workflow and flag it rather than silently continuing.
- Scope is **file-level forensics only** — file analysis, deleted file recovery at the filesystem level, metadata, browser artifacts, USB activity logs. Disk image acquisition and memory dump analysis are explicitly out of scope (see `DECISIONS.md` D003) — do not add Volatility or full disk-imaging tooling without a new decision entry.
- Evidence files themselves go in object storage (MinIO); only metadata, hashes, and chain-of-custody records go in Postgres.

## Testing Approach

- Unit test: hashing + chain-of-custody record creation on intake
- Unit test: integrity re-verification catches a deliberately corrupted test file
- Integration test: metadata extraction against sample files with known metadata (confirm extracted values match)
- Manual test: browser artifact parser against a sample browser profile directory

## Gotchas

- Never modify evidence files in place — always work on a copy, keep the original untouched to preserve integrity.
- Be careful with timezone handling in metadata/log timestamps — forensic timelines depend on getting this right.
