# CHANGELOG.md

All notable changes to MMS are logged here, one entry per completed and tested feature. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- _(nothing yet)_

### Changed
- _(nothing yet)_

### Fixed
- _(nothing yet)_

---

## How to Add an Entry

After a feature is implemented and tested (per `TEST_REPORT.md`), add a line under the relevant heading in `[Unreleased]`:

```
### Added
- SOC: basic log ingestion service reading from sample syslog source
- Honeypot: Cowrie SSH honeypot deployed and publishing sessions to event bus
```

When you reach a meaningful milestone (e.g. "Phase 1 complete", "MVP demo-ready"), cut a dated version:

```
## [0.1.0] - 2026-08-20
### Added
- Core event pipeline: ingestion → event bus → OpenSearch → basic dashboard
```

Keep entries short — one line per feature, written for a human skimming history, not a full description (that belongs in `DECISIONS.md` if it needs explaining).
