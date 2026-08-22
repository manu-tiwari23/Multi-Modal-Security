# DECISIONS.md

Architecture Decision Record (ADR) log. Every non-obvious technical or scope choice gets an entry here — this is what lets a future session (or a future you) understand *why* the code looks the way it does, not just what it does.

Format: one entry per decision, newest at the bottom.

---

## D001 — Project renamed to Multi Modal Security (MMS)

**Date:** 2026-08-16
**Decision:** The project is officially named "Multi Modal Security (MMS)."
**Why:** Reflects that the platform pulls signal from multiple modalities (network logs, honeypot sessions, email/phishing content, forensic artifacts, physical alerts) into one system.
**Status:** Final

---

## D002 — Deepfake detection removed from scope

**Date:** 2026-08-16
**Decision:** Image manipulation, AI-generated audio, and AI-generated video detection are removed from the current build.
**Why:** Scope reduction to focus build effort on the core SOC/Copilot/Honeypot/Forensics/Phishing pipeline first. Phishing detection (email/URL/attachment) remains in scope.
**Status:** Final for this version — see `REQUIREMENTS.md` §3 if revisited later.

---

## D003 — Disk image and memory dump forensics removed from scope

**Date:** 2026-08-16
**Decision:** Full disk image acquisition/analysis and memory dump analysis (e.g. Volatility) are removed. Forensics module now covers file-level analysis, logs, metadata, browser artifacts, and USB activity only.
**Why:** Scope reduction — disk/memory forensics requires significantly more tooling and time than file-level forensics for comparable learning/demo value.
**Status:** Final for this version.

---

## D004 — ESP32 physical alert system added

**Date:** 2026-08-16
**Decision:** Added a hardware alert module (ESP32 + LEDs + buzzer) that receives severity-only notifications over MQTT and provides an ambient physical signal of attack status.
**Why:** Gives the platform a tangible, demoable output beyond the dashboard; useful for a lab/demo setting.
**Constraint:** The ESP32 must never receive raw logs, evidence, or credentials — severity/type metadata only, to keep it a low-risk add-on (see `AGENTS.md` guardrails).
**Status:** Final

---

## D005 — Event bus choice: Redis Streams

**Date:** 2026-08-17
**Decision:** Redis Streams (not Kafka).
**Why:** Single container (redis:7-alpine) vs Kafka + ZooKeeper/KRaft. Sufficient throughput for the project's single-host, demo/portfolio scale. Simpler consumer-group API for Python services. Redis is also useful as a cache/session store later.
**Status:** Final

---

## D006 — Python runtime: Windows CPython 3.11

**Date:** 2026-08-17
**Decision:** Use Windows-native CPython 3.11 (`C:\Users\manut\AppData\Local\Programs\Python\Python311`) for the venv, not the MSYS2/MinGW Python 3.14 that's first on PATH.
**Why:** MSYS2 Python can't build Rust-based wheels (pydantic-core, watchfiles) — the `maturin` build backend reports "Unsupported platform: mingw_x86_64_ucrt_gnu". CPython 3.11 has pre-built wheels for all deps.
**Status:** Final

---

## D007 — Sigma-style YAML detection rules & sliding-window threshold tracking

**Date:** 2026-08-22
**Decision:** Store detection rules as declarative Sigma-style YAML files in `src/soc/rules/` with standard field modifiers (`|contains`, `|re`, `|startswith`, `|endswith`, `|in`) and MITRE ATT&CK tagging. Support both immediate single-event conditions and sliding-window threshold aggregations (`count` within `timeframe` grouped by entity fields).
**Why:** Keeps detection rules data-driven and easily extensible without modifying Python code. Enables security analysts to author, hot-reload, and test new detection patterns independently.
**Status:** Final

---

## D008 — Sliding-window entity correlation (300s default window)

**Date:** 2026-08-22
**Decision:** The Correlation Engine maintains active incidents in memory and links incoming `SecurityEvent` and `RuleMatch` objects across multi-modal sources using a configurable 300-second (5 minutes) sliding window per entity key (`ip`, `user`, `host`, `hash`). Incident severity dynamically escalates to the highest severity observed across all correlated events, and attack progression is maintained as a chronologically sorted `IncidentTimelineEntry` list.
**Why:** Automatically groups distributed attack stages (e.g. brute force auth failure -> successful logon -> privilege escalation) into a coherent, single incident investigation unit without alert fragmentation.
**Status:** Final

---

## D009 — Transparent weighted risk scoring formula

**Date:** 2026-08-22
**Decision:** Risk scoring uses a documented additive weighted formula: Base Severity (10/25/50/75) + Event Frequency (log2 scale, capped at 10) + MITRE Technique Breadth (3 pts each, capped at 15) + Critical User Bonus (8 for root/admin/system) + Critical Host Bonus (5 for prod/dc/firewall hosts) + Threat Intel Match (7) + Multi-Source Correlation (5). Clamped to 0–100. Every component is recorded in a `ScoreBreakdown` dataclass with `to_dict()` and `explain()` methods for full analyst transparency.
**Why:** ARCHITECTURE.md §4.1 and SOC SKILL.md require an explainable, auditable scoring formula — analysts must see *why* a score is what it is, not just the number. An additive weighted sum (vs a black-box model) satisfies this with clear documentation.
**Status:** Final

---

## D010 — Alert Manager deduplication and priority bucketing strategy

**Date:** 2026-08-22
**Decision:** Alert Manager deduplicates by `incident_id` — if the same incident produces a new rule match or additional events, the existing alert is updated rather than creating a duplicate. Priority uses fixed score thresholds: ≥80 → P1-critical, ≥50 → P2-high, ≥25 → P3-medium, <25 → P4-low. A configurable `min_score_to_alert` (default 15.0) suppresses noise from benign low-severity events. Publishing to Redis Streams / OpenSearch / dashboard is done via a pluggable `on_alert(alert, is_new)` callback.
**Why:** SOC analysts need stable, deduplicated alerts rather than a flood of notifications per-event. The callback pattern allows the alert manager to remain infrastructure-agnostic — unit-testable without Redis/OpenSearch.
**Status:** Final

---

## Template for New Entries

```
## D0XX — [short title]

**Date:** YYYY-MM-DD
**Decision:** [what was decided]
**Why:** [reasoning, alternatives considered if relevant]
**Status:** [Final / Open / Superseded by D0XX]
```
