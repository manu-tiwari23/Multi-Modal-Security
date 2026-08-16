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

## D005 — Event bus choice: Redis Streams vs Kafka

**Date:** [fill in when decided]
**Decision:** [Redis Streams / Kafka — pending]
**Why:** [fill in — e.g. Redis Streams is lighter for project scale; Kafka chosen if demonstrating production-grade infra is a goal]
**Status:** Open — resolve before Phase 1 ingestion work begins, then update `PROJECT_CONTEXT.md`

---

## Template for New Entries

```
## D0XX — [short title]

**Date:** YYYY-MM-DD
**Decision:** [what was decided]
**Why:** [reasoning, alternatives considered if relevant]
**Status:** [Final / Open / Superseded by D0XX]
```
