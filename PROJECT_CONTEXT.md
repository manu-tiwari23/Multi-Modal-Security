# PROJECT_CONTEXT.md

Living document. Update this as the project evolves — it should always reflect the *current real state*, not the plan. The agent reads this at the start of every session.

_Last updated: 2026-08-22 — update this line every time you edit the file_

## Tech Stack (current, as actually implemented)

| Layer | Chosen | Notes |
|---|---|---|
| Language(s) | Python (backend services), JavaScript/React (frontend) | |
| Event bus | Redis Streams (redis:7-alpine) | Decided in D005 — see DECISIONS.md |
| Log/alert store | OpenSearch | |
| Relational store | PostgreSQL | |
| Object storage | MinIO | |
| API layer | FastAPI | |
| Frontend | React | |
| AI Copilot | OpenAI API | |
| MQTT broker | Mosquitto | |
| Containerization | Docker Compose | |

## Repository Layout

```
src/
├── soc/
├── copilot/
├── honeypot/
├── phishing/
├── forensics/
├── threat-intel/
├── incident-response/
├── alert-esp32/
├── dashboard/
tests/
├── soc/
├── copilot/
├── honeypot/
├── phishing/
├── forensics/
├── threat-intel/
├── incident-response/
├── alert-esp32/
├── dashboard/
```

_Update this if the real folder structure diverges from the plan._

## Environment / Local Setup

| Variable | Purpose | Example |
|---|---|---|
| `OPENSEARCH_URL` | OpenSearch connection | `http://localhost:9200` |
| `POSTGRES_URL` | Postgres connection | `postgresql://user:pass@localhost:5432/mms` |
| `MINIO_ENDPOINT` | Object storage | `localhost:9000` |
| `MQTT_BROKER_URL` | Mosquitto broker | `mqtt://localhost:1883` |
| `OPENAI_API_KEY` | AI Copilot | (secret, in `.env`, never committed) |
| `VT_API_KEY` | VirusTotal (threat intel) | (secret) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (threat intel) | (secret) |

_Add new variables here the moment they're introduced in code._

## External Integrations

| Service | Used by | Status |          
|---|---|---|
| VirusTotal API | Threat Intelligence module | Not yet integrated |
| AbuseIPDB API | Threat Intelligence module | Not yet integrated |
| OpenAI API | AI Copilot | Not yet integrated |
| MISP (self-hosted) | Threat Intelligence module | Deferred — see DECISIONS.md |

## Current Implementation Status (snapshot)

| Module | Status |
|---|---|
| SOC | Phase 2 complete — normalization, detection, correlation, scoring, alerting all implemented and tested (107 unit tests) |
| AI Copilot | Not started |
| Honeypot | Phase 3 complete — deceptive virtual shell, bounded recorder, Cowrie parser, event normalizer, TTP clustering, & cross-modal correlation tested (35 unit tests) |
| Phishing Detection | Not started |
| Digital Forensics | Not started |
| Threat Intelligence | Not started |
| Incident Response | Not started |
| Physical Alert (ESP32) | Not started |
| Dashboard | Phase 1 complete (live event feed) |

_Update per-module status as features land — keep this in sync with `TODO.md`, this is just the high-level view._

## Known Constraints

- SOC Correlation Engine sliding window: 300 seconds (5 minutes) per entity (`ip`, `user`, `host`, `hash`)
- Honeypot must remain network-isolated from anything real (see `AGENTS.md` guardrails)
- ESP32 receives severity/type metadata only, never raw data
- All containment actions require human approval — no fully autonomous response
