# Multi Modal Security (MMS)

An AI-powered, integrated cybersecurity platform combining a Security Operations Center (SOC), an AI Security Copilot, a Honeypot deception system, Phishing Detection, a Digital Forensics Toolkit, Threat Intelligence, Incident Response, and a physical ESP32-based alert system — all behind one centralized real-time dashboard.

## Status

🚧 In active development. Built incrementally: one feature of one module at a time, tested before moving to the next. See `TODO.md` for current progress.

## Modules

| Module | Purpose |
|---|---|
| SOC | Real-time log collection, threat detection, correlation, alerting |
| AI Security Copilot | Natural-language investigation assistant over live security data |
| Honeypot | Deceptive services that capture and record attacker behavior |
| Phishing Detection | Email/URL/attachment analysis for phishing and social engineering |
| Digital Forensics Toolkit | File, log, metadata, browser, and USB artifact analysis |
| Incident Investigation & Correlation | Cross-source timeline reconstruction, IOC extraction |
| Threat Intelligence | IP/domain/URL/hash reputation and enrichment |
| Incident Response | Human-approved containment actions |
| Physical Alert System | ESP32 + LEDs + buzzer for ambient, real-world attack alerts |
| Dashboard & Reporting | Centralized real-time UI, automated report generation |

## Documentation

| File | Purpose |
|---|---|
| `AGENTS.md` | Rules and workflow for the AI coding agent (Antigravity) |
| `PROJECT_CONTEXT.md` | Current tech stack, status snapshot, environment setup |
| `REQUIREMENTS.md` | Full functional/non-functional requirements, in/out of scope |
| `ARCHITECTURE.md` | Full system architecture (layers, components, data flow) |
| `TODO.md` | Feature-by-feature build tracker |
| `CHANGELOG.md` | What's shipped, by date |
| `DECISIONS.md` | Why we chose what we chose (ADR log) |
| `BUGS.md` | Known issues tracker |
| `TEST_REPORT.md` | Test results per feature |
| `HOW_TO_RUN.md` | Complete guide on running, commands, demo, API, dashboard, and testing |

## Tech Stack (summary)

- **Event bus:** Redis Streams / Kafka
- **Log & alert store:** OpenSearch
- **Relational store:** PostgreSQL
- **Object storage:** MinIO
- **API layer:** FastAPI
- **Frontend:** React   
- **AI Copilot:** OpenAI API (tool-calling + RAG)
- **Physical alerts:** ESP32 + Mosquitto (MQTT)

Full details in `ARCHITECTURE.md`.

## Getting Started

See [`HOW_TO_RUN.md`](HOW_TO_RUN.md) for full instructions, commands, and options.

### Quick Start (Standalone Demo — No Docker Needed)
```bash
python demo_pipeline.py
```

### Full Infrastructure (Optional)
```bash
cp .env.example .env       # fill in API keys, ports, credentials
docker compose up -d       # brings up opensearch, postgres, minio, redis, mosquitto
uvicorn src.api.main:app --reload --port 8000   # starts API gateway
```
In another terminal:
```bash
cd src/dashboard && npm install && npm run dev  # starts React UI at http://localhost:5173
```

## Contributing / Build Process

This project is built one feature at a time:
1. Pick the next unchecked item in `TODO.md`
2. Implement it in isolation (its own module folder under `src/`)
3. Write/run tests for it (`tests/<module>/`)
4. Log the result in `TEST_REPORT.md`
5. Update `TODO.md` and `CHANGELOG.md`
6. Only then move to the next feature

See `AGENTS.md` for the full rules the AI agent follows during this process.
