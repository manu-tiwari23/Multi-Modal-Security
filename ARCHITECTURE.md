# Multi Modal Security (MMS)
## System Architecture Document

**Version:** 1.0
**Date:** August 2026
**Status:** Draft for Development

---

## 1. Executive Summary

This document defines the system architecture for **Multi Modal Security (MMS)**, an integrated cybersecurity platform that unifies six major capabilities into a single system: a Security Operations Center (SOC), an AI Security Copilot, a Honeypot deception system, Phishing Detection, a Digital Forensics Toolkit, and centralized Incident Response and Reporting. It also includes an optional ESP32-based physical alert system (LEDs + buzzer) that gives analysts an ambient, real-world signal when an attack is detected.

The platform is designed around a **modular, event-driven microservices architecture**. Each capability is built as an independently deployable service that communicates through a shared event bus and shared data stores, rather than through direct service-to-service calls. This allows MMS to be built and demonstrated incrementally, keeps each module testable in isolation, and avoids the common failure mode of "integrated platform" projects where every component becomes tightly coupled to every other component.

---

## 2. Goals and Design Principles

**Primary goals**
- Detect, investigate, and respond to security threats in near real time
- Provide analysts with an AI copilot that can reason over live security data in natural language
- Capture attacker behavior safely via deception (honeypot) infrastructure
- Detect AI-generated phishing content and social-engineering attacks
- Support full digital forensic investigation from raw evidence to final report
- Present all of the above through one real-time dashboard

**Design principles**

| Principle | Why it matters here |
|---|---|
| Loose coupling via events | 6 modules built by possibly different people/times shouldn't block each other |
| Single source of truth for logs | All modules read/write the same log & alert store — no duplicated pipelines |
| Human-in-the-loop for response actions | Automated containment must be analyst-approved, never fully autonomous |
| Evidence integrity | Forensic data must be tamper-evident (hashing, chain of custody) from the moment it's collected |
| Incremental buildability | Every phase of the build should produce something demoable on its own |
| Explainability | Every AI-generated verdict (phishing score, risk score) must show *why*, not just a number |

---

## 3. High-Level Architecture

The system is organized into five horizontal layers. Data flows upward from collection to presentation, while control/response actions flow downward from the analyst through the API layer.

```
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 5 — PRESENTATION                                          │
│  Centralized Dashboard (React)  |  AI Copilot Chat Interface     │
└──────────────────────────────────────────────────────────────────┘
                          ▲                     │
                          │ REST/WebSocket       │ commands
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 4 — API / ORCHESTRATION                                   │
│  FastAPI Gateway  |  Auth/RBAC  |  Response Orchestrator          │
└──────────────────────────────────────────────────────────────────┘
                          ▲                     │
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 3 — ANALYSIS & INTELLIGENCE SERVICES                      │
│  SOC Correlation Engine │ AI Copilot (RAG+LLM) │ Phishing        │
│  Detector │ Forensics Toolkit │ Threat Intel Enrichment          │
└──────────────────────────────────────────────────────────────────┘
                          ▲
                          │ publish/subscribe
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 2 — EVENT BUS / STREAM (Kafka or Redis Streams)           │
└──────────────────────────────────────────────────────────────────┘
                          ▲
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 1 — INGESTION & COLLECTION                                │
│  Log Shippers │ Honeypot Sensors │ Network Sniffers │             │
│  Email/File Intake │ Forensic Evidence Intake                    │
└──────────────────────────────────────────────────────────────────┘
```

**Persistent stores sit beside Layers 1–3** (not shown as a layer since every module touches them):
- **OpenSearch/Elasticsearch** — logs, alerts, full-text search, time-series data for the dashboard
- **PostgreSQL** — structured data: users, incidents, cases, IOC records, chain-of-custody metadata
- **Object storage (MinIO/S3-compatible)** — raw evidence: PCAPs, email files, attachments, forensic artifacts
- **Vector store (e.g. pgvector or Qdrant)** — embeddings of logs/incidents/knowledge base for the AI Copilot's RAG retrieval

---

## 4. Component Breakdown

### 4.1 AI-Powered SOC

| Sub-component | Responsibility |
|---|---|
| Log Collector | Normalizes logs from endpoints, network devices, cloud services into a common schema (ECS-style) |
| Detection Engine | Sigma/YARA-style rule matching + anomaly detection models over the log stream |
| Correlation Engine | Groups related events across sources into a single incident using entity linking (IP, user, host, hash) |
| Risk Scoring | Weighted scoring model combining rule severity, asset criticality, and threat intel matches |
| Alert Manager | Deduplicates, prioritizes, and routes alerts to the dashboard and copilot |

**Data flow:** Log Collector → Event Bus → Detection Engine → Correlation Engine → Alert Manager → OpenSearch (alerts index) → Dashboard

### 4.2 AI Security Copilot

| Sub-component | Responsibility |
|---|---|
| Retrieval Layer (RAG) | Pulls relevant logs, past incidents, and threat intel from OpenSearch/vector store based on the analyst's question |
| LLM Orchestrator | Sends retrieved context + conversation history to the LLM (OpenAI API) with tool definitions |
| Tool Layer | Callable functions: query_logs(), get_incident(), lookup_ioc(), run_correlation(), draft_report() |
| Response Composer | Formats the LLM's answer with citations back to the specific logs/incidents it used |

The copilot **never executes containment actions directly** — it can only *recommend* them. Recommendations are passed to the Response Orchestrator (Layer 4), which requires analyst approval before execution. This is a hard boundary, not a configuration option — see Section 8.

### 4.3 Honeypot System

| Sub-component | Responsibility |
|---|---|
| Deception Services | Low/medium-interaction fake services (SSH, HTTP, SMB, RDP) — e.g. Cowrie, or a custom set for services relevant to your demo |
| Session Recorder | Captures full attacker sessions: commands typed, files uploaded, credentials attempted |
| Sensor Feed | Publishes every interaction as an event onto the bus, tagged `source: honeypot` |
| Behavior Analyzer | Clusters attacker sessions by TTPs (tactics/techniques) for the dashboard's attacker-behavior view |

Honeypot events flow through the **same event bus and log schema** as production logs, so the SOC correlation engine and AI Copilot can reason over them identically — this is what makes the honeypot "integrated" rather than a bolted-on separate tool.

### 4.4 Phishing Detection

| Sub-component | Responsibility |
|---|---|
| Email Analyzer | Header analysis, sender reputation, NLP-based social-engineering language detection |
| URL/Attachment Scanner | Sandboxed detonation or static analysis + reputation lookups (VirusTotal/AbuseIPDB) |
| Explanation Generator | Converts model confidence scores into human-readable reasoning (which signals fired) |

Each detector is a **stateless scoring microservice**: input → score + explanation. This makes them easy to swap out or upgrade (e.g. replacing a classifier with a newer pretrained model) without touching the rest of the platform.

### 4.5 Digital Forensics Toolkit

| Sub-component | Responsibility |
|---|---|
| Evidence Intake | Hashes (SHA-256) and stores raw evidence immediately on upload; starts chain-of-custody record |
| File Analysis | Filesystem-level parsing and deleted file recovery on collected files/logs |
| Metadata Extraction | ExifTool and custom parsers for file/document metadata |
| Browser Artifact Analysis | History, cookies, downloads, cache parsing per browser |
| USB Activity Analysis | Registry/log parsing for device insertion history (Windows) |
| Integrity Verifier | Continuously re-validates evidence hashes; flags any discrepancy |

Forensics is the most self-contained module — it can be built and tested independently of the live SOC pipeline, using static evidence files, which is why it's positioned last in the build roadmap.

### 4.6 Incident Investigation & Correlation

Sits above the SOC and Forensics modules. Takes alerts, honeypot sessions, and forensic findings and builds:
- A unified **attack timeline** (chronological, cross-source)
- **IOC extraction** (IPs, domains, hashes, file paths) linked back to source evidence
- **Severity assessment** combining SOC risk score + forensic findings + threat intel

### 4.7 Threat Intelligence

A thin enrichment service: given an IP, domain, URL, or hash, queries internal historical data plus external feeds (MISP self-hosted instance, VirusTotal, AbuseIPDB) and returns a classification + confidence. Cached in PostgreSQL to avoid repeat external calls.

### 4.8 Incident Response

| Sub-component | Responsibility |
|---|---|
| Response Recommender | Suggests containment actions based on incident type (block IP, isolate host, disable account) |
| Action Executor | Executes approved actions via integrations (firewall API, EDR API, IAM API) |
| Approval Workflow | Requires an analyst to explicitly approve before Action Executor runs anything |
| Incident Tracker | State machine: New → Investigating → Contained → Resolved → Closed |

### 4.9 Centralized Dashboard & Reporting

React front end consuming the API Gateway over REST (for queries) and WebSocket (for live alert/incident updates). Reporting service assembles incident/forensic/threat data into structured PDF/HTML reports on demand, using the same data the dashboard displays — so reports are always consistent with what analysts saw live.

### 4.10 Physical Alert System (ESP32 IoT Alerting)

A small hardware add-on that gives analysts a **physical, ambient signal** when the platform detects an attack — useful for a lab/demo setting where you want a visible or audible cue without staring at the dashboard.

| Sub-component | Responsibility |
|---|---|
| Alert Notifier Service | Subscribes to high/critical severity alerts on the event bus; publishes a lightweight notification (severity + incident type only, no sensitive data) to an MQTT topic |
| MQTT Broker | Message broker (e.g. Mosquitto) sitting between the platform and the ESP32 — decouples the alert system from the ESP32's availability |
| ESP32 Firmware | Connects to Wi-Fi, subscribes to the MQTT topic, drives LEDs and buzzer based on the message received |
| LED Indicators | Multi-color LED (or 3 separate LEDs: green/yellow/red) reflecting current system status — green = normal, yellow = medium/low alert, red = high/critical |
| Buzzer | Sounds a pattern on high/critical alerts only, to avoid alert fatigue from lower-severity events |
| Acknowledge Button (optional) | Physical push-button on the ESP32; pressing it publishes an "acknowledged" message back over MQTT, which the platform uses to mute the buzzer and mark the alert as seen |

**Data flow**

```
SOC Alert Manager / Correlation Engine
        │  (alert: severity=critical)
        ▼
Alert Notifier Service
        │  publish → topic: alerts/status
        ▼
MQTT Broker (Mosquitto)
        │  subscribe
        ▼
ESP32 (Wi-Fi client)
        │
        ├─► LEDs: red solid/blinking (severity-based pattern)
        └─► Buzzer: tone pattern (critical only)
        │
        ▼ (button press)
Publish → topic: alerts/ack ──► Alert Notifier Service ──► marks alert acknowledged
```

**Example message payload published to the ESP32:**

```json
{
  "severity": "critical",
  "incident_type": "brute_force",
  "source": "honeypot",
  "timestamp": "2026-08-13T10:15:00Z"
}
```

The ESP32 only ever receives this small status payload — never raw logs, IOCs, or evidence — so even if the device or its Wi-Fi network is compromised, it can't leak sensitive investigation data. This keeps it a genuinely optional, low-risk add-on rather than a new attack surface into the core platform.

**Suggested LED/buzzer behavior**

| System state | Green LED | Yellow LED | Red LED | Buzzer |
|---|---|---|---|---|
| Normal | On (steady) | Off | Off | Silent |
| Low/Medium alert | Off | On (steady) | Off | Silent |
| High alert | Off | Off | Blinking (slow) | Short beep every 5s |
| Critical alert | Off | Off | Blinking (fast) | Continuous pattern until acknowledged |

**Hardware**
- ESP32 dev board (Wi-Fi + Bluetooth, plenty of GPIO for this use case)
- 3x LEDs (green/yellow/red) with current-limiting resistors, or a single RGB LED
- Active buzzer module
- Optional push-button for acknowledge
- Powered via USB or a 5V supply; sits on the analyst's desk as a physical status indicator

---

## 5. Data Architecture

**Common event schema** (all modules normalize into this before publishing to the bus):

```
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "source": "soc | honeypot | phishing | forensics | threat_intel",
  "entity": { "ip": "", "user": "", "host": "", "hash": "" },
  "event_type": "string",
  "severity": "low | medium | high | critical",
  "raw": { ... },
  "enrichment": { ... }
}
```

Using one schema across all modules is what lets the correlation engine and AI Copilot query across the entire system with a single interface, instead of writing source-specific parsers for each module.

**Storage responsibilities**

| Store | Holds |
|---|---|
| OpenSearch | All normalized events, alerts, honeypot sessions — optimized for search/time-series dashboards |
| PostgreSQL | Incidents, cases, users/roles, IOC registry, chain-of-custody records, response action log |
| Object Storage | Raw evidence: PCAPs, email files, media attachments, collected forensic files |
| Vector Store | Embeddings of past incidents + knowledge base articles for Copilot retrieval |

---

## 6. Technology Stack Summary

| Layer | Recommended Stack |
|---|---|
| Ingestion | Filebeat/Fluentd, custom Python agents, Cowrie/T-Pot for honeypot |
| Event Bus | Redis Streams (lightweight) or Kafka (if scaling matters for the demo) |
| Log/Alert Store | OpenSearch |
| Relational Store | PostgreSQL |
| Object Store | MinIO |
| Detection/ML | Python — scikit-learn, PyTorch, pretrained phishing/NLP models |
| Forensics | File/log parsing utilities, ExifTool |
| Threat Intel | MISP (self-hosted), VirusTotal API, AbuseIPDB API |
| AI Copilot | OpenAI API with tool-calling + RAG over OpenSearch/vector store |
| API Layer | FastAPI (Python) |
| Frontend | React + Recharts/D3, WebSocket client |
| Auth | JWT-based, RBAC (analyst / senior analyst / admin roles) |
| Containerization | Docker + Docker Compose (or Kubernetes if scaling beyond a single host) |
| Physical Alerting | ESP32 (Arduino/C++ firmware, PubSubClient MQTT library), Mosquitto MQTT broker |

---

## 7. AI Copilot Architecture Detail

```
Analyst question
      │
      ▼
Retrieval Layer ──► Vector Store (past incidents, KB)
      │              OpenSearch (recent logs/alerts)
      ▼
Context Assembly (question + retrieved data + conversation history)
      │
      ▼
LLM Orchestrator (OpenAI API, tool-calling enabled)
      │
      ├─► Tool: query_logs(filters)
      ├─► Tool: get_incident(id)
      ├─► Tool: lookup_ioc(value)
      └─► Tool: draft_report(incident_id)
      │
      ▼
Response Composer (adds citations to source logs/incidents)
      │
      ▼
Analyst sees answer + linked evidence
```

Every tool call and every piece of retrieved context is logged, so any AI-generated conclusion in an incident report can be traced back to the exact data that produced it — important both for analyst trust and for forensic defensibility of the report itself.

---

## 8. Security & Trust Boundaries

Because MMS *is* a security product, its own security posture matters:

- **Human-in-the-loop enforcement**: the Action Executor (Section 4.8) is the only component permitted to call external containment APIs, and it hard-rejects any request lacking an analyst approval record — the AI Copilot has no code path that bypasses this.
- **RBAC everywhere**: forensic evidence and raw honeypot capture data are restricted beyond standard analyst read access, given their sensitivity.
- **Evidence integrity**: all forensic evidence is hashed on intake and re-verified on every access; any mismatch halts the investigation workflow and flags it.
- **Isolated honeypot network**: honeypot services must run in a network segment with no route to production systems or the internet beyond what's needed to appear convincing, to prevent it becoming a pivot point.
- **Audit logging**: every dashboard action, AI Copilot query, and response action is logged immutably (append-only) in PostgreSQL for later review.
- **IoT alert isolation**: the MQTT broker used by the ESP32 requires authentication (and TLS if reachable beyond the local network); the Alert Notifier Service only ever publishes severity/type metadata to it, never raw logs or evidence, so the physical alert device cannot become a data-leak or pivot point.

---

## 9. Deployment Architecture

For a project of this scope, Docker Compose is sufficient to demonstrate the full system on a single host; Kubernetes is a natural upgrade path if you need horizontal scaling later.

```
docker-compose services:
  - api-gateway (FastAPI)
  - soc-engine
  - copilot-service
  - honeypot-cowrie
  - phishing-detector
  - forensics-toolkit
  - threat-intel
  - response-orchestrator
  - alert-notifier
  - mosquitto (MQTT broker)
  - frontend (React, served via Nginx)
  - opensearch
  - postgres
  - minio
  - redis (event bus)
```

The ESP32 itself is not a container — it's a physical device on the same network (or reachable over the internet if the broker is exposed securely) that connects to the `mosquitto` broker as an MQTT client.

Each analysis service is its own container so it can be scaled, restarted, or replaced independently — e.g. swapping the phishing detector's model doesn't require touching the SOC engine.

---

## 10. Build Roadmap

| Phase | Deliverable | Depends on |
|---|---|---|
| 1 | Log ingestion → event bus → OpenSearch → basic dashboard | Nothing — proves the core pipeline |
| 2 | SOC detection + correlation engine + alerting | Phase 1 |
| 3 | Honeypot feeding into the same pipeline | Phase 1 |
| 4 | AI Copilot with RAG + tool-calling over live data | Phase 1–2 (needs real data to query) |
| 5 | Phishing detection service | Independent — can be built in parallel with 2–4 |
| 6 | Forensics toolkit (mostly standalone, static-evidence based) | Independent — can be built in parallel |
| 7 | Incident response orchestrator + approval workflow | Phase 2 |
| 8 | Automated reporting | Phases 2, 4, 6 |
| 9 | ESP32 physical alert system (LEDs + buzzer) | Phase 2 (needs alerts to subscribe to) |

Phases 5, 6, and 9 have no hard dependency on each other, so if you're working with a team, they can be built concurrently with the SOC/Copilot track. Phase 9 is a good "fun add-on" to build last — it's a small, self-contained piece of firmware once the alert pipeline exists.

---

## 11. Open Design Decisions

A few choices are left for you to lock in based on scope/timeline, since they materially affect build effort:

- **Kafka vs. Redis Streams** — Kafka is more "production-grade" for a resume/demo but adds real operational overhead; Redis Streams is enough to prove the architecture for most academic/portfolio purposes.
- **Self-hosted MISP vs. API-only threat intel** — self-hosting MISP is a bigger lift; using VirusTotal/AbuseIPDB APIs directly is faster to demo.
- **Local ML models vs. pretrained third-party APIs** for phishing detection — training your own NLP classifier is more impressive but far more time-consuming than integrating existing open-source pretrained models.
- **Kubernetes vs. Docker Compose** — only worth it if you specifically want to demonstrate orchestration/scaling skills.

