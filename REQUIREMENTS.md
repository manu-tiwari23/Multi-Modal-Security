# REQUIREMENTS.md

## 1. Functional Requirements

### 1.1 AI-Powered SOC
- Collect and normalize logs from multiple sources into a common event schema
- Detect threats via rule-based matching and anomaly detection
- Correlate related events across sources into a single incident
- Score and prioritize alerts by risk
- Deduplicate and route alerts to the dashboard and AI Copilot

### 1.2 AI Security Copilot
- Answer natural-language questions about security data (logs, alerts, incidents)
- Summarize incidents automatically
- Explain detected threats in plain language
- Recommend mitigation/response actions (recommendation only — never auto-executes)
- Generate draft investigation reports
- Cite the specific logs/incidents behind every answer

### 1.3 Honeypot System
- Run deceptive services that attract and log attacker interaction
- Record full attacker sessions (commands, credentials attempted, files touched)
- Publish attacker activity onto the same event pipeline as production logs
- Cluster/analyze attacker behavior for a "attacker behavior" dashboard view

### 1.4 Phishing Detection
- Analyze email headers and content for phishing indicators
- Detect suspicious URLs (reputation lookups, structural analysis)
- Analyze attachments for malicious indicators
- Produce a risk score with a human-readable explanation of contributing signals

### 1.5 Digital Forensics Toolkit
- File-level analysis and deleted file recovery
- Log analysis
- File metadata extraction
- Browser artifact analysis (history, cookies, downloads, cache)
- USB activity investigation
- Evidence integrity verification (hashing, chain of custody)
- Digital evidence collection and storage

### 1.6 Incident Investigation & Correlation
- Reconstruct attack timelines across all data sources
- Extract Indicators of Compromise (IOCs) and link them to source evidence
- Assess incident severity from combined SOC/honeypot/forensic signals

### 1.7 Threat Intelligence
- Look up IPs, domains, URLs, and file hashes against known threat data
- Classify and enrich indicators with external feed data
- Cache lookups to avoid redundant external API calls

### 1.8 Incident Response
- Recommend containment actions per incident type
- Require explicit analyst approval before executing any action
- Execute approved actions (block IP, isolate host/account) via integrations
- Track incident state (New → Investigating → Contained → Resolved → Closed)

### 1.9 Physical Alert System (ESP32)
- Receive severity/incident-type notifications via MQTT
- Drive LED indicators reflecting current system status (green/yellow/red)
- Sound a buzzer pattern on high/critical alerts
- Support a physical acknowledge button that mutes the alert and reports back to the platform

### 1.10 Centralized Dashboard & Reporting
- Real-time security overview (alerts, incidents, risk stats)
- Threat and attack timeline visualization
- Incident management interface
- Forensic investigation interface
- Automated generation of incident, forensic, and threat analysis reports

## 2. Non-Functional Requirements

| Requirement | Target |
|---|---|
| Alert latency | Detected event → dashboard alert in under a few seconds |
| Modularity | Each module independently deployable/testable |
| Auditability | Every AI-generated conclusion traceable to source data |
| Evidence integrity | Forensic evidence hash-verified on every access |
| Human oversight | No automated containment action without explicit approval |
| Data isolation | Physical alert device never receives sensitive data |

## 3. Out of Scope

Explicitly excluded from this version of the project:
- Deepfake detection (image/audio/video manipulation detection) — removed from scope
- Disk image acquisition and analysis — removed from scope
- Memory dump analysis (e.g. Volatility-style memory forensics) — removed from scope

These may be revisited later, but are not part of the current build. If reintroduced, add them back to `ARCHITECTURE.md` and this file together, and log the decision in `DECISIONS.md`.

## 4. Hardware Requirements (Physical Alert System)

- 1x ESP32 development board (Wi-Fi capable)
- 3x LEDs (green/yellow/red) or 1x RGB LED, with appropriate resistors
- 1x active buzzer module
- 1x push-button (optional, for acknowledge)
- USB or 5V power source
