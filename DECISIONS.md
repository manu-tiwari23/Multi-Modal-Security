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

## D011 — Deceptive Honeypot Architecture: Sandboxed Emulation, Normalization, and TTP Clustering

**Date:** 2026-08-22
**Decision:** The Honeypot module operates on three decoupled layers:
1. **Deception & Ingestion**: A sandboxed virtual shell (`VirtualShell`) that emulates Linux command responses (`uname`, `whoami`, `cat /etc/passwd`, `wget`, etc.) without executing host binaries, paired with a memory-bounded `SessionRecorder` (limiting active sessions, max commands, and credentials) and a `CowrieLogParser` for real Cowrie JSON feeds.
2. **Canonical Normalization**: Maps honeypot interactions into standard `SecurityEvent` models (`source: "honeypot"`) with MITRE ATT&CK technique tags (`T1110`, `T1059`, `T1105`, `T1082`, `T1548.003`), flowing into the unified event bus (`events:raw`).
3. **Behavior Analysis**: Downstream `BehaviorAnalyzer` clusters attacker sessions by TTP categories and maps attackers to campaign archetypes (`Automated Dropper`, `Interactive Recon`, `Targeted Multi-Stage`, `Credential Brute Force`).
**Why:** Complies with `AGENTS.md` and `SKILL.md` strict safety requirements (honeypot isolated from real hosts/credentials), guarantees honeypot events flow through the same pipeline as SOC logs, and unlocks cross-modal correlation bonuses (+5.0) in the SOC risk scoring engine.
**Status:** Final

---

## D012 — AI Copilot RAG, OpenAI Tool Calling, and Human-in-the-Loop Containment Boundary

**Date:** 2026-08-22
**Decision:** The AI Security Copilot implements a strict Retrieval-Augmented Generation (RAG) and tool-calling architecture:
1. **Multi-Source Retrieval**: Queries OpenSearch (with in-memory fallback), SOC correlation incident records, and honeypot attacker sessions before answering.
2. **Explicit Tool Specs**: Exposes `query_logs`, `get_incident`, `lookup_ioc`, `run_correlation`, and `draft_report` with strict JSON schemas.
3. **Evidence Grounding & Citations**: Every tool execution yields structured `Citation` records (`[EVENT]`, `[INCIDENT]`, `[IOC]`) attached to the response.
4. **Hard Containment Boundary**: Copilot can only *recommend* containment actions (`requires_approval: true`). It has zero direct execution path to firewall/EDR APIs, and strictly rejects adversarial prompt attempts to bypass analyst authorization.
5. **Deterministic Offline Engine**: When `OPENAI_API_KEY` is not provided, the Copilot falls back to an intelligent local security reasoning engine that executes real tools and produces grounded answers, ensuring full testability and demo capabilities offline.
**Why:** Aligns with `ARCHITECTURE.md` §4.2, §7, §8 and `.agents/skills/copilot/SKILL.md`. Security platforms must provide defensible, auditable evidence for conclusions and never permit autonomous unchecked containment.
**Status:** Final

---

## D013 — Python Runtime Upgrade to CPython 3.12 (.venv312)

**Date:** 2026-10-04
**Decision:** Updated the Python execution environment to Windows CPython 3.12 (`C:\Users\manut\AppData\Local\Programs\Python\Python312\python.exe`) using `.venv312`.
**Why:** The host's Python 3.11 binaries were upgraded to 3.12, causing `.venv` to point to a missing executable. All dependencies and wheels (`fastapi`, `pydantic`, `watchfiles`, `psycopg2-binary`, `redis`, `opensearch-py`) install cleanly and all 180 unit tests pass under Python 3.12.
**Status:** Final

---

## D014 — Tamper-Evident Evidence Vault, Dual Cryptographic Hashing, and Mandatory Halt on Access Mismatch

**Date:** 2026-10-04
**Decision:** In the Digital Forensics module (`src/forensics/`):
1. **Intake Hashing**: Evidence is hashed with streaming SHA-256 and MD5 immediately upon upload/intake before any parsing, indexing, or storage.
2. **Access Re-verification**: Every subsequent access through `get_evidence_bytes()` or `export_evidence_copy()` recalculates the SHA-256 checksum and compares against the recorded intake hash. If a mismatch is detected, the workflow immediately halts with an `EvidenceTamperedError`, marks `metadata.is_tampered = True`, and logs a critical `MISMATCH` custody entry.
3. **Immutability via Copy Dispatch**: The vault never returns raw internal mutable file references or allows in-place modifications — callers always receive an isolated byte copy or an exported copy.
4. **Pluggable Storage**: Abstracted via `StorageBackend` supporting `MemoryStorageBackend` (testing), `LocalStorageBackend` (disk containment), and `MinIOStorageBackend` (production object store).
5. **Event Pipeline Integration**: Ingesting evidence publishes a canonical `SecurityEvent` (`source: "forensics"`, `event_type: "evidence_intake"`) to notify downstream correlation engines and Copilot retrieval.
**Why:** Complies strictly with `ARCHITECTURE.md` §4.5, §8 and `.agents/skills/forensics/SKILL.md`. In forensic science, chain of custody and cryptographic integrity are paramount; silent continuation on corrupted evidence is unacceptable.
**Status:** Final

---

## D015 — File-level Analysis Heuristics, Multi-Format Carving, and Artifact Recovery Strategy

**Date:** 2026-10-04
**Decision:** Implement file-level forensics analysis (`src/forensics/file_analyzer.py`) using lightweight, pure-Python algorithms without heavy external C-extensions:
1. **Shannon Entropy**: Measures informational density (0.0–8.0); scores $\ge 7.2$ flag suspicious packed, compressed, or encrypted ransomware payloads.
2. **Magic Byte Verification vs. Extension Spoofing**: Inspects true binary magic numbers (`MZ` with `PE\x00\x00`, `\x7fELF`, `%PDF-`, `\xff\xd8\xff`, `\x89PNG`, `PK\x03\x04`, etc.). If an executable binary carries an innocent document/image extension (`.pdf`, `.png`, `.jpg`, `.txt`), it is immediately escalated to a `critical` security indicator.
3. **IOC & String Extraction**: Dual ASCII and UTF-16LE string decoders scan for IPs, domains, URLs, emails, and attacker execution signatures (PowerShell hidden windows, volume shadow copy deletion, mimikatz, webshells). Base64 blobs are decoded and recursively checked for embedded binaries or scripts.
4. **Signature-Based File Carving**: Scans raw byte streams or corrupted binary dumps for known headers and footers to carve out embedded JPEG, PNG, PDF, and ZIP artifacts.
5. **Filesystem Deleted File Recovery**: Parses structured deletion artifacts including Windows Vista/7/8/10/11 Recycle Bin index metadata (`$I` files: Windows FILETIME timestamps, original file size, UTF-16LE original paths) paired with `$R` data files, alongside Linux/macOS `.trashinfo` metadata pairs, recovering original filenames and data safely.
**Why:** Complies with D003 (file-level forensics only, no raw disk imaging), operates deterministically across all operating systems without requiring elevated driver privileges, and enables the SOC correlation engine and AI Copilot to reason over file-level forensic findings.
**Status:** Final

---

## D016 — Multi-Format Forensic Metadata Engine with Weaponization Detection & Pure-Python Parsers

**Date:** 2026-10-04
**Decision:** The Forensic Metadata Extraction subsystem (`src/forensics/metadata_extractor.py`) implements a hybrid architecture:
1. **Pure-Python Native Parsers**: Implements dedicated format decoders without requiring external binaries:
   - **Office OOXML** (`.docx`, `.xlsx`, `.pptx`, `.docm`, etc.): Unpacks XML structures (`docProps/core.xml`, `docProps/app.xml`) to extract authors, editors, revisions, and editing time, and scans for embedded VBA macro binaries (`vbaProject.bin`).
   - **PDF**: Parses `/Info` dictionaries and scans object streams for critical weaponization primitives (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, `/EmbeddedFiles`).
   - **Image EXIF**: Decodes TIFF structures within JPEG APP1 segments (Make, Model, Software, DateTimeOriginal, and GPS Rational coordinate conversions) and PNG metadata chunks (`IHDR`, `tEXt`).
   - **PE Executables**: Reads COFF FileHeader and OptionalHeader (`TimeDateStamp` compilation timestamp, target architecture, subsystem) and analyzes section entropy to flag packed sections.
2. **Filesystem MACB Timestamps**: Extracts disk-level Modified, Accessed, Changed/Created, and Birth times in UTC.
3. **Optional ExifTool CLI Integration**: Detects whether `exiftool` is installed on the system PATH and maps its output into the common `ExtractedMetadata` schema when requested, with seamless fallback to internal parsers.
**Why:** Aligns with `ARCHITECTURE.md` §4.5 and ensures the platform is fully portable across developer machines, CI/CD runners, and Docker containers without depending on system Perl installations or external ExifTool dependencies.
**Status:** Final

---

## D017 — Browser Forensic Artifact Parsing, Lock-Free SQLite Querying, and Anomaly Detection

**Date:** 2026-10-04
**Decision:** The Browser Artifacts Forensics subsystem (`src/forensics/browser_analyzer.py`) implements:
1. **Lock-Free Database Access**: All SQLite artifacts (`History`, `Cookies`, `places.sqlite`, `cookies.sqlite`) are copied to an isolated temporary copy with associated WAL and SHM journal files before querying. This eliminates file-lock contention with running browser processes and guarantees that original evidence files are never modified.
2. **Epoch Timestamp Normalization**: Converts WebKit/Chrome 64-bit microsecond timestamps (1601 UTC epoch) and Mozilla PRTime microsecond timestamps (1970 UTC epoch) to timezone-aware UTC `datetime` objects.
3. **Suspicious Keyword Search Detection**: Analyzes omnibox and search engine queries against threat intelligence and offensive security taxonomy: credential dumping (`mimikatz`, `lsass`), log tampering (`wevtutil`, `clear event log`), defense evasion (`disable defender`), C2 frameworks (`cobalt strike`), and dark web/ransomware research.
4. **Untrusted Download Scoring**: Evaluates downloaded files against high-risk executable/script extensions (`.exe`, `.scr`, `.ps1`, `.bat`, `.iso`), browser-assigned danger codes (`danger_type > 0`), and direct IP address origin hosts.
5. **Chronological Unified Timeline**: Merges navigation visits, file downloads, and search queries into a single chronological timeline for analyst incident reconstruction.
**Why:** Aligns with `ARCHITECTURE.md` §4.5 and `.agents/skills/forensics/SKILL.md`. Web browsers are the primary entry point for social engineering, malware ingress, and data exfiltration.
**Status:** Final

---

## D018 — USB Activity Forensic Investigation Engine, BadUSB / Keystroke Injection Signatures, and Multi-Source Correlation

**Date:** 2026-10-04
**Decision:** The USB Activity Forensics subsystem (`src/forensics/usb_analyzer.py`) implements:
1. **Multi-Source Ingestion**:
   - **Windows Device Setup Logs**: Parses `setupapi.dev.log` and `setupapi.offline.log` sections to extract device instance paths (`USBSTOR`, `USB`), vendor IDs, product IDs, serial numbers, first installation timestamps, and exit codes.
   - **Windows Registry Exports**: Parses `.reg` files or dumps (`SYSTEM\CurrentControlSet\Enum\USBSTOR`, `USB`, and `MountedDevices`) to extract friendly device names, container IDs, and associated drive letters (`E:`, `F:`) by matching serial numbers and volume signatures.
   - **Linux Syslog / Kernel dmesg**: Parses kernel device discovery, manufacturer, product, serial number, SCSI block device attachments (`sdX`), and disconnection timestamps.
2. **Hardware Threat & BadUSB Detection**:
   - Matches hardware Vendor/Product IDs against known programmable keystroke injection platforms: Rubber Ducky (`1fc9:0080`), Flipper Zero (`1d50:6089`), Teensy (`16c0:0486`, `16c0:0478`), Digispark (`16d0:0753`), Arduino Leonardo/Micro (`2341:8036`, `2341:8037`), and SparkFun Pro Micro (`1b4f:9206`).
   - Flags suspicious serial number patterns characteristic of default firmware payloads (`00000000`, `12345678`, `DEADBEEF`, `badusb`, `ducky`).
   - Flags composite anomalies where storage devices register unauthorized HID keyboard or network adapter interfaces.
3. **Multi-Source Correlation & Chronological Timeline**:
   - Merges artifacts across setupapi, registry, and syslog by serial number/device ID into unified `USBDeviceArtifact` records.
   - Constructs a unified chronological event timeline tracking first installation, connection, drive mounting, and disconnection.
**Why:** Aligns with `ARCHITECTURE.md` §4.5 and `.agents/skills/forensics/SKILL.md`. USB mass storage and rogue HID hardware are common attack vectors for physical initial access, payload execution, and data exfiltration.
**Status:** Final

---

## D019 — Forensic Evidence Integrity Re-Verification Engine, Background Daemon Sweeps, and Pipeline Tamper Alerts

**Date:** 2026-10-04
**Decision:** The Forensic Evidence Integrity Re-Verification subsystem (`src/forensics/integrity_job.py`) implements:
1. **Direct Backend Dual-Hash Verification**: Recalculates streaming SHA-256 and MD5 cryptographic hashes directly from backend storage bytes without invoking read-access abort exceptions, enabling exhaustive batch sweeps across all registered vault artifacts or specific case boundaries (`case_id`).
2. **Immediate Chain-of-Custody Logging & Tamper Flagging**:
   - Every verification operation appends a `CustodyAction.VERIFY` record with `CustodyStatus.VERIFIED` (if matching) or `CustodyStatus.MISMATCH` (if corrupted or missing).
   - Flagged items immediately update `metadata.is_tampered = True` so subsequent access attempts remain locked and guarded.
3. **MMS SecurityEvent Alert Dispatch**:
   - Hash mismatches trigger a critical `SecurityEvent` (`event_type: "evidence_tampering_detected"`, MITRE `T1565` Data Manipulation).
   - Missing storage objects trigger a critical `SecurityEvent` (`event_type: "evidence_missing_detected"`, MITRE `T1070` Indicator Removal).
   - Pluggable `alert_callback` enables immediate operator or test hooks.
4. **Daemon and On-Demand Lifecycle**:
   - Supports synchronous full sweeps, case-filtered sweeps, and single-evidence checks.
   - Background daemon thread (`start_background_job`, `stop_background_job`) supports scheduled periodic sweeps with graceful `threading.Event` shutdown.
5. **Defensible Audit Certificates**:
   - Produces structured dictionary records and defensible Markdown Integrity Audit Certificates suitable for legal proceedings, internal audits, and compliance verification.
**Why:** Aligns with `ARCHITECTURE.md` §4.5, `REQUIREMENTS.md` §1.5, and `.agents/skills/forensics/SKILL.md`. Evidence integrity is legally defensible only if continuous cryptographic verification is auditable, immutable, and alertable across its entire storage lifecycle.
**Status:** Final

---

## D020 — Phishing Detection Architecture: Stateless Scoring Services, Mandatory Explainability, and Pipeline Mapping

**Date:** 2026-10-05
**Decision:** The Phishing Detection module (`src/phishing/`) implements:
1. **Stateless Scoring Services**: Each detector (`EmailAnalyzer`, and future `URLScanner`, `AttachmentScanner`) is completely decoupled and stateless: input in → `PhishingVerdict` out. Detectors maintain zero mutable session state and can run independently or concurrently.
2. **Mandatory Explainability**: Every verdict returns a normalized score (0–100), a severity level, and a mandatory list of `PhishingSignal` objects detail each specific indicator that triggered (category, rule name, weight, evidence snippet, description). Never returns a bare score.
3. **Multi-Vector Email Heuristics**: Evaluates 8 detection categories: email authentication (SPF, DKIM, DMARC), header anomalies (Reply-To / Return-Path domain mismatches, missing Received hops), sender reputation (free email masquerading, high-risk TLDs), display name / brand impersonation, urgency/coercion language, deceptive links (IP addresses, URL shorteners, deceptive @-userinfo, credential keywords), attachment risk (dangerous extensions, macros, archives), and content anomalies (hidden HTML, embedded forms, anchor text/href mismatches).
4. **Pipeline Interoperability**: Every `PhishingVerdict` can export directly to a canonical `SecurityEvent` (`source: "phishing"`, `event_type: "phishing_email_detected"`) with MITRE ATT&CK tagging (`T1566.001`, `T1566.002`, `T1204.001`, `T1204.002`) for event bus ingestion, SOC correlation, and Copilot retrieval.
5. **Ethical & Safety Guardrails**: Testing uses strictly synthetic and mock RFC 822 sample templates, without containing real victim data or live malicious payloads.
**Why:** Aligns strictly with `ARCHITECTURE.md` §4.4, `AGENTS.md` ethical guardrails, and `.agents/skills/phishing-detection/SKILL.md`. Security analysts require transparent, explainable verdicts with concrete evidence, and decoupled services allow flexible deployment and easy extension.
**Status:** Final

---

## D021 — URL Reputation Scanner: Lexical Parsing, Obfuscated IP Decoding, Homograph Detection, and TTL Caching Architecture

**Date:** 2026-10-06
**Decision:** The URL Reputation Scanner (`src/phishing/url_scanner.py`) implements:
1. **Multi-Vector Lexical & Structural Feature Extraction**: Safely parses standard schemes as well as pseudo-schemes (`javascript:`, `data:`, `file:`) without crashing, extracts authority userinfo (`@` credentials), normalizes subdomains with multi-part TLD support (`.co.uk`, `.com.au`), and calculates Shannon entropy to detect DGA/randomized domain generation.
2. **Obfuscated IP Representation Decoding**: Automatically detects and decodes non-standard IP notations commonly employed in evasion techniques: dword/integer IPs (e.g. `http://2130706433/`), dotted octal IPs (e.g. `http://0177.0.0.1/`), hex IPs (`http://0x7f000001/` or `http://0x7f.0.0.1`), mixed radix encodings, and raw IPv4/IPv6 literals.
3. **IDN Homograph & Optical Typosquatting Engine**: Detects mixed-script attacks (Cyrillic and Greek homoglyphs visually substituting Latin letters, e.g. `pаypal.com`), decodes Punycode (`xn--`), identifies Leetspeak and optical substitutions (`0` for `o`, `1`/`l` for `i`, `rn` for `m`, `vv` for `w`), Levenshtein edit distance ($d \le 2$), and subdomain brand injection against an extensible protected brand catalog.
4. **Thread-Safe In-Memory TTL Reputation Cache**: Implements `URLReputationCache` with configurable TTL (default 3600s) and LRU capacity bounds (default 5000 entries) guarded by thread locks, avoiding redundant external lookups.
5. **Pluggable Providers with Graceful Timeout Degradation**: Implements `ThreatIntelProvider` abstraction supporting `MockThreatIntelProvider`, `SyntheticBlocklistProvider`, and `VirusTotalLookupProvider`. All external lookups are bounded by strict timeouts (1.5s default) and catch all network/rate-limit exceptions, cleanly degrading to local heuristic scoring without ever blocking or raising (satisfying SKILL.md gotchas).
6. **Pipeline Mapping**: Converts verdicts directly to canonical `SecurityEvent` models (`source: "phishing"`, `event_type: "phishing_url_detected"`) with MITRE ATT&CK tagging (`T1566.002`, `T1204.001`, `T1583.001`, `T1584.001`).
**Why:** Complies strictly with `ARCHITECTURE.md` §4.4, `AGENTS.md` guardrails, and `.agents/skills/phishing-detection/SKILL.md`. Malicious URLs represent the primary mechanism of spearphishing and payload delivery; robust lexical decoding paired with resilient cached intelligence ensures rapid, offline-capable, and non-blocking threat scoring.
**Status:** Final

---

## D022 — Phishing REST Gateway Integration, Cross-Modal Attack Simulation, and Console Safe ASCII Guardrails

**Date:** 2026-10-06
**Decision:**
1. **Phishing REST API Endpoints**: Exposed stateless phishing scanning through FastAPI Gateway (`src/api/main.py`) with `POST /api/phishing/scan/url`, `POST /api/phishing/scan/email`, and `GET /api/phishing/stats`. Clients can request standalone scoring or automatically dispatch the resulting `SecurityEvent` to the live pipeline.
2. **Unified Attack Simulation**: Extended `/api/simulate/attack` to support `"phishing"` scenarios and incorporated targeted credential harvesting spearphishing into the `"multistage"` attack demonstration, enabling end-to-end multi-modal correlation (`MULTI_SOURCE_BONUS`) across SOC, Honeypot, and Phishing modalities.
3. **Safe ASCII Character Escaping**: Implemented `LookalikeAnalyzer.safe_ascii()` across all lookalike signal descriptions and evidence, safely escaping Unicode homoglyphs (e.g. `p[U+0430]ypal`) so that verdicts never crash Windows consoles with `UnicodeEncodeError: 'charmap'`.
4. **Canonical SecurityEvent Severity Mapping**: Explicitly mapped internal `PhishingSeverity` values (`SAFE` -> `"low"`) before instantiation of canonical `SecurityEvent` models, ensuring strict Pydantic Literal validation compliance.
5. **Non-blocking Ingestion Optimization**: Added time-based throttling (15s interval) to `_get_os()` OpenSearch ping checks, preventing connection timeouts from delaying event ingestion and pipeline test execution when running in standalone mode.
**Why:** Complies with `ARCHITECTURE.md` §4.4, `AGENTS.md` build rules, and cross-platform reliability standards. Allows automated frontends, dashboards, and API clients to access phishing detection seamlessly without environmental crashes.
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




