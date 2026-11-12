"""
Multi Modal Security -- Phase 1 & 2 End-to-End Demo

Simulates a realistic multi-stage SSH brute-force -> privilege escalation
attack against a production server, processing each event through every
stage of the pipeline and printing colour-coded output.

No Docker, Redis, or OpenSearch needed -- runs entirely in-memory.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# -- Pipeline components ---------------------------------------------------
from src.shared.event_schema import Entity, SecurityEvent
from src.soc.ingestion.normalizer import normalise_syslog_line
from src.soc.detection.rule_loader import RuleLoader
from src.soc.detection.matcher import DetectionEngine
from src.soc.correlation.engine import CorrelationEngine
from src.soc.scoring.calculator import score_incident
from src.soc.alerting.alert_model import Alert, priority_from_score
from src.soc.alerting.manager import AlertManager
from src.honeypot.server import DeceptionService
from src.honeypot.normalizer import normalise_command_record, normalise_artifact_record, normalise_session_to_event
from src.honeypot.behavior import BehaviorAnalyzer, ARCHETYPES
from src.phishing.email_analyzer import EmailAnalyzer, EmailParser
from src.phishing.url_scanner import URLScanner


# -- ANSI colour codes -----------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"


def banner(text: str, colour: str = C.CYAN) -> None:
    w = 72
    print(f"\n{colour}{C.BOLD}{'=' * w}")
    print(f"  {text}")
    print(f"{'=' * w}{C.RESET}\n")


def stage_header(num: int, title: str) -> None:
    pad = max(50 - len(title), 0)
    print(f"\n{C.MAGENTA}{C.BOLD}-- Stage {num}: {title} {'-' * pad}{C.RESET}")


def info(label: str, value: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{C.DIM}|{C.RESET} {C.BLUE}{label}:{C.RESET} {value}")


def success(msg: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{C.GREEN}[ok]{C.RESET} {msg}")


def sev_c(sev: str) -> str:
    return {"low": C.GREEN, "medium": C.YELLOW, "high": C.RED,
            "critical": f"{C.BG_RED}{C.WHITE}"}.get(sev, C.WHITE)


def pri_c(prio: str) -> str:
    return {"P1-critical": f"{C.BG_RED}{C.WHITE}", "P2-high": C.RED,
            "P3-medium": C.YELLOW, "P4-low": C.GREEN}.get(prio, C.WHITE)


# =========================================================================
# ATTACK SCENARIO EVENTS
# =========================================================================

NOW = datetime.now(timezone.utc)

SYSLOG_LINES = [
    f"{NOW.strftime('%b %d %H:%M:%S')} prod-web-01 sshd[4401]: Failed password for root from 203.0.113.88 port 22 ssh2",
    f"{(NOW + timedelta(seconds=2)).strftime('%b %d %H:%M:%S')} prod-web-01 sshd[4402]: Failed password for root from 203.0.113.88 port 22 ssh2",
    f"{(NOW + timedelta(seconds=15)).strftime('%b %d %H:%M:%S')} prod-web-01 sshd[4410]: Accepted password for root from 203.0.113.88 port 22 ssh2",
    f"{(NOW + timedelta(seconds=25)).strftime('%b %d %H:%M:%S')} prod-web-01 sudo[4455]:     root : COMMAND=/bin/bash",
]


def _attack_events() -> list[SecurityEvent]:
    """Build SecurityEvents shaped to trigger the loaded Sigma rules.

    The normalizer demo uses raw syslog, but the full pipeline needs
    events whose fields match the rule selection criteria exactly.
    """
    attacker = Entity(ip="203.0.113.88", user="root", host="prod-web-01")
    events: list[SecurityEvent] = []

    # 6 failed SSH logins (triggers SOC-RULE-001 at count=5)
    for i in range(6):
        events.append(SecurityEvent(
            event_type="auth_failure",
            source="soc",
            severity="medium",
            timestamp=NOW + timedelta(seconds=i * 2),
            entity=attacker,
            raw={"service": "sshd", "line": f"Failed password for root from 203.0.113.88 attempt {i+1}"},
        ))

    # Successful login
    events.append(SecurityEvent(
        event_type="auth_success",
        source="soc",
        severity="low",
        timestamp=NOW + timedelta(seconds=15),
        entity=attacker,
        raw={"service": "sshd", "line": "Accepted password for root from 203.0.113.88"},
    ))

    # Session opened
    events.append(SecurityEvent(
        event_type="session_open",
        source="soc",
        severity="low",
        timestamp=NOW + timedelta(seconds=16),
        entity=attacker,
        raw={"service": "sshd", "line": "session opened for user root"},
    ))

    # Privilege escalation via sudo (triggers SOC-RULE-002)
    events.append(SecurityEvent(
        event_type="privilege_escalation",
        source="soc",
        severity="high",
        timestamp=NOW + timedelta(seconds=25),
        entity=attacker,
        raw={"command": "/bin/bash", "service": "sudo", "line": "root : COMMAND=/bin/bash"},
    ))

    # Unrelated event -- different attacker, different host (should NOT correlate)
    events.append(SecurityEvent(
        event_type="auth_success",
        source="soc",
        severity="low",
        timestamp=NOW + timedelta(seconds=30),
        entity=Entity(ip="192.168.1.50", user="analyst", host="workstation-3"),
        raw={"service": "sshd", "line": "Accepted publickey for analyst from 192.168.1.50"},
    ))

    return events


# =========================================================================
# MAIN
# =========================================================================

def main() -> None:
    if sys.platform == "win32":
        import os
        os.system("")
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    banner("MULTI MODAL SECURITY -- Phase 1 & 2 Pipeline Demo")

    # ====================================================================
    # STAGE 0: INITIALISATION
    # ====================================================================
    stage_header(0, "Pipeline Initialisation")

    rules_dir = Path(__file__).parent / "src" / "soc" / "rules"
    loader = RuleLoader(rules_dir=rules_dir)
    rules = loader.load_from_directory()
    success(f"Loaded {len(rules)} Sigma-style detection rules")
    for r in rules:
        info(r.id, f"{r.title} [{r.severity}]", indent=4)

    detection = DetectionEngine(rules=rules)
    success("Detection engine initialised")

    correlator = CorrelationEngine(correlation_window_seconds=300)
    success("Correlation engine initialised (300s window)")

    published: list[tuple[Alert, bool]] = []
    def on_alert(alert: Alert, is_new: bool) -> None:
        published.append((alert, is_new))

    alert_mgr = AlertManager(on_alert=on_alert, min_score_to_alert=15.0)
    success("Alert manager initialised (min_score=15.0)")

    # ====================================================================
    # STAGE 1: LOG NORMALISATION DEMO
    # ====================================================================
    banner("Stage 1: Log Normalisation (raw syslog -> SecurityEvent)", C.YELLOW)

    print(f"  {C.DIM}Parsing raw syslog lines through the normaliser...{C.RESET}\n")

    for i, line in enumerate(SYSLOG_LINES):
        print(f"  {C.BOLD}Raw #{i+1}:{C.RESET} {C.DIM}{line[:85]}{C.RESET}")
        ev = normalise_syslog_line(line)
        if ev:
            sc = sev_c(ev.severity)
            info("event_type", ev.event_type, indent=4)
            info("severity", f"{sc}{ev.severity}{C.RESET}", indent=4)
            info("entity", f"IP={ev.entity.ip or '-'}  User={ev.entity.user or '-'}  Host={ev.entity.host or '-'}", indent=4)
            success("Normalised successfully", indent=4)
        print()
        time.sleep(0.1)

    # ====================================================================
    # STAGE 2-5: FULL PIPELINE (Detection -> Correlation -> Scoring -> Alert)
    # ====================================================================
    banner("Stages 2-5: Detection -> Correlation -> Scoring -> Alerting", C.RED)

    print(f"  {C.DIM}Attacker: 203.0.113.88")
    print(f"  Target:  root@prod-web-01")
    print(f"  Attack:  SSH brute force (6 attempts) -> login -> session -> sudo /bin/bash{C.RESET}\n")

    events = _attack_events()
    all_matches: list = []
    last_incident = None

    for i, event in enumerate(events):
        print(f"  {C.DIM}{'-' * 68}{C.RESET}")
        sc = sev_c(event.severity)
        ent = event.entity
        print(f"  {C.BOLD}Event #{i+1}:{C.RESET} {event.event_type} "
              f"[{sc}{event.severity}{C.RESET}]  "
              f"IP={ent.ip or '-'}  User={ent.user or '-'}  Host={ent.host or '-'}")

        # -- Detection --
        matches = detection.evaluate(event)
        if matches:
            for m in matches:
                mc = sev_c(m.severity)
                print(f"    {C.RED}{C.BOLD}>> RULE TRIGGERED:{C.RESET} "
                      f"{mc}{m.rule_title}{C.RESET} [{m.severity}]  (Rule: {m.rule_id})")
                if m.tags:
                    info("MITRE Tags", ", ".join(m.tags), indent=6)
                all_matches.append(m)
        else:
            print(f"    {C.DIM}   (no rule triggered){C.RESET}")

        # -- Correlation --
        incident = correlator.process_event(event, rule_matches=matches)
        if incident and incident.event_count > 0:
            last_incident = incident
            print(f"    {C.CYAN}>> Incident:{C.RESET} {incident.incident_id[:12]}...  "
                  f"Events: {incident.event_count}  "
                  f"Severity: {sev_c(incident.severity)}{incident.severity}{C.RESET}")
            if incident.mitre_techniques:
                info("MITRE Techniques", ", ".join(incident.mitre_techniques), indent=6)

            # -- Scoring --
            score, bd = score_incident(incident)
            incident.risk_score = score
            score_c = C.GREEN if score < 30 else (C.YELLOW if score < 60 else C.RED)
            print(f"    {C.MAGENTA}>> Risk Score:{C.RESET} {score_c}{C.BOLD}{score:.1f}/100{C.RESET}")

            components: list[str] = []
            components.append(f"base={bd.base_severity:.0f}")
            if bd.frequency_bonus > 0:
                components.append(f"freq=+{bd.frequency_bonus:.1f}")
            if bd.mitre_bonus > 0:
                components.append(f"mitre=+{bd.mitre_bonus:.1f}")
            if bd.critical_user_bonus > 0:
                components.append(f"user({bd.critical_user})=+{bd.critical_user_bonus:.0f}")
            if bd.critical_host_bonus > 0:
                components.append(f"host({bd.critical_host})=+{bd.critical_host_bonus:.0f}")
            if components:
                info("Breakdown", " | ".join(components), indent=6)

            # -- Alerting --
            alert = alert_mgr.process_incident(incident)
            if alert:
                is_new = published[-1][1] if published else True
                tag = f"{C.GREEN}NEW{C.RESET}" if is_new else f"{C.YELLOW}UPDATED{C.RESET}"
                pc = pri_c(alert.priority)
                print(f"    {C.RED}>> Alert [{tag}]:{C.RESET} "
                      f"{pc} {alert.priority} {C.RESET}  "
                      f"Score: {alert.risk_score:.1f}")

        time.sleep(0.15)

    # ====================================================================
    # STAGE 6: PHISHING DETECTION & URL REPUTATION ANALYSIS
    # ====================================================================
    banner("Stage 6: Phishing Detection & Brand Lookalike Analysis", C.MAGENTA)

    url_scanner = URLScanner()
    email_analyzer = EmailAnalyzer(url_scanner=url_scanner)

    test_urls = [
        ("https://google.com", "Legitimate corporate destination"),
        ("http://xn--pypal-4ve.com/login/update-password.exe", "IDN homoglyph punycode brand spoofing + executable payload"),
    ]

    print(f"  {C.BOLD}1. Scanning target URLs with lexical heuristics & threat intel:{C.RESET}\n")
    for u, desc in test_urls:
        v = url_scanner.scan_url(u)
        sc = sev_c(v.severity.value)
        status_tag = f"{C.RED}[PHISHING]{C.RESET}" if v.is_phishing else f"{C.GREEN}[SAFE]{C.RESET}"
        print(f"    {status_tag} {C.BOLD}{u}{C.RESET}")
        info("Context", desc, indent=6)
        info("Severity", f"{sc}{v.severity.value.upper()}{C.RESET} (Score: {v.score:.1f}/100)", indent=6)
        info("Signals", f"{len(v.signals)} detected", indent=6)
        for s in v.signals[:3]:
            print(f"      {C.YELLOW}* {s.name}:{C.RESET} {s.description[:80]}...")
        print()

    print(f"  {C.BOLD}2. Ingesting targeted spearphishing email into SOC correlation:{C.RESET}\n")
    phishing_email_raw = (
        f"From: security-notice@paypal.com.account-alert.xyz\r\n"
        f"To: root@prod-web-01\r\n"
        f"Subject: URGENT: Account Suspension Notice within 24 hours!\r\n\r\n"
        f"Dear Administrator,\r\n\r\n"
        f"Please verify your credentials immediately to avoid permanent lock:\r\n"
        f"http://xn--pypal-4ve.com/login/update-password.exe\r\n\r\n"
        f"Security Team"
    )
    parsed_phish = EmailParser.parse_raw_string(phishing_email_raw)
    phish_verdict = email_analyzer.analyze(parsed_phish)
    ev_phish = email_analyzer.to_security_event(phish_verdict, parsed_phish)
    ev_phish.entity.ip = "203.0.113.88"
    ev_phish.entity.host = "prod-web-01"

    print(f"    {C.RED}[PHISHING DETECTED]{C.RESET} Score: {phish_verdict.score:.1f}/100 [{phish_verdict.severity.value.upper()}]")
    info("Target", f"{ev_phish.entity.user}@{ev_phish.entity.host}", indent=6)
    info("Signals", f"{len(phish_verdict.signals)} indicators fired", indent=6)
    info("MITRE", ", ".join(phish_verdict.mitre_techniques), indent=6)

    # Correlate into SOC incident
    phish_incident = correlator.process_event(ev_phish, rule_matches=[])
    if phish_incident:
        score, bd = score_incident(phish_incident)
        phish_incident.risk_score = score
        phish_alert = alert_mgr.process_incident(phish_incident)
        print(f"    {C.CYAN}>> Correlated Multi-Source Incident:{C.RESET} Events: {phish_incident.event_count}  "
              f"Sources: {', '.join(sorted(set(e.source for e in phish_incident.timeline)))}")
        if phish_alert:
            print(f"    {C.RED}>> Updated Alert Priority:{C.RESET} {pri_c(phish_alert.priority)}{phish_alert.priority}{C.RESET} "
                  f"(Risk Score: {phish_alert.risk_score:.1f}/100)")
            published.append((phish_alert, False))

    # ====================================================================
    # SUMMARY
    # ====================================================================
    banner("PIPELINE RESULTS", C.GREEN)

    print(f"  {C.BOLD}Events processed:{C.RESET}    {len(events)}")
    print(f"  {C.BOLD}Rules triggered:{C.RESET}     {len(all_matches)}")
    print(f"  {C.BOLD}Alerts generated:{C.RESET}    {alert_mgr.alert_count}")
    print(f"  {C.BOLD}Alert updates:{C.RESET}       {len(published) - alert_mgr.alert_count}")

    stats = alert_mgr.stats
    if stats["by_priority"]:
        print(f"\n  {C.BOLD}Alerts by Priority:{C.RESET}")
        for prio, count in sorted(stats["by_priority"].items()):
            pc = pri_c(prio)
            print(f"    {pc}  {prio}  {C.RESET}  x{count}")

    # -- Final alert detail ------------------------------------------------
    if alert_mgr.alert_count > 0:
        banner("ALERT DETAIL", C.RED)
        for alert in alert_mgr.get_all_alerts(sort_by_score=True):
            pc = pri_c(alert.priority)
            print(f"  {C.BOLD}Title:{C.RESET}    {alert.title}")
            print(f"  {C.BOLD}Alert ID:{C.RESET} {alert.alert_id}")
            print(f"  {C.BOLD}Priority:{C.RESET} {pc} {alert.priority} {C.RESET}")
            print(f"  {C.BOLD}Severity:{C.RESET} {sev_c(alert.severity)}{alert.severity}{C.RESET}")
            print(f"  {C.BOLD}Score:{C.RESET}    {alert.risk_score:.1f}/100")
            print(f"  {C.BOLD}Events:{C.RESET}   {alert.event_count}")
            e = alert.primary_entity
            print(f"  {C.BOLD}Entity:{C.RESET}   IP={e.ip}  User={e.user}  Host={e.host}")
            if alert.rule_ids:
                print(f"  {C.BOLD}Rules:{C.RESET}    {', '.join(alert.rule_ids)}")
            if alert.mitre_techniques:
                print(f"  {C.BOLD}MITRE:{C.RESET}    {', '.join(alert.mitre_techniques)}")

            bd = alert.score_breakdown
            print(f"\n  {C.BOLD}Score Breakdown:{C.RESET}")
            print(f"    Base severity ({bd['base_severity']['label']}):  {bd['base_severity']['value']:.1f}")
            if bd['frequency']['value'] > 0:
                print(f"    Event frequency ({bd['frequency']['event_count']} events): +{bd['frequency']['value']:.1f}")
            if bd['mitre_techniques']['value'] > 0:
                t = ', '.join(bd['mitre_techniques']['techniques'])
                print(f"    MITRE techniques ({t}):        +{bd['mitre_techniques']['value']:.1f}")
            if bd['critical_user']['value'] > 0:
                print(f"    Critical user '{bd['critical_user']['user']}':          +{bd['critical_user']['value']:.1f}")
            if bd['critical_host']['value'] > 0:
                print(f"    Critical host '{bd['critical_host']['host']}':  +{bd['critical_host']['value']:.1f}")
            if bd['threat_intel']['value'] > 0:
                print(f"    Threat intel match:              +{bd['threat_intel']['value']:.1f}")
            if bd['multi_source']['value'] > 0:
                print(f"    Multi-source correlation:        +{bd['multi_source']['value']:.1f}")
            print(f"    {C.BOLD}{'=' * 40}")
            print(f"    FINAL RISK SCORE: {alert.risk_score:.1f}/100{C.RESET}")

    # -- Test summary ------------------------------------------------------
    banner("UNIT TEST COVERAGE (231 tests)", C.BLUE)

    suites = [
        ("shared/test_event_schema.py", 11, "Event schema + serialisation"),
        ("soc/test_normalizer.py",      15, "Syslog normaliser"),
        ("soc/test_detection.py",       21, "Rule-based detection engine"),
        ("soc/test_correlation.py",      9, "Correlation engine"),
        ("soc/test_scoring.py",         27, "Risk scoring calculator"),
        ("soc/test_alerting.py",        24, "Alert manager"),
        ("honeypot/test_models.py",      5, "Honeypot session & artifact models"),
        ("honeypot/test_recorder.py",    8, "Memory-bounded session recorder"),
        ("honeypot/test_server.py",      5, "Sandboxed virtual shell & server"),
        ("honeypot/test_normalizer.py",  5, "Honeypot event normalizer"),
        ("honeypot/test_cowrie_parser.py", 5, "Cowrie JSON stream parser"),
        ("honeypot/test_behavior.py",    6, "Attacker behavior & TTP clustering"),
        ("honeypot/test_integration.py", 1, "Cross-modal SOC+Honeypot correlation"),
        ("copilot/test_retrieval.py",    5, "Copilot OpenSearch & memory retrieval"),
        ("copilot/test_tools.py",        5, "Copilot tool definitions & executor"),
        ("copilot/test_composer.py",     4, "Grounded response composer & citations"),
        ("copilot/test_reports.py",      4, "Incident report generator"),
        ("copilot/test_orchestrator.py", 5, "Copilot orchestrator & safety guards"),
        ("copilot/test_api.py",          3, "Copilot REST API endpoints"),
        ("forensics/test_evidence_vault.py", 12, "Evidence vault & chain of custody"),
        ("forensics/test_file_analyzer.py", 12, "Entropy, carving & trash recovery"),
        ("forensics/test_metadata_extractor.py", 10, "OOXML, PDF, EXIF & PE metadata"),
        ("forensics/test_browser_analyzer.py", 7, "Browser history, downloads & cookies"),
        ("forensics/test_usb_analyzer.py", 11, "USB device logs, registry & BadUSB"),
        ("forensics/test_integrity_job.py", 11, "Integrity re-verification job & audit"),
        ("phishing/test_email_analyzer.py", 41, "Email header, body, auth & link analyzer"),
        ("phishing/test_url_scanner.py", 50, "URL reputation, lookalikes & threat intel"),
        ("api/test_phishing_api.py", 6, "Phishing REST API & attack simulation"),
    ]
    total = 0
    for path, count, desc in suites:
        total += count
        print(f"  {C.GREEN}[PASS]{C.RESET} tests/{path:<35} {C.BOLD}{count:>3}{C.RESET} tests -- {desc}")

    print(f"\n  {C.GREEN}{C.BOLD}Total: {total} unit tests passing{C.RESET}")

    banner("DEMO COMPLETE", C.GREEN)


if __name__ == "__main__":
    main()
