"""
Unit tests for Honeypot SessionRecorder.
"""

from __future__ import annotations

import datetime

import pytest

from src.honeypot.recorder import SessionRecorder


@pytest.fixture
def recorder() -> SessionRecorder:
    rec = SessionRecorder(
        max_commands_per_session=5,
        max_credentials_per_session=5,
        max_active_sessions=5,
        max_closed_history=5,
    )
    yield rec
    rec.clear()


def test_start_and_get_session(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50", source_port=2222)
    assert sess.session_id
    assert sess.is_active
    assert recorder.get_session(sess.session_id) is sess


def test_record_credentials(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50")

    # Record 2 failures, 1 success
    recorder.record_credential(sess.session_id, "root", "toor", success=False)
    recorder.record_credential(sess.session_id, "admin", "admin", success=False)
    recorder.record_credential(sess.session_id, "root", "123456", success=True)

    updated = recorder.get_session(sess.session_id)
    assert updated is not None
    assert len(updated.credentials) == 3
    assert updated.authenticated
    assert updated.authenticated_user == "root"


def test_credential_capping(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50")
    for i in range(10):
        recorder.record_credential(sess.session_id, f"user{i}", "pass")

    updated = recorder.get_session(sess.session_id)
    assert updated is not None
    assert len(updated.credentials) == 5  # capped at 5


def test_record_commands_and_capping(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50")
    for i in range(8):
        recorder.record_command(sess.session_id, f"echo {i}", output_preview=f"{i}")

    updated = recorder.get_session(sess.session_id)
    assert updated is not None
    assert len(updated.commands) == 5  # capped at 5
    assert updated.commands[0].command == "echo 0"


def test_record_artifact(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50")
    art = recorder.record_artifact(
        sess.session_id,
        filename_or_url="http://bad.com/bot.exe",
        file_hash="deadbeef",
        size_bytes=2048,
    )
    assert art is not None
    updated = recorder.get_session(sess.session_id)
    assert updated is not None
    assert len(updated.artifacts) == 1
    assert updated.artifacts[0].file_hash == "deadbeef"


def test_close_session_and_history(recorder: SessionRecorder):
    sess = recorder.start_session(source_ip="192.168.1.50")
    recorder.record_command(sess.session_id, "whoami")
    recorder.record_credential(sess.session_id, "root", "root", success=True)

    closed = recorder.close_session(sess.session_id)
    assert closed is not None
    assert not closed.is_active
    assert "whoami" in closed.summary

    # Should be in history, not active
    assert sess.session_id not in [s.session_id for s in recorder.get_active_sessions()]
    assert sess.session_id in [s.session_id for s in recorder.get_closed_sessions()]


def test_capacity_eviction(recorder: SessionRecorder):
    # max_active_sessions is 5
    sessions = [recorder.start_session(source_ip=f"10.0.0.{i}") for i in range(7)]

    active = recorder.get_active_sessions()
    assert len(active) == 5
    history = recorder.get_closed_sessions()
    assert len(history) == 2  # 2 oldest were evicted into history


def test_get_sessions_for_ip(recorder: SessionRecorder):
    s1 = recorder.start_session(source_ip="192.168.1.10")
    s2 = recorder.start_session(source_ip="192.168.1.10")
    s3 = recorder.start_session(source_ip="192.168.1.20")
    recorder.close_session(s1.session_id)

    found = recorder.get_sessions_for_ip("192.168.1.10")
    assert len(found) == 2
    assert s1.session_id in [s.session_id for s in found]
    assert s2.session_id in [s.session_id for s in found]
