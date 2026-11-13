import io
import sqlite3
import zipfile

import pytest

from src.forensics.workflows import analyze_evidence_bytes
from src.shared.config import settings


def browser_bytes(tmp_path, firefox=False, timestamp=13300000000000000):
    path = tmp_path / "browser.db"
    with sqlite3.connect(path) as conn:
        if firefox:
            conn.execute("CREATE TABLE moz_places (url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER)")
            conn.execute("INSERT INTO moz_places VALUES (?,?,?,?,?)", ("https://example.test", "Example", 2, 1, timestamp))
        else:
            conn.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)")
            conn.execute("INSERT INTO urls VALUES (?,?,?,?,?)", ("https://example.test", "Example", 2, 1, timestamp))
    return path.read_bytes()


@pytest.mark.parametrize("firefox,timestamp", [(False, 13300000000000000), (True, 1700000000000000)])
def test_browser_snapshot_is_parsed_without_mutation(tmp_path, firefox, timestamp):
    data = browser_bytes(tmp_path, firefox, timestamp)
    result = analyze_evidence_bytes(data, "upload.db", "browser")
    assert result["browser_type"] == ("firefox" if firefox else "chrome")
    assert result["history_count"] == 1
    assert result["history_entries"][0]["url"] == "https://example.test"
    assert result["timeline"][0]["timestamp"].endswith("+00:00")
    assert result["profile_dir"] == "uploaded evidence"
    assert (tmp_path / "browser.db").read_bytes() == data


def test_invalid_browser_timestamp_remains_unknown(tmp_path):
    result = analyze_evidence_bytes(browser_bytes(tmp_path, timestamp=0), "History", "browser")
    assert result["history_entries"][0]["visit_time"] is None
    assert result["timeline"] == []


def test_browser_cookie_metadata_without_cookie_secret_values(tmp_path):
    path = tmp_path / "cookies.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, creation_utc INTEGER, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, value TEXT)")
        conn.execute("INSERT INTO cookies VALUES ('.example.test', 'session', '/', 13300000000000000, 0, 1, 1, 'synthetic-secret')")
    result = analyze_evidence_bytes(path.read_bytes(), "Cookies", "browser")
    assert result["cookies_count"] == 1
    assert result["cookies"][0]["is_httponly"]
    assert "synthetic-secret" not in str(result)


def test_corrupt_browser_or_unrecognized_schema_is_not_empty_success(tmp_path):
    with pytest.raises(ValueError):
        analyze_evidence_bytes(b"not a database", "History", "browser")
    path = tmp_path / "unknown.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE unrelated (value TEXT)")
    with pytest.raises(ValueError, match="supported browser"):
        analyze_evidence_bytes(path.read_bytes(), "History", "browser")


def test_browser_row_limit_does_not_silently_truncate(tmp_path, monkeypatch):
    browser_bytes(tmp_path)
    with sqlite3.connect(tmp_path / "browser.db") as conn:
        conn.execute("INSERT INTO urls SELECT * FROM urls")
    monkeypatch.setattr(settings, "forensics_max_artifact_rows", 1)
    with pytest.raises(ValueError, match="row limit"):
        analyze_evidence_bytes((tmp_path / "browser.db").read_bytes(), "History", "browser")


def docx(core):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("docProps/core.xml", core)
    return buffer.getvalue()


def test_document_metadata_contains_collected_author():
    xml = b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Example Analyst</dc:creator></cp:coreProperties>'
    result = analyze_evidence_bytes(docx(xml), "document.docx", "metadata")
    assert result["document"]["author"] == "Example Analyst"
    assert len(result["sha256"]) == 64


@pytest.mark.parametrize("xml", [b"x" * (512 * 1024 + 1), b'<!DOCTYPE test [<!ENTITY sample "sample">]><test/>'], ids=["oversized", "entity-declaration"])
def test_metadata_xml_resource_or_entity_limits(xml):
    with pytest.raises(ValueError, match="XML"):
        analyze_evidence_bytes(docx(xml), "bounded.docx", "metadata")


def test_uploaded_usb_content_cannot_be_interpreted_as_local_path(tmp_path, monkeypatch):
    from src.forensics.usb_analyzer import LinuxSyslogParser
    path = tmp_path / "private.log"
    path.write_text("local host data that must not be read")
    seen = []
    monkeypatch.setattr(LinuxSyslogParser, "parse_syslog_text", lambda text: (seen.append(text) or [], []))
    analyze_evidence_bytes(str(path).encode(), "log.txt", "usb_syslog")
    assert seen == [str(path) + "\n"]


def test_usb_binary_hive_is_rejected():
    with pytest.raises(ValueError):
        analyze_evidence_bytes(b"regf\x00\x00", "registry.hive", "usb_registry")
