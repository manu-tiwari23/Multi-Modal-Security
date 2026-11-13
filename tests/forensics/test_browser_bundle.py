import io
import json
import sqlite3
import zipfile

import pytest

from src.forensics.workflows import analyze_evidence_bytes


def bundle(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def test_har_cache_provenance_and_sensitive_fields_omitted():
    data = json.dumps({"log": {"entries": [{"startedDateTime": "2026-11-13T10:00:00Z",
        "request": {"url": "https://user:password@example.test/path?token=secret", "postData": {"text": "private-body"}},
        "response": {"status": 200, "_fromDiskCache": True, "headers": [{"name": "Set-Cookie", "value": "private-cookie"}, {"name": "Cache-Control", "value": "max-age=3600"}]}, "cache": {}}]}}).encode()
    result = analyze_evidence_bytes(data, "cache.har", "browser_cache_har")
    assert result["reported_cache_hits"] == 1
    assert result["entries"][0]["url_without_credentials_or_query"] == "https://example.test/path"
    assert result["entries"][0]["cache_headers"] == {"cache-control": "max-age=3600"}
    for value in ("password", "private-body", "private-cookie", "token=secret"):
        assert value not in json.dumps(result)


def test_bundle_queries_committed_wal_without_changing_originals(tmp_path):
    path = tmp_path / "History"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)")
        connection.commit()
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("INSERT INTO urls VALUES(1,'https://example.test/','Synthetic',1,0,13300000000000000)")
        connection.commit()
        database, wal = path.read_bytes(), path.with_name("History-wal").read_bytes()
        archive = bundle({"History": database, "History-wal": wal})
        result = analyze_evidence_bytes(archive, "browser.zip", "browser_bundle")
        assert "https://example.test/" in json.dumps(result)
        assert result["artifacts"][0]["wal_sha256"]
        assert path.read_bytes() == database
        assert path.with_name("History-wal").read_bytes() == wal


@pytest.mark.parametrize("files", [{"../History": b"invalid"}, {"History-wal": b"invalid"}, {"unknown": b"invalid"}])
def test_bundle_rejects_paths_unknown_members_and_unpaired_wal(files):
    with pytest.raises(ValueError):
        analyze_evidence_bytes(bundle(files), "browser.zip", "browser_bundle")
