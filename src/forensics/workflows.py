"""Bounded, bytes-only entry point for forensic analysis of vault evidence."""

from contextlib import closing
import io
from pathlib import Path
import sqlite3
import tempfile
from typing import Literal
import zipfile

from .browser_analyzer import BrowserAnalyzer
from .file_analyzer import FileAnalyzer
from .metadata_extractor import MetadataExtractor
from .usb_analyzer import USBAnalyzer

AnalysisKind = Literal["file", "metadata", "browser", "usb_setupapi", "usb_registry", "usb_syslog"]


def analyze_evidence_bytes(data: bytes, filename: str, kind: AnalysisKind = "file") -> dict:
    """Analyze a verified copy; never treat uploaded content as a host path."""
    if kind == "file":
        return FileAnalyzer().analyze_bytes(data, filename).model_dump(mode="json")
    if kind == "metadata":
        _check_metadata_container(data)
        result = MetadataExtractor().extract_from_bytes(data, filename)
        if result.raw_metadata.get("error"):
            raise ValueError("Metadata container could not be parsed")
        return result.model_dump(mode="json")
    if kind == "browser":
        return _analyze_browser(data)
    if kind.startswith("usb_"):
        try:
            text = data.decode("utf-16") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ValueError("USB logs must be UTF-8 or BOM-marked UTF-16 text") from exc
        if "\x00" in text:
            raise ValueError("USB logs must be text, not a binary registry hive")
        # A trailing newline prevents the legacy string-or-path API from reading
        # a local path that happens to be present in the uploaded evidence bytes.
        parser = {"usb_setupapi": USBAnalyzer().analyze_setupapi_log,
                  "usb_registry": USBAnalyzer().analyze_registry_export,
                  "usb_syslog": USBAnalyzer().analyze_syslog}[kind]
        result = parser(text + "\n").model_dump(mode="json")
        result["limitations"] = ["Only the supplied log text was examined; no host device/registry access."]
        if kind == "usb_syslog":
            result["limitations"].append("Yearless syslog timestamps use the parser's current-year assumption; verify the collection year independently.")
        return result
    raise ValueError("Unsupported analysis kind")


def _check_metadata_container(data):
    if not data.startswith(b"PK"):
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 250:
                raise ValueError("Metadata archive exceeds 250 members")
            for name in ("docProps/core.xml", "docProps/app.xml"):
                if name not in archive.namelist():
                    continue
                info = archive.getinfo(name)
                if info.file_size > 512 * 1024 or info.flag_bits & 1:
                    raise ValueError("Metadata XML exceeds limits or is encrypted")
                with archive.open(info) as member:
                    xml = member.read(512 * 1024 + 1)
                if len(xml) > 512 * 1024 or b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
                    raise ValueError("Metadata XML exceeds limits or declares entities")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid metadata archive") from exc


def _analyze_browser(data):
    if not data.startswith(b"SQLite format 3\x00"):
        raise ValueError("Browser analysis requires a SQLite artifact database")
    with tempfile.TemporaryDirectory(prefix="mms-browser-") as directory:
        artifact = Path(directory) / "artifact.db"
        artifact.write_bytes(data)
        try:
            with closing(sqlite3.connect(artifact.as_uri() + "?mode=ro", uri=True)) as conn:
                conn.execute("PRAGMA trusted_schema=OFF")
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                required = {"urls": {"url", "title", "visit_count", "typed_count", "last_visit_time"},
                            "moz_places": {"url", "title", "visit_count", "typed", "last_visit_date"},
                            "cookies": {"host_key", "name", "path", "creation_utc", "expires_utc", "is_secure", "is_httponly"},
                            "moz_cookies": {"host", "name", "path", "creationTime", "expiry", "isSecure", "isHttpOnly"}}
                candidates = set(required) & tables
                if not candidates:
                    raise ValueError("No supported browser history or cookie tables found")
                for table in candidates:
                    columns = {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}
                    if not required[table] <= columns:
                        raise ValueError(f"Unsupported browser table schema: {table}")
        except sqlite3.Error as exc:
            raise ValueError("Invalid browser database") from exc
        is_firefox = bool(tables & {"moz_places", "moz_cookies"})
        if is_firefox:
            names = [name for table, name in (("moz_places", "places.sqlite"), ("moz_cookies", "cookies.sqlite")) if table in tables]
        else:
            names = [name for table, name in (("urls", "History"), ("cookies", "Cookies")) if table in tables]
        for name in names:
            (Path(directory) / name).write_bytes(data)
        result = BrowserAnalyzer().analyze_profile_directory(directory).model_dump(mode="json")
        if result["browser_type"] == "unknown":
            result["browser_type"] = "firefox" if is_firefox else "chrome"
        result["profile_dir"] = "uploaded evidence"
        result["summary"] = result["summary"].replace(directory, "uploaded evidence")
        result["limitations"] = [
            "Only the uploaded SQLite snapshot was analyzed; uncollected WAL files, browser cache and encrypted cookie values are not included.",
            "Invalid or missing timestamps remain unknown and are omitted from chronological timelines.",
        ]
        return result
