"""Bounded browser database/WAL bundles and HAR cache metadata exports."""
from datetime import datetime
import hashlib
import io
import json
from urllib.parse import urlsplit, urlunsplit
import zipfile

from src.shared.config import settings


def analyze_cache_har(data):
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
        entries = parsed["log"]["entries"]
        if not isinstance(entries, list):
            raise ValueError("entries must be a list")
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("Expected a HAR export with log.entries") from exc
    if len(entries) > settings.forensics_max_artifact_rows:
        raise ValueError("HAR exceeds configured artifact row limit")
    results = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid HAR entry")
        request, response = entry.get("request", {}), entry.get("response", {})
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError("Invalid HAR request/response")
        url = request.get("url", "")
        if not isinstance(url, str) or len(url) > 8192:
            raise ValueError("Invalid HAR URL")
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            sanitized_url = urlunsplit((parts.scheme, host, parts.path, "", ""))
        except ValueError as exc:
            raise ValueError("Malformed HAR URL") from exc
        cache = entry.get("cache") or {}
        if not isinstance(cache, dict):
            raise ValueError("Invalid HAR cache record")
        explicit_hit = any(entry.get(key) is True or response.get(key) is True
            for key in ("_fromCache", "_fromDiskCache", "_fromMemoryCache"))
        cache_state = "hit_reported" if explicit_hit else "metadata_present" if cache else "unknown"
        timestamp = None
        try:
            stamp = datetime.fromisoformat(entry.get("startedDateTime", "").replace("Z", "+00:00"))
            if stamp.tzinfo is not None:
                timestamp = stamp.isoformat()
        except (ValueError, TypeError, AttributeError):
            pass
        headers = response.get("headers", [])
        if not isinstance(headers, list):
            raise ValueError("Invalid HAR headers")
        cache_headers = {}
        for header in headers:
            if isinstance(header, dict) and str(header.get("name", "")).lower() in ("age", "cache-control", "expires", "last-modified", "etag"):
                cache_headers[str(header["name"]).lower()] = str(header.get("value", ""))[:1024]
        results.append({"url_without_credentials_or_query": sanitized_url, "timestamp": timestamp,
            "cache_state": cache_state, "response_status": response.get("status"), "cache_headers": cache_headers,
            "cache_before_present": bool(cache.get("beforeRequest")), "cache_after_present": bool(cache.get("afterRequest"))})
    return {"artifact_type": "browser_cache_har", "entries": results, "entry_count": len(results),
        "reported_cache_hits": sum(item["cache_state"] == "hit_reported" for item in results),
        "limitations": ["Analyzes cache metadata recorded in a HAR export, not raw Chromium/Firefox binary cache files.",
            "Absent cache metadata is unknown, not proof of a network fetch. HAR flags are exporter observations.",
            "Request bodies, cookie values, authorization headers and URL queries are omitted; no URL is visited."]}


def analyze_browser_bundle(data):
    from .workflows import _analyze_browser
    databases = {"History", "Cookies", "places.sqlite", "cookies.sqlite"}
    allowed = databases | {name + "-wal" for name in databases} | {"cache.har"}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if not members or len(members) > len(allowed):
                raise ValueError("Browser bundle has an invalid member count")
            names = [member.filename for member in members]
            if len(set(names)) != len(names) or any(name not in allowed for name in names):
                raise ValueError("Bundle accepts only root History, Cookies, places.sqlite, cookies.sqlite, their -wal files, and cache.har; duplicate names are rejected")
            if sum(member.file_size for member in members) > settings.evidence_max_bytes:
                raise ValueError("Expanded browser bundle exceeds evidence size limit")
            blobs = {}
            for member in members:
                if member.flag_bits & 1:
                    raise ValueError("Encrypted browser bundles are unsupported")
                with archive.open(member) as source:
                    content = source.read(settings.evidence_max_bytes + 1)
                if len(content) > settings.evidence_max_bytes:
                    raise ValueError("Browser bundle member exceeds limit")
                blobs[member.filename] = content
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("Invalid browser ZIP bundle") from exc
    for name in blobs:
        if name.endswith("-wal") and name[:-4] not in blobs:
            raise ValueError("WAL requires its matching database in the bundle")
    artifacts = []
    for name in sorted(databases & blobs.keys()):
        wal = blobs.get(name + "-wal")
        artifacts.append({"filename": name, "sha256": hashlib.sha256(blobs[name]).hexdigest(),
            "wal_sha256": hashlib.sha256(wal).hexdigest() if wal is not None else None,
            "analysis": _analyze_browser(blobs[name], wal)})
    if "cache.har" in blobs:
        artifacts.append({"filename": "cache.har", "sha256": hashlib.sha256(blobs["cache.har"]).hexdigest(),
            "analysis": analyze_cache_har(blobs["cache.har"])})
    if not artifacts:
        raise ValueError("Bundle contains no supported browser artifacts")
    return {"artifact_type": "browser_bundle", "artifacts": artifacts,
        "limitations": ["Bundle members are analyzed as temporary copies; the registered archive remains unchanged.",
            "Only supplied artifacts are covered. Cache support uses HAR export metadata; binary cache formats are not parsed."]}
