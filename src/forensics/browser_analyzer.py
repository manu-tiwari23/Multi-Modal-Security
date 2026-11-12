"""
Forensic Browser Artifacts Analyzer.

Implements ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- Extraction and timeline reconstruction of browser history, downloads, cookies, and search queries.
- Support for Chromium-based browsers (Chrome, Edge, Brave, Opera) and Mozilla Firefox.
- Lock-free, read-only extraction that guarantees evidence immutability.
- WebKit (Chrome) and Mozilla PRTime epoch conversion to timezone-aware UTC datetimes.
- Forensic detection of suspicious keyword searches (anti-forensics, hacking tools, evasion).
- Detection of dangerous or untrusted file downloads (executables, direct IPs, browser danger flags).
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.forensics.models import (
    BrowserAnalysisResult,
    BrowserCookieEntry,
    BrowserDownloadEntry,
    BrowserHistoryEntry,
    BrowserSearchEntry,
    BrowserType,
)


# ---------------------------------------------------------------------------
# Suspicious Patterns for Searches and Downloads
# ---------------------------------------------------------------------------

SUSPICIOUS_SEARCH_PATTERNS = [
    (r"(?i)\b(mimikatz|sekurlsa|procdump|lsass\s+dump)\b", "Credential Theft"),
    (r"(?i)\b(clear\s+event\s+log|wevtutil|delete\s+journal|anti-forensics)\b", "Anti-Forensics / Log Tampering"),
    (r"(?i)\b(disable\s+defender|tamper\s+protection|bypass\s+uac|uacme)\b", "Defense Evasion"),
    (r"(?i)\b(cobalt\s+strike|metasploit|sliver\s+c2|havoc\s+c2)\b", "C2 / Post-Exploitation Framework"),
    (r"(?i)\b(cve-202[0-9]-[0-9]+|privilege\s+escalation\s+exploit|zeroday)\b", "Exploit Research"),
    (r"(?i)\b(ransomware\s+builder|decryptor|onion\s+site|darknet\s+market)\b", "Ransomware / Dark Web"),
    (r"(?i)\b(reverse\s+shell\s+generator|webshell\s+github|php\s+c99|alfa\s+shell)\b", "Webshell / Backdoor"),
]

SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".exe", ".scr", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".hta", ".iso", ".img", ".vhd", ".jar", ".cpl"
}


# ---------------------------------------------------------------------------
# Timestamp Conversion Helpers
# ---------------------------------------------------------------------------

def webkit_to_datetime(webkit_timestamp: int) -> Optional[datetime]:
    """Convert WebKit/Chrome timestamp (microseconds since Jan 1 1601 UTC) to UTC datetime."""
    if not webkit_timestamp or webkit_timestamp <= 0:
        return None
    try:
        epoch_seconds = (webkit_timestamp / 1_000_000) - 11644473600
        if 0 < epoch_seconds < 4102444800:  # 1970 - 2100
            return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except Exception:
        pass
    return None


def mozilla_to_datetime(moz_timestamp: int) -> Optional[datetime]:
    """Convert Mozilla PRTime timestamp (microseconds since Jan 1 1970 UTC) to UTC datetime."""
    if not moz_timestamp or moz_timestamp <= 0:
        return None
    try:
        epoch_seconds = moz_timestamp / 1_000_000
        if 0 < epoch_seconds < 4102444800:
            return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except Exception:
        pass
    return None


def extract_search_query_from_url(url: str) -> Optional[str]:
    """Extract search keywords from popular search engine URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Google, Bing, DuckDuckGo, Yahoo, Baidu query parameters
        for key in ["q", "query", "p", "wd"]:
            if key in params and params[key]:
                term = params[key][0].strip()
                if term:
                    return term
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Safe Isolated SQLite Loader
# ---------------------------------------------------------------------------

def safe_sqlite_query(db_path: Path, query: str, params: Tuple = ()) -> List[Tuple]:
    """Execute a query against an isolated temporary copy of a SQLite database.
    
    Guarantees:
    - Never mutates or locks the original evidence file.
    - Operates even if the original database is locked by a running browser.
    """
    if not db_path.is_file():
        return []

    # Copy to a temporary file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_name = tmp.name

    try:
        shutil.copy2(db_path, tmp_name)
        # Also copy WAL and SHM if present
        wal = db_path.parent / (db_path.name + "-wal")
        if wal.is_file():
            shutil.copy2(wal, tmp_name + "-wal")
        shm = db_path.parent / (db_path.name + "-shm")
        if shm.is_file():
            shutil.copy2(shm, tmp_name + "-shm")

        conn = sqlite3.connect(tmp_name)
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []
    finally:
        for f in [tmp_name, tmp_name + "-wal", tmp_name + "-shm"]:
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Chrome / Chromium Parser
# ---------------------------------------------------------------------------

class ChromeArtifactParser:
    """Extracts forensic artifacts from Chrome, Edge, Brave, and Chromium profiles."""

    @classmethod
    def parse_history(
        cls,
        history_path: Path,
        browser_type: BrowserType = BrowserType.CHROME,
    ) -> Tuple[List[BrowserHistoryEntry], List[BrowserDownloadEntry], List[BrowserSearchEntry]]:
        history_entries: List[BrowserHistoryEntry] = []
        downloads: List[BrowserDownloadEntry] = []
        searches: List[BrowserSearchEntry] = []

        # 1. Navigation History from 'urls' table
        url_rows = safe_sqlite_query(
            history_path,
            "SELECT url, title, visit_count, typed_count, last_visit_time FROM urls WHERE url IS NOT NULL",
        )
        for url, title, v_count, t_count, last_time in url_rows:
            dt = webkit_to_datetime(last_time) or datetime.now(timezone.utc)
            history_entries.append(
                BrowserHistoryEntry(
                    url=url,
                    title=title or url,
                    visit_time=dt,
                    visit_count=v_count or 1,
                    typed_count=t_count or 0,
                    browser_type=browser_type,
                )
            )
            # Check URL for search engine queries
            search_query = extract_search_query_from_url(url)
            if search_query:
                searches.append(cls._evaluate_search_term(search_query, dt, browser_type))

        # 2. Keyword Search Terms from 'keyword_search_terms' table if present
        keyword_rows = safe_sqlite_query(
            history_path,
            "SELECT term FROM keyword_search_terms WHERE term IS NOT NULL",
        )
        for (term,) in keyword_rows:
            if term and not any(s.term.lower() == term.lower() for s in searches):
                searches.append(cls._evaluate_search_term(term, None, browser_type))

        # 3. Downloads from 'downloads' table
        download_rows = safe_sqlite_query(
            history_path,
            "SELECT target_path, tab_url, start_time, end_time, total_bytes, state, danger_type FROM downloads",
        )
        for target, tab_url, start_t, end_t, total_b, state_code, danger_type in download_rows:
            s_dt = webkit_to_datetime(start_t) or datetime.now(timezone.utc)
            e_dt = webkit_to_datetime(end_t)

            state_map = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}
            state_str = state_map.get(state_code, "unknown")

            download = BrowserDownloadEntry(
                target_path=target or "unknown",
                source_url=tab_url or "unknown",
                start_time=s_dt,
                end_time=e_dt,
                total_bytes=total_b or 0,
                state=state_str,
                danger_type=danger_type or 0,
                browser_type=browser_type,
            )
            cls._evaluate_download(download)
            downloads.append(download)

        return history_entries, downloads, searches

    @classmethod
    def parse_cookies(
        cls,
        cookies_path: Path,
        browser_type: BrowserType = BrowserType.CHROME,
    ) -> List[BrowserCookieEntry]:
        cookies: List[BrowserCookieEntry] = []
        rows = safe_sqlite_query(
            cookies_path,
            "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly FROM cookies",
        )
        for host, name, path, creation_utc, expires_utc, is_sec, is_http in rows:
            c_dt = webkit_to_datetime(creation_utc) or datetime.now(timezone.utc)
            e_dt = webkit_to_datetime(expires_utc)
            cookies.append(
                BrowserCookieEntry(
                    host=host,
                    name=name,
                    path=path or "/",
                    creation_time=c_dt,
                    expires_time=e_dt,
                    is_secure=bool(is_sec),
                    is_httponly=bool(is_http),
                )
            )
        return cookies

    @classmethod
    def _evaluate_search_term(cls, term: str, dt: Optional[datetime], browser: BrowserType) -> BrowserSearchEntry:
        is_susp = False
        category: Optional[str] = None
        for pattern, cat in SUSPICIOUS_SEARCH_PATTERNS:
            if re.search(pattern, term):
                is_susp = True
                category = cat
                break
        return BrowserSearchEntry(
            term=term,
            search_time=dt,
            browser_type=browser,
            is_suspicious=is_susp,
            category=category,
        )

    @classmethod
    def _evaluate_download(cls, download: BrowserDownloadEntry) -> None:
        reasons: List[str] = []
        ext = Path(download.target_path).suffix.lower()

        if ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS:
            reasons.append(f"Executable/script download extension '{ext}'")

        if download.danger_type > 0:
            reasons.append(f"Browser flagged danger type ({download.danger_type})")

        # Check if source URL is a raw IP address (common for malware drop sites)
        if re.search(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", download.source_url):
            reasons.append("Downloaded directly from an IP address host")

        if reasons:
            download.is_suspicious = True
            download.suspicious_reason = "; ".join(reasons)


# ---------------------------------------------------------------------------
# Firefox Parser
# ---------------------------------------------------------------------------

class FirefoxArtifactParser:
    """Extracts forensic artifacts from Mozilla Firefox profiles."""

    @classmethod
    def parse_places(
        cls,
        places_path: Path,
    ) -> Tuple[List[BrowserHistoryEntry], List[BrowserDownloadEntry], List[BrowserSearchEntry]]:
        history_entries: List[BrowserHistoryEntry] = []
        downloads: List[BrowserDownloadEntry] = []
        searches: List[BrowserSearchEntry] = []

        # 1. Navigation history from moz_places
        url_rows = safe_sqlite_query(
            places_path,
            "SELECT url, title, visit_count, typed, last_visit_date FROM moz_places WHERE url IS NOT NULL",
        )
        for url, title, v_count, typed, last_date in url_rows:
            dt = mozilla_to_datetime(last_date) or datetime.now(timezone.utc)
            history_entries.append(
                BrowserHistoryEntry(
                    url=url,
                    title=title or url,
                    visit_time=dt,
                    visit_count=v_count or 1,
                    typed_count=typed or 0,
                    browser_type=BrowserType.FIREFOX,
                )
            )
            # Check URL for search engine queries
            search_query = extract_search_query_from_url(url)
            if search_query:
                searches.append(ChromeArtifactParser._evaluate_search_term(search_query, dt, BrowserType.FIREFOX))

        # 2. Check for downloads recorded in moz_annos
        anno_rows = safe_sqlite_query(
            places_path,
            """
            SELECT p.url, a.content, a.dateAdded
            FROM moz_annos a
            JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id
            JOIN moz_places p ON a.place_id = p.id
            WHERE n.name = 'downloads/destinationFileURI'
            """,
        )
        for url, content, date_added in anno_rows:
            dt = mozilla_to_datetime(date_added) or datetime.now(timezone.utc)
            # destinationFileURI is typically file:///...
            dest_path = urllib.parse.unquote(content).replace("file:///", "").replace("file://", "")
            download = BrowserDownloadEntry(
                target_path=dest_path,
                source_url=url,
                start_time=dt,
                browser_type=BrowserType.FIREFOX,
            )
            ChromeArtifactParser._evaluate_download(download)
            downloads.append(download)

        return history_entries, downloads, searches

    @classmethod
    def parse_cookies(cls, cookies_path: Path) -> List[BrowserCookieEntry]:
        cookies: List[BrowserCookieEntry] = []
        rows = safe_sqlite_query(
            cookies_path,
            "SELECT host, name, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies",
        )
        for host, name, path, creation_time, expiry, is_sec, is_http in rows:
            c_dt = mozilla_to_datetime(creation_time) or datetime.now(timezone.utc)
            e_dt = datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry and expiry > 0 else None
            cookies.append(
                BrowserCookieEntry(
                    host=host,
                    name=name,
                    path=path or "/",
                    creation_time=c_dt,
                    expires_time=e_dt,
                    is_secure=bool(is_sec),
                    is_httponly=bool(is_http),
                )
            )
        return cookies


# ---------------------------------------------------------------------------
# Browser Analyzer Orchestrator
# ---------------------------------------------------------------------------

class BrowserAnalyzer:
    """Forensic browser artifact analysis engine."""

    def detect_browser_type(self, path: Path) -> BrowserType:
        """Infer browser type from directory structure or filename."""
        p_str = str(path).lower()
        if "edge" in p_str:
            return BrowserType.EDGE
        elif "brave" in p_str:
            return BrowserType.BRAVE
        elif "opera" in p_str:
            return BrowserType.OPERA
        elif "firefox" in p_str or (path.is_dir() and (path / "places.sqlite").exists()) or path.name == "places.sqlite":
            return BrowserType.FIREFOX
        elif "chrome" in p_str or (path.is_dir() and (path / "History").exists()) or path.name == "History":
            return BrowserType.CHROME
        return BrowserType.UNKNOWN

    def analyze_profile_directory(self, profile_dir: Union[str, Path]) -> BrowserAnalysisResult:
        """Analyze a complete browser profile directory."""
        dir_path = Path(profile_dir).resolve()
        if not dir_path.is_dir():
            raise FileNotFoundError(f"Browser profile directory not found: '{dir_path}'")

        browser = self.detect_browser_type(dir_path)

        all_history: List[BrowserHistoryEntry] = []
        all_downloads: List[BrowserDownloadEntry] = []
        all_cookies: List[BrowserCookieEntry] = []
        all_searches: List[BrowserSearchEntry] = []

        # 1. Chromium profile parsing (History, Cookies)
        history_file = dir_path / "History"
        if history_file.is_file():
            h, d, s = ChromeArtifactParser.parse_history(history_file, browser_type=browser if browser != BrowserType.UNKNOWN else BrowserType.CHROME)
            all_history.extend(h)
            all_downloads.extend(d)
            all_searches.extend(s)

        cookies_file = dir_path / "Cookies"
        if not cookies_file.is_file():
            cookies_file = dir_path / "Network" / "Cookies"
        if cookies_file.is_file():
            all_cookies.extend(ChromeArtifactParser.parse_cookies(cookies_file, browser_type=browser))

        # 2. Firefox profile parsing (places.sqlite, cookies.sqlite)
        places_file = dir_path / "places.sqlite"
        if places_file.is_file():
            browser = BrowserType.FIREFOX
            h, d, s = FirefoxArtifactParser.parse_places(places_file)
            all_history.extend(h)
            all_downloads.extend(d)
            all_searches.extend(s)

        ff_cookies = dir_path / "cookies.sqlite"
        if ff_cookies.is_file():
            all_cookies.extend(FirefoxArtifactParser.parse_cookies(ff_cookies))

        return self._build_result(browser, str(dir_path), all_history, all_downloads, all_cookies, all_searches)

    def analyze_history_file(
        self,
        file_path: Union[str, Path],
        browser_type: Optional[BrowserType] = None,
    ) -> BrowserAnalysisResult:
        """Analyze a standalone History database file (History or places.sqlite)."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"History file not found: '{path}'")

        b_type = browser_type or self.detect_browser_type(path)
        all_history: List[BrowserHistoryEntry] = []
        all_downloads: List[BrowserDownloadEntry] = []
        all_searches: List[BrowserSearchEntry] = []

        if b_type == BrowserType.FIREFOX or path.name.lower() == "places.sqlite":
            h, d, s = FirefoxArtifactParser.parse_places(path)
            all_history.extend(h)
            all_downloads.extend(d)
            all_searches.extend(s)
            b_type = BrowserType.FIREFOX
        else:
            actual_type = b_type if b_type != BrowserType.UNKNOWN else BrowserType.CHROME
            h, d, s = ChromeArtifactParser.parse_history(path, browser_type=actual_type)
            all_history.extend(h)
            all_downloads.extend(d)
            all_searches.extend(s)
            b_type = actual_type

        return self._build_result(b_type, str(path.parent), all_history, all_downloads, [], all_searches)

    def _build_result(
        self,
        browser: BrowserType,
        profile_path: str,
        history: List[BrowserHistoryEntry],
        downloads: List[BrowserDownloadEntry],
        cookies: List[BrowserCookieEntry],
        searches: List[BrowserSearchEntry],
    ) -> BrowserAnalysisResult:
        susp_searches = [s.term for s in searches if s.is_suspicious]
        susp_downloads = [d for d in downloads if d.is_suspicious]

        # Build chronological timeline
        timeline: List[Dict[str, Any]] = []

        for h in history:
            timeline.append({
                "timestamp": h.visit_time.isoformat(),
                "type": "navigation",
                "url": h.url,
                "title": h.title,
                "is_suspicious": False,
            })

        for d in downloads:
            timeline.append({
                "timestamp": d.start_time.isoformat(),
                "type": "download",
                "target_path": d.target_path,
                "source_url": d.source_url,
                "is_suspicious": d.is_suspicious,
                "reason": d.suspicious_reason,
            })

        for s in searches:
            if s.search_time:
                timeline.append({
                    "timestamp": s.search_time.isoformat(),
                    "type": "search",
                    "term": s.term,
                    "is_suspicious": s.is_suspicious,
                    "category": s.category,
                })

        # Sort timeline chronologically
        timeline.sort(key=lambda item: item["timestamp"])

        summary_parts = [
            f"Parsed {browser.value.upper()} artifacts from '{profile_path}':",
            f"{len(history)} visit(s), {len(downloads)} download(s), {len(cookies)} cookie(s), {len(searches)} search(es).",
        ]
        if susp_searches:
            summary_parts.append(f"FLAGGED: {len(susp_searches)} suspicious search query(ies).")
        if susp_downloads:
            summary_parts.append(f"FLAGGED: {len(susp_downloads)} high-risk file download(s).")

        return BrowserAnalysisResult(
            browser_type=browser,
            profile_dir=profile_path,
            history_count=len(history),
            downloads_count=len(downloads),
            cookies_count=len(cookies),
            search_terms_count=len(searches),
            history_entries=history,
            downloads=downloads,
            cookies=cookies,
            search_terms=searches,
            suspicious_searches=susp_searches,
            suspicious_downloads=susp_downloads,
            timeline=timeline,
            summary=" ".join(summary_parts),
        )
