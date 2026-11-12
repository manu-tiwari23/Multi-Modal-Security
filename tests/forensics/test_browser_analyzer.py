"""
Unit tests for Forensic Browser Artifacts Analyzer.

Verifies:
1. WebKit/Chrome and Mozilla PRTime epoch timestamp conversions.
2. Search query extraction from search engine URLs.
3. Chrome/Chromium history, downloads, cookies, and keyword search term parsing.
4. Detection of suspicious search terms (anti-forensics, credential theft, evasion).
5. Detection of high-risk file downloads (executables, direct IPs, danger flags).
6. Firefox places.sqlite and cookies.sqlite parsing.
7. End-to-end browser profile directory analysis and chronological timeline reconstruction.
8. Immutability and lock-free SQLite querying.
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.forensics.browser_analyzer import (
    BrowserAnalyzer,
    ChromeArtifactParser,
    FirefoxArtifactParser,
    extract_search_query_from_url,
    mozilla_to_datetime,
    safe_sqlite_query,
    webkit_to_datetime,
)
from src.forensics.models import (
    BrowserAnalysisResult,
    BrowserType,
)


class TestBrowserAnalyzer:
    """Test suite for browser forensic artifact parsing and timeline reconstruction."""

    def test_timestamp_conversions(self):
        """Verify WebKit and Mozilla epoch timestamp conversions to UTC."""
        # 2026-08-20 12:00:00 UTC
        target_dt = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
        unix_secs = int(target_dt.timestamp())

        # WebKit: microseconds since Jan 1 1601
        webkit_ts = (unix_secs + 11644473600) * 1_000_000
        converted_webkit = webkit_to_datetime(webkit_ts)
        assert converted_webkit is not None
        assert converted_webkit.year == 2026
        assert converted_webkit.month == 8
        assert converted_webkit.day == 20
        assert converted_webkit.hour == 12

        # Mozilla: microseconds since Jan 1 1970
        moz_ts = unix_secs * 1_000_000
        converted_moz = mozilla_to_datetime(moz_ts)
        assert converted_moz is not None
        assert converted_moz.year == 2026
        assert converted_moz.month == 8

        # Edge cases
        assert webkit_to_datetime(0) is None
        assert webkit_to_datetime(-100) is None
        assert mozilla_to_datetime(0) is None

    def test_extract_search_queries_from_urls(self):
        """Verify extraction of search terms from search engine URLs."""
        g_url = "https://www.google.com/search?q=how+to+clear+event+log&oq=how..."
        assert extract_search_query_from_url(g_url) == "how to clear event log"

        ddg_url = "https://duckduckgo.com/?q=mimikatz+download+github&t=h_"
        assert extract_search_query_from_url(ddg_url) == "mimikatz download github"

        bing_url = "https://www.bing.com/search?q=disable+windows+defender+powershell"
        assert extract_search_query_from_url(bing_url) == "disable windows defender powershell"

        plain_url = "https://example.com/index.html"
        assert extract_search_query_from_url(plain_url) is None

    def test_chrome_history_and_download_parsing(self):
        """Verify parsing of Chrome History SQLite database (urls, visits, downloads)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            hist_file = Path(tmp_dir) / "History"
            conn = sqlite3.connect(hist_file)
            c = conn.cursor()

            # Create Chrome tables
            c.execute("""
                CREATE TABLE urls (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    visit_count INTEGER,
                    typed_count INTEGER,
                    last_visit_time INTEGER
                )
            """)
            c.execute("""
                CREATE TABLE downloads (
                    id INTEGER PRIMARY KEY,
                    target_path TEXT,
                    tab_url TEXT,
                    start_time INTEGER,
                    end_time INTEGER,
                    total_bytes INTEGER,
                    state INTEGER,
                    danger_type INTEGER
                )
            """)
            c.execute("""
                CREATE TABLE keyword_search_terms (
                    keyword_id INTEGER,
                    url_id INTEGER,
                    term TEXT
                )
            """)

            # Insert sample data (WebKit timestamp for Aug 2026)
            ts = (1787227200 + 11644473600) * 1_000_000
            c.execute(
                "INSERT INTO urls VALUES (1, 'https://www.google.com/search?q=reverse+shell+generator', 'Google Search', 2, 1, ?)",
                (ts,),
            )
            c.execute(
                "INSERT INTO urls VALUES (2, 'https://github.com/security/tools', 'Security Tools', 1, 0, ?)",
                (ts + 60_000_000,),
            )

            # Insert a suspicious download (executable from direct IP, danger_type=1)
            c.execute(
                "INSERT INTO downloads VALUES (1, 'C:\\\\Users\\\\Victim\\\\Downloads\\\\payload.exe', 'http://198.51.100.25/dropper.exe', ?, ?, 1048576, 1, 1)",
                (ts + 120_000_000, ts + 130_000_000),
            )

            # Insert keyword search
            c.execute("INSERT INTO keyword_search_terms VALUES (1, 1, 'reverse shell generator')")
            conn.commit()
            conn.close()

            entries, downloads, searches = ChromeArtifactParser.parse_history(hist_file, browser_type=BrowserType.CHROME)

            # Assertions
            assert len(entries) == 2
            assert entries[0].url.startswith("https://www.google.com")
            assert entries[0].visit_count == 2
            assert entries[0].visit_time.year == 2026

            # Download checks
            assert len(downloads) == 1
            dl = downloads[0]
            assert "payload.exe" in dl.target_path
            assert dl.is_suspicious is True
            assert "Executable" in dl.suspicious_reason
            assert "IP address" in dl.suspicious_reason
            assert "danger type" in dl.suspicious_reason

            # Search checks
            assert len(searches) >= 1
            assert any(s.term == "reverse shell generator" and s.is_suspicious for s in searches)
            assert any(s.category == "Webshell / Backdoor" for s in searches)

    def test_chrome_cookies_parsing(self):
        """Verify extraction of Chrome cookies."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cookies_file = Path(tmp_dir) / "Cookies"
            conn = sqlite3.connect(cookies_file)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE cookies (
                    host_key TEXT,
                    name TEXT,
                    path TEXT,
                    creation_utc INTEGER,
                    expires_utc INTEGER,
                    is_secure INTEGER,
                    is_httponly INTEGER
                )
            """)

            ts = (1787227200 + 11644473600) * 1_000_000
            c.execute("INSERT INTO cookies VALUES ('.example.com', 'session_id', '/', ?, ?, 1, 1)", (ts, ts + 86400_000_000))
            conn.commit()
            conn.close()

            cookies = ChromeArtifactParser.parse_cookies(cookies_file, browser_type=BrowserType.CHROME)
            assert len(cookies) == 1
            assert cookies[0].host == ".example.com"
            assert cookies[0].name == "session_id"
            assert cookies[0].is_secure is True
            assert cookies[0].is_httponly is True
            assert cookies[0].creation_time.year == 2026

    def test_firefox_places_and_cookies_parsing(self):
        """Verify extraction from Firefox places.sqlite and cookies.sqlite databases."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            places_file = Path(tmp_dir) / "places.sqlite"
            cookies_file = Path(tmp_dir) / "cookies.sqlite"

            # Create places.sqlite
            p_conn = sqlite3.connect(places_file)
            p_c = p_conn.cursor()
            p_c.execute("""
                CREATE TABLE moz_places (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    visit_count INTEGER,
                    typed INTEGER,
                    last_visit_date INTEGER
                )
            """)
            p_c.execute("CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT)")
            p_c.execute("CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER)")

            # Insert sample places (PRTime: microseconds since 1970)
            moz_ts = 1787227200 * 1_000_000
            p_c.execute("INSERT INTO moz_places VALUES (1, 'https://www.google.com/search?q=mimikatz+guide', 'Google Search', 3, 1, ?)", (moz_ts,))
            p_c.execute("INSERT INTO moz_places VALUES (2, 'http://malware-drop.org/script.ps1', 'Dropper', 1, 0, ?)", (moz_ts + 60_000_000,))

            # Insert download annotation
            p_c.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI')")
            p_c.execute("INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///C:/Users/Victim/Downloads/script.ps1', ?)", (moz_ts + 60_000_000,))
            p_conn.commit()
            p_conn.close()

            # Create cookies.sqlite
            c_conn = sqlite3.connect(cookies_file)
            c_c = c_conn.cursor()
            c_c.execute("""
                CREATE TABLE moz_cookies (
                    id INTEGER PRIMARY KEY,
                    host TEXT,
                    name TEXT,
                    path TEXT,
                    creationTime INTEGER,
                    expiry INTEGER,
                    isSecure INTEGER,
                    isHttpOnly INTEGER
                )
            """)
            c_c.execute("INSERT INTO moz_cookies VALUES (1, '.corp-login.net', 'auth_token', '/', ?, ?, 1, 1)", (moz_ts, 1787313600))
            c_conn.commit()
            c_conn.close()

            # Parse Firefox artifacts
            history, downloads, searches = FirefoxArtifactParser.parse_places(places_file)
            cookies = FirefoxArtifactParser.parse_cookies(cookies_file)

            assert len(history) == 2
            assert history[0].browser_type == BrowserType.FIREFOX
            assert len(downloads) == 1
            assert "script.ps1" in downloads[0].target_path
            assert downloads[0].is_suspicious is True

            assert len(cookies) == 1
            assert cookies[0].host == ".corp-login.net"

            # Search term checks
            assert len(searches) >= 1
            assert any(s.term == "mimikatz guide" and s.is_suspicious for s in searches)
            assert any(s.category == "Credential Theft" for s in searches)

    def test_browser_analyzer_full_profile_directory(self):
        """Verify full directory analysis and chronological timeline assembly."""
        analyzer = BrowserAnalyzer()

        with tempfile.TemporaryDirectory() as prof_dir:
            p_dir = Path(prof_dir)
            hist_file = p_dir / "History"

            conn = sqlite3.connect(hist_file)
            c = conn.cursor()
            c.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)")
            c.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER)")
            c.execute("CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT)")

            ts = (1787227200 + 11644473600) * 1_000_000
            c.execute("INSERT INTO urls VALUES (1, 'https://www.google.com/search?q=how+to+clear+event+log', 'Search', 1, 1, ?)", (ts,))
            c.execute("INSERT INTO downloads VALUES (1, 'C:\\\\tools\\\\nmap.exe', 'https://nmap.org/dist/nmap.exe', ?, ?, 5000000, 1, 0)", (ts + 50_000_000, ts + 60_000_000))
            conn.commit()
            conn.close()

            result = analyzer.analyze_profile_directory(p_dir)
            assert isinstance(result, BrowserAnalysisResult)
            assert result.history_count == 1
            assert result.downloads_count == 1
            assert len(result.suspicious_searches) == 1
            assert "how to clear event log" in result.suspicious_searches[0]

            # Timeline checks
            assert len(result.timeline) >= 2
            timeline_types = [event["type"] for event in result.timeline]
            assert "navigation" in timeline_types
            assert "download" in timeline_types
            assert "FLAGGED:" in result.summary

    def test_safe_sqlite_query_immutability(self):
        """Verify safe_sqlite_query does not lock or mutate the original file."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("CREATE TABLE test (val TEXT)")
            conn.execute("INSERT INTO test VALUES ('sample_data')")
            conn.commit()
            conn.close()

            # Execute query via safe_sqlite_query
            rows = safe_sqlite_query(tmp_path, "SELECT val FROM test")
            assert rows == [("sample_data",)]

            # Verify original file is pristine and unmodified
            conn2 = sqlite3.connect(tmp_path)
            rows2 = conn2.execute("SELECT val FROM test").fetchall()
            conn2.close()
            assert rows2 == [("sample_data",)]
        finally:
            tmp_path.unlink(missing_ok=True)
