"""
Unit tests for Digital Forensics USB Activity Analyzer (Phase 6, Feature 5).

Verifies:
- Windows setupapi.dev.log parsing (sections, timestamps, VID/PID, serial numbers).
- Windows Registry export parsing (USBSTOR, USB, MountedDevices drive letter mapping).
- Linux kernel and syslog USB connection records (connection, SCSI storage mount, disconnect).
- Detection of BadUSB and keystroke injection hardware (Rubber Ducky, Teensy, Flipper Zero).
- Suspicious firmware default serial numbers.
- Multi-source forensic correlation across logs and registry.
- Edge cases: corrupt logs, empty files, non-USB device sections.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.forensics.models import (
    USBAnalysisResult,
    USBDeviceArtifact,
    USBTimelineEntry,
)
from src.forensics.usb_analyzer import (
    KNOWN_USB_VENDORS,
    LinuxSyslogParser,
    RegistryParser,
    SetupApiParser,
    ThreatEvaluator,
    USBAnalyzer,
    parse_setupapi_timestamp,
    parse_syslog_timestamp,
)


class TestUSBAnalyzer:
    """Test suite for USB device forensic investigation engine."""

    def test_vendor_id_database_lookups(self):
        """Verify known hardware vendor IDs resolve accurately."""
        assert KNOWN_USB_VENDORS.get("0781") == "SanDisk Corp."
        assert KNOWN_USB_VENDORS.get("0951") == "Kingston Technology Corp."
        assert KNOWN_USB_VENDORS.get("05ac") == "Apple, Inc."
        assert KNOWN_USB_VENDORS.get("1d50") == "OpenMoko, Inc. (Flipper Zero / Great Scott Gadgets)"
        assert KNOWN_USB_VENDORS.get("2341") == "Arduino SA"

    def test_parse_setupapi_timestamp(self):
        """Test parsing setupapi timestamps with and without milliseconds."""
        ts1 = parse_setupapi_timestamp("2026/08/15 14:22:10.123")
        assert ts1 is not None
        assert ts1.year == 2026
        assert ts1.month == 8
        assert ts1.day == 15
        assert ts1.hour == 14
        assert ts1.minute == 22
        assert ts1.second == 10
        assert ts1.microsecond == 123000
        assert ts1.tzinfo == timezone.utc

        ts2 = parse_setupapi_timestamp("2026/08/15 14:22:10")
        assert ts2 is not None
        assert ts2.microsecond == 0

        assert parse_setupapi_timestamp("invalid-date") is None

    def test_setupapi_usbstor_and_vid_pid_parsing(self):
        """Test parsing realistic Windows setupapi.dev.log sections."""
        synthetic_setupapi = """
[Device Install Log]
     os: Major = 10, Minor = 0, Build = 22631, Platform = 2
>>>  [Device Install (DiShowUpdateDevice) - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001280424116043&0]
>>>  Section start 2026/08/15 14:22:10.500
     dvi: Device Description: Disk drive
     dvi: Matching Device ID: usbstor\\disk
     inf: Opened INF: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\disk.inf_amd64_xxx\\disk.inf'
<<<  [Exit status: SUCCESS]
<<<  Section end 2026/08/15 14:22:11.200
>>>  [Device Install (DiShowUpdateDevice) - USB\\VID_0781&PID_5583\\4C530001280424116043]
>>>  Section start 2026/08/15 14:22:08.100
     dvi: Device Description: USB Mass Storage Device
<<<  [Exit status: SUCCESS]
<<<  Section end 2026/08/15 14:22:09.000
"""
        analyzer = USBAnalyzer()
        result = analyzer.analyze_setupapi_log(synthetic_setupapi)

        assert isinstance(result, USBAnalysisResult)
        assert result.device_count == 1  # Correlated under the same serial number: 4C530001280424116043
        dev = result.devices_detected[0]

        assert dev.serial_number == "4C530001280424116043"
        assert dev.vendor_name in ("SanDisk", "SanDisk Corp.")
        assert dev.product_name == "Ultra"
        assert dev.vendor_id == "0781"
        assert dev.product_id == "5583"
        assert dev.first_install_time == datetime(2026, 8, 15, 14, 22, 8, 100000, tzinfo=timezone.utc)
        assert dev.device_class == "Mass Storage"
        assert not dev.is_suspicious

    def test_registry_parsing_with_mounted_devices(self):
        """Test parsing Windows Registry .reg export containing USBSTOR and MountedDevices."""
        synthetic_reg = r"""
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler&Rev_PMAP\0014D11654321A&0]
"FriendlyName"="Kingston DataTraveler 3.0 USB Device"
"ContainerID"="{11223344-5566-7788-99aa-bbccddeeff00}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_0951&PID_1666\0014D11654321A]
"FriendlyName"="Kingston USB 3.0 Storage"

[HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices]
"\\DosDevices\\E:"=hex:5c,00,3f,00,3f,00,5c,00,55,00,53,00,42,00,53,00,54,00,4f,\
  00,52,00,23,00,44,00,69,00,73,00,6b,00,26,00,56,00,65,00,6e,00,5f,00,4b,00,\
  69,00,6e,00,67,00,73,00,74,00,6f,00,6e,00,23,00,30,00,30,00,31,00,34,00,44,\
  00,31,00,31,00,36,00,35,00,34,00,33,00,32,00,31,00,41,00,26,00,30,00,23,00
"""
        analyzer = USBAnalyzer()
        result = analyzer.analyze_registry_export(synthetic_reg)

        assert result.device_count == 1
        dev = result.devices_detected[0]
        assert dev.serial_number == "0014D11654321A"
        assert dev.vendor_id == "0951"
        assert dev.product_id == "1666"
        assert dev.vendor_name == "Kingston Technology Corp."
        assert dev.device_description == "Kingston DataTraveler 3.0 USB Device"
        assert "E:" in dev.drive_letters

    def test_badusb_hardware_signature_detection(self):
        """Test detection of known hardware keystroke injection and attack devices."""
        attack_cases = [
            ("16d0", "0753", "Digispark"),
            ("16c0", "0486", "Teensy"),
            ("1d50", "6089", "Flipper Zero"),
            ("2341", "8036", "Arduino Leonardo"),
            ("1b4f", "9206", "SparkFun Pro Micro"),
            ("1fc9", "0080", "Rubber Ducky"),
        ]

        for vid, pid, expected_keyword in attack_cases:
            artifact = USBDeviceArtifact(
                device_id=f"USB\\VID_{vid}&PID_{pid}\\12345",
                vendor_id=vid,
                product_id=pid,
                serial_number="SERIAL001",
            )
            ThreatEvaluator.evaluate(artifact)
            assert artifact.is_suspicious is True
            assert artifact.suspicious_reason is not None
            assert expected_keyword.lower() in artifact.suspicious_reason.lower()

    def test_badusb_suspicious_serial_patterns(self):
        """Test detection of suspicious default attack firmware serial numbers."""
        suspicious_serials = [
            "000000000001",
            "12345678",
            "DEADBEEF42",
            "badusb_v1",
            "rubberducky_payload",
            "flipper_lab",
        ]

        for s in suspicious_serials:
            artifact = USBDeviceArtifact(
                device_id=f"USB\\VID_0781&PID_5583\\{s}",
                vendor_id="0781",
                product_id="5583",
                serial_number=s,
            )
            ThreatEvaluator.evaluate(artifact)
            assert artifact.is_suspicious is True
            assert "serial pattern" in artifact.suspicious_reason.lower()

    def test_linux_syslog_and_dmesg_parsing(self):
        """Test parsing Linux kernel syslog lines for device connection, SCSI attach, and removal."""
        syslog_content = """
Aug 15 14:22:10 sec-workstation kernel: [ 100.123] usb 1-1: New USB device found, idVendor=0781, idProduct=5583, bcdDevice= 1.00
Aug 15 14:22:10 sec-workstation kernel: [ 100.124] usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
Aug 15 14:22:10 sec-workstation kernel: [ 100.125] usb 1-1: Product: Ultra USB 3.0
Aug 15 14:22:10 sec-workstation kernel: [ 100.126] usb 1-1: Manufacturer: SanDisk
Aug 15 14:22:10 sec-workstation kernel: [ 100.127] usb 1-1: SerialNumber: 4C530001280424116043
Aug 15 14:22:12 sec-workstation kernel: [ 102.400] sd 2:0:0:0: [sdb] Attached SCSI removable disk
Aug 15 14:25:30 sec-workstation kernel: [ 300.000] usb 1-1: USB disconnect, device number 2
"""
        analyzer = USBAnalyzer()
        result = analyzer.analyze_syslog(syslog_content)

        assert result.device_count == 1
        dev = result.devices_detected[0]
        assert dev.vendor_id == "0781"
        assert dev.product_id == "5583"
        assert dev.vendor_name == "SanDisk"
        assert dev.product_name == "Ultra USB 3.0"
        assert dev.serial_number == "4C530001280424116043"
        assert "sdb" in dev.drive_letters
        assert dev.last_disconnected_time is not None

        # Verify timeline records
        assert len(result.timeline) == 3
        types = [t["event_type"] for t in result.timeline]
        assert "connection" in types
        assert "drive_mounted" in types
        assert "disconnection" in types

    def test_multi_source_forensic_correlation(self):
        """Test cross-correlating setupapi logs, registry exports, and syslog."""
        setupapi_log = """
>>>  [Device Install - USB\\VID_0781&PID_5583\\SAN_SERIAL_999]
>>>  Section start 2026/08/15 10:00:00.000
<<<  [Exit status: SUCCESS]
<<<  Section end 2026/08/15 10:00:01.000
"""
        registry_dump = r"""
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Extreme\SAN_SERIAL_999&0]
"FriendlyName"="SanDisk Extreme Pro"

[HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices]
"\\DosDevices\\F:"=hex:5c,00,3f,00,53,00,41,00,4e,00,5f,00,53,00,45,00,52,00,49,\
  00,41,00,4c,00,5f,00,39,00,39,00,39,00
"""
        analyzer = USBAnalyzer()
        result = analyzer.analyze_multi_source(
            setupapi_content=setupapi_log,
            registry_content=registry_dump,
        )

        assert result.device_count == 1
        dev = result.devices_detected[0]
        assert dev.serial_number == "SAN_SERIAL_999"
        assert dev.vendor_id == "0781"
        assert dev.vendor_name in ("SanDisk", "SanDisk Corp.")
        assert dev.device_description == "SanDisk Extreme Pro"
        assert "F:" in dev.drive_letters
        assert "setupapi.dev.log" in dev.source_artifacts
        assert "registry_usbstor" in dev.source_artifacts
        assert dev.first_install_time == datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc)

    def test_file_input_from_disk(self):
        """Verify analyzing log and registry files directly from disk."""
        log_text = """
>>>  [Device Install - USB\\VID_1d50&PID_6089\\FLIPPER_001]
>>>  Section start 2026/08/15 11:30:00.000
<<<  [Exit status: SUCCESS]
<<<  Section end 2026/08/15 11:30:02.000
"""
        with tempfile.NamedTemporaryFile("w", suffix=".dev.log", delete=False) as f:
            f.write(log_text)
            f_path = Path(f.name)

        try:
            analyzer = USBAnalyzer()
            res = analyzer.analyze_setupapi_log(f_path)
            assert res.device_count == 1
            assert res.suspicious_device_count == 1
            assert res.devices_detected[0].is_suspicious is True
            assert "Flipper Zero" in res.devices_detected[0].suspicious_reason
        finally:
            if f_path.is_file():
                f_path.unlink()

    def test_corrupted_or_empty_log_handling(self):
        """Verify graceful recovery on corrupted, binary, or empty log data."""
        analyzer = USBAnalyzer()

        # 1. Empty string
        res_empty = analyzer.analyze_setupapi_log("")
        assert res_empty.device_count == 0
        assert len(res_empty.timeline) == 0

        # 2. Random binary garbage
        garbage = "Random text with symbols \x00\x01\xfe\xff without any USB sections."
        res_garbage = analyzer.analyze_setupapi_log(garbage)
        assert res_garbage.device_count == 0

        # 3. Non-USB sections (e.g. PCI, Bluetooth, Audio)
        non_usb = """
>>>  [Device Install - PCI\\VEN_10DE&DEV_1F02\\3&11583659&0&00]
>>>  Section start 2026/08/15 12:00:00.000
<<<  [Exit status: SUCCESS]
"""
        res_non_usb = analyzer.analyze_setupapi_log(non_usb)
        assert res_non_usb.device_count == 0

    def test_timeline_chronological_ordering(self):
        """Verify multiple USB events from different timestamps are sorted chronologically."""
        setupapi_content = """
>>>  [Device Install - USB\\VID_0781&PID_5583\\SERIAL_LATER]
>>>  Section start 2026/08/15 18:00:00.000
<<<  [Exit status: SUCCESS]

>>>  [Device Install - USB\\VID_0951&PID_1666\\SERIAL_EARLIER]
>>>  Section start 2026/08/15 09:00:00.000
<<<  [Exit status: SUCCESS]
"""
        analyzer = USBAnalyzer()
        res = analyzer.analyze_setupapi_log(setupapi_content)
        assert len(res.timeline) == 2
        # Earlier event should come first
        assert res.timeline[0]["timestamp"] < res.timeline[1]["timestamp"]
        assert "SERIAL_EARLIER" in res.timeline[0]["description"]
        assert "SERIAL_LATER" in res.timeline[1]["description"]
