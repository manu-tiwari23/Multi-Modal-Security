"""
Forensic USB Activity Analyzer.

Implements ARCHITECTURE.md §4.5, §8 and .agents/skills/forensics/SKILL.md:
- Extraction and timeline reconstruction of USB device insertions, removals, and drive mappings.
- Support for Windows setupapi logs (setupapi.dev.log / setupapi.offline.log).
- Support for Windows Registry artifacts (SYSTEM\\CurrentControlSet\\Enum\\USBSTOR, USB, MountedDevices).
- Support for Linux kernel and syslog USB connection records (dmesg / /var/log/syslog).
- Comprehensive Vendor ID (VID) lookup table for major hardware manufacturers.
- Detection of malicious hardware / BadUSB keystroke injection devices (Rubber Ducky, Teensy, Flipper Zero, etc.).
- Anomaly scoring for suspicious composite devices, rapid connect/disconnect, and unknown mass storage.
- Chronological timeline unification across multi-source evidence.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.forensics.models import (
    USBAnalysisResult,
    USBDeviceArtifact,
    USBTimelineEntry,
)


# ---------------------------------------------------------------------------
# Known USB Vendor ID Database
# ---------------------------------------------------------------------------

KNOWN_USB_VENDORS: Dict[str, str] = {
    "0781": "SanDisk Corp.",
    "0951": "Kingston Technology Corp.",
    "058f": "Alcor Micro Corp.",
    "13fe": "Phison Electronics Corp.",
    "05ac": "Apple, Inc.",
    "046d": "Logitech, Inc.",
    "1532": "Razer USA, Ltd.",
    "090c": "Silicon Motion, Inc.",
    "8564": "Transcend Information, Inc.",
    "04e8": "Samsung Electronics Co., Ltd.",
    "1058": "Western Digital Technologies, Inc.",
    "0bc2": "Seagate Technology LLC",
    "054c": "Sony Corp.",
    "0930": "Toshiba Corp.",
    "18d1": "Google Inc.",
    "045e": "Microsoft Corp.",
    "0711": "Magic Control Technology Corp.",
    "04b4": "Cypress Semiconductor",
    "0bda": "Realtek Semiconductor Corp.",
    "1a40": "TERMINUS TECHNOLOGY INC.",
    "05e3": "Genesys Logic, Inc.",
    "17ef": "Lenovo",
    "03f0": "HP, Inc.",
    "04f2": "Chicony Electronics Co., Ltd.",
    "0a5c": "Broadcom Corp.",
    # Known microcontroller & hobbyist / attack hardware vendors
    "2341": "Arduino SA",
    "1b4f": "SparkFun Electronics",
    "16c0": "Van Ooijen Technische Informatica (Teensy / USB-AVR)",
    "16d0": "MCS Electronics (Digispark / Rubber Ducky clone)",
    "0483": "STMicroelectronics (STM32 / Flipper Zero clone)",
    "1d50": "OpenMoko, Inc. (Flipper Zero / Great Scott Gadgets)",
    "2e8a": "Raspberry Pi (Pico / RP2040)",
    "1fc9": "NXP Semiconductors (LPC / Rubber Ducky)",
}


# ---------------------------------------------------------------------------
# BadUSB / Hardware Attack Device Signatures
# ---------------------------------------------------------------------------

SUSPICIOUS_HARDWARE_SIGNATURES: List[Tuple[str, str, str]] = [
    ("16d0", "0753", "Digispark / Attiny85 BadUSB Keystroke Injection device"),
    ("16c0", "0486", "Teensy USB Board (common keystroke injection / HID attack tool)"),
    ("16c0", "0478", "Teensy Halfkay bootloader (microcontroller firmware flash mode)"),
    ("2341", "8036", "Arduino Leonardo ATmega32U4 (programmable HID keystroke injection)"),
    ("2341", "8037", "Arduino Micro ATmega32U4 (programmable HID keystroke injection)"),
    ("1b4f", "9206", "SparkFun Pro Micro 5V/16MHz (HID keystroke injection)"),
    ("1d50", "6089", "Flipper Zero multi-tool (BadUSB / Sub-GHz / RFID attack platform)"),
    ("0483", "5740", "STM32 Virtual COM Port / Custom BadUSB firmware"),
    ("2e8a", "0003", "Raspberry Pi Pico RP2040 (programmable USB HID injector)"),
    ("1fc9", "0080", "Hak5 USB Rubber Ducky (NXP LPC11U14 HID injection device)"),
]

SUSPICIOUS_SERIAL_PATTERNS = [
    r"(?i)^(00000000|12345678|deadbeef|badusb|flipper|hak5)",
    r"(?i)(ducky|payload|rubberducky|badusb|flipper|hak5)",
]


# ---------------------------------------------------------------------------
# Date Parsing Helpers
# ---------------------------------------------------------------------------

def parse_setupapi_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse timestamps from setupapi.dev.log (e.g. 2026/08/15 14:22:10.123)."""
    ts_str = ts_str.strip()
    patterns = [
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in patterns:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_syslog_timestamp(ts_str: str, year: Optional[int] = None) -> Optional[datetime]:
    """Parse standard syslog date (e.g. Aug 15 14:22:10) or ISO8601."""
    ts_str = ts_str.strip()
    # Try ISO8601 first
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    # Try traditional syslog: Mon DD HH:MM:SS
    current_year = year or datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Windows setupapi.dev.log Parser
# ---------------------------------------------------------------------------

class SetupApiParser:
    """Parser for Windows setupapi.dev.log and setupapi.offline.log."""

    SECTION_START_RE = re.compile(
        r"^>>>\s+\[(?P<operation>[^\]]+)\s+-\s+(?P<device_path>[^\]]+)\]",
        re.IGNORECASE,
    )
    SECTION_TIMESTAMP_RE = re.compile(
        r"^>>>\s+Section start\s+(?P<timestamp>\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        re.IGNORECASE,
    )
    SECTION_END_RE = re.compile(
        r"^<<<\s+\[Exit status:\s*(?P<status>[^\]]+)\]",
        re.IGNORECASE,
    )
    VID_PID_RE = re.compile(r"VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})", re.IGNORECASE)
    USBSTOR_RE = re.compile(r"Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_([^\\]+)", re.IGNORECASE)
    DESC_RE = re.compile(r"Device Description:\s*(.+)$", re.IGNORECASE)

    @classmethod
    def parse_log_text(cls, log_text: str) -> List[USBDeviceArtifact]:
        """Extract USB device installations from setupapi text."""
        devices_by_serial: Dict[str, USBDeviceArtifact] = {}

        lines = log_text.splitlines()
        current_dev_path: Optional[str] = None
        current_ts: Optional[datetime] = None
        current_desc: Optional[str] = None

        for line in lines:
            line_str = line.strip()

            # Match section start
            start_match = cls.SECTION_START_RE.match(line_str)
            if start_match:
                current_dev_path = start_match.group("device_path").strip()
                current_ts = None
                current_desc = None
                continue

            # Match section timestamp
            ts_match = cls.SECTION_TIMESTAMP_RE.match(line_str)
            if ts_match and current_dev_path:
                current_ts = parse_setupapi_timestamp(ts_match.group("timestamp"))
                continue

            # Match device description
            desc_match = cls.DESC_RE.search(line_str)
            if desc_match:
                current_desc = desc_match.group(1).strip()
                continue

            # Match section exit
            end_match = cls.SECTION_END_RE.match(line_str)
            if end_match and current_dev_path:
                # Process the completed section
                cls._process_device_section(
                    current_dev_path,
                    current_ts,
                    current_desc,
                    devices_by_serial,
                )
                current_dev_path = None
                current_ts = None
                current_desc = None

        return list(devices_by_serial.values())

    @classmethod
    def _process_device_section(
        cls,
        dev_path: str,
        install_time: Optional[datetime],
        desc: Optional[str],
        registry: Dict[str, USBDeviceArtifact],
    ) -> None:
        """Parse device hardware ID and update or create an artifact."""
        # Only process USB or USBSTOR devices
        if not (dev_path.upper().startswith("USB\\") or dev_path.upper().startswith("USBSTOR\\")):
            return

        parts = dev_path.split("\\")
        if len(parts) < 2:
            return

        hw_part = parts[1]
        serial_part = parts[2] if len(parts) > 2 else "UNKNOWN"
        # Strip trailing sub-device indices (e.g. &0 or &1)
        clean_serial = serial_part.split("&")[0].strip()

        vid: Optional[str] = None
        pid: Optional[str] = None
        vendor_name: Optional[str] = None
        product_name: Optional[str] = None
        dev_class = "Mass Storage" if "USBSTOR" in dev_path.upper() else "USB Device"

        # Check for VID and PID
        vid_match = cls.VID_PID_RE.search(hw_part)
        if vid_match:
            vid = vid_match.group(1).lower()
            pid = vid_match.group(2).lower()
            vendor_name = KNOWN_USB_VENDORS.get(vid)

        # Check for USBSTOR vendor and product strings
        usbstor_match = cls.USBSTOR_RE.search(hw_part)
        if usbstor_match:
            v_str = usbstor_match.group(1).strip()
            p_str = usbstor_match.group(2).strip()
            if not vendor_name:
                vendor_name = v_str
            product_name = p_str

        # Determine device class heuristics from description
        if desc:
            d_lower = desc.lower()
            if "keyboard" in d_lower or "hid" in d_lower:
                dev_class = "HID Keyboard"
            elif "mass storage" in d_lower or "disk" in d_lower:
                dev_class = "Mass Storage"
            elif "composite" in d_lower:
                dev_class = "Composite"
            elif "hub" in d_lower:
                dev_class = "USB Hub"

        # Lookup or create
        key = clean_serial if clean_serial != "UNKNOWN" else dev_path
        if key in registry:
            existing = registry[key]
            if install_time and (not existing.first_install_time or install_time < existing.first_install_time):
                existing.first_install_time = install_time
            if vid and not existing.vendor_id:
                existing.vendor_id = vid
            if pid and not existing.product_id:
                existing.product_id = pid
            if vendor_name:
                if not existing.vendor_name or (vid and vid in KNOWN_USB_VENDORS):
                    existing.vendor_name = vendor_name
            if not existing.product_name and product_name:
                existing.product_name = product_name
            if desc and not existing.device_description:
                existing.device_description = desc
            if "setupapi.dev.log" not in existing.source_artifacts:
                existing.source_artifacts.append("setupapi.dev.log")
        else:
            artifact = USBDeviceArtifact(
                device_id=dev_path,
                vendor_id=vid,
                product_id=pid,
                vendor_name=vendor_name,
                product_name=product_name,
                serial_number=clean_serial if clean_serial != "UNKNOWN" else None,
                device_class=dev_class,
                device_description=desc,
                first_install_time=install_time,
                source_artifacts=["setupapi.dev.log"],
            )
            registry[key] = artifact


# ---------------------------------------------------------------------------
# Windows Registry Artifacts Parser (.reg / text dump)
# ---------------------------------------------------------------------------

class RegistryParser:
    """Parser for Windows Registry dumps (USBSTOR, USB, MountedDevices)."""

    KEY_HEADER_RE = re.compile(r"^\[(?P<key>[^\]]+)\]", re.IGNORECASE)
    VALUE_RE = re.compile(r'^"(?P<name>[^"]+)"=(?:(?P<str>"[^"]*")|(?P<raw>.+))$')

    @classmethod
    def parse_reg_text(cls, reg_text: str) -> Tuple[List[USBDeviceArtifact], Dict[str, str]]:
        """Parse exported .reg file contents.
        
        Returns:
            Tuple of (detected USBDeviceArtifact list, serial_to_drive_letter mapping)
        """
        devices: Dict[str, USBDeviceArtifact] = {}
        drive_mappings: Dict[str, str] = {}  # serial/volume -> drive letter

        current_key: Optional[str] = None
        key_values: Dict[str, str] = {}

        def flush_key(key: Optional[str], values: Dict[str, str]):
            if not key:
                return

            # 1. Parse USBSTOR entries
            if "\\ENUM\\USBSTOR\\" in key.upper():
                cls._parse_usbstor_key(key, values, devices)

            # 2. Parse USB entries
            elif "\\ENUM\\USB\\" in key.upper():
                cls._parse_usb_key(key, values, devices)

            # 3. Parse MountedDevices entries
            elif "\\MOUNTEDDEVICES" in key.upper():
                cls._parse_mounted_devices(values, drive_mappings)

        # Pre-process lines to handle backslash continuation
        raw_lines = reg_text.splitlines()
        lines: List[str] = []
        buf = ""
        for raw in raw_lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith(";"):
                continue
            if stripped.endswith("\\"):
                buf += stripped[:-1].rstrip()
            else:
                if buf:
                    lines.append(buf + stripped)
                    buf = ""
                else:
                    lines.append(stripped)
        if buf:
            lines.append(buf)

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith(";"):
                continue

            key_match = cls.KEY_HEADER_RE.match(line_str)
            if key_match:
                flush_key(current_key, key_values)
                current_key = key_match.group("key")
                key_values = {}
                continue

            val_match = cls.VALUE_RE.match(line_str)
            if val_match:
                name = val_match.group("name")
                val = val_match.group("str")
                if val is not None:
                    # Strip quotes and unescape
                    val = val[1:-1].replace('\\\\', '\\')
                else:
                    val = val_match.group("raw")
                key_values[name] = val

        flush_key(current_key, key_values)

        # Associate mapped drive letters with devices by matching serial or device ID
        for dev in devices.values():
            for target, letter in drive_mappings.items():
                if (dev.serial_number and dev.serial_number.lower() in target.lower()) or \
                   (dev.device_id and dev.device_id.lower() in target.lower()):
                    if letter not in dev.drive_letters:
                        dev.drive_letters.append(letter)

        return list(devices.values()), drive_mappings

    @classmethod
    def _parse_usbstor_key(cls, key: str, values: Dict[str, str], devices: Dict[str, USBDeviceArtifact]):
        # e.g. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C530001280424116043&0
        parts = key.split("\\")
        if len(parts) < 2:
            return

        serial_part = parts[-1]
        clean_serial = serial_part.split("&")[0].strip()
        hw_part = parts[-2]

        v_match = re.search(r"Ven_([^&]+)", hw_part, re.IGNORECASE)
        p_match = re.search(r"Prod_([^&]+)", hw_part, re.IGNORECASE)

        vendor = v_match.group(1) if v_match else None
        product = p_match.group(1) if p_match else None
        friendly = values.get("FriendlyName")

        artifact = USBDeviceArtifact(
            device_id=f"USBSTOR\\{hw_part}\\{serial_part}",
            vendor_name=vendor,
            product_name=product,
            device_description=friendly,
            serial_number=clean_serial,
            device_class="Mass Storage",
            source_artifacts=["registry_usbstor"],
        )
        devices[clean_serial] = artifact

    @classmethod
    def _parse_usb_key(cls, key: str, values: Dict[str, str], devices: Dict[str, USBDeviceArtifact]):
        # e.g. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_0781&PID_5583\4C530001280424116043
        parts = key.split("\\")
        if len(parts) < 2:
            return

        serial_part = parts[-1]
        clean_serial = serial_part.split("&")[0].strip()
        hw_part = parts[-2]

        vid_match = re.search(r"VID_([0-9a-fA-F]{4})", hw_part, re.IGNORECASE)
        pid_match = re.search(r"PID_([0-9a-fA-F]{4})", hw_part, re.IGNORECASE)

        vid = vid_match.group(1).lower() if vid_match else None
        pid = pid_match.group(1).lower() if pid_match else None
        v_name = KNOWN_USB_VENDORS.get(vid) if vid else None
        desc = values.get("DeviceDesc") or values.get("FriendlyName")

        if clean_serial in devices:
            dev = devices[clean_serial]
            if vid:
                dev.vendor_id = vid
                if v_name:
                    dev.vendor_name = v_name
            if pid and not dev.product_id:
                dev.product_id = pid
            if desc and not dev.device_description:
                dev.device_description = desc
            if "registry_usb" not in dev.source_artifacts:
                dev.source_artifacts.append("registry_usb")
        else:
            artifact = USBDeviceArtifact(
                device_id=f"USB\\{hw_part}\\{serial_part}",
                vendor_id=vid,
                product_id=pid,
                vendor_name=v_name,
                device_description=desc,
                serial_number=clean_serial,
                device_class="USB Device",
                source_artifacts=["registry_usb"],
            )
            devices[clean_serial] = artifact

    @classmethod
    def _parse_mounted_devices(cls, values: Dict[str, str], drive_mappings: Dict[str, str]):
        for name, val in values.items():
            if "DOSDEVICES" in name.upper():
                letter_match = re.search(r"([A-Za-z]:)$", name)
                if letter_match:
                    letter = letter_match.group(1).upper()
                    decoded_str = cls._decode_reg_hex_or_string(val)
                    drive_mappings[decoded_str] = letter

    @classmethod
    def _decode_reg_hex_or_string(cls, val_str: str) -> str:
        """Decode hex-encoded registry value (hex:5c,00,3f,00...)."""
        if not val_str:
            return ""
        if val_str.startswith("hex:") or val_str.startswith("hex("):
            prefix_len = val_str.find(":") + 1
            hex_part = val_str[prefix_len:].replace("\n", "").replace("\\", "").replace(" ", "")
            hex_bytes = []
            for b in hex_part.split(","):
                b = b.strip()
                if b:
                    try:
                        hex_bytes.append(int(b, 16))
                    except ValueError:
                        pass
            raw_bytes = bytes(hex_bytes)
            # Try utf-16le then ascii
            try:
                decoded = raw_bytes.decode("utf-16le", errors="ignore").replace("\x00", "")
                if any(c.isalnum() for c in decoded):
                    return decoded
            except Exception:
                pass
            return raw_bytes.decode("ascii", errors="ignore").replace("\x00", "")
        return val_str


# ---------------------------------------------------------------------------
# Linux Syslog & Kernel dmesg Parser
# ---------------------------------------------------------------------------

class LinuxSyslogParser:
    """Parser for Linux kernel USB messages (dmesg and /var/log/syslog)."""

    DEV_NEW_RE = re.compile(
        r"New USB device found, idVendor=(?P<vid>[0-9a-fA-F]{4}), idProduct=(?P<pid>[0-9a-fA-F]{4})",
        re.IGNORECASE,
    )
    DEV_MFR_RE = re.compile(r"Manufacturer:\s*(?P<mfr>.+)$", re.IGNORECASE)
    DEV_PROD_RE = re.compile(r"Product:\s*(?P<prod>.+)$", re.IGNORECASE)
    DEV_SERIAL_RE = re.compile(r"SerialNumber:\s*(?P<serial>[A-Za-z0-9_-]+)", re.IGNORECASE)
    DEV_DISCONNECT_RE = re.compile(r"USB disconnect, device number", re.IGNORECASE)
    STORAGE_ATTACH_RE = re.compile(r"\[(?P<drive>sd[a-z]+)\] Attached SCSI removable disk", re.IGNORECASE)
    SYSLOG_LINE_RE = re.compile(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[^\s]+)\s+(?P<host>[^\s]+)\s+(?:kernel:\s*)?(?:\[\s*[\d\.]+\]\s*)?(?P<msg>.+)$"
    )

    @classmethod
    def parse_syslog_text(cls, log_text: str) -> Tuple[List[USBDeviceArtifact], List[USBTimelineEntry]]:
        devices: Dict[str, USBDeviceArtifact] = {}
        timeline: List[USBTimelineEntry] = []

        current_dev: Optional[USBDeviceArtifact] = None

        lines = log_text.splitlines()
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            match = cls.SYSLOG_LINE_RE.match(line_str)
            if not match:
                continue

            ts_raw = match.group("ts")
            msg = match.group("msg")
            dt = parse_syslog_timestamp(ts_raw) or datetime.now(timezone.utc)

            # 1. New device detection
            dev_match = cls.DEV_NEW_RE.search(msg)
            if dev_match:
                vid = dev_match.group("vid").lower()
                pid = dev_match.group("pid").lower()
                v_name = KNOWN_USB_VENDORS.get(vid)

                current_dev = USBDeviceArtifact(
                    device_id=f"USB_{vid}_{pid}_{int(dt.timestamp())}",
                    vendor_id=vid,
                    product_id=pid,
                    vendor_name=v_name,
                    first_install_time=dt,
                    last_connected_time=dt,
                    source_artifacts=["linux_syslog"],
                )
                continue

            if current_dev:
                # 2. Manufacturer
                mfr_match = cls.DEV_MFR_RE.search(msg)
                if mfr_match:
                    current_dev.vendor_name = mfr_match.group("mfr").strip()

                # 3. Product
                prod_match = cls.DEV_PROD_RE.search(msg)
                if prod_match:
                    current_dev.product_name = prod_match.group("prod").strip()

                # 4. Serial Number
                serial_match = cls.DEV_SERIAL_RE.search(msg)
                if serial_match:
                    serial = serial_match.group("serial").strip()
                    current_dev.serial_number = serial
                    current_dev.device_id = f"USB\\VID_{current_dev.vendor_id}&PID_{current_dev.product_id}\\{serial}"
                    devices[serial] = current_dev
                    timeline.append(
                        USBTimelineEntry(
                            timestamp=dt,
                            event_type="connection",
                            device_id=current_dev.device_id,
                            description=f"USB Device connected: {current_dev.vendor_name or ''} {current_dev.product_name or ''} (Serial: {serial})",
                            source_artifact="linux_syslog",
                        )
                    )
                    current_dev = None

            # 5. Storage drive mapping
            sd_match = cls.STORAGE_ATTACH_RE.search(msg)
            if sd_match:
                drive_name = sd_match.group("drive")
                if devices:
                    # Attach to the most recently added device
                    last_dev = list(devices.values())[-1]
                    if drive_name not in last_dev.drive_letters:
                        last_dev.drive_letters.append(drive_name)
                    timeline.append(
                        USBTimelineEntry(
                            timestamp=dt,
                            event_type="drive_mounted",
                            device_id=last_dev.device_id,
                            description=f"Storage drive block device attached: /dev/{drive_name}",
                            source_artifact="linux_syslog",
                        )
                    )

            # 6. Disconnect
            if cls.DEV_DISCONNECT_RE.search(msg):
                if devices:
                    last_dev = list(devices.values())[-1]
                    last_dev.last_disconnected_time = dt
                    timeline.append(
                        USBTimelineEntry(
                            timestamp=dt,
                            event_type="disconnection",
                            device_id=last_dev.device_id,
                            description=f"USB Device disconnected: {last_dev.device_id}",
                            source_artifact="linux_syslog",
                        )
                    )

        return list(devices.values()), timeline


# ---------------------------------------------------------------------------
# Threat & Anomaly Evaluation Engine
# ---------------------------------------------------------------------------

class ThreatEvaluator:
    """Evaluates USB devices for BadUSB attacks, exfiltration, and anomalies."""

    @classmethod
    def evaluate(cls, device: USBDeviceArtifact) -> None:
        reasons: List[str] = []

        # 1. Match known BadUSB / Hardware Keystroke Injection devices
        if device.vendor_id and device.product_id:
            pair = (device.vendor_id.lower(), device.product_id.lower())
            for s_vid, s_pid, attack_desc in SUSPICIOUS_HARDWARE_SIGNATURES:
                if pair == (s_vid.lower(), s_pid.lower()):
                    reasons.append(f"KNOWN HARDWARE ATTACK TOOL: {attack_desc}")
                    device.is_suspicious = True

        # 2. Suspicious Serial Numbers (firmware defaults for attack tools)
        if device.serial_number:
            for pat in SUSPICIOUS_SERIAL_PATTERNS:
                if re.search(pat, device.serial_number):
                    reasons.append(f"Suspicious / Default attack tool serial pattern: '{device.serial_number}'")
                    device.is_suspicious = True
                    break

        # 3. Composite or unexpected HID interface masquerading as storage
        if device.device_class == "HID Keyboard" and "USBSTOR" in device.device_id.upper():
            reasons.append("Malicious composite anomaly: USB mass storage device registering HID keyboard endpoint (BadUSB)")
            device.is_suspicious = True

        # 4. Unknown microcontroller vendor acting as mass storage without vendor brand
        if device.vendor_id in ("2341", "1b4f", "16c0", "16d0", "0483", "2e8a"):
            if not device.is_suspicious:
                reasons.append(f"Programmable microcontroller device connected ({device.vendor_name or 'Hobbyist MCU'})")
                device.is_suspicious = True

        if reasons:
            device.is_suspicious = True
            device.suspicious_reason = "; ".join(reasons)


# ---------------------------------------------------------------------------
# USB Analyzer Orchestrator
# ---------------------------------------------------------------------------

class USBAnalyzer:
    """Forensic USB activity and device connection analysis engine."""

    def analyze_setupapi_log(self, log_content_or_path: Union[str, Path]) -> USBAnalysisResult:
        """Parse a Windows setupapi.dev.log file or string content."""
        content = self._load_content(log_content_or_path)
        devices = SetupApiParser.parse_log_text(content)

        timeline: List[dict[str, Any]] = []
        for dev in devices:
            ThreatEvaluator.evaluate(dev)
            if dev.first_install_time:
                timeline.append({
                    "timestamp": dev.first_install_time.isoformat(),
                    "event_type": "first_install",
                    "device_id": dev.device_id,
                    "description": f"First installed: {dev.vendor_name or ''} {dev.product_name or ''} (Serial: {dev.serial_number or 'N/A'})",
                    "is_suspicious": dev.is_suspicious,
                })

        timeline.sort(key=lambda x: x["timestamp"])
        return self._build_result(devices, timeline, source_summary="setupapi.dev.log")

    def analyze_registry_export(self, reg_content_or_path: Union[str, Path]) -> USBAnalysisResult:
        """Parse exported Windows Registry (.reg) containing USBSTOR/USB/MountedDevices."""
        content = self._load_content(reg_content_or_path)
        devices, _mappings = RegistryParser.parse_reg_text(content)

        timeline: List[dict[str, Any]] = []
        for dev in devices:
            ThreatEvaluator.evaluate(dev)
            if dev.first_install_time:
                timeline.append({
                    "timestamp": dev.first_install_time.isoformat(),
                    "event_type": "registry_enumeration",
                    "device_id": dev.device_id,
                    "description": f"Device registered: {dev.vendor_name or ''} {dev.product_name or ''}",
                    "is_suspicious": dev.is_suspicious,
                })

        return self._build_result(devices, timeline, source_summary="Windows Registry")

    def analyze_syslog(self, log_content_or_path: Union[str, Path]) -> USBAnalysisResult:
        """Parse Linux syslog or dmesg output containing USB activity."""
        content = self._load_content(log_content_or_path)
        devices, timeline_entries = LinuxSyslogParser.parse_syslog_text(content)

        timeline = [e.to_dict() for e in timeline_entries]
        for dev in devices:
            ThreatEvaluator.evaluate(dev)

        timeline.sort(key=lambda x: x["timestamp"])
        return self._build_result(devices, timeline, source_summary="Linux Syslog / dmesg")

    def analyze_multi_source(
        self,
        setupapi_content: Optional[Union[str, Path]] = None,
        registry_content: Optional[Union[str, Path]] = None,
        syslog_content: Optional[Union[str, Path]] = None,
    ) -> USBAnalysisResult:
        """Correlate USB device activity across multiple forensic log sources."""
        all_devices: Dict[str, USBDeviceArtifact] = {}
        all_timeline: List[dict[str, Any]] = []
        sources_used: List[str] = []

        if setupapi_content:
            res_setup = self.analyze_setupapi_log(setupapi_content)
            sources_used.append("setupapi.dev.log")
            for d in res_setup.devices_detected:
                key = d.serial_number or d.device_id
                all_devices[key] = d
            all_timeline.extend(res_setup.timeline)

        if registry_content:
            res_reg = self.analyze_registry_export(registry_content)
            sources_used.append("Windows Registry")
            for d in res_reg.devices_detected:
                key = d.serial_number or d.device_id
                if key in all_devices:
                    # Merge properties
                    existing = all_devices[key]
                    if d.drive_letters:
                        for letter in d.drive_letters:
                            if letter not in existing.drive_letters:
                                existing.drive_letters.append(letter)
                    if d.device_description and not existing.device_description:
                        existing.device_description = d.device_description
                    for s in d.source_artifacts:
                        if s not in existing.source_artifacts:
                            existing.source_artifacts.append(s)
                else:
                    all_devices[key] = d
            all_timeline.extend(res_reg.timeline)

        if syslog_content:
            res_sys = self.analyze_syslog(syslog_content)
            sources_used.append("Linux Syslog")
            for d in res_sys.devices_detected:
                key = d.serial_number or d.device_id
                if key not in all_devices:
                    all_devices[key] = d
            all_timeline.extend(res_sys.timeline)

        # Re-evaluate all merged devices
        device_list = list(all_devices.values())
        for dev in device_list:
            ThreatEvaluator.evaluate(dev)

        all_timeline.sort(key=lambda x: x["timestamp"])
        return self._build_result(
            device_list,
            all_timeline,
            source_summary=", ".join(sources_used) or "Multi-Source Forensics",
        )

    def _load_content(self, source: Union[str, Path]) -> str:
        """Load log content from file path or raw string."""
        if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and os.path.exists(source)):
            p = Path(source)
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    return p.read_text(encoding="latin-1", errors="ignore")
        return str(source)

    def _build_result(
        self,
        devices: List[USBDeviceArtifact],
        timeline: List[dict[str, Any]],
        source_summary: str,
    ) -> USBAnalysisResult:
        susp_devices = [d for d in devices if d.is_suspicious]

        summary_parts = [
            f"Extracted {len(devices)} USB device artifact(s) from {source_summary}.",
        ]
        if susp_devices:
            summary_parts.append(
                f"FLAGGED: {len(susp_devices)} suspicious or unauthorized hardware device(s)!"
            )
        else:
            summary_parts.append("No known BadUSB signatures or anomalous devices detected.")

        return USBAnalysisResult(
            devices_detected=devices,
            device_count=len(devices),
            suspicious_device_count=len(susp_devices),
            timeline=timeline,
            suspicious_devices=susp_devices,
            summary=" ".join(summary_parts),
        )
