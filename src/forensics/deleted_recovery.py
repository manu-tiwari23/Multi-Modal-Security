"""Validate paired deletion metadata and content without accessing host paths."""
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
import struct
from urllib.parse import unquote

from .file_analyzer import parse_windows_recycle_i_file


def validate_deleted_pair(metadata, metadata_name, content, content_name):
    limitations = []
    if metadata_name.startswith("$I"):
        expected = "$R" + metadata_name[2:]
        if content_name.casefold() != expected.casefold():
            raise ValueError("Recycle Bin metadata requires its matching $R filename")
        if len(metadata) < 28:
            raise ValueError("Truncated Recycle Bin metadata")
        version = struct.unpack_from("<Q", metadata)[0]
        if version == 2:
            characters = struct.unpack_from("<I", metadata, 24)[0]
            if characters < 1 or characters > 32768 or 28 + characters * 2 > len(metadata):
                raise ValueError("Invalid Recycle Bin path length")
        record = parse_windows_recycle_i_file(metadata, metadata_name)
        if record is None or not record.original_path:
            raise ValueError("Unsupported Recycle Bin metadata")
        if record.file_size_bytes != len(content):
            raise ValueError("Content size differs from the deletion metadata")
        name = PureWindowsPath(record.original_path).name
        deletion = record.deletion_time.isoformat() if record.deletion_time else None
        original_path = record.original_path
        kind = "windows_recycle_bin"
    elif metadata_name.endswith(".trashinfo"):
        if content_name != metadata_name[:-10]:
            raise ValueError("Trash metadata requires the matching stored content filename")
        try:
            text = metadata.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ValueError("Trash metadata must be UTF-8 text") from exc
        fields = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in fields:
                    raise ValueError("Duplicate Trash metadata fields")
                fields[key] = value
        if "[Trash Info]" not in text or not fields.get("Path"):
            raise ValueError("Invalid Trash metadata")
        original_path = unquote(fields["Path"], errors="strict")
        name = PurePosixPath(original_path).name
        deletion = None
        if fields.get("DeletionDate"):
            try:
                stamp = datetime.fromisoformat(fields["DeletionDate"])
                if stamp.tzinfo:
                    deletion = stamp.isoformat()
                else:
                    limitations.append("DeletionDate has no timezone; its UTC time is unknown. Recorded local time: " + fields["DeletionDate"])
            except ValueError:
                limitations.append("DeletionDate is invalid; deletion time remains unknown.")
        limitations.append("Trash metadata has no expected content hash or size; pairing is based on the stored filename.")
        kind = "freedesktop_trash"
    else:
        raise ValueError("Select a Windows $I file or a .trashinfo metadata file")
    if not name or name in (".", "..") or len(name) > 240 or any(char in name for char in '/\\:\x00') or any(ord(char) < 32 for char in name):
        raise ValueError("Recovered filename is unsafe or unsupported")
    return {"recovered_filename": name, "original_path": original_path, "deletion_time": deletion,
            "format": kind, "content_size": len(content), "limitations": limitations + [
                "Recovery preserves the supplied content partner; it does not reconstruct absent or overwritten bytes."]}
