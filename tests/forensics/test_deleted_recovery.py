import struct

import pytest

from src.forensics.deleted_recovery import validate_deleted_pair


def index_file(path, size):
    text = (path + "\x00").encode("utf-16le")
    return struct.pack("<QQQI", 2, size, 0, len(text) // 2) + text


def test_windows_pair_recovers_filename_and_preserves_unknown_time():
    result = validate_deleted_pair(index_file(r"C:\Users\Example\notes.txt", 3), "$I123.txt", b"abc", "$R123.txt")
    assert result["recovered_filename"] == "notes.txt"
    assert result["deletion_time"] is None
    assert result["content_size"] == 3


@pytest.mark.parametrize("name,content", [("$Rwrong.txt", b"abc"), ("$R123.txt", b"short")])
def test_windows_pair_rejects_wrong_partner_or_size(name, content):
    with pytest.raises(ValueError):
        validate_deleted_pair(index_file(r"C:\notes.txt", 3), "$I123.txt", content, name)


def test_trash_pair_decodes_path_without_inventing_timezone():
    result = validate_deleted_pair(b"[Trash Info]\nPath=/home/example/my%20notes.txt\nDeletionDate=2026-11-13T10:00:00\n", "my notes.txt.trashinfo", b"synthetic", "my notes.txt")
    assert result["recovered_filename"] == "my notes.txt"
    assert result["deletion_time"] is None
    assert any("no timezone" in note for note in result["limitations"])


def test_deleted_pair_rejects_unsafe_recovered_filename():
    with pytest.raises(ValueError):
        validate_deleted_pair(b"[Trash Info]\nPath=/tmp/file%00.txt", "record.trashinfo", b"x", "record")
