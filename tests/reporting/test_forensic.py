from copy import deepcopy

import pytest

from src.forensics.evidence_vault import EvidenceVault
from src.forensics.file_analyzer import FileAnalyzer
from src.reporting.forensic import build_forensic_report


def evidence():
    data = b"Synthetic log: source=203.0.113.80 account=test"
    vault = EvidenceVault()
    item = vault.ingest_bytes(data, "sample.log", "analyst", "case-one")
    vault.get_evidence_bytes(item.evidence_id, "report_generator")
    return item.model_dump(mode="json"), FileAnalyzer().analyze_bytes(data, item.filename).model_dump(mode="json")


def test_report_preserves_full_hashes_custody_and_indicator_provenance():
    item, analysis = evidence()
    before = deepcopy(item)
    report = build_forensic_report("case-one", [item], {item["evidence_id"]: analysis})
    assert item == before
    html = report.to_html()
    for expected in (item["sha256"], item["md5"], item["evidence_id"], "analyst", "verified", "203.0.113.80"):
        assert expected in html
    assert report.source_ids == [f"evidence:{item['evidence_id']}"]


@pytest.mark.parametrize("change", ["case", "tamper", "hash"])
def test_report_rejects_inconsistent_evidence(change):
    item, analysis = evidence()
    if change == "case":
        item["case_id"] = "other-case"
    elif change == "tamper":
        item["is_tampered"] = True
    else:
        analysis["sha256"] = "wrong"
    with pytest.raises(ValueError):
        build_forensic_report("case-one", [item], {item["evidence_id"]: analysis})


def test_empty_case_does_not_claim_integrity():
    with pytest.raises(ValueError):
        build_forensic_report("empty", [], {})
