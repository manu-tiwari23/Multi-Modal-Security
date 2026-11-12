"""Forensic case reports from verified metadata and analysis snapshots."""

from .models import Report, ReportSection


def build_forensic_report(case_id: str, evidence: list[dict], analyses: dict[str, dict]) -> Report:
    if not evidence:
        raise ValueError("A forensic report requires evidence")
    sections = []
    source_ids = []
    finding_count = 0
    for item in evidence:
        evidence_id = item["evidence_id"]
        if item.get("case_id") != case_id:
            raise ValueError("Evidence belongs to another case")
        if item.get("is_tampered"):
            raise ValueError("Tampered evidence cannot be used in an investigation report")
        analysis = analyses[evidence_id]
        if analysis.get("sha256") != item["sha256"]:
            raise ValueError("Analysis hash does not match evidence")
        source_ids.append(f"evidence:{evidence_id}")
        findings = analysis.get("suspicious_indicators", [])
        finding_count += len(findings)
        sections.extend([
            ReportSection(title=f"Evidence: {item['filename']}", columns=["Field", "Recorded value"], rows=[
                ["Evidence ID", evidence_id], ["SHA-256", item["sha256"]], ["MD5 (legacy reference)", item["md5"]],
                ["Size (bytes)", str(item["file_size_bytes"])], ["Acquired by", item["acquired_by"]],
                ["Intake time", str(item["intake_timestamp"])], ["Source host", item.get("source_host") or "not recorded"],
                ["Detected type", analysis.get("detected_type", "unknown")],
                ["Shannon entropy", str(analysis.get("shannon_entropy", "unknown"))],
            ]),
            ReportSection(title=f"Findings: {evidence_id}", paragraphs=[
                analysis.get("summary", "No analysis summary recorded"),
                "Heuristic indicators require analyst review and do not establish that a file is malicious.",
            ], columns=["Category", "Severity", "Observation", "Evidence match"], rows=[
                [f["category"], f["severity"], f["description"], f["evidence_match"]] for f in findings
            ]),
            ReportSection(title=f"Extracted indicators: {evidence_id}", columns=["Type", "Value", "Source"], rows=[
                [kind, value, f"evidence:{evidence_id}"] for kind, values in sorted(analysis.get("extracted_iocs", {}).items())
                for value in sorted(set(values))
            ]),
            ReportSection(title=f"Chain of custody: {evidence_id}", columns=["Timestamp", "Actor / action", "Status", "Expected SHA-256", "Actual SHA-256", "Notes"], rows=[
                [str(c["timestamp"]), f"{c['actor']} / {c['action']}", c["status"], c["expected_hash"], c["actual_hash"], c.get("notes") or ""]
                for c in item.get("custody_history", [])
            ]),
        ])
    return Report(kind="forensic", subject_id=case_id, title=f"Forensic investigation: {case_id}",
                  summary=f"Case {case_id} contains {len(evidence)} evidence items and {finding_count} static analysis indicators. Evidence bytes were hash-verified before this report's analysis.",
                  sections=sections, source_ids=source_ids, limitations=[
                      "File-level static analysis only; no execution of evidence, disk imaging or memory analysis.",
                      "Hash verification establishes consistency with intake bytes, not authenticity of the original source.",
                      "Custody records reflect recorded actions and identities; legal admissibility requires independent review.",
                  ])
