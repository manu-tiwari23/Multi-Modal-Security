from src.copilot.history import MemoryHistoryStore, PastIncidentRetriever, summary_document, vectorize


def records():
    return [{"incident_id": "ssh-case", "title": "SSH brute force authentication", "status": "closed", "tags": ["brute_force"], "mitre_techniques": ["T1110"], "timeline": [{"event_type": "auth_failure", "raw": {"password": "private-marker"}}]},
            {"incident_id": "email-case", "title": "Phishing email attachment", "status": "resolved", "tags": ["phishing"], "timeline": []}]


def test_local_history_ranks_matching_evidence_and_excludes_current_incident():
    retriever = PastIncidentRetriever(records, MemoryHistoryStore())
    result = retriever.search("previous SSH brute force incidents")
    assert result["incidents"][0]["incident_id"] == "ssh-case"
    assert result["incidents"][0]["historical_reference"]
    assert retriever.search("SSH brute force", exclude_incident_id="ssh-case")["incidents"] == []


def test_vectors_are_normalized_and_summary_omits_raw_payload():
    vector = vectorize("SSH SSH authentication")
    assert abs(sum(value * value for value in vector.values()) - 1) < 1e-10
    assert "private-marker" not in str(summary_document(records()[0]))


def test_blank_search_and_removed_sources_do_not_return_stale_matches():
    source = records()
    retriever = PastIncidentRetriever(lambda: source, MemoryHistoryStore())
    assert retriever.search("show previous incidents")["incidents"] == []
    assert retriever.search("SSH")["incidents"]
    source.clear()
    assert retriever.search("SSH")["incidents"] == []
