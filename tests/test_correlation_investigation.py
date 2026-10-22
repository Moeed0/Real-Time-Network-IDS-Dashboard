from dashboard_pages.correlation_investigation import _bundle_evidence_for_alert, _slugify_case_name


def test_case_name_slug_is_safe_and_readable():
    assert _slugify_case_name("SOC Review: Lab/SQL Injection") == (
        "soc-review-lab-sql-injection"
    )


def test_case_name_slug_rejects_names_without_letters_or_numbers():
    assert _slugify_case_name("../../ ///") == ""


def test_case_name_slug_is_bounded():
    assert len(_slugify_case_name("A" * 120)) == 80

def test_bundle_evidence_reads_direct_imported_fields():
    alert = {
        "bundle_intelligence": {
            "lookup_mode": "offline_local",
            "identifiers": {"cves": ["CVE-2021-44228"]},
        },
        "bundle_packet_investigation": {
            "packet_summary": {"total_packets": 4},
            "packets": [{"packet_number": 1, "protocol": "TCP"}],
        },
        "bundle_source_file": "sample.json",
        "bundle_record": {
            "alert": {"id": 101, "engine": "snort"},
            "source_bundle": {
                "filename": "sample.json",
                "evidence_note": "Retained observations only.",
            },
        },
    }

    evidence = _bundle_evidence_for_alert(alert)

    assert evidence["intelligence"]["lookup_mode"] == "offline_local"
    assert evidence["intelligence"]["identifiers"]["cves"] == [
        "CVE-2021-44228"
    ]
    assert evidence["packet_investigation"]["packet_summary"]["total_packets"] == 4
    assert evidence["packet_investigation"]["packets"][0]["packet_number"] == 1
    assert evidence["source_bundle"]["filename"] == "sample.json"
    assert evidence["original_alert"]["id"] == 101


def test_bundle_evidence_falls_back_to_nested_saved_case_fields():
    alert = {
        "bundle_record": {
            "alert": {"id": 202, "engine": "suricata"},
            "intelligence": {"lookup_mode": "offline_local"},
            "packet_investigation": {
                "packet_summary": {"total_packets": 2}
            },
            "source_bundle": {"filename": "saved-case-source.json"},
        }
    }

    evidence = _bundle_evidence_for_alert(alert)

    assert evidence["intelligence"]["lookup_mode"] == "offline_local"
    assert evidence["packet_investigation"]["packet_summary"]["total_packets"] == 2
    assert evidence["source_bundle"]["filename"] == "saved-case-source.json"
    assert evidence["original_alert"]["id"] == 202


def test_bundle_evidence_handles_missing_optional_evidence():
    evidence = _bundle_evidence_for_alert({"id": 303, "engine": "snort"})

    assert evidence == {
        "intelligence": {},
        "packet_investigation": {},
        "source_bundle": {
            "filename": None,
            "created_at_utc": None,
        },
        "original_alert": {},
    }
