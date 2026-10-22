from __future__ import annotations

import csv
import gzip
import json
import sqlite3
from pathlib import Path

import pytest

import ids.offline_intelligence as offline_module

from ids.offline_intelligence import (
    connect_offline_db,
    get_attack_technique,
    get_cve_record,
    get_epss_record,
    get_kev_record,
    get_source_metadata,
    search_attack_techniques,
    search_cves,
)
from scripts.import_offline_intelligence import import_sources


def build_fixture_sources(tmp_path: Path) -> dict[str, Path]:
    nvd_dir = tmp_path / "nvd"
    epss_dir = tmp_path / "epss"
    nvd_dir.mkdir()
    epss_dir.mkdir()

    nvd_data = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-16T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-10-01T00:00:00.000",
                    "lastModified": "2026-10-02T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Remote code execution in a test service.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/example",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-94"}
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.test/advisory",
                            "source": "example.test",
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "configurations": [],
                }
            }
        ],
    }
    nvd_file = nvd_dir / "nvdcve-2.0-2026.json"
    nvd_file.write_text(json.dumps(nvd_data), encoding="utf-8")
    # Modified feeds may repeat CVEs from yearly feeds.
    (nvd_dir / "nvdcve-2.0-modified.json").write_text(
        json.dumps(nvd_data), encoding="utf-8"
    )

    epss_file = epss_dir / "epss_scores-2026-10-16.csv"
    with epss_file.open("w", encoding="utf-8", newline="") as handle:
        handle.write("#model_version: test-version\n")
        handle.write("#score_date: 2026-10-15T12:03:56Z\n")
        writer = csv.writer(handle)
        writer.writerow(["cve", "epss", "percentile"])
        writer.writerow(["CVE-2026-12345", "0.75", "0.96"])

    kev_file = tmp_path / "known_exploited_vulnerabilities.json"
    kev_file.write_text(
        json.dumps({
            "catalogVersion": "test",
            "dateReleased": "2026-10-16",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-12345",
                    "vendorProject": "Example",
                    "product": "Example Service",
                    "vulnerabilityName": "Example RCE",
                    "dateAdded": "2026-10-10",
                    "shortDescription": "A test KEV entry.",
                    "requiredAction": "Apply vendor updates.",
                    "dueDate": "2026-11-01",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                }
            ],
        }),
        encoding="utf-8",
    )

    mitre_file = tmp_path / "enterprise-attack.json"
    mitre_file.write_text(
        json.dumps({
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test",
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command interpreters.",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1059",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "execution",
                        }
                    ],
                    "x_mitre_platforms": ["Windows", "Linux"],
                    "x_mitre_data_sources": ["Process: Process Creation"],
                    "x_mitre_is_subtechnique": False,
                }
            ],
        }),
        encoding="utf-8",
    )
    mitre_file.with_suffix(".meta.json").write_text(
        json.dumps({
            "retrieved_at": "2026-10-16T00:00:00+00:00",
            "dataset_version": "test-version",
        }),
        encoding="utf-8",
    )

    return {
        "nvd": nvd_dir,
        "epss": epss_dir,
        "kev": kev_file,
        "mitre": mitre_file,
    }


@pytest.fixture
def offline_db(tmp_path: Path) -> Path:
    paths = build_fixture_sources(tmp_path)
    target = tmp_path / "intel.db"

    result = import_sources(
        nvd_paths=[paths["nvd"]],
        epss_paths=[paths["epss"]],
        kev_path=paths["kev"],
        mitre_path=paths["mitre"],
        output_path=target,
    )

    assert result["integrity"] == "ok"
    assert target.is_file()
    return target


def test_imported_cve_fields_and_cvss_are_available(offline_db: Path) -> None:
    result = get_cve_record("cve-2026-12345", offline_db)

    assert result is not None
    assert result["id"] == "CVE-2026-12345"
    assert result["cvss"]["base_score"] == 9.8
    assert result["cvss"]["base_severity"] == "CRITICAL"
    assert result["cwe"] == ["CWE-94"]
    assert result["references"][0]["url"] == "https://example.test/advisory"


def test_epss_and_kev_lookups(offline_db: Path) -> None:
    epss = get_epss_record("CVE-2026-12345", offline_db)
    kev = get_kev_record("CVE-2026-12345", offline_db)

    assert epss is not None
    assert epss["epss"] == pytest.approx(0.75)
    assert epss["percentile"] == pytest.approx(0.96)
    assert kev is not None
    assert kev["vendorProject"] == "Example"


def test_mitre_lookup_and_offline_search(offline_db: Path) -> None:
    technique = get_attack_technique("T1059", offline_db)

    assert technique is not None
    assert technique["name"] == "Command and Scripting Interpreter"
    assert technique["tactics"] == ["execution"]
    assert search_attack_techniques("Command and Scripting", db_path=offline_db)

    cve_results = search_cves("Remote code execution", db_path=offline_db)
    assert any(row["cve_id"] == "CVE-2026-12345" for row in cve_results)


def test_source_metadata_has_import_dates_and_checksums(offline_db: Path) -> None:
    metadata = get_source_metadata(offline_db)

    # The same CVE in two feeds should count once in the index.
    assert metadata["nvd"]["record_count"] == 1

    assert {"nvd", "epss", "cisa_kev", "mitre_attack"} <= set(metadata)
    assert metadata["nvd"]["sha256"]
    assert metadata["mitre_attack"]["version"] == "test-version"
    assert metadata["epss"]["data_as_of"] == "2026-10-15"
    assert get_epss_record("CVE-2026-12345", offline_db)["date"] == "2026-10-15"


def test_database_connections_are_read_only(offline_db: Path) -> None:
    with connect_offline_db(offline_db) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute(
                "CREATE TABLE should_not_be_created (id INTEGER)"
            )


def test_existing_database_is_not_replaced_without_explicit_permission(
    tmp_path: Path,
) -> None:
    paths = build_fixture_sources(tmp_path)
    target = tmp_path / "existing.db"
    target.write_bytes(b"preserve-this-file")

    with pytest.raises(FileExistsError):
        import_sources(
            nvd_paths=[paths["nvd"]],
            epss_paths=[paths["epss"]],
            kev_path=paths["kev"],
            mitre_path=paths["mitre"],
            output_path=target,
        )

    assert target.read_bytes() == b"preserve-this-file"


def test_search_functions_use_fts_indexes(
    offline_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    class TrackingConnection:
        def __init__(self, db_path: Path) -> None:
            self.connection = sqlite3.connect(
                db_path.resolve().as_uri() + "?mode=ro",
                uri=True,
            )
            self.connection.row_factory = sqlite3.Row

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self.connection.close()

        def execute(self, sql: str, parameters=()):
            statements.append(sql)
            return self.connection.execute(sql, parameters)

    monkeypatch.setattr(
        offline_module,
        "connect_offline_db",
        lambda db_path: TrackingConnection(Path(db_path)),
    )

    cve_results = offline_module.search_cves(
        "execution Remote",
        db_path=offline_db,
    )
    assert any(row["cve_id"] == "CVE-2026-12345" for row in cve_results)
    assert len(statements) == 1
    assert "cve_search MATCH ?" in statements[0]

    statements.clear()
    attack_results = offline_module.search_attack_techniques(
        "Interpreter Command",
        db_path=offline_db,
    )
    assert any(row["technique_id"] == "T1059" for row in attack_results)
    assert len(statements) == 1
    assert "attack_search MATCH ?" in statements[0]


def test_read_connection_is_closed_after_lookup(
    offline_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}
    original_connect = offline_module.sqlite3.connect

    def tracked_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        captured["connection"] = connection
        return connection

    monkeypatch.setattr(
        offline_module.sqlite3,
        "connect",
        tracked_connect,
    )

    get_source_metadata(offline_db)

    with pytest.raises(sqlite3.ProgrammingError):
        captured["connection"].execute("SELECT 1")


def test_source_discovery_filters_by_source_format(
    tmp_path: Path,
) -> None:
    from scripts.import_offline_intelligence import _source_files

    mixed = tmp_path / "mixed"
    mixed.mkdir()

    filenames = (
        "nvdcve.json",
        "nvdcve.json.gz",
        "nvdcve.zip",
        "epss_scores.csv",
        "epss_scores.csv.gz",
        "notes.txt",
    )
    for name in filenames:
        (mixed / name).write_text("fixture", encoding="utf-8")

    nvd_files = _source_files(
        [mixed],
        allowed_suffixes=(".json", ".json.gz", ".zip"),
    )
    epss_files = _source_files(
        [mixed],
        allowed_suffixes=(".csv", ".csv.gz"),
    )

    assert {path.name for path in nvd_files} == {
        "nvdcve.json",
        "nvdcve.json.gz",
        "nvdcve.zip",
    }
    assert {path.name for path in epss_files} == {
        "epss_scores.csv",
        "epss_scores.csv.gz",
    }


def test_import_streams_compressed_nvd_feed(tmp_path: Path) -> None:
    sources = build_fixture_sources(tmp_path)
    original = sources["nvd"] / "nvdcve-2.0-2026.json"
    compressed = tmp_path / "nvdcve-2.0-2026.json.gz"

    with original.open("rb") as input_handle:
        with gzip.open(compressed, "wb") as output_handle:
            output_handle.write(input_handle.read())

    database = tmp_path / "streamed-intel.db"
    result = import_sources(
        nvd_paths=[compressed],
        epss_paths=[sources["epss"]],
        kev_path=sources["kev"],
        mitre_path=sources["mitre"],
        output_path=database,
    )

    assert result["integrity"] == "ok"
    record = get_cve_record("CVE-2026-12345", database)
    assert record is not None
    assert record["cvss"]["base_score"] == 9.8



def test_offline_alert_intelligence_adapter(
    offline_db: Path,
) -> None:
    from ids.offline_intelligence import get_offline_live_intelligence

    alert = {
        "id": 10001,
        "engine": "snort",
        "gid": 1,
        "sid": 999999999,
        "rev": 1,
        "msg": "Test CVE-2026-12345 T1059",
        "rule": "Test CVE-2026-12345 T1059",
        "protocol": "TCP",
    }

    context, from_cache = get_offline_live_intelligence(
        alert,
        db_path=offline_db,
    )

    assert from_cache is False
    assert context["lookup_mode"] == "offline_local"
    assert context["alert"] == alert
    assert context["identifiers"]["cves"] == ["CVE-2026-12345"]
    assert context["identifiers"]["mitre_attack"] == ["T1059"]

    vulnerability = context["vulnerabilities"]["CVE-2026-12345"]
    assert vulnerability["nvd"]["cvss"]["base_score"] == 9.8
    assert vulnerability["epss"]["score"] == pytest.approx(0.75)
    assert vulnerability["cisa_kev"]["cveID"] == "CVE-2026-12345"
    assert vulnerability["circl"] == {}

    assert (
        context["data_as_of"]["epss"]
        == "2026-10-15"
    )
    assert context["mitre_enrichment"]["T1059"][0]["name"] == (
        "Command and Scripting Interpreter"
    )
