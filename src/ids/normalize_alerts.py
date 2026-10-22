#!/usr/bin/env python3

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RULE_DB = PROJECT_ROOT / "data/lab/rules/ids_rules.db"
DOC_FILE = PROJECT_ROOT / "data/json/rule_docs_preprocessed_by_sid.json"
PHASE_FILE = PROJECT_ROOT / "config/lab_phases.json"

RAW_SNORT = PROJECT_ROOT / "data/lab/raw/snort"
RAW_SURICATA = PROJECT_ROOT / "data/lab/raw/suricata"

OUTPUT_DIR = PROJECT_ROOT / "data/lab/normalized"

SNORT_OUTPUT = OUTPUT_DIR / "snort_alerts.json"
SURICATA_OUTPUT = OUTPUT_DIR / "suricata_alerts.json"
COMBINED_OUTPUT = OUTPUT_DIR / "all_alerts_normalized.json"
SUMMARY_OUTPUT = OUTPUT_DIR / "normalization_summary.json"


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        return json.load(handle)


def load_json_lines(path: Path) -> list[dict[str, Any]]:
    records = []

    if not path.exists():
        return records

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                value = json.loads(line)

                if isinstance(value, dict):
                    records.append(value)

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSON in {path} line {line_number}: {exc}"
                ) from exc

    return records


def load_rule(
    conn: sqlite3.Connection,
    engine: str,
    gid: int | None,
    sid: int | None,
    rev: int | None,
) -> dict[str, Any] | None:

    if sid is None:
        return None

    # First attempt: exact engine + GID + SID + revision.
    if gid is not None and rev is not None:
        row = conn.execute(
            """
            SELECT *
            FROM rules
            WHERE engine = ?
              AND gid = ?
              AND sid = ?
              AND rev = ?
            LIMIT 1
            """,
            (
                engine,
                gid,
                sid,
                rev,
            ),
        ).fetchone()

        if row is not None:
            return dict(row)

    # Second attempt: engine + SID, newest revision.
    row = conn.execute(
        """
        SELECT *
        FROM rules
        WHERE engine = ?
          AND sid = ?
        ORDER BY rev DESC
        LIMIT 1
        """,
        (
            engine,
            sid,
        ),
    ).fetchone()

    if row is None:
        return None

    return dict(row)


def decode_rule_json_fields(rule: dict[str, Any]) -> dict[str, Any]:

    for key in (
        "metadata_json",
        "references_json",
        "content_matches_json",
        "cve_ids_json",
        "mitre_ids_json",
        "urls_json",
        "options_json",
    ):
        if key not in rule:
            continue

        value = rule[key]

        if value is None:
            rule[key] = []

            continue

        try:
            rule[key] = json.loads(value)

        except (json.JSONDecodeError, TypeError):
            # Preserve malformed/unexpected values rather than dropping them.
            rule[key] = value

    return rule


def public_rule_record(
    rule: dict[str, Any] | None,
) -> dict[str, Any]:

    if rule is None:
        return {
            "found": False,
            "source": "ids_rules.db",
        }

    rule = decode_rule_json_fields(rule)

    return {
        "found": True,
        "engine": rule.get("engine"),
        "gid": rule.get("gid"),
        "sid": rule.get("sid"),
        "rev": rule.get("rev"),
        "action": rule.get("action"),
        "protocol": rule.get("protocol"),
        "src_addr": rule.get("src_addr"),
        "src_port": rule.get("src_port"),
        "direction": rule.get("direction"),
        "dst_addr": rule.get("dst_addr"),
        "dst_port": rule.get("dst_port"),
        "rule_header": rule.get("rule_header"),
        "msg": rule.get("msg"),
        "classtype": rule.get("classtype"),
        "priority": rule.get("priority"),
        "service": rule.get("service"),
        "flow": rule.get("flow"),
        "metadata": rule.get("metadata_json"),
        "references": rule.get("references_json"),
        "content_matches": rule.get("content_matches_json"),
        "detection_filter": rule.get("detection_filter"),
        "app_layer_event": rule.get("app_layer_event"),
        "cve_ids": rule.get("cve_ids_json"),
        "mitre_ids": rule.get("mitre_ids_json"),
        "urls": rule.get("urls_json"),
        "options": rule.get("options_json"),
        "raw_options": rule.get("raw_options"),
        "rule_text": rule.get("rule_text"),
        "source_file": rule.get("source_file"),
        "source_line": rule.get("source_line"),
        "source": "ids_rules.db",
    }


def normalize_snort_alert(
    native: dict[str, Any],
    phase_id: str,
    phase: dict[str, Any],
    conn: sqlite3.Connection,
    docs: dict[str, Any],
    record_number: int,
) -> dict[str, Any]:

    gid = native.get("gid")
    sid = native.get("sid")
    rev = native.get("rev")

    if sid is None:

        rule_string = native.get("rule")

        if isinstance(rule_string, str):

            try:
                parts = rule_string.split(":")

                if len(parts) >= 3:
                    gid = int(parts[0])
                    sid = int(parts[1])
                    rev = int(parts[2])

            except (ValueError, TypeError):
                pass

    rule = load_rule(
        conn,
        "snort",
        gid,
        sid,
        rev,
    )

    project_doc = None

    if sid is not None:
        project_doc = docs.get(str(sid))

    return {
        "record_id": f"snort-{int(phase_id):02d}-{record_number:04d}",
        "normalization_version": "1.0",

        "engine": "Snort",
        "phase": {
            "phase_id": int(phase_id),
            "name": phase["name"],
            "pcap": phase["pcap"],
            **phase,
        },

        "network": {
            "source_ip": native.get("src_addr"),
            "source_port": native.get("src_port"),
            "destination_ip": native.get("dst_addr"),
            "destination_port": native.get("dst_port"),
            "protocol": native.get("proto"),
            "direction": native.get("dir"),
            "service": native.get("service"),
            "interface_native": native.get("iface"),
            "capture_interface": "ens38",
        },

        "alert": {
            "timestamp": native.get("timestamp"),
            "message": native.get("msg"),
            "rule_id": native.get("rule"),
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "classification": native.get("class"),
            "priority": native.get("priority"),
            "action": native.get("action"),
        },

        "packet": {
            "packet_number": native.get("pkt_num"),
            "packet_generation": native.get("pkt_gen"),
            "packet_length": native.get("pkt_len"),
            "ip_id": native.get("ip_id"),
            "ip_length": native.get("ip_len"),
            "ttl": native.get("ttl"),
            "tos": native.get("tos"),
            "vlan": native.get("vlan"),
            "ethernet_source": native.get("eth_src"),
            "ethernet_destination": native.get("eth_dst"),
            "ethernet_type": native.get("eth_type"),
        },

        "flow": {
            "flow_start_time": native.get("flowstart_time"),
            "server_packets": native.get("server_pkts"),
            "server_bytes": native.get("server_bytes"),
            "client_packets": native.get("client_pkts"),
            "client_bytes": native.get("client_bytes"),
        },

        "rule": public_rule_record(rule),

        "project_enrichment": {
            "documentation_found": project_doc is not None,
            "documentation_source": (
                "rule_docs_preprocessed_by_sid.json"
                if project_doc is not None
                else None
            ),
            "documentation": project_doc,
        },

        "enrichment_status": {
            "exact_rule_found": rule is not None,
            "project_rule_documentation_found": project_doc is not None,
            "external_vulnerability_enrichment": "pending",
            "mitre_external_enrichment": "pending",
        },

        # Complete native event. Nothing gets discarded.
        "native_event": native,
    }


def normalize_suricata_alert(
    native: dict[str, Any],
    phase_id: str,
    phase: dict[str, Any],
    conn: sqlite3.Connection,
    docs: dict[str, Any],
    record_number: int,
) -> dict[str, Any]:

    alert = native.get("alert") or {}

    gid = alert.get("gid")
    sid = alert.get("signature_id")
    rev = alert.get("rev")

    rule = load_rule(
        conn,
        "suricata",
        gid,
        sid,
        rev,
    )

    # There is intentionally no Snort-project documentation lookup
    # for Suricata signatures. It would be misleading to treat a SID
    # collision between engines as equivalent documentation.
    project_doc = None

    flow = native.get("flow") or {}

    return {
        "record_id": f"suricata-{int(phase_id):02d}-{record_number:04d}",
        "normalization_version": "1.0",

        "engine": "Suricata",
        "phase": {
            "phase_id": int(phase_id),
            "name": phase["name"],
            "pcap": phase["pcap"],
            **phase,
        },

        "network": {
            "source_ip": native.get("src_ip"),
            "source_port": native.get("src_port"),
            "destination_ip": native.get("dest_ip"),
            "destination_port": native.get("dest_port"),
            "protocol": native.get("proto"),
            "direction": native.get("direction"),
            "service": native.get("app_proto"),
            "interface_native": native.get("in_iface"),
            "capture_interface": "ens38",
            "ip_version": native.get("ip_v"),
        },

        "alert": {
            "timestamp": native.get("timestamp"),
            "message": alert.get("signature"),
            "rule_id": (
                f"{gid}:{sid}:{rev}"
                if gid is not None
                and sid is not None
                and rev is not None
                else None
            ),
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "classification": alert.get("category"),
            "priority": None,
            "severity": alert.get("severity"),
            "action": alert.get("action"),
        },

        "packet": {
            "pcap_packet_number": native.get("pcap_cnt"),
            "packet_source": native.get("pkt_src"),
            "community_id": native.get("community_id"),
            "flow_id": native.get("flow_id"),
            "transaction_id": native.get("tx_id"),
        },

        "flow": {
            "packets_to_server": flow.get("pkts_toserver"),
            "packets_to_client": flow.get("pkts_toclient"),
            "bytes_to_server": flow.get("bytes_toserver"),
            "bytes_to_client": flow.get("bytes_toclient"),
            "start": flow.get("start"),
            "source_ip": flow.get("src_ip"),
            "destination_ip": flow.get("dest_ip"),
            "source_port": flow.get("src_port"),
            "destination_port": flow.get("dest_port"),
        },

        "application_layer": {
            "app_proto": native.get("app_proto"),
            "http": native.get("http"),
            "dns": native.get("dns"),
            "tls": native.get("tls"),
            "ssh": native.get("ssh"),
            "smb": native.get("smb"),
            "ftp": native.get("ftp"),
            "smtp": native.get("smtp"),
        },

        "alert_metadata": alert.get("metadata", {}),

        "rule": public_rule_record(rule),

        "project_enrichment": {
            "documentation_found": False,
            "documentation_source": None,
            "documentation": None,
        },

        "enrichment_status": {
            "exact_rule_found": rule is not None,
            "project_rule_documentation_found": False,
            "external_vulnerability_enrichment": "pending",
            "mitre_external_enrichment": "pending",
        },

        # Complete original Suricata EVE event.
        "native_event": native,
    }


def sort_key(record: dict[str, Any]) -> tuple:

    timestamp = (
        record.get("alert", {}).get("timestamp")
        or ""
    )

    return (
        record["phase"]["phase_id"],
        timestamp,
        record["record_id"],
    )


def write_json(path: Path, data: Any) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
        )


def process_snort(
    conn: sqlite3.Connection,
    phases: dict[str, Any],
    docs: dict[str, Any],
) -> list[dict[str, Any]]:

    records = []

    for phase_id in sorted(
        phases,
        key=lambda value: int(value),
    ):

        phase_dir = RAW_SNORT / f"phase{phase_id}"
        alert_file = phase_dir / "alert_json.txt"

        native_alerts = load_json_lines(alert_file)

        for number, native in enumerate(
            native_alerts,
            start=1,
        ):

            records.append(
                normalize_snort_alert(
                    native,
                    phase_id,
                    phases[phase_id],
                    conn,
                    docs,
                    number,
                )
            )

    return sorted(
        records,
        key=sort_key,
    )


def process_suricata(
    conn: sqlite3.Connection,
    phases: dict[str, Any],
    docs: dict[str, Any],
) -> list[dict[str, Any]]:

    records = []

    for phase_id in sorted(
        phases,
        key=lambda value: int(value),
    ):

        phase_dir = RAW_SURICATA / f"phase{phase_id}"
        eve_file = phase_dir / "eve.json"

        native_events = load_json_lines(eve_file)

        alert_number = 0

        for native in native_events:

            if native.get("event_type") != "alert":
                continue

            alert_number += 1

            records.append(
                normalize_suricata_alert(
                    native,
                    phase_id,
                    phases[phase_id],
                    conn,
                    docs,
                    alert_number,
                )
            )

    return sorted(
        records,
        key=sort_key,
    )


def build_summary(
    snort_records: list[dict[str, Any]],
    suricata_records: list[dict[str, Any]],
) -> dict[str, Any]:

    summary = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "snort": {
            "total_alerts": len(snort_records),
            "exact_rule_matches": sum(
                x["enrichment_status"]["exact_rule_found"]
                for x in snort_records
            ),
            "project_documentation_matches": sum(
                x["enrichment_status"]["project_rule_documentation_found"]
                for x in snort_records
            ),
        },
        "suricata": {
            "total_alerts": len(suricata_records),
            "exact_rule_matches": sum(
                x["enrichment_status"]["exact_rule_found"]
                for x in suricata_records
            ),
            "project_documentation_matches": sum(
                x["enrichment_status"]["project_rule_documentation_found"]
                for x in suricata_records
            ),
        },
    }

    summary["combined"] = {
        "total_alerts": (
            summary["snort"]["total_alerts"]
            + summary["suricata"]["total_alerts"]
        ),
        "exact_rule_matches": (
            summary["snort"]["exact_rule_matches"]
            + summary["suricata"]["exact_rule_matches"]
        ),
    }

    by_phase = {}

    for phase_id in range(1, 6):

        snort_count = sum(
            x["phase"]["phase_id"] == phase_id
            for x in snort_records
        )

        suricata_count = sum(
            x["phase"]["phase_id"] == phase_id
            for x in suricata_records
        )

        by_phase[str(phase_id)] = {
            "snort_alerts": snort_count,
            "suricata_alerts": suricata_count,
        }

    summary["by_phase"] = by_phase

    return summary


def main() -> None:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    docs = load_json(
        DOC_FILE,
        {},
    )

    phases = load_json(
        PHASE_FILE,
        {},
    )

    if not RULE_DB.exists():
        raise SystemExit(
            f"Rule database not found: {RULE_DB}"
        )

    if not phases:
        raise SystemExit(
            f"Lab phase manifest not found or empty: {PHASE_FILE}"
        )

    conn = sqlite3.connect(RULE_DB)

    conn.row_factory = sqlite3.Row

    snort_records = process_snort(
        conn,
        phases,
        docs,
    )

    suricata_records = process_suricata(
        conn,
        phases,
        docs,
    )

    conn.close()

    combined = sorted(
        snort_records + suricata_records,
        key=sort_key,
    )

    write_json(
        SNORT_OUTPUT,
        snort_records,
    )

    write_json(
        SURICATA_OUTPUT,
        suricata_records,
    )

    write_json(
        COMBINED_OUTPUT,
        combined,
    )

    summary = build_summary(
        snort_records,
        suricata_records,
    )

    write_json(
        SUMMARY_OUTPUT,
        summary,
    )

    print("Alert normalization complete.")
    print()
    print(f"Snort normalized:    {len(snort_records)}")
    print(f"Suricata normalized: {len(suricata_records)}")
    print(f"Combined:             {len(combined)}")
    print()
    print(
        "Snort exact rule matches:    "
        f"{summary['snort']['exact_rule_matches']}"
    )
    print(
        "Suricata exact rule matches: "
        f"{summary['suricata']['exact_rule_matches']}"
    )
    print()
    print(
        "Snort project documentation matches: "
        f"{summary['snort']['project_documentation_matches']}"
    )
    print()
    print(f"Output: {COMBINED_OUTPUT}")
    print(f"Summary: {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()
