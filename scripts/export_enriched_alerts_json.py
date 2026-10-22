import json
import sqlite3
from pathlib import Path


DB_FILE = Path("ids_live.db")
RULE_DOC_JSON_FILE = Path("rule_docs_preprocessed_by_sid.json")
OUTPUT_FILE = Path("enriched_snort_alerts_with_rule_docs.json")


def normalize_rule_key(value):
    if value is None:
        return None

    try:
        return str(int(float(value)))
    except Exception:
        text = str(value).strip()
        if text.endswith(".0"):
            text = text[:-2]
        return text if text else None


def load_rule_docs():
    if not RULE_DOC_JSON_FILE.exists():
        raise FileNotFoundError(f"Missing rule documentation JSON: {RULE_DOC_JSON_FILE}")

    with RULE_DOC_JSON_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def find_rule_doc(rule_docs, gid, sid):
    gid_key = normalize_rule_key(gid) or "1"
    sid_key = normalize_rule_key(sid)

    if not sid_key:
        return {}

    possible_keys = [
        sid_key,
        f"{gid_key}:{sid_key}",
        f"{gid_key}-{sid_key}",
    ]

    for key in possible_keys:
        if key in rule_docs:
            return rule_docs[key]

    return {}


def read_alerts():
    if not DB_FILE.exists():
        raise FileNotFoundError(f"Missing database: {DB_FILE}")

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            id,
            timestamp,
            COALESCE(NULLIF(msg, ''), rule) AS alert_message,
            snort_rule,
            classification,
            priority,
            protocol,
            service,
            COALESCE(NULLIF(src_addr, ''), src) AS source_ip,
            src_port,
            COALESCE(NULLIF(dst_addr, ''), dst) AS destination_ip,
            dst_port,
            direction,
            pkt_len,
            ttl,
            tcp_flags,
            icmp_type,
            icmp_code,
            client_pkts,
            client_bytes,
            server_pkts,
            server_bytes,
            gid,
            sid,
            rev
        FROM alerts
        ORDER BY id DESC
    """

    rows = conn.execute(query).fetchall()
    conn.close()

    return [dict(row) for row in rows]


def clean_rule_doc(rule_doc):
    if not rule_doc:
        return {}

    useful_fields = [
        "gid",
        "sid",
        "rev",
        "msg",
        "rule_category",
        "classtype",
        "protocol",
        "service",
        "flow",
        "rule_explanation",
        "what_to_look_for",
        "known_usage",
        "false_positives",
        "rule_vulnerability",
        "cve_ids",
        "mitre_id",
        "mitre_tactic",
        "mitre_technique",
        "references_text",
        "content_matches",
        "metadata",
        "rule_text",
        "doc_url",
        "doc_found",
    ]

    cleaned = {}

    for field in useful_fields:
        value = rule_doc.get(field)

        if value is None:
            continue

        text = str(value).strip()

        if text.lower() in ["", "nan", "none", "null", "n/a", "na"]:
            continue

        cleaned[field] = value

    return cleaned


def main():
    rule_docs = load_rule_docs()
    alerts = read_alerts()

    enriched_alerts = []
    documentation_matches = 0

    for alert in alerts:
        gid = alert.get("gid")
        sid = alert.get("sid")

        rule_doc = find_rule_doc(rule_docs, gid, sid)
        cleaned_rule_doc = clean_rule_doc(rule_doc)

        if cleaned_rule_doc:
            documentation_matches += 1

        enriched_alerts.append({
            "alert_id": alert.get("id"),
            "alert": {
                "timestamp": alert.get("timestamp"),
                "alert_message": alert.get("alert_message"),
                "rule_id": alert.get("snort_rule"),
                "classification": alert.get("classification"),
                "priority": alert.get("priority"),
                "protocol": alert.get("protocol"),
                "service": alert.get("service"),
                "source_ip": alert.get("source_ip"),
                "source_port": alert.get("src_port"),
                "destination_ip": alert.get("destination_ip"),
                "destination_port": alert.get("dst_port"),
                "direction": alert.get("direction"),
                "packet_length": alert.get("pkt_len"),
                "ttl": alert.get("ttl"),
                "tcp_flags": alert.get("tcp_flags"),
                "icmp_type": alert.get("icmp_type"),
                "icmp_code": alert.get("icmp_code"),
                "client_packets": alert.get("client_pkts"),
                "client_bytes": alert.get("client_bytes"),
                "server_packets": alert.get("server_pkts"),
                "server_bytes": alert.get("server_bytes"),
                "gid": alert.get("gid"),
                "sid": alert.get("sid"),
                "rev": alert.get("rev"),
            },
            "rule_documentation_found": bool(cleaned_rule_doc),
            "rule_documentation": cleaned_rule_doc,
        })

    output = {
        "export_name": "Enriched Snort Alerts with Rule Documentation",
        "source_database": str(DB_FILE),
        "source_rule_docs": str(RULE_DOC_JSON_FILE),
        "total_exported_alerts": len(enriched_alerts),
        "alerts_with_rule_documentation": documentation_matches,
        "alerts_without_rule_documentation": len(enriched_alerts) - documentation_matches,
        "note": "Alerts are exported from ids_live.db. Rule explanations are joined from rule_docs_preprocessed_by_sid.json using GID and SID.",
        "alerts": enriched_alerts,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2, ensure_ascii=False)

    print(f"[+] Exported alerts: {len(enriched_alerts)}")
    print(f"[+] Alerts with rule documentation: {documentation_matches}")
    print(f"[+] Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
