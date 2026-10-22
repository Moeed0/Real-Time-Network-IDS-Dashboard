import json
import sqlite3
import sys
from pathlib import Path

DB_FILE = Path("ids_live.db")


def fetch_one_dict(cur, query, params=()):
    """Return one database row as a dictionary, or None."""
    cur.execute(query, params)
    row = cur.fetchone()

    if row is None:
        return None

    return dict(row)


def fetch_all_dicts(cur, query, params=()):
    """Return all database rows as a list of dictionaries."""
    cur.execute(query, params)
    return [dict(row) for row in cur.fetchall()]


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 get_rule_context.py <gid> <sid>")
        print("Example: python3 get_rule_context.py 1 408")
        sys.exit(1)

    try:
        gid = int(sys.argv[1])
        sid = int(sys.argv[2])
    except ValueError:
        print("Error: gid and sid must be numbers.")
        sys.exit(1)

    if not DB_FILE.exists():
        print(f"Error: database not found: {DB_FILE}")
        sys.exit(1)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rule = fetch_one_dict(cur, """
        SELECT
            gid,
            sid,
            rev,
            msg,
            classtype,
            action,
            protocol,
            src_net,
            src_port,
            direction_label,
            dst_net,
            dst_port,
            flow,
            service,
            metadata,
            rule_text
        FROM rules
        WHERE gid = ? AND sid = ?
    """, (gid, sid))

    if rule is None:
        conn.close()
        print(f"No rule found for {gid}:{sid}")
        sys.exit(1)

    # Do not select cve_text or cve_additional_information here.
    # CVEs now come from the normalized rule_cves table.
    documentation = fetch_one_dict(cur, """
        SELECT
            doc_found,
            doc_url,
            rule_category,
            alert_message_doc,
            rule_explanation,
            what_to_look_for,
            known_usage,
            false_positives,
            rule_groups,
            rule_vulnerability
        FROM rule_documentation
        WHERE gid = ? AND sid = ?
    """, (gid, sid))

    cves = fetch_all_dicts(cur, """
        SELECT cve_id
        FROM rule_cves
        WHERE gid = ? AND sid = ?
        ORDER BY cve_id
    """, (gid, sid))

    mitre = fetch_all_dicts(cur, """
        SELECT
            mitre_id,
            mitre_tactic,
            mitre_technique
        FROM rule_mitre
        WHERE gid = ? AND sid = ?
        ORDER BY mitre_id
    """, (gid, sid))

    references = fetch_all_dicts(cur, """
        SELECT
            reference_type,
            reference_value
        FROM rule_references
        WHERE gid = ? AND sid = ?
        ORDER BY reference_type, reference_value
    """, (gid, sid))

    content_matches = fetch_all_dicts(cur, """
        SELECT
            content_index,
            content_value,
            is_negated
        FROM rule_content_matches
        WHERE gid = ? AND sid = ?
        ORDER BY content_index
    """, (gid, sid))

    conn.close()

    result = {
        "rule": rule,
        "documentation": documentation or {},
        "cves": cves,
        "mitre": mitre,
        "references": references,
        "content_matches": content_matches,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
