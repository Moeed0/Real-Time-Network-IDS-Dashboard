import argparse
import csv
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup


DB_FILE = Path("ids_live.db")
RULES_FILE = Path("/usr/local/etc/snort/rules/snort3-community.rules")
BASE_URL = "https://www.snort.org/rule_docs"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; IDS-Dashboard-RuleDocCollector/1.0; "
        "educational-project)"
    )
}


def clean_text(text):
    if not text:
        return ""

    text = text.replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def to_int(value):
    if value is None or value == "":
        return None

    try:
        return int(value)
    except Exception:
        return None


def create_table(conn):
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS rule_docs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        gid INTEGER,
        sid INTEGER,
        rev INTEGER,

        action TEXT,
        protocol TEXT,
        src_net TEXT,
        src_port TEXT,
        direction TEXT,
        dst_net TEXT,
        dst_port TEXT,

        msg TEXT,
        classtype TEXT,
        priority INTEGER,
        flow TEXT,
        service TEXT,
        metadata TEXT,
        references_text TEXT,
        content_matches TEXT,
        rule_text TEXT,

        doc_url TEXT,
        doc_found INTEGER DEFAULT 0,
        http_status INTEGER,
        fetched_at TEXT,
        fetch_error TEXT,

        rule_category TEXT,
        alert_message_doc TEXT,
        rule_explanation TEXT,
        what_to_look_for TEXT,
        known_usage TEXT,
        false_positives TEXT,
        contributors TEXT,

        rule_groups TEXT,
        cve_ids TEXT,
        cve_text TEXT,
        rule_vulnerability TEXT,
        cve_additional_information TEXT,

        mitre_id TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        mitre_description TEXT,

        raw_doc_text TEXT,

        UNIQUE(gid, sid)
    )
    """)

    conn.commit()

def extract_option(rule, name):
    # Match real Snort option names only, not substrings inside words.
    # Example: sid should match "sid:3148;" but not "clsid:..."
    option_prefix = rf'(?<![A-Za-z0-9_]){re.escape(name)}\s*:\s*'

    quoted = re.search(option_prefix + r'"([^"]*)"', rule)
    if quoted:
        return quoted.group(1).strip()

    plain = re.search(option_prefix + r'([^;)]*)\s*;', rule)
    if plain:
        return plain.group(1).strip()

    return None

def extract_all_options(rule, name):
    values = []

    # Match real Snort option names only, not substrings inside words.
    option_prefix = rf'(?<![A-Za-z0-9_]){re.escape(name)}\s*:\s*'

    quoted_values = re.findall(option_prefix + r'"([^"]*)"', rule)

    # For options like content:"abc", keep only the clean quoted value.
    if quoted_values:
        for value in quoted_values:
            value = value.strip()
            if value and value not in values:
                values.append(value)
        return values

    plain_values = re.findall(option_prefix + r'([^;)]*)\s*;', rule)

    for value in plain_values:
        value = value.strip()
        if value and value not in values:
            values.append(value)

    return values


def normalize_rule_lines(rules_file):
    """
    Reads enabled rules from snort3-community.rules.
    Supports normal one-line rules and simple multi-line rules.
    """
    rules = []
    buffer = ""

    starters = ("alert ", "drop ", "block ", "log ", "pass ", "reject ", "rewrite ")

    with rules_file.open("r", errors="ignore") as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if line.startswith(starters):
                buffer = line

                if line.endswith(")"):
                    rules.append(buffer)
                    buffer = ""

            elif buffer:
                buffer += " " + line

                if line.endswith(")"):
                    rules.append(buffer)
                    buffer = ""

    return rules


def parse_header(rule):
    before_options = rule.split("(", 1)[0].strip()
    parts = before_options.split()

    data = {
        "action": "",
        "protocol": "",
        "src_net": "",
        "src_port": "",
        "direction": "",
        "dst_net": "",
        "dst_port": "",
    }

    if len(parts) >= 7:
        data["action"] = parts[0]
        data["protocol"] = parts[1]
        data["src_net"] = parts[2]
        data["src_port"] = parts[3]
        data["direction"] = parts[4]
        data["dst_net"] = parts[5]
        data["dst_port"] = parts[6]

    return data


def parse_local_rule(rule):
    sid = to_int(extract_option(rule, "sid"))

    if sid is None:
        return None

    gid = to_int(extract_option(rule, "gid")) or 1
    rev = to_int(extract_option(rule, "rev"))

    header = parse_header(rule)

    references = extract_all_options(rule, "reference")
    contents = extract_all_options(rule, "content")

    return {
        "gid": gid,
        "sid": sid,
        "rev": rev,

        "action": header["action"],
        "protocol": header["protocol"],
        "src_net": header["src_net"],
        "src_port": header["src_port"],
        "direction": header["direction"],
        "dst_net": header["dst_net"],
        "dst_port": header["dst_port"],

        "msg": extract_option(rule, "msg"),
        "classtype": extract_option(rule, "classtype"),
        "priority": to_int(extract_option(rule, "priority")),
        "flow": extract_option(rule, "flow"),
        "service": extract_option(rule, "service"),
        "metadata": extract_option(rule, "metadata"),
        "references_text": " | ".join(references),
        "content_matches": " | ".join(contents),
        "rule_text": rule,
        "doc_url": f"{BASE_URL}/{gid}-{sid}",
    }


def upsert_local_rule(conn, data):
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO rule_docs (
        gid, sid, rev,
        action, protocol, src_net, src_port, direction, dst_net, dst_port,
        msg, classtype, priority, flow, service, metadata,
        references_text, content_matches, rule_text, doc_url
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(gid, sid) DO UPDATE SET
        rev = excluded.rev,
        action = excluded.action,
        protocol = excluded.protocol,
        src_net = excluded.src_net,
        src_port = excluded.src_port,
        direction = excluded.direction,
        dst_net = excluded.dst_net,
        dst_port = excluded.dst_port,
        msg = excluded.msg,
        classtype = excluded.classtype,
        priority = excluded.priority,
        flow = excluded.flow,
        service = excluded.service,
        metadata = excluded.metadata,
        references_text = excluded.references_text,
        content_matches = excluded.content_matches,
        rule_text = excluded.rule_text,
        doc_url = excluded.doc_url
    """, (
        data["gid"],
        data["sid"],
        data["rev"],

        data["action"],
        data["protocol"],
        data["src_net"],
        data["src_port"],
        data["direction"],
        data["dst_net"],
        data["dst_port"],

        data["msg"],
        data["classtype"],
        data["priority"],
        data["flow"],
        data["service"],
        data["metadata"],
        data["references_text"],
        data["content_matches"],
        data["rule_text"],
        data["doc_url"],
    ))

    conn.commit()


def section_between(text, heading, all_headings):
    pattern = re.compile(rf"(?im)^\s*{re.escape(heading)}\s*$")
    match = pattern.search(text)

    if not match:
        return ""

    start = match.end()
    end = len(text)

    for other in all_headings:
        if other == heading:
            continue

        other_pattern = re.compile(rf"(?im)^\s*{re.escape(other)}\s*$")
        other_match = other_pattern.search(text, start)

        if other_match:
            end = min(end, other_match.start())

    return clean_text(text[start:end])


def label_value(text, label):
    """
    Gets value after label if page text looks like:
    MITRE ID
    T1595
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    for i, line in enumerate(lines):
        if line.lower() == label.lower() and i + 1 < len(lines):
            return lines[i + 1]

    return ""


def parse_doc_page(html):
    soup = BeautifulSoup(html, "html.parser")
    text = clean_text(soup.get_text("\n"))

    if "Missing documentation for" in text or "There is currently no documentation" in text:
        return {
            "doc_found": 0,
            "rule_category": "",
            "alert_message_doc": "",
            "rule_explanation": "",
            "what_to_look_for": "",
            "known_usage": "",
            "false_positives": "",
            "contributors": "",
            "rule_groups": "",
            "cve_ids": "",
            "cve_text": "",
            "rule_vulnerability": "",
            "cve_additional_information": "",
            "mitre_id": "",
            "mitre_tactic": "",
            "mitre_technique": "",
            "mitre_description": "",
            "raw_doc_text": text,
        }

    headings = [
        "Rule Category",
        "Alert Message",
        "Rule Explanation",
        "What To Look For",
        "Known Usage",
        "False Positives",
        "Contributors",
        "Rule Groups",
        "CVE",
        "Rule Vulnerability",
        "CVE Additional Information",
        "MITRE TTP",
        "MITRE ID",
        "Tactic",
        "Technique",
        "Description",
    ]

    rule_category = section_between(text, "Rule Category", headings)
    alert_message_doc = section_between(text, "Alert Message", headings)
    rule_explanation = section_between(text, "Rule Explanation", headings)
    what_to_look_for = section_between(text, "What To Look For", headings)
    known_usage = section_between(text, "Known Usage", headings)
    false_positives = section_between(text, "False Positives", headings)
    contributors = section_between(text, "Contributors", headings)

    rule_groups = section_between(text, "Rule Groups", headings)
    cve_text = section_between(text, "CVE", headings)
    rule_vulnerability = section_between(text, "Rule Vulnerability", headings)
    cve_additional_information = section_between(text, "CVE Additional Information", headings)

    cve_ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

    mitre_ids = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))

    mitre_id = label_value(text, "MITRE ID")
    mitre_tactic = label_value(text, "Tactic")
    mitre_technique = label_value(text, "Technique")
    mitre_description = label_value(text, "Description")

    if not mitre_id and mitre_ids:
        mitre_id = ", ".join(mitre_ids)

    # Try to extract MITRE tactic and technique from rule groups like:
    # MITRE::ATT&CK Framework::Enterprise::Reconnaissance::Active Scanning
    if rule_groups and "MITRE::" in rule_groups:
        for line in rule_groups.splitlines():
            line = line.strip()

            if line.startswith("MITRE::"):
                parts = [part.strip() for part in line.split("::")]

                if len(parts) >= 5:
                    mitre_tactic = parts[-2]
                    mitre_technique = parts[-1]

                break

    return {
        "doc_found": 1,
        "rule_category": rule_category,
        "alert_message_doc": alert_message_doc,
        "rule_explanation": rule_explanation,
        "what_to_look_for": what_to_look_for,
        "known_usage": known_usage,
        "false_positives": false_positives,
        "contributors": contributors,
        "rule_groups": rule_groups,
        "cve_ids": ", ".join(cve_ids),
        "cve_text": cve_text,
        "rule_vulnerability": rule_vulnerability,
        "cve_additional_information": cve_additional_information,
        "mitre_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "mitre_description": mitre_description,
        "raw_doc_text": text,
    }


def fetch_doc(gid, sid):
    url = f"{BASE_URL}/{gid}-{sid}"

    result = {
        "doc_url": url,
        "http_status": None,
        "fetch_error": "",
    }

    try:
        response = requests.get(url, headers=HEADERS, timeout=20)
        result["http_status"] = response.status_code

        if response.status_code != 200:
            result["fetch_error"] = f"HTTP {response.status_code}"
            result.update(parse_doc_page(""))
            return result

        result.update(parse_doc_page(response.text))
        return result

    except Exception as error:
        result["fetch_error"] = str(error)
        result.update(parse_doc_page(""))
        return result


def update_doc_result(conn, gid, sid, doc):
    cur = conn.cursor()

    cur.execute("""
    UPDATE rule_docs
    SET
        doc_found = ?,
        http_status = ?,
        fetched_at = ?,
        fetch_error = ?,

        rule_category = ?,
        alert_message_doc = ?,
        rule_explanation = ?,
        what_to_look_for = ?,
        known_usage = ?,
        false_positives = ?,
        contributors = ?,

        rule_groups = ?,
        cve_ids = ?,
        cve_text = ?,
        rule_vulnerability = ?,
        cve_additional_information = ?,

        mitre_id = ?,
        mitre_tactic = ?,
        mitre_technique = ?,
        mitre_description = ?,

        raw_doc_text = ?
    WHERE gid = ? AND sid = ?
    """, (
        doc.get("doc_found", 0),
        doc.get("http_status"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        doc.get("fetch_error", ""),

        doc.get("rule_category", ""),
        doc.get("alert_message_doc", ""),
        doc.get("rule_explanation", ""),
        doc.get("what_to_look_for", ""),
        doc.get("known_usage", ""),
        doc.get("false_positives", ""),
        doc.get("contributors", ""),

        doc.get("rule_groups", ""),
        doc.get("cve_ids", ""),
        doc.get("cve_text", ""),
        doc.get("rule_vulnerability", ""),
        doc.get("cve_additional_information", ""),

        doc.get("mitre_id", ""),
        doc.get("mitre_tactic", ""),
        doc.get("mitre_technique", ""),
        doc.get("mitre_description", ""),

        doc.get("raw_doc_text", ""),

        gid,
        sid,
    ))

    conn.commit()


def export_csv(conn, output_file):
    cur = conn.cursor()

    rows = cur.execute("""
    SELECT
        gid, sid, rev,
        msg, classtype, priority,
        action, protocol, src_net, src_port, direction, dst_net, dst_port,
        flow, service, metadata, references_text, content_matches,
        doc_url, doc_found, http_status, fetch_error,
        rule_category, alert_message_doc, rule_explanation, what_to_look_for,
        known_usage, false_positives, contributors,
        rule_groups, cve_ids, cve_text, rule_vulnerability,
        cve_additional_information,
        mitre_id, mitre_tactic, mitre_technique, mitre_description,
        rule_text
    FROM rule_docs
    ORDER BY gid, sid
    """).fetchall()

    columns = [desc[0] for desc in cur.description]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-file", default=str(RULES_FILE))
    parser.add_argument("--db", default=str(DB_FILE))
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--only-triggered", action="store_true")
    parser.add_argument("--export-csv", default="rule_docs_export.csv")
    args = parser.parse_args()

    rules_file = Path(args.rules_file)
    db_file = Path(args.db)

    if not rules_file.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_file}")

    conn = sqlite3.connect(db_file)
    create_table(conn)

    rules = normalize_rule_lines(rules_file)
    parsed_count = 0

    for rule in rules:
        parsed = parse_local_rule(rule)

        if parsed:
            upsert_local_rule(conn, parsed)
            parsed_count += 1

    print(f"[+] Stored local metadata for {parsed_count} enabled rules.")

    if args.no_fetch:
        export_csv(conn, args.export_csv)
        print(f"[+] Exported CSV: {args.export_csv}")
        conn.close()
        return

    cur = conn.cursor()

    if args.only_triggered:
        rows = cur.execute("""
        SELECT DISTINCT COALESCE(gid, 1), sid
        FROM alerts
        WHERE sid IS NOT NULL
        ORDER BY COALESCE(gid, 1), sid
        """).fetchall()
    else:
        rows = cur.execute("""
        SELECT gid, sid
        FROM rule_docs
        ORDER BY gid, sid
        """).fetchall()

    rows = rows[args.start:]

    if args.limit:
        rows = rows[:args.limit]

    print(f"[+] Fetching Snort.org documentation for {len(rows)} rules.")
    print(f"[+] Delay between requests: {args.delay} seconds")

    for index, (gid, sid) in enumerate(rows, start=1):
        if args.resume:
            existing = cur.execute("""
            SELECT fetched_at
            FROM rule_docs
            WHERE gid = ? AND sid = ?
              AND fetched_at IS NOT NULL
            """, (gid, sid)).fetchone()

            if existing:
                print(f"[{index}/{len(rows)}] Skipping already fetched {gid}:{sid}")
                continue

        print(f"[{index}/{len(rows)}] Fetching {gid}:{sid}")

        doc = fetch_doc(gid, sid)
        update_doc_result(conn, gid, sid, doc)

        if doc.get("doc_found") == 1:
            print("    documentation found")
        else:
            print("    missing documentation")

        time.sleep(args.delay)

    export_csv(conn, args.export_csv)
    print(f"[+] Exported CSV: {args.export_csv}")

    conn.close()


if __name__ == "__main__":
    main()
