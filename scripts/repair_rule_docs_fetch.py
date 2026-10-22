import argparse
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup


DB_FILE = Path("ids_live.db")
BASE_URL = "https://www.snort.org/rule_docs"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; IDS-Dashboard-RuleDocRepair/1.0; "
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


def empty_doc(raw_text=""):
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
        "raw_doc_text": raw_text,
    }


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
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    for i, line in enumerate(lines):
        if line.lower() == label.lower() and i + 1 < len(lines):
            return lines[i + 1]

    return ""


def parse_doc_page(html):
    soup = BeautifulSoup(html or "", "html.parser")
    text = clean_text(soup.get_text("\n"))

    if not text:
        return empty_doc("")

    missing_markers = [
        "Missing documentation for",
        "There is currently no documentation",
    ]

    if any(marker in text for marker in missing_markers):
        return empty_doc(text)

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

    if rule_groups and "MITRE::" in rule_groups:
        for line in rule_groups.splitlines():
            line = line.strip()

            if line.startswith("MITRE::"):
                parts = [part.strip() for part in line.split("::")]

                if len(parts) >= 5:
                    mitre_tactic = parts[-2]
                    mitre_technique = parts[-1]

                break

    useful_fields = [
        rule_category,
        rule_explanation,
        rule_groups,
        cve_text,
        rule_vulnerability,
        ", ".join(cve_ids),
        mitre_id,
        mitre_tactic,
        mitre_technique,
    ]

    doc_found = 1 if any(str(value).strip() for value in useful_fields) else 0

    return {
        "doc_found": doc_found,
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


def fetch_doc(gid, sid, max_retries=3, retry_wait=60):
    url = f"{BASE_URL}/{gid}-{sid}"

    result = {
        "doc_url": url,
        "http_status": None,
        "fetch_error": "",
    }

    retryable_statuses = {429, 500, 502, 503, 504}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
            result["http_status"] = response.status_code

            if response.status_code == 200:
                parsed = parse_doc_page(response.text)
                result.update(parsed)
                result["fetch_error"] = ""
                return result

            result["fetch_error"] = f"HTTP {response.status_code}"
            result.update(empty_doc())

            if response.status_code in retryable_statuses and attempt < max_retries:
                wait_time = retry_wait * attempt
                print(f"    retryable HTTP {response.status_code}; sleeping {wait_time}s")
                time.sleep(wait_time)
                continue

            return result

        except Exception as error:
            result["fetch_error"] = str(error)
            result.update(empty_doc())

            if attempt < max_retries:
                wait_time = retry_wait * attempt
                print(f"    error: {error}; sleeping {wait_time}s")
                time.sleep(wait_time)
                continue

            return result

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


BAD_ROWS_QUERY = """
SELECT gid, sid
FROM rule_docs
WHERE fetched_at IS NULL
   OR http_status IS NULL
   OR http_status != 200
   OR (fetch_error IS NOT NULL AND TRIM(fetch_error) != '')
   OR (
        doc_found = 1
        AND TRIM(COALESCE(rule_category, '')) = ''
        AND TRIM(COALESCE(rule_explanation, '')) = ''
        AND TRIM(COALESCE(rule_groups, '')) = ''
        AND TRIM(COALESCE(cve_ids, '')) = ''
        AND TRIM(COALESCE(mitre_id, '')) = ''
        AND TRIM(COALESCE(rule_vulnerability, '')) = ''
   )
ORDER BY gid, sid
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(DB_FILE))
    parser.add_argument("--delay", type=float, default=8.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--retry-wait", type=int, default=60)
    parser.add_argument("--count-only", action="store_true")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()

    rows = cur.execute(BAD_ROWS_QUERY).fetchall()

    if args.limit:
        rows = rows[:args.limit]

    print(f"[+] Bad/uncertain rows to repair: {len(rows)}")

    if args.count_only:
        conn.close()
        return

    for index, (gid, sid) in enumerate(rows, start=1):
        print(f"[{index}/{len(rows)}] Re-fetching {gid}:{sid}")

        doc = fetch_doc(
            gid,
            sid,
            max_retries=args.max_retries,
            retry_wait=args.retry_wait,
        )

        update_doc_result(conn, gid, sid, doc)

        if doc.get("fetch_error"):
            print(f"    fetch_error: {doc.get('fetch_error')}")
        elif doc.get("doc_found") == 1:
            print("    documentation found")
        else:
            print("    no documentation page content found")

        time.sleep(args.delay)

    conn.close()
    print("[+] Repair pass complete.")


if __name__ == "__main__":
    main()
