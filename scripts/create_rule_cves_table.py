import re
import sqlite3
from pathlib import Path

DB_FILE = Path("ids_live.db")


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def extract_cves(*values):
    found = set()

    for value in values:
        text = clean(value)

        if not text:
            continue

        # Standard format: CVE-2002-0012
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE):
            found.add(cve.upper())

        # Snort reference format: cve,2002-0012
        for year, number in re.findall(
            r"\bcve\s*,\s*(\d{4})-(\d{4,7})",
            text,
            flags=re.IGNORECASE
        ):
            found.add(f"CVE-{year}-{number}")

    return sorted(found)


conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

cur.executescript("""
DROP TABLE IF EXISTS rule_cves;

CREATE TABLE rule_cves (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (gid, sid, cve_id)
);
""")

rows = cur.execute("""
SELECT
    gid,
    sid,
    cve_ids,
    cve_text,
    references_text
FROM rule_docs_preprocessed
ORDER BY gid, sid
""").fetchall()

for gid, sid, cve_ids, cve_text, references_text in rows:
    cves = extract_cves(cve_ids, cve_text, references_text)

    for cve in cves:
        cur.execute("""
        INSERT OR IGNORE INTO rule_cves (gid, sid, cve_id)
        VALUES (?, ?, ?)
        """, (gid, sid, cve))

conn.commit()

print("[+] Created rule_cves table")
print("[+] CVE rows:", cur.execute("SELECT COUNT(*) FROM rule_cves").fetchone()[0])
print("[+] Rules with CVEs:", cur.execute("""
    SELECT COUNT(DISTINCT gid || ':' || sid)
    FROM rule_cves
""").fetchone()[0])

conn.close()
