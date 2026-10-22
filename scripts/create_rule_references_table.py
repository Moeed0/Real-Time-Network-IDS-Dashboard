import re
import sqlite3
from pathlib import Path

DB_FILE = Path("ids_live.db")


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def split_references(references_text):
    """
    references_text examples:
    cve,2000-0138
    url,www.example.com
    bugtraq,11467 | cve,2002-0693 | url,example.com
    """
    text = clean(references_text)

    if not text:
        return []

    # Your scraper joined multiple reference options with ' | '
    raw_refs = [part.strip() for part in text.split(" | ") if part.strip()]

    refs = []

    for raw_ref in raw_refs:
        if "," in raw_ref:
            ref_type, ref_value = raw_ref.split(",", 1)
            ref_type = ref_type.strip().lower()
            ref_value = ref_value.strip()
        else:
            ref_type = "unknown"
            ref_value = raw_ref.strip()

        # Normalize CVE references from cve,2000-0138 to CVE-2000-0138
        if ref_type == "cve":
            if re.match(r"^\d{4}-\d{4,7}$", ref_value):
                ref_value = "CVE-" + ref_value

        # Normalize type names a little
        if ref_type in ["url", "cve", "bugtraq", "nessus", "arachnids", "mcafee"]:
            normalized_type = ref_type
        else:
            normalized_type = ref_type if ref_type else "unknown"

        if ref_value:
            refs.append((normalized_type, ref_value))

    return refs


conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

cur.executescript("""
DROP TABLE IF EXISTS rule_references;

CREATE TABLE rule_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    reference_type TEXT NOT NULL,
    reference_value TEXT NOT NULL,
    UNIQUE(gid, sid, reference_type, reference_value)
);
""")

rows = cur.execute("""
SELECT
    gid,
    sid,
    references_text
FROM rule_docs_preprocessed
WHERE references_text IS NOT NULL
ORDER BY gid, sid
""").fetchall()

inserted = 0

for gid, sid, references_text in rows:
    refs = split_references(references_text)

    for ref_type, ref_value in refs:
        cur.execute("""
        INSERT OR IGNORE INTO rule_references (
            gid,
            sid,
            reference_type,
            reference_value
        )
        VALUES (?, ?, ?, ?)
        """, (
            gid,
            sid,
            ref_type,
            ref_value,
        ))

        inserted += cur.rowcount

conn.commit()

print("[+] Created rule_references table")
print("[+] Reference rows:", cur.execute("SELECT COUNT(*) FROM rule_references").fetchone()[0])
print("[+] Rules with references:", cur.execute("""
    SELECT COUNT(DISTINCT gid || ':' || sid)
    FROM rule_references
""").fetchone()[0])

print("[+] Reference types:")
for ref_type, count in cur.execute("""
    SELECT reference_type, COUNT(*)
    FROM rule_references
    GROUP BY reference_type
    ORDER BY COUNT(*) DESC
""").fetchall():
    print(f"    {ref_type}: {count}")

conn.close()
