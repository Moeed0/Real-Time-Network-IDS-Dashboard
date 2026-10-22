import re
import sqlite3
from pathlib import Path

DB_FILE = Path("ids_live.db")


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def parse_mitre_from_rule_groups(rule_groups):
    """
    Parse MITRE blocks from rule_groups.

    Example:
    MITRE::ATT&CK Framework::Enterprise::Reconnaissance::Active Scanning

    T1595
    """
    text = clean(rule_groups)

    if not text:
        return []

    rows = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    for i, line in enumerate(lines):
        if not line.startswith("MITRE::"):
            continue

        parts = [part.strip() for part in line.split("::")]

        tactic = ""
        technique = ""

        # Example parts:
        # MITRE, ATT&CK Framework, Enterprise, Reconnaissance, Active Scanning
        if len(parts) >= 5:
            tactic = parts[3]
            technique = " / ".join(parts[4:])

        mitre_ids = []

        for next_line in lines[i + 1:]:
            if (
                next_line.startswith("MITRE::")
                or next_line.startswith("Vulnerability::")
                or next_line.startswith("Rule Categories::")
            ):
                break

            mitre_ids.extend(
                re.findall(r"\bT\d{4}(?:\.\d{3})?\b", next_line)
            )

        for mitre_id in sorted(set(mitre_ids)):
            rows.append((mitre_id, tactic, technique))

    return rows


def parse_mitre_from_columns(mitre_id, mitre_tactic, mitre_technique):
    """
    Fallback parser using mitre_id, mitre_tactic, mitre_technique columns.
    """
    text = clean(mitre_id)

    if not text:
        return []

    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)

    rows = []

    for mid in sorted(set(ids)):
        rows.append((
            mid,
            clean(mitre_tactic),
            clean(mitre_technique)
        ))

    return rows


conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

cur.executescript("""
DROP TABLE IF EXISTS rule_mitre;

CREATE TABLE rule_mitre (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    mitre_id TEXT NOT NULL,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    PRIMARY KEY (gid, sid, mitre_id)
);
""")

rows = cur.execute("""
SELECT
    gid,
    sid,
    mitre_id,
    mitre_tactic,
    mitre_technique,
    rule_groups
FROM rule_docs_preprocessed
ORDER BY gid, sid
""").fetchall()

for gid, sid, mitre_id, mitre_tactic, mitre_technique, rule_groups in rows:
    mitre_rows = parse_mitre_from_rule_groups(rule_groups)

    if not mitre_rows:
        mitre_rows = parse_mitre_from_columns(
            mitre_id,
            mitre_tactic,
            mitre_technique
        )

    for mid, tactic, technique in mitre_rows:
        cur.execute("""
        INSERT OR IGNORE INTO rule_mitre (
            gid,
            sid,
            mitre_id,
            mitre_tactic,
            mitre_technique
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            gid,
            sid,
            mid,
            tactic if tactic else None,
            technique if technique else None,
        ))

conn.commit()

print("[+] Created rule_mitre table")
print("[+] MITRE rows:", cur.execute("SELECT COUNT(*) FROM rule_mitre").fetchone()[0])
print("[+] Rules with MITRE:", cur.execute("""
    SELECT COUNT(DISTINCT gid || ':' || sid)
    FROM rule_mitre
""").fetchone()[0])

conn.close()
