import re
import sqlite3
from pathlib import Path

DB_FILE = Path("ids_live.db")


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def find_closing_quote(text, start_index):
    """
    Find closing quote after start_index.
    Handles escaped quotes like \".
    """
    i = start_index

    while i < len(text):
        if text[i] == '"' and (i == 0 or text[i - 1] != "\\"):
            return i
        i += 1

    return -1


def extract_content_options(rule_text):
    """
    Extract Snort content options from full rule_text.

    Handles:
    content:"abc";
    content:!"abc";
    content:"|00 00|ABC|0D 0A|";

    Does NOT split on pipe characters because pipes can be part of
    Snort byte-pattern syntax.
    """
    text = clean(rule_text)

    if not text:
        return []

    results = []

    pattern = re.compile(
        r"(?<![A-Za-z0-9_])content\s*:\s*(!?)\s*\"",
        flags=re.IGNORECASE
    )

    for match in pattern.finditer(text):
        is_negated = 1 if match.group(1) == "!" else 0

        content_start = match.end()
        content_end = find_closing_quote(text, content_start)

        if content_end == -1:
            continue

        content_value = text[content_start:content_end].strip()

        if content_value:
            results.append((content_value, is_negated))

    return results


conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

cur.executescript("""
DROP TABLE IF EXISTS rule_content_matches;

CREATE TABLE rule_content_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    content_index INTEGER NOT NULL,
    content_value TEXT NOT NULL,
    is_negated INTEGER NOT NULL DEFAULT 0,
    UNIQUE(gid, sid, content_index, content_value, is_negated)
);
""")

rows = cur.execute("""
SELECT
    gid,
    sid,
    rule_text
FROM rule_docs_preprocessed
ORDER BY gid, sid
""").fetchall()

inserted = 0

for gid, sid, rule_text in rows:
    content_options = extract_content_options(rule_text)

    for index, (content_value, is_negated) in enumerate(content_options, start=1):
        cur.execute("""
        INSERT OR IGNORE INTO rule_content_matches (
            gid,
            sid,
            content_index,
            content_value,
            is_negated
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            gid,
            sid,
            index,
            content_value,
            is_negated,
        ))

        inserted += cur.rowcount

conn.commit()

print("[+] Created rule_content_matches table")
print("[+] Content rows:", cur.execute("SELECT COUNT(*) FROM rule_content_matches").fetchone()[0])
print("[+] Rules with content:", cur.execute("""
    SELECT COUNT(DISTINCT gid || ':' || sid)
    FROM rule_content_matches
""").fetchone()[0])
print("[+] Negated content rows:", cur.execute("""
    SELECT COUNT(*)
    FROM rule_content_matches
    WHERE is_negated = 1
""").fetchone()[0])

conn.close()
