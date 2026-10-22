#!/usr/bin/env python3

import json
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_ROOT / "config" / "ids_sources.json"
OUTPUT_DIR = PROJECT_ROOT / "data" / "lab" / "rules"

DB_FILE = OUTPUT_DIR / "ids_rules.db"
SUMMARY_FILE = OUTPUT_DIR / "index_summary.json"
ERROR_FILE = OUTPUT_DIR / "rule_parse_errors.jsonl"

RULE_START_RE = re.compile(
    r"^(alert|drop|reject|pass|sdrop)\s+",
    re.IGNORECASE,
)

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)", re.IGNORECASE)
GID_RE = re.compile(r"\bgid\s*:\s*(\d+)", re.IGNORECASE)
REV_RE = re.compile(r"\brev\s*:\s*(\d+)", re.IGNORECASE)
PRIORITY_RE = re.compile(r"\bpriority\s*:\s*(\d+)", re.IGNORECASE)

# The value ends at the next semicolon.
SIMPLE_OPTION_PATTERNS = {
    "classtype": re.compile(r"\bclasstype\s*:\s*([^;]+)", re.IGNORECASE),
    "service": re.compile(r"\bservice\s*:\s*([^;]+)", re.IGNORECASE),
    "flow": re.compile(r"\bflow\s*:\s*([^;]+)", re.IGNORECASE),
    "detection_filter": re.compile(
        r"\bdetection_filter\s*:\s*([^;]+)", re.IGNORECASE
    ),
    "app_layer_event": re.compile(
        r"\bapp-layer-event\s*:\s*([^;]+)", re.IGNORECASE
    ),
}

MSG_RE = re.compile(
    r'\bmsg\s*:\s*"(.*?)"\s*;',
    re.IGNORECASE | re.DOTALL,
)

REFERENCE_RE = re.compile(
    r"\breference\s*:\s*([^;]+)",
    re.IGNORECASE,
)

METADATA_RE = re.compile(
    r"\bmetadata\s*:\s*([^;]+)",
    re.IGNORECASE,
)

CONTENT_RE = re.compile(
    r"\bcontent\s*:\s*(.*?)(?=;\s*[A-Za-z][A-Za-z0-9_-]*\s*:|;\s*\)|\s*$)",
    re.IGNORECASE,
)

# These are deliberately broad because rule text can contain unusual
# quoting, PCRE expressions, binary content and nested syntax.
CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

MITRE_RE = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

URL_RE = re.compile(
    r"https?://[^\s,;)]+",
    re.IGNORECASE,
)


def clean_value(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    if len(value) >= 2 and value[0] == value[-1]:
        if value[0] in ('"', "'"):
            value = value[1:-1]

    return value


def extract_first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None

    return clean_value(match.group(1))


def extract_all(pattern: re.Pattern[str], text: str) -> list[str]:
    values = []

    for match in pattern.finditer(text):
        value = clean_value(match.group(1))

        if value:
            values.append(value)

    return values


def extract_integer(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)

    if not match:
        return None

    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_header(header: str) -> dict[str, Any]:
    """
    Parse the rule header without assuming traditional TCP/UDP syntax.

    Supports both:

        alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (...)

    and Snort 3 service/application rules such as:

        alert http (...)

        alert file (...)
    """

    tokens = header.split()

    result = {
        "action": tokens[0] if tokens else None,
        "protocol": None,
        "src_addr": None,
        "src_port": None,
        "direction": None,
        "dst_addr": None,
        "dst_port": None,
        "header_tokens": tokens,
    }

    if len(tokens) < 2:
        return result

    # For Snort 3 service rules: alert http (...)
    # For file rules: alert file (...)
    if len(tokens) == 2:
        result["protocol"] = tokens[1]
        return result

    # Traditional rule format:
    # action protocol src_addr src_port direction dst_addr dst_port
    if len(tokens) >= 7 and tokens[4] in ("->", "<>"):
        result["protocol"] = tokens[1]
        result["src_addr"] = tokens[2]
        result["src_port"] = tokens[3]
        result["direction"] = tokens[4]
        result["dst_addr"] = tokens[5]
        result["dst_port"] = tokens[6]
        return result

    # Fallback: preserve the first useful protocol token.
    result["protocol"] = tokens[1]

    return result


def parse_rule(line: str) -> dict[str, Any] | None:
    raw = line.strip()

    if not raw or raw.startswith("#"):
        return None

    if not RULE_START_RE.match(raw):
        return None

    open_paren = raw.find("(")
    close_paren = raw.rfind(")")

    if open_paren <= 0 or close_paren <= open_paren:
        return None

    header = raw[:open_paren].strip()
    option_text = raw[open_paren + 1:close_paren].strip()

    header_data = parse_header(header)

    # Extract identity fields directly from raw rule text.
    # This avoids losing SIDs because of complex PCRE/quote syntax.
    sid = extract_integer(SID_RE, raw)

    if sid is None:
        return {
            "missing_sid": True,
            "action": header_data["action"],
            "protocol": header_data["protocol"],
            "src_addr": header_data["src_addr"],
            "src_port": header_data["src_port"],
            "direction": header_data["direction"],
            "dst_addr": header_data["dst_addr"],
            "dst_port": header_data["dst_port"],
            "header_tokens": header_data["header_tokens"],
            "raw_options": option_text,
            "rule_text": raw,
        }

    gid = extract_integer(GID_RE, raw)
    rev = extract_integer(REV_RE, raw)

    if gid is None:
        gid = 1

    # Common fields are extracted independently.
    # Failure to extract one optional field does NOT invalidate the rule.
    msg = extract_first(MSG_RE, raw)

    classtype = extract_first(
        SIMPLE_OPTION_PATTERNS["classtype"],
        raw,
    )

    service = extract_first(
        SIMPLE_OPTION_PATTERNS["service"],
        raw,
    )

    flow = extract_first(
        SIMPLE_OPTION_PATTERNS["flow"],
        raw,
    )

    detection_filter = extract_first(
        SIMPLE_OPTION_PATTERNS["detection_filter"],
        raw,
    )

    app_layer_event = extract_first(
        SIMPLE_OPTION_PATTERNS["app_layer_event"],
        raw,
    )

    priority = extract_integer(PRIORITY_RE, raw)

    references = extract_all(REFERENCE_RE, raw)
    metadata = extract_all(METADATA_RE, raw)
    content_matches = extract_all(CONTENT_RE, raw)

    cve_ids = sorted(
        set(
            x.upper()
            for x in CVE_RE.findall(raw)
        )
    )

    mitre_ids = sorted(
        set(
            x.upper()
            for x in MITRE_RE.findall(raw)
        )
    )

    urls = sorted(
        set(URL_RE.findall(raw))
    )

    # Keep a structured "known options" object while preserving the
    # COMPLETE original options text separately.
    options: dict[str, Any] = {}

    if msg is not None:
        options["msg"] = msg

    if classtype is not None:
        options["classtype"] = classtype

    if priority is not None:
        options["priority"] = priority

    if service is not None:
        options["service"] = service

    if flow is not None:
        options["flow"] = flow

    if detection_filter is not None:
        options["detection_filter"] = detection_filter

    if app_layer_event is not None:
        options["app-layer-event"] = app_layer_event

    if references:
        options["reference"] = references

    if metadata:
        options["metadata"] = metadata

    if content_matches:
        options["content"] = content_matches

    return {
        "missing_sid": False,
        "action": header_data["action"],
        "protocol": header_data["protocol"],
        "src_addr": header_data["src_addr"],
        "src_port": header_data["src_port"],
        "direction": header_data["direction"],
        "dst_addr": header_data["dst_addr"],
        "dst_port": header_data["dst_port"],
        "header_tokens": header_data["header_tokens"],
        "msg": msg,
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "classtype": classtype,
        "priority": priority,
        "service": service,
        "flow": flow,
        "metadata": metadata,
        "references": references,
        "content_matches": content_matches,
        "detection_filter": detection_filter,
        "app_layer_event": app_layer_event,
        "cve_ids": cve_ids,
        "mitre_ids": mitre_ids,
        "urls": urls,
        "options": options,
        "raw_options": option_text,
        "rule_text": raw,
    }


def initialize_database(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

        DROP TABLE IF EXISTS rules;

        CREATE TABLE rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            engine TEXT NOT NULL,

            gid INTEGER,
            sid INTEGER NOT NULL,
            rev INTEGER,

            action TEXT,
            protocol TEXT,

            src_addr TEXT,
            src_port TEXT,
            direction TEXT,
            dst_addr TEXT,
            dst_port TEXT,

            rule_header TEXT,

            msg TEXT,
            classtype TEXT,
            priority INTEGER,
            service TEXT,
            flow TEXT,

            metadata_json TEXT,
            references_json TEXT,
            content_matches_json TEXT,
            detection_filter TEXT,
            app_layer_event TEXT,

            cve_ids_json TEXT,
            mitre_ids_json TEXT,
            urls_json TEXT,

            options_json TEXT,
            raw_options TEXT,
            rule_text TEXT,

            source_file TEXT NOT NULL,
            source_line INTEGER NOT NULL
        );

        CREATE INDEX idx_rules_engine_sid
            ON rules(engine, sid);

        CREATE INDEX idx_rules_engine_gid_sid_rev
            ON rules(engine, gid, sid, rev);

        CREATE INDEX idx_rules_sid
            ON rules(sid);

        CREATE INDEX idx_rules_msg
            ON rules(msg);
        """
    )


def index_rule_file(
    conn: sqlite3.Connection,
    engine: str,
    path: Path,
    error_handle,
) -> dict[str, int]:

    stats = Counter()

    insert_sql = """
        INSERT INTO rules (
            engine,
            gid,
            sid,
            rev,
            action,
            protocol,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            rule_header,
            msg,
            classtype,
            priority,
            service,
            flow,
            metadata_json,
            references_json,
            content_matches_json,
            detection_filter,
            app_layer_event,
            cve_ids_json,
            mitre_ids_json,
            urls_json,
            options_json,
            raw_options,
            rule_text,
            source_file,
            source_line
        )
        VALUES (
            :engine,
            :gid,
            :sid,
            :rev,
            :action,
            :protocol,
            :src_addr,
            :src_port,
            :direction,
            :dst_addr,
            :dst_port,
            :rule_header,
            :msg,
            :classtype,
            :priority,
            :service,
            :flow,
            :metadata_json,
            :references_json,
            :content_matches_json,
            :detection_filter,
            :app_layer_event,
            :cve_ids_json,
            :mitre_ids_json,
            :urls_json,
            :options_json,
            :raw_options,
            :rule_text,
            :source_file,
            :source_line
        )
    """

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line_number, line in enumerate(handle, start=1):

            stripped = line.strip()

            if not RULE_START_RE.match(stripped):
                stats["non_rule_lines"] += 1
                continue

            stats["candidate_rule_lines"] += 1

            try:
                parsed = parse_rule(stripped)

                if parsed is None:
                    stats["parse_failed"] += 1

                    error_handle.write(
                        json.dumps(
                            {
                                "engine": engine,
                                "source_file": str(path),
                                "source_line": line_number,
                                "reason": "invalid_rule_structure",
                                "rule": stripped,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                    continue

                if parsed.get("missing_sid"):
                    stats["missing_sid"] += 1

                    error_handle.write(
                        json.dumps(
                            {
                                "engine": engine,
                                "source_file": str(path),
                                "source_line": line_number,
                                "reason": "missing_sid",
                                "rule": stripped,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                    continue

                header_tokens = parsed["header_tokens"]

                conn.execute(
                    insert_sql,
                    {
                        "engine": engine,
                        "gid": parsed["gid"],
                        "sid": parsed["sid"],
                        "rev": parsed["rev"],
                        "action": parsed["action"],
                        "protocol": parsed["protocol"],
                        "src_addr": parsed["src_addr"],
                        "src_port": parsed["src_port"],
                        "direction": parsed["direction"],
                        "dst_addr": parsed["dst_addr"],
                        "dst_port": parsed["dst_port"],
                        "rule_header": " ".join(header_tokens),
                        "msg": parsed["msg"],
                        "classtype": parsed["classtype"],
                        "priority": parsed["priority"],
                        "service": parsed["service"],
                        "flow": parsed["flow"],
                        "metadata_json": json.dumps(
                            parsed["metadata"],
                            ensure_ascii=False,
                        ),
                        "references_json": json.dumps(
                            parsed["references"],
                            ensure_ascii=False,
                        ),
                        "content_matches_json": json.dumps(
                            parsed["content_matches"],
                            ensure_ascii=False,
                        ),
                        "detection_filter": parsed["detection_filter"],
                        "app_layer_event": parsed["app_layer_event"],
                        "cve_ids_json": json.dumps(
                            parsed["cve_ids"],
                            ensure_ascii=False,
                        ),
                        "mitre_ids_json": json.dumps(
                            parsed["mitre_ids"],
                            ensure_ascii=False,
                        ),
                        "urls_json": json.dumps(
                            parsed["urls"],
                            ensure_ascii=False,
                        ),
                        "options_json": json.dumps(
                            parsed["options"],
                            ensure_ascii=False,
                        ),
                        "raw_options": parsed["raw_options"],
                        "rule_text": parsed["rule_text"],
                        "source_file": str(path),
                        "source_line": line_number,
                    },
                )

                stats["parsed_rules"] += 1

            except Exception as exc:
                stats["processing_failed"] += 1

                error_handle.write(
                    json.dumps(
                        {
                            "engine": engine,
                            "source_file": str(path),
                            "source_line": line_number,
                            "reason": f"processing_exception: {exc}",
                            "rule": stripped,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )

    return dict(stats)


def load_config() -> dict[str, Any]:
    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def get_rule_count(
    conn: sqlite3.Connection,
    engine: str,
) -> int:

    row = conn.execute(
        "SELECT COUNT(*) FROM rules WHERE engine = ?",
        (engine,),
    ).fetchone()

    return int(row[0])


def get_unique_sid_count(
    conn: sqlite3.Connection,
    engine: str,
) -> int:

    row = conn.execute(
        "SELECT COUNT(DISTINCT sid) FROM rules WHERE engine = ?",
        (engine,),
    ).fetchone()

    return int(row[0])


def main() -> None:

    config = load_config()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if DB_FILE.exists():
        DB_FILE.unlink()

    if ERROR_FILE.exists():
        ERROR_FILE.unlink()

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    initialize_database(conn)

    summary: dict[str, Any] = {
        "database": str(DB_FILE),
        "engines": {},
    }

    with ERROR_FILE.open(
        "a",
        encoding="utf-8",
    ) as error_handle:

        # =========================
        # SNORT
        # =========================

        snort_config = config["snort"]
        snort_root = Path(snort_config["rules_path"])

        snort_files = sorted(
            snort_root.rglob("*.rules")
        )

        snort_total = Counter()

        for rule_file in snort_files:

            file_stats = index_rule_file(
                conn,
                "snort",
                rule_file,
                error_handle,
            )

            snort_total.update(file_stats)

        conn.commit()

        summary["engines"]["snort"] = {
            "rules_path": str(snort_root),
            "rule_files": len(snort_files),
            "candidate_rule_lines": snort_total["candidate_rule_lines"],
            "parsed_rules": get_rule_count(
                conn,
                "snort",
            ),
            "unique_sids": get_unique_sid_count(
                conn,
                "snort",
            ),
            "parse_failed": snort_total["parse_failed"],
            "missing_sid": snort_total["missing_sid"],
            "processing_failed": snort_total["processing_failed"],
            "engine_reported_loaded_rules": snort_config.get(
                "engine_rule_count"
            ),
        }

        # =========================
        # SURICATA
        # =========================

        suricata_config = config["suricata"]
        suricata_file = Path(
            suricata_config["rules_file"]
        )

        suricata_stats = index_rule_file(
            conn,
            "suricata",
            suricata_file,
            error_handle,
        )

        conn.commit()

        summary["engines"]["suricata"] = {
            "rules_file": str(suricata_file),
            "candidate_rule_lines": suricata_stats.get(
                "candidate_rule_lines",
                0,
            ),
            "parsed_rules": get_rule_count(
                conn,
                "suricata",
            ),
            "unique_sids": get_unique_sid_count(
                conn,
                "suricata",
            ),
            "parse_failed": suricata_stats.get(
                "parse_failed",
                0,
            ),
            "missing_sid": suricata_stats.get(
                "missing_sid",
                0,
            ),
            "processing_failed": suricata_stats.get(
                "processing_failed",
                0,
            ),
            "engine_reported_loaded_rules": suricata_config.get(
                "engine_rule_count"
            ),
        }

    duplicate_rows = conn.execute(
        """
        SELECT engine, gid, sid, rev, COUNT(*) AS count
        FROM rules
        GROUP BY engine, gid, sid, rev
        HAVING COUNT(*) > 1
        ORDER BY count DESC
        """
    ).fetchall()

    summary["duplicate_exact_rule_ids"] = [
        {
            "engine": row["engine"],
            "gid": row["gid"],
            "sid": row["sid"],
            "rev": row["rev"],
            "count": row["count"],
        }
        for row in duplicate_rows
    ]

    summary["total_indexed_rules"] = conn.execute(
        "SELECT COUNT(*) FROM rules"
    ).fetchone()[0]

    summary["index_format"] = {
        "database": "SQLite",
        "native_rule_text_preserved": True,
        "raw_options_preserved": True,
        "known_options_extracted": True,
        "service_style_rules_supported": True,
        "source_file_and_line_preserved": True,
    }

    conn.close()

    with SUMMARY_FILE.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            summary,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    print("Rule indexing complete.")
    print()
    print(f"Database: {DB_FILE}")
    print(f"Summary:  {SUMMARY_FILE}")
    print(f"Errors:   {ERROR_FILE}")
    print()

    print(
        "Snort indexed:    "
        f"{summary['engines']['snort']['parsed_rules']}"
    )

    print(
        "Suricata indexed: "
        f"{summary['engines']['suricata']['parsed_rules']}"
    )

    print(
        "Total indexed:    "
        f"{summary['total_indexed_rules']}"
    )

    print()

    print(
        "Snort parse failures: "
        f"{summary['engines']['snort']['parse_failed']}"
    )

    print(
        "Snort missing SID: "
        f"{summary['engines']['snort']['missing_sid']}"
    )

    print(
        "Snort processing failures: "
        f"{summary['engines']['snort']['processing_failed']}"
    )

    print()

    print(
        "Suricata parse failures: "
        f"{summary['engines']['suricata']['parse_failed']}"
    )

    print(
        "Suricata missing SID: "
        f"{summary['engines']['suricata']['missing_sid']}"
    )

    print(
        "Suricata processing failures: "
        f"{summary['engines']['suricata']['processing_failed']}"
    )

    print()

    print(
        "Duplicate exact rule IDs: "
        f"{len(summary['duplicate_exact_rule_ids'])}"
    )


if __name__ == "__main__":
    main()
