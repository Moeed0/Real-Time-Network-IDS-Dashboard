import sqlite3
from pathlib import Path

import pandas as pd

DB_FILE = Path("ids_live.db")
OUT_FILE = Path("normalized_snort_rule_database.xlsx")

TABLES = [
    "rules",
    "rule_documentation",
    "rule_cves",
    "rule_mitre",
    "rule_references",
    "rule_content_matches",
]


def main():
    conn = sqlite3.connect(DB_FILE)

    overview_rows = [
        {
            "Table": "rules",
            "Purpose": "Main parent table. One row per Snort rule.",
            "Key": "Primary key: gid + sid",
        },
        {
            "Table": "rule_documentation",
            "Purpose": "Snort.org documentation and analyst explanation fields.",
            "Key": "Connected to rules using gid + sid",
        },
        {
            "Table": "rule_cves",
            "Purpose": "One CVE per rule.",
            "Key": "Connected to rules using gid + sid",
        },
        {
            "Table": "rule_mitre",
            "Purpose": "One MITRE ATT&CK technique per rule.",
            "Key": "Connected to rules using gid + sid",
        },
        {
            "Table": "rule_references",
            "Purpose": "One external reference per rule.",
            "Key": "Connected to rules using gid + sid",
        },
        {
            "Table": "rule_content_matches",
            "Purpose": "One Snort content match per rule.",
            "Key": "Connected to rules using gid + sid",
        },
    ]

    relationships_rows = [
        {
            "Parent Table": "rules",
            "Parent Key": "gid, sid",
            "Child Table": "rule_documentation",
            "Child Key": "gid, sid",
            "Relationship": "One rule has one documentation record",
        },
        {
            "Parent Table": "rules",
            "Parent Key": "gid, sid",
            "Child Table": "rule_cves",
            "Child Key": "gid, sid",
            "Relationship": "One rule can have many CVEs",
        },
        {
            "Parent Table": "rules",
            "Parent Key": "gid, sid",
            "Child Table": "rule_mitre",
            "Child Key": "gid, sid",
            "Relationship": "One rule can have many MITRE techniques",
        },
        {
            "Parent Table": "rules",
            "Parent Key": "gid, sid",
            "Child Table": "rule_references",
            "Child Key": "gid, sid",
            "Relationship": "One rule can have many external references",
        },
        {
            "Parent Table": "rules",
            "Parent Key": "gid, sid",
            "Child Table": "rule_content_matches",
            "Child Key": "gid, sid",
            "Relationship": "One rule can have many content matches",
        },
    ]

    with pd.ExcelWriter(OUT_FILE, engine="openpyxl") as writer:
        pd.DataFrame(overview_rows).to_excel(writer, sheet_name="Overview", index=False)
        pd.DataFrame(relationships_rows).to_excel(writer, sheet_name="Table_Relationships", index=False)

        for table in TABLES:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
	    # For Excel display only: show NULL values as N/A
            df = df.fillna("N/A")
            df.to_excel(writer, sheet_name=table[:31], index=False)

        workbook = writer.book

        for sheet_name in workbook.sheetnames:
            ws = workbook[sheet_name]
            ws.freeze_panes = "A2"

            for cell in ws[1]:
                cell.style = "Headline 4"

            for column_cells in ws.columns:
                max_length = 0
                column_letter = column_cells[0].column_letter

                for cell in column_cells[:100]:
                    if cell.value is not None:
                        max_length = max(max_length, len(str(cell.value)))

                adjusted_width = min(max(max_length + 2, 12), 60)
                ws.column_dimensions[column_letter].width = adjusted_width

    conn.close()

    print(f"[+] Exported: {OUT_FILE}")
    print("[+] Sheets created:")
    print("    Overview")
    print("    Table_Relationships")
    for table in TABLES:
        print(f"    {table}")


if __name__ == "__main__":
    main()
