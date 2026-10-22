# Scripts

This folder contains helper scripts used to build, clean, normalize, export, and retrieve Snort rule documentation data.

## Script Summary

- `build_rule_docs_db.py`
  Scrapes Snort rule documentation and stores rule metadata and documentation fields in SQLite.

- `repair_rule_docs_fetch.py`
  Re-fetches failed or incomplete Snort rule documentation rows.

- `export_preprocessed_rules.py`
  Exports the cleaned preprocessed rule documentation table to Excel.

- `create_rule_preprocessed_json.py`
  Converts the preprocessed Excel dataset into JSON keyed by SID.

- `export_normalized_database_excel.py`
  Exports normalized rule database tables into a multi-sheet Excel workbook.

- `create_rule_cves_table.py`
  Creates the normalized CVE mapping table.

- `create_rule_mitre_table.py`
  Creates the normalized MITRE ATT&CK mapping table.

- `create_rule_references_table.py`
  Creates the normalized rule references table.

- `create_rule_content_matches_table.py`
  Creates the normalized content match table.

- `get_rule_context.py`
  Retrieves full context for a Snort rule using GID and SID.