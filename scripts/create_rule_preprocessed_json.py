import json
import math
from pathlib import Path

import pandas as pd


INPUT_XLSX = Path("rule_docs_preprocessed.xlsx")
OUTPUT_JSON = Path("rule_docs_preprocessed_by_sid.json")


# Columns that should not be included in the JSON output
# because they are raw/debug/noisy/less useful for LLM context.
DROP_COLUMNS = {
    "http_status",
    "fetched_at",
    "raw_doc_text",
    "cve_additional_information",
    "direction",  # use direction_label instead
}


# Values that should be treated as empty/missing.
EMPTY_VALUES = {
    "",
    "none",
    "null",
    "nan",
    "n/a",
    "na",
    "not applicable",
}


def is_empty_value(value):
    """Return True if a value should be skipped from JSON."""
    if value is None:
        return True

    if isinstance(value, float) and math.isnan(value):
        return True

    text = str(value).strip()

    if text.lower() in EMPTY_VALUES:
        return True

    return False


def clean_value(value):
    """Convert pandas/numpy values into JSON-safe Python values."""
    if is_empty_value(value):
        return None

    # Convert floats like 408.0 to integer 408
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return value

    # Convert pandas integers/floats safely
    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass

    if isinstance(value, str):
        return value.strip()

    return value


def map_direction_label(row):
    """
    Make sure direction_label exists even if the Excel file only has direction.
    direction itself will not be included in final JSON.
    """
    if "direction_label" in row and not is_empty_value(row["direction_label"]):
        return clean_value(row["direction_label"])

    direction = row.get("direction")

    if is_empty_value(direction):
        return None

    direction = str(direction).strip()

    if direction == "->":
        return "source_to_destination"

    if direction == "<>":
        return "bidirectional"

    return None


def main():
    if not INPUT_XLSX.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_XLSX}")

    df = pd.read_excel(INPUT_XLSX)

    if "sid" not in df.columns:
        raise ValueError("The Excel file must contain a 'sid' column.")

    # Add direction_label if needed
    df["direction_label"] = df.apply(map_direction_label, axis=1)

    # Check duplicate SIDs so we do not accidentally overwrite rules
    duplicate_sids = df[df["sid"].duplicated(keep=False)]["sid"].dropna().unique()

    if len(duplicate_sids) > 0:
        print("[!] Duplicate SID values found.")
        print("[!] To avoid overwriting, JSON keys will use gid:sid format.")
        use_gid_sid_key = True
    else:
        use_gid_sid_key = False

    output = {}

    for _, row in df.iterrows():
        sid_value = clean_value(row["sid"])

        if sid_value is None:
            continue

        gid_value = clean_value(row["gid"]) if "gid" in df.columns else None

        if use_gid_sid_key:
            if gid_value is None:
                key = str(sid_value)
            else:
                key = f"{gid_value}:{sid_value}"
        else:
            key = str(sid_value)

        rule_data = {}

        for column in df.columns:
            if column in DROP_COLUMNS:
                continue

            value = clean_value(row[column])

            # Skip NULL / blank / N/A values
            if value is None:
                continue

            rule_data[column] = value

        output[key] = rule_data

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Quality checks
    total_rules = len(output)
    total_fields = sum(len(rule_data) for rule_data in output.values())

    print(f"[+] Created JSON file: {OUTPUT_JSON}")
    print(f"[+] Rules exported: {total_rules}")
    print(f"[+] Total non-empty fields exported: {total_fields}")

    # Check if any empty-like values accidentally remained
    bad_values = []

    for sid, rule_data in output.items():
        for field, value in rule_data.items():
            if is_empty_value(value):
                bad_values.append((sid, field, value))

    if bad_values:
        print(f"[!] Warning: Found {len(bad_values)} empty-like values in JSON.")
        print("[!] First 10 examples:")
        for item in bad_values[:10]:
            print(item)
    else:
        print("[+] No NULL/N/A/blank values included in JSON.")


if __name__ == "__main__":
    main()
