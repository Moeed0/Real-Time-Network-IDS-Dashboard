import sqlite3
import pandas as pd
from pathlib import Path

DB_FILE = Path("ids_live.db")
OUT_XLSX = Path("rule_docs_preprocessed.xlsx")
OUT_CSV = Path("rule_docs_preprocessed.csv")

conn = sqlite3.connect(DB_FILE)

df = pd.read_sql_query("""
SELECT *
FROM rule_docs_preprocessed
ORDER BY gid, sid
""", conn)

conn.close()

df.to_excel(OUT_XLSX, index=False)
df.to_csv(OUT_CSV, index=False)

print(f"Exported Excel: {OUT_XLSX}")
print(f"Exported CSV: {OUT_CSV}")
print(f"Rows exported: {len(df)}")
print(f"Columns exported: {len(df.columns)}")
