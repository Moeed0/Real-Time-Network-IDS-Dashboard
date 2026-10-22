# Real-Time Network IDS Dashboard

A local research dashboard for passive network intrusion-detection monitoring
using Snort 3, Suricata, SQLite and Streamlit.

The project collects and normalizes alerts, stores selected observations,
presents rule and vulnerability context, and supports investigation of
correlated observations. It is designed for a controlled lab environment.
It is a passive IDS research project, not an inline IPS or traffic-blocking tool.

## Features

- Snort 3 and Suricata alert ingestion.
- Normalization of alerts from both IDS engines.
- Local SQLite storage and alert exploration.
- Streamlit dashboard for live alerts and research data.
- Detection-rule context and alert intelligence.
- CVE, EPSS, CISA KEV and MITRE ATT&CK context from local datasets.
- Investigation of potentially related live observations.
- Individual-alert export and inspection.
- Independent sample alerts from Snort and Suricata.

An alert means a detection rule matched observed traffic. It does not, by
itself, prove that an attack succeeded.

## Architecture

```text
Lab network traffic
        |
Passive monitoring visibility
        |
  +-----+------+
  |            |
Snort 3      Suricata
  |            |
Alert JSON   EVE JSON
  +-----+------+
        |
Local alert collector
        |
      SQLite
        |
Streamlit dashboard
        |
Alert intelligence and investigation

## Sample data

The `sample_data/` directory contains standalone example alert records:
- `sample_data/snort/alert_json.txt`
- `sample_data/suricata/eve.json`

These examples are provided for inspection and testing. They are not a
complete traffic capture or proof of a successful attack. The examples are
independent; they do not provide cross-engine correlation test cases.

## Project data

The repository includes the local intelligence database at
`data/intel/intel.db` and the IDS rule index at
`data/lab/rules/ids_rules.db`. These large files are tracked with Git LFS.

Generated logs, packet captures, environment files, temporary databases and
local runtime data should not be committed.
