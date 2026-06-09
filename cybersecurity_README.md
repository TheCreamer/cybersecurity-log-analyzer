# Cybersecurity Network Log Analyzer

**Author:** Kareem Kassamia  
**Stack:** Python, Pandas, SQLite, SQLAlchemy, Matplotlib  
**GitHub:** github.com/TheCreamer

---

## Overview

A Python-based security analytics pipeline that simulates, stores, and analyzes network security event logs to detect cybersecurity anomalies including brute force attacks, port scans, data exfiltration attempts, and privilege escalation events.

Built to demonstrate the data analysis and information security skills relevant to federal cybersecurity roles at CISA, DISA, and the Department of the Air Force.

---

## Features

- Generates 2,000+ realistic synthetic network security logs with injected anomalies
- Stores all log data in a structured SQLite database using SQLAlchemy
- Runs advanced SQL queries including window functions (RANK, PARTITION BY) to detect:
  - Brute force login attempts (5+ failures from same IP)
  - Port scan activity (unusual ports, multiple targets)
  - High volume data transfers (potential exfiltration)
  - Privilege escalation events
  - Suspicious IP behavior patterns
- Produces a 4-panel security dashboard visualization
- Generates a plain-language incident summary report

---

## How to Run

```bash
# Clone the repository
git clone https://github.com/TheCreamer/cybersecurity-log-analyzer
cd cybersecurity-log-analyzer

# Install dependencies
pip install pandas matplotlib sqlalchemy

# Run the analyzer
python log_analyzer.py
```

---

## Output

- `output/security_dashboard.png` — 4-panel visual dashboard
- `output/security_report.txt` — Plain-language incident summary
- `security_logs.db` — SQLite database with all log records

---

## SQL Techniques Used

- `GROUP BY` with `HAVING` for threshold-based anomaly detection
- `RANK() OVER (ORDER BY ...)` window function for event frequency ranking
- `COUNT(DISTINCT ...)` for port diversity analysis
- Subqueries and aggregations for behavioral pattern detection
- `CASE WHEN` conditional aggregations for status breakdowns

---

## Relevance to Federal Cybersecurity Roles

This project mirrors core responsibilities in federal INFOSEC analyst roles:

- **CISA** — Anomaly detection and threat identification across network data
- **DISA** — Log analysis supporting IT security operations
- **Air Force INFOSEC** — COMPUSEC monitoring and security event reporting
- **Secret Service** — High-accountability data analysis in secure environments
