"""
Cybersecurity Network Log Analyzer
====================================
Author: Kareem Kassamia
Description:
    Simulates, stores, and analyzes network security logs to detect
    anomalies including brute force login attempts, port scans,
    unusual data transfers, and suspicious IP activity.
    
    Relevant to: CISA, DISA, Air Force INFOSEC, federal cybersecurity roles.
"""

import pandas as pd
import sqlite3
import random
import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(_SCRIPT_DIR, "security_logs.db")
OUTPUT_DIR  = os.path.join(_SCRIPT_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

KNOWN_USERS      = ["jsmith", "adavis", "mbrown", "lwhite", "rjones", "klee", "admin"]
INTERNAL_IPS     = [f"192.168.1.{i}" for i in range(10, 50)]
SUSPICIOUS_IPS   = ["45.33.32.156", "198.20.69.74", "66.240.192.138", "209.126.110.1"]
NORMAL_PORTS     = [80, 443, 22, 3389, 8080]
UNUSUAL_PORTS    = [4444, 6667, 31337, 12345, 9999]
EVENT_TYPES      = ["LOGIN_SUCCESS", "LOGIN_FAILURE", "FILE_ACCESS",
                    "PORT_SCAN", "DATA_TRANSFER", "PRIVILEGE_ESCALATION"]


# ─────────────────────────────────────────────
# STEP 1 — GENERATE SYNTHETIC SECURITY LOGS
# ─────────────────────────────────────────────
def generate_logs(n: int = 2000) -> pd.DataFrame:
    """Generate realistic synthetic network security event logs."""
    records = []
    base_time = datetime.now() - timedelta(days=30)

    for i in range(n):
        # Inject anomalies in ~15% of records
        is_anomaly = random.random() < 0.15

        timestamp  = base_time + timedelta(
            minutes=random.randint(0, 43200))  # spread over 30 days

        source_ip  = (random.choice(SUSPICIOUS_IPS)
                      if is_anomaly else random.choice(INTERNAL_IPS))
        username   = (random.choice(["root", "anonymous", "guest"])
                      if is_anomaly else random.choice(KNOWN_USERS))
        event_type = (random.choice(["LOGIN_FAILURE", "PORT_SCAN", "PRIVILEGE_ESCALATION"])
                      if is_anomaly else random.choice(EVENT_TYPES))
        port       = (random.choice(UNUSUAL_PORTS)
                      if is_anomaly else random.choice(NORMAL_PORTS))
        bytes_xfer = (random.randint(500_000, 5_000_000)
                      if is_anomaly else random.randint(100, 50_000))
        status     = ("FAILED" if event_type == "LOGIN_FAILURE"
                      else random.choice(["SUCCESS", "SUCCESS", "BLOCKED"]))

        records.append({
            "log_id"         : i + 1,
            "timestamp"      : timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip"      : source_ip,
            "username"       : username,
            "event_type"     : event_type,
            "port"           : port,
            "bytes_transferred": bytes_xfer,
            "status"         : status,
            "is_flagged"     : int(is_anomaly)
        })

    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# STEP 2 — LOAD INTO SQLITE
# ─────────────────────────────────────────────
def load_to_db(df: pd.DataFrame) -> sqlite3.Connection:
    """Store log data in a SQLite database via SQLAlchemy."""
    engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
    df.to_sql("security_logs", con=engine, if_exists="replace", index=False)
    print(f"[+] Loaded {len(df):,} log records into '{DB_PATH}'")
    return sqlite3.connect(DB_PATH)


# ─────────────────────────────────────────────
# STEP 3 — SQL ANOMALY DETECTION QUERIES
# ─────────────────────────────────────────────
def run_anomaly_queries(conn: sqlite3.Connection) -> dict:
    """Run targeted SQL queries to surface security anomalies."""
    results = {}

    # 3a — Brute force: IPs with 5+ failed logins
    results["brute_force"] = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(*)            AS failed_attempts,
               MIN(timestamp)      AS first_seen,
               MAX(timestamp)      AS last_seen
        FROM   security_logs
        WHERE  status = 'FAILED'
        GROUP  BY source_ip
        HAVING COUNT(*) >= 5
        ORDER  BY failed_attempts DESC
    """, conn)

    # 3b — Port scan detection: unusual ports by source IP
    results["port_scans"] = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(DISTINCT port) AS unique_ports,
               GROUP_CONCAT(DISTINCT port) AS ports_hit
        FROM   security_logs
        WHERE  event_type = 'PORT_SCAN'
        GROUP  BY source_ip
        HAVING COUNT(DISTINCT port) >= 2
        ORDER  BY unique_ports DESC
    """, conn)

    # 3c — High volume data transfers (top 10)
    results["data_exfil"] = pd.read_sql_query("""
        SELECT source_ip, username, bytes_transferred,
               timestamp, status
        FROM   security_logs
        WHERE  event_type = 'DATA_TRANSFER'
        ORDER  BY bytes_transferred DESC
        LIMIT  10
    """, conn)

    # 3d — Privilege escalation events
    results["priv_esc"] = pd.read_sql_query("""
        SELECT source_ip, username, timestamp, status
        FROM   security_logs
        WHERE  event_type = 'PRIVILEGE_ESCALATION'
        ORDER  BY timestamp DESC
    """, conn)

    # 3e — Event summary by type (RANK window function)
    results["event_summary"] = pd.read_sql_query("""
        SELECT event_type,
               COUNT(*)  AS total_events,
               SUM(CASE WHEN status = 'FAILED'  THEN 1 ELSE 0 END) AS failed,
               SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked,
               ROUND(AVG(bytes_transferred), 2) AS avg_bytes,
               RANK() OVER (ORDER BY COUNT(*) DESC) AS frequency_rank
        FROM   security_logs
        GROUP  BY event_type
        ORDER  BY total_events DESC
    """, conn)

    # 3f — Suspicious IP activity summary
    results["suspicious_ips"] = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(*)   AS total_events,
               COUNT(DISTINCT event_type) AS event_variety,
               SUM(bytes_transferred) AS total_bytes
        FROM   security_logs
        WHERE  is_flagged = 1
        GROUP  BY source_ip
        ORDER  BY total_events DESC
    """, conn)

    return results


# ─────────────────────────────────────────────
# STEP 4 — VISUALIZATIONS
# ─────────────────────────────────────────────
def generate_visualizations(df: pd.DataFrame, results: dict) -> None:
    """Generate security dashboard charts."""

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Cybersecurity Network Log Analysis Dashboard",
                 fontsize=16, fontweight="bold", y=1.01)

    # Chart 1 — Event type distribution
    ax1 = axes[0, 0]
    event_counts = df["event_type"].value_counts()
    colors = ["#d62728" if e in ["LOGIN_FAILURE", "PORT_SCAN", "PRIVILEGE_ESCALATION"]
              else "#1f77b4" for e in event_counts.index]
    ax1.barh(event_counts.index, event_counts.values, color=colors)
    ax1.set_title("Event Type Distribution\n(Red = Suspicious)", fontweight="bold")
    ax1.set_xlabel("Event Count")
    for i, v in enumerate(event_counts.values):
        ax1.text(v + 5, i, str(v), va="center", fontsize=9)

    # Chart 2 — Failed vs Successful logins over time
    ax2 = axes[0, 1]
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.date
    login_df = df[df["event_type"].isin(["LOGIN_SUCCESS", "LOGIN_FAILURE"])]
    login_pivot = login_df.groupby(["date", "status"]).size().unstack(fill_value=0)
    if "SUCCESS" in login_pivot.columns:
        ax2.plot(login_pivot.index, login_pivot["SUCCESS"],
                 label="Success", color="#2ca02c", linewidth=2)
    if "FAILED" in login_pivot.columns:
        ax2.plot(login_pivot.index, login_pivot["FAILED"],
                 label="Failed", color="#d62728", linewidth=2)
    ax2.set_title("Login Events Over Time", fontweight="bold")
    ax2.set_xlabel("Date")
    ax2.set_ylabel("Event Count")
    ax2.legend()
    plt.setp(ax2.xaxis.get_majorticklabels(), rotation=30, ha="right")

    # Chart 3 — Top 10 source IPs by event count
    ax3 = axes[1, 0]
    top_ips = df["source_ip"].value_counts().head(10)
    bar_colors = ["#d62728" if ip in SUSPICIOUS_IPS else "#1f77b4"
                  for ip in top_ips.index]
    ax3.bar(range(len(top_ips)), top_ips.values, color=bar_colors)
    ax3.set_xticks(range(len(top_ips)))
    ax3.set_xticklabels([ip.split(".")[-1] + ".*" if ip.startswith("192")
                         else ip[:12] for ip in top_ips.index],
                        rotation=45, ha="right", fontsize=8)
    ax3.set_title("Top 10 Source IPs by Activity\n(Red = Known Suspicious)",
                  fontweight="bold")
    ax3.set_ylabel("Event Count")

    # Chart 4 — Bytes transferred distribution (flagged vs normal)
    ax4 = axes[1, 1]
    normal  = df[df["is_flagged"] == 0]["bytes_transferred"] / 1000
    flagged = df[df["is_flagged"] == 1]["bytes_transferred"] / 1000
    ax4.hist(normal,  bins=40, alpha=0.6, color="#1f77b4", label="Normal")
    ax4.hist(flagged, bins=40, alpha=0.6, color="#d62728", label="Flagged")
    ax4.set_title("Data Transfer Distribution\n(KB)", fontweight="bold")
    ax4.set_xlabel("Kilobytes Transferred")
    ax4.set_ylabel("Frequency")
    ax4.legend()

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "security_dashboard.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Dashboard saved → {out}")


# ─────────────────────────────────────────────
# STEP 5 — GENERATE TEXT REPORT
# ─────────────────────────────────────────────
def generate_report(df: pd.DataFrame, results: dict) -> None:
    flagged   = df["is_flagged"].sum()
    total     = len(df)
    flag_rate = flagged / total * 100

    report_lines = [
        "=" * 60,
        "  CYBERSECURITY LOG ANALYSIS -- INCIDENT SUMMARY REPORT",
        "=" * 60,
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Total Logs: {total:,}   |   Flagged Events: {flagged:,} ({flag_rate:.1f}%)",
        "",
        "-- BRUTE FORCE ATTEMPTS --------------------------------------",
    ]
    if not results["brute_force"].empty:
        for _, row in results["brute_force"].iterrows():
            report_lines.append(
                f"  IP {row['source_ip']:20s}  {int(row['failed_attempts'])} failed attempts  "
                f"(first: {row['first_seen'][:10]})"
            )
    else:
        report_lines.append("  No brute force activity detected.")

    report_lines += [
        "",
        "-- PORT SCAN ACTIVITY ----------------------------------------",
    ]
    if not results["port_scans"].empty:
        for _, row in results["port_scans"].iterrows():
            report_lines.append(
                f"  IP {row['source_ip']:20s}  hit {int(row['unique_ports'])} unique ports  "
                f"[{row['ports_hit']}]"
            )
    else:
        report_lines.append("  No port scan activity detected.")

    report_lines += [
        "",
        "-- TOP DATA TRANSFERS (potential exfiltration) ---------------",
    ]
    for _, row in results["data_exfil"].head(5).iterrows():
        mb = row["bytes_transferred"] / 1_000_000
        report_lines.append(
            f"  {row['source_ip']:20s}  {mb:.2f} MB  user={row['username']}  "
            f"status={row['status']}"
        )

    report_lines += [
        "",
        "-- PRIVILEGE ESCALATION EVENTS -------------------------------",
    ]
    if not results["priv_esc"].empty:
        report_lines.append(
            f"  {len(results['priv_esc'])} privilege escalation events detected.")
        for _, row in results["priv_esc"].head(3).iterrows():
            report_lines.append(
                f"  {row['timestamp'][:16]}  IP {row['source_ip']}  "
                f"user={row['username']}  status={row['status']}"
            )
    else:
        report_lines.append("  No privilege escalation detected.")

    report_lines += [
        "",
        "-- EVENT FREQUENCY RANKING -----------------------------------",
    ]
    for _, row in results["event_summary"].iterrows():
        report_lines.append(
            f"  Rank {int(row['frequency_rank'])}  {row['event_type']:25s}  "
            f"{int(row['total_events']):>5} events  "
            f"failed={int(row['failed'])}  blocked={int(row['blocked'])}"
        )

    report_lines += ["", "=" * 60, "  END OF REPORT", "=" * 60]

    report_path = os.path.join(OUTPUT_DIR, "security_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    for line in report_lines:
        print(line)
    print(f"\n[+] Report saved -> {report_path}")
# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n[*] Cybersecurity Network Log Analyzer")
    print("[*] Generating synthetic security logs...")
    df   = generate_logs(n=2000)

    print("[*] Loading data into SQLite database...")
    conn = load_to_db(df)

    print("[*] Running anomaly detection queries...")
    results = run_anomaly_queries(conn)

    print("[*] Generating visualizations...")
    generate_visualizations(df, results)

    print("[*] Writing incident report...")
    generate_report(df, results)

    conn.close()
    print("\n[+] Analysis complete.")


if __name__ == "__main__":
    main()
