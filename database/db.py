"""
SQLite Database Layer

Responsible for:
- Creating the database
- Creating tables
- Providing a database connection
- Storing password analyses
- Logging security events
- Retrieving dashboard statistics
"""

import sqlite3
from pathlib import Path
from datetime import datetime

DATABASE_PATH = Path(__file__).parent / "password_checker.db"


# ==========================================================
# Database Connection
# ==========================================================

def get_connection():
    print(f"Using database: {DATABASE_PATH.resolve()}")

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# ==========================================================
# Database Initialization
# ==========================================================

def initialize_database() -> None:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses(
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            password_length INTEGER NOT NULL,
            entropy REAL NOT NULL,
            zxcvbn_score INTEGER NOT NULL,
            breached INTEGER NOT NULL,
            overall_status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events(
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY(analysis_id)
            REFERENCES analyses(analysis_id)
        )
    """)

    connection.commit()
    connection.close()


# ==========================================================
# Insert Analysis
# ==========================================================

def insert_analysis(report: dict) -> int:

    if report["breach"]["breached"]:
        overall_status = "High Risk"

    elif report["strength"]["score"] < 3 or not report["rules"]["passed"]:
        overall_status = "Needs Improvement"

    else:
        overall_status = "Strong Password"

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO analyses(
            timestamp,
            password_length,
            entropy,
            zxcvbn_score,
            breached,
            overall_status
        )
        VALUES(?,?,?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report["entropy"]["length"],
        report["entropy"]["entropy"],
        report["strength"]["score"],
        int(report["breach"]["breached"]),
        overall_status,
    ))

    analysis_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return analysis_id


# ==========================================================
# Events
# ==========================================================

def insert_event(
    analysis_id: int,
    source: str,
    severity: str,
    message: str,
) -> None:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events(
            analysis_id,
            source,
            severity,
            message
        )
        VALUES(?,?,?,?)
    """, (
        analysis_id,
        source,
        severity,
        message,
    ))

    connection.commit()
    connection.close()


def log_analysis_events(
    analysis_id: int,
    report: dict,
) -> None:

    breach = report["breach"]

    if breach["breached"]:
        insert_event(
            analysis_id,
            "HIBP",
            "High",
            f"Password found in {breach['count']:,} known data breaches."
        )

    warning = report["strength"]["feedback"]["warning"]

    if warning:
        insert_event(
            analysis_id,
            "zxcvbn",
            "Medium",
            warning,
        )

    entropy = report["entropy"]

    if entropy["entropy"] < 60:
        insert_event(
            analysis_id,
            "Entropy",
            "Medium",
            f"Low password entropy ({entropy['entropy']} bits)."
        )

    if not report["rules"]["passed"]:
        for issue in report["rules"]["issues"]:
            insert_event(
                analysis_id,
                "Custom Rules",
                "Medium",
                issue,
            )


def save_analysis(report: dict) -> int:

    analysis_id = insert_analysis(report)

    log_analysis_events(
        analysis_id,
        report,
    )

    return analysis_id


# ==========================================================
# Queries
# ==========================================================

def get_all_analyses() -> list[dict]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM analyses
        ORDER BY analysis_id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]

def get_export_data() -> list[dict]:
    """
    Return every saved password analysis.

    Used by the export service.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            analysis_id,
            timestamp,
            password_length,
            entropy,
            zxcvbn_score,
            breached,
            overall_status
        FROM analyses
        ORDER BY analysis_id ASC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]

def get_recent_analyses(limit: int = 5) -> list[dict]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM analyses
        ORDER BY analysis_id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


# ==========================================================
# Dashboard
# ==========================================================

def get_dashboard_data() -> dict:
    """
    Return all data required by the dashboard.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # ==========================
    # Statistics
    # ==========================

    cursor.execute("""
        SELECT
            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN LOWER(TRIM(overall_status)) LIKE '%strong%'
                    THEN 1
                    ELSE 0
                END
            ) AS strong,
            
            SUM(
		CASE
			WHEN LOWER(TRIM(overall_status)) LIKE '%high%'
			THEN 1
			ELSE 0
		END
	    ) AS high_risk,

            SUM(
                CASE
                    WHEN LOWER(TRIM(overall_status)) LIKE '%need%'
                    THEN 1
                    ELSE 0
                END
            ) AS needs_improvement,

            SUM(
                CASE
                    WHEN breached = 1
                    THEN 1
                    ELSE 0
                END
            ) AS breached,

            AVG(entropy) AS average_entropy

        FROM analyses
    """)

    stats = dict(cursor.fetchone())

    stats["strong"] = stats["strong"] or 0
    stats["needs_improvement"] = stats["needs_improvement"] or 0
    stats["breached"] = stats["breached"] or 0
    stats["average_entropy"] = round(
        stats["average_entropy"] or 0,
        2,
    )

    # ==========================
    # Status Distribution
    # ==========================

    cursor.execute("""
        SELECT
            overall_status,
            COUNT(*) AS total
        FROM analyses
        GROUP BY overall_status
    """)

    distribution = {
        "Strong Password": 0,
        "Needs Improvement": 0,
        "High Risk": 0,
    }

    for row in cursor.fetchall():
        status = row["overall_status"].strip().lower()

        if "strong" in status:
            distribution["Strong Password"] += row["total"]

        elif "need" in status:
            distribution["Needs Improvement"] += row["total"]

        elif "high" in status:
            distribution["High Risk"] += row["total"]
    # ==========================
    # Entropy History
    # ==========================

    cursor.execute("""
        SELECT
            analysis_id,
            entropy
        FROM analyses
        ORDER BY analysis_id DESC
        LIMIT 10
    """)

    entropy = [dict(row) for row in cursor.fetchall()]
    entropy.reverse()

    connection.close()

    return {
        "stats": stats,
        "status": distribution,
        "entropy": entropy,
    }

# ==========================================================
# Main
# ==========================================================

def main():

    initialize_database()

    print("Database initialized.")
    print(DATABASE_PATH.resolve())


if __name__ == "__main__":
    main()
