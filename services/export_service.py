"""
Export Service

Responsible for:
- Exporting password analyses
- Supporting CSV, JSON, and PDF formats
- Returning the generated file path
"""

from pathlib import Path
from datetime import datetime
import csv
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ------------------------------------------------------------------
# Export directory
# ------------------------------------------------------------------

EXPORT_DIR = Path("reports")
EXPORT_DIR.mkdir(exist_ok=True)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def timestamp() -> str:
    """
    Generate a timestamp used in exported filenames.
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def recommendations(data: list[dict]) -> list[str]:
    """
    Generate high-level security recommendations.
    """

    breached = sum(item["breached"] for item in data)

    recommendations = []

    if breached:
        recommendations.append(
            "Replace all breached passwords immediately."
        )

    recommendations.extend([
        "Use unique passwords for every account.",
        "Use a password manager.",
        "Enable Multi-Factor Authentication (MFA).",
        "Aim for passwords with entropy above 80 bits.",
    ])

    return recommendations


# ------------------------------------------------------------------
# CSV Export
# ------------------------------------------------------------------

def export_csv(data: list[dict]) -> Path:
    """
    Export analyses to CSV.
    """

    file_path = EXPORT_DIR / f"password_report_{timestamp()}.csv"

    columns = [
        "analysis_id",
        "timestamp",
        "password_length",
        "entropy",
        "zxcvbn_score",
        "breached",
        "overall_status",
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns,
        )

        writer.writeheader()

        writer.writerows(data)

    return file_path


# ------------------------------------------------------------------
# JSON Export
# ------------------------------------------------------------------

def export_json(data: list[dict]) -> Path:
    """
    Export analyses to JSON.
    """

    file_path = EXPORT_DIR / f"password_report_{timestamp()}.json"

    with open(file_path, "w", encoding="utf-8") as file:

        json.dump(
            data,
            file,
            indent=4,
        )

    return file_path


# ------------------------------------------------------------------
# PDF Export
# ------------------------------------------------------------------

def export_pdf(
    data: list[dict],
    stats: dict,
) -> Path:
    """
    Export analyses to a professional PDF report.
    """

    file_path = EXPORT_DIR / f"password_report_{timestamp()}.pdf"

    document = SimpleDocTemplate(
        str(file_path),
        pagesize=A4,
    )

    styles = getSampleStyleSheet()

    elements = []

    # --------------------------------------------------------------

    elements.append(
        Paragraph(
            "<b>Password Security Assessment Report</b>",
            styles["Title"],
        )
    )

    elements.append(
        Paragraph(
            f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
            styles["Normal"],
        )
    )

    elements.append(Spacer(1, 20))

    # --------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------

    elements.append(
        Paragraph(
            "<b>Executive Summary</b>",
            styles["Heading2"],
        )
    )

    summary = [
        ["Total Analyses", stats["total"]],
        ["Strong Passwords", stats["strong"]],
        ["Needs Improvement", stats["needs_improvement"]],
        ["Breached Passwords", stats["breached"]],
        ["Average Entropy", stats["average_entropy"]],
    ]

    summary_table = Table(summary)

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    elements.append(summary_table)

    elements.append(Spacer(1, 20))

    # --------------------------------------------------------------
    # Analyses
    # --------------------------------------------------------------

    elements.append(
        Paragraph(
            "<b>Recent Password Analyses</b>",
            styles["Heading2"],
        )
    )

    table_data = [[
        "ID",
        "Entropy",
        "Score",
        "Breached",
        "Status",
    ]]

    for item in data:

        table_data.append([
            item["analysis_id"],
            f'{item["entropy"]:.1f}',
            item["zxcvbn_score"],
            "Yes" if item["breached"] else "No",
            item["overall_status"],
        ])

    table = Table(table_data)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
    ]))

    elements.append(table)

    elements.append(Spacer(1, 20))

    # --------------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------------

    elements.append(
        Paragraph(
            "<b>Security Recommendations</b>",
            styles["Heading2"],
        )
    )

    for recommendation in recommendations(data):

        elements.append(
            Paragraph(
                f"• {recommendation}",
                styles["Normal"],
            )
        )

    document.build(elements)

    return file_path


# ------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------

def export_report(
    export_format: str,
    analyses: list[dict],
    stats: dict,
) -> Path:
    """
    Export analyses in the requested format.
    """

    export_format = export_format.lower()

    if export_format == "csv":
        return export_csv(analyses)

    if export_format == "json":
        return export_json(analyses)

    if export_format == "pdf":
        return export_pdf(
            analyses,
            stats,
        )

    raise ValueError(
        f"Unsupported export format: {export_format}"
    )
