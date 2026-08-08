"""
Analysis Service

Coordinates password analysis, optional email breach checking,
database persistence, and security-event logging.
"""

from modules.password_analyzer import analyze_password

from modules.logger import (
    logger,
    log_password_analysis,
    log_password_breach,
)

from database.db import save_analysis


def analyze_and_save(
    password: str,
    email: str | None = None,
    hibp_api_key: str | None = None,
) -> dict:
    """
    Analyze a password, optionally check an email address
    against HIBP, save the analysis, and log security events.

    The password and HIBP API key are never written to
    the security log.

    Parameters
    ----------
    password:
        Password to analyze.

    email:
        Optional email address for breach checking.

    hibp_api_key:
        Optional HIBP API key.

        Used only for the current request and never
        persisted.
    """

    # ========================================================
    # Run Analysis
    # ========================================================

    report = analyze_password(
        password=password,
        email=email,
        hibp_api_key=hibp_api_key,
    )

    # ========================================================
    # Save Analysis
    # ========================================================

    save_analysis(report)

    # ========================================================
    # Log Password Analysis
    # ========================================================

    log_password_analysis(
        logger,
        score=report["strength"]["score"],
        breached=report["breach"]["breached"],
    )

    # ========================================================
    # Log Password Breach
    # ========================================================

    if report["breach"]["breached"]:

        log_password_breach(
            logger,
            report["breach"]["count"],
        )

    return report
