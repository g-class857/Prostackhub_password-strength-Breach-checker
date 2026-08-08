"""
Generator Service

Responsible for:
- Generating secure passwords
- Analyzing generated passwords
- Returning a complete report
- Logging security-relevant generation events
"""

from pathlib import Path
import sys


# ============================================================
# Project Root
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# Application Imports
# ============================================================

from modules.password_generator import generate_password
from modules.password_analyzer import analyze_password

from modules.logger import (
    logger,
    log_password_generated,
    log_generator_error,
)


# ============================================================
# Generator Service
# ============================================================

def generate_and_analyze(
    length: int,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> dict:
    """
    Generate a secure password and immediately analyze it.

    The generated password is returned to the caller but is
    never written to the application security log.
    """

    try:

        # ----------------------------------------------------
        # Generate secure password
        # ----------------------------------------------------

        password = generate_password(
            length=length,
            uppercase=uppercase,
            lowercase=lowercase,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )

        # ----------------------------------------------------
        # Log generation event
        # ----------------------------------------------------

        log_password_generated(
            logger,
            length=length,
        )

        # ----------------------------------------------------
        # Analyze generated password
        # ----------------------------------------------------

        report = analyze_password(password)

        # ----------------------------------------------------
        # Return complete result
        # ----------------------------------------------------

        return {
            "password": password,
            "report": report,
        }

    except (ValueError, TypeError) as error:

        # ----------------------------------------------------
        # Log expected generator errors
        # ----------------------------------------------------

        log_generator_error(
            logger,
            error,
        )

        raise


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    result = generate_and_analyze(
        length=20,
        uppercase=True,
        lowercase=True,
        digits=True,
        symbols=True,
        exclude_ambiguous=True,
    )

    print(result["password"])

    print(
        result["report"]["strength"]["score"]
    )
