"""
Application security logger.

Provides a centralized logging configuration for the Password
Strength & Breach Checker application.

The logger writes security events to:

    logs/security.log

The file is designed to be monitored by the Watchdog service.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "logs"

LOG_FILE = LOG_DIR / "security.log"


# ============================================================
# Logging Configuration
# ============================================================

LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ============================================================
# Logger Factory
# ============================================================

def get_logger(name: str = "password_checker") -> logging.Logger:
    """
    Return a configured application logger.

    The logger writes security/application events to the
    rotating security.log file.

    Parameters
    ----------
    name:
        Logger name.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """

    logger = logging.getLogger(name)

    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers when Flask reloads the application.
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    # --------------------------------------------------------
    # Rotating file handler
    # --------------------------------------------------------

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )

    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


# ============================================================
# Default Application Logger
# ============================================================

logger = get_logger()


# ============================================================
# Security Event Helpers
# ============================================================

def log_password_analysis(
    logger_instance: logging.Logger,
    score: int,
    breached: bool,
) -> None:
    """
    Log a password analysis event.

    The actual password is intentionally NOT logged.
    """

    logger_instance.info(
        "Password analyzed | score=%s | breached=%s",
        score,
        breached,
    )


def log_password_generated(
    logger_instance: logging.Logger,
    length: int,
) -> None:
    """
    Log a password-generation event.

    The generated password is intentionally NOT logged.
    """

    logger_instance.info(
        "Password generated | length=%s",
        length,
    )


def log_password_breach(
    logger_instance: logging.Logger,
    count: int,
) -> None:
    """
    Log when a password is found in known breaches.

    The password itself is never written to the log.
    """

    logger_instance.warning(
        "Password found in breach database | count=%s",
        count,
    )


def log_email_breach(
    logger_instance: logging.Logger,
    email: str,
    count: int,
) -> None:
    """
    Log an email breach event.

    Only the email identifier is logged here.
    Passwords and API keys must never be logged.
    """

    logger_instance.warning(
        "Email breach detected | email=%s | count=%s",
        mask_email(email),
        count,
    )


def log_email_check(
    logger_instance: logging.Logger,
    email: str,
) -> None:
    """
    Log an email breach lookup.
    """

    logger_instance.info(
        "Email breach check performed | email=%s",
        mask_email(email),
    )


def log_generator_error(
    logger_instance: logging.Logger,
    error: Exception,
) -> None:
    """
    Log a password generator error.
    """

    logger_instance.error(
        "Password generation error | error=%s",
        error,
    )


def log_api_error(
    logger_instance: logging.Logger,
    service: str,
    error: Exception,
) -> None:
    """
    Log an external API error.

    API keys, passwords, and other secrets must never
    be included in the error message.
    """

    logger_instance.error(
        "External API error | service=%s | error=%s",
        service,
        error,
    )

def mask_email(email: str) -> str:
    """
    Mask an email address before writing it to logs.
    """

    if "@" not in email:
        return "***"

    local, domain = email.split("@", 1)

    if not local:
        return f"***@{domain}"

    return f"{local[0]}***@{domain}"
    
    
