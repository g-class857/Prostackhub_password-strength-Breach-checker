"""
Security Event Service

Provides read-only access to security_events.json.

Used by Flask routes and dashboard views so they do not need
to know how security events are stored.
"""

from __future__ import annotations

from pathlib import Path
import json


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENTS_FILE = PROJECT_ROOT / "logs" / "security_events.json"


# ============================================================
# Internal Loader
# ============================================================

def _load_events() -> list[dict]:
    """
    Load all stored security events.

    Returns an empty list when the file does not exist,
    is invalid, or does not contain a list.
    """

    if not EVENTS_FILE.exists():
        return []

    try:
        with EVENTS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            events = json.load(file)

        if not isinstance(events, list):
            return []

        return events

    except (
        json.JSONDecodeError,
        OSError,
    ):
        return []


# ============================================================
# Public API
# ============================================================

def get_events() -> list[dict]:
    """
    Return all stored security events.
    """

    return _load_events()


def get_recent_events(
    limit: int = 20,
) -> list[dict]:
    """
    Return the most recent security events.

    Events are returned newest first.
    """

    if limit <= 0:
        return []

    events = _load_events()

    return list(reversed(events[-limit:]))


def get_events_by_severity(
    severity: str,
) -> list[dict]:
    """
    Return events matching a severity.

    Example:

        get_events_by_severity("HIGH")
    """

    if not severity:
        return []

    severity = severity.upper()

    events = _load_events()

    return [
        event
        for event in events
        if str(
            event.get("severity", "")
        ).upper() == severity
    ]


def get_event_count() -> int:
    """
    Return the total number of stored events.
    """

    return len(_load_events())


def get_event_counts_by_severity() -> dict:
    """
    Return event counts grouped by severity.
    """

    events = _load_events()

    counts = {
        "HIGH": 0,
        "ERROR": 0,
        "WARNING": 0,
        "INFO": 0,
    }

    for event in events:

        severity = str(
            event.get("severity", "")
        ).upper()

        if severity in counts:
            counts[severity] += 1

    return counts
