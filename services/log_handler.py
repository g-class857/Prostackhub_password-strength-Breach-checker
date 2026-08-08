"""
Security Log Handler

Processes newly appended security.log entries and converts
security-relevant log messages into normalized security events.

Pipeline:

    security.log
        ↓
    parse_log_line()
        ↓
    classify_log_message()
        ↓
    normalize_security_event()
        ↓
    store_security_event()
        ↓
    security_events.json

Security requirements:
- Never store passwords.
- Never store HIBP API keys.
- Never store raw sensitive credentials.
- Do not modify security.log.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional


# ============================================================
# Project Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_FILE = PROJECT_ROOT / "logs" / "security.log"

EVENTS_FILE = PROJECT_ROOT / "logs" / "security_events.json"

MAX_STORED_EVENTS = 1000


# ============================================================
# Event Definitions
# ============================================================

EVENT_DEFINITIONS = {

    "password_breach": {
        "severity": "HIGH",
        "description": (
            "Password found in known breach database."
        ),
    },

    "email_breach": {
        "severity": "HIGH",
        "description": (
            "Email address found in known data breaches."
        ),
    },

    "api_error": {
        "severity": "WARNING",
        "description": (
            "External API error detected."
        ),
    },

    "password_analysis": {
        "severity": "INFO",
        "description": (
            "Password analysis performed."
        ),
    },

    "password_generated": {
        "severity": "INFO",
        "description": (
            "Password generated."
        ),
    },

    "email_check": {
        "severity": "INFO",
        "description": (
            "Email breach lookup performed."
        ),
    },

    "generator_error": {
        "severity": "ERROR",
        "description": (
            "Password generator error detected."
        ),
    },
}


# ============================================================
# Event Classification
# ============================================================

def classify_log_message(
    message: str,
) -> Optional[str]:

    message_lower = message.lower()

    # High severity events

    if "password found in breach database" in message_lower:
        return "password_breach"

    if "email breach detected" in message_lower:
        return "email_breach"

    # API events

    if "external api error" in message_lower:
        return "api_error"

    # Generator events

    if "password generation error" in message_lower:
        return "generator_error"

    if "password generated" in message_lower:
        return "password_generated"

    # Analysis events

    if "password analyzed" in message_lower:
        return "password_analysis"

    if "email breach check performed" in message_lower:
        return "email_check"

    return None


# ============================================================
# Log Parser
# ============================================================

def parse_log_line(
    line: str,
) -> Optional[dict]:

    line = line.strip()

    if not line:
        return None

    parts = line.split(" | ", 3)

    if len(parts) != 4:
        return None

    timestamp, level, logger_name, message = parts

    event_type = classify_log_message(message)

    if event_type is None:
        return None

    definition = EVENT_DEFINITIONS[event_type]

    return {
        "timestamp": timestamp,
        "level": level,
        "logger": logger_name,
        "message": message,
        "event_type": event_type,
        "severity": definition["severity"],
        "description": definition["description"],
    }


# ============================================================
# Event Normalization
# ============================================================

def normalize_security_event(
    event: dict,
) -> dict:
    """
    Convert a parsed log event into the application's
    standardized security-event structure.
    """

    return {
        "id": str(uuid.uuid4()),
        "timestamp": event["timestamp"],
        "severity": event["severity"],
        "event_type": event["event_type"],
        "description": event["description"],
        "source": event["logger"],
        "level": event["level"],
        "message": event["message"],
    }


# ============================================================
# Event Storage
# ============================================================

def load_security_events() -> list[dict]:
    """
    Load previously stored security events.

    Returns an empty list if the file does not exist or
    contains invalid JSON.
    """

    if not EVENTS_FILE.exists():
        return []

    try:

        with EVENTS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):
            return []

        return data

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return []


def store_security_event(
    event: dict,
) -> None:
    """
    Persist a normalized security event.

    Only the most recent MAX_STORED_EVENTS events are kept.
    """

    EVENTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    events = load_security_events()

    events.append(event)

    events = events[-MAX_STORED_EVENTS:]

    temporary_file = EVENTS_FILE.with_suffix(
        ".tmp"
    )

    try:

        with temporary_file.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                events,
                file,
                indent=2,
                ensure_ascii=False,
            )

            file.write("\n")

        temporary_file.replace(
            EVENTS_FILE
        )

    except OSError as exc:

        print(
            f"[SECURITY EVENTS] "
            f"Failed to store event: {exc}"
        )

        if temporary_file.exists():

            try:
                temporary_file.unlink()
            except OSError:
                pass


# ============================================================
# Security Event Processor
# ============================================================

def handle_security_event(
    event: dict,
) -> dict:
    """
    Normalize, persist and display a security event.
    """

    normalized_event = normalize_security_event(
        event
    )

    store_security_event(
        normalized_event
    )

    print("\n" + "=" * 70)

    print("SECURITY EVENT DETECTED")

    print("=" * 70)

    print(
        f"ID         : "
        f"{normalized_event['id']}"
    )

    print(
        f"Time       : "
        f"{normalized_event['timestamp']}"
    )

    print(
        f"Severity   : "
        f"{normalized_event['severity']}"
    )

    print(
        f"Type       : "
        f"{normalized_event['event_type']}"
    )

    print(
        f"Description: "
        f"{normalized_event['description']}"
    )

    print(
        f"Source     : "
        f"{normalized_event['source']}"
    )

    print("=" * 70)

    return normalized_event


# ============================================================
# Process New Log Lines
# ============================================================

def process_new_lines(
    lines: list[str],
) -> list[dict]:
    """
    Process newly appended log lines.
    """

    events = []

    for line in lines:

        event = parse_log_line(line)

        if event is None:
            continue

        processed_event = handle_security_event(
            event
        )

        events.append(
            processed_event
        )

    return events


# ============================================================
# Log Reader
# ============================================================

class SecurityLogReader:
    """
    Tracks the current read position in security.log.

    This prevents Watchdog from repeatedly processing
    historical log entries.
    """

    def __init__(
        self,
        log_file: Path = LOG_FILE,
    ):

        self.log_file = Path(log_file)

        self.position = 0

    def initialize(self) -> None:
        """
        Start monitoring from the current end of the file.
        """

        if not self.log_file.exists():

            self.position = 0

            return

        self.position = (
            self.log_file.stat().st_size
        )

    def read_new_lines(self) -> list[str]:
        """
        Read only data appended since the last read.
        """

        if not self.log_file.exists():

            return []

        current_size = (
            self.log_file.stat().st_size
        )

        # Handle log rotation/truncation.

        if current_size < self.position:

            self.position = 0

        if current_size == self.position:

            return []

        with self.log_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            file.seek(self.position)

            data = file.read()

            self.position = file.tell()

        return data.splitlines()
