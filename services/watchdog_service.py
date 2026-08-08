"""
Watchdog Security Log Monitoring Service.

Monitors logs/security.log for newly appended security events
and passes them to the security log handler.

Usage:
    python services/watchdog_service.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# ============================================================
# Project Root
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "security.log"


# Make project modules importable when this file is executed as:
#
#     python services/watchdog_service.py
#
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from services.log_handler import SecurityLogReader, process_new_lines


# ============================================================
# Watchdog Event Handler
# ============================================================

class SecurityLogHandler(FileSystemEventHandler):
    """
    Handles filesystem changes to security.log.
    """

    def __init__(self, log_file: Path):
        super().__init__()

        self.log_file = Path(log_file)

        self.reader = SecurityLogReader(
            self.log_file
        )

        # Ignore existing historical entries.
        self.reader.initialize()

    # --------------------------------------------------------
    # File Modified
    # --------------------------------------------------------

    def on_modified(self, event):
        """
        Called by Watchdog when a monitored file changes.
        """

        if event.is_directory:
            return

        changed_path = Path(event.src_path).resolve()

        if changed_path != self.log_file.resolve():
            return

        self.process_changes()

    # --------------------------------------------------------
    # File Created
    # --------------------------------------------------------

    def on_created(self, event):
        """
        Handle creation/recreation of security.log.

        This can happen after log rotation or if the log
        directory is recreated.
        """

        if event.is_directory:
            return

        changed_path = Path(event.src_path).resolve()

        if changed_path != self.log_file.resolve():
            return

        print(
            f"[WATCHDOG] Log file created: {self.log_file}"
        )

        self.reader.position = 0

        self.process_changes()

    # --------------------------------------------------------
    # Process Changes
    # --------------------------------------------------------

    def process_changes(self):
        """
        Read only newly appended log lines.
        """

        try:

            new_lines = self.reader.read_new_lines()

            if not new_lines:
                return

            process_new_lines(new_lines)

        except Exception as exc:

            print(
                "[WATCHDOG] Error processing log:",
                exc,
            )


# ============================================================
# Watchdog Service
# ============================================================

def start_watchdog():
    """
    Start the Watchdog observer.
    """

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 70)
    print("PASSWORD SECURITY WATCHDOG")
    print("=" * 70)

    print(
        f"Project root : {PROJECT_ROOT}"
    )

    print(
        f"Monitoring   : {LOG_FILE}"
    )

    print(
        "Status       : ACTIVE"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print("=" * 70)

    event_handler = SecurityLogHandler(
        LOG_FILE
    )

    observer = Observer()

    observer.schedule(
        event_handler,
        str(LOG_DIR),
        recursive=False,
    )

    observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\n[WATCHDOG] Shutdown requested."
        )

        observer.stop()

    finally:

        observer.join()

        print(
            "[WATCHDOG] Stopped."
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    start_watchdog()
