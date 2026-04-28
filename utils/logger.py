"""
pyrecovery.utils.logger — Forensic-grade structured logging.

Design rationale:
- ISO 8601 timestamps with microsecond precision for forensic traceability
- Separate console (rich-formatted) and file (plain text, machine-parseable) handlers
- Forensic mode adds PID and thread name for multi-process scenarios
- File handler always uses append mode ('a') to prevent accidental log truncation

Usage:
    from utils.logger import setup_logging, get_logger
    setup_logging(level="DEBUG", log_file="session.log")
    logger = get_logger(__name__)
    logger.info("Opened disk image", extra={"source": "/dev/sda"})
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from rich.logging import RichHandler
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ISO 8601 format with microseconds and timezone
_FORENSIC_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)-30s | PID:%(process)d | %(message)s"
)
_STANDARD_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

# Track whether setup has been called to avoid duplicate handlers
_initialized = False


class _UTCFormatter(logging.Formatter):
    """Formatter that forces UTC timestamps with microsecond precision."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    forensic_mode: bool = False,
) -> None:
    """Configure the root logger for PyRecovery.

    Args:
        level: Logging level — "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL".
        log_file: Optional path for file-based logging (append mode).
        forensic_mode: If True, adds process ID and thread name to log format.
                       Recommended for actual forensic investigations.

    This function is idempotent — calling it multiple times updates the level
    but does not add duplicate handlers.
    """
    global _initialized

    root_logger = logging.getLogger()
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    if _initialized:
        # Just update level on subsequent calls
        root_logger.setLevel(numeric_level)
        return

    # Console handler — rich-formatted if available, else plain
    if HAS_RICH:
        console_handler = RichHandler(
            level=numeric_level,
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
        )
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        fmt = _FORENSIC_FORMAT if forensic_mode else _STANDARD_FORMAT
        console_handler.setFormatter(_UTCFormatter(fmt))

    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)

    # File handler — plain text, append-only, machine-parseable
    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(
            str(log_path),
            mode="a",       # Append-only: never truncate forensic logs
            encoding="utf-8",
        )
        fmt = _FORENSIC_FORMAT if forensic_mode else _STANDARD_FORMAT
        file_handler.setFormatter(_UTCFormatter(fmt))
        file_handler.setLevel(logging.DEBUG)  # File always captures everything
        root_logger.addHandler(file_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Convention: use ``__name__`` as the argument.

    Args:
        name: Logger name, typically the module's ``__name__``.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    return logging.getLogger(name)
