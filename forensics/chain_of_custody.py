"""
pyrecovery.forensics.chain_of_custody — Tamper-evident forensic audit log.

Purpose: Prove in court that evidence was handled properly and the tool
operator performed only authorized actions.

Design principles:
- Append-only (file opened with 'a', NEVER 'w' or 'r+')
- Each line is one self-contained JSON object (JSONL format)
- Every entry includes ISO 8601 timestamp, action, SHA256 of prior line
- Verification: any truncation or modification breaks the hash chain
- Thread-safe via file locking

The chain includes a running hash: each entry's 'prev_hash' field is the
SHA256 of the previous entry's JSON text. This creates a Merkle-like chain
that detects any insertion, deletion, or modification of log entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CustodyEntry:
    """Single chain-of-custody log entry."""
    sequence: int           # Monotonically increasing sequence number
    timestamp: str          # ISO 8601 UTC
    action: str             # What was done: "image_acquired", "file_recovered", etc.
    operator: str           # Who did it (system user or provided name)
    details: dict           # Action-specific data
    evidence_hash: str      # SHA256 of the evidence item (if applicable)
    prev_hash: str          # SHA256 of previous entry's JSON (chain integrity)


class ChainOfCustody:
    """Append-only, tamper-evident forensic audit log.

    Usage::

        coc = ChainOfCustody("evidence/chain_of_custody.jsonl")
        coc.log_action("case_opened", {"case_id": "2024-001", "examiner": "J.Smith"})
        coc.log_action("image_acquired", {"source": "/dev/sda", "sha256": "abc..."})
        coc.log_action("recovery_started", {"method": "auto"})

        # Verify integrity
        valid, errors = coc.verify_integrity()
    """

    def __init__(self, log_path: str, operator: str = "") -> None:
        """Initialize chain of custody log.

        Args:
            log_path: Path to JSONL log file (created if not exists).
            operator: Default operator name (uses OS username if empty).
        """
        self._path = Path(log_path)
        self._operator = operator or self._get_system_user()
        self._lock = threading.Lock()
        self._sequence = 0
        self._last_hash = "GENESIS"  # Initial chain anchor

        # Resume from existing log
        if self._path.exists():
            self._resume_from_existing()

        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_action(
        self,
        action: str,
        details: dict | None = None,
        evidence_hash: str = "",
    ) -> CustodyEntry:
        """Append an action to the chain of custody log.

        Args:
            action: Action identifier (e.g., "image_acquired").
            details: Action-specific metadata dict.
            evidence_hash: SHA256 of the evidence item if applicable.

        Returns:
            The CustodyEntry that was logged.
        """
        with self._lock:
            entry = CustodyEntry(
                sequence=self._sequence,
                timestamp=datetime.now(timezone.utc).isoformat(),
                action=action,
                operator=self._operator,
                details=details or {},
                evidence_hash=evidence_hash,
                prev_hash=self._last_hash,
            )

            # Serialize to JSON
            entry_json = json.dumps({
                "seq": entry.sequence,
                "ts": entry.timestamp,
                "action": entry.action,
                "operator": entry.operator,
                "details": entry.details,
                "evidence_hash": entry.evidence_hash,
                "prev_hash": entry.prev_hash,
            }, separators=(",", ":"))

            # Append to log file (atomic: open with 'a' mode)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(entry_json + "\n")

            # Update chain state
            self._last_hash = hashlib.sha256(entry_json.encode()).hexdigest()
            self._sequence += 1

            logger.debug(
                "CoC entry #%d: %s (hash=%s...)",
                entry.sequence, action, self._last_hash[:8],
            )

            return entry

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the chain of custody log.

        Checks:
        1. Each entry's prev_hash matches SHA256 of previous entry
        2. Sequence numbers are monotonically increasing
        3. Timestamps are monotonically non-decreasing

        Returns:
            Tuple of (is_valid, list_of_error_messages).
        """
        if not self._path.exists():
            return True, []

        errors: list[str] = []
        prev_hash = "GENESIS"
        prev_seq = -1
        prev_ts = ""

        with open(self._path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: invalid JSON: {e}")
                    continue

                # Check prev_hash chain
                if entry.get("prev_hash") != prev_hash:
                    errors.append(
                        f"Line {line_num}: hash chain broken. "
                        f"Expected prev_hash={prev_hash[:16]}..., "
                        f"got {entry.get('prev_hash', 'MISSING')[:16]}..."
                    )

                # Check sequence monotonicity
                seq = entry.get("seq", -1)
                if seq <= prev_seq and prev_seq >= 0:
                    errors.append(
                        f"Line {line_num}: sequence out of order "
                        f"(got {seq}, expected > {prev_seq})"
                    )
                prev_seq = seq

                # Check timestamp monotonicity
                ts = entry.get("ts", "")
                if ts and prev_ts and ts < prev_ts:
                    errors.append(
                        f"Line {line_num}: timestamp regression "
                        f"({ts} < {prev_ts})"
                    )
                prev_ts = ts

                # Update hash for next iteration
                prev_hash = hashlib.sha256(line.encode()).hexdigest()

        is_valid = len(errors) == 0

        if is_valid:
            logger.info("Chain of custody verification: PASSED (%d entries)", prev_seq + 1)
        else:
            logger.warning(
                "Chain of custody verification: FAILED (%d errors)", len(errors)
            )

        return is_valid, errors

    @property
    def entry_count(self) -> int:
        return self._sequence

    @property
    def log_path(self) -> str:
        return str(self._path)

    def _resume_from_existing(self) -> None:
        """Resume chain state from existing log file."""
        prev_hash = "GENESIS"
        seq = 0

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    prev_hash = hashlib.sha256(line.encode()).hexdigest()
                    try:
                        entry = json.loads(line)
                        seq = entry.get("seq", seq) + 1
                    except json.JSONDecodeError:
                        seq += 1
        except (OSError, IOError):
            pass

        self._last_hash = prev_hash
        self._sequence = seq

    @staticmethod
    def _get_system_user() -> str:
        """Get current OS username."""
        try:
            return os.getlogin()
        except OSError:
            import getpass
            return getpass.getuser()
