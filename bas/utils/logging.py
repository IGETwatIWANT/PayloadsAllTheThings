"""
Audit logging for BAS Engine.

Every operation is logged for compliance and forensic review.
Logs are tamper-evident with chained hashes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """
    Tamper-evident audit logger for BAS engagements.

    Every entry includes a hash of the previous entry, creating a
    chain that makes it detectable if logs are modified after the fact.
    """

    def __init__(
        self,
        engagement_id: str,
        log_dir: Path | None = None,
        console_output: bool = True,
    ):
        self._engagement_id = engagement_id
        self._log_dir = log_dir or Path("./bas_logs")
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / f"{engagement_id}.audit.jsonl"
        self._prev_hash = "0" * 64
        self._sequence = 0

        # Python logger for console output
        self._logger = logging.getLogger(f"bas.audit.{engagement_id}")
        if console_output and not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] BAS %(levelname)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.DEBUG)

    def log(self, event_type: str, detail: dict[str, Any], level: str = "info") -> str:
        """
        Write a tamper-evident audit log entry.

        Returns the hash of this entry for chain verification.
        """
        self._sequence += 1
        entry = {
            "seq": self._sequence,
            "ts": datetime.now().isoformat(),
            "engagement_id": self._engagement_id,
            "event": event_type,
            "detail": detail,
            "prev_hash": self._prev_hash,
        }

        # Compute chain hash
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        entry["hash"] = entry_hash
        self._prev_hash = entry_hash

        # Write to file
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Console output
        log_fn = getattr(self._logger, level, self._logger.info)
        log_fn(f"[{event_type}] {json.dumps(detail)}")

        return entry_hash

    def verify_chain(self) -> tuple[bool, int]:
        """
        Verify the integrity of the audit log chain.

        Returns (is_valid, entries_checked).
        """
        if not self._log_file.exists():
            return True, 0

        prev_hash = "0" * 64
        count = 0

        with open(self._log_file) as f:
            for line in f:
                entry = json.loads(line.strip())
                stored_hash = entry.pop("hash")

                if entry["prev_hash"] != prev_hash:
                    return False, count

                entry_bytes = json.dumps(entry, sort_keys=True).encode()
                computed_hash = hashlib.sha256(entry_bytes).hexdigest()

                if computed_hash != stored_hash:
                    return False, count

                prev_hash = stored_hash
                count += 1

        return True, count
