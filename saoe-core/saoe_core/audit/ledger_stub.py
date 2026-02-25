"""Append-only ledger stub for future distributed ledger integration.

In the MVP this writes JSON lines to a local file and returns a pseudo-hash.
The interface matches what a real distributed ledger would expose so the
production implementation can be substituted without changing callers.

Production gap: replace with a real DLT transaction (e.g., Merkle-linked
append-only log or a blockchain anchor). See docs/production_gaps.md.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class LedgerStub:
    """Append-only local ledger that mimics a distributed ledger interface.

    Parameters
    ----------
    log_path:
        Path to the JSONL file where records are appended.
        Created if it does not exist.
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._log_path.exists():
            self._log_path.touch()

    def append(self, record: dict[str, Any]) -> str:
        """Append *record* to the ledger and return a pseudo-hash.

        Parameters
        ----------
        record:
            Arbitrary dict to record.  A ``_ledger_ts`` field is added.

        Returns
        -------
        str
            Hex SHA-256 of the serialised record line (pseudo transaction ID).
            In production this would be a DLT transaction ID.

        TODO (production):
            - Replace file append with a real ledger transaction.
            - Chain hashes (each record includes hash of previous).
            - Add cryptographic timestamp from a trusted time authority.
        """
        enriched = dict(record)
        enriched["_ledger_ts"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(enriched, sort_keys=True, separators=(",", ":")) + "\n"
        line_bytes = line.encode("utf-8")

        with self._log_path.open("ab") as f:
            f.write(line_bytes)

        return hashlib.sha256(line_bytes).hexdigest()
