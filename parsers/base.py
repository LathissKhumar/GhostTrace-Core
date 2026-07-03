"""Abstract base class for all GhostTrace evidence parsers.

Every parser must subclass BaseParser and implement parse() and can_parse().
The base class provides shared utilities for case ID generation and metadata.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any
import uuid


class BaseParser(ABC):
    """Abstract base for all evidence parsers.

    Subclasses must set ``format_name`` and implement ``parse`` / ``can_parse``.
    """

    format_name: str = "unknown"

    @abstractmethod
    def parse(self, content: bytes, filename: str) -> dict:
        """Parse raw file content into GhostTrace evidence format.

        Args:
            content: Raw file bytes.
            filename: Original filename (used for metadata and format detection).

        Returns:
            A dict matching the GhostTrace evidence schema.
        """
        ...

    @abstractmethod
    def can_parse(self, content: bytes, filename: str) -> bool:
        """Return True if this parser can handle the given file.

        Implementations should check both the file extension AND content sniffing
        for robust detection.
        """
        ...

    def _make_case_id(self) -> str:
        """Generate a PARSED-{hex} case identifier."""
        return f"PARSED-{uuid.uuid4().hex[:8].upper()}"

    def _make_metadata(self, filename: str, format_name: str, record_count: int) -> dict:
        """Build the metadata dict for the evidence output."""
        return {
            "filename": filename,
            "format": format_name,
            "record_count": record_count,
            "parsed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _make_empty_evidence(self, filename: str, record_count: int = 0) -> dict:
        """Return a fully-formed but empty evidence dict."""
        return {
            "case_id": self._make_case_id(),
            "incident_type": f"parsed_{self.format_name}_evidence",
            "artifacts": {
                "process_tree": [],
                "network_logs": [],
                "file_events": [],
                "registry_changes": [],
                "auth_logs": [],
            },
            "parser": self.format_name,
            "metadata": self._make_metadata(filename, self.format_name, record_count),
        }
