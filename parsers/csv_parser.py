"""Generic CSV evidence parser.

Detects CSV files by extension or content sniffing, then maps column names
to the appropriate GhostTrace artifact types (process_tree, network_logs,
file_events, registry_changes, auth_logs).
"""

import csv
import io
from typing import Any

from parsers.base import BaseParser


# Column-name → artifact-type mapping keywords
_COLUMN_MAP: dict[str, list[str]] = {
    "process_tree": ["process", "pid", "cmd", "command_line", "parent_pid", "process_name"],
    "network_logs": ["src", "dst", "port", "bytes", "protocol", "src_ip", "dst_ip", "network"],
    "file_events": ["file", "path", "hash", "action"],
    "registry_changes": ["registry", "key", "value"],
    "auth_logs": ["auth", "logon", "event_id", "status", "user", "logon_type"],
}


class CSVParser(BaseParser):
    """Parse comma-separated values into GhostTrace evidence artifacts.

    Automatically maps columns to the correct artifact type based on
    header name heuristics.
    """

    format_name = "csv"

    def can_parse(self, content: bytes, filename: str) -> bool:
        """Detect CSV files by extension or comma-separated content."""
        if filename.lower().endswith(".csv"):
            return True

        # Content sniffing: check first non-empty line for commas
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return False

        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            return False

        first_line = lines[0]
        return "," in first_line and first_line.count(",") >= 2

    def parse(self, content: bytes, filename: str) -> dict:
        """Parse CSV content and route rows to appropriate artifact types."""
        evidence = self._make_empty_evidence(filename)

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return evidence

        reader = csv.reader(io.StringIO(text))
        rows = list(reader)

        if not rows:
            return evidence

        # Detect header row: first row where all cells are non-numeric strings
        headers: list[str] | None = None
        data_rows: list[list[str]] = rows

        first_row = rows[0]
        if all(cell.isalpha() or "_" in cell or " " in cell for cell in first_row if cell.strip()):
            headers = [h.strip().lower().replace(" ", "_") for h in first_row]
            data_rows = rows[1:]

        if not data_rows:
            return evidence

        # If no headers detected, try to infer from first data row
        if headers is None:
            headers = [f"col_{i}" for i in range(len(data_rows[0]))]

        # Determine which artifact types this CSV maps to
        artifact_buckets: dict[str, list[dict[str, Any]]] = {
            "process_tree": [],
            "network_logs": [],
            "file_events": [],
            "registry_changes": [],
            "auth_logs": [],
        }

        # Map each header to an artifact type
        column_mapping: dict[int, str] = {}
        for idx, header in enumerate(headers):
            for artifact_type, keywords in _COLUMN_MAP.items():
                if any(kw in header for kw in keywords):
                    column_mapping[idx] = artifact_type
                    break

        # If no columns matched any artifact type, try auth_logs as fallback
        # for simple 2-3 column CSVs (user, action, etc.)
        if not column_mapping and len(headers) <= 5:
            for idx, header in enumerate(headers):
                if any(kw in header for kw in ["user", "name", "id"]):
                    column_mapping[idx] = "auth_logs"

        # Parse each row
        for row in data_rows:
            if not row or all(not cell.strip() for cell in row):
                continue

            # Build a dict from header → value
            row_dict = {}
            for idx, value in enumerate(row):
                if idx < len(headers):
                    row_dict[headers[idx]] = value.strip()

            # Route to appropriate artifact type based on detected columns
            mapped_types: set[str] = set()
            for idx, artifact_type in column_mapping.items():
                if idx < len(row):
                    mapped_types.add(artifact_type)

            if not mapped_types:
                # Default to auth_logs for unclassified CSVs
                mapped_types = {"auth_logs"}

            for artifact_type in mapped_types:
                artifact = self._map_row_to_artifact(row_dict, artifact_type)
                if artifact:
                    artifact_buckets[artifact_type].append(artifact)

        evidence["artifacts"] = artifact_buckets
        evidence["metadata"] = self._make_metadata(
            filename,
            self.format_name,
            sum(len(v) for v in artifact_buckets.values()),
        )
        return evidence

    def _map_row_to_artifact(self, row: dict[str, str], artifact_type: str) -> dict[str, Any] | None:
        """Map a CSV row dict to a single artifact dict of the given type."""
        try:
            if artifact_type == "auth_logs":
                return self._to_auth_log(row)
            elif artifact_type == "process_tree":
                return self._to_process_tree(row)
            elif artifact_type == "network_logs":
                return self._to_network_log(row)
            elif artifact_type == "file_events":
                return self._to_file_event(row)
            elif artifact_type == "registry_changes":
                return self._to_registry_change(row)
        except Exception:
            return None
        return None

    def _get(self, row: dict[str, str], *keys: str) -> str:
        """Get first matching value from row by trying multiple key variants."""
        for key in keys:
            # Try exact match first
            if key in row:
                return row[key]
            # Try case-insensitive
            for row_key in row:
                if row_key.lower() == key.lower():
                    return row[row_key]
        return ""

    def _get_int(self, row: dict[str, str], *keys: str, default: int = 0) -> int:
        """Get first matching integer value from row."""
        val = self._get(row, *keys)
        if not val:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _to_auth_log(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Convert a row to an auth_logs artifact."""
        user = self._get(row, "user", "username", "account", "src_user")
        if not user:
            user = "unknown"

        return {
            "timestamp": self._get(row, "timestamp", "time", "datetime", "date"),
            "event_id": self._get(row, "event_id", "eventid", "event"),
            "user": user,
            "src_ip": self._get(row, "src_ip", "src", "source_ip", "ip", "source"),
            "logon_type": self._get(row, "logon_type", "logontype", "type"),
            "status": self._get(row, "status", "result", "outcome"),
        }

    def _to_process_tree(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Convert a row to a process_tree artifact."""
        return {
            "timestamp": self._get(row, "timestamp", "time", "datetime"),
            "pid": self._get_int(row, "pid", "process_id"),
            "parent_pid": self._get_int(row, "parent_pid", "ppid", "parent_process_id"),
            "process_name": self._get(row, "process_name", "process", "image", "name"),
            "command_line": self._get(row, "command_line", "cmd", "cmdline", "command"),
            "user": self._get(row, "user", "username"),
        }

    def _to_network_log(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Convert a row to a network_logs artifact."""
        return {
            "timestamp": self._get(row, "timestamp", "time", "datetime"),
            "src_ip": self._get(row, "src_ip", "src", "source_ip", "source"),
            "dst_ip": self._get(row, "dst_ip", "dst", "dest", "destination_ip", "destination"),
            "dst_port": self._get_int(row, "dst_port", "dport", "dest_port", "port"),
            "protocol": self._get(row, "protocol", "proto"),
            "bytes_sent": self._get_int(row, "bytes_sent", "sent", "orig_bytes"),
            "bytes_received": self._get_int(row, "bytes_received", "received", "resp_bytes"),
            "domain": self._get(row, "domain", "host", "query"),
        }

    def _to_file_event(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Convert a row to a file_events artifact."""
        return {
            "timestamp": self._get(row, "timestamp", "time", "datetime"),
            "action": self._get(row, "action", "event_type", "operation"),
            "path": self._get(row, "path", "file", "filename", "target_filename"),
            "hash": self._get(row, "hash", "hashes", "sha256", "md5"),
            "user": self._get(row, "user", "username"),
        }

    def _to_registry_change(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Convert a row to a registry_changes artifact."""
        return {
            "timestamp": self._get(row, "timestamp", "time", "datetime"),
            "action": self._get(row, "action", "event_type", "operation"),
            "key": self._get(row, "key", "registry_key", "target_object"),
            "value": self._get(row, "value", "details", "data"),
            "user": self._get(row, "user", "username"),
        }
