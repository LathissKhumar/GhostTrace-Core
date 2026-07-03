"""Zeek conn.log parser.

Parses Zeek/Bro tab-separated network connection logs into
GhostTrace ``network_logs`` artifacts.  Handles the standard
Zeek header with ``#separator``, ``#fields``, and ``#types`` lines.
"""

import time
from datetime import datetime, timezone
from typing import Any

from parsers.base import BaseParser


# Standard Zeek conn.log field names (after the separator line)
_ZEEK_CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "history",
    "orig_pkts", "resp_pkts", "tunnel_parents",
]

# Mapping from Zeek proto/service → human-readable protocol
_PROTO_MAP: dict[str, str] = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
}


class ZeekParser(BaseParser):
    """Parse Zeek conn.log tab-separated files into network_logs artifacts."""

    format_name = "zeek"

    def can_parse(self, content: bytes, filename: str) -> bool:
        """Detect Zeek conn.log by extension or header sniffing."""
        lower = filename.lower()
        if "zeek" in lower or "conn" in lower and lower.endswith(".log"):
            return True

        # Content sniffing: look for Zeek header markers
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return False

        first_lines = text.split("\n")[:10]
        has_separator = any("#separator" in line for line in first_lines)
        has_fields = any("#fields" in line and "id.orig_h" in line for line in first_lines)
        return has_separator and has_fields

    def parse(self, content: bytes, filename: str) -> dict:
        """Parse Zeek conn.log into GhostTrace evidence format."""
        evidence = self._make_empty_evidence(filename)

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return evidence

        lines = text.split("\n")
        if not lines:
            return evidence

        # Parse header lines to discover the field separator and field list
        separator = "\t"
        fields: list[str] = []
        data_start = 0

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("#separator"):
                # Format: #separator \x09
                sep_part = stripped.split(" ", 1)
                if len(sep_part) > 1:
                    raw = sep_part[1].strip()
                    if raw.startswith("\\x"):
                        try:
                            separator = chr(int(raw[2:], 16))
                        except ValueError:
                            separator = "\t"
                    else:
                        separator = raw
                data_start = idx + 1
                continue

            if stripped.startswith("#fields"):
                fields = stripped.split(separator)[1:]
                fields = [f.strip() for f in fields]
                data_start = idx + 1
                continue

            if stripped.startswith("#") or stripped.startswith("#set_separator"):
                data_start = idx + 1
                continue

            # First non-comment, non-header line is data
            break

        if not fields:
            fields = list(_ZEEK_CONN_FIELDS)

        # Parse data lines
        network_logs: list[dict[str, Any]] = []

        for line in lines[data_start:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split(separator)
            if len(parts) < 6:
                continue

            row: dict[str, str] = {}
            for i, field_name in enumerate(fields):
                if i < len(parts):
                    row[field_name] = parts[i]
                else:
                    row[field_name] = ""

            artifact = self._map_zeek_row(row)
            if artifact:
                network_logs.append(artifact)

        evidence["artifacts"]["network_logs"] = network_logs
        evidence["metadata"] = self._make_metadata(
            filename, self.format_name, len(network_logs),
        )
        return evidence

    def _map_zeek_row(self, row: dict[str, str]) -> dict[str, Any] | None:
        """Map a Zeek conn.log row to a GhostTrace network_logs artifact."""
        try:
            timestamp = self._zeek_ts_to_iso(row.get("ts", ""))
            src_ip = row.get("id.orig_h", "")
            dst_ip = row.get("id.resp_h", "")

            if not src_ip or not dst_ip:
                return None

            src_port = self._safe_int(row.get("id.orig_p", "0"))
            dst_port = self._safe_int(row.get("id.resp_p", "0"))

            proto_raw = row.get("proto", "").lower()
            service = row.get("service", "")
            protocol = _PROTO_MAP.get(proto_raw, service.upper() if service else proto_raw.upper())

            orig_bytes = self._safe_int(row.get("orig_bytes", "0"))
            resp_bytes = self._safe_int(row.get("resp_bytes", "0"))

            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes_sent": orig_bytes,
                "bytes_received": resp_bytes,
                "domain": "",
            }
        except Exception:
            return None

    @staticmethod
    def _zeek_ts_to_iso(ts_str: str) -> str:
        """Convert Zeek epoch float timestamp to ISO 8601 string."""
        if not ts_str:
            return ""
        try:
            epoch = float(ts_str)
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            return ts_str

    @staticmethod
    def _safe_int(value: str, default: int = 0) -> int:
        """Safely convert a string to int."""
        if not value:
            return default
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return default
