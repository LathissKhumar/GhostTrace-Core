"""Sysmon JSON event log parser.

Parses Sysmon event logs in JSON format (one JSON object per line
or a JSON array) and maps EventIDs to GhostTrace artifact types:

- EventID  1 → process_tree
- EventID  3 → network_logs
- EventID 11 → file_events
- EventID 12/13/14 → registry_changes
"""

import json
from typing import Any

from parsers.base import BaseParser


# Sysmon EventIDs that we map to artifact types
_PROCESS_EVENTIDS = {1}
_NETWORK_EVENTIDS = {3}
_FILE_EVENTIDS = {11}
_REGISTRY_EVENTIDS = {12, 13, 14}


class SysmonParser(BaseParser):
    """Parse Sysmon JSON event logs into GhostTrace evidence artifacts."""

    format_name = "sysmon"

    def can_parse(self, content: bytes, filename: str) -> bool:
        """Detect Sysmon JSON by extension or content sniffing."""
        lower = filename.lower()
        if lower.endswith(".json") and ("sysmon" in lower or "event" in lower):
            return True

        # Content sniffing: look for Sysmon JSON structure
        try:
            text = content.decode("utf-8", errors="replace").strip()
        except Exception:
            return False

        if not text:
            return False

        # Try parsing as JSON first
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                return isinstance(first, dict) and "EventID" in first
            elif isinstance(data, dict) and "EventID" in data:
                return True
        except (json.JSONDecodeError, ValueError):
            pass

        # Try line-delimited JSON
        first_line = text.split("\n", 1)[0].strip()
        try:
            obj = json.loads(first_line)
            return isinstance(obj, dict) and "EventID" in obj
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, content: bytes, filename: str) -> dict:
        """Parse Sysmon JSON events into GhostTrace evidence format."""
        evidence = self._make_empty_evidence(filename)

        try:
            text = content.decode("utf-8", errors="replace").strip()
        except Exception:
            return evidence

        if not text:
            return evidence

        # Parse events: try JSON array first, then line-delimited
        events: list[dict] = self._parse_events(text)

        if not events:
            return evidence

        # Route each event to the appropriate artifact type
        process_tree: list[dict[str, Any]] = []
        network_logs: list[dict[str, Any]] = []
        file_events: list[dict[str, Any]] = []
        registry_changes: list[dict[str, Any]] = []

        for event in events:
            event_id = self._safe_int(event.get("EventID", 0))

            if event_id in _PROCESS_EVENTIDS:
                artifact = self._to_process_tree(event)
                if artifact:
                    process_tree.append(artifact)

            elif event_id in _NETWORK_EVENTIDS:
                artifact = self._to_network_log(event)
                if artifact:
                    network_logs.append(artifact)

            elif event_id in _FILE_EVENTIDS:
                artifact = self._to_file_event(event)
                if artifact:
                    file_events.append(artifact)

            elif event_id in _REGISTRY_EVENTIDS:
                artifact = self._to_registry_change(event)
                if artifact:
                    registry_changes.append(artifact)

        evidence["artifacts"] = {
            "process_tree": process_tree,
            "network_logs": network_logs,
            "file_events": file_events,
            "registry_changes": registry_changes,
            "auth_logs": [],
        }

        total = len(process_tree) + len(network_logs) + len(file_events) + len(registry_changes)
        evidence["metadata"] = self._make_metadata(filename, self.format_name, total)
        return evidence

    def _parse_events(self, text: str) -> list[dict]:
        """Parse JSON array or line-delimited JSON into a list of event dicts."""
        # Try JSON array first
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            elif isinstance(data, dict):
                return [data]
        except (json.JSONDecodeError, ValueError):
            pass

        # Fall back to line-delimited JSON
        events: list[dict] = []
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    events.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue
        return events

    def _to_process_tree(self, event: dict) -> dict[str, Any] | None:
        """Map a Sysmon EventID 1 (Process Create) to process_tree artifact."""
        try:
            image = event.get("Image", "")
            if not image:
                return None

            process_name = image.rsplit("\\", 1)[-1] if "\\" in image else image

            return {
                "timestamp": event.get("UtcTime", ""),
                "pid": self._safe_int(event.get("ProcessId", "0")),
                "parent_pid": self._safe_int(event.get("ParentProcessId", "0")),
                "process_name": process_name,
                "command_line": event.get("CommandLine", ""),
                "user": event.get("User", ""),
            }
        except Exception:
            return None

    def _to_network_log(self, event: dict) -> dict[str, Any] | None:
        """Map a Sysmon EventID 3 (Network Connection) to network_logs artifact."""
        try:
            src_ip = event.get("SourceIp", "")
            dst_ip = event.get("DestinationIp", "")

            if not dst_ip:
                return None

            return {
                "timestamp": event.get("UtcTime", ""),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": self._safe_int(event.get("DestinationPort", "0")),
                "protocol": event.get("Protocol", ""),
                "bytes_sent": 0,
                "bytes_received": 0,
                "domain": event.get("DestinationHostname", ""),
            }
        except Exception:
            return None

    def _to_file_event(self, event: dict) -> dict[str, Any] | None:
        """Map a Sysmon EventID 11 (File Create) to file_events artifact."""
        try:
            target = event.get("TargetFilename", "")
            if not target:
                return None

            return {
                "timestamp": event.get("UtcTime", ""),
                "action": "create",
                "path": target,
                "hash": event.get("Hashes", ""),
                "user": event.get("User", ""),
            }
        except Exception:
            return None

    def _to_registry_change(self, event: dict) -> dict[str, Any] | None:
        """Map Sysmon EventID 12/13/14 (Registry) to registry_changes artifact."""
        try:
            target_object = event.get("TargetObject", "")
            if not target_object:
                return None

            event_id = self._safe_int(event.get("EventID", 0))
            action_map = {12: "Object added/deleted", 13: "Value set", 14: "Object renamed"}
            action = action_map.get(event_id, "registry_change")

            return {
                "timestamp": event.get("UtcTime", ""),
                "action": action,
                "key": target_object,
                "value": event.get("Details", ""),
                "user": event.get("User", ""),
            }
        except Exception:
            return None

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """Safely convert a value to int."""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
