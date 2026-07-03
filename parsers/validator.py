"""Evidence validation against the GhostTrace schema.

Provides ``validate_evidence`` for checking parsed output and
``list_supported_formats`` for documenting supported input types.
"""

from typing import Any


def validate_evidence(data: dict | None) -> tuple[bool, list[str]]:
    """Validate evidence dict against the GhostTrace schema.

    Args:
        data: The evidence dict to validate (typically from a parser).

    Returns:
        A tuple of (is_valid, list_of_error_messages).
    """
    errors: list[str] = []

    # Must be a dict
    if not isinstance(data, dict):
        return False, ["Evidence must be a JSON object"]

    # Must have artifacts key
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("Missing or invalid 'artifacts' object")
        return False, errors

    valid_types = ["process_tree", "network_logs", "file_events", "registry_changes", "auth_logs"]

    # Check case_id exists
    case_id = data.get("case_id")
    if not isinstance(case_id, str) or not case_id:
        errors.append("Missing or invalid 'case_id' string")

    # Check parser field
    parser = data.get("parser")
    if not isinstance(parser, str) or not parser:
        errors.append("Missing or invalid 'parser' string")

    # Check metadata field
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("Missing or invalid 'metadata' object")

    # At least one artifact type must have data
    has_data = False
    for atype in valid_types:
        items = artifacts.get(atype, [])
        if isinstance(items, list) and len(items) > 0:
            has_data = True
            # Validate each item is a dict
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    errors.append(f"artifacts.{atype}[{i}] must be a dict")
                elif not item:
                    errors.append(f"artifacts.{atype}[{i}] is empty")
        elif atype in artifacts and not isinstance(items, list):
            errors.append(f"artifacts.{atype} must be a list")

    if not has_data:
        errors.append("At least one artifact type must contain data")

    return len(errors) == 0, errors


def list_supported_formats() -> list[dict[str, str]]:
    """Return metadata about all supported input formats.

    Returns:
        A list of dicts, each with ``ext``, ``name``, and ``description`` keys.
    """
    return [
        {
            "ext": ".csv",
            "name": "CSV",
            "description": "Comma-separated values with security log columns",
        },
        {
            "ext": ".log",
            "name": "Zeek conn.log",
            "description": "Zeek/Bro network traffic logs",
        },
        {
            "ext": ".json",
            "name": "Sysmon JSON",
            "description": "Sysmon JSON event logs",
        },
        {
            "ext": ".txt",
            "name": "System Log",
            "description": "Generic syslog/auth log text files",
        },
    ]
