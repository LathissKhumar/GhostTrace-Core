"""MCP tool for querying forensic evidence artifacts.

Provides structured access to evidence artifacts by type, with optional
time-range filtering and result limiting. Returns JSON strings suitable
for consumption by AI agents in the debate pipeline.
"""

import json

from . import server as _server
from .server import VALID_ARTIFACT_TYPES


def query_evidence(
    artifact_type: str,
    time_range_start: str | None = None,
    limit: int = 50,
) -> str:
    """Query evidence artifacts by type and optional time range.

    Retrieves forensic artifacts from the loaded evidence bundle,
    filtered by artifact type and optionally by a start timestamp.
    Results are limited to avoid overwhelming agent context windows.

    Args:
        artifact_type: The category of artifact to query. Must be one of:
            process_tree, network_logs, file_events, registry_changes,
            auth_logs.
        time_range_start: Optional ISO 8601 timestamp string. When provided,
            only artifacts with a timestamp >= this value are returned.
            Uses string comparison (ISO 8601 strings sort lexicographically).
        limit: Maximum number of artifacts to return. Defaults to 50.

    Returns:
        JSON string containing an array of matching artifact dicts,
        or a JSON error string if the artifact_type is invalid.
    """
    # Validate artifact type
    if artifact_type not in VALID_ARTIFACT_TYPES:
        return json.dumps({
            "error": f"Invalid artifact type: '{artifact_type}'. "
                     f"Valid types are: {VALID_ARTIFACT_TYPES}"
        })

    # Access the artifacts from the evidence store (use module reference
    # to always get the current state after load_evidence is called)
    artifacts = _server._evidence_store.get("artifacts", {})
    items = artifacts.get(artifact_type, [])

    # If no evidence loaded or artifact_type key doesn't exist, return empty array
    if not items:
        return json.dumps([])

    # Filter by time_range_start if provided (ISO 8601 string comparison)
    if time_range_start is not None:
        items = [
            artifact for artifact in items
            if artifact.get("timestamp", "") >= time_range_start
        ]

    # Apply limit
    items = items[:limit]

    return json.dumps(items)
