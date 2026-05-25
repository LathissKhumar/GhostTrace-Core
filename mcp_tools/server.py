"""GhostTrace Evidence Tools.

This module provides evidence query and scoring tools used internally by the
GhostTrace agents. It manages the in-memory evidence store and exposes functions
for querying artifacts, looking up MITRE techniques, and scoring claims.

No external MCP server dependency required — these are plain Python functions.
"""

import json

# Module-level in-memory evidence storage
_evidence_store: dict = {}

# Valid artifact types recognized by the system
VALID_ARTIFACT_TYPES = [
    "process_tree",
    "network_logs",
    "file_events",
    "registry_changes",
    "auth_logs",
]

# Base confidence scores for each artifact type
BASE_SCORES: dict[str, int] = {
    "process_tree": 85,
    "network_logs": 70,
    "registry_changes": 80,
    "file_events": 75,
    "auth_logs": 65,
}


def load_evidence(evidence_json: dict) -> None:
    """Load evidence into the MCP server's in-memory store.

    This is NOT an MCP tool. It is called by the backend when evidence
    is uploaded, making it available to MCP tool queries.

    Args:
        evidence_json: A dictionary containing the full evidence bundle,
            typically with 'case_id', 'incident_type', and 'artifacts' keys.
    """
    global _evidence_store
    _evidence_store = evidence_json


def score_evidence_claim(
    claim: str,
    cited_artifact_type: str,
    artifact_count: int,
) -> str:
    """Score a claim's confidence based on the cited evidence type and artifact count.

    Computes a confidence score using base scores per artifact type, adjusted
    by the number of supporting artifacts. Higher artifact counts increase
    confidence, while zero artifacts significantly reduce it.

    Scoring formula:
        - Start with base score for the artifact type
        - Add +10 if artifact_count > 2
        - Subtract -20 if artifact_count == 0
        - Clamp final score to [0, 100]

    Args:
        claim: The claim text to score (maximum 1000 characters).
        cited_artifact_type: The type of artifact cited as evidence.
            Must be one of: process_tree, network_logs, file_events,
            registry_changes, auth_logs.
        artifact_count: The number of artifacts supporting the claim (>= 0).

    Returns:
        A JSON string containing either:
        - {"score": int, "rationale": str} on success
        - {"error": str} with valid types listed if cited_artifact_type is invalid
    """
    # Validate cited_artifact_type
    if cited_artifact_type not in VALID_ARTIFACT_TYPES:
        return json.dumps({
            "error": (
                f"Invalid artifact type: '{cited_artifact_type}'. "
                f"Valid types are: {VALID_ARTIFACT_TYPES}"
            ),
            "valid_types": VALID_ARTIFACT_TYPES,
        })

    # Truncate claim to max 1000 characters for processing
    claim_text = claim[:1000]

    # Calculate score using base + adjustments
    base = BASE_SCORES[cited_artifact_type]

    if artifact_count > 2:
        adjustment = 10
        adjustment_rationale = (
            f"artifact_count ({artifact_count}) > 2: +10 for strong corroboration"
        )
    elif artifact_count == 0:
        adjustment = -20
        adjustment_rationale = "artifact_count is 0: -20 for no supporting artifacts"
    else:
        adjustment = 0
        adjustment_rationale = (
            f"artifact_count ({artifact_count}) between 1-2: no adjustment"
        )

    # Clamp to [0, 100]
    score = max(0, min(100, base + adjustment))

    rationale = (
        f"Base score for {cited_artifact_type}: {base}. "
        f"{adjustment_rationale}. "
        f"Final score (clamped 0-100): {score}."
    )

    return json.dumps({
        "score": score,
        "rationale": rationale,
    })
