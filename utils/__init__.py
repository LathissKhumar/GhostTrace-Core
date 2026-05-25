"""GhostTrace Utility Modules.

This package provides shared utilities for the GhostTrace backend:
- safe_parse_json: Resilient JSON parser for LLM output (strips fences, extracts objects)
- compute_overall_confidence: Weighted average confidence scorer for debate outcomes
"""

from .confidence_scorer import compute_overall_confidence
from .json_parser import safe_parse_json

__all__ = ["compute_overall_confidence", "safe_parse_json"]
