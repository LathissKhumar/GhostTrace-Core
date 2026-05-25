"""Resilient JSON parser for LLM output.

LLMs frequently wrap valid JSON in markdown code fences, add prose preambles
or postambles, or include extra whitespace. This module provides a single
utility function that handles all common formatting issues so the rest of
the pipeline can work with clean Python dicts.
"""

import json
import re


def safe_parse_json(raw: str) -> dict:
    """Parse a JSON object from potentially messy LLM output.

    Handles the most common LLM output formatting issues:
    1. Markdown code fences (```json, ```, ```JSON, and all case variations)
    2. Leading/trailing whitespace (spaces, tabs, newlines)
    3. Prose text before or after fences (e.g., "Here is the JSON:\\n```json\\n{...}\\n```\\nDone.")
    4. Partial JSON extraction between first '{' and last '}'

    The function applies these strategies in order:
    - Strip markdown code fences (all variations)
    - Strip leading/trailing whitespace
    - Attempt json.loads() on the cleaned string
    - On failure: extract substring between first '{' and last '}' and retry
    - On total failure: raise ValueError with first 500 chars for debugging

    Args:
        raw: The raw string output from an LLM that should contain a JSON object.

    Returns:
        A Python dict parsed from the JSON content.

    Raises:
        ValueError: If no valid JSON object can be extracted. The error message
            includes the first 500 characters of the raw input for debugging.

    Examples:
        >>> safe_parse_json('{"key": "value"}')
        {'key': 'value'}

        >>> safe_parse_json('```json\\n{"key": "value"}\\n```')
        {'key': 'value'}

        >>> safe_parse_json('Here is the JSON:\\n```json\\n{"key": "value"}\\n```\\nDone.')
        {'key': 'value'}
    """
    # Step 1: Strip markdown code fences
    # Handle variations: ```json, ```JSON, ```Json, ``` (plain), with optional whitespace
    cleaned = _strip_code_fences(raw)

    # Step 2: Strip leading/trailing whitespace (spaces, tabs, newlines)
    cleaned = cleaned.strip()

    # Step 3: Try json.loads() directly
    try:
        result = json.loads(cleaned)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Step 4: Extract JSON between first '{' and last '}'
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")

    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        substring = cleaned[first_brace : last_brace + 1]
        try:
            result = json.loads(substring)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 5: Also try extraction on the original raw input (in case fence stripping
    # mangled something, or there are nested fences)
    raw_stripped = raw.strip()
    first_brace = raw_stripped.find("{")
    last_brace = raw_stripped.rfind("}")

    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        substring = raw_stripped[first_brace : last_brace + 1]
        try:
            result = json.loads(substring)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 6: Total failure — raise ValueError with context
    preview = raw[:500]
    raise ValueError(
        f"Failed to parse JSON from LLM output. First 500 characters of raw input:\n{preview}"
    )


def _strip_code_fences(text: str) -> str:
    """Remove markdown code fences from text, handling prose before/after.

    Handles patterns like:
    - ```json\\n{...}\\n```
    - ```JSON\\n{...}\\n```
    - ```Json\\n{...}\\n```
    - ```\\n{...}\\n```
    - Here is the JSON:\\n```json\\n{...}\\n```\\nDone.

    The function is case-insensitive for the language tag and handles
    any amount of whitespace around the fences.
    """
    # Pattern matches opening fence with optional language tag and closing fence
    # Captures the content between them
    # re.DOTALL so . matches newlines, re.IGNORECASE for json/JSON/Json/etc.
    fence_pattern = re.compile(
        r"```(?:json)?\s*\n?(.*?)\n?\s*```",
        re.DOTALL | re.IGNORECASE,
    )

    match = fence_pattern.search(text)
    if match:
        return match.group(1)

    return text
