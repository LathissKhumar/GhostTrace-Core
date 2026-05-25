"""Confidence score computation for GhostTrace debate outcomes.

This module provides the algorithmic confidence scoring used by the Arbiter Agent
to produce an objective, reproducible overall confidence score from the classified
debate findings. The score is computed as a weighted average of confirmed findings
(HIGH=100), unresolved items (MEDIUM=50), and excluded claims (EXCLUDED=0).
"""


def compute_overall_confidence(
    confirmed_findings: list,
    unresolved_items: list,
    excluded_claims: list,
) -> int:
    """Compute the weighted average overall confidence score from debate outcomes.

    Calculates a single integer confidence score based on the distribution of
    findings across confidence tiers:
      - confirmed_findings: weighted at 100 points each (HIGH confidence)
      - unresolved_items: weighted at 50 points each (MEDIUM confidence)
      - excluded_claims: weighted at 0 points each (EXCLUDED)

    The formula is:
        score = (len(confirmed_findings) * 100 + len(unresolved_items) * 50
                 + len(excluded_claims) * 0) / total_items

    Parameters
    ----------
    confirmed_findings : list
        Items that received HIGH confidence (SUSTAINED verdict). Each element
        can be any object; only the list length is used. Accepts 0 to 1000 items.
    unresolved_items : list
        Items that received MEDIUM confidence (NEEDS_MORE_EVIDENCE or
        ALTERNATIVE_EXPLANATION verdict). Accepts 0 to 1000 items.
    excluded_claims : list
        Items that were excluded (OVERRULED verdict). Accepts 0 to 1000 items.

    Returns
    -------
    int
        The overall confidence score as an integer in the range [0, 100] inclusive.
        Returns 0 when no items are provided (total_items == 0).
    """
    total_items = len(confirmed_findings) + len(unresolved_items) + len(excluded_claims)

    if total_items == 0:
        return 0

    weighted_sum = len(confirmed_findings) * 100 + len(unresolved_items) * 50
    score = round(weighted_sum / total_items)

    return max(0, min(100, score))
