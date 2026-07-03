"""Metrics calculation for the GhostTrace benchmark system.

Provides algorithmic measurement of single-agent vs multi-agent pipeline quality,
covering claim counts, dispute analysis, confidence deltas, kill chain coverage,
hallucination detection, and processing time breakdowns.
"""

from __future__ import annotations

import time
from typing import Any


# All MITRE ATT&CK kill chain stages the system recognises
ALL_KILL_CHAIN_STAGES: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class MetricsCalculator:
    """Compute benchmark-quality metrics from agent pipeline outputs.

    Every public method is stateless and operates on parsed dicts/lists.
    """

    # ------------------------------------------------------------------
    # Claim counting
    # ------------------------------------------------------------------
    @staticmethod
    def claim_count(attacker_parsed: dict | None) -> int:
        """Return the number of kill chain stages (claims) the Attacker made."""
        if not attacker_parsed:
            return 0
        return len(attacker_parsed.get("kill_chain", []))

    # ------------------------------------------------------------------
    # Disputed claims
    # ------------------------------------------------------------------
    @staticmethod
    def disputed_claims(
        attacker_parsed: dict | None,
        skeptic_parsed: dict | None,
    ) -> list[dict]:
        """Return list of claims the Skeptic challenged or overruled.

        A claim is "disputed" when its verdict is NOT SUSTAINED.
        Each entry contains the claim text, verdict, and reasoning.
        """
        if not attacker_parsed or not skeptic_parsed:
            return []

        challenges = skeptic_parsed.get("challenges", [])
        disputed: list[dict] = []
        for ch in challenges:
            verdict = ch.get("verdict", "SUSTAINED")
            if verdict != "SUSTAINED":
                disputed.append({
                    "claim": ch.get("claim_challenged", ""),
                    "verdict": verdict,
                    "reasoning": ch.get("reasoning", ""),
                })
        return disputed

    # ------------------------------------------------------------------
    # Confidence delta
    # ------------------------------------------------------------------
    @staticmethod
    def confidence_delta(
        single_confidence: int | float,
        multi_confidence: int | float,
    ) -> float:
        """Return the absolute change in confidence between pipelines.

        A positive value means multi-agent produced a *higher* (more
        calibrated) confidence score.  A negative value means the single
        agent was over-confident — which is the common hallucination case.
        """
        return round(multi_confidence - single_confidence, 1)

    # ------------------------------------------------------------------
    # Kill chain coverage
    # ------------------------------------------------------------------
    @staticmethod
    def kill_chain_coverage(report: dict | None) -> dict[str, Any]:
        """Count how many of the 14 canonical kill chain stages appear.

        Returns ``{"covered": int, "total": int, "stages": list[str]}``.
        The stage list contains the names of stages that appear in the report
        (either in confirmed_findings or unresolved_items).
        """
        if not report:
            return {"covered": 0, "total": len(ALL_KILL_CHAIN_STAGES), "stages": []}

        covered_stages: set[str] = set()

        # Check confirmed findings
        for finding in report.get("confirmed_findings", []):
            if isinstance(finding, dict):
                stage = finding.get("stage") or finding.get("mitre_technique", "")
                for s in ALL_KILL_CHAIN_STAGES:
                    if s.lower() in str(finding).lower():
                        covered_stages.add(s)

        # Check unresolved items
        for item in report.get("unresolved_items", []):
            if isinstance(item, dict):
                for s in ALL_KILL_CHAIN_STAGES:
                    if s.lower() in str(item).lower():
                        covered_stages.add(s)

        # Check excluded claims (they still indicate coverage, just overruled)
        for claim in report.get("excluded_claims", []):
            for s in ALL_KILL_CHAIN_STAGES:
                if s.lower() in str(claim).lower():
                    covered_stages.add(s)

        return {
            "covered": len(covered_stages),
            "total": len(ALL_KILL_CHAIN_STAGES),
            "stages": sorted(covered_stages),
        }

    # ------------------------------------------------------------------
    # Hallucination examples
    # ------------------------------------------------------------------
    @staticmethod
    def hallucination_examples(
        skeptic_parsed: dict | None,
    ) -> list[str]:
        """Return the reasoning strings for OVERRULED claims.

        These are the concrete hallucination examples caught by the
        adversarial pipeline.
        """
        if not skeptic_parsed:
            return []

        examples: list[str] = []
        for ch in skeptic_parsed.get("challenges", []):
            if ch.get("verdict") == "OVERRULED":
                examples.append(
                    f"OVERRULED: {ch.get('claim_challenged', '')} — "
                    f"{ch.get('reasoning', '')}"
                )
        return examples

    # ------------------------------------------------------------------
    # Processing time helpers
    # ------------------------------------------------------------------
    @staticmethod
    def make_timer() -> _Timer:
        """Create a timer context for measuring pipeline duration."""
        return _Timer()


class _Timer:
    """Lightweight manual timer used inside the benchmark runner."""

    def __init__(self) -> None:
        self._start: float = 0.0
        self._end: float = 0.0
        self._agent_times: dict[str, float] = {}

    def start(self) -> None:
        self._start = time.perf_counter()

    def stop(self) -> None:
        self._end = time.perf_counter()

    def record_agent(self, name: str, elapsed: float) -> None:
        self._agent_times[name] = elapsed

    @property
    def total_ms(self) -> float:
        return round((self._end - self._start) * 1000, 1)

    @property
    def agent_breakdown(self) -> dict[str, float]:
        return {k: round(v * 1000, 1) for k, v in self._agent_times.items()}

    def to_dict(self) -> dict:
        return {
            "total_ms": self.total_ms,
            "per_agent": self.agent_breakdown,
        }
