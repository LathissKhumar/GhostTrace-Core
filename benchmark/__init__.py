"""GhostTrace Benchmark System.

Runs evidence through single-agent (Attacker only) and multi-agent
(Attacker → Skeptic → Arbiter) pipelines, then produces structured
comparison data for the hackathon impact report.
"""

from .metrics import MetricsCalculator
from .runner import BenchmarkRunner

__all__ = ["BenchmarkRunner", "MetricsCalculator"]
