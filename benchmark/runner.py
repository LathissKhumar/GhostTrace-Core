"""Benchmark runner for GhostTrace single-agent vs multi-agent comparison.

Runs evidence through two pipelines and produces a structured comparison:

1. **Single-agent** — Attacker Agent only (no Skeptic, no Arbiter)
2. **Multi-agent** — Full Attacker → Skeptic → Arbiter debate

The comparison data quantifies the adversarial pipeline's impact:
- Claims made vs. claims disputed
- Confidence calibration improvement
- Kill chain coverage expansion
- Hallucinations caught by the Skeptic

Usage (CLI):
    python -m benchmark.runner --evidence evidence/sample_ransomware.json
    python -m benchmark.runner --demo
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

from agents.attacker import attacker_node
from agents.skeptic import skeptic_node
from agents.arbiter import arbiter_node
from graph import ghosttrace_graph
from llm_client import get_model_name
from state import GhostTraceState
from utils.confidence_scorer import compute_overall_confidence

from .metrics import MetricsCalculator

# ── Pre-computed demo results directory ──────────────────────────────
RESULTS_DIR = Path(__file__).parent / "results"

# ── Sample evidence file mapping ─────────────────────────────────────
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence"
EVIDENCE_MAP: dict[str, str] = {
    "ransomware": "sample_ransomware.json",
    "insider": "sample_insider_threat.json",
    "apt": "sample_apt_lateral.json",
}


class BenchmarkRunner:
    """Execute single-agent and multi-agent pipelines and compare them.

    The runner does **not** modify or depend on the existing debate
    pipeline — it creates fresh state dicts and invokes the same
    agent functions directly (single-agent) or via the LangGraph
    graph (multi-agent).
    """

    def __init__(self) -> None:
        self.metrics = MetricsCalculator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_benchmark(self, evidence: dict) -> dict[str, Any]:
        """Run both pipelines on *evidence* and return comparison data.

        Parameters
        ----------
        evidence : dict
            A GhostTrace evidence bundle (with ``artifacts`` key).

        Returns
        -------
        dict
            Structured comparison with ``single_agent``, ``multi_agent``,
            and ``improvement`` sections.
        """
        single = await self._run_single_agent(evidence)
        multi = await self._run_multi_agent(evidence)

        return self._build_comparison(single, multi)

    def get_demo_results(self, scenario: str | None = None) -> dict[str, Any]:
        """Return pre-computed benchmark results.

        If *scenario* is ``None``, returns the aggregate of all three.
        """
        if scenario and scenario in EVIDENCE_MAP:
            return self._load_result(scenario)

        # Aggregate all three
        results: list[dict] = []
        for key in EVIDENCE_MAP:
            try:
                results.append(self._load_result(key))
            except FileNotFoundError:
                continue

        if not results:
            return {"error": "No pre-computed results available"}

        return self._aggregate_results(results)

    # ------------------------------------------------------------------
    # Single-agent pipeline (Attacker only)
    # ------------------------------------------------------------------

    async def _run_single_agent(self, evidence: dict) -> dict[str, Any]:
        """Run Attacker Agent independently — no Skeptic, no Arbiter."""
        timer = MetricsCalculator.make_timer()
        timer.start()

        state: GhostTraceState = {
            "case_id": "benchmark-single",
            "evidence_json": evidence,
            "attacker_narrative": None,
            "attacker_parsed": None,
            "skeptic_rebuttal": None,
            "skeptic_parsed": None,
            "final_report": None,
            "stream_log": [],
            "error": None,
        }

        t0 = time.perf_counter()
        attacker_result = await attacker_node(state)
        t1 = time.perf_counter()
        timer.record_agent("attacker", t1 - t0)

        if attacker_result.get("error"):
            timer.stop()
            return {
                "error": attacker_result["error"],
                "claims": 0,
                "confidence": 0,
                "kill_chain_stages": 0,
                "time_ms": timer.total_ms,
            }

        attacker_parsed = attacker_result.get("attacker_parsed")

        # Single-agent "confidence" = average of individual stage confidences
        confidences = [
            kc.get("confidence", 0)
            for kc in (attacker_parsed or {}).get("kill_chain", [])
        ]
        single_confidence = (
            round(sum(confidences) / len(confidences)) if confidences else 0
        )

        claim_count = self.metrics.claim_count(attacker_parsed)

        # Coverage: count unique stage names from kill chain
        stages_found: set[str] = set()
        for kc in (attacker_parsed or {}).get("kill_chain", []):
            stages_found.add(kc.get("stage", ""))

        timer.stop()

        return {
            "claims": claim_count,
            "confidence": single_confidence,
            "kill_chain_stages": len(stages_found),
            "time_ms": timer.total_ms,
            "per_agent": timer.agent_breakdown,
            "attacker_parsed": attacker_parsed,
        }

    # ------------------------------------------------------------------
    # Multi-agent pipeline (full debate via graph)
    # ------------------------------------------------------------------

    async def _run_multi_agent(self, evidence: dict) -> dict[str, Any]:
        """Run full Attacker → Skeptic → Arbiter debate via LangGraph."""
        timer = MetricsCalculator.make_timer()
        timer.start()

        state: GhostTraceState = {
            "case_id": "benchmark-multi",
            "evidence_json": evidence,
            "attacker_narrative": None,
            "attacker_parsed": None,
            "skeptic_rebuttal": None,
            "skeptic_parsed": None,
            "final_report": None,
            "stream_log": [],
            "error": None,
        }

        final_state: dict[str, Any] = {}

        try:
            # Use LangGraph astream for the full pipeline
            async for event in ghosttrace_graph.astream(state):
                for node_name, node_output in event.items():
                    final_state.update(node_output)
        except Exception as e:
            timer.stop()
            return {
                "error": str(e),
                "claims": 0,
                "disputed": 0,
                "confidence": 0,
                "kill_chain_stages": 0,
                "time_ms": timer.total_ms,
            }

        timer.stop()

        attacker_parsed = final_state.get("attacker_parsed")
        skeptic_parsed = final_state.get("skeptic_parsed")
        final_report = final_state.get("final_report")

        claim_count = self.metrics.claim_count(attacker_parsed)
        disputed = self.metrics.disputed_claims(attacker_parsed, skeptic_parsed)
        coverage = self.metrics.kill_chain_coverage(final_report)

        multi_confidence = final_report.get("overall_confidence", 0) if final_report else 0

        return {
            "claims": claim_count,
            "disputed": len(disputed),
            "confidence": multi_confidence,
            "kill_chain_stages": coverage["covered"],
            "time_ms": timer.total_ms,
            "per_agent": timer.agent_breakdown,
            "hallucinations_caught": len(
                self.metrics.hallucination_examples(skeptic_parsed)
            ),
            "attacker_parsed": attacker_parsed,
            "skeptic_parsed": skeptic_parsed,
            "final_report": final_report,
        }

    # ------------------------------------------------------------------
    # Comparison builder
    # ------------------------------------------------------------------

    def _build_comparison(
        self,
        single: dict[str, Any],
        multi: dict[str, Any],
    ) -> dict[str, Any]:
        """Assemble the final comparison JSON."""
        single_conf = single.get("confidence", 0)
        multi_conf = multi.get("confidence", 0)

        delta = self.metrics.confidence_delta(single_conf, multi_conf)
        single_stages = single.get("kill_chain_stages", 0)
        multi_stages = multi.get("kill_chain_stages", 0)

        hallucinations = multi.get("hallucinations_caught", 0)

        return {
            "single_agent": {
                "claims": single.get("claims", 0),
                "confidence": single_conf,
                "kill_chain_stages": single_stages,
                "time_ms": single.get("time_ms", 0),
            },
            "multi_agent": {
                "claims": multi.get("claims", 0),
                "disputed": multi.get("disputed", 0),
                "confidence": multi_conf,
                "kill_chain_stages": multi_stages,
                "time_ms": multi.get("time_ms", 0),
            },
            "improvement": {
                "confidence_delta": f"{delta:+.0f}%" if delta != 0 else "0%",
                "coverage_delta": (
                    f"{multi_stages - single_stages:+d} stages"
                    if multi_stages != single_stages
                    else "0 stages"
                ),
                "hallucinations_caught": hallucinations,
            },
        }

    # ------------------------------------------------------------------
    # Pre-computed results
    # ------------------------------------------------------------------

    def _load_result(self, scenario: str) -> dict[str, Any]:
        result_path = RESULTS_DIR / f"{scenario}.json"
        if not result_path.exists():
            raise FileNotFoundError(f"No pre-computed result for {scenario}")
        with open(result_path) as f:
            return json.load(f)

    def _aggregate_results(self, results: list[dict]) -> dict[str, Any]:
        """Average numeric fields across multiple benchmark results."""
        n = len(results)
        if n == 0:
            return {}

        def avg(key_path: str, default=0) -> int | float:
            vals = []
            for r in results:
                parts = key_path.split(".")
                obj = r
                for p in parts:
                    if isinstance(obj, dict):
                        obj = obj.get(p, default)
                    else:
                        obj = default
                        break
                if isinstance(obj, (int, float)):
                    vals.append(obj)
            return round(sum(vals) / len(vals), 1) if vals else default

        single_claims = avg("single_agent.claims")
        single_conf = avg("single_agent.confidence")
        single_stages = avg("single_agent.kill_chain_stages")
        single_time = avg("single_agent.time_ms")

        multi_claims = avg("multi_agent.claims")
        multi_disputed = avg("multi_agent.disputed")
        multi_conf = avg("multi_agent.confidence")
        multi_stages = avg("multi_agent.kill_chain_stages")
        multi_time = avg("multi_agent.time_ms")

        hallucinations = sum(
            r.get("improvement", {}).get("hallucinations_caught", 0)
            for r in results
        )

        delta = self.metrics.confidence_delta(single_conf, multi_conf)

        return {
            "scenario_count": n,
            "single_agent": {
                "claims": single_claims,
                "confidence": single_conf,
                "kill_chain_stages": single_stages,
                "time_ms": single_time,
            },
            "multi_agent": {
                "claims": multi_claims,
                "disputed": multi_disputed,
                "confidence": multi_conf,
                "kill_chain_stages": multi_stages,
                "time_ms": multi_time,
            },
            "improvement": {
                "confidence_delta": f"{delta:+.0f}%" if delta != 0 else "0%",
                "coverage_delta": f"{multi_stages - single_stages:+.1f} stages",
                "hallucinations_caught": hallucinations,
            },
        }


# ======================================================================
# CLI entry point
# ======================================================================

async def _main() -> None:
    parser = argparse.ArgumentParser(
        description="GhostTrace Benchmark — single vs multi-agent comparison"
    )
    parser.add_argument(
        "--evidence",
        type=str,
        help="Path to an evidence JSON file",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show pre-computed demo results",
    )
    parser.add_argument(
        "--scenario",
        choices=list(EVIDENCE_MAP.keys()),
        help="Demo scenario name (for --demo mode)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Write comparison JSON to this file",
    )

    args = parser.parse_args()
    runner = BenchmarkRunner()

    if args.demo:
        result = runner.get_demo_results(args.scenario)
        print(json.dumps(result, indent=2))
        return

    if not args.evidence:
        parser.error("Provide --evidence <path> or use --demo")

    evidence_path = Path(args.evidence)
    if not evidence_path.exists():
        parser.error(f"Evidence file not found: {evidence_path}")

    with open(evidence_path) as f:
        evidence = json.load(f)

    print(f"Running benchmark on: {evidence_path.name}")
    print(f"Model: {get_model_name()}")
    print("─" * 50)

    result = await runner.run_benchmark(evidence)
    print(json.dumps(result, indent=2))

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults written to {out}")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
