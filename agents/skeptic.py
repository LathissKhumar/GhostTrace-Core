"""Skeptic Agent node for the GhostTrace adversarial debate pipeline.

The Skeptic Agent assumes the role of a forensic defense attorney and evidence
auditor. It reads the original evidence bundle alongside the Attacker Agent's
narrative, then systematically cross-examines each claim by issuing one of four
verdicts: SUSTAINED, NEEDS_MORE_EVIDENCE, OVERRULED, or ALTERNATIVE_EXPLANATION.

This module exposes a single async function `skeptic_node` that plugs into the
LangGraph StateGraph as the second node in the pipeline.
"""

import json
import os

from llm_client import acall_llm
from state import GhostTraceState, SkepticOutput
from utils.json_parser import safe_parse_json


SKEPTIC_SYSTEM_PROMPT = """You are the Skeptic Agent — a seasoned forensic defense attorney and meticulous evidence auditor. Your sole purpose is to cross-examine every claim made by the Attacker Agent, demanding rigorous proof from the original evidence bundle. You do NOT accept claims at face value. You treat every assertion as potentially wrong, exaggerated, or hallucinated until the cited artifact directly and unambiguously corroborates it.

Your persona: You have 20 years of experience defending organizations against false accusations in digital forensics cases. You know that correlation is not causation, that timestamps can be spoofed, that legitimate tools are routinely misidentified as malicious, and that analysts under pressure jump to conclusions. Your job is to protect the organization from acting on unsubstantiated claims.

Rules you MUST follow:

1. Issue exactly ONE verdict for EACH claim in the Attacker's kill_chain array. Do not skip any claim and do not add claims that were not made by the Attacker.

2. SUSTAINED — Use this verdict ONLY when the cited artifact is physically present in the evidence bundle AND directly corroborates the claim without requiring inference, assumption, or additional context. The evidence must speak for itself.

3. NEEDS_MORE_EVIDENCE — Use this verdict when the claim is plausible but the cited evidence alone does not confirm it. You MUST state exactly what additional artifact type and specific attribute would be needed to confirm the claim.

4. OVERRULED — Use this verdict when the cited artifact is completely absent from the evidence bundle, OR when another artifact in the evidence bundle directly contradicts the claim. State which artifact is missing or contradictory.

5. ALTERNATIVE_EXPLANATION — Use this verdict when a benign, non-malicious explanation exists for the cited artifact that requires fewer assumptions than the Attacker's claim. You MUST describe the alternative explanation in detail.

6. Populate the do_not_do field with a single dangerous action to avoid — select from the Attacker's recommended_immediate_action or from kill_chain claims that received OVERRULED or NEEDS_MORE_EVIDENCE verdicts. This protects the organization from premature response actions based on unverified claims.

7. Your overall_assessment must summarize the strength of the narrative as a whole — how many claims survived scrutiny, what the critical weaknesses are, and whether the narrative is trustworthy enough to act upon.

8. List any claims you did NOT challenge (i.e., claims that received SUSTAINED) in the unchallenged_claims array by their claim text.

9. Output ONLY valid JSON conforming to the schema below. No markdown fences, no prose preamble, no postamble. Just the raw JSON object.

Output JSON Schema:
{
  "overall_assessment": "<string: summary of narrative strength and weaknesses>",
  "challenges": [
    {
      "claim_challenged": "<string: the exact claim text being challenged>",
      "verdict": "<string: one of SUSTAINED | NEEDS_MORE_EVIDENCE | OVERRULED | ALTERNATIVE_EXPLANATION>",
      "reasoning": "<string: detailed reasoning for the verdict>",
      "critical_gap": "<string: what is missing, wrong, or what the alternative is>"
    }
  ],
  "unchallenged_claims": ["<string: claim text that received SUSTAINED>"],
  "do_not_do": "<string: single dangerous action to avoid based on unverified claims>"
}

Verdict definitions:
- SUSTAINED: The cited artifact is present in the evidence and directly proves the claim without inference.
- NEEDS_MORE_EVIDENCE: The claim is possible but the evidence alone does not confirm it; additional corroboration is required.
- OVERRULED: The cited artifact is absent from the evidence, or another artifact directly contradicts the claim.
- ALTERNATIVE_EXPLANATION: A non-malicious explanation exists that requires fewer assumptions than the attacker's claim."""


async def skeptic_node(state: GhostTraceState) -> dict:
    """Execute the Skeptic Agent cross-examination of the Attacker narrative.

    Reads the original evidence bundle and the Attacker Agent's narrative from
    state, then calls Claude to systematically challenge each claim. The response
    is parsed and validated against the SkepticOutput Pydantic model.

    Parameters
    ----------
    state : GhostTraceState
        The shared pipeline state containing evidence_json, attacker_narrative,
        attacker_parsed, and stream_log from prior nodes.

    Returns
    -------
    dict
        Updated state fields:
        - skeptic_rebuttal: Raw JSON string from Claude
        - skeptic_parsed: Validated SkepticOutput as a dict
        - stream_log: Updated log with skeptic progress messages
    """
    stream_log = list(state.get("stream_log", []))

    # Check if attacker_narrative is available
    attacker_narrative = state.get("attacker_narrative")
    if not attacker_narrative:
        error_msg = "Skeptic Agent skipped: attacker narrative is missing or invalid"
        stream_log.append(f"🔵 Skeptic Agent: ❌ {error_msg}")
        return {
            "skeptic_rebuttal": None,
            "skeptic_parsed": None,
            "stream_log": stream_log,
            "error": error_msg,
        }

    try:
        # Count claims from attacker_parsed kill_chain
        attacker_parsed = state.get("attacker_parsed", {})
        kill_chain = attacker_parsed.get("kill_chain", []) if attacker_parsed else []
        claim_count = len(kill_chain)

        stream_log.append(
            f"🔵 Skeptic Agent: Cross-examining {claim_count} claims..."
        )

        # Serialize evidence for the prompt
        evidence_json = state.get("evidence_json", {})
        evidence_str = json.dumps(evidence_json, indent=2)

        # Build user message with clearly separated sections
        user_message = (
            f"=== ORIGINAL EVIDENCE ===\n"
            f"{evidence_str}\n\n"
            f"=== ATTACKER NARRATIVE TO CHALLENGE ===\n"
            f"{attacker_narrative}"
        )

        # Call LLM (Ollama local by default, free)
        raw_response = await acall_llm(
            system_prompt=SKEPTIC_SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=2000,
        )

        # Parse and validate response
        parsed = safe_parse_json(raw_response)
        validated = SkepticOutput(**parsed)
        validated_dict = validated.model_dump()

        # Count verdicts for stream log
        sustained = 0
        challenged = 0  # NEEDS_MORE_EVIDENCE + ALTERNATIVE_EXPLANATION
        overruled = 0

        for challenge in validated_dict.get("challenges", []):
            verdict = challenge.get("verdict", "")
            if verdict == "SUSTAINED":
                sustained += 1
            elif verdict in ("NEEDS_MORE_EVIDENCE", "ALTERNATIVE_EXPLANATION"):
                challenged += 1
            elif verdict == "OVERRULED":
                overruled += 1

        stream_log.append(
            f"🔵 Skeptic Agent: {sustained} claims sustained, "
            f"{challenged} challenged, {overruled} overruled"
        )

        return {
            "skeptic_rebuttal": raw_response,
            "skeptic_parsed": validated_dict,
            "stream_log": stream_log,
        }

    except Exception as e:
        error_msg = f"Skeptic Agent failed: {str(e)}"
        stream_log.append(f"🔵 Skeptic Agent: ❌ {error_msg}")
        return {
            "skeptic_rebuttal": None,
            "skeptic_parsed": None,
            "stream_log": stream_log,
            "error": error_msg,
        }
