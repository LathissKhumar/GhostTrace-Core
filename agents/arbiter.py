"""Arbiter Agent node for GhostTrace debate pipeline.

The Arbiter Agent acts as a neutral judge, synthesizing the forensic debate
between the Attacker and Skeptic agents into a final confidence-scored
incident response report suitable for executive presentation.
"""

import json
import os

from llm_client import call_llm
from state import ArbiterReportModel, GhostTraceState
from utils import compute_overall_confidence, safe_parse_json

ARBITER_SYSTEM_PROMPT = """You are the Arbiter Agent — a neutral, impartial judge presiding over a cybersecurity forensic debate. Your role is to synthesize the arguments presented by the Attacker Agent (prosecution) and the Skeptic Agent (defense) into a final, confidence-scored Incident Response report. You do not advocate for either side. You weigh evidence objectively, apply structured verdict mappings, and produce a report suitable for CISO-level executive presentation.

You must follow these rules without exception:

1. You SHALL only include claims in the incident_summary that received SUSTAINED or NEEDS_MORE_EVIDENCE verdicts. Claims that were OVERRULED must never appear in the summary narrative.

2. You SHALL classify each claim according to the Skeptic's verdict using this exact mapping:
   - SUSTAINED → Place in confirmed_findings with HIGH confidence (100 points)
   - NEEDS_MORE_EVIDENCE → Place in unresolved_items with MEDIUM confidence (50 points)
   - OVERRULED → Place in excluded_claims with EXCLUDED status (0 points)
   - ALTERNATIVE_EXPLANATION → Place in unresolved_items with LOW confidence (10 points), noting the alternative

3. You SHALL compute the overall_confidence as the weighted average of all classified items using the point values above, rounded to the nearest integer and clamped to [0, 100].

4. You SHALL ensure that recommended_actions contains NO action that matches or is semantically equivalent to the Skeptic's do_not_do warning. If the Attacker recommended an action that the Skeptic flagged as dangerous, you must exclude it.

5. You SHALL populate skeptic_key_flag with the single most critical concern raised by the Skeptic Agent — the one finding that, if ignored, poses the greatest risk of an incorrect response.

6. You SHALL assign a classification label based on overall_confidence: "Confirmed" (≥80), "Probable" (60-79), "Suspected" (40-59), "Inconclusive" (<40).

7. You SHALL output ONLY valid JSON conforming to the schema below. No markdown fences, no prose preamble, no postamble — just the raw JSON object.

8. Each entry in confirmed_findings must include "finding" (description string) and "mitre_technique" (technique ID) fields. Each entry in unresolved_items must include "item" (description string) and "required_evidence" (what's needed to confirm) fields.

9. You SHALL include at least one recommended_action that is actionable and specific to the incident evidence.

Output JSON Schema:
{
  "incident_summary": "<string: summary based on surviving evidence only>",
  "classification": "<string: one of Confirmed|Probable|Suspected|Inconclusive>",
  "overall_confidence": <integer: 0-100 weighted average>,
  "confirmed_findings": [
    {"finding": "<string>", "mitre_technique": "<string: TNNNN or TNNNN.NNN>", "confidence": 100}
  ],
  "unresolved_items": [
    {"item": "<string>", "required_evidence": "<string>", "confidence": 50}
  ],
  "recommended_actions": ["<string: specific actionable step>"],
  "excluded_claims": ["<string: claim that was OVERRULED>"],
  "skeptic_key_flag": "<string: most critical skeptic concern>"
}
"""


async def arbiter_node(state: GhostTraceState) -> dict:
    """Synthesize the Attacker-Skeptic debate into a final IR report.

    Reads all prior agent outputs from state, calls Claude with the full
    debate context, and produces a validated ArbiterReport with algorithmically
    verified confidence scores.

    Parameters
    ----------
    state : GhostTraceState
        The shared pipeline state containing evidence, attacker narrative,
        and skeptic rebuttal.

    Returns
    -------
    dict
        Updated state fields: final_report (validated dict), stream_log.
        On error: error field set, stream_log updated with error message.
    """
    stream_log = list(state.get("stream_log", []))

    # Read prior outputs from state
    evidence_json = state.get("evidence_json", {})
    attacker_narrative = state.get("attacker_narrative")
    attacker_parsed = state.get("attacker_parsed")
    skeptic_rebuttal = state.get("skeptic_rebuttal")
    skeptic_parsed = state.get("skeptic_parsed")

    # Abort if required inputs are missing
    if not attacker_narrative:
        error_msg = "Arbiter Agent: Cannot synthesize — attacker narrative is missing or empty."
        stream_log.append(f"❌ {error_msg}")
        return {"error": error_msg, "stream_log": stream_log}

    if not skeptic_rebuttal:
        error_msg = "Arbiter Agent: Cannot synthesize — skeptic rebuttal is missing or empty."
        stream_log.append(f"❌ {error_msg}")
        return {"error": error_msg, "stream_log": stream_log}

    stream_log.append("⚖️ Arbiter: Synthesizing debate — computing confidence scores...")

    try:
        # Build user message with all context
        user_message = _build_user_message(
            evidence_json=evidence_json,
            attacker_narrative=attacker_narrative,
            attacker_parsed=attacker_parsed,
            skeptic_rebuttal=skeptic_rebuttal,
            skeptic_parsed=skeptic_parsed,
        )

        # Call LLM (Ollama local by default, free)
        raw_response = call_llm(
            system_prompt=ARBITER_SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=2000,
        )

        # Parse and validate response
        parsed = safe_parse_json(raw_response)
        validated = ArbiterReportModel.model_validate(parsed)
        report_dict = validated.model_dump()

        # Use compute_overall_confidence to verify/override the LLM's score
        computed_confidence = compute_overall_confidence(
            confirmed_findings=report_dict.get("confirmed_findings", []),
            unresolved_items=report_dict.get("unresolved_items", []),
            excluded_claims=report_dict.get("excluded_claims", []),
        )
        report_dict["overall_confidence"] = computed_confidence

        stream_log.append(
            f"✅ GhostTrace: Debate complete — {computed_confidence}% confidence IR report ready"
        )

        return {"final_report": report_dict, "stream_log": stream_log}

    except Exception as e:
        error_msg = f"Arbiter Agent failed: {str(e)}"
        stream_log.append(f"❌ {error_msg}")
        return {"error": error_msg, "stream_log": stream_log}


def _build_user_message(
    evidence_json: dict,
    attacker_narrative: str,
    attacker_parsed: dict | None,
    skeptic_rebuttal: str,
    skeptic_parsed: dict | None,
) -> str:
    """Build the user message containing all debate context for the Arbiter.

    Structures the message with clearly separated sections for the original
    evidence, attacker narrative, and skeptic rebuttal.
    """
    sections = []

    # Section 1: Original Evidence
    sections.append("=== ORIGINAL EVIDENCE ===")
    sections.append(json.dumps(evidence_json, indent=2))

    # Section 2: Attacker Narrative
    sections.append("\n=== ATTACKER NARRATIVE (Raw) ===")
    sections.append(attacker_narrative)

    if attacker_parsed:
        sections.append("\n=== ATTACKER NARRATIVE (Parsed) ===")
        sections.append(json.dumps(attacker_parsed, indent=2))

    # Section 3: Skeptic Rebuttal
    sections.append("\n=== SKEPTIC REBUTTAL (Raw) ===")
    sections.append(skeptic_rebuttal)

    if skeptic_parsed:
        sections.append("\n=== SKEPTIC REBUTTAL (Parsed) ===")
        sections.append(json.dumps(skeptic_parsed, indent=2))

    # Instructions
    sections.append("\n=== INSTRUCTIONS ===")
    sections.append(
        "Synthesize the above debate into a final IR report. "
        "Map each claim's verdict to the appropriate confidence tier: "
        "SUSTAINED→confirmed_findings (HIGH/100), "
        "NEEDS_MORE_EVIDENCE→unresolved_items (MEDIUM/50), "
        "OVERRULED→excluded_claims (EXCLUDED/0), "
        "ALTERNATIVE_EXPLANATION→unresolved_items (LOW/10). "
        "Compute overall_confidence as the weighted average. "
        "Ensure recommended_actions excludes anything the Skeptic flagged in do_not_do. "
        "Output ONLY the JSON object — no markdown, no prose."
    )

    return "\n".join(sections)
