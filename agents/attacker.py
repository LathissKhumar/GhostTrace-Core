"""Attacker Agent node for the GhostTrace adversarial debate pipeline.

This module implements the Attacker Agent — a red team threat hunter persona
that analyzes forensic evidence bundles and constructs detailed attack narratives
with kill chain stages mapped to MITRE ATT&CK techniques.

The attacker_node function is designed to be used as a LangGraph StateGraph node,
receiving the shared GhostTraceState and returning updated state fields.
"""

import json
import os

from llm_client import call_llm
from state import AttackerOutput, GhostTraceState
from utils.json_parser import safe_parse_json

ATTACKER_SYSTEM_PROMPT = """You are the Attacker Agent — an elite red team threat hunter operating as a prosecution attorney in a structured adversarial debate. Your mission is to construct the most compelling, technically rigorous attack narrative from the forensic evidence presented to you. You think like an advanced persistent threat actor and reconstruct the intrusion timeline with surgical precision.

You approach every evidence bundle as if you are presenting a case to a jury of senior incident responders. Every claim you make must be anchored to specific artifacts — timestamps, process IDs, file paths, IP addresses, registry keys, or authentication events drawn directly from the evidence. You do not speculate without basis; you build chains of inference where each link is supported by observable data.

Rules:
1. You MUST produce a complete attack hypothesis that explains the overall intrusion campaign, including the likely threat actor motivation and capability level.
2. You MUST construct a kill chain with at least one stage. Each stage MUST cite specific artifacts from the evidence bundle including exact timestamps, PIDs, file paths, IPs, or registry keys.
3. You MUST map every kill chain stage to a valid MITRE ATT&CK technique ID in the format TNNNN or TNNNN.NNN (e.g., T1059.001 for PowerShell execution).
4. You MUST assign a confidence score (0-100) to each kill chain stage: 80-100 means the artifact directly proves the claim with no ambiguity, 50-79 means the artifact is consistent but circumstantial, 0-49 means the claim is inferred with limited direct support.
5. You MUST provide an attribution assessment identifying the likely threat actor group, toolset, or campaign based on TTPs observed in the evidence.
6. You MUST identify the first_seen timestamp — the earliest artifact timestamp that indicates malicious activity — in ISO 8601 format.
7. You MUST recommend exactly one immediate action the incident response team should take right now to contain the threat.
8. If multiple attack hypotheses are equally supported, select the most technically sophisticated one and note the alternative in your attribution assessment.
9. You MUST output ONLY valid JSON with no markdown fences, no prose preamble, and no postamble. Your entire response must be a single JSON object.
10. Do NOT fabricate artifacts. Every piece of evidence you cite must exist in the provided evidence bundle.

Your output MUST conform to this exact JSON schema:
{
  "hypothesis": "<string: overall attack hypothesis explaining the campaign>",
  "kill_chain": [
    {
      "stage": "<string: kill chain stage name, e.g. 'Initial Access', 'Execution', 'Persistence'>",
      "claim": "<string: specific claim about what happened at this stage>",
      "evidence": "<string: exact artifact details cited — timestamps, PIDs, paths, IPs, registry keys>",
      "mitre_technique": "<string: MITRE ATT&CK technique ID, format TNNNN or TNNNN.NNN>",
      "confidence": <integer: 0-100 confidence score for this claim>
    }
  ],
  "attribution": "<string: threat actor attribution assessment>",
  "first_seen": "<string: ISO 8601 timestamp of earliest malicious activity>",
  "recommended_immediate_action": "<string: single immediate containment action>"
}
"""


async def attacker_node(state: GhostTraceState) -> dict:
    """Execute the Attacker Agent node in the GhostTrace debate pipeline.

    Reads the evidence bundle from state, calls Claude with the red team
    threat hunter system prompt, parses and validates the response against
    the AttackerOutput Pydantic model, and returns updated state fields.

    The function appends progress messages to stream_log at the start and
    completion of analysis, including the number of artifact types analyzed
    and kill chain stages identified.

    Args:
        state: The shared GhostTraceState containing evidence_json and
            other pipeline fields.

    Returns:
        A dict containing updated state fields:
            - attacker_narrative: Raw response text from Claude
            - attacker_parsed: Validated AttackerOutput as a dict
            - stream_log: Updated list with progress messages

    Raises:
        No exceptions are raised directly. All errors from the Claude API
        call are caught and recorded in the state error field and stream_log.
    """
    evidence_json = state["evidence_json"]
    stream_log = list(state.get("stream_log", []))

    # Serialize evidence to indented JSON string for the prompt
    evidence_str = json.dumps(evidence_json, indent=2)

    # Count artifact types in the evidence bundle
    artifacts = evidence_json.get("artifacts", {})
    artifact_type_count = len(artifacts)

    stream_log.append(
        f"🔴 Attacker Agent: Analyzing {artifact_type_count} artifact types..."
    )

    try:
        # Call LLM (Ollama local by default, free)
        user_message = (
            "Analyze the following forensic evidence bundle and construct "
            "a detailed attack narrative with kill chain stages.\n\n"
            f"EVIDENCE BUNDLE:\n{evidence_str}"
        )

        raw_text = call_llm(
            system_prompt=ATTACKER_SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=2000,
        )

        # Parse response with safe_parse_json
        parsed_dict = safe_parse_json(raw_text)

        # Validate with AttackerOutput Pydantic model
        validated_output = AttackerOutput.model_validate(parsed_dict)

        # Count kill chain stages
        kill_chain_count = len(validated_output.kill_chain)

        stream_log.append(
            f"🔴 Attacker Agent: Narrative complete — {kill_chain_count} kill chain stages identified"
        )

        return {
            "attacker_narrative": raw_text,
            "attacker_parsed": validated_output.model_dump(),
            "stream_log": stream_log,
        }

    except Exception as e:
        error_message = f"Attacker Agent failed: {str(e)}"
        stream_log.append(f"🔴 Attacker Agent ERROR: {error_message}")

        return {
            "attacker_narrative": None,
            "attacker_parsed": None,
            "stream_log": stream_log,
            "error": error_message,
        }
