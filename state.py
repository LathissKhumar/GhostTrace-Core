"""GhostTrace state definitions and Pydantic models.

This module defines the shared state TypedDict used by the LangGraph pipeline
and all Pydantic models for validating structured agent outputs.
"""

from typing import Literal, Optional, TypedDict

from pydantic import BaseModel, Field, field_validator


class GhostTraceState(TypedDict):
    """Shared state for the LangGraph debate pipeline.

    This TypedDict flows through all agent nodes, accumulating outputs
    from each stage of the Attacker → Skeptic → Arbiter pipeline.
    """

    case_id: str
    evidence_json: dict
    attacker_narrative: Optional[str]
    attacker_parsed: Optional[dict]
    skeptic_rebuttal: Optional[str]
    skeptic_parsed: Optional[dict]
    final_report: Optional[dict]
    stream_log: list[str]
    error: Optional[str]


class KillChainStage(BaseModel):
    """A single step in the reconstructed attack narrative.

    Each stage maps to a MITRE ATT&CK technique and cites specific
    artifacts from the evidence bundle.
    """

    stage: str = Field(..., min_length=1, description="Kill chain stage name, e.g. 'Initial Access'")
    claim: str = Field(..., min_length=1, description="Specific claim text for this stage")
    evidence: str = Field(..., min_length=1, description="Cited artifact details supporting the claim")
    mitre_technique: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="MITRE ATT&CK technique ID in format T0000 or T0000.000",
    )
    confidence: int = Field(
        ...,
        ge=0,
        le=100,
        description="Confidence score 0-100 for this claim",
    )


class AttackerOutput(BaseModel):
    """Validated output schema for the Attacker Agent.

    Contains the full attack hypothesis with kill chain stages,
    attribution assessment, and recommended immediate action.
    """

    hypothesis: str = Field(..., min_length=1, description="Overall attack hypothesis")
    kill_chain: list[KillChainStage] = Field(
        ...,
        min_length=1,
        description="Ordered list of kill chain stages (minimum 1)",
    )
    attribution: str = Field(..., description="Attribution assessment")
    first_seen: str = Field(..., description="ISO 8601 timestamp of first observed activity")
    recommended_immediate_action: str = Field(
        ...,
        min_length=1,
        description="Suggested immediate response action",
    )


class SkepticChallenge(BaseModel):
    """A single challenge issued by the Skeptic Agent against an Attacker claim.

    Each challenge contains a verdict, reasoning, and identification of
    critical gaps in the evidence.
    """

    claim_challenged: str = Field(..., min_length=1, description="The claim being challenged")
    verdict: Literal[
        "SUSTAINED",
        "NEEDS_MORE_EVIDENCE",
        "OVERRULED",
        "ALTERNATIVE_EXPLANATION",
    ] = Field(..., description="Verdict for this claim")
    reasoning: str = Field(..., min_length=1, description="Detailed reasoning for the verdict")
    critical_gap: str = Field(..., description="What is missing or wrong with the claim")


class SkepticOutput(BaseModel):
    """Validated output schema for the Skeptic Agent.

    Contains the overall assessment, individual challenges for each claim,
    unchallenged claims, and a recommended action to avoid.
    """

    overall_assessment: str = Field(..., min_length=1, description="Summary assessment of the narrative")
    challenges: list[SkepticChallenge] = Field(
        ...,
        min_length=1,
        description="List of challenges (minimum 1)",
    )
    unchallenged_claims: list[str] = Field(
        default_factory=list,
        description="Claims that were not challenged",
    )
    do_not_do: str = Field(
        ...,
        min_length=1,
        description="Single recommended action to avoid",
    )


class ArbiterReportModel(BaseModel):
    """Validated output schema for the Arbiter Agent's final IR report.

    Synthesizes the debate into a confidence-scored incident response report
    suitable for executive presentation.
    """

    incident_summary: str = Field(
        ...,
        min_length=1,
        description="Summary based on surviving evidence only",
    )
    classification: Literal["Confirmed", "Probable", "Suspected", "Inconclusive"] = Field(
        ...,
        description="Incident classification",
    )
    overall_confidence: int = Field(
        ...,
        ge=0,
        le=100,
        description="Weighted average confidence score 0-100",
    )
    confirmed_findings: list[dict] = Field(
        default_factory=list,
        description="HIGH confidence items (SUSTAINED verdicts)",
    )
    unresolved_items: list[dict] = Field(
        default_factory=list,
        description="MEDIUM confidence items (NEEDS_MORE_EVIDENCE verdicts)",
    )
    recommended_actions: list[str] = Field(
        ...,
        min_length=1,
        description="Recommended response actions (minimum 1)",
    )
    excluded_claims: list[str] = Field(
        default_factory=list,
        description="OVERRULED items excluded from the report",
    )
    skeptic_key_flag: str = Field(
        ...,
        min_length=1,
        description="Key concern raised by the Skeptic Agent",
    )
