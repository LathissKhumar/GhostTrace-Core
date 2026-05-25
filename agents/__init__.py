"""GhostTrace Agent Nodes.

This package contains the three adversarial debate agents:
- attacker_node: Red team threat hunter that builds attack narratives from evidence
- skeptic_node: Forensic defense attorney that cross-examines attacker claims
- arbiter_node: Neutral judge that synthesizes the debate into a confidence-scored IR report

Agents execute sequentially via LangGraph StateGraph:
    attacker_node → skeptic_node → arbiter_node
"""
