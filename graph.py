"""LangGraph StateGraph orchestration for the GhostTrace debate pipeline.

This module defines the sequential agent pipeline (Attacker → Skeptic → Arbiter)
using LangGraph's StateGraph, and provides an async streaming generator that
yields SSE-ready event dicts as the pipeline executes.

The compiled graph enforces linear execution order, ensuring each agent receives
the complete state populated by prior agents. The streaming generator tracks
state changes and emits structured events for real-time frontend consumption.
"""

from collections.abc import AsyncGenerator

from langgraph.graph import END, StateGraph

from agents.attacker import attacker_node
from agents.arbiter import arbiter_node
from agents.skeptic import skeptic_node
from state import GhostTraceState

# Build the StateGraph with GhostTraceState as the state schema
_graph_builder = StateGraph(GhostTraceState)

# Add agent nodes
_graph_builder.add_node("attacker", attacker_node)
_graph_builder.add_node("skeptic", skeptic_node)
_graph_builder.add_node("arbiter", arbiter_node)

# Set entry point and define linear edges
_graph_builder.set_entry_point("attacker")
_graph_builder.add_edge("attacker", "skeptic")
_graph_builder.add_edge("skeptic", "arbiter")
_graph_builder.add_edge("arbiter", END)

# Compile and export the graph
ghosttrace_graph = _graph_builder.compile()


async def async_stream_graph(
    evidence_json: dict, case_id: str
) -> AsyncGenerator[dict, None]:
    """Stream the GhostTrace debate pipeline, yielding SSE-ready event dicts.

    Initializes the pipeline state and iterates through node outputs using
    LangGraph's async streaming interface. For each node completion, emits
    log events for new stream_log entries and a node_complete event with the
    node's output data.

    Args:
        evidence_json: The parsed evidence bundle dict to analyze.
        case_id: Unique identifier for this analysis session.

    Yields:
        SSE-ready dicts with one of these structures:
        - {"type": "log", "message": str} — New stream log entry
        - {"type": "node_complete", "node": str, "data": dict} — Node finished
        - {"type": "complete", "report": dict} — Pipeline finished successfully
        - {"type": "error", "message": str} — Pipeline error occurred
    """
    # Initialize state with all required fields
    initial_state: GhostTraceState = {
        "case_id": case_id,
        "evidence_json": evidence_json,
        "attacker_narrative": None,
        "attacker_parsed": None,
        "skeptic_rebuttal": None,
        "skeptic_parsed": None,
        "final_report": None,
        "stream_log": [],
        "error": None,
    }

    # Track how many log entries we've already emitted
    emitted_log_count = 0

    try:
        async for event in ghosttrace_graph.astream(initial_state):
            # Each event is a dict with the node name as key and its output as value
            for node_name, node_output in event.items():
                # Emit new stream_log entries
                if "stream_log" in node_output:
                    new_logs = node_output["stream_log"][emitted_log_count:]
                    for msg in new_logs:
                        yield {"type": "log", "message": msg}
                    emitted_log_count = len(node_output["stream_log"])

                # Check for error in node output
                if node_output.get("error"):
                    yield {"type": "error", "message": node_output["error"]}
                    return

                # Emit node_complete event
                yield {
                    "type": "node_complete",
                    "node": node_name,
                    "data": node_output,
                }

                # If this is the arbiter node and we have a final report, emit complete
                if node_name == "arbiter" and node_output.get("final_report"):
                    yield {
                        "type": "complete",
                        "report": node_output["final_report"],
                    }

    except Exception as e:
        yield {"type": "error", "message": str(e)}
