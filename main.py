"""GhostTrace FastAPI Application.

This module defines the main FastAPI application with all API routes for the
GhostTrace adversarial multi-agent debate system. It handles evidence upload,
debate streaming via SSE, case listing, and health checks.
"""

import sys
from pathlib import Path

# Ensure the backend directory is on sys.path so agent imports work
sys.path.insert(0, str(Path(__file__).parent))

import json
import logging
import os
import uuid

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from graph import async_stream_graph
from mcp_tools.server import load_evidence
from llm_client import LLM_PROVIDER, GROQ_MODEL, OLLAMA_MODEL, get_model_name

# Load environment variables from .env file
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)

# Load API key from environment (only needed for Anthropic provider)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

if LLM_PROVIDER == "anthropic" and not ANTHROPIC_API_KEY:
    logger.warning(
        "ANTHROPIC_API_KEY environment variable is not set. "
        "Agent-dependent endpoints will return HTTP 503 until configured."
    )
elif LLM_PROVIDER == "groq" and not GROQ_API_KEY:
    logger.warning(
        "GROQ_API_KEY environment variable is not set. "
        "Get a free key at https://console.groq.com"
    )
elif LLM_PROVIDER == "groq":
    logger.info(f"Using Groq (free cloud) with model: {GROQ_MODEL}")
elif LLM_PROVIDER == "ollama":
    logger.info(f"Using Ollama (free, local) with model: {OLLAMA_MODEL}")

# Valid artifact types recognized by the system
VALID_ARTIFACT_TYPES = [
    "process_tree",
    "network_logs",
    "file_events",
    "registry_changes",
    "auth_logs",
]

# Maximum upload file size: 10 MB
MAX_FILE_SIZE = 10 * 1024 * 1024

# Module-level in-memory evidence store
_evidence_store: dict[str, dict] = {}

# FastAPI application instance
app = FastAPI(title="GhostTrace", version="1.0.0")

# Serve sample evidence files as static assets
evidence_dir = Path(__file__).parent / "evidence"
if evidence_dir.exists():
    app.mount("/evidence", StaticFiles(directory=str(evidence_dir)), name="evidence")

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/upload")
async def upload_evidence(file: UploadFile) -> dict:
    """Accept an evidence JSON file upload and store it for analysis.

    Parses the uploaded file as JSON, validates that it contains at least one
    recognized artifact type within an "artifacts" object, checks file size,
    and stores the evidence in memory keyed by case_id.

    Args:
        file: The uploaded file (multipart form data).

    Returns:
        A dict with case_id, artifact_types found, total_artifacts count,
        and status "ready".

    Raises:
        HTTPException: 400 if file is not valid JSON, 413 if file exceeds
            10MB, 422 if artifacts structure is missing or invalid.
    """
    # Read file content
    content = await file.read()

    # Check file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File size exceeds maximum allowed size of 10MB.",
        )

    # Parse as JSON
    try:
        evidence_data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON: {str(e)}",
        )

    # Validate "artifacts" key exists
    if "artifacts" not in evidence_data or not isinstance(evidence_data["artifacts"], dict):
        raise HTTPException(
            status_code=422,
            detail=(
                "Missing or malformed 'artifacts' object. "
                "Expected a JSON object with an 'artifacts' key containing "
                "at least one recognized artifact type: "
                f"{VALID_ARTIFACT_TYPES}"
            ),
        )

    # Validate at least one valid artifact type exists
    artifacts = evidence_data["artifacts"]
    found_types = [t for t in VALID_ARTIFACT_TYPES if t in artifacts and artifacts[t]]
    if not found_types:
        raise HTTPException(
            status_code=422,
            detail=(
                "No recognized artifact types found in 'artifacts' object. "
                f"Expected at least one of: {VALID_ARTIFACT_TYPES}"
            ),
        )

    # Extract or generate case_id
    case_id = evidence_data.get("case_id", f"IR-{uuid.uuid4().hex[:8].upper()}")

    # Count total artifacts
    total_artifacts = sum(
        len(artifacts[t]) for t in found_types if isinstance(artifacts[t], list)
    )

    # Store in evidence store
    _evidence_store[case_id] = evidence_data

    # Load evidence into MCP tools server
    load_evidence(evidence_data)

    return {
        "case_id": case_id,
        "artifact_types": found_types,
        "total_artifacts": total_artifacts,
        "status": "ready",
    }


@app.get("/run")
async def run_debate(case_id: str) -> StreamingResponse:
    """Initiate a debate for the given case and stream results via SSE.

    Looks up the evidence bundle by case_id, then returns a Server-Sent Events
    stream that delivers real-time debate progress as the LangGraph pipeline
    executes the Attacker → Skeptic → Arbiter sequence.

    Args:
        case_id: The unique identifier of a previously uploaded evidence bundle.

    Returns:
        A StreamingResponse with media_type text/event-stream.

    Raises:
        HTTPException: 404 if case_id is not found in the evidence store.
    """
    if case_id not in _evidence_store:
        # Try to auto-load from preset evidence files
        preset_map = {
            "IR-2024-001": "sample_ransomware.json",
            "IR-2024-002": "sample_insider_threat.json",
            "IR-2024-003": "sample_apt_lateral.json",
        }
        if case_id in preset_map:
            evidence_path = Path(__file__).parent / "evidence" / preset_map[case_id]
            if evidence_path.exists():
                with open(evidence_path) as f:
                    evidence_data = json.load(f)
                _evidence_store[case_id] = evidence_data
                load_evidence(evidence_data)

    if case_id not in _evidence_store:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id}' not found. Upload evidence first.",
        )

    evidence_json = _evidence_store[case_id]

    async def event_generator():
        """Async generator that yields SSE-formatted events from the debate pipeline."""
        async for item in async_stream_graph(evidence_json, case_id):
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/cases")
async def list_cases() -> list[dict]:
    """Return a list of case metadata from the in-memory evidence store.

    Each entry includes the case_id, incident_type (if available), and
    the count of artifact types present in the evidence bundle.

    Returns:
        A list of dicts with case metadata.
    """
    cases = []
    for case_id, evidence_data in _evidence_store.items():
        artifacts = evidence_data.get("artifacts", {})
        artifact_count = sum(
            len(v) for v in artifacts.values() if isinstance(v, list)
        )
        cases.append({
            "case_id": case_id,
            "incident_type": evidence_data.get("incident_type", "unknown"),
            "artifact_count": artifact_count,
        })
    return cases


@app.get("/health")
async def health_check() -> dict:
    """Return system health status and configured model name.

    Returns a degraded status with a warning if the ANTHROPIC_API_KEY
    environment variable is not configured.

    Returns:
        A dict with status, model name, and optional warning.
    """
    if LLM_PROVIDER == "anthropic" and not ANTHROPIC_API_KEY:
        return {
            "status": "degraded",
            "provider": "anthropic",
            "model": get_model_name(),
            "warning": "ANTHROPIC_API_KEY not configured",
        }
    return {
        "status": "ok",
        "provider": LLM_PROVIDER,
        "model": get_model_name(),
    }
