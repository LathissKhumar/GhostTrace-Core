"""GhostTrace FastAPI Application.

Production-grade FastAPI backend for the GhostTrace adversarial multi-agent
debate system. Handles evidence upload, debate streaming via SSE, case listing,
health checks, structured logging, rate limiting, and global error handling.
"""

import sys
from pathlib import Path

# Ensure the backend directory is on sys.path so agent imports work
sys.path.insert(0, str(Path(__file__).parent))

import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from benchmark.runner import BenchmarkRunner
from config import settings
from graph import async_stream_graph
from llm_client import LLM_PROVIDER, get_model_name
from logging_config import log_event, setup_logging
from middleware import RateLimitMiddleware, RequestIDMiddleware, TimingMiddleware
from mcp_tools.server import load_evidence
from parsers import auto_detect_and_parse, list_supported_formats, validate_evidence

# Configure structured logging at import time
setup_logging(level=settings.log_level, format_type=settings.log_format)
logger = logging.getLogger(__name__)

# Application version
APP_VERSION = "1.1.0"

# Valid artifact types recognized by the system
VALID_ARTIFACT_TYPES = [
    "process_tree",
    "network_logs",
    "file_events",
    "registry_changes",
    "auth_logs",
]

# Module-level in-memory evidence store
_evidence_store: dict[str, dict] = {}

CASES_DIR = Path(settings.cases_dir)
CASES_DIR.mkdir(exist_ok=True)


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    status: str = Field(default="completed")
    evidence_summary: str = Field(default="")
    attacker_output: dict = Field(default_factory=dict)
    skeptic_output: dict = Field(default_factory=dict)
    arbiter_report: dict = Field(default_factory=dict)
    confidence_score: int = Field(default=0, ge=0, le=100)
    kill_chain_stages: list = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None)
    status: str | None = Field(default=None)


def _read_case(case_id: str) -> dict | None:
    case_path = CASES_DIR / f"{case_id}.json"
    if not case_path.exists():
        return None
    try:
        with open(case_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read case %s: %s", case_id, e)
        return None


def _write_case(case_id: str, data: dict) -> None:
    case_path = CASES_DIR / f"{case_id}.json"
    try:
        with open(case_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except OSError as e:
        logger.error("Failed to write case %s: %s", case_id, e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to persist case to disk: {e}",
        ) from e


def _delete_case_file(case_id: str) -> bool:
    case_path = CASES_DIR / f"{case_id}.json"
    if case_path.exists():
        try:
            case_path.unlink()
            return True
        except OSError as e:
            logger.error("Failed to delete case %s: %s", case_id, e)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete case from disk: {e}",
            ) from e
    return False


def _list_all_cases() -> list[dict]:
    cases: list[dict] = []
    for case_file in CASES_DIR.glob("*.json"):
        try:
            with open(case_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            cases.append({
                "id": data.get("id", case_file.stem),
                "title": data.get("title", "Untitled"),
                "status": data.get("status", "unknown"),
                "confidence_score": data.get("confidence_score", 0),
                "createdAt": data.get("createdAt", ""),
                "updatedAt": data.get("updatedAt", ""),
                "evidence_summary": data.get("evidence_summary", ""),
                "kill_chain_stages": data.get("kill_chain_stages", []),
            })
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Skipping corrupt case file %s: %s", case_file.name, e)
            continue
    cases.sort(key=lambda c: c.get("createdAt", ""), reverse=True)
    return cases


# ---------------------------------------------------------------------------
# Lifespan: startup / shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler — runs at startup and shutdown."""
    log_event(
        logger,
        logging.INFO,
        "GhostTrace starting",
        version=APP_VERSION,
        provider=LLM_PROVIDER,
        model=get_model_name(),
        host=settings.host,
        port=settings.port,
        cors_origins=settings.cors_origins,
        rate_limit_per_minute=settings.rate_limit_per_minute,
    )
    yield
    # Graceful shutdown
    log_event(
        logger,
        logging.INFO,
        "GhostTrace shutting down",
        cases_in_memory=len(_evidence_store),
    )
    _evidence_store.clear()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="GhostTrace",
    version=APP_VERSION,
    description="Adversarial multi-agent debate system for cybersecurity incident response",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware — order matters (outermost = first to execute)
# 1. RequestIDMiddleware  — injects request ID into logs
# 2. RateLimitMiddleware  — blocks excessive requests early
# 3. TimingMiddleware     — logs duration after response
# 4. CORSMiddleware       — handles CORS preflight
# ---------------------------------------------------------------------------

# CORS middleware (FastAPI built-in)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware (outermost first)
app.add_middleware(TimingMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
app.add_middleware(RequestIDMiddleware)

# Serve sample evidence files as static assets
evidence_dir = Path(__file__).parent / "evidence"
if evidence_dir.exists():
    app.mount("/evidence", StaticFiles(directory=str(evidence_dir)), name="evidence")


# ---------------------------------------------------------------------------
# Global error handlers
# ---------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return structured JSON for all HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
            "status_code": exc.status_code,
            "request_id": getattr(request.state, "request_id", "-"),
        },
    )


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """Handle Pydantic validation errors with structured response."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "detail": exc.errors(),
            "request_id": getattr(request.state, "request_id", "-"),
        },
    )


@app.exception_handler(json.JSONDecodeError)
async def json_decode_exception_handler(request: Request, exc: json.JSONDecodeError) -> JSONResponse:
    """Handle JSON parsing errors gracefully."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "invalid_json",
            "detail": f"Failed to parse JSON: {exc.msg}",
            "request_id": getattr(request.state, "request_id", "-"),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler — returns structured JSON instead of HTML stack traces."""
    logger.error(
        "Unhandled exception: %s %s — %s",
        request.method,
        request.url.path,
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": "An unexpected error occurred. Please try again later.",
            "request_id": getattr(request.state, "request_id", "-"),
        },
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
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
            the configured max size, 422 if artifacts structure is missing or invalid.
    """
    # Read file content
    content = await file.read()

    # Check file size
    if len(content) > settings.max_upload_size_bytes:
        max_mb = settings.max_upload_size_bytes // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds maximum allowed size of {max_mb}MB.",
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

    log_event(
        logger,
        logging.INFO,
        "Evidence uploaded",
        case_id=case_id,
        artifact_types=found_types,
        total_artifacts=total_artifacts,
    )

    return {
        "case_id": case_id,
        "artifact_types": found_types,
        "total_artifacts": total_artifacts,
        "status": "ready",
    }


# ---------------------------------------------------------------------------
# Evidence Parsers
# ---------------------------------------------------------------------------


@app.post("/api/parse")
async def parse_evidence_file(file: UploadFile) -> dict:
    """Parse an uploaded raw log file (CSV, Zeek, Sysmon, text) into GhostTrace evidence format.

    Auto-detects the format, parses into the standard evidence bundle,
    validates it, stores it for debate, and returns the parsed result.
    """
    content = await file.read()

    if len(content) > settings.max_upload_size_bytes:
        max_mb = settings.max_upload_size_bytes // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"File exceeds {max_mb}MB limit.")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown.log"

    try:
        evidence_data = auto_detect_and_parse(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("Parse error for %s: %s", filename, e)
        raise HTTPException(status_code=500, detail=f"Failed to parse file: {e}")

    # Validate the parsed evidence
    is_valid, errors = validate_evidence(evidence_data)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail=f"Parsed file produced invalid evidence: {'; '.join(errors)}",
        )

    # Store for debate
    case_id = evidence_data.get("case_id", f"PARSED-{uuid.uuid4().hex[:8].upper()}")
    evidence_data["case_id"] = case_id
    _evidence_store[case_id] = evidence_data
    load_evidence(evidence_data)

    # Count artifacts
    artifacts = evidence_data.get("artifacts", {})
    total = sum(len(v) for v in artifacts.values() if isinstance(v, list))

    log_event(
        logger, logging.INFO, "Evidence parsed",
        case_id=case_id, parser=evidence_data.get("parser", "unknown"),
        filename=filename, artifact_count=total,
    )

    return {
        "case_id": case_id,
        "parser": evidence_data.get("parser", "unknown"),
        "artifact_types": [k for k, v in artifacts.items() if isinstance(v, list) and v],
        "total_artifacts": total,
        "metadata": evidence_data.get("metadata", {}),
        "status": "ready",
    }


@app.get("/api/formats")
async def get_supported_formats() -> list[dict]:
    """Return metadata about all supported evidence input formats."""
    return list_supported_formats()


@app.post("/api/parse/preview")
async def preview_parsed_evidence(file: UploadFile) -> dict:
    """Parse a file and return the evidence bundle without storing it.

    Useful for letting users preview what their log file will look like
    before committing to a full analysis pipeline.
    """
    content = await file.read()

    if len(content) > settings.max_upload_size_bytes:
        max_mb = settings.max_upload_size_bytes // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"File exceeds {max_mb}MB limit.")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown.log"

    try:
        evidence_data = auto_detect_and_parse(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("Preview parse error for %s: %s", filename, e)
        raise HTTPException(status_code=500, detail=f"Failed to parse file: {e}")

    is_valid, errors = validate_evidence(evidence_data)
    artifacts = evidence_data.get("artifacts", {})
    total = sum(len(v) for v in artifacts.values() if isinstance(v, list))

    # Truncate large artifact lists for preview (max 5 items each)
    preview_artifacts = {}
    for k, v in artifacts.items():
        if isinstance(v, list):
            preview_artifacts[k] = v[:5]
            preview_artifacts[f"{k}_total"] = len(v)
        else:
            preview_artifacts[k] = v

    return {
        "parser": evidence_data.get("parser", "unknown"),
        "is_valid": is_valid,
        "errors": errors,
        "total_artifacts": total,
        "preview": preview_artifacts,
        "metadata": evidence_data.get("metadata", {}),
    }


@app.get("/run")
async def run_debate(case_id: str) -> StreamingResponse:
    """Initiate a debate for the given case and stream results via SSE.

    Looks up the evidence bundle by case_id, then returns a Server-Sent Events
    stream that delivers real-time debate progress as the LangGraph pipeline
    executes the Attacker -> Skeptic -> Arbiter sequence.

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

    log_event(
        logger,
        logging.INFO,
        "Debate started",
        case_id=case_id,
        artifact_types=list(evidence_json.get("artifacts", {}).keys()),
    )

    async def event_generator():
        """Async generator that yields SSE-formatted events from the debate pipeline."""
        try:
            async for item in async_stream_graph(evidence_json, case_id):
                yield f"data: {json.dumps(item)}\n\n"
        except Exception as e:
            logger.error("SSE stream error for case %s: %s", case_id, e)
            error_event = {
                "type": "error",
                "message": f"Stream error: {str(e)}",
            }
            yield f"data: {json.dumps(error_event)}\n\n"

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
    """Return system health status, version, and configured model name.

    Used by Railway/Render for health probes. Returns a degraded status
    with a warning if the required API key for the selected provider
    is not configured.

    Returns:
        A dict with status, version, provider, model, and optional warning.
    """
    warning = None
    status = "ok"

    if LLM_PROVIDER == "groq" and not settings.groq_api_key:
        warning = "GROQ_API_KEY not configured — LLM calls will fail"
        status = "degraded"
    elif LLM_PROVIDER == "anthropic" and not settings.anthropic_api_key:
        warning = "ANTHROPIC_API_KEY not configured — LLM calls will fail"
        status = "degraded"

    result: dict[str, Any] = {
        "status": status,
        "version": APP_VERSION,
        "provider": LLM_PROVIDER,
        "model": get_model_name(),
    }
    if warning:
        result["warning"] = warning

    return result


@app.post("/api/cases", status_code=201)
async def create_case(payload: CaseCreate) -> dict:
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    case_data = {
        "id": case_id,
        "title": payload.title,
        "status": payload.status,
        "evidence_summary": payload.evidence_summary,
        "attacker_output": payload.attacker_output,
        "skeptic_output": payload.skeptic_output,
        "arbiter_report": payload.arbiter_report,
        "confidence_score": payload.confidence_score,
        "kill_chain_stages": payload.kill_chain_stages,
        "createdAt": now,
        "updatedAt": now,
    }
    _write_case(case_id, case_data)
    log_event(logger, logging.INFO, "Case saved", case_id=case_id, title=payload.title)
    return case_data


@app.get("/api/cases")
async def list_case_history() -> list[dict]:
    return _list_all_cases()


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str) -> dict:
    case_data = _read_case(case_id)
    if case_data is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case_data


@app.put("/api/cases/{case_id}")
async def update_case(case_id: str, payload: CaseUpdate) -> dict:
    case_data = _read_case(case_id)
    if case_data is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    if payload.title is not None:
        case_data["title"] = payload.title
    if payload.notes is not None:
        case_data["notes"] = payload.notes
    if payload.status is not None:
        case_data["status"] = payload.status
    case_data["updatedAt"] = datetime.now(timezone.utc).isoformat()

    _write_case(case_id, case_data)
    return case_data


@app.delete("/api/cases/{case_id}", status_code=204)
async def delete_case(case_id: str) -> None:
    deleted = _delete_case_file(case_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")


# ---------------------------------------------------------------------------
# Benchmark Endpoints
# ---------------------------------------------------------------------------

class BenchmarkRequest(BaseModel):
    evidence: dict = Field(..., description="Evidence bundle to benchmark against")


@app.post("/api/benchmark")
async def run_benchmark(payload: BenchmarkRequest) -> dict:
    """Run single-agent vs multi-agent benchmark on the provided evidence.

    Executes both pipelines and returns structured comparison data
    quantifying the adversarial pipeline's impact.

    This is a compute-heavy endpoint — expect 15-30 seconds of latency.
    """
    log_event(logger, logging.INFO, "Benchmark started")
    runner = BenchmarkRunner()

    try:
        result = await runner.run_benchmark(payload.evidence)
    except Exception as e:
        logger.error("Benchmark failed: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Benchmark pipeline failed: {e}",
        )

    log_event(logger, logging.INFO, "Benchmark completed", result=result)
    return result


@app.get("/api/benchmark/demo")
async def get_benchmark_demo(scenario: str | None = None) -> dict:
    """Return pre-computed benchmark results for demo scenarios.

    Args:
        scenario: Optional scenario key ('ransomware', 'insider', 'apt').
            If omitted, returns aggregate results across all three.

    Returns:
        Cached benchmark comparison JSON so judges don't wait for LLM calls.
    """
    runner = BenchmarkRunner()
    try:
        result = runner.get_demo_results(scenario)
    except FileNotFoundError:
        available = list(BenchmarkRunner().get_demo_results().get("results", {}).keys()) if False else []
        raise HTTPException(
            status_code=404,
            detail=f"No pre-computed results for scenario '{scenario}'",
        )
    return result


# ---------------------------------------------------------------------------
# Demo Mode
# ---------------------------------------------------------------------------

DEMO_SCENARIOS_META: list[dict] = [
    {
        "id": "ransomware",
        "title": "Ransomware Attack — LockBit 3.0",
        "description": (
            "Phishing payload triggers PowerShell execution, C2 beaconing "
            "to darkcloud.cc, lateral movement via WMI, and full-disk "
            "encryption with .LOCKED extension."
        ),
        "severity": "critical",
        "file": "sample_ransomware.json",
        "duration": "12 minutes",
    },
    {
        "id": "insider",
        "title": "Insider Threat — Data Exfiltration",
        "description": (
            "Privileged employee accesses HR salary data and finance reports "
            "after hours via VPN, compresses with 7-Zip, and uploads 56 MB "
            "to personal Google Drive."
        ),
        "severity": "high",
        "file": "sample_insider_threat.json",
        "duration": "50 minutes",
    },
    {
        "id": "apt",
        "title": "APT Lateral Movement — Cozy Bear",
        "description": (
            "Compromised svc_deploy account performs Pass-the-Hash, credential "
            "dumping via LSASS MiniDump, WMI/PsExec lateral movement across "
            "domain controllers, and Golden Ticket forged TGT."
        ),
        "severity": "critical",
        "file": "sample_apt_lateral.json",
        "duration": "40 minutes",
    },
]


def _load_demo_file(scenario: dict) -> dict:
    """Read and return raw evidence JSON for a demo scenario."""
    evidence_path = Path(__file__).parent / "evidence" / scenario["file"]
    if not evidence_path.exists():
        return {}
    with open(evidence_path) as f:
        return json.load(f)


def _count_events(evidence_data: dict) -> int:
    """Count total artefact events in an evidence bundle."""
    artifacts = evidence_data.get("artifacts", {})
    return sum(len(v) for v in artifacts.values() if isinstance(v, list))


@app.get("/api/demo/evidence")
async def list_demo_evidence() -> list[dict]:
    """Return all available demo scenarios with metadata and full evidence data."""
    results = []
    for meta in DEMO_SCENARIOS_META:
        evidence_data = _load_demo_file(meta)
        results.append({
            "id": meta["id"],
            "title": meta["title"],
            "description": meta["description"],
            "severity": meta["severity"],
            "event_count": _count_events(evidence_data),
            "duration": meta["duration"],
            "evidence": evidence_data,
        })
    return results


@app.get("/api/demo/evidence/{scenario_id}")
async def get_demo_evidence(scenario_id: str) -> dict:
    """Return a single demo scenario with full evidence and register it for /run."""
    meta = next((s for s in DEMO_SCENARIOS_META if s["id"] == scenario_id), None)
    if meta is None:
        raise HTTPException(
            status_code=404,
            detail=f"Demo scenario '{scenario_id}' not found. "
            f"Available: {[s['id'] for s in DEMO_SCENARIOS_META]}",
        )

    evidence_data = _load_demo_file(meta)
    if not evidence_data:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load evidence file for scenario '{scenario_id}'.",
        )

    case_id = evidence_data.get("case_id", f"DEMO-{uuid.uuid4().hex[:8].upper()}")

    _evidence_store[case_id] = evidence_data
    load_evidence(evidence_data)

    log_event(
        logger,
        logging.INFO,
        "Demo evidence loaded",
        scenario_id=scenario_id,
        case_id=case_id,
    )

    return {
        "id": meta["id"],
        "title": meta["title"],
        "description": meta["description"],
        "severity": meta["severity"],
        "event_count": _count_events(evidence_data),
        "duration": meta["duration"],
        "case_id": case_id,
        "evidence": evidence_data,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower(),
    )
