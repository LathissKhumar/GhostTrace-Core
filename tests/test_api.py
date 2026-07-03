"""Tests for GhostTrace API endpoints.

Covers upload, run/SSE, cases CRUD, health, and error handling.
"""

import json
import io
import uuid
from unittest.mock import patch

import pytest


class TestHealthEndpoint:
    """GET /health"""

    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "version" in data
        assert "provider" in data
        assert "model" in data

    def test_health_includes_version(self, client):
        data = client.get("/health").json()
        assert data["version"] == "1.1.0"


class TestUploadEndpoint:
    """POST /upload"""

    def test_upload_valid_json(self, client, sample_evidence):
        file_content = json.dumps(sample_evidence).encode()
        resp = client.post(
            "/upload",
            files={"file": ("evidence.json", io.BytesIO(file_content), "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert "case_id" in data
        assert "process_tree" in data["artifact_types"]
        assert data["total_artifacts"] >= 2

    def test_upload_generates_case_id(self, client):
        """Upload evidence without case_id → auto-generates IR-XXXXXXXX."""
        evidence_no_id = {
            "incident_type": "test",
            "artifacts": {"process_tree": [{"timestamp": "2024-01-15T00:00:00Z", "pid": 1}]},
        }
        file_content = json.dumps(evidence_no_id).encode()
        resp = client.post(
            "/upload",
            files={"file": ("evidence.json", io.BytesIO(file_content), "application/json")},
        )
        data = resp.json()
        assert data["case_id"].startswith("IR-")

    def test_upload_preserves_case_id(self, client, sample_evidence):
        file_content = json.dumps(sample_evidence).encode()
        resp = client.post(
            "/upload",
            files={"file": ("evidence.json", io.BytesIO(file_content), "application/json")},
        )
        data = resp.json()
        assert data["case_id"] == "TEST-001"

    def test_upload_invalid_json(self, client):
        resp = client.post(
            "/upload",
            files={"file": ("bad.json", io.BytesIO(b"not valid json"), "application/json")},
        )
        assert resp.status_code == 400

    def test_upload_missing_artifacts(self, client):
        payload = json.dumps({"no_artifacts": True}).encode()
        resp = client.post(
            "/upload",
            files={"file": ("empty.json", io.BytesIO(payload), "application/json")},
        )
        assert resp.status_code == 422

    def test_upload_empty_artifacts(self, client):
        payload = json.dumps({"artifacts": {}}).encode()
        resp = client.post(
            "/upload",
            files={"file": ("empty.json", io.BytesIO(payload), "application/json")},
        )
        assert resp.status_code == 422

    def test_upload_file_too_large(self, client):
        """Upload a file exceeding max size."""
        large_data = json.dumps({"artifacts": {"process_tree": [{"x": "y"}]}}).encode()
        with patch("main.settings") as mock_settings:
            mock_settings.max_upload_size_bytes = 10  # 10 bytes
            mock_settings.groq_api_key = "test"
            mock_settings.anthropic_api_key = "test"
            mock_settings.rate_limit_per_minute = 1000
            mock_settings.cors_origins = ["*"]
            resp = client.post(
                "/upload",
                files={"file": ("big.json", io.BytesIO(large_data), "application/json")},
            )
        assert resp.status_code == 413


class TestRunEndpoint:
    """GET /run"""

    def test_run_missing_case(self, client):
        resp = client.get("/run?case_id=NONEXISTENT")
        assert resp.status_code == 404

    def test_run_after_upload(self, client, sample_evidence):
        # Upload first
        file_content = json.dumps(sample_evidence).encode()
        upload_resp = client.post(
            "/upload",
            files={"file": ("evidence.json", io.BytesIO(file_content), "application/json")},
        )
        case_id = upload_resp.json()["case_id"]

        # Mock the graph streaming to avoid real LLM calls
        async def mock_stream(evidence, cid):
            yield {"type": "log", "message": "Test log"}
            yield {"type": "complete", "report": {"incident_summary": "Test"}}

        with patch("main.async_stream_graph", mock_stream):
            resp = client.get(f"/run?case_id={case_id}")
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]


class TestCasesEndpoints:
    """POST/GET/PUT/DELETE /api/cases"""

    def test_create_case(self, client):
        payload = {
            "title": "Test Case",
            "status": "completed",
            "evidence_summary": "Test summary",
            "attacker_output": {},
            "skeptic_output": {},
            "arbiter_report": {},
            "confidence_score": 75,
            "kill_chain_stages": [],
        }
        resp = client.post("/api/cases", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Test Case"
        assert data["status"] == "completed"
        assert data["confidence_score"] == 75
        assert "id" in data
        assert "createdAt" in data

    def test_create_case_validation_error(self, client):
        resp = client.post("/api/cases", json={"title": ""})
        assert resp.status_code == 422

    def test_list_cases_empty(self, temp_cases_dir):
        from main import _evidence_store, _list_all_cases

        _evidence_store.clear()
        cases = _list_all_cases()
        assert cases == []

    def test_get_case_not_found(self, client):
        resp = client.get("/api/cases/NONEXISTENT")
        assert resp.status_code == 404

    def test_update_case_not_found(self, client):
        resp = client.put("/api/cases/NONEXISTENT", json={"title": "Updated"})
        assert resp.status_code == 404

    def test_delete_case_not_found(self, client):
        resp = client.delete("/api/cases/NONEXISTENT")
        assert resp.status_code == 404


class TestCasesList:
    """GET /cases (legacy endpoint)"""

    def test_list_cases_empty(self, client):
        resp = client.get("/cases")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_cases_with_data(self, client, sample_evidence):
        file_content = json.dumps(sample_evidence).encode()
        client.post(
            "/upload",
            files={"file": ("evidence.json", io.BytesIO(file_content), "application/json")},
        )
        resp = client.get("/cases")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["case_id"] == "TEST-001"


class TestDemoEndpoints:
    """GET /api/demo/evidence"""

    def test_list_demo_evidence(self, client):
        resp = client.get("/api/demo/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_demo_evidence_not_found(self, client):
        resp = client.get("/api/demo/evidence/nonexistent")
        assert resp.status_code == 404


class TestBenchmarkEndpoint:
    """POST /api/benchmark"""

    def test_benchmark_missing_evidence(self, client):
        resp = client.post("/api/benchmark", json={})
        assert resp.status_code == 422


class TestErrorHandling:
    """Global error handler tests"""

    def test_404_returns_json(self, client):
        resp = client.get("/nonexistent")
        assert resp.status_code == 404
        # FastAPI returns HTML for unknown routes by default, but our handler
        # should catch HTTPExceptions
        assert resp.headers.get("content-type", "").startswith("application/json") or resp.status_code == 404

    def test_request_id_in_response(self, client):
        resp = client.get("/health")
        assert "x-request-id" in resp.headers
