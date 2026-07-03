"""Shared test fixtures for GhostTrace backend tests.

Provides test client, mock LLM responses, sample evidence bundles,
and common state dictionaries used across all test modules.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure the backend directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Sample evidence bundles
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_evidence() -> dict:
    """Minimal valid evidence bundle with one artifact type."""
    return {
        "case_id": "TEST-001",
        "incident_type": "suspected_ransomware",
        "artifacts": {
            "process_tree": [
                {
                    "timestamp": "2024-01-15T02:14:33Z",
                    "pid": 4520,
                    "ppid": 1200,
                    "name": "powershell.exe",
                    "cmdline": "powershell.exe -enc SQBmACgA...",
                    "user": "svc_backup",
                },
            ],
            "network_logs": [
                {
                    "timestamp": "2024-01-15T02:15:01Z",
                    "src_ip": "10.0.3.45",
                    "dst_ip": "185.220.101.34",
                    "dst_port": 443,
                    "protocol": "https",
                    "bytes_sent": 2048,
                },
            ],
        },
    }


@pytest.fixture
def sample_evidence_large() -> dict:
    """Larger evidence bundle with multiple artifact types."""
    return {
        "case_id": "TEST-002",
        "incident_type": "suspected_apt",
        "artifacts": {
            "process_tree": [
                {
                    "timestamp": "2024-01-15T01:32:15Z",
                    "pid": 1001,
                    "ppid": 500,
                    "name": "cmd.exe",
                    "cmdline": "cmd.exe /c whoami",
                    "user": "svc_monitor",
                },
                {
                    "timestamp": "2024-01-15T01:33:45Z",
                    "pid": 1002,
                    "ppid": 1001,
                    "name": "mimikatz.exe",
                    "cmdline": "mimikatz.exe sekurlsa::logonpasswords",
                    "user": "svc_monitor",
                },
            ],
            "network_logs": [
                {
                    "timestamp": "2024-01-15T01:36:20Z",
                    "src_ip": "10.0.3.45",
                    "dst_ip": "10.0.0.5",
                    "dst_port": 135,
                    "protocol": "wmi",
                    "bytes_sent": 512,
                },
            ],
            "auth_logs": [
                {
                    "timestamp": "2024-01-15T01:30:00Z",
                    "event_id": 4624,
                    "logon_type": 3,
                    "user": "svc_monitor",
                    "src_ip": "203.0.113.50",
                },
            ],
            "file_events": [
                {
                    "timestamp": "2024-01-15T01:40:00Z",
                    "path": "C:\\Windows\\Temp\\exfil\\data.cab",
                    "action": "created",
                    "user": "svc_monitor",
                },
            ],
        },
    }


@pytest.fixture
def sample_attacker_output() -> dict:
    """Valid attacker output dict matching AttackerOutput schema."""
    return {
        "hypothesis": "Ransomware deployment via compromised service account with lateral movement.",
        "kill_chain": [
            {
                "stage": "Initial Access",
                "claim": "svc_backup account compromised via external IP",
                "evidence": "auth_logs: svc_backup logon Type 3 from 10.0.5.200 at 02:10:00",
                "mitre_technique": "T1078",
                "confidence": 85,
            },
            {
                "stage": "Execution",
                "claim": "PowerShell execution from staged binary",
                "evidence": "process_tree: powershell.exe (PID 4520) spawned by svchost32.exe at 02:14:33",
                "mitre_technique": "T1059.001",
                "confidence": 90,
            },
        ],
        "attribution": "Likely financially motivated threat actor using LockBit 3.0 toolset",
        "first_seen": "2024-01-15T02:10:00Z",
        "recommended_immediate_action": "Isolate affected endpoints from network immediately",
    }


@pytest.fixture
def sample_skeptic_output() -> dict:
    """Valid skeptic output dict matching SkepticOutput schema."""
    return {
        "overall_assessment": "The narrative is partially supported. Kill chain stages have varying evidence quality.",
        "challenges": [
            {
                "claim_challenged": "svc_backup account compromised via external IP",
                "verdict": "SUSTAINED",
                "reasoning": "The auth log entry at 02:10:00 shows Type 3 logon from 10.0.5.200 which is external.",
                "critical_gap": "No additional evidence needed.",
            },
            {
                "claim_challenged": "PowerShell execution from staged binary",
                "verdict": "NEEDS_MORE_EVIDENCE",
                "reasoning": "PID chain is plausible but svchost32.exe origin is unclear.",
                "critical_gap": "Need file_events showing svchost32.exe creation.",
            },
        ],
        "unchallenged_claims": [],
        "do_not_do": "Do not isolate endpoints without verifying all affected systems first.",
    }


@pytest.fixture
def sample_arbiter_output() -> dict:
    """Valid arbiter output dict matching ArbiterReportModel schema."""
    return {
        "incident_summary": "Confirmed ransomware deployment via compromised service account.",
        "classification": "Probable",
        "overall_confidence": 72,
        "confirmed_findings": [
            {
                "finding": "Service account compromise via external IP",
                "mitre_technique": "T1078",
                "confidence": 100,
            },
        ],
        "unresolved_items": [
            {
                "item": "PowerShell execution origin",
                "required_evidence": "File events showing svchost32.exe creation",
                "confidence": 50,
            },
        ],
        "recommended_actions": [
            "Isolate affected endpoints",
            "Reset all service account credentials",
        ],
        "excluded_claims": [],
        "skeptic_key_flag": "svchost32.exe origin unknown — could be legitimate binary",
    }


# ---------------------------------------------------------------------------
# Mock LLM responses (raw text format agents expect)
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_attacker_raw_response() -> str:
    """Raw JSON string the attacker agent would receive from LLM."""
    return json.dumps(
        {
            "hypothesis": "Ransomware deployment via compromised service account.",
            "kill_chain": [
                {
                    "stage": "Initial Access",
                    "claim": "svc_backup account compromised",
                    "evidence": "auth_logs: Type 3 logon from 10.0.5.200",
                    "mitre_technique": "T1078",
                    "confidence": 85,
                },
            ],
            "attribution": "Financially motivated threat actor",
            "first_seen": "2024-01-15T02:10:00Z",
            "recommended_immediate_action": "Isolate affected endpoints",
        }
    )


@pytest.fixture
def mock_skeptic_raw_response() -> str:
    """Raw JSON string the skeptic agent would receive from LLM."""
    return json.dumps(
        {
            "overall_assessment": "Partially supported narrative.",
            "challenges": [
                {
                    "claim_challenged": "svc_backup account compromised",
                    "verdict": "SUSTAINED",
                    "reasoning": "Auth log entry directly corroborates.",
                    "critical_gap": "None",
                },
            ],
            "unchallenged_claims": [],
            "do_not_do": "Do not act on unverified claims.",
        }
    )


@pytest.fixture
def mock_arbiter_raw_response() -> str:
    """Raw JSON string the arbiter agent would receive from LLM."""
    return json.dumps(
        {
            "incident_summary": "Service account compromise confirmed.",
            "classification": "Probable",
            "overall_confidence": 85,
            "confirmed_findings": [
                {"finding": "Service account compromise", "mitre_technique": "T1078", "confidence": 100},
            ],
            "unresolved_items": [],
            "recommended_actions": ["Isolate endpoints"],
            "excluded_claims": [],
            "skeptic_key_flag": "No critical gaps found",
        }
    )


# ---------------------------------------------------------------------------
# State fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def base_state(sample_evidence) -> dict:
    """Initial GhostTraceState before any agent runs."""
    return {
        "case_id": "TEST-001",
        "evidence_json": sample_evidence,
        "attacker_narrative": None,
        "attacker_parsed": None,
        "skeptic_rebuttal": None,
        "skeptic_parsed": None,
        "final_report": None,
        "stream_log": [],
        "error": None,
    }


@pytest.fixture
def post_attacker_state(base_state, mock_attacker_raw_response, sample_attacker_output):
    """State after attacker node has run."""
    base_state["attacker_narrative"] = mock_attacker_raw_response
    base_state["attacker_parsed"] = sample_attacker_output
    base_state["stream_log"] = [
        "🔴 Attacker Agent: Analyzing 2 artifact types...",
        "🔴 Attacker Agent: Narrative complete — 2 kill chain stages identified",
    ]
    return base_state


# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    """FastAPI TestClient with evidence store reset."""
    from main import app, _evidence_store

    # Clear evidence store before each test
    _evidence_store.clear()

    with TestClient(app) as c:
        yield c

    # Clear after test too
    _evidence_store.clear()


# ---------------------------------------------------------------------------
# Temp directory for case files
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_cases_dir(tmp_path):
    """Provide a temporary cases directory and patch settings."""
    with patch("main.CASES_DIR", tmp_path), patch("main.settings") as mock_settings:
        mock_settings.cases_dir = str(tmp_path)
        mock_settings.groq_api_key = "test-key"
        mock_settings.anthropic_api_key = "test-key"
        mock_settings.rate_limit_per_minute = 1000
        mock_settings.max_upload_size_bytes = 10 * 1024 * 1024
        mock_settings.cors_origins = ["*"]
        mock_settings.log_level = "INFO"
        mock_settings.log_format = "readable"
        yield tmp_path
