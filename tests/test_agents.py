"""Tests for GhostTrace agent nodes (attacker, skeptic, arbiter).

Each agent node receives GhostTraceState and returns updated state fields.
All LLM calls are mocked — no real API calls are made.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestAttackerNode:
    """Tests for agents.attacker.attacker_node"""

    @pytest.mark.asyncio
    async def test_attacker_returns_narrative(self, base_state, mock_attacker_raw_response):
        with patch("agents.attacker.call_llm", return_value=mock_attacker_raw_response):
            from agents.attacker import attacker_node

            result = await attacker_node(base_state)

        assert result["attacker_narrative"] == mock_attacker_raw_response
        assert result["attacker_parsed"] is not None
        assert result["attacker_parsed"]["hypothesis"]
        assert len(result["attacker_parsed"]["kill_chain"]) >= 1

    @pytest.mark.asyncio
    async def test_attacker_stream_log_updated(self, base_state, mock_attacker_raw_response):
        with patch("agents.attacker.call_llm", return_value=mock_attacker_raw_response):
            from agents.attacker import attacker_node

            result = await attacker_node(base_state)

        assert len(result["stream_log"]) >= 2
        assert any("Attacker Agent" in msg for msg in result["stream_log"])

    @pytest.mark.asyncio
    async def test_attacker_error_handling(self, base_state):
        with patch("agents.attacker.call_llm", side_effect=Exception("LLM failed")):
            from agents.attacker import attacker_node

            result = await attacker_node(base_state)

        assert result["attacker_parsed"] is None
        assert result["attacker_narrative"] is None
        assert result["error"] is not None
        assert "LLM failed" in result["error"]

    @pytest.mark.asyncio
    async def test_attacker_validates_output_schema(self, base_state):
        """Ensure AttackerOutput Pydantic validation works."""
        bad_response = json.dumps({"hypothesis": "test"})  # missing required fields
        with patch("agents.attacker.call_llm", return_value=bad_response):
            from agents.attacker import attacker_node

            result = await attacker_node(base_state)

        assert result["attacker_parsed"] is None
        assert result["error"] is not None


class TestSkepticNode:
    """Tests for agents.skeptic.skeptic_node"""

    @pytest.mark.asyncio
    async def test_skeptic_returns_rebuttal(self, post_attacker_state, mock_skeptic_raw_response):
        with patch("agents.skeptic.acall_llm", new_callable=AsyncMock, return_value=mock_skeptic_raw_response):
            from agents.skeptic import skeptic_node

            result = await skeptic_node(post_attacker_state)

        assert result["skeptic_rebuttal"] == mock_skeptic_raw_response
        assert result["skeptic_parsed"] is not None
        assert "challenges" in result["skeptic_parsed"]

    @pytest.mark.asyncio
    async def test_skeptic_skips_when_no_attacker(self, base_state):
        """Skeptic should skip gracefully if attacker_narrative is missing."""
        from agents.skeptic import skeptic_node

        result = await skeptic_node(base_state)

        assert result["skeptic_rebuttal"] is None
        assert result["skeptic_parsed"] is None
        assert result["error"] is not None
        assert "missing" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_skeptic_error_handling(self, post_attacker_state):
        with patch("agents.skeptic.acall_llm", new_callable=AsyncMock, side_effect=Exception("LLM failed")):
            from agents.skeptic import skeptic_node

            result = await skeptic_node(post_attacker_state)

        assert result["skeptic_parsed"] is None
        assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_skeptic_stream_log_updated(self, post_attacker_state, mock_skeptic_raw_response):
        with patch("agents.skeptic.acall_llm", new_callable=AsyncMock, return_value=mock_skeptic_raw_response):
            from agents.skeptic import skeptic_node

            result = await skeptic_node(post_attacker_state)

        assert len(result["stream_log"]) > len(post_attacker_state["stream_log"])

    @pytest.mark.asyncio
    async def test_skeptic_counts_verdicts(self, post_attacker_state, mock_skeptic_raw_response):
        with patch("agents.skeptic.acall_llm", new_callable=AsyncMock, return_value=mock_skeptic_raw_response):
            from agents.skeptic import skeptic_node

            result = await skeptic_node(post_attacker_state)

        log_messages = " ".join(result["stream_log"])
        assert "sustained" in log_messages.lower() or "challenged" in log_messages.lower()


class TestArbiterNode:
    """Tests for agents.arbiter.arbiter_node"""

    @pytest.mark.asyncio
    async def test_arbiter_returns_report(self, post_attacker_state, mock_skeptic_raw_response, mock_arbiter_raw_response):
        state = post_attacker_state.copy()
        state["skeptic_rebuttal"] = mock_skeptic_raw_response
        state["skeptic_parsed"] = {
            "overall_assessment": "Partially supported",
            "challenges": [],
            "unchallenged_claims": [],
            "do_not_do": "Don't act on unverified claims",
        }

        with patch("agents.arbiter.call_llm", return_value=mock_arbiter_raw_response):
            from agents.arbiter import arbiter_node

            result = await arbiter_node(state)

        assert result["final_report"] is not None
        assert "incident_summary" in result["final_report"]
        assert "overall_confidence" in result["final_report"]

    @pytest.mark.asyncio
    async def test_arbiter_skips_without_attacker(self, base_state):
        from agents.arbiter import arbiter_node

        result = await arbiter_node(base_state)

        assert result.get("final_report") is None
        assert result["error"] is not None
        assert "attacker" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_arbiter_skips_without_skeptic(self, post_attacker_state):
        from agents.arbiter import arbiter_node

        result = await arbiter_node(post_attacker_state)

        assert result.get("final_report") is None
        assert result["error"] is not None
        assert "skeptic" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_arbiter_overrides_confidence(self, post_attacker_state, mock_skeptic_raw_response):
        """Arbiter should use compute_overall_confidence to override LLM score."""
        state = post_attacker_state.copy()
        state["skeptic_rebuttal"] = mock_skeptic_raw_response
        state["skeptic_parsed"] = {
            "overall_assessment": "Partially supported",
            "challenges": [],
            "unchallenged_claims": [],
            "do_not_do": "Don't act on unverified claims",
        }

        # LLM returns confidence=99, but compute_overall_confidence should override
        arbiter_response = json.dumps({
            "incident_summary": "Test incident",
            "classification": "Confirmed",
            "overall_confidence": 99,
            "confirmed_findings": [],
            "unresolved_items": [],
            "recommended_actions": ["Isolate"],
            "excluded_claims": [],
            "skeptic_key_flag": "No issues",
        })

        with patch("agents.arbiter.call_llm", return_value=arbiter_response):
            from agents.arbiter import arbiter_node

            result = await arbiter_node(state)

        # With no findings, score should be 0 (not 99)
        assert result["final_report"]["overall_confidence"] == 0

    @pytest.mark.asyncio
    async def test_arbiter_error_handling(self, post_attacker_state, mock_skeptic_raw_response):
        state = post_attacker_state.copy()
        state["skeptic_rebuttal"] = mock_skeptic_raw_response
        state["skeptic_parsed"] = {"overall_assessment": "test", "challenges": [], "unchallenged_claims": [], "do_not_do": "test"}

        with patch("agents.arbiter.call_llm", side_effect=Exception("LLM failed")):
            from agents.arbiter import arbiter_node

            result = await arbiter_node(state)

        assert result.get("final_report") is None
        assert result["error"] is not None
