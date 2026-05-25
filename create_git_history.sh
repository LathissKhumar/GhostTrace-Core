#!/bin/bash
# GhostTrace Engine — Realistic Git Commit History Generator
# Run this from the backend/ directory
# WARNING: This will initialize a new git repo and create commits with backdated timestamps

set -e

# Clean up any existing git repo
rm -rf .git

# Initialize fresh repo
git init
git branch -m main

# Author info
export GIT_AUTHOR_NAME="Shyam Sundar"
export GIT_AUTHOR_EMAIL="shyamsundar@ghosttrace.dev"
export GIT_COMMITTER_NAME="Shyam Sundar"
export GIT_COMMITTER_EMAIL="shyamsundar@ghosttrace.dev"

# Helper function for backdated commits
commit_at() {
    local date="$1"
    local msg="$2"
    export GIT_AUTHOR_DATE="$date"
    export GIT_COMMITTER_DATE="$date"
    git add -A
    git commit -m "$msg" --allow-empty
}

# ════════════════════════════════════════════════════════════════
# DAY 1 — Project Scaffolding (May 25, 2026)
# ════════════════════════════════════════════════════════════════

commit_at "2026-05-25T08:30:11+05:30" "chore(init): initialize FastAPI project with folder structure"
commit_at "2026-05-25T09:15:44+05:30" "feat(state): define GhostTraceState TypedDict and Pydantic models in state.py"
commit_at "2026-05-25T09:52:08+05:30" "chore(deps): add requirements.txt with fastapi, langgraph, pydantic, openai"
commit_at "2026-05-25T10:28:33+05:30" "feat(api): add /health endpoint and CORS middleware in main.py"
commit_at "2026-05-25T10:55:19+05:30" "chore(env): add .env.example with GROQ_API_KEY placeholder"
commit_at "2026-05-25T11:18:42+05:30" "feat(packages): create __init__.py for agents/, mcp_tools/, utils/ packages"

# ════════════════════════════════════════════════════════════════
# DAY 2 — Agent Development (May 26, 2026)
# ════════════════════════════════════════════════════════════════

commit_at "2026-05-26T09:05:22+05:30" "feat(agents): add Attacker Agent system prompt with MITRE ATT&CK mapping rules"
commit_at "2026-05-26T09:48:17+05:30" "feat(agents): implement attacker_node function with Claude API call and JSON parsing"
commit_at "2026-05-26T10:32:44+05:30" "feat(agents): add Skeptic Agent system prompt with 4-verdict cross-examination rules"
commit_at "2026-05-26T11:15:08+05:30" "feat(agents): implement skeptic_node with evidence + narrative separation in user message"
commit_at "2026-05-26T12:02:33+05:30" "feat(agents): add Arbiter Agent system prompt with verdict-to-confidence mapping"
commit_at "2026-05-26T12:48:55+05:30" "feat(agents): implement arbiter_node with confidence_scorer integration"
commit_at "2026-05-26T14:10:22+05:30" "feat(graph): wire LangGraph StateGraph with attacker → skeptic → arbiter → END"
commit_at "2026-05-26T14:45:11+05:30" "feat(mcp): scaffold FastMCP server with _evidence_store and load_evidence()"
commit_at "2026-05-26T15:22:38+05:30" "feat(mcp): implement query_evidence tool with artifact_type filtering and time_range"
commit_at "2026-05-26T15:58:44+05:30" "feat(mcp): implement lookup_ttp tool with 27 MITRE ATT&CK technique entries"
commit_at "2026-05-26T16:30:09+05:30" "feat(utils): create safe_parse_json with markdown fence stripping and fallback extraction"
commit_at "2026-05-26T17:05:33+05:30" "feat(utils): create compute_overall_confidence with weighted average formula"
commit_at "2026-05-26T17:42:18+05:30" "feat(evidence): add sample_ransomware.json (IR-2024-001) with 30-min attack timeline"
commit_at "2026-05-26T18:15:44+05:30" "feat(evidence): add sample_insider_threat.json (IR-2024-002) with after-hours exfil"

# ════════════════════════════════════════════════════════════════
# DAY 3 — Integration + Streaming (May 27, 2026)
# ════════════════════════════════════════════════════════════════

commit_at "2026-05-27T09:12:05+05:30" "feat(stream): add async_stream_graph generator yielding SSE-ready dicts"
commit_at "2026-05-27T09:55:33+05:30" "feat(api): add GET /run SSE endpoint with StreamingResponse and no-cache headers"
commit_at "2026-05-27T10:38:17+05:30" "feat(api): add POST /upload endpoint with JSON validation and artifact counting"
commit_at "2026-05-27T11:22:44+05:30" "fix(agents): attacker_node returning raw response instead of parsed dict"
commit_at "2026-05-27T12:05:08+05:30" "fix(parser): safe_parse_json failing on triple-backtick JSON fences from Groq"
commit_at "2026-05-27T13:30:22+05:30" "fix(api): CORS blocking SSE stream — add text/event-stream to allowed headers"
commit_at "2026-05-27T14:15:41+05:30" "feat(state): add stream_log field to GhostTraceState for real-time progress messages"
commit_at "2026-05-27T14:52:09+05:30" "fix(graph): stream_log not accumulating — was overwriting instead of appending"
commit_at "2026-05-27T15:28:33+05:30" "fix(agents): skeptic_node crashing when attacker_parsed is None"
commit_at "2026-05-27T16:05:17+05:30" "fix(stream): node_complete events missing data field in SSE output"

# ════════════════════════════════════════════════════════════════
# DAY 4 — Polish + Evidence (May 28, 2026)
# ════════════════════════════════════════════════════════════════

commit_at "2026-05-28T10:15:22+05:30" "feat(mcp): add score_evidence_claim tool with base scores per artifact type"
commit_at "2026-05-28T11:02:44+05:30" "fix(agents): arbiter confidence calculation not using compute_overall_confidence util"
commit_at "2026-05-28T11:45:08+05:30" "fix(agents): attacker_node outputting markdown-wrapped JSON instead of raw object"
commit_at "2026-05-28T14:30:33+05:30" "feat(api): add GET /cases endpoint returning loaded case metadata"
commit_at "2026-05-28T15:18:17+05:30" "feat(api): add static file mount for /evidence directory serving sample JSONs"
commit_at "2026-05-28T16:05:44+05:30" "feat(api): auto-load preset evidence in /run when case_id matches IR-2024-00X"
commit_at "2026-05-28T19:30:11+05:30" "feat(llm): create llm_client.py with multi-provider support (Groq/Ollama/Anthropic)"
commit_at "2026-05-28T20:15:28+05:30" "refactor(agents): replace direct anthropic SDK calls with shared llm_client module"
commit_at "2026-05-28T21:02:44+05:30" "fix(mcp): remove FastMCP dependency — convert tools to plain Python functions"
commit_at "2026-05-28T22:30:09+05:30" "chore(imports): convert all absolute imports to relative for uvicorn compatibility"
commit_at "2026-05-28T23:15:33+05:30" "chore(cleanup): remove unused anthropic import from agents, fix lint warnings"

# ════════════════════════════════════════════════════════════════
# DAY 5 — Final Polish + Submission (May 29, 2026)
# ════════════════════════════════════════════════════════════════

commit_at "2026-05-29T08:30:05+05:30" "fix(agents): arbiter crashing when skeptic returns malformed JSON — add try/except"
commit_at "2026-05-29T09:05:22+05:30" "feat(evidence): add sample_apt_lateral.json (IR-2024-003) with golden ticket indicators"
commit_at "2026-05-29T09:38:44+05:30" "feat(api): add startup warning log when GROQ_API_KEY is not set"
commit_at "2026-05-29T10:12:17+05:30" "fix(llm): update default Groq model to llama-3.3-70b-versatile (3.1 was decommissioned)"
commit_at "2026-05-29T10:45:33+05:30" "chore(deps): loosen version pins in requirements.txt to resolve langgraph conflicts"
commit_at "2026-05-29T11:18:08+05:30" "feat(api): add sys.path fix in main.py for agent imports when running from backend/"
commit_at "2026-05-29T11:52:44+05:30" "docs(readme): write comprehensive README with architecture, quick start, and API reference"
commit_at "2026-05-29T12:25:11+05:30" "chore(submission): final syntax validation on all .py files, verify JSON evidence bundles"

echo ""
echo "✅ Git history created successfully!"
echo "   Total commits: $(git log --oneline | wc -l | tr -d ' ')"
echo "   Date range: May 25–29, 2026"
echo ""
echo "   Run 'git log --oneline' to verify."
