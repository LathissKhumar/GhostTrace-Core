# 👻 GhostTrace

*Two AI agents argue about your evidence — the truth emerges from the debate.*

GhostTrace is an adversarial multi-agent debate system for cybersecurity incident response. It pits an Attacker Agent against a Skeptic Agent in a structured forensic debate, then synthesizes the surviving claims into a confidence-scored IR report through a neutral Arbiter. The core insight is simple but powerful: LLM hallucinations collapse under cross-examination. A claim that sounds confident to one agent cannot survive a second agent reading the same evidence and demanding proof.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI 0.115](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph 0.2](https://img.shields.io/badge/LangGraph-0.2-purple?logo=data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)](https://langchain-ai.github.io/langgraph/)
[![Groq Free Tier](https://img.shields.io/badge/Groq-Free_Tier-orange?logo=data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)](https://console.groq.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Hackathon: Build Beyond Tomorrow](https://img.shields.io/badge/Hackathon-Build_Beyond_Tomorrow-ff6b6b)](https://hackathon.dev)

---

## Table of Contents

- [The Problem](#the-problem)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Agent Deep Dive](#agent-deep-dive)
- [Verdict System](#verdict-system)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage Walkthrough](#usage-walkthrough)
- [Sample Evidence Bundles](#sample-evidence-bundles)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [How Hallucinations Are Eliminated](#how-hallucinations-are-eliminated)
- [Roadmap](#roadmap)
- [The Core Insight](#the-core-insight)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## The Problem

Traditional single-agent AI systems for incident response suffer from a fundamental flaw: confirmation bias. When you ask one LLM to analyze forensic evidence, it constructs a narrative and then unconsciously seeks evidence to support that narrative. There is no adversarial pressure, no cross-examination, no mechanism to challenge weak claims. The result is a confident-sounding report built on a foundation of unchecked assumptions.

This problem is amplified by LLM hallucinations. A single agent analyzing a SIFT evidence bundle might claim "the attacker used PowerShell to establish persistence via registry run keys" — and that claim might sound perfectly reasonable. But did the evidence actually contain a registry modification at that path? Was the timestamp consistent with the alleged attack timeline? Without a second agent reading the same evidence and demanding proof, hallucinated claims pass through unchallenged.

The failure mode is predictable and dangerous: analysts receive a polished report with high confidence scores, but the underlying claims were never stress-tested. In incident response, acting on hallucinated findings can mean isolating the wrong host, blocking legitimate traffic, or missing the actual attack vector entirely.

```
┌─────────────────────────────────────────────────────────┐
│              SINGLE-AGENT FAILURE MODE                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   Evidence ──→ [ Single LLM Agent ] ──→ Report          │
│                       │                                 │
│                       ├── Confirmation bias             │
│                       ├── No cross-examination          │
│                       ├── Hallucinations pass through   │
│                       └── False confidence scores       │
│                                                         │
│   Result: Confident report built on unchecked claims    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## How It Works

GhostTrace operates like a courtroom. The Attacker Agent is the prosecutor — it builds the most compelling attack narrative from the forensic evidence, citing specific artifacts, timestamps, and MITRE ATT&CK techniques. The Skeptic Agent is the defense attorney — it reads the same evidence and systematically challenges every claim, demanding proof and proposing alternative explanations. The Arbiter Agent is the judge — it weighs the surviving arguments and produces a final verdict with confidence scores.

This adversarial structure means that only claims which survive cross-examination make it into the final report. If the Attacker claims "lateral movement via PsExec" but the Skeptic finds no corresponding network connection or authentication event, that claim gets downgraded or excluded. The debate itself is the quality filter.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        GHOSTTRACE PIPELINE                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────┐    ┌─────────┐    ┌───────────────────────────────┐    │
│  │ Evidence │    │ FastAPI │    │        LangGraph Pipeline      │    │
│  │  Bundle  │───▶│  /run   │───▶│                               │    │
│  │  (JSON)  │    │  (SSE)  │    │  ┌──────────┐                │    │
│  └─────────┘    └─────────┘    │  │ Attacker │ Build narrative │    │
│                       │         │  │  Agent   │ + kill chain    │    │
│                       │         │  └────┬─────┘                │    │
│                       │         │       │                       │    │
│                  SSE Stream     │  ┌────▼─────┐                │    │
│                       │         │  │ Skeptic  │ Cross-examine  │    │
│                       │         │  │  Agent   │ every claim    │    │
│                       │         │  └────┬─────┘                │    │
│                       │         │       │                       │    │
│                       │         │  ┌────▼─────┐                │    │
│                       │         │  │ Arbiter  │ Synthesize     │    │
│                       │         │  │  Agent   │ final report   │    │
│                       │         │  └──────────┘                │    │
│                       │         └───────────────────────────────┘    │
│                       │                        │                     │
│                       ▼                        ▼                     │
│              ┌─────────────────────────────────────┐                │
│              │   Confidence-Scored IR Report        │                │
│              │   (Only surviving claims included)   │                │
│              └─────────────────────────────────────┘                │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

The adversarial approach prevents hallucinations because every claim must withstand scrutiny from an agent whose explicit goal is to find weaknesses. Claims backed by real artifacts survive; claims built on inference or assumption are exposed and downgraded. The final report contains only what the evidence actually supports.

## Architecture

GhostTrace is composed of four architectural layers.

Each layer has a single responsibility and communicates with adjacent layers through well-defined interfaces. The Presentation layer handles user interaction and real-time rendering. The Streaming layer manages SSE connections and event delivery. The Orchestration layer sequences agent execution via LangGraph. The Tool layer provides structured evidence access through MCP. The Data layer holds evidence bundles and agent outputs in memory.

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                            │
│  React + Vite + TailwindCSS                                     │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐           │
│  │  Upload  │  │    Debate    │  │     Report     │           │
│  │   Page   │  │  (Split View)│  │  (IR Document) │           │
│  └──────────┘  └──────────────┘  └────────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                    STREAMING LAYER                               │
│  Server-Sent Events (SSE)                                       │
│  ┌──────────────────────────────────────────────────────┐      │
│  │  EventSource ←── text/event-stream ←── FastAPI       │      │
│  │  (log | node_complete | complete | error)            │      │
│  └──────────────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────────────┤
│                   ORCHESTRATION LAYER                            │
│  LangGraph StateGraph                                           │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐           │
│  │  Attacker  │───▶│  Skeptic   │───▶│  Arbiter   │           │
│  │    Node    │    │    Node    │    │    Node    │           │
│  └────────────┘    └────────────┘    └────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                      TOOL LAYER                                  │
│  MCP Server (FastMCP)                                           │
│  ┌────────────────┐ ┌────────────┐ ┌──────────────────┐       │
│  │ query_evidence │ │ lookup_ttp │ │ score_evidence   │       │
│  │                │ │            │ │ _claim           │       │
│  └────────────────┘ └────────────┘ └──────────────────┘       │
├─────────────────────────────────────────────────────────────────┤
│                      DATA LAYER                                  │
│  In-Memory Store                                                │
│  ┌──────────────────────────────────────────────────────┐      │
│  │  _evidence_store: dict[case_id → evidence_bundle]    │      │
│  │  GhostTraceState: TypedDict (pipeline shared state)  │      │
│  └──────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

The LangGraph state acts as a "shared whiteboard" that flows through all three agent nodes. Each agent reads from the state, performs its analysis, and writes its output back. This means the Skeptic can read exactly what the Attacker claimed, and the Arbiter can see both the original claims and the challenges. No information is lost between stages, and the full debate history is preserved for the final report.

## Agent Deep Dive

### Attacker Agent (Red Team Threat Hunter)

The Attacker Agent assumes the persona of an elite red team operator analyzing a compromised environment. Its job is to construct the most technically sophisticated and plausible attack narrative from the available evidence. It thinks like an attacker: what would I have done given these artifacts?

The system prompt philosophy is aggressive attribution. The Attacker Agent is instructed to find the attack, not to be cautious. It maps every stage to MITRE ATT&CK, cites specific artifacts with timestamps and process IDs, and assigns confidence scores based on evidence quality. This deliberate aggressiveness ensures that all possible attack vectors are surfaced for the Skeptic to challenge.

```
┌─────────────────────────────────────────────────────────┐
│                   ATTACKER AGENT                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  INPUT:                                                 │
│  ┌─────────────────────────────────┐                   │
│  │ Evidence Bundle (full JSON)     │                   │
│  │ - process_tree                  │                   │
│  │ - network_logs                  │                   │
│  │ - file_events                   │                   │
│  │ - registry_changes              │                   │
│  │ - auth_logs                     │                   │
│  └─────────────────────────────────┘                   │
│                    │                                    │
│                    ▼                                    │
│  PROCESSING: Build kill chain, map to ATT&CK           │
│                    │                                    │
│                    ▼                                    │
│  OUTPUT:                                               │
│  ┌─────────────────────────────────┐                   │
│  │ AttackerOutput (JSON)           │                   │
│  │ - hypothesis                    │                   │
│  │ - kill_chain[] (with MITRE IDs) │                   │
│  │ - attribution                   │                   │
│  │ - first_seen (ISO 8601)         │                   │
│  │ - recommended_immediate_action  │                   │
│  └─────────────────────────────────┘                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Skeptic Agent (Forensic Defense Attorney)

The Skeptic Agent assumes the persona of a meticulous forensic defense attorney. Its job is to find every weakness, gap, and alternative explanation in the Attacker's narrative. It reads the same evidence and asks: does this artifact actually prove what the Attacker claims? Could there be a benign explanation?

The system prompt philosophy is principled skepticism. The Skeptic is not contrarian for its own sake — it applies Occam's Razor. If a simpler, non-malicious explanation exists that requires fewer assumptions, the Skeptic will propose it. This ensures that only genuinely suspicious findings survive into the final report.

```
┌─────────────────────────────────────────────────────────┐
│                   SKEPTIC AGENT                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  INPUT:                                                 │
│  ┌─────────────────────────────────┐                   │
│  │ Evidence Bundle (full JSON)     │                   │
│  │ + Attacker Narrative (JSON)     │                   │
│  └─────────────────────────────────┘                   │
│                    │                                    │
│                    ▼                                    │
│  PROCESSING: Challenge each claim, issue verdicts      │
│                    │                                    │
│                    ▼                                    │
│  OUTPUT:                                               │
│  ┌─────────────────────────────────┐                   │
│  │ SkepticOutput (JSON)            │                   │
│  │ - overall_assessment            │                   │
│  │ - challenges[] (with verdicts)  │                   │
│  │ - unchallenged_claims[]         │                   │
│  │ - do_not_do                     │                   │
│  └─────────────────────────────────┘                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Arbiter Agent (Neutral Judge)

The Arbiter Agent assumes the persona of a senior CISO synthesizing a courtroom debate into an executive-ready incident response report. It reads the full debate record — the Attacker's narrative, the Skeptic's challenges, and the original evidence — then produces a confidence-scored report based solely on what survived cross-examination.

The system prompt philosophy is evidence-based synthesis. The Arbiter never introduces new claims. It only classifies, scores, and summarizes what the debate produced. Claims that were SUSTAINED get high confidence. Claims that were OVERRULED are excluded entirely. The result is a report that executives can trust because every finding has been stress-tested.

```
┌─────────────────────────────────────────────────────────┐
│                   ARBITER AGENT                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  INPUT:                                                 │
│  ┌─────────────────────────────────┐                   │
│  │ Evidence Bundle (full JSON)     │                   │
│  │ + Attacker Narrative (JSON)     │                   │
│  │ + Skeptic Rebuttal (JSON)       │                   │
│  └─────────────────────────────────┘                   │
│                    │                                    │
│                    ▼                                    │
│  PROCESSING: Classify claims, compute confidence       │
│                    │                                    │
│                    ▼                                    │
│  OUTPUT:                                               │
│  ┌─────────────────────────────────┐                   │
│  │ ArbiterReport (JSON)            │                   │
│  │ - incident_summary              │                   │
│  │ - classification                │                   │
│  │ - overall_confidence (0-100)    │                   │
│  │ - confirmed_findings[]          │                   │
│  │ - unresolved_items[]            │                   │
│  │ - recommended_actions[]         │                   │
│  │ - excluded_claims[]             │                   │
│  │ - skeptic_key_flag              │                   │
│  └─────────────────────────────────┘                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Verdict System

The Skeptic Agent issues exactly one verdict per claim in the Attacker's kill chain. These verdicts drive the entire downstream classification — the Arbiter uses them to determine confidence scores, and the frontend uses them to render color-coded badges.

| Verdict | Meaning | Arbiter Mapping | Badge Color |
|---------|---------|-----------------|-------------|
| `SUSTAINED` | Claim is directly supported by cited artifacts with no inference required | Confirmed Finding (HIGH confidence, 100 pts) | Green |
| `NEEDS_MORE_EVIDENCE` | Claim is plausible but cited evidence alone does not confirm it | Unresolved Item (MEDIUM confidence, 50 pts) | Amber |
| `OVERRULED` | Cited artifact is absent from evidence or another artifact contradicts the claim | Excluded Claim (0 pts, removed from report) | Red |
| `ALTERNATIVE_EXPLANATION` | A simpler non-malicious explanation exists requiring fewer assumptions | Unresolved Item (LOW confidence, 10 pts) | Purple |

These four categories were chosen because they map cleanly to incident response decision-making. SUSTAINED means "act on this." NEEDS_MORE_EVIDENCE means "investigate further before acting." OVERRULED means "do not act on this — it's wrong." ALTERNATIVE_EXPLANATION means "consider the benign interpretation before escalating." Together, they give analysts a clear framework for prioritizing response actions.

## Tech Stack

| Layer | Technology | Version | Why This Choice |
|-------|-----------|---------|-----------------|
| LLM (Default) | Groq (Llama 3.3 70B) | Free Tier | Free cloud inference, no credit card, 30 req/min, blazing fast |
| LLM (Optional) | Anthropic Claude | claude-sonnet-4-20250514 | Premium option for maximum reasoning quality |
| Backend Framework | FastAPI | 0.115+ | Async-native, built-in SSE support, automatic OpenAPI docs |
| Agent Orchestration | LangGraph | 0.2+ | StateGraph enforces sequential execution, typed state passing |
| Data Validation | Pydantic | 2.8+ | Strict schema validation catches malformed LLM output |
| Frontend Framework | React | 18.3 | Component model fits agent card UI, hooks for SSE state |
| Build Tool | Vite | 6.0 | Sub-second HMR, native ESM, zero-config React support |
| Styling | TailwindCSS | 4.0 | Utility-first enables rapid dark-theme prototyping |
| Streaming | Server-Sent Events | Native | Unidirectional, simpler than WebSockets, proxy-friendly |
| Evidence Tools | FastMCP | Latest | Structured tool access, typed parameters, auditable queries |
| HTTP Client | OpenAI SDK | 1.40+ | Compatible with Groq, Ollama, and Anthropic via base_url swap |

Every technology choice was deliberate. Groq provides free, fast inference that makes the system accessible to anyone without a credit card. LangGraph was chosen over raw async chains because its StateGraph provides compile-time guarantees about execution order. Pydantic was chosen over manual validation because it generates clear error messages when LLM output deviates from the expected schema. SSE was chosen over WebSockets because the data flow is strictly server-to-client — the analyst observes the debate but does not participate in it.

## Project Structure

```
ghosttrace/
├── backend/
│   ├── main.py                  # FastAPI app, routes, CORS, evidence store
│   ├── graph.py                 # LangGraph StateGraph pipeline orchestration
│   ├── state.py                 # GhostTraceState TypedDict + Pydantic models
│   ├── llm_client.py            # Multi-provider LLM client (Groq/Ollama/Anthropic)
│   ├── requirements.txt         # Python dependencies
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── attacker.py          # Attacker Agent node (red team threat hunter)
│   │   ├── skeptic.py           # Skeptic Agent node (forensic defense attorney)
│   │   └── arbiter.py           # Arbiter Agent node (neutral judge)
│   ├── mcp_tools/
│   │   ├── __init__.py
│   │   ├── server.py            # FastMCP server + score_evidence_claim tool
│   │   ├── query_evidence.py    # Evidence query tool (filter by type/time)
│   │   └── lookup_ttp.py        # MITRE ATT&CK technique lookup tool
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── json_parser.py       # safe_parse_json (resilient LLM output parsing)
│   │   └── confidence_scorer.py # Algorithmic confidence score computation
│   └── evidence/
│       ├── sample_ransomware.json       # IR-2024-001: Ransomware scenario
│       ├── sample_insider_threat.json   # IR-2024-002: Insider threat scenario
│       └── sample_apt_lateral.json      # IR-2024-003: APT lateral movement
├── frontend/
│   ├── index.html               # Vite entry point
│   ├── package.json             # Node dependencies
│   ├── vite.config.js           # Vite configuration
│   ├── tailwind.config.js       # TailwindCSS dark theme config
│   └── src/
│       ├── main.jsx             # React entry point
│       ├── App.jsx              # Router setup (Upload → Debate → Report)
│       ├── index.css            # Global styles + JetBrains Mono import
│       ├── pages/
│       │   ├── Upload.jsx       # Evidence upload with drag-drop + presets
│       │   ├── Debate.jsx       # Split-panel real-time debate view
│       │   └── Report.jsx       # Professional IR report layout
│       ├── components/
│       │   ├── EvidenceUploader.jsx  # Drag-drop zone with validation
│       │   ├── StreamLog.jsx         # Terminal-style scrolling log
│       │   ├── AttackerCard.jsx      # Red-tinted attacker narrative
│       │   ├── SkepticCard.jsx       # Blue-tinted skeptic challenges
│       │   ├── ArbiterReport.jsx     # Full report rendering
│       │   ├── ClaimRow.jsx          # Single claim with verdict badge
│       │   ├── VerdictBadge.jsx      # Color-coded verdict pill
│       │   ├── MitreBadge.jsx        # Clickable ATT&CK technique link
│       │   └── ConfidenceMeter.jsx   # SVG circular progress gauge
│       └── lib/
│           ├── api.js               # HTTP client (upload, getCases)
│           └── useDebateStream.js   # SSE hook (phase, logs, data)
└── README.md
```

The project follows a strict separation of concerns. The backend is organized by responsibility: agents handle LLM interaction, mcp_tools handle evidence access, utils handle data transformation. The frontend mirrors this with pages for navigation flow and components for reusable UI elements. The lib directory contains stateful logic (API calls, SSE streaming) that components consume through hooks.

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Free Groq API key (get one at [console.groq.com](https://console.groq.com) — no credit card required)

### Step 1: Clone the repository

```bash
git clone https://github.com/your-username/ghosttrace.git
cd ghosttrace
```

### Step 2: Set up the backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Configure your API key

```bash
# Create .env file in the backend directory
echo "GROQ_API_KEY=your_groq_api_key_here" > .env
```

> **⚠️ Note:** Groq offers a generous free tier (30 requests/minute, 14,400 requests/day). Sign up at [console.groq.com](https://console.groq.com), create an API key, and paste it above. No credit card needed.

### Step 4: Start the backend

```bash
uvicorn main:app --reload --port 8000
```

### Step 5: Set up and start the frontend

```bash
cd ../frontend
npm install
npm run dev
```

### Step 6: Open the application

Navigate to [http://localhost:5173](http://localhost:5173) in your browser. You should see the GhostTrace upload interface with the dark terminal aesthetic.

> **⚠️ Note:** Want to use Anthropic Claude instead? Set `LLM_PROVIDER=anthropic` and `ANTHROPIC_API_KEY=your_key` in your `.env` file. See the [Configuration](#configuration) section for all options.

## Usage Walkthrough

### 1. Upload Evidence

**What you see:** A dark terminal-themed upload page with a drag-drop zone and three preset scenario buttons.

**What's happening:** The frontend validates the JSON structure client-side, extracts artifact metadata, and displays the file details before you commit to launching the debate.

### 2. Launch the Debate

**What you see:** After clicking "Launch Debate," the UI transitions to a split-panel view with a streaming log terminal at the top.

**What's happening:** The frontend POSTs the evidence to `/upload`, receives a `case_id`, then opens an SSE connection to `GET /run?case_id=X`. The LangGraph pipeline initializes the shared state and begins execution.

### 3. Watch the Attacker Build Its Case

**What you see:** The left panel (red-tinted) populates with the Attacker's narrative — kill chain stages appear one by one, each with a MITRE ATT&CK badge and confidence score. The streaming log shows progress messages.

**What's happening:** The Attacker Agent reads the full evidence bundle, constructs a kill chain hypothesis, maps each stage to ATT&CK techniques, and outputs structured JSON. The SSE stream delivers a `node_complete` event with the full parsed output.

### 4. Watch the Skeptic Cross-Examine

**What you see:** The right panel (blue-tinted) populates with the Skeptic's challenges. Each claim gets a color-coded verdict badge: green (SUSTAINED), amber (NEEDS MORE EVIDENCE), red (OVERRULED), or purple (ALTERNATIVE EXPLANATION).

**What's happening:** The Skeptic Agent reads both the evidence and the Attacker's narrative, then issues verdicts for each claim. It identifies gaps, contradictions, and simpler explanations. The streaming log shows verdict counts.

### 5. Receive the Arbiter's Report

**What you see:** The Arbiter report panel slides up from the bottom with a confidence meter, confirmed findings table, unresolved items, and recommended actions.

**What's happening:** The Arbiter Agent synthesizes the debate, classifying each claim based on its verdict. It computes a weighted confidence score, filters out excluded claims, and produces an executive-ready IR report.

### 6. Review the Final Report

**What you see:** A professional IR report layout with sections for executive summary, confirmed findings (with MITRE badges), unresolved items (with investigation notes), recommended actions, and the Skeptic's key flag.

**What's happening:** The Report page renders the ArbiterReport data in a format suitable for CISO presentation. The confidence meter uses color thresholds (green/amber/red) to communicate overall certainty at a glance.

## Sample Evidence Bundles

GhostTrace ships with three pre-built evidence scenarios that demonstrate different attack patterns and debate dynamics.

### Scenario 1: Ransomware (IR-2024-001)

A classic ransomware deployment chain starting with a phishing payload, progressing through PowerShell execution, C2 communication, lateral movement, and culminating in file encryption. The evidence bundle contains clear indicators at each stage, making this scenario ideal for demonstrating SUSTAINED verdicts.

```
ATTACK TIMELINE (IR-2024-001)
─────────────────────────────────────────────────────────
02:10:00  auth_logs     │ svc_backup logon (Type 3) from 10.0.5.200
02:14:10  file_events   │ svchost32.exe created in C:\ProgramData\
02:14:33  process_tree  │ powershell.exe spawned by svchost32.exe
02:14:45  registry      │ Run key persistence: WindowsUpdate
02:15:01  network_logs  │ HTTPS beacon to update-service.xyz (185.220.101.34)
02:17:22  file_events   │ .encrypted extensions appearing across shares
02:18:00  file_events   │ RANSOM_NOTE.txt dropped in multiple directories
─────────────────────────────────────────────────────────
```

### Scenario 2: Insider Threat (IR-2024-002)

A data exfiltration scenario involving a privileged user accessing sensitive files outside normal business hours, staging data in a temp directory, and uploading to a personal cloud storage service. This scenario demonstrates ALTERNATIVE_EXPLANATION verdicts — the Skeptic proposes legitimate reasons for after-hours access.

```
ATTACK TIMELINE (IR-2024-002)
─────────────────────────────────────────────────────────
23:45:00  auth_logs     │ jdoe VPN logon from home IP
23:47:12  file_events   │ Bulk read: /finance/Q4_projections/*.xlsx
23:48:30  file_events   │ Files copied to C:\Users\jdoe\AppData\Temp\export\
23:49:15  process_tree  │ 7z.exe compressing export directory
23:50:01  network_logs  │ HTTPS upload to personal-cloud.io (2.1 GB)
23:52:00  auth_logs     │ jdoe accessed HR/termination_list.pdf
23:55:00  auth_logs     │ jdoe session disconnect
─────────────────────────────────────────────────────────
```

### Scenario 3: APT Lateral Movement (IR-2024-003)

An advanced persistent threat scenario showing initial access via a compromised service account, credential harvesting with Mimikatz, lateral movement via WMI and PsExec, and data staging for exfiltration. This scenario produces mixed verdicts — some stages have strong evidence while others rely on circumstantial indicators.

```
ATTACK TIMELINE (IR-2024-003)
─────────────────────────────────────────────────────────
01:30:00  auth_logs     │ svc_monitor logon from external IP (unusual)
01:32:15  process_tree  │ cmd.exe → whoami, net group "domain admins"
01:33:45  process_tree  │ mimikatz.exe (renamed: sysdiag.exe) execution
01:35:00  auth_logs     │ admin_backup logon (harvested credentials)
01:36:20  network_logs  │ WMI connection to DC01 (10.0.0.5:135)
01:37:45  process_tree  │ PsExec lateral to FILE-SVR01
01:40:00  file_events   │ Data staging: C:\Windows\Temp\exfil\*.cab
01:42:30  network_logs  │ DNS tunneling to ns1.legit-looking-domain.com
─────────────────────────────────────────────────────────
```

## API Reference

### Endpoints

| Method | Path | Description | Request | Response |
|--------|------|-------------|---------|----------|
| `POST` | `/upload` | Upload evidence bundle | Multipart file (JSON) | `{case_id, artifact_types, total_artifacts, status}` |
| `GET` | `/run?case_id=X` | Start debate, stream results | Query param: case_id | SSE stream (`text/event-stream`) |
| `GET` | `/cases` | List uploaded cases | None | `[{case_id, incident_type, artifact_count}]` |
| `GET` | `/health` | Health check | None | `{status, provider, model}` |

### Upload Evidence

```bash
curl -X POST http://localhost:8000/upload \
  -F "file=@evidence_bundle.json"
```

Response:

```json
{
  "case_id": "IR-2024-001",
  "artifact_types": ["process_tree", "network_logs", "file_events", "registry_changes", "auth_logs"],
  "total_artifacts": 21,
  "status": "ready"
}
```

### Start Debate (SSE Stream)

```bash
curl -N http://localhost:8000/run?case_id=IR-2024-001
```

Response (SSE stream):

```
data: {"type": "log", "message": "Attacker Agent: Analyzing 5 artifact types..."}

data: {"type": "log", "message": "Attacker Agent: Identified 5 kill chain stages"}

data: {"type": "node_complete", "node": "attacker", "data": {"hypothesis": "...", "kill_chain": [...]}}

data: {"type": "log", "message": "Skeptic Agent: 3 SUSTAINED, 1 challenged, 1 OVERRULED"}

data: {"type": "node_complete", "node": "skeptic", "data": {"overall_assessment": "...", "challenges": [...]}}

data: {"type": "complete", "report": {"incident_summary": "...", "overall_confidence": 72, ...}}
```

### Health Check

```bash
curl http://localhost:8000/health
```

Response:

```json
{
  "status": "ok",
  "provider": "groq",
  "model": "llama-3.3-70b-versatile"
}
```

### List Cases

```bash
curl http://localhost:8000/cases
```

Response:

```json
[
  {
    "case_id": "IR-2024-001",
    "incident_type": "suspected_ransomware",
    "artifact_count": 21
  }
]
```

## Configuration

All configuration is managed through environment variables. Create a `.env` file in the `backend/` directory.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | Yes (if using Groq) | — | Free API key from [console.groq.com](https://console.groq.com) |
| `GROQ_MODEL` | No | `llama-3.3-70b-versatile` | Groq model to use (see Groq docs for options) |
| `LLM_PROVIDER` | No | `groq` | LLM provider: `groq`, `anthropic`, or `ollama` |
| `ANTHROPIC_API_KEY` | Only if provider=anthropic | — | Anthropic API key (paid) |
| `OLLAMA_BASE_URL` | No | `http://localhost:11434/v1` | Ollama server URL for local inference |
| `OLLAMA_MODEL` | No | `llama3.1:8b` | Ollama model name |

Example `.env` file (Groq — recommended):

```bash
# Default: Groq (free, fast, no credit card)
GROQ_API_KEY=gsk_your_key_here
```

Example `.env` file (Anthropic — premium):

```bash
# Optional: Switch to Anthropic Claude for maximum quality
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your_key_here
```

Example `.env` file (Ollama — fully local):

```bash
# Optional: Run completely offline with local models
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.1:70b
```

## How Hallucinations Are Eliminated

The fundamental problem with single-agent LLM systems is that hallucinations are invisible. When one agent generates a claim, there is no mechanism to verify whether that claim is grounded in the actual input data. The agent's confidence in its own output provides no signal about accuracy — LLMs are confidently wrong as often as they are confidently right.

GhostTrace eliminates hallucinations through structural adversarial pressure. The Skeptic Agent has one job: find claims that are not directly supported by the evidence. It reads the same evidence bundle as the Attacker and asks, for each claim: "Show me the artifact. Show me the timestamp. Show me the process ID." If the Attacker cited an artifact that does not exist in the evidence, the Skeptic issues an OVERRULED verdict. If the Attacker made an inferential leap that the evidence does not directly support, the Skeptic issues NEEDS_MORE_EVIDENCE.

This works because hallucinations are structurally fragile. A hallucinated claim — by definition — is not grounded in the input data. When a second agent reads that same input data and looks for the cited evidence, the hallucination is exposed. The Attacker cannot defend a claim that references a non-existent artifact. The cross-examination collapses the hallucination into a visible gap.

The Arbiter then enforces the consequence: hallucinated claims (OVERRULED) are excluded from the final report entirely. They do not contribute to the confidence score. They do not appear in recommended actions. The analyst never sees them as findings — only as excluded items with an explanation of why they were rejected.

```
┌─────────────────────────────────────────────────────────────┐
│           WHY HALLUCINATIONS COLLAPSE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Attacker claims: "PsExec lateral movement at 02:36:20"    │
│                          │                                  │
│                          ▼                                  │
│  Skeptic checks: Is there a network connection to port     │
│  445 at 02:36:20 in the evidence?                          │
│                          │                                  │
│              ┌───────────┴───────────┐                     │
│              │                       │                      │
│         Found in                Not found in               │
│         evidence                evidence                    │
│              │                       │                      │
│              ▼                       ▼                      │
│        SUSTAINED              OVERRULED                    │
│     (enters report)      (excluded from report)            │
│                                                             │
│  Result: Only evidence-backed claims survive                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Roadmap

| Feature | Status | Priority | Notes |
|---------|--------|----------|-------|
| Multi-round debate (Attacker rebuts Skeptic) | Planned | High | Allow 2-3 rounds of back-and-forth before Arbiter |
| PDF report export | Planned | High | Generate downloadable PDF from ArbiterReport |
| STIX/TAXII evidence ingestion | Planned | Medium | Accept standardized threat intelligence formats |
| Persistent case database (PostgreSQL) | Planned | Medium | Replace in-memory store for production use |
| Multi-case comparison view | Planned | Medium | Compare findings across related incidents |
| Custom agent personas | Planned | Low | Let analysts tune agent aggressiveness/skepticism |
| Splunk/Elastic integration | Planned | High | Pull evidence directly from SIEM platforms |
| Confidence score calibration | In Progress | High | Tune scoring weights based on real-world outcomes |
| MITRE ATT&CK Navigator export | Planned | Low | Export kill chain to ATT&CK Navigator layer file |
| Webhook notifications | Planned | Low | Alert SOC channels when debate completes |
| Role-based access control | Planned | Medium | Restrict case access by analyst role |
| Audit trail logging | Planned | High | Full provenance chain for compliance |

## The Core Insight

Most AI systems fail at incident response not because the models are bad, but because the architecture is wrong. A single agent analyzing evidence is like a prosecutor who also serves as judge and jury. There is no adversarial pressure, no burden of proof, no mechanism for challenge. The result is a system that is confidently wrong in ways that are invisible to the analyst.

GhostTrace inverts this. Instead of asking one agent to be both thorough and cautious — contradictory goals that produce mediocre results — we give each goal to a separate agent. The Attacker is rewarded for finding attacks. The Skeptic is rewarded for finding weaknesses. Neither agent needs to be balanced, because the system achieves balance through opposition.

The disagreement is the signal. When the Attacker and Skeptic agree, you have a high-confidence finding. When they disagree, you have identified exactly where the evidence is ambiguous and what additional investigation is needed. The debate does not just produce a report — it produces a map of certainty and uncertainty that tells analysts exactly where to focus next.

## Contributing

Contributions are welcome. GhostTrace is built for the Build Beyond Tomorrow hackathon, but we intend to maintain and grow it as an open-source project.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run the test suite:
   ```bash
   cd backend && pytest --cov
   ```
5. Commit your changes (`git commit -m 'Add: brief description of change'`)
6. Push to your branch (`git push origin feature/your-feature-name`)
7. Open a Pull Request

### Development Guidelines

- All LLM output must be parsed through `safe_parse_json` — never call `json.loads` directly on agent responses
- All agent outputs must be validated against their Pydantic schema before being stored in state
- New agents must follow the existing pattern: receive full state, call LLM, parse response, validate, return updated state
- Frontend components should be stateless where possible; state lives in hooks and pages
- Use the existing dark terminal aesthetic (background `#0a0a0f`, accent `#00ff88`, monospace font)

### Reporting Issues

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Evidence bundle used (if applicable — use sample scenarios for reproducibility)

## License

MIT License

Copyright (c) 2024 GhostTrace Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments

- **Groq** — For providing free, blazing-fast LLM inference that makes adversarial multi-agent systems accessible to everyone without a credit card
- **LangGraph** — For the StateGraph abstraction that makes sequential agent orchestration with typed state passing both simple and correct
- **SANS SIFT** — For the forensic workstation framework that inspired the evidence bundle format and artifact taxonomy
- **MITRE ATT&CK** — For the adversary tactics and techniques knowledge base that provides a shared vocabulary for attack classification
- **Build Beyond Tomorrow Hackathon** — For the challenge that inspired building an AI system where disagreement, not agreement, is the path to truth
